//! A zero-copy PDB reader.
//!
//! [`Pdb`] borrows a mapped PDB file. Streams are borrowed directly when
//! their blocks are contiguous (the common case for files written by
//! link.exe) and gathered once otherwise. Each part (DBI, TPI, IPI, the
//! symbol hashes, ...) is parsed on first use and cached. Lookups use the
//! PDB's own hash tables and address maps rather than scanning:
//!
//! - types and ids by index: the TPI/IPI hash stream's index offsets;
//! - UDTs by name: the TPI hash buckets;
//! - globals and publics by name: the GSI/PSI hash tables;
//! - publics by address: the PSI address map;
//! - lines by address: the DBI section contributions, then the module's
//!   C13 line tables.

// Stream sizes and offsets are 32-bit in the MSF format, so positions
// within a stream fit in u32.
#![allow(clippy::cast_possible_truncation)]

pub mod dbi;
pub mod gsi;
pub mod hash;
pub mod info;
pub mod module;
pub mod msf;
pub mod names;
pub mod tpi;

use std::cell::OnceCell;

use hexcavator_codeview::symbols::SymbolRecord;
use hexcavator_core::{Error, ErrorKind, Result};

pub use dbi::{DbiStream, Module};
pub use gsi::{PublicsStream, SymbolHash};
pub use info::InfoStream;
pub use module::ModuleStream;
pub use msf::{Msf, StreamData};
pub use names::StringTable;
pub use tpi::TypeStream;

/// Fixed stream indexes.
pub mod stream {
    pub const OLD_DIRECTORY: u32 = 0;
    pub const INFO: u32 = 1;
    pub const TPI: u32 = 2;
    pub const DBI: u32 = 3;
    pub const IPI: u32 = 4;
}

/// A PDB file.
pub struct Pdb<'data> {
    msf: Msf<'data>,
    info: StreamData<'data>,
    dbi_data: StreamData<'data>,
    names_data: OnceCell<StreamData<'data>>,
    records_data: OnceCell<StreamData<'data>>,
    publics_data: OnceCell<StreamData<'data>>,
    globals_data: OnceCell<StreamData<'data>>,
    tpi: OnceCell<TypeStream<'data>>,
    ipi: OnceCell<TypeStream<'data>>,
}

impl<'data> Pdb<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let msf = Msf::parse(data)?;
        let info = msf.stream(stream::INFO)?;
        InfoStream::parse(&info)?;
        let dbi_data = msf.stream_or_empty(stream::DBI)?;
        Ok(Self {
            msf,
            info,
            dbi_data,
            names_data: OnceCell::new(),
            records_data: OnceCell::new(),
            publics_data: OnceCell::new(),
            globals_data: OnceCell::new(),
            tpi: OnceCell::new(),
            ipi: OnceCell::new(),
        })
    }

    pub fn msf(&self) -> &Msf<'data> {
        &self.msf
    }

    pub fn info(&self) -> InfoStream<'_> {
        InfoStream::parse(&self.info).expect("validated in parse")
    }

    pub fn dbi(&self) -> Result<DbiStream<'_>> {
        DbiStream::parse(&self.dbi_data)
    }

    fn cached<'a>(&'a self, cell: &'a OnceCell<StreamData<'data>>, index: Option<u32>) -> &'a [u8] {
        cell.get_or_init(|| {
            index
                .and_then(|i| self.msf.stream_or_empty(i).ok())
                .unwrap_or_default()
        })
    }

    /// The `/names` string table.
    pub fn names(&self) -> Result<StringTable<'_>> {
        let index = self.info().named_stream("/names");
        StringTable::parse(self.cached(&self.names_data, index))
    }

    /// The symbol record stream shared by the global and public hashes.
    pub fn symbol_records(&self) -> &[u8] {
        let index = self.dbi().ok().map(|d| d.symbol_records_stream());
        self.cached(&self.records_data, index)
    }

    pub fn publics(&self) -> Result<PublicsStream<'_>> {
        let index = self.dbi().ok().map(|d| d.publics_stream());
        PublicsStream::parse(self.cached(&self.publics_data, index))
    }

    pub fn globals(&self) -> Result<SymbolHash<'_>> {
        let index = self.dbi().ok().map(|d| d.globals_stream());
        SymbolHash::parse(self.cached(&self.globals_data, index))
    }

    fn type_stream(&self, index: u32) -> Result<TypeStream<'data>> {
        let data = self.msf.stream_or_empty(index)?;
        let hash = match tpi::hash_stream_of(&data) {
            Some(h) => self.msf.stream_or_empty(h)?,
            None => StreamData::Borrowed(&[]),
        };
        TypeStream::parse(data, hash)
    }

    /// The type stream (TPI).
    pub fn types(&self) -> Result<&TypeStream<'data>> {
        if let Some(t) = self.tpi.get() {
            return Ok(t);
        }
        let t = self.type_stream(stream::TPI)?;
        Ok(self.tpi.get_or_init(|| t))
    }

    /// The id stream (IPI): function ids, build info, string ids, ...
    pub fn ids(&self) -> Result<&TypeStream<'data>> {
        if let Some(t) = self.ipi.get() {
            return Ok(t);
        }
        let t = self.type_stream(stream::IPI)?;
        Ok(self.ipi.get_or_init(|| t))
    }

    /// A module's symbol and line stream.
    pub fn module_stream(&self, module: &Module<'_>) -> Result<Option<ModuleStream<'data>>> {
        let Some(index) = module.stream() else {
            return Ok(None);
        };
        Ok(Some(ModuleStream::new(self.msf.stream(index)?, module)))
    }

    /// Finds global symbols named `name` (via the GSI hash).
    pub fn find_globals(&self, name: &str) -> Result<Vec<SymbolRecord<'_>>> {
        let globals = self.globals()?;
        let records = self.symbol_records();
        Ok(globals
            .bucket(name.as_bytes())
            .filter_map(|off| gsi::symbol_at(records, off))
            .filter(|s| s.name() == Some(name.as_bytes()))
            .collect())
    }

    /// Finds a public symbol by name (via the PSI hash).
    pub fn find_public(&self, name: &str) -> Result<Option<SymbolRecord<'_>>> {
        let publics = self.publics()?;
        let records = self.symbol_records();
        Ok(publics
            .hash
            .bucket(name.as_bytes())
            .filter_map(|off| gsi::symbol_at(records, off))
            .find(|s| s.name() == Some(name.as_bytes())))
    }

    /// The public symbol at or before `section:offset`, and the distance
    /// from it.
    pub fn public_at(&self, section: u16, offset: u32) -> Result<Option<(SymbolRecord<'_>, u32)>> {
        let publics = self.publics()?;
        Ok(gsi::public_at(
            &publics,
            self.symbol_records(),
            section,
            offset,
        ))
    }

    /// The image's section headers, from the DBI's optional debug header:
    /// each is (virtual address, virtual size, name).
    pub fn sections(&self) -> Result<Vec<(u32, u32, [u8; 8])>> {
        let dbi = self.dbi()?;
        let Some(index) = dbi.debug_stream(dbi::dbg_stream::SECTION_HEADERS) else {
            return Ok(Vec::new());
        };
        let data = self.msf.stream(index)?;
        Ok(data
            .as_chunks::<40>()
            .0
            .iter()
            .map(|h| {
                let mut name = [0u8; 8];
                name.copy_from_slice(&h[..8]);
                let word = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
                (word(12), word(8), name)
            })
            .collect())
    }

    /// Converts `section:offset` (1-based section) to an RVA.
    pub fn rva(&self, sections: &[(u32, u32, [u8; 8])], section: u16, offset: u32) -> Option<u32> {
        if section == 0 {
            // Section 0 holds absolute symbols such as __ImageBase.
            return Some(offset);
        }
        let (va, _, _) = sections.get(usize::from(section) - 1)?;
        va.checked_add(offset)
    }

    /// The source file and line for `section:offset`.
    pub fn line_at(&self, section: u16, offset: u32) -> Result<Option<SourceLine>> {
        let dbi = self.dbi()?;
        let Some(contrib) = dbi.contribution_at(section, offset) else {
            return Ok(None);
        };
        let Some(module) = dbi.modules().get(usize::from(contrib.module_index.get())) else {
            return Ok(None);
        };
        let Some(stream) = self.module_stream(module)? else {
            return Ok(None);
        };
        let Some((block, line)) = stream.line_at(section, offset) else {
            return Ok(None);
        };
        let file = stream
            .file_checksum(block.file)
            .and_then(|c| {
                self.names()
                    .ok()?
                    .get(c.name)
                    .map(|n| String::from_utf8_lossy(n).into_owned())
            })
            .unwrap_or_default();
        Ok(Some(SourceLine {
            file,
            line: line.line(),
            offset: block.offset + line.offset.get(),
        }))
    }
}

/// A resolved source location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLine {
    pub file: String,
    pub line: u32,
    /// The section offset where the line's code starts.
    pub offset: u32,
}

/// Returns an error if `data` does not look like a PDB.
pub fn check(data: &[u8]) -> Result<()> {
    if data.starts_with(msf::MAGIC) {
        Ok(())
    } else if data.starts_with(b"Microsoft C/C++ program database 2.00") {
        Err(Error::new(
            ErrorKind::Unsupported,
            0,
            "MSF 2.00 (old-format PDB)",
        ))
    } else {
        Err(Error::new(ErrorKind::BadMagic, 0, "PDB"))
    }
}

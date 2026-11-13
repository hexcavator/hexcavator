//! The DBI stream (stream 3): modules, section contributions, the section
//! map, source files, and the indexes of other streams.

use crate::msf::SN_NIL;
use hexcavator_core::{
    Error, ErrorKind, I32Le, Reader, Result, U16Le, U32Le, pod, read_at, read_slice_at,
};

pod! {
    #[derive(Debug)]
    pub struct DbiHeader {
        pub version_signature: I32Le,
        pub version_header: U32Le,
        pub age: U32Le,
        pub global_stream_index: U16Le,
        pub build_number: U16Le,
        pub public_stream_index: U16Le,
        pub pdb_dll_version: U16Le,
        pub sym_record_stream: U16Le,
        pub pdb_dll_rbld: U16Le,
        pub mod_info_size: I32Le,
        pub section_contribution_size: I32Le,
        pub section_map_size: I32Le,
        pub source_info_size: I32Le,
        pub type_server_map_size: I32Le,
        pub mfc_type_server_index: U32Le,
        pub optional_dbg_header_size: I32Le,
        pub ec_substream_size: I32Le,
        pub flags: U16Le,
        pub machine: U16Le,
        pub padding: U32Le,
    }

    /// A section contribution: a range of a section that came from a module.
    #[derive(Debug)]
    pub struct SectionContrib {
        pub section: U16Le,
        pub padding1: U16Le,
        pub offset: I32Le,
        pub size: I32Le,
        pub characteristics: U32Le,
        pub module_index: U16Le,
        pub padding2: U16Le,
        pub data_crc: U32Le,
        pub reloc_crc: U32Le,
    }

    #[derive(Debug)]
    pub struct ModInfoHeader {
        pub unused: U32Le,
        pub section_contrib: SectionContrib,
        pub flags: U16Le,
        pub module_sym_stream: U16Le,
        pub sym_byte_size: U32Le,
        pub c11_byte_size: U32Le,
        pub c13_byte_size: U32Le,
        pub source_file_count: U16Le,
        pub padding: U16Le,
        pub unused2: U32Le,
        pub source_file_name_index: U32Le,
        pub pdb_file_path_name_index: U32Le,
    }

    #[derive(Debug)]
    pub struct SectionMapEntry {
        pub flags: U16Le,
        pub ovl: U16Le,
        pub group: U16Le,
        pub frame: U16Le,
        pub section_name: U16Le,
        pub class_name: U16Le,
        pub offset: U32Le,
        pub section_length: U32Le,
    }
}

/// Section contribution substream versions.
const SC_VER60: u32 = 0xEFFE_0000 + 19970605;
const SC_V2: u32 = 0xEFFE_0000 + 20140516;

/// Indexes of the optional debug header's streams.
pub mod dbg_stream {
    pub const FPO: usize = 0;
    pub const EXCEPTION: usize = 1;
    pub const FIXUP: usize = 2;
    pub const OMAP_TO_SRC: usize = 3;
    pub const OMAP_FROM_SRC: usize = 4;
    pub const SECTION_HEADERS: usize = 5;
    pub const TOKEN_RID_MAP: usize = 6;
    pub const XDATA: usize = 7;
    pub const PDATA: usize = 8;
    pub const NEW_FPO: usize = 9;
    pub const SECTION_HEADERS_ORIG: usize = 10;
}

/// The section contribution substream: an array of [`SectionContrib`]s,
/// 28 bytes each in the original version and 32 in V2 (which appends the
/// contribution's COFF section index in its object).
#[derive(Clone, Copy, Debug)]
pub struct SectionContribs<'s> {
    entries: &'s [u8],
    stride: usize,
}

impl<'s> SectionContribs<'s> {
    fn parse(data: &'s [u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self {
                entries: &[],
                stride: size_of::<SectionContrib>(),
            });
        }
        let stride = match read_at::<U32Le>(data, 0)?.get() {
            SC_VER60 => size_of::<SectionContrib>(),
            SC_V2 => size_of::<SectionContrib>() + 4,
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    0,
                    "section contribution version",
                ));
            }
        };
        Ok(Self {
            entries: &data[4..],
            stride,
        })
    }

    /// Whether this is the V2 layout.
    pub fn is_v2(&self) -> bool {
        self.stride != size_of::<SectionContrib>()
    }

    pub fn len(&self) -> usize {
        self.entries.len() / self.stride
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&'s SectionContrib> {
        let offset = index.checked_mul(self.stride)?;
        if index >= self.len() {
            return None;
        }
        read_at(self.entries, offset as u64).ok()
    }

    /// For V2: the COFF section index, in its object, of entry `index`.
    pub fn coff_section(&self, index: usize) -> Option<u32> {
        if !self.is_v2() || index >= self.len() {
            return None;
        }
        let offset = index * self.stride + size_of::<SectionContrib>();
        read_at::<U32Le>(self.entries, offset as u64)
            .ok()
            .map(|v| v.get())
    }

    pub fn iter(&self) -> impl Iterator<Item = &'s SectionContrib> + 's {
        let this = *self;
        // `get` cannot fail for an index below `len`.
        (0..this.len()).filter_map(move |i| this.get(i))
    }
}

/// A module (compiland) as described by the DBI stream.
#[derive(Clone, Copy, Debug)]
pub struct Module<'s> {
    pub index: usize,
    pub header: &'s ModInfoHeader,
    pub name: &'s [u8],
    pub object_name: &'s [u8],
}

impl Module<'_> {
    /// The module's symbol stream, if any.
    pub fn stream(&self) -> Option<u32> {
        let s = self.header.module_sym_stream.get();
        (s != SN_NIL).then_some(u32::from(s))
    }

    pub fn name_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.name)
    }
}

/// The parsed DBI stream. Substreams are located once; their contents are
/// read on demand.
#[derive(Debug)]
pub struct DbiStream<'s> {
    pub header: &'s DbiHeader,
    modules: Vec<Module<'s>>,
    section_contribs: &'s [u8],
    section_map: &'s [u8],
    file_info: &'s [u8],
    ec: &'s [u8],
    dbg_streams: &'s [U16Le],
}

impl<'s> DbiStream<'s> {
    pub fn parse(data: &'s [u8]) -> Result<Self> {
        let header: &DbiHeader = read_at(data, 0)?;
        if header.version_signature.get() != -1 {
            return Err(Error::new(ErrorKind::Unsupported, 0, "DBI version"));
        }
        let mut r = Reader::with_base(data, 0);
        r.skip(size_of::<DbiHeader>())?;
        let size = |v: i32| {
            usize::try_from(v)
                .map_err(|_| Error::new(ErrorKind::Malformed, 0, "DBI substream size"))
        };
        let mod_info = r.bytes(size(header.mod_info_size.get())?)?;
        let section_contribs = r.bytes(size(header.section_contribution_size.get())?)?;
        let section_map = r.bytes(size(header.section_map_size.get())?)?;
        let file_info = r.bytes(size(header.source_info_size.get())?)?;
        r.skip(size(header.type_server_map_size.get())?)?;
        let ec = r.bytes(size(header.ec_substream_size.get())?)?;
        let dbg = r.bytes(size(header.optional_dbg_header_size.get())?)?;
        let dbg_streams = read_slice_at(dbg, 0, (dbg.len() / 2) as u64)?;

        let mut modules = Vec::new();
        let mut m = Reader::new(mod_info);
        while !m.is_empty() {
            let header: &ModInfoHeader = m.read()?;
            let name = m.cstr()?;
            let object_name = m.cstr()?;
            m.align_to(4)?;
            modules.push(Module {
                index: modules.len(),
                header,
                name,
                object_name,
            });
        }
        Ok(Self {
            header,
            modules,
            section_contribs,
            section_map,
            file_info,
            ec,
            dbg_streams,
        })
    }

    pub fn modules(&self) -> &[Module<'s>] {
        &self.modules
    }

    pub fn machine(&self) -> u16 {
        self.header.machine.get()
    }

    /// Stream indexes of the global and public symbol hashes and the symbol
    /// record stream.
    pub fn globals_stream(&self) -> u32 {
        u32::from(self.header.global_stream_index.get())
    }

    pub fn publics_stream(&self) -> u32 {
        u32::from(self.header.public_stream_index.get())
    }

    pub fn symbol_records_stream(&self) -> u32 {
        u32::from(self.header.sym_record_stream.get())
    }

    /// A stream from the optional debug header (see [`dbg_stream`]).
    pub fn debug_stream(&self, which: usize) -> Option<u32> {
        let s = self.dbg_streams.get(which)?.get();
        (s != SN_NIL).then_some(u32::from(s))
    }

    /// Section contributions, sorted by section and offset, in either
    /// substream version.
    pub fn section_contribs(&self) -> Result<SectionContribs<'s>> {
        SectionContribs::parse(self.section_contribs)
    }

    /// The contribution containing `section:offset`, by binary search.
    pub fn contribution_at(&self, section: u16, offset: u32) -> Option<&'s SectionContrib> {
        let contribs = self.section_contribs().ok()?;
        let key = (section, i64::from(offset));
        let mut lo = 0;
        let mut hi = contribs.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let c = contribs.get(mid)?;
            if (c.section.get(), i64::from(c.offset.get())) <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let c = contribs.get(lo.checked_sub(1)?)?;
        (c.section.get() == section
            && i64::from(offset) < i64::from(c.offset.get()) + i64::from(c.size.get()))
        .then_some(c)
    }

    pub fn section_map(&self) -> Result<&'s [SectionMapEntry]> {
        if self.section_map.len() < 4 {
            return Ok(&[]);
        }
        let count = read_at::<U16Le>(self.section_map, 0)?.get();
        read_slice_at(self.section_map, 4, u64::from(count))
    }

    /// The source files of each module (as offsets into the file name
    /// buffer, resolved).
    pub fn module_files(&self, module: usize) -> Result<Vec<&'s [u8]>> {
        // PDBs with no modules (managed code) have no file info at all.
        if self.file_info.is_empty() {
            return Ok(Vec::new());
        }
        let mut r = Reader::new(self.file_info);
        let modules = usize::from(r.u16_le()?);
        let _ignored = r.u16_le()?;
        let indices: &[U16Le] = r.read_slice(modules)?;
        let counts: &[U16Le] = r.read_slice(modules)?;
        let total: usize = counts.iter().map(|c| usize::from(c.get())).sum();
        let offsets: &[U32Le] = r.read_slice(total)?;
        let names = r.remaining();
        let (Some(start), Some(count)) = (indices.get(module), counts.get(module)) else {
            return Ok(Vec::new());
        };
        // Some writers leave the start indices unset; compute them.
        let start: usize = if start.get() == 0 && module > 0 {
            counts[..module].iter().map(|c| usize::from(c.get())).sum()
        } else {
            usize::from(start.get())
        };
        let mut out = Vec::new();
        for off in offsets.iter().skip(start).take(usize::from(count.get())) {
            out.push(hexcavator_core::cstr_at(names, u64::from(off.get()))?);
        }
        Ok(out)
    }

    /// The EC (edit and continue) name table.
    pub fn ec_names(&self) -> Result<crate::names::StringTable<'s>> {
        crate::names::StringTable::parse(self.ec)
    }
}

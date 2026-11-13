//! Module (compiland) streams: symbols, and C13 debug subsections (line
//! numbers, file checksums, inlinee lines, ...).

use hexcavator_codeview::lines::{self, FileChecksum, LineBlock, LineEntry, subsection};
use hexcavator_codeview::symbols::{SymbolIter, SymbolRecord};
use hexcavator_core::{Reader, U32Le};

use crate::dbi::Module;
use crate::msf::StreamData;

/// The size of the signature a module stream starts with
/// (`CV_SIGNATURE_C13`).
const SIGNATURE_SIZE: usize = 4;

/// A module's stream.
#[derive(Debug)]
pub struct ModuleStream<'s> {
    data: StreamData<'s>,
    symbols_len: usize,
    c11_len: usize,
    c13_len: usize,
}

impl<'s> ModuleStream<'s> {
    pub fn new(data: StreamData<'s>, module: &Module<'_>) -> Self {
        let h = module.header;
        Self {
            data,
            symbols_len: h.sym_byte_size.get() as usize,
            c11_len: h.c11_byte_size.get() as usize,
            c13_len: h.c13_byte_size.get() as usize,
        }
    }

    /// The module's symbols. Offsets are relative to the stream start (as
    /// S_PROCREF and parent/end fields use them).
    pub fn symbols(&self) -> SymbolIter<'_> {
        let end = self.symbols_len.min(self.data.len());
        SymbolIter::new(
            self.data.get(SIGNATURE_SIZE..end).unwrap_or(&[]),
            SIGNATURE_SIZE as u32,
        )
    }

    /// The symbol at `offset`.
    pub fn symbol_at(&self, offset: u32) -> Option<SymbolRecord<'_>> {
        let end = self.symbols_len.min(self.data.len());
        SymbolIter::new(self.data.get(offset as usize..end)?, offset).next()
    }

    fn c13(&self) -> &[u8] {
        let start = self.symbols_len + self.c11_len;
        self.data.get(start..start + self.c13_len).unwrap_or(&[])
    }

    /// The C13 subsections: (kind, contents).
    pub fn subsections(&self) -> impl Iterator<Item = (u32, &[u8])> + '_ {
        lines::subsections(self.c13())
    }

    /// All line blocks in the module.
    pub fn line_blocks(&self) -> Vec<LineBlock<'_>> {
        let mut out = Vec::new();
        for (kind, body) in self.subsections() {
            if kind != subsection::DEBUG_S_LINES {
                continue;
            }
            let _ = lines::parse_lines(body, &mut out);
        }
        out
    }

    /// The file checksums subsection, keyed by entry offset.
    pub fn file_checksum(&self, offset: u32) -> Option<FileChecksum<'_>> {
        let (_, body) = self
            .subsections()
            .find(|(k, _)| *k == subsection::DEBUG_S_FILECHKSMS)?;
        lines::file_checksum(body, offset)
    }

    /// The source line for `segment:offset`, if this module has one.
    pub fn line_at(&self, segment: u16, offset: u32) -> Option<(LineBlock<'_>, &LineEntry)> {
        for block in self.line_blocks() {
            if block.segment != segment
                || offset < block.offset
                // (Both from the file: a block can't run past the end.)
                || offset >= block.offset.saturating_add(block.code_size)
            {
                continue;
            }
            let rel = offset - block.offset;
            let i = block.lines.partition_point(|l| l.offset.get() <= rel);
            if let Some(line) = i.checked_sub(1).and_then(|i| block.lines.get(i)) {
                return Some((block, line));
            }
        }
        None
    }

    /// Global references: offsets (into the global symbol stream) of the
    /// globals this module refers to.
    pub fn global_refs(&self) -> &[U32Le] {
        let start = self.symbols_len + self.c11_len + self.c13_len;
        let Some(rest) = self.data.get(start..) else {
            return &[];
        };
        let mut r = Reader::new(rest);
        let Ok(len) = r.u32_le() else { return &[] };
        r.read_slice((len / 4) as usize).unwrap_or(&[])
    }
}

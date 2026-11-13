//! C13 debug subsections (`DEBUG_S_*` in cvinfo.h): line numbers and file
//! checksums. A PDB's module streams hold them after the symbols; a COFF
//! object holds them in `.debug$S` after the `CV_SIGNATURE_C13` signature.

use hexcavator_core::{Reader, Result, U16Le, U32Le, pod};

/// Subsection kinds (`DEBUG_S_SUBSECTION_TYPE`).
pub mod subsection {
    /// A kind with this bit set is to be ignored (`DEBUG_S_IGNORE`).
    pub const DEBUG_S_IGNORE: u32 = 0x8000_0000;
    /// Symbol records.
    pub const DEBUG_S_SYMBOLS: u32 = 0xF1;
    /// Line numbers.
    pub const DEBUG_S_LINES: u32 = 0xF2;
    /// A string table.
    pub const DEBUG_S_STRINGTABLE: u32 = 0xF3;
    /// File checksums.
    pub const DEBUG_S_FILECHKSMS: u32 = 0xF4;
    /// Frame data.
    pub const DEBUG_S_FRAMEDATA: u32 = 0xF5;
    /// Inlinee lines.
    pub const DEBUG_S_INLINEELINES: u32 = 0xF6;
    /// Cross-scope imports.
    pub const DEBUG_S_CROSSSCOPEIMPORTS: u32 = 0xF7;
    /// Cross-scope exports.
    pub const DEBUG_S_CROSSSCOPEEXPORTS: u32 = 0xF8;
    /// IL line numbers.
    pub const DEBUG_S_IL_LINES: u32 = 0xF9;
    /// Function metadata tokens.
    pub const DEBUG_S_FUNC_MDTOKEN_MAP: u32 = 0xFA;
    /// Type metadata tokens.
    pub const DEBUG_S_TYPE_MDTOKEN_MAP: u32 = 0xFB;
    /// Merged assembly input.
    pub const DEBUG_S_MERGED_ASSEMBLYINPUT: u32 = 0xFC;
    /// COFF symbol RVAs.
    pub const DEBUG_S_COFF_SYMBOL_RVA: u32 = 0xFD;
}

/// A lines subsection's flag: each line has a column entry
/// (`CV_LINES_HAVE_COLUMNS`).
pub const CV_LINES_HAVE_COLUMNS: u16 = 0x0001;

/// `CV_Line_t`'s start line: its low 24 bits (`linenumStart`).
pub const CV_LINE_START_MASK: u32 = 0x00FF_FFFF;
/// `CV_Line_t`'s statement flag: its top bit (`fStatement`).
pub const CV_LINE_STATEMENT: u32 = 0x8000_0000;

pod! {
    /// A lines subsection's header (`CV_LineSection`).
    #[derive(Debug)]
    pub struct LinesHeader {
        pub offset: U32Le,
        pub segment: U16Le,
        pub flags: U16Le,
        pub code_size: U32Le,
    }

    /// A line (`CV_Line_t`).
    #[derive(Debug)]
    pub struct LineEntry {
        pub offset: U32Le,
        /// Bits 0-23: start line; 24-30: delta to end line; 31: is statement.
        pub flags: U32Le,
    }

    /// A line's columns (`CV_Column_t`).
    #[derive(Debug)]
    pub struct ColumnEntry {
        pub start: U16Le,
        pub end: U16Le,
    }
}

impl LineEntry {
    /// The start line.
    pub fn line(&self) -> u32 {
        self.flags.get() & CV_LINE_START_MASK
    }

    /// Whether the line is a statement (rather than an expression).
    pub fn is_statement(&self) -> bool {
        self.flags.get() & CV_LINE_STATEMENT != 0
    }
}

/// A block of lines for one source file within a lines subsection.
#[derive(Clone, Copy, Debug)]
pub struct LineBlock<'a> {
    pub segment: u16,
    /// The offset of the code the lines describe.
    pub offset: u32,
    pub code_size: u32,
    /// Offset of the file's entry in the file checksums subsection.
    pub file: u32,
    pub lines: &'a [LineEntry],
    pub columns: &'a [ColumnEntry],
}

/// A file checksum entry.
#[derive(Clone, Copy, Debug)]
pub struct FileChecksum<'a> {
    /// Offset of the file name in the string table (`/names` in a PDB).
    pub name: u32,
    pub kind: u8,
    pub checksum: &'a [u8],
}

/// The subsections in `data`: (kind, contents), each aligned to 4 bytes.
pub fn subsections(data: &[u8]) -> impl Iterator<Item = (u32, &[u8])> + '_ {
    let mut r = Reader::new(data);
    std::iter::from_fn(move || {
        let kind = r.u32_le().ok()?;
        let len = r.u32_le().ok()? as usize;
        let body = r.bytes(len).ok()?;
        r.align_to(4).ok()?;
        Some((kind, body))
    })
}

/// The line blocks of a `DEBUG_S_LINES` subsection's contents, appended to
/// `out`.
pub fn parse_lines<'a>(body: &'a [u8], out: &mut Vec<LineBlock<'a>>) -> Result<()> {
    let mut r = Reader::new(body);
    let h: &LinesHeader = r.read()?;
    let has_columns = h.flags.get() & CV_LINES_HAVE_COLUMNS != 0;
    while !r.is_empty() {
        let file = r.u32_le()?;
        let count = r.u32_le()? as usize;
        let _block_size = r.u32_le()?;
        let lines = r.read_slice(count)?;
        let columns = if has_columns {
            r.read_slice(count)?
        } else {
            &[]
        };
        out.push(LineBlock {
            segment: h.segment.get(),
            offset: h.offset.get(),
            code_size: h.code_size.get(),
            file,
            lines,
            columns,
        });
    }
    Ok(())
}

/// The entry at `offset` in a `DEBUG_S_FILECHKSMS` subsection's contents.
pub fn file_checksum(body: &[u8], offset: u32) -> Option<FileChecksum<'_>> {
    let mut r = Reader::new(body.get(offset as usize..)?);
    let name = r.u32_le().ok()?;
    let len = usize::from(r.u8().ok()?);
    let kind = r.u8().ok()?;
    Some(FileChecksum {
        name,
        kind,
        checksum: r.bytes(len).ok()?,
    })
}

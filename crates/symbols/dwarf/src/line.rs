//! Line-number programs (`.debug_line`, DWARF 2 to 5): the header's
//! directories and files, and the rows the program produces.

use alloc::string::String;
use alloc::vec::Vec;

use crate::consts::*;
use crate::{Reader, Sections};

/// A file of the program's file table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileEntry<'d> {
    pub name: &'d [u8],
    pub directory: u64,
}

/// One row of the line table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub address: u64,
    pub line: u64,
    pub column: u64,
    /// An index into [`LineProgram::files`].
    pub file: u64,
    pub is_stmt: bool,
    pub end_sequence: bool,
    /// The row's sequence was set to address 0: code the linker discarded.
    pub discarded: bool,
}

/// A line-number program: its header and the rows it produces.
#[derive(Clone, Debug)]
pub struct LineProgram<'d> {
    pub version: u16,
    pub directories: Vec<&'d [u8]>,
    /// The file table. In DWARF 2-4, entry 0 is a placeholder (files are
    /// numbered from 1); in DWARF 5 it is the primary source file.
    pub files: Vec<FileEntry<'d>>,
    pub rows: Vec<Row>,
}

/// Whether `p` is an absolute path, POSIX or Windows (`/`, `\`, `C:`).
fn is_absolute(p: &[u8]) -> bool {
    p.first().is_some_and(|&c| c == b'/' || c == b'\\') || p.get(1) == Some(&b':')
}

/// `dir` and `name` joined, by the separator `dir` uses.
fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        return String::from(name);
    }
    if name.is_empty() {
        return String::from(dir);
    }
    let windows =
        !dir.contains('/') && (dir.contains('\\') || dir.as_bytes().get(1) == Some(&b':'));
    let sep = if windows { '\\' } else { '/' };
    let mut out = String::from(dir);
    if !out.ends_with(['/', '\\']) {
        out.push(sep);
    }
    out.push_str(name);
    out
}

impl LineProgram<'_> {
    /// A file's path, as DWARF resolves it: its name in its directory, the
    /// directory in the compilation directory when it is relative (DWARF
    /// 5's directory 0; before 5, the unit's `comp_dir`).
    pub fn path(&self, index: u64, comp_dir: &[u8]) -> Option<String> {
        let f = self.files.get(usize::try_from(index).ok()?)?;
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        if is_absolute(f.name) {
            return Some(lossy(f.name));
        }
        let v5 = self.version >= 5;
        let dir: &[u8] = if !v5 && f.directory == 0 {
            comp_dir
        } else {
            self.directories
                .get(usize::try_from(f.directory).ok()?)
                .copied()
                .unwrap_or(b"")
        };
        let mut dir = lossy(dir);
        if !is_absolute(dir.as_bytes()) {
            let base: &[u8] = match (v5, f.directory) {
                (true, 0) => b"",
                (true, _) => self.directories.first().copied().unwrap_or(b""),
                (false, 0) => b"",
                (false, _) => comp_dir,
            };
            dir = join(&lossy(base), &dir);
        }
        Some(join(&dir, &lossy(f.name)))
    }
    /// A file's name as bloaty spells it: its directory, `/`, and its name
    /// (an absolute name alone).
    pub fn file_name(&self, index: u64) -> Option<String> {
        let f = self.files.get(usize::try_from(index).ok()?)?;
        let name = String::from_utf8_lossy(f.name);
        if name.starts_with('/') || name.as_bytes().get(1) == Some(&b':') {
            return Some(name.into_owned());
        }
        let dir = self
            .directories
            .get(usize::try_from(f.directory).ok()?)
            .copied()
            .unwrap_or(b"");
        let mut out = String::from_utf8_lossy(dir).into_owned();
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&name);
        Some(out)
    }
}

/// A header field of the form `form` (DWARF 5 entry formats).
fn header_value<'d>(
    r: &mut Reader<'d>,
    s: &Sections<'d>,
    form: u16,
    dwarf64: bool,
) -> Option<HeaderValue<'d>> {
    let w = if dwarf64 { 8 } else { 4 };
    Some(match form {
        DW_FORM_STRING => HeaderValue::Str(r.cstr()?),
        DW_FORM_LINE_STRP => {
            let o = r.uint(w)?;
            HeaderValue::Str(Reader::new(s.line_str, usize::try_from(o).ok()?, s.endian).cstr()?)
        }
        DW_FORM_STRP => {
            let o = r.uint(w)?;
            HeaderValue::Str(Reader::new(s.str, usize::try_from(o).ok()?, s.endian).cstr()?)
        }
        DW_FORM_UDATA => HeaderValue::Uint(r.uleb()?),
        DW_FORM_DATA1 => HeaderValue::Uint(r.uint(1)?),
        DW_FORM_DATA2 => HeaderValue::Uint(r.uint(2)?),
        DW_FORM_DATA4 => HeaderValue::Uint(r.uint(4)?),
        DW_FORM_DATA8 => HeaderValue::Uint(r.uint(8)?),
        DW_FORM_DATA16 => {
            r.bytes(16)?;
            HeaderValue::Other
        }
        DW_FORM_BLOCK => {
            let n = r.uleb()?;
            r.bytes(n)?;
            HeaderValue::Other
        }
        _ => return None,
    })
}

enum HeaderValue<'d> {
    Str(&'d [u8]),
    Uint(u64),
    Other,
}

const DW_LNCT_PATH: u64 = 1;
const DW_LNCT_DIRECTORY_INDEX: u64 = 2;

/// Reads the DWARF 5 directory or file table.
fn entry_table<'d>(
    r: &mut Reader<'d>,
    s: &Sections<'d>,
    dwarf64: bool,
) -> Option<Vec<FileEntry<'d>>> {
    let nformats = r.u8()?;
    let mut formats = Vec::new();
    for _ in 0..nformats {
        let kind = r.uleb()?;
        let form = u16::try_from(r.uleb()?).ok()?;
        formats.push((kind, form));
    }
    let count = r.uleb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let mut e = FileEntry {
            name: b"",
            directory: 0,
        };
        // (An entry that reads nothing, with no formats or only forms
        // without data, is malformed: a count alone can't make entries.)
        let at = r.pos;
        for &(kind, form) in &formats {
            match (kind, header_value(r, s, form, dwarf64)?) {
                (DW_LNCT_PATH, HeaderValue::Str(p)) => e.name = p,
                (DW_LNCT_DIRECTORY_INDEX, HeaderValue::Uint(d)) => e.directory = d,
                _ => {}
            }
        }
        if r.pos == at {
            return None;
        }
        out.push(e);
    }
    Some(out)
}

/// The line-number program at `offset` of `.debug_line`, for a unit of
/// `address_size`. `None` if its header is malformed; a malformed program
/// gives the rows before the damage.
pub fn line_program<'d>(
    s: &Sections<'d>,
    offset: u64,
    address_size: u8,
) -> Option<LineProgram<'d>> {
    let mut r = Reader::new(s.line, usize::try_from(offset).ok()?, s.endian);
    let (_, end, dwarf64) = r.initial_length()?;
    r.data = &s.line[..end];
    let version = u16::try_from(r.uint(2)?).ok()?;
    if !(2..=5).contains(&version) {
        return None;
    }
    let mut address_size = address_size;
    if version >= 5 {
        address_size = r.u8()?;
        r.u8()?; // segment selector size
    }
    let header_length = r.offset(dwarf64)?;
    let program = r.pos.checked_add(usize::try_from(header_length).ok()?)?;
    let min_inst = u64::from(r.u8()?);
    let max_ops = if version >= 4 { u64::from(r.u8()?) } else { 1 };
    let default_is_stmt = r.u8()? != 0;
    let line_base = i64::from(r.u8()? as i8);
    let line_range = u64::from(r.u8()?);
    let opcode_base = r.u8()?;
    if line_range == 0 || max_ops == 0 {
        return None;
    }
    let mut opcode_lengths = Vec::new();
    for _ in 1..opcode_base {
        opcode_lengths.push(r.u8()?);
    }
    let (directories, files) = if version >= 5 {
        let dirs = entry_table(&mut r, s, dwarf64)?
            .into_iter()
            .map(|e| e.name)
            .collect();
        (dirs, entry_table(&mut r, s, dwarf64)?)
    } else {
        // Directory 0 is the compilation directory, unnamed here.
        let mut dirs: Vec<&[u8]> = alloc::vec![b""];
        loop {
            let d = r.cstr()?;
            if d.is_empty() {
                break;
            }
            dirs.push(d);
        }
        let mut files = alloc::vec![FileEntry {
            name: b"",
            directory: 0
        }];
        loop {
            let name = r.cstr()?;
            if name.is_empty() {
                break;
            }
            let directory = r.uleb()?;
            r.uleb()?;
            r.uleb()?;
            files.push(FileEntry { name, directory });
        }
        (dirs, files)
    };
    let mut p = LineProgram {
        version,
        directories,
        files,
        rows: Vec::new(),
    };

    r.pos = program;
    let fresh = |address: u64| Row {
        address,
        line: 1,
        column: 0,
        file: 1,
        is_stmt: default_is_stmt,
        end_sequence: false,
        discarded: false,
    };
    let mut row = fresh(0);
    let mut op_index = 0u64;
    let advance = |row: &mut Row, op_index: &mut u64, n: u64| {
        let total = op_index.wrapping_add(n);
        row.address = row
            .address
            .wrapping_add(min_inst.wrapping_mul(total / max_ops));
        *op_index = total % max_ops;
    };
    while !r.is_empty() {
        let Some(op) = r.u8() else { break };
        if op >= opcode_base {
            let adjusted = u64::from(op - opcode_base);
            advance(&mut row, &mut op_index, adjusted / line_range);
            row.line = row
                .line
                .wrapping_add((line_base + (adjusted % line_range) as i64) as u64);
            p.rows.push(row);
            continue;
        }
        let ok = match op {
            0 => {
                let Some(len) = r.uleb() else { break };
                let start = r.pos;
                let Some(ext) = r.u8() else { break };
                match ext {
                    1 => {
                        row.end_sequence = true;
                        p.rows.push(row);
                        let discarded = row.discarded;
                        row = fresh(0);
                        row.discarded = discarded;
                        op_index = 0;
                    }
                    2 => {
                        let n = usize::try_from(len)
                            .ok()
                            .and_then(|l| l.checked_sub(1))
                            .unwrap_or(0);
                        let n = if n == 0 || n > 8 {
                            usize::from(address_size)
                        } else {
                            n
                        };
                        let Some(a) = r.uint(n) else { break };
                        row.address = a;
                        op_index = 0;
                        row.discarded = a == 0;
                    }
                    3 => {
                        let (Some(name), Some(directory)) = (r.cstr(), r.uleb()) else {
                            break;
                        };
                        if r.uleb().is_none() || r.uleb().is_none() {
                            break;
                        }
                        p.files.push(FileEntry { name, directory });
                    }
                    _ => {}
                }
                // Whatever the extended opcode read, it is `len` bytes long.
                match start.checked_add(usize::try_from(len).unwrap_or(usize::MAX)) {
                    Some(e) if e <= r.data.len() => {
                        r.pos = e;
                        true
                    }
                    _ => false,
                }
            }
            1 => {
                p.rows.push(row);
                true
            }
            2 => r
                .uleb()
                .map(|n| advance(&mut row, &mut op_index, n))
                .is_some(),
            3 => r
                .sleb()
                .map(|n| row.line = row.line.wrapping_add(n as u64))
                .is_some(),
            4 => r.uleb().map(|f| row.file = f).is_some(),
            5 => r.uleb().map(|c| row.column = c).is_some(),
            6 => {
                row.is_stmt = !row.is_stmt;
                true
            }
            7 | 10 | 11 => true,
            8 => {
                advance(
                    &mut row,
                    &mut op_index,
                    (255 - u64::from(opcode_base)) / line_range,
                );
                true
            }
            9 => r
                .uint(2)
                .map(|n| {
                    row.address = row.address.wrapping_add(n);
                    op_index = 0;
                })
                .is_some(),
            12 => r.uleb().is_some(),
            _ => {
                // An opcode this version doesn't define: skip its operands.
                let n = opcode_lengths
                    .get(usize::from(op) - 1)
                    .copied()
                    .unwrap_or(0);
                (0..n).all(|_| r.uleb().is_some())
            }
        };
        if !ok {
            break;
        }
    }
    Some(p)
}

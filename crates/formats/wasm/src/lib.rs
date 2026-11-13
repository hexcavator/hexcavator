//! WebAssembly modules (the binary format, version 1): sections, the
//! `name` custom section's function and data-segment names, imports,
//! function bodies (the code section's entries), and data segments, each
//! with where its bytes lie.
//!
//! Malformed modules give errors or fewer entries, never a panic.
//!
//! Decoding function bodies' instructions is `hexcavator-wasm-isa`'s job.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

mod linking;
pub use linking::{
    Import, LinkingSymbol, Relocation, SYMBOL_DATA, SYMBOL_EXPLICIT_NAME, SYMBOL_FUNCTION,
    SYMBOL_GLOBAL, SYMBOL_SECTION, SYMBOL_TABLE, SYMBOL_TAG, SYMBOL_UNDEFINED, SegmentInfo,
    relocation_has_addend, relocation_name,
};

use hexcavator_core::{Error, ErrorKind, Result};

/// The module's first four bytes.
pub const MAGIC: &[u8; 4] = b"\0asm";

/// A custom section.
pub const SECTION_CUSTOM: u8 = 0;
/// The type section.
pub const SECTION_TYPE: u8 = 1;
/// The import section.
pub const SECTION_IMPORT: u8 = 2;
/// The function section.
pub const SECTION_FUNCTION: u8 = 3;
/// The table section.
pub const SECTION_TABLE: u8 = 4;
/// The memory section.
pub const SECTION_MEMORY: u8 = 5;
/// The global section.
pub const SECTION_GLOBAL: u8 = 6;
/// The export section.
pub const SECTION_EXPORT: u8 = 7;
/// The start section.
pub const SECTION_START: u8 = 8;
/// The element section.
pub const SECTION_ELEMENT: u8 = 9;
/// The code section.
pub const SECTION_CODE: u8 = 10;
/// The data section.
pub const SECTION_DATA: u8 = 11;
/// The data count section.
pub const SECTION_DATA_COUNT: u8 = 12;
/// The tag section.
pub const SECTION_TAG: u8 = 13;

/// The name of a standard section (as bloaty spells them).
pub fn section_name(id: u8) -> Option<&'static str> {
    Some(match id {
        SECTION_TYPE => "Type",
        SECTION_IMPORT => "Import",
        SECTION_FUNCTION => "Function",
        SECTION_TABLE => "Table",
        SECTION_MEMORY => "Memory",
        SECTION_GLOBAL => "Global",
        SECTION_EXPORT => "Export",
        SECTION_START => "Start",
        SECTION_ELEMENT => "Element",
        SECTION_CODE => "Code",
        SECTION_DATA => "Data",
        SECTION_DATA_COUNT => "DataCount",
        SECTION_TAG => "Event",
        _ => return None,
    })
}

struct Reader<'d> {
    data: &'d [u8],
    pos: usize,
}

impl<'d> Reader<'d> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
            if shift >= 70 {
                return None;
            }
        }
    }

    fn u32(&mut self) -> Option<u32> {
        u32::try_from(self.uleb()?).ok()
    }

    fn bytes(&mut self, n: u64) -> Option<&'d [u8]> {
        let n = usize::try_from(n).ok()?;
        let b = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(b)
    }

    fn name(&mut self) -> Option<&'d [u8]> {
        let n = self.uleb()?;
        self.bytes(n)
    }
}

/// A section: its id, its name (a custom section's own, or the standard
/// name), and where its bytes lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'d> {
    /// Its id (`SECTION_*`).
    pub id: u8,
    /// Its name.
    pub name: &'d [u8],
    /// Where the section starts (its id byte) and its whole size, header
    /// included.
    pub offset: u64,
    /// Its whole size.
    pub size: u64,
    /// Where its contents start (after the id and size; for a custom
    /// section, before its name) and their size.
    pub contents_offset: u64,
    /// Their size.
    pub contents_size: u64,
    /// Where its data starts: its contents', or for a custom section, what
    /// follows its name.
    pub data_offset: u64,
}

/// A byte range of the module, with what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    /// Its index (function index for code, segment index for data).
    pub index: u32,
    /// Where it starts (a file offset).
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
}

/// A name from the `name` section, and where its entry lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name<'d> {
    /// What it names (an index).
    pub index: u32,
    /// The name.
    pub name: &'d [u8],
    /// Where its entry starts (a file offset).
    pub offset: u64,
    /// Its entry's size.
    pub size: u64,
}

/// An export: its name, kind (`EXTERNAL_*`), and index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Export<'d> {
    /// Its name.
    pub name: &'d [u8],
    /// What it exports: 0 a function, 1 a table, 2 a memory, 3 a global,
    /// 4 a tag.
    pub kind: u8,
    /// Its index in its kind's index space.
    pub index: u32,
}

/// Where a data segment goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentOffset {
    /// An active segment at an `i32.const` address.
    I32(i32),
    /// An active segment at an `i64.const` address (memory64).
    I64(i64),
    /// An active segment at a global's value (`global.get`).
    Global(u32),
    /// An active segment at another constant expression (extended-const).
    Other,
    /// A passive segment (`memory.init` copies it).
    Passive,
}

/// A data segment's offset and contents' size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSegment {
    /// Where it goes.
    pub offset: SegmentOffset,
    /// Its contents' size in bytes.
    pub size: u64,
}

/// Globals' names.
pub const NAME_GLOBAL: u8 = 7;

/// Which names of the `name` section.
pub const NAME_FUNCTION: u8 = 1;
/// Data segments' names.
pub const NAME_DATA_SEGMENT: u8 = 9;

/// A WebAssembly module.
#[derive(Clone, Debug)]
pub struct Module<'d> {
    data: &'d [u8],
    /// The binary format's version (1).
    pub version: u32,
    sections: Vec<Section<'d>>,
}

/// Whether `data` starts like a module.
pub fn is_wasm(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

impl<'d> Module<'d> {
    /// Parses the module's sections. A malformed section ends the list
    /// (the rest of the file is left out).
    pub fn parse(data: &'d [u8]) -> Result<Self> {
        if !is_wasm(data) {
            return Err(Error::new(ErrorKind::BadMagic, 0, "wasm magic"));
        }
        let v = data
            .get(4..8)
            .ok_or(Error::new(ErrorKind::Truncated, 4, "wasm version"))?;
        let version = u32::from_le_bytes(v.try_into().unwrap_or([0; 4]));
        let mut r = Reader { data, pos: 8 };
        let mut sections = Vec::new();
        while r.pos < data.len() {
            let start = r.pos;
            let Some(id) = r.u8() else { break };
            let Some(size) = r.uleb() else { break };
            let contents_offset = r.pos;
            let Some(contents) = r.bytes(size) else { break };
            let mut data_offset = contents_offset;
            let name: &[u8] = if id == SECTION_CUSTOM {
                let mut c = Reader {
                    data: contents,
                    pos: 0,
                };
                let Some(n) = c.name() else { break };
                data_offset += c.pos;
                n
            } else {
                match section_name(id) {
                    Some(n) => n.as_bytes(),
                    None => break,
                }
            };
            sections.push(Section {
                id,
                name,
                offset: start as u64,
                size: (r.pos - start) as u64,
                contents_offset: contents_offset as u64,
                contents_size: size,
                data_offset: data_offset as u64,
            });
        }
        Ok(Self {
            data,
            version,
            sections,
        })
    }

    /// The module's bytes.
    pub fn data(&self) -> &'d [u8] {
        self.data
    }

    /// Its sections, in order.
    pub fn sections(&self) -> &[Section<'d>] {
        &self.sections
    }

    fn contents(&self, s: &Section<'d>) -> Reader<'d> {
        // Sections come from positions in the data, so these fit.
        let start = usize::try_from(s.contents_offset).unwrap_or(self.data.len());
        let end = usize::try_from(s.contents_offset + s.contents_size).unwrap_or(self.data.len());
        Reader {
            data: &self.data[..end],
            pos: start,
        }
    }

    fn section(&self, id: u8) -> Option<&Section<'d>> {
        self.sections.iter().find(|s| s.id == id)
    }

    /// The custom section named `name`.
    pub fn custom(&self, name: &[u8]) -> Option<&Section<'d>> {
        self.sections
            .iter()
            .find(|s| s.id == SECTION_CUSTOM && s.name == name)
    }

    /// How many of each kind of thing are imported: functions, tables,
    /// memories, globals, tags (the `EXTERNAL_*` kinds, by index; they come
    /// first in their index spaces).
    pub fn imported(&self) -> [u32; 5] {
        let mut n = [0u32; 5];
        let Some(s) = self.section(SECTION_IMPORT) else {
            return n;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return n };
        for _ in 0..count {
            let (Some(_), Some(_), Some(kind)) = (r.name(), r.name(), r.u8()) else {
                break;
            };
            let ok = match kind {
                0 => r.u32().is_some(),
                1 => r.u8().is_some() && limits(&mut r),
                2 => limits(&mut r),
                3 => r.u8().is_some() && r.u8().is_some(),
                4 => r.u8().is_some() && r.u32().is_some(),
                _ => false,
            };
            if !ok {
                break;
            }
            n[usize::from(kind)] += 1;
        }
        n
    }

    /// The export section's entries: name, kind (`EXTERNAL_*`: 0 a
    /// function, 1 a table, 2 a memory, 3 a global, 4 a tag), and index.
    pub fn exports(&self) -> Vec<Export<'d>> {
        let mut out = Vec::new();
        let Some(s) = self.section(SECTION_EXPORT) else {
            return out;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return out };
        for _ in 0..count {
            let (Some(name), Some(kind), Some(index)) = (r.name(), r.u8(), r.u32()) else {
                break;
            };
            out.push(Export { name, kind, index });
        }
        out
    }

    /// The functions the element section puts in tables (or declares), by
    /// index: they can be called indirectly. Every encoding of a segment
    /// is read (function indices, or `ref.func` expressions).
    pub fn element_functions(&self) -> Vec<u32> {
        let mut out = Vec::new();
        let Some(s) = self.section(SECTION_ELEMENT) else {
            return out;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return out };
        for _ in 0..count {
            let Some(flags) = r.u32() else { break };
            if flags > 7 {
                break;
            }
            // Active segments with a table index (2, 6), or the default
            // table (0, 4), have an offset expression.
            if flags & 2 != 0 && flags & 1 == 0 && r.u32().is_none() {
                break;
            }
            if flags & 1 == 0 && !const_expr(&mut r) {
                break;
            }
            // An element kind (1, 2, 3) or reference type (5, 6, 7).
            if flags & 3 != 0 && r.u8().is_none() {
                break;
            }
            let Some(n) = r.u32() else { break };
            let mut ok = true;
            for _ in 0..n {
                if flags & 4 == 0 {
                    match r.u32() {
                        Some(f) => out.push(f),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                    continue;
                }
                // An expression: `ref.func f` is a function; others not.
                let start = r.pos;
                if r.u8() == Some(0xD2)
                    && let Some(f) = r.u32()
                {
                    out.push(f);
                }
                r.pos = start;
                if !const_expr(&mut r) {
                    ok = false;
                    break;
                }
            }
            if !ok {
                break;
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The start function's index, if the module has one.
    pub fn start_function(&self) -> Option<u32> {
        self.contents(self.section(SECTION_START)?).u32()
    }

    /// The data section's segments: each one's offset expression (for an
    /// active segment) and its contents' size.
    pub fn data_segment_details(&self) -> Vec<DataSegment> {
        let mut out = Vec::new();
        let Some(s) = self.section(SECTION_DATA) else {
            return out;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return out };
        for _ in 0..count {
            let Some(mode) = r.u32() else { break };
            let offset = match mode {
                0 => offset_expr(&mut r),
                1 => Some(SegmentOffset::Passive),
                2 => r.u32().and_then(|_| offset_expr(&mut r)),
                _ => None,
            };
            let Some(offset) = offset else { break };
            let Some(n) = r.uleb() else { break };
            if r.bytes(n).is_none() {
                break;
            }
            out.push(DataSegment { offset, size: n });
        }
        out
    }

    /// How many functions are imported (they come first in the function
    /// index space).
    pub fn imported_functions(&self) -> u32 {
        let Some(s) = self.section(SECTION_IMPORT) else {
            return 0;
        };
        let mut r = self.contents(s);
        let mut n = 0;
        let Some(count) = r.u32() else { return 0 };
        for _ in 0..count {
            let (Some(_), Some(_), Some(kind)) = (r.name(), r.name(), r.u8()) else {
                break;
            };
            let ok = match kind {
                0 => {
                    n += 1;
                    r.u32().is_some()
                }
                // A table: element type, then limits.
                1 => r.u8().is_some() && limits(&mut r),
                2 => limits(&mut r),
                // A global: value type and mutability.
                3 => r.u8().is_some() && r.u8().is_some(),
                // A tag: attribute and type index.
                4 => r.u8().is_some() && r.u32().is_some(),
                _ => false,
            };
            if !ok {
                break;
            }
        }
        n
    }

    /// The code section's entries (function bodies, size field included),
    /// indexed by function index (imports come first).
    pub fn functions(&self) -> Vec<Piece> {
        let mut out = Vec::new();
        let Some(s) = self.section(SECTION_CODE) else {
            return out;
        };
        let base = self.imported_functions();
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return out };
        for i in 0..count {
            let start = r.pos;
            let Some(size) = r.uleb() else { break };
            if r.bytes(size).is_none() {
                break;
            }
            out.push(Piece {
                index: base.saturating_add(i),
                offset: start as u64,
                size: (r.pos - start) as u64,
            });
        }
        out
    }

    /// A code section entry's body (after its size field), and where it
    /// starts in the module.
    pub fn body(&self, function: &Piece) -> Option<(u64, &'d [u8])> {
        let start = usize::try_from(function.offset).ok()?;
        let end = start.checked_add(usize::try_from(function.size).ok()?)?;
        let mut r = Reader {
            data: self.data.get(..end)?,
            pos: start,
        };
        let size = r.uleb()?;
        let at = r.pos;
        Some((at as u64, r.bytes(size)?))
    }

    /// The data section's segments (header and bytes).
    pub fn data_segments(&self) -> Vec<Piece> {
        let mut out = Vec::new();
        let Some(s) = self.section(SECTION_DATA) else {
            return out;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return out };
        for index in 0..count {
            let start = r.pos;
            let Some(mode) = r.u32() else { break };
            let ok = match mode {
                0 => const_expr(&mut r),
                1 => true,
                2 => r.u32().is_some() && const_expr(&mut r),
                _ => false,
            };
            if !ok {
                break;
            }
            let Some(n) = r.uleb() else { break };
            if r.bytes(n).is_none() {
                break;
            }
            out.push(Piece {
                index,
                offset: start as u64,
                size: (r.pos - start) as u64,
            });
        }
        out
    }

    /// The names of subsection `kind` of the `name` section
    /// ([`NAME_FUNCTION`], [`NAME_DATA_SEGMENT`]).
    pub fn names(&self, kind: u8) -> Vec<Name<'d>> {
        let mut out = Vec::new();
        let Some(s) = self.custom(b"name") else {
            return out;
        };
        let mut r = self.contents(s);
        if r.name().is_none() {
            return out;
        }
        while r.pos < r.data.len() {
            let (Some(k), Some(size)) = (r.u8(), r.uleb()) else {
                break;
            };
            let start = r.pos;
            let Some(sub) = r.bytes(size) else { break };
            if k != kind {
                continue;
            }
            let mut sr = Reader {
                data: &r.data[..start + sub.len()],
                pos: start,
            };
            let Some(count) = sr.u32() else { break };
            for _ in 0..count {
                let at = sr.pos;
                let (Some(index), Some(name)) = (sr.u32(), sr.name()) else {
                    break;
                };
                out.push(Name {
                    index,
                    name,
                    offset: at as u64,
                    size: (sr.pos - at) as u64,
                });
            }
        }
        out
    }

    /// The `sourceMappingURL` custom section's URL.
    pub fn source_mapping_url(&self) -> Option<&'d [u8]> {
        let s = self.custom(b"sourceMappingURL")?;
        let mut r = self.contents(s);
        r.name()?;
        r.name()
    }

    /// The `build_id` custom section's ID (the tool conventions' build ID,
    /// as ELF's `NT_GNU_BUILD_ID`).
    pub fn build_id(&self) -> Option<&'d [u8]> {
        let s = self.custom(b"build_id")?;
        let mut r = self.contents(s);
        r.name()?;
        r.name()
    }

    /// The `external_debug_info` custom section's path: where this
    /// module's DWARF is, when it isn't in the module.
    pub fn external_debug_info(&self) -> Option<&'d [u8]> {
        let s = self.custom(b"external_debug_info")?;
        let mut r = self.contents(s);
        r.name()?;
        r.name()
    }

    /// Whether this is a relocatable object (it has a `linking` section).
    pub fn is_object(&self) -> bool {
        self.custom(b"linking").is_some()
    }

    /// Whether its memory (defined or imported) is a 64-bit one
    /// (memory64).
    pub fn is_memory64(&self) -> bool {
        const MEMORY64: u8 = 0x04;
        if let Some(s) = self.section(SECTION_MEMORY) {
            let mut r = self.contents(s);
            if r.u32().is_some_and(|n| n > 0) {
                return r.u8().is_some_and(|f| f & MEMORY64 != 0);
            }
        }
        let Some(s) = self.section(SECTION_IMPORT) else {
            return false;
        };
        let mut r = self.contents(s);
        let Some(count) = r.u32() else { return false };
        for _ in 0..count {
            let (Some(_), Some(_), Some(kind)) = (r.name(), r.name(), r.u8()) else {
                return false;
            };
            let ok = match kind {
                0 => r.u32().is_some(),
                1 => r.u8().is_some() && limits(&mut r),
                2 => return r.u8().is_some_and(|f| f & MEMORY64 != 0),
                3 => r.u8().is_some() && r.u8().is_some(),
                4 => r.u8().is_some() && r.u32().is_some(),
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        false
    }
}

/// Skips resizable limits.
fn limits(r: &mut Reader<'_>) -> bool {
    let Some(flags) = r.u8() else { return false };
    if r.uleb().is_none() {
        return false;
    }
    if flags & 1 != 0 && r.uleb().is_none() {
        return false;
    }
    true
}

/// Skips a constant expression (up to and including its `end`).
/// An active segment's offset expression, if it is one constant or one
/// global (else [`SegmentOffset::Other`]).
fn offset_expr(r: &mut Reader<'_>) -> Option<SegmentOffset> {
    let start = r.pos;
    let first = r.u8()?;
    let value = match first {
        0x41 | 0x42 => Some(sleb(r)?),
        0x23 => Some(i64::from(r.u32()?)),
        _ => None,
    };
    let simple = value.is_some() && r.data.get(r.pos) == Some(&0x0B);
    if simple {
        r.pos += 1;
        let v = value.unwrap_or(0);
        return Some(match first {
            0x41 => SegmentOffset::I32(i32::try_from(v).ok()?),
            0x42 => SegmentOffset::I64(v),
            _ => SegmentOffset::Global(u32::try_from(v).ok()?),
        });
    }
    r.pos = start;
    const_expr(r).then_some(SegmentOffset::Other)
}

/// A signed LEB128 (at most ten bytes).
fn sleb(r: &mut Reader<'_>) -> Option<i64> {
    let mut v: i64 = 0;
    let mut shift = 0;
    loop {
        let b = r.u8()?;
        if shift < 64 {
            v |= i64::from(b & 0x7F) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                v |= -1i64 << shift;
            }
            return Some(v);
        }
        if shift >= 70 {
            return None;
        }
    }
}

fn const_expr(r: &mut Reader<'_>) -> bool {
    loop {
        let Some(op) = r.u8() else { return false };
        let ok = match op {
            0x0B => return true,
            // global.get, i32.const, i64.const, ref.func
            0x23 | 0x41 | 0x42 | 0xD2 => r.uleb().is_some(),
            0x43 => r.bytes(4).is_some(),
            0x44 => r.bytes(8).is_some(),
            // ref.null t
            0xD0 => r.u8().is_some(),
            // extended-const arithmetic
            0x6A | 0x6B | 0x6C | 0x7C | 0x7D | 0x7E => true,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
}

#[cfg(test)]
mod tests;

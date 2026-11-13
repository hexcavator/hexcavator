//! 16-bit "NE" (New Executable) files: Windows 1.0 to 3.x programs,
//! libraries, drivers, and fonts (`.fon`), and OS/2 1.x programs.
//!
//! After the MZ header (see `hexcavator-mz`), the NE header gives the
//! module's segments (each with its relocations), resources, entry points
//! (by ordinal), the names exported by name (resident and nonresident),
//! and the modules it imports from. Everything is read from the file as
//! it is: nothing is loaded or run.
//!
//! Damaged tables end early rather than fail; a table's entries are no
//! more than its bytes allow, so reading is linear in the file's size.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_mz::{MzFile, NewHeaderKind};

/// `ne_flags`: the module is a library (DLL or driver).
pub const NE_FFLAGS_LIBMODULE: u16 = 0x8000;
/// `ne_flags`: errors in the image (the linker said so).
pub const NE_FFLAGS_IMAGE_ERROR: u16 = 0x2000;
/// `ne_flags`: one shared automatic data segment (`SINGLEDATA`).
pub const NE_FFLAGS_SINGLEDATA: u16 = 0x0001;
/// `ne_flags`: an automatic data segment per instance (`MULTIPLEDATA`).
pub const NE_FFLAGS_MULTIPLEDATA: u16 = 0x0002;

/// A segment's flags: a data segment (else code).
pub const NE_SEGFLAGS_DATA: u16 = 0x0001;
/// A segment's flags: it moves in memory (else fixed).
pub const NE_SEGFLAGS_MOVEABLE: u16 = 0x0010;
/// A segment's flags: it is preloaded (else loaded on demand).
pub const NE_SEGFLAGS_PRELOAD: u16 = 0x0040;
/// A segment's flags: relocations follow its data.
pub const NE_SEGFLAGS_RELOCINFO: u16 = 0x0100;
/// A segment's flags: it may be discarded.
pub const NE_SEGFLAGS_DISCARDABLE: u16 = 0x1000;

/// `ne_exetyp`: the target operating system.
pub const NE_OS_UNKNOWN: u8 = 0;
/// `ne_exetyp`: OS/2.
pub const NE_OS_OS2: u8 = 1;
/// `ne_exetyp`: Windows.
pub const NE_OS_WINDOWS: u8 = 2;
/// `ne_exetyp`: European MS-DOS 4.x.
pub const NE_OS_DOS4: u8 = 3;
/// `ne_exetyp`: Windows/386.
pub const NE_OS_WIN386: u8 = 4;
/// `ne_exetyp`: the Borland Operating System Services.
pub const NE_OS_BOSS: u8 = 5;

/// Resource types, as integers (the type ID without its high bit).
pub const RT_CURSOR: u16 = 1;
/// A bitmap.
pub const RT_BITMAP: u16 = 2;
/// An icon.
pub const RT_ICON: u16 = 3;
/// A menu.
pub const RT_MENU: u16 = 4;
/// A dialog box.
pub const RT_DIALOG: u16 = 5;
/// A string table block.
pub const RT_STRING: u16 = 6;
/// A font directory.
pub const RT_FONTDIR: u16 = 7;
/// A font.
pub const RT_FONT: u16 = 8;
/// An accelerator table.
pub const RT_ACCELERATOR: u16 = 9;
/// Application-defined data.
pub const RT_RCDATA: u16 = 10;
/// A group of cursors.
pub const RT_GROUP_CURSOR: u16 = 12;
/// A group of icons.
pub const RT_GROUP_ICON: u16 = 14;
/// Version information.
pub const RT_VERSION: u16 = 16;

/// The NE header's fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The linker's version and revision.
    pub linker: (u8, u8),
    /// The entry table's offset (from the NE header) and size.
    pub entry_table: (u16, u16),
    /// The file's CRC (rarely set).
    pub crc: u32,
    /// `NE_FFLAGS_*`.
    pub flags: u16,
    /// The automatic data segment's number (1-based; 0: none).
    pub auto_data: u16,
    /// The local heap's and the stack's initial sizes.
    pub heap: u16,
    /// The stack's initial size.
    pub stack: u16,
    /// The entry point: segment number (1-based) and offset.
    pub cs_ip: (u16, u16),
    /// The initial stack: segment number and offset.
    pub ss_sp: (u16, u16),
    /// How many segments.
    pub segments: u16,
    /// How many module references.
    pub modules: u16,
    /// The nonresident names table's size.
    pub nonresident_size: u16,
    /// The segment table's offset (from the NE header).
    pub segment_table: u16,
    /// The resource table's offset (from the NE header).
    pub resource_table: u16,
    /// The resident names table's offset (from the NE header).
    pub resident_names: u16,
    /// The module reference table's offset (from the NE header).
    pub module_table: u16,
    /// The imported names table's offset (from the NE header).
    pub imported_names: u16,
    /// The nonresident names table's file offset.
    pub nonresident_names: u32,
    /// How many entries are moveable.
    pub moveable_entries: u16,
    /// Segments' data offsets are in units of 2^this bytes.
    pub alignment_shift: u16,
    /// How many resource segments (OS/2).
    pub resource_segments: u16,
    /// `NE_OS_*`.
    pub target_os: u8,
    /// Other flags (Windows: 0x02 2.x protected mode, 0x04 proportional
    /// fonts, 0x08 the fast-load area).
    pub other_flags: u8,
    /// The fast-load (gangload) area: its offset and length, in units of
    /// the alignment.
    pub gangload: (u16, u16),
    /// The minimum code swap area size.
    pub swap_area: u16,
    /// The Windows version expected (major, minor).
    pub windows_version: (u8, u8),
}

/// A segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Its number (1-based).
    pub number: u16,
    /// Its data's file offset (0: it has none: an uninitialized segment).
    pub offset: u64,
    /// Its data's size in the file.
    pub size: u32,
    /// `NE_SEGFLAGS_*`.
    pub flags: u16,
    /// Its size in memory, at least.
    pub min_alloc: u32,
}

impl Segment {
    /// Whether it is a data segment.
    pub fn is_data(&self) -> bool {
        self.flags & NE_SEGFLAGS_DATA != 0
    }
}

/// What a relocation's address refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// An address in this module: in a fixed segment (number, offset), or
    /// (segment 0xFF) a moveable segment's entry point (by ordinal: then
    /// `offset` is the ordinal).
    Internal {
        /// The segment's number, or 0xFF.
        segment: u8,
        /// The offset (or the entry's ordinal).
        offset: u16,
    },
    /// An imported function, by its module (1-based, in the module
    /// reference table) and ordinal.
    ImportOrdinal {
        /// The module's index (1-based).
        module: u16,
        /// The ordinal.
        ordinal: u16,
    },
    /// An imported function, by its module and name (an offset in the
    /// imported names table).
    ImportName {
        /// The module's index (1-based).
        module: u16,
        /// The name's offset in the imported names table.
        name: u16,
    },
    /// A floating-point fixup the operating system resolves (`OSFIXUP`).
    OsFixup(u16),
}

/// A relocation in a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// What is patched: 0 a low byte, 2 a selector, 3 a far pointer, 5 an
    /// offset, 11 a 48-bit pointer, 13 a 32-bit offset.
    pub source: u8,
    /// Whether the target is added to what is there (else the offsets
    /// form a chain through the segment, ending at 0xFFFF).
    pub additive: bool,
    /// The (first) patched offset in the segment.
    pub offset: u16,
    /// What it refers to.
    pub target: Target,
}

/// A name or an integer, as resources are named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Id {
    /// An integer ID.
    Int(u16),
    /// A name.
    Name(String),
}

/// A resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    /// Its type (`RT_*`, or a name).
    pub kind: Id,
    /// Its ID.
    pub id: Id,
    /// Its data's file offset and size.
    pub offset: u64,
    /// Its data's size.
    pub size: u64,
    /// Its flags (0x10 moveable, 0x20 pure, 0x40 preloaded).
    pub flags: u16,
}

/// An entry point (an export, by ordinal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its ordinal.
    pub ordinal: u16,
    /// Its segment's number (0xFE: a constant, `offset` its value).
    pub segment: u8,
    /// Its offset in the segment.
    pub offset: u16,
    /// Its flags (1 exported, 2 uses the shared data segment).
    pub flags: u8,
    /// Whether its segment is moveable (it is reached through a thunk).
    pub moveable: bool,
}

/// A name and its ordinal (the resident and nonresident names tables).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    /// The name.
    pub name: String,
    /// The entry's ordinal (0 for the first, the module's name or
    /// description).
    pub ordinal: u16,
}

/// An NE file.
#[derive(Clone, Copy, Debug)]
pub struct NeFile<'data> {
    data: &'data [u8],
    /// The NE header's file offset.
    base: u64,
    header: Header,
}

/// A little-endian reader of `data`, from `pos`.
struct Reader<'d> {
    data: &'d [u8],
    pos: usize,
}

impl<'d> Reader<'d> {
    fn at(data: &'d [u8], pos: u64) -> Self {
        Reader {
            data,
            pos: usize::try_from(pos).unwrap_or(usize::MAX),
        }
    }

    fn bytes(&mut self, n: usize) -> Option<&'d [u8]> {
        let b = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(b)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed string (`None` at the 0 length that ends a table).
    fn pascal(&mut self) -> Option<&'d [u8]> {
        let n = self.u8()?;
        if n == 0 {
            return None;
        }
        self.bytes(usize::from(n))
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl<'data> NeFile<'data> {
    /// Parses the NE file `data` (from its MZ header).
    ///
    /// # Errors
    ///
    /// If it isn't one (no MZ header, or its new header isn't NE), or its
    /// NE header is cut short.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let mz = MzFile::parse(data)?;
        let base = match mz.new_header() {
            Some(h) if h.kind == NewHeaderKind::Ne => h.offset,
            _ => return Err(Error::new(ErrorKind::BadMagic, 0, "NE")),
        };
        let truncated = || Error::new(ErrorKind::Truncated, base, "NE header");
        let mut r = Reader::at(data, base + 2);
        let mut h = Header::default();
        (|| {
            h.linker = (r.u8()?, r.u8()?);
            h.entry_table = (r.u16()?, r.u16()?);
            h.crc = r.u32()?;
            h.flags = r.u16()?;
            h.auto_data = r.u16()?;
            h.heap = r.u16()?;
            h.stack = r.u16()?;
            let (ip, cs) = (r.u16()?, r.u16()?);
            h.cs_ip = (cs, ip);
            let (sp, ss) = (r.u16()?, r.u16()?);
            h.ss_sp = (ss, sp);
            h.segments = r.u16()?;
            h.modules = r.u16()?;
            h.nonresident_size = r.u16()?;
            h.segment_table = r.u16()?;
            h.resource_table = r.u16()?;
            h.resident_names = r.u16()?;
            h.module_table = r.u16()?;
            h.imported_names = r.u16()?;
            h.nonresident_names = r.u32()?;
            h.moveable_entries = r.u16()?;
            h.alignment_shift = r.u16()?;
            h.resource_segments = r.u16()?;
            h.target_os = r.u8()?;
            h.other_flags = r.u8()?;
            h.gangload = (r.u16()?, r.u16()?);
            h.swap_area = r.u16()?;
            let (minor, major) = (r.u8()?, r.u8()?);
            h.windows_version = (major, minor);
            Some(())
        })()
        .ok_or_else(truncated)?;
        Ok(NeFile {
            data,
            base,
            header: h,
        })
    }

    /// The file's bytes.
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// The NE header's file offset.
    pub fn header_offset(&self) -> u64 {
        self.base
    }

    /// The NE header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Whether the module is a library (a DLL, driver, or font).
    pub fn is_library(&self) -> bool {
        self.header.flags & NE_FFLAGS_LIBMODULE != 0
    }

    /// A reader at `offset` from the NE header.
    fn table(&self, offset: u16) -> Reader<'data> {
        Reader::at(self.data, self.base + u64::from(offset))
    }

    /// The segments, in order.
    pub fn segments(&self) -> Vec<Segment> {
        let mut out = Vec::new();
        let mut r = self.table(self.header.segment_table);
        // (A shift past 16 would put data beyond any 16-bit file's reach.)
        let shift = u32::from(self.header.alignment_shift.min(16));
        let shift = if self.header.alignment_shift == 0 {
            9
        } else {
            shift
        };
        for number in 1..=self.header.segments {
            let (Some(sector), Some(size), Some(flags), Some(min)) =
                (r.u16(), r.u16(), r.u16(), r.u16())
            else {
                break;
            };
            let size = if size == 0 && sector != 0 {
                0x10000
            } else {
                u32::from(size)
            };
            out.push(Segment {
                number,
                offset: u64::from(sector) << shift,
                size,
                flags,
                min_alloc: if min == 0 { 0x10000 } else { u32::from(min) },
            });
        }
        out
    }

    /// The data of segment `s`, as far as the file has it.
    pub fn segment_data(&self, s: &Segment) -> &'data [u8] {
        if s.offset == 0 {
            return &[];
        }
        let Ok(at) = usize::try_from(s.offset) else {
            return &[];
        };
        let end = at.saturating_add(s.size as usize).min(self.data.len());
        self.data.get(at..end).unwrap_or(&[])
    }

    /// The relocations of segment `s` (none unless it has
    /// `NE_SEGFLAGS_RELOCINFO`).
    pub fn relocations(&self, s: &Segment) -> Vec<Relocation> {
        let mut out = Vec::new();
        if s.flags & NE_SEGFLAGS_RELOCINFO == 0 || s.offset == 0 {
            return out;
        }
        let mut r = Reader::at(self.data, s.offset + u64::from(s.size));
        let Some(count) = r.u16() else { return out };
        for _ in 0..count {
            let Some(b) = r.bytes(8) else { break };
            let w = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
            let target = match b[1] & 3 {
                0 => Target::Internal {
                    segment: b[4],
                    offset: w(6),
                },
                1 => Target::ImportOrdinal {
                    module: w(4),
                    ordinal: w(6),
                },
                2 => Target::ImportName {
                    module: w(4),
                    name: w(6),
                },
                _ => Target::OsFixup(w(4)),
            };
            out.push(Relocation {
                source: b[0],
                additive: b[1] & 4 != 0,
                offset: w(2),
                target,
            });
        }
        out
    }

    /// The resources, in the table's order.
    pub fn resources(&self) -> Vec<Resource> {
        let mut out = Vec::new();
        // (No resource table: its offset is the resident names'.)
        if self.header.resource_table == self.header.resident_names {
            return out;
        }
        let start = self.base + u64::from(self.header.resource_table);
        let mut r = Reader::at(self.data, start);
        let Some(shift) = r.u16() else { return out };
        let shift = u32::from(shift.min(24));
        let id = |v: u16| -> Id {
            if v & 0x8000 != 0 {
                Id::Int(v & 0x7FFF)
            } else {
                let mut n = Reader::at(self.data, start + u64::from(v));
                Id::Name(n.pascal().map(text).unwrap_or_default())
            }
        };
        while let Some(kind) = r.u16().filter(|&k| k != 0) {
            let (Some(count), Some(_)) = (r.u16(), r.u32()) else {
                break;
            };
            let kind = id(kind);
            for _ in 0..count {
                let Some(b) = r.bytes(12) else {
                    return out;
                };
                let w = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
                out.push(Resource {
                    kind: kind.clone(),
                    id: id(w(6)),
                    offset: u64::from(w(0)) << shift,
                    size: u64::from(w(2)) << shift,
                    flags: w(4),
                });
            }
        }
        out
    }

    /// The data of resource `res`, as far as the file has it.
    pub fn resource_data(&self, res: &Resource) -> &'data [u8] {
        let (Ok(at), Ok(size)) = (usize::try_from(res.offset), usize::try_from(res.size)) else {
            return &[];
        };
        let end = at.saturating_add(size).min(self.data.len());
        self.data.get(at..end).unwrap_or(&[])
    }

    fn names(mut r: Reader<'data>) -> Vec<Name> {
        let mut out = Vec::new();
        while let Some(name) = r.pascal() {
            let Some(ordinal) = r.u16() else { break };
            out.push(Name {
                name: text(name),
                ordinal,
            });
        }
        out
    }

    /// The resident names: first the module's name, then names exported
    /// by name, kept in memory.
    pub fn resident_names(&self) -> Vec<Name> {
        Self::names(self.table(self.header.resident_names))
    }

    /// The nonresident names: first the module's description, then names
    /// exported by name, read from the file when needed.
    pub fn nonresident_names(&self) -> Vec<Name> {
        if self.header.nonresident_names == 0 {
            return Vec::new();
        }
        let at = u64::from(self.header.nonresident_names);
        let end = (at + u64::from(self.header.nonresident_size)).min(self.data.len() as u64);
        let Some(table) = usize::try_from(end).ok().and_then(|e| self.data.get(..e)) else {
            return Vec::new();
        };
        Self::names(Reader::at(table, at))
    }

    /// The module's name (its first resident name).
    pub fn module_name(&self) -> Option<String> {
        self.resident_names().into_iter().next().map(|n| n.name)
    }

    /// The module's description (its first nonresident name).
    pub fn description(&self) -> Option<String> {
        self.nonresident_names().into_iter().next().map(|n| n.name)
    }

    /// The name at `offset` of the imported names table.
    pub fn imported_name(&self, offset: u16) -> Option<String> {
        let mut r = self.table(self.header.imported_names);
        r.pos = r.pos.checked_add(usize::from(offset))?;
        r.pascal().map(text)
    }

    /// The modules it imports from, in the module reference table's order
    /// (relocations' module indices are 1-based in this).
    pub fn modules(&self) -> Vec<String> {
        let mut r = self.table(self.header.module_table);
        let mut out = Vec::new();
        for _ in 0..self.header.modules {
            let Some(offset) = r.u16() else { break };
            out.push(self.imported_name(offset).unwrap_or_default());
        }
        out
    }

    /// The entry points, by ordinal (unused ordinals left out).
    pub fn entries(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        let (offset, size) = self.header.entry_table;
        let start = self.base + u64::from(offset);
        let end = (start + u64::from(size)).min(self.data.len() as u64);
        let Some(table) = usize::try_from(end).ok().and_then(|e| self.data.get(..e)) else {
            return out;
        };
        let mut r = Reader::at(table, start);
        let mut ordinal: u16 = 1;
        while let Some(count) = r.u8() {
            if count == 0 {
                break;
            }
            let Some(kind) = r.u8() else { break };
            for _ in 0..count {
                let entry = match kind {
                    0 => None,
                    0xFF => {
                        let Some(b) = r.bytes(6) else { return out };
                        Some(Entry {
                            ordinal,
                            segment: b[3],
                            offset: u16::from_le_bytes([b[4], b[5]]),
                            flags: b[0],
                            moveable: true,
                        })
                    }
                    segment => {
                        let Some(b) = r.bytes(3) else { return out };
                        Some(Entry {
                            ordinal,
                            segment,
                            offset: u16::from_le_bytes([b[1], b[2]]),
                            flags: b[0],
                            moveable: false,
                        })
                    }
                };
                out.extend(entry);
                let Some(next) = ordinal.checked_add(1) else {
                    return out;
                };
                ordinal = next;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;

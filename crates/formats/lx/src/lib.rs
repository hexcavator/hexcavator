//! "Linear Executable" files: LE (Windows 3.x/9x virtual device drivers,
//! VxDs; 386 DOS extenders) and LX (32-bit OS/2, and some DOS extenders).
//!
//! After the MZ header (see `hexcavator-mz`), the LE/LX header gives the
//! module's objects (its segments: flat, page-granular), the page map
//! (where each page's data is in the file), resources, entry points (by
//! ordinal), names exported by name (resident and nonresident), the
//! modules and procedures it imports, and each page's fixups. The two
//! differ in the page map: LE's entries are page numbers; LX's are offsets
//! and sizes, and may be iterated (compressed) or zero-filled.
//!
//! Only little-endian files are read (no big-endian LX was ever shipped).
//! Damaged tables end early rather than fail; a table's entries are no
//! more than its bytes allow.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_mz::{MzFile, NewHeaderKind};

/// An object's flags: readable.
pub const OBJ_READ: u32 = 0x0001;
/// An object's flags: writable.
pub const OBJ_WRITE: u32 = 0x0002;
/// An object's flags: executable.
pub const OBJ_EXEC: u32 = 0x0004;
/// An object's flags: a resource object.
pub const OBJ_RESOURCE: u32 = 0x0008;
/// An object's flags: discardable.
pub const OBJ_DISCARD: u32 = 0x0010;
/// An object's flags: shared.
pub const OBJ_SHARED: u32 = 0x0020;
/// An object's flags: preloaded.
pub const OBJ_PRELOAD: u32 = 0x0040;
/// An object's flags: invalid pages.
pub const OBJ_INVALID: u32 = 0x0080;
/// An object's flags: zero-filled.
pub const OBJ_ZEROFILL: u32 = 0x0100;
/// An object's flags: 16:16 alias required.
pub const OBJ_ALIAS16: u32 = 0x1000;
/// An object's flags: 32-bit (big/default) code or data.
pub const OBJ_BIG: u32 = 0x2000;
/// An object's flags: conforming code.
pub const OBJ_CONFORMING: u32 = 0x4000;
/// An object's flags: I/O privilege (OS/2).
pub const OBJ_IOPL: u32 = 0x8000;

/// The module's flags: a library (DLL).
pub const MOD_LIBRARY: u32 = 0x8000;
/// The module's flags: a physical device driver.
pub const MOD_PDD: u32 = 0x0002_0000;
/// The module's flags: a virtual device driver.
pub const MOD_VDD: u32 = 0x0002_8000;
/// The module's flags' module type bits.
pub const MOD_TYPE_MASK: u32 = 0x0003_8000;

/// The header's fields (offsets from the LE/LX header unless said).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// LX (else LE).
    pub lx: bool,
    /// The byte and word order (0: little-endian).
    pub byte_order: u8,
    /// The word order.
    pub word_order: u8,
    /// The format's level (0).
    pub format_level: u32,
    /// 1 80286, 2 80386, 3 80486, ...
    pub cpu: u16,
    /// 1 OS/2, 2 Windows, 3 DOS 4.x, 4 Windows 386.
    pub os: u16,
    /// The module's version.
    pub version: u32,
    /// `MOD_*`, and others.
    pub flags: u32,
    /// How many pages.
    pub pages: u32,
    /// The entry point: object (1-based) and offset.
    pub eip: (u32, u32),
    /// The initial stack: object (1-based) and offset.
    pub esp: (u32, u32),
    /// The page size.
    pub page_size: u32,
    /// LE: the last page's size; LX: pages' offsets are in units of
    /// 2^this.
    pub page_shift_or_last: u32,
    /// The fixup section's size and checksum.
    pub fixup_size: u32,
    /// The loader section's size.
    pub loader_size: u32,
    /// The object table's offset, and how many objects.
    pub object_table: (u32, u32),
    /// The page map's offset.
    pub page_map: u32,
    /// The iterated pages' offset (LE: from the file's start).
    pub iterated_pages: u32,
    /// The resource table's offset, and how many resources.
    pub resource_table: (u32, u32),
    /// The resident names table's offset.
    pub resident_names: u32,
    /// The entry table's offset.
    pub entry_table: u32,
    /// The module directives table's offset, and how many directives.
    pub directives: (u32, u32),
    /// The fixup page table's offset.
    pub fixup_pages: u32,
    /// The fixup record table's offset.
    pub fixup_records: u32,
    /// The imported modules table's offset, and how many modules.
    pub import_modules: (u32, u32),
    /// The imported procedures table's offset.
    pub import_procs: u32,
    /// The per-page checksums' offset.
    pub page_checksums: u32,
    /// The data pages' file offset.
    pub data_pages: u32,
    /// How many pages are preloaded.
    pub preload_pages: u32,
    /// The nonresident names table's file offset and size.
    pub nonresident_names: (u32, u32),
    /// The automatic data object (1-based; 0: none).
    pub auto_data: u32,
    /// The debug information's file offset and size.
    pub debug_info: (u32, u32),
    /// The heap's size.
    pub heap: u32,
    /// The stack's size (LX).
    pub stack: u32,
    /// A VxD's (LE, winnt.h's `IMAGE_VXD_HEADER`): its Windows resources'
    /// file offset and size.
    pub vxd_resources: (u32, u32),
    /// A VxD's device ID (0: none).
    pub device_id: u16,
    /// A VxD's DDK version.
    pub ddk_version: u16,
}

/// An object (a segment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    /// Its number (1-based).
    pub number: u32,
    /// Its size in memory.
    pub size: u32,
    /// The address it was linked at.
    pub base: u32,
    /// `OBJ_*`.
    pub flags: u32,
    /// Its first page's index in the page map (1-based), and how many.
    pub first_page: u32,
    /// How many pages it has.
    pub page_count: u32,
}

/// How a page's data is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageKind {
    /// As it is.
    Legal,
    /// Iterated (LX's run-length compression, `EXEPACK`).
    Iterated,
    /// Invalid (no data).
    Invalid,
    /// Zero-filled (no data).
    Zeroed,
    /// A range of pages (LX).
    Range,
    /// Compressed (LX's `EXEPACK2`).
    Compressed,
    /// Something else (its type).
    Other(u16),
}

/// A page: where its data is in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    /// Its file offset.
    pub offset: u64,
    /// Its data's size in the file.
    pub size: u32,
    /// How it is stored.
    pub kind: PageKind,
}

/// A resource (OS/2's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    /// Its type.
    pub kind: u16,
    /// Its ID.
    pub id: u16,
    /// Its size.
    pub size: u32,
    /// The object it is in (1-based), and its offset there.
    pub object: u16,
    /// Its offset in the object.
    pub offset: u32,
}

/// A name and its ordinal (the resident and nonresident names tables).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name {
    /// The name.
    pub name: String,
    /// The entry's ordinal (0 for the first: the module's name, or its
    /// description).
    pub ordinal: u16,
}

/// What an entry point is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A 16-bit entry: object and 16-bit offset.
    Offset16 {
        /// The object (1-based).
        object: u16,
        /// Its offset.
        offset: u16,
    },
    /// A 286 call gate: object, offset, and the gate's selector.
    CallGate {
        /// The object (1-based).
        object: u16,
        /// Its offset.
        offset: u16,
        /// The call gate's selector (set by the loader).
        selector: u16,
    },
    /// A 32-bit entry: object and offset.
    Offset32 {
        /// The object (1-based).
        object: u16,
        /// Its offset.
        offset: u32,
    },
    /// A forwarder (LX): another module's entry, by ordinal or by name.
    Forwarder {
        /// The module (1-based, in the import modules table).
        module: u16,
        /// By ordinal (else `value` is a name's offset in the imported
        /// procedures table).
        by_ordinal: bool,
        /// The ordinal or name offset.
        value: u32,
    },
}

/// An entry point (an export, by ordinal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its ordinal.
    pub ordinal: u16,
    /// Its flags (1 exported, 2 shared data; for 16-bit, parameter words
    /// in the high five bits).
    pub flags: u8,
    /// What it is.
    pub kind: EntryKind,
}

/// What a fixup's address refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixupTarget {
    /// An address in this module: object (1-based) and offset.
    Internal {
        /// The object (1-based).
        object: u16,
        /// Its offset (none for a selector fixup).
        offset: Option<u32>,
    },
    /// An imported procedure, by module (1-based) and ordinal.
    ImportOrdinal {
        /// The module (1-based).
        module: u16,
        /// The ordinal.
        ordinal: u32,
    },
    /// An imported procedure, by module and name (an offset in the
    /// imported procedures table).
    ImportName {
        /// The module (1-based).
        module: u16,
        /// The name's offset.
        name: u32,
    },
    /// An entry of this module, by ordinal.
    Entry(u16),
}

/// A fixup: one or more places in a page patched with a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixup {
    /// What is patched (the low four bits): 0 a byte, 2 a selector, 3 a
    /// 16:16 pointer, 5 a 16-bit offset, 6 a 16:32 pointer, 7 a 32-bit
    /// offset, 8 a 32-bit self-relative offset.
    pub source: u8,
    /// Where in the page (several, for a source list; negative: the
    /// fixup crosses in from the page before).
    pub offsets: Vec<i16>,
    /// What it refers to.
    pub target: FixupTarget,
    /// Added to the target, if additive.
    pub additive: Option<u32>,
}

/// An LE or LX file.
#[derive(Clone, Copy, Debug)]
pub struct LxFile<'data> {
    data: &'data [u8],
    /// The LE/LX header's file offset.
    base: u64,
    header: Header,
}

/// A little-endian reader of `data`, from `pos`.
#[derive(Clone, Copy)]
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

impl<'data> LxFile<'data> {
    /// Parses the LE or LX file `data` (from its MZ header).
    ///
    /// # Errors
    ///
    /// If it isn't one (no MZ header, or its new header isn't LE or LX),
    /// it is big-endian, or its header is cut short.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let mz = MzFile::parse(data)?;
        let (base, lx) = match mz.new_header() {
            Some(h) if h.kind == NewHeaderKind::Le => (h.offset, false),
            Some(h) if h.kind == NewHeaderKind::Lx => (h.offset, true),
            _ => return Err(Error::new(ErrorKind::BadMagic, 0, "LE or LX")),
        };
        let mut r = Reader::at(data, base + 2);
        let mut h = Header {
            lx,
            ..Header::default()
        };
        (|| {
            h.byte_order = r.u8()?;
            h.word_order = r.u8()?;
            h.format_level = r.u32()?;
            h.cpu = r.u16()?;
            h.os = r.u16()?;
            h.version = r.u32()?;
            h.flags = r.u32()?;
            h.pages = r.u32()?;
            h.eip = (r.u32()?, r.u32()?);
            h.esp = (r.u32()?, r.u32()?);
            h.page_size = r.u32()?;
            h.page_shift_or_last = r.u32()?;
            h.fixup_size = r.u32()?;
            r.u32()?;
            h.loader_size = r.u32()?;
            r.u32()?;
            h.object_table = (r.u32()?, r.u32()?);
            h.page_map = r.u32()?;
            h.iterated_pages = r.u32()?;
            h.resource_table = (r.u32()?, r.u32()?);
            h.resident_names = r.u32()?;
            h.entry_table = r.u32()?;
            h.directives = (r.u32()?, r.u32()?);
            h.fixup_pages = r.u32()?;
            h.fixup_records = r.u32()?;
            h.import_modules = (r.u32()?, r.u32()?);
            h.import_procs = r.u32()?;
            h.page_checksums = r.u32()?;
            h.data_pages = r.u32()?;
            h.preload_pages = r.u32()?;
            h.nonresident_names = (r.u32()?, r.u32()?);
            r.u32()?;
            h.auto_data = r.u32()?;
            h.debug_info = (r.u32()?, r.u32()?);
            r.u32()?;
            r.u32()?;
            h.heap = r.u32()?;
            Some(())
        })()
        .ok_or_else(|| Error::new(ErrorKind::Truncated, base, "LE/LX header"))?;
        // (Optional: LX's stack size; a VxD's resources and device ID.)
        h.stack = if lx { r.u32().unwrap_or(0) } else { 0 };
        if !lx {
            let mut d = Reader::at(data, base + 0xB8);
            if let (Some(at), Some(len), Some(id), Some(ddk)) = (d.u32(), d.u32(), d.u16(), d.u16())
            {
                h.vxd_resources = (at, len);
                h.device_id = id;
                h.ddk_version = ddk;
            }
        }
        if h.byte_order != 0 || h.word_order != 0 {
            return Err(Error::new(ErrorKind::Unsupported, base, "big-endian LE/LX"));
        }
        Ok(LxFile {
            data,
            base,
            header: h,
        })
    }

    /// The file's bytes.
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// The LE/LX header's file offset.
    pub fn header_offset(&self) -> u64 {
        self.base
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Whether this is a virtual device driver (an LE VxD, or an LX
    /// module marked as one).
    pub fn is_vxd(&self) -> bool {
        self.header.flags & MOD_TYPE_MASK == MOD_VDD || (!self.header.lx && self.header.os == 4)
    }

    fn table(&self, offset: u32) -> Reader<'data> {
        Reader::at(self.data, self.base + u64::from(offset))
    }

    /// The objects, in order.
    pub fn objects(&self) -> Vec<Object> {
        let mut out = Vec::new();
        let (offset, count) = self.header.object_table;
        let mut r = self.table(offset);
        for number in 1..=count {
            let Some(b) = r.bytes(24) else { break };
            let w = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
            out.push(Object {
                number,
                size: w(0),
                base: w(4),
                flags: w(8),
                first_page: w(12),
                page_count: w(16),
            });
        }
        out
    }

    /// The page map: every page, in order (`pages(o)` gives an object's).
    pub fn pages(&self) -> Vec<Page> {
        let mut out = Vec::new();
        let h = &self.header;
        let mut r = self.table(h.page_map);
        let data = u64::from(h.data_pages);
        for i in 0..h.pages {
            let page = if h.lx {
                let (Some(offset), Some(size), Some(flags)) = (r.u32(), r.u16(), r.u16()) else {
                    break;
                };
                let shift = h.page_shift_or_last.min(31);
                let base = if flags == 1 {
                    u64::from(h.iterated_pages)
                } else {
                    data
                };
                Page {
                    offset: base + (u64::from(offset) << shift),
                    size: u32::from(size),
                    kind: match flags {
                        0 => PageKind::Legal,
                        1 => PageKind::Iterated,
                        2 => PageKind::Invalid,
                        3 => PageKind::Zeroed,
                        4 => PageKind::Range,
                        5 => PageKind::Compressed,
                        f => PageKind::Other(f),
                    },
                }
            } else {
                // A page number (big-endian, 1-based, in 24 bits), and its
                // type.
                let Some(b) = r.bytes(4) else { break };
                let number = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
                let last = i + 1 == h.pages;
                Page {
                    offset: data + u64::from(number.saturating_sub(1)) * u64::from(h.page_size),
                    size: if last {
                        h.page_shift_or_last
                    } else {
                        h.page_size
                    },
                    kind: match b[3] {
                        0 => PageKind::Legal,
                        1 => PageKind::Iterated,
                        2 => PageKind::Invalid,
                        3 => PageKind::Zeroed,
                        f => PageKind::Other(u16::from(f)),
                    },
                }
            };
            out.push(page);
        }
        out
    }

    /// The data of page `p`, as far as the file has it (none for a page
    /// without data).
    pub fn page_data(&self, p: &Page) -> &'data [u8] {
        if matches!(p.kind, PageKind::Invalid | PageKind::Zeroed) {
            return &[];
        }
        let Ok(at) = usize::try_from(p.offset) else {
            return &[];
        };
        let end = at.saturating_add(p.size as usize).min(self.data.len());
        self.data.get(at..end).unwrap_or(&[])
    }

    /// The resources.
    pub fn resources(&self) -> Vec<Resource> {
        let mut out = Vec::new();
        let (offset, count) = self.header.resource_table;
        let mut r = self.table(offset);
        for _ in 0..count {
            let (Some(kind), Some(id), Some(size), Some(object), Some(offset)) =
                (r.u16(), r.u16(), r.u32(), r.u16(), r.u32())
            else {
                break;
            };
            out.push(Resource {
                kind,
                id,
                size,
                object,
                offset,
            });
        }
        out
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
    /// by name.
    pub fn resident_names(&self) -> Vec<Name> {
        if self.header.resident_names == 0 {
            return Vec::new();
        }
        Self::names(self.table(self.header.resident_names))
    }

    /// The nonresident names: first the module's description, then names
    /// exported by name.
    pub fn nonresident_names(&self) -> Vec<Name> {
        let (at, size) = self.header.nonresident_names;
        if at == 0 {
            return Vec::new();
        }
        let end = (u64::from(at) + u64::from(size)).min(self.data.len() as u64);
        let Some(table) = usize::try_from(end).ok().and_then(|e| self.data.get(..e)) else {
            return Vec::new();
        };
        Self::names(Reader::at(table, u64::from(at)))
    }

    /// The module's name (its first resident name).
    pub fn module_name(&self) -> Option<String> {
        self.resident_names().into_iter().next().map(|n| n.name)
    }

    /// The module's description (its first nonresident name).
    pub fn description(&self) -> Option<String> {
        self.nonresident_names().into_iter().next().map(|n| n.name)
    }

    /// The modules it imports from, in order (fixups' module numbers are
    /// 1-based in this).
    pub fn import_modules(&self) -> Vec<String> {
        let (offset, count) = self.header.import_modules;
        let mut r = self.table(offset);
        let mut out = Vec::new();
        for _ in 0..count {
            let Some(name) = r.pascal() else { break };
            out.push(text(name));
        }
        out
    }

    /// The imported procedure name at `offset` of its table.
    pub fn import_name(&self, offset: u32) -> Option<String> {
        let mut r = self.table(self.header.import_procs);
        r.pos = r.pos.checked_add(usize::try_from(offset).ok()?)?;
        r.pascal().map(text)
    }

    /// The entry points, by ordinal (unused ordinals left out).
    pub fn entries(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        if self.header.entry_table == 0 {
            return out;
        }
        let mut r = self.table(self.header.entry_table);
        let mut ordinal: u16 = 1;
        while let Some(count) = r.u8() {
            if count == 0 {
                break;
            }
            let Some(kind) = r.u8() else { break };
            // (Bit 7: the bundle has parameter type information.)
            let kind = kind & 0x7F;
            let object = if kind == 0 {
                0
            } else {
                let Some(o) = r.u16() else { break };
                o
            };
            for _ in 0..count {
                let entry = match kind {
                    0 => None,
                    1 => {
                        let (Some(flags), Some(offset)) = (r.u8(), r.u16()) else {
                            return out;
                        };
                        Some((flags, EntryKind::Offset16 { object, offset }))
                    }
                    2 => {
                        let (Some(flags), Some(offset), Some(selector)) =
                            (r.u8(), r.u16(), r.u16())
                        else {
                            return out;
                        };
                        Some((
                            flags,
                            EntryKind::CallGate {
                                object,
                                offset,
                                selector,
                            },
                        ))
                    }
                    3 => {
                        let (Some(flags), Some(offset)) = (r.u8(), r.u32()) else {
                            return out;
                        };
                        Some((flags, EntryKind::Offset32 { object, offset }))
                    }
                    4 => {
                        let (Some(flags), Some(module), Some(value)) = (r.u8(), r.u16(), r.u32())
                        else {
                            return out;
                        };
                        // (A forwarder bundle's "object" field is reserved;
                        // the module is in each entry.)
                        let _ = object;
                        Some((
                            flags,
                            EntryKind::Forwarder {
                                module,
                                by_ordinal: flags & 1 != 0,
                                value,
                            },
                        ))
                    }
                    _ => return out,
                };
                if let Some((flags, kind)) = entry {
                    out.push(Entry {
                        ordinal,
                        flags,
                        kind,
                    });
                }
                let Some(next) = ordinal.checked_add(1) else {
                    return out;
                };
                ordinal = next;
            }
        }
        out
    }

    /// The fixups of page `page` (0-based, of the page map), in order.
    pub fn fixups(&self, page: u32) -> Vec<Fixup> {
        let mut out = Vec::new();
        let h = &self.header;
        if h.fixup_pages == 0 || page >= h.pages {
            return out;
        }
        let mut t = self.table(h.fixup_pages);
        t.pos = t
            .pos
            .saturating_add(usize::try_from(page).unwrap_or(usize::MAX) * 4);
        let (Some(start), Some(end)) = (t.u32(), t.u32()) else {
            return out;
        };
        let records = self.base + u64::from(h.fixup_records);
        let end = (records + u64::from(end)).min(self.data.len() as u64);
        let Some(table) = usize::try_from(end).ok().and_then(|e| self.data.get(..e)) else {
            return out;
        };
        let mut r = Reader::at(table, records + u64::from(start));
        while r.pos < table.len() {
            let Some(f) = Self::fixup(&mut r) else { break };
            out.push(f);
        }
        out
    }

    fn fixup(r: &mut Reader<'_>) -> Option<Fixup> {
        let source = r.u8()?;
        let flags = r.u8()?;
        let list = source & 0x20 != 0;
        let mut offsets = Vec::new();
        let count = if list {
            r.u8()?
        } else {
            offsets.push(i16::from_le_bytes(r.bytes(2)?.try_into().ok()?));
            0
        };
        let wide_object = flags & 0x40 != 0;
        let object = |r: &mut Reader<'_>| -> Option<u16> {
            if wide_object {
                r.u16()
            } else {
                r.u8().map(u16::from)
            }
        };
        let offset32 = flags & 0x10 != 0;
        let target = match flags & 3 {
            0 => {
                let object = object(r)?;
                // (A selector fixup has no offset.)
                let offset = if source & 0x0F == 2 {
                    None
                } else if offset32 {
                    Some(r.u32()?)
                } else {
                    Some(u32::from(r.u16()?))
                };
                FixupTarget::Internal { object, offset }
            }
            1 => {
                let module = object(r)?;
                let ordinal = if flags & 0x80 != 0 {
                    u32::from(r.u8()?)
                } else if offset32 {
                    r.u32()?
                } else {
                    u32::from(r.u16()?)
                };
                FixupTarget::ImportOrdinal { module, ordinal }
            }
            2 => {
                let module = object(r)?;
                let name = if offset32 {
                    r.u32()?
                } else {
                    u32::from(r.u16()?)
                };
                FixupTarget::ImportName { module, name }
            }
            _ => FixupTarget::Entry(object(r)?),
        };
        let additive = if flags & 4 != 0 {
            Some(if flags & 0x20 != 0 {
                r.u32()?
            } else {
                u32::from(r.u16()?)
            })
        } else {
            None
        };
        for _ in 0..count {
            offsets.push(i16::from_le_bytes(r.bytes(2)?.try_into().ok()?));
        }
        Some(Fixup {
            source: source & 0x0F,
            offsets,
            target,
            additive,
        })
    }
}

#[cfg(test)]
mod tests;

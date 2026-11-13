//! The DWARF backend: debug information in an ELF, Mach-O, or WebAssembly
//! file (the image itself, a separate debug file, or a dSYM's), versions 2
//! to 5.
//!
//! The file is indexed once (its units and their bases, abbreviation
//! tables, type units' signatures); DIEs are read by offset as they are
//! needed. Type references ([`TypeRef`]) are DIE offsets: of
//! `.debug_info`, or of `.debug_types` with the top bit set, and of the
//! file's own sections or (bits 40 to 62: its index, from 1) a split
//! file's; an absent type is `void` ([`VOID`]).
//!
//! Split DWARF (`-gsplit-dwarf`: DWARF 5's, and GNU's extension of DWARF
//! 4) leaves skeleton units in the file and the rest in `.dwo` files, or a
//! `.dwp` package of them: [`DwarfInfo::split_files`] names them, and
//! [`DwarfInfo::add_split`] adds each one found. A split unit is then read
//! as its skeleton's compiland, with the skeleton's addresses.
//!
//! Damaged data gives fewer results, never a panic; trees, names, and
//! chains of references are bounded (see the `MAX_*` constants).

mod debugmap;
mod layouts;
mod types;
mod vars;

use std::borrow::Cow;
use std::cell::{Cell, OnceCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hexcavator_core::{Arch, Endian, Error, ErrorKind, Result};
use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Abbrevs, Attr, Die, Sections, Unit, UnitSection, Value, line_program};
use hexcavator_image::{DebugId, Image, Kind};

pub use debugmap::AddrMap;

use crate::{
    Compiland, Contribution, EnclosingFunction, InlineSite, InlineSites, LineSpan, SourceLines,
    Symbol, SymbolKind, TypeRef,
};

/// The type of something with no `DW_AT_type`: `void`.
pub const VOID: TypeRef = TypeRef(u64::MAX);
/// Set in a [`TypeRef`] of a `.debug_types` DIE.
const TYPES: u64 = 1 << 63;
/// Where a [`TypeRef`]'s file index starts: offsets are below this.
const FILE_SHIFT: u32 = 40;
const MAX_OFFSET: u64 = 1 << FILE_SHIFT;
/// How many split files there are at most (one fewer than fit, so that
/// no reference is [`VOID`]).
const MAX_FILES: usize = (1 << (63 - FILE_SHIFT)) - 2;
/// How deep a DIE tree is followed.
const MAX_DEPTH: i64 = 256;
/// How many scopes a qualified name has at most, and how long it is.
const MAX_SCOPES: usize = 64;
const MAX_NAME: usize = 4096;
/// How many references (specifications, abstract origins, typedefs,
/// qualifiers) are followed in a chain.
const MAX_CHAIN: usize = 64;

/// A unit, as indexed: where it is, and its bases.
#[derive(Clone, Copy, Debug)]
struct UnitMeta {
    /// The file it is in: 0 for this one, from 1 for split files.
    file: u32,
    section: UnitSection,
    offset: u64,
    end: u64,
    /// Its abbreviations' offset (of the whole `.dwp` section, in a
    /// package).
    abbrev_offset: u64,
    /// Whether it is a split unit.
    split: bool,
    addr_base: u64,
    str_offsets_base: u64,
    rnglists_base: u64,
    loclists_base: u64,
    low_pc: u64,
    /// Its compiland's index, for compile (and partial and skeleton) units,
    /// and a split unit's skeleton's.
    compiland: Option<u32>,
}

#[derive(Debug, Default)]
struct Index {
    /// By file, section, then offset.
    units: Vec<UnitMeta>,
    /// The order units are walked in: the file's, each split unit after
    /// its skeleton, then split files' other units (type units).
    order: Vec<usize>,
    /// By file and offset.
    abbrevs: HashMap<(u32, u64), Abbrevs>,
    /// Type units' signatures, and their types.
    signatures: HashMap<u64, TypeRef>,
}

/// DWARF debug information.
pub struct DwarfInfo<'data> {
    data: &'data [u8],
    endian: Endian,
    arch: Arch,
    /// Whether the file is linked: addresses of 0 (and the tombstone) are
    /// then discarded code.
    linked: bool,
    /// The file's own identities (build ID, UUID).
    ids: Vec<DebugId<'data>>,
    sections: Vec<(&'data [u8], Cow<'data, [u8]>)>,
    index: OnceCell<Index>,
    /// For qualified names: each DIE's enclosing scope, for DIEs in
    /// namespaces, classes, and the like.
    parents: OnceCell<HashMap<u64, u64>>,
    functions: OnceCell<HashMap<u64, Vec<TypeRef>>>,
    /// The split files added (file 1 is the first).
    splits: Vec<Split<'data>>,
    /// How many more ranges [`DwarfInfo::ranges`] may give (see
    /// [`RANGES_PER_BYTE`]).
    ranges_left: Cell<u64>,
}

/// The most ranges DIEs may have, all told: this many per byte of debug
/// information. Many DIEs naming one long range list would otherwise each
/// have all of its ranges (a list of 100,000, named by 100,000 DIEs, is
/// 10^10); past it, a DIE has just its first range.
const RANGES_PER_BYTE: u64 = 4;

/// The ranges budget for a file of `len` bytes with these sections (some
/// perhaps decompressed).
fn ranges_budget(len: usize, sections: &[(&[u8], Cow<'_, [u8]>)]) -> u64 {
    let bytes = sections
        .iter()
        .fold(len as u64, |n, (_, d)| n.saturating_add(d.len() as u64));
    bytes
        .saturating_mul(RANGES_PER_BYTE)
        .saturating_add(1 << 20)
}

/// A split file: a `.dwo`'s sections (names without their `.dwo`), or a
/// `.dwp`'s and its units' contributions to them.
struct Split<'data> {
    sections: Vec<(&'data [u8], Cow<'data, [u8]>)>,
    /// A package's units, by section and start (`None` for a `.dwo`).
    rows: Option<Vec<Row>>,
    /// For an object file of a debug map (not split DWARF: whole units of
    /// their own), where its addresses are in the image.
    map: Option<AddrMap>,
    /// The library (archive) an object file is from, if any.
    library: String,
}

/// A package's unit: its extent in `.debug_info` (or `.debug_types`), and
/// where its contributions to the other sections start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Row {
    types: bool,
    start: u64,
    end: u64,
    abbrev: u64,
    /// Of `.debug_loc.dwo` (DWARF 4) or `.debug_loclists.dwo` (5).
    loc: u64,
    str_offsets: u64,
    rnglists: u64,
}

/// What a split unit takes from its skeleton.
#[derive(Clone, Copy, Debug)]
struct Skeleton {
    addr_base: u64,
    low_pc: u64,
    /// GNU's `DW_AT_GNU_ranges_base`, of the split unit's range lists.
    ranges_base: u64,
    compiland: u32,
}

/// A split file a skeleton unit names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitFile {
    /// Its name (`DW_AT_dwo_name`, or GNU's `DW_AT_GNU_dwo_name`), as the
    /// compiler wrote it: relative to `comp_dir`, often.
    pub name: String,
    /// The compilation directory (`DW_AT_comp_dir`).
    pub comp_dir: String,
    /// The ID the split unit must have.
    pub dwo_id: u64,
}

/// Where to look for the `.dwp` package of the debug information at
/// `debug_path` (of the image at `image_path`), in order, as GDB and LLDB
/// look: the debug file's name with `.dwp` added (or in place of a
/// `.debug`), then the image's.
pub fn package_paths(image_path: &Path, debug_path: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let with = |p: &Path, ext: &str| {
        let mut s = p.as_os_str().to_owned();
        s.push(ext);
        PathBuf::from(s)
    };
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    push(with(debug_path, ".dwp"));
    if debug_path.extension().is_some_and(|e| e == "debug") {
        push(debug_path.with_extension("dwp"));
    }
    push(with(image_path, ".dwp"));
    out
}

/// Where to look for the split file `f`, which the debug information at
/// `debug_path` (of the image at `image_path`) names, in order: its path
/// (absolute, or relative to an absolute compilation directory), then by
/// the debug file's directory and the image's, relative to a relative
/// compilation directory and not.
///
/// Only a name ending in `.dwo` is followed, and never to a UNC or device
/// path (`\\server\share`, `//server`): the names are the file's to
/// choose, and the file may be hostile.
pub fn split_paths(image_path: &Path, debug_path: &Path, f: &SplitFile) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let remote = |s: &str| {
        let s = s.as_bytes();
        s.len() >= 2 && matches!(s[0], b'/' | b'\\') && matches!(s[1], b'/' | b'\\')
    };
    let dwo = f
        .name
        .len()
        .checked_sub(4)
        .and_then(|i| f.name.get(i..))
        .is_some_and(|e| e.eq_ignore_ascii_case(".dwo"));
    if !dwo || f.name.contains('\0') || f.comp_dir.contains('\0') || remote(&f.name) {
        return out;
    }
    let comp_dir = if remote(&f.comp_dir) {
        ""
    } else {
        f.comp_dir.as_str()
    };
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    let name = Path::new(&f.name);
    let absolute = |p: &Path| p.has_root() || p.is_absolute();
    if absolute(name) {
        push(name.to_path_buf());
    } else if absolute(Path::new(comp_dir)) {
        push(Path::new(comp_dir).join(name));
    }
    // (The recorded name may use either separator, whatever the host's.)
    let base = f.name.rsplit(['/', '\\']).next().unwrap_or_default();
    for dir in [debug_path.parent(), image_path.parent()] {
        let dir = dir.unwrap_or(Path::new(""));
        if !absolute(name) {
            if !comp_dir.is_empty() && !absolute(Path::new(comp_dir)) {
                push(dir.join(comp_dir).join(name));
            }
            push(dir.join(name));
        }
        if !base.is_empty() {
            push(dir.join(base));
        }
    }
    out
}

/// The units a `.dwp`'s `.debug_cu_index` or `.debug_tu_index` lists
/// (versions 2, GNU's, and 5), or `None` if it is damaged.
fn package_rows(d: &[u8], endian: Endian) -> Option<Vec<Row>> {
    use hexcavator_dwarf::Reader;
    let version = if Reader::new(d, 0, endian).uint(2)? == 5 {
        5
    } else if Reader::new(d, 0, endian).uint(4)? == 2 {
        2
    } else {
        return None;
    };
    let mut r = Reader::new(d, 4, endian);
    let columns = usize::try_from(r.uint(4)?).ok()?;
    let units = usize::try_from(r.uint(4)?).ok()?;
    let slots = usize::try_from(r.uint(4)?).ok()?;
    // The signatures and their row numbers, which aren't needed: rows are
    // read in order.
    r.bytes(u64::try_from(slots.checked_mul(12)?).ok()?)?;
    if columns > 16 {
        return None;
    }
    let ids = (0..columns)
        .map(|_| r.uint(4))
        .collect::<Option<Vec<u64>>>()?;
    let table = units.checked_mul(columns)?.checked_mul(4)?;
    let offsets = r.bytes(u64::try_from(table).ok()?)?;
    let sizes = r.bytes(u64::try_from(table).ok()?)?;
    let mut rows = Vec::with_capacity(units.min(d.len()));
    for unit in 0..units {
        let mut row = Row::default();
        let mut has_unit = false;
        for (c, &id) in ids.iter().enumerate() {
            let at = (unit * columns + c) * 4;
            let off = Reader::new(offsets, at, endian).uint(4)?;
            let size = Reader::new(sizes, at, endian).uint(4)?;
            match (version, id) {
                (_, 1) | (2, 2) => {
                    row.types = id == 2;
                    row.start = off;
                    row.end = off + size;
                    has_unit = true;
                }
                (_, 3) => row.abbrev = off,
                (_, 5) => row.loc = off,
                (_, 6) => row.str_offsets = off,
                (5, 8) => row.rnglists = off,
                _ => {}
            }
        }
        if has_unit {
            rows.push(row);
        }
    }
    Some(rows)
}

/// The debug sections of `image`: names without their prefixes, contents
/// decompressed.
fn debug_sections<'d>(image: &Image<'d>) -> Vec<(&'d [u8], Cow<'d, [u8]>)> {
    if let Some(elf) = image.elf() {
        return crate::decompress::elf_dwarf_sections(elf, None)
            .into_iter()
            .map(|(n, d, _)| (n, d))
            .collect();
    }
    let data = image.data();
    let mut out = Vec::new();
    for s in image.sections() {
        let Some((name, gnu)) = crate::decompress::debug_name(s.name, b"__debug_", b"__zdebug_")
            .or_else(|| crate::decompress::debug_name(s.name, b".debug_", b".zdebug_"))
        else {
            continue;
        };
        let (Ok(at), Ok(len)) = (usize::try_from(s.file_offset), usize::try_from(s.file_size))
        else {
            continue;
        };
        let Some(bytes) = data.get(at..at.saturating_add(len)) else {
            continue;
        };
        if gnu {
            if let Some(d) = crate::decompress::gnu_zdebug(bytes) {
                out.push((name, Cow::Owned(d)));
            }
        } else {
            out.push((name, Cow::Borrowed(bytes)));
        }
    }
    out
}

impl<'data> DwarfInfo<'data> {
    /// Reads the DWARF of the ELF, Mach-O, or WebAssembly file `data`.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let image = Image::parse(data)?;
        let sections = debug_sections(&image);
        if !sections.iter().any(|(n, _)| *n == b"info") {
            return Err(Error::new(ErrorKind::BadMagic, 0, "DWARF (no .debug_info)"));
        }
        let ids = image
            .debug_ids()
            .into_iter()
            .filter(|id| matches!(id, DebugId::BuildId(_) | DebugId::Uuid(_)))
            .collect();
        Ok(Self {
            data,
            endian: image.endian(),
            arch: image.arch(),
            linked: !matches!(image.kind(), Kind::Object),
            ids,
            ranges_left: Cell::new(ranges_budget(data.len(), &sections)),
            sections,
            index: OnceCell::new(),
            parents: OnceCell::new(),
            functions: OnceCell::new(),
            splits: Vec::new(),
        })
    }

    /// The split files this file's skeleton units name, in order.
    pub fn split_files(&self) -> Vec<SplitFile> {
        let s = self.sections();
        let mut out: Vec<SplitFile> = Vec::new();
        let mut attrs = Vec::new();
        for mut u in Unit::iter(s, UnitSection::Info, 0) {
            let Some(abbrevs) = Abbrevs::parse(s.abbrev, u.abbrev_offset, s.endian) else {
                continue;
            };
            let mut r = u.dies();
            let Some(a) = r.next(&abbrevs) else { continue };
            if r.attrs(&u, a, &mut attrs).is_none() {
                continue;
            }
            u.set_bases(&attrs);
            let string = |name: u16| {
                let a = attrs.iter().find(|a| a.name == name)?;
                let s = u.string(&a.value)?;
                Some(String::from_utf8_lossy(s.bytes).into_owned())
            };
            let Some(name) = string(DW_AT_DWO_NAME).or_else(|| string(DW_AT_GNU_DWO_NAME)) else {
                continue;
            };
            let Some(dwo_id) = u.dwo_id.or_else(|| {
                attrs
                    .iter()
                    .find(|a| a.name == DW_AT_GNU_DWO_ID)
                    .and_then(|a| u.uint(&a.value))
            }) else {
                continue;
            };
            out.push(SplitFile {
                name,
                comp_dir: string(DW_AT_COMP_DIR).unwrap_or_default(),
                dwo_id,
            });
        }
        out
    }

    /// Adds a split file: a `.dwo`, or a `.dwp` package of them. Its
    /// split units whose skeletons this file has (and not yet given a
    /// split unit) are read as theirs; others are left out.
    ///
    /// # Errors
    ///
    /// If `data` isn't an object file with split DWARF, a package's index
    /// is damaged, or there are too many split files.
    pub fn add_split(&mut self, data: &'data [u8]) -> Result<()> {
        let image = Image::parse(data)?;
        let mut sections = debug_sections(&image);
        for (name, _) in &mut sections {
            if let Some(n) = name.strip_suffix(b".dwo") {
                *name = n;
            }
        }
        if !sections.iter().any(|(n, _)| *n == b"info") {
            return Err(Error::new(
                ErrorKind::BadMagic,
                0,
                "split DWARF (no .debug_info.dwo)",
            ));
        }
        let mut rows: Option<Vec<Row>> = None;
        for index in [&b"cu_index"[..], b"tu_index"] {
            if let Some((_, d)) = sections.iter().find(|(n, _)| *n == index) {
                let r = package_rows(d, image.endian()).ok_or_else(|| {
                    Error::new(ErrorKind::Malformed, 0, "split DWARF package index")
                })?;
                rows.get_or_insert_with(Vec::new).extend(r);
            }
        }
        if let Some(rows) = &mut rows {
            rows.sort_unstable_by_key(|r| (r.types, r.start));
        }
        if self.splits.len() >= MAX_FILES {
            return Err(Error::new(
                ErrorKind::Unsupported,
                0,
                "too many split DWARF files",
            ));
        }
        let more = ranges_budget(0, &sections);
        self.ranges_left
            .set(self.ranges_left.get().saturating_add(more));
        self.splits.push(Split {
            sections,
            rows,
            map: None,
            library: String::new(),
        });
        self.index = OnceCell::new();
        self.parents = OnceCell::new();
        self.functions = OnceCell::new();
        Ok(())
    }

    /// The debug information of a Mach-O image whose DWARF stays in its
    /// object files (no dSYM): none, until [`DwarfInfo::add_object`] adds
    /// the objects its debug map names.
    ///
    /// # Errors
    ///
    /// If `image` isn't a Mach-O image.
    pub fn from_debug_map(image: &'data [u8]) -> Result<Self> {
        let parsed = Image::parse(image)?;
        if parsed.macho().is_none() {
            return Err(Error::new(ErrorKind::BadMagic, 0, "Mach-O (a debug map)"));
        }
        let ids = parsed
            .debug_ids()
            .into_iter()
            .filter(|id| matches!(id, DebugId::Uuid(_)))
            .collect();
        Ok(Self {
            data: image,
            endian: parsed.endian(),
            arch: parsed.arch(),
            linked: true,
            ids,
            ranges_left: Cell::new(ranges_budget(0, &[])),
            sections: Vec::new(),
            index: OnceCell::new(),
            parents: OnceCell::new(),
            functions: OnceCell::new(),
            splits: Vec::new(),
        })
    }

    /// Adds an object file of the image's debug map, whose functions and
    /// variables the image has at `symbols` (see
    /// [`hexcavator_macho::MachO::debug_map`]), from the archive `library`
    /// (empty if none): its units, their addresses moved to the image's.
    ///
    /// # Errors
    ///
    /// If `data` isn't a Mach-O object file with DWARF, or there are too
    /// many files.
    pub fn add_object(
        &mut self,
        data: &'data [u8],
        symbols: &[hexcavator_macho::debugmap::DebugMapSymbol<'_>],
        library: &str,
    ) -> Result<()> {
        let image = Image::parse(data)?;
        let Some(object) = image.macho() else {
            return Err(Error::new(ErrorKind::BadMagic, 0, "Mach-O object file"));
        };
        let sections = debug_sections(&image);
        if !sections.iter().any(|(n, _)| *n == b"info") {
            return Err(Error::new(
                ErrorKind::BadMagic,
                0,
                "DWARF (no __debug_info)",
            ));
        }
        if self.splits.len() >= MAX_FILES {
            return Err(Error::new(
                ErrorKind::Unsupported,
                0,
                "too many object files",
            ));
        }
        let map = AddrMap::new(object, symbols);
        let more = ranges_budget(data.len(), &sections);
        self.ranges_left
            .set(self.ranges_left.get().saturating_add(more));
        self.splits.push(Split {
            sections,
            rows: None,
            map: Some(map),
            library: library.to_string(),
        });
        self.index = OnceCell::new();
        self.parents = OnceCell::new();
        self.functions = OnceCell::new();
        Ok(())
    }

    /// Where file `file`'s addresses are in the image, if it is an object
    /// file of a debug map.
    fn object_map(&self, file: u32) -> Option<&AddrMap> {
        let i = usize::try_from(file.checked_sub(1)?).ok()?;
        self.splits.get(i)?.map.as_ref()
    }

    /// Whether file `file` is an object file of a debug map.
    fn is_object(&self, file: u32) -> bool {
        self.object_map(file).is_some()
    }

    /// File `file`'s address `addr`, as the image has it (`None` if it
    /// is an object file's address the image doesn't have).
    fn image_addr(&self, file: u32, addr: u64) -> Option<u64> {
        match self.object_map(file) {
            Some(m) => m.addr(addr),
            None => Some(addr),
        }
    }

    /// File `file`'s location list entries, as the image has them.
    fn image_list<'a>(
        &self,
        file: u32,
        list: Vec<(u64, u64, &'a [u8])>,
    ) -> Vec<(u64, u64, &'a [u8])> {
        let Some(m) = self.object_map(file) else {
            return list;
        };
        let mut out = Vec::with_capacity(list.len());
        let mut moved = Vec::new();
        for (start, end, expr) in list {
            moved.clear();
            m.range(start, end.saturating_sub(start), &mut moved);
            out.extend(
                moved
                    .iter()
                    .map(|&(at, n)| (at, at.saturating_add(n), expr)),
            );
        }
        out
    }

    /// File `file`'s ranges, as the image has them.
    fn image_ranges(&self, file: u32, ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
        let Some(m) = self.object_map(file) else {
            return ranges;
        };
        let mut out = Vec::with_capacity(ranges.len());
        for (at, size) in ranges {
            m.range(at, size, &mut out);
        }
        out
    }

    /// The instruction set the debug information describes.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The sections, for the DWARF reader.
    pub fn sections(&self) -> Sections<'_> {
        let mut s = Sections::new(self.endian);
        for (name, data) in &self.sections {
            s.set(name, data);
        }
        s
    }

    /// The sections of `file` (0: this one): a split file's, with this
    /// one's addresses and (GNU's DWARF 4) range lists, which its units
    /// use.
    fn sections_of(&self, file: u32) -> Sections<'_> {
        let main = self.sections();
        let Some(split) = file
            .checked_sub(1)
            .and_then(|i| self.splits.get(usize::try_from(i).ok()?))
        else {
            return main;
        };
        let mut s = Sections::new(self.endian);
        for (name, data) in &split.sections {
            s.set(name, data);
        }
        // (An object file's units are whole: its own.)
        if split.map.is_none() {
            s.addr = main.addr;
            s.ranges = main.ranges;
        }
        s
    }

    /// Whether this is the debug information `id` names.
    pub fn matches(&self, id: &DebugId<'_>) -> bool {
        match *id {
            DebugId::BuildId(want) | DebugId::AltLink { build_id: want, .. } => self
                .ids
                .iter()
                .any(|i| matches!(i, DebugId::BuildId(have) if *have == want)),
            DebugId::Uuid(want) => self
                .ids
                .iter()
                .any(|i| matches!(i, DebugId::Uuid(have) if *have == want)),
            DebugId::DebugLink { crc: Some(crc), .. } => crc32(self.data) == crc,
            // (WebAssembly's link names a file, and gives nothing to check.)
            DebugId::DebugLink { crc: None, .. } => true,
            _ => false,
        }
    }

    fn index(&self) -> &Index {
        self.index.get_or_init(|| self.build_index())
    }

    fn build_index(&self) -> Index {
        let mut index = Index::default();
        let mut compilands = 0u32;
        let mut skeletons: HashMap<u64, Skeleton> = HashMap::new();
        let mut attrs = Vec::new();
        for (file, split) in (0u32..).zip(std::iter::once(None).chain(self.splits.iter().map(Some)))
        {
            let s = self.sections_of(file);
            let rows = split.and_then(|p| p.rows.as_deref());
            // (A debug map's object file is whole units, not split ones.)
            let split = split.filter(|p| p.map.is_none());
            for section in [UnitSection::Info, UnitSection::Types] {
                for mut u in Unit::iter(s, section, 0) {
                    if u.end > MAX_OFFSET {
                        break;
                    }
                    u.source = file;
                    // A package's unit: where its contributions are.
                    let row = match rows {
                        None => Row::default(),
                        Some(rows) => {
                            let key = (section == UnitSection::Types, u.offset);
                            let i = rows.partition_point(|r| (r.types, r.start) <= key);
                            match i.checked_sub(1).map(|i| rows[i]) {
                                Some(r) if r.types == key.0 && u.offset < r.end => r,
                                _ => continue,
                            }
                        }
                    };
                    let Some(abbrev_offset) = u.abbrev_offset.checked_add(row.abbrev) else {
                        continue;
                    };
                    u.abbrev_offset = abbrev_offset;
                    let abbrevs = match index.abbrevs.entry((file, abbrev_offset)) {
                        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                        std::collections::hash_map::Entry::Vacant(e) => {
                            let Some(a) = Abbrevs::parse(s.abbrev, abbrev_offset, s.endian) else {
                                continue;
                            };
                            e.insert(a)
                        }
                    };
                    let mut r = u.dies();
                    let Some(a) = r.next(abbrevs) else { continue };
                    let tag = a.tag;
                    if r.attrs(&u, a, &mut attrs).is_none() {
                        continue;
                    }
                    u.set_bases(&attrs);
                    let attr = |name: u16| {
                        attrs
                            .iter()
                            .find(|a| a.name == name)
                            .and_then(|a| u.uint(&a.value))
                    };
                    let dwo_id = u.dwo_id.or_else(|| attr(DW_AT_GNU_DWO_ID));
                    let ranges_base = attr(DW_AT_GNU_RANGES_BASE).unwrap_or(0);
                    if split.is_some() {
                        // Split units' bases are of their contributions
                        // (past DWARF 5's list headers).
                        u.split = true;
                        u.str_offsets_base = u.str_offsets_base.saturating_add(row.str_offsets);
                        if u.version >= 5 {
                            let header = if u.dwarf64 { 20 } else { 12 };
                            u.loclists_base = row.loc.saturating_add(header);
                            u.rnglists_base = row.rnglists.saturating_add(header);
                        } else {
                            u.loclists_base = row.loc;
                        }
                    }
                    let is_type = u.unit_type == DW_UT_TYPE || u.unit_type == DW_UT_SPLIT_TYPE;
                    if let Some((sig, at)) = u.type_signature() {
                        index
                            .signatures
                            .entry(sig)
                            .or_insert_with(|| to_ref(file, section, at));
                    }
                    let is_compile = !is_type
                        && matches!(
                            tag,
                            DW_TAG_COMPILE_UNIT | DW_TAG_PARTIAL_UNIT | DW_TAG_SKELETON_UNIT
                        );
                    let compiland = if split.is_none() {
                        is_compile.then(|| {
                            compilands += 1;
                            compilands - 1
                        })
                    } else if is_compile {
                        // A split unit: its skeleton's compiland, with its
                        // addresses (and no other split unit's).
                        let Some(k) = dwo_id.and_then(|id| skeletons.remove(&id)) else {
                            continue;
                        };
                        u.addr_base = k.addr_base;
                        u.low_pc = k.low_pc;
                        if u.version < 5 {
                            u.rnglists_base = k.ranges_base;
                        }
                        Some(k.compiland)
                    } else {
                        None
                    };
                    if let (None, Some(c), Some(id)) = (split, compiland, dwo_id) {
                        skeletons.entry(id).or_insert(Skeleton {
                            addr_base: u.addr_base,
                            low_pc: u.low_pc,
                            ranges_base,
                            compiland: c,
                        });
                    }
                    index.units.push(UnitMeta {
                        file,
                        section,
                        offset: u.offset,
                        end: u.end,
                        abbrev_offset,
                        split: u.split,
                        addr_base: u.addr_base,
                        str_offsets_base: u.str_offsets_base,
                        rnglists_base: u.rnglists_base,
                        loclists_base: u.loclists_base,
                        low_pc: u.low_pc,
                        compiland,
                    });
                }
            }
        }
        let split_of: HashMap<u32, usize> = (0..)
            .zip(&index.units)
            .filter(|(_, m)| m.split)
            .filter_map(|(i, m)| Some((m.compiland?, i)))
            .collect();
        for (i, m) in index.units.iter().enumerate() {
            if m.file == 0 || self.is_object(m.file) {
                index.order.push(i);
                if let Some(&j) = m.compiland.and_then(|c| split_of.get(&c)) {
                    index.order.push(j);
                }
            } else if m.compiland.is_none() {
                index.order.push(i);
            }
        }
        index
    }

    /// A unit's abbreviations.
    fn abbrevs_of(&self, u: &Unit<'_>) -> Option<&Abbrevs> {
        self.index().abbrevs.get(&(u.source, u.abbrev_offset))
    }

    /// The index entry of the unit holding the DIE `r` names.
    fn meta_of(&self, r: TypeRef) -> Option<&UnitMeta> {
        let (file, section, offset) = locate(r)?;
        let units = &self.index().units;
        let i = units.partition_point(|m| (m.file, m.section, m.offset) <= (file, section, offset));
        let m = units.get(i.checked_sub(1)?)?;
        (m.file == file && m.section == section && offset < m.end).then_some(m)
    }

    /// The functions (subprogram DIEs with code), by their first
    /// address.
    fn functions(&self) -> &HashMap<u64, Vec<TypeRef>> {
        self.functions.get_or_init(|| {
            let mut out: HashMap<u64, Vec<TypeRef>> = HashMap::new();
            self.walk(|w| {
                if w.die.tag == DW_TAG_SUBPROGRAM
                    && let Some(&(low, _)) = self.ranges(w.unit, w.die).first()
                {
                    out.entry(low).or_default().push(w.at);
                }
                Walk::Into
            });
            out
        })
    }

    /// A unit, its bases set, and its abbreviations.
    fn unit(&self, m: &UnitMeta) -> Option<(Unit<'_>, &Abbrevs)> {
        let mut u = Unit::iter(self.sections_of(m.file), m.section, m.offset).next()?;
        u.source = m.file;
        u.split = m.split;
        u.abbrev_offset = m.abbrev_offset;
        u.addr_base = m.addr_base;
        u.str_offsets_base = m.str_offsets_base;
        u.rnglists_base = m.rnglists_base;
        u.loclists_base = m.loclists_base;
        u.low_pc = m.low_pc;
        let abbrevs = self.index().abbrevs.get(&(m.file, m.abbrev_offset))?;
        Some((u, abbrevs))
    }

    /// The unit holding the DIE `r` names.
    fn unit_of(&self, r: TypeRef) -> Option<(Unit<'_>, &Abbrevs, u64)> {
        let m = self.meta_of(r)?;
        let (u, a) = self.unit(m)?;
        Some((u, a, locate(r)?.2))
    }

    /// The DIE `r` names.
    fn die(&self, r: TypeRef) -> Option<(Unit<'_>, &Abbrevs, Die<'_>)> {
        let (u, a, offset) = self.unit_of(r)?;
        let d = u.entry(a, offset)?;
        Some((u, a, d))
    }

    /// The DIE a reference attribute leads to (a type unit's, by its
    /// signature).
    fn reference(&self, u: &Unit<'_>, attr: &Attr<'_>) -> Option<TypeRef> {
        if attr.form == DW_FORM_REF_SIG8 {
            let Value::Uint(sig) = attr.value else {
                return None;
            };
            return self.index().signatures.get(&sig).copied();
        }
        let at = u.reference(attr)?;
        let section = if attr.form == DW_FORM_REF_ADDR {
            UnitSection::Info
        } else {
            u.section
        };
        Some(to_ref(u.source, section, at))
    }

    /// The type a DIE's `DW_AT_type` names: [`VOID`] if it names none,
    /// `TypeRef(0)` if it leads nowhere.
    fn type_of(&self, u: &Unit<'_>, d: &Die<'_>) -> TypeRef {
        match d.attr(DW_AT_TYPE) {
            None => VOID,
            Some(a) => self.reference(u, a).unwrap_or(TypeRef(0)),
        }
    }

    fn string(u: &Unit<'_>, d: &Die<'_>, name: u16) -> Option<String> {
        let a = d.attr(name)?;
        let s = u.string(&a.value)?;
        Some(String::from_utf8_lossy(s.bytes).into_owned())
    }

    fn uint(u: &Unit<'_>, d: &Die<'_>, name: u16) -> Option<u64> {
        u.uint(&d.attr(name)?.value)
    }

    /// Where the DIE `r` (a type, a function, a variable) is declared: its
    /// `DW_AT_decl_file` (a path, by its unit's line table and compilation
    /// directory) and `DW_AT_decl_line`, or its specification's.
    pub fn type_definition(&self, r: TypeRef) -> Option<(String, u32)> {
        let mut at = r;
        for _ in 0..MAX_CHAIN {
            let (u, a, d) = self.die(at)?;
            if let (Some(file), Some(line)) = (
                Self::uint(&u, &d, DW_AT_DECL_FILE),
                Self::uint(&u, &d, DW_AT_DECL_LINE),
            ) {
                let root = u.entry(a, u.dies)?;
                let offset = Self::uint(&u, &root, DW_AT_STMT_LIST)?;
                let s = self.sections_of(u.source);
                let program = line_program(&s, offset, u.address_size)?;
                let comp_dir = Self::string(&u, &root, DW_AT_COMP_DIR).unwrap_or_default();
                let path = program.path(file, comp_dir.as_bytes())?;
                return Some((path, u32::try_from(line).unwrap_or(u32::MAX)));
            }
            // (A definition apart from its declaration names it.)
            let next = d
                .attr(DW_AT_SPECIFICATION)
                .or_else(|| d.attr(DW_AT_ABSTRACT_ORIGIN))?;
            at = self.reference(&u, next)?;
        }
        None
    }

    /// The DIE a declaration's definition, or an inlined or out-of-line
    /// copy, is of (following `DW_AT_specification` and
    /// `DW_AT_abstract_origin`), and the first name along the way.
    fn origin(&self, r: TypeRef) -> (TypeRef, Option<String>) {
        let mut at = r;
        let mut name = None;
        for _ in 0..MAX_CHAIN {
            let Some((u, _, d)) = self.die(at) else { break };
            if name.is_none() {
                name = Self::string(&u, &d, DW_AT_NAME);
            }
            let next = d
                .attr(DW_AT_SPECIFICATION)
                .or_else(|| d.attr(DW_AT_ABSTRACT_ORIGIN))
                .and_then(|a| self.reference(&u, a));
            match next {
                Some(n) if n != at => at = n,
                _ => break,
            }
        }
        (at, name)
    }

    /// The enclosing scope of every DIE in a namespace, class, structure,
    /// union, or enumeration.
    fn parents(&self) -> &HashMap<u64, u64> {
        self.parents.get_or_init(|| {
            let mut out = HashMap::new();
            self.walk(|w| {
                if let Some(p) = w.stack.last()
                    && is_scope(p.tag)
                {
                    out.insert(w.at.0, p.at.0);
                }
                Walk::Into
            });
            out
        })
    }

    /// The qualified name of the DIE `r` names (that of what it defines or
    /// is a copy of): its scopes' names and its own, joined by `::`.
    pub fn qualified_name(&self, r: TypeRef) -> String {
        let (decl, name) = self.origin(r);
        let mut parts = vec![name.unwrap_or_else(|| self.anonymous(decl))];
        let parents = self.parents();
        let mut at = decl.0;
        while let Some(&p) = parents.get(&at) {
            if parts.len() >= MAX_SCOPES || p == at {
                break;
            }
            let Some((u, _, d)) = self.die(TypeRef(p)) else {
                break;
            };
            parts.push(
                Self::string(&u, &d, DW_AT_NAME).unwrap_or_else(|| self.anonymous(TypeRef(p))),
            );
            at = p;
        }
        parts.reverse();
        let mut out = parts.join("::");
        if out.len() > MAX_NAME {
            let mut end = MAX_NAME;
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
            out.push_str("...");
        }
        out
    }

    /// What an unnamed DIE is called, as LLVM's tools call it.
    fn anonymous(&self, r: TypeRef) -> String {
        let tag = self.die(r).map_or(0, |(_, _, d)| d.tag);
        match tag {
            DW_TAG_NAMESPACE => "(anonymous namespace)",
            DW_TAG_CLASS_TYPE => "(anonymous class)",
            DW_TAG_STRUCTURE_TYPE => "(anonymous struct)",
            DW_TAG_UNION_TYPE => "(anonymous union)",
            DW_TAG_ENUMERATION_TYPE => "(anonymous enum)",
            _ => "(anonymous)",
        }
        .to_string()
    }

    /// Every DIE of every unit, depth first, with the DIEs enclosing it;
    /// `f` says whether to read a DIE's children.
    fn walk(&self, mut f: impl FnMut(&Walked<'_, '_>) -> Walk) {
        let mut stack: Vec<Frame> = Vec::new();
        let mut attrs = Vec::new();
        let index = self.index();
        for m in index.order.iter().map(|&i| &index.units[i]) {
            let Some((u, abbrevs)) = self.unit(m) else {
                continue;
            };
            stack.clear();
            let mut r = u.dies();
            while let Some(a) = r.next(abbrevs) {
                let offset = r.offset;
                let depth = r.depth - i64::from(a.children);
                if r.attrs(&u, a, &mut attrs).is_none() {
                    break;
                }
                while stack.last().is_some_and(|s| s.depth >= depth) {
                    stack.pop();
                }
                let die = Die {
                    offset,
                    tag: a.tag,
                    children: a.children,
                    attrs: std::mem::take(&mut attrs),
                    next: r.position(),
                };
                let at = to_ref(m.file, m.section, offset);
                let what = f(&Walked {
                    unit: &u,
                    meta: m,
                    die: &die,
                    at,
                    stack: &stack,
                });
                if a.children {
                    if what == Walk::Over || depth >= MAX_DEPTH {
                        if r.skip_children(&u, abbrevs, a).is_none() {
                            break;
                        }
                    } else {
                        let low_pc = (a.tag == DW_TAG_SUBPROGRAM)
                            .then(|| self.ranges(&u, &die).first().map(|r| r.0))
                            .flatten();
                        stack.push(Frame {
                            depth,
                            tag: a.tag,
                            at,
                            low_pc,
                        });
                    }
                }
                attrs = die.attrs;
            }
        }
    }

    /// A DIE's code: its `DW_AT_low_pc` and `DW_AT_high_pc`, or its
    /// `DW_AT_ranges`, as (address, size), discarded code left out.
    fn ranges(&self, u: &Unit<'_>, d: &Die<'_>) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        if let Some(low) = d.attr(DW_AT_LOW_PC).and_then(|a| u.uint(&a.value))
            && let Some(high) = d.attr(DW_AT_HIGH_PC)
        {
            let size = match high.form {
                DW_FORM_ADDR
                | DW_FORM_ADDRX
                | DW_FORM_ADDRX1
                | DW_FORM_ADDRX2
                | DW_FORM_ADDRX3
                | DW_FORM_ADDRX4
                | DW_FORM_GNU_ADDR_INDEX => u.uint(&high.value).and_then(|h| h.checked_sub(low)),
                _ => u.uint(&high.value),
            };
            if let Some(size) = size {
                out.push((low, size));
            }
        }
        if let Some(a) = d.attr(DW_AT_RANGES) {
            let list = match a.value {
                Value::ListIndex(i) => u.rnglist_offset(i).and_then(|o| u.rnglist(o)),
                _ => u.uint(&a.value).and_then(|o| {
                    if u.version >= 5 {
                        u.rnglist(o)
                    } else {
                        // (A split unit's are of its skeleton's
                        // `DW_AT_GNU_ranges_base`.)
                        let base = if u.split { u.rnglists_base } else { 0 };
                        u.range_list(o.checked_add(base)?, u.low_pc)
                    }
                }),
            };
            if let Some((list, _)) = list {
                let left = self.ranges_left.get();
                let n = list.len() as u64;
                let take = usize::try_from(n.min(left.max(1))).unwrap_or(usize::MAX);
                out.extend(list.into_iter().take(take));
                self.ranges_left.set(left.saturating_sub(n));
            }
        }
        let mut out = self.image_ranges(u.source, out);
        out.retain(|&(at, size)| size > 0 && (!self.linked || u.is_valid_address(at)));
        out
    }

    /// The code of a unit's functions (subprograms).
    fn function_ranges(&self, u: &Unit<'_>, abbrevs: &Abbrevs) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut attrs = Vec::new();
        let mut r = u.dies();
        while let Some(a) = r.next(abbrevs) {
            let offset = r.offset;
            if r.attrs(u, a, &mut attrs).is_none() {
                break;
            }
            if a.tag == DW_TAG_SUBPROGRAM {
                let die = Die {
                    offset,
                    tag: a.tag,
                    children: a.children,
                    attrs: std::mem::take(&mut attrs),
                    next: r.position(),
                };
                out.extend(self.ranges(u, &die));
                attrs = die.attrs;
            }
        }
        out
    }

    /// The compilands: compile, partial, and skeleton units, in order (see [`crate::DebugInfo::compilands`]).
    pub fn compilands(&self) -> Result<Vec<Compiland>> {
        let mut out = Vec::new();
        let name = |m: &UnitMeta, names: &[u16]| {
            let (u, a) = self.unit(m)?;
            let d = u.entry(a, u.dies)?;
            names.iter().find_map(|&n| Self::string(&u, &d, n))
        };
        for m in &self.index().units {
            let Some(c) = m.compiland else { continue };
            if m.split {
                // The split unit's name, over its skeleton's.
                if let (Some(n), Some(o)) = (
                    name(m, &[DW_AT_NAME]),
                    usize::try_from(c).ok().and_then(|c| out.get_mut(c)),
                ) {
                    let o: &mut Compiland = o;
                    o.name = n;
                }
            } else {
                // A skeleton without its split unit is named by its file.
                out.push(Compiland {
                    name: name(m, &[DW_AT_NAME, DW_AT_DWO_NAME, DW_AT_GNU_DWO_NAME])
                        .unwrap_or_default(),
                    library: m
                        .file
                        .checked_sub(1)
                        .and_then(|i| self.splits.get(usize::try_from(i).ok()?))
                        .map(|f| f.library.clone())
                        .unwrap_or_default(),
                });
            }
        }
        Ok(out)
    }

    /// The compilands' code (see [`crate::DebugInfo::contributions`]).
    pub fn contributions(&self) -> Result<Vec<Contribution>> {
        let mut out: Vec<Contribution> = Vec::new();
        // The compilands with code so far.
        let mut with_code = std::collections::HashSet::new();
        for m in &self.index().units {
            let Some(compiland) = m.compiland else {
                continue;
            };
            // A split unit's code is its skeleton's, unless the skeleton
            // gave none.
            if m.split && with_code.contains(&compiland) {
                continue;
            }
            let Some((u, a)) = self.unit(m) else { continue };
            let Some(d) = u.entry(a, u.dies) else {
                continue;
            };
            for (addr, size) in self.ranges(&u, &d) {
                with_code.insert(compiland);
                out.push(Contribution {
                    addr,
                    size,
                    compiland,
                    characteristics: 0,
                });
            }
        }
        // Units without ranges: the address ranges table's.
        if out.is_empty() {
            let s = self.sections();
            let by_offset: HashMap<u64, u32> = self
                .index()
                .units
                .iter()
                .filter(|m| m.file == 0 && m.section == UnitSection::Info)
                .filter_map(|m| Some((m.offset, m.compiland?)))
                .collect();
            for e in hexcavator_dwarf::aranges(s.aranges, s.endian) {
                if let Some(&compiland) = by_offset.get(&e.info_offset)
                    && e.length > 0
                {
                    out.push(Contribution {
                        addr: e.address,
                        size: e.length,
                        compiland,
                        characteristics: 0,
                    });
                }
            }
        }
        out.sort_unstable_by_key(|c| (c.addr, c.size, c.compiland));
        Ok(out)
    }

    /// The line tables (see [`crate::DebugInfo::source_lines`]).
    pub fn source_lines(&self) -> Result<SourceLines> {
        let mut files: Vec<String> = Vec::new();
        let mut by_name: HashMap<String, u32> = HashMap::new();
        let mut spans = Vec::new();
        for m in &self.index().units {
            // (A split unit's lines are its skeleton's.)
            let Some(compiland) = m.compiland.filter(|_| !m.split) else {
                continue;
            };
            let Some((u, a)) = self.unit(m) else { continue };
            let Some(d) = u.entry(a, u.dies) else {
                continue;
            };
            let Some(offset) = Self::uint(&u, &d, DW_AT_STMT_LIST) else {
                continue;
            };
            let s = self.sections_of(m.file);
            let map = self.object_map(m.file);
            let mut moved = Vec::new();
            // An object's rows run on over the padding between its
            // functions: they are kept to the unit's code (as dsymutil
            // keeps them).
            let mut code = match map {
                Some(_) => self.function_ranges(&u, a),
                None => Vec::new(),
            };
            code.sort_unstable();
            let Some(program) = line_program(&s, offset, u.address_size) else {
                continue;
            };
            let comp_dir = Self::string(&u, &d, DW_AT_COMP_DIR).unwrap_or_default();
            let mut local: HashMap<u64, u32> = HashMap::new();
            let mut file = |index: u64| -> u32 {
                *local.entry(index).or_insert_with(|| {
                    let name = program.path(index, comp_dir.as_bytes()).unwrap_or_default();
                    *by_name.entry(name.clone()).or_insert_with(|| {
                        files.push(name);
                        u32::try_from(files.len() - 1).unwrap_or(u32::MAX)
                    })
                })
            };
            for w in program.rows.windows(2) {
                let (row, next) = (&w[0], &w[1]);
                // (An object file's code starts at 0: not discarded.)
                let discarded = row.discarded && map.is_none();
                if row.end_sequence || discarded || next.address <= row.address {
                    continue;
                }
                let size = next.address - row.address;
                moved.clear();
                match map {
                    Some(map) => {
                        map.range(row.address, size, &mut moved);
                        clip(&mut moved, &code);
                    }
                    None => moved.push((row.address, size)),
                }
                for &(addr, size) in &moved {
                    if self.linked && !u.is_valid_address(addr) {
                        continue;
                    }
                    spans.push(LineSpan {
                        addr,
                        size,
                        file: file(row.file),
                        line: u32::try_from(row.line).unwrap_or(u32::MAX),
                        compiland,
                    });
                }
            }
        }
        spans.sort_unstable_by_key(|l| (l.addr, l.size));
        Ok(SourceLines { files, spans })
    }

    /// The functions, blocks, and variables (see [`crate::DebugInfo::symbols`]).
    pub fn symbols(&self) -> Result<Vec<Symbol>> {
        let mut out = Vec::new();
        self.walk(|w| {
            let d = w.die;
            let u = w.unit;
            let compiland = w.meta.compiland;
            let function = w
                .stack
                .iter()
                .rev()
                .find(|f| f.tag == DW_TAG_SUBPROGRAM)
                .copied();
            match d.tag {
                DW_TAG_SUBPROGRAM => {
                    if d.flag(DW_AT_DECLARATION) {
                        return Walk::Into;
                    }
                    let ranges = self.ranges(u, d);
                    let Some(&(addr, size)) = ranges.first() else {
                        return Walk::Into;
                    };
                    let (decl, _) = self.origin(w.at);
                    out.push(Symbol {
                        kind: SymbolKind::Function,
                        addr,
                        size: Some(size),
                        name: self.qualified_name(w.at),
                        compiland,
                        global: self.external(decl),
                        thread_local: false,
                        parent: None,
                        function: None,
                        type_index: w.at.0,
                        flags: 0,
                    });
                    // Pieces of the function elsewhere.
                    for &(at, size) in &ranges[1..] {
                        out.push(Symbol {
                            kind: SymbolKind::SeparatedBlock,
                            addr: at,
                            size: Some(size),
                            name: self.qualified_name(w.at),
                            compiland,
                            global: false,
                            thread_local: false,
                            parent: Some(addr),
                            function: None,
                            type_index: w.at.0,
                            flags: 0,
                        });
                    }
                }
                DW_TAG_LEXICAL_BLOCK | DW_TAG_LABEL => {
                    let kind = if d.tag == DW_TAG_LABEL {
                        SymbolKind::Label
                    } else {
                        SymbolKind::Block
                    };
                    let mut ranges = self.ranges(u, d);
                    if d.tag == DW_TAG_LABEL
                        && let Some(low) = Self::uint(u, d, DW_AT_LOW_PC)
                    {
                        ranges = match self.image_addr(u.source, low) {
                            Some(low) => vec![(low, 0)],
                            None => Vec::new(),
                        };
                    }
                    for (addr, size) in ranges {
                        out.push(Symbol {
                            kind,
                            addr,
                            size: (size > 0).then_some(size),
                            name: Self::string(u, d, DW_AT_NAME).unwrap_or_default(),
                            compiland,
                            global: false,
                            thread_local: false,
                            parent: function.and_then(|f| f.low_pc),
                            function: None,
                            type_index: 0,
                            flags: 0,
                        });
                    }
                }
                DW_TAG_VARIABLE => {
                    let Some(loc) = d.attr(DW_AT_LOCATION) else {
                        return Walk::Into;
                    };
                    let Some((addr, tls)) = static_address(u, &loc.value) else {
                        return Walk::Into;
                    };
                    let Some(addr) = self.image_addr(u.source, addr) else {
                        return Walk::Into;
                    };
                    if self.linked && !tls && !u.is_valid_address(addr) {
                        return Walk::Into;
                    }
                    let (decl, _) = self.origin(w.at);
                    let ty = self.declared_type(w.at);
                    let enclosing = function.and_then(|f| self.enclosing(f.at));
                    out.push(Symbol {
                        kind: SymbolKind::Data,
                        addr,
                        size: self.type_size(ty),
                        name: self.qualified_name(w.at),
                        compiland,
                        global: self.external(decl),
                        thread_local: tls,
                        parent: function.and_then(|f| f.low_pc),
                        function: enclosing.map(Box::new),
                        type_index: ty.0,
                        flags: 0,
                    });
                }
                _ => {}
            }
            Walk::Into
        });
        out.sort_by(|a, b| (a.addr, a.kind, &a.name).cmp(&(b.addr, b.kind, &b.name)));
        out.dedup_by(|a, b| a.addr == b.addr && a.kind == b.kind && a.name == b.name);
        Ok(out)
    }

    /// Whether the declaration `decl` has external linkage.
    fn external(&self, decl: TypeRef) -> bool {
        self.die(decl)
            .is_some_and(|(_, _, d)| d.flag(DW_AT_EXTERNAL))
    }

    /// The type a DIE declares (its own, or its declaration's).
    fn declared_type(&self, r: TypeRef) -> TypeRef {
        let mut at = r;
        for _ in 0..MAX_CHAIN {
            let Some((u, _, d)) = self.die(at) else {
                return TypeRef(0);
            };
            if d.attr(DW_AT_TYPE).is_some() {
                return self.type_of(&u, &d);
            }
            match d
                .attr(DW_AT_SPECIFICATION)
                .or_else(|| d.attr(DW_AT_ABSTRACT_ORIGIN))
                .and_then(|a| self.reference(&u, a))
            {
                Some(n) if n != at => at = n,
                _ => return VOID,
            }
        }
        TypeRef(0)
    }

    /// The function the subprogram DIE `r` is, for a variable in it.
    fn enclosing(&self, r: TypeRef) -> Option<EnclosingFunction> {
        let (decl, _) = self.origin(r);
        let (u, a, d) = self.die(decl)?;
        let params = u
            .children(a, &d)
            .iter()
            .filter(|c| c.tag == DW_TAG_FORMAL_PARAMETER && !c.flag(DW_AT_ARTIFICIAL))
            .map(|c| {
                (
                    Self::string(&u, c, DW_AT_NAME).unwrap_or_default(),
                    self.type_of(&u, c),
                )
            })
            .collect();
        Some(EnclosingFunction {
            name: self.qualified_name(r),
            ty: decl,
            params,
        })
    }

    /// Every inline site (see [`crate::DebugInfo::inline_sites`]).
    pub fn inline_sites(&self) -> Result<InlineSites> {
        let mut inlinees: Vec<String> = Vec::new();
        let mut by_origin: HashMap<u64, u32> = HashMap::new();
        let mut sites = Vec::new();
        self.walk(|w| {
            let d = w.die;
            if d.tag == DW_TAG_INLINED_SUBROUTINE {
                {
                    let ranges = self.ranges(w.unit, d);
                    let function = w
                        .stack
                        .iter()
                        .find(|f| f.tag == DW_TAG_SUBPROGRAM)
                        .and_then(|f| f.low_pc);
                    let (Some(function), Some(compiland)) = (function, w.meta.compiland) else {
                        return Walk::Into;
                    };
                    if ranges.is_empty() {
                        return Walk::Into;
                    }
                    let (origin, _) = self.origin(w.at);
                    let inlinee = *by_origin.entry(origin.0).or_insert_with(|| {
                        inlinees.push(self.qualified_name(origin));
                        u32::try_from(inlinees.len() - 1).unwrap_or(u32::MAX)
                    });
                    let depth = w
                        .stack
                        .iter()
                        .filter(|f| f.tag == DW_TAG_INLINED_SUBROUTINE)
                        .count();
                    sites.push(InlineSite {
                        inlinee,
                        function,
                        ranges,
                        compiland,
                        depth: u32::try_from(depth).unwrap_or(u32::MAX),
                    });
                }
            }
            Walk::Into
        });
        Ok(InlineSites { inlinees, sites })
    }
}

/// `spans` (address, size), cut to the parts within the sorted `code`
/// ranges.
fn clip(spans: &mut Vec<(u64, u64)>, code: &[(u64, u64)]) {
    let mut out = Vec::with_capacity(spans.len());
    for &(at, size) in spans.iter() {
        let end = at.saturating_add(size);
        let first = code.partition_point(|c| c.0.saturating_add(c.1) <= at);
        for &(c, n) in &code[first..] {
            if c >= end {
                break;
            }
            let lo = at.max(c);
            let hi = end.min(c.saturating_add(n));
            if hi > lo {
                out.push((lo, hi - lo));
            }
        }
    }
    *spans = out;
}

/// A DIE being walked, and those enclosing it.
struct Walked<'a, 'u> {
    unit: &'a Unit<'u>,
    meta: &'a UnitMeta,
    die: &'a Die<'u>,
    at: TypeRef,
    stack: &'a [Frame],
}

/// An enclosing DIE.
#[derive(Clone, Copy, Debug)]
struct Frame {
    depth: i64,
    tag: u16,
    at: TypeRef,
    low_pc: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Walk {
    Into,
    Over,
}

/// The [`TypeRef`] of the DIE at `offset` of `section` of `file`; one that
/// can't be (an offset too large) leads nowhere.
fn to_ref(file: u32, section: UnitSection, offset: u64) -> TypeRef {
    if offset >= MAX_OFFSET || u64::from(file) > MAX_FILES as u64 {
        return TypeRef(0);
    }
    let r = offset | u64::from(file) << FILE_SHIFT;
    match section {
        UnitSection::Info => TypeRef(r),
        UnitSection::Types => TypeRef(r | TYPES),
    }
}

/// Where the DIE `r` names is: file, section, offset.
fn locate(r: TypeRef) -> Option<(u32, UnitSection, u64)> {
    if r == VOID || r.0 == 0 {
        return None;
    }
    let file = u32::try_from((r.0 & !TYPES) >> FILE_SHIFT).ok()?;
    let offset = r.0 & (MAX_OFFSET - 1);
    let section = if r.0 & TYPES != 0 {
        UnitSection::Types
    } else {
        UnitSection::Info
    };
    Some((file, section, offset))
}

/// Whether a DIE of `tag` is a scope its children's names are in.
fn is_scope(tag: u16) -> bool {
    matches!(
        tag,
        DW_TAG_NAMESPACE
            | DW_TAG_CLASS_TYPE
            | DW_TAG_STRUCTURE_TYPE
            | DW_TAG_UNION_TYPE
            | DW_TAG_INTERFACE_TYPE
            | DW_TAG_ENUMERATION_TYPE
            | DW_TAG_MODULE
    )
}

/// The address of a variable at a fixed place (`DW_OP_addr`), or at an
/// offset in the thread-local storage block (a constant, then
/// `DW_OP_form_tls_address` or GNU's `DW_OP_GNU_push_tls_address`):
/// (address, thread-local).
fn static_address(u: &Unit<'_>, v: &Value<'_>) -> Option<(u64, bool)> {
    if let Some(a) = u.location_address(v) {
        return Some((a, false));
    }
    let Value::Block(b) = *v else { return None };
    let (&last, rest) = b.split_last()?;
    if last != DW_OP_FORM_TLS_ADDRESS && last != DW_OP_GNU_PUSH_TLS_ADDRESS {
        return None;
    }
    let mut r = hexcavator_dwarf::Reader::new(rest, 1, u.sections().endian);
    let at = match *rest.first()? {
        DW_OP_CONST4U => r.uint(4)?,
        DW_OP_CONST8U => r.uint(8)?,
        DW_OP_CONSTU => r.uleb()?,
        DW_OP_ADDR => r.uint(usize::from(u.address_size))?,
        DW_OP_CONSTX | DW_OP_GNU_CONST_INDEX => u.indexed_address(r.uleb()?)?,
        _ => return None,
    };
    r.is_empty().then_some((at, true))
}

/// The CRC-32 `.gnu_debuglink` checks (ISO 3309, as zlib's).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in (0u32..).zip(t.iter_mut()) {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    !data.iter().fold(!0u32, |crc, &b| {
        table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_is_zlibs() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn type_refs_round_trip() {
        assert_eq!(
            locate(to_ref(0, UnitSection::Info, 0x40)),
            Some((0, UnitSection::Info, 0x40))
        );
        assert_eq!(
            locate(to_ref(0, UnitSection::Types, 0x40)),
            Some((0, UnitSection::Types, 0x40))
        );
        // The file's own DIEs' references are their offsets.
        assert_eq!(to_ref(0, UnitSection::Info, 0x40), TypeRef(0x40));
        let max_file = u32::try_from(MAX_FILES).unwrap();
        for file in [1, 2, max_file] {
            for section in [UnitSection::Info, UnitSection::Types] {
                let max = MAX_OFFSET - 1;
                assert_eq!(
                    locate(to_ref(file, section, max)),
                    Some((file, section, max))
                );
                assert_eq!(locate(to_ref(file, section, 0)), Some((file, section, 0)));
            }
        }
        // Too large to name: nowhere.
        assert_eq!(to_ref(0, UnitSection::Info, MAX_OFFSET), TypeRef(0));
        assert_eq!(to_ref(max_file + 1, UnitSection::Info, 0), TypeRef(0));
        assert_ne!(to_ref(max_file, UnitSection::Types, MAX_OFFSET - 1), VOID);
        assert_eq!(locate(VOID), None);
        assert_eq!(locate(TypeRef(0)), None);
    }
}

//! Size attribution: which sections, groups, libraries, and compilands
//! account for each byte of an executable.
//!
//! A [`Model`] is built once from an image and its debug information (see
//! [`pe::build`]) and is independent of the file format: sections hold
//! groups (COFF groups for PE), and compilands (translation units), which
//! belong to libraries, contribute [`Piece`]s, address ranges each lying in
//! one section and at most one group. Totals for any pivot (compilands by
//! section, libraries by group, ...) are computed from the pieces by
//! [`Model::totals`].
//!
//! Sizes come in two kinds, as SizeBench defines them: *file* size (bytes
//! on disk) and *memory* size (bytes when loaded; zero-fill data such as
//! `.bss` takes memory but no file space). Padding to the file and section
//! alignments is counted separately.

// Model indices are `u32`: every count they index (sections, groups,
// compilands, ...) comes from a 32-bit field of the input formats. Group
// padding is computed in wrapping 32-bit arithmetic on purpose (see `pe`).
#![allow(clippy::cast_possible_truncation)]

pub mod budget;
pub mod custom;
/// (Moved to the debug information crate, which reads DWARF too.)
pub use hexcavator_debuginfo::decompress;
pub mod disasm;
pub mod dwarf_units;
pub mod eh;
pub mod elf;
pub mod findings;
pub mod fingerprint;
pub mod index;
mod lcid;
pub mod macho;
pub mod map;
pub mod model;
pub mod names;
pub mod objects;
pub mod pe;
pub mod pe_symbols;
pub mod range;
pub mod rangemap;
pub mod recommend;
pub mod report;
pub mod rollup;
pub mod rsrc;
pub mod sourcemap;
pub mod sources;
pub mod symbols;
pub mod table;
#[cfg(test)]
mod testimage;
pub mod unixmap;
pub mod wasm;
pub mod xref;

use std::collections::BTreeMap;

use hexcavator_image::Arch;

pub use range::Range;

/// A size in the file and in memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Size {
    /// Bytes in the file.
    pub file: u64,
    /// Bytes in memory.
    pub vm: u64,
}

impl Size {
    pub const fn new(file: u64, vm: u64) -> Self {
        Self { file, vm }
    }
}

impl std::ops::Add for Size {
    type Output = Size;
    fn add(self, other: Size) -> Size {
        Size::new(
            self.file.saturating_add(other.file),
            self.vm.saturating_add(other.vm),
        )
    }
}

impl std::ops::AddAssign for Size {
    fn add_assign(&mut self, other: Size) {
        *self = *self + other;
    }
}

/// A section of the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Unique among the model's sections (duplicates are disambiguated).
    pub name: String,
    pub addr: u64,
    /// File bytes and memory bytes. The file size includes the padding to
    /// the file alignment; the memory size does not include the padding to
    /// the section alignment.
    pub size: Size,
    /// Memory bytes after the section, up to the section alignment.
    pub vm_padding: u64,
    /// The format's section flags (PE: `Characteristics`).
    pub characteristics: u32,
    /// What it holds and how it is mapped, whatever the format.
    pub flags: hexcavator_image::SectionFlags,
}

impl Section {
    pub fn executable(&self) -> bool {
        self.flags.contains(hexcavator_image::SectionFlags::EXECUTE)
    }

    pub fn writable(&self) -> bool {
        self.flags.contains(hexcavator_image::SectionFlags::WRITE)
    }
}

/// Where a group came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GroupOrigin {
    /// The debug information (PDB `S_COFFGROUP`).
    DebugInfo,
    /// Many small groups of one family, merged (obfuscated code makes
    /// thousands of them).
    Merged,
    /// A table the image's headers locate, where the debug information
    /// records no group (lld-link leaves such holes; link.exe never makes a
    /// group for base relocations).
    Table(TableKind),
}

/// A table located by the image's headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TableKind {
    Exports,
    BaseRelocations,
    LoadConfig,
    /// The debug directory.
    DebugDirectory,
    /// The data of a debug directory entry, by its type (`IMAGE_DEBUG_TYPE_*`).
    DebugData(u32),
    /// The delay-load import descriptors.
    DelayImportDescriptors,
    /// Control Flow Guard's table of valid call targets.
    CfgFunctions,
    /// Control Flow Guard's table of address-taken import entries.
    CfgAddressTakenImports,
    /// Delay-load import address tables (the n-th run of them).
    DelayImportThunks(u32),
    /// Delay-load DLL names and hint/name entries (the n-th run).
    DelayImportNames(u32),
    /// Delay-load module handles (the n-th run).
    DelayImportHandles(u32),
}

impl TableKind {
    /// A name for the table, in the bracketed form used for synthetic labels.
    pub fn label(&self) -> String {
        let n = |i: &u32| {
            if *i == 0 {
                String::new()
            } else {
                format!(" #{}", i + 1)
            }
        };
        match self {
            TableKind::Exports => "[exports]".into(),
            TableKind::BaseRelocations => "[base relocations]".into(),
            TableKind::LoadConfig => "[load config]".into(),
            TableKind::DebugDirectory => "[debug directory]".into(),
            TableKind::DebugData(t) => format!("[debug data: {}]", report::debug_type_name(*t)),
            TableKind::DelayImportDescriptors => "[delay-load descriptors]".into(),
            TableKind::CfgFunctions => "[CFG function table]".into(),
            TableKind::CfgAddressTakenImports => "[CFG address-taken IAT table]".into(),
            TableKind::DelayImportThunks(i) => format!("[delay-load IAT{}]", n(i)),
            TableKind::DelayImportNames(i) => format!("[delay-load names{}]", n(i)),
            TableKind::DelayImportHandles(i) => format!("[delay-load module handles{}]", n(i)),
        }
    }
}

/// A named part of a section (a COFF group for PE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Unique among the model's groups (duplicates are disambiguated).
    pub name: String,
    /// The index of the containing section.
    pub section: u32,
    pub addr: u64,
    pub size: Size,
    /// Bytes from the end of the group to the next group (or the end of
    /// the section), in the file and in memory: alignment padding.
    pub padding: Size,
    pub characteristics: u32,
    pub origin: GroupOrigin,
}

impl Group {
    /// Whether the group occupies memory but no file bytes.
    pub fn zero_fill(&self) -> bool {
        self.size.file == 0 && self.size.vm > 0
    }

    /// The extent of the group in memory (at least its file extent).
    pub fn extent(&self) -> u64 {
        self.size.file.max(self.size.vm)
    }
}

/// A library (archive), or a place-holder for compilands with none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Library {
    /// Its path; empty if unknown.
    pub name: String,
}

/// A translation unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiland {
    /// Its name, normally its object's path; empty if unknown.
    pub name: String,
    pub library: u32,
}

/// No group: a piece in a section with no group covering it.
pub const NO_GROUP: u32 = u32::MAX;

/// An address range contributed by a compiland.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Piece {
    pub range: Range,
    pub compiland: u32,
    pub section: u32,
    /// The group, or [`NO_GROUP`].
    pub group: u32,
}

/// The size model of an image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Model {
    pub arch: Option<Arch>,
    /// Sorted by address.
    pub sections: Vec<Section>,
    /// Sorted by address.
    pub groups: Vec<Group>,
    pub libraries: Vec<Library>,
    pub compilands: Vec<Compiland>,
    /// Sorted by address.
    pub pieces: Vec<Piece>,
}

/// The ranges and total size of one key of a pivot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// Merged where they touch or overlap (separately for file and
    /// zero-fill ranges), sorted by address.
    pub ranges: Vec<Range>,
    pub size: Size,
}

impl Model {
    /// The pieces grouped by `key` (pieces it maps to `None` are left out),
    /// with each key's ranges merged where they touch or overlap, and its
    /// total size.
    pub fn totals<K: Ord>(&self, mut key: impl FnMut(&Piece) -> Option<K>) -> BTreeMap<K, Totals> {
        let mut out: BTreeMap<K, Totals> = BTreeMap::new();
        for piece in &self.pieces {
            if let Some(k) = key(piece) {
                range::push_coalescing(&mut out.entry(k).or_default().ranges, piece.range, 0);
            }
        }
        for t in out.values_mut() {
            // Pieces are sorted by address, but a key's file and zero-fill
            // ranges can interleave; `push_coalescing` keeps them apart.
            let (file, vm) = range::totals(&t.ranges);
            t.size = Size::new(file, vm);
        }
        out
    }

    /// The library of a compiland.
    pub fn library_of(&self, compiland: u32) -> u32 {
        self.compilands[compiland as usize].library
    }

    /// The groups of a section, in address order.
    pub fn section_groups(&self, section: u32) -> impl Iterator<Item = (u32, &Group)> + '_ {
        self.groups
            .iter()
            .enumerate()
            .filter(move |(_, g)| g.section == section)
            .map(|(i, g)| (i as u32, g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(addr: u64, len: u64, compiland: u32, section: u32) -> Piece {
        Piece {
            range: Range::new(addr, len, false),
            compiland,
            section,
            group: NO_GROUP,
        }
    }

    #[test]
    fn size_arithmetic_saturates() {
        let mut s = Size::new(1, 2) + Size::new(3, 4);
        assert_eq!(s, Size::new(4, 6));
        s += Size::new(u64::MAX, 0);
        assert_eq!(s, Size::new(u64::MAX, 6));
    }

    #[test]
    fn totals_by_key() {
        let model = Model {
            compilands: vec![
                Compiland {
                    name: "a.obj".into(),
                    library: 0,
                },
                Compiland {
                    name: "b.obj".into(),
                    library: 0,
                },
            ],
            pieces: vec![
                piece(0x1000, 0x10, 0, 0),
                piece(0x1010, 0x10, 1, 0),
                piece(0x1020, 0x10, 0, 0),
                piece(0x2000, 0x08, 0, 1),
                Piece {
                    range: Range::new(0x3000, 0x40, true),
                    compiland: 1,
                    section: 2,
                    group: NO_GROUP,
                },
            ],
            ..Model::default()
        };
        let by_compiland = model.totals(|p| Some(p.compiland));
        assert_eq!(by_compiland[&0].size, Size::new(0x28, 0x28));
        assert_eq!(by_compiland[&0].ranges.len(), 3);
        assert_eq!(by_compiland[&1].size, Size::new(0x10, 0x50));

        // Merging across compilands when the key ignores them.
        let by_section = model.totals(|p| Some(p.section));
        assert_eq!(by_section[&0].ranges, [Range::new(0x1000, 0x30, false)]);
        assert_eq!(by_section[&2].size, Size::new(0, 0x40));

        // Filtering.
        let only_code = model.totals(|p| (p.section == 0).then_some(()));
        assert_eq!(only_code.len(), 1);
        assert_eq!(only_code[&()].size.file, 0x30);
        assert!(model.totals(|_| None::<u8>).is_empty());
    }

    #[test]
    fn group_extent_and_zero_fill() {
        let g = Group {
            name: ".bss".into(),
            section: 0,
            addr: 0,
            size: Size::new(0, 100),
            padding: Size::default(),
            characteristics: 0,
            origin: GroupOrigin::DebugInfo,
        };
        assert!(g.zero_fill());
        assert_eq!(g.extent(), 100);
        let g = Group {
            size: Size::new(8, 8),
            ..g
        };
        assert!(!g.zero_fill());
        assert_eq!(g.extent(), 8);
        let g = Group {
            size: Size::new(0, 0),
            ..g
        };
        assert!(!g.zero_fill());
    }

    #[test]
    fn table_labels() {
        assert_eq!(TableKind::BaseRelocations.label(), "[base relocations]");
        assert_eq!(TableKind::DebugData(2).label(), "[debug data: CodeView]");
        assert_eq!(TableKind::DelayImportThunks(0).label(), "[delay-load IAT]");
        assert_eq!(
            TableKind::DelayImportThunks(1).label(),
            "[delay-load IAT #2]"
        );
    }
}

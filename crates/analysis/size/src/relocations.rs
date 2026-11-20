//! An image's relocations: what the loader patches when it loads it (ELF's
//! dynamic relocations, packed relative ones too; PE's base relocations;
//! Mach-O's rebases and binds), each with its type, where it is, what it
//! points to, and its share of the table it's in ([`relocations`]).
//!
//! Each costs the image twice: its entry in a table (24 bytes for an ELF
//! `Elf64_Rela`, a fraction of a byte packed as RELR, 2 bytes and a share
//! of a block's header in PE, a share of a Mach-O fixup table), and the
//! page it patches, which the loader writes and so can't share with other
//! processes. Pointer-heavy data (vtables, tables of string pointers)
//! is most of an image's relocations; [`pointer_tables`] measures what
//! storing offsets instead would save.

use rustc_hash::FxHashMap;

/// One relocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// The address it patches.
    pub addr: u64,
    /// Its type: `R_X86_64_RELATIVE`, `RELR` (a packed relative one),
    /// `DIR64`, `rebase`, `bind`, ...
    pub kind: String,
    /// The table it's in (an index into [`Relocations::tables`]).
    pub table: u32,
    /// What it points to, if an address in the image.
    pub target: Option<u64>,
    /// The symbol it binds, if it binds one by name (an import, or an
    /// ELF symbolic relocation's symbol).
    pub symbol: Option<String>,
    /// Whether it's relative (the image's own address, moved with it; as
    /// against a symbol's address, resolved by name).
    pub relative: bool,
}

/// A table of relocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    /// Its name: a section's (`.rela.dyn`, `.relr.dyn`, `.reloc`) or a
    /// Mach-O table's (`chained fixups`, `rebase opcodes`, `bind opcodes`).
    pub name: String,
    /// Its bytes.
    pub size: u64,
    /// How many relocations it holds.
    pub entries: u64,
}

/// An image's relocations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relocations {
    pub tables: Vec<Table>,
    /// By address.
    pub list: Vec<Relocation>,
    /// The width of a pointer, in bytes.
    pub word: u8,
}

impl Relocations {
    /// The table bytes `items` (indexes into `list`) take: each one's
    /// share of its table.
    pub fn cost(&self, items: impl IntoIterator<Item = usize>) -> f64 {
        items.into_iter().map(|i| self.share(&self.list[i])).sum()
    }

    /// A relocation's share of its table's bytes.
    pub fn share(&self, r: &Relocation) -> f64 {
        let t = &self.tables[r.table as usize];
        if t.entries == 0 {
            0.0
        } else {
            t.size as f64 / t.entries as f64
        }
    }

    /// Their tables' bytes.
    pub fn total(&self) -> u64 {
        self.tables.iter().map(|t| t.size).sum()
    }
}

/// An image's relocations (none for an object, or a format without them).
pub fn relocations(image: &hexcavator_image::Image<'_>) -> Relocations {
    let slots: FxHashMap<u64, Option<u64>> = image
        .pointer_slots()
        .into_iter()
        .map(|p| (p.addr, p.target))
        .collect();
    let mut out = if let Some(elf) = image.elf() {
        elf_relocations(elf, &slots)
    } else if let Some(pe) = image.pe() {
        pe_relocations(pe, image.image_base(), &slots)
    } else if let Some(m) = image.macho() {
        macho_relocations(m)
    } else {
        Relocations::default()
    };
    out.list.sort_by_key(|r| r.addr);
    out
}

fn elf_relocations(
    elf: &hexcavator_elf::ElfFile<'_>,
    slots: &FxHashMap<u64, Option<u64>>,
) -> Relocations {
    use hexcavator_elf::consts::*;
    let word: u8 = if elf.class() == hexcavator_elf::Class::Elf64 {
        8
    } else {
        4
    };
    let mut out = Relocations {
        word,
        ..Relocations::default()
    };
    if elf.is_object() {
        return out;
    }
    let machine = elf.header().machine;
    let relative = relative_type(machine);
    let sections: Vec<_> = elf.sections().collect();
    let dynsym = sections
        .iter()
        .find(|s| s.kind == SHT_DYNSYM)
        .map(|s| elf.symbols(s))
        .unwrap_or_default();
    for s in sections.iter().filter(|s| s.is_alloc()) {
        let table = out.tables.len() as u32;
        let mut entries = 0u64;
        if s.kind == SHT_RELA || s.kind == SHT_REL {
            for r in elf.relocations(s) {
                let kind = hexcavator_elf::spelling::relocation(machine, r.kind)
                    .map_or_else(|| format!("type {}", r.kind), str::to_string);
                let sym = (r.symbol != 0)
                    .then(|| dynsym.get(r.symbol as usize))
                    .flatten();
                let is_relative = Some(r.kind) == relative || r.symbol == 0;
                let target = slots.get(&r.offset).copied().flatten().or_else(|| {
                    let s = sym.filter(|s| s.shndx != u32::from(SHN_UNDEF))?;
                    Some(s.value.wrapping_add_signed(r.addend.unwrap_or(0)))
                });
                out.list.push(Relocation {
                    addr: r.offset,
                    kind,
                    table,
                    target,
                    symbol: sym
                        .filter(|s| !s.name.is_empty())
                        .map(|s| String::from_utf8_lossy(s.name).into_owned()),
                    relative: is_relative,
                });
                entries += 1;
            }
        } else if s.kind == SHT_RELR || s.kind == SHT_ANDROID_RELR {
            for at in elf.relr(s) {
                out.list.push(Relocation {
                    addr: at,
                    kind: "RELR".into(),
                    table,
                    target: slots.get(&at).copied().flatten(),
                    symbol: None,
                    relative: true,
                });
                entries += 1;
            }
        } else {
            continue;
        }
        out.tables.push(Table {
            name: String::from_utf8_lossy(s.name).into_owned(),
            size: s.size,
            entries,
        });
    }
    out
}

/// The relative relocation type of `machine`.
fn relative_type(machine: u16) -> Option<u32> {
    use hexcavator_elf::consts::*;
    Some(match machine {
        EM_X86_64 | EM_386 => 8,
        EM_AARCH64 => 1027,
        EM_ARM => 23,
        EM_RISCV => 3,
        EM_PPC64 => 22,
        _ => return None,
    })
}

fn pe_relocations(
    pe: &hexcavator_pe::PeFile<'_>,
    base: u64,
    slots: &FxHashMap<u64, Option<u64>>,
) -> Relocations {
    use hexcavator_pe::reloc::base_reloc as kind;
    let word: u8 = if pe
        .optional_header()
        .is_some_and(hexcavator_pe::OptionalHeader::is_64)
    {
        8
    } else {
        4
    };
    let mut out = Relocations {
        word,
        ..Relocations::default()
    };
    // (The directory's bytes, padding and block headers among them.)
    let size = pe
        .data_directory(hexcavator_pe::consts::directory::BASERELOC)
        .map_or(0, |d| u64::from(d.size.get()));
    for r in pe.base_relocs() {
        let name = match r.kind {
            // (Padding: in the table's bytes, not a relocation.)
            kind::ABSOLUTE => continue,
            kind::HIGH => "HIGH",
            kind::LOW => "LOW",
            kind::HIGHLOW => "HIGHLOW",
            kind::HIGHADJ => "HIGHADJ",
            kind::DIR64 => "DIR64",
            k => {
                out.list.push(Relocation {
                    addr: u64::from(r.rva.0),
                    kind: format!("type {k}"),
                    table: 0,
                    target: None,
                    symbol: None,
                    relative: true,
                });
                continue;
            }
        };
        // (Images are analyzed by RVA: a target is one too.)
        let at = u64::from(r.rva.0);
        let target = slots
            .get(&at)
            .copied()
            .flatten()
            .map(|t| if t >= base { t - base } else { t });
        out.list.push(Relocation {
            addr: at,
            kind: name.into(),
            table: 0,
            target,
            symbol: None,
            relative: true,
        });
    }
    out.tables.push(Table {
        name: ".reloc".into(),
        size,
        entries: out.list.len() as u64,
    });
    out
}

fn macho_relocations(m: &hexcavator_macho::MachO<'_>) -> Relocations {
    use hexcavator_macho::FixupKind;
    use hexcavator_macho::consts::*;
    let mut out = Relocations {
        word: if m.header().is64 { 8 } else { 4 },
        ..Relocations::default()
    };
    if m.is_object() {
        return out;
    }
    // The tables: chained fixups' (one), or the opcodes' (rebases', and
    // binds' of every kind).
    let mut chained = None;
    let mut opcodes = None;
    for lc in m.load_commands() {
        match lc.cmd {
            LC_DYLD_CHAINED_FIXUPS => chained = m.linkedit_data(&lc).map(|(_, size)| size),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                opcodes = m
                    .dyld_info(&lc)
                    .map(|i| (i.rebase.1, i.bind.1 + i.weak_bind.1 + i.lazy_bind.1));
            }
            _ => {}
        }
    }
    let (rebases, binds) = match (chained, opcodes) {
        (Some(size), _) => {
            out.tables.push(Table {
                name: "chained fixups".into(),
                size: u64::from(size),
                entries: 0,
            });
            (0, 0)
        }
        (None, Some((rebase, bind))) => {
            out.tables.push(Table {
                name: "rebase opcodes".into(),
                size: u64::from(rebase),
                entries: 0,
            });
            out.tables.push(Table {
                name: "bind opcodes".into(),
                size: u64::from(bind),
                entries: 0,
            });
            (0, 1)
        }
        (None, None) => return out,
    };
    for f in m.fixups() {
        let (kind, table, target, symbol, relative) = match f.kind {
            FixupKind::Rebase { target } => ("rebase", rebases, Some(target), None, true),
            FixupKind::Bind { symbol, .. } => (
                "bind",
                binds,
                None,
                Some(String::from_utf8_lossy(symbol).into_owned()),
                false,
            ),
        };
        out.tables[table as usize].entries += 1;
        out.list.push(Relocation {
            addr: f.addr,
            kind: kind.into(),
            table,
            target,
            symbol,
            relative,
        });
    }
    out
}

/// A table of pointers: data (a vtable, an array of string pointers) whose
/// relative relocations an offset table would do without.
#[derive(Clone, Debug, PartialEq)]
pub struct PointerTable {
    /// The data's name.
    pub name: String,
    /// How many relative relocations patch it.
    pub pointers: u64,
    /// What they cost: their tables' bytes, and the bytes 32-bit offsets
    /// would save over the pointers (none with 32-bit pointers).
    pub relocations: f64,
    pub narrower: u64,
}

/// The data among `symbols` ((start, end, name), by start) with at least
/// `min` relative relocations patching it, most costly first: what storing
/// 32-bit offsets (from the table, or into one blob of strings) instead of
/// pointers would save, the relocations and the pointers' width beyond 4
/// bytes. (A table of code pointers, a vtable's, can't be offsets in C++
/// as it is; clang's relative vtables, -fexperimental-relative-c++-abi-
/// vtables, make them so.)
pub fn pointer_tables(
    r: &Relocations,
    symbols: &[(u64, u64, String)],
    min: u64,
) -> Vec<PointerTable> {
    let mut by: FxHashMap<usize, (u64, f64)> = FxHashMap::default();
    for rel in r.list.iter().filter(|x| x.relative) {
        let Some(i) = containing(symbols, rel.addr) else {
            continue;
        };
        let e = by.entry(i).or_default();
        e.0 += 1;
        e.1 += r.share(rel);
    }
    let wider = u64::from(r.word.saturating_sub(4));
    let mut out: Vec<PointerTable> = by
        .into_iter()
        .filter(|(_, (n, _))| *n >= min)
        .map(|(i, (pointers, relocations))| PointerTable {
            name: symbols[i].2.clone(),
            pointers,
            relocations,
            narrower: pointers * wider,
        })
        .collect();
    out.sort_by(|a, b| {
        (b.relocations + b.narrower as f64)
            .total_cmp(&(a.relocations + a.narrower as f64))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// An image's own symbols (ELF's `.symtab`, or `.dynsym`; Mach-O's symbol
/// table), as (start, end, name) by start, for where relocations are
/// without debug information. A Mach-O symbol ends where the next in its
/// section starts.
pub fn image_symbols(image: &hexcavator_image::Image<'_>) -> Vec<(u64, u64, String)> {
    let mut out: Vec<(u64, u64, String)> = Vec::new();
    if let Some(elf) = image.elf() {
        use hexcavator_elf::consts::*;
        let sections: Vec<_> = elf.sections().collect();
        let table = sections
            .iter()
            .find(|s| s.kind == SHT_SYMTAB)
            .or_else(|| sections.iter().find(|s| s.kind == SHT_DYNSYM));
        if let Some(t) = table {
            out = elf
                .symbols(t)
                .into_iter()
                .filter(|s| {
                    s.shndx != u32::from(SHN_UNDEF)
                        && s.shndx < u32::from(SHN_LORESERVE)
                        && s.size > 0
                        && !s.name.is_empty()
                        && matches!(s.kind, STT_OBJECT | STT_FUNC | STT_NOTYPE | 10)
                })
                .map(|s| {
                    (
                        s.value,
                        s.value + s.size,
                        String::from_utf8_lossy(s.name).into_owned(),
                    )
                })
                .collect();
        }
    } else if let Some(m) = image.macho() {
        let mut syms: Vec<(u64, u8, String)> = m
            .symbols()
            .into_iter()
            .filter(|s| s.is_section_defined() && !s.name.is_empty())
            .map(|s| {
                (
                    s.n_value,
                    s.n_sect,
                    String::from_utf8_lossy(s.name).into_owned(),
                )
            })
            .collect();
        syms.sort();
        syms.dedup_by(|a, b| a.0 == b.0);
        let sections = m.sections();
        for (i, (at, sect, name)) in syms.iter().enumerate() {
            let end = syms
                .get(i + 1)
                .filter(|n| n.1 == *sect)
                .map(|n| n.0)
                .or_else(|| {
                    let s = sections.get(usize::from(*sect).checked_sub(1)?)?;
                    Some(s.addr + s.size)
                })
                .unwrap_or(*at);
            if end > *at {
                out.push((*at, end, name.clone()));
            }
        }
    }
    out.sort_by_key(|s| s.0);
    out
}

/// The symbol of `symbols` ((start, end, name), by start) that holds
/// `at`: the one starting last at or before it that reaches past it (one
/// may hold others: a vtable, the debug information's variable for its
/// address point).
pub fn containing(symbols: &[(u64, u64, String)], at: u64) -> Option<usize> {
    let i = symbols.partition_point(|s| s.0 <= at);
    (i.saturating_sub(16)..i).rev().find(|&j| at < symbols[j].1)
}

/// `primary` ((start, end, name), by start) with those of `secondary` no
/// one of it holds whole added, by start: the debug information's symbols,
/// say, with the image's own where it describes less (line tables only
/// describe no variables; a vtable is described by its address point).
pub fn merge_symbols(
    primary: Vec<(u64, u64, String)>,
    secondary: Vec<(u64, u64, String)>,
) -> Vec<(u64, u64, String)> {
    let mut out = primary;
    let covered = |at: u64, end: u64, list: &[(u64, u64, String)]| {
        let i = list.partition_point(|s| s.0 <= at);
        list[i.saturating_sub(16)..i].iter().any(|s| s.1 >= end)
    };
    let extra: Vec<(u64, u64, String)> = secondary
        .into_iter()
        .filter(|s| !covered(s.0, s.1, &out))
        .collect();
    out.extend(extra);
    out.sort_by_key(|s| s.0);
    out
}

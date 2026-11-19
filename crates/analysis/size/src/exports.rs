//! What an image's exported symbols cost, and what hiding them would save
//! (see [`recommend`]): each export's entry in the dynamic symbol table,
//! its name, its hash entries, and its version (ELF), or its share of the
//! exports trie (Mach-O); and, in an ELF shared object, the library's calls
//! to its own exported functions, which go through the PLT (a PLT entry, a
//! GOT slot, and a relocation each) because another library might replace
//! them.
//!
//! Exports are measured from the image; whether one may be hidden isn't
//! (a library's API is what others import), except for what's never API:
//! a C++ library's inline functions and template instantiations (vague
//! linkage: weak definitions). The rest are hidable when the importers
//! given (the executables and libraries that load the image) don't import
//! them ([`Imports`]).

use rustc_hash::FxHashSet;

use crate::recommend::{MIN_SAVING, Recommendation};

/// An exported symbol, and what it costs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export<'d> {
    /// Its (mangled) name, as importers name it (Mach-O's with its `_`).
    pub name: &'d [u8],
    /// The bytes its export costs: its symbol, name, hash, and version
    /// entries (ELF), or its share of the exports trie (Mach-O).
    pub table: u64,
    /// The bytes of the PLT entry, GOT slot, and relocation by which the
    /// library calls it (ELF; 0 if it doesn't).
    pub plt: u64,
    /// A function.
    pub function: bool,
    /// Of vague linkage: a C++ inline function or template instantiation
    /// (a weak definition of an Itanium-mangled function).
    pub vague: bool,
}

/// What kind of image exports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exporter {
    /// An ELF shared object or PIE (with a dynamic symbol table).
    ElfShared,
    /// A Mach-O dylib or bundle.
    MachOLibrary,
    /// A Mach-O executable (which exports its global symbols by default).
    MachOExecutable,
}

/// An image's exports.
#[derive(Clone, Debug)]
pub struct Exports<'d> {
    pub exporter: Exporter,
    /// Its name as importers record it: an ELF `DT_SONAME` (or else the
    /// file name), a Mach-O install name (if any).
    pub name: Option<&'d [u8]>,
    pub list: Vec<Export<'d>>,
}

/// The JUMP_SLOT relocation type of `machine`.
fn jump_slot_type(machine: u16) -> Option<u32> {
    use hexcavator_elf::consts::*;
    Some(match machine {
        EM_X86_64 | EM_386 => 7,
        EM_AARCH64 => 1026,
        EM_ARM => 22,
        EM_RISCV => 5,
        EM_PPC64 => 21,
        _ => return None,
    })
}

/// `STB_GNU_UNIQUE`: a vague-linkage object every library shares.
const STB_GNU_UNIQUE: u8 = 10;

/// Symbols every ELF shared object defines that its linker makes, which
/// hiding the rest leaves (or which aren't API either way).
fn linker_defined(name: &[u8]) -> bool {
    matches!(
        name,
        b"_init"
            | b"_fini"
            | b"_edata"
            | b"_end"
            | b"__bss_start"
            | b"_DYNAMIC"
            | b"_GLOBAL_OFFSET_TABLE_"
    )
}

/// An image's exports, if it's an ELF shared object (or PIE) with a
/// dynamic symbol table, or a Mach-O image with an exports trie.
pub fn exports<'d>(image: &hexcavator_image::Image<'d>) -> Option<Exports<'d>> {
    if let Some(elf) = image.elf() {
        return elf_exports(elf);
    }
    if let Some(m) = image.macho() {
        return macho_exports(m);
    }
    None
}

fn elf_exports<'d>(elf: &hexcavator_elf::ElfFile<'d>) -> Option<Exports<'d>> {
    use hexcavator_elf::consts::*;
    if elf.is_object() {
        return None;
    }
    let sections: Vec<_> = elf.sections().collect();
    let dynsym = sections.iter().find(|s| s.kind == SHT_DYNSYM)?;
    let symbols = elf.symbols(dynsym);
    let word: u64 = if elf.class() == hexcavator_elf::Class::Elf64 {
        8
    } else {
        4
    };
    let entry = if dynsym.entsize != 0 {
        dynsym.entsize
    } else {
        3 * word
    };
    let defined = symbols
        .iter()
        .filter(|s| s.shndx != u32::from(SHN_UNDEF))
        .count() as u64;
    let size_of = |kind: u32| {
        sections
            .iter()
            .find(|s| s.kind == kind)
            .map_or(0, |s| s.size)
    };
    let versym = if size_of(SHT_GNU_VERSYM) > 0 { 2 } else { 0 };
    // Each defined symbol's share of .gnu.hash (its chain word, and the
    // buckets and Bloom filter among them); each symbol's of .hash.
    let gnu_hash = size_of(SHT_GNU_HASH);
    let sysv_hash = size_of(SHT_HASH);
    let share = |total: u64, count: u64| total.checked_div(count).unwrap_or(0);
    let hash = share(gnu_hash, defined) + share(sysv_hash, symbols.len() as u64);
    // The library's calls to its own exported functions: JUMP_SLOT
    // relocations of symbols it defines, each with its share of the PLT
    // (.plt, and .plt.sec with IBT), a GOT slot, and the relocation.
    let mut plt_of: rustc_hash::FxHashMap<u32, u64> = rustc_hash::FxHashMap::default();
    if let Some(jump) = jump_slot_type(elf.header().machine) {
        let plt_size: u64 = sections
            .iter()
            .filter(|s| s.kind == SHT_PROGBITS && (s.name == b".plt" || s.name == b".plt.sec"))
            .map(|s| s.size)
            .sum();
        let mut slots: Vec<(u32, u64)> = Vec::new();
        for s in sections
            .iter()
            .filter(|s| (s.kind == SHT_RELA || s.kind == SHT_REL) && s.is_alloc())
        {
            let rel = if s.entsize != 0 {
                s.entsize
            } else if s.kind == SHT_RELA {
                3 * word
            } else {
                2 * word
            };
            for r in elf.relocations(s) {
                if r.kind == jump {
                    slots.push((r.symbol, rel));
                }
            }
        }
        let plt_share = share(plt_size, slots.len() as u64);
        for (sym, rel) in slots {
            let Some(s) = symbols.get(sym as usize) else {
                continue;
            };
            if s.shndx != u32::from(SHN_UNDEF) && s.visibility == STV_DEFAULT {
                *plt_of.entry(sym).or_default() += plt_share + word + rel;
            }
        }
    }
    let list = symbols
        .iter()
        .filter(|s| {
            s.shndx != u32::from(SHN_UNDEF)
                && matches!(s.bind, STB_GLOBAL | STB_WEAK | STB_GNU_UNIQUE)
                && matches!(s.visibility, STV_DEFAULT | STV_PROTECTED)
                && !s.name.is_empty()
                && !linker_defined(s.name)
        })
        .map(|s| {
            let function = matches!(s.kind, STT_FUNC | 10);
            Export {
                name: s.name,
                table: entry + s.name.len() as u64 + 1 + versym + hash,
                plt: plt_of.get(&(s.index as u32)).copied().unwrap_or(0),
                function,
                vague: function && s.bind == STB_WEAK && s.name.starts_with(b"_Z"),
            }
        })
        .collect();
    let name = elf
        .dynamic()
        .iter()
        .find(|d| d.tag == DT_SONAME)
        .and_then(|d| dynstr(elf, &sections, d.value));
    Some(Exports {
        exporter: Exporter::ElfShared,
        name,
        list,
    })
}

/// The string at `offset` in the dynamic string table.
fn dynstr<'d>(
    elf: &hexcavator_elf::ElfFile<'d>,
    sections: &[hexcavator_elf::Section<'d>],
    offset: u64,
) -> Option<&'d [u8]> {
    let s = sections.iter().find(|s| s.name == b".dynstr")?;
    let data = elf.section_data(s).get(usize::try_from(offset).ok()?..)?;
    Some(&data[..data.iter().position(|&b| b == 0)?])
}

fn macho_exports<'d>(m: &hexcavator_macho::MachO<'d>) -> Option<Exports<'d>> {
    use hexcavator_macho::consts::*;
    use hexcavator_macho::fixups::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
    let trie = m.export_trie();
    if trie.is_empty() {
        return None;
    }
    let exporter = match m.header().filetype {
        MH_EXECUTE => Exporter::MachOExecutable,
        MH_DYLIB | MH_BUNDLE => Exporter::MachOLibrary,
        _ => return None,
    };
    let exports = m.exports();
    // Names are borrowed from the symbol table (the trie's are built).
    let names: rustc_hash::FxHashMap<&[u8], (&'d [u8], u8)> = m
        .symbols()
        .into_iter()
        .filter(|s| s.is_section_defined() && s.n_type & N_EXT != 0)
        .map(|s| (s.name, (s.name, s.n_sect)))
        .collect();
    let code: FxHashSet<u8> = m
        .sections()
        .iter()
        .filter(|s| s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0)
        .filter_map(|s| u8::try_from(s.index + 1).ok())
        .collect();
    let share = trie.len() as u64 / exports.len().max(1) as u64;
    let list = exports
        .iter()
        .filter(|e| e.reexport.is_none() && e.name != b"__mh_execute_header")
        .filter_map(|e| {
            let &(name, sect) = names.get(e.name.as_slice())?;
            let function = code.contains(&sect);
            Some(Export {
                name,
                table: share,
                plt: 0,
                function,
                vague: function
                    && e.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0
                    && name.starts_with(b"__Z"),
            })
        })
        .collect();
    let name = m
        .load_commands()
        .iter()
        .find(|c| c.cmd == LC_ID_DYLIB)
        .and_then(|c| {
            let off = usize::try_from(read32(m, c.data, 8)?).ok()?;
            let s = c.data.get(off..)?;
            Some(&s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())])
        });
    Some(Exports {
        exporter,
        name,
        list,
    })
}

fn read32(m: &hexcavator_macho::MachO<'_>, d: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = d.get(at..at + 4)?.try_into().ok()?;
    Some(if m.header().endian == hexcavator_core::Endian::Big {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    })
}

/// What importers import of an image: the names the executables and
/// libraries that load it leave undefined.
#[derive(Clone, Debug, Default)]
pub struct Imports {
    /// The importers read (those that load the image).
    pub importers: usize,
    /// The names they import (as they name them).
    pub names: FxHashSet<Vec<u8>>,
}

/// What an importer (`data`, an ELF or Mach-O image) imports of the image
/// named `name` (its `DT_SONAME` or install name, or file name): its
/// undefined symbols, if it loads that image (`DT_NEEDED`, a Mach-O
/// dylib command), or any image when `name` is `None`.
pub fn imports_of(data: &[u8], name: Option<&[u8]>) -> Option<Vec<Vec<u8>>> {
    let image = hexcavator_image::Image::parse(data).ok()?;
    let base = |p: &[u8]| -> Vec<u8> {
        p.rsplit(|&c| c == b'/' || c == b'\\')
            .next()
            .unwrap_or(p)
            .to_vec()
    };
    if let Some(elf) = image.elf() {
        use hexcavator_elf::consts::*;
        let sections: Vec<_> = elf.sections().collect();
        if let Some(want) = name {
            let needed = elf
                .dynamic()
                .iter()
                .filter(|d| d.tag == DT_NEEDED)
                .filter_map(|d| dynstr(elf, &sections, d.value))
                .any(|n| n == want || base(n) == base(want));
            if !needed {
                return None;
            }
        }
        let dynsym = sections.iter().find(|s| s.kind == SHT_DYNSYM)?;
        return Some(
            elf.symbols(dynsym)
                .into_iter()
                .filter(|s| s.shndx == u32::from(SHN_UNDEF) && !s.name.is_empty())
                .map(|s| s.name.to_vec())
                .collect(),
        );
    }
    if let Some(m) = image.macho() {
        use hexcavator_macho::consts::*;
        if let Some(want) = name {
            let loads = m
                .dylibs()
                .iter()
                .any(|d| d.name == want || base(d.name) == base(want));
            if !loads {
                return None;
            }
        }
        return Some(
            m.symbols()
                .into_iter()
                .filter(|s| !s.is_stab() && s.n_type & N_TYPE == N_UNDF && s.n_type & N_EXT != 0)
                .filter(|s| !s.name.is_empty())
                .map(|s| s.name.to_vec())
                .collect(),
        );
    }
    None
}

/// How many examples a recommendation lists.
const EXAMPLES: usize = 5;

/// The recommendations an image's exports make (each saving at least
/// [`MIN_SAVING`] bytes; names demangled by `name`):
///
/// - `vague-linkage`: its exported template instantiations and inline
///   functions (`-fvisibility=hidden`; `-fvisibility-inlines-hidden` hides
///   only inline member functions, and the image doesn't say which are
///   which), their entries and the
///   library's calls to them through the PLT.
/// - `bsymbolic`: an ELF library's calls to its other exported functions
///   through the PLT (`-Bsymbolic-functions`, `-fno-semantic-interposition`).
/// - `visibility`: the rest of its exports, those `imports` (if given)
///   don't name (`-fvisibility=hidden`, a version script, or an exported
///   symbols list); for a Mach-O executable, which exports its global
///   symbols by default, all of them unless given.
pub fn recommend(
    exports: &Exports<'_>,
    imports: Option<&Imports>,
    name: &dyn Fn(&[u8]) -> String,
) -> Vec<Recommendation> {
    let mut out = Vec::new();
    let elf = exports.exporter == Exporter::ElfShared;
    let examples = |list: &[&Export<'_>], cost: &dyn Fn(&Export<'_>) -> u64| {
        let mut v: Vec<(String, u64)> = list.iter().map(|e| (name(e.name), cost(e))).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(EXAMPLES);
        v
    };
    // Inline functions and template instantiations.
    let vague: Vec<&Export<'_>> = exports.list.iter().filter(|e| e.vague).collect();
    let all = |e: &Export<'_>| e.table + e.plt;
    let saving: u64 = vague.iter().map(|e| all(e)).sum();
    if saving >= MIN_SAVING {
        let calls = vague.iter().filter(|e| e.plt > 0).count();
        out.push(Recommendation {
            kind: "vague-linkage",
            advice: format!(
                "compile with -fvisibility=hidden, marking its API visible (-fvisibility-inlines-hidden hides only inline member functions): it exports {} template instantiations and inline functions, which importers make their own copies of{}",
                vague.len(),
                if calls > 0 {
                    format!(", and {calls} of them called through the PLT")
                } else {
                    String::new()
                }
            ),
            saving,
            examples: examples(&vague, &all),
        });
    }
    // Calls through the PLT to the library's other exports.
    if elf {
        let called: Vec<&Export<'_>> = exports
            .list
            .iter()
            .filter(|e| !e.vague && e.plt > 0)
            .collect();
        let saving: u64 = called.iter().map(|e| e.plt).sum();
        if saving >= MIN_SAVING {
            out.push(Recommendation {
                kind: "bsymbolic",
                advice: format!(
                    "link with -Wl,-Bsymbolic-functions (or compile with -fno-semantic-interposition): it calls {} of its own exported functions through the PLT, as if another library might replace them",
                    called.len()
                ),
                saving,
                examples: examples(&called, &|e| e.plt),
            });
        }
    }
    // The rest, unless imported.
    let executable = exports.exporter == Exporter::MachOExecutable;
    if imports.is_some() || executable {
        let hidable: Vec<&Export<'_>> = exports
            .list
            .iter()
            .filter(|e| !e.vague && imports.is_none_or(|i| !i.names.contains(e.name)))
            .collect();
        let saving: u64 = hidable.iter().map(|e| e.table).sum();
        if saving >= MIN_SAVING {
            let by = |i: &Imports| match i.importers {
                0 => "any importer (none of those given loads it)".to_string(),
                1 => "the importer given".to_string(),
                n => format!("any of the {n} importers given"),
            };
            let advice = match (exports.exporter, imports) {
                (Exporter::MachOExecutable, None) => Some(format!(
                    "link with -Wl,-no_exported_symbols (or compile with -fvisibility=hidden): an executable exports its global symbols, {} here, which only plugins it loads could use",
                    hidable.len()
                )),
                (Exporter::ElfShared, Some(i)) => Some(format!(
                    "compile with -fvisibility=hidden, marking what's imported visible (or link with a version script exporting only it): {} exported symbols aren't imported by {}",
                    hidable.len(),
                    by(i)
                )),
                (_, Some(i)) => Some(format!(
                    "compile with -fvisibility=hidden, marking what's imported visible (or link with -Wl,-exported_symbols_list): {} exported symbols aren't imported by {}",
                    hidable.len(),
                    by(i)
                )),
                // (Only an executable's are judged without importers.)
                (_, None) => None,
            };
            if let Some(advice) = advice {
                out.push(Recommendation {
                    kind: "visibility",
                    advice,
                    saving,
                    examples: examples(&hidable, &|e| e.table),
                });
            }
        }
    }
    out
}

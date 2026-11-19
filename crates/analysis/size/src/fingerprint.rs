//! Fingerprints of a PE image's functions and data (see
//! `hexcavator_fingerprint`), over its cross-reference graph's nodes.
//!
//! Code is hashed from its instructions; data from its bytes with its
//! pointers (the base relocations in it) masked; imports by name. The
//! classes compare across images: two builds' functions with the same
//! class do the same thing and refer to things that are the same.

use hexcavator_fingerprint::{Item, Resolve, code, data, named, refine};
use hexcavator_image::Image;
use hexcavator_xref::Arch;

use crate::Model;
use crate::symbols::SymbolKind;
use crate::xref::Xref;

/// How many rounds of refinement at most (each splits classes until none
/// do; a chain of references this long is far past what images have).
const ROUNDS: usize = 64;

struct Nodes<'a>(&'a hexcavator_xref::Graph);

impl Resolve for Nodes<'_> {
    fn node_at(&self, address: u64) -> Option<u32> {
        self.0.node_at(address)
    }

    fn node_starting_at(&self, address: u64) -> Option<u32> {
        self.0.node_starting_at(address)
    }
}

/// What two nodes with the same class have in common.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// They do the same thing (for matching across builds): code and
    /// read-only data by contents, variables by name.
    Same,
    /// The linker could fold them into one (`/OPT:ICF`, `--icf=all`):
    /// COMDAT code and read-only COMDAT data by contents; everything else
    /// is only itself. On ELF, as lld's `--icf=all` folds: never a
    /// function with an LSDA (its exception table, which the linker
    /// doesn't compare), one in `.init` or `.fini` or a section named as a
    /// C identifier (which `__start_`/`__stop_` symbols enumerate), nor
    /// two in different output sections.
    Foldable,
}

/// Each node's local hash and references, its class, and its identity (a
/// name that says which node it is across builds: the import table's
/// `dll!function` for an import address table slot, else its name).
pub struct Fingerprints {
    pub items: Vec<Item>,
    pub classes: Vec<u64>,
    pub identities: Vec<String>,
}

/// Each slot that holds an import's address, and the import, by slot
/// address: PE's import address tables' (`dll!function`, or
/// `dll!#ordinal`), ELF's GOT and PLT entries for symbols it doesn't
/// define (`function`).
fn imports(image: &Image<'_>) -> rustc_hash::FxHashMap<u64, String> {
    use hexcavator_pe::imports::ImportName;
    let mut out = rustc_hash::FxHashMap::default();
    if let Some(elf) = image.elf() {
        use hexcavator_elf::consts::{SHN_UNDEF, SHT_REL, SHT_RELA};
        let sections: Vec<_> = elf.sections().collect();
        let machine = elf.header().machine;
        for s in sections
            .iter()
            .filter(|s| s.is_alloc() && (s.kind == SHT_REL || s.kind == SHT_RELA))
        {
            let symbols = sections
                .get(s.link as usize)
                .map(|t| elf.symbols(t))
                .unwrap_or_default();
            for r in elf.relocations(s) {
                if hexcavator_elf::address_relocation(machine, r.kind)
                    != Some(hexcavator_elf::AddressRelocation::Symbol)
                {
                    continue;
                }
                if let Some(sym) = symbols
                    .get(r.symbol as usize)
                    .filter(|sym| sym.shndx == u32::from(SHN_UNDEF) && !sym.name.is_empty())
                {
                    out.insert(r.offset, String::from_utf8_lossy(sym.name).into_owned());
                }
            }
        }
        return out;
    }
    let Some(file) = image.pe() else {
        return out;
    };
    let name = |dll: &[u8], import: ImportName<'_>| match import {
        ImportName::Name { name, .. } => {
            format!(
                "{}!{}",
                String::from_utf8_lossy(dll),
                String::from_utf8_lossy(name)
            )
        }
        ImportName::Ordinal(o) => format!("{}!#{o}", String::from_utf8_lossy(dll)),
    };
    for dll in file.imports() {
        for t in dll.thunks() {
            out.insert(u64::from(t.iat_rva.0), name(dll.name, t.import));
        }
    }
    for dll in file.delay_imports() {
        for t in dll.thunks() {
            out.insert(u64::from(t.iat_rva.0), name(dll.name, t.import));
        }
    }
    out
}

/// The functions an ELF image's `.eh_frame` gives an LSDA (a language's
/// exception table: catch clauses, cleanups), by address.
fn lsda_functions(image: &Image<'_>) -> rustc_hash::FxHashSet<u64> {
    use hexcavator_dwarf::cfi::{Cfi, CfiKind, Entry};
    let mut out = rustc_hash::FxHashSet::default();
    if image.elf().is_none() {
        return out;
    }
    for s in image
        .sections()
        .into_iter()
        .filter(|s| s.name == b".eh_frame" && s.file_size > 0)
    {
        let Some(data) = image.bytes_at(s.addr, s.file_size.min(s.vm_size)) else {
            continue;
        };
        let cfi = Cfi {
            data,
            kind: CfiKind::EhFrame,
            endian: image.endian(),
            address: s.addr,
            address_size: image.arch().pointer_size().unwrap_or(8),
            text_base: None,
            data_base: None,
        };
        for e in cfi.entries() {
            if let Entry::Fde(f) = e
                && f.lsda.is_some()
            {
                out.insert(f.pc_begin);
            }
        }
    }
    out
}

/// Whether ELF's linkers fold nothing in an output section named `name`:
/// `.init` and `.fini` (instructions run in order), and a name that is a C
/// identifier (its sections enumerated by `__start_` and `__stop_`).
fn elf_unfoldable(name: &str) -> bool {
    name == ".init"
        || name == ".fini"
        || name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The fingerprints of `x`'s nodes (of `image`, of any format), as `mode`
/// says.
pub fn build(image: &Image<'_>, model: &Model, x: &Xref, mode: Mode) -> Fingerprints {
    let graph = &x.graph;
    let resolve = Nodes(graph);
    // The pointers the loader fills: (slot, width, target), by slot.
    let pointers: Vec<(u64, u32, u64)> = image
        .pointer_slots()
        .into_iter()
        .filter_map(|p| Some((p.addr, u32::from(p.width), p.target?)))
        .collect();
    // A node's file bytes (what its section has in the file of it).
    let bytes = |start: u64, end: u64| -> &[u8] {
        let Some(sec) = model
            .sections
            .iter()
            .find(|s| start >= s.addr && start < s.addr + s.size.vm.max(s.size.file))
        else {
            return &[];
        };
        let available = (sec.addr + sec.size.file).saturating_sub(start);
        let len = (end - start).min(available);
        image.bytes_at(start, len).unwrap_or(&[])
    };
    let writable = |at: u64| {
        model
            .sections
            .iter()
            .any(|s| at >= s.addr && at < s.addr + s.size.vm.max(s.size.file) && s.writable())
    };
    let in_range = |start: u64, end: u64| {
        let i = pointers.partition_point(|p| p.0 < start);
        let j = pointers.partition_point(|p| p.0 < end);
        &pointers[i..j]
    };
    let slots = imports(image);
    // (ELF, as lld folds: see [`Mode::Foldable`].)
    let elf = image.elf().is_some() && mode == Mode::Foldable;
    let lsda = if elf {
        lsda_functions(image)
    } else {
        Default::default()
    };
    let section_of = |at: u64| {
        model
            .sections
            .iter()
            .position(|s| at >= s.addr && at < s.addr + s.size.vm.max(s.size.file))
    };
    let identities: Vec<String> = x
        .ids()
        .map(|n| match slots.get(&graph.nodes()[n as usize].start) {
            Some(import) => import.clone(),
            None => x.names[n as usize].clone(),
        })
        .collect();
    let items: Vec<Item> = x
        .ids()
        .map(|n| {
            let node = graph.nodes()[n as usize];
            // An import address table slot is the function it imports.
            if let Some(import) = slots.get(&node.start) {
                return named(import);
            }
            if matches!(
                x.kinds[n as usize],
                Some(SymbolKind::ImportThunk | SymbolKind::ImportByName | SymbolKind::ImportString)
            ) {
                return named(&x.names[n as usize]);
            }
            // Writable data is a variable: two are never the same, however
            // alike their starting values (code that uses one isn't code
            // that uses the other). So it is known by its name; read-only
            // data, which a linker may fold, by its contents.
            // (Data with no symbol has no name to be known by.)
            // (Within one image, two variables of one name, a file-scope
            // `static` in each of several objects, are two: code that uses
            // one doesn't do what code that uses the other does.)
            if !node.code && writable(node.start) && x.kinds[n as usize].is_some() {
                return match mode {
                    Mode::Same => named(&format!(
                        "{}\0{}",
                        x.names[n as usize],
                        node.end - node.start
                    )),
                    Mode::Foldable => named(&format!("{}\0{:#x}", x.names[n as usize], node.start)),
                };
            }
            // What the linker can't fold is only itself.
            let section = section_of(node.start);
            if mode == Mode::Foldable
                && (!matches!(x.contribution[n as usize], Some((_, true)))
                    || elf
                        && (node.code && lsda.contains(&node.start)
                            || section.is_none_or(|i| elf_unfoldable(&model.sections[i].name))))
            {
                return named(&format!("{}\0{:#x}", x.names[n as usize], node.start));
            }
            let here = in_range(node.start, node.end);
            // (Nor across output sections.)
            let apart = |mut item: Item| {
                if elf && let Some(i) = section {
                    item.local ^= (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                }
                item
            };
            if node.code {
                let absolute: Vec<(u64, u64)> = if x.arch == Arch::X86 {
                    here.iter().map(|&(s, _, t)| (s, t)).collect()
                } else {
                    Vec::new()
                };
                let image_base = (x.arch == Arch::X64).then_some(0);
                apart(code(
                    x.arch,
                    bytes(node.start, node.end),
                    node.start,
                    image_base,
                    &absolute,
                    &resolve,
                ))
            } else {
                let ptrs: Vec<(u64, u32, Option<u32>)> = here
                    .iter()
                    .map(|&(s, w, t)| (s - node.start, w, graph.node_at(t)))
                    .collect();
                let mut item = data(bytes(node.start, node.end), node.end - node.start, &ptrs);
                // What belongs to it is part of it (a vtable's RTTI slot,
                // which the linker keeps in the vtable's COMDAT).
                item.refs.extend(
                    graph
                        .references(n)
                        .iter()
                        .filter(|r| r.1 == hexcavator_xref::Edge::Attached)
                        .map(|r| r.0),
                );
                apart(item)
            }
        })
        .collect();
    let classes = refine(&items, ROUNDS);
    Fingerprints {
        items,
        classes,
        identities,
    }
}

/// A family of near-identical functions: instantiations of one template
/// (one name, its template arguments aside) whose code has one shape
/// ([`hexcavator_fingerprint::shape`]) but isn't identical: they differ
/// only in constants, the sizes of what they work on, or what they call,
/// which a shared, non-template core could take as arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearFamily {
    /// The template's name, its arguments elided: `Vector<>::grow()`.
    pub family: String,
    /// Its functions, largest first.
    pub members: Vec<u32>,
    /// How many of them differ (by [`Mode::Foldable`] class): copies
    /// identical to another are ICF's to fold.
    pub versions: usize,
    /// What one copy of their code would save, at most: each version's
    /// size, less the largest's (the shared core's; the wrappers left, and
    /// the arguments passed, cost some of it back).
    pub saving: u64,
}

/// The smallest function counted in a [`NearFamily`]: below it, unrelated
/// code shares shapes, and sharing saves little.
pub const NEAR_MIN_SIZE: u64 = 32;

/// The families of near-identical functions of an image's graph `x`
/// (`classes`: [`Mode::Foldable`]'s), largest saving first; shapes are
/// computed in parallel.
pub fn near_identical(
    image: &Image<'_>,
    model: &Model,
    x: &Xref,
    classes: &[u64],
) -> Vec<NearFamily> {
    let candidates: Vec<(u32, String)> = x
        .ids()
        .filter(|&n| {
            x.graph.nodes()[n as usize].code
                && x.kinds[n as usize].is_some()
                && x.size(n) >= NEAR_MIN_SIZE
        })
        .filter_map(|n| Some((n, crate::findings::template_family(&x.names[n as usize])?)))
        .collect();
    let bytes = |start: u64, end: u64| -> &[u8] {
        let Some(sec) = model
            .sections
            .iter()
            .find(|s| start >= s.addr && start < s.addr + s.size.vm.max(s.size.file))
        else {
            return &[];
        };
        let available = (sec.addr + sec.size.file).saturating_sub(start);
        image
            .bytes_at(start, (end - start).min(available))
            .unwrap_or(&[])
    };
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(candidates.len().max(1));
    let chunk = candidates.len().div_ceil(threads).max(1);
    let shapes: Vec<Option<u64>> = std::thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(chunk)
            .map(|part| {
                let bytes = &bytes;
                scope.spawn(move || {
                    part.iter()
                        .map(|&(n, _)| {
                            let node = x.graph.nodes()[n as usize];
                            let code = bytes(node.start, node.end);
                            // (Code not all in the file: no shape.)
                            if code.len() as u64 != node.end - node.start {
                                return None;
                            }
                            hexcavator_fingerprint::shape(x.arch, code, node.start)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    let mut groups: rustc_hash::FxHashMap<(&str, u64), Vec<u32>> = rustc_hash::FxHashMap::default();
    for ((n, family), shape) in candidates.iter().zip(shapes) {
        if let Some(shape) = shape {
            groups.entry((family.as_str(), shape)).or_default().push(*n);
        }
    }
    let mut out: Vec<NearFamily> = groups
        .into_iter()
        .filter_map(|((family, _), mut members)| {
            // Each version's size, once.
            let mut sizes: rustc_hash::FxHashMap<u64, u64> = rustc_hash::FxHashMap::default();
            for &n in &members {
                sizes.entry(classes[n as usize]).or_insert(x.size(n));
            }
            if sizes.len() < 2 {
                return None;
            }
            let total: u64 = sizes.values().sum();
            let largest = sizes.values().copied().max().unwrap_or(0);
            members.sort_by_key(|&n| (std::cmp::Reverse(x.size(n)), n));
            Some(NearFamily {
                family: family.to_string(),
                members,
                versions: sizes.len(),
                saving: total - largest,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.saving
            .cmp(&a.saving)
            .then_with(|| a.family.cmp(&b.family))
    });
    out
}

/// Groups of code nodes with the same class (of [`Mode::Foldable`]: code
/// the linker could have folded but didn't), largest saving first: each
/// group's nodes, and the bytes folding it would save (all but one copy).
pub fn identical(x: &Xref, classes: &[u64]) -> Vec<(Vec<u32>, u64)> {
    let mut code: Vec<u32> = x
        .ids()
        .filter(|&n| {
            x.graph.nodes()[n as usize].code && x.kinds[n as usize].is_some() && x.size(n) > 0
        })
        .collect();
    code.sort_by_key(|&n| (classes[n as usize], n));
    let mut out: Vec<(Vec<u32>, u64)> = code
        .chunk_by(|&a, &b| classes[a as usize] == classes[b as usize])
        .filter(|g| g.len() > 1)
        .map(|g| (g.to_vec(), x.size(g[0]) * (g.len() as u64 - 1)))
        .collect();
    out.sort_by_key(|(g, saved)| (std::cmp::Reverse(*saved), g[0]));
    out
}

/// Two builds' functions compared (each a node of its own graph): pairs
/// `(old, new)` and lone nodes, largest (or largest change) first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionDiff {
    /// How many are the same: by name, with the same code referring to the
    /// same things.
    pub unchanged: usize,
    /// The same name, other code.
    pub changed: Vec<(u32, u32)>,
    /// The same code (by fingerprint) under another name.
    pub renamed: Vec<(u32, u32)>,
    pub added: Vec<u32>,
    pub removed: Vec<u32>,
}

/// Compares two builds' functions: paired by name (several of one name:
/// the same code first), then the rest by fingerprint class (renamed: the
/// same code under another name); unchanged where the code and what it
/// refers to (by identity, or a renamed pair) are the same.
pub fn compare(
    old: &Xref,
    old_fp: &Fingerprints,
    new: &Xref,
    new_fp: &Fingerprints,
) -> FunctionDiff {
    let (old_classes, new_classes) = (&old_fp.classes, &new_fp.classes);
    let functions = |x: &Xref| -> Vec<u32> {
        x.ids()
            .filter(|&n| x.graph.nodes()[n as usize].code && x.kinds[n as usize].is_some())
            .collect()
    };
    let (olds, news) = (functions(old), functions(new));
    // Pair them: by name (several of one name: the same class first), then
    // the rest by class (renamed: the same code under another name).
    let mut by_name: std::collections::HashMap<&str, Vec<u32>> = std::collections::HashMap::new();
    for &n in &olds {
        by_name
            .entry(old.names[n as usize].as_str())
            .or_default()
            .push(n);
    }
    let mut old_used = vec![false; old.names.len()];
    let (mut named_pairs, mut unmatched) = (Vec::new(), Vec::new());
    for &n in &news {
        let cands = by_name
            .get_mut(new.names[n as usize].as_str())
            .filter(|c| !c.is_empty());
        let Some(cands) = cands else {
            unmatched.push(n);
            continue;
        };
        let pick = cands
            .iter()
            .position(|&o| old_classes[o as usize] == new_classes[n as usize])
            .unwrap_or(0);
        let o = cands.remove(pick);
        old_used[o as usize] = true;
        named_pairs.push((o, n));
    }
    let mut by_class: std::collections::HashMap<u64, Vec<u32>> = std::collections::HashMap::new();
    for &o in olds.iter().filter(|&&o| !old_used[o as usize]) {
        by_class.entry(old_classes[o as usize]).or_default().push(o);
    }
    let (mut renamed, mut added) = (Vec::new(), Vec::new());
    for n in unmatched {
        match by_class
            .get_mut(&new_classes[n as usize])
            .and_then(Vec::pop)
        {
            Some(o) => {
                old_used[o as usize] = true;
                renamed.push((o, n));
            }
            None => added.push(n),
        }
    }
    // Unchanged: the same code, referring to the same things (by identity,
    // or the pair of a renamed one). What it refers to may itself have
    // changed: that is its change, not this one's.
    let paired: std::collections::HashMap<u32, u32> = renamed.iter().copied().collect();
    let same_code = |o: u32, n: u32| {
        let (a, b) = (&old_fp.items[o as usize], &new_fp.items[n as usize]);
        a.local == b.local
            && a.refs.len() == b.refs.len()
            && a.refs.iter().zip(&b.refs).all(|(&x, &y)| {
                paired.get(&x) == Some(&y)
                    || old_fp.identities[x as usize] == new_fp.identities[y as usize]
            })
    };
    type Pairs = Vec<(u32, u32)>;
    let (same, mut changed): (Pairs, Pairs) =
        named_pairs.into_iter().partition(|&(o, n)| same_code(o, n));
    let mut removed: Vec<u32> = olds
        .iter()
        .copied()
        .filter(|&o| !old_used[o as usize])
        .collect();
    changed.sort_by_key(|&(o, n)| (std::cmp::Reverse(new.size(n).abs_diff(old.size(o))), n));
    renamed.sort_by_key(|&(_, n)| (std::cmp::Reverse(new.size(n)), n));
    added.sort_by_key(|&n| (std::cmp::Reverse(new.size(n)), n));
    removed.sort_by_key(|&o| (std::cmp::Reverse(old.size(o)), o));
    FunctionDiff {
        unchanged: same.len(),
        changed,
        renamed,
        added,
        removed,
    }
}

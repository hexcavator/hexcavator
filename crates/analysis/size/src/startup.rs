//! What runs when an image is loaded, before its own code's `main` (or, of
//! a library, what runs when it is loaded): in the order it runs, phase by
//! phase, each function the loader or the runtime calls, and (from the
//! cross-reference graph, see [`crate::xref`]) what each calls.
//!
//! - PE: the TLS callbacks (the loader's, before the entry point), the
//!   entry point, then what the CRT calls from it: the runtime checks'
//!   initializers (`.rtc$I*`), the C initializers (`.CRT$XI*`, by
//!   `_initterm_e`), and the C++ dynamic initializers (`.CRT$XC*`, by
//!   `_initterm`), each group's entries in order; then `main`, `wmain`,
//!   `WinMain`, `wWinMain` (or a DLL's `DllMain`).
//! - ELF: `.preinit_array` (a program's), `DT_INIT`, `.ctors` (last
//!   first), `.init_array`, the entry point, then `main`.
//! - Mach-O: the initializers dyld calls (`__mod_init_func` pointers, or
//!   `__init_offsets` offsets), then the entry point (`LC_MAIN`'s is
//!   `main` itself).
//!
//! The groups' bounds come from the debug information (a PE image's COFF
//! groups) or the sections; their entries are read from the file, through
//! the loader's relocations where it writes them.

use hexcavator_image::Image;
use hexcavator_xref::Edge;

use crate::Model;
use crate::xref::Xref;

/// A phase of loading: what runs, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase {
    /// Its name: a group's or section's (`.CRT$XCU`, `.init_array`), or
    /// what it is (`TLS callbacks`, `the entry point`).
    pub name: String,
    /// Who calls it, and when.
    pub detail: &'static str,
    pub entries: Vec<Entry>,
}

/// A function a phase calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its address (the image crate's).
    pub addr: u64,
    /// Its node in the graph, if one is there.
    pub node: Option<u32>,
    /// Where its address is (an initializer list's slot).
    pub slot: Option<u64>,
}

/// What runs when an image is loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Startup {
    /// Whether the image is a library (what runs is when it is loaded,
    /// not before a `main`).
    pub library: bool,
    /// The phases, in the order they run.
    pub phases: Vec<Phase>,
    /// The program's own code's first function (`main`, `WinMain`,
    /// `DllMain`, ...), if one is found.
    pub main: Option<u32>,
}

/// The most entries read of one list.
const MAX_ENTRIES: u64 = 1 << 16;

/// What runs when `image` (whose graph is `x`) is loaded.
pub fn startup(image: &Image<'_>, x: &Xref, model: &Model) -> Startup {
    let mut s = if let Some(pe) = image.pe() {
        pe_startup(image, pe, x, model)
    } else if let Some(elf) = image.elf() {
        elf_startup(image, elf, x)
    } else if let Some(m) = image.macho() {
        macho_startup(image, m, x)
    } else {
        Startup::default()
    };
    s.phases.retain(|p| !p.entries.is_empty());
    // (A Mach-O image's entry point is main itself: one phase.)
    if let Some(m) = s.main
        && s.phases
            .last()
            .is_some_and(|p| p.entries.iter().any(|e| e.node == Some(m)))
    {
        s.main = None;
    }
    s
}

fn entry(x: &Xref, addr: u64, slot: Option<u64>) -> Entry {
    Entry {
        addr,
        node: x
            .graph
            .node_starting_at(addr)
            .or_else(|| x.graph.node_at(addr)),
        slot,
    }
}

/// The words of `[start, end)` (pointer-sized, in the image's byte
/// order), each with its address: as the loader leaves them (a slot's
/// relocation target, where it writes one).
fn words(
    image: &Image<'_>,
    start: u64,
    end: u64,
    wide: bool,
    slots: &[hexcavator_image::PointerSlot],
) -> Vec<(u64, u64)> {
    let w: u64 = if wide { 8 } else { 4 };
    let big = image.endian() == hexcavator_core::Endian::Big;
    let mut out = Vec::new();
    let mut at = start;
    while at.saturating_add(w) <= end && out.len() < MAX_ENTRIES as usize {
        let relocated = slots
            .binary_search_by_key(&at, |p| p.addr)
            .ok()
            .and_then(|i| slots[i].target);
        let raw = image.bytes_at(at, w).map(|b| {
            let mut v = [0u8; 8];
            if big {
                v[8 - b.len()..].copy_from_slice(b);
                u64::from_be_bytes(v)
            } else {
                v[..b.len()].copy_from_slice(b);
                u64::from_le_bytes(v)
            }
        });
        if let Some(value) = relocated.or(raw) {
            out.push((at, value));
        }
        at += w;
    }
    out
}

/// The code node named one of `names` (by its name without parameters),
/// a global one first.
fn named(x: &Xref, names: &[&str]) -> Option<u32> {
    let base = |n: &str| -> String {
        let n = n.split('(').next().unwrap_or(n).trim();
        // (Mach-O's and 32-bit Windows' leading underscore.)
        n.strip_prefix('_')
            .filter(|_| !n.starts_with("__"))
            .unwrap_or(n)
            .to_string()
    };
    names.iter().find_map(|want| {
        x.ids().find(|&i| {
            x.graph.nodes()[i as usize].code
                && (base(&x.names[i as usize]) == *want
                    || x.aliases[i as usize].iter().any(|a| base(a) == *want))
        })
    })
}

fn pe_startup(
    image: &Image<'_>,
    pe: &hexcavator_pe::PeFile<'_>,
    x: &Xref,
    model: &Model,
) -> Startup {
    let base = image.image_base();
    let wide = pe
        .optional_header()
        .is_some_and(hexcavator_pe::OptionalHeader::is_64);
    let library = pe.is_dll();
    let mut phases = Vec::new();
    let tls: Vec<Entry> = pe
        .tls_callbacks()
        .take(MAX_ENTRIES as usize)
        .filter_map(|va| va.get().checked_sub(base))
        .map(|rva| entry(x, rva, None))
        .collect();
    phases.push(Phase {
        name: "TLS callbacks".into(),
        detail: "the loader calls each before the entry point (and again as each thread starts and ends)",
        entries: tls,
    });
    let start = pe
        .optional_header()
        .map_or(0, |h| u64::from(h.address_of_entry_point()));
    if start != 0 {
        phases.push(Phase {
            name: "the entry point".into(),
            detail: if library {
                "the loader calls it when the DLL is loaded (DLL_PROCESS_ATTACH), and as threads start and end"
            } else {
                "the loader calls it once the program and its DLLs are loaded"
            },
            entries: vec![entry(x, start, None)],
        });
    }
    // The CRT's lists, as it calls them: runtime checks', C, then C++.
    let mut groups: Vec<&crate::Group> = model
        .groups
        .iter()
        .filter(|g| {
            g.name.starts_with(".rtc$I")
                || g.name.starts_with(".CRT$XI")
                || g.name.starts_with(".CRT$XC")
        })
        .collect();
    let rank = |n: &str| {
        if n.starts_with(".rtc$") {
            0
        } else if n.starts_with(".CRT$XI") {
            1
        } else {
            2
        }
    };
    groups.sort_by(|a, b| (rank(&a.name), &a.name).cmp(&(rank(&b.name), &b.name)));
    for g in groups {
        let entries: Vec<Entry> = words(
            image,
            g.addr,
            g.addr.saturating_add(g.size.vm.max(g.size.file)),
            wide,
            &[],
        )
        .into_iter()
        .filter(|&(_, v)| v != 0)
        .filter_map(|(slot, va)| Some(entry(x, va.checked_sub(base)?, Some(slot))))
        .collect();
        phases.push(Phase {
            name: g.name.clone(),
            detail: match rank(&g.name) {
                0 => "the runtime checks' initializers: the CRT calls them from the entry point, first",
                1 => "C initializers: the CRT calls them from the entry point (_initterm_e), before C++'s",
                _ => "C++ dynamic initializers (global objects' constructors): the CRT calls them from the entry point (_initterm)",
            },
            entries,
        });
    }
    let main = if library {
        named(x, &["DllMain"])
    } else {
        named(x, &["main", "wmain", "WinMain", "wWinMain"])
    };
    Startup {
        library,
        phases,
        main,
    }
}

fn elf_startup(image: &Image<'_>, elf: &hexcavator_elf::ElfFile<'_>, x: &Xref) -> Startup {
    use hexcavator_elf::consts::*;
    let h = elf.header();
    let wide = h.class == hexcavator_elf::Class::Elf64;
    let library = h.kind == ET_DYN && !elf.segments().any(|s| s.kind == PT_INTERP);
    let slots = image.pointer_slots();
    // (Thumb functions' addresses have their low bit set.)
    let thumb = h.machine == EM_ARM;
    let code = |v: u64| if thumb { v & !1 } else { v };
    let list = |kind: u32, name: &str, reverse: bool| -> Vec<Entry> {
        let mut out = Vec::new();
        for s in elf
            .sections()
            .filter(|s| s.kind == kind || (kind == 0 && s.name == name.as_bytes()))
        {
            if !s.is_alloc() {
                continue;
            }
            let mut w = words(image, s.addr, s.addr.saturating_add(s.size), wide, &slots);
            if reverse {
                w.reverse();
            }
            // (`.ctors` has -1 and 0 at its ends.)
            let all = if wide { u64::MAX } else { u64::from(u32::MAX) };
            out.extend(
                w.into_iter()
                    .filter(|&(_, v)| v != 0 && v != all)
                    .map(|(slot, v)| entry(x, code(v), Some(slot))),
            );
        }
        out
    };
    let mut phases = Vec::new();
    if !library {
        phases.push(Phase {
            name: ".preinit_array".into(),
            detail: "the dynamic loader calls these first, before any library's initializers (a program's only)",
            entries: list(SHT_PREINIT_ARRAY, "", false),
        });
    }
    let init: Vec<Entry> = elf
        .dynamic()
        .iter()
        .filter(|d| d.tag == DT_INIT)
        .map(|d| entry(x, code(d.value), None))
        .collect();
    phases.push(Phase {
        name: "DT_INIT".into(),
        detail: "the loader calls it (_init), before .init_array",
        entries: init,
    });
    phases.push(Phase {
        name: ".ctors".into(),
        detail: "older constructors' list: _init's __do_global_ctors_aux calls them, last first",
        entries: list(0, ".ctors", true),
    });
    phases.push(Phase {
        name: ".init_array".into(),
        detail: if library {
            "the loader calls these when the library is loaded, in order"
        } else {
            "the loader (or, in a static program, __libc_start_main) calls these in order, before main"
        },
        entries: list(SHT_INIT_ARRAY, "", false),
    });
    if !library && h.entry != 0 {
        phases.push(Phase {
            name: "the entry point".into(),
            detail: "the loader jumps to it (_start) once everything is loaded; it calls __libc_start_main, which calls main",
            entries: vec![entry(x, code(h.entry), None)],
        });
    }
    let main = if library { None } else { named(x, &["main"]) };
    Startup {
        library,
        phases,
        main,
    }
}

fn macho_startup(image: &Image<'_>, m: &hexcavator_macho::MachO<'_>, x: &Xref) -> Startup {
    use hexcavator_macho::consts::*;
    const MH_EXECUTE: u32 = 2;
    let library = m.header().filetype != MH_EXECUTE;
    let wide = m.header().is64;
    let slots = image.pointer_slots();
    let base = m
        .segments()
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .map_or(0, |s| s.vmaddr);
    let mut entries = Vec::new();
    let mut names = Vec::new();
    for s in m.sections() {
        let (start, end) = (s.addr, s.addr.saturating_add(s.size));
        match s.kind() {
            S_MOD_INIT_FUNC_POINTERS => {
                entries.extend(
                    words(image, start, end, wide, &slots)
                        .into_iter()
                        .filter(|&(_, v)| v != 0)
                        .map(|(slot, v)| entry(x, v, Some(slot))),
                );
            }
            S_INIT_FUNC_OFFSETS => {
                let bytes = image.bytes_at(start, s.size).unwrap_or_default();
                for (i, w) in bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .take(MAX_ENTRIES as usize)
                {
                    let off = u64::from(u32::from_le_bytes(*w));
                    entries.push(entry(x, base.wrapping_add(off), Some(start + 4 * i as u64)));
                }
            }
            _ => continue,
        }
        names.push(String::from_utf8_lossy(s.sectname).into_owned());
    }
    let mut phases = vec![Phase {
        name: if names.is_empty() {
            "__mod_init_func".into()
        } else {
            names.join(", ")
        },
        detail: if library {
            "dyld calls these when the library is loaded, in order"
        } else {
            "dyld calls these in order, once everything is loaded, before the entry point"
        },
        entries,
    }];
    if !library && let Some(e) = m.entry() {
        phases.push(Phase {
            name: "the entry point".into(),
            detail: "dyld calls it last (LC_MAIN's is main itself)",
            entries: vec![entry(x, e, None)],
        });
    }
    let main = if library { None } else { named(x, &["main"]) };
    Startup {
        library,
        phases,
        main,
    }
}

/// The code `node` calls or jumps to (a tail call, a jump table), each
/// once, in the order its code first does (its pieces', disassembled
/// again for their call sites; any the scan doesn't place, after).
pub fn callees(image: &Image<'_>, x: &Xref, node: u32) -> Vec<(u32, Edge)> {
    let nodes = x.graph.nodes();
    let mut set: Vec<(u32, Edge)> = Vec::new();
    // (A function split in pieces: all of its pieces' references.)
    let own = x.graph.pieces(x.graph.origin(node));
    for piece in own.clone() {
        for &(to, edge) in x.graph.references(piece) {
            if !matches!(edge, Edge::Call | Edge::Jump) || own.contains(&to) {
                continue;
            }
            if nodes.get(to as usize).is_some_and(|n| n.code) && !set.iter().any(|&(t, _)| t == to)
            {
                set.push((to, edge));
            }
        }
    }
    // In call-site order.
    let mut refs = Vec::new();
    for piece in own {
        let Some(n) = nodes.get(piece as usize) else {
            continue;
        };
        if let Some(code) = image.bytes_at(n.start, n.end.saturating_sub(n.start)) {
            hexcavator_xref::scan_image(x.arch, code, n.start, image.pe().map(|_| 0), &mut refs);
        }
    }
    let mut out = Vec::with_capacity(set.len());
    for r in &refs {
        let Some(t) = x
            .graph
            .node_starting_at(r.to)
            .or_else(|| x.graph.node_at(r.to))
        else {
            continue;
        };
        if let Some(i) = set.iter().position(|&(s, _)| s == t) {
            out.push(set.swap_remove(i));
        }
    }
    // (What the scan doesn't place, by the graph's order.)
    set.sort_unstable_by_key(|&(t, _)| t);
    out.extend(set);
    out
}

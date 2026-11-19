//! What exception handling costs each function ([`exceptions`]): its
//! unwind information (an ELF `.eh_frame` FDE; a PE `.pdata` entry and its
//! unwind data), and its handlers' data (an ELF LSDA in
//! `.gcc_except_table`; MSVC's C++ EH tables, SEH scope tables): the
//! cleanups and handlers it runs when an exception passes through it.
//!
//! And which functions carry cleanups though nothing they reach can throw
//! ([`Exceptions::needless`]): their handlers' data is only there because
//! the compiler couldn't tell (what they call isn't `noexcept`). A function
//! may throw if it throws (`__cxa_throw`, `__cxa_rethrow`,
//! `_Unwind_RaiseException`, `_CxxThrowException`), calls through a pointer
//! (anything), calls an import of C++ (not C's: C doesn't throw), or calls
//! one that may. (Mach-O's compact unwind isn't read yet: none there.)

use rustc_hash::{FxHashMap, FxHashSet};

use crate::symbols::{Symbol, SymbolKind};
use crate::xref::Xref;
use hexcavator_xref::Edge;

/// What exception handling costs one function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionEh {
    /// The function (a node of the graph).
    pub node: u32,
    /// Its unwind information's bytes.
    pub unwind: u64,
    /// Its handlers' data's bytes (cleanups, catches): none if it has none.
    pub handlers: u64,
}

/// An image's exception handling, by function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exceptions {
    /// By function, most costly first.
    pub functions: Vec<FunctionEh>,
    /// The functions with handlers' data that nothing they reach can
    /// throw through (indexes into `functions`).
    pub needless: Vec<usize>,
}

impl Exceptions {
    /// Their unwind information's bytes, and their handlers' data's.
    pub fn totals(&self) -> (u64, u64) {
        self.functions
            .iter()
            .fold((0, 0), |(u, h), f| (u + f.unwind, h + f.handlers))
    }
}

/// The exception handling of the image of graph `x`.
pub fn exceptions(image: &hexcavator_image::Image<'_>, x: &Xref, symbols: &[Symbol]) -> Exceptions {
    let mut costs: FxHashMap<u32, (u64, u64)> = FxHashMap::default();
    if image.elf().is_some() {
        elf_costs(image, x, &mut costs);
    } else if image.pe().is_some() {
        pe_costs(x, symbols, &mut costs);
    }
    let mut functions: Vec<FunctionEh> = costs
        .into_iter()
        .filter(|(_, (u, h))| u + h > 0)
        .map(|(node, (unwind, handlers))| FunctionEh {
            node,
            unwind,
            handlers,
        })
        .collect();
    functions.sort_by(|a, b| {
        (b.unwind + b.handlers)
            .cmp(&(a.unwind + a.handlers))
            .then_with(|| a.node.cmp(&b.node))
    });
    // (Only if something has handlers' data: which may throw is a pass
    // over all the code.)
    let throws = if functions.iter().any(|f| f.handlers > 0) {
        may_throw(image, x)
    } else {
        FxHashSet::default()
    };
    let needless = functions
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.handlers > 0 && !throws.contains(&f.node) && !reaches_throw(x, f.node, &throws)
        })
        .map(|(i, _)| i)
        .collect();
    Exceptions {
        functions,
        needless,
    }
}

/// ELF: each function's FDE (its entry in `.eh_frame`, to the next), and
/// its LSDA (in `.gcc_except_table`, to the next LSDA or the section's
/// end).
fn elf_costs(
    image: &hexcavator_image::Image<'_>,
    x: &Xref,
    costs: &mut FxHashMap<u32, (u64, u64)>,
) {
    use hexcavator_dwarf::cfi::{Cfi, CfiKind, Entry};
    let sections = image.sections();
    let mut fdes: Vec<(u64, u64, Option<u64>)> = Vec::new();
    for s in sections
        .iter()
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
        let entries: Vec<Entry<'_>> = cfi.entries().collect();
        let offset = |e: &Entry<'_>| match e {
            Entry::Cie(c) => c.offset,
            Entry::Fde(f) => f.offset,
        };
        for (i, e) in entries.iter().enumerate() {
            if let Entry::Fde(f) = e {
                let end = entries.get(i + 1).map_or(data.len() as u64, offset);
                fdes.push((f.pc_begin, end.saturating_sub(f.offset), f.lsda));
            }
        }
    }
    // The LSDAs, by address, each to the next (or its section's end).
    let tables: Vec<(u64, u64)> = sections
        .iter()
        .filter(|s| s.name == b".gcc_except_table")
        .map(|s| (s.addr, s.addr + s.vm_size))
        .collect();
    let mut lsdas: Vec<u64> = fdes.iter().filter_map(|f| f.2).collect();
    lsdas.sort_unstable();
    lsdas.dedup();
    let lsda_size = |at: u64| -> u64 {
        let end = tables
            .iter()
            .find(|t| (t.0..t.1).contains(&at))
            .map_or(at, |t| t.1);
        let i = lsdas.partition_point(|&l| l <= at);
        lsdas.get(i).copied().filter(|&n| n < end).unwrap_or(end) - at
    };
    for (pc, size, lsda) in fdes {
        let Some(n) = x.graph.node_at(pc) else {
            continue;
        };
        let e = costs.entry(n).or_default();
        e.0 += size;
        if let Some(l) = lsda {
            e.1 += lsda_size(l);
        }
    }
}

/// PE: the exception data attached to each function in the graph (its
/// `.pdata` entry, unwind data, and handlers' data), through at most two
/// owners (a function owns its `.pdata` entry, which owns its unwind data,
/// which owns its handlers').
fn pe_costs(x: &Xref, symbols: &[Symbol], costs: &mut FxHashMap<u32, (u64, u64)>) {
    let kinds: FxHashMap<u64, SymbolKind> = symbols.iter().map(|s| (s.addr, s.kind)).collect();
    let handlers = |k: SymbolKind| {
        matches!(
            k,
            SymbolKind::CppXdata
                | SymbolKind::StateUnwindMap
                | SymbolKind::TryMap
                | SymbolKind::HandlerMap
                | SymbolKind::IpToStateMap
                | SymbolKind::SegmentMap
        )
    };
    let unwind = |k: SymbolKind| {
        matches!(
            k,
            SymbolKind::Pdata
                | SymbolKind::PackedPdata
                | SymbolKind::ForwarderPdata
                | SymbolKind::Unwind
                | SymbolKind::ChainUnwind
        )
    };
    // (Each once, for the first function: a catch funclet shares its
    // parent's handlers' data.)
    let mut claimed: FxHashSet<u32> = FxHashSet::default();
    for f in x.ids().filter(|&n| x.graph.nodes()[n as usize].code) {
        let mut stack = vec![(f, 0u32)];
        let mut seen = FxHashSet::default();
        while let Some((n, depth)) = stack.pop() {
            for &(to, e) in x.graph.references(n) {
                if e != Edge::Attached || !seen.insert(to) || depth > 3 {
                    continue;
                }
                let node = x.graph.nodes()[to as usize];
                if let Some(&k) = kinds.get(&node.start)
                    && claimed.insert(to)
                {
                    let size = node.end - node.start;
                    let c = costs.entry(f).or_default();
                    if handlers(k) {
                        c.1 += size;
                    } else if unwind(k) {
                        c.0 += size;
                    }
                }
                stack.push((to, depth + 1));
            }
        }
    }
}

/// The names of what throws.
fn throws_by_name(name: &str) -> bool {
    let base = name
        .split('(')
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    matches!(
        base,
        "cxa_throw" | "cxa_rethrow" | "Unwind_RaiseException" | "CxxThrowException"
    ) || name.starts_with("std::__throw_")
        || name.starts_with("std::rethrow_exception")
}

/// The functions of graph `x` that may throw: those that throw, call
/// through a pointer, or call (or tail-call) an import of C++'s, and those
/// that call them.
fn may_throw(image: &hexcavator_image::Image<'_>, x: &Xref) -> FxHashSet<u32> {
    let nodes = x.graph.nodes();
    let mut out: FxHashSet<u32> = FxHashSet::default();
    let mut code = Vec::new();
    for n in x.ids() {
        let name = x.names[n as usize].as_str();
        let node = nodes[n as usize];
        if throws_by_name(name) {
            out.insert(n);
            continue;
        }
        // An import, or what else the linker made (no compile unit's: a
        // PLT entry): C++'s may throw (a name with parameters, or mangled;
        // C's has neither).
        if node.code
            && x.contribution[n as usize].is_none()
            && (name.contains('(')
                || name.contains("::")
                || name.starts_with("_Z")
                || name.starts_with('?'))
        {
            out.insert(n);
            continue;
        }
        if node.code {
            code.push(n);
        }
    }
    // What calls what the graph doesn't know: decoded in parallel.
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(code.len().max(1));
    let chunk = code.len().div_ceil(threads).max(1);
    let unknown: Vec<u32> = std::thread::scope(|scope| {
        let handles: Vec<_> = code
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .copied()
                        .filter(|&n| {
                            let node = nodes[n as usize];
                            calls_unknown(image, x, node.start, node.end)
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
    out.extend(unknown);
    // And their callers, to a fixed point (backwards over calls).
    let mut work: Vec<u32> = out.iter().copied().collect();
    while let Some(n) = work.pop() {
        for &(from, e) in x.graph.referrers(n) {
            if matches!(e, Edge::Call | Edge::Jump) && out.insert(from) {
                work.push(from);
            }
        }
    }
    out
}

/// Whether `f` calls (or tail-calls) anything in `throws`.
fn reaches_throw(x: &Xref, f: u32, throws: &FxHashSet<u32>) -> bool {
    x.graph
        .references(f)
        .iter()
        .any(|&(to, e)| matches!(e, Edge::Call | Edge::Jump) && throws.contains(&to))
}

/// Whether the code `[start, end)` calls what the graph doesn't know: a
/// pointer (x86's `call` of a register or memory, an import's address
/// table entry among them; ARM64's `blr` and its authenticated forms), or
/// an address no function of `x` starts at (an unresolved symbol's).
fn calls_unknown(image: &hexcavator_image::Image<'_>, x: &Xref, start: u64, end: u64) -> bool {
    use hexcavator_core::Arch;
    let arch = x.arch;
    let known = |to: u64| x.graph.node_starting_at(to).is_some();
    let Some(code) = image.bytes_at(start, end - start) else {
        return false;
    };
    match arch {
        Arch::X86 | Arch::X64 => {
            let mode = if arch == Arch::X86 {
                hexcavator_x86::Mode::Bits32
            } else {
                hexcavator_x86::Mode::Bits64
            };
            let mut at = 0usize;
            while at < code.len() {
                let Ok(inst) = hexcavator_x86::decode(&code[at..], mode, start + at as u64) else {
                    return false;
                };
                if inst.mnemonic() == hexcavator_x86::Mnemonic::Call
                    && inst.operands().iter().any(|o| match o {
                        hexcavator_x86::Operand::Reg(_) | hexcavator_x86::Operand::Mem(_) => true,
                        hexcavator_x86::Operand::Rel(to) => !known(*to),
                        _ => false,
                    })
                {
                    return true;
                }
                at += inst.len().max(1);
            }
            false
        }
        Arch::Arm64 => code.as_chunks::<4>().0.iter().enumerate().any(|(i, w)| {
            let word = u32::from_le_bytes(*w);
            // BL to what isn't a function's start.
            if word & 0xFC00_0000 == 0x9400_0000 {
                let imm = i64::from(((word & 0x03FF_FFFF) << 6).cast_signed() >> 6) * 4;
                let pc = start + i as u64 * 4;
                return !known(pc.wrapping_add_signed(imm));
            }
            // BLR, BLRAA/BLRAB/BLRAAZ/BLRABZ: the BLR group.
            word & 0xFFFF_FC1F == 0xD63F_0000 || word & 0xFEFF_F800 == 0xD63F_0800
        }),
        _ => false,
    }
}

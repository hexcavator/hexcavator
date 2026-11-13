//! The cross-reference graph of a PE image (see `hexcavator_xref`), built
//! from its symbols, code, relocations, and exception data, and what its
//! roots reach.
//!
//! - Nodes: the image's symbols (folded names are aliases of one node), and
//!   the CRT's initializer groups (`.CRT$X*`, `.rtc$*`), so that an entry
//!   with no symbol of its own still counts.
//! - Code: every symbol in an executable section is disassembled.
//! - Pointers: the base relocations. One in data is a pointer to what it
//!   holds; one in (32-bit x86) code, an address the code uses. The slot
//!   just before a vtable, its RTTI complete object locator's, belongs to
//!   the vtable.
//! - Exception data: a function owns its `.pdata` entries, which own their
//!   unwind data. Unwind data, C++ EH tables, and x64 RTTI refer to one
//!   another and to funclets (catch blocks, unwind actions, SEH filters) by
//!   RVA: every 32-bit value in them, at any offset (FH4 packs them
//!   unaligned), that is the start of a code symbol or of another such
//!   table counts. These tables hang off their function, so a value that
//!   only happens to match can make a funclet seem reached only where its
//!   function is.
//! - Roots: the entry point, the exports, the loader's directories (load
//!   config, TLS, imports, resources, debug, delay-load) and what else it
//!   reads (import names, tables the headers locate, resources),
//!   thread-local data (which code reaches by offsets from the thread's
//!   block), and the initializer groups, whose entries the CRT calls
//!   between bounds it names, not entry by entry.

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::consts::{directory, machine};
use hexcavator_pe::exception::RuntimeFunction;
use hexcavator_pe::reloc::base_reloc;
use hexcavator_xref::{Arch, Builder, Edge, Graph, Node, Reach};

use crate::Model;
use crate::symbols::{Symbol, SymbolKind};

/// Why a node is a root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Root {
    EntryPoint,
    Export(String),
    /// A loader directory, by name.
    Directory(&'static str),
    /// An initializer group, by name.
    Initializers(String),
    /// Data the loader reads, by what it is.
    LoaderData(&'static str),
}

impl std::fmt::Display for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Root::EntryPoint => f.write_str("the entry point"),
            Root::Export(name) => write!(f, "exported as {name}"),
            Root::Directory(name) => write!(f, "the {name} directory"),
            Root::Initializers(group) => write!(f, "the initializers in {group}"),
            Root::LoaderData(what) => write!(f, "{what}, which the loader reads"),
        }
    }
}

/// Whose linker's terms the graph's input sections are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Linker {
    /// link.exe and lld-link: COMDATs, `/OPT:REF`, `/Gy`, `/Gw`.
    Msvc,
    /// ELF linkers (ld, lld, gold): sections of their own
    /// (`-ffunction-sections`, `-fdata-sections`), `--gc-sections`.
    Elf,
    /// ld64 and ld64.lld: atoms, `-dead_strip`.
    MachO,
}

/// The graph of an image, its nodes' names, and what its roots reach.
pub struct Xref {
    /// Whose terms its input sections are in.
    pub linker: Linker,
    /// The instruction set of the image's code.
    pub arch: Arch,
    pub graph: Graph,
    /// Each node's name (its first symbol's, or a group's in brackets).
    pub names: Vec<String>,
    /// Each node's other names (symbols folded into it).
    pub aliases: Vec<Vec<String>>,
    /// Each node's symbol kind (`None` for a group).
    pub kinds: Vec<Option<SymbolKind>>,
    /// Each root, and why.
    pub roots: Vec<(u32, Root)>,
    pub reach: Reach,
    /// Each node's input section, from the debug information's section
    /// contributions: the compiland (an index into `compilands`), and
    /// whether the section was a COMDAT (which `/OPT:REF` can drop alone).
    pub contribution: Vec<Option<(u32, bool)>>,
    /// The debug information's modules' names (their objects' paths), which
    /// `contribution` indexes.
    pub compilands: Vec<String>,
    /// Each module's library (its object's path again, for an object given
    /// to the linker directly).
    pub libraries: Vec<String>,
    /// What the linker must keep reaches: from the roots and every node
    /// whose section is not a COMDAT (which `/OPT:REF` never drops).
    pub kept_reach: Reach,
}

/// Why the linker kept a node nothing reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// Its input section was not a COMDAT: the linker keeps such a section
    /// whole when anything in it is used. Code compiled with `/Gy`, and data
    /// with `/Gw`, is in COMDATs.
    WithSection { code: bool },
    /// A COMDAT (or the linker's own data) that something kept for the
    /// first reason refers to, directly or not: that node.
    ReferencedBy(u32),
    /// A COMDAT: kept for a reason the graph doesn't see (`/OPT:NOREF`,
    /// `/INCLUDE`, or a reference it misses).
    Comdat,
    /// No contribution covers it (the linker's own data).
    Unknown,
}

impl Xref {
    /// Every node's index.
    pub fn ids(&self) -> std::ops::Range<u32> {
        // The builder holds the count below u32::MAX.
        0..self.names.len() as u32
    }

    /// The nodes named `name` (or with it as an alias).
    pub fn find(&self, name: &str) -> Vec<u32> {
        self.ids()
            .filter(|&i| {
                self.names[i as usize] == name || self.aliases[i as usize].iter().any(|a| a == name)
            })
            .collect()
    }

    /// Why `node` is a root, if it is one.
    pub fn root_reason(&self, node: u32) -> Option<&Root> {
        self.roots.iter().find(|r| r.0 == node).map(|r| &r.1)
    }

    /// Why the linker kept `node` (meaningful for nodes nothing reaches).
    pub fn kept(&self, node: u32) -> Kept {
        if let Some((_, false)) = self.contribution[node as usize] {
            return Kept::WithSection {
                code: self.graph.nodes()[node as usize].code,
            };
        }
        if let Some((root, _)) = self.kept_reach.chain(node)
            && root != node
        {
            return Kept::ReferencedBy(root);
        }
        match self.contribution[node as usize] {
            Some(_) => Kept::Comdat,
            None => Kept::Unknown,
        }
    }

    /// The object `node` came from, if known.
    pub fn object(&self, node: u32) -> Option<&str> {
        let (c, _) = self.contribution[node as usize]?;
        self.compilands.get(c as usize).map(String::as_str)
    }

    /// A node's size in memory.
    pub fn size(&self, node: u32) -> u64 {
        let n = self.graph.nodes()[node as usize];
        n.end - n.start
    }
}

fn is_rva_table(kind: SymbolKind, name: &str) -> bool {
    use SymbolKind as K;
    matches!(
        kind,
        K::Unwind
            | K::ChainUnwind
            | K::CppXdata
            | K::StateUnwindMap
            | K::TryMap
            | K::HandlerMap
            | K::IpToStateMap
            | K::SegmentMap
    ) || name.contains("`RTTI ")
        || is_throw_info(name)
}

/// C++ throw information (`_TI`, `_CTA`, `_CT`): x64 links it by RVA, as
/// RTTI.
fn is_throw_info(name: &str) -> bool {
    name.starts_with("_TI") || name.starts_with("_CTA") || name.starts_with("_CT??")
}

/// What the loader reads, for a symbol of `kind`.
fn loader_data(kind: SymbolKind) -> Option<&'static str> {
    use SymbolKind as K;
    Some(match kind {
        K::ImportDescriptor | K::ImportThunk | K::ImportByName | K::ImportString => "an import",
        K::PeDirectory => "a table the headers locate",
        K::LoadConfigTable => "a load config table",
        K::RsrcDirectory
        | K::RsrcDataEntry
        | K::RsrcString
        | K::RsrcData
        | K::RsrcGroupIcon
        | K::RsrcGroupCursor
        | K::RsrcStringTables => "a resource",
        _ => return None,
    })
}

fn is_initializer_group(name: &str) -> bool {
    name.starts_with(".CRT$X") || name.starts_with(".rtc$")
}

/// The graph of `file`, with its debug information and the model and
/// symbols built from it.
pub fn pe(
    file: &PeFile<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &Model,
    symbols: &[Symbol],
) -> Result<Xref, String> {
    let arch = match file.machine() {
        machine::AMD64 => Arch::X64,
        machine::I386 => Arch::X86,
        machine::ARM64 | machine::ARM64X => Arch::Arm64,
        m => return Err(format!("no cross-references for machine {m:#06x}")),
    };
    let executable = |addr: u64| {
        model
            .sections
            .iter()
            .any(|s| s.executable() && addr >= s.addr && addr < s.addr + s.size.vm.max(s.size.file))
    };

    let mut nodes = symbol_nodes(symbols, &executable);
    for g in model
        .groups
        .iter()
        .filter(|g| is_initializer_group(&g.name))
    {
        nodes.push((
            Node {
                start: g.addr,
                end: g.addr + g.extent(),
                code: false,
            },
            Info {
                name: format!("[{}]", g.name),
                aliases: Vec::new(),
                kind: None,
                unlabeled: None,
            },
        ));
    }
    // The base relocations: (slot, width).
    let relocs: Vec<(u64, u32)> = file
        .base_relocs()
        .filter_map(|r| match r.kind {
            base_reloc::DIR64 => Some((u64::from(r.rva.0), 8)),
            base_reloc::HIGHLOW => Some((u64::from(r.rva.0), 4)),
            _ => None,
        })
        .collect();
    unlabeled_data(&mut nodes, relocs.iter().map(|r| r.0), model);
    let (mut b, infos) = builder(nodes);
    // Nodes are at RVAs: the image starts at 0.
    b.image_base(0);

    // Code.
    for i in 0..b.nodes().len() as u32 {
        let n = b.nodes()[i as usize];
        if !n.code {
            continue;
        }
        let len = u32::try_from(n.end - n.start).unwrap_or(u32::MAX);
        let Ok(rva) = u32::try_from(n.start) else {
            continue;
        };
        if let Ok(code) = file.bytes_at_rva(Rva(rva), len).or_else(|_| {
            // A function's last bytes can lie past its section's file data.
            file.bytes_at_rva(Rva(rva), 0).map(|_| &[][..])
        }) {
            b.code(i, arch, code);
        }
    }

    // Each vtable's RTTI slot: the pointer just before it.
    let pointer_size: u64 = if file
        .optional_header()
        .is_some_and(hexcavator_pe::OptionalHeader::is_64)
    {
        8
    } else {
        4
    };
    let mut rtti_slots = rustc_hash::FxHashMap::default();
    for (i, info) in infos.iter().enumerate() {
        if info.name.contains("`vftable'") || info.aliases.iter().any(|a| a.contains("`vftable'")) {
            let start = b.nodes()[i].start;
            if let Some(slot) = start.checked_sub(pointer_size) {
                rtti_slots.insert(slot, i as u32);
            }
        }
    }

    // Pointers, from the base relocations.
    let base = file.optional_header().map_or(0, |h| h.image_base().get());
    for &(slot, width) in &relocs {
        let Ok(bytes) = file.bytes_at_rva(Rva(slot as u32), width) else {
            continue;
        };
        let value = if width == 8 {
            u64::from_le_bytes(bytes.try_into().unwrap_or_default())
        } else {
            u64::from(u32::from_le_bytes(bytes.try_into().unwrap_or_default()))
        };
        let Some(to) = value.checked_sub(base) else {
            continue;
        };
        // (Only if it is one: without RTTI, the slot is the last of the
        // vtable before.)
        if let Some(&vtable) = rtti_slots.get(&slot)
            && let Some(t) = b.node_at(to)
            && infos[t as usize]
                .name
                .contains("`RTTI Complete Object Locator'")
        {
            b.edge(vtable, t, Edge::Attached);
            continue;
        }
        let in_code = b.node_at(slot).is_some_and(|f| b.nodes()[f as usize].code);
        b.edge_at(
            slot,
            to,
            if in_code {
                Edge::Address
            } else {
                Edge::Pointer
            },
        );
    }

    // Exception data: functions own their .pdata entries, which own their
    // unwind data.
    for e in file.runtime_functions() {
        let entry = u64::from(e.rva.0);
        let (Some(func), Some(pdata)) =
            (b.node_at(u64::from(e.function.begin().0)), b.node_at(entry))
        else {
            continue;
        };
        b.edge(func, pdata, Edge::Attached);
        let unwind = match e.function {
            RuntimeFunction::X64 { unwind, .. } => Some(unwind.0),
            RuntimeFunction::Arm { unwind, .. } => (unwind & 3 == 0).then_some(unwind),
        };
        if let Some(u) = unwind.and_then(|u| b.node_at(u64::from(u))) {
            b.edge(pdata, u, Edge::Attached);
        }
    }
    // What delay-load descriptors name by RVA (the module handle, and each
    // table's entries up to and including the zero that ends it): the
    // delay-load helper reads it, as the loader reads imports.
    let mut delay_data: Vec<u32> = Vec::new();
    for dll in file.delay_imports() {
        let d = dll.descriptor;
        if let Some(h) = dll.rva(d.module_handle.get())
            && let Some(n) = b.node_at(u64::from(h.0))
        {
            delay_data.push(n);
        }
        for table in [
            d.import_address_table.get(),
            d.import_name_table.get(),
            d.bound_import_address_table.get(),
            d.unload_information_table.get(),
        ] {
            let Some(start) = dll.rva(table) else {
                continue;
            };
            for i in 0..1 << 16 {
                let at = u64::from(start.0) + i * pointer_size;
                // (An RVA is 32 bits: a table that runs past them ends.)
                let Ok(rva) = u32::try_from(at) else {
                    break;
                };
                let Ok(entry) = file.bytes_at_rva(Rva(rva), pointer_size as u32) else {
                    break;
                };
                if let Some(n) = b.node_at(at) {
                    delay_data.push(n);
                }
                if entry.iter().all(|&x| x == 0) {
                    break;
                }
            }
        }
    }
    delay_data.sort_unstable();
    delay_data.dedup();

    // RVA tables: values that are the start of code or of another table.
    let tables: Vec<u32> = (0..infos.len() as u32)
        .filter(|&i| {
            infos[i as usize]
                .kind
                .is_some_and(|k| is_rva_table(k, &infos[i as usize].name))
        })
        .collect();
    let mut targets = rustc_hash::FxHashMap::default();
    for (i, n) in b.nodes().iter().enumerate() {
        let table = tables.binary_search(&(i as u32)).is_ok();
        if n.code || table {
            targets.entry(n.start).or_insert((i as u32, table));
        }
    }
    for &t in &tables {
        let n = b.nodes()[t as usize];
        let (Ok(rva), Ok(len)) = (u32::try_from(n.start), u32::try_from(n.end - n.start)) else {
            continue;
        };
        let Ok(bytes) = file.bytes_at_rva(Rva(rva), len) else {
            continue;
        };
        for w in bytes.windows(4) {
            let v = u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
            if let Some(&(to, table)) = targets.get(&v) {
                b.edge(t, to, if table { Edge::Attached } else { Edge::Pointer });
            }
        }
    }

    // Roots.
    let mut roots: Vec<(u32, Root)> = Vec::new();
    if let Some(h) = file.optional_header()
        && let Some(n) = b.node_at(u64::from(h.address_of_entry_point()))
    {
        roots.push((n, Root::EntryPoint));
    }
    if let Some(exports) = file.exports() {
        for e in exports.iter() {
            if let hexcavator_pe::exports::ExportTarget::Rva(rva) = e.target
                && let Some(n) = b.node_at(u64::from(rva.0))
            {
                let name = e.name.map_or_else(
                    || format!("#{}", e.ordinal),
                    |n| String::from_utf8_lossy(n).into_owned(),
                );
                roots.push((n, Root::Export(name)));
            }
        }
    }
    for (index, name) in [
        (directory::LOAD_CONFIG, "load config"),
        (directory::TLS, "TLS"),
        (directory::IMPORT, "import"),
        (directory::IAT, "import address table"),
        (directory::RESOURCE, "resource"),
        (directory::DEBUG, "debug"),
        (directory::DELAY_IMPORT, "delay-load import"),
    ] {
        if let Some(d) = file.data_directory(index) {
            let start = u64::from(d.virtual_address.get());
            let end = start + u64::from(d.size.get());
            let mut inside = within(&b, start, end);
            if inside.is_empty()
                && let Some(n) = b.node_at(start)
            {
                inside.push(n);
            }
            roots.extend(inside.into_iter().map(|n| (n, Root::Directory(name))));
        }
    }
    // Thread-local data: code reaches it by offsets from the thread's
    // block, which no relocation or address shows.
    if let Some(t) = file.tls() {
        let start = t.start_of_raw_data.get().wrapping_sub(base);
        let end = t.end_of_raw_data.get().wrapping_sub(base) + u64::from(t.size_of_zero_fill);
        if start < end {
            for n in within(&b, start, end) {
                roots.push((n, Root::LoaderData("thread-local data")));
            }
        }
    }
    roots.extend(
        delay_data
            .into_iter()
            .map(|n| (n, Root::LoaderData("a delay-load import"))),
    );
    for (i, info) in infos.iter().enumerate() {
        if let Some(what) = info.kind.and_then(loader_data) {
            roots.push((i as u32, Root::LoaderData(what)));
        }
    }
    for g in model
        .groups
        .iter()
        .filter(|g| is_initializer_group(&g.name))
    {
        for n in within(&b, g.addr, g.addr + g.extent()) {
            roots.push((n, Root::Initializers(g.name.clone())));
        }
    }

    finish(b, &infos, roots, debug, arch, Linker::Msvc, |c| {
        c.characteristics & LNK_COMDAT != 0
    })
}

/// What the graph says of each node, while it is built.
struct Info {
    name: String,
    aliases: Vec<String>,
    kind: Option<SymbolKind>,
    /// For unlabeled data, its section: it is split where referred
    /// to, and each piece named for its address.
    unlabeled: Option<String>,
}

/// Nodes: one per address range of the symbols; folded names are aliases.
fn symbol_nodes(symbols: &[Symbol], executable: &dyn Fn(u64) -> bool) -> Vec<(Node, Info)> {
    let mut nodes: Vec<(Node, Info)> = Vec::new();
    let mut sorted: Vec<&Symbol> = symbols.iter().collect();
    sorted.sort_by_key(|s| (s.addr, s.folded));
    for s in sorted {
        let size = s.size.vm.max(s.size.file);
        if let Some((n, info)) = nodes.last_mut()
            && n.start == s.addr
            && (s.folded || size == n.end - n.start)
        {
            info.aliases.push(s.name.clone());
            continue;
        }
        if s.folded || size == 0 {
            continue;
        }
        nodes.push((
            Node {
                start: s.addr,
                end: s.addr + size,
                code: executable(s.addr),
            },
            Info {
                name: s.name.clone(),
                aliases: Vec::new(),
                kind: Some(s.kind),
                unlabeled: None,
            },
        ));
    }
    nodes
}

/// Data that holds pointers (at `slots`) but has no symbol (a Rust trait
/// object's vtable, a compiler's anonymous table): the range between its
/// neighbors in its section, as a node, so that what refers to it and
/// what it points to stay connected; split where it is referred to (an
/// object starts where code takes its address), so that one object
/// doesn't make the others in the range reached.
fn unlabeled_data(nodes: &mut Vec<(Node, Info)>, slots: impl Iterator<Item = u64>, model: &Model) {
    let mut spans: Vec<(u64, u64)> = nodes.iter().map(|(n, _)| (n.start, n.end)).collect();
    spans.sort_unstable();
    let mut covered = Vec::with_capacity(spans.len());
    let mut end = 0;
    for s in &spans {
        end = end.max(s.1);
        covered.push(end);
    }
    let mut gaps = std::collections::BTreeMap::new();
    for slot in slots {
        let i = spans.partition_point(|s| s.0 <= slot);
        let before = if i == 0 { 0 } else { covered[i - 1] };
        if before > slot {
            continue;
        }
        let Some(sec) = model
            .sections
            .iter()
            .find(|s| slot >= s.addr && slot < s.addr + s.size.vm.max(s.size.file))
            .filter(|s| !s.executable())
        else {
            continue;
        };
        let lo = before.max(sec.addr);
        let hi = spans
            .get(i)
            .map_or(u64::MAX, |s| s.0)
            .min(sec.addr + sec.size.vm.max(sec.size.file));
        gaps.entry(lo).or_insert((hi, sec.name.clone()));
    }
    for (lo, (hi, section)) in gaps {
        nodes.push((
            Node {
                start: lo,
                end: hi,
                code: false,
            },
            Info {
                name: String::new(),
                aliases: Vec::new(),
                kind: None,
                unlabeled: Some(section),
            },
        ));
    }
}

/// The builder of `nodes` (in its order: by start, outer first), with
/// their names along; unlabeled data split where referred to.
fn builder(mut nodes: Vec<(Node, Info)>) -> (Builder, Vec<Info>) {
    nodes.sort_by_key(|(n, _)| (n.start, std::cmp::Reverse(n.end)));
    let (nodes, infos): (Vec<Node>, Vec<Info>) = nodes.into_iter().unzip();
    let mut b = Builder::new(nodes);
    for (i, info) in infos.iter().enumerate() {
        if info.unlabeled.is_some() {
            b.split(i as u32);
        }
    }
    debug_assert!(
        b.nodes()
            .windows(2)
            .all(|w| (w[0].start, std::cmp::Reverse(w[0].end))
                <= (w[1].start, std::cmp::Reverse(w[1].end)))
    );
    (b, infos)
}

/// The nodes wholly within `[start, end)`.
fn within(b: &Builder, start: u64, end: u64) -> Vec<u32> {
    let nodes = b.nodes();
    let i = nodes.partition_point(|n| n.start < start);
    (i..nodes.len())
        .take_while(|&j| nodes[j].start < end)
        .filter(|&j| nodes[j].end <= end)
        .map(|j| j as u32)
        .collect()
}

/// The graph built, and what its roots (and the linker's keeping)
/// reach. `comdat` says whether a contribution's input section is one the
/// linker could have dropped alone.
fn finish(
    b: Builder,
    infos: &[Info],
    roots: Vec<(u32, Root)>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    arch: Arch,
    linker: Linker,
    comdat: impl Fn(&hexcavator_debuginfo::Contribution) -> bool,
) -> Result<Xref, String> {
    let graph = b.finish();
    // Roots and names, for the graph's nodes (pieces of split ones).
    let roots: Vec<(u32, Root)> = roots
        .into_iter()
        .flat_map(|(n, why)| graph.pieces(n).map(move |p| (p, why.clone())))
        .collect();
    let ids: Vec<u32> = roots.iter().map(|r| r.0).collect();
    let reach = graph.reach(&ids);
    let count = graph.nodes().len() as u32;
    let info = |j: u32| &infos[graph.origin(j) as usize];
    let kinds = (0..count).map(|j| info(j).kind).collect();
    let aliases = (0..count).map(|j| info(j).aliases.clone()).collect();
    let names = (0..count)
        .map(|j| match &info(j).unlabeled {
            Some(section) => format!(
                "[unnamed data in {section} at {:#x}]",
                graph.nodes()[j as usize].start
            ),
            None => info(j).name.clone(),
        })
        .collect();
    // Each node's input section.
    let mut contributions = debug.contributions().map_err(|e| e.to_string())?;
    contributions.sort_by_key(|c| c.addr);
    let (compilands, libraries) = debug
        .compilands()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|c| (c.name, c.library))
        .unzip();
    let contribution: Vec<Option<(u32, bool)>> = graph
        .nodes()
        .iter()
        .map(|n| {
            let i = contributions.partition_point(|c| c.addr <= n.start);
            let c = contributions[..i]
                .last()
                .filter(|c| n.start < c.addr + c.size)?;
            Some((c.compiland, comdat(c)))
        })
        .collect();
    // What the linker must keep: the roots, and every section that is not
    // a COMDAT (whole, if anything in it is used; here, every one, since
    // only linked objects contribute).
    let mut kept: Vec<u32> = ids;
    kept.extend((0..count).filter(|&j| matches!(contribution[j as usize], Some((_, false)))));
    let kept_reach = graph.reach(&kept);
    Ok(Xref {
        linker,
        arch,
        graph,
        names,
        aliases,
        kinds,
        roots,
        reach,
        contribution,
        compilands,
        libraries,
        kept_reach,
    })
}

/// The cross-reference graph of an image: PE's (see [`pe`]) or ELF's
/// (see [`elf`]).
pub fn build(
    image: &hexcavator_image::Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &Model,
    symbols: &[Symbol],
) -> Result<Xref, String> {
    if let Some(file) = image.pe() {
        return pe(file, debug, model, symbols);
    }
    if image.elf().is_some() {
        return elf(image, debug, model, symbols);
    }
    if image.macho().is_some() {
        return macho(image, debug, model, symbols);
    }
    if image.wasm().is_some() {
        return wasm(image, debug, model, symbols);
    }
    Err("cross-references are of PE, ELF, Mach-O, and WebAssembly images, so far".into())
}

/// The parts of a graph every format's builder makes the same way: the
/// symbols' nodes (with unlabeled data where pointers are), their code's
/// references, and the pointers the image's slots hold. The builder, the
/// nodes' names, and the slots.
fn common(
    image: &hexcavator_image::Image<'_>,
    model: &Model,
    symbols: &[Symbol],
    arch: Arch,
) -> (Builder, Vec<Info>, Vec<hexcavator_image::PointerSlot>) {
    let executable = |addr: u64| {
        model
            .sections
            .iter()
            .any(|s| s.executable() && addr >= s.addr && addr < s.addr + s.size.vm.max(s.size.file))
    };
    let mut nodes = symbol_nodes(symbols, &executable);
    let slots = image.pointer_slots();
    unlabeled_data(&mut nodes, slots.iter().map(|s| s.addr), model);
    let (mut b, infos) = builder(nodes);
    for i in 0..b.nodes().len() as u32 {
        let n = b.nodes()[i as usize];
        if n.code {
            b.code(i, arch, file_bytes(image, n.start, n.end - n.start));
        }
    }
    for s in &slots {
        if let Some(to) = s.target {
            pointer_edge(&mut b, s.addr, to);
        }
    }
    (b, infos, slots)
}

/// The file's bytes at an address: as many as its section has there.
fn file_bytes<'d>(image: &hexcavator_image::Image<'d>, start: u64, len: u64) -> &'d [u8] {
    let Some(s) = image
        .sections()
        .into_iter()
        .find(|s| s.file_size > 0 && start >= s.addr && start - s.addr < s.file_size)
    else {
        return &[];
    };
    let len = len.min(s.file_size - (start - s.addr));
    image.bytes_at(start, len).unwrap_or(&[])
}

/// A pointer at `slot` to `to`: an address code takes, or data's pointer.
fn pointer_edge(b: &mut Builder, slot: u64, to: u64) {
    let in_code = b.node_at(slot).is_some_and(|f| b.nodes()[f as usize].code);
    b.edge_at(
        slot,
        to,
        if in_code {
            Edge::Address
        } else {
            Edge::Pointer
        },
    );
}

/// Nodes without a contribution take their symbol's compiland (DWARF
/// records compile units' ranges of code only).
fn units_of_data(x: &mut Xref, symbols: &[Symbol]) {
    let units: rustc_hash::FxHashMap<u64, u32> = symbols
        .iter()
        .filter_map(|s| Some((s.addr, s.compiland?)))
        .collect();
    for (j, n) in x.graph.nodes().iter().enumerate() {
        if x.contribution[j].is_none() {
            x.contribution[j] = units.get(&n.start).map(|&c| (c, true));
        }
    }
}

/// The cross-reference graph of a Mach-O image (an executable, dylib, or
/// bundle), from its symbols, code, and fixups (rebases; binds are
/// imports'). Roots: the entry point (`LC_MAIN`), the exports (its exports
/// trie), the initializers and terminators dyld calls
/// (`S_MOD_INIT_FUNC_POINTERS`, `S_MOD_TERM_FUNC_POINTERS`,
/// `S_INIT_FUNC_OFFSETS`), and thread-local data. Contributions are
/// compile units', taken as atoms `-dead_strip` could drop alone.
pub fn macho(
    image: &hexcavator_image::Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &Model,
    symbols: &[Symbol],
) -> Result<Xref, String> {
    use hexcavator_macho::consts::*;
    let m = image.macho().ok_or("not a Mach-O image")?;
    let arch = image.arch();
    if !matches!(arch, Arch::X64 | Arch::X86 | Arch::Arm64) {
        return Err(format!("no cross-references for {}", arch.name()));
    }
    let (b, infos, slots) = common(image, model, symbols, arch);

    let mut roots: Vec<(u32, Root)> = Vec::new();
    if let Some(n) = m.entry().and_then(|e| b.node_at(e)) {
        roots.push((n, Root::EntryPoint));
    }
    for e in m.exports() {
        if let Some(n) = e.address.and_then(|a| b.node_at(a)) {
            roots.push((
                n,
                Root::Export(String::from_utf8_lossy(&e.name).into_owned()),
            ));
        }
    }
    let base = m
        .segments()
        .iter()
        .find(|s| s.fileoff == 0 && s.filesize > 0)
        .map_or(0, |s| s.vmaddr);
    for s in m.sections() {
        let name = format!(
            "{},{}",
            String::from_utf8_lossy(s.segname),
            String::from_utf8_lossy(s.sectname)
        );
        let (start, end) = (s.addr, s.addr.saturating_add(s.size));
        match s.kind() {
            S_MOD_INIT_FUNC_POINTERS | S_MOD_TERM_FUNC_POINTERS => {
                let i = slots.partition_point(|p| p.addr < start);
                for p in slots[i..].iter().take_while(|p| p.addr < end) {
                    if let Some(n) = p.target.and_then(|t| b.node_at(t)) {
                        roots.push((n, Root::Initializers(name.clone())));
                    }
                }
            }
            S_INIT_FUNC_OFFSETS => {
                let bytes = file_bytes(image, start, s.size);
                for w in bytes.as_chunks::<4>().0.iter().take(1 << 20) {
                    let off = u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
                    if let Some(n) = b.node_at(base.wrapping_add(off)) {
                        roots.push((n, Root::Initializers(name.clone())));
                    }
                }
            }
            S_THREAD_LOCAL_REGULAR
            | S_THREAD_LOCAL_ZEROFILL
            | S_THREAD_LOCAL_VARIABLES
            | S_THREAD_LOCAL_VARIABLE_POINTERS => {
                for n in within(&b, start, end) {
                    roots.push((n, Root::LoaderData("thread-local data")));
                }
            }
            _ => continue,
        }
        for n in within(&b, start, end) {
            roots.push((n, Root::Initializers(name.clone())));
        }
    }
    let mut x = finish(b, &infos, roots, debug, arch, Linker::MachO, |_| true)?;
    units_of_data(&mut x, symbols);
    Ok(x)
}

/// The cross-reference graph of a WebAssembly module, from its symbols
/// (functions at their bodies' code-section offsets, as DWARF has them)
/// and code: its calls, tail calls, and `ref.func`s. Roots: its exports,
/// its start function, and the functions its element segments put in
/// tables (any of them can be called indirectly). Its linker is taken to
/// be wasm-ld, which drops functions as ELF linkers drop sections
/// (`--gc-sections`).
pub fn wasm(
    image: &hexcavator_image::Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &Model,
    symbols: &[Symbol],
) -> Result<Xref, String> {
    use hexcavator_wasm_isa::code;
    let m = image.wasm().ok_or("not a WebAssembly module")?;
    let arch = image.arch();
    let (mut b, infos, _) = common(image, model, symbols, arch);
    let code_at = m
        .sections()
        .iter()
        .find(|s| s.id == hexcavator_wasm::SECTION_CODE)
        .map_or(0, |s| s.contents_offset);
    // Each defined function's address: its body's (after its size), in
    // the code section.
    let mut address: rustc_hash::FxHashMap<u32, u64> = rustc_hash::FxHashMap::default();
    let pieces = m.functions();
    for p in &pieces {
        if let Some((at, _)) = m.body(p) {
            address.insert(p.index, at - code_at);
        }
    }
    for p in &pieces {
        let (Some((at, body)), Some(&from)) = (m.body(p), address.get(&p.index)) else {
            continue;
        };
        let Ok(locals) = code::locals(body) else {
            continue;
        };
        let Some(instructions) = body.get(locals.code_start..) else {
            continue;
        };
        let first = at - code_at + locals.code_start as u64;
        for (off, inst) in code::instructions(instructions) {
            let Ok(i) = inst else { break };
            let code::Imm::Index(f) = i.imm else { continue };
            let kind = match i.op.name {
                "call" => Edge::Call,
                "return_call" => Edge::Jump,
                "ref.func" => Edge::Address,
                _ => continue,
            };
            if let Some(&to) = address.get(&f) {
                // (From the instruction, in the calling function.)
                let pc = first + off as u64;
                if b.node_at(pc).is_some() {
                    b.edge_at(pc, to, kind);
                } else {
                    b.edge_at(from, to, kind);
                }
            }
        }
    }
    let mut roots: Vec<(u32, Root)> = Vec::new();
    for e in m.exports() {
        if e.kind != 0 {
            continue;
        }
        if let Some(n) = address.get(&e.index).and_then(|&a| b.node_at(a)) {
            roots.push((
                n,
                Root::Export(String::from_utf8_lossy(e.name).into_owned()),
            ));
        }
    }
    if let Some(n) = m
        .start_function()
        .and_then(|f| address.get(&f))
        .and_then(|&a| b.node_at(a))
    {
        roots.push((n, Root::EntryPoint));
    }
    for f in m.element_functions() {
        if let Some(n) = address.get(&f).and_then(|&a| b.node_at(a)) {
            roots.push((
                n,
                Root::LoaderData("a table's functions (called indirectly)"),
            ));
        }
    }
    let mut x = finish(b, &infos, roots, debug, arch, Linker::Elf, |_| true)?;
    units_of_data(&mut x, symbols);
    Ok(x)
}

/// The cross-reference graph of an ELF image (an executable or shared
/// object), from its symbols, code, and pointers:
///
/// - Pointers: the slots its dynamic relocations (and packed relative
///   ones) fill. An executable with none (not position-independent: the
///   linker resolved every address in place) has its data's aligned words
///   that are the start of a symbol taken as pointers to it.
/// - Roots: the entry point, the exported (dynamic) symbols, the
///   initializers and finalizers the loader calls (`.preinit_array`,
///   `.init_array`, `.fini_array`, `.ctors`, `.dtors`, `DT_INIT`,
///   `DT_FINI`), and thread-local data.
///
/// (Exception data, `.eh_frame`'s FDEs, isn't followed yet: a function's
/// is its own.) Contributions are compile units', whose input sections
/// DWARF doesn't record: each is taken as one the linker could drop alone
/// (as `-ffunction-sections` and `--gc-sections` make them).
pub fn elf(
    image: &hexcavator_image::Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &Model,
    symbols: &[Symbol],
) -> Result<Xref, String> {
    use hexcavator_elf::consts::*;
    let file = image.elf().ok_or("not an ELF image")?;
    let arch = image.arch();
    if !matches!(arch, Arch::X64 | Arch::X86 | Arch::Arm64) {
        return Err(format!("no cross-references for {}", arch.name()));
    }
    let (mut b, infos, slots) = common(image, model, symbols, arch);
    let bytes = |start: u64, len: u64| file_bytes(image, start, len);
    let width = u64::from(arch.pointer_size().unwrap_or(8));
    let word = |at: u64| -> Option<u64> {
        let w = bytes(at, width);
        (w.len() as u64 == width).then(|| match file.endian() {
            hexcavator_core::Endian::Little => {
                w.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x))
            }
            hexcavator_core::Endian::Big => w.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)),
        })
    };
    if slots.is_empty() && !file.is_object() {
        // Every address resolved in place: data's words that start a node.
        let starts: rustc_hash::FxHashSet<u64> = b.nodes().iter().map(|n| n.start).collect();
        for s in model
            .sections
            .iter()
            .filter(|s| !s.executable() && s.size.file > 0)
        {
            let mut at = s.addr.next_multiple_of(width);
            while at + width <= s.addr + s.size.file {
                if let Some(v) = word(at).filter(|v| starts.contains(v)) {
                    pointer_edge(&mut b, at, v);
                }
                at += width;
            }
        }
    }

    // Roots.
    let mut roots: Vec<(u32, Root)> = Vec::new();
    if let Some(n) = b.node_at(file.header().entry) {
        roots.push((n, Root::EntryPoint));
    }
    for sym in file
        .sections()
        .filter(|s| s.kind == SHT_DYNSYM)
        .flat_map(|t| file.symbols(&t))
    {
        let exported = sym.shndx != u32::from(SHN_UNDEF)
            && matches!(sym.bind, STB_GLOBAL | STB_WEAK)
            && matches!(sym.visibility, 0 | 3);
        if exported
            && !sym.name.is_empty()
            && let Some(n) = b.node_at(sym.value)
        {
            roots.push((
                n,
                Root::Export(String::from_utf8_lossy(sym.name).into_owned()),
            ));
        }
    }
    // The loader's initializers and finalizers: arrays of them, and the
    // dynamic table's single ones.
    for s in file.sections() {
        let name = String::from_utf8_lossy(s.name).into_owned();
        let array = matches!(s.kind, SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY)
            || matches!(name.as_str(), ".ctors" | ".dtors");
        if !array || !s.is_alloc() {
            continue;
        }
        for i in 0..(s.size / width).min(1 << 20) {
            let at = s.addr + i * width;
            let to = slots
                .binary_search_by_key(&at, |p| p.addr)
                .ok()
                .and_then(|j| slots[j].target)
                .or_else(|| word(at));
            if let Some(n) = to.and_then(|t| b.node_at(t)) {
                roots.push((n, Root::Initializers(name.clone())));
            }
        }
        for n in within(&b, s.addr, s.addr + s.size) {
            roots.push((n, Root::Initializers(name.clone())));
        }
    }
    for d in file.dynamic() {
        let what = match d.tag {
            DT_INIT => "DT_INIT",
            DT_FINI => "DT_FINI",
            _ => continue,
        };
        if let Some(n) = b.node_at(d.value) {
            roots.push((n, Root::Initializers(what.to_string())));
        }
    }
    // Thread-local data: code reaches it by offsets from the thread's
    // block, which no relocation or address shows.
    for p in file.segments().filter(|p| p.kind == PT_TLS) {
        for n in within(&b, p.vaddr, p.vaddr.saturating_add(p.memsz)) {
            roots.push((n, Root::LoaderData("thread-local data")));
        }
    }
    let mut x = finish(b, &infos, roots, debug, arch, Linker::Elf, |_| true)?;
    units_of_data(&mut x, symbols);
    Ok(x)
}

/// `IMAGE_SCN_LNK_COMDAT`.
const LNK_COMDAT: u32 = 0x1000;

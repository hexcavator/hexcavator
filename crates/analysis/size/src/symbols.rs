//! The symbols of an image: what occupies each range of bytes, by name.
//!
//! Symbols come from the debug information (functions, blocks of code,
//! thunks, data, publics) and from the image's own structures: exception
//! data ([`crate::eh`]), imports and directories ([`crate::pe_symbols`]),
//! and resources ([`crate::rsrc`]).
//!
//! Several names can share one address: identical COMDAT folding (ICF)
//! keeps one copy of identical functions or data. One name is *canonical*
//! (the least, by ordinal comparison, as SizeBench chooses) and carries the
//! size; the others are listed as *folded*, with size 0, so that sizes sum
//! to the bytes the image holds.

use std::collections::HashMap;

use hexcavator_core::Result;
use hexcavator_debuginfo::{DebugInfo, Symbol as DebugSymbol, SymbolKind as DebugKind};
use hexcavator_image::Image;

use crate::{Model, Size};

/// What a [`Symbol`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SymbolKind {
    /// A function in one piece.
    Function,
    /// The main block of a function whose code is split (by PGO, say).
    PrimaryBlock,
    /// A separated block of such a function.
    SeparatedBlock,
    Thunk,
    Data,
    /// A public symbol with no other debug information.
    Public,
    /// A string literal (a `??_C@` public).
    String,
    /// A `.pdata` entry (`RUNTIME_FUNCTION`) pointing to unwind data.
    Pdata,
    /// An ARM `.pdata` entry holding packed unwind data itself.
    PackedPdata,
    /// An ARM `.pdata` entry forwarding to another entry.
    ForwarderPdata,
    /// Unwind data (`UNWIND_INFO`, or ARM `.xdata`), with its handler's
    /// language-specific data.
    Unwind,
    /// x64 unwind data chained to another function's.
    ChainUnwind,
    /// C++ EH: a `FuncInfo` (or FH4 `FuncInfo4`).
    CppXdata,
    /// C++ EH: the state unwind map.
    StateUnwindMap,
    /// C++ EH: the try block map.
    TryMap,
    /// C++ EH: a try block's catch handlers.
    HandlerMap,
    /// C++ EH: an IP-to-state map.
    IpToStateMap,
    /// FH4: a separated function's segment map.
    SegmentMap,
    /// An `IMAGE_IMPORT_DESCRIPTOR` or `IMAGE_DELAYLOAD_DESCRIPTOR`.
    ImportDescriptor,
    /// An import name (or delay-load address) table entry.
    ImportThunk,
    /// An imported function's hint and name (`IMAGE_IMPORT_BY_NAME`).
    ImportByName,
    /// An imported DLL's name.
    ImportString,
    /// A PE data directory's table, or a debug directory entry's data.
    PeDirectory,
    /// A guard table of the load configuration.
    LoadConfigTable,
    /// A resource directory table.
    RsrcDirectory,
    /// A resource data entry (`IMAGE_RESOURCE_DATA_ENTRY`).
    RsrcDataEntry,
    /// A resource directory's name string.
    RsrcString,
    /// A resource's data.
    RsrcData,
    /// An icon group and its icons.
    RsrcGroupIcon,
    /// A cursor group and its cursors.
    RsrcGroupCursor,
    /// A run of string tables.
    RsrcStringTables,
}

impl SymbolKind {
    /// A short lowercase name for the kind, for queries and tables
    /// (`function`, `primary-block`, `pdata`, ...).
    pub fn label(self) -> &'static str {
        use SymbolKind as K;
        match self {
            K::Function => "function",
            K::PrimaryBlock => "primary-block",
            K::SeparatedBlock => "separated-block",
            K::Thunk => "thunk",
            K::Data => "data",
            K::Public => "public",
            K::String => "string",
            K::Pdata => "pdata",
            K::PackedPdata => "packed-pdata",
            K::ForwarderPdata => "forwarder-pdata",
            K::Unwind => "unwind",
            K::ChainUnwind => "chain-unwind",
            K::CppXdata => "cpp-xdata",
            K::StateUnwindMap => "state-unwind-map",
            K::TryMap => "try-map",
            K::HandlerMap => "handler-map",
            K::IpToStateMap => "ip-to-state-map",
            K::SegmentMap => "segment-map",
            K::ImportDescriptor => "import-descriptor",
            K::ImportThunk => "import-thunk",
            K::ImportByName => "import-by-name",
            K::ImportString => "import-string",
            K::PeDirectory => "pe-directory",
            K::LoadConfigTable => "load-config-table",
            K::RsrcDirectory => "resource-directory",
            K::RsrcDataEntry => "resource-data-entry",
            K::RsrcString => "resource-string",
            K::RsrcData => "resource-data",
            K::RsrcGroupIcon => "resource-icon-group",
            K::RsrcGroupCursor => "resource-cursor-group",
            K::RsrcStringTables => "resource-string-tables",
        }
    }

    /// The name of SizeBench's class for this kind of symbol.
    pub fn sizebench_name(self) -> &'static str {
        match self {
            SymbolKind::Function => "SimpleFunctionCodeSymbol",
            SymbolKind::PrimaryBlock => "PrimaryCodeBlockSymbol",
            SymbolKind::SeparatedBlock => "SeparatedCodeBlockSymbol",
            SymbolKind::Thunk => "ThunkSymbol",
            SymbolKind::Data => "StaticDataSymbol",
            SymbolKind::Public => "PublicSymbol",
            SymbolKind::String => "StringSymbol",
            SymbolKind::Pdata => "PDataSymbol",
            SymbolKind::PackedPdata => "PackedUnwindDataPDataSymbol",
            SymbolKind::ForwarderPdata => "ForwarderPDataSymbol",
            SymbolKind::Unwind => "UnwindInfoSymbol",
            SymbolKind::ChainUnwind => "ChainUnwindInfoSymbol",
            SymbolKind::CppXdata => "CppXdataSymbol",
            SymbolKind::StateUnwindMap => "StateUnwindMapSymbol",
            SymbolKind::TryMap => "TryMapSymbol",
            SymbolKind::HandlerMap => "HandlerMapSymbol",
            SymbolKind::IpToStateMap => "IpToStateMapSymbol",
            SymbolKind::SegmentMap => "SeparatedIpToStateMapSymbol",
            SymbolKind::ImportDescriptor => "ImportDescriptorSymbol",
            SymbolKind::ImportThunk => "ImportThunkSymbol",
            SymbolKind::ImportByName => "ImportByNameSymbol",
            SymbolKind::ImportString => "ImportStringSymbol",
            SymbolKind::PeDirectory => "PEDirectorySymbol",
            SymbolKind::LoadConfigTable => "LoadConfigTableSymbol",
            SymbolKind::RsrcDirectory => "RsrcDirectorySymbol",
            SymbolKind::RsrcDataEntry => "RsrcDataEntrySymbol",
            SymbolKind::RsrcString => "RsrcStringSymbol",
            SymbolKind::RsrcData => "RsrcDataSymbol",
            SymbolKind::RsrcGroupIcon => "RsrcGroupIconDataSymbol",
            SymbolKind::RsrcGroupCursor => "RsrcGroupCursorDataSymbol",
            SymbolKind::RsrcStringTables => "RsrcGroupStringTablesDataSymbol",
        }
    }

    /// Every kind, in declaration order (`ALL[k as usize] == k`).
    pub const ALL: [SymbolKind; 31] = [
        SymbolKind::Function,
        SymbolKind::PrimaryBlock,
        SymbolKind::SeparatedBlock,
        SymbolKind::Thunk,
        SymbolKind::Data,
        SymbolKind::Public,
        SymbolKind::String,
        SymbolKind::Pdata,
        SymbolKind::PackedPdata,
        SymbolKind::ForwarderPdata,
        SymbolKind::Unwind,
        SymbolKind::ChainUnwind,
        SymbolKind::CppXdata,
        SymbolKind::StateUnwindMap,
        SymbolKind::TryMap,
        SymbolKind::HandlerMap,
        SymbolKind::IpToStateMap,
        SymbolKind::SegmentMap,
        SymbolKind::ImportDescriptor,
        SymbolKind::ImportThunk,
        SymbolKind::ImportByName,
        SymbolKind::ImportString,
        SymbolKind::PeDirectory,
        SymbolKind::LoadConfigTable,
        SymbolKind::RsrcDirectory,
        SymbolKind::RsrcDataEntry,
        SymbolKind::RsrcString,
        SymbolKind::RsrcData,
        SymbolKind::RsrcGroupIcon,
        SymbolKind::RsrcGroupCursor,
        SymbolKind::RsrcStringTables,
    ];

    /// The prefix of the names of symbols of this kind that describe
    /// another (`[pdata] f()`), if it is one.
    pub fn prefix(self) -> Option<&'static str> {
        Some(match self {
            SymbolKind::Pdata => "[pdata]",
            SymbolKind::PackedPdata => "[packedUnwindData-pdata]",
            SymbolKind::ForwarderPdata => "[forwarder-pdata]",
            SymbolKind::Unwind => "[unwind]",
            SymbolKind::ChainUnwind => "[chain-unwind]",
            SymbolKind::CppXdata => "[cppxdata]",
            SymbolKind::StateUnwindMap => "[stateUnwindMap]",
            SymbolKind::TryMap => "[tryMap]",
            SymbolKind::HandlerMap => "[handlerMap]",
            SymbolKind::IpToStateMap => "[ip2state]",
            SymbolKind::SegmentMap => "[seg2ip2state]",
            _ => return None,
        })
    }
}

/// A symbol of the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub addr: u64,
    /// File and memory size; zero for folded symbols.
    pub size: Size,
    pub kind: SymbolKind,
    /// Whether this name was folded into another symbol at the same address.
    pub folded: bool,
    pub name: String,
    /// The compiland whose debug information holds the symbol, if known.
    pub compiland: Option<u32>,
    /// A variable with internal linkage at file scope (C++ `static`, or
    /// `const` without `extern`): every compiland that includes its
    /// definition gets a copy.
    pub file_static: bool,
}

/// A candidate symbol at one address, before folding is resolved.
struct Candidate<'a> {
    kind: SymbolKind,
    size: u64,
    name: String,
    /// What makes two names at one address the same name.
    identity: (String, u32),
    debug: &'a DebugSymbol,
}

/// Builds the symbol list of `image` from `debug`, attributing sizes as
/// file or memory-only by the groups of `model`.
pub fn build(image: &Image<'_>, debug: &DebugInfo<'_>, model: &Model) -> Result<Vec<Symbol>> {
    let symbols = debug.symbols()?;
    // Thunks of modules with no section contributions at all (lld-link
    // records its import thunks in such modules, `Import:<dll>`) are not
    // shown, as DIA doesn't show them; they still give the publics at the
    // same addresses their sizes. (Other symbols of such modules are shown:
    // a module all of whose code was folded into others' contributes
    // nothing, but its functions are folded names.)
    let contributing: std::collections::HashSet<u32> =
        debug.contributions()?.iter().map(|c| c.compiland).collect();
    let (mut shown, hidden): (Vec<DebugSymbol>, Vec<DebugSymbol>) =
        symbols.into_iter().partition(|s| {
            s.kind != DebugKind::Thunk || s.compiland.is_none_or(|m| contributing.contains(&m))
        });
    // Functions are named with their signatures, which also tells
    // overloads apart.
    let mut namer = crate::names::Namer::new(debug);
    for s in &mut shown {
        if matches!(s.kind, DebugKind::Function | DebugKind::SeparatedBlock) {
            s.name = namer.function(&s.name, hexcavator_debuginfo::TypeRef(s.type_index));
        } else if let (DebugKind::Data, Some(f)) = (s.kind, &s.function) {
            // A function's static: `x (in static bool C::f())`.
            s.name = format!(
                "{} (in {})",
                s.name,
                namer.qualified_function(&f.name, f.ty, &f.params)
            );
        }
    }
    let mut demangler = hexcavator_demangle::msvc::Demangler::default();
    // The publics at each address, for naming vtables.
    let mut publics_at: HashMap<u64, Vec<&str>> = HashMap::new();
    for s in shown.iter().filter(|s| s.kind == DebugKind::Public) {
        publics_at.entry(s.addr).or_default().push(&s.name);
    }
    let mut display = |s: &DebugSymbol, kind: SymbolKind, size: u64, name: String| match kind {
        SymbolKind::String => string_name(image, s.addr, size, &s.name).unwrap_or(name),
        SymbolKind::Public => {
            // Rust's and Swift's publics are mangled their own ways, on
            // Windows too.
            let mut rust = String::new();
            if hexcavator_demangle::rust::demangle_into(&name, &mut rust) {
                rust
            } else if let Some(swift) = hexcavator_demangle::swift::demangle(&name) {
                swift
            } else {
                demangler
                    .demangle(&name, hexcavator_demangle::msvc::flags::NO_PTR64)
                    .unwrap_or(name)
            }
        }
        // A thunk is named by its public, if it has one (x86 C names keep
        // their underscore), undecorated without access, `virtual`, return
        // type, calling convention, `this` qualifiers, or class-keys:
        // `[thunk]:C::f`adjustor{8}' (void)` (undname flags 0xA2E6).
        SymbolKind::Thunk => match publics_at.get(&s.addr).and_then(|p| p.iter().min()) {
            Some(public) => {
                use hexcavator_demangle::msvc::flags::*;
                let flags = NO_ACCESS_SPECIFIERS
                    | NO_MEMBER_TYPE
                    | NO_FUNCTION_RETURNS
                    | NO_MS_KEYWORDS
                    | NO_THISTYPE
                    | NO_ECSU
                    | NO_PTR64;
                demangler
                    .demangle(public, flags)
                    .unwrap_or_else(|| public.to_string())
            }
            None => name,
        },
        // A vtable's data symbol records `X::`vftable'`; its public has the
        // whole name, `X::`vftable'{for `Base'}`. Of several publics here
        // (vtables folded together), the least name.
        SymbolKind::Data if name.ends_with("`vftable'") => publics_at
            .get(&s.addr)
            .into_iter()
            .flatten()
            .filter_map(|p| demangler.demangle(p, hexcavator_demangle::msvc::flags::NO_PTR64))
            .map(|p| p.strip_prefix("const ").map(str::to_string).unwrap_or(p))
            .filter(|p| p.starts_with(name.as_str()))
            .min()
            .unwrap_or(name),
        _ => name,
    };
    let from_debug = from_debug_symbols(&shown, &hidden, model, &mut display);

    // Symbols for what the image itself describes.
    let Some(pe) = image.pe() else {
        return Ok(from_debug);
    };
    let mut handlers: HashMap<u64, crate::eh::Handler> = HashMap::new();
    for s in shown.iter().chain(&hidden) {
        if matches!(
            s.kind,
            DebugKind::Function | DebugKind::Thunk | DebugKind::Public
        ) {
            let h = crate::eh::Handler::from_name(&s.name);
            if h != crate::eh::Handler::Other {
                handlers.insert(s.addr, h);
            }
        }
    }
    // Targets are named by the canonical (non-folded) symbol holding them.
    let canonical: Vec<&Symbol> = from_debug.iter().filter(|s| !s.folded).collect();
    let context = Targets {
        symbols: &canonical,
        handlers,
    };
    let eh_symbols = crate::eh::symbols(pe, &context);
    let pe_symbols = crate::pe_symbols::symbols(pe);
    let rsrc_symbols = crate::rsrc::symbols(pe);

    // Debug symbols in `.pdata` and the resource directory are not shown
    // (the entries and resources are), nor those at the address of one of
    // the image's own structures.
    let pdata = pe
        .data_directory(hexcavator_pe::consts::directory::EXCEPTION)
        .map(|d| {
            let start = u64::from(d.virtual_address.get());
            (start, start + u64::from(d.size.get()))
        });
    let rsrc = crate::rsrc::resource_range(pe);
    let outside =
        |range: Option<(u64, u64)>, addr: u64| range.is_none_or(|(a, e)| addr < a || addr >= e);
    let structures: std::collections::HashSet<u64> = pe_symbols.iter().map(|s| s.addr).collect();
    let mut out: Vec<Symbol> = from_debug
        .into_iter()
        .filter(|s| {
            outside(pdata, s.addr) && outside(rsrc, s.addr) && !structures.contains(&s.addr)
        })
        .chain(eh_symbols)
        .chain(pe_symbols)
        .chain(rsrc_symbols)
        .collect();
    out.sort_by_key(|s| s.addr);
    Ok(out)
}

/// Names targets by the debug information's symbols, and knows handlers by
/// their names.
struct Targets<'a> {
    /// The canonical symbols, sorted by address.
    symbols: &'a [&'a Symbol],
    handlers: HashMap<u64, crate::eh::Handler>,
}

impl crate::eh::Context for Targets<'_> {
    fn target_name(&self, addr: u64) -> Option<String> {
        let i = self.symbols.partition_point(|s| s.addr <= addr);
        // (A few back, for symbols inside others: data in code, say.)
        let s = self.symbols[..i]
            .iter()
            .rev()
            .take(8)
            .find(|s| addr >= s.addr && addr - s.addr < s.size.vm.max(1))?;
        Some(s.name.clone())
    }

    fn handler(&self, addr: u64) -> crate::eh::Handler {
        self.handlers
            .get(&addr)
            .copied()
            .unwrap_or(crate::eh::Handler::Other)
    }
}

/// A string literal's name as SizeBench shows it: `` `string': "text" ``
/// (`L"text"` for wide strings), with newlines, returns, and tabs escaped.
/// Its contents are read from the image; `None` if they can't be.
pub fn string_name(image: &Image<'_>, addr: u64, size: u64, decorated: &str) -> Option<String> {
    let bytes = image.bytes_at(addr, size)?;
    let wide = decorated.starts_with("??_C@_1");
    let text = if wide {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    };
    let escaped = text
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    Some(if wide {
        format!("`string': L\"{escaped}\"")
    } else {
        format!("`string': \"{escaped}\"")
    })
}

/// The length in bytes of a string literal from its decorated name,
/// `??_C@_<width><length>@...`: the length is a decorated number (a digit
/// `d` for d + 1, or hex digits written `A`-`P` ending in `@`).
pub fn string_literal_length(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("??_C@_")?;
    let mut chars = rest.bytes();
    let _width = chars.next().filter(|c| matches!(c, b'0' | b'1'))?;
    match chars.next()? {
        d @ b'0'..=b'9' => Some(u64::from(d - b'0') + 1),
        first @ b'A'..=b'P' => {
            let mut value = u64::from(first - b'A');
            for c in chars {
                match c {
                    b'A'..=b'P' => value = value.checked_mul(16)? + u64::from(c - b'A'),
                    b'@' => return Some(value),
                    _ => return None,
                }
            }
            None
        }
        _ => None,
    }
}

/// Whether `addr` is in memory-only (zero-fill) data, by the model's groups.
fn zero_fill_at(model: &Model, addr: u64) -> bool {
    let i = model.groups.partition_point(|g| g.addr <= addr);
    i > 0 && {
        let g = &model.groups[i - 1];
        addr < g.addr + g.extent() && g.zero_fill()
    }
}

/// The symbols from the debug information's `symbols`; `hidden` symbols
/// are not shown but size the publics at their addresses.
/// `display` gives each candidate's shown name from the symbol, its kind,
/// its size, and its name so far.
pub fn from_debug_symbols(
    symbols: &[DebugSymbol],
    hidden: &[DebugSymbol],
    model: &Model,
    display: &mut dyn FnMut(&DebugSymbol, SymbolKind, u64, String) -> String,
) -> Vec<Symbol> {
    // A public at the same address as a sized symbol has that size.
    let mut sized_at: HashMap<u64, u64> = HashMap::new();
    for s in symbols.iter().chain(hidden) {
        if matches!(s.kind, DebugKind::Function | DebugKind::Thunk)
            && let Some(size) = s.size
        {
            sized_at.entry(s.addr).or_insert(size);
        }
    }
    // Publics have no size of their own: they extend to the next public or
    // to the end of the contribution that holds them, whichever is first
    // (a vtable's public starts after the pointer to its complete object
    // locator, and the next vtable may follow in the same contribution).
    let mut public_addrs: Vec<u64> = symbols
        .iter()
        .filter(|s| s.kind == DebugKind::Public)
        .map(|s| s.addr)
        .collect();
    public_addrs.dedup();
    // A public outside every contribution has size 0.
    let public_size = |addr: u64| -> u64 {
        let i = model.pieces.partition_point(|p| p.range.addr <= addr);
        let Some(limit) = model.pieces[..i]
            .iter()
            .rev()
            .take(8)
            .find(|p| p.range.contains(addr))
            .map(|p| p.range.end())
        else {
            return 0;
        };
        let next = public_addrs.partition_point(|&a| a <= addr);
        public_addrs.get(next).map_or(limit, |&n| n.min(limit)) - addr
    };
    // Data of a basic type takes no more than its public says: assembly
    // declares labels such as `Foo_End` as (say) 8-byte integers.
    let public_by_name: HashMap<&str, u64> = symbols
        .iter()
        .filter(|s| s.kind == DebugKind::Public)
        .map(|s| (s.name.as_str(), s.addr))
        .collect();
    // Labels: a public at one is an alternate entry point into code.
    let labels: std::collections::HashSet<u64> = symbols
        .iter()
        .filter(|s| s.kind == DebugKind::Label)
        .map(|s| s.addr)
        .collect();
    // Functions whose code is split: their addresses.
    let mut split: HashMap<u64, ()> = HashMap::new();
    for s in symbols
        .iter()
        .filter(|s| s.kind == DebugKind::SeparatedBlock)
    {
        if let Some(p) = s.parent {
            split.insert(p, ());
        }
    }

    let mut out = Vec::new();
    let mut previous_end: Option<(u64, u64)> = None; // (start, end) of the last non-folded symbol
    let mut i = 0;
    while i < symbols.len() {
        let addr = symbols[i].addr;
        let mut j = i;
        while j < symbols.len() && symbols[j].addr == addr {
            j += 1;
        }
        let here = &symbols[i..j];
        i = j;
        if addr == 0 {
            continue;
        }

        // The candidates at this address, in the order names are considered:
        // code and data, then thunks, then publics.
        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        for s in here {
            let (kind, name) = match s.kind {
                DebugKind::Function if split.contains_key(&s.addr) => (
                    SymbolKind::PrimaryBlock,
                    format!("Block of code in {}", s.name),
                ),
                DebugKind::Function => (SymbolKind::Function, s.name.clone()),
                DebugKind::SeparatedBlock => (
                    SymbolKind::SeparatedBlock,
                    format!("Block of code in {}", s.name),
                ),
                DebugKind::Thunk => (SymbolKind::Thunk, s.name.clone()),
                // A thread-local's offset is in the TLS template, not an address
                // (it can land anywhere: in the import address table, say).
                DebugKind::Data if s.thread_local => continue,
                // Nameless data (ARM literal pools, jump tables) lies in
                // its function's code, which holds its bytes.
                DebugKind::Data if s.name.is_empty() || s.name.starts_with(" (in ") => continue,
                DebugKind::Data => (SymbolKind::Data, s.name.clone()),
                DebugKind::Public if s.name.starts_with("??_C@") => {
                    (SymbolKind::String, s.name.clone())
                }
                DebugKind::Public => (SymbolKind::Public, s.name.clone()),
                // (Blocks and labels have no bytes of their own; nor do
                // kinds other debug formats will add, for now.)
                _ => continue,
            };
            // A marker the compiler puts at each function's unwind data (the
            // unwind data itself is described from the image), and unnamed
            // data (ARM32 literal pools).
            if name == "$xdatasym" || name.is_empty() {
                continue;
            }
            let size = match kind {
                SymbolKind::String => {
                    string_literal_length(&s.name).unwrap_or_else(|| public_size(s.addr))
                }
                SymbolKind::Public => sized_at
                    .get(&s.addr)
                    .copied()
                    .unwrap_or_else(|| public_size(s.addr)),
                // A vtable's type doesn't give its size; its public does.
                SymbolKind::Data
                    if s.name.contains("`vftable'")
                        && public_addrs.binary_search(&s.addr).is_ok() =>
                {
                    public_size(s.addr)
                }
                // A global of one of PDB's simple types (a basic type, or a
                // pointer to one) is no larger than its public says. (Only
                // PDBs have publics: for other formats this changes
                // nothing.)
                SymbolKind::Data
                    if s.global
                        && hexcavator_debuginfo::TypeRef(s.type_index)
                            .pdb_index()
                            .is_simple() =>
                {
                    let size = s.size.unwrap_or(0);
                    public_by_name
                        .get(s.name.as_str())
                        .map_or(size, |&a| size.min(public_size(a)))
                }
                _ => s.size.unwrap_or(0),
            };
            // Names as shown (publics undecorated, strings by their
            // contents) decide which name is canonical, and two symbols of
            // one name are one symbol (functions' names include their
            // signatures, so overloads stay apart).
            let name = display(s, kind, size, name);
            let identity = (name.clone(), 0);
            candidates.push(Candidate {
                kind,
                size,
                name,
                identity,
                debug: s,
            });
        }
        // A function's static recorded both in the function and at file
        // scope (an inline function's, compiled in several modules) is one
        // variable, named for its function.
        let raw = |c: &Candidate<'_>| -> String {
            match &c.debug.function {
                Some(_) => c
                    .debug
                    .name
                    .rsplit_once(" (in ")
                    .map_or(&*c.debug.name, |r| r.0)
                    .to_string(),
                None => c.debug.name.clone(),
            }
        };
        let scoped: Vec<(String, u64)> = candidates
            .iter()
            .filter(|c| c.kind == SymbolKind::Data && c.debug.function.is_some())
            .map(|c| (raw(c), c.size))
            .collect();
        if !scoped.is_empty() {
            candidates.retain(|c| {
                c.kind != SymbolKind::Data
                    || c.debug.function.is_some()
                    || !scoped
                        .iter()
                        .any(|(n, size)| *n == c.debug.name && *size == c.size)
            });
        }
        if candidates.is_empty() {
            continue;
        }
        let rank = |k: SymbolKind| match k {
            SymbolKind::Thunk => 1,
            SymbolKind::Public | SymbolKind::String => 2,
            _ => 0,
        };
        candidates.sort_by_key(|c| rank(c.kind));

        // Names considered for folding: publics only if nothing else is
        // here, thunks only if only thunks (and publics) are.
        // A name recorded more than once (a variable's definition and an
        // `extern` declaration of it, or one record per compiler that saw
        // it) counts once, at the largest size that fits within the public
        // of that name, if there is one (DIA instead picks one arbitrarily).
        let best_rank = rank(candidates[0].kind);
        // The next symbol's address bounds a variable here.
        let next_addr = symbols.get(i).map(|s| s.addr);
        let fits = |c: &Candidate<'_>| {
            c.kind != SymbolKind::Data
                || (next_addr.is_none_or(|n| addr + c.size <= n)
                    && public_by_name
                        .get(c.name.as_str())
                        .is_none_or(|&a| a != addr || c.size <= public_size(a)))
        };
        let mut names: Vec<&Candidate<'_>> = Vec::new();
        // Index into `names` by identity (one address can have hundreds of
        // folded names); all thunks share one slot: folded thunks are
        // shown as one.
        let mut index: HashMap<&str, usize> = HashMap::new();
        let mut thunk: Option<usize> = None;
        for c in &candidates {
            if rank(c.kind) != best_rank {
                continue;
            }
            let slot = if c.kind == SymbolKind::Thunk {
                &mut thunk
            } else {
                // A fresh slot per identity, through the index.
                let existing = index.get(c.identity.0.as_str()).copied();
                &mut { existing }
            };
            match *slot {
                Some(i) => {
                    let n = names[i];
                    let better = match (fits(c), fits(n)) {
                        (true, false) => true,
                        (false, true) => false,
                        _ => c.size > n.size,
                    };
                    if better {
                        names[i] = c;
                    }
                }
                None => {
                    if c.kind == SymbolKind::Thunk {
                        thunk = Some(names.len());
                    } else {
                        index.insert(c.identity.0.as_str(), names.len());
                    }
                    names.push(c);
                }
            }
        }

        // The primary symbol: the largest candidate. Skip everything here if
        // it lies within the previous symbol (labels and alternate entry
        // points inside a function, say).
        let primary_size = names.iter().map(|c| c.size).max().unwrap_or(0);
        let end = addr + primary_size.max(1);
        if let Some((start, prev_end)) = previous_end {
            if start <= addr && end <= prev_end {
                continue;
            }
            // An alternate entry point (a public at a label) that starts
            // within the previous symbol is part of it, even if the public
            // seems to extend beyond it.
            if start <= addr
                && addr < prev_end
                && best_rank == rank(SymbolKind::Public)
                && labels.contains(&addr)
            {
                continue;
            }
        }
        previous_end = Some((addr, end));

        // The canonical name is the least; it carries the size.
        let canonical = names
            .iter()
            .enumerate()
            .min_by(|a, b| a.1.name.cmp(&b.1.name))
            .map_or(0, |(k, _)| k);
        let zero_fill = zero_fill_at(model, addr);
        for (k, c) in names.iter().enumerate() {
            let folded = k != canonical;
            let size = if folded {
                Size::default()
            } else if zero_fill {
                Size::new(0, c.size)
            } else {
                Size::new(c.size, c.size)
            };
            out.push(Symbol {
                addr,
                size,
                kind: c.kind,
                folded,
                name: c.name.clone(),
                compiland: c.debug.compiland,
                file_static: c.kind == SymbolKind::Data
                    && !c.debug.global
                    && c.debug.function.is_none()
                    && c.debug.compiland.is_some(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Compiland, Group, GroupOrigin, NO_GROUP, Piece, Range, Section};

    fn sym(kind: DebugKind, addr: u64, size: Option<u64>, name: &str) -> DebugSymbol {
        DebugSymbol {
            kind,
            addr,
            size,
            name: name.into(),
            compiland: Some(0),
            global: true,
            thread_local: false,
            function: None,
            parent: None,
            type_index: 0,
            flags: 0,
        }
    }

    /// A model with one code section (0x1000..0x2000, one contribution)
    /// and one data section with a zero-fill group at 0x3000.
    fn model() -> Model {
        Model {
            sections: vec![
                Section {
                    name: ".text".into(),
                    addr: 0x1000,
                    size: Size::new(0x1000, 0x1000),
                    vm_padding: 0,
                    characteristics: 0x6000_0020,
                    flags: hexcavator_image::coff_section_flags(0x6000_0020),
                },
                Section {
                    name: ".data".into(),
                    addr: 0x3000,
                    size: Size::new(0, 0x100),
                    vm_padding: 0,
                    characteristics: 0xC000_0080,
                    flags: hexcavator_image::coff_section_flags(0xC000_0080),
                },
            ],
            groups: vec![Group {
                name: ".bss".into(),
                section: 1,
                addr: 0x3000,
                size: Size::new(0, 0x100),
                padding: Size::default(),
                characteristics: 0xC000_0080,
                origin: GroupOrigin::DebugInfo,
            }],
            compilands: vec![Compiland {
                name: "a.obj".into(),
                library: 0,
            }],
            pieces: vec![Piece {
                range: Range::new(0x1000, 0x200, false),
                compiland: 0,
                section: 0,
                group: NO_GROUP,
            }],
            ..Model::default()
        }
    }

    fn run(symbols: &[DebugSymbol], hidden: &[DebugSymbol]) -> Vec<Symbol> {
        let mut sorted = symbols.to_vec();
        sorted.sort_by_key(|s| s.addr);
        from_debug_symbols(&sorted, hidden, &model(), &mut |_, _, _, n| n)
    }

    #[test]
    fn folded_names_share_one_size() {
        let out = run(
            &[
                sym(DebugKind::Function, 0x1000, Some(0x20), "zeta()"),
                sym(DebugKind::Function, 0x1000, Some(0x20), "alpha()"),
                sym(DebugKind::Function, 0x1000, Some(0x20), "alpha()"),
            ],
            &[],
        );
        // One name per distinct name; the least is canonical.
        assert_eq!(out.len(), 2);
        let canonical = out.iter().find(|s| !s.folded).unwrap();
        assert_eq!(canonical.name, "alpha()");
        assert_eq!(canonical.size, Size::new(0x20, 0x20));
        let folded = out.iter().find(|s| s.folded).unwrap();
        assert_eq!(
            (folded.name.as_str(), folded.size),
            ("zeta()", Size::default())
        );
    }

    #[test]
    fn symbols_inside_the_previous_one_are_skipped() {
        let out = run(
            &[
                sym(DebugKind::Function, 0x1000, Some(0x40), "outer()"),
                sym(DebugKind::Data, 0x1010, Some(4), "inside"),
                sym(DebugKind::Function, 0x1040, Some(0x10), "next()"),
                // Address 0 never names anything.
                sym(DebugKind::Data, 0, Some(4), "__ImageBase"),
            ],
            &[],
        );
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["outer()", "next()"]);
    }

    #[test]
    fn publics_yield_to_other_symbols_and_thunks_to_code() {
        let out = run(
            &[
                sym(DebugKind::Public, 0x1000, None, "?f@@YAXXZ"),
                sym(DebugKind::Thunk, 0x1000, Some(0x10), "f_thunk"),
                sym(DebugKind::Function, 0x1000, Some(0x10), "f()"),
            ],
            &[],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SymbolKind::Function);
    }

    #[test]
    fn public_sizes() {
        let out = run(
            &[
                // Ends at the next public.
                sym(DebugKind::Public, 0x1000, None, "first"),
                sym(DebugKind::Public, 0x1018, None, "second"),
                // Ends at its contribution's end (0x1200).
                sym(DebugKind::Public, 0x1100, None, "last"),
                // Outside every contribution: 0.
                sym(DebugKind::Public, 0x1800, None, "nowhere"),
            ],
            &[],
        );
        let size = |n: &str| out.iter().find(|s| s.name == n).unwrap().size.file;
        assert_eq!(size("first"), 0x18);
        assert_eq!(size("second"), 0x1100 - 0x1018);
        assert_eq!(size("last"), 0x100);
        assert_eq!(size("nowhere"), 0);
        // A hidden thunk at a public's address gives it the thunk's size.
        let out = run(
            &[sym(DebugKind::Public, 0x1000, None, "memset")],
            &[sym(DebugKind::Thunk, 0x1000, Some(6), "memset")],
        );
        assert_eq!(out[0].size.file, 6);
    }

    #[test]
    fn duplicate_records_take_the_largest_that_fits() {
        let out = run(
            &[
                sym(DebugKind::Data, 0x1000, Some(0), "table"),
                sym(DebugKind::Data, 0x1000, Some(8), "table"),
                sym(DebugKind::Data, 0x1000, Some(64), "table"),
                sym(DebugKind::Data, 0x1010, Some(4), "after"),
            ],
            &[],
        );
        let table = out.iter().find(|s| s.name == "table").unwrap();
        // 64 would run into `after`; 8 fits.
        assert_eq!(table.size.file, 8);
        assert_eq!(out.iter().filter(|s| s.name == "table").count(), 1);
    }

    #[test]
    fn alternate_entry_points_are_part_of_their_procedure() {
        let mut label = sym(DebugKind::Label, 0x1008, None, "AltEntry");
        label.compiland = Some(0);
        let out = run(
            &[
                sym(DebugKind::Function, 0x1000, Some(0x10), "Proc()"),
                label,
                // The public at the label seems to run past the procedure.
                sym(DebugKind::Public, 0x1008, None, "AltEntry"),
                sym(DebugKind::Function, 0x1010, Some(0x8), "Next()"),
            ],
            &[],
        );
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["Proc()", "Next()"]);
    }

    #[test]
    fn zero_fill_data_has_no_file_size() {
        let out = run(&[sym(DebugKind::Data, 0x3010, Some(0x20), "buffer")], &[]);
        assert_eq!(out[0].size, Size::new(0, 0x20));
    }

    #[test]
    fn markers_and_nameless_data_are_left_out() {
        let out = run(
            &[
                sym(DebugKind::Data, 0x1000, Some(1), "$xdatasym"),
                sym(DebugKind::Data, 0x1004, Some(4), ""),
                sym(DebugKind::Block, 0x1008, Some(4), "block"),
            ],
            &[],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn strings_are_sized_by_their_decorated_length() {
        let out = run(
            &[sym(
                DebugKind::Public,
                0x1000,
                None,
                "??_C@_03KJCAMLEN@abc?$AA@",
            )],
            &[],
        );
        assert_eq!(out[0].kind, SymbolKind::String);
        assert_eq!(out[0].size.file, 4);
    }
}

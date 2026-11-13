//! Building a [`Model`] for a PE image from its PDB.
//!
//! The rules follow SizeBench's, so that the two agree byte for byte:
//!
//! - Sections come from the image's section table, sorted by address.
//!   Adjacent sections with the same name and flags are merged; names
//!   truncated to 8 characters are completed from a group at the same
//!   address; names still duplicated get the flags appended.
//! - Groups are the PDB's COFF groups (`S_COFFGROUP` in `* Linker *`) with a
//!   non-zero size, plus tables the headers locate (base relocations, the
//!   debug directory, ...) where no COFF group covers them. Each is placed
//!   in the section that contains it. In images with a section alignment of
//!   at least 4 KB, uninitialized-data groups occupy memory only.
//! - Contributions (DBI section contributions) are attributed to the group
//!   containing their start, and to that group's section. Contributions
//!   inside `.pdata` are ignored (older linkers wrote wrong ones); each
//!   `.pdata` entry is attributed instead to the compiland whose code it
//!   describes. Empty contributions (lld-link writes some) are ignored.
//! - Compilands are identified by (library, name), case-insensitively.
//!
//! [`extract`] reads the inputs from the files; [`build`] is a pure
//! function of them.

use std::collections::HashMap;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_debuginfo::{Contribution, DebugInfo, Group as DebugGroup};
use hexcavator_image::{Arch, Image};
use hexcavator_pe::consts::{directory, section_characteristics as sc};
use hexcavator_pe::load_config::field;

use crate::range::{self, Range};
use crate::{
    Compiland, Group, GroupOrigin, Library, Model, NO_GROUP, Piece, Section, Size, TableKind,
};

/// A section header, as the image has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSection {
    pub name: String,
    pub addr: u64,
    /// `SizeOfRawData`.
    pub raw_size: u64,
    /// `VirtualSize`.
    pub vm_size: u64,
    pub characteristics: u32,
}

/// A table the image's headers locate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Table {
    pub kind: TableKind,
    pub addr: u64,
    pub size: u64,
}

/// One `.pdata` entry: where it is and the code it describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdataEntry {
    pub addr: u64,
    pub size: u64,
    pub target: u64,
}

/// Everything [`build`] needs, read from the image and its PDB.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeInputs {
    pub arch: Option<Arch>,
    pub sections: Vec<InputSection>,
    pub section_alignment: u64,
    pub file_alignment: u64,
    pub groups: Vec<DebugGroup>,
    pub tables: Vec<Table>,
    /// The exception directory.
    pub pdata: Option<(u64, u64)>,
    pub pdata_entries: Vec<PdataEntry>,
    pub compilands: Vec<hexcavator_debuginfo::Compiland>,
    pub contributions: Vec<Contribution>,
}

/// Why an image can't be analyzed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// The image holds managed (.NET) code.
    Managed,
    /// The PDB is a `/DEBUG:FASTLINK` PDB, which leaves the symbols in the
    /// objects' PDBs.
    MinimalPdb,
    /// The PDB is not the image's.
    PdbMismatch,
    /// The debug information (DWARF) is not the image's.
    DebugMismatch,
}

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Unsupported::Managed => "the image contains managed code",
            Unsupported::MinimalPdb => "the PDB is a /DEBUG:FASTLINK PDB; relink with /DEBUG:FULL",
            Unsupported::PdbMismatch => "the PDB does not match the image",
            Unsupported::DebugMismatch => "the debug information does not match the image",
        })
    }
}

/// Checks that `image` and `debug` can be analyzed together.
pub fn check(image: &Image<'_>, debug: &DebugInfo<'_>) -> std::result::Result<(), Unsupported> {
    let pe = image.pe().ok_or(Unsupported::PdbMismatch)?;
    if pe.data_directory(directory::COM_DESCRIPTOR).is_some() {
        return Err(Unsupported::Managed);
    }
    let ids = image.debug_ids();
    if !ids.is_empty() && !ids.iter().any(|id| debug.matches(id)) {
        return Err(Unsupported::PdbMismatch);
    }
    if debug.linker_info().is_ok_and(|l| l.minimal) {
        return Err(Unsupported::MinimalPdb);
    }
    Ok(())
}

/// Reads the inputs for [`build`] from a PE image and its debug info.
pub fn extract(image: &Image<'_>, debug: &DebugInfo<'_>) -> Result<PeInputs> {
    Ok(PeInputs {
        groups: debug.groups()?,
        compilands: debug.compilands()?,
        contributions: debug.contributions()?,
        ..extract_image(image)?
    })
}

/// The inputs the image alone gives: everything but groups, compilands,
/// and contributions (which come from debug information or a map).
pub fn extract_image(image: &Image<'_>) -> Result<PeInputs> {
    let pe = image
        .pe()
        .ok_or(Error::new(ErrorKind::Unsupported, 0, "not a PE image"))?;
    let header =
        pe.optional_header()
            .ok_or(Error::new(ErrorKind::Unsupported, 0, "not a PE image"))?;
    let sections = pe
        .sections()
        .iter()
        .map(|h| InputSection {
            name: String::from_utf8_lossy(pe.section_name(h)).into_owned(),
            addr: u64::from(h.virtual_address.get()),
            raw_size: u64::from(h.size_of_raw_data.get()),
            vm_size: u64::from(h.virtual_size.get()),
            characteristics: h.characteristics.get(),
        })
        .collect();

    let dir = |index: usize| {
        pe.data_directory(index)
            .map(|d| (u64::from(d.virtual_address.get()), u64::from(d.size.get())))
    };
    let mut tables = Vec::new();
    let mut table = |kind, (addr, size): (u64, u64)| {
        if addr != 0 && size != 0 {
            tables.push(Table { kind, addr, size });
        }
    };
    if let Some(d) = dir(directory::EXPORT) {
        table(TableKind::Exports, d);
    }
    if let Some(d) = dir(directory::BASERELOC) {
        table(TableKind::BaseRelocations, d);
    }
    if let Some(d) = dir(directory::DEBUG) {
        table(TableKind::DebugDirectory, d);
        for entry in pe.debug_directories().unwrap_or(&[]) {
            table(
                TableKind::DebugData(entry.kind.get()),
                (
                    u64::from(entry.address_of_raw_data.get()),
                    u64::from(entry.size_of_data.get()),
                ),
            );
        }
    }
    if let Some(d) = dir(directory::LOAD_CONFIG) {
        table(TableKind::LoadConfig, d);
    }
    if let Some(lc) = pe.load_config() {
        let stride = 4 + lc.guard_table_stride() as u64;
        let base = header.image_base().get();
        for (kind, at, count) in [
            (
                TableKind::CfgFunctions,
                field::GUARD_CF_FUNCTION_TABLE,
                field::GUARD_CF_FUNCTION_COUNT,
            ),
            (
                TableKind::CfgAddressTakenImports,
                field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_TABLE,
                field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_COUNT,
            ),
        ] {
            if let (Some(va), Some(count)) = (lc.get(at), lc.get(count))
                && let (Some(rva), Some(size)) = (va.checked_sub(base), count.checked_mul(stride))
            {
                table(kind, (rva, size));
            }
        }
    }
    if let Some(d) = dir(directory::DELAY_IMPORT) {
        table(TableKind::DelayImportDescriptors, d);
        delay_import_tables(pe, &mut table);
    }

    let pdata = dir(directory::EXCEPTION);
    // The exception directory's own entries (a hybrid image's second table
    // lies in other data, which contributions account for).
    let pdata_entries = pdata_entries(pe);

    Ok(PeInputs {
        arch: Some(image.arch()),
        sections,
        section_alignment: u64::from(header.section_alignment()),
        file_alignment: u64::from(header.file_alignment()),
        groups: Vec::new(),
        tables,
        pdata,
        pdata_entries,
        compilands: Vec::new(),
        contributions: Vec::new(),
    })
}

/// The exception directory's entries: where each is, its size, and the
/// code it describes (ARM32's Thumb bit cleared). Empty entries are left
/// out.
pub fn pdata_entries(pe: &hexcavator_pe::PeFile<'_>) -> Vec<PdataEntry> {
    use hexcavator_pe::exception::RuntimeFunction;
    let thumb = pe.machine() == hexcavator_pe::consts::machine::ARMNT;
    pe.runtime_functions()
        .filter(|e| e.in_exception_directory)
        .filter_map(|e| {
            let (size, empty) = match e.function {
                RuntimeFunction::X64 { begin, end, unwind } => {
                    (12, begin.get() == 0 && end.get() == 0 && unwind.get() == 0)
                }
                RuntimeFunction::Arm { begin, unwind } => (8, begin.get() == 0 && unwind == 0),
            };
            let begin = u64::from(e.function.begin().get());
            (!empty).then_some(PdataEntry {
                addr: u64::from(e.rva.get()),
                size,
                target: if thumb { begin & !1 } else { begin },
            })
        })
        .collect()
}

/// The delay-load thunks, names, and module handles, each merged into runs
/// (ranges at most 7 bytes apart).
fn delay_import_tables(
    pe: &hexcavator_pe::PeFile<'_>,
    table: &mut impl FnMut(TableKind, (u64, u64)),
) {
    let pointer = match pe.optional_header() {
        Some(h) if h.is_64() => 8u64,
        _ => 4,
    };
    let mut thunks = Vec::new();
    let mut names = Vec::new();
    let mut handles = Vec::new();
    for dll in pe.delay_imports() {
        let d = dll.descriptor;
        if d.import_address_table.get() == 0 || d.import_name_table.get() == 0 {
            break;
        }
        if let Some(rva) = dll.rva(d.dll_name.get()) {
            names.push(Range::new(
                u64::from(rva.get()),
                dll.name.len() as u64 + 1,
                false,
            ));
        }
        if let Some(rva) = dll.rva(d.module_handle.get()) {
            handles.push(Range::new(u64::from(rva.get()), pointer, false));
        }
        let (Some(int), Some(iat)) = (
            dll.rva(d.import_name_table.get()),
            dll.rva(d.import_address_table.get()),
        ) else {
            continue;
        };
        let mut count = 0u64;
        for thunk in dll.thunks() {
            if let hexcavator_pe::imports::ImportName::Name { name, .. } = thunk.import
                && let Ok(rva) = u32::try_from(thunk.name_thunk)
            {
                names.push(Range::new(u64::from(rva), name.len() as u64 + 3, false));
            }
            count += 1;
        }
        // Each table, including its null terminator.
        let len = (count + 1) * pointer;
        thunks.push(Range::new(u64::from(int.get()), len, false));
        thunks.push(Range::new(u64::from(iat.get()), len, false));
    }
    for (ranges, kind) in [
        (
            &mut thunks,
            TableKind::DelayImportThunks as fn(u32) -> TableKind,
        ),
        (&mut names, TableKind::DelayImportNames),
        (&mut handles, TableKind::DelayImportHandles),
    ] {
        range::coalesce(ranges, 7);
        for (i, r) in ranges.iter().enumerate() {
            table(kind(i as u32), (r.addr, r.len));
        }
    }
}

/// Merges adjacent same-named sections and makes names unique.
fn sections(inputs: &PeInputs, groups: &[RawGroup]) -> Vec<Section> {
    let mut sorted: Vec<&InputSection> = inputs.sections.iter().collect();
    sorted.sort_by_key(|s| s.addr);
    // (name, addr, raw size, vm size, characteristics)
    let mut merged: Vec<(String, u64, u64, u64, u32)> = Vec::new();
    for s in sorted {
        match merged.last_mut() {
            Some(last) if last.0 == s.name && last.4 == s.characteristics => {
                // The merged section spans both, with any gap between.
                last.2 = (s.addr + s.raw_size).saturating_sub(last.1);
                last.3 = (s.addr + s.vm_size).saturating_sub(last.1);
            }
            _ => merged.push((
                s.name.clone(),
                s.addr,
                s.raw_size,
                s.vm_size,
                s.characteristics,
            )),
        }
    }
    let mut seen: Vec<String> = Vec::new();
    let align = inputs.section_alignment;
    merged
        .into_iter()
        .map(|(mut name, addr, raw, vm, characteristics)| {
            // Names longer than 8 characters are truncated in the section
            // table; a COFF group at the same address may have the full one.
            if name.len() == 8
                && let Some(g) = groups.iter().find(|g| {
                    g.addr == addr && g.name.len() > name.len() && g.name.starts_with(&name)
                })
            {
                name = g.name.clone();
            }
            if seen.contains(&name) {
                name = format!("{name} ({characteristics:X})");
            }
            seen.push(name.clone());
            let vm_padding = if align == 0 || vm % align == 0 {
                0
            } else {
                align - vm % align
            };
            Section {
                name,
                addr,
                size: Size::new(raw, vm),
                vm_padding,
                characteristics,
                flags: hexcavator_image::coff_section_flags(characteristics),
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
struct RawGroup {
    name: String,
    addr: u64,
    size: u64,
    characteristics: u32,
    origin: GroupOrigin,
}

/// The groups: the debug info's, with obfuscator families merged and
/// duplicate names made unique, then tables no group covers.
fn raw_groups(inputs: &PeInputs) -> Vec<RawGroup> {
    let mut from_debug: Vec<&DebugGroup> = inputs.groups.iter().filter(|g| g.size > 0).collect();
    from_debug.sort_by_key(|g| g.addr);

    // Ranges the debug info's groups cover, merged across small gaps.
    let mut covered: Vec<Range> = from_debug
        .iter()
        .map(|g| Range::new(g.addr, g.size, false))
        .collect();
    range::coalesce(&mut covered, 7);
    let overlaps = |addr: u64, size: u64| {
        let end = addr.saturating_add(size);
        covered
            .iter()
            .any(|r| r.addr < end.max(addr + 1) && addr < r.end())
    };

    let mut out: Vec<RawGroup> = Vec::new();
    for g in &from_debug {
        out.push(RawGroup {
            name: g.name.clone(),
            addr: g.addr,
            size: g.size,
            characteristics: g.characteristics,
            origin: GroupOrigin::DebugInfo,
        });
    }
    for t in &inputs.tables {
        if !overlaps(t.addr, t.size) {
            out.push(RawGroup {
                name: t.kind.label(),
                addr: t.addr,
                size: t.size,
                characteristics: 0,
                origin: GroupOrigin::Table(t.kind),
            });
        }
    }
    out.sort_by_key(|g| g.addr);

    // Merge families of tiny obfuscator groups (`.text$wbrd123`, ...).
    let family = |name: &str| -> Option<String> {
        if let Some(i) = name.find("$wbrd") {
            return Some(name[..i + "$wbrd".len()].to_string());
        }
        if name.starts_with("?g_EncryptedSegment") {
            let rest = &name["?g_E".len()..];
            let i = rest.find('_')?;
            return Some(name[..="?g_E".len() + i].to_string());
        }
        None
    };
    let mut merged: Vec<RawGroup> = Vec::new();
    let mut prefix: Option<String> = None;
    for g in out {
        if let Some(fam) = family(&g.name) {
            match (&prefix, merged.last_mut()) {
                (Some(p), Some(last)) if g.name.starts_with(p.as_str()) => {
                    last.size = (g.addr + g.size).saturating_sub(last.addr);
                }
                _ => {
                    merged.push(RawGroup {
                        name: format!("{fam}<all>"),
                        origin: GroupOrigin::Merged,
                        ..g
                    });
                    prefix = Some(fam);
                }
            }
        } else {
            prefix = None;
            merged.push(g);
        }
    }

    let mut seen = std::collections::HashSet::new();
    for g in &mut merged {
        if !seen.insert(g.name.clone()) {
            g.name = format!("{} ({:X})", g.name, g.characteristics);
            seen.insert(g.name.clone());
        }
    }
    merged
}

/// Places groups in sections, sizes them, and computes the padding after
/// each.
fn groups(inputs: &PeInputs, raw: Vec<RawGroup>, sections: &[Section]) -> Vec<Group> {
    let mut out = Vec::new();
    for g in raw {
        // The group must fit in the section's memory extent.
        let Some(section) = sections
            .iter()
            .position(|s| g.addr >= s.addr && g.addr + g.size <= s.addr + s.size.vm)
        else {
            continue;
        };
        let zero_fill = inputs.section_alignment >= 0x1000
            && g.characteristics & sc::CNT_UNINITIALIZED_DATA != 0
            && g.characteristics & sc::CNT_INITIALIZED_DATA == 0;
        out.push(Group {
            name: g.name,
            section: section as u32,
            addr: g.addr,
            size: Size::new(if zero_fill { 0 } else { g.size }, g.size),
            padding: Size::default(),
            characteristics: g.characteristics,
            origin: g.origin,
        });
    }
    out.sort_by_key(|g| g.addr);

    // Padding: the gap from each group to the next in its section, and
    // from the last to the end of the section. Arithmetic wraps at 32 bits,
    // as SizeBench's does, so overlapping groups give the same results.
    let w = |v: u64| v as u32;
    for (si, s) in sections.iter().enumerate() {
        let members: Vec<usize> = (0..out.len())
            .filter(|&i| out[i].section == si as u32)
            .collect();
        let mut furthest = w(s.addr);
        for pair in members.windows(2) {
            let (prev, next) = (&out[pair[0]], &out[pair[1]]);
            let gap_vm = w(next.addr).wrapping_sub(w(prev.addr).wrapping_add(w(prev.size.vm)));
            let gap_file = w(next.addr).wrapping_sub(w(prev.addr).wrapping_add(w(prev.size.file)));
            let total = w(prev.size.file).wrapping_add(gap_file);
            if total > 0 && w(prev.addr).wrapping_add(total) > furthest {
                furthest = w(prev.addr).wrapping_add(total);
            }
            out[pair[0]].padding = Size::new(u64::from(gap_file), u64::from(gap_vm));
        }
        if let Some(&last) = members.last() {
            let g = &out[last];
            let section_end_vm = w(s.addr)
                .wrapping_add(w(s.size.vm))
                .wrapping_add(w(s.vm_padding));
            let vm = section_end_vm.wrapping_sub(w(g.addr).wrapping_add(w(g.size.vm)));
            let file = w(s.addr)
                .wrapping_add(w(s.size.file))
                .wrapping_sub(furthest)
                .wrapping_sub(w(g.size.file));
            out[last].padding = Size::new(u64::from(file), u64::from(vm));
        }
    }
    out
}

/// Builds the model from `inputs`.
pub fn build(inputs: &PeInputs) -> Model {
    let raw = raw_groups(inputs);
    let sections = sections(inputs, &raw);
    let groups = groups(inputs, raw, &sections);

    // Libraries and compilands, keyed case-insensitively.
    let mut libraries: Vec<Library> = Vec::new();
    let mut library_index: HashMap<String, u32> = HashMap::new();
    let mut compilands: Vec<Compiland> = Vec::new();
    let mut compiland_index: HashMap<(u32, String), u32> = HashMap::new();
    let mut module_compiland: Vec<Option<u32>> = vec![None; inputs.compilands.len()];
    let mut compiland_for = |module: usize,
                             libraries: &mut Vec<Library>,
                             compilands: &mut Vec<Compiland>|
     -> Option<u32> {
        if let Some(c) = module_compiland.get(module).copied().flatten() {
            return Some(c);
        }
        let m = inputs.compilands.get(module)?;
        let lib = *library_index
            .entry(m.library.to_lowercase())
            .or_insert_with(|| {
                libraries.push(Library {
                    name: m.library.clone(),
                });
                (libraries.len() - 1) as u32
            });
        let c = *compiland_index
            .entry((lib, m.name.to_lowercase()))
            .or_insert_with(|| {
                compilands.push(Compiland {
                    name: m.name.clone(),
                    library: lib,
                });
                (compilands.len() - 1) as u32
            });
        module_compiland[module] = Some(c);
        Some(c)
    };

    let in_pdata = |addr: u64, size: u64| {
        inputs
            .pdata
            .is_some_and(|(start, len)| addr >= start && addr + size <= start + len && len > 0)
    };
    // The group containing `addr` (groups are sorted by address).
    let group_ranges: Vec<Range> = groups
        .iter()
        .map(|g| Range::new(g.addr, g.extent(), false))
        .collect();
    let group_index = range::Lookup::new(&group_ranges);
    let group_at = |addr: u64| group_index.first_containing(&group_ranges, addr);

    let mut pieces = Vec::new();
    for c in &inputs.contributions {
        // lld-link writes empty contributions (DIA doesn't report them).
        if c.size == 0 || in_pdata(c.addr, c.size) {
            continue;
        }
        let Some(gi) = group_at(c.addr) else {
            continue;
        };
        let Some(compiland) = compiland_for(c.compiland as usize, &mut libraries, &mut compilands)
        else {
            continue;
        };
        let g = &groups[gi];
        pieces.push(Piece {
            range: Range::new(c.addr, c.size, g.zero_fill()),
            compiland,
            section: g.section,
            group: gi as u32,
        });
    }

    // `.pdata` entries go to the compiland whose code they describe.
    let pdata_section = sections.iter().position(|s| s.name == ".pdata");
    if let Some(pdata_section) = pdata_section {
        let pdata_group = groups
            .iter()
            .position(|g| g.section == pdata_section as u32 && g.name == ".pdata");
        // Executable ranges of each compiland, sorted, for lookup.
        let mut code: Vec<(Range, u32)> = pieces
            .iter()
            .filter(|p| sections[p.section as usize].executable())
            .map(|p| (p.range, p.compiland))
            .collect();
        code.sort_by_key(|(r, c)| (r.addr, *c));
        let code_ranges: Vec<Range> = code.iter().map(|(r, _)| *r).collect();
        let code_index = range::Lookup::new(&code_ranges);
        let owner = |target: u64| {
            // The first compiland (in order of appearance) whose code
            // contains the target; ranges can overlap.
            code_index
                .all_containing(&code_ranges, target)
                .map(|i| code[i].1)
                .min()
        };
        for e in &inputs.pdata_entries {
            if let Some(compiland) = owner(e.target) {
                pieces.push(Piece {
                    range: Range::new(e.addr, e.size, false),
                    compiland,
                    section: pdata_section as u32,
                    group: pdata_group.map_or(NO_GROUP, |g| g as u32),
                });
            }
        }
    }
    pieces.sort_by_key(|p| (p.range.addr, p.range.len, p.compiland));

    Model {
        arch: inputs.arch,
        sections,
        groups,
        libraries,
        compilands,
        pieces,
    }
}

/// Reads and builds the model of `image` with `debug`.
pub fn model(image: &Image<'_>, debug: &DebugInfo<'_>) -> Result<Model> {
    Ok(build(&extract(image, debug)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: u32 = sc::CNT_CODE | sc::MEM_EXECUTE | sc::MEM_READ;
    const RDATA: u32 = sc::CNT_INITIALIZED_DATA | sc::MEM_READ;
    const DATA: u32 = sc::CNT_INITIALIZED_DATA | sc::MEM_READ | sc::MEM_WRITE;
    const BSS: u32 = sc::CNT_UNINITIALIZED_DATA | sc::MEM_READ | sc::MEM_WRITE;

    fn section(name: &str, addr: u64, raw: u64, vm: u64, characteristics: u32) -> InputSection {
        InputSection {
            name: name.into(),
            addr,
            raw_size: raw,
            vm_size: vm,
            characteristics,
        }
    }

    fn group(name: &str, addr: u64, size: u64, characteristics: u32) -> DebugGroup {
        DebugGroup {
            name: name.into(),
            addr,
            size,
            characteristics,
        }
    }

    fn module(library: &str, name: &str) -> hexcavator_debuginfo::Compiland {
        hexcavator_debuginfo::Compiland {
            name: name.into(),
            library: library.into(),
        }
    }

    fn contrib(addr: u64, size: u64, compiland: u32) -> Contribution {
        Contribution {
            addr,
            size,
            compiland,
            characteristics: 0,
        }
    }

    /// A small image: .text (two groups), .data (data + bss), .pdata.
    fn inputs() -> PeInputs {
        PeInputs {
            arch: Some(Arch::X64),
            sections: vec![
                section(".text", 0x1000, 0x400, 0x320, TEXT),
                section(".data", 0x2000, 0x200, 0x900, DATA),
                section(".pdata", 0x3000, 0x200, 0x18, RDATA),
            ],
            section_alignment: 0x1000,
            file_alignment: 0x200,
            groups: vec![
                group(".text$mn", 0x1000, 0x300, TEXT),
                group(".text$x", 0x1300, 0x20, TEXT),
                group(".data", 0x2000, 0x100, DATA),
                group(".bss", 0x2100, 0x800, BSS),
                group(".pdata", 0x3000, 0x18, RDATA),
                group(".edata", 0x2000, 0, RDATA),
            ],
            tables: vec![],
            pdata: Some((0x3000, 0x18)),
            pdata_entries: vec![
                PdataEntry {
                    addr: 0x3000,
                    size: 12,
                    target: 0x1000,
                },
                PdataEntry {
                    addr: 0x300C,
                    size: 12,
                    target: 0x1200,
                },
            ],
            compilands: vec![
                module("a.lib", "a.obj"),
                module("", "* Linker *"),
                module("A.LIB", "A.OBJ"),
            ],
            contributions: vec![
                contrib(0x1000, 0x100, 0),
                contrib(0x1100, 0x100, 2),
                contrib(0x1200, 0x100, 1),
                contrib(0x1300, 0x20, 0),
                contrib(0x2000, 0x40, 0),
                contrib(0x2100, 0x800, 1),
                // Ignored: in .pdata, empty, outside every group, and from a
                // module the PDB doesn't list.
                contrib(0x3000, 0x18, 1),
                contrib(0x1080, 0, 1),
                contrib(0x5000, 0x10, 0),
                contrib(0x1000, 0x10, 99),
            ],
        }
    }

    #[test]
    fn sections_and_groups() {
        let m = build(&inputs());
        let names: Vec<&str> = m.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, [".text", ".data", ".pdata"]);
        assert_eq!(m.sections[0].size, Size::new(0x400, 0x320));
        assert_eq!(m.sections[0].vm_padding, 0x1000 - 0x320);

        // Empty groups are dropped; the rest are placed in their sections.
        let names: Vec<&str> = m.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, [".text$mn", ".text$x", ".data", ".bss", ".pdata"]);
        assert_eq!(
            m.groups.iter().map(|g| g.section).collect::<Vec<_>>(),
            [0, 0, 1, 1, 2]
        );
        // .bss is memory-only; padding runs to the next group, then to the
        // end of the section's memory (including its alignment padding).
        let bss = &m.groups[3];
        assert_eq!(bss.size, Size::new(0, 0x800));
        assert!(bss.zero_fill());
        assert_eq!(bss.padding.vm, 0x3000 - 0x2900);
        assert_eq!(m.groups[2].padding, Size::new(0, 0));
        assert_eq!(m.groups[0].padding, Size::new(0, 0));
        assert_eq!(m.groups[1].padding.vm, 0x2000 - 0x1320);
    }

    #[test]
    fn compilands_merge_case_insensitively() {
        let m = build(&inputs());
        // a.lib/a.obj and A.LIB/A.OBJ are one compiland; the first name wins.
        assert_eq!(m.libraries.len(), 2);
        assert_eq!(m.compilands.len(), 2);
        assert_eq!(m.compilands[0].name, "a.obj");
        assert_eq!(m.libraries[m.compilands[0].library as usize].name, "a.lib");
        let by = m.totals(|p| Some(p.compiland));
        // a.obj: .text 0x200 + 0x20, .data 0x40, plus one .pdata entry.
        assert_eq!(
            by[&0].size,
            Size::new(0x200 + 0x20 + 0x40 + 12, 0x200 + 0x20 + 0x40 + 12)
        );
        // * Linker *: 0x100 of code, 0x800 of .bss (memory only), one entry.
        assert_eq!(by[&1].size, Size::new(0x100 + 12, 0x100 + 0x800 + 12));
    }

    #[test]
    fn ignored_contributions() {
        let m = build(&inputs());
        // Nothing from the ignored contributions: in .pdata only the two
        // entries, nothing outside groups, nothing empty.
        assert!(m.pieces.iter().all(|p| p.range.len > 0));
        assert!(m.pieces.iter().all(|p| p.range.addr < 0x5000));
        let pdata: Vec<_> = m.pieces.iter().filter(|p| p.section == 2).collect();
        assert_eq!(pdata.len(), 2);
        assert_eq!(pdata[0].compiland, 0);
        assert_eq!(pdata[1].compiland, 1);
        assert_eq!(pdata[0].group, 4);
    }

    #[test]
    fn pdata_without_a_pdata_group_counts_only_toward_the_section() {
        let mut i = inputs();
        i.groups.retain(|g| g.name != ".pdata");
        let m = build(&i);
        let pdata: Vec<_> = m.pieces.iter().filter(|p| p.range.addr >= 0x3000).collect();
        assert_eq!(pdata.len(), 2);
        assert!(pdata.iter().all(|p| p.group == NO_GROUP && p.section == 2));
        // Without a .pdata section, entries aren't attributed at all.
        let mut i = inputs();
        i.sections[2].name = ".xdata".into();
        let m = build(&i);
        assert!(m.pieces.iter().all(|p| p.range.addr < 0x3000));
    }

    #[test]
    fn pdata_targets_outside_code_are_dropped() {
        let mut i = inputs();
        i.pdata_entries.push(PdataEntry {
            addr: 0x3018,
            size: 12,
            target: 0x2000,
        });
        i.pdata_entries.push(PdataEntry {
            addr: 0x3024,
            size: 12,
            target: 0x9999,
        });
        let m = build(&i);
        assert_eq!(m.pieces.iter().filter(|p| p.section == 2).count(), 2);
    }

    #[test]
    fn pdata_owner_is_the_first_compiland_whose_code_holds_the_target() {
        let mut i = inputs();
        // Overlapping code from * Linker * at the first entry's target.
        i.contributions.push(contrib(0x0FF0, 0x40, 1));
        let m = build(&i);
        let first = m.pieces.iter().find(|p| p.range.addr == 0x3000).unwrap();
        assert_eq!(first.compiland, 0);
    }

    #[test]
    fn small_section_alignment_keeps_bss_in_the_file() {
        let mut i = inputs();
        i.section_alignment = 0x200;
        let m = build(&i);
        let bss = m.groups.iter().find(|g| g.name == ".bss").unwrap();
        assert_eq!(bss.size, Size::new(0x800, 0x800));
        assert!(!bss.zero_fill());
        assert_eq!(m.sections[0].vm_padding, 0x400 - 0x320);
        // No alignment at all.
        i.section_alignment = 0;
        assert_eq!(build(&i).sections[0].vm_padding, 0);
    }

    #[test]
    fn same_named_sections_merge_and_others_are_disambiguated() {
        let mut i = PeInputs {
            sections: vec![
                section(".text", 0x1000, 0x200, 0x100, TEXT),
                section(".text", 0x2000, 0x200, 0x180, TEXT),
                section(".text", 0x3000, 0x200, 0x10, RDATA),
                section(".rdata", 0x4000, 0x200, 0x10, RDATA),
            ],
            section_alignment: 0x1000,
            ..PeInputs::default()
        };
        // Out of order in the section table: sorted by address first.
        i.sections.swap(0, 3);
        let m = build(&i);
        let names: Vec<&str> = m.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, [".text", ".text (40000040)", ".rdata"]);
        // The merged section spans the gap between its parts.
        assert_eq!(m.sections[0].addr, 0x1000);
        assert_eq!(m.sections[0].size, Size::new(0x1200, 0x1180));
    }

    #[test]
    fn truncated_section_names_are_completed_from_groups() {
        let i = PeInputs {
            sections: vec![
                section("?g_Encry", 0x1000, 0x200, 0x100, RDATA),
                section("?g_Encry", 0x2000, 0x200, 0x100, DATA),
                section(".longnam", 0x3000, 0x200, 0x100, DATA),
            ],
            groups: vec![
                group(".longname1", 0x3000, 0x10, DATA),
                group(".other", 0x3010, 0x10, DATA),
            ],
            section_alignment: 0x1000,
            ..PeInputs::default()
        };
        let m = build(&i);
        let names: Vec<&str> = m.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["?g_Encry", "?g_Encry (C0000040)", ".longname1"]);
    }

    #[test]
    fn obfuscator_group_families_merge() {
        let i = PeInputs {
            sections: vec![section(".text", 0x1000, 0x1000, 0x1000, TEXT)],
            groups: vec![
                group(".text$mn", 0x1000, 0x100, TEXT),
                group(".text$wbrd1", 0x1100, 0x10, TEXT),
                group(".text$wbrd2", 0x1110, 0x10, TEXT),
                group(".text$wbrd9", 0x1130, 0x08, TEXT),
                group(
                    "?g_EncryptedSegmentSystemCall_1@W@@3U_E@1@C",
                    0x1200,
                    0x10,
                    TEXT,
                ),
                group(
                    "?g_EncryptedSegmentSystemCall_2@W@@3U_E@1@C",
                    0x1210,
                    0x10,
                    TEXT,
                ),
                group("?g_EncryptedSegmentOther_1@W@@3U_E@1@C", 0x1220, 0x10, TEXT),
                group(".text$x", 0x1300, 0x10, TEXT),
                group(".text$x", 0x1400, 0x10, TEXT | sc::MEM_WRITE),
            ],
            section_alignment: 0x1000,
            ..PeInputs::default()
        };
        let m = build(&i);
        let groups: Vec<(&str, u64, u64)> = m
            .groups
            .iter()
            .map(|g| (g.name.as_str(), g.addr, g.size.vm))
            .collect();
        assert_eq!(
            groups,
            [
                (".text$mn", 0x1000, 0x100),
                (".text$wbrd<all>", 0x1100, 0x38),
                ("?g_EncryptedSegmentSystemCall_<all>", 0x1200, 0x20),
                ("?g_EncryptedSegmentOther_<all>", 0x1220, 0x10),
                (".text$x", 0x1300, 0x10),
                (".text$x (E0000020)", 0x1400, 0x10),
            ]
        );
        assert_eq!(m.groups[1].origin, GroupOrigin::Merged);
    }

    #[test]
    fn tables_become_groups_where_no_group_covers_them() {
        let mut i = inputs();
        i.sections
            .push(section(".reloc", 0x4000, 0x200, 0x30, RDATA));
        i.tables = vec![
            Table {
                kind: TableKind::BaseRelocations,
                addr: 0x4000,
                size: 0x30,
            },
            // Overlaps .data (or comes within 8 bytes of it): no group.
            Table {
                kind: TableKind::DebugDirectory,
                addr: 0x2010,
                size: 0x1C,
            },
            Table {
                kind: TableKind::Exports,
                addr: 0x2105,
                size: 0x4,
            },
            // Too big for any section: dropped.
            Table {
                kind: TableKind::LoadConfig,
                addr: 0x4000,
                size: 0x1000,
            },
        ];
        let m = build(&i);
        let tables: Vec<(&str, GroupOrigin)> = m
            .groups
            .iter()
            .filter(|g| matches!(g.origin, GroupOrigin::Table(_)))
            .map(|g| (g.name.as_str(), g.origin))
            .collect();
        assert_eq!(
            tables,
            [(
                "[base relocations]",
                GroupOrigin::Table(TableKind::BaseRelocations)
            )]
        );
        let reloc = m
            .groups
            .iter()
            .find(|g| g.name == "[base relocations]")
            .unwrap();
        assert_eq!(reloc.size, Size::new(0x30, 0x30));
        assert_eq!(m.sections[reloc.section as usize].name, ".reloc");
        assert_eq!(reloc.padding.vm, 0x1000 - 0x30);
    }

    #[test]
    fn empty_inputs() {
        let m = build(&PeInputs::default());
        assert!(m.sections.is_empty() && m.groups.is_empty() && m.pieces.is_empty());
        // Sections and contributions but no groups: nothing is attributed.
        let mut i = inputs();
        i.groups.clear();
        let m = build(&i);
        assert_eq!(m.sections.len(), 3);
        assert!(m.pieces.is_empty());
    }

    #[test]
    fn overlapping_groups_wrap_like_sizebench() {
        // Group padding uses 32-bit wrapping arithmetic, so overlapping
        // groups give the same (huge) padding SizeBench reports.
        let i = PeInputs {
            sections: vec![section(".text", 0x1000, 0x200, 0x100, TEXT)],
            groups: vec![
                group(".a", 0x1000, 0x40, TEXT),
                group(".b", 0x1020, 0x40, TEXT),
            ],
            section_alignment: 0x1000,
            ..PeInputs::default()
        };
        let m = build(&i);
        assert_eq!(m.groups[0].padding.vm, u64::from(0u32.wrapping_sub(0x20)));
    }
}

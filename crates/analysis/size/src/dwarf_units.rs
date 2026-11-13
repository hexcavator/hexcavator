//! bloaty's `compileunits`: which compile unit each byte belongs to, from
//! the DWARF debug information (bloaty's `ReadDWARFCompileUnits`), for
//! ELF and Mach-O (the DWARF in the file, or in a separate debug file).
//!
//! A unit is charged the code and data its DIEs locate: `DW_AT_low_pc` /
//! `DW_AT_high_pc` pairs, range lists, and variables at fixed addresses
//! (sized by the symbol there); `.debug_aranges` entries; and the debug
//! information's own bytes: the unit, its abbreviations, line program,
//! strings, range and location lists, aranges and name-table entries,
//! and (DWARF 5) its contributions to the string-offset, address, range-
//! list, and location-list tables, which bloaty leaves unattributed.
//! The first unit to claim a byte keeps it.
//!
//! Where bloaty is wrong we are not: `DW_OP_addrx` locations (DWARF 5's
//! usual form) count, not only `DW_OP_addr`; range lists are relative to
//! the unit's base address, as the standard says (bloaty uses a DIE's own
//! `DW_AT_low_pc`, or for DWARF 5 the unit's address-table base); the
//! strings a unit's own name uses are charged to it (bloaty charges them
//! to an empty name); and strings include their terminating NUL.

use std::collections::HashMap;

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{
    Abbrevs, Attr, Sections, StrSection, Unit, UnitSection, Value, aranges, contribution,
    line_program_len, name_sets,
};

use crate::rangemap::{DualMap, Label, Labels};

pub const MISSING_FILENAME: &str = "[DWARF is missing filename]";

/// Where each DWARF section starts in the input file.
#[derive(Default)]
struct Offsets {
    info: Option<u64>,
    types: Option<u64>,
    abbrev: Option<u64>,
    str: Option<u64>,
    line_str: Option<u64>,
    ranges: Option<u64>,
    rnglists: Option<u64>,
    loc: Option<u64>,
    loclists: Option<u64>,
    str_offsets: Option<u64>,
    addr: Option<u64>,
    line: Option<u64>,
    aranges: Option<u64>,
    pubnames: Option<u64>,
    pubtypes: Option<u64>,
}

struct Charger<'m> {
    map: &'m mut DualMap,
    base: &'m DualMap,
    file_len: u64,
}

impl Charger<'_> {
    /// `len` bytes at `at` of a section that starts at `base` of the
    /// input (`None`: the section is not in the input, but in a separate
    /// debug file).
    fn file(&mut self, base: Option<u64>, at: u64, len: u64, l: Label) {
        let Some(at) = base.and_then(|b| b.checked_add(at)) else {
            return;
        };
        let end = at.saturating_add(len).min(self.file_len);
        if at < end {
            self.map.add_file(at, end, l, self.base);
        }
    }

    fn vm(&mut self, at: u64, len: u64, l: Label) {
        if len > 0 {
            self.map.add_vm(at, at.saturating_add(len), l, self.base);
        }
    }
}

/// A DWARF section: its name without the `.debug_`/`__debug_` prefix, its
/// contents (decompressed if need be), and where those start in the input
/// (`None` when they aren't the input's own bytes).
pub type DwarfSection<'d> = hexcavator_debuginfo::decompress::DebugSection<'d>;

/// DWARF sections, each with where it starts in the input file (`None`
/// when it comes from a separate debug file: its bytes are not the
/// input's to charge).
pub struct DwarfInput<'d> {
    pub endian: hexcavator_core::Endian,
    /// (name without its `.debug_`/`__debug_` prefix, bytes, offset).
    pub sections: Vec<DwarfSection<'d>>,
}

/// Charges code, data, and the DWARF's own bytes to compile units in
/// `map`. `sizes` gives symbol sizes by start address, for variables'
/// locations.
pub fn compile_units(
    input: &DwarfInput<'_>,
    sizes: &HashMap<u64, u64>,
    file_len: u64,
    labels: &mut Labels,
    map: &mut DualMap,
    base: &DualMap,
) {
    let mut s = Sections::new(input.endian);
    let mut off = Offsets::default();
    for (name, data, at) in &input.sections {
        let (name, at) = (*name, *at);
        if s.set(name, data) {
            let slot = match name {
                b"info" => &mut off.info,
                b"types" => &mut off.types,
                b"abbrev" => &mut off.abbrev,
                b"str" => &mut off.str,
                b"line_str" => &mut off.line_str,
                b"ranges" => &mut off.ranges,
                b"rnglists" => &mut off.rnglists,
                b"loc" => &mut off.loc,
                b"loclists" => &mut off.loclists,
                b"str_offsets" | b"str_offs" => &mut off.str_offsets,
                b"addr" => &mut off.addr,
                b"line" => &mut off.line,
                b"aranges" => &mut off.aranges,
                b"pubnames" => &mut off.pubnames,
                b"pubtypes" => &mut off.pubtypes,
                _ => continue,
            };
            *slot = at;
        }
    }
    if s.info.is_empty() {
        return;
    }
    let mut c = Charger {
        map,
        base,
        file_len,
    };
    let mut names: HashMap<u64, Label> = HashMap::new();
    let mut unit_name = |labels: &mut Labels, info_offset: u64| -> Label {
        *names.entry(info_offset).or_insert_with(|| {
            let name = Unit::at(s, info_offset)
                .and_then(|u| top_name(&u))
                .unwrap_or_else(|| MISSING_FILENAME.into());
            labels.intern(&name)
        })
    };

    for e in aranges(s.aranges, s.endian) {
        let l = unit_name(labels, e.info_offset);
        let valid = e.address != 0
            && !(e.address_size == 4 && e.address == u64::from(u32::MAX))
            && e.address != u64::MAX;
        if valid {
            c.vm(e.address, e.length, l);
        }
        c.file(off.aranges, e.offset, e.size, l);
    }
    // The sets' headers and terminators, to the unit too (bloaty leaves
    // them unattributed).
    for set in name_sets(s.aranges, s.endian) {
        let l = unit_name(labels, set.info_offset);
        c.file(off.aranges, set.offset, set.size, l);
    }

    let mut stmt_names: HashMap<u64, String> = HashMap::new();
    let mut attrs: Vec<Attr<'_>> = Vec::new();
    for (section, section_off) in [
        (UnitSection::Info, off.info),
        (UnitSection::Types, off.types),
    ] {
        for mut unit in Unit::iter(s, section, 0) {
            let Some(abbrevs) = Abbrevs::parse(s.abbrev, unit.abbrev_offset, s.endian) else {
                continue;
            };
            let mut dies = unit.dies();
            let Some(top) = dies.next(&abbrevs) else {
                continue;
            };
            if dies.attrs(&unit, top, &mut attrs).is_none() {
                continue;
            }
            unit.set_bases(&attrs);
            let mut name = attrs
                .iter()
                .find(|a| a.name == DW_AT_NAME)
                .and_then(|a| unit.string(&a.value))
                .map(|r| String::from_utf8_lossy(r.bytes).into_owned())
                .unwrap_or_default();
            let stmt_list = attrs
                .iter()
                .find(|a| a.name == DW_AT_STMT_LIST && a.form == DW_FORM_SEC_OFFSET)
                .and_then(|a| unit.uint(&a.value));
            if let Some(sl) = stmt_list {
                if name.is_empty() {
                    name = stmt_names.get(&sl).cloned().unwrap_or_default();
                } else {
                    stmt_names.insert(sl, name.clone());
                }
            }
            if name.is_empty() {
                continue;
            }
            let l = labels.intern(&name);
            c.file(section_off, unit.offset, unit.end - unit.offset, l);
            charge_strings(&mut c, &unit, &attrs, &off, l);
            add_die(&mut c, &unit, &attrs, sizes, &off, l);
            if let Some(sl) = stmt_list
                && let Some(len) = line_program_len(s.line, sl, s.endian)
            {
                c.file(off.line, sl, len, l);
            }
            c.file(off.abbrev, abbrevs.offset, abbrevs.len, l);
            // DWARF 5's per-unit tables belong to the unit whole.
            if unit.version >= 5 {
                for (present, data, base, header, at) in [
                    (
                        !s.str_offsets.is_empty(),
                        s.str_offsets,
                        unit.str_offsets_base,
                        4,
                        off.str_offsets,
                    ),
                    (!s.addr.is_empty(), s.addr, unit.addr_base, 4, off.addr),
                    (
                        !s.rnglists.is_empty(),
                        s.rnglists,
                        unit.rnglists_base,
                        8,
                        off.rnglists,
                    ),
                    (
                        !s.loclists.is_empty(),
                        s.loclists,
                        unit.loclists_base,
                        8,
                        off.loclists,
                    ),
                ] {
                    if present
                        && let Some((start, len)) = contribution(data, base, header, s.endian)
                    {
                        c.file(at, start, len, l);
                    }
                }
            }
            while let Some(a) = dies.next(&abbrevs) {
                if dies.attrs(&unit, a, &mut attrs).is_none() {
                    break;
                }
                charge_strings(&mut c, &unit, &attrs, &off, l);
                let low = attrs
                    .iter()
                    .find(|x| x.name == DW_AT_LOW_PC)
                    .and_then(|x| unit.uint(&x.value));
                let declaration = attrs
                    .iter()
                    .find(|x| x.name == DW_AT_DECLARATION)
                    .and_then(|x| unit.uint(&x.value))
                    .is_some_and(|v| v != 0);
                if low.is_some_and(|lo| !unit.is_valid_address(lo)) || declaration {
                    // Discarded code, or a declaration: skip what it holds.
                    if dies.skip_children(&unit, &abbrevs, a).is_none() {
                        break;
                    }
                } else {
                    add_die(&mut c, &unit, &attrs, sizes, &off, l);
                }
            }
        }
    }

    for (data, at) in [(s.pubnames, off.pubnames), (s.pubtypes, off.pubtypes)] {
        for set in name_sets(data, s.endian) {
            let Some(u) = Unit::at(s, set.info_offset) else {
                continue;
            };
            let Some(name) = top_name(&u) else { continue };
            let l = labels.intern(&name);
            c.file(at, set.offset, set.size, l);
        }
    }
}

/// bloaty's `inlines`: each unit's line table as spans of code, each
/// labeled `file:line` by the row that begins it (a span ends where a row
/// names another line, or its sequence ends). Discarded code's sequences
/// (at address 0) are left out.
pub fn inlines(input: &DwarfInput<'_>, labels: &mut Labels, map: &mut DualMap, base: &DualMap) {
    line_spans(input, labels, map, base, true);
}

/// Each span of code labeled by its source file (the `sourcefiles` source):
/// [`inlines`]'s spans, without their lines.
pub fn source_files(
    input: &DwarfInput<'_>,
    labels: &mut Labels,
    map: &mut DualMap,
    base: &DualMap,
) {
    line_spans(input, labels, map, base, false);
}

fn line_spans(
    input: &DwarfInput<'_>,
    labels: &mut Labels,
    map: &mut DualMap,
    base: &DualMap,
    with_line: bool,
) {
    let mut s = Sections::new(input.endian);
    for (name, data, _) in &input.sections {
        s.set(name, data);
    }
    let mut attrs = Vec::new();
    for mut unit in Unit::iter(s, UnitSection::Info, 0) {
        let Some(abbrevs) = Abbrevs::parse(s.abbrev, unit.abbrev_offset, s.endian) else {
            continue;
        };
        let mut dies = unit.dies();
        let Some(top) = dies.next(&abbrevs) else {
            continue;
        };
        if dies.attrs(&unit, top, &mut attrs).is_none() {
            continue;
        }
        unit.set_bases(&attrs);
        let Some(sl) = attrs
            .iter()
            .find(|a| a.name == DW_AT_STMT_LIST)
            .and_then(|a| unit.uint(&a.value))
        else {
            continue;
        };
        let Some(program) = hexcavator_dwarf::line_program(&s, sl, unit.address_size) else {
            continue;
        };
        let mut start: Option<u64> = None;
        let mut last = String::new();
        for row in program.rows.iter().filter(|r| !r.discarded) {
            let name = if row.end_sequence {
                last.clone()
            } else if with_line {
                format!(
                    "{}:{}",
                    program.file_name(row.file).unwrap_or_default(),
                    row.line
                )
            } else {
                program.file_name(row.file).unwrap_or_default()
            };
            match start {
                None => start = Some(row.address),
                Some(s) if row.end_sequence || (!last.is_empty() && name != last) => {
                    if row.address > s {
                        let l = labels.intern(&last);
                        map.add_vm(s, row.address, l, base);
                    }
                    start = (!row.end_sequence).then_some(row.address);
                }
                Some(_) => {}
            }
            last = name;
        }
    }
}

/// A unit's `DW_AT_name`.
fn top_name(u: &Unit<'_>) -> Option<String> {
    let s = u.sections();
    let abbrevs = Abbrevs::parse(s.abbrev, u.abbrev_offset, s.endian)?;
    let mut u = *u;
    let mut dies = u.dies();
    let a = dies.next(&abbrevs)?;
    let mut attrs = Vec::new();
    dies.attrs(&u, a, &mut attrs)?;
    u.set_bases(&attrs);
    let n = attrs
        .iter()
        .find(|a| a.name == DW_AT_NAME)
        .and_then(|a| u.string(&a.value))?;
    (!n.bytes.is_empty()).then(|| String::from_utf8_lossy(n.bytes).into_owned())
}

/// The strings a DIE's attributes use, charged to the unit.
fn charge_strings(
    c: &mut Charger<'_>,
    unit: &Unit<'_>,
    attrs: &[Attr<'_>],
    off: &Offsets,
    l: Label,
) {
    for a in attrs {
        if let Some(r) = unit.string(&a.value)
            && let Some((sec, at)) = r.at
        {
            let base = match sec {
                StrSection::Str => off.str,
                StrSection::LineStr => off.line_str,
            };
            c.file(base, at, r.bytes.len() as u64 + 1, l);
        }
    }
}

/// bloaty's `AddDIE`: the addresses and list bytes a DIE locates.
fn add_die(
    c: &mut Charger<'_>,
    unit: &Unit<'_>,
    attrs: &[Attr<'_>],
    sizes: &HashMap<u64, u64>,
    off: &Offsets,
    l: Label,
) {
    let get = |n: u16| attrs.iter().find(|a| a.name == n);
    let low = get(DW_AT_LOW_PC).and_then(|a| unit.uint(&a.value));
    if let Some(lo) = low
        && let Some(hi) = get(DW_AT_HIGH_PC)
    {
        let size = match hi.value {
            Value::Addr(_) | Value::AddrIndex(_) => {
                unit.uint(&hi.value).and_then(|h| h.checked_sub(lo))
            }
            _ => unit.uint(&hi.value),
        };
        if let Some(size) = size {
            c.vm(lo, size, l);
        }
    }
    if let Some(loc) = get(DW_AT_LOCATION) {
        if let Some(addr) = unit.location_address(&loc.value) {
            if let Some(&size) = sizes.get(&addr) {
                c.vm(addr, size, l);
            }
        } else if unit.version < 5
            && matches!(loc.form, DW_FORM_SEC_OFFSET | DW_FORM_DATA4 | DW_FORM_DATA8)
            && let Some(o) = unit.uint(&loc.value)
            && let Some(len) = unit.location_list_len(o)
        {
            c.file(off.loc, o, len, l);
        }
    }
    let ranges = get(DW_AT_RANGES).or_else(|| {
        if unit.version < 5 {
            get(DW_AT_START_SCOPE)
        } else {
            None
        }
    });
    let Some(r) = ranges else { return };
    if unit.version >= 5 {
        let o = match r.value {
            Value::ListIndex(i) => unit.rnglist_offset(i),
            ref v => unit.uint(v),
        };
        if let Some(o) = o
            && let Some((list, len)) = unit.rnglist(o)
        {
            for (a, n) in list {
                c.vm(a, n, l);
            }
            c.file(off.rnglists, o, len, l);
        }
    } else if let Some(o) = unit.uint(&r.value)
        && let Some((list, len)) = unit.range_list(o, unit.low_pc)
    {
        for (a, n) in list {
            c.vm(a, n, l);
        }
        c.file(off.ranges, o, len, l);
    }
}

//! The DWARF of the testdata/elf fixtures (two units; DWARF 4 with aranges
//! and 5; little- and big-endian) against llvm-dwarfdump's dump of it:
//! every DIE's offset, name, pc range, range list, and `DW_OP_addr`
//! location, and every `.debug_aranges` entry.

use std::path::PathBuf;

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Abbrevs, Sections, Unit, UnitSection, Value, aranges};
use hexcavator_elf::ElfFile;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/elf")
        .join(name)
}

/// What both sides report of a DIE.
#[derive(Debug, Default, PartialEq, Eq)]
struct Die {
    offset: u64,
    name: Option<String>,
    low_pc: Option<u64>,
    high_pc: Option<u64>,
    ranges: Vec<(u64, u64)>,
    addr: Option<u64>,
    /// `DW_OP_addrx`'s index (dwarfdump shows the index, not the address).
    addrx: Option<u64>,
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap()
}

/// `[0xA, 0xB)` pairs in a line.
fn pairs(line: &str) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find('[') {
        let r = &rest[i + 1..];
        let Some(j) = r.find(')') else { break };
        let (a, b) = r[..j].split_once(',').unwrap();
        out.push((hex(a), hex(b)));
        rest = &r[j..];
    }
    out
}

fn theirs(text: &str) -> (Vec<Die>, Vec<(u64, u64, u64)>) {
    let mut dies: Vec<Die> = Vec::new();
    let mut aranges = Vec::new();
    let mut in_ranges = false;
    let mut cu_offset = 0;
    let mut in_aranges = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with(".debug_aranges contents:") {
            in_aranges = true;
            continue;
        }
        if in_aranges {
            if let Some(h) = t.strip_prefix("Address Range Header:") {
                cu_offset = hex(h
                    .split("cu_offset = ")
                    .nth(1)
                    .unwrap()
                    .split(',')
                    .next()
                    .unwrap());
            } else {
                for (a, b) in pairs(t) {
                    aranges.push((cu_offset, a, b - a));
                }
            }
            continue;
        }
        if let Some((off, rest)) = t.split_once(": ")
            && off.starts_with("0x")
            && off.len() == 10
        {
            let rest = rest.trim();
            if rest.starts_with("DW_TAG_") {
                dies.push(Die {
                    offset: hex(off),
                    ..Die::default()
                });
            }
            in_ranges = false;
            continue;
        }
        let Some(d) = dies.last_mut() else { continue };
        if in_ranges {
            d.ranges.extend(pairs(t));
            if t.ends_with("))") {
                in_ranges = false;
            }
            continue;
        }
        let Some((attr, value)) = t.split_once('\t') else {
            continue;
        };
        let value = value.trim().trim_start_matches('(').trim_end_matches(')');
        match attr {
            "DW_AT_name" => d.name = Some(value.trim_matches('"').to_string()),
            "DW_AT_low_pc" => d.low_pc = Some(hex(value)),
            "DW_AT_high_pc" => d.high_pc = Some(hex(value)),
            "DW_AT_ranges" => {
                d.ranges.extend(pairs(t));
                in_ranges = !t.ends_with("))");
            }
            "DW_AT_location" => {
                if let Some(a) = value.strip_prefix("DW_OP_addr ") {
                    d.addr = Some(hex(a));
                } else if let Some(i) = value.strip_prefix("DW_OP_addrx ") {
                    d.addrx = Some(hex(i));
                }
            }
            _ => {}
        }
    }
    (dies, aranges)
}

fn ours(s: Sections<'_>) -> Vec<Die> {
    let mut out = Vec::new();
    let mut attrs = Vec::new();
    for mut unit in Unit::iter(s, UnitSection::Info, 0) {
        let abbrevs = Abbrevs::parse(s.abbrev, unit.abbrev_offset, s.endian).unwrap();
        let mut dies = unit.dies();
        let mut first = true;
        while let Some(a) = dies.next(&abbrevs) {
            dies.attrs(&unit, a, &mut attrs).unwrap();
            if first {
                unit.set_bases(&attrs);
                first = false;
            }
            let mut d = Die {
                offset: dies.offset,
                ..Die::default()
            };
            for at in &attrs {
                match at.name {
                    DW_AT_NAME => {
                        d.name = unit
                            .string(&at.value)
                            .map(|r| String::from_utf8_lossy(r.bytes).into_owned());
                    }
                    DW_AT_LOW_PC => d.low_pc = unit.uint(&at.value),
                    DW_AT_HIGH_PC => d.high_pc = unit.uint(&at.value),
                    DW_AT_RANGES => {
                        let list = match at.value {
                            Value::ListIndex(i) => {
                                unit.rnglist_offset(i).and_then(|o| unit.rnglist(o))
                            }
                            ref v if unit.version >= 5 => unit.rnglist(unit.uint(v).unwrap()),
                            ref v => unit.range_list(unit.uint(v).unwrap(), unit.low_pc),
                        };
                        d.ranges = list
                            .unwrap()
                            .0
                            .into_iter()
                            .map(|(a, n)| (a, a + n))
                            .collect();
                    }
                    DW_AT_LOCATION => {
                        if let Value::Block(b) = at.value
                            && b.first() == Some(&DW_OP_ADDR)
                            && b.len() == 1 + usize::from(unit.address_size)
                        {
                            d.addr =
                                hexcavator_dwarf::Reader::new(b, 1, s.endian).uint(b.len() - 1);
                        }
                        if let Value::Block(b) = at.value
                            && b.first() == Some(&DW_OP_ADDRX)
                        {
                            d.addrx = hexcavator_dwarf::Reader::new(b, 1, s.endian).uleb();
                            // The helper resolves it through .debug_addr.
                            assert!(unit.location_address(&at.value).is_some());
                        }
                        if d.addr.is_some() {
                            assert_eq!(unit.location_address(&at.value), d.addr);
                        }
                    }
                    _ => {}
                }
            }
            // A size: the high pc is relative to the low.
            if let (Some(lo), Some(hi)) = (d.low_pc, d.high_pc)
                && let Some(at) = attrs.iter().find(|a| a.name == DW_AT_HIGH_PC)
                && matches!(at.value, Value::Data(_) | Value::Uint(_))
            {
                d.high_pc = Some(lo + hi);
            }
            out.push(d);
        }
    }
    out
}

fn sections<'d>(elf: &ElfFile<'d>) -> Sections<'d> {
    let mut s = Sections::new(elf.endian());
    for sec in elf.sections() {
        if let Some(name) = sec.name.strip_prefix(b".debug_") {
            s.set(name, elf.section_data(&sec));
        }
    }
    s
}

#[test]
fn matches_llvm_dwarfdump() {
    for f in [
        "dwarf4-x86_64-linux-gnu",
        "dwarf5-x86_64-linux-gnu",
        "dwarf4-aarch64_be-linux-gnu",
        "dwarf5-aarch64_be-linux-gnu",
    ] {
        let data = std::fs::read(testdata(f)).unwrap();
        let elf = ElfFile::parse(&data).unwrap();
        let s = sections(&elf);
        let (dies, their_aranges) =
            theirs(&std::fs::read_to_string(testdata(&format!("{f}.dwarfdump.txt"))).unwrap());
        let mine = ours(s);
        assert!(dies.len() > 20, "{f}");
        assert_eq!(mine.len(), dies.len(), "{f} DIE count");
        for (a, b) in mine.iter().zip(&dies) {
            assert_eq!(a, b, "{f}");
        }
        assert!(
            mine.iter().any(|d| d.ranges.len() >= 3),
            "{f}: a unit with a range list"
        );
        assert!(
            mine.iter().any(|d| d.addr.is_some() || d.addrx.is_some()),
            "{f}: a variable at an address"
        );
        let units: Vec<_> = Unit::iter(s, UnitSection::Info, 0).collect();
        assert_eq!(units.len(), 2, "{f}");
        assert_eq!(
            units[0].version,
            if f.starts_with("dwarf4") { 4 } else { 5 }
        );
        let ours_ar: Vec<_> = aranges(s.aranges, s.endian)
            .iter()
            .map(|e| (e.info_offset, e.address, e.length))
            .collect();
        assert_eq!(ours_ar, their_aranges, "{f}");
        assert!(!ours_ar.is_empty());
    }
}

/// A line table as dwarfdump shows it: its offset, file names, and rows
/// (address, line, column, file, end of sequence).
type LineTable = (u64, Vec<String>, Vec<(u64, u64, u64, u64, bool)>);

/// Every row of every line table, and its file table, against
/// `llvm-dwarfdump --debug-line`.
#[test]
fn line_tables_match_llvm_dwarfdump() {
    for f in [
        "dwarf4-x86_64-linux-gnu",
        "dwarf5-x86_64-linux-gnu",
        "dwarf4-aarch64_be-linux-gnu",
        "dwarf5-aarch64_be-linux-gnu",
    ] {
        let data = std::fs::read(testdata(f)).unwrap();
        let elf = ElfFile::parse(&data).unwrap();
        let s = sections(&elf);
        let text = std::fs::read_to_string(testdata(&format!("{f}.lines.txt"))).unwrap();
        // (offset, files, rows): rows as (address, line, column, file, end_sequence).
        let mut theirs: Vec<LineTable> = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            if let Some(o) = t
                .strip_prefix("debug_line[")
                .and_then(|r| r.strip_suffix(']'))
            {
                theirs.push((hex(o), Vec::new(), Vec::new()));
            } else if let Some(n) = t.strip_prefix("name: ") {
                theirs
                    .last_mut()
                    .unwrap()
                    .1
                    .push(n.trim_matches('"').to_string());
            } else if t.starts_with("0x") && t.len() > 40 {
                let w: Vec<&str> = t.split_whitespace().collect();
                theirs.last_mut().unwrap().2.push((
                    hex(w[0]),
                    w[1].parse().unwrap(),
                    w[2].parse().unwrap(),
                    w[3].parse().unwrap(),
                    t.contains("end_sequence"),
                ));
            }
        }
        assert_eq!(theirs.len(), 2, "{f}");
        for (offset, files, rows) in &theirs {
            let p = hexcavator_dwarf::line_program(&s, *offset, 8).unwrap();
            let ours_rows: Vec<_> = p
                .rows
                .iter()
                .map(|r| (r.address, r.line, r.column, r.file, r.end_sequence))
                .collect();
            assert_eq!(&ours_rows, rows, "{f} at {offset:#x}");
            // DWARF 4 numbers files from 1, behind a placeholder.
            let skip = usize::from(p.version < 5);
            let names: Vec<String> = p.files[skip..]
                .iter()
                .map(|e| String::from_utf8_lossy(e.name).into_owned())
                .collect();
            assert_eq!(&names, files, "{f}");
            assert!(p.rows.iter().all(|r| !r.discarded));
            let first = p.rows[0].file;
            let name = p.file_name(first).unwrap();
            assert!(name.ends_with(".c"), "{f}: {name}");
        }
    }
}

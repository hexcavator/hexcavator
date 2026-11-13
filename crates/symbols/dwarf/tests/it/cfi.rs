//! Call frame information against llvm-dwarfdump: every FDE's unwind rule
//! table, row by row, in llvm-dwarfdump's notation.
//!
//! `fixtures` uses testdata/cfi (built by tools/cfi/build.py, with
//! llvm-dwarfdump's output beside each file). The ignored `corpus` runs
//! llvm-dwarfdump live on the files `HEXC_CFI_FILES` lists (separated by
//! `;`; `build.py corpus` builds compiler-rt's builtins for each target),
//! with `LLVM_BIN` naming llvm-dwarfdump's directory.

#![allow(clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hexcavator_core::Endian;
use hexcavator_dwarf::Reader;
use hexcavator_dwarf::cfi::{self, CfaRule, Cfi, CfiKind, Entry, RegisterRule, UnwindRow};
use hexcavator_elf::{Class, ElfFile};

/// llvm-dwarfdump's register names.
fn register(machine: u16, n: u16) -> String {
    let named = match machine {
        62 => {
            const X64: [&str; 17] = [
                "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
                "R12", "R13", "R14", "R15", "RIP",
            ];
            X64.get(usize::from(n))
                .map(std::string::ToString::to_string)
                .or_else(|| match n {
                    17..=32 => Some(format!("XMM{}", n - 17)),
                    _ => None,
                })
        }
        3 => {
            const X86: [&str; 9] = [
                "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP",
            ];
            X86.get(usize::from(n))
                .map(std::string::ToString::to_string)
        }
        183 => match n {
            0..=30 => Some(format!("W{n}")),
            31 => Some("WSP".into()),
            64..=95 => Some(format!("B{}", n - 64)),
            _ => None,
        },
        40 => match n {
            0..=12 => Some(format!("R{n}")),
            13 => Some("SP".into()),
            14 => Some("LR".into()),
            15 => Some("PC".into()),
            256..=287 => Some(format!("D{}", n - 256)),
            _ => None,
        },
        _ => None,
    };
    named.unwrap_or_else(|| format!("reg{n}"))
}

/// An expression in llvm-dwarfdump's notation.
fn expression(machine: u16, expr: &[u8], endian: Endian, address_size: u8) -> String {
    let mut r = Reader::new(expr, 0, endian);
    let mut parts = Vec::new();
    while let Some(op) = r.u8() {
        let text = match op {
            0x03 => format!(
                "DW_OP_addr 0x{:x}",
                r.uint(usize::from(address_size)).unwrap_or(0)
            ),
            0x06 => "DW_OP_deref".into(),
            0x08 => format!("DW_OP_const1u 0x{:x}", r.uint(1).unwrap_or(0)),
            0x09 => format!("DW_OP_const1s {}", r.uint(1).unwrap_or(0) as u8 as i8),
            0x0a => format!("DW_OP_const2u 0x{:x}", r.uint(2).unwrap_or(0)),
            0x0b => format!("DW_OP_const2s {}", r.uint(2).unwrap_or(0) as u16 as i16),
            0x0c => format!("DW_OP_const4u 0x{:x}", r.uint(4).unwrap_or(0)),
            0x0d => format!("DW_OP_const4s {}", r.uint(4).unwrap_or(0) as u32 as i32),
            0x10 => format!("DW_OP_constu 0x{:x}", r.uleb().unwrap_or(0)),
            0x11 => format!("DW_OP_consts {}", r.sleb().unwrap_or(0)),
            0x12 => "DW_OP_dup".into(),
            0x13 => "DW_OP_drop".into(),
            0x1a => "DW_OP_and".into(),
            0x1c => "DW_OP_minus".into(),
            0x1e => "DW_OP_mul".into(),
            0x22 => "DW_OP_plus".into(),
            0x23 => format!("DW_OP_plus_uconst 0x{:x}", r.uleb().unwrap_or(0)),
            0x24 => "DW_OP_shl".into(),
            0x30..=0x4f => format!("DW_OP_lit{}", op - 0x30),
            0x70..=0x8f => {
                let off = r.sleb().unwrap_or(0);
                format!(
                    "DW_OP_breg{} {}{off:+}",
                    op - 0x70,
                    register(machine, u16::from(op - 0x70))
                )
            }
            0x92 => {
                let reg = r.uleb().unwrap_or(0) as u16;
                let off = r.sleb().unwrap_or(0);
                format!("DW_OP_bregx {}{off:+}", register(machine, reg))
            }
            0x94 => format!("DW_OP_deref_size 0x{:x}", r.u8().unwrap_or(0)),
            0x96 => "DW_OP_nop".into(),
            _ => format!("<op 0x{op:02x}>"),
        };
        parts.push(text);
    }
    parts.join(", ")
}

fn offset(n: i64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!("{n:+}")
    }
}

/// A row as llvm-dwarfdump prints it.
fn format_row(machine: u16, row: &UnwindRow<'_>, endian: Endian, address_size: u8) -> String {
    let mut s = format!("0x{:x}: CFA=", row.address);
    match row.cfa {
        CfaRule::RegisterOffset {
            register: r,
            offset: o,
        } => {
            write!(s, "{}{}", register(machine, r), offset(o)).unwrap();
        }
        CfaRule::Expression(e) => s.push_str(&expression(machine, e, endian, address_size)),
    }
    let mut rules: Vec<(u16, String)> = row
        .registers
        .iter()
        .map(|&(r, rule)| {
            let value = match rule {
                RegisterRule::Undefined => "undefined".into(),
                RegisterRule::SameValue => "same".into(),
                RegisterRule::Offset(o) => format!("[CFA{}]", offset(o)),
                RegisterRule::ValOffset(o) => format!("CFA{}", offset(o)),
                RegisterRule::Register(from) => register(machine, from),
                RegisterRule::Expression(e) => {
                    format!("[{}]", expression(machine, e, endian, address_size))
                }
                RegisterRule::ValExpression(e) => expression(machine, e, endian, address_size),
            };
            (r, format!("{}={value}", register(machine, r)))
        })
        .collect();
    // (AArch64's return address signing state: llvm's pseudo-register 34,
    // in number order.)
    if let Some(signed) = row.return_address_signed {
        rules.push((34, format!("reg34={}", u8::from(signed))));
        rules.sort_by_key(|&(r, _)| r);
    }
    if !rules.is_empty() {
        let texts: Vec<String> = rules.into_iter().map(|(_, t)| t).collect();
        write!(s, ": {}", texts.join(", ")).unwrap();
    }
    s
}

/// Each FDE's rows: (section, FDE offset) -> lines.
type Tables = BTreeMap<(String, u64), Vec<String>>;

/// llvm-dwarfdump's tables.
fn theirs(text: &str) -> Tables {
    let mut out = Tables::new();
    let mut section = String::new();
    let mut current: Option<(String, u64)> = None;
    for line in text.lines() {
        if let Some(name) = line.strip_suffix(" contents:") {
            section = name.trim_start_matches('.').into();
            current = None;
        } else if line.contains(" FDE cie=") {
            let off = u64::from_str_radix(line.split(' ').next().unwrap(), 16).unwrap();
            current = Some((section.clone(), off));
            out.entry((section.clone(), off)).or_default();
        } else if line.contains(" CIE") && !line.starts_with(' ') {
            current = None;
        } else if let (Some(key), Some(row)) = (&current, line.strip_prefix("  0x"))
            && row.contains(": CFA=")
        {
            out.get_mut(key).unwrap().push(format!("0x{row}"));
        }
    }
    out
}

/// Ours, for the same file.
fn ours(path: &Path) -> Tables {
    let data = std::fs::read(path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    let machine = elf.header().machine;
    let endian = elf.endian();
    let address_size = if elf.class() == Class::Elf64 { 8 } else { 4 };
    let mut out = Tables::new();
    for (name, kind) in [
        (&b".eh_frame"[..], CfiKind::EhFrame),
        (b".debug_frame", CfiKind::DebugFrame),
    ] {
        let Some(section) = elf.section_by_name(name) else {
            continue;
        };
        let cfi = Cfi {
            data: elf.section_data(&section),
            kind,
            endian,
            address: if kind == CfiKind::EhFrame {
                section.addr
            } else {
                0
            },
            address_size,
            text_base: None,
            data_base: None,
        };
        let key = String::from_utf8_lossy(&name[1..]).to_string();
        for entry in cfi.entries() {
            let Entry::Fde(fde) = entry else { continue };
            let Some(Entry::Cie(cie)) = cfi.entry_at(fde.cie as usize).map(|e| e.0) else {
                out.insert((key.clone(), fde.offset), vec!["<no CIE>".into()]);
                continue;
            };
            let lines = match cfi::rows(&cfi, &cie, &fde) {
                Some(rows) => rows
                    .iter()
                    .map(|r| format_row(machine, r, endian, address_size))
                    .collect(),
                None => vec!["<malformed>".into()],
            };
            out.insert((key.clone(), fde.offset), lines);
        }
    }
    out
}

/// Compares one file; returns (FDEs, rows, mismatching FDEs).
fn compare(path: &Path, dump: &str, show: &mut usize) -> (usize, usize, usize) {
    let (theirs, ours) = (theirs(dump), ours(path));
    let mut bad = 0;
    let rows = theirs.values().map(Vec::len).sum();
    for key in theirs
        .keys()
        .chain(ours.keys().filter(|k| !theirs.contains_key(k)))
    {
        let (t, o) = (theirs.get(key), ours.get(key));
        if t != o {
            bad += 1;
            if *show > 0 {
                *show -= 1;
                eprintln!("MISMATCH {} {} FDE {:#x}", path.display(), key.0, key.1);
                eprintln!("  theirs: {t:#?}");
                eprintln!("  ours:   {o:#?}");
            }
        }
    }
    (theirs.len(), rows, bad)
}

#[test]
fn fixtures() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/cfi");
    let mut show = 10;
    let (mut fdes, mut rows, mut bad) = (0, 0, 0);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        // (Only the images with DWARF CFI: the Mach-O ones are for
        // __unwind_info, the ehabi ones for ARM EHABI.)
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.extension().is_some() || name.starts_with("macho-") || name.starts_with("ehabi-") {
            continue;
        }
        let dump = std::fs::read_to_string(path.with_extension("frames.txt")).unwrap();
        let (f, r, b) = compare(&path, &dump, &mut show);
        assert!(f > 0, "{}: no FDEs", path.display());
        (fdes, rows, bad) = (fdes + f, rows + r, bad + b);
    }
    eprintln!("{fdes} FDEs, {rows} rows, {bad} mismatches");
    assert_eq!(bad, 0);
}

//! ARM EHABI against llvm-readobj --unwind: every `.ARM.exidx` entry's
//! function, table entry, model, personality, and opcode bytes; and an
//! unwind from each (which must work, or refuse cleanly).
//!
//! `fixtures` uses testdata/cfi/ehabi-* (tools/cfi/build.py); the ignored
//! `corpus` runs llvm-readobj live on the files `HEXC_EHABI_FILES` lists.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use hexcavator_elf::ElfFile;
use hexcavator_unwind::Memory;
use hexcavator_unwind::arm_ehabi::{self, Entry, Exidx, Model};
use hexcavator_unwind::dwarf_cfi::Registers;

/// The image's bytes by virtual address.
struct Image<'a>(&'a ElfFile<'a>);

impl Memory for Image<'_> {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        let Some(offset) = self.0.vaddr_to_offset(address) else {
            return false;
        };
        let Some(bytes) = usize::try_from(offset)
            .ok()
            .and_then(|o| self.0.data().get(o..o + buf.len()))
        else {
            return false;
        };
        buf.copy_from_slice(bytes);
        true
    }
}

/// Memory that is all there (a stack for the unwinds).
struct Anything;

impl Memory for Anything {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (address.wrapping_add(i as u64) >> 2) as u8;
        }
        true
    }
}

/// llvm-readobj's entries, as text keys.
fn theirs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "Entry {" {
            current = Some(String::new());
        } else if let Some(cur) = &mut current {
            if t == "}" {
                out.push(current.take().unwrap());
            } else if let Some(v) = t.strip_prefix("FunctionAddress: ") {
                cur.push_str(&format!("function={v} "));
            } else if let Some(v) = t.strip_prefix("TableEntryAddress: ") {
                cur.push_str(&format!("table={v} "));
            } else if let Some(v) = t.strip_prefix("Model: ") {
                cur.push_str(&format!("model={v} "));
            } else if let Some(v) = t.strip_prefix("PersonalityIndex: ") {
                cur.push_str(&format!("personality={v} "));
            } else if let Some(v) = t.strip_prefix("PersonalityRoutineAddress: ") {
                cur.push_str(&format!("routine={v} "));
            } else if t.starts_with("0x") {
                let bytes = t.split(';').next().unwrap();
                for b in bytes.split_whitespace() {
                    cur.push_str(&format!("{} ", &b[2..]));
                }
            }
        }
    }
    out
}

fn ours(entry: &Entry) -> String {
    let mut s = format!("function=0x{:X} ", entry.function);
    if let Some(t) = entry.table {
        s.push_str(&format!("table=0x{t:X} "));
    }
    match entry.model {
        Model::CantUnwind => s.push_str("model=CantUnwind "),
        Model::Compact {
            personality,
            inline,
        } => {
            s.push_str(if inline {
                "model=Compact (Inline) "
            } else {
                "model=Compact "
            });
            s.push_str(&format!("personality={personality} "));
        }
        // (llvm-readobj doesn't decode a personality routine's own data;
        // we read GNU's layout, the opcodes first.)
        Model::Generic { personality } => {
            return s + &format!("model=Generic routine=0x{personality:X} ");
        }
    }
    for b in &entry.opcodes {
        s.push_str(&format!("{b:02X} "));
    }
    s
}

/// Compares one file; returns its entry count.
fn compare(path: &Path, text: &str) -> usize {
    let data = std::fs::read(path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    let section = elf.section_by_name(b".ARM.exidx").unwrap();
    let exidx = Exidx {
        data: elf.section_data(&section),
        address: section.addr,
        endian: elf.endian(),
    };
    let image = Image(&elf);
    let expected = theirs(text);
    let mut got = Vec::new();
    for i in 0..exidx.len() {
        let entry = exidx.entry(i, &image).unwrap();
        // Unwinding from it works, or refuses cleanly.
        let mut regs = Registers::default();
        for r in 0..16 {
            regs.set(r, Some(0x10_0000 + 0x100 * u64::from(r)));
        }
        let result = arm_ehabi::unwind(&entry, elf.endian(), &mut regs, &Anything);
        assert!(
            result.is_ok() || entry.model == Model::CantUnwind,
            "{}: {result:?} for {entry:x?}",
            path.display()
        );
        // A lookup of its function finds it (or, where several entries
        // share a start, the last of them).
        let last = (i..exidx.len())
            .take_while(|&j| exidx.entry(j, &image).unwrap().function == entry.function)
            .last()
            .unwrap();
        assert_eq!(exidx.lookup(entry.function), Some(last));
        got.push(ours(&entry));
    }
    assert_eq!(got, expected, "{}", path.display());
    got.len()
}

#[test]
fn fixtures() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/cfi");
    for name in ["ehabi-arm", "ehabi-thumb"] {
        let text = std::fs::read_to_string(dir.join(format!("{name}.unwind.txt"))).unwrap();
        assert!(compare(&dir.join(name), &text) > 0);
    }
}

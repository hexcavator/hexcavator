//! `__unwind_info` against llvm-objdump --unwind-info: every function's
//! entry, and lookups of each function's first and last bytes. The
//! fixtures are testdata/cfi/macho-* (built by tools/cfi/build.py, with
//! llvm-objdump's output beside each).

#![allow(clippy::cast_possible_truncation)]

use std::path::PathBuf;

use hexcavator_macho::MachO;
use hexcavator_macho::unwind_info::{Entry, UnwindInfo};

fn theirs(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut second_level = false;
    for line in text.lines() {
        if line.contains("Second level indices:") {
            second_level = true;
            continue;
        }
        if !second_level
            || !line.contains("function offset=")
            || line.contains("Second level index")
        {
            continue;
        }
        // `function offset=0x...`, then `encoding=0x...` or
        // `encoding[n]=0x...`.
        let hex = |rest: &str| -> u32 {
            let digits: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            u32::from_str_radix(&digits, 16).unwrap()
        };
        let function = &line[line.find("function offset=0x").unwrap() + 18..];
        let encoding = line[line.find("encoding").unwrap()..]
            .split_once("=0x")
            .unwrap()
            .1;
        out.push(Entry {
            function: hex(function),
            encoding: hex(encoding),
        });
    }
    out
}

/// Compares one image; returns its entry count.
fn compare(name: &str, data: &[u8], text: &str) -> usize {
    let macho = MachO::parse(data).unwrap();
    let section = macho
        .sections()
        .into_iter()
        .find(|s| s.sectname == b"__unwind_info")
        .unwrap();
    let bytes = &data[section.offset as usize..][..section.size as usize];
    let info = UnwindInfo::parse(bytes, macho.endian()).unwrap();
    let ours = info.entries();
    let expected = theirs(text);
    assert!(!expected.is_empty(), "{name}");
    assert_eq!(ours, expected, "{name}");
    // Every function's first and last byte finds it.
    for (i, e) in ours.iter().enumerate() {
        let found = info.lookup(e.function).unwrap();
        assert_eq!(found.entry, *e, "{name} {:#x}", e.function);
        if let Some(next) = ours.get(i + 1) {
            assert_eq!(found.end, next.function);
            assert_eq!(info.lookup(next.function - 1).unwrap().entry, *e);
        }
    }
    assert_eq!(info.lookup(ours[0].function - 1), None);
    ours.len()
}

#[test]
fn matches_llvm_objdump() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/cfi");
    for name in ["macho-arm64", "macho-x86_64"] {
        let data = std::fs::read(dir.join(name)).unwrap();
        let text = std::fs::read_to_string(dir.join(format!("{name}.unwind.txt"))).unwrap();
        compare(name, &data, &text);
    }
}

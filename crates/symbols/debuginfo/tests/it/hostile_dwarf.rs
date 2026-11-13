//! DWARF built to make the reader do too much: base classes shared down a
//! long chain (exponential if each path is followed), an array type whose
//! element is itself (endless if followed), and one long range list named
//! by many functions (each would have all of it). Each finishes quickly,
//! with bounded results, on a small stack.

#![allow(clippy::cast_possible_truncation, reason = "small test data")]

use hexcavator_debuginfo::DebugInfo;

/// A little-endian ELF64 relocatable object with these sections.
fn elf(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut names = vec![0u8];
    let mut name_at = Vec::new();
    for (n, _) in sections {
        name_at.push(names.len() as u32);
        names.extend_from_slice(n.as_bytes());
        names.push(0);
    }
    let shstrtab_name = names.len() as u32;
    names.extend_from_slice(b".shstrtab\0");
    let mut all: Vec<(u32, u32, &[u8])> = vec![(0, 0, &[])];
    for (i, (_, d)) in sections.iter().enumerate() {
        all.push((name_at[i], 1, d));
    }
    all.push((shstrtab_name, 3, &names));
    let mut out = Vec::new();
    out.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    out.extend_from_slice(&1u16.to_le_bytes()); // ET_REL
    out.extend_from_slice(&62u16.to_le_bytes()); // x86-64
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // entry
    out.extend_from_slice(&0u64.to_le_bytes()); // phoff
    let shoff_at = out.len();
    out.extend_from_slice(&0u64.to_le_bytes()); // shoff (patched)
    out.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, 0, 64, all.len() as u16, (all.len() - 1) as u16] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut offsets = Vec::new();
    for (_, _, d) in &all {
        out.resize(out.len().next_multiple_of(8), 0);
        offsets.push(out.len() as u64);
        out.extend_from_slice(d);
    }
    out.resize(out.len().next_multiple_of(8), 0);
    let shoff = out.len() as u64;
    out[shoff_at..shoff_at + 8].copy_from_slice(&shoff.to_le_bytes());
    for (i, (name, kind, d)) in all.iter().enumerate() {
        out.extend_from_slice(&name.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        let offset = if i == 0 { 0 } else { offsets[i] };
        for v in [0u64, 0, offset, d.len() as u64] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
    }
    out
}

// Abbreviation codes.
const CU: u8 = 1;
const STRUCT: u8 = 2;
const BASE: u8 = 3;
const ARRAY: u8 = 4;
const MEMBER: u8 = 5;
const FUNCTION: u8 = 6;

fn abbrevs() -> Vec<u8> {
    vec![
        CU, 0x11, 1, 0, 0, // compile unit, children
        STRUCT, 0x13, 1, 0x03, 0x08, 0x0B, 0x0B, 0, 0, // name, byte size
        BASE, 0x1C, 0, 0x49, 0x13, 0x38, 0x0B, 0, 0, // type (ref4), location
        ARRAY, 0x01, 0, 0x49, 0x13, 0, 0, // element type (ref4)
        MEMBER, 0x0D, 0, 0x03, 0x08, 0x49, 0x13, 0x38, 0x0B, 0, 0, FUNCTION, 0x2E, 0, 0x03, 0x08,
        0x55, 0x17, 0, 0, // name, ranges
        0,
    ]
}

/// A DWARF 4 compile unit (64-bit addresses) holding `dies` (which start
/// at unit offset 12, after the header and the unit's own DIE).
fn unit(dies: &[u8]) -> Vec<u8> {
    let mut body = vec![4, 0, 0, 0, 0, 0, 8, CU];
    body.extend_from_slice(dies);
    body.push(0);
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(body);
    out
}

const FIRST_DIE: usize = 12;

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn shared_empty_bases_take_linear_time() {
    // S0 .. S69: each but the last has two bases, both the next; all are
    // empty (so each base must be looked into). A struct "Top" of byte size
    // 1 has S0 as its base twice.
    let n = 70;
    let struct_len = |k: usize| 7 + if k + 1 < n { 12 } else { 0 } + 1;
    let top_len = 1 + 4 + 1 + 12 + 1;
    let mut at = FIRST_DIE + top_len;
    let mut offsets = Vec::new();
    for k in 0..n {
        offsets.push(at as u32);
        at += struct_len(k);
    }
    let base = |out: &mut Vec<u8>, to: u32| {
        out.push(BASE);
        out.extend_from_slice(&to.to_le_bytes());
        out.push(0);
    };
    let mut dies = vec![STRUCT];
    dies.extend_from_slice(b"Top\0");
    dies.push(1);
    base(&mut dies, offsets[0]);
    base(&mut dies, offsets[0]);
    dies.push(0);
    for k in 0..n {
        dies.push(STRUCT);
        dies.extend_from_slice(format!("S{k:03}").as_bytes());
        dies.push(0);
        dies.push(1);
        if k + 1 < n {
            base(&mut dies, offsets[k + 1]);
            base(&mut dies, offsets[k + 1]);
        }
        dies.push(0);
    }
    let file = elf(&[(".debug_info", &unit(&dies)), (".debug_abbrev", &abbrevs())]);
    let start = std::time::Instant::now();
    let layouts = on_small_stack(move || {
        let d = DebugInfo::parse(&file).unwrap();
        d.layouts().unwrap().len()
    });
    assert!(layouts > n);
    assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
}

#[test]
fn an_array_of_itself_has_no_size() {
    // An array whose element type is itself, and a struct with a member of
    // it.
    let array = (FIRST_DIE + 1 + 2 + 1 + 8 + 1) as u32;
    let mut dies = vec![STRUCT];
    dies.extend_from_slice(b"A\0");
    dies.push(8);
    dies.push(MEMBER);
    dies.extend_from_slice(b"a\0");
    dies.extend_from_slice(&array.to_le_bytes());
    dies.push(0);
    dies.push(0);
    assert_eq!(FIRST_DIE + dies.len(), array as usize);
    dies.push(ARRAY);
    dies.extend_from_slice(&array.to_le_bytes());
    let file = elf(&[(".debug_info", &unit(&dies)), (".debug_abbrev", &abbrevs())]);
    let layouts = on_small_stack(move || {
        let d = DebugInfo::parse(&file).unwrap();
        d.layouts().unwrap().len()
    });
    assert_eq!(layouts, 1);
}

#[test]
fn a_range_list_many_functions_name_is_bounded() {
    // 2,000 functions, each naming the one list of 20,000 ranges: 40
    // million if each had all of them.
    let (functions, ranges) = (2_000, 20_000u64);
    let mut list = Vec::new();
    for i in 0..ranges {
        list.extend_from_slice(&(0x1000 + i * 16).to_le_bytes());
        list.extend_from_slice(&(0x1000 + i * 16 + 8).to_le_bytes());
    }
    list.extend_from_slice(&[0; 16]);
    let mut dies = Vec::new();
    for _ in 0..functions {
        dies.push(FUNCTION);
        dies.extend_from_slice(b"f\0");
        dies.extend_from_slice(&0u32.to_le_bytes());
    }
    let file = elf(&[
        (".debug_info", &unit(&dies)),
        (".debug_abbrev", &abbrevs()),
        (".debug_ranges", &list),
    ]);
    let budget = 4 * (2 * file.len() as u64) + (1 << 20);
    let start = std::time::Instant::now();
    let symbols = on_small_stack(move || {
        let d = DebugInfo::parse(&file).unwrap();
        d.symbols().unwrap().len() as u64
    });
    assert!(symbols >= functions as u64, "{symbols}");
    assert!(symbols <= budget + functions as u64, "{symbols}");
    // (About 2 s natively. Under emulation, as CI's big-endian job runs
    // it, the job says how much slower it is.)
    let slowdown: u64 = std::env::var("HEXC_TEST_SLOWDOWN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    assert!(
        start.elapsed().as_secs() < 30 * slowdown,
        "{:?}",
        start.elapsed()
    );
}

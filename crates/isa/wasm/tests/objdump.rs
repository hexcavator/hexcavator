//! Checks the instruction decoder against `llvm-objdump -d` on
//! testdata/wasm/ops.wasm, a module with every instruction LLVM knows
//! (see tools/wasm/all_ops.py): each instruction's length, and its
//! immediates as LLVM prints them. Where LLVM has no decoder for an
//! instruction (`<unknown>`: relaxed SIMD and half-precision ops), ours
//! must still decode it to the bytes LLVM shows.

use std::path::Path;

use hexcavator_wasm_isa::code::{self, BlockType, Catch, Imm, Instruction, ValType, natural_align};
use hexcavator_wasm_isa::ops::Kind;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."))
}

/// A float in LLVM's hex form (`0x1.8p0`, `-0x1.2p1`, `0x0p0`).
fn hex_float(mut bits: u64, exp_bits: u32, frac_bits: u32) -> String {
    let sign = if bits >> (exp_bits + frac_bits) == 1 {
        "-"
    } else {
        ""
    };
    bits &= (1u64 << (exp_bits + frac_bits)) - 1;
    let bias = (1i64 << (exp_bits - 1)) - 1;
    let exp = (bits >> frac_bits) as i64;
    let mut frac = bits & ((1u64 << frac_bits) - 1);
    if exp == 0 && frac == 0 {
        return format!("{sign}0x0p0");
    }
    let (lead, e) = if exp == 0 {
        (0, 1 - bias)
    } else {
        (1, exp - bias)
    };
    // As hex digits: the fraction padded to a multiple of 4 bits, trailing
    // zeros dropped.
    let pad = (4 - frac_bits % 4) % 4;
    frac <<= pad;
    let mut digits = format!("{frac:0w$x}", w = ((frac_bits + pad) / 4) as usize);
    while digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        format!("{sign}0x{lead}p{e}")
    } else {
        format!("{sign}0x{lead}.{digits}p{e}")
    }
}

fn val_type(t: &ValType) -> String {
    t.to_string()
}

/// Where LLVM's names are older than the specification's.
const LLVM_NAMES: &[(&str, &str)] = &[
    ("v128.load8x8_s", "i16x8.load8x8_s"),
    ("v128.load8x8_u", "i16x8.load8x8_u"),
    ("v128.load16x4_s", "i32x4.load16x4_s"),
    ("v128.load16x4_u", "i32x4.load16x4_u"),
    ("v128.load32x2_s", "i64x2.load32x2_s"),
    ("v128.load32x2_u", "i64x2.load32x2_u"),
];

/// An instruction as llvm-objdump prints it (name and operands).
fn llvm_text(i: &Instruction) -> String {
    let name = LLVM_NAMES
        .iter()
        .find(|(ours, _)| *ours == i.op.name)
        .map_or(i.op.name, |(_, llvm)| llvm);
    let ops = match (&i.imm, i.op.kind) {
        (Imm::None, _) => String::new(),
        (Imm::Block(BlockType::Empty), _) => String::new(),
        (Imm::Block(BlockType::Value(t)), _) => val_type(t),
        (Imm::Block(BlockType::Index(n)), _) => n.to_string(),
        (Imm::Index(n), _) => n.to_string(),
        (Imm::Two(t, _), Kind::CallIndirect) => t.to_string(),
        (Imm::Two(a, b), _) => format!("{a}, {b}"),
        (Imm::BrTable(l), _) => format!(
            "{{{}}}",
            l.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
        ),
        (Imm::SelectT(t), _) => t.iter().map(val_type).collect::<Vec<_>>().join(", "),
        (Imm::TryTable(_, c), _) => c
            .iter()
            .map(|c| match c {
                Catch::Catch { tag, label } => format!("(catch {tag} {label})"),
                Catch::CatchRef { tag, label } => format!("(catch_ref {tag} {label})"),
                Catch::CatchAll { label } => format!("(catch_all {label})"),
                Catch::CatchAllRef { label } => format!("(catch_all_ref {label})"),
            })
            .collect::<Vec<_>>()
            .join(" "),
        (Imm::MemArg(m) | Imm::MemArgLane(m, _), _) => {
            let mut s = m.offset.to_string();
            if m.align != natural_align(name) {
                s += &format!(":p2align={}", m.align);
            }
            if let Imm::MemArgLane(_, lane) = &i.imm {
                s += &format!(", {lane}");
            }
            s
        }
        (Imm::I32(v), _) => v.to_string(),
        (Imm::I64(v), _) => v.to_string(),
        (Imm::F32(b), _) => hex_float(u64::from(*b), 8, 23),
        (Imm::F64(b), _) => hex_float(*b, 11, 52),
        (Imm::V128(b), _) => b
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        (Imm::Shuffle(l), _) => l.iter().map(u8::to_string).collect::<Vec<_>>().join(", "),
        (Imm::Heap(h), _) => return format!("{name}_{h}"),
        (Imm::Ref(ValType::Ref { heap, .. }), _) => heap.to_string(),
        (Imm::Ref(t), _) => val_type(t),
        (Imm::BrOnCast { .. }, _) => String::from("?"),
        (_, _) => String::from("?"),
    };
    format!("{name} {ops}")
}

fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Compares every instruction llvm-objdump lists for `file` (in
/// testdata/wasm) with ours; returns how many were compared.
fn check(file: &str) -> usize {
    let data = std::fs::read(root().join("testdata/wasm").join(file)).unwrap();
    let listing = format!("{file}.objdump.txt");
    let text = std::fs::read_to_string(root().join("testdata/wasm").join(listing)).unwrap();
    let mut checked = 0;
    let mut unknown = 0;
    let mut failures = Vec::new();
    for line in text.lines() {
        // "     25c: 00           \tunreachable  # comment"
        let Some((addr, rest)) = line.trim_start().split_once(": ") else {
            continue;
        };
        let Ok(offset) = usize::from_str_radix(addr, 16) else {
            continue;
        };
        let (bytes, llvm) = rest.split_once('\t').unwrap_or((rest, ""));
        let len = bytes.split_whitespace().count();
        let llvm = normalize(llvm.split(" #").next().unwrap_or(""));
        let ours = match code::decode(&data[offset..]) {
            Ok(i) => i,
            Err(e) => {
                failures.push(format!("{offset:x}: {e} (llvm: {llvm})"));
                continue;
            }
        };
        if llvm == "<unknown>" {
            // (LLVM shows the opcode's bytes only, not its immediates.)
            if ours.len < len {
                failures.push(format!(
                    "{offset:x}: {} bytes, llvm {len} (unknown)",
                    ours.len
                ));
            }
            unknown += 1;
            continue;
        }
        if ours.len != len {
            failures.push(format!(
                "{offset:x}: {} bytes, llvm {len} ({llvm})",
                ours.len
            ));
            continue;
        }
        let mine = normalize(&llvm_text(&ours));
        // LLVM names the untyped select (0x1B) by the type it selects.
        let typed_select = mine == "select" && llvm.ends_with(".select");
        if mine != llvm && !typed_select {
            failures.push(format!("{offset:x}: ours '{mine}', llvm '{llvm}'"));
        }
        checked += 1;
    }
    assert!(
        failures.is_empty(),
        "{file}: {} of {} differ ({unknown} unknown to LLVM):\n{}",
        failures.len(),
        checked + failures.len(),
        failures.join("\n")
    );
    checked
}

/// Every instruction LLVM knows, once each.
#[test]
fn every_instruction_matches_llvm_objdump() {
    let checked = check("ops.wasm");
    assert!(checked > 1000, "only {checked} instructions checked");
}

/// Real compiler output (tools/wasm/sample.rs).
#[test]
fn compiled_code_matches_llvm_objdump() {
    let checked = check("sample.wasm");
    assert!(checked > 200, "only {checked} instructions checked");
}

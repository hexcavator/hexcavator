//! APX: hermetic checks of `tests/data/apx.txt` (decodings checked against
//! LLVM by tests/llvm.rs), and of what an APX instruction reports.

use hexcavator_x86::{Encoding, Flow, Mode, Operand, decode, format};

fn bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

#[test]
fn golden() {
    let data = include_str!("../data/apx.txt");
    let mut checked = 0;
    let mut failures = Vec::new();
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let parts: Vec<&str> = line.split(" | ").collect();
        let mut b = bytes(parts[0]);
        b.resize(32, 0xCC);
        let actual = match decode(&b, Mode::Bits64, 0) {
            Ok(i) => format!("{} | {}", format::to_string(&i), i.len()),
            Err(_) => "(invalid)".to_string(),
        };
        let expected = parts[1..].join(" | ");
        if actual != expected {
            failures.push(format!("{}: expected {expected}, got {actual}", parts[0]));
        }
        checked += 1;
    }
    assert!(checked > 10_000, "only {checked} cases");
    assert!(
        failures.is_empty(),
        "{} of {checked} differ:\n{}",
        failures.len(),
        failures[..failures.len().min(30)].join("\n")
    );
}

fn one(hex: &str) -> hexcavator_x86::Instruction {
    decode(&bytes(hex), Mode::Bits64, 0x1000).unwrap()
}

#[test]
fn decorations() {
    let nf = one("62 F4 FC 0C 01 D8");
    assert_eq!(format::to_string(&nf), "{nf} add    rax,rbx");
    assert!(nf.no_flags() && !nf.evex_promoted());
    let evex = one("62 F4 FC 08 01 D8");
    assert!(evex.evex_promoted() && !evex.no_flags());
    let ndd = one("62 F4 FC 18 01 CB");
    assert_eq!(format::to_string(&ndd), "add         rax,rbx,rcx");
    assert!(!ndd.evex_promoted());
    let ccmp = one("62 F4 C4 04 39 D8");
    assert_eq!(ccmp.default_flags(), Some(8));
    assert_eq!(format::to_string(&ccmp), "ccmpe       {dfv=of} rax,rbx");
    assert_eq!(one("62 F4 FC 0C 01 D8").encoding(), Encoding::Evex);
}

#[test]
fn rex2() {
    let pushp = one("D5 08 50");
    assert_eq!(pushp.encoding(), Encoding::Rex2);
    assert_eq!(format::to_string(&pushp), "pushp       rax");
    assert_eq!(format::to_string(&one("D5 10 50")), "push        r16");
    let jmpabs = one("D5 00 A1 89 67 45 23 01 00 00 00");
    assert_eq!(jmpabs.flow(), Flow::Jump);
    assert_eq!(jmpabs.branch_target(), Some(0x1_2345_6789));
    // #UD with REX2: Jcc, moffs, and JMPABS with W or a 66.
    for hex in [
        "D5 00 74 00",
        "D5 00 A0 00 00 00 00 00 00 00 00",
        "D5 08 A1 00 00 00 00 00 00 00 00",
        "66 D5 00 A1 00 00 00 00 00 00 00 00",
    ] {
        assert!(decode(&bytes(hex), Mode::Bits64, 0).is_err(), "{hex}");
    }
    // R4/X4/B4 extend general-purpose registers only.
    assert_eq!(
        format::to_string(&one("D5 FF 10 C0 00")),
        "movups      xmm8,xmm8"
    );
}

#[test]
fn reserved_fields() {
    // A reserved opmask bit, z, L'L, X4 in a register form, NF on ADC, and
    // POP2 into one register twice are all #UD.
    for hex in [
        "62 F4 7C 09 00 C0",
        "62 F4 7C 88 00 C0",
        "62 F4 7C 28 00 C0",
        "62 F4 78 08 00 C0",
        "62 F4 7C 0C 10 C0",
        "62 F4 7C 18 8F C0",
    ] {
        assert!(decode(&bytes(hex), Mode::Bits64, 0).is_err(), "{hex}");
    }
    // EGPRs in an EVEX memory operand.
    let i = one("62 F9 78 48 28 04 48");
    assert!(
        matches!(i.operands()[1], Operand::Mem(m) if m.base.is_some_and(|r| r.index() == 16) && m.index.is_some_and(|r| r.index() == 17))
    );
}

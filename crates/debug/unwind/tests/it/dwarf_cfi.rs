//! DWARF CFI unwinding: rows applied to registers and a stack.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_core::Endian;
use hexcavator_dwarf::cfi::{CfaRule, RegisterRule, UnwindRow};

use crate::support::{STACK, Stack};
use hexcavator_unwind::Error;
use hexcavator_unwind::dwarf_cfi::{self, Registers, Target};

const X64: Target = Target {
    endian: Endian::Little,
    address_size: 8,
    stack_pointer: 7,
};
const RSP: u16 = 7;
const RBP: u16 = 6;
const RIP: u16 = 16;
const RETURN: u64 = 0x7777_0000;

fn row<'a>(cfa: CfaRule<'a>, registers: Vec<(u16, RegisterRule<'a>)>) -> UnwindRow<'a> {
    UnwindRow {
        address: 0x1000,
        cfa,
        registers,
        return_address_signed: None,
        args_size: 0,
    }
}

fn registers(pairs: &[(u16, u64)]) -> Registers {
    let mut r = Registers::default();
    for &(n, v) in pairs {
        r.set(n, Some(v));
    }
    r
}

#[test]
fn classic_frame() {
    // CFA = rbp + 16; rbp at CFA-16; rip at CFA-8.
    let rbp = STACK + 0x40;
    let mut s = Stack::new();
    s.set(rbp, 0x5555);
    s.set(rbp + 8, RETURN);
    let r = row(
        CfaRule::RegisterOffset {
            register: RBP,
            offset: 16,
        },
        vec![
            (RBP, RegisterRule::Offset(-16)),
            (RIP, RegisterRule::Offset(-8)),
        ],
    );
    let mut regs = registers(&[(RSP, STACK), (RBP, rbp), (3, 0x3333)]);
    let frame = dwarf_cfi::unwind(&r, RIP, X64, &mut regs, &s).unwrap();
    assert_eq!((frame.cfa, frame.return_address), (rbp + 16, Some(RETURN)));
    assert_eq!(frame.saved, [(RBP, rbp), (RIP, rbp + 8)]);
    assert_eq!(regs.get(RSP), Some(rbp + 16));
    assert_eq!(regs.get(RBP), Some(0x5555));
    assert_eq!(regs.get(RIP), Some(RETURN));
    // (No rule: kept.)
    assert_eq!(regs.get(3), Some(0x3333));
}

#[test]
fn every_rule_kind() {
    let mut s = Stack::new();
    s.set(STACK + 0x108, RETURN);
    s.set(STACK + 0x40, 0x4040);
    // r0 = [rbp + 16 (expression)], r1 = rsp+0 (val expression), r2 = r3,
    // r4 undefined, r5 same, r8 = CFA - 8 (val offset).
    let at_rbp_16 = [0x76, 0x10];
    let rsp_value = [0x77, 0x00];
    let r = row(
        CfaRule::RegisterOffset {
            register: RSP,
            offset: 0x10,
        },
        vec![
            (0, RegisterRule::Expression(&at_rbp_16)),
            (1, RegisterRule::ValExpression(&rsp_value)),
            (2, RegisterRule::Register(3)),
            (4, RegisterRule::Undefined),
            (5, RegisterRule::SameValue),
            (8, RegisterRule::ValOffset(-8)),
            (RIP, RegisterRule::Offset(-8)),
        ],
    );
    let mut regs = registers(&[
        (RSP, STACK + 0x100),
        (RBP, STACK + 0x30),
        (3, 0x33),
        (4, 0x44),
        (5, 0x55),
    ]);
    let frame = dwarf_cfi::unwind(&r, RIP, X64, &mut regs, &s).unwrap();
    assert_eq!(frame.return_address, Some(RETURN));
    assert_eq!(regs.get(0), Some(0x4040));
    assert_eq!(regs.get(1), Some(STACK + 0x100));
    assert_eq!(regs.get(2), Some(0x33));
    assert_eq!(regs.get(4), None);
    assert_eq!(regs.get(5), Some(0x55));
    assert_eq!(regs.get(8), Some(STACK + 0x108));
    assert_eq!(regs.get(RSP), Some(STACK + 0x110));
    assert_eq!(frame.saved, [(0, STACK + 0x40), (RIP, STACK + 0x108)]);
}

#[test]
fn rules_read_the_frames_registers() {
    // rbx = rbp and rbp = rbx (a swap): both from the frame's values.
    let r = row(
        CfaRule::RegisterOffset {
            register: RSP,
            offset: 8,
        },
        vec![
            (3, RegisterRule::Register(RBP)),
            (RBP, RegisterRule::Register(3)),
            (RIP, RegisterRule::Offset(-8)),
        ],
    );
    let mut s = Stack::new();
    s.set(STACK, RETURN);
    let mut regs = registers(&[(RSP, STACK), (RBP, 0x6666), (3, 0x3333)]);
    dwarf_cfi::unwind(&r, RIP, X64, &mut regs, &s).unwrap();
    assert_eq!((regs.get(3), regs.get(RBP)), (Some(0x6666), Some(0x3333)));
}

#[test]
fn cfa_expressions_and_the_stack_pointer_rule() {
    // CFA = [rsp + 8] (a signal frame's saved stack pointer); rsp has its
    // own rule.
    let cfa = [0x77, 0x08, 0x06];
    let r = row(
        CfaRule::Expression(&cfa),
        vec![
            (RSP, RegisterRule::Offset(-16)),
            (RIP, RegisterRule::Offset(-8)),
        ],
    );
    let mut s = Stack::new();
    s.set(STACK + 8, STACK + 0x200);
    s.set(STACK + 0x1F0, STACK + 0x300);
    s.set(STACK + 0x1F8, RETURN);
    let mut regs = registers(&[(RSP, STACK)]);
    let frame = dwarf_cfi::unwind(&r, RIP, X64, &mut regs, &s).unwrap();
    assert_eq!(frame.cfa, STACK + 0x200);
    assert_eq!(regs.get(RSP), Some(STACK + 0x300));
}

#[test]
fn outermost_frames_and_leaves() {
    // An undefined return address: the end of the stack.
    let r = row(
        CfaRule::RegisterOffset {
            register: RSP,
            offset: 8,
        },
        vec![(RIP, RegisterRule::Undefined)],
    );
    let mut regs = registers(&[(RSP, STACK)]);
    let frame = dwarf_cfi::unwind(&r, RIP, X64, &mut regs, &Stack::new()).unwrap();
    assert_eq!(frame.return_address, None);
    // AArch64 leaf: no rule for x30, so the return address is still in it;
    // and a signed one is reported.
    let a64 = Target {
        endian: Endian::Little,
        address_size: 8,
        stack_pointer: 31,
    };
    let mut r = row(
        CfaRule::RegisterOffset {
            register: 31,
            offset: 0,
        },
        vec![],
    );
    r.return_address_signed = Some(true);
    let mut regs = registers(&[(31, STACK), (30, RETURN)]);
    let frame = dwarf_cfi::unwind(&r, 30, a64, &mut regs, &Stack::new()).unwrap();
    assert_eq!(
        (frame.return_address, frame.return_address_signed),
        (Some(RETURN), true)
    );
}

#[test]
fn thirty_two_bit_big_endian() {
    // ARM big-endian: CFA = sp + 8; lr at CFA-4.
    let arm = Target {
        endian: Endian::Big,
        address_size: 4,
        stack_pointer: 13,
    };
    let r = row(
        CfaRule::RegisterOffset {
            register: 13,
            offset: 8,
        },
        vec![(14, RegisterRule::Offset(-4))],
    );
    let mut s = Stack::new();
    // (The test stack's words are little-endian: these are the bytes 12 34
    // 56 78 at STACK.)
    s.set(STACK, 0x7856_3412);
    let mut regs = registers(&[(13, STACK - 4)]);
    let frame = dwarf_cfi::unwind(&r, 14, arm, &mut regs, &s).unwrap();
    assert_eq!(frame.return_address, Some(0x1234_5678));
    assert_eq!(regs.get(13), Some(STACK + 4));
    // Addresses wrap at 32 bits.
    let r = row(
        CfaRule::RegisterOffset {
            register: 13,
            offset: 8,
        },
        vec![],
    );
    let mut regs = registers(&[(13, 0xFFFF_FFFC)]);
    let frame = dwarf_cfi::unwind(&r, 14, arm, &mut regs, &s).unwrap();
    assert_eq!(frame.cfa, 4);
}

#[test]
fn failures() {
    let s = Stack::new();
    // The CFA's register is unknown.
    let r = row(
        CfaRule::RegisterOffset {
            register: RBP,
            offset: 16,
        },
        vec![],
    );
    assert_eq!(
        dwarf_cfi::unwind(&r, RIP, X64, &mut registers(&[]), &s),
        Err(Error::Register { register: RBP })
    );
    // A saved register's slot isn't there.
    let r = row(
        CfaRule::RegisterOffset {
            register: RSP,
            offset: 8,
        },
        vec![(RIP, RegisterRule::Offset(-8))],
    );
    assert_eq!(
        dwarf_cfi::unwind(&r, RIP, X64, &mut registers(&[(RSP, 0x10)]), &s),
        Err(Error::Memory { address: 0x10 })
    );
    // Bad expressions.
    let bad = [0x22];
    let r = row(CfaRule::Expression(&bad), vec![]);
    assert_eq!(
        dwarf_cfi::unwind(&r, RIP, X64, &mut registers(&[]), &s),
        Err(Error::Expression)
    );
    let reads_r40 = [0x92, 40, 0];
    let r = row(CfaRule::Expression(&reads_r40), vec![]);
    assert_eq!(
        dwarf_cfi::unwind(&r, RIP, X64, &mut registers(&[]), &s),
        Err(Error::Register { register: 40 })
    );
    // Registers past the limit are ignored, not stored.
    let mut regs = Registers::default();
    regs.set(Registers::LIMIT, Some(1));
    assert_eq!(regs.get(Registers::LIMIT), None);
    assert_eq!(regs.iter().count(), 0);
}

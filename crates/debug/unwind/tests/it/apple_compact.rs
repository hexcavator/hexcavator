//! Compact unwind encodings applied to synthetic stacks.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use crate::support::{STACK, Stack};
use hexcavator_unwind::Error;
use hexcavator_unwind::apple_compact::{self, Step};
use hexcavator_unwind::dwarf_cfi::{Frame, Registers};

const RETURN: u64 = 0x7777_0000;
// DWARF numbers.
const RBX: u16 = 3;
const RBP: u16 = 6;
const RSP: u16 = 7;
const RIP: u16 = 16;
const R12: u16 = 12;
const R15: u16 = 15;
const FP: u16 = 29;
const LR: u16 = 30;
const SP: u16 = 31;
const PC: u16 = 32;

fn regs(pairs: &[(u16, u64)]) -> Registers {
    let mut r = Registers::default();
    for &(n, v) in pairs {
        r.set(n, Some(v));
    }
    r
}

fn unwound(step: Step) -> Frame {
    match step {
        Step::Unwound(f) => f,
        other => panic!("{other:?}"),
    }
}

#[test]
fn x86_64_rbp_frame() {
    // rbx at rbp-8 (offset 1, slot 0 = rbx); rbp points at the saved rbp.
    let rbp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rbp - 8, 0xB0B0);
    s.set(rbp, 0x5555);
    s.set(rbp + 8, RETURN);
    let mut r = regs(&[(RBP, rbp), (RSP, STACK)]);
    let frame = unwound(apple_compact::unwind_x86_64(0x0101_0001, 0, &mut r, &s).unwrap());
    assert_eq!((frame.cfa, frame.return_address), (rbp + 16, Some(RETURN)));
    assert_eq!(
        (r.get(RBX), r.get(RBP), r.get(RSP), r.get(RIP)),
        (Some(0xB0B0), Some(0x5555), Some(rbp + 16), Some(RETURN))
    );
    assert_eq!(frame.saved, [(RBX, rbp - 8), (RBP, rbp), (RIP, rbp + 8)]);
    // Five slots: r12, r13, r14, r15, rbx from rbp-40 up.
    let mut s = Stack::new();
    for (i, v) in [0x12u64, 0x13, 0x14, 0x15, 0xB0B0].iter().enumerate() {
        s.set(rbp - 40 + 8 * i as u64, *v);
    }
    s.set(rbp + 8, RETURN);
    let slots = 2 | 3 << 3 | 4 << 6 | 5 << 9 | 1 << 12;
    let mut r = regs(&[(RBP, rbp)]);
    apple_compact::unwind_x86_64(0x0100_0000 | 5 << 16 | slots, 0, &mut r, &s).unwrap();
    assert_eq!(
        (r.get(R12), r.get(R15), r.get(RBX)),
        (Some(0x12), Some(0x15), Some(0xB0B0))
    );
}

#[test]
fn x86_64_frameless() {
    // Stack size 0x20, two registers: rbx then r12 (permutation 0).
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp + 0x08, 0xB0B0);
    s.set(rsp + 0x10, 0x1212);
    s.set(rsp + 0x18, RETURN);
    let mut r = regs(&[(RSP, rsp)]);
    let frame = unwound(
        apple_compact::unwind_x86_64(0x0200_0000 | 4 << 16 | 2 << 10, 0, &mut r, &s).unwrap(),
    );
    assert_eq!(
        (r.get(RBX), r.get(R12), r.get(RIP), r.get(RSP)),
        (Some(0xB0B0), Some(0x1212), Some(RETURN), Some(rsp + 0x20))
    );
    assert_eq!(frame.cfa, rsp + 0x20);
    // r15 then rbx: the first is the 5th of (rbx, r12, r13, r14, r15, rbp),
    // the second the 1st of those left: permutation 4 * 5 + 0.
    let mut r = regs(&[(RSP, rsp)]);
    apple_compact::unwind_x86_64(0x0200_0000 | 4 << 16 | 2 << 10 | 20, 0, &mut r, &s).unwrap();
    assert_eq!((r.get(R15), r.get(RBX)), (Some(0xB0B0), Some(0x1212)));
    // All six (rbp, r15, r14, r13, r12, rbx: the last of each list left).
    let mut s = Stack::new();
    for i in 0..6u64 {
        s.set(rsp + 8 * i, 0x100 + i);
    }
    s.set(rsp + 0x30, RETURN);
    let perm = 5 * 120 + 4 * 24 + 3 * 6 + 2 * 2 + 1;
    let mut r = regs(&[(RSP, rsp)]);
    apple_compact::unwind_x86_64(0x0200_0000 | 7 << 16 | 6 << 10 | perm, 0, &mut r, &s).unwrap();
    assert_eq!(
        (r.get(RBP), r.get(R15), r.get(RBX), r.get(RIP)),
        (Some(0x100), Some(0x101), Some(0x105), Some(RETURN))
    );
    // No registers, no stack: just the return address.
    let mut s = Stack::new();
    s.set(rsp, RETURN);
    let mut r = regs(&[(RSP, rsp)]);
    apple_compact::unwind_x86_64(0x0201_0000, 0, &mut r, &s).unwrap();
    assert_eq!((r.get(RIP), r.get(RSP)), (Some(RETURN), Some(rsp + 8)));
}

#[test]
fn x86_64_frameless_indirect() {
    // The stack size is the `sub`'s immediate (at function + 0x10), plus 8
    // * adjust (1).
    let function = STACK;
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(function + 0x10, 0x0000_0000_0000_00F0);
    s.set(rsp + 0xF0, RETURN);
    let mut r = regs(&[(RSP, rsp)]);
    apple_compact::unwind_x86_64(
        0x0300_0000 | 0x10 << 16 | 1 << 13 | 1 << 10,
        function,
        &mut r,
        &s,
    )
    .unwrap();
    // size 0xF8: rbx at rsp + 0xF8 - 8 - 8, return at rsp + 0xF0.
    assert_eq!((r.get(RIP), r.get(RSP)), (Some(RETURN), Some(rsp + 0xF8)));
}

#[test]
fn other_steps_and_errors() {
    let s = Stack::new();
    let mut r = regs(&[(RSP, STACK), (RBP, STACK)]);
    assert_eq!(
        apple_compact::unwind_x86_64(0, 0, &mut r, &s),
        Ok(Step::None)
    );
    assert_eq!(
        apple_compact::unwind_x86_64(0x0400_1234, 0, &mut r, &s),
        Ok(Step::Dwarf {
            eh_frame_offset: 0x1234
        })
    );
    for bad in [
        0x0100_0006,
        0x0100_0007,
        0x0200_1C00,
        0x0500_0000,
        0x0000_0001,
    ] {
        assert_eq!(
            apple_compact::unwind_x86_64(bad, 0, &mut r, &s),
            Err(Error::Encoding { encoding: bad }),
            "{bad:#x}"
        );
    }
    // Missing registers and memory.
    let mut empty = Registers::default();
    assert_eq!(
        apple_compact::unwind_x86_64(0x0100_0000, 0, &mut empty, &s),
        Err(Error::Register { register: RBP })
    );
    assert_eq!(
        apple_compact::unwind_x86_64(0x0200_0000, 0, &mut empty, &s),
        Err(Error::Register { register: RSP })
    );
    let mut far = regs(&[(RBP, 0x10)]);
    assert_eq!(
        apple_compact::unwind_x86_64(0x0100_0000, 0, &mut far, &s),
        Err(Error::Memory { address: 0x10 })
    );
}

#[test]
fn arm64_frames() {
    // x19/x20 and d8/d9 below fp; fp and lr at fp.
    let fp = STACK + 0x100;
    let mut s = Stack::new();
    for (at, v) in [(8u64, 0x1919u64), (16, 0x2020), (24, 0x88), (32, 0x99)] {
        s.set(fp - at, v);
    }
    s.set(fp, 0xF0F0);
    s.set(fp + 8, RETURN);
    let mut r = regs(&[(FP, fp), (SP, STACK), (LR, 0x4141)]);
    let frame = unwound(apple_compact::unwind_arm64(0x0400_0101, &mut r, &s).unwrap());
    assert_eq!(
        (r.get(19), r.get(20), r.get(64 + 8), r.get(64 + 9)),
        (Some(0x1919), Some(0x2020), Some(0x88), Some(0x99))
    );
    assert_eq!(
        (r.get(FP), r.get(LR), r.get(SP), r.get(PC)),
        (Some(0xF0F0), Some(RETURN), Some(fp + 16), Some(RETURN))
    );
    assert_eq!(
        (frame.cfa, frame.return_address, frame.return_address_signed),
        (fp + 16, Some(RETURN), false)
    );
    // arm64e: lr signed.
    let mut r = regs(&[(FP, fp)]);
    let frame = unwound(apple_compact::unwind_arm64(0x0500_0000, &mut r, &s).unwrap());
    assert!(frame.return_address_signed);
}

#[test]
fn arm64_frameless_and_others() {
    // A leaf with 0x30 bytes of stack: the return address is in lr.
    let mut r = regs(&[(SP, STACK), (LR, RETURN)]);
    let s = Stack::new();
    let frame = unwound(apple_compact::unwind_arm64(0x0200_3000, &mut r, &s).unwrap());
    assert_eq!(
        (r.get(SP), r.get(PC), frame.return_address),
        (Some(STACK + 0x30), Some(RETURN), Some(RETURN))
    );
    assert_eq!(apple_compact::unwind_arm64(0, &mut r, &s), Ok(Step::None));
    assert_eq!(
        apple_compact::unwind_arm64(0x0300_0040, &mut r, &s),
        Ok(Step::Dwarf {
            eh_frame_offset: 0x40
        })
    );
    for bad in [0x0100_0000, 0x0600_0000, 0x0000_0010] {
        assert_eq!(
            apple_compact::unwind_arm64(bad, &mut r, &s),
            Err(Error::Encoding { encoding: bad }),
            "{bad:#x}"
        );
    }
    let mut empty = Registers::default();
    assert_eq!(
        apple_compact::unwind_arm64(0x0400_0000, &mut empty, &s),
        Err(Error::Register { register: FP })
    );
    assert_eq!(
        apple_compact::unwind_arm64(0x0200_0000, &mut empty, &s),
        Err(Error::Register { register: SP })
    );
    let mut no_lr = regs(&[(SP, STACK)]);
    assert_eq!(
        apple_compact::unwind_arm64(0x0200_0000, &mut no_lr, &s),
        Err(Error::Register { register: LR })
    );
}

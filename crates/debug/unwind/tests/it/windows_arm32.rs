//! Hermetic ARM (Thumb-2) tests: the worked examples in Microsoft's "ARM
//! exception handling", and synthetic `.pdata`, `.xdata`, and stacks.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_unwind::windows_arm32::{self, Context, Op, Position, RuntimeFunction, reg};
use hexcavator_unwind::{Error, Memory};

const BASE: u32 = 0x0040_0000;
const STACK: u32 = 0x0010_0000;
/// The return address the context starts with (in LR), Thumb.
const LR: u32 = 0x4141_0001;
/// The return address a frame saved, Thumb.
const RETURN: u32 = 0x7777_0001;

/// A stack of 256 words from [`STACK`]; unset words hold a marker.
struct Stack {
    words: Vec<u32>,
}

impl Stack {
    fn new() -> Self {
        Stack {
            words: (0..256).map(|i| 0xAA00_0000 + i * 4).collect(),
        }
    }
    fn set(&mut self, address: u32, value: u32) {
        self.words[((address - STACK) / 4) as usize] = value;
    }
    fn marker(address: u32) -> u32 {
        0xAA00_0000 + (address - STACK)
    }
}

impl Memory for Stack {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        for (i, b) in buf.iter_mut().enumerate() {
            let Some(off) = (address + i as u64).checked_sub(u64::from(STACK)) else {
                return false;
            };
            let Some(w) = self.words.get((off / 4) as usize) else {
                return false;
            };
            *b = w.to_le_bytes()[(off % 4) as usize];
        }
        true
    }
}

struct Builder {
    bytes: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Builder {
            bytes: vec![0; 0x4000],
        }
    }
    fn put(&mut self, rva: u32, b: &[u8]) {
        self.bytes[rva as usize..rva as usize + b.len()].copy_from_slice(b);
    }
    /// An `.xdata` record: header, `scopes`, codes (padded with `end`s),
    /// handler.
    #[allow(clippy::too_many_arguments)]
    fn xdata(
        &mut self,
        rva: u32,
        length: u32,
        e: bool,
        f: bool,
        epilogs: u32,
        scopes: &[u32],
        codes: &[u8],
        handler: Option<u32>,
    ) {
        let words = codes.len().div_ceil(4) as u32;
        let header = (length / 2)
            | (u32::from(handler.is_some()) << 20)
            | (u32::from(e) << 21)
            | (u32::from(f) << 22)
            | (epilogs << 23)
            | (words << 28);
        let mut b = header.to_le_bytes().to_vec();
        for s in scopes {
            b.extend(s.to_le_bytes());
        }
        b.extend(codes);
        while !b.len().is_multiple_of(4) {
            b.push(0xFF);
        }
        if let Some(h) = handler {
            b.extend(h.to_le_bytes());
        }
        self.put(rva, &b);
    }
}

/// An epilog scope word.
fn scope(start: u32, condition: u32, index: u32) -> u32 {
    (start / 2) | (condition << 20) | (index << 24)
}

/// Packed unwind data.
#[allow(clippy::too_many_arguments)]
fn packed(
    length: u32,
    ret: u32,
    h: bool,
    reg_: u32,
    r: bool,
    l: bool,
    c: bool,
    stack_adjust: u32,
) -> u32 {
    1 | (length / 2) << 2
        | ret << 13
        | u32::from(h) << 15
        | reg_ << 16
        | u32::from(r) << 19
        | u32::from(l) << 20
        | u32::from(c) << 21
        | stack_adjust << 22
}

fn context(pc_rva: u32, sp: u32) -> Context {
    let mut c = Context::default();
    c.r[reg::PC] = BASE + pc_rva;
    c.r[reg::SP] = sp;
    c.r[reg::LR] = LR;
    for n in 4..12 {
        c.r[n] = 0x1000 + n as u32;
    }
    c
}

fn f(begin: u32, unwind: u32) -> RuntimeFunction {
    RuntimeFunction {
        begin: begin | 1,
        unwind,
    }
}

const POP_R: fn(u16, bool) -> Op = |regs, wide| Op::Pop { regs, wide };
const LRB: u16 = 1 << 14;

fn alloc(bytes: u32, wide: bool) -> Op {
    Op::Alloc { bytes, wide }
}

#[test]
fn example_1_leaf_no_locals() {
    // push {r4-r5} ... pop {r4-r5}; bx lr.
    let w = packed(0x62, 1, false, 1, false, false, false, 0);
    let d = windows_arm32::describe(&[][..], f(0x535F8, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x30, false)]);
    assert_eq!(d.epilogs.len(), 1);
    assert_eq!(d.epilogs[0].start, 0x5E);
    assert_eq!(d.epilogs[0].ops, [POP_R(0x30, false), Op::End(Some(false))]);
}

#[test]
fn example_2_nested_with_locals() {
    // push {r4-r7, lr}; sub sp, sp, #0xC ... add sp, sp, #0xC; pop {r4-r7, pc}.
    let w = packed(0x6A, 0, false, 3, false, true, false, 3);
    let d = windows_arm32::describe(&[][..], f(0x533AC, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(0xF0 | LRB, false), alloc(12, false)]);
    assert_eq!(
        d.epilogs[0].ops,
        [alloc(12, false), POP_R(0xF0 | LRB, false), Op::End(None)]
    );
    assert_eq!(d.epilogs[0].start, 0x66);

    // From the body: sp += 12, pop r4-r7 and LR.
    let mut stack = Stack::new();
    let sp = STACK + 0x40;
    for (i, v) in [4u32, 5, 6, 7, RETURN].iter().enumerate() {
        stack.set(sp + 12 + 4 * i as u32, 0x5000 + v);
    }
    stack.set(sp + 12 + 16, RETURN);
    let mut c = context(0x533AC + 0x10, sp);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x533AC, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Body);
    assert_eq!(c.r[4], 0x5004);
    assert_eq!(c.r[7], 0x5007);
    assert_eq!(c.r[reg::LR], RETURN);
    assert_eq!(c.r[reg::PC], RETURN & !1);
    assert_ne!(c.cpsr & windows_arm32::CPSR_T, 0);
    assert_eq!(c.r[reg::SP], sp + 32);
    assert_eq!(fr.establisher_frame, sp + 32);
    assert_eq!(fr.saved_r[reg::LR], Some(sp + 28));

    // After the prolog's push only: just the pop.
    let mut c = context(0x533AC + 2, sp);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x533AC, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Prolog(1));
    assert_eq!(c.r[reg::SP], sp + 20);
    assert_eq!(c.r[4], Stack::marker(sp));

    // At the function start: nothing to undo.
    let mut c = context(0x533AC, sp);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x533AC, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Prolog(0));
    assert_eq!((c.r[reg::SP], c.r[reg::PC]), (sp, LR & !1));

    // At the epilog's `pop {r4-r7, pc}`: the `add` has run.
    let mut c = context(0x533AC + 0x68, sp + 12);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x533AC, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Epilog(1));
    assert_eq!(c.r[reg::SP], sp + 32);
    assert_eq!(c.r[reg::LR], RETURN);
}

#[test]
fn example_3_variadic() {
    // push {r0-r3}; push {r4-r6, lr} ... pop {r4-r6}; ldr pc, [sp], #0x14.
    let w = packed(0x54, 0, true, 2, false, true, false, 0);
    let d = windows_arm32::describe(&[][..], f(0x53988, w)).unwrap();
    assert_eq!(d.prolog, [alloc(16, false), POP_R(0x70 | LRB, false)]);
    assert_eq!(
        d.epilogs[0].ops,
        [POP_R(0x70, false), Op::LdrLr(0x14), Op::End(None)]
    );

    let mut stack = Stack::new();
    let sp = STACK + 0x40;
    stack.set(sp + 12, RETURN);
    // From the body: pop r4-r6 and LR, then the 16 homing bytes.
    let mut c = context(0x53988 + 0x10, sp);
    windows_arm32::unwind(&[][..], BASE, f(0x53988, w), &mut c, &stack).unwrap();
    assert_eq!(c.r[reg::SP], sp + 32);
    assert_eq!(c.r[reg::LR], RETURN);
    // At the `ldr pc, [sp], #0x14`.
    let mut c = context(0x53988 + 0x54 - 4, sp + 12);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x53988, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Epilog(1));
    assert_eq!((c.r[reg::SP], c.r[reg::LR]), (sp + 32, RETURN));
}

#[test]
fn example_4_multiple_epilogs() {
    let mut b = Builder::new();
    let scopes: Vec<u32> = [0x22, 0x14A, 0x2E0, 0x312]
        .iter()
        .map(|&s| scope(s, 0xE, 0))
        .collect();
    b.xdata(
        0x100,
        0x346,
        false,
        false,
        4,
        &scopes,
        &[0x06, 0xDE, 0xFF],
        None,
    );
    let d = windows_arm32::describe(&b.bytes[..], f(0x592F4, 0x100)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x07F0 | LRB, true), alloc(0x18, false)]);
    assert_eq!(d.epilogs.len(), 4);
    assert_eq!(d.epilogs[3].start, 0x312);
    assert_eq!(d.epilogs[3].len(), 6);
    assert_eq!(d.length, 0x346);

    let mut stack = Stack::new();
    let sp = STACK + 0x40;
    stack.set(sp + 0x18 + 28, RETURN);
    // Inside the second epilog, at its `ldm`.
    let mut c = context(0x592F4 + 0x14C, sp + 0x18);
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x592F4, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Epilog(1));
    assert_eq!((c.r[reg::SP], c.r[reg::LR]), (sp + 0x18 + 32, RETURN));
    // Just after it: the body.
    let mut c = context(0x592F4 + 0x150, sp);
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x592F4, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Body);
    assert_eq!(c.r[reg::SP], sp + 0x18 + 32);
}

#[test]
fn example_5_dynamic_stack() {
    // push {r0-r3}; push.w {r4-r8, lr}; mov r6, sp; ...; mov sp, r4;
    // subw sp, ... / mov sp, r6; ldm sp!, {r4-r8, lr}; add sp, #16; bx lr.
    let mut b = Builder::new();
    b.xdata(
        0x100,
        0x40C,
        false,
        false,
        1,
        &[scope(0x18C, 0xE, 0)],
        &[0xC6, 0xDC, 0x04, 0xFD],
        None,
    );
    let d = windows_arm32::describe(&b.bytes[..], f(0x85A20, 0x100)).unwrap();
    assert_eq!(
        d.prolog,
        [alloc(16, false), POP_R(0x01F0 | LRB, true), Op::MovSp(6)]
    );
    assert_eq!(d.epilogs[0].len(), 2 + 4 + 2 + 2);
    assert_eq!(d.prolog_len(), 8);

    let mut stack = Stack::new();
    let frame = STACK + 0x80;
    stack.set(frame + 20, RETURN);
    // From the body, SP far below: recovered from r6.
    let mut c = context(0x85A20 + 0x100, STACK);
    c.r[6] = frame;
    windows_arm32::unwind(&b.bytes[..], BASE, f(0x85A20, 0x100), &mut c, &stack).unwrap();
    assert_eq!(c.r[reg::SP], frame + 24 + 16);
    assert_eq!(c.r[reg::LR], RETURN);
    // At the final `bx lr`: everything has run.
    let mut c = context(0x85A20 + 0x18C + 8, STACK + 0x100);
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x85A20, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Epilog(3));
    assert_eq!((c.r[reg::SP], c.r[reg::PC]), (STACK + 0x100, LR & !1));
}

#[test]
fn example_6_handler_and_single_epilog() {
    let mut b = Builder::new();
    b.xdata(
        0x100,
        0x4E,
        true,
        false,
        0,
        &[],
        &[0xC7, 0x05, 0xED, 0x90, 0xFF],
        Some(0x0019_A7ED),
    );
    let d = windows_arm32::describe(&b.bytes[..], f(0x88C24, 0x100)).unwrap();
    let h = d.handler.unwrap();
    assert_eq!((h.routine, h.data), (0x0019_A7ED, 0x110));
    assert_eq!(
        d.prolog,
        [POP_R(0x90 | LRB, false), alloc(0x14, false), Op::MovSp(7)]
    );
    assert_eq!(d.epilogs[0].start, 0x48);

    let mut stack = Stack::new();
    stack.set(STACK + 0x14 + 8, RETURN);
    let mut c = context(0x88C24 + 0x20, STACK - 0x1000);
    c.r[7] = STACK;
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x88C24, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.handler, Some(h));
    assert_eq!(c.r[reg::SP], STACK + 0x14 + 12);
    // In the epilog the handler isn't reported.
    let mut c = context(0x88C24 + 0x4A, STACK);
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x88C24, 0x100), &mut c, &stack).unwrap();
    assert_eq!((fr.position, fr.handler), (Position::Epilog(1), None));
}

#[test]
fn packed_frame_chain_and_vfp() {
    // C=1, L=1, R=1, Reg=1: push {r11, lr}; mov r11, sp; vpush {d8-d9};
    // sub sp, #8.
    let w = packed(0x40, 1, false, 1, true, true, true, 2);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(
        d.prolog,
        [
            POP_R(1 << 11 | LRB, true),
            Op::Nop { wide: false },
            Op::Vpop { first: 8, last: 9 },
            alloc(8, false),
        ]
    );
    assert_eq!(
        d.epilogs[0].ops,
        [
            alloc(8, false),
            Op::Vpop { first: 8, last: 9 },
            POP_R(1 << 11 | LRB, true),
            Op::End(Some(false)),
        ]
    );

    let mut stack = Stack::new();
    let sp = STACK + 0x40;
    stack.set(sp + 8, 0x1111_2222);
    stack.set(sp + 12, 0x3333_4444);
    stack.set(sp + 24 + 4, RETURN);
    let mut c = context(0x110, sp);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x100, w), &mut c, &stack).unwrap();
    assert_eq!(c.d[8], 0x3333_4444_1111_2222);
    assert_eq!(fr.saved_d[9], Some(sp + 16));
    assert_eq!(c.r[11], Stack::marker(sp + 24));
    assert_eq!((c.r[reg::SP], c.r[reg::LR]), (sp + 32, RETURN));
}

#[test]
fn packed_frame_chain_with_registers_is_an_add() {
    // C=1, R=0: push {r4-r5, r11, lr} (32-bit); add r11, sp, #8.
    let w = packed(0x40, 0, false, 1, false, true, true, 0);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(
        d.prolog,
        [POP_R(0x30 | 1 << 11 | LRB, true), Op::Nop { wide: true }]
    );
    // Returning with `pop {..., pc}`: still 32-bit, r11 being high.
    assert_eq!(
        d.epilogs[0].ops,
        [POP_R(0x30 | 1 << 11 | LRB, true), Op::End(None)]
    );
}

#[test]
fn packed_folding() {
    // Stack Adjust 0x3F5: 2 words folded into the prolog's push (r2-r3),
    // not the epilog's.
    let w = packed(0x40, 0, false, 0, false, true, false, 0x3F5);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x1C | LRB, false)]);
    assert_eq!(
        d.epilogs[0].ops,
        [alloc(8, false), POP_R(0x10 | LRB, false), Op::End(None)]
    );
    // Both folded (0x3FC | 0): r3 pushed and popped.
    let w = packed(0x40, 0, false, 0, false, true, false, 0x3FC);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x18 | LRB, false)]);
    assert_eq!(d.epilogs[0].ops, [POP_R(0x18 | LRB, false), Op::End(None)]);
    // R=1 and folded: r(S)-r3 and LR only.
    let w = packed(0x40, 0, false, 7, true, true, false, 0x3F4);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x08 | LRB, false)]);
}

#[test]
fn packed_large_allocation_is_wide() {
    let w = packed(0x40, 3, false, 7, true, true, false, 0x80);
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert_eq!(d.prolog, [POP_R(LRB, false), alloc(0x200, true)]);
    // Ret 3: no epilog.
    assert!(d.epilogs.is_empty());
}

#[test]
fn packed_fragment_has_no_prolog() {
    let w = packed(0x40, 1, false, 1, false, false, false, 0) & !3 | 2;
    let d = windows_arm32::describe(&[][..], f(0x100, w)).unwrap();
    assert!(d.fragment);
    assert_eq!(d.prolog_len(), 0);
    let mut stack = Stack::new();
    stack.set(STACK, 0x44);
    // At offset 0: a full unwind (no partial prolog).
    let mut c = context(0x100, STACK);
    let fr = windows_arm32::unwind(&[][..], BASE, f(0x100, w), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Body);
    assert_eq!((c.r[4], c.r[reg::SP]), (0x44, STACK + 8));
}

#[test]
fn packed_invalid_combinations() {
    // C without L; Ret 0 without L; flag 3.
    for w in [
        packed(0x40, 1, false, 1, false, false, true, 0),
        packed(0x40, 0, false, 1, false, false, false, 0),
        packed(0x40, 1, false, 1, false, false, false, 0) | 3,
    ] {
        assert_eq!(
            windows_arm32::describe(&[][..], f(0x100, w)),
            Err(Error::UnwindData { rva: 0x100 })
        );
    }
}

#[test]
fn conditional_epilog() {
    let mut b = Builder::new();
    // An epilog under EQ at 0x20: add sp, #8; pop {r4, pc}.
    b.xdata(
        0x100,
        0x40,
        false,
        false,
        1,
        &[scope(0x20, 0x0, 0)],
        &[0x02, 0xD4, 0xFF],
        None,
    );
    let mut stack = Stack::new();
    stack.set(STACK + 4, RETURN);
    stack.set(STACK + 12, RETURN + 0x100);
    // Z set: in the epilog, after its `add`.
    let mut c = context(0x1022, STACK);
    c.cpsr = 1 << 30;
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x1000, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Epilog(1));
    assert_eq!(c.r[reg::LR], RETURN);
    // Z clear: the epilog's instructions don't run; the body.
    let mut c = context(0x1022, STACK);
    let fr = windows_arm32::unwind(&b.bytes[..], BASE, f(0x1000, 0x100), &mut c, &stack).unwrap();
    assert_eq!(fr.position, Position::Body);
    assert_eq!(c.r[reg::LR], RETURN + 0x100);
}

#[test]
fn every_code() {
    let mut b = Builder::new();
    let codes = [
        0x7F, // add sp, #508
        0xA0, 0x0F, // pop.w {r0-r3, lr}
        0xC3, // mov sp, r3
        0xD7, 0xDF, // pop {r4-r7, lr}; pop.w {r4-r11, lr}
        0xE7, // vpop {d8-d15}
        0xE9, 0x01, // addw sp, #0x404
        0xEC, 0x81, // pop {r0, r7}
        0xEF, 0x03, // ldr lr, [sp], #12
        0xF5, 0x13, 0xF6, 0x0F, // vpop {d1-d3}; vpop {d16-d31}
        0xF7, 0x01, 0x00, // add sp, #0x400
        0xF8, 0x01, 0x00, 0x00, // add sp, #0x40000
        0xF9, 0x00, 0x01, // add.w sp, #4
        0xFA, 0x00, 0x00, 0x02, // add.w sp, #8
        0xFB, 0xFC, 0xFE,
    ];
    b.xdata(0x100, 0x400, false, false, 0, &[], &codes, None);
    let d = windows_arm32::describe(&b.bytes[..], f(0x1000, 0x100)).unwrap();
    let mut p = d.prolog.clone();
    p.reverse();
    assert_eq!(
        p,
        [
            alloc(508, false),
            POP_R(0x0F | LRB, true),
            Op::MovSp(3),
            POP_R(0xF0 | LRB, false),
            POP_R(0x0FF0 | LRB, true),
            Op::Vpop { first: 8, last: 15 },
            alloc(0x404, true),
            POP_R(0x81, false),
            Op::LdrLr(12),
            Op::Vpop { first: 1, last: 3 },
            Op::Vpop {
                first: 16,
                last: 31
            },
            alloc(0x400, false),
            alloc(0x40000, false),
            alloc(4, true),
            alloc(8, true),
            Op::Nop { wide: false },
            Op::Nop { wide: true },
        ]
    );
}

#[test]
fn malformed_xdata() {
    let mut b = Builder::new();
    // Unassigned codes, a backwards vpop range, Microsoft-specific codes,
    // codes without an end, an epilog index inside a code.
    let cases: [(&[u8], &[u32], Error); 6] = [
        (&[0xF0, 0xFF], &[], Error::UnwindData { rva: 0x100 }),
        (&[0xEF, 0x10, 0xFF], &[], Error::UnwindData { rva: 0x100 }),
        (&[0xF5, 0x31, 0xFF], &[], Error::UnwindData { rva: 0x100 }),
        (&[0xEE, 0x01, 0xFF], &[], Error::Unsupported { rva: 0x100 }),
        (
            &[0x01, 0x02, 0x03, 0x04],
            &[],
            Error::UnwindData { rva: 0x100 },
        ),
        (
            &[0xE8, 0x01, 0xFF],
            &[scope(0x10, 0xE, 1)],
            Error::UnwindData { rva: 0x100 },
        ),
    ];
    for (codes, scopes, err) in cases {
        b.bytes[0x100..0x140].fill(0);
        b.xdata(
            0x100,
            0x40,
            false,
            false,
            scopes.len() as u32,
            scopes,
            codes,
            None,
        );
        // (The padding is `end`s; overwrite it for the no-end case.)
        if codes.len() == 4 {
            b.put(0x108, &[0, 0, 0, 0]);
        }
        assert_eq!(
            windows_arm32::describe(&b.bytes[..], f(0x1000, 0x100)),
            Err(err)
        );
    }
    // Version 1; truncated.
    b.put(
        0x100,
        &((0x40u32 / 2) | (1 << 18) | (1 << 28)).to_le_bytes(),
    );
    assert_eq!(
        windows_arm32::describe(&b.bytes[..], f(0x1000, 0x100)),
        Err(Error::Unsupported { rva: 0x100 })
    );
    assert_eq!(
        windows_arm32::describe(&b.bytes[..], f(0x1000, 0x3FFC)),
        Err(Error::UnwindData { rva: 0x3FFC })
    );
}

#[test]
fn extended_header() {
    let mut b = Builder::new();
    // Epilog count and code words 0: the second word has them.
    let mut x = (0x40u32 / 2).to_le_bytes().to_vec();
    x.extend((1u32 | 1 << 16).to_le_bytes());
    x.extend(scope(0x3C, 0xE, 0).to_le_bytes());
    x.extend([0xD4, 0xFD, 0xFF, 0xFF]);
    b.put(0x100, &x);
    let d = windows_arm32::describe(&b.bytes[..], f(0x1000, 0x100)).unwrap();
    assert_eq!(d.prolog, [POP_R(0x10 | LRB, false)]);
    assert_eq!(d.epilogs[0].start, 0x3C);
}

#[test]
fn lookup_and_leaf() {
    let mut b = Builder::new();
    let table: Vec<u8> = [
        (0x1001u32, packed(0x20, 1, false, 0, false, false, false, 0)),
        (0x1041, packed(0x10, 1, false, 0, false, false, false, 0)),
    ]
    .iter()
    .flat_map(|&(a, w)| [a.to_le_bytes(), w.to_le_bytes()].concat())
    .collect();
    b.put(0x200, &table);
    let at = |rva| windows_arm32::lookup(&b.bytes[..], 0x200, 16, rva).map(|f| f.begin);
    assert_eq!(at(0x1000), Some(0x1001));
    assert_eq!(at(0x101E), Some(0x1001));
    assert_eq!(at(0x1020), None);
    assert_eq!(at(0x1048), Some(0x1041));
    assert_eq!(at(0x1050), None);
    assert_eq!(at(0xFFF), None);

    let mut c = context(0x10, STACK);
    let fr = windows_arm32::unwind_leaf(&mut c);
    assert_eq!((c.r[reg::PC], fr.establisher_frame), (LR & !1, STACK));
}

#[test]
fn missing_stack() {
    let w = packed(0x40, 1, false, 1, false, false, false, 0);
    let mut c = context(0x110, 0x10);
    assert_eq!(
        windows_arm32::unwind(&[][..], BASE, f(0x100, w), &mut c, &Stack::new()),
        Err(Error::Memory { address: 0x10 })
    );
}

#[test]
fn hostile_unwind_data_never_panics() {
    // Random packed words, and random `.xdata` (and stack) bytes.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut b = Builder::new();
    let stack = Stack::new();
    for round in 0..100_000 {
        let w = next() as u32;
        let unwind = if round % 2 == 0 {
            w | 1
        } else {
            for i in 0..16 {
                let v = next();
                b.put(0x100 + 8 * i, &v.to_le_bytes());
            }
            // (Mostly small counts, so the codes are in the image.)
            let header = w & 0x00FF_FFFF | (next() as u32 % 4) << 23 | (next() as u32 % 8) << 28;
            b.put(0x100, &header.to_le_bytes());
            0x100
        };
        let func = f(0x1000, unwind);
        let _ = windows_arm32::describe(&b.bytes[..], func);
        for off in [0u32, 2, 4, 6, 0x10, 0x3E] {
            let mut c = context(0x1000 + off, STACK + 0x200);
            c.cpsr = next() as u32;
            let _ = windows_arm32::unwind(&b.bytes[..], BASE, func, &mut c, &stack);
        }
    }
}

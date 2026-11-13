//! Hermetic ARM64 tests: synthetic `.pdata`, `.xdata`, and stacks, built
//! from the patterns Microsoft's "ARM64 exception handling" documents.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use crate::support::{STACK, Stack};
use hexcavator_unwind::Error;
use hexcavator_unwind::windows_arm64::{self, Context, Position, RuntimeFunction, reg};

const BASE: u64 = 0x1_4000_0000;
const RETURN: u64 = 0x7777_0000;
/// The return address the context starts with (in LR).
const LR: u64 = 0x4141_0000;

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
    /// An `.xdata` record at `rva`: one header word, then `scopes`, then
    /// the codes (padded with `nop`s to whole words), then the handler.
    #[allow(clippy::too_many_arguments)]
    fn xdata(
        &mut self,
        rva: u32,
        length: u32,
        e: bool,
        epilogs: u32,
        scopes: &[u32],
        codes: &[u8],
        handler: Option<u32>,
    ) {
        let words = codes.len().div_ceil(4) as u32;
        let header = (length / 4)
            | (u32::from(handler.is_some()) << 20)
            | (u32::from(e) << 21)
            | (epilogs << 22)
            | (words << 27);
        let mut b = header.to_le_bytes().to_vec();
        for s in scopes {
            b.extend(s.to_le_bytes());
        }
        b.extend(codes);
        while !b.len().is_multiple_of(4) {
            b.push(0xE3);
        }
        if let Some(h) = handler {
            b.extend(h.to_le_bytes());
        }
        self.put(rva, &b);
    }
    fn image(&self) -> &[u8] {
        &self.bytes
    }
}

/// Packed unwind data.
fn packed(length: u32, reg_f: u32, reg_i: u32, h: bool, cr: u32, frame_size: u32) -> u32 {
    1 | (length / 4) << 2
        | reg_f << 13
        | reg_i << 16
        | u32::from(h) << 20
        | cr << 21
        | (frame_size / 16) << 23
}

fn context(pc_rva: u32, sp: u64) -> Context {
    let mut c = Context {
        pc: BASE + u64::from(pc_rva),
        sp,
        ..Context::default()
    };
    for (i, x) in c.x.iter_mut().enumerate() {
        *x = 0xC0DE_0000 + i as u64;
    }
    c.x[reg::LR] = LR;
    c
}

fn run(b: &Builder, f: RuntimeFunction, c: &mut Context, s: &Stack) -> windows_arm64::Frame {
    windows_arm64::unwind(b.image(), BASE, f, c, s).unwrap()
}

/// ```text
/// 00 stp x19, x20, [sp, #-0x30]!     save_r19r20_x 0x30
/// 04 stp x21, x22, [sp, #0x10]       save_next
/// 08 stp fp, lr, [sp, #0x20]         save_fplr 0x20
/// 0C add fp, sp, #0x20               add_fp 0x20
/// 10 sub sp, sp, #0x40               alloc_s 0x40
/// 14 (body)
/// 1C add sp, sp, #0x40               (the epilog, at the end: E)
/// 20 ldp fp, lr, [sp, #0x20]
/// 24 ldp x21, x22, [sp, #0x10]
/// 28 ldp x19, x20, [sp], #0x30
/// 2C ret
/// ```
fn xdata_function() -> (Builder, RuntimeFunction) {
    let mut b = Builder::new();
    let codes = [
        0x04, 0xE2, 0x04, 0x44, 0xE6, 0x26, 0xE4, // prolog
        0x04, 0x44, 0xE6, 0x26, 0xE4, // epilog, at index 7
    ];
    b.xdata(0x3000, 0x30, true, 7, &[], &codes, None);
    (
        b,
        RuntimeFunction {
            begin: 0x2000,
            unwind: 0x3000,
        },
    )
}

/// The entry SP, and the stack `xdata_function`'s prolog leaves below it.
fn xdata_stack() -> (u64, Stack) {
    let e = STACK + 0x200;
    let mut s = Stack::new();
    for (at, v) in [
        (0x30, 0x1919),
        (0x28, 0x2020),
        (0x20, 0x2121),
        (0x18, 0x2222),
        (0x10, 0xF0F0),
        (0x8, RETURN),
    ] {
        s.set(e - at, v);
    }
    (e, s)
}

fn assert_restored(c: &Context, e: u64) {
    assert_eq!(
        (c.x[19], c.x[20], c.x[21], c.x[22]),
        (0x1919, 0x2020, 0x2121, 0x2222)
    );
    assert_eq!(
        (c.x[reg::FP], c.x[reg::LR], c.pc, c.sp),
        (0xF0F0, RETURN, RETURN, e)
    );
}

#[test]
fn xdata_body() {
    let (b, f) = xdata_function();
    let (e, s) = xdata_stack();
    let mut c = context(0x2014, e - 0x70);
    c.x[reg::FP] = e - 0x10;
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Body);
    assert_restored(&c, e);
    assert_eq!(frame.saved_x[19], Some(e - 0x30));
    assert_eq!(frame.saved_x[22], Some(e - 0x18));
    assert_eq!(frame.saved_x[reg::LR], Some(e - 0x8));
    assert_eq!(frame.saved_x[23], None);
    assert_eq!(frame.establisher_frame, e);
    assert!(!frame.machine_frame && !frame.signed_return);
}

#[test]
fn xdata_prolog() {
    let (b, f) = xdata_function();
    let (e, s) = xdata_stack();
    // Before anything: LR is the return address.
    let mut c = context(0x2000, e);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Prolog(0));
    assert_eq!((c.pc, c.sp, c.x[19]), (LR, e, 0xC0DE_0013));
    // After the first store: x19 and x20 only.
    let mut c = context(0x2004, e - 0x30);
    run(&b, f, &mut c, &s);
    assert_eq!(
        (c.pc, c.sp, c.x[19], c.x[20], c.x[21]),
        (LR, e, 0x1919, 0x2020, 0xC0DE_0015)
    );
    // After saving fp and lr.
    let mut c = context(0x200C, e - 0x30);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Prolog(3));
    assert_restored(&c, e);
    // After `add fp`: SP comes back from fp.
    let mut c = context(0x2010, e - 0x30);
    c.x[reg::FP] = e - 0x10;
    run(&b, f, &mut c, &s);
    assert_restored(&c, e);
}

#[test]
fn xdata_epilog() {
    let (b, f) = xdata_function();
    let (e, s) = xdata_stack();
    for (pc, sp, done) in [
        (0x201C, e - 0x70, 0),
        (0x2020, e - 0x30, 1),
        (0x2024, e - 0x30, 2),
        (0x2028, e - 0x30, 3),
    ] {
        let mut c = context(pc, sp);
        if done >= 2 {
            // (Already restored by the epilog.)
            c.x[reg::FP] = 0xF0F0;
            c.x[reg::LR] = RETURN;
        }
        if done >= 3 {
            c.x[21] = 0x2121;
            c.x[22] = 0x2222;
        }
        let frame = run(&b, f, &mut c, &s);
        assert_eq!(frame.position, Position::Epilog(done), "{pc:#x}");
        assert_restored(&c, e);
        // Registers the epilog already restored aren't read again.
        assert_eq!(frame.saved_x[reg::LR].is_some(), done < 2, "{pc:#x}");
    }
    // At the `ret`, everything is restored: PC is LR.
    let mut c = context(0x202C, e);
    c.x[reg::LR] = RETURN;
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Epilog(4));
    assert_eq!((c.pc, c.sp, frame.saved_x), (RETURN, e, [None; 31]));
}

#[test]
fn epilog_scopes() {
    // The same function, with its epilog listed as a scope (at 0x1C, codes
    // from index 7) instead of E.
    let mut b = Builder::new();
    let codes = [
        0x04, 0xE2, 0x04, 0x44, 0xE6, 0x26, 0xE4, 0x04, 0x44, 0xE6, 0x26, 0xE4,
    ];
    let scope = (0x1C / 4) | (14 << 18) | (7 << 22);
    b.xdata(0x3000, 0x30, false, 1, &[scope], &codes, None);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let (e, s) = xdata_stack();
    let mut c = context(0x2020, e - 0x30);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Epilog(1));
    assert_restored(&c, e);
    // An epilog that shares the prolog's codes (index 0): `mov sp, fp`
    // (the undone `add fp`) is its second instruction.
    let scope = (0x1C / 4) | (14 << 18);
    b.xdata(0x3000, 0x30, false, 1, &[scope], &codes, None);
    let mut c = context(0x2020, e - 0x10);
    c.x[reg::FP] = e - 0x10;
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Epilog(1));
    assert_restored(&c, e);
}

#[test]
fn other_saves() {
    // sub sp, sp, #0x60; stp x19, lr, [sp]; stp d8, d9, [sp, #0x10];
    // str d10, [sp, #0x20]; stp q12, q13, [sp, #0x30].
    let mut b = Builder::new();
    let codes = [
        0xE7, 0x4C, 0x83, 0xDC, 0x84, 0xD8, 0x02, 0xD6, 0x00, 0x06, 0xE4,
    ];
    b.xdata(0x3000, 0x18, false, 0, &[], &codes, None);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let sp = STACK + 0x100;
    let mut s = Stack::new();
    for (at, v) in [
        (0, 0x1919),
        (8, RETURN),
        (0x10, 0x88),
        (0x18, 0x99),
        (0x20, 0xAA),
        (0x30, 0xC0),
        (0x38, 0xC1),
        (0x40, 0xD0),
        (0x48, 0xD1),
    ] {
        s.set(sp + at, v);
    }
    let mut c = context(0x2014, sp);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!((c.x[19], c.pc, c.sp), (0x1919, RETURN, sp + 0x60));
    assert_eq!((c.v[8], c.v[9], c.v[10]), (0x88, 0x99, 0xAA));
    assert_eq!(
        (c.v[12], c.v[13]),
        (0xC1_u128 << 64 | 0xC0, 0xD1_u128 << 64 | 0xD0)
    );
    assert_eq!(
        (frame.saved_v[9], frame.saved_v[13]),
        (Some(sp + 0x18), Some(sp + 0x40))
    );
}

#[test]
fn save_any_reg_writeback() {
    // str x23, [sp, #-0x10]! (save_any_reg: x, writeback, o = 0), then
    // stp d14, d15, [sp, #0x0] (pair, o = 0).
    let mut b = Builder::new();
    let codes = [0xE7, 0x4E, 0x40, 0xE7, 0x37, 0x00, 0xE4];
    b.xdata(0x3000, 0x0C, false, 0, &[], &codes, None);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let sp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(sp, 0xEE);
    s.set(sp + 8, 0xFF);
    let mut c = context(0x2008, sp);
    run(&b, f, &mut c, &s);
    assert_eq!(
        (c.v[14], c.v[15], c.x[23], c.sp),
        (0xEE, 0xFF, 0xEE, sp + 0x10)
    );
}

#[test]
fn packed_chained() {
    // RegI=2, CR=3, frame 0x40: stp x19, x20, [sp, #-0x10]!; stp fp, lr,
    // [sp, #-0x30]!; mov fp, sp; (body); ldp fp, lr, [sp], #0x30; ldp x19,
    // x20, [sp], #0x10; ret.
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 3, 0x40),
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    for (at, v) in [
        (0x10, 0x1919),
        (0x8, 0x2020),
        (0x40, 0xF0F0),
        (0x38, RETURN),
    ] {
        s.set(e - at, v);
    }
    let check = |c: &Context| {
        assert_eq!(
            (c.x[19], c.x[20], c.x[reg::FP], c.pc, c.sp),
            (0x1919, 0x2020, 0xF0F0, RETURN, e)
        );
    };
    // The body, with SP moved: fp finds the frame.
    let mut c = context(0x200C, e - 0x80);
    c.x[reg::FP] = e - 0x40;
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Body);
    check(&c);
    // The epilog, at 0x14.
    let mut c = context(0x2014, e - 0x40);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Epilog(0));
    check(&c);
    let mut c = context(0x2018, e - 0x10);
    c.x[reg::FP] = 0xF0F0;
    c.x[reg::LR] = RETURN;
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Epilog(1));
    check(&c);
    // The prolog, after its first instruction.
    let mut c = context(0x2004, e - 0x10);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Prolog(1));
    assert_eq!((c.x[19], c.pc, c.sp), (0x1919, LR, e));
    // After both stores (before `mov fp, sp`).
    let mut c = context(0x200C - 4, e - 0x40);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Prolog(2));
    check(&c);
}

#[test]
fn packed_lr_with_x19() {
    // RegI=1, CR=1, frame 0x10: sub sp, sp, #0x10; stp x19, lr, [sp];
    // (body); ldp x19, lr, [sp]; add sp, sp, #0x10; ret. (Not the doc's
    // merged pre-indexed stp: real code, and dumpbin, have these two.)
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x18, 0, 1, false, 1, 0x10),
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0x1919);
    s.set(e - 0x8, RETURN);
    let mut c = context(0x2008, e - 0x10);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Body);
    assert_eq!((c.x[19], c.pc, c.sp), (0x1919, RETURN, e));
    // After the `sub` only.
    let mut c = context(0x2004, e - 0x10);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Prolog(1));
    assert_eq!((c.x[19], c.pc, c.sp), (0xC0DE_0013, LR, e));
    // The epilog's `add sp` (its second instruction).
    let mut c = context(0x2010, e - 0x10);
    c.x[reg::LR] = RETURN;
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Epilog(1));
    assert_eq!((c.pc, c.sp, frame.saved_x[19]), (RETURN, e, None));
}

#[test]
fn packed_fragments_have_no_epilog() {
    // Flag 2: no prolog and no epilog; even the last instructions are body.
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 0, 0x10) + 1,
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0x1919);
    s.set(e - 0x8, 0x2020);
    let mut c = context(0x201C, e - 0x10);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Body);
    assert_eq!((c.x[19], c.sp), (0x1919, e));
    assert_eq!(windows_arm64::layout(b.image(), f).unwrap().epilogs, []);
    assert_eq!(windows_arm64::describe(b.image(), f).unwrap().epilogs, []);
}

#[test]
fn epilog_index_inside_a_code_is_malformed() {
    // Codes: save_regp (2 bytes), alloc_s, end; an epilog scope at index 1,
    // inside the save_regp.
    let mut b = Builder::new();
    let scope = (0x8 / 4) | (14 << 18) | (1 << 22);
    b.xdata(
        0x3000,
        0x10,
        false,
        1,
        &[scope],
        &[0xC8, 0x02, 0x01, 0xE4],
        None,
    );
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let mut c = context(0x2008, STACK + 0x100);
    assert_eq!(
        windows_arm64::unwind(b.image(), BASE, f, &mut c, &Stack::new()),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    assert!(windows_arm64::layout(b.image(), f).is_err());
    // At index 2 (the alloc_s), it's fine.
    let scope = (0x8 / 4) | (14 << 18) | (2 << 22);
    b.xdata(
        0x3000,
        0x10,
        false,
        1,
        &[scope],
        &[0xC8, 0x02, 0x01, 0xE4],
        None,
    );
    assert!(windows_arm64::layout(b.image(), f).is_ok());
}

#[test]
fn packed_large_locals() {
    // CR=0, frame 0x1FF0 (the most; all locals): sub sp, sp, 4080; sub sp, sp,
    // #(0x1FF0 - 4080): two instructions, as the doc's step 6e says (even
    // though one `sub ..., lsl #12` could do it).
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 0, false, 0, 0x1FF0),
    };
    let mut c = context(0x2004, STACK + 0x100);
    let frame = run(&b, f, &mut c, &Stack::new());
    assert_eq!(frame.position, Position::Prolog(1));
    assert_eq!(c.sp, STACK + 0x100 + 4080);
    assert_eq!(
        windows_arm64::layout(b.image(), f).unwrap().epilogs[0],
        windows_arm64::Epilog {
            start: 0x20 - 12,
            instructions: 3,
            returns: true
        }
    );
}

#[test]
fn packed_signed_return() {
    // CR=2: pacibsp; stp fp, lr, [sp, #-0x10]!; mov fp, sp; ...; autibsp;
    // ret. The return address on the stack is signed.
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x1C, 0, 0, false, 2, 0x10),
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0xF0F0);
    s.set(e - 0x8, 0x002A_0000_0000_0000 | RETURN);
    let mut c = context(0x200C, e - 0x10);
    c.x[reg::FP] = e - 0x10;
    let frame = run(&b, f, &mut c, &s);
    assert!(frame.signed_return);
    assert_eq!((c.pc, c.sp, c.x[reg::FP]), (RETURN, e, 0xF0F0));
    // (The register keeps what was saved.)
    assert_eq!(c.x[reg::LR], 0x002A_0000_0000_0000 | RETURN);
    // Kernel addresses keep their top bits.
    let mut s = Stack::new();
    s.set(e - 0x8, 0xFFAA_8000_0000_1000);
    let mut c = context(0x200C, e - 0x10);
    c.x[reg::FP] = e - 0x10;
    run(&b, f, &mut c, &s);
    assert_eq!(c.pc, 0xFFFF_8000_0000_1000);
}

#[test]
fn packed_homing_and_floats() {
    // RegI=0, RegF=1 (d8, d9), H: stp d8, d9, [sp, #-0x50]!; stp x0, x1 ...
    // (4 homing stores, not restored); sub sp, sp, #0x20 (frame 0x70).
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x40, 1, 0, true, 0, 0x70),
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x50, 0x88);
    s.set(e - 0x48, 0x99);
    let mut c = context(0x2018, e - 0x70);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Body);
    assert_eq!((c.v[8], c.v[9], c.pc, c.sp), (0x88, 0x99, LR, e));
    assert_eq!(frame.saved_x, [None; 31]);
    // In the homing stores (after 3 of the prolog's 6 instructions).
    let mut c = context(0x200C, e - 0x50);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Prolog(3));
    assert_eq!((c.v[8], c.sp), (0x88, e));
}

#[test]
fn packed_fragment_has_no_prolog() {
    // Flag 2: at offset 0 it is already in the body.
    let b = Builder::new();
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 0, 0x10) + 1,
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0x1919);
    s.set(e - 0x8, 0x2020);
    let mut c = context(0x2000, e - 0x10);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Body);
    assert_eq!((c.x[19], c.x[20], c.sp), (0x1919, 0x2020, e));
}

#[test]
fn chained_scopes() {
    // alloc_s 0x10, end_c, then a chained scope: save_r19r20_x 0x10, end.
    let mut b = Builder::new();
    b.xdata(0x3000, 0x10, false, 0, &[], &[0x01, 0xE5, 0x22, 0xE4], None);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0x1919);
    s.set(e - 0x8, 0x2020);
    // In the first scope's prolog (before its one instruction): only the
    // chained scope's codes.
    let mut c = context(0x2000, e - 0x10);
    let frame = run(&b, f, &mut c, &s);
    assert_eq!(frame.position, Position::Prolog(0));
    assert_eq!((c.x[19], c.sp), (0x1919, e));
    // In the body: both.
    let mut c = context(0x2008, e - 0x20);
    assert_eq!(run(&b, f, &mut c, &s).position, Position::Body);
    assert_eq!((c.x[19], c.sp), (0x1919, e));
}

#[test]
fn contexts_and_machine_frames() {
    // A whole CONTEXT at SP.
    let mut b = Builder::new();
    b.xdata(0x3000, 0x8, false, 0, &[], &[0xEA, 0xE4], None);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    let base = STACK + 0x200;
    let mut s = Stack::new();
    s.set(base, 0x6000_0000_u64 << 32); // ContextFlags, Cpsr
    for n in 0..31 {
        s.set(base + 8 + 8 * n, 0x1000 + n);
    }
    s.set(base + 0x100, STACK + 0x40);
    s.set(base + 0x108, RETURN);
    s.set(base + 0x110 + 16 * 8, 0x88);
    s.set(base + 0x118 + 16 * 8, 0);
    let mut c = context(0x2004, base);
    let frame = run(&b, f, &mut c, &s);
    assert!(frame.machine_frame);
    assert_eq!(
        (c.pc, c.sp, c.cpsr, c.x[0], c.x[reg::LR], c.v[8]),
        (RETURN, STACK + 0x40, 0x6000_0000, 0x1000, 0x101E, 0x88)
    );

    // A machine frame: SP, then PC.
    b.xdata(0x3000, 0x8, false, 0, &[], &[0xE9, 0xE4], None);
    let mut s = Stack::new();
    s.set(base, STACK + 0x40);
    s.set(base + 8, RETURN);
    let mut c = context(0x2004, base);
    let frame = run(&b, f, &mut c, &s);
    assert!(frame.machine_frame);
    assert_eq!((c.pc, c.sp, c.x[reg::LR]), (RETURN, STACK + 0x40, LR));

    // An ARM64EC (x64) context: rcx is x0, rsp is sp, rip is pc.
    b.xdata(0x3000, 0x8, false, 0, &[], &[0xEB, 0xE4], None);
    let mut s = Stack::new();
    s.set(base + 0x80, 0xCCCC); // rcx
    s.set(base + 0x98, STACK + 0x40); // rsp
    s.set(base + 0xF8, RETURN); // rip
    let mut c = context(0x2004, base);
    run(&b, f, &mut c, &s);
    assert_eq!((c.pc, c.sp, c.x[0]), (RETURN, STACK + 0x40, 0xCCCC));
}

#[test]
fn handlers() {
    let (mut b, f) = xdata_function();
    let codes = [
        0x04, 0xE2, 0x04, 0x44, 0xE6, 0x26, 0xE4, 0x04, 0x44, 0xE6, 0x26, 0xE4,
    ];
    b.xdata(0x3000, 0x30, true, 7, &[], &codes, Some(0x2800));
    let (e, s) = xdata_stack();
    for (pc, sp, has) in [
        (0x2000, e, false),
        (0x2014, e - 0x70, true),
        (0x201C, e - 0x70, false),
    ] {
        let mut c = context(pc, sp);
        c.x[reg::FP] = e - 0x10;
        let frame = run(&b, f, &mut c, &s);
        assert_eq!(frame.handler.is_some(), has, "{pc:#x}");
        if let Some(h) = frame.handler {
            assert_eq!((h.routine, h.data), (0x2800, 0x3000 + 4 + 12 + 4));
        }
    }
}

#[test]
fn leaf() {
    let mut c = context(0x2000, STACK);
    let frame = windows_arm64::unwind_leaf(&mut c);
    assert_eq!((c.pc, c.sp, frame.establisher_frame), (LR, STACK, STACK));
}

#[test]
fn lookup() {
    let mut b = Builder::new();
    let packed_entry = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 3, 0x40),
    };
    let xdata_entry = RuntimeFunction {
        begin: 0x2100,
        unwind: 0x3000,
    };
    b.xdata(0x3000, 0x30, true, 7, &[], &[0xE4], None);
    for (i, f) in [packed_entry, xdata_entry].iter().enumerate() {
        b.put(0x1000 + 8 * i as u32, &f.begin.to_le_bytes());
        b.put(0x1004 + 8 * i as u32, &f.unwind.to_le_bytes());
    }
    let find = |rva| windows_arm64::lookup(b.image(), 0x1000, 16, rva);
    assert_eq!(find(0x2000), Some(packed_entry));
    assert_eq!(find(0x201F), Some(packed_entry));
    assert_eq!(find(0x2100), Some(xdata_entry));
    assert_eq!(find(0x212F), Some(xdata_entry));
    for rva in [0, 0x1FFF, 0x2020, 0x20FF, 0x2130, u32::MAX] {
        assert_eq!(find(rva), None, "{rva:#x}");
    }
    assert_eq!(windows_arm64::lookup(b.image(), 0x1000, 0, 0x2000), None);
    assert_eq!(windows_arm64::lookup(b.image(), 0x3FFC, 16, 0x2000), None);
    assert_eq!(packed_entry.length(b.image()), Some(0x20));
    assert_eq!(
        RuntimeFunction {
            begin: 0,
            unwind: 3
        }
        .length(b.image()),
        None
    );
}

#[test]
fn malformed() {
    let s = Stack::new();
    let try_codes = |codes: &[u8]| {
        let mut b = Builder::new();
        b.xdata(0x3000, 0x10, false, 0, &[], codes, None);
        let f = RuntimeFunction {
            begin: 0x2000,
            unwind: 0x3000,
        };
        let mut c = context(0x2008, STACK + 0x100);
        windows_arm64::unwind(b.image(), BASE, f, &mut c, &s)
    };
    // A reserved code; codes with no end; save_next with no pair after it.
    assert_eq!(
        try_codes(&[0xF0, 0xE4]),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    assert_eq!(
        try_codes(&[0x01, 0x01, 0x01, 0x01]),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    assert_eq!(
        try_codes(&[0xE6, 0x04, 0xE4]),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    assert_eq!(
        try_codes(&[0xE6, 0xE4]),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    // save_next after a non-adjacent pair (x19, lr).
    assert_eq!(
        try_codes(&[0xE6, 0xD6, 0x00, 0xE4]),
        Err(Error::UnwindData { rva: 0x3000 })
    );
    // SVE, trap frames, and invalid save_any_reg forms.
    for codes in [
        &[0xDF, 0x01, 0xE4][..],
        &[0xE8, 0xE4],
        &[0xE7, 0x08, 0xC1, 0xE4],
        &[0xE7, 0x80, 0x00, 0xE4],
        &[0xE7, 0x1F, 0x00, 0xE4],
    ] {
        assert!(
            matches!(try_codes(codes), Err(Error::Unsupported { .. })),
            "{codes:02x?}"
        );
    }
    // A truncated record, flag 3, and a record off the image.
    let mut b = Builder::new();
    b.put(0x3FFC, &(4u32 | 4 << 27).to_le_bytes());
    let mut c = context(0x2008, STACK + 0x100);
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3FFC,
    };
    assert_eq!(
        windows_arm64::unwind(b.image(), BASE, f, &mut c, &s),
        Err(Error::UnwindData { rva: 0x3FFC })
    );
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3003,
    };
    assert!(windows_arm64::unwind(b.image(), BASE, f, &mut c, &s).is_err());
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0xFFFF_FFF0,
    };
    assert!(windows_arm64::unwind(b.image(), BASE, f, &mut c, &s).is_err());
    // Memory that isn't there.
    let (b, f) = xdata_function();
    let mut c = context(0x2014, 0x10);
    assert!(matches!(
        windows_arm64::unwind(b.image(), BASE, f, &mut c, &s),
        Err(Error::Memory { .. })
    ));
}

#[test]
fn layouts() {
    use windows_arm64::{Epilog, Layout};
    let (b, f) = xdata_function();
    assert_eq!(
        windows_arm64::layout(b.image(), f),
        Ok(Layout {
            prolog: 5,
            epilogs: vec![Epilog {
                start: 0x1C,
                instructions: 5,
                returns: true
            }],
        })
    );
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 3, 0x40),
    };
    assert_eq!(
        windows_arm64::layout(b.image(), f),
        Ok(Layout {
            prolog: 3,
            epilogs: vec![Epilog {
                start: 0x14,
                instructions: 3,
                returns: true
            }],
        })
    );
    // A fragment without a prolog.
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 0, 0x10) + 1,
    };
    assert_eq!(windows_arm64::layout(b.image(), f).map(|l| l.prolog), Ok(0));
    // An epilog whose codes end with `end_c`: its `ret` is in another
    // fragment, so `end` isn't counted. (Prolog: end_c alone, so none.)
    let mut b = Builder::new();
    let scope = (0x8 / 4) | (14 << 18) | (1 << 22);
    b.xdata(
        0x3000,
        0x10,
        false,
        1,
        &[scope],
        &[0xE5, 0x81, 0xFC, 0xE5, 0xE4],
        None,
    );
    let f = RuntimeFunction {
        begin: 0x2000,
        unwind: 0x3000,
    };
    assert_eq!(
        windows_arm64::layout(b.image(), f),
        Ok(Layout {
            prolog: 0,
            epilogs: vec![Epilog {
                start: 0x8,
                instructions: 2,
                returns: false
            }],
        })
    );
    assert_eq!(
        windows_arm64::layout(
            b.image(),
            // (A link record whose parent is off the image.)
            RuntimeFunction {
                begin: 0,
                unwind: 0xFFFF_FFF3
            }
        ),
        Err(Error::UnwindData { rva: 0xFFFF_FFF0 })
    );
}

#[test]
fn link_records() {
    // Entries: the parent (packed: RegI=2, CR=0, frame 0x10) at 0x2000, and
    // a jump island at 0x2100 linking to it (Flag 3, its record's RVA).
    let mut b = Builder::new();
    let parent = RuntimeFunction {
        begin: 0x2000,
        unwind: packed(0x20, 0, 2, false, 0, 0x10),
    };
    let island = RuntimeFunction {
        begin: 0x2100,
        unwind: 0x1000 | 3,
    };
    for (i, f) in [parent, island].iter().enumerate() {
        b.put(0x1000 + 8 * i as u32, &f.begin.to_le_bytes());
        b.put(0x1004 + 8 * i as u32, &f.unwind.to_le_bytes());
    }
    assert!(island.is_link() && !parent.is_link());
    assert_eq!(windows_arm64::resolve(b.image(), island), Ok(parent));
    // The island runs to the next entry (or, the last, as far as asked).
    assert_eq!(
        windows_arm64::lookup(b.image(), 0x1000, 16, 0x2108),
        Some(island)
    );
    assert_eq!(windows_arm64::lookup(b.image(), 0x1000, 16, 0x2020), None);
    // Unwinding in the island: the parent's body (x19, x20 at sp).
    let e = STACK + 0x200;
    let mut s = Stack::new();
    s.set(e - 0x10, 0x1919);
    s.set(e - 0x8, 0x2020);
    let mut c = context(0x2104, e - 0x10);
    let frame = run(&b, island, &mut c, &s);
    assert_eq!(frame.position, Position::Body);
    assert_eq!((c.x[19], c.x[20], c.sp, c.pc), (0x1919, 0x2020, e, LR));
    // No prolog or epilog of its own.
    assert_eq!(
        windows_arm64::layout(b.image(), island).unwrap().epilogs,
        []
    );
    // A loop of links, and a link off the image.
    b.put(0x1004, &(0x1008u32 | 3).to_le_bytes());
    assert!(windows_arm64::resolve(b.image(), island).is_err());
    let off = RuntimeFunction {
        begin: 0x2100,
        unwind: 0xFFFF_FFF3,
    };
    let mut c = context(0x2104, e);
    assert!(windows_arm64::unwind(b.image(), BASE, off, &mut c, &s).is_err());
}

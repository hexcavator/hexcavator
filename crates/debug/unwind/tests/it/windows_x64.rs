//! Hermetic tests: synthetic images (laid out by RVA), unwind data, and
//! stacks. (`tests/windows_x64_rtl.rs` checks the x64 rules against
//! `RtlVirtualUnwind` itself.)

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_unwind::Error;
use hexcavator_unwind::windows_x64::{self, Context, Handler, Position, RuntimeFunction, reg};

use crate::support::{STACK, Stack};

const BASE: u64 = 0x1_4000_0000;

/// A PE image's bytes by RVA: headers naming an exception directory at
/// 0x1000; code goes from 0x2000, unwind information from 0x3000.
struct Builder {
    bytes: Vec<u8>,
    entries: u32,
}

const PDATA: u32 = 0x1000;
const OPTIONAL: usize = 0x98;

impl Builder {
    fn new() -> Self {
        let mut bytes = vec![0u8; 0x4000];
        bytes[0x3C] = 0x80;
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[OPTIONAL..OPTIONAL + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[OPTIONAL + 108..OPTIONAL + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = OPTIONAL + 112 + 3 * 8;
        bytes[dir..dir + 4].copy_from_slice(&PDATA.to_le_bytes());
        Builder { bytes, entries: 0 }
    }

    fn put(&mut self, rva: u32, b: &[u8]) {
        self.bytes[rva as usize..rva as usize + b.len()].copy_from_slice(b);
    }

    /// Adds a `.pdata` entry (in address order).
    fn function(&mut self, begin: u32, end: u32, unwind: u32) -> RuntimeFunction {
        let at = PDATA + self.entries * 12;
        self.put(at, &begin.to_le_bytes());
        self.put(at + 4, &end.to_le_bytes());
        self.put(at + 8, &unwind.to_le_bytes());
        self.entries += 1;
        let size = self.entries * 12;
        self.put((OPTIONAL + 112 + 3 * 8 + 4) as u32, &size.to_le_bytes());
        RuntimeFunction { begin, end, unwind }
    }

    /// Writes an `UNWIND_INFO` at `rva`: the header, the codes (`(offset,
    /// op, info)`, or a raw slot as `(lo, hi, RAW)`), padding, then `tail`.
    fn info(
        &mut self,
        rva: u32,
        version_flags: u8,
        prolog: u8,
        frame: u8,
        codes: &[(u8, u8, u8)],
        tail: &[u8],
    ) {
        let mut b = vec![version_flags, prolog, codes.len() as u8, frame];
        for &(offset, op, info) in codes {
            if info == RAW {
                b.extend([offset, op]);
            } else {
                b.extend([offset, op | info << 4]);
            }
        }
        if codes.len() % 2 == 1 {
            b.extend([0, 0]);
        }
        b.extend(tail);
        self.put(rva, &b);
    }

    fn image(&self) -> &[u8] {
        &self.bytes
    }
}

const RAW: u8 = 0xFF;
const V1: u8 = 1;
const V2: u8 = 2;
const EHANDLER: u8 = 1 << 3;
const UHANDLER: u8 = 2 << 3;
const CHAININFO: u8 = 4 << 3;

const PUSH_NONVOL: u8 = 0;
const ALLOC_LARGE: u8 = 1;
const ALLOC_SMALL: u8 = 2;
const SET_FPREG: u8 = 3;
const SAVE_NONVOL: u8 = 4;
const EPILOG: u8 = 6;
const SAVE_XMM128: u8 = 8;
const PUSH_MACHFRAME: u8 = 10;

const RETURN: u64 = 0x7777_0000;

fn context(rip_rva: u32, rsp: u64) -> Context {
    let mut c = Context {
        rip: BASE + u64::from(rip_rva),
        ..Context::default()
    };
    for (i, g) in c.gpr.iter_mut().enumerate() {
        *g = 0xC0DE_0000 + i as u64;
    }
    c.gpr[reg::RSP] = rsp;
    c
}

fn chain_to(begin: u32, end: u32, unwind: u32) -> Vec<u8> {
    let mut tail = vec![];
    tail.extend(begin.to_le_bytes());
    tail.extend(end.to_le_bytes());
    tail.extend(unwind.to_le_bytes());
    tail
}

/// `push rbx; push rsi; sub rsp, 28h; <body>; add rsp, 28h; pop rsi;
/// pop rbx; ret`, at 0x2000.
fn pushes() -> (Builder, RuntimeFunction) {
    let mut b = Builder::new();
    let code = [
        0x53, 0x56, 0x48, 0x83, 0xEC, 0x28, // prolog
        0x90, 0x90, 0x90, 0x90, // body
        0x48, 0x83, 0xC4, 0x28, 0x5E, 0x5B, 0xC3, // epilog
    ];
    b.put(0x2000, &code);
    b.info(
        0x3000,
        V1,
        6,
        0,
        &[
            (6, ALLOC_SMALL, 4),
            (2, PUSH_NONVOL, reg::RSI as u8),
            (1, PUSH_NONVOL, reg::RBX as u8),
        ],
        &[],
    );
    let f = b.function(0x2000, 0x2000 + code.len() as u32, 0x3000);
    (b, f)
}

/// The stack `pushes` leaves at `rsp`: rsi, rbx, then the return address.
fn pushed(rsp: u64) -> Stack {
    let mut s = Stack::new();
    s.set(rsp + 0x28, 0x5151);
    s.set(rsp + 0x30, 0xB0B0);
    s.set(rsp + 0x38, RETURN);
    s
}

#[test]
fn leaf() {
    let mut s = Stack::new();
    s.set(STACK + 0x40, 0x1234);
    let mut c = context(0x2000, STACK + 0x40);
    let f = windows_x64::unwind_leaf(&mut c, &s).unwrap();
    assert_eq!((c.rip, c.rsp()), (0x1234, STACK + 0x48));
    assert_eq!(f.establisher_frame, STACK + 0x40);
    assert_eq!(f.saved_gpr, [None; 16]);
}

#[test]
fn body_undoes_every_code() {
    let (b, f) = pushes();
    let rsp = STACK + 0x100;
    let s = pushed(rsp);
    let mut c = context(0x2007, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Body);
    assert_eq!((c.rip, c.rsp()), (RETURN, rsp + 0x40));
    assert_eq!((c.gpr[reg::RSI], c.gpr[reg::RBX]), (0x5151, 0xB0B0));
    assert_eq!(frame.saved_gpr[reg::RSI], Some(rsp + 0x28));
    assert_eq!(frame.saved_gpr[reg::RBX], Some(rsp + 0x30));
    assert_eq!(frame.establisher_frame, rsp);
    // Untouched registers stay.
    assert_eq!(c.gpr[reg::RDI], 0xC0DE_0007);
    assert_eq!(frame.saved_gpr[reg::RDI], None);
    assert!(!frame.machine_frame);
}

#[test]
fn prolog_undoes_only_what_has_run() {
    let (b, f) = pushes();
    // At offset 2 (after both pushes, before the allocation).
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp, 0x5151);
    s.set(rsp + 8, 0xB0B0);
    s.set(rsp + 16, RETURN);
    let mut c = context(0x2002, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Prolog(2));
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RSI], c.gpr[reg::RBX]),
        (RETURN, rsp + 24, 0x5151, 0xB0B0)
    );

    // At the very start, nothing has run.
    let mut s = Stack::new();
    s.set(rsp, RETURN);
    let mut c = context(0x2000, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Prolog(0));
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RBX]),
        (RETURN, rsp + 8, 0xC0DE_0003)
    );
}

#[test]
fn epilog_is_simulated() {
    let (b, f) = pushes();
    let rsp = STACK + 0x100;
    // At the `add rsp`: as from the body.
    let s = pushed(rsp);
    let mut c = context(0x200A, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Epilog);
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RSI], c.gpr[reg::RBX]),
        (RETURN, rsp + 0x40, 0x5151, 0xB0B0)
    );
    // At `pop rbx`: rsi was already restored (its value stays).
    let mut s = Stack::new();
    s.set(rsp, 0xB0B0);
    s.set(rsp + 8, RETURN);
    let mut c = context(0x200F, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Epilog);
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RSI], c.gpr[reg::RBX]),
        (RETURN, rsp + 16, 0xC0DE_0006, 0xB0B0)
    );
    assert_eq!(frame.saved_gpr[reg::RSI], None);
    assert_eq!(frame.establisher_frame, rsp);
}

/// A function `push rbx; <tail>` with the tail at 0x2001.
fn tail(tail: &[u8], end: u32) -> (Builder, RuntimeFunction) {
    let mut b = Builder::new();
    b.put(0x2000, &[0x53]);
    b.put(0x2001, tail);
    b.info(0x3000, V1, 1, 0, &[(1, PUSH_NONVOL, reg::RBX as u8)], &[]);
    let f = b.function(0x2000, end, 0x3000);
    (b, f)
}

/// Unwinds (pushed rbx, return address) at `pc`, checking the result
/// either way; returns whether it was an epilog.
fn at_tail(b: &Builder, f: RuntimeFunction, pc: u32) -> bool {
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp, 0xB0B0);
    s.set(rsp + 8, RETURN);
    let mut c = context(pc, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RBX]),
        (RETURN, rsp + 16, 0xB0B0),
        "{frame:?}"
    );
    frame.position == Position::Epilog
}

#[test]
fn epilog_terminators() {
    // pop rbx (bare, or with a REX prefix), then each way out.
    for pop in [&[0x5Bu8][..], &[0x40, 0x5B], &[0x48, 0x5B]] {
        for (end, epilog) in [
            (&[0xC3u8][..], true),                   // ret
            (&[0xC2, 0x08, 0x00], true),             // ret 8
            (&[0xF3, 0xC3], true),                   // rep ret
            (&[0xFF, 0x25, 0, 0, 0, 0], true),       // jmp [rip+0]
            (&[0x48, 0xFF, 0x25, 0, 0, 0, 0], true), // rex.w jmp [rip+0]
            (&[0x48, 0xFF, 0xE0], true),             // rex.w jmp rax
            (&[0x49, 0xFF, 0xE3], true),             // rex.w jmp r11
            (&[0x90], false),                        // nop
            (&[0xFF, 0xE0], false),                  // jmp rax (no REX.W)
            (&[0xFF, 0x24, 0x24], false),            // jmp [rsp]
        ] {
            let mut code = pop.to_vec();
            code.extend(end);
            let (b, f) = tail(&code, 0x2100);
            assert_eq!(at_tail(&b, f, 0x2001), epilog, "{code:02x?}");
        }
    }
    // A REX.B pop: r11.
    let (b, f) = tail(&[0x41, 0x5B, 0xC3], 0x2100);
    let mut s = Stack::new();
    s.set(STACK + 0x100, 0x1111);
    s.set(STACK + 0x108, RETURN);
    let mut c = context(0x2001, STACK + 0x100);
    windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!((c.gpr[11], c.gpr[reg::RBX]), (0x1111, 0xC0DE_0003));
}

#[test]
fn jumps_out_are_tail_calls() {
    // jmp rel32 to 0x3001 (no function there): a tail call.
    let (b, f) = tail(&[0x5B, 0xE9, 0xFA, 0x0F, 0, 0], 0x2100);
    assert!(at_tail(&b, f, 0x2001));
    // jmp rel8 to 0x2010 (inside): a branch in the body.
    let (b, f) = tail(&[0x5B, 0xEB, 0x0C], 0x2100);
    assert!(!at_tail(&b, f, 0x2001));
    // jmp rel8 to 0x2000, the function's own entry: recursion.
    let (b, f) = tail(&[0x5B, 0xEB, 0xFC], 0x2100);
    assert!(at_tail(&b, f, 0x2001));
}

#[test]
fn jumps_within_a_chain_are_not_tail_calls() {
    // Root 0x2000..0x2010 (push rbx), and a fragment 0x2010..0x2020
    // chained to it.
    let mut b = Builder::new();
    b.put(0x2000, &[0x53]);
    b.info(0x3000, V1, 1, 0, &[(1, PUSH_NONVOL, reg::RBX as u8)], &[]);
    b.info(
        0x3100,
        V1 | CHAININFO,
        0,
        0,
        &[],
        &chain_to(0x2000, 0x2010, 0x3000),
    );
    b.function(0x2000, 0x2010, 0x3000);
    let fragment = b.function(0x2010, 0x2020, 0x3100);
    // pop rbx; jmp into the root's body (0x2004): a branch.
    b.put(0x2010, &[0x5B, 0xEB, 0xF1]);
    assert!(!at_tail(&b, fragment, 0x2010));
    // ...to the fragment's own start: still within the function.
    b.put(0x2010, &[0x5B, 0xEB, 0xFD]);
    assert!(!at_tail(&b, fragment, 0x2010));
    // ...to the root's entry: recursion, a tail call.
    b.put(0x2010, &[0x5B, 0xEB, 0xED]);
    assert!(at_tail(&b, fragment, 0x2010));
}

#[test]
fn iretq_pops_a_machine_frame() {
    let (b, f) = tail(&[0x5B, 0x48, 0xCF], 0x2100);
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp, 0xB0B0);
    s.set(rsp + 8, RETURN); // rip, cs, eflags, rsp, ss
    s.set(rsp + 32, STACK + 0x180);
    let mut c = context(0x2001, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert!(frame.machine_frame);
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RBX]),
        (RETURN, STACK + 0x180, 0xB0B0)
    );
}

/// `push rbp; sub rsp, 40h; lea rbp, [rsp+20h]; <body>; lea rsp,
/// [rbp+20h]; pop rbp; ret`, saving rbx at frame base + 0x30 and xmm6 at
/// + 0x10.
fn framed() -> (Builder, RuntimeFunction) {
    let mut b = Builder::new();
    let code = [
        0x55, // push rbp
        0x48, 0x83, 0xEC, 0x40, // sub rsp, 40h
        0x48, 0x8D, 0x6C, 0x24, 0x20, // lea rbp, [rsp+20h]
        0x90, 0x90, // body
        0x48, 0x8D, 0x65, 0x20, // lea rsp, [rbp+20h]
        0x5D, 0xC3, // pop rbp; ret
    ];
    b.put(0x2000, &code);
    b.info(
        0x3000,
        V1,
        10,
        reg::RBP as u8 | 2 << 4,
        &[
            (10, SAVE_XMM128, 6),
            (1, 0, RAW), // × 16
            (10, SAVE_NONVOL, reg::RBX as u8),
            (6, 0, RAW), // × 8
            (10, SET_FPREG, 0),
            (5, ALLOC_SMALL, 7),
            (1, PUSH_NONVOL, reg::RBP as u8),
        ],
        &[],
    );
    let f = b.function(0x2000, 0x2000 + code.len() as u32, 0x3000);
    (b, f)
}

/// The stack `framed` leaves at frame base `base`.
fn framed_stack(base: u64) -> Stack {
    let mut s = Stack::new();
    s.set(base + 0x10, 0x6666); // xmm6
    s.set(base + 0x18, 0x6767);
    s.set(base + 0x30, 0xB0B0); // rbx
    s.set(base + 0x40, 0x5555); // rbp
    s.set(base + 0x48, RETURN);
    s
}

#[test]
fn frame_pointer() {
    let (b, f) = framed();
    let base = STACK + 0x100;
    let s = framed_stack(base);
    // RSP moved below the frame (an alloca): the frame pointer finds it.
    let mut c = context(0x200A, STACK + 0x40);
    c.gpr[reg::RBP] = base + 0x20;
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Body);
    assert_eq!(frame.establisher_frame, base);
    assert_eq!(
        (frame.saved_gpr[reg::RBX], c.gpr[reg::RBX]),
        (Some(base + 0x30), 0xB0B0)
    );
    assert_eq!(
        (frame.saved_xmm[6], c.xmm[6]),
        (Some(base + 0x10), 0x6767_u128 << 64 | 0x6666)
    );
    assert_eq!(
        (frame.saved_gpr[reg::RBP], c.gpr[reg::RBP]),
        (Some(base + 0x40), 0x5555)
    );
    assert_eq!((c.rip, c.rsp()), (RETURN, base + 0x50));
}

#[test]
fn frame_pointer_epilog_and_prolog() {
    let (b, f) = framed();
    let base = STACK + 0x100;
    let s = framed_stack(base);
    // At `lea rsp, [rbp+20h]`.
    let mut c = context(0x200C, STACK + 0x40);
    c.gpr[reg::RBP] = base + 0x20;
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Epilog);
    assert_eq!(
        (c.rip, c.rsp(), c.gpr[reg::RBP]),
        (RETURN, base + 0x50, 0x5555)
    );
    // (The establisher frame is where the epilog leaves RSP, at the
    // return address, not the frame pointer's base.)
    assert_eq!(frame.establisher_frame, base + 0x48);
    // In the prolog before `lea rbp`: RSP.
    let mut c = context(0x2005, base);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Prolog(5));
    assert_eq!(frame.establisher_frame, base);
    assert_eq!(
        (c.rip, c.gpr[reg::RBP], c.gpr[reg::RBX]),
        (RETURN, 0x5555, 0xC0DE_0003)
    );
}

/// `sub rsp, 28h; <body>; add rsp, 28h; ret`, with a handler.
fn handled(flags: u8) -> (Builder, RuntimeFunction) {
    let mut b = Builder::new();
    b.put(
        0x2000,
        &[
            0x48, 0x83, 0xEC, 0x28, 0x90, 0x90, 0x48, 0x83, 0xC4, 0x28, 0xC3,
        ],
    );
    b.info(
        0x3000,
        V1 | flags,
        4,
        0,
        &[(4, ALLOC_SMALL, 4)],
        &0x2800u32.to_le_bytes(),
    );
    let f = b.function(0x2000, 0x200B, 0x3000);
    (b, f)
}

#[test]
fn handlers_only_in_the_body() {
    let (b, f) = handled(EHANDLER | UHANDLER);
    let s = Stack::new();
    let handler = Some(Handler {
        flags: 3,
        routine: 0x2800,
        data: 0x300C,
    });
    for (pc, expected) in [
        (0x2000, None),
        (0x2004, handler),
        (0x2006, None),
        (0x200A, None),
    ] {
        let mut c = context(pc, STACK + 0x100);
        let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
        assert_eq!(frame.handler, expected, "{pc:#x}");
    }
    let (b, f) = handled(UHANDLER);
    let mut c = context(0x2004, STACK + 0x100);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.handler.map(|h| h.flags), Some(2));
}

#[test]
fn no_codes_no_epilog() {
    // A function with a handler and no codes: even at its `ret`, the
    // handler is returned.
    let mut b = Builder::new();
    b.put(0x2000, &[0x90, 0xC3]);
    b.info(0x3000, V1 | EHANDLER, 0, 0, &[], &0x2800u32.to_le_bytes());
    let f = b.function(0x2000, 0x2002, 0x3000);
    let mut s = Stack::new();
    s.set(STACK + 0x100, RETURN);
    let mut c = context(0x2001, STACK + 0x100);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Body);
    assert!(frame.handler.is_some());
    assert_eq!((c.rip, c.rsp()), (RETURN, STACK + 0x108));
}

#[test]
fn chained_fragments() {
    // Root: push rbx; push rsi; sub rsp, 20h, with a handler. Fragment:
    // saves rdi at +0x10 in a 0x10-byte prolog of its own.
    let mut b = Builder::new();
    b.put(0x2000, &[0x53, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90]);
    b.info(
        0x3000,
        V1 | EHANDLER,
        6,
        0,
        &[
            (6, ALLOC_SMALL, 3),
            (2, PUSH_NONVOL, reg::RSI as u8),
            (1, PUSH_NONVOL, reg::RBX as u8),
        ],
        &0x2800u32.to_le_bytes(),
    );
    b.info(
        0x3100,
        V1 | CHAININFO,
        0x10,
        0,
        &[(8, SAVE_NONVOL, reg::RDI as u8), (2, 0, RAW)],
        &chain_to(0x2000, 0x2008, 0x3000),
    );
    b.put(0x2010, &[0x90; 0x20]);
    b.function(0x2000, 0x2008, 0x3000);
    let fragment = b.function(0x2010, 0x2030, 0x3100);

    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp + 0x10, 0xD1D1);
    s.set(rsp + 0x20, 0x5151);
    s.set(rsp + 0x28, 0xB0B0);
    s.set(rsp + 0x30, RETURN);
    // In the fragment's body: its save, then the root's codes.
    let mut c = context(0x2020, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, fragment, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Body);
    assert_eq!(
        (c.gpr[reg::RDI], c.gpr[reg::RSI], c.gpr[reg::RBX]),
        (0xD1D1, 0x5151, 0xB0B0)
    );
    assert_eq!((c.rip, c.rsp()), (RETURN, rsp + 0x38));
    assert_eq!(frame.handler.map(|h| h.routine), Some(0x2800));
    // In the fragment's prolog, before its save: the root's codes in full,
    // and still the root's handler.
    let mut c = context(0x2014, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, fragment, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Prolog(4));
    assert_eq!(
        (c.gpr[reg::RDI], c.gpr[reg::RSI], c.gpr[reg::RBX]),
        (0xC0DE_0007, 0x5151, 0xB0B0)
    );
    assert_eq!(frame.handler.map(|h| h.routine), Some(0x2800));
}

#[test]
fn machine_frames() {
    for error_code in [0u8, 1] {
        let mut b = Builder::new();
        b.put(0x2000, &[0x90; 4]);
        // (Codes are in reverse order: the allocation came after the
        // frame was pushed.)
        b.info(
            0x3000,
            V1 | EHANDLER,
            0,
            0,
            &[(0, ALLOC_SMALL, 1), (0, PUSH_MACHFRAME, error_code)],
            &0x2800u32.to_le_bytes(),
        );
        let f = b.function(0x2000, 0x2004, 0x3000);
        let rsp = STACK + 0x100;
        let frame_at = rsp + 16 + 8 * u64::from(error_code);
        let mut s = Stack::new();
        s.set(frame_at, RETURN);
        s.set(frame_at + 24, STACK + 0x1F0);
        let mut c = context(0x2002, rsp);
        let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
        assert!(frame.machine_frame);
        assert_eq!((c.rip, c.rsp()), (RETURN, STACK + 0x1F0));
        // (The handler is still returned.)
        assert!(frame.handler.is_some());
    }
}

#[test]
fn version_2_lists_its_epilogs() {
    // push rbx; sub rsp, 20h; <body>; add rsp, 20h; [pop rbx; ret], the
    // bracketed epilog listed (2 bytes, at the end).
    let mut b = Builder::new();
    let code = [
        0x53, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3,
    ];
    b.put(0x2000, &code);
    b.info(
        0x3000,
        V2,
        5,
        0,
        &[
            (2, EPILOG, 1),
            (0, EPILOG, 0),
            (5, ALLOC_SMALL, 3),
            (1, PUSH_NONVOL, reg::RBX as u8),
        ],
        &[],
    );
    let f = b.function(0x2000, 0x200C, 0x3000);
    let rsp = STACK + 0x100;
    let mut s = Stack::new();
    s.set(rsp + 0x20, 0xB0B0);
    s.set(rsp + 0x28, RETURN);
    // `add rsp` isn't in the listed epilog: the body.
    let mut c = context(0x2006, rsp);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Body);
    assert_eq!(
        (c.rip, c.gpr[reg::RBX], c.rsp()),
        (RETURN, 0xB0B0, rsp + 0x30)
    );
    // `pop rbx` is.
    let mut c = context(0x200A, rsp + 0x20);
    let frame = windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(frame.position, Position::Epilog);
    assert_eq!(
        (c.rip, c.gpr[reg::RBX], c.rsp()),
        (RETURN, 0xB0B0, rsp + 0x30)
    );
}

#[test]
fn large_allocations() {
    // ALLOC_LARGE with a 16-bit size (× 8) and a 32-bit one.
    for (codes, size) in [
        (&[(4u8, ALLOC_LARGE, 0u8), (0x20, 0, RAW)][..], 0x100u64),
        (&[(4, ALLOC_LARGE, 1), (0x48, 0, RAW), (0, 0, RAW)], 0x48),
    ] {
        let mut b = Builder::new();
        b.put(0x2000, &[0x90; 8]);
        b.info(0x3000, V1, 4, 0, codes, &[]);
        let f = b.function(0x2000, 0x2008, 0x3000);
        let mut s = Stack::new();
        s.set(STACK + 0x10 + size, RETURN);
        let mut c = context(0x2006, STACK + 0x10);
        windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
        assert_eq!((c.rip, c.rsp()), (RETURN, STACK + 0x18 + size));
    }
}

#[test]
fn malformed_unwind_data() {
    let mut s = Stack::new();
    s.set(STACK + 0x100, RETURN);
    let run = |b: &Builder, f| {
        let mut c = context(0x2001, STACK + 0x100);
        windows_x64::unwind(b.image(), BASE, f, &mut c, &s)
    };
    // Versions 0 and 3+.
    for version in [0u8, 3, 7] {
        let mut b = Builder::new();
        b.info(0x3000, version, 0, 0, &[(0, ALLOC_SMALL, 0)], &[]);
        let f = b.function(0x2000, 0x2004, 0x3000);
        assert_eq!(run(&b, f), Err(Error::UnwindData { rva: 0x3000 }));
    }
    // An unknown operation (7).
    let mut b = Builder::new();
    b.info(0x3000, V1, 0, 0, &[(0, 7, 0)], &[]);
    let f = b.function(0x2000, 0x2004, 0x3000);
    assert_eq!(run(&b, f), Err(Error::UnwindData { rva: 0x3000 }));
    // Codes running off the image.
    let mut b = Builder::new();
    b.put(0x3FFC, &[V1, 0, 200, 0]);
    let f = b.function(0x2000, 0x2004, 0x3FFC);
    assert_eq!(run(&b, f), Err(Error::UnwindData { rva: 0x3FFC }));
    // Unwind information outside the image.
    let mut b = Builder::new();
    let f = b.function(0x2000, 0x2004, 0xFFFF_FFF0);
    assert_eq!(run(&b, f), Err(Error::UnwindData { rva: 0xFFFF_FFF0 }));
    // A handler RVA missing from the end of the image.
    let mut b = Builder::new();
    b.put(0x3FFC, &[V1 | EHANDLER, 0, 0, 0]);
    let f = b.function(0x2000, 0x2004, 0x3FFC);
    assert_eq!(run(&b, f), Err(Error::UnwindData { rva: 0x4000 }));
    // A chain that loops.
    let mut b = Builder::new();
    b.info(
        0x3000,
        V1 | CHAININFO,
        0,
        0,
        &[],
        &chain_to(0x2000, 0x2004, 0x3000),
    );
    let f = b.function(0x2000, 0x2004, 0x3000);
    assert_eq!(run(&b, f), Err(Error::ChainTooDeep));
    // A multi-slot code missing its slots ends the codes.
    let mut b = Builder::new();
    b.put(0x2000, &[0x90; 4]);
    b.info(0x3000, V1, 0, 0, &[(0, ALLOC_LARGE, 1)], &[]);
    let f = b.function(0x2000, 0x2004, 0x3000);
    let mut c = context(0x2001, STACK + 0x100);
    windows_x64::unwind(b.image(), BASE, f, &mut c, &s).unwrap();
    assert_eq!(c.rip, RETURN);
    // A PC outside the image's address space.
    let (b, f) = pushes();
    let mut c = context(0, STACK + 0x100);
    c.rip = 0x10;
    assert!(windows_x64::unwind(b.image(), BASE, f, &mut c, &s).is_ok());
}

#[test]
fn unavailable_memory() {
    let (b, f) = pushes();
    let s = Stack::new();
    let mut c = context(0x2007, 0x9999_0000);
    assert_eq!(
        windows_x64::unwind(b.image(), BASE, f, &mut c, &s),
        Err(Error::Memory {
            address: 0x9999_0028
        })
    );
    let mut c = context(0x2007, u64::MAX - 4);
    assert!(matches!(
        windows_x64::unwind(b.image(), BASE, f, &mut c, &s),
        Err(Error::Memory { .. })
    ));
    let mut c = context(0x2000, 0x10);
    assert_eq!(
        windows_x64::unwind_leaf(&mut c, &s),
        Err(Error::Memory { address: 0x10 })
    );
}

#[test]
fn lookup() {
    let mut b = Builder::new();
    let f1 = b.function(0x2000, 0x2010, 0x3000);
    let f2 = b.function(0x2010, 0x2020, 0x3010);
    let f3 = b.function(0x2040, 0x2050, 0x3020);
    // An indirect entry, giving f1's.
    b.function(0x2060, 0x2070, PDATA | 1);
    let (table, size) = (PDATA, b.entries * 12);
    let find = |rva| windows_x64::lookup(b.image(), table, size, rva);
    assert_eq!(find(0x2000), Some(f1));
    assert_eq!(find(0x200F), Some(f1));
    assert_eq!(find(0x2010), Some(f2));
    assert_eq!(find(0x204F), Some(f3));
    assert_eq!(find(0x2065), Some(f1));
    for rva in [0, 0x1FFF, 0x2020, 0x203F, 0x2050, 0x2070, u32::MAX] {
        assert_eq!(find(rva), None, "{rva:#x}");
    }
    // An empty table, and tables running off the image.
    assert_eq!(windows_x64::lookup(b.image(), table, 0, 0x2000), None);
    assert_eq!(windows_x64::lookup(b.image(), 0x3FF8, 24, 0x2000), None);
    assert_eq!(
        windows_x64::lookup(b.image(), u32::MAX - 4, u32::MAX, 0x2000),
        None
    );
}

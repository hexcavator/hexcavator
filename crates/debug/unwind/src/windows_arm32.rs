//! Windows ARM (Thumb-2) unwinding: `.pdata` entries (packed unwind data,
//! or an `.xdata` record's unwind codes), following Microsoft's "ARM
//! exception handling" documentation.
//!
//! Each unwind code stands for one prolog or epilog instruction, 16 or 32
//! bits wide, so a PC's byte offset into a prolog or epilog says which
//! codes still apply:
//!
//! - **the prolog**: its codes are stored in reverse; those for the
//!   instructions that haven't run are skipped;
//! - **an epilog** (listed in `.xdata`, or at the end of the function): its
//!   codes are in execution order; those already run are skipped. An `end`
//!   of `0xFD`/`0xFE` stands for a final 16/32-bit branch (`bx lr`, a tail
//!   call). A conditional epilog applies only when its condition holds;
//! - **the body**: every prolog code applies.
//!
//! Then PC is LR. Packed unwind data is expanded into the canonical prolog
//! and epilog it stands for.
//!
//! The specification is Microsoft's "ARM exception handling" document.
//! `tests/windows_arm32_code.rs` checks it, and this module, against real code
//! (296 ARM32 images from NuGet packages: .NET, WinUI 2, Win2D, ONNX
//! Runtime, SQLite; 307,670 functions):
//!
//! - each prolog and epilog instruction the unwind data describes
//!   ([`describe`]) is matched with the one in the image, size included
//!   (1.06M instructions);
//! - each function's prolog and epilogs are emulated on a synthetic
//!   stack, and at every instruction boundary [`unwind`] must give back
//!   the caller's SP, return address, r4-r11, and d8-d15 (1.36M
//!   boundaries).
//!
//! What the doc leaves open, as the code shows it:
//!
//! - Packed R=0 with Reg=7 saves r4-r11, as the doc's table says (its
//!   Example 7, `push {lr}`, has R=1).
//! - Packed pushes and pops are 16-bit when their registers allow (r0-r7,
//!   with LR for a push or PC for a pop), else 32-bit; allocations above
//!   508 bytes are 32-bit.
//! - An E epilog (one packed into the `.xdata` header) is at the end of
//!   its function.
//!
//! The test also accepts what the codes describe by its effect:
//! `__security_push_cookie`/`__security_pop_cookie` calls for a 32-bit
//! 4-byte `sub`/`add sp`, `sub.w sp, sp, rN` after `__chkstk`, and homing
//! some of r0-r3 for a `sub sp`. Microsoft's toolchain sometimes (655
//! functions) describes as the E epilog an earlier tail-call epilog, the
//! function ending in a one-instruction `pop {..., pc}`: such data unwinds
//! wrongly in both, here as by the doc.
//!
//! Not checked against `RtlVirtualUnwind`: no Windows still runs ARM32
//! code. Unverified details: the establisher frame (here, the caller's SP),
//! and that PC drops LR's Thumb bit (setting CPSR's T bit instead), as a
//! Windows `CONTEXT` holds it. The Microsoft-specific codes (`0xEE 0x00` to
//! `0xEE 0x0F`) aren't documented and are unsupported.

use alloc::vec::Vec;

use crate::{Error, Image, Memory, Result};

/// Register numbers: r0..r12, then sp (13), lr (14), pc (15).
pub mod reg {
    pub const R11: usize = 11;
    pub const SP: usize = 13;
    pub const LR: usize = 14;
    pub const PC: usize = 15;
}

/// CPSR's Thumb state bit.
pub const CPSR_T: u32 = 1 << 5;

/// The registers an unwind reads and writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// r0..r12, sp, lr, pc.
    pub r: [u32; 16],
    /// d0..d31.
    pub d: [u64; 32],
    /// The condition flags decide whether a conditional epilog runs.
    pub cpsr: u32,
}

/// A `.pdata` entry: the function's start RVA (its low bit set for Thumb
/// code) and its unwind word (packed unwind data, or an `.xdata` RVA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub unwind: u32,
}

impl RuntimeFunction {
    /// The function's first byte (without the Thumb bit).
    pub fn start(&self) -> u32 {
        self.begin & !1
    }

    /// The function's length in bytes, from its packed data or `.xdata`.
    pub fn length(&self, image: &(impl Image + ?Sized)) -> Option<u32> {
        match self.unwind & 3 {
            0 => Some((word(image, self.unwind)? & 0x3_FFFF) * 2),
            1 | 2 => Some(((self.unwind >> 2) & 0x7FF) * 2),
            _ => None,
        }
    }
}

fn word(image: &(impl Image + ?Sized), rva: u32) -> Option<u32> {
    let b = image.bytes(rva, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The `.pdata` entry for the code at `rva`: the last one starting at or
/// before it, if `rva` is within its length.
pub fn lookup(
    image: &(impl Image + ?Sized),
    table_rva: u32,
    table_size: u32,
    rva: u32,
) -> Option<RuntimeFunction> {
    let count = table_size / 8;
    let entry = |i: u32| -> Option<RuntimeFunction> {
        let at = table_rva.checked_add(i.checked_mul(8)?)?;
        Some(RuntimeFunction {
            begin: word(image, at)?,
            unwind: word(image, at.checked_add(4)?)?,
        })
    };
    let (mut lo, mut hi) = (0u32, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entry(mid)?.start() <= rva {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let f = entry(lo.checked_sub(1)?)?;
    (rva - f.start() < f.length(image)?).then_some(f)
}

/// Where in its function a frame's PC was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// In the prolog, after this many of its instructions.
    Prolog(u32),
    Body,
    /// In an epilog, after this many of its instructions.
    Epilog(u32),
}

/// A language-specific handler the frame's `.xdata` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler {
    pub routine: u32,
    /// The RVA of its data.
    pub data: u32,
}

/// What an unwind found out about the frame it unwound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub position: Position,
    /// The caller's SP (see the module notes).
    pub establisher_frame: u32,
    pub handler: Option<Handler>,
    /// Where each restored integer register (r0..lr) was read from.
    pub saved_r: [Option<u32>; 15],
    /// Where each restored d register was read from.
    pub saved_d: [Option<u32>; 32],
}

impl Frame {
    fn new() -> Self {
        Frame {
            position: Position::Body,
            establisher_frame: 0,
            handler: None,
            saved_r: [None; 15],
            saved_d: [None; 32],
        }
    }
}

/// A prolog or epilog instruction, by what undoing (or, in an epilog,
/// finishing) it does; `wide` for a 32-bit instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `add sp, sp, #bytes` (undoing a `sub`, or `push {r0-r3}` homing).
    Alloc { bytes: u32, wide: bool },
    /// `pop` of these registers (bit n for rn; bit 14, LR, stands for PC
    /// too where an epilog returns with it), lowest at the lowest address.
    Pop { regs: u16, wide: bool },
    /// `mov sp, rN`.
    MovSp(u8),
    /// `vpop {dFirst-dLast}` (32 bits).
    Vpop { first: u8, last: u8 },
    /// `ldr lr, [sp], #bytes` (32 bits; `ldr pc` in an epilog).
    LdrLr(u32),
    /// An instruction with nothing to undo.
    Nop { wide: bool },
    /// The end of the codes; in an epilog, `Some(wide)` stands for one more
    /// (branch) instruction.
    End(Option<bool>),
}

impl Op {
    /// The size in bytes of the instruction the code stands for (not
    /// counting an epilog's final branch).
    pub fn size(self) -> u32 {
        match self {
            Op::Alloc { wide, .. } | Op::Pop { wide, .. } | Op::Nop { wide } => {
                if wide {
                    4
                } else {
                    2
                }
            }
            Op::MovSp(_) => 2,
            Op::Vpop { .. } | Op::LdrLr(_) => 4,
            Op::End(_) => 0,
        }
    }

    /// The size of the instruction(s) the code stands for in an epilog.
    fn epilog_size(self) -> u32 {
        match self {
            Op::End(Some(true)) => 4,
            Op::End(Some(false)) => 2,
            _ => self.size(),
        }
    }
}

/// The length in bytes of the unwind code starting with `first`.
fn code_len(first: u8) -> usize {
    match first {
        0x80..=0xBF | 0xE8..=0xEF | 0xF5 | 0xF6 => 2,
        0xF7 | 0xF9 => 3,
        0xF8 | 0xFA => 4,
        _ => 1,
    }
}

/// Decodes unwind codes from byte `index`, up to and including the first
/// `end`.
fn decode(codes: &[u8], index: usize, rva: u32) -> Result<Vec<Op>> {
    let bad = Error::UnwindData { rva };
    let mut ops = Vec::new();
    let mut i = index;
    loop {
        let c = *codes.get(i).ok_or(bad)?;
        let b = codes.get(i..i + code_len(c)).ok_or(bad)?;
        i += b.len();
        let be = |n: usize| b[1..=n].iter().fold(0u32, |a, &x| a << 8 | u32::from(x));
        let op = match c {
            0x00..=0x7F => Op::Alloc {
                bytes: u32::from(c) * 4,
                wide: false,
            },
            0x80..=0xBF => {
                let v = u16::from_be_bytes([b[0], b[1]]);
                // (Bit 13 is LR, at register 14.)
                Op::Pop {
                    regs: v & 0x1FFF | (v & 0x2000) << 1,
                    wide: true,
                }
            }
            0xC0..=0xCF => Op::MovSp(c & 0xF),
            0xD0..=0xDF => {
                let last = (c & 3) + if c < 0xD8 { 4 } else { 8 };
                let low = (1u16 << (last + 1)) - (1 << 4);
                Op::Pop {
                    regs: low | if c & 4 != 0 { 1 << 14 } else { 0 },
                    wide: c >= 0xD8,
                }
            }
            0xE0..=0xE7 => Op::Vpop {
                first: 8,
                last: (c & 7) + 8,
            },
            0xE8..=0xEB => Op::Alloc {
                bytes: (u32::from(c & 3) << 8 | u32::from(b[1])) * 4,
                wide: true,
            },
            0xEC | 0xED => Op::Pop {
                regs: u16::from(b[1]) | if c & 1 != 0 { 1 << 14 } else { 0 },
                wide: false,
            },
            0xEE if b[1] < 0x10 => return Err(Error::Unsupported { rva }),
            0xEF if b[1] < 0x10 => Op::LdrLr(u32::from(b[1]) * 4),
            0xF5 | 0xF6 => {
                let base = if c == 0xF6 { 16 } else { 0 };
                let (first, last) = ((b[1] >> 4) + base, (b[1] & 0xF) + base);
                if first > last {
                    return Err(bad);
                }
                Op::Vpop { first, last }
            }
            0xF7 | 0xF8 => Op::Alloc {
                bytes: be(b.len() - 1).checked_mul(4).ok_or(bad)?,
                wide: false,
            },
            0xF9 | 0xFA => Op::Alloc {
                bytes: be(b.len() - 1).checked_mul(4).ok_or(bad)?,
                wide: true,
            },
            0xFB => Op::Nop { wide: false },
            0xFC => Op::Nop { wide: true },
            0xFD => Op::End(Some(false)),
            0xFE => Op::End(Some(true)),
            0xFF => Op::End(None),
            // (`0xEE`/`0xEF` with 0x10 and up, and 0xF0..0xF4: unassigned.)
            _ => return Err(bad),
        };
        ops.push(op);
        if let Op::End(_) = op {
            return Ok(ops);
        }
    }
}

/// Packed unwind data (`.pdata` flag 1 or 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Packed {
    /// Flag 2: no prolog.
    fragment: bool,
    length: u32,
    ret: u32,
    h: bool,
    reg: u32,
    r: bool,
    l: bool,
    c: bool,
    stack_adjust: u32,
}

impl Packed {
    fn decode(w: u32) -> Option<Self> {
        let p = Packed {
            fragment: w & 3 == 2,
            length: ((w >> 2) & 0x7FF) * 2,
            ret: (w >> 13) & 3,
            h: (w >> 15) & 1 != 0,
            reg: (w >> 16) & 7,
            r: (w >> 19) & 1 != 0,
            l: (w >> 20) & 1 != 0,
            c: (w >> 21) & 1 != 0,
            stack_adjust: w >> 22,
        };
        // (Frame chaining needs LR; so does returning with `pop {pc}`.)
        if w & 3 == 3 || p.c && !p.l || p.ret == 0 && !p.l {
            return None;
        }
        Some(p)
    }

    fn folded(&self) -> bool {
        self.stack_adjust >= 0x3F4
    }

    /// Prolog folding, epilog folding.
    fn pf(&self) -> bool {
        self.folded() && self.stack_adjust & 4 != 0
    }

    fn ef(&self) -> bool {
        self.folded() && self.stack_adjust & 8 != 0
    }

    /// The stack adjustment in bytes.
    fn adjust(&self) -> u32 {
        if self.folded() {
            ((self.stack_adjust & 3) + 1) * 4
        } else {
            self.stack_adjust * 4
        }
    }

    /// The integer registers pushed (folding as `fold` says), LR included.
    fn pushed(&self, fold: bool) -> u16 {
        let mut regs = 0u16;
        // (Folding pushes r(S)..r3 to adjust the stack too.)
        let s = (!self.stack_adjust) & 3;
        let first = if fold { s } else { 4 };
        let last = if self.r { 3 } else { self.reg + 4 };
        if first <= last && (fold || !self.r) {
            regs |= (((1u32 << (last + 1)) - (1u32 << first)) & 0x1FFF) as u16;
        }
        if self.c {
            regs |= 1 << reg::R11;
        }
        if self.l {
            regs |= 1 << reg::LR;
        }
        regs
    }

    fn alloc(bytes: u32) -> Op {
        Op::Alloc {
            bytes,
            // (`sub sp, sp, #imm7*4` reaches 508.)
            wide: bytes > 508,
        }
    }

    /// The prolog and the epilog, in execution order (the epilog ending
    /// with `End`, which stands for its branch if it has one).
    #[allow(clippy::cast_possible_truncation)] // (`reg` is 3 bits.)
    fn expand(&self) -> (Vec<Op>, Vec<Op>) {
        let mut prolog = Vec::new();
        if self.h {
            prolog.push(Op::Alloc {
                bytes: 16,
                wide: false,
            });
        }
        let pf = self.pf();
        if self.c || self.l || !self.r || pf {
            let regs = self.pushed(pf);
            prolog.push(Op::Pop {
                regs,
                wide: regs & !(0xFF | 1 << reg::LR) != 0,
            });
        }
        if self.c {
            // `mov r11, sp` when only r11 and LR are pushed, else
            // `add r11, sp, #n`.
            prolog.push(Op::Nop {
                wide: !self.r || pf,
            });
        }
        if self.r && self.reg != 7 {
            prolog.push(Op::Vpop {
                first: 8,
                last: (self.reg + 8) as u8,
            });
        }
        if self.stack_adjust != 0 && !pf {
            prolog.push(Self::alloc(self.adjust()));
        }

        let mut epilog = Vec::new();
        let ef = self.ef();
        if self.stack_adjust != 0 && !ef {
            epilog.push(Self::alloc(self.adjust()));
        }
        if self.r && self.reg != 7 {
            epilog.push(Op::Vpop {
                first: 8,
                last: (self.reg + 8) as u8,
            });
        }
        if self.c || self.l && (!self.h || self.ret != 0) || !self.r || ef {
            let mut regs = self.pushed(ef);
            // With `Ret` 0, LR is popped as PC (here, or by `ldr pc`
            // after the homing area).
            if self.ret == 0 && self.h {
                regs &= !(1 << reg::LR);
            }
            let pc = self.ret == 0 && !self.h;
            let narrow = regs & !(0xFF | if pc { 1 << reg::LR } else { 0 }) == 0;
            epilog.push(Op::Pop {
                regs,
                wide: !narrow,
            });
        }
        if self.h {
            if self.l && self.ret == 0 {
                epilog.push(Op::LdrLr(0x14));
            } else {
                epilog.push(Op::Alloc {
                    bytes: 16,
                    wide: false,
                });
            }
        }
        epilog.push(Op::End(match self.ret {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        }));
        (prolog, epilog)
    }
}

/// An epilog, as unwind data describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epilog {
    /// Its offset from the function start, in bytes.
    pub start: u32,
    /// The condition it runs under (0xE: always).
    pub condition: u8,
    /// Its instructions in execution order, ending with `End` (standing for
    /// a final branch if it has one).
    pub ops: Vec<Op>,
}

impl Epilog {
    /// Its length in bytes.
    pub fn len(&self) -> u32 {
        self.ops.iter().map(|o| o.epilog_size()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A function's unwind data, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    /// The prolog's instructions in execution order (without `End`), or
    /// for a fragment, the pseudo-prolog that unwinds its body.
    pub prolog: Vec<Op>,
    /// Whether the function has no prolog of its own (a fragment).
    pub fragment: bool,
    pub epilogs: Vec<Epilog>,
    pub handler: Option<Handler>,
    /// The function's length in bytes.
    pub length: u32,
}

impl Description {
    /// The prolog's length in bytes (0 for a fragment).
    pub fn prolog_len(&self) -> u32 {
        if self.fragment {
            0
        } else {
            self.prolog.iter().map(|o| o.size()).sum()
        }
    }
}

/// The most epilog scopes read from one `.xdata` record (hostile data).
const MAX_EPILOGS: u32 = 4096;

/// `function`'s prolog and epilogs, by its unwind data.
pub fn describe(image: &(impl Image + ?Sized), function: RuntimeFunction) -> Result<Description> {
    match function.unwind & 3 {
        0 => describe_xdata(image, function.unwind),
        1 | 2 => {
            let p = Packed::decode(function.unwind).ok_or(Error::UnwindData {
                rva: function.start(),
            })?;
            let (prolog, ops) = p.expand();
            let mut epilogs = Vec::new();
            if p.ret != 3 {
                let mut e = Epilog {
                    start: 0,
                    condition: 0xE,
                    ops,
                };
                e.start = p.length.wrapping_sub(e.len());
                epilogs.push(e);
            }
            Ok(Description {
                prolog,
                fragment: p.fragment,
                epilogs,
                handler: None,
                length: p.length,
            })
        }
        _ => Err(Error::UnwindData {
            rva: function.start(),
        }),
    }
}

fn describe_xdata(image: &(impl Image + ?Sized), rva: u32) -> Result<Description> {
    let bad = Error::UnwindData { rva };
    let first = word(image, rva).ok_or(bad)?;
    if (first >> 18) & 3 != 0 {
        return Err(Error::Unsupported { rva });
    }
    let mut epilog_count = (first >> 23) & 0x1F;
    let mut code_words = first >> 28;
    let mut header = 4u32;
    if epilog_count == 0 && code_words == 0 {
        let second = word(image, rva.checked_add(4).ok_or(bad)?).ok_or(bad)?;
        epilog_count = second & 0xFFFF;
        code_words = (second >> 16) & 0xFF;
        header = 8;
    }
    let x = (first >> 20) & 1 != 0;
    let e = (first >> 21) & 1 != 0;
    let fragment = (first >> 22) & 1 != 0;
    let length = (first & 0x3_FFFF) * 2;
    if !e && epilog_count > MAX_EPILOGS {
        return Err(bad);
    }
    let scopes_len = if e { 0 } else { epilog_count * 4 };
    let scopes_rva = rva.checked_add(header).ok_or(bad)?;
    let scopes = image.bytes(scopes_rva, scopes_len).ok_or(bad)?;
    let codes_rva = scopes_rva.checked_add(scopes_len).ok_or(bad)?;
    let codes = image.bytes(codes_rva, code_words * 4).ok_or(bad)?;
    let handler = if x {
        let at = codes_rva.checked_add(code_words * 4).ok_or(bad)?;
        Some(Handler {
            routine: word(image, at).ok_or(bad)?,
            data: at.wrapping_add(4),
        })
    } else {
        None
    };

    // (An index inside a code: the unwind data is malformed.)
    let is_code_start = |index: usize| {
        let mut i = 0;
        while i < index && i < codes.len() {
            i += code_len(codes[i]);
        }
        i == index
    };
    let mut prolog = decode(codes, 0, rva)?;
    prolog.pop();
    prolog.reverse();
    let mut epilogs = Vec::new();
    if e {
        let index = epilog_count as usize;
        if !is_code_start(index) {
            return Err(bad);
        }
        let mut ep = Epilog {
            start: 0,
            condition: 0xE,
            ops: decode(codes, index, rva)?,
        };
        ep.start = length.wrapping_sub(ep.len());
        epilogs.push(ep);
    } else {
        for s in scopes.as_chunks::<4>().0 {
            let w = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
            let index = (w >> 24) as usize;
            if !is_code_start(index) {
                return Err(bad);
            }
            epilogs.push(Epilog {
                start: (w & 0x3_FFFF) * 2,
                condition: ((w >> 20) & 0xF) as u8,
                ops: decode(codes, index, rva)?,
            });
        }
    }
    Ok(Description {
        prolog,
        fragment,
        epilogs,
        handler,
        length,
    })
}

/// Whether condition `cond` holds for CPSR's flags.
fn condition_holds(cond: u8, cpsr: u32) -> bool {
    let (n, z, c, v) = (
        cpsr >> 31 & 1 != 0,
        cpsr >> 30 & 1 != 0,
        cpsr >> 29 & 1 != 0,
        cpsr >> 28 & 1 != 0,
    );
    match cond {
        0x0 => z,
        0x1 => !z,
        0x2 => c,
        0x3 => !c,
        0x4 => n,
        0x5 => !n,
        0x6 => v,
        0x7 => !v,
        0x8 => c && !z,
        0x9 => !c || z,
        0xA => n == v,
        0xB => n != v,
        0xC => !z && n == v,
        0xD => z || n != v,
        _ => true,
    }
}

/// Unwinds a leaf frame (code with no `.pdata` entry): the return address
/// is in LR.
pub fn unwind_leaf(context: &mut Context) -> Frame {
    set_pc_from_lr(context);
    let mut frame = Frame::new();
    frame.establisher_frame = context.r[reg::SP];
    frame
}

fn set_pc_from_lr(context: &mut Context) {
    let lr = context.r[reg::LR];
    context.r[reg::PC] = lr & !1;
    if lr & 1 != 0 {
        context.cpsr |= CPSR_T;
    } else {
        context.cpsr &= !CPSR_T;
    }
}

/// Unwinds the frame whose code is described by `function`, in an image
/// loaded at `image_base`: `context` becomes the caller's.
pub fn unwind(
    image: &(impl Image + ?Sized),
    image_base: u32,
    function: RuntimeFunction,
    context: &mut Context,
    memory: &dyn Memory,
) -> Result<Frame> {
    let d = describe(image, function)?;
    let pc_rva = context.r[reg::PC].wrapping_sub(image_base) & !1;
    let offset = pc_rva.wrapping_sub(function.start());
    let mut frame = Frame::new();
    frame.handler = d.handler;

    // The codes to apply, in order.
    let ops: Vec<Op> = if let Some(e) = d.epilogs.iter().find(|e| {
        offset.wrapping_sub(e.start) < e.len() && condition_holds(e.condition, context.cpsr)
    }) {
        // (Wrapping as in the test: a hostile length can put an epilog's
        // start "before" the function.)
        let done = offset.wrapping_sub(e.start);
        let (n, rest) = skip(&e.ops, done, Op::epilog_size);
        frame.position = Position::Epilog(n);
        frame.handler = None;
        rest.to_vec()
    } else if offset < d.prolog_len() {
        // The prolog's instructions from `offset` on haven't run.
        let mut codes = d.prolog.clone();
        codes.reverse();
        let (_, rest) = skip(&codes, d.prolog_len() - offset, Op::size);
        // (What remains are the codes of the instructions that ran.)
        let ran = rest.len();
        frame.position = Position::Prolog(u32::try_from(ran).unwrap_or(u32::MAX));
        frame.handler = None;
        rest.to_vec()
    } else {
        let mut codes = d.prolog;
        codes.reverse();
        codes
    };

    for op in ops {
        undo(op, context, memory, &mut frame)?;
    }
    set_pc_from_lr(context);
    frame.establisher_frame = context.r[reg::SP];
    Ok(frame)
}

/// `ops` without the instructions in its first `bytes` bytes (an
/// instruction partly in them counts as not run), and how many were
/// skipped.
fn skip(ops: &[Op], bytes: u32, size: fn(Op) -> u32) -> (u32, &[Op]) {
    let mut i = 0;
    let mut done = 0;
    while done < bytes && i < ops.len() && !matches!(ops[i], Op::End(_)) {
        let s = size(ops[i]);
        if done + s > bytes {
            break;
        }
        done += s;
        i += 1;
    }
    (u32::try_from(i).unwrap_or(u32::MAX), &ops[i..])
}

fn read_u32(memory: &dyn Memory, address: u32) -> Result<u32> {
    let mut b = [0u8; 4];
    if memory.read(u64::from(address), &mut b) {
        Ok(u32::from_le_bytes(b))
    } else {
        Err(Error::Memory {
            address: u64::from(address),
        })
    }
}

fn undo(op: Op, context: &mut Context, memory: &dyn Memory, frame: &mut Frame) -> Result<()> {
    let sp = context.r[reg::SP];
    match op {
        Op::Alloc { bytes, .. } => context.r[reg::SP] = sp.wrapping_add(bytes),
        Op::Pop { regs, .. } => {
            let mut at = sp;
            for n in 0..15 {
                if regs & (1 << n) != 0 {
                    context.r[n] = read_u32(memory, at)?;
                    frame.saved_r[n] = Some(at);
                    at = at.wrapping_add(4);
                }
            }
            context.r[reg::SP] = at;
        }
        Op::MovSp(n) => {
            if usize::from(n) == reg::PC {
                return Err(Error::Register {
                    register: u16::from(n),
                });
            }
            context.r[reg::SP] = context.r[usize::from(n)];
        }
        Op::Vpop { first, last } => {
            let mut at = sp;
            for n in first..=last {
                let lo = read_u32(memory, at)?;
                let hi = read_u32(memory, at.wrapping_add(4))?;
                context.d[usize::from(n)] = u64::from(hi) << 32 | u64::from(lo);
                frame.saved_d[usize::from(n)] = Some(at);
                at = at.wrapping_add(8);
            }
            context.r[reg::SP] = at;
        }
        Op::LdrLr(bytes) => {
            let at = sp;
            context.r[reg::LR] = read_u32(memory, at)?;
            frame.saved_r[reg::LR] = Some(at);
            context.r[reg::SP] = at.wrapping_add(bytes);
        }
        Op::Nop { .. } | Op::End(_) => {}
    }
    Ok(())
}

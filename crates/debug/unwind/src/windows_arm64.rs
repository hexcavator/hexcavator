//! Windows ARM64 unwinding: `.pdata` entries (packed unwind data, or an
//! `.xdata` record's unwind codes), following Microsoft's "ARM64
//! exception handling" documentation.
//!
//! Each unwind code describes one prolog instruction, in reverse order;
//! epilogs reuse them in execution order (`end` standing for the `ret`).
//! A frame's PC is in:
//!
//! - **the prolog** (its first instructions): only the codes for the
//!   instructions that have run are undone;
//! - **an epilog** (listed in `.xdata`, or at the end of a packed
//!   function): the codes for its remaining instructions are undone;
//! - **the body**: every prolog code is undone.
//!
//! Then PC is LR (or what a machine frame or context gave). Packed unwind
//! data is expanded into the canonical prolog and epilog it stands for.
//!
//! An `end_c` ends a scope's codes; those after it are a chained scope's,
//! whose prolog has always run. An epilog whose codes reach an `end_c`
//! has no `ret` of its own (its function continues in another fragment),
//! and an epilog may begin in one fragment and end in another.
//!
//! The specification is Microsoft's "ARM64 exception handling" document.
//! `tests/windows_arm64_code.rs` checks it, and this module, against real code:
//! for every function in the ARM64 images of a Visual Studio and Windows
//! SDK install (14,735 images, 840,648 functions, 6.2M instructions), each
//! prolog and epilog instruction the unwind data describes ([`describe`])
//! is encoded and compared with the one there; and the same over the ARM64
//! Windows 11 24H2 binaries in its update packages (2,135 images, 1.79M
//! functions, 14.8M instructions). Link records (`Flag` 3: jump islands)
//! unwind as the body of the record they link to. Where code and the doc
//! differ, the code was followed:
//!
//! - Packed CR=01 with RegI=1 is `sub sp, sp, #savsz; stp x19, lr, [sp]`,
//!   two instructions (as dumpbin shows it), not one merged `stp`.
//! - Packed Flag=2 code has no epilog as well as no prolog.
//! - With no registers saved, the first homing store allocates the area
//!   (`stp x0, x1, [sp, #-savsz]!`); `.xdata` allocations can likewise be
//!   a pre-indexed store (or, in an epilog, a post-indexed load) of
//!   registers the codes don't describe.
//! - An epilog's `end` can be a call that doesn't return.
//! - An E epilog sits at the end of its function.
//! - An epilog's `set_fp` may be an `add sp, sp, #n` that comes to the same,
//!   or have no instruction where SP is already FP.
//!
//! Inconsistent unwind data is rejected where it can be seen (an epilog
//! start index inside a code); the test also lists functions whose data
//! doesn't match their code (some from Microsoft's own toolchain).
//!
//! Not yet checked against `RtlVirtualUnwind` (`tests/windows_arm64_rtl.rs` does
//! that, on an ARM64 machine). Unverified details: what the establisher
//! frame is (here, the caller's SP); the machine frame's layout (SP, then
//! PC); the ARM64EC context's register mapping; and how signed return
//! addresses are stripped. SVE (`alloc_z`, `save_zreg`, `save_preg`) and
//! kernel trap frames are unsupported.

use alloc::vec::Vec;

use hexcavator_pe::exception::{Arm64PackedUnwind, Arm64UnwindCode};

use crate::{Error, Image, Memory, Result, read_u64, read_u128};

/// Register numbers: x0..x28, then fp (29) and lr (30).
pub mod reg {
    pub const X19: usize = 19;
    pub const FP: usize = 29;
    pub const LR: usize = 30;
}

/// The registers an unwind reads and writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub pc: u64,
    pub sp: u64,
    /// x0..x28, fp, lr.
    pub x: [u64; 31],
    /// v0..v31 (d8..d15 are the low halves of v8..v15).
    pub v: [u128; 32],
    /// Restored only by a context.
    pub cpsr: u32,
}

/// A `.pdata` entry: the function's start RVA and its unwind word (packed
/// unwind data, or an `.xdata` RVA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub unwind: u32,
}

impl RuntimeFunction {
    /// Whether this is a link record (`Flag` 3): a jump island, whose
    /// unwinding is its parent's (see [`resolve`]).
    pub fn is_link(&self) -> bool {
        self.unwind & 3 == 3
    }

    /// The function's length in bytes, from its packed data or `.xdata`
    /// (`None` for a link record, whose island's length isn't recorded).
    pub fn length(&self, image: &(impl Image + ?Sized)) -> Option<u32> {
        match self.unwind & 3 {
            0 => {
                let b = image.bytes(self.unwind, 4)?;
                Some((u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x3_FFFF) * 4)
            }
            1 | 2 => Some(((self.unwind >> 2) & 0x7FF) * 4),
            _ => None,
        }
    }
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
        let b = image.bytes(table_rva.checked_add(i.checked_mul(8)?)?, 8)?;
        Some(RuntimeFunction {
            begin: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            unwind: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    };
    // The first entry starting after `rva`.
    let (mut lo, mut hi) = (0u32, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entry(mid)?.begin <= rva {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let i = lo.checked_sub(1)?;
    let f = entry(i)?;
    match f.length(image) {
        Some(len) => (rva - f.begin < len).then_some(f),
        // (A link record's island runs to the next entry, as far as it can
        // be told.)
        None if f.is_link() => (i + 1 >= count || rva < entry(i + 1)?.begin).then_some(f),
        None => None,
    }
}

/// The most links followed from a link record to its parent.
const MAX_LINKS: usize = 8;

/// A record's own unwind information: itself, or for a link record (a
/// jump island), the parent record it links to (following links).
pub fn resolve(
    image: &(impl Image + ?Sized),
    function: RuntimeFunction,
) -> Result<RuntimeFunction> {
    let mut f = function;
    for _ in 0..MAX_LINKS {
        if !f.is_link() {
            return Ok(f);
        }
        let at = f.unwind & !3;
        let b = image.bytes(at, 8).ok_or(Error::UnwindData { rva: at })?;
        f = RuntimeFunction {
            begin: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            unwind: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        };
    }
    Err(Error::UnwindData {
        rva: function.unwind & !3,
    })
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
    pub establisher_frame: u64,
    pub handler: Option<Handler>,
    /// Whether a machine frame or context gave PC and SP directly.
    pub machine_frame: bool,
    /// Whether the return address was signed (`pacibsp`); it is returned
    /// stripped.
    pub signed_return: bool,
    /// Where each restored x register (x0..lr) was read from.
    pub saved_x: [Option<u64>; 31],
    /// Where each restored v register (or its low half, for d8..d15) was
    /// read from.
    pub saved_v: [Option<u64>; 32],
}

/// A register a prolog saves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reg {
    X(u8),
    /// The low 64 bits of a v register.
    D(u8),
    /// A whole v register.
    Q(u8),
}

impl Reg {
    fn size(self) -> u64 {
        if matches!(self, Reg::Q(_)) { 16 } else { 8 }
    }

    /// The register after it (the second of a pair).
    fn next(self) -> Reg {
        match self {
            Reg::X(n) => Reg::X(n + 1),
            Reg::D(n) => Reg::D(n + 1),
            Reg::Q(n) => Reg::Q(n + 1),
        }
    }
}

/// A prolog instruction, by what undoing it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `sub sp, sp, #n`.
    Alloc(u64),
    /// `str`/`stp` of one or two registers (the second just after the
    /// first in memory) at `[sp, #offset]`, or with writeback,
    /// `[sp, #-offset]!`.
    Save {
        first: Reg,
        second: Option<Reg>,
        offset: u64,
        writeback: bool,
    },
    /// `mov fp, sp`.
    SetFp,
    /// `add fp, sp, #n`.
    AddFp(u64),
    /// An instruction with nothing to undo (`nop`, homing stores).
    Nop,
    /// `pacibsp`.
    PacSign,
    /// The frame is a machine frame / a context / an ARM64EC context.
    MachineFrame,
    Context,
    EcContext,
    /// A flag only (`MSFT_OP_CLEAR_UNWOUND_TO_CALL`).
    ClearUnwoundToCall,
    /// `save_next`, before it is resolved.
    SaveNext,
    /// End (of the prolog's codes, or an epilog's `ret`).
    End,
    /// End of this scope's codes: those after it (a chained scope's) apply
    /// in full.
    EndC,
}

impl Op {
    /// Whether the code stands for an instruction (in a prolog).
    fn is_instruction(self) -> bool {
        !matches!(
            self,
            Op::End
                | Op::EndC
                | Op::MachineFrame
                | Op::Context
                | Op::EcContext
                | Op::ClearUnwoundToCall
        )
    }
}

/// Decodes unwind code bytes from `index` (up to and including the first
/// `end`) into operations, resolving `save_next`.
fn decode(codes: &[u8], index: usize, rva: u32) -> Result<Vec<Op>> {
    let bad = Error::UnwindData { rva };
    let mut ops = Vec::new();
    let mut i = index;
    loop {
        let (code, len) = Arm64UnwindCode::decode(codes.get(i..).ok_or(bad)?).ok_or(bad)?;
        i += len;
        let x = |n: u8| Reg::X(n);
        let op = match code {
            Arm64UnwindCode::AllocS { size }
            | Arm64UnwindCode::AllocM { size }
            | Arm64UnwindCode::AllocL { size } => Op::Alloc(u64::from(size)),
            Arm64UnwindCode::SaveR19R20X { offset } => save(x(19), true, offset, true),
            Arm64UnwindCode::SaveFpLr { offset } => save(x(29), true, offset, false),
            Arm64UnwindCode::SaveFpLrX { offset } => save(x(29), true, offset, true),
            Arm64UnwindCode::SaveRegp { reg, offset } => save(x(19 + reg), true, offset, false),
            Arm64UnwindCode::SaveRegpX { reg, offset } => save(x(19 + reg), true, offset, true),
            Arm64UnwindCode::SaveReg { reg, offset } => save(x(19 + reg), false, offset, false),
            Arm64UnwindCode::SaveRegX { reg, offset } => save(x(19 + reg), false, offset, true),
            Arm64UnwindCode::SaveLrpair { reg, offset } => Op::Save {
                first: x(19 + 2 * reg),
                second: Some(x(30)),
                offset: u64::from(offset),
                writeback: false,
            },
            Arm64UnwindCode::SaveFregp { reg, offset } => {
                save(Reg::D(8 + reg), true, offset, false)
            }
            Arm64UnwindCode::SaveFregpX { reg, offset } => {
                save(Reg::D(8 + reg), true, offset, true)
            }
            Arm64UnwindCode::SaveFreg { reg, offset } => {
                save(Reg::D(8 + reg), false, offset, false)
            }
            Arm64UnwindCode::SaveFregX { reg, offset } => {
                save(Reg::D(8 + reg), false, offset, true)
            }
            Arm64UnwindCode::SetFp => Op::SetFp,
            Arm64UnwindCode::AddFp { offset } => Op::AddFp(u64::from(offset)),
            Arm64UnwindCode::Nop => Op::Nop,
            Arm64UnwindCode::End => Op::End,
            Arm64UnwindCode::EndC => Op::EndC,
            Arm64UnwindCode::SaveNext => Op::SaveNext,
            Arm64UnwindCode::PacSignLr => Op::PacSign,
            Arm64UnwindCode::SaveAnyReg { raw } => {
                save_any_reg(raw).ok_or(Error::Unsupported { rva })?
            }
            Arm64UnwindCode::Custom { op: 0xE9 } => Op::MachineFrame,
            Arm64UnwindCode::Custom { op: 0xEA } => Op::Context,
            Arm64UnwindCode::Custom { op: 0xEB } => Op::EcContext,
            Arm64UnwindCode::Custom { op: 0xEC } => Op::ClearUnwoundToCall,
            // (Kernel trap frames; SVE.)
            Arm64UnwindCode::Custom { .. } | Arm64UnwindCode::AllocZ { .. } => {
                return Err(Error::Unsupported { rva });
            }
            Arm64UnwindCode::Reserved { .. } => return Err(bad),
        };
        ops.push(op);
        if op == Op::End {
            break;
        }
    }
    resolve_save_next(&mut ops, rva)?;
    Ok(ops)
}

fn save(first: Reg, pair: bool, offset: u32, writeback: bool) -> Op {
    Op::Save {
        first,
        second: pair.then(|| first.next()),
        offset: u64::from(offset),
        writeback,
    }
}

/// `save_any_reg` (`11100111 0pxrrrrr ffoooooo`): any x, d, or q register
/// or pair; writeback offsets are `(o + 1) * 16`, others `o * 16` (pairs, q)
/// or `o * 8`. (The `ff = 11` forms are SVE.)
fn save_any_reg(raw: u16) -> Option<Op> {
    let [b1, b2] = raw.to_be_bytes();
    if b1 & 0x80 != 0 || b2 >> 6 == 3 {
        return None;
    }
    let pair = b1 & 0x40 != 0;
    let writeback = b1 & 0x20 != 0;
    let r = b1 & 0x1F;
    let kind = b2 >> 6;
    let mut o = u64::from(b2 & 0x3F);
    if writeback {
        o += 1;
    }
    let offset = if !writeback && !pair && kind != 2 {
        o * 8
    } else {
        o * 16
    };
    let max = 0x1F - u8::from(pair) - u8::from(kind == 0);
    if r > max {
        return None;
    }
    let first = match kind {
        0 => Reg::X(r),
        1 => Reg::D(r),
        _ => Reg::Q(r),
    };
    Some(Op::Save {
        first,
        second: pair.then(|| first.next()),
        offset,
        writeback,
    })
}

/// Gives each `save_next` its registers: the pair after the next real
/// pair save's (they precede it, nearest first), in the next pair's space.
fn resolve_save_next(ops: &mut [Op], rva: u32) -> Result<()> {
    let mut i = 0;
    while i < ops.len() {
        if ops[i] != Op::SaveNext {
            i += 1;
            continue;
        }
        let run = ops[i..].iter().take_while(|&&o| o == Op::SaveNext).count();
        let base = ops.get(i + run).copied();
        let Some(Op::Save {
            first,
            second: Some(second),
            offset,
            writeback,
        }) = base
        else {
            return Err(Error::UnwindData { rva });
        };
        if second != first.next() {
            return Err(Error::UnwindData { rva });
        }
        let base_offset = if writeback { 0 } else { offset };
        for k in 0..run {
            // (The one nearest the base saves the pair right after it.)
            let step = (run - k) as u64;
            let mut reg = first;
            for _ in 0..2 * step {
                reg = reg.next();
            }
            // (The next pair is the pair's size on: 16 bytes, or 32 for q.)
            ops[i + k] = Op::Save {
                first: reg,
                second: Some(reg.next()),
                offset: base_offset + 2 * first.size() * step,
                writeback: false,
            };
        }
        i += run + 1;
    }
    Ok(())
}

/// The prolog and epilog that packed unwind data stands for: the prolog's
/// instructions in order, and the epilog's (each as the prolog
/// instruction it undoes), `End` being its `ret`.
// (Register numbers come from 4- and 3-bit fields.)
#[allow(clippy::cast_possible_truncation)]
fn packed(p: &Arm64PackedUnwind) -> (Vec<Op>, Vec<Op>) {
    let reg_i = u32::from(p.reg_i);
    let cr = p.cr;
    let fp_count = if p.reg_f > 0 {
        u32::from(p.reg_f) + 1
    } else {
        0
    };
    let int_size = reg_i * 8 + if cr == 1 { 8 } else { 0 };
    let fp_size = fp_count * 8;
    let save_size = (int_size + fp_size + if p.h { 64 } else { 0 } + 15) & !15;
    let local = p.frame_size.saturating_sub(save_size);
    let chained = cr == 2 || cr == 3;
    let s = |first, pair, offset, writeback| save(first, pair, offset, writeback);
    // stp x(r), lr (not adjacent registers).
    let with_lr = |r: u8, offset: u32| Op::Save {
        first: Reg::X(r),
        second: Some(Reg::X(30)),
        offset: u64::from(offset),
        writeback: false,
    };

    let mut prolog = Vec::new();
    let mut epilog = Vec::new();
    if cr == 2 {
        prolog.push(Op::PacSign);
    }
    let mut first = true;
    if cr == 1 && reg_i == 1 {
        // (The doc merges steps 2 and 3 into one `save_regp`; real code
        // and dumpbin have `sub sp, sp, #savsz; stp x19, lr, [sp]`.)
        let alloc = Op::Alloc(u64::from(save_size));
        prolog.extend([alloc, with_lr(19, 0)]);
        epilog.extend([alloc, with_lr(19, 0)]);
        first = false;
    } else {
        let mut i = 0;
        while i + 1 < reg_i {
            let r = (19 + i) as u8;
            let op = if first {
                s(Reg::X(r), true, save_size, true)
            } else {
                s(Reg::X(r), true, i * 8, false)
            };
            prolog.push(op);
            epilog.push(op);
            first = false;
            i += 2;
        }
        let at = i * 8;
        if reg_i % 2 == 1 {
            let r = (19 + reg_i - 1) as u8;
            if cr == 1 {
                prolog.push(with_lr(r, at));
                epilog.push(with_lr(r, at));
            } else {
                let op = if first {
                    s(Reg::X(r), false, save_size, true)
                } else {
                    s(Reg::X(r), false, at, false)
                };
                prolog.push(op);
                epilog.push(op);
            }
            first = false;
        } else if cr == 1 {
            let op = if first {
                s(Reg::X(30), false, save_size, true)
            } else {
                s(Reg::X(30), false, at, false)
            };
            prolog.push(op);
            epilog.push(op);
            first = false;
        }
    }
    let mut j = 0;
    while j + 1 < fp_count {
        let r = (8 + j) as u8;
        let op = if first {
            s(Reg::D(r), true, save_size, true)
        } else {
            s(Reg::D(r), true, int_size + j * 8, false)
        };
        prolog.push(op);
        epilog.push(op);
        first = false;
        j += 2;
    }
    if fp_count % 2 == 1 {
        let op = s(Reg::D((8 + j) as u8), false, int_size + j * 8, false);
        prolog.push(op);
        epilog.push(op);
    }
    if p.h {
        // Homed arguments, not restored. (With nothing saved before them,
        // the first allocates the save area.)
        if first {
            prolog.push(Op::Alloc(u64::from(save_size)));
            epilog.push(Op::Alloc(u64::from(save_size)));
        }
        prolog.extend([Op::Nop; 4]);
    }
    let local = u64::from(local);
    // Locals over 4080 bytes take two: `sub sp, sp, 4080` and the rest.
    let subs = |n: u64| -> Vec<Op> {
        if n > 4080 {
            alloc::vec![Op::Alloc(4080), Op::Alloc(n - 4080)]
        } else {
            alloc::vec![Op::Alloc(n)]
        }
    };
    let mut tail_epilog = Vec::new();
    if chained {
        let fplr = if local <= 512 {
            let op = Op::Save {
                first: Reg::X(29),
                second: Some(Reg::X(30)),
                offset: local,
                writeback: true,
            };
            prolog.push(op);
            tail_epilog.push(op);
            None
        } else {
            let allocs = subs(local);
            prolog.extend(&allocs);
            let op = s(Reg::X(29), true, 0, false);
            prolog.push(op);
            tail_epilog.push(op);
            Some(allocs)
        };
        if let Some(mut allocs) = fplr {
            allocs.reverse();
            tail_epilog.extend(allocs);
        }
        prolog.push(Op::SetFp);
    } else if local > 0 {
        let allocs = subs(local);
        prolog.extend(&allocs);
        let mut r = allocs;
        r.reverse();
        tail_epilog.extend(r);
    }
    epilog.reverse();
    let mut full = tail_epilog;
    full.extend(epilog);
    if cr == 2 {
        full.push(Op::PacSign);
    }
    full.push(Op::End);
    (prolog, full)
}

/// Where a function's prolog and epilogs are, as its unwind data says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The prolog's length, in instructions (0 for a fragment without one).
    pub prolog: u32,
    pub epilogs: Vec<Epilog>,
}

/// An epilog's place in its function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epilog {
    /// Its offset from the function start, in bytes.
    pub start: u32,
    /// Its length in instructions (counting its `ret`, if it has one).
    pub instructions: u32,
    /// Whether it ends in this function (its `end`, standing for a `ret`
    /// or tail call); not if an `end_c` ends its codes first.
    pub returns: bool,
}

/// A function's prolog and epilogs as its unwind data describes them,
/// instruction by instruction, in execution order (an epilog's [`Op`]s
/// are the prolog operations each of its instructions undoes, `End` its
/// `ret`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub prolog: Vec<Op>,
    /// Each epilog: its offset from the function start, and its
    /// instructions.
    pub epilogs: Vec<(u32, Vec<Op>)>,
}

/// The instructions `function`'s prolog and epilogs are made of, by its
/// unwind data. (Codes after an `end_c`, a chained scope's, are left out.)
pub fn describe(image: &(impl Image + ?Sized), function: RuntimeFunction) -> Result<Description> {
    if function.is_link() {
        resolve(image, function)?;
        return Ok(Description {
            prolog: Vec::new(),
            epilogs: Vec::new(),
        });
    }
    let first_scope = |ops: &[Op]| -> Vec<Op> {
        ops.iter()
            .copied()
            .take_while(|&o| o != Op::End && o != Op::EndC)
            .collect()
    };
    match function.unwind & 3 {
        0 => {
            let x = Xdata::read(image, function.unwind)?;
            let mut prolog = first_scope(&decode(x.codes, 0, x.rva)?);
            prolog.reverse();
            let epilogs = x
                .epilogs()?
                .into_iter()
                .map(|(start, ops)| {
                    let mut e = first_scope(&ops);
                    if !ops.contains(&Op::EndC) {
                        e.push(Op::End);
                    }
                    (start, e)
                })
                .collect();
            Ok(Description { prolog, epilogs })
        }
        flag @ (1 | 2) => {
            let p = Arm64PackedUnwind::decode(function.unwind).ok_or(Error::UnwindData {
                rva: function.begin,
            })?;
            let (prolog, epilog) = packed(&p);
            let len = instructions_with_ret(&epilog);
            Ok(Description {
                // (Flag 2: code with no prolog or epilog.)
                prolog: if flag == 1 { prolog } else { Vec::new() },
                epilogs: if flag == 1 {
                    alloc::vec![(p.function_length.wrapping_sub(4 * len), epilog)]
                } else {
                    Vec::new()
                },
            })
        }
        _ => Err(Error::UnwindData {
            rva: function.begin,
        }),
    }
}

/// The prolog and epilogs `function`'s unwind data describes.
pub fn layout(image: &(impl Image + ?Sized), function: RuntimeFunction) -> Result<Layout> {
    if function.is_link() {
        resolve(image, function)?;
        return Ok(Layout {
            prolog: 0,
            epilogs: Vec::new(),
        });
    }
    match function.unwind & 3 {
        0 => {
            let x = Xdata::read(image, function.unwind)?;
            let prolog = first_scope(&decode(x.codes, 0, x.rva)?);
            let epilogs = x
                .epilogs()?
                .iter()
                .map(|(start, ops)| Epilog {
                    start: *start,
                    instructions: instructions_with_ret(ops),
                    returns: !ops.contains(&Op::EndC),
                })
                .collect();
            Ok(Layout { prolog, epilogs })
        }
        flag @ (1 | 2) => {
            let p = Arm64PackedUnwind::decode(function.unwind).ok_or(Error::UnwindData {
                rva: function.begin,
            })?;
            let (prolog, epilog) = packed(&p);
            let len = instructions_with_ret(&epilog);
            Ok(Layout {
                prolog: if flag == 1 { instructions(&prolog) } else { 0 },
                epilogs: if flag == 1 {
                    alloc::vec![Epilog {
                        start: p.function_length.wrapping_sub(4 * len),
                        instructions: len,
                        returns: true,
                    }]
                } else {
                    Vec::new()
                },
            })
        }
        _ => Err(Error::UnwindData {
            rva: function.begin,
        }),
    }
}

/// The deepest ops list unwound before giving up (hostile `.xdata`).
const MAX_OPS: usize = 1024;

/// Unwinds a leaf frame (code with no `.pdata` entry): the return address
/// is in LR.
pub fn unwind_leaf(context: &mut Context) -> Frame {
    context.pc = context.x[reg::LR];
    Frame {
        position: Position::Body,
        establisher_frame: context.sp,
        handler: None,
        machine_frame: false,
        signed_return: false,
        saved_x: [None; 31],
        saved_v: [None; 32],
    }
}

/// Unwinds the frame whose code is described by `function`, in an image
/// loaded at `image_base`: `context` becomes the caller's.
pub fn unwind(
    image: &(impl Image + ?Sized),
    image_base: u64,
    function: RuntimeFunction,
    context: &mut Context,
    memory: &dyn Memory,
) -> Result<Frame> {
    #[allow(clippy::cast_possible_truncation)]
    let pc_rva = context.pc.wrapping_sub(image_base) as u32;
    // (A jump island unwinds as the body of the function it links to:
    // an offset no prolog or epilog contains.)
    let (function, offset) = if function.is_link() {
        (resolve(image, function)?, u32::MAX)
    } else {
        (function, pc_rva.wrapping_sub(function.begin))
    };
    let k = offset / 4;
    let mut frame = Frame {
        position: Position::Body,
        establisher_frame: 0,
        handler: None,
        machine_frame: false,
        signed_return: false,
        saved_x: [None; 31],
        saved_v: [None; 32],
    };

    // The operations to undo, in order.
    let ops: Vec<Op> = match function.unwind & 3 {
        0 => {
            let x = Xdata::read(image, function.unwind)?;
            frame.handler = x.handler;
            let prolog = decode(x.codes, 0, x.rva)?;
            // (A PC can be only in the first scope's prolog; codes after an
            // `end_c` are a chained scope's, whose prolog has run.)
            let scope = first_scope(&prolog);
            let epilog = x.epilogs()?.into_iter().find(|&(start, ref ops)| {
                offset.wrapping_sub(start) < 4 * instructions_with_ret(ops)
            });
            if let Some((start, ops)) = epilog {
                let m = (offset - start) / 4;
                frame.position = Position::Epilog(m);
                frame.handler = None;
                skip(&ops, m)
            } else if k < scope {
                frame.position = Position::Prolog(k);
                frame.handler = None;
                skip(&prolog, scope - k)
            } else {
                prolog
            }
        }
        flag @ (1 | 2) => {
            let p = Arm64PackedUnwind::decode(function.unwind).ok_or(Error::UnwindData {
                rva: function.begin,
            })?;
            let (prolog, epilog) = packed(&p);
            let epilog_len = instructions_with_ret(&epilog);
            let epilog_start = p.function_length.wrapping_sub(4 * epilog_len);
            let prolog_len = instructions(&prolog);
            // (Flag 2: code with no prolog or epilog.)
            if flag == 1 && offset.wrapping_sub(epilog_start) < 4 * epilog_len {
                let m = (offset - epilog_start) / 4;
                frame.position = Position::Epilog(m);
                skip(&epilog, m)
            } else if flag == 1 && k < prolog_len {
                frame.position = Position::Prolog(k);
                let mut done: Vec<Op> = prolog[..k as usize].to_vec();
                done.reverse();
                done
            } else {
                let mut all = prolog;
                all.reverse();
                all
            }
        }
        _ => {
            return Err(Error::UnwindData {
                rva: function.begin,
            });
        }
    };
    if ops.len() > MAX_OPS {
        return Err(Error::UnwindData {
            rva: function.unwind,
        });
    }

    let mut done = false;
    for op in ops {
        if undo(op, context, memory, &mut frame)? {
            done = true;
            break;
        }
    }
    if !done {
        context.pc = context.x[reg::LR];
    }
    if frame.signed_return {
        context.pc = strip(context.pc);
    }
    frame.establisher_frame = context.sp;
    Ok(frame)
}

/// The number of instructions `ops` stand for, up to `end` (a prolog).
fn instructions(ops: &[Op]) -> u32 {
    let n = ops
        .iter()
        .take_while(|&&o| o != Op::End)
        .filter(|o| o.is_instruction())
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The same, counting `end` as the `ret` (an epilog), unless an `end_c`
/// comes first: then the `ret` is beyond this scope (in another fragment),
/// and the codes after the `end_c` are a chained scope's.
fn instructions_with_ret(ops: &[Op]) -> u32 {
    match ops.iter().position(|&o| o == Op::EndC) {
        Some(i) => instructions(&ops[..i]),
        None => instructions(ops).saturating_add(u32::from(ops.contains(&Op::End))),
    }
}

/// The instructions before `end_c` (the scope a prolog's PC can be in).
fn first_scope(ops: &[Op]) -> u32 {
    match ops.iter().position(|&o| o == Op::EndC) {
        Some(i) => instructions(&ops[..i]),
        None => instructions(ops),
    }
}

/// `ops` without its first `n` instructions.
fn skip(ops: &[Op], n: u32) -> Vec<Op> {
    let mut left = n;
    let mut out = Vec::new();
    for &op in ops {
        if left > 0 && op.is_instruction() {
            left -= 1;
            continue;
        }
        out.push(op);
    }
    out
}

/// Undoes one operation; true if it ended the unwind (a machine frame or
/// context gave PC).
fn undo(op: Op, context: &mut Context, memory: &dyn Memory, frame: &mut Frame) -> Result<bool> {
    match op {
        Op::Alloc(n) => context.sp = context.sp.wrapping_add(n),
        Op::Save {
            first,
            second,
            offset,
            writeback,
        } => {
            let at = if writeback {
                context.sp
            } else {
                context.sp.wrapping_add(offset)
            };
            restore(first, at, context, memory, frame)?;
            if let Some(second) = second {
                restore(
                    second,
                    at.wrapping_add(first.size()),
                    context,
                    memory,
                    frame,
                )?;
            }
            if writeback {
                context.sp = context.sp.wrapping_add(offset);
            }
        }
        Op::SetFp => context.sp = context.x[reg::FP],
        Op::AddFp(n) => context.sp = context.x[reg::FP].wrapping_sub(n),
        Op::Nop | Op::ClearUnwoundToCall | Op::EndC | Op::SaveNext => {}
        Op::PacSign => frame.signed_return = true,
        Op::End => return Ok(false),
        Op::MachineFrame => {
            let sp = context.sp;
            context.sp = read_u64(memory, sp)?;
            context.pc = read_u64(memory, sp.wrapping_add(8))?;
            frame.machine_frame = true;
            return Ok(true);
        }
        Op::Context => {
            restore_context(context, memory, frame)?;
            return Ok(true);
        }
        Op::EcContext => {
            restore_ec_context(context, memory, frame)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn restore(
    r: Reg,
    at: u64,
    context: &mut Context,
    memory: &dyn Memory,
    frame: &mut Frame,
) -> Result<()> {
    match r {
        Reg::X(n) if usize::from(n) < 31 => {
            context.x[usize::from(n)] = read_u64(memory, at)?;
            frame.saved_x[usize::from(n)] = Some(at);
        }
        // (x31 would be sp; nothing saves it.)
        Reg::X(_) => {}
        Reg::D(n) => {
            // (Only the low half; the ABI preserves no more.)
            let n = usize::from(n & 31);
            context.v[n] = context.v[n] & !u128::from(u64::MAX) | u128::from(read_u64(memory, at)?);
            frame.saved_v[n] = Some(at);
        }
        Reg::Q(n) => {
            let n = usize::from(n & 31);
            context.v[n] = read_u128(memory, at)?;
            frame.saved_v[n] = Some(at);
        }
    }
    Ok(())
}

/// Restores from an ARM64 `CONTEXT` at SP.
fn restore_context(context: &mut Context, memory: &dyn Memory, frame: &mut Frame) -> Result<()> {
    let base = context.sp;
    let mut b = [0u8; 4];
    if !memory.read(base.wrapping_add(4), &mut b) {
        return Err(Error::Memory {
            address: base.wrapping_add(4),
        });
    }
    context.cpsr = u32::from_le_bytes(b);
    for n in 0..31 {
        let at = base.wrapping_add(8 + 8 * n as u64);
        context.x[n] = read_u64(memory, at)?;
        frame.saved_x[n] = Some(at);
    }
    context.sp = read_u64(memory, base.wrapping_add(0x100))?;
    context.pc = read_u64(memory, base.wrapping_add(0x108))?;
    for n in 0..32 {
        let at = base.wrapping_add(0x110 + 16 * n as u64);
        context.v[n] = read_u128(memory, at)?;
        frame.saved_v[n] = Some(at);
    }
    frame.machine_frame = true;
    Ok(())
}

/// Restores from an x64 `CONTEXT` at SP (ARM64EC), mapping its registers
/// onto the ARM64 ones the ARM64EC ABI pairs them with.
fn restore_ec_context(context: &mut Context, memory: &dyn Memory, frame: &mut Frame) -> Result<()> {
    // x64 RAX..R15 (CONTEXT offsets 0x78..0xF0) → x8, x0, x1, x27, sp, fp,
    // x25, x26, x2, x3, x4, x5, x19, x20, x21, x22.
    const MAP: [usize; 16] = [8, 0, 1, 27, 31, 29, 25, 26, 2, 3, 4, 5, 19, 20, 21, 22];
    let base = context.sp;
    let mut sp = None;
    for (i, &r) in MAP.iter().enumerate() {
        let at = base.wrapping_add(0x78 + 8 * i as u64);
        let v = read_u64(memory, at)?;
        if r == 31 {
            sp = Some(v);
        } else {
            context.x[r] = v;
            frame.saved_x[r] = Some(at);
        }
    }
    context.pc = read_u64(memory, base.wrapping_add(0xF8))?;
    for n in 0..16 {
        let at = base.wrapping_add(0x1A0 + 16 * n as u64);
        context.v[n] = read_u128(memory, at)?;
        frame.saved_v[n] = Some(at);
    }
    if let Some(sp) = sp {
        context.sp = sp;
    }
    frame.machine_frame = true;
    Ok(())
}

/// A return address without its pointer authentication code: bits 48 and
/// up copy bit 55 (set for kernel addresses).
fn strip(address: u64) -> u64 {
    if address & (1 << 55) != 0 {
        address | 0xFFFF_0000_0000_0000
    } else {
        address & 0x0000_FFFF_FFFF_FFFF
    }
}

/// An `.xdata` record.
struct Xdata<'a> {
    rva: u32,
    function_length: u32,
    /// Whether the single epilog is at the end, its codes at `epilog_count`.
    e: bool,
    epilog_count: u32,
    scopes: &'a [u8],
    codes: &'a [u8],
    handler: Option<Handler>,
}

impl<'a> Xdata<'a> {
    fn read(image: &'a (impl Image + ?Sized), rva: u32) -> Result<Self> {
        let bad = Error::UnwindData { rva };
        let word = |at: u32| -> Result<u32> {
            let b = image.bytes(at, 4).ok_or(bad)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let first = word(rva)?;
        let mut epilog_count = (first >> 22) & 0x1F;
        let mut code_words = first >> 27;
        let mut header = 4u32;
        if epilog_count == 0 && code_words == 0 {
            let second = word(rva.checked_add(4).ok_or(bad)?)?;
            epilog_count = second & 0xFFFF;
            code_words = (second >> 16) & 0xFF;
            header = 8;
        }
        let x = (first >> 20) & 1 != 0;
        let e = (first >> 21) & 1 != 0;
        let scopes_len = if e { 0 } else { epilog_count * 4 };
        let scopes_rva = rva.checked_add(header).ok_or(bad)?;
        let scopes = image.bytes(scopes_rva, scopes_len).ok_or(bad)?;
        let codes_rva = scopes_rva.checked_add(scopes_len).ok_or(bad)?;
        let codes = image.bytes(codes_rva, code_words * 4).ok_or(bad)?;
        let handler = if x {
            let at = codes_rva.checked_add(code_words * 4).ok_or(bad)?;
            Some(Handler {
                routine: word(at)?,
                data: at.wrapping_add(4),
            })
        } else {
            None
        };
        Ok(Self {
            rva,
            function_length: (first & 0x3_FFFF) * 4,
            e,
            epilog_count,
            scopes,
            codes,
            handler,
        })
    }

    /// Each epilog: its start (from the function start) and its codes.
    /// Whether a code starts at byte `index` (walking the codes from 0).
    fn is_code_start(&self, index: usize) -> bool {
        let mut i = 0;
        while i < index {
            match Arm64UnwindCode::decode(&self.codes[i..]) {
                Some((_, len)) => i += len,
                None => return false,
            }
        }
        i == index
    }

    fn epilogs(&self) -> Result<Vec<(u32, Vec<Op>)>> {
        let mut out = Vec::new();
        if self.e {
            let index = self.epilog_count as usize;
            if !self.is_code_start(index) {
                return Err(Error::UnwindData { rva: self.rva });
            }
            let ops = decode(self.codes, index, self.rva)?;
            let start = self
                .function_length
                .wrapping_sub(4 * instructions_with_ret(&ops));
            out.push((start, ops));
        } else {
            for s in self.scopes.as_chunks::<4>().0 {
                let w = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
                let start = (w & 0x3_FFFF) * 4;
                let index = (w >> 22) as usize;
                // (An index inside a code: the unwind data is malformed.)
                if !self.is_code_start(index) {
                    return Err(Error::UnwindData { rva: self.rva });
                }
                out.push((start, decode(self.codes, index, self.rva)?));
            }
        }
        Ok(out)
    }
}

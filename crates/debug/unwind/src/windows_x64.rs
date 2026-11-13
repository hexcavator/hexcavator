//! Windows x64 unwinding: `.pdata` `RUNTIME_FUNCTION`s and their
//! `UNWIND_INFO`, the way `RtlVirtualUnwind` reads them.
//!
//! A frame's PC is in one of three places in its function:
//!
//! - **the prolog** (before `SizeOfProlog`): only the unwind codes whose
//!   operations have already run are undone;
//! - **an epilog**: recognized by its instructions (`add rsp`/`lea rsp`,
//!   pops, then `ret` or a jump out of the function), and finished by
//!   simulating them rather than by the codes;
//! - **the body**: every code is undone, then those of any chained entries.
//!
//! A function without a `.pdata` entry is a leaf: its return address is at
//! RSP (see [`unwind_leaf`]).
//!
//! `tests/windows_x64_rtl.rs` compares every result field (registers, where each
//! was restored from, the establisher frame, the handler) with
//! `RtlVirtualUnwind` on system DLLs: millions of PCs, with no differences
//! at instruction boundaries. Rules it settled that the documentation
//! doesn't spell out:
//!
//! - Epilogs are recognized even in a prolog (a chained fragment's prolog
//!   can hold its tail call), but not in an unchained function with no
//!   codes (whose handler is then returned even at its `ret`).
//! - Pops may carry any REX prefix. An epilog ends in `ret`, `ret n`, `rep
//!   ret`, `jmp [rip+n]` (with or without REX.W), `rex.w jmp reg`, `iretq`,
//!   or a relative `jmp` that leaves the function: its own range and its
//!   chain's other fragments. A jump to the chain root's entry is a tail
//!   call (recursion); one to a fragment's start isn't.
//! - Version 2 lists its epilogs (`UWOP_EPILOG`); only PCs inside a listed
//!   one are in an epilog, so an `add rsp` before it is still the body.
//! - In an epilog of a function with a frame register, the establisher
//!   frame is RSP at the return, not the frame pointer's base.
//! - The handler is the last chained entry's, and only that entry's
//!   prolog hides it; a machine frame doesn't.
//! - A function whose codes push a machine frame returns through it, even
//!   from an epilog's `ret`.
//! - A machine frame restores only RIP and RSP.

use hexcavator_pe::exception::{X64UnwindCode, unwind_flags, x64_unwind_codes};

use crate::{Error, Image, Memory, Result, read_u64, read_u128};

/// Register numbers (as unwind codes and the frame register give them).
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R15: usize = 15;
}

/// The registers an unwind reads and writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub rip: u64,
    /// RAX..R15, in encoding order (RSP is `gpr[4]`).
    pub gpr: [u64; 16],
    pub xmm: [u128; 16],
    /// Restored only by a machine frame.
    pub cs: u16,
    pub ss: u16,
    pub eflags: u32,
}

impl Context {
    #[inline]
    pub fn rsp(&self) -> u64 {
        self.gpr[reg::RSP]
    }

    #[inline]
    fn set_rsp(&mut self, v: u64) {
        self.gpr[reg::RSP] = v;
    }
}

/// A `.pdata` entry: `[begin, end)` and its unwind information, as RVAs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

/// The `.pdata` entry for the code at `rva`, by binary search of the
/// exception directory (`table_rva`, `table_size`), as
/// `RtlLookupFunctionEntry` finds it. An entry whose unwind RVA has its
/// low bit set is indirect: it gives the RVA of the real entry.
pub fn lookup(
    image: &(impl Image + ?Sized),
    table_rva: u32,
    table_size: u32,
    rva: u32,
) -> Option<RuntimeFunction> {
    let count = table_size / 12;
    let entry = |i: u32| read_entry(image, table_rva.checked_add(i.checked_mul(12)?)?);
    let (mut lo, mut hi) = (0u32, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let e = entry(mid)?;
        if rva < e.begin {
            hi = mid;
        } else if rva >= e.end {
            lo = mid + 1;
        } else {
            return if e.unwind & 1 != 0 {
                read_entry(image, e.unwind & !1)
            } else {
                Some(e)
            };
        }
    }
    None
}

fn read_entry(image: &(impl Image + ?Sized), rva: u32) -> Option<RuntimeFunction> {
    let b = image.bytes(rva, 12)?;
    let w = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    Some(RuntimeFunction {
        begin: w(0),
        end: w(4),
        unwind: w(8),
    })
}

/// Where in its function a frame's PC was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// In the prolog, this many bytes in.
    Prolog(u8),
    Body,
    Epilog,
}

/// A language-specific handler the frame's unwind information names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler {
    /// `UNW_FLAG_EHANDLER` and/or `UNW_FLAG_UHANDLER`.
    pub flags: u8,
    /// The handler's RVA.
    pub routine: u32,
    /// The RVA of its language-specific data.
    pub data: u32,
}

/// What an unwind found out about the frame it unwound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub position: Position,
    /// The frame's establisher frame (`RtlVirtualUnwind`'s
    /// `EstablisherFrame`): its frame pointer's base, or its RSP.
    pub establisher_frame: u64,
    /// The handler, if the frame has one and its PC is in the body.
    pub handler: Option<Handler>,
    /// Whether the frame ended in a machine frame (an interrupt or
    /// exception), which gave RIP and RSP directly.
    pub machine_frame: bool,
    /// Where each restored general register was read from.
    pub saved_gpr: [Option<u64>; 16],
    /// Where each restored XMM register was read from.
    pub saved_xmm: [Option<u64>; 16],
}

/// `UNWIND_INFO`'s header and codes.
#[derive(Clone, Copy, Debug)]
struct Info<'a> {
    rva: u32,
    version: u8,
    flags: u8,
    prolog_size: u8,
    frame_register: usize,
    frame_offset: u64,
    codes: &'a [u8],
    /// The RVA after the codes: the handler, or the chained entry.
    tail: u32,
}

impl<'a> Info<'a> {
    fn read(image: &'a (impl Image + ?Sized), rva: u32) -> Result<Self> {
        let bad = Error::UnwindData { rva };
        let h = image.bytes(rva, 4).ok_or(bad)?;
        let version = h[0] & 7;
        if !(1..=2).contains(&version) {
            return Err(bad);
        }
        let count = u32::from(h[2]);
        let codes_rva = rva.checked_add(4).ok_or(bad)?;
        let codes = if count == 0 {
            &[][..]
        } else {
            image.bytes(codes_rva, count * 2).ok_or(bad)?
        };
        Ok(Self {
            rva,
            version,
            flags: h[0] >> 3,
            prolog_size: h[1],
            frame_register: usize::from(h[3] & 0xF),
            frame_offset: u64::from(h[3] >> 4) * 16,
            codes,
            tail: codes_rva.checked_add(count.div_ceil(2) * 4).ok_or(bad)?,
        })
    }

    /// Version 2: whether `pc_rva` is in one of the epilogs the
    /// `UWOP_EPILOG` codes list. The first gives their common size (and,
    /// in bit 0 of its flags, that one ends the function); the others give
    /// each start's distance from the function's end.
    fn in_listed_epilog(&self, function: RuntimeFunction, pc_rva: u32) -> bool {
        let mut size = None;
        let inside = |start: u32, size: u32| pc_rva.wrapping_sub(start) < size;
        for (_, code) in x64_unwind_codes(self.codes, self.version) {
            match code {
                X64UnwindCode::EpilogFirst { flags, size: s } => {
                    let s = u32::from(s);
                    size = Some(s);
                    if flags & 1 != 0 && inside(function.end.wrapping_sub(s), s) {
                        return true;
                    }
                }
                X64UnwindCode::Epilog { offset_from_end } => {
                    if let Some(s) = size
                        && inside(function.end.wrapping_sub(offset_from_end), s)
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Whether the codes' `UWOP_SET_FPREG` has run, `offset` bytes into
    /// the prolog.
    fn frame_set(&self, offset: Option<u32>) -> bool {
        self.frame_register != 0
            && match offset {
                None => true,
                Some(offset) => x64_unwind_codes(self.codes, self.version)
                    .any(|(at, c)| c == X64UnwindCode::SetFpreg && u32::from(at) <= offset),
            }
    }
}

/// Unwinds a leaf frame (code with no `.pdata` entry): the return address
/// is at RSP.
pub fn unwind_leaf(context: &mut Context, memory: &dyn Memory) -> Result<Frame> {
    let rsp = context.rsp();
    let frame = Frame {
        position: Position::Body,
        establisher_frame: rsp,
        handler: None,
        machine_frame: false,
        saved_gpr: [None; 16],
        saved_xmm: [None; 16],
    };
    context.rip = read_u64(memory, rsp)?;
    context.set_rsp(rsp.wrapping_add(8));
    Ok(frame)
}

/// The deepest chain of entries followed before giving up.
const MAX_CHAIN: usize = 32;

/// The image's exception directory (RVA, size), from its headers.
fn exception_directory(image: &(impl Image + ?Sized)) -> Option<(u32, u32)> {
    let u32_at = |rva: u32| {
        image
            .bytes(rva, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let optional = u32_at(0x3C)?.checked_add(24)?;
    let magic = image.bytes(optional, 2)?;
    if magic != [0x0B, 0x02] {
        return None;
    }
    let count = u32_at(optional.checked_add(108)?)?;
    if count <= 3 {
        return None;
    }
    let dir = optional.checked_add(112 + 3 * 8)?;
    Some((u32_at(dir)?, u32_at(dir.checked_add(4)?)?))
}

/// The first entry of `function`'s chain (itself, if it isn't chained).
fn chain_root(image: &(impl Image + ?Sized), function: RuntimeFunction) -> Option<RuntimeFunction> {
    let mut f = function;
    for _ in 0..MAX_CHAIN {
        let info = Info::read(image, f.unwind).ok()?;
        if info.flags & unwind_flags::CHAININFO == 0 {
            return Some(f);
        }
        f = read_entry(image, info.tail)?;
    }
    None
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
    let info = Info::read(image, function.unwind)?;
    // (RVAs are 32 bits; a PC outside the image just isn't in the function.)
    #[allow(clippy::cast_possible_truncation)]
    let pc_rva = context.rip.wrapping_sub(image_base) as u32;
    let offset = pc_rva.wrapping_sub(function.begin);
    let in_prolog = offset < u32::from(info.prolog_size);
    let prolog = in_prolog.then_some(offset);

    let establisher_frame = if info.frame_set(prolog) {
        context.gpr[info.frame_register].wrapping_sub(info.frame_offset)
    } else {
        context.rsp()
    };
    let mut frame = Frame {
        position: match prolog {
            // (Within the prolog, whose size is a byte.)
            Some(o) => Position::Prolog(u8::try_from(o).unwrap_or(u8::MAX)),
            None => Position::Body,
        },
        establisher_frame,
        handler: None,
        machine_frame: false,
        saved_gpr: [None; 16],
        saved_xmm: [None; 16],
    };

    // Epilogs are recognized everywhere, even in a prolog (a chained
    // fragment's prolog can hold its tail call), except:
    // - in a function with no codes of its own, unchained (unwinding is the
    //   same either way, but its handler stays);
    // - in version 2, outside the epilogs its codes list.
    let trivial = info.codes.is_empty() && info.flags & unwind_flags::CHAININFO == 0;
    let listed = info.version < 2 || info.in_listed_epilog(function, pc_rva);
    if !trivial
        && listed
        && let Some(mut epilog) = Epilog::recognize(image, pc_rva, function, &info)
    {
        frame.position = Position::Epilog;
        // (A function whose codes push a machine frame (a dispatcher,
        // entered by the system with one) returns through it, as
        // RtlVirtualUnwind sees it.)
        if let Some(error_code) =
            x64_unwind_codes(info.codes, info.version).find_map(|(_, c)| match c {
                X64UnwindCode::PushMachframe { error_code } => Some(error_code),
                _ => None,
            })
        {
            epilog.iret = true;
            epilog.error_code = error_code;
        }
        let at_return = epilog.simulate(context, memory, &mut frame)?;
        if info.frame_register != 0 {
            // (The frame pointer may be gone: the frame is where the
            // epilog leaves RSP, at the return address.)
            frame.establisher_frame = at_return;
        }
        return Ok(frame);
    }

    let mut info = info;
    let mut prolog = prolog;
    for _ in 0..MAX_CHAIN {
        undo(&info, prolog, context, memory, &mut frame)?;
        let last = info.flags & unwind_flags::CHAININFO == 0;
        // (The handler is the last entry's, and its prolog is the one that
        // counts: a chained fragment's prolog doesn't hide it.)
        if last
            && prolog.is_none()
            && info.flags & (unwind_flags::EHANDLER | unwind_flags::UHANDLER) != 0
        {
            let routine = read_u32(image, info.tail)?;
            frame.handler = Some(Handler {
                flags: info.flags & (unwind_flags::EHANDLER | unwind_flags::UHANDLER),
                routine,
                data: info.tail.wrapping_add(4),
            });
        }
        if frame.machine_frame {
            return Ok(frame);
        }
        if last {
            let rsp = context.rsp();
            context.rip = read_u64(memory, rsp)?;
            context.set_rsp(rsp.wrapping_add(8));
            return Ok(frame);
        }
        let parent = read_entry(image, info.tail).ok_or(Error::UnwindData { rva: info.rva })?;
        info = Info::read(image, parent.unwind)?;
        // (A chained entry's prolog has run in full.)
        prolog = None;
    }
    Err(Error::ChainTooDeep)
}

fn read_u32(image: &(impl Image + ?Sized), rva: u32) -> Result<u32> {
    let b = image.bytes(rva, 4).ok_or(Error::UnwindData { rva })?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Undoes one `UNWIND_INFO`'s codes (those that have run, `prolog` bytes
/// into the prolog).
fn undo(
    info: &Info<'_>,
    prolog: Option<u32>,
    context: &mut Context,
    memory: &dyn Memory,
    frame: &mut Frame,
) -> Result<()> {
    // Saves are relative to the frame's fixed allocation: the frame
    // pointer's base once it is set, else RSP.
    let base = if info.frame_set(prolog) {
        context.gpr[info.frame_register].wrapping_sub(info.frame_offset)
    } else {
        context.rsp()
    };
    for (at, code) in x64_unwind_codes(info.codes, info.version) {
        // (Codes whose operations haven't run yet.)
        if prolog.is_some_and(|o| u32::from(at) > o) {
            continue;
        }
        match code {
            X64UnwindCode::PushNonvol { reg } => pop(usize::from(reg), context, memory, frame)?,
            X64UnwindCode::AllocLarge { size } | X64UnwindCode::AllocSmall { size } => {
                context.set_rsp(context.rsp().wrapping_add(u64::from(size)));
            }
            X64UnwindCode::SetFpreg => {
                context.set_rsp(context.gpr[info.frame_register].wrapping_sub(info.frame_offset));
            }
            X64UnwindCode::SaveNonvol { reg, offset }
            | X64UnwindCode::SaveNonvolFar { reg, offset } => {
                let at = base.wrapping_add(u64::from(offset));
                let r = usize::from(reg);
                context.gpr[r] = read_u64(memory, at)?;
                frame.saved_gpr[r] = Some(at);
            }
            X64UnwindCode::SaveXmm128 { reg, offset }
            | X64UnwindCode::SaveXmm128Far { reg, offset } => {
                let at = base.wrapping_add(u64::from(offset));
                let r = usize::from(reg);
                context.xmm[r] = read_u128(memory, at)?;
                frame.saved_xmm[r] = Some(at);
            }
            X64UnwindCode::EpilogFirst { .. } | X64UnwindCode::Epilog { .. } => {}
            X64UnwindCode::PushMachframe { error_code } => {
                let at = context.rsp().wrapping_add(if error_code { 8 } else { 0 });
                // (RIP, CS, EFLAGS, RSP, SS; like RtlVirtualUnwind, only
                // RIP and RSP are restored.)
                context.rip = read_u64(memory, at)?;
                context.set_rsp(read_u64(memory, at.wrapping_add(24))?);
                frame.machine_frame = true;
                return Ok(());
            }
            X64UnwindCode::Unknown { .. } => return Err(Error::UnwindData { rva: info.rva }),
        }
    }
    Ok(())
}

/// Pops a register. (`pop rsp` sets RSP to the value plus 8, as
/// `RtlVirtualUnwind` does; no real epilog has one.)
fn pop(r: usize, context: &mut Context, memory: &dyn Memory, frame: &mut Frame) -> Result<()> {
    let rsp = context.rsp();
    context.gpr[r] = read_u64(memory, rsp)?;
    frame.saved_gpr[r] = Some(rsp);
    context.set_rsp(context.rsp().wrapping_add(8));
    Ok(())
}

/// An epilog recognized at the PC: what is left of it to run.
#[derive(Debug)]
struct Epilog {
    /// The new RSP from `add rsp`/`lea rsp`, if the PC is at one.
    rsp: Option<Rsp>,
    /// The registers popped, in order.
    pops: [u8; 16],
    pop_count: usize,
    /// Whether it ends in `iretq` (which pops a machine frame).
    iret: bool,
    /// Whether that frame starts with an error code.
    error_code: bool,
}

#[derive(Clone, Copy, Debug)]
enum Rsp {
    Add(u64),
    Lea { base: usize, disp: u64 },
}

impl Epilog {
    fn recognize(
        image: &(impl Image + ?Sized),
        pc_rva: u32,
        function: RuntimeFunction,
        info: &Info<'_>,
    ) -> Option<Self> {
        let byte = |i: u32| image.bytes(pc_rva.checked_add(i)?, 1).map(|b| b[0]);
        let mut i = 0u32;
        let mut epilog = Epilog {
            rsp: None,
            pops: [0; 16],
            pop_count: 0,
            iret: false,
            error_code: false,
        };
        let rex = byte(0)?;
        if rex & 0xF8 == 0x48 {
            let op = byte(1)?;
            let modrm = byte(2)?;
            if rex == 0x48 && op == 0x83 && modrm == 0xC4 {
                epilog.rsp = Some(Rsp::Add(i64::from(byte(3)? as i8) as u64));
                i = 4;
            } else if rex == 0x48 && op == 0x81 && modrm == 0xC4 {
                let d = u32::from_le_bytes([byte(3)?, byte(4)?, byte(5)?, byte(6)?]);
                epilog.rsp = Some(Rsp::Add(i64::from(d as i32) as u64));
                i = 7;
            } else if op == 0x8D
                && (modrm >> 3) & 7 == 4
                && modrm & 7 != 4
                && matches!(modrm >> 6, 1 | 2)
            {
                let base = usize::from(modrm & 7) | usize::from(rex & 1) << 3;
                if info.frame_register == 0 || base != info.frame_register {
                    return None;
                }
                let disp = if modrm >> 6 == 1 {
                    i = 4;
                    i64::from(byte(3)? as i8)
                } else {
                    i = 7;
                    i64::from(i32::from_le_bytes([byte(3)?, byte(4)?, byte(5)?, byte(6)?]))
                };
                epilog.rsp = Some(Rsp::Lea {
                    base,
                    disp: disp as u64,
                });
            }
        }
        loop {
            let b = byte(i)?;
            // (Any REX prefix; only REX.B matters.)
            let (r, len) = match b {
                0x58..=0x5F => (b - 0x58, 1),
                0x40..=0x4F if matches!(byte(i + 1)?, 0x58..=0x5F) => {
                    (byte(i + 1)? - 0x58 + ((b & 1) << 3), 2)
                }
                _ => break,
            };
            if epilog.pop_count == epilog.pops.len() {
                return None;
            }
            epilog.pops[epilog.pop_count] = r;
            epilog.pop_count += 1;
            i += len;
        }
        // A jump is a tail call (ending an epilog) only if it leaves the
        // function: its own range, and any fragment chained to the same
        // root.
        // (A jump to the function's entry, the start of its chain's root,
        // is a tail call too: recursion.)
        let inside = |target: u32| {
            if target > function.begin && target < function.end {
                return true;
            }
            let root = chain_root(image, function);
            if target == function.begin {
                return root.is_some_and(|r| r.begin != target);
            }
            let Some((table, size)) = exception_directory(image) else {
                return false;
            };
            let Some(other) = lookup(image, table, size, target) else {
                return false;
            };
            root.is_some_and(|r| r.begin != target) && chain_root(image, other) == root
        };
        let next = pc_rva.wrapping_add(i);
        let ends = match byte(i)? {
            0xC3 | 0xC2 => true,
            0xF3 => byte(i + 1)? == 0xC3,
            // (iretq)
            0x48 if byte(i + 1)? == 0xCF => {
                epilog.iret = true;
                true
            }
            0xEB => !inside(next.wrapping_add(2).wrapping_add(byte(i + 1)? as i8 as u32)),
            0xE9 => {
                let d =
                    u32::from_le_bytes([byte(i + 1)?, byte(i + 2)?, byte(i + 3)?, byte(i + 4)?]);
                !inside(next.wrapping_add(5).wrapping_add(d))
            }
            // jmp [rip+disp32]
            0xFF => byte(i + 1)? == 0x25,
            // rex.w jmp [rip+disp32] / rex.w jmp reg
            0x48 | 0x49 => {
                byte(i + 1)? == 0xFF && {
                    let modrm = byte(i + 2)?;
                    (byte(i)? == 0x48 && modrm == 0x25) || modrm & 0xF8 == 0xE0
                }
            }
            _ => false,
        };
        ends.then_some(epilog)
    }

    /// Runs the rest of the epilog; returns RSP at its return.
    fn simulate(
        &self,
        context: &mut Context,
        memory: &dyn Memory,
        frame: &mut Frame,
    ) -> Result<u64> {
        match self.rsp {
            Some(Rsp::Add(d)) => context.set_rsp(context.rsp().wrapping_add(d)),
            Some(Rsp::Lea { base, disp }) => context.set_rsp(context.gpr[base].wrapping_add(disp)),
            None => {}
        }
        for &r in &self.pops[..self.pop_count] {
            pop(usize::from(r), context, memory, frame)?;
        }
        let at_return = context.rsp();
        let rsp = at_return.wrapping_add(if self.error_code { 8 } else { 0 });
        context.rip = read_u64(memory, rsp)?;
        if self.iret {
            context.set_rsp(read_u64(memory, rsp.wrapping_add(24))?);
            frame.machine_frame = true;
        } else {
            context.set_rsp(rsp.wrapping_add(8));
        }
        Ok(at_return)
    }
}

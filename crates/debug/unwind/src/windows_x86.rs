//! Windows x86 unwinding from PDB frame data: FrameData records (the
//! DBI's "new FPO" stream: block sizes and a postfix program that computes
//! the caller's registers), old FPO records (`FPO_DATA`: sizes only), and
//! EBP frame chains where neither describes the code.
//!
//! x86 frames aren't fully described: a program's `.raSearch` asks the
//! unwinder to find the return address on the stack, from where the
//! frame's locals, saved registers, and its callee's arguments say it
//! should be. A caller-supplied test decides what may be a return address
//! (in practice: in a loaded module's code, after a call instruction).
//!
//! Program strings are a sequence of space-separated tokens, evaluated
//! with a stack:
//!
//! - an operand pushes a value: a register (`$eip`, `$esp`, `$ebp`,
//!   `$ebx`, `$esi`, `$edi`, `$eax`, `$ecx`, `$edx`, or by CodeView
//!   number: `$17` to `$24`, `$33`), a temporary (`$T0`
//!   to `$T9`, ...), a number, or a frame constant (`.raSearch`,
//!   `.raSearchStart`, `.cbSavedRegs`, `.cbLocals`, `.cbParams`,
//!   `.cbCalleeParams`);
//! - `+ - * / %` pop two values and push the result; `@` aligns
//!   (`a b @` is `a` rounded down to a multiple of `b`); `^` replaces the
//!   top value with the 32-bit word at that address;
//! - `=` pops a value and a register or temporary, and assigns it.
//!
//! In a function's prolog (by its record's prolog size), the frame isn't
//! set up yet: the return address is the first on the stack.
//!
//! Two oracles check this (`tests/windows_x86_walk.rs`, on stacks of MSVC-built
//! code from `tools/x86fpo`): the true return addresses a test program
//! records as it runs, and dbghelp's `StackWalk64`, where it doesn't lose
//! its way (a frame no module has, or a caller that doesn't call the
//! callee). Every true frame is found. In 6,000 snapshots taken at
//! random points, dbghelp agreed in 1,088 and lost its way in 4,889:
//! after system-call stubs (it inserts a stale frame) and after
//! `KiUserExceptionDispatcher` (whose caller is the `CONTEXT` it was
//! given, which [`unwind_context_record`] reads). Known limits: code
//! with no record (ntdll's `ExecuteHandler`) is walked by its EBP chain,
//! which skips a frame that doesn't set up EBP, as WinDbg's walk does.

use alloc::vec::Vec;

use crate::{Error, Memory, Result};

// (`CONTEXT` offsets: Edi 0x9C, Esi 0xA0, Ebx 0xA4, Edx 0xA8, Ecx 0xAC,
// Eax 0xB0, Ebp 0xB4, Eip 0xB8, Esp 0xC4.)

/// The registers an unwind reads and writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub eip: u32,
    pub esp: u32,
    pub ebp: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
}

/// An old-style FPO record (`FPO_DATA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fpo {
    /// The function's first byte (an RVA) and its size.
    pub start: u32,
    pub size: u32,
    /// Locals and parameters, in dwords.
    pub locals: u32,
    pub params: u16,
    /// The prolog's size in bytes, and how many registers it saves.
    pub prolog: u8,
    pub regs: u8,
    pub has_seh: bool,
    /// Whether the function sets up EBP as a frame pointer.
    pub uses_bp: bool,
    /// 0 FPO, 1 trap frame, 2 TSS, 3 standard (EBP) frame.
    pub frame: u8,
}

impl Fpo {
    /// Every 16-byte record of an FPO stream.
    pub fn parse(stream: &[u8]) -> Vec<Fpo> {
        stream
            .as_chunks::<16>()
            .0
            .iter()
            .map(|r| {
                let w = |o: usize| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
                let bits = u16::from_le_bytes([r[14], r[15]]);
                Fpo {
                    start: w(0),
                    size: w(4),
                    locals: w(8),
                    params: u16::from_le_bytes([r[12], r[13]]),
                    prolog: (bits & 0xFF) as u8,
                    regs: ((bits >> 8) & 7) as u8,
                    has_seh: bits & 0x800 != 0,
                    uses_bp: bits & 0x1000 != 0,
                    frame: (bits >> 14) as u8,
                }
            })
            .collect()
    }
}

/// A FrameData record (`FRAMEDATA`): one block of a function's code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameData {
    /// The block's first byte (an RVA) and its size.
    pub start: u32,
    pub size: u32,
    /// Bytes of locals, parameters, and the most the block pushes.
    pub locals: u32,
    pub params: u32,
    pub max_stack: u32,
    /// The program's offset in the PDB's string table (`/names`).
    pub program: u32,
    /// The prolog's size in bytes, and the bytes of saved registers.
    pub prolog: u16,
    pub saved_regs: u16,
    pub has_seh: bool,
    pub has_eh: bool,
    pub is_function_start: bool,
}

impl FrameData {
    /// Every 32-byte record of a FrameData stream.
    pub fn parse(stream: &[u8]) -> Vec<FrameData> {
        stream
            .as_chunks::<32>()
            .0
            .iter()
            .map(|r| {
                let w = |o: usize| u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
                let flags = w(28);
                FrameData {
                    start: w(0),
                    size: w(4),
                    locals: w(8),
                    params: w(12),
                    max_stack: w(16),
                    program: w(20),
                    prolog: u16::from_le_bytes([r[24], r[25]]),
                    saved_regs: u16::from_le_bytes([r[26], r[27]]),
                    has_seh: flags & 1 != 0,
                    has_eh: flags & 2 != 0,
                    is_function_start: flags & 4 != 0,
                }
            })
            .collect()
    }
}

/// A module's frame records, sorted for lookup.
#[derive(Clone, Debug, Default)]
pub struct FrameTable {
    pub frame_data: Vec<FrameData>,
    pub fpo: Vec<Fpo>,
}

/// The record describing an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    FrameData(FrameData),
    Fpo(Fpo),
}

impl Record {
    /// The bytes of arguments the frame's function takes (its callers
    /// push them; they lie between the caller's frame and the return
    /// address).
    pub fn params(&self) -> u32 {
        match *self {
            Record::FrameData(d) => d.params,
            Record::Fpo(f) => u32::from(f.params) * 4,
        }
    }
}

impl FrameTable {
    pub fn new(mut frame_data: Vec<FrameData>, mut fpo: Vec<Fpo>) -> Self {
        frame_data.sort_by_key(|d| d.start);
        fpo.sort_by_key(|f| f.start);
        FrameTable { frame_data, fpo }
    }

    /// The record for the code at `rva`: the FrameData block that starts
    /// last at or before it and still contains it, else the FPO record.
    pub fn find(&self, rva: u32) -> Option<Record> {
        let i = self.frame_data.partition_point(|d| d.start <= rva);
        // (Blocks can nest: look back past ones that end before `rva`.)
        let data = self.frame_data[..i]
            .iter()
            .rev()
            .take(64)
            .find(|d| rva - d.start < d.size);
        if let Some(d) = data {
            return Some(Record::FrameData(*d));
        }
        let i = self.fpo.partition_point(|f| f.start <= rva);
        let f = self.fpo.get(i.checked_sub(1)?)?;
        (rva - f.start < f.size).then_some(Record::Fpo(*f))
    }
}

/// How a frame was unwound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// By its FrameData program.
    Program,
    /// By its record's sizes (an FPO record, or FrameData without a
    /// program).
    Sizes,
    /// By the EBP chain.
    FramePointer,
    /// From a `CONTEXT` record (an exception dispatcher's frame).
    ContextRecord,
    /// In a prolog: by the first return address on the stack.
    Prolog,
}

/// What an unwind found out about the frame it unwound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub method: Method,
    /// Where the return address was read from.
    pub return_address_at: u32,
    /// The frame's arguments' size in bytes (its record's), for unwinding
    /// its caller.
    pub params: u32,
}

/// What the unwinder needs besides memory.
pub struct Env<'a> {
    pub memory: &'a dyn Memory,
    /// Whether a value may be a return address.
    pub is_return_address: &'a dyn Fn(u32) -> bool,
    /// The bytes of arguments the unwound frame's callee takes (0 for the
    /// innermost frame).
    pub callee_params: u32,
    /// The frame's EIP as an RVA in its module (for whether it is in its
    /// function's prolog).
    pub rva: u32,
}

/// How far `.raSearch` looks for a return address, in words.
const SEARCH_WORDS: u32 = 64;

/// The longest program evaluated, in tokens (hostile string tables).
const MAX_TOKENS: usize = 1024;

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

/// The first word from `start` (up to [`SEARCH_WORDS`] on) that may be a
/// return address, by its address; or `start` itself. Where the frame
/// keeps a frame pointer (`ebp`: pointing at the saved EBP, under the
/// return address) in that range, its return address is the one: a
/// realigned frame's padding, under it, can hold stale ones.
fn search(env: &Env<'_>, start: u32, ebp: Option<u32>) -> u32 {
    let end = start.wrapping_add(4 * SEARCH_WORDS);
    if let Some(at) = ebp.map(|e| e.wrapping_add(4))
        && (start..end).contains(&at)
        && read_u32(env.memory, at).is_ok_and(|v| (env.is_return_address)(v))
    {
        return at;
    }
    for k in 0..SEARCH_WORDS {
        let at = start.wrapping_add(4 * k);
        match read_u32(env.memory, at) {
            Ok(v) if (env.is_return_address)(v) => return at,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    start
}

/// Evaluates a FrameData program for `context`'s frame.
fn run_program(program: &[u8], d: &FrameData, context: &mut Context, env: &Env<'_>) -> Result<u32> {
    // Names to values: the registers (read as the frame has them, written
    // as the caller's), temporaries, and the frame's constants.
    let mut names: Vec<(&[u8], u32)> = Vec::new();
    let start = context
        .esp
        .wrapping_add(d.locals)
        .wrapping_add(u32::from(d.saved_regs));
    let mut ra_search = None;
    let mut ra_search_start = None;
    let mut stack: Vec<Value<'_>> = Vec::new();
    let regs = *context;
    let reg = |name: &[u8]| -> Option<u32> {
        Some(match name {
            b"$eip" => regs.eip,
            b"$esp" => regs.esp,
            b"$ebp" => regs.ebp,
            b"$eax" => regs.eax,
            b"$ebx" => regs.ebx,
            b"$ecx" => regs.ecx,
            b"$edx" => regs.edx,
            b"$esi" => regs.esi,
            b"$edi" => regs.edi,
            _ => return None,
        })
    };
    let bad = Error::Expression;
    let keeps_ebp = keeps_frame_pointer(program);
    for (n, token) in program
        .split(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
        .filter(|t| !t.is_empty())
        .enumerate()
    {
        if n >= MAX_TOKENS {
            return Err(bad);
        }
        let mut pop = || stack.pop().ok_or(bad);
        match token {
            b"+" | b"-" | b"*" | b"/" | b"%" | b"@" => {
                let b = pop()?.get(&names, &reg)?;
                let a = pop()?.get(&names, &reg)?;
                let v = match token[0] {
                    b'+' => a.wrapping_add(b),
                    b'-' => a.wrapping_sub(b),
                    b'*' => a.wrapping_mul(b),
                    b'/' => a.checked_div(b).ok_or(bad)?,
                    b'%' => a.checked_rem(b).ok_or(bad)?,
                    _ => {
                        if b == 0 {
                            return Err(bad);
                        }
                        a & !(b.wrapping_sub(1))
                    }
                };
                stack.push(Value::Number(v));
            }
            b"^" => {
                let a = pop()?.get(&names, &reg)?;
                stack.push(Value::Number(read_u32(env.memory, a)?));
            }
            b"=" => {
                let v = pop()?.get(&names, &reg)?;
                let Value::Name(name) = pop()? else {
                    return Err(bad);
                };
                match names.iter_mut().find(|(n, _)| *n == name) {
                    Some(slot) => slot.1 = v,
                    None => names.push((name, v)),
                }
            }
            // `.raSearch`: past the frame's locals and saved registers;
            // `.raSearchStart`: from the stack pointer (code, such as an
            // exception filter's call, run on a frame it didn't set up).
            b".raSearch" => {
                let at = *ra_search
                    .get_or_insert_with(|| search(env, start, keeps_ebp.then_some(regs.ebp)));
                stack.push(Value::Number(at));
            }
            b".raSearchStart" => {
                let at = *ra_search_start.get_or_insert_with(|| {
                    search(env, context.esp.wrapping_add(env.callee_params), None)
                });
                stack.push(Value::Number(at));
            }
            b".cbSavedRegs" => stack.push(Value::Number(u32::from(d.saved_regs))),
            b".cbLocals" => stack.push(Value::Number(d.locals)),
            b".cbParams" => stack.push(Value::Number(d.params)),
            b".cbCalleeParams" => stack.push(Value::Number(env.callee_params)),
            _ if token[0] == b'$' => stack.push(Value::Name(canonical(token))),
            _ => {
                let (neg, digits) = match token.strip_prefix(b"-") {
                    Some(d) => (true, d),
                    None => (false, token),
                };
                let v = parse_number(digits).ok_or(bad)?;
                stack.push(Value::Number(if neg { v.wrapping_neg() } else { v }));
            }
        }
    }
    // The caller's registers: those the program assigned.
    let get = |name: &[u8]| names.iter().find(|(n, _)| *n == name).map(|&(_, v)| v);
    let eip = get(b"$eip").ok_or(bad)?;
    let esp = get(b"$esp").ok_or(bad)?;
    let mut caller = *context;
    caller.eip = eip;
    caller.esp = esp;
    for (name, slot) in [
        (&b"$ebp"[..], &mut caller.ebp),
        (b"$ebx", &mut caller.ebx),
        (b"$esi", &mut caller.esi),
        (b"$edi", &mut caller.edi),
    ] {
        if let Some(v) = get(name) {
            *slot = v;
        }
    }
    *context = caller;
    Ok(esp.wrapping_sub(4))
}

/// Whether a program restores EBP from just under the return address it
/// searches for (`$T1 .raSearch = ... $ebp $T1 4 - ^ =`): the frame keeps
/// EBP as its frame pointer there.
fn keeps_frame_pointer(program: &[u8]) -> bool {
    let tokens: Vec<&[u8]> = program
        .split(u8::is_ascii_whitespace)
        .filter(|t| !t.is_empty())
        .take(MAX_TOKENS)
        .collect();
    let Some(ra) = tokens
        .windows(3)
        .find(|w| w[1] == b".raSearch" && w[2] == b"=")
        .map(|w| w[0])
    else {
        return false;
    };
    tokens.windows(6).any(|w| {
        canonical(w[0]) == b"$ebp"
            && w[1] == ra
            && w[2] == b"4"
            && w[3] == b"-"
            && w[4] == b"^"
            && w[5] == b"="
    })
}

/// A register's name for its CodeView number (`$20` is `$ebx`), as
/// MSVC's programs also name them.
fn canonical(name: &[u8]) -> &[u8] {
    match name {
        b"$17" => b"$eax",
        b"$18" => b"$ecx",
        b"$19" => b"$edx",
        b"$20" => b"$ebx",
        b"$21" => b"$esp",
        b"$22" => b"$ebp",
        b"$23" => b"$esi",
        b"$24" => b"$edi",
        b"$33" => b"$eip",
        _ => name,
    }
}

fn parse_number(digits: &[u8]) -> Option<u32> {
    let (radix, digits) = match digits {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        _ => (10, digits),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &c in digits {
        let d = char::from(c).to_digit(radix)?;
        v = v.checked_mul(radix)?.checked_add(d)?;
    }
    Some(v)
}

/// A value on a program's stack: a number, or a name not yet looked up
/// (the left side of an assignment).
#[derive(Clone, Copy)]
enum Value<'p> {
    Number(u32),
    Name(&'p [u8]),
}

impl Value<'_> {
    fn get(&self, names: &[(&[u8], u32)], reg: &dyn Fn(&[u8]) -> Option<u32>) -> Result<u32> {
        match *self {
            Value::Number(v) => Ok(v),
            Value::Name(n) => names
                .iter()
                .rev()
                .find(|(m, _)| *m == n)
                .map(|&(_, v)| v)
                .or_else(|| reg(n))
                .ok_or(Error::Expression),
        }
    }
}

/// Unwinds `context`'s frame, which `record` describes (`program` being
/// its FrameData program's text, if it has one), or with no record by the
/// EBP chain: `context` becomes the caller's.
pub fn unwind(
    context: &mut Context,
    record: Option<Record>,
    program: Option<&[u8]>,
    env: &Env<'_>,
) -> Result<Frame> {
    let params = record.map_or(0, |r| r.params());
    // In a function's prolog its frame isn't set up: what the record says
    // of the body doesn't hold yet.
    let prolog = match record {
        Some(Record::FrameData(d)) => {
            d.is_function_start && env.rva.wrapping_sub(d.start) < u32::from(d.prolog)
        }
        Some(Record::Fpo(f)) => env.rva.wrapping_sub(f.start) < u32::from(f.prolog),
        None => false,
    };
    if prolog {
        let at = in_prolog(context, env)?;
        return Ok(Frame {
            method: Method::Prolog,
            return_address_at: at,
            params,
        });
    }
    match record {
        Some(Record::FrameData(d)) => {
            if let Some(p) = program.filter(|p| !p.is_empty()) {
                let at = run_program(p, &d, context, env)?;
                return Ok(Frame {
                    method: Method::Program,
                    return_address_at: at,
                    params,
                });
            }
            let at = sizes(context, env, d.locals, u32::from(d.saved_regs), false)?;
            Ok(Frame {
                method: Method::Sizes,
                return_address_at: at,
                params,
            })
        }
        Some(Record::Fpo(f)) if f.frame == 0 => {
            let at = sizes(
                context,
                env,
                f.locals.wrapping_mul(4),
                u32::from(f.regs) * 4,
                f.uses_bp,
            )?;
            Ok(Frame {
                method: Method::Sizes,
                return_address_at: at,
                params,
            })
        }
        Some(Record::Fpo(f)) if f.frame != 3 => Err(Error::Unsupported { rva: f.start }),
        _ => {
            let at = frame_pointer(context, env)?;
            Ok(Frame {
                method: Method::FramePointer,
                return_address_at: at,
                params,
            })
        }
    }
}

/// A frame laid out by sizes: the return address above the callee's
/// arguments, the saved registers, and the locals (EBP saved last among
/// the registers, where the function uses it).
fn sizes(
    context: &mut Context,
    env: &Env<'_>,
    locals: u32,
    saved: u32,
    uses_bp: bool,
) -> Result<u32> {
    let start = context.esp.wrapping_add(locals).wrapping_add(saved);
    let at = search(env, start, uses_bp.then_some(context.ebp));
    let eip = read_u32(env.memory, at)?;
    if uses_bp && saved >= 4 {
        let ebp_at = context
            .esp
            .wrapping_add(env.callee_params)
            .wrapping_add(saved)
            .wrapping_sub(8);
        context.ebp = read_u32(env.memory, ebp_at)?;
    }
    context.eip = eip;
    context.esp = at.wrapping_add(4);
    Ok(at)
}

/// A frame whose prolog hasn't finished: the return address is the first
/// on the stack (above the callee's arguments); registers haven't been
/// changed since they were saved, except EBP once `push ebp; mov ebp, esp`
/// has run (EBP then points just under the return address).
fn in_prolog(context: &mut Context, env: &Env<'_>) -> Result<u32> {
    let at = search(env, context.esp.wrapping_add(env.callee_params), None);
    let eip = read_u32(env.memory, at)?;
    if context.ebp == at.wrapping_sub(4) {
        context.ebp = read_u32(env.memory, context.ebp)?;
    }
    context.eip = eip;
    context.esp = at.wrapping_add(4);
    Ok(at)
}

/// A standard frame: `push ebp; mov ebp, esp`.
fn frame_pointer(context: &mut Context, env: &Env<'_>) -> Result<u32> {
    let ebp = context.ebp;
    let at = ebp.wrapping_add(4);
    let eip = read_u32(env.memory, at)?;
    context.ebp = read_u32(env.memory, ebp)?;
    context.eip = eip;
    context.esp = ebp.wrapping_add(8);
    Ok(at)
}

/// Unwinds a frame whose caller's registers are a `CONTEXT` record at
/// `at`: `ntdll!KiUserExceptionDispatcher`'s, which the kernel enters with
/// pointers to the exception's record and context instead of a return
/// address (its second argument, at its entry ESP + 4, is the context).
/// Which frames these are is the caller's to know, by symbol.
pub fn unwind_context_record(context: &mut Context, memory: &dyn Memory, at: u32) -> Result<Frame> {
    let field = |off: u32| read_u32(memory, at.wrapping_add(off));
    *context = Context {
        edi: field(0x9C)?,
        esi: field(0xA0)?,
        ebx: field(0xA4)?,
        edx: field(0xA8)?,
        ecx: field(0xAC)?,
        eax: field(0xB0)?,
        ebp: field(0xB4)?,
        eip: field(0xB8)?,
        esp: field(0xC4)?,
    };
    Ok(Frame {
        method: Method::ContextRecord,
        return_address_at: at.wrapping_add(0xB8),
        params: 0,
    })
}

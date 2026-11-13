//! DWARF expressions (DWARF 5 section 2.5) evaluated to a value: the
//! stack machine that computes addresses and values from registers and
//! memory, as call frame information and simple variable locations use it.
//!
//! Location descriptions proper (`DW_OP_reg*`, `DW_OP_piece`, implicit
//! values) and operations needing a frame base, an object, TLS, or types
//! are reported as [`ExprError::Unsupported`]. Evaluation is bounded:
//! hostile expressions (loops through `DW_OP_bra`, deep stacks) end with
//! an error, never a hang or a panic.

use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::{Reader, sext};

/// What an expression reads.
pub trait ExprContext {
    /// A register's value, by DWARF register number.
    fn register(&self, register: u16) -> Option<u64>;
    /// `size` bytes (1 to 8) of memory at `address`, as an integer in the
    /// target's byte order.
    fn memory(&self, address: u64, size: u8) -> Option<u64>;
    /// The canonical frame address, for `DW_OP_call_frame_cfa`.
    fn cfa(&self) -> Option<u64> {
        None
    }
}

/// Why an expression has no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExprError {
    /// It ended early, has a malformed operand, or left nothing.
    Malformed,
    /// It uses an operation this evaluator doesn't (with its opcode).
    Unsupported(u8),
    /// A register it reads is unknown.
    Register(u16),
    /// Memory it reads is unavailable.
    Memory(u64),
    /// Division by zero.
    DivisionByZero,
    /// It ran too long or grew too deep.
    TooComplex,
}

/// The most operations evaluated, and the deepest stack.
const MAX_STEPS: usize = 10_000;
const MAX_STACK: usize = 1_000;

// DW_OP_*.
const ADDR: u8 = 0x03;
const DEREF: u8 = 0x06;
const CONST1U: u8 = 0x08;
const CONST1S: u8 = 0x09;
const CONST2U: u8 = 0x0a;
const CONST2S: u8 = 0x0b;
const CONST4U: u8 = 0x0c;
const CONST4S: u8 = 0x0d;
const CONST8U: u8 = 0x0e;
const CONST8S: u8 = 0x0f;
const CONSTU: u8 = 0x10;
const CONSTS: u8 = 0x11;
const DUP: u8 = 0x12;
const DROP: u8 = 0x13;
const OVER: u8 = 0x14;
const PICK: u8 = 0x15;
const SWAP: u8 = 0x16;
const ROT: u8 = 0x17;
const ABS: u8 = 0x19;
const AND: u8 = 0x1a;
const DIV: u8 = 0x1b;
const MINUS: u8 = 0x1c;
const MOD: u8 = 0x1d;
const MUL: u8 = 0x1e;
const NEG: u8 = 0x1f;
const NOT: u8 = 0x20;
const OR: u8 = 0x21;
const PLUS: u8 = 0x22;
const PLUS_UCONST: u8 = 0x23;
const SHL: u8 = 0x24;
const SHR: u8 = 0x25;
const SHRA: u8 = 0x26;
const XOR: u8 = 0x27;
const BRA: u8 = 0x28;
const EQ: u8 = 0x29;
const GE: u8 = 0x2a;
const GT: u8 = 0x2b;
const LE: u8 = 0x2c;
const LT: u8 = 0x2d;
const NE: u8 = 0x2e;
const SKIP: u8 = 0x2f;
const LIT0: u8 = 0x30;
const LIT31: u8 = 0x4f;
const BREG0: u8 = 0x70;
const BREG31: u8 = 0x8f;
const BREGX: u8 = 0x92;
const DEREF_SIZE: u8 = 0x94;
const NOP: u8 = 0x96;
const CALL_FRAME_CFA: u8 = 0x9c;

/// Evaluates `expr` with `initial` already on the stack (bottom first);
/// the value left on top is the result. Values are `address_size` bytes
/// wide: arithmetic wraps to that width.
pub fn evaluate(
    expr: &[u8],
    endian: Endian,
    address_size: u8,
    initial: &[u64],
    context: &dyn ExprContext,
) -> Result<u64, ExprError> {
    let mask = match address_size {
        1..=7 => (1u64 << (8 * u32::from(address_size))) - 1,
        _ => u64::MAX,
    };
    let bits = if address_size == 0 || address_size >= 8 {
        64
    } else {
        8 * u32::from(address_size)
    };
    // A value's signed reading, at the address width.
    let signed = |v: u64| -> i64 {
        let shift = 64 - bits;
        ((v << shift) as i64) >> shift
    };
    let mut stack: Vec<u64> = initial.iter().map(|&v| v & mask).collect();
    let mut r = Reader::new(expr, 0, endian);
    let bad = ExprError::Malformed;
    let mut steps = 0usize;
    while !r.is_empty() {
        steps += 1;
        if steps > MAX_STEPS || stack.len() > MAX_STACK {
            return Err(ExprError::TooComplex);
        }
        let op = r.u8().ok_or(bad)?;
        let pop = |s: &mut Vec<u64>| s.pop().ok_or(bad);
        match op {
            ADDR => stack.push(r.uint(usize::from(address_size.clamp(1, 8))).ok_or(bad)?),
            DEREF => {
                let a = pop(&mut stack)?;
                stack.push(
                    context
                        .memory(a, address_size.clamp(1, 8))
                        .ok_or(ExprError::Memory(a))?,
                );
            }
            DEREF_SIZE => {
                let size = r.u8().ok_or(bad)?;
                if !(1..=8).contains(&size) {
                    return Err(bad);
                }
                let a = pop(&mut stack)?;
                stack.push(context.memory(a, size).ok_or(ExprError::Memory(a))?);
            }
            CONST1U => stack.push(r.uint(1).ok_or(bad)?),
            CONST1S => stack.push(sext(r.uint(1).ok_or(bad)?, 1)),
            CONST2U => stack.push(r.uint(2).ok_or(bad)?),
            CONST2S => stack.push(sext(r.uint(2).ok_or(bad)?, 2)),
            CONST4U => stack.push(r.uint(4).ok_or(bad)?),
            CONST4S => stack.push(sext(r.uint(4).ok_or(bad)?, 4)),
            CONST8U | CONST8S => stack.push(r.uint(8).ok_or(bad)?),
            CONSTU => stack.push(r.uleb().ok_or(bad)?),
            CONSTS => stack.push(r.sleb().ok_or(bad)? as u64),
            DUP => stack.push(*stack.last().ok_or(bad)?),
            DROP => {
                pop(&mut stack)?;
            }
            OVER => stack.push(
                *stack
                    .get(stack.len().checked_sub(2).ok_or(bad)?)
                    .ok_or(bad)?,
            ),
            PICK => {
                let i = usize::from(r.u8().ok_or(bad)?);
                let at = stack.len().checked_sub(1 + i).ok_or(bad)?;
                stack.push(stack[at]);
            }
            SWAP => {
                let n = stack.len();
                if n < 2 {
                    return Err(bad);
                }
                stack.swap(n - 1, n - 2);
            }
            ROT => {
                let n = stack.len();
                if n < 3 {
                    return Err(bad);
                }
                // (top, second, third) -> (second, third, top)
                let top = stack[n - 1];
                stack[n - 1] = stack[n - 2];
                stack[n - 2] = stack[n - 3];
                stack[n - 3] = top;
            }
            ABS => {
                let a = pop(&mut stack)?;
                stack.push(signed(a).unsigned_abs());
            }
            NEG => {
                let a = pop(&mut stack)?;
                stack.push(signed(a).wrapping_neg() as u64);
            }
            NOT => {
                let a = pop(&mut stack)?;
                stack.push(!a);
            }
            PLUS_UCONST => {
                let a = pop(&mut stack)?;
                stack.push(a.wrapping_add(r.uleb().ok_or(bad)?));
            }
            AND | DIV | MINUS | MOD | MUL | OR | PLUS | SHL | SHR | SHRA | XOR | EQ | GE | GT
            | LE | LT | NE => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                let (sa, sb) = (signed(a), signed(b));
                let shift = |n: u64| u32::try_from(n).ok().filter(|&n| n < bits);
                stack.push(match op {
                    AND => a & b,
                    OR => a | b,
                    XOR => a ^ b,
                    PLUS => a.wrapping_add(b),
                    MINUS => a.wrapping_sub(b),
                    MUL => a.wrapping_mul(b),
                    DIV => {
                        if sb == 0 {
                            return Err(ExprError::DivisionByZero);
                        }
                        sa.wrapping_div(sb) as u64
                    }
                    MOD => {
                        if b == 0 {
                            return Err(ExprError::DivisionByZero);
                        }
                        (a & mask) % (b & mask)
                    }
                    SHL => shift(b).map_or(0, |n| a << n),
                    SHR => shift(b).map_or(0, |n| (a & mask) >> n),
                    SHRA => match shift(b) {
                        Some(n) => (sa >> n) as u64,
                        None => (sa >> 63) as u64,
                    },
                    EQ => u64::from(sa == sb),
                    GE => u64::from(sa >= sb),
                    GT => u64::from(sa > sb),
                    LE => u64::from(sa <= sb),
                    LT => u64::from(sa < sb),
                    _ => u64::from(sa != sb),
                });
            }
            SKIP | BRA => {
                let d = sext(r.uint(2).ok_or(bad)?, 2) as i64;
                let take = op == SKIP || pop(&mut stack)? & mask != 0;
                if take {
                    let to = (r.pos as i64).checked_add(d).ok_or(bad)?;
                    r.pos = usize::try_from(to)
                        .ok()
                        .filter(|&t| t <= expr.len())
                        .ok_or(bad)?;
                }
            }
            LIT0..=LIT31 => stack.push(u64::from(op - LIT0)),
            BREG0..=BREG31 => {
                let reg = u16::from(op - BREG0);
                let off = r.sleb().ok_or(bad)?;
                let v = context.register(reg).ok_or(ExprError::Register(reg))?;
                stack.push(v.wrapping_add(off as u64));
            }
            BREGX => {
                let reg = u16::try_from(r.uleb().ok_or(bad)?).map_err(|_| bad)?;
                let off = r.sleb().ok_or(bad)?;
                let v = context.register(reg).ok_or(ExprError::Register(reg))?;
                stack.push(v.wrapping_add(off as u64));
            }
            NOP => {}
            CALL_FRAME_CFA => stack.push(context.cfa().ok_or(ExprError::Unsupported(op))?),
            _ => return Err(ExprError::Unsupported(op)),
        }
        if let Some(top) = stack.last_mut() {
            *top &= mask;
        }
    }
    stack.pop().ok_or(bad)
}

/// The DWARF registers an expression reads (through `DW_OP_breg*`), for
/// callers that want to know what it depends on. Stops at the first
/// operation it can't step over.
pub fn registers_read(expr: &[u8], endian: Endian, address_size: u8) -> Vec<u16> {
    let mut out = Vec::new();
    let mut r = Reader::new(expr, 0, endian);
    while let Some(op) = r.u8() {
        let ok = match op {
            BREG0..=BREG31 => {
                out.push(u16::from(op - BREG0));
                r.sleb().is_some()
            }
            BREGX => match (r.uleb(), r.sleb()) {
                (Some(reg), Some(_)) => {
                    out.push(u16::try_from(reg).unwrap_or(u16::MAX));
                    true
                }
                _ => false,
            },
            ADDR => r.uint(usize::from(address_size.clamp(1, 8))).is_some(),
            CONST1U | CONST1S | PICK | DEREF_SIZE => r.u8().is_some(),
            CONST2U | CONST2S | SKIP | BRA => r.uint(2).is_some(),
            CONST4U | CONST4S => r.uint(4).is_some(),
            CONST8U | CONST8S => r.uint(8).is_some(),
            CONSTU | PLUS_UCONST => r.uleb().is_some(),
            CONSTS => r.sleb().is_some(),
            DEREF
            | DUP
            | DROP
            | OVER
            | SWAP
            | ROT
            | ABS..=XOR
            | EQ..=NE
            | LIT0..=LIT31
            | NOP
            | CALL_FRAME_CFA => true,
            _ => false,
        };
        if !ok {
            break;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

//! DWARF call frame information unwinding (`.eh_frame`, `.debug_frame`):
//! applying the unwind rule table's row for a PC (from
//! `hexcavator_dwarf::cfi`) to a frame's registers and its stack.
//!
//! Registers are by DWARF number, so this serves every architecture; the
//! caller says which is the stack pointer. The CFA becomes the caller's
//! stack pointer (unless a rule gives it), and registers without a rule
//! keep their values (the usual reading of "unspecified" for callee-saved
//! registers; callers that track volatility can discard the others).

use alloc::vec::Vec;

use hexcavator_core::Endian;
use hexcavator_dwarf::cfi::{CfaRule, RegisterRule, UnwindRow};
use hexcavator_dwarf::expr::{self, ExprContext, ExprError};

use crate::{Error, Memory, Result};

/// Register values by DWARF number (`None`: unknown).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registers {
    values: Vec<Option<u64>>,
}

impl Registers {
    /// The most registers tracked (DWARF numbers below this).
    pub const LIMIT: u16 = 512;

    pub fn get(&self, register: u16) -> Option<u64> {
        self.values.get(usize::from(register)).copied().flatten()
    }

    pub fn set(&mut self, register: u16, value: Option<u64>) {
        if register >= Self::LIMIT {
            return;
        }
        let i = usize::from(register);
        if i >= self.values.len() {
            if value.is_none() {
                return;
            }
            self.values.resize(i + 1, None);
        }
        self.values[i] = value;
    }

    /// The known registers, in number order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, u64)> + '_ {
        self.values
            .iter()
            .enumerate()
            .filter_map(|(i, v)| Some((u16::try_from(i).ok()?, (*v)?)))
    }
}

/// What the target looks like to the unwinder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub endian: Endian,
    /// 4 or 8.
    pub address_size: u8,
    /// The stack pointer's DWARF number (x86-64 7, i386 4, AArch64 31,
    /// ARM 13).
    pub stack_pointer: u16,
}

/// What an unwind found out about the frame it unwound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The frame's canonical frame address.
    pub cfa: u64,
    /// The return address (the return address column's new value); `None`
    /// if the rules leave it undefined: the outermost frame.
    pub return_address: Option<u64>,
    /// Whether the return address is signed (AArch64 pointer
    /// authentication): the caller strips it.
    pub return_address_signed: bool,
    /// Where each restored register was read from.
    pub saved: Vec<(u16, u64)>,
}

/// Unwinds one frame: `registers` (the frame's) become the caller's.
/// `return_address_register` is the CIE's return address column.
pub fn unwind(
    row: &UnwindRow<'_>,
    return_address_register: u16,
    target: Target,
    registers: &mut Registers,
    memory: &dyn Memory,
) -> Result<Frame> {
    let width = target.address_size.clamp(1, 8);
    let read = |address: u64| -> Result<u64> {
        let mut b = [0u8; 8];
        let n = usize::from(width);
        if !memory.read(address, &mut b[..n]) {
            return Err(Error::Memory { address });
        }
        let mut v = 0u64;
        match target.endian {
            Endian::Little => {
                for &x in b[..n].iter().rev() {
                    v = v << 8 | u64::from(x);
                }
            }
            Endian::Big => {
                for &x in &b[..n] {
                    v = v << 8 | u64::from(x);
                }
            }
        }
        Ok(v)
    };
    let eval = |e: &[u8], cfa: Option<u64>| -> Result<u64> {
        let context = Context {
            registers,
            memory,
            target,
            cfa,
        };
        let initial: &[u64] = match &cfa {
            Some(c) => core::slice::from_ref(c),
            None => &[],
        };
        expr::evaluate(e, target.endian, width, initial, &context).map_err(|e| match e {
            ExprError::Memory(address) => Error::Memory { address },
            ExprError::Register(r) => Error::Register { register: r },
            _ => Error::Expression,
        })
    };

    let cfa = match row.cfa {
        CfaRule::RegisterOffset { register, offset } => registers
            .get(register)
            .ok_or(Error::Register { register })?
            .wrapping_add(offset as u64),
        CfaRule::Expression(e) => eval(e, None)?,
    };
    let mask = if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * u32::from(width))) - 1
    };
    let cfa = cfa & mask;

    // Every rule reads the frame's registers, so compute them all first.
    let mut saved = Vec::new();
    let mut changes: Vec<(u16, Option<u64>)> = Vec::with_capacity(row.registers.len());
    for &(register, rule) in &row.registers {
        let value = match rule {
            RegisterRule::Undefined => None,
            RegisterRule::SameValue => registers.get(register),
            RegisterRule::Offset(o) => {
                let at = cfa.wrapping_add(o as u64) & mask;
                saved.push((register, at));
                Some(read(at)?)
            }
            RegisterRule::ValOffset(o) => Some(cfa.wrapping_add(o as u64) & mask),
            RegisterRule::Register(from) => registers.get(from),
            RegisterRule::Expression(e) => {
                let at = eval(e, Some(cfa))?;
                saved.push((register, at));
                Some(read(at)?)
            }
            RegisterRule::ValExpression(e) => Some(eval(e, Some(cfa))?),
        };
        changes.push((register, value));
    }
    let return_address = match row.rule(return_address_register) {
        Some(_) => changes
            .iter()
            .find(|(r, _)| *r == return_address_register)
            .and_then(|&(_, v)| v),
        // (No rule: the return address is still in its register, as on
        // AArch64 and ARM in a leaf.)
        None => registers.get(return_address_register),
    };
    for (register, value) in changes {
        registers.set(register, value);
    }
    if row.rule(target.stack_pointer).is_none() {
        registers.set(target.stack_pointer, Some(cfa));
    }
    Ok(Frame {
        cfa,
        return_address,
        return_address_signed: row.return_address_signed.unwrap_or(false),
        saved,
    })
}

/// What an expression sees.
struct Context<'a> {
    registers: &'a Registers,
    memory: &'a dyn Memory,
    target: Target,
    cfa: Option<u64>,
}

impl ExprContext for Context<'_> {
    fn register(&self, register: u16) -> Option<u64> {
        self.registers.get(register)
    }

    fn memory(&self, address: u64, size: u8) -> Option<u64> {
        let n = usize::from(size.clamp(1, 8));
        let mut b = [0u8; 8];
        if !self.memory.read(address, &mut b[..n]) {
            return None;
        }
        let mut v = 0u64;
        match self.target.endian {
            Endian::Little => {
                for &x in b[..n].iter().rev() {
                    v = v << 8 | u64::from(x);
                }
            }
            Endian::Big => {
                for &x in &b[..n] {
                    v = v << 8 | u64::from(x);
                }
            }
        }
        Some(v)
    }

    fn cfa(&self) -> Option<u64> {
        self.cfa
    }
}

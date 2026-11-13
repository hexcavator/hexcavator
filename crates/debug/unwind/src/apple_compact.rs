// SPDX-License-Identifier: Apache-2.0 AND Apache-2.0 WITH LLVM-exception
// (The encodings' meaning follows LLVM libunwind's CompactUnwinder.hpp and
// compact_unwind_encoding.h; see crates/debug/unwind/LICENSE-LLVM.)

//! Darwin compact unwind encodings (from `__unwind_info`, read by
//! `hexcavator_macho::unwind_info`) applied to a frame, for x86-64 and
//! ARM64. Registers are by DWARF number, as in [`crate::dwarf_cfi`], and the
//! result is the same [`Frame`].
//!
//! An encoding describes the function's body (after its prolog, before
//! its epilogs): like Apple's unwinder, this assumes the PC is there. An
//! encoding can instead say to use the function's DWARF FDE
//! ([`Step::Dwarf`]), or that there is no unwind information. (32-bit x86
//! encodings, which Apple no longer ships, are not handled.)

use alloc::vec::Vec;

use crate::dwarf_cfi::{Frame, Registers};
use crate::{Error, Memory, Result};

/// What an encoding says to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// The frame was unwound.
    Unwound(Frame),
    /// Use the DWARF FDE at this offset in `__eh_frame`.
    Dwarf { eh_frame_offset: u32 },
    /// The encoding is zero: no unwind information (a leaf, or unknown).
    None,
}

// DWARF register numbers.
const X64_RBX: u16 = 3;
const X64_RBP: u16 = 6;
const X64_RSP: u16 = 7;
const X64_RIP: u16 = 16;
const A64_FP: u16 = 29;
const A64_LR: u16 = 30;
const A64_SP: u16 = 31;
const A64_PC: u16 = 32;
const A64_V0: u16 = 64;

fn read(memory: &dyn Memory, address: u64, size: usize) -> Result<u64> {
    let mut b = [0u8; 8];
    if !memory.read(address, &mut b[..size]) {
        return Err(Error::Memory { address });
    }
    Ok(u64::from_le_bytes(b))
}

/// The x86-64 register a compact encoding's 3-bit number names.
fn x64_register(n: u32) -> Option<u16> {
    match n {
        1 => Some(X64_RBX),
        // r12..r15
        2..=5 => u16::try_from(10 + n).ok(),
        6 => Some(X64_RBP),
        _ => None,
    }
}

/// Applies an x86-64 encoding. `function_start` is the function's address
/// (for frameless functions whose stack size is in their `sub`).
pub fn unwind_x86_64(
    encoding: u32,
    function_start: u64,
    registers: &mut Registers,
    memory: &dyn Memory,
) -> Result<Step> {
    let bad = Error::Encoding { encoding };
    let mut saved = Vec::new();
    let mut restore = |registers: &mut Registers, r: u16, at: u64| -> Result<()> {
        registers.set(r, Some(read(memory, at, 8)?));
        saved.push((r, at));
        Ok(())
    };
    match encoding & 0x0F00_0000 {
        0 if encoding & 0x00FF_FFFF == 0 => Ok(Step::None),
        // RBP frame: registers at rbp - 8 * offset, five 3-bit slots.
        0x0100_0000 => {
            let rbp = registers
                .get(X64_RBP)
                .ok_or(Error::Register { register: X64_RBP })?;
            let offset = u64::from((encoding >> 16) & 0xFF);
            let mut at = rbp.wrapping_sub(8 * offset);
            let mut slots = encoding & 0x7FFF;
            for _ in 0..5 {
                match slots & 7 {
                    0 => {}
                    n => restore(
                        registers,
                        x64_register(n).filter(|&r| r != X64_RBP).ok_or(bad)?,
                        at,
                    )?,
                }
                at = at.wrapping_add(8);
                slots >>= 3;
            }
            // rbp points at the saved rbp, then the return address.
            restore(registers, X64_RBP, rbp)?;
            restore(registers, X64_RIP, rbp.wrapping_add(8))?;
            registers.set(X64_RSP, Some(rbp.wrapping_add(16)));
            Ok(Step::Unwound(Frame {
                cfa: rbp.wrapping_add(16),
                return_address: registers.get(X64_RIP),
                return_address_signed: false,
                saved,
            }))
        }
        // Frameless, the stack size in the encoding or in the `sub`.
        mode @ (0x0200_0000 | 0x0300_0000) => {
            let size_field = (encoding >> 16) & 0xFF;
            let adjust = (encoding >> 13) & 7;
            let count = (encoding >> 10) & 7;
            let mut permutation = encoding & 0x3FF;
            let stack_size = if mode == 0x0300_0000 {
                let sub = read(
                    memory,
                    function_start.wrapping_add(u64::from(size_field)),
                    4,
                )?;
                sub.wrapping_add(8 * u64::from(adjust))
            } else {
                8 * u64::from(size_field)
            };
            if count > 6 {
                return Err(bad);
            }
            // The permutation numbers each register among those left.
            let mut order = [0u32; 6];
            let radices: &[u32] = match count {
                6 | 5 => &[120, 24, 6, 2, 1],
                4 => &[60, 12, 3, 1],
                3 => &[20, 4, 1],
                2 => &[5, 1],
                1 => &[1],
                _ => &[],
            };
            for (i, &r) in radices.iter().enumerate() {
                order[i] = permutation / r;
                permutation -= order[i] * r;
            }
            let mut used = [false; 7];
            let mut regs = [0u16; 6];
            for i in 0..count as usize {
                let mut k = 0;
                let mut found = None;
                for u in 1..7u32 {
                    if !used[u as usize] {
                        if k == order[i] {
                            found = Some(u);
                            break;
                        }
                        k += 1;
                    }
                }
                let u = found.ok_or(bad)?;
                used[u as usize] = true;
                regs[i] = x64_register(u).ok_or(bad)?;
            }
            let rsp = registers
                .get(X64_RSP)
                .ok_or(Error::Register { register: X64_RSP })?;
            let mut at = rsp
                .wrapping_add(stack_size)
                .wrapping_sub(8)
                .wrapping_sub(8 * u64::from(count));
            for &r in &regs[..count as usize] {
                restore(registers, r, at)?;
                at = at.wrapping_add(8);
            }
            // The return address is after the saved registers.
            restore(registers, X64_RIP, at)?;
            registers.set(X64_RSP, Some(at.wrapping_add(8)));
            Ok(Step::Unwound(Frame {
                cfa: at.wrapping_add(8),
                return_address: registers.get(X64_RIP),
                return_address_signed: false,
                saved,
            }))
        }
        0x0400_0000 => Ok(Step::Dwarf {
            eh_frame_offset: encoding & 0x00FF_FFFF,
        }),
        _ => Err(bad),
    }
}

/// The register pairs ARM64 encodings save, by bit: x19..x28, then d8..d15.
const A64_PAIRS: [(u32, u16); 9] = [
    (0x001, 19),
    (0x002, 21),
    (0x004, 23),
    (0x008, 25),
    (0x010, 27),
    (0x100, A64_V0 + 8),
    (0x200, A64_V0 + 10),
    (0x400, A64_V0 + 12),
    (0x800, A64_V0 + 14),
];

/// Restores an ARM64 encoding's register pairs downward from `at`;
/// returns where it ended.
fn arm64_pairs(
    encoding: u32,
    mut at: u64,
    registers: &mut Registers,
    memory: &dyn Memory,
    saved: &mut Vec<(u16, u64)>,
) -> Result<u64> {
    for &(bit, first) in &A64_PAIRS {
        if encoding & bit != 0 {
            for r in [first, first + 1] {
                registers.set(r, Some(read(memory, at, 8)?));
                saved.push((r, at));
                at = at.wrapping_sub(8);
            }
        }
    }
    Ok(at)
}

/// Applies an ARM64 encoding.
pub fn unwind_arm64(encoding: u32, registers: &mut Registers, memory: &dyn Memory) -> Result<Step> {
    let mut saved = Vec::new();
    match encoding & 0x0F00_0000 {
        0 if encoding & 0x00FF_FFFF == 0 => Ok(Step::None),
        // Frameless: registers saved from sp + size down (as libunwind
        // reads them); the return address is still in lr.
        0x0200_0000 => {
            let sp = registers
                .get(A64_SP)
                .ok_or(Error::Register { register: A64_SP })?;
            let size = 16 * u64::from((encoding >> 12) & 0xFFF);
            let end = arm64_pairs(
                encoding,
                sp.wrapping_add(size),
                registers,
                memory,
                &mut saved,
            )?;
            let lr = registers
                .get(A64_LR)
                .ok_or(Error::Register { register: A64_LR })?;
            registers.set(A64_SP, Some(end));
            registers.set(A64_PC, Some(lr));
            Ok(Step::Unwound(Frame {
                cfa: end,
                return_address: Some(lr),
                return_address_signed: false,
                saved,
            }))
        }
        0x0300_0000 => Ok(Step::Dwarf {
            eh_frame_offset: encoding & 0x00FF_FFFF,
        }),
        // A frame: registers below fp; fp and lr at fp.
        mode @ (0x0400_0000 | 0x0500_0000) => {
            let fp = registers
                .get(A64_FP)
                .ok_or(Error::Register { register: A64_FP })?;
            arm64_pairs(encoding, fp.wrapping_sub(8), registers, memory, &mut saved)?;
            let saved_fp = read(memory, fp, 8)?;
            let lr = read(memory, fp.wrapping_add(8), 8)?;
            saved.push((A64_FP, fp));
            saved.push((A64_LR, fp.wrapping_add(8)));
            registers.set(A64_FP, Some(saved_fp));
            registers.set(A64_LR, Some(lr));
            registers.set(A64_SP, Some(fp.wrapping_add(16)));
            registers.set(A64_PC, Some(lr));
            Ok(Step::Unwound(Frame {
                cfa: fp.wrapping_add(16),
                return_address: Some(lr),
                // (arm64e: lr was signed by a pacibsppc.)
                return_address_signed: mode == 0x0500_0000,
                saved,
            }))
        }
        _ => Err(Error::Encoding { encoding }),
    }
}

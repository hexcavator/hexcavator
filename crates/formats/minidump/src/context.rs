//! Thread register contexts: Windows' `CONTEXT` structures (which
//! Crashpad also writes, and Breakpad for x86, x64, and ARM64), and
//! Breakpad's own ARM context.
//!
//! A context is identified by the dump's processor architecture where
//! there is one ([`crate::SystemInfo`]), else by its flags and size.
//! Breakpad's old ARM64 layout (flags 0x80000000, before it adopted
//! Windows') is reported as [`Context::Unknown`].

// (Register fields are named as the registers are.)
#![allow(missing_docs)]

use crate::{cpu, u16_at, u32_at, u64_at};

/// `CONTEXT_i386` (and Breakpad's x86).
pub const CONTEXT_X86: u32 = 0x0001_0000;
/// `CONTEXT_AMD64`.
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
/// `CONTEXT_ARM`.
pub const CONTEXT_ARM: u32 = 0x0020_0000;
/// `CONTEXT_ARM64`.
pub const CONTEXT_ARM64: u32 = 0x0040_0000;
/// Breakpad's ARM (`MD_CONTEXT_ARM`).
pub const BREAKPAD_ARM: u32 = 0x4000_0000;

/// A thread's registers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // (Decoded one at a time.)
pub enum Context {
    /// x86.
    X86(X86),
    /// x64.
    Amd64(Amd64),
    /// ARM (32-bit).
    Arm(Arm),
    /// ARM64.
    Arm64(Arm64),
    /// A layout not decoded: its flags (the first word).
    Unknown {
        /// The context's flags, or 0 if it is too short to have them.
        flags: u32,
    },
}

/// x86 registers (`CONTEXT`, 716 bytes; the first 204 suffice).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86 {
    /// Which groups of registers are valid.
    pub flags: u32,
    pub eip: u32,
    pub esp: u32,
    pub ebp: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub eflags: u32,
    /// GS, FS, ES, DS, CS, SS.
    pub segments: [u32; 6],
}

/// x64 registers (`CONTEXT`, 1232 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Amd64 {
    /// Which groups of registers are valid.
    pub flags: u32,
    pub rip: u64,
    pub rsp: u64,
    /// RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15 (by encoding).
    pub gpr: [u64; 16],
    pub eflags: u32,
    pub mxcsr: u32,
    /// CS, DS, ES, FS, GS, SS.
    pub segments: [u16; 6],
    /// XMM0..XMM15.
    pub xmm: [u128; 16],
}

/// ARM registers (Windows' `CONTEXT`, 416 bytes, or Breakpad's, 368).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arm {
    /// Which groups of registers are valid.
    pub flags: u32,
    /// r0..r12, sp, lr, pc.
    pub r: [u32; 16],
    pub cpsr: u32,
    pub fpscr: u64,
    /// d0..d31.
    pub d: [u64; 32],
}

/// ARM64 registers (`CONTEXT`, 912 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arm64 {
    /// Which groups of registers are valid.
    pub flags: u32,
    pub cpsr: u32,
    /// x0..x28, fp, lr.
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    /// v0..v31.
    pub v: [u128; 32],
    pub fpcr: u32,
    pub fpsr: u32,
}

fn u128_at(d: &[u8], o: usize) -> u128 {
    let lo = u64_at(d, o).unwrap_or(0);
    let hi = u64_at(d, o + 8).unwrap_or(0);
    u128::from(hi) << 64 | u128::from(lo)
}

impl Context {
    /// Decodes a raw context; `architecture` is the dump's
    /// `ProcessorArchitecture`, where it has system information.
    pub fn parse(raw: &[u8], architecture: Option<u16>) -> Context {
        let flags = u32_at(raw, 0).unwrap_or(0);
        let amd64_flags = u32_at(raw, 0x30).unwrap_or(0);
        let kind = match architecture {
            Some(cpu::X86) => Some(CONTEXT_X86),
            Some(cpu::AMD64) => Some(CONTEXT_AMD64),
            Some(cpu::ARM) if flags & BREAKPAD_ARM != 0 => Some(BREAKPAD_ARM),
            Some(cpu::ARM) => Some(CONTEXT_ARM),
            Some(cpu::ARM64 | cpu::ARM64_OLD) if flags & CONTEXT_ARM64 != 0 => Some(CONTEXT_ARM64),
            Some(_) => None,
            // (By the flags, and the size each has.)
            None if raw.len() >= 0x4D0 && amd64_flags & CONTEXT_AMD64 != 0 => Some(CONTEXT_AMD64),
            None if raw.len() >= 0x390 && flags & CONTEXT_ARM64 != 0 => Some(CONTEXT_ARM64),
            None if raw.len() >= 0x1A0 && flags & CONTEXT_ARM != 0 => Some(CONTEXT_ARM),
            None if raw.len() >= 368 && flags & BREAKPAD_ARM != 0 => Some(BREAKPAD_ARM),
            None if raw.len() >= 0xCC && flags & CONTEXT_X86 != 0 => Some(CONTEXT_X86),
            None => None,
        };
        let unknown = Context::Unknown { flags };
        match kind {
            Some(CONTEXT_X86) if raw.len() >= 0xCC => Context::X86(X86 {
                flags,
                edi: u32_at(raw, 0x9C).unwrap_or(0),
                esi: u32_at(raw, 0xA0).unwrap_or(0),
                ebx: u32_at(raw, 0xA4).unwrap_or(0),
                edx: u32_at(raw, 0xA8).unwrap_or(0),
                ecx: u32_at(raw, 0xAC).unwrap_or(0),
                eax: u32_at(raw, 0xB0).unwrap_or(0),
                ebp: u32_at(raw, 0xB4).unwrap_or(0),
                eip: u32_at(raw, 0xB8).unwrap_or(0),
                eflags: u32_at(raw, 0xC0).unwrap_or(0),
                esp: u32_at(raw, 0xC4).unwrap_or(0),
                segments: [0x8C, 0x90, 0x94, 0x98, 0xBC, 0xC8].map(|o| u32_at(raw, o).unwrap_or(0)),
            }),
            Some(CONTEXT_AMD64) if raw.len() >= 0x4D0 => {
                let mut gpr = [0u64; 16];
                for (i, g) in gpr.iter_mut().enumerate() {
                    *g = u64_at(raw, 0x78 + 8 * i).unwrap_or(0);
                }
                let mut xmm = [0u128; 16];
                for (i, x) in xmm.iter_mut().enumerate() {
                    *x = u128_at(raw, 0x1A0 + 16 * i);
                }
                Context::Amd64(Amd64 {
                    flags: amd64_flags,
                    rip: u64_at(raw, 0xF8).unwrap_or(0),
                    rsp: gpr[4],
                    gpr,
                    eflags: u32_at(raw, 0x44).unwrap_or(0),
                    mxcsr: u32_at(raw, 0x34).unwrap_or(0),
                    segments: [0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x42]
                        .map(|o| u16_at(raw, o).unwrap_or(0)),
                    xmm,
                })
            }
            Some(CONTEXT_ARM) if raw.len() >= 0x1A0 => {
                let mut a = Arm {
                    flags,
                    cpsr: u32_at(raw, 0x44).unwrap_or(0),
                    fpscr: u64::from(u32_at(raw, 0x48).unwrap_or(0)),
                    ..Arm::default()
                };
                for (i, r) in a.r.iter_mut().enumerate() {
                    *r = u32_at(raw, 4 + 4 * i).unwrap_or(0);
                }
                for (i, d) in a.d.iter_mut().enumerate() {
                    *d = u64_at(raw, 0x50 + 8 * i).unwrap_or(0);
                }
                Context::Arm(a)
            }
            Some(BREAKPAD_ARM) if raw.len() >= 368 => {
                // context_flags, iregs[16], cpsr, then float_save: fpscr
                // (u64), regs[32] (u64), extra[8].
                let mut a = Arm {
                    flags,
                    cpsr: u32_at(raw, 68).unwrap_or(0),
                    fpscr: u64_at(raw, 72).unwrap_or(0),
                    ..Arm::default()
                };
                for (i, r) in a.r.iter_mut().enumerate() {
                    *r = u32_at(raw, 4 + 4 * i).unwrap_or(0);
                }
                for (i, d) in a.d.iter_mut().enumerate() {
                    *d = u64_at(raw, 80 + 8 * i).unwrap_or(0);
                }
                Context::Arm(a)
            }
            Some(CONTEXT_ARM64) if raw.len() >= 0x390 => {
                let mut a = Arm64 {
                    flags,
                    cpsr: u32_at(raw, 4).unwrap_or(0),
                    sp: u64_at(raw, 0x100).unwrap_or(0),
                    pc: u64_at(raw, 0x108).unwrap_or(0),
                    fpcr: u32_at(raw, 0x310).unwrap_or(0),
                    fpsr: u32_at(raw, 0x314).unwrap_or(0),
                    ..Arm64::default()
                };
                for (i, x) in a.x.iter_mut().enumerate() {
                    *x = u64_at(raw, 8 + 8 * i).unwrap_or(0);
                }
                for (i, v) in a.v.iter_mut().enumerate() {
                    *v = u128_at(raw, 0x110 + 16 * i);
                }
                Context::Arm64(a)
            }
            _ => unknown,
        }
    }

    /// The instruction pointer.
    pub fn pc(&self) -> Option<u64> {
        match self {
            Context::X86(c) => Some(u64::from(c.eip)),
            Context::Amd64(c) => Some(c.rip),
            Context::Arm(c) => Some(u64::from(c.r[15])),
            Context::Arm64(c) => Some(c.pc),
            Context::Unknown { .. } => None,
        }
    }

    /// The stack pointer.
    pub fn sp(&self) -> Option<u64> {
        match self {
            Context::X86(c) => Some(u64::from(c.esp)),
            Context::Amd64(c) => Some(c.rsp),
            Context::Arm(c) => Some(u64::from(c.r[13])),
            Context::Arm64(c) => Some(c.sp),
            Context::Unknown { .. } => None,
        }
    }
}

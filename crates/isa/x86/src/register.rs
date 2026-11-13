//! x86 registers.

use core::fmt;

/// The kind of a register.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RegClass {
    /// `al`, `cl`, ..., `r31b` (index 4-7 are `spl`..`dil`).
    Gpr8,
    /// `ah`, `ch`, `dh`, `bh` (index 0-3).
    Gpr8High,
    /// `ax`, `cx`, ... (16-bit).
    Gpr16,
    /// `eax`, `ecx`, ... (32-bit).
    Gpr32,
    /// `rax`, `rcx`, ... (64-bit).
    Gpr64,
    /// `es`, `cs`, `ss`, `ds`, `fs`, `gs`.
    Segment,
    /// `cr0`..`cr15`.
    Control,
    /// `dr0`..`dr15`.
    Debug,
    /// `st(0)`..`st(7)`; index 8 is the implicit top of stack, `st`.
    St,
    /// MMX `mm0`..`mm7`.
    Mmx,
    /// `xmm0`..`xmm31`.
    Xmm,
    /// `ymm0`..`ymm31`.
    Ymm,
    /// `zmm0`..`zmm31`.
    Zmm,
    /// AVX-512 opmask registers `k0`..`k7`.
    Mask,
    /// MPX bound registers `bnd0`..`bnd3`.
    Bound,
    /// AMX tile registers `tmm0`..`tmm7`.
    Tmm,
    /// `rip`, `eip`, `ip` (by size: index 0, 1, 2).
    Ip,
    /// 386/486 test registers `tr0`..`tr7`.
    Test,
}

/// A register: a class and an index within it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Register {
    class: RegClass,
    index: u8,
}

impl Register {
    /// Register `index` of `class`.
    #[inline]
    pub const fn new(class: RegClass, index: u8) -> Self {
        Self { class, index }
    }

    /// Its class.
    #[inline]
    pub const fn class(self) -> RegClass {
        self.class
    }

    /// Its number in its class.
    #[inline]
    pub const fn index(self) -> u8 {
        self.index
    }

    /// A general-purpose register of `size` bytes (1, 2, 4, or 8). With
    /// `rex` false, byte registers 4-7 are `ah`..`bh`.
    #[inline]
    pub const fn gpr(size: u8, index: u8, rex: bool) -> Self {
        match size {
            1 if !rex && index >= 4 && index < 8 => Self::new(RegClass::Gpr8High, index - 4),
            1 => Self::new(RegClass::Gpr8, index),
            2 => Self::new(RegClass::Gpr16, index),
            4 => Self::new(RegClass::Gpr32, index),
            _ => Self::new(RegClass::Gpr64, index),
        }
    }

    /// A vector register of `bytes` width (16, 32, or 64).
    #[inline]
    pub const fn vector(bytes: u16, index: u8) -> Self {
        match bytes {
            32 => Self::new(RegClass::Ymm, index),
            64 => Self::new(RegClass::Zmm, index),
            _ => Self::new(RegClass::Xmm, index),
        }
    }

    /// The size of the register in bytes, where meaningful.
    pub const fn size(self) -> u16 {
        match self.class {
            RegClass::Gpr8 | RegClass::Gpr8High => 1,
            RegClass::Gpr16 | RegClass::Segment => 2,
            RegClass::Gpr32 => 4,
            RegClass::Gpr64 | RegClass::Mmx | RegClass::Mask => 8,
            RegClass::Control | RegClass::Debug | RegClass::Test => 8,
            RegClass::St => 10,
            RegClass::Xmm | RegClass::Bound => 16,
            RegClass::Ymm => 32,
            RegClass::Zmm => 64,
            RegClass::Tmm => 1024,
            RegClass::Ip => match self.index {
                0 => 8,
                1 => 4,
                _ => 2,
            },
        }
    }

    /// The full-width register that contains this one: `rax` for `al`,
    /// `ah`, `ax`, and `eax`; `zmm0` for `xmm0` and `ymm0`; `st(0)` for `st`.
    /// This is the unit of aliasing for dataflow analysis.
    pub const fn full(self) -> Self {
        match self.class {
            RegClass::Gpr8 | RegClass::Gpr16 | RegClass::Gpr32 => {
                Self::new(RegClass::Gpr64, self.index)
            }
            RegClass::Gpr8High => Self::new(RegClass::Gpr64, self.index),
            RegClass::Xmm | RegClass::Ymm => Self::new(RegClass::Zmm, self.index),
            RegClass::St if self.index == 8 => Self::new(RegClass::St, 0),
            RegClass::Ip => Self::new(RegClass::Ip, 0),
            _ => self,
        }
    }

    /// `rax`.
    pub const RAX: Self = Self::new(RegClass::Gpr64, 0);
    /// `rsp`.
    pub const RSP: Self = Self::new(RegClass::Gpr64, 4);
    /// `rip`.
    pub const RIP: Self = Self::new(RegClass::Ip, 0);
    /// `st`: the top of the x87 stack.
    pub const ST: Self = Self::new(RegClass::St, 8);

    /// The register's name, in lowercase Intel syntax.
    pub fn name(self) -> &'static str {
        const GPR64: [&str; 32] = [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
            "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
        ];
        const GPR32: [&str; 32] = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d", "r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d",
            "r23d", "r24d", "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d",
        ];
        const GPR16: [&str; 32] = [
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
            "r13w", "r14w", "r15w", "r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w",
            "r24w", "r25w", "r26w", "r27w", "r28w", "r29w", "r30w", "r31w",
        ];
        const GPR8: [&str; 32] = [
            "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b",
            "r12b", "r13b", "r14b", "r15b", "r16b", "r17b", "r18b", "r19b", "r20b", "r21b", "r22b",
            "r23b", "r24b", "r25b", "r26b", "r27b", "r28b", "r29b", "r30b", "r31b",
        ];
        const HIGH8: [&str; 4] = ["ah", "ch", "dh", "bh"];
        const SEG: [&str; 8] = ["es", "cs", "ss", "ds", "fs", "gs", "?seg6", "?seg7"];
        const CR: [&str; 16] = [
            "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11",
            "cr12", "cr13", "cr14", "cr15",
        ];
        const DR: [&str; 16] = [
            "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11",
            "dr12", "dr13", "dr14", "dr15",
        ];
        const ST: [&str; 9] = [
            "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)", "st",
        ];
        const MM: [&str; 8] = ["mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"];
        const XMM: [&str; 32] = [
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
            "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18",
            "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27",
            "xmm28", "xmm29", "xmm30", "xmm31",
        ];
        const YMM: [&str; 32] = [
            "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9",
            "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18",
            "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27",
            "ymm28", "ymm29", "ymm30", "ymm31",
        ];
        const ZMM: [&str; 32] = [
            "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9",
            "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18",
            "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27",
            "zmm28", "zmm29", "zmm30", "zmm31",
        ];
        const K: [&str; 8] = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
        const BND: [&str; 4] = ["bnd0", "bnd1", "bnd2", "bnd3"];
        const TMM: [&str; 8] = [
            "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7",
        ];
        const IP: [&str; 3] = ["rip", "eip", "ip"];
        const TR: [&str; 8] = ["tr0", "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7"];

        let i = usize::from(self.index);
        let table: &[&str] = match self.class {
            RegClass::Gpr8 => &GPR8,
            RegClass::Gpr8High => &HIGH8,
            RegClass::Gpr16 => &GPR16,
            RegClass::Gpr32 => &GPR32,
            RegClass::Gpr64 => &GPR64,
            RegClass::Segment => &SEG,
            RegClass::Control => &CR,
            RegClass::Debug => &DR,
            RegClass::St => &ST,
            RegClass::Mmx => &MM,
            RegClass::Xmm => &XMM,
            RegClass::Ymm => &YMM,
            RegClass::Zmm => &ZMM,
            RegClass::Mask => &K,
            RegClass::Bound => &BND,
            RegClass::Tmm => &TMM,
            RegClass::Ip => &IP,
            RegClass::Test => &TR,
        };
        table.get(i).copied().unwrap_or("?reg")
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_aliasing() {
        assert_eq!(Register::gpr(1, 4, false).name(), "ah");
        assert_eq!(Register::gpr(1, 4, true).name(), "spl");
        assert_eq!(Register::gpr(4, 17, true).name(), "r17d");
        assert_eq!(
            Register::gpr(1, 7, false).full(),
            Register::new(RegClass::Gpr64, 3)
        );
        assert_eq!(Register::vector(32, 9).full().name(), "zmm9");
        assert_eq!(Register::ST.name(), "st");
        assert_eq!(Register::ST.full().name(), "st(0)");
    }
}

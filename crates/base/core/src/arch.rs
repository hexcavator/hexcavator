//! Instruction set architectures, as every format and analysis names them.
//!
//! One enumeration for all: each format crate maps its own field (a COFF
//! machine, an ELF `e_machine`, a Mach-O CPU type) to it, and analyses
//! (disassembly, references, registers) take it. How a format packages
//! code (Windows' ARM64EC and ARM64X hybrid images, say) isn't an
//! architecture: the format crates say that separately.

/// An instruction set architecture.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Arch {
    /// 32-bit x86 (IA-32).
    X86,
    /// x86-64 (AMD64, Intel 64).
    X64,
    /// 32-bit ARM: A32 and T32 (Thumb).
    Arm,
    /// 64-bit ARM: A64.
    Arm64,
    /// WebAssembly with 32-bit memories.
    Wasm32,
    /// WebAssembly with 64-bit memories (memory64).
    Wasm64,
    /// 32-bit MIPS.
    Mips,
    /// 64-bit MIPS.
    Mips64,
    /// 32-bit PowerPC.
    PowerPc,
    /// 64-bit PowerPC.
    PowerPc64,
    /// 32-bit RISC-V.
    RiscV32,
    /// 64-bit RISC-V.
    RiscV64,
    /// 32-bit LoongArch.
    LoongArch32,
    /// 64-bit LoongArch.
    LoongArch64,
    /// 64-bit z/Architecture (IBM Z).
    S390x,
    /// 32-bit SPARC.
    Sparc,
    /// 64-bit SPARC (SPARC V9).
    Sparc64,
    /// Itanium.
    Ia64,
    /// 32-bit Alpha (Windows NT's).
    Alpha,
    /// 64-bit Alpha.
    Alpha64,
    /// SuperH.
    SuperH,
    /// Motorola 68000.
    M68k,
    /// EFI byte code.
    Ebc,
    /// One a format names that isn't any of these.
    Unknown,
}

impl Arch {
    /// Every architecture, in order.
    pub const ALL: &'static [Arch] = &[
        Arch::X86,
        Arch::X64,
        Arch::Arm,
        Arch::Arm64,
        Arch::Wasm32,
        Arch::Wasm64,
        Arch::Mips,
        Arch::Mips64,
        Arch::PowerPc,
        Arch::PowerPc64,
        Arch::RiscV32,
        Arch::RiscV64,
        Arch::LoongArch32,
        Arch::LoongArch64,
        Arch::S390x,
        Arch::Sparc,
        Arch::Sparc64,
        Arch::Ia64,
        Arch::Alpha,
        Arch::Alpha64,
        Arch::SuperH,
        Arch::M68k,
        Arch::Ebc,
        Arch::Unknown,
    ];

    /// Its usual short name (`x64`, `arm64`, `riscv64`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Wasm32 => "wasm32",
            Arch::Wasm64 => "wasm64",
            Arch::Mips => "mips",
            Arch::Mips64 => "mips64",
            Arch::PowerPc => "powerpc",
            Arch::PowerPc64 => "powerpc64",
            Arch::RiscV32 => "riscv32",
            Arch::RiscV64 => "riscv64",
            Arch::LoongArch32 => "loongarch32",
            Arch::LoongArch64 => "loongarch64",
            Arch::S390x => "s390x",
            Arch::Sparc => "sparc",
            Arch::Sparc64 => "sparc64",
            Arch::Ia64 => "ia64",
            Arch::Alpha => "alpha",
            Arch::Alpha64 => "alpha64",
            Arch::SuperH => "sh",
            Arch::M68k => "m68k",
            Arch::Ebc => "ebc",
            Arch::Unknown => "unknown",
        }
    }

    /// The width of its addresses (and general registers), in bits, if one
    /// width.
    pub fn bits(self) -> Option<u8> {
        Some(match self {
            Arch::X86
            | Arch::Arm
            | Arch::Wasm32
            | Arch::Mips
            | Arch::PowerPc
            | Arch::RiscV32
            | Arch::LoongArch32
            | Arch::Sparc
            | Arch::Alpha
            | Arch::SuperH
            | Arch::M68k => 32,
            Arch::X64
            | Arch::Arm64
            | Arch::Wasm64
            | Arch::Mips64
            | Arch::PowerPc64
            | Arch::RiscV64
            | Arch::LoongArch64
            | Arch::S390x
            | Arch::Sparc64
            | Arch::Ia64
            | Arch::Alpha64 => 64,
            Arch::Ebc | Arch::Unknown => return None,
        })
    }

    /// The size of a pointer in bytes, if one size.
    pub fn pointer_size(self) -> Option<u8> {
        self.bits().map(|b| b / 8)
    }

    /// Whether it's a known architecture.
    pub fn is_known(self) -> bool {
        self != Arch::Unknown
    }
}

impl core::fmt::Display for Arch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_distinct_and_widths_consistent() {
        for (i, a) in Arch::ALL.iter().enumerate() {
            assert!(
                Arch::ALL[i + 1..].iter().all(|b| b.name() != a.name()),
                "{a}"
            );
            assert_eq!(a.pointer_size(), a.bits().map(|b| b / 8));
        }
        assert_eq!(Arch::X64.pointer_size(), Some(8));
        assert_eq!(Arch::Arm.pointer_size(), Some(4));
        assert_eq!(Arch::Unknown.bits(), None);
        assert!(!Arch::Unknown.is_known());
        assert_eq!(Arch::RiscV64.name(), "riscv64");
    }
}

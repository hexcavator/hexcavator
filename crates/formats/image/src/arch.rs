//! Architectures: the instruction set (shared by every crate, from
//! `hexcavator-core`), and how an image mixes code of several (Windows'
//! hybrid images).

use hexcavator_pe::consts::machine;

pub use hexcavator_core::Arch;

/// How an image mixes code: Windows' hybrid images.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hybrid {
    /// ARM64EC: ARM64 code that follows the x64 calling convention, in an
    /// image that may also hold x64 code.
    Arm64Ec,
    /// ARM64X: an ARM64 image that also holds ARM64EC and x64 code.
    Arm64X,
    /// CHPE: x86 code with ARM64 code beside it (Windows on ARM's
    /// compiled hybrid portable executables).
    Chpe,
}

impl Hybrid {
    /// The hybrid a COFF machine value names, if any.
    pub fn from_coff_machine(value: u16) -> Option<Self> {
        match value {
            machine::ARM64EC => Some(Hybrid::Arm64Ec),
            machine::ARM64X => Some(Hybrid::Arm64X),
            machine::CHPE_X86 => Some(Hybrid::Chpe),
            _ => None,
        }
    }

    /// Its usual short name (`arm64ec`, `arm64x`, `chpe`).
    pub fn name(self) -> &'static str {
        match self {
            Hybrid::Arm64Ec => "arm64ec",
            Hybrid::Arm64X => "arm64x",
            Hybrid::Chpe => "chpe",
        }
    }
}

/// A COFF machine value as a short name: the hybrid's (`arm64ec`), else
/// the architecture's (`x64`), else the machine's own name (`R4000`), else
/// `unknown`.
pub fn coff_machine_name(value: u16) -> &'static str {
    if let Some(h) = Hybrid::from_coff_machine(value) {
        return h.name();
    }
    match machine::arch(value) {
        Arch::Unknown => match machine::name(value) {
            Some(name) if value != machine::UNKNOWN => name,
            _ => "unknown",
        },
        arch => arch.name(),
    }
}

/// Whether a COFF machine value is one we know (an object's only magic).
pub fn is_known_coff_machine(value: u16) -> bool {
    value != machine::UNKNOWN && machine::name(value).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coff_machines() {
        assert_eq!(machine::arch(machine::AMD64), Arch::X64);
        assert_eq!(machine::arch(machine::I386), Arch::X86);
        assert_eq!(machine::arch(machine::ARMNT), Arch::Arm);
        assert_eq!(machine::arch(machine::THUMB), Arch::Arm);
        assert_eq!(machine::arch(machine::ARM), Arch::Arm);
        assert_eq!(machine::arch(machine::ARM64), Arch::Arm64);
        assert_eq!(machine::arch(machine::ARM64EC), Arch::Arm64);
        assert_eq!(machine::arch(machine::ARM64X), Arch::Arm64);
        assert_eq!(machine::arch(machine::RISCV64), Arch::RiscV64);
        assert_eq!(machine::arch(0x1234), Arch::Unknown);
        assert_eq!(
            Hybrid::from_coff_machine(machine::ARM64EC),
            Some(Hybrid::Arm64Ec)
        );
        assert_eq!(
            Hybrid::from_coff_machine(machine::ARM64X),
            Some(Hybrid::Arm64X)
        );
        assert_eq!(Hybrid::from_coff_machine(machine::ARM64), None);
    }

    #[test]
    fn names() {
        assert_eq!(coff_machine_name(machine::AMD64), "x64");
        assert_eq!(coff_machine_name(machine::ARM64EC), "arm64ec");
        assert_eq!(coff_machine_name(machine::RISCV64), "riscv64");
        assert_eq!(coff_machine_name(machine::R4000), "mips");
        assert_eq!(coff_machine_name(machine::CEE), "CEE");
        assert_eq!(coff_machine_name(machine::UNKNOWN), "unknown");
        assert_eq!(coff_machine_name(0x1234), "unknown");
        assert!(is_known_coff_machine(machine::RISCV64));
        assert!(!is_known_coff_machine(machine::UNKNOWN));
        assert!(!is_known_coff_machine(0x1234));
    }
}

//! DWARF register numbers, as each architecture's ABI assigns them (the
//! numbers of `DW_OP_reg*`, `DW_OP_breg*`, and call frame information).
//!
//! - x86-64: the System V psABI's table.
//! - x86: the i386 psABI's (Darwin swaps 4 and 5 in its `.eh_frame`, but
//!   not in its DWARF).
//! - AArch64: the Arm ABI's DWARF for the Arm 64-bit Architecture.
//! - Arm: the Arm ABI's DWARF for the Arm Architecture.

use alloc::format;
use alloc::string::String;

use hexcavator_core::Arch;

/// The name of register `n` of `arch`, if the ABI assigns `n`.
pub fn name(arch: Arch, n: u16) -> Option<String> {
    match arch {
        Arch::X64 => x64(n),
        Arch::X86 => x86(n),
        Arch::Arm64 => arm64(n),
        Arch::Arm => arm(n),
        _ => None,
    }
}

/// The register a frame's return address is in (or is described as),
/// which call frame information names.
pub fn return_address(arch: Arch) -> Option<u16> {
    match arch {
        Arch::X64 => Some(16),
        Arch::X86 => Some(8),
        Arch::Arm64 => Some(30),
        Arch::Arm => Some(14),
        _ => None,
    }
}

/// The stack pointer.
pub fn stack_pointer(arch: Arch) -> Option<u16> {
    match arch {
        Arch::X64 => Some(7),
        Arch::X86 => Some(4),
        Arch::Arm64 => Some(31),
        Arch::Arm => Some(13),
        _ => None,
    }
}

fn indexed(prefix: &str, n: u16, first: u16) -> String {
    format!("{prefix}{}", n - first)
}

fn x64(n: u16) -> Option<String> {
    const GPR: [&str; 17] = [
        "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "rip",
    ];
    const SEG: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];
    Some(match n {
        0..=16 => GPR[usize::from(n)].into(),
        17..=32 => indexed("xmm", n, 17),
        33..=40 => indexed("st", n, 33),
        41..=48 => indexed("mm", n, 41),
        49 => "rflags".into(),
        50..=55 => SEG[usize::from(n - 50)].into(),
        58 => "fs.base".into(),
        59 => "gs.base".into(),
        62 => "tr".into(),
        63 => "ldtr".into(),
        64 => "mxcsr".into(),
        65 => "fcw".into(),
        66 => "fsw".into(),
        67..=82 => format!("xmm{}", n - 67 + 16),
        118..=125 => indexed("k", n, 118),
        // APX's extended general-purpose registers.
        130..=145 => format!("r{}", n - 130 + 16),
        _ => return None,
    })
}

fn x86(n: u16) -> Option<String> {
    const GPR: [&str; 10] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags",
    ];
    const SEG: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];
    Some(match n {
        0..=9 => GPR[usize::from(n)].into(),
        11..=18 => indexed("st", n, 11),
        21..=28 => indexed("xmm", n, 21),
        29..=36 => indexed("mm", n, 29),
        37 => "fcw".into(),
        38 => "fsw".into(),
        39 => "mxcsr".into(),
        40..=45 => SEG[usize::from(n - 40)].into(),
        48 => "tr".into(),
        49 => "ldtr".into(),
        93..=100 => indexed("k", n, 93),
        _ => return None,
    })
}

fn arm64(n: u16) -> Option<String> {
    Some(match n {
        0..=28 => indexed("x", n, 0),
        // The frame pointer and link register, by their usual names.
        29 => "fp".into(),
        30 => "lr".into(),
        31 => "sp".into(),
        32 => "pc".into(),
        33 => "elr_mode".into(),
        34 => "ra_sign_state".into(),
        35 => "tpidrro_el0".into(),
        36 => "tpidr_el0".into(),
        37 => "tpidr_el1".into(),
        38 => "tpidr_el2".into(),
        39 => "tpidr_el3".into(),
        46 => "vg".into(),
        47 => "ffr".into(),
        48..=63 => indexed("p", n, 48),
        64..=95 => indexed("v", n, 64),
        96..=127 => indexed("z", n, 96),
        _ => return None,
    })
}

fn arm(n: u16) -> Option<String> {
    Some(match n {
        0..=12 => indexed("r", n, 0),
        13 => "sp".into(),
        14 => "lr".into(),
        15 => "pc".into(),
        // The obsolete single-precision numbering.
        64..=95 => indexed("s", n, 64),
        104..=111 => indexed("wcgr", n, 104),
        112..=127 => indexed("wr", n, 112),
        128 => "spsr".into(),
        129 => "spsr_fiq".into(),
        130 => "spsr_irq".into(),
        131 => "spsr_abt".into(),
        132 => "spsr_und".into(),
        133 => "spsr_svc".into(),
        256..=287 => indexed("d", n, 256),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_by_the_abis() {
        let n = |a, r| name(a, r).unwrap();
        assert_eq!(n(Arch::X64, 0), "rax");
        assert_eq!(n(Arch::X64, 1), "rdx");
        assert_eq!(n(Arch::X64, 7), "rsp");
        assert_eq!(n(Arch::X64, 16), "rip");
        assert_eq!(n(Arch::X64, 17), "xmm0");
        assert_eq!(n(Arch::X64, 32), "xmm15");
        assert_eq!(n(Arch::X64, 67), "xmm16");
        assert_eq!(n(Arch::X64, 82), "xmm31");
        assert_eq!(n(Arch::X64, 130), "r16");
        assert_eq!(n(Arch::X86, 1), "ecx");
        assert_eq!(n(Arch::X86, 4), "esp");
        assert_eq!(n(Arch::X86, 21), "xmm0");
        assert_eq!(n(Arch::Arm64, 0), "x0");
        assert_eq!(n(Arch::Arm64, 29), "fp");
        assert_eq!(n(Arch::Arm64, 31), "sp");
        assert_eq!(n(Arch::Arm64, 64), "v0");
        assert_eq!(n(Arch::Arm64, 127), "z31");
        assert_eq!(n(Arch::Arm, 11), "r11");
        assert_eq!(n(Arch::Arm, 13), "sp");
        assert_eq!(n(Arch::Arm, 256), "d0");
        assert_eq!(n(Arch::Arm, 287), "d31");
        for (a, unassigned) in [
            (Arch::X64, 56),
            (Arch::X86, 10),
            (Arch::Arm64, 40),
            (Arch::Arm, 16),
            (Arch::Wasm32, 0),
        ] {
            assert_eq!(name(a, unassigned), None, "{a:?}");
        }
    }

    #[test]
    fn every_number_names_at_most_one_register() {
        for arch in [Arch::X64, Arch::X86, Arch::Arm64, Arch::Arm] {
            let mut seen = alloc::collections::BTreeSet::new();
            for n in 0..=u16::MAX {
                if let Some(r) = name(arch, n) {
                    assert!(seen.insert(r.clone()), "{arch:?} {r} twice");
                }
            }
            assert!(seen.len() > 30);
            let sp = name(arch, stack_pointer(arch).unwrap()).unwrap();
            assert!(sp.ends_with("sp"), "{sp}");
            assert!(name(arch, return_address(arch).unwrap()).is_some());
        }
    }
}

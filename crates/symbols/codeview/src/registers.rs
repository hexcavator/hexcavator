//! CodeView's register numbers (`CV_REG_*`, `CV_AMD64_*`, `CV_ARM64_*`,
//! as cvconst.h has them), named as the disassemblers write them.

/// The instruction sets (CodeView numbers registers of x86, x64, and
/// ARM64; others have none here).
pub use hexcavator_core::Arch;

const X86_LOW: [&str; 24] = [
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
];

const X64_QWORD: [&str; 16] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// Register `n`'s name on `machine`, if it is one of those read here.
pub fn name(machine: Arch, n: u16) -> Option<String> {
    let s = |x: &str| Some(x.to_string());
    match machine {
        Arch::X86 | Arch::X64 => match n {
            1..=24 => s(X86_LOW[usize::from(n - 1)]),
            128..=135 => Some(format!("st({})", n - 128)),
            154..=161 => Some(format!("xmm{}", n - 154)),
            252..=259 if machine == Arch::X64 => Some(format!("xmm{}", n - 252 + 8)),
            324 => s("sil"),
            325 => s("dil"),
            326 => s("bpl"),
            327 => s("spl"),
            328..=343 if machine == Arch::X64 => s(X64_QWORD[usize::from(n - 328)]),
            344..=351 => Some(format!("r{}b", n - 344 + 8)),
            352..=359 => Some(format!("r{}w", n - 352 + 8)),
            360..=367 => Some(format!("r{}d", n - 360 + 8)),
            368..=383 => Some(format!("ymm{}", n - 368)),
            _ => None,
        },
        Arch::Arm64 => match n {
            10..=40 => Some(format!("w{}", n - 10)),
            41 => s("wzr"),
            50..=78 => Some(match n - 50 {
                16 => "xip0".to_string(),
                17 => "xip1".to_string(),
                r => format!("x{r}"),
            }),
            79 => s("fp"),
            80 => s("lr"),
            81 => s("sp"),
            82 => s("xzr"),
            100..=131 => Some(format!("s{}", n - 100)),
            140..=171 => Some(format!("d{}", n - 140)),
            180..=211 => Some(format!("q{}", n - 180)),
            _ => None,
        },
        _ => None,
    }
}

/// The register an S_FRAMEPROC frame pointer encoding names (1 the stack
/// pointer, 2 the frame pointer, 3 the base pointer).
pub fn frame_pointer(machine: Arch, encoded: u8) -> Option<&'static str> {
    Some(match (machine, encoded) {
        (Arch::X86, 1) => "esp",
        (Arch::X86, 2) => "ebp",
        (Arch::X86, 3) => "ebx",
        (Arch::X64, 1) => "rsp",
        (Arch::X64, 2) => "rbp",
        (Arch::X64, 3) => "r13",
        (Arch::Arm64, 1) => "sp",
        (Arch::Arm64, 2) => "fp",
        (Arch::Arm64, 3) => "x19",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(name(Arch::X64, 330).as_deref(), Some("rcx"));
        assert_eq!(name(Arch::X64, 18).as_deref(), Some("ecx"));
        assert_eq!(name(Arch::X64, 336).as_deref(), Some("r8"));
        assert_eq!(name(Arch::X64, 367).as_deref(), Some("r15d"));
        assert_eq!(name(Arch::X64, 154).as_deref(), Some("xmm0"));
        assert_eq!(name(Arch::X64, 259).as_deref(), Some("xmm15"));
        assert_eq!(name(Arch::X86, 22).as_deref(), Some("ebp"));
        assert_eq!(name(Arch::X86, 330), None);
        assert_eq!(name(Arch::Arm64, 50).as_deref(), Some("x0"));
        assert_eq!(name(Arch::Arm64, 10).as_deref(), Some("w0"));
        assert_eq!(name(Arch::Arm64, 66).as_deref(), Some("xip0"));
        assert_eq!(name(Arch::Arm64, 79).as_deref(), Some("fp"));
        assert_eq!(name(Arch::Arm64, 141).as_deref(), Some("d1"));
        assert_eq!(name(Arch::Arm64, 0), None);
        assert_eq!(frame_pointer(Arch::X64, 1), Some("rsp"));
        assert_eq!(frame_pointer(Arch::Arm64, 2), Some("fp"));
        assert_eq!(frame_pointer(Arch::X64, 0), None);
    }
}

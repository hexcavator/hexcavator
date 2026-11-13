//! Named values for PE/COFF header fields.

/// `IMAGE_FILE_MACHINE_*` values.
pub mod machine {
    pub const UNKNOWN: u16 = 0x0000;
    pub const I386: u16 = 0x014C;
    pub const R3000_BE: u16 = 0x0160;
    pub const R3000: u16 = 0x0162;
    pub const R4000: u16 = 0x0166;
    pub const R10000: u16 = 0x0168;
    pub const WCEMIPSV2: u16 = 0x0169;
    pub const ALPHA: u16 = 0x0184;
    pub const SH3: u16 = 0x01A2;
    pub const SH3DSP: u16 = 0x01A3;
    pub const SH3E: u16 = 0x01A4;
    pub const SH4: u16 = 0x01A6;
    pub const SH5: u16 = 0x01A8;
    pub const ARM: u16 = 0x01C0;
    pub const THUMB: u16 = 0x01C2;
    pub const ARMNT: u16 = 0x01C4;
    pub const AM33: u16 = 0x01D3;
    pub const POWERPC: u16 = 0x01F0;
    pub const POWERPCFP: u16 = 0x01F1;
    pub const POWERPCBE: u16 = 0x01F2;
    pub const IA64: u16 = 0x0200;
    pub const MIPS16: u16 = 0x0266;
    pub const M68K: u16 = 0x0268;
    pub const ALPHA64: u16 = 0x0284;
    pub const PARISC: u16 = 0x0290;
    pub const MIPSFPU: u16 = 0x0366;
    pub const MIPSFPU16: u16 = 0x0466;
    pub const TRICORE: u16 = 0x0520;
    pub const MPPC_601: u16 = 0x0601;
    pub const CEF: u16 = 0x0CEF;
    pub const EBC: u16 = 0x0EBC;
    pub const CHPE_X86: u16 = 0x3A64;
    pub const RISCV32: u16 = 0x5032;
    pub const RISCV64: u16 = 0x5064;
    pub const RISCV128: u16 = 0x5128;
    pub const LOONGARCH32: u16 = 0x6232;
    pub const LOONGARCH64: u16 = 0x6264;
    pub const AMD64: u16 = 0x8664;
    pub const M32R: u16 = 0x9041;
    pub const ARM64EC: u16 = 0xA641;
    pub const ARM64X: u16 = 0xA64E;
    pub const ARM64: u16 = 0xAA64;
    pub const CEE: u16 = 0xC0EE;

    /// A short display name, or `None` if the value is not a known machine.
    pub const fn name(machine: u16) -> Option<&'static str> {
        Some(match machine {
            UNKNOWN => "Unknown",
            I386 => "x86",
            R3000_BE => "R3000 big-endian",
            R3000 => "R3000",
            R4000 => "R4000",
            R10000 => "R10000",
            WCEMIPSV2 => "WCEMIPSV2",
            ALPHA => "Alpha",
            SH3 => "SH3",
            SH3DSP => "SH3DSP",
            SH3E => "SH3E",
            SH4 => "SH4",
            SH5 => "SH5",
            ARM => "ARM",
            THUMB => "Thumb",
            ARMNT => "ARMNT",
            AM33 => "AM33",
            POWERPC => "PowerPC",
            POWERPCFP => "PowerPCFP",
            POWERPCBE => "PowerPC big-endian",
            IA64 => "IA64",
            MIPS16 => "MIPS16",
            M68K => "M68K",
            ALPHA64 => "Alpha64",
            PARISC => "PA-RISC",
            MIPSFPU => "MIPSFPU",
            MIPSFPU16 => "MIPSFPU16",
            TRICORE => "TriCore",
            MPPC_601 => "PowerPC Mac",
            CEF => "CEF",
            EBC => "EBC",
            CHPE_X86 => "HYBRID_x86_ARM64",
            RISCV32 => "RISCV32",
            RISCV64 => "RISCV64",
            RISCV128 => "RISCV128",
            LOONGARCH32 => "LOONGARCH32",
            LOONGARCH64 => "LOONGARCH64",
            AMD64 => "x64",
            M32R => "M32R",
            ARM64EC => "ARM64EC",
            ARM64X => "ARM64X",
            ARM64 => "ARM64",
            CEE => "CEE",
            _ => return None,
        })
    }

    /// The instruction set a machine value's code is in. (ARM64EC and
    /// ARM64X images hold ARM64 code, with x64 code beside it in places;
    /// CHPE images, x86 code.)
    pub const fn arch(machine: u16) -> hexcavator_core::Arch {
        use hexcavator_core::Arch;
        match machine {
            I386 | CHPE_X86 => Arch::X86,
            AMD64 => Arch::X64,
            ARM | THUMB | ARMNT => Arch::Arm,
            ARM64 | ARM64EC | ARM64X => Arch::Arm64,
            R3000_BE | R3000 | R4000 | R10000 | WCEMIPSV2 | MIPS16 | MIPSFPU | MIPSFPU16 => {
                Arch::Mips
            }
            ALPHA => Arch::Alpha,
            ALPHA64 => Arch::Alpha64,
            SH3 | SH3DSP | SH3E | SH4 | SH5 => Arch::SuperH,
            POWERPC | POWERPCFP | POWERPCBE | MPPC_601 => Arch::PowerPc,
            IA64 => Arch::Ia64,
            M68K => Arch::M68k,
            EBC => Arch::Ebc,
            RISCV32 => Arch::RiscV32,
            RISCV64 => Arch::RiscV64,
            LOONGARCH32 => Arch::LoongArch32,
            LOONGARCH64 => Arch::LoongArch64,
            _ => Arch::Unknown,
        }
    }
}

/// `IMAGE_FILE_*` characteristics.
pub mod file_characteristics {
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    pub const MACHINE_32BIT: u16 = 0x0100;
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    pub const SYSTEM: u16 = 0x1000;
    pub const DLL: u16 = 0x2000;
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// Optional header magic numbers.
pub mod magic {
    pub const PE32: u16 = 0x010B;
    pub const PE32_PLUS: u16 = 0x020B;
    pub const ROM: u16 = 0x0107;
}

/// `IMAGE_SUBSYSTEM_*` values.
pub mod subsystem {
    pub const UNKNOWN: u16 = 0;
    pub const NATIVE: u16 = 1;
    pub const WINDOWS_GUI: u16 = 2;
    pub const WINDOWS_CUI: u16 = 3;
    pub const OS2_CUI: u16 = 5;
    pub const POSIX_CUI: u16 = 7;
    pub const NATIVE_WINDOWS: u16 = 8;
    pub const WINDOWS_CE_GUI: u16 = 9;
    pub const EFI_APPLICATION: u16 = 10;
    pub const EFI_BOOT_SERVICE_DRIVER: u16 = 11;
    pub const EFI_RUNTIME_DRIVER: u16 = 12;
    pub const EFI_ROM: u16 = 13;
    pub const XBOX: u16 = 14;
    pub const WINDOWS_BOOT_APPLICATION: u16 = 16;
    pub const XBOX_CODE_CATALOG: u16 = 17;
}

/// `IMAGE_DLLCHARACTERISTICS_*` flags.
pub mod dll_characteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_ISOLATION: u16 = 0x0200;
    pub const NO_SEH: u16 = 0x0400;
    pub const NO_BIND: u16 = 0x0800;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const WDM_DRIVER: u16 = 0x2000;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

/// `IMAGE_SCN_*` section characteristics.
pub mod section_characteristics {
    pub const TYPE_NO_PAD: u32 = 0x0000_0008;
    pub const CNT_CODE: u32 = 0x0000_0020;
    pub const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const LNK_OTHER: u32 = 0x0000_0100;
    pub const LNK_INFO: u32 = 0x0000_0200;
    pub const LNK_REMOVE: u32 = 0x0000_0800;
    pub const LNK_COMDAT: u32 = 0x0000_1000;
    pub const NO_DEFER_SPEC_EXC: u32 = 0x0000_4000;
    pub const GPREL: u32 = 0x0000_8000;
    pub const MEM_PURGEABLE: u32 = 0x0002_0000;
    pub const MEM_LOCKED: u32 = 0x0004_0000;
    pub const MEM_PRELOAD: u32 = 0x0008_0000;
    /// Objects only: `(flags & ALIGN_MASK) >> 20` is log2(alignment) + 1.
    pub const ALIGN_MASK: u32 = 0x00F0_0000;
    pub const LNK_NRELOC_OVFL: u32 = 0x0100_0000;
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
    pub const MEM_NOT_CACHED: u32 = 0x0400_0000;
    pub const MEM_NOT_PAGED: u32 = 0x0800_0000;
    pub const MEM_SHARED: u32 = 0x1000_0000;
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;

    /// The alignment an object section requests, in bytes, if any.
    pub const fn alignment(flags: u32) -> Option<u32> {
        match (flags & ALIGN_MASK) >> 20 {
            n @ 1..=14 => Some(1 << (n - 1)),
            _ => None,
        }
    }
}

/// Indexes into the data directory array.
pub mod directory {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const COM_DESCRIPTOR: usize = 14;
}

/// `IMAGE_DEBUG_TYPE_*` values.
pub mod debug_type {
    pub const UNKNOWN: u32 = 0;
    pub const COFF: u32 = 1;
    pub const CODEVIEW: u32 = 2;
    pub const FPO: u32 = 3;
    pub const MISC: u32 = 4;
    pub const EXCEPTION: u32 = 5;
    pub const FIXUP: u32 = 6;
    pub const OMAP_TO_SRC: u32 = 7;
    pub const OMAP_FROM_SRC: u32 = 8;
    pub const BORLAND: u32 = 9;
    pub const RESERVED10: u32 = 10;
    pub const CLSID: u32 = 11;
    pub const VC_FEATURE: u32 = 12;
    pub const POGO: u32 = 13;
    pub const ILTCG: u32 = 14;
    pub const MPX: u32 = 15;
    pub const REPRO: u32 = 16;
    pub const EMBEDDED_PDB: u32 = 17;
    pub const PDB_CHECKSUM: u32 = 19;
    pub const EX_DLLCHARACTERISTICS: u32 = 20;
}

/// `IMAGE_SYM_CLASS_*` storage classes.
pub mod storage_class {
    pub const EXTERNAL: u8 = 2;
    pub const STATIC: u8 = 3;
    pub const SECTION: u8 = 104;
}

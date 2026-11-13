//! A Mach-O file, as llvm-readobj shows it (`--file-headers`,
//! `--sections`, `--relocations`, `--symbols`, `--macho-segment`,
//! `--macho-version-min`, `--macho-dysymtab`, `--needed-libs`), following
//! LLVM's MachODumper.

use hexcavator_macho::MachO;
use hexcavator_macho::consts::*;

use super::{Parts, Printer};

pub fn dump(out: &mut String, file_name: &str, data: &[u8], parts: &Parts) -> Result<(), String> {
    let m = MachO::parse(data).map_err(|e| e.to_string())?;
    one(out, file_name, &m, parts);
    Ok(())
}

fn identity(m: &MachO<'_>) -> (String, &'static str, &'static str) {
    let h = m.header();
    let (format, arch) = match h.cputype {
        CPU_TYPE_X86_64 => ("Mach-O 64-bit x86-64", "x86_64"),
        CPU_TYPE_X86 => ("Mach-O 32-bit i386", "i386"),
        CPU_TYPE_ARM64 => ("Mach-O arm64", "aarch64"),
        CPU_TYPE_ARM64_32 => ("Mach-O arm64 (ILP32)", "aarch64_32"),
        CPU_TYPE_ARM => ("Mach-O arm", "arm"),
        CPU_TYPE_POWERPC => ("Mach-O 32-bit ppc", "powerpc"),
        CPU_TYPE_POWERPC64 => ("Mach-O 64-bit ppc64", "powerpc64"),
        _ => (
            if h.is64 {
                "Mach-O 64-bit unknown"
            } else {
                "Mach-O 32-bit unknown"
            },
            "unknown",
        ),
    };
    (
        format.to_string(),
        arch,
        if h.is64 { "64bit" } else { "32bit" },
    )
}

fn one(out: &mut String, file_name: &str, m: &MachO<'_>, parts: &Parts) {
    let (format, arch, size) = identity(m);
    let mut p = Printer::new(out);
    p.raw("");
    p.line("File", file_name);
    p.line("Format", format);
    p.line("Arch", arch);
    p.line("AddressSize", size);
    if parts.file_headers {
        header(&mut p, m);
    }
    if parts.sections {
        sections(&mut p, m);
    }
    // (llvm-readobj's order: the needed libraries before relocations.)
    if parts.needed_libs {
        needed(&mut p, m);
    }
    if parts.relocations {
        relocations(&mut p, m);
    }
    if parts.symbols {
        symbols(&mut p, m);
    }
    if parts.dyn_symbols {
        p.open("DynamicSymbols [");
        p.close("]");
    }
    if parts.macho_segment {
        segments(&mut p, m);
    }
    if parts.macho_version_min {
        version_min(&mut p, m);
    }
    if parts.macho_dysymtab {
        dysymtab(&mut p, m);
    }
}

fn header(p: &mut Printer<'_>, m: &MachO<'_>) {
    let h = m.header();
    let magic = m
        .data()
        .get(..4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let magic_name = match magic {
        MH_MAGIC => Some("Magic"),
        MH_CIGAM => Some("Cigam"),
        MH_MAGIC_64 => Some("Magic64"),
        MH_CIGAM_64 => Some("Cigam64"),
        _ => None,
    };
    p.open("MachHeader {");
    // (llvm-readobj shows the magic as the host reads it: little-endian.)
    let shown = if h.endian == hexcavator_core::Endian::Big {
        magic.swap_bytes()
    } else {
        magic
    };
    p.enumerated(
        "Magic",
        magic_name.or(if h.is64 {
            Some("Magic64")
        } else {
            Some("Magic")
        }),
        u64::from(shown),
    );
    p.enumerated("CpuType", cpu_type(h.cputype), u64::from(h.cputype));
    let sub = h.cpusubtype & !CPU_SUBTYPE_MASK;
    match cpu_subtype(h.cputype, sub) {
        Some(n) => p.enumerated("CpuSubType", Some(n), u64::from(sub)),
        None => p.line("CpuSubType", format_args!("0x{sub:X}")),
    }
    p.line(
        "CpuCapabilities",
        format_args!("0x{:X}", (h.cpusubtype & CPU_SUBTYPE_MASK) >> 24),
    );
    p.enumerated("FileType", file_type(h.filetype), u64::from(h.filetype));
    p.line("NumOfLoadCommands", h.ncmds);
    p.line("SizeOfLoadCommands", h.sizeofcmds);
    p.flags("Flags", u64::from(h.flags), HEADER_FLAGS);
    if h.is64 {
        let reserved = m
            .data()
            .get(28..32)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        p.line("Reserved", format_args!("0x{reserved:X}"));
    }
    p.close("}");
}

const HEADER_FLAGS: &[(&str, u64)] = &[
    ("MH_NOUNDEFS", 0x1),
    ("MH_INCRLINK", 0x2),
    ("MH_DYLDLINK", 0x4),
    ("MH_BINDATLOAD", 0x8),
    ("MH_PREBOUND", 0x10),
    ("MH_SPLIT_SEGS", 0x20),
    ("MH_LAZY_INIT", 0x40),
    ("MH_TWOLEVEL", 0x80),
    ("MH_FORCE_FLAT", 0x100),
    ("MH_NOMULTIDEFS", 0x200),
    ("MH_NOFIXPREBINDING", 0x400),
    ("MH_PREBINDABLE", 0x800),
    ("MH_ALLMODSBOUND", 0x1000),
    ("MH_SUBSECTIONS_VIA_SYMBOLS", 0x2000),
    ("MH_CANONICAL", 0x4000),
    ("MH_WEAK_DEFINES", 0x8000),
    ("MH_BINDS_TO_WEAK", 0x1_0000),
    ("MH_ALLOW_STACK_EXECUTION", 0x2_0000),
    ("MH_ROOT_SAFE", 0x4_0000),
    ("MH_SETUID_SAFE", 0x8_0000),
    ("MH_NO_REEXPORTED_DYLIBS", 0x10_0000),
    ("MH_PIE", 0x20_0000),
    ("MH_DEAD_STRIPPABLE_DYLIB", 0x40_0000),
    ("MH_HAS_TLV_DESCRIPTORS", 0x80_0000),
    ("MH_NO_HEAP_EXECUTION", 0x100_0000),
    ("MH_APP_EXTENSION_SAFE", 0x200_0000),
];

fn cpu_type(t: u32) -> Option<&'static str> {
    Some(match t {
        0xFFFF_FFFF => "Any",
        CPU_TYPE_X86 => "X86",
        CPU_TYPE_X86_64 => "X86-64",
        10 => "Mc98000",
        CPU_TYPE_ARM => "Arm",
        CPU_TYPE_ARM64 => "Arm64",
        CPU_TYPE_ARM64_32 => "Arm64 (ILP32)",
        14 => "Sparc",
        CPU_TYPE_POWERPC => "PowerPC",
        CPU_TYPE_POWERPC64 => "PowerPC64",
        _ => return None,
    })
}

fn cpu_subtype(t: u32, s: u32) -> Option<&'static str> {
    Some(match (t, s) {
        (CPU_TYPE_X86, 3) => "CPU_SUBTYPE_I386_ALL",
        (CPU_TYPE_X86_64, 3) => "CPU_SUBTYPE_X86_64_ALL",
        (CPU_TYPE_X86_64, 4) => "CPU_SUBTYPE_X86_ARCH1",
        (CPU_TYPE_X86_64, 8) => "CPU_SUBTYPE_X86_64_H",
        (CPU_TYPE_ARM64, 0) => "CPU_SUBTYPE_ARM64_ALL",
        (CPU_TYPE_ARM64, 1) => "CPU_SUBTYPE_ARM64_V8",
        (CPU_TYPE_ARM64, 2) => "CPU_SUBTYPE_ARM64E",
        (CPU_TYPE_ARM64_32, 1) => "CPU_SUBTYPE_ARM64_32_V8",
        (CPU_TYPE_ARM, 0) => "CPU_SUBTYPE_ARM_ALL",
        (CPU_TYPE_ARM, 5) => "CPU_SUBTYPE_ARM_V4T",
        (CPU_TYPE_ARM, 6) => "CPU_SUBTYPE_ARM_V6",
        (CPU_TYPE_ARM, 7) => "CPU_SUBTYPE_ARM_V5",
        (CPU_TYPE_ARM, 9) => "CPU_SUBTYPE_ARM_V7",
        (CPU_TYPE_ARM, 11) => "CPU_SUBTYPE_ARM_V7S",
        (CPU_TYPE_ARM, 12) => "CPU_SUBTYPE_ARM_V7K",
        (CPU_TYPE_ARM, 14) => "CPU_SUBTYPE_ARM_V6M",
        (CPU_TYPE_ARM, 15) => "CPU_SUBTYPE_ARM_V7M",
        (CPU_TYPE_ARM, 16) => "CPU_SUBTYPE_ARM_V7EM",
        (CPU_TYPE_POWERPC, 0) => "CPU_SUBTYPE_POWERPC_ALL",
        (14, 0) => "CPU_SUBTYPE_SPARC_ALL",
        _ => return None,
    })
}

fn file_type(t: u32) -> Option<&'static str> {
    Some(match t {
        MH_OBJECT => "Relocatable",
        MH_EXECUTE => "Executable",
        MH_FVMLIB => "FixedVMLibrary",
        MH_CORE => "Core",
        MH_PRELOAD => "PreloadedExecutable",
        MH_DYLIB => "DynamicLibrary",
        MH_DYLINKER => "DynamicLinker",
        MH_BUNDLE => "Bundle",
        MH_DYLIB_STUB => "DynamicLibraryStub",
        MH_DSYM => "DWARFSymbol",
        MH_KEXT_BUNDLE => "KextBundle",
        _ => return None,
    })
}

/// A name as llvm-readobj's printBinary shows it: the text, then its 16
/// bytes in hex.
fn binary(name: &[u8]) -> String {
    let mut raw = [0u8; 16];
    for (r, b) in raw.iter_mut().zip(name) {
        *r = *b;
    }
    let hex: Vec<String> = raw.iter().map(|b| format!("{b:02X}")).collect();
    format!("{} ({})", String::from_utf8_lossy(name), hex.join(" "))
}

const SECTION_TYPES: &[&str] = &[
    "Regular",
    "ZeroFill",
    "CStringLiterals",
    "4ByteLiterals",
    "8ByteLiterals",
    "LiteralPointers",
    "NonLazySymbolPointers",
    "LazySymbolPointers",
    "SymbolStubs",
    "ModInitFuncPointers",
    "ModTermFuncPointers",
    "Coalesced",
    "GBZeroFill",
    "Interposing",
    "16ByteLiterals",
    "DTraceDOF",
    "LazyDylibSymbolPointers",
    "ThreadLocalRegular",
    "ThreadLocalZerofill",
    "ThreadLocalVariables",
    "ThreadLocalVariablePointers",
    "ThreadLocalInitFunctionPointers",
];

const SECTION_ATTRIBUTES: &[(&str, u64)] = &[
    ("LocReloc", 1 << 0),
    ("ExtReloc", 1 << 1),
    ("SomeInstructions", 1 << 2),
    ("Debug", 1 << 17),
    ("SelfModifyingCode", 1 << 18),
    ("LiveSupport", 1 << 19),
    ("NoDeadStrip", 1 << 20),
    ("StripStaticSyms", 1 << 21),
    ("NoTOC", 1 << 22),
    ("PureInstructions", 1 << 23),
];

fn sections(p: &mut Printer<'_>, m: &MachO<'_>) {
    let is64 = m.header().is64;
    p.open("Sections [");
    for s in m.sections() {
        p.open("Section {");
        p.line("Index", s.index);
        p.line("Name", binary(s.sectname));
        p.line("Segment", binary(s.segname));
        p.line("Address", format_args!("0x{:X}", s.addr));
        p.line("Size", format_args!("0x{:X}", s.size));
        p.line("Offset", s.offset);
        p.line("Alignment", s.align);
        p.line("RelocationOffset", format_args!("0x{:X}", s.reloff));
        p.line("RelocationCount", s.nreloc);
        let kind = s.flags & 0xFF;
        p.enumerated(
            "Type",
            SECTION_TYPES.get(kind as usize).copied(),
            u64::from(kind),
        );
        p.flags("Attributes", u64::from(s.flags >> 8), SECTION_ATTRIBUTES);
        p.line("Reserved1", format_args!("0x{:X}", s.reserved1));
        p.line("Reserved2", format_args!("0x{:X}", s.reserved2));
        if is64 {
            p.line("Reserved3", format_args!("0x{:X}", s.reserved3));
        }
        p.close("}");
    }
    p.close("]");
}

fn relocations(p: &mut Printer<'_>, m: &MachO<'_>) {
    let syms = m.symbols();
    let sections = m.sections();
    let data = m.data();
    let big = m.header().endian == hexcavator_core::Endian::Big;
    let word = |at: usize| -> Option<u32> {
        let b: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    p.open("Relocations [");
    for s in &sections {
        if s.nreloc == 0 {
            continue;
        }
        p.open(&format!(
            "Section {} {{",
            String::from_utf8_lossy(s.sectname)
        ));
        for i in 0..s.nreloc.min(1 << 20) as usize {
            let at = s.reloff as usize + i * 8;
            let (Some(a), Some(b)) = (word(at), word(at + 4)) else {
                break;
            };
            if a & 0x8000_0000 != 0 {
                // Scattered.
                let pcrel = (a >> 30) & 1;
                let len = (a >> 28) & 3;
                let kind = (a >> 24) & 0xF;
                let offset = a & 0x00FF_FFFF;
                p.raw(format_args!(
                    "0x{offset:X} {pcrel} {len} n/a {} 1 0x{b:X}",
                    reloc_type(m.header().cputype, kind)
                ));
                continue;
            }
            let symnum = b & 0x00FF_FFFF;
            let pcrel = (b >> 24) & 1;
            let len = (b >> 25) & 3;
            let ext = (b >> 27) & 1;
            let kind = b >> 28;
            let target = if ext == 1 {
                syms.get(symnum as usize).map_or_else(
                    || "-".to_string(),
                    |s| String::from_utf8_lossy(s.name).into_owned(),
                )
            } else {
                sections.get((symnum as usize).wrapping_sub(1)).map_or_else(
                    || "-".to_string(),
                    |s| String::from_utf8_lossy(s.sectname).into_owned(),
                )
            };
            p.raw(format_args!(
                "0x{a:X} {pcrel} {len} {ext} {} 0 {target}",
                reloc_type(m.header().cputype, kind)
            ));
        }
        p.close("}");
    }
    p.close("]");
}

fn reloc_type(cpu: u32, kind: u32) -> String {
    let names: &[&str] = match cpu {
        CPU_TYPE_X86_64 => &[
            "X86_64_RELOC_UNSIGNED",
            "X86_64_RELOC_SIGNED",
            "X86_64_RELOC_BRANCH",
            "X86_64_RELOC_GOT_LOAD",
            "X86_64_RELOC_GOT",
            "X86_64_RELOC_SUBTRACTOR",
            "X86_64_RELOC_SIGNED_1",
            "X86_64_RELOC_SIGNED_2",
            "X86_64_RELOC_SIGNED_4",
            "X86_64_RELOC_TLV",
        ],
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => &[
            "ARM64_RELOC_UNSIGNED",
            "ARM64_RELOC_SUBTRACTOR",
            "ARM64_RELOC_BRANCH26",
            "ARM64_RELOC_PAGE21",
            "ARM64_RELOC_PAGEOFF12",
            "ARM64_RELOC_GOT_LOAD_PAGE21",
            "ARM64_RELOC_GOT_LOAD_PAGEOFF12",
            "ARM64_RELOC_POINTER_TO_GOT",
            "ARM64_RELOC_TLVP_LOAD_PAGE21",
            "ARM64_RELOC_TLVP_LOAD_PAGEOFF12",
            "ARM64_RELOC_ADDEND",
            "ARM64_RELOC_AUTHENTICATED_POINTER",
        ],
        CPU_TYPE_X86 => &[
            "GENERIC_RELOC_VANILLA",
            "GENERIC_RELOC_PAIR",
            "GENERIC_RELOC_SECTDIFF",
            "GENERIC_RELOC_PB_LA_PTR",
            "GENERIC_RELOC_LOCAL_SECTDIFF",
            "GENERIC_RELOC_TLV",
        ],
        _ => &[],
    };
    names
        .get(kind as usize)
        .map_or_else(|| "Unknown".to_string(), |s| (*s).to_string())
}

const SYMBOL_FLAGS: &[(&str, u64)] = &[
    ("ThumbDef", 0x8),
    ("ReferencedDynamically", 0x10),
    ("NoDeadStrip", 0x20),
    ("WeakRef", 0x40),
    ("WeakDef", 0x80),
    ("SymbolResolver", 0x100),
    ("AltEntry", 0x200),
    ("ColdFunc", 0x400),
];

fn symbols(p: &mut Printer<'_>, m: &MachO<'_>) {
    let sections = m.sections();
    p.open("Symbols [");
    for s in m.symbols() {
        p.open("Symbol {");
        p.line(
            "Name",
            format_args!("{} ({})", String::from_utf8_lossy(s.name), s.strx),
        );
        let stab = s.n_type & 0xE0 != 0;
        if stab {
            p.line("Type", format_args!("SymDebugTable (0x{:X})", s.n_type));
        } else {
            if s.n_type & 0x10 != 0 {
                p.raw("PrivateExtern");
            }
            if s.n_type & 0x01 != 0 {
                p.raw("Extern");
            }
            let t = s.n_type & 0x0E;
            let name = match t {
                0x0 => Some("Undef"),
                0x2 => Some("Abs"),
                0xA => Some("Indirect"),
                0xC => Some("PreboundUndef"),
                0xE => Some("Section"),
                _ => None,
            };
            p.enumerated("Type", name, u64::from(t));
        }
        // (A section-defined symbol's section; stabs and others, none.)
        let section = if !stab && s.n_type & 0x0E == 0xE && s.n_sect != 0 {
            sections
                .get(usize::from(s.n_sect) - 1)
                .map_or("", |x| std::str::from_utf8(x.sectname).unwrap_or(""))
        } else {
            ""
        };
        p.line("Section", format_args!("{section} (0x{:X})", s.n_sect));
        let rt = s.n_desc & 0x7;
        let ref_types = [
            "UndefinedNonLazy",
            "ReferenceFlagUndefinedLazy",
            "ReferenceFlagDefined",
            "ReferenceFlagPrivateDefined",
            "ReferenceFlagPrivateUndefinedNonLazy",
            "ReferenceFlagPrivateUndefinedLazy",
        ];
        p.enumerated(
            "RefType",
            ref_types.get(usize::from(rt)).copied(),
            u64::from(rt),
        );
        p.flags("Flags", u64::from(s.n_desc & !0x7), SYMBOL_FLAGS);
        p.line("Value", format_args!("0x{:X}", s.n_value));
        p.close("}");
    }
    p.close("]");
}

fn needed(p: &mut Printer<'_>, m: &MachO<'_>) {
    let mut libs: Vec<String> = Vec::new();
    let big = m.header().endian == hexcavator_core::Endian::Big;
    for lc in m.load_commands() {
        if !matches!(
            lc.cmd,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | 0x20 | LC_LOAD_UPWARD_DYLIB
        ) {
            continue;
        }
        let Some(b) = lc.data.get(8..12) else {
            continue;
        };
        let b: [u8; 4] = b.try_into().unwrap_or([0; 4]);
        let off = if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        } as usize;
        if let Some(rest) = lc.data.get(off..) {
            let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
            libs.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        }
    }
    libs.sort();
    p.open("NeededLibraries [");
    for l in libs {
        p.raw(l);
    }
    p.close("]");
}

fn prot(v: u32) -> String {
    format!(
        "{}{}{}",
        if v & 1 != 0 { 'r' } else { '-' },
        if v & 2 != 0 { 'w' } else { '-' },
        if v & 4 != 0 { 'x' } else { '-' }
    )
}

fn segments(p: &mut Printer<'_>, m: &MachO<'_>) {
    let lcs = m.load_commands();
    for s in m.segments() {
        let lc = lcs.get(s.command);
        p.open("Segment {");
        p.line(
            "Cmd",
            if lc.is_some_and(|l| l.cmd == LC_SEGMENT_64) {
                "LC_SEGMENT_64"
            } else {
                "LC_SEGMENT"
            },
        );
        p.line("Name", String::from_utf8_lossy(s.name));
        p.line("Size", lc.map_or(0, |l| l.size));
        p.line("vmaddr", format_args!("0x{:X}", s.vmaddr));
        p.line("vmsize", format_args!("0x{:X}", s.vmsize));
        p.line("fileoff", s.fileoff);
        p.line("filesize", s.filesize);
        p.line("maxprot", prot(s.maxprot));
        p.line("initprot", prot(s.initprot));
        p.line("nsects", s.sections.len());
        p.line("flags", format_args!("0x{:X}", s.flags));
        p.close("}");
    }
}

/// A packed version (`xxxx.yy.zz`) as Mach-O tools print it.
fn version(v: u32) -> String {
    let (major, minor, update) = (v >> 16, (v >> 8) & 0xFF, v & 0xFF);
    if update == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{update}")
    }
}

fn platform(v: u32) -> String {
    match v {
        1 => "macos".into(),
        2 => "ios".into(),
        3 => "tvos".into(),
        4 => "watchos".into(),
        5 => "bridgeos".into(),
        6 => "macCatalyst".into(),
        7 => "iossim".into(),
        8 => "tvossim".into(),
        9 => "watchossim".into(),
        10 => "driverkit".into(),
        11 => "xros".into(),
        12 => "xrsimulator".into(),
        _ => format!("unknown({v})"),
    }
}

fn version_min(p: &mut Printer<'_>, m: &MachO<'_>) {
    let big = m.header().endian == hexcavator_core::Endian::Big;
    let word = |d: &[u8], at: usize| -> u32 {
        let b: [u8; 4] = d
            .get(at..at + 4)
            .and_then(|x| x.try_into().ok())
            .unwrap_or([0; 4]);
        if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    };
    for lc in m.load_commands() {
        let name = match lc.cmd {
            LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
            LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
            LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
            LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
            LC_BUILD_VERSION => "LC_BUILD_VERSION",
            _ => continue,
        };
        p.open("MinVersion {");
        p.line("Cmd", name);
        p.line("Size", lc.size);
        if lc.cmd == LC_BUILD_VERSION {
            p.line("Platform", platform(word(lc.data, 8)));
            p.line("Version", version(word(lc.data, 12)));
            let sdk = word(lc.data, 16);
            p.line(
                "SDK",
                if sdk == 0 {
                    "n/a".to_string()
                } else {
                    version(sdk)
                },
            );
        } else {
            p.line("Version", version(word(lc.data, 8)));
            let sdk = word(lc.data, 12);
            p.line(
                "SDK",
                if sdk == 0 {
                    "n/a".to_string()
                } else {
                    version(sdk)
                },
            );
        }
        p.close("}");
    }
}

fn dysymtab(p: &mut Printer<'_>, m: &MachO<'_>) {
    let Some(d) = m.dysymtab() else { return };
    p.open("Dysymtab {");
    for (n, v) in [
        ("ilocalsym", d.ilocalsym),
        ("nlocalsym", d.nlocalsym),
        ("iextdefsym", d.iextdefsym),
        ("nextdefsym", d.nextdefsym),
        ("iundefsym", d.iundefsym),
        ("nundefsym", d.nundefsym),
        ("tocoff", d.tocoff),
        ("ntoc", d.ntoc),
        ("modtaboff", d.modtaboff),
        ("nmodtab", d.nmodtab),
        ("extrefsymoff", d.extrefsymoff),
        ("nextrefsyms", d.nextrefsyms),
        ("indirectsymoff", d.indirectsymoff),
        ("nindirectsyms", d.nindirectsyms),
        ("extreloff", d.extreloff),
        ("nextrel", d.nextrel),
        ("locreloff", d.locreloff),
        ("nlocrel", d.nlocrel),
    ] {
        p.line(n, v);
    }
    p.close("}");
}

//! An ELF file, as llvm-readobj shows it (`--file-headers`, `--sections`,
//! `--program-headers`, `--dynamic-table`, `--relocations`, `--symbols`,
//! `--dyn-symbols`, `--notes`).

use hexcavator_elf::consts::*;
use hexcavator_elf::spelling;
use hexcavator_elf::{Class, ElfFile, Section};

use super::{Parts, Printer};

/// llvm-readobj's `Format:`, `Arch:`, and `AddressSize:` for a file.
fn identity(elf: &ElfFile<'_>) -> (String, &'static str, &'static str) {
    let h = elf.header();
    let big = elf.endian() == hexcavator_core::Endian::Big;
    let wide = elf.class() == Class::Elf64;
    let (format, arch) = match h.machine {
        EM_X86_64 => ("x86-64".to_string(), "x86_64"),
        EM_386 => ("i386".to_string(), "i386"),
        EM_AARCH64 => (
            if big { "bigaarch64" } else { "littleaarch64" }.to_string(),
            if big { "aarch64_be" } else { "aarch64" },
        ),
        EM_ARM => (
            if big { "bigarm" } else { "littlearm" }.to_string(),
            if big { "armeb" } else { "arm" },
        ),
        EM_RISCV => (
            "littleriscv".to_string(),
            if wide { "riscv64" } else { "riscv32" },
        ),
        EM_PPC64 => (
            if big { "powerpc" } else { "powerpcle" }.to_string(),
            if big { "powerpc64" } else { "powerpc64le" },
        ),
        EM_PPC => ("powerpc".to_string(), "powerpc"),
        EM_S390 => ("s390".to_string(), "systemz"),
        EM_MIPS => (
            if big { "mips" } else { "mipsel" }.to_string(),
            if big {
                if wide { "mips64" } else { "mips" }
            } else if wide {
                "mips64el"
            } else {
                "mipsel"
            },
        ),
        EM_LOONGARCH => (
            "loongarch".to_string(),
            if wide { "loongarch64" } else { "loongarch32" },
        ),
        _ => ("unknown".to_string(), "unknown"),
    };
    // (llvm-readobj names a big-endian ARM "arm": its triple's arch.)
    let arch = if h.machine == EM_ARM { "arm" } else { arch };
    (
        format!("elf{}-{format}", if wide { 64 } else { 32 }),
        arch,
        if wide { "64bit" } else { "32bit" },
    )
}

pub fn dump(out: &mut String, file_name: &str, elf: &ElfFile<'_>, parts: &Parts) {
    let (format, arch, size) = identity(elf);
    let mut p = Printer::new(out);
    p.raw("");
    p.line("File", file_name);
    p.line("Format", format);
    p.line("Arch", arch);
    p.line("AddressSize", size);
    let soname = dynamic_string(elf, DT_SONAME);
    p.line("LoadName", soname.as_deref().unwrap_or("<Not found>"));
    if parts.file_headers {
        file_header(&mut p, elf);
    }
    if parts.sections {
        sections(&mut p, elf);
    }
    if parts.program_headers {
        program_headers(&mut p, elf);
    }
    if parts.dynamic_table {
        dynamic_table(&mut p, elf);
    }
    if parts.relocations {
        relocations(&mut p, elf);
    }
    if parts.symbols {
        symbols(&mut p, elf, SHT_SYMTAB, "Symbols");
    }
    if parts.dyn_symbols {
        symbols(&mut p, elf, SHT_DYNSYM, "DynamicSymbols");
    }
    if parts.notes {
        notes(&mut p, elf);
    }
}

fn file_header(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    let h = elf.header();
    let data = elf.data();
    p.open("ElfHeader {");
    p.open("Ident {");
    let magic: Vec<String> = data.iter().take(4).map(|b| format!("{b:02X}")).collect();
    p.line("Magic", format_args!("({})", magic.join(" ")));
    let class = data.get(4).copied().unwrap_or(0);
    p.enumerated(
        "Class",
        match class {
            1 => Some("32-bit"),
            2 => Some("64-bit"),
            _ => None,
        },
        u64::from(class),
    );
    let enc = data.get(5).copied().unwrap_or(0);
    p.enumerated(
        "DataEncoding",
        match enc {
            1 => Some("LittleEndian"),
            2 => Some("BigEndian"),
            _ => None,
        },
        u64::from(enc),
    );
    p.line("FileVersion", data.get(6).copied().unwrap_or(0));
    p.enumerated("OS/ABI", os_abi(h.os_abi), u64::from(h.os_abi));
    p.line("ABIVersion", h.abi_version);
    let unused: Vec<String> = data
        .iter()
        .skip(9)
        .take(7)
        .map(|b| format!("{b:02X}"))
        .collect();
    p.line("Unused", format_args!("({})", unused.join(" ")));
    p.close("}");
    p.enumerated("Type", file_type(h.kind), u64::from(h.kind));
    p.enumerated(
        "Machine",
        spelling::machine(u64::from(h.machine)),
        u64::from(h.machine),
    );
    p.line("Version", h.version);
    p.line("Entry", format_args!("0x{:X}", h.entry));
    p.line("ProgramHeaderOffset", format_args!("0x{:X}", h.phoff));
    p.line("SectionHeaderOffset", format_args!("0x{:X}", h.shoff));
    p.flags("Flags", u64::from(h.flags), &header_flags(h.machine));
    p.line("HeaderSize", h.ehsize);
    p.line("ProgramHeaderEntrySize", h.phentsize);
    p.line("ProgramHeaderCount", h.phnum);
    p.line("SectionHeaderEntrySize", h.shentsize);
    p.line("SectionHeaderCount", h.shnum);
    p.line("StringTableSectionIndex", h.shstrndx);
    p.close("}");
}

/// The header flags llvm-readobj names (it names the RISC-V and AArch64
/// ones it knows; ARM's EABI flags it shows as numbers).
fn header_flags(machine: u16) -> Vec<(&'static str, u64)> {
    match machine {
        EM_RISCV => vec![
            ("EF_RISCV_RVC", 0x1),
            ("EF_RISCV_RVE", 0x8),
            ("EF_RISCV_TSO", 0x10),
        ],
        _ => Vec::new(),
    }
}

fn os_abi(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "SystemV",
        1 => "HPUX",
        2 => "NetBSD",
        3 => "GNU/Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        64 => "AMDGPU_HSA",
        97 => "ARM",
        255 => "Standalone",
        _ => return None,
    })
}

fn file_type(v: u16) -> Option<&'static str> {
    Some(match v {
        0 => "None",
        1 => "Relocatable",
        2 => "Executable",
        3 => "SharedObject",
        4 => "Core",
        _ => return None,
    })
}

fn sections(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    let machine = elf.header().machine;
    let flags = spelling::section_flags(machine);
    p.open("Sections [");
    for s in elf.sections() {
        p.open("Section {");
        p.line("Index", s.index);
        p.line(
            "Name",
            format_args!("{} ({})", String::from_utf8_lossy(s.name), s.name_offset),
        );
        p.enumerated(
            "Type",
            spelling::section_type(machine, u64::from(s.kind)),
            u64::from(s.kind),
        );
        p.flags("Flags", s.flags, &flags);
        p.line("Address", format_args!("0x{:X}", s.addr));
        p.line("Offset", format_args!("0x{:X}", s.offset));
        p.line("Size", s.size);
        p.line("Link", s.link);
        p.line("Info", s.info);
        p.line("AddressAlignment", s.addralign);
        p.line("EntrySize", s.entsize);
        p.close("}");
    }
    p.close("]");
}

fn program_headers(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    let machine = elf.header().machine;
    p.open("ProgramHeaders [");
    for s in elf.segments() {
        p.open("ProgramHeader {");
        p.enumerated(
            "Type",
            spelling::segment_type(machine, u64::from(s.kind)),
            u64::from(s.kind),
        );
        p.line("Offset", format_args!("0x{:X}", s.offset));
        p.line("VirtualAddress", format_args!("0x{:X}", s.vaddr));
        p.line("PhysicalAddress", format_args!("0x{:X}", s.paddr));
        p.line("FileSize", s.filesz);
        p.line("MemSize", s.memsz);
        p.flags(
            "Flags",
            u64::from(s.flags),
            &[("PF_X", 1), ("PF_W", 2), ("PF_R", 4)],
        );
        p.line("Alignment", s.align);
        p.close("}");
    }
    p.close("]");
}

/// A dynamic string (`DT_NEEDED`'s, `DT_SONAME`'s) at `off` in
/// `DT_STRTAB`.
fn dynamic_str(elf: &ElfFile<'_>, off: u64) -> Option<String> {
    let strtab = elf.dynamic().iter().find(|d| d.tag == DT_STRTAB)?.value;
    let base = elf.vaddr_to_offset(strtab)?;
    let start = usize::try_from(base.checked_add(off)?).ok()?;
    let rest = elf.data().get(start..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..end.min(4096)]).into_owned())
}

fn dynamic_string(elf: &ElfFile<'_>, tag: u64) -> Option<String> {
    let v = elf.dynamic().iter().find(|d| d.tag == tag)?.value;
    dynamic_str(elf, v)
}

fn dynamic_table(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    let machine = elf.header().machine;
    let mut entries = elf.dynamic();
    if entries.is_empty() {
        return;
    }
    // (llvm-readobj lists the terminating DT_NULL too.)
    entries.push(hexcavator_elf::Dynamic {
        tag: DT_NULL,
        value: 0,
    });
    let names: Vec<String> = entries
        .iter()
        .map(|d| {
            spelling::dynamic_tag(machine, d.tag)
                .map_or_else(|| format!("<unknown:>0x{:x}", d.tag), str::to_string)
        })
        .collect();
    let width = names.iter().map(String::len).max().unwrap_or(4);
    p.open(&format!("DynamicSection [ ({} entries)", entries.len()));
    p.raw(format_args!("{:<18} {:<width$} Name/Value", "Tag", "Type"));
    for (d, name) in entries.iter().zip(&names) {
        let value = dynamic_value(elf, d.tag, d.value);
        p.raw(format_args!("0x{:016X} {:<width$} {value}", d.tag, name));
    }
    p.close("]");
}

fn dynamic_value(elf: &ElfFile<'_>, tag: u64, v: u64) -> String {
    let s = |what: &str| format!("{what}: [{}]", dynamic_str(elf, v).unwrap_or_default());
    match tag {
        DT_NEEDED => s("Shared library"),
        DT_SONAME => s("Library soname"),
        DT_RPATH => s("Library rpath"),
        DT_RUNPATH => s("Library runpath"),
        DT_PLTRELSZ | DT_RELASZ | DT_RELAENT | DT_STRSZ | DT_SYMENT | DT_RELSZ | DT_RELENT
        | DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | 35 | 37 | 0x6FFF_FE00 | 0x6FFF_FE01 => {
            format!("{v} (bytes)")
        }
        DT_PLTREL => (if v == 7 {
            "RELA"
        } else if v == 17 {
            "REL"
        } else {
            ""
        })
        .to_string(),
        DT_FLAGS => {
            let names = [
                (1, "ORIGIN"),
                (2, "SYMBOLIC"),
                (4, "TEXTREL"),
                (8, "BIND_NOW"),
                (16, "STATIC_TLS"),
            ];
            names
                .iter()
                .filter(|(b, _)| v & b != 0)
                .map(|(_, n)| *n)
                .collect::<Vec<_>>()
                .join(" ")
        }
        DT_FLAGS_1 => {
            let names = [
                (0x1, "NOW"),
                (0x2, "GLOBAL"),
                (0x4, "GROUP"),
                (0x8, "NODELETE"),
                (0x10, "LOADFLTR"),
                (0x20, "INITFIRST"),
                (0x40, "NOOPEN"),
                (0x80, "ORIGIN"),
                (0x100, "DIRECT"),
                (0x400, "INTERPOSE"),
                (0x800, "NODEFLIB"),
                (0x1000, "NODUMP"),
                (0x8000, "NODIRECT"),
                (0x8_0000, "NOHDR"),
                (0x10_0000, "EDITED"),
                (0x40_0000, "PIE"),
                (0x0800_0000, "PIE"),
            ];
            names
                .iter()
                .filter(|(b, _)| v & b != 0)
                .map(|(_, n)| *n)
                .collect::<Vec<_>>()
                .join(" ")
        }
        DT_RELACOUNT | DT_RELCOUNT | 0x6FFF_FFFF | 0x6FFF_FFFD => format!("{v}"),
        _ => format!("0x{v:X}"),
    }
}

fn relocations(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    let machine = elf.header().machine;
    let sections: Vec<Section<'_>> = elf.sections().collect();
    let wide = elf.class() == Class::Elf64;
    p.open("Relocations [");
    for s in &sections {
        let relr = s.kind == SHT_RELR || s.kind == 0x6FFF_FF00;
        if s.kind != SHT_REL
            && s.kind != SHT_RELA
            && !relr
            && s.kind != 0x6000_0001
            && s.kind != 0x6000_0002
        {
            continue;
        }
        p.open(&format!(
            "Section ({}) {} {{",
            s.index,
            String::from_utf8_lossy(s.name)
        ));
        if relr {
            let kind = relative_type(machine);
            for addr in elf.relr(s) {
                p.raw(format_args!("0x{addr:X} {kind} -"));
            }
        } else {
            let symtab = sections.get(s.link as usize);
            let syms = symtab.map(|t| elf.symbols(t)).unwrap_or_default();
            let versions = if symtab.is_some_and(|t| t.kind == SHT_DYNSYM) {
                elf.symbol_versions()
            } else {
                Vec::new()
            };
            for r in elf.relocations(s) {
                let kind = spelling::relocation(machine, r.kind)
                    .map_or_else(|| format!("Unknown ({})", r.kind), str::to_string);
                let sym = syms.get(r.symbol as usize).map_or_else(
                    || "-".to_string(),
                    |sym| {
                        if r.symbol == 0 {
                            "-".to_string()
                        } else if sym.kind == STT_SECTION {
                            sections
                                .get(sym.shndx as usize)
                                .map_or_else(String::new, |t| {
                                    String::from_utf8_lossy(t.name).into_owned()
                                })
                        } else {
                            format!(
                                "{}{}",
                                String::from_utf8_lossy(sym.name),
                                version_suffix(&versions, r.symbol as usize, sym.shndx)
                            )
                        }
                    },
                );
                match r.addend {
                    Some(a) if wide => p.raw(format_args!(
                        "0x{:X} {kind} {sym} 0x{:X}",
                        r.offset, a as u64
                    )),
                    // (A 32-bit file's addend, as its 32 bits.)
                    Some(a) => p.raw(format_args!(
                        "0x{:X} {kind} {sym} 0x{:X}",
                        r.offset,
                        a as u64 & 0xFFFF_FFFF
                    )),
                    None => p.raw(format_args!("0x{:X} {kind} {sym}", r.offset)),
                }
            }
        }
        p.close("}");
    }
    p.close("]");
}

/// The relative relocation type RELR stands for, by machine.
fn relative_type(machine: u16) -> &'static str {
    match machine {
        EM_X86_64 => "R_X86_64_RELATIVE",
        EM_386 => "R_386_RELATIVE",
        EM_AARCH64 => "R_AARCH64_RELATIVE",
        EM_ARM => "R_ARM_RELATIVE",
        EM_RISCV => "R_RISCV_RELATIVE",
        EM_PPC64 => "R_PPC64_RELATIVE",
        _ => "R_RELATIVE",
    }
}

fn symbols(p: &mut Printer<'_>, elf: &ElfFile<'_>, kind: u32, head: &str) {
    let sections: Vec<Section<'_>> = elf.sections().collect();
    // Dynamic symbols' versions: `name@version` (needed, or hidden), or
    // `name@@version` (defined, the default).
    let versions = if kind == SHT_DYNSYM {
        elf.symbol_versions()
    } else {
        Vec::new()
    };
    p.open(&format!("{head} ["));
    for table in sections.iter().filter(|s| s.kind == kind) {
        for (i, sym) in elf.symbols(table).into_iter().enumerate() {
            p.open("Symbol {");
            // (A section symbol without a name is named by its section.)
            let name = if sym.name.is_empty() && sym.kind == STT_SECTION {
                sections
                    .get(sym.shndx as usize)
                    .map_or(sym.name, |s| s.name)
            } else {
                sym.name
            };
            let version = version_suffix(&versions, i, sym.shndx);
            p.line(
                "Name",
                format_args!(
                    "{}{version} ({})",
                    String::from_utf8_lossy(name),
                    sym.name_offset
                ),
            );
            p.line("Value", format_args!("0x{:X}", sym.value));
            p.line("Size", sym.size);
            p.enumerated("Binding", binding(sym.bind), u64::from(sym.bind));
            p.enumerated("Type", symbol_type(sym.kind), u64::from(sym.kind));
            if sym.visibility == 0 {
                p.line("Other", 0);
            } else {
                p.flags(
                    "Other",
                    u64::from(sym.visibility),
                    &[("STV_INTERNAL", 1), ("STV_HIDDEN", 2), ("STV_PROTECTED", 3)]
                        [usize::from(sym.visibility) - 1..usize::from(sym.visibility)],
                );
            }
            let section = match sym.shndx {
                0 => "Undefined".to_string(),
                0xFFF1 => "Absolute".to_string(),
                0xFFF2 => "Common".to_string(),
                n => sections.get(n as usize).map_or_else(
                    || format!("<section {n}>"),
                    |s| String::from_utf8_lossy(s.name).into_owned(),
                ),
            };
            p.line("Section", format_args!("{section} (0x{:X})", sym.shndx));
            p.close("}");
        }
    }
    p.close("]");
}

/// A dynamic symbol's version as llvm-readobj appends it: `@version` for
/// one needed (or hidden), `@@version` for one defined, the default.
fn version_suffix(
    versions: &[Option<hexcavator_elf::versions::SymbolVersion<'_>>],
    i: usize,
    shndx: u32,
) -> String {
    match versions.get(i).copied().flatten() {
        Some(v) if v.file.is_none() && !v.hidden && shndx != 0 => {
            format!("@@{}", String::from_utf8_lossy(v.name))
        }
        Some(v) => format!("@{}", String::from_utf8_lossy(v.name)),
        None => String::new(),
    }
}

fn binding(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "Local",
        1 => "Global",
        2 => "Weak",
        10 => "Unique",
        _ => return None,
    })
}

fn symbol_type(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "None",
        1 => "Object",
        2 => "Function",
        3 => "Section",
        4 => "File",
        5 => "Common",
        6 => "TLS",
        10 => "GNU_IFunc",
        _ => return None,
    })
}

fn notes(p: &mut Printer<'_>, elf: &ElfFile<'_>) {
    p.open("NoteSections [");
    let sections: Vec<Section<'_>> = elf.sections().filter(|s| s.kind == SHT_NOTE).collect();
    for s in &sections {
        p.open("NoteSection {");
        p.line("Name", String::from_utf8_lossy(s.name));
        p.line("Offset", format_args!("0x{:X}", s.offset));
        p.line("Size", format_args!("0x{:X}", s.size));
        p.open("Notes [");
        for n in elf.notes(elf.section_data(s)) {
            p.open("{");
            let owner =
                String::from_utf8_lossy(n.name.strip_suffix(b"\0").unwrap_or(n.name)).into_owned();
            p.line("Owner", &owner);
            p.line("Data size", format_args!("0x{:X}", n.desc.len()));
            match (owner.as_str(), n.kind) {
                ("GNU", 3) => {
                    p.line("Type", "NT_GNU_BUILD_ID (unique build ID bitstring)");
                    let id: String = n.desc.iter().map(|b| format!("{b:02x}")).collect();
                    p.line("Build ID", id);
                }
                ("GNU", 1) => {
                    p.line("Type", "NT_GNU_ABI_TAG (ABI version tag)");
                }
                ("GNU", 4) => {
                    p.line("Type", "NT_GNU_GOLD_VERSION (gold version)");
                    p.line(
                        "Version",
                        String::from_utf8_lossy(n.desc.split(|&b| b == 0).next().unwrap_or(&[])),
                    );
                }
                ("GNU", 5) => {
                    p.line("Type", "NT_GNU_PROPERTY_TYPE_0 (property note)");
                }
                (_, k) => p.line("Type", format_args!("Unknown (0x{k:08x})")),
            }
            p.close("}");
        }
        p.close("]");
        p.close("}");
    }
    p.close("]");
}

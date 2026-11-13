//! PE image and COFF object output, matching `dumpbin`.

use std::io::{self, Write};

use hexcavator_pe::consts::{machine, magic, section_characteristics as scn, subsystem};
use hexcavator_pe::{FileKind, OptionalHeader, PeFile};

use super::{Options, Summary};
use crate::time::asctime_utc;

const UNKNOWN_FLAG: &str = "RESERVED - UNKNOWN";

pub fn dump(
    out: &mut dyn Write,
    options: &Options,
    path: &str,
    file: &PeFile<'_>,
    summary: &mut Summary,
) -> io::Result<()> {
    let file_type = match file.kind() {
        FileKind::Object if file.is_bigobj() => "EXTENDED COFF OBJECT",
        FileKind::Object => "COFF OBJECT",
        FileKind::Image if file.is_dll() => "DLL",
        FileKind::Image => "EXECUTABLE IMAGE",
    };
    if options.headers && file.kind() == FileKind::Image {
        writeln!(out, "PE signature found\n")?;
    }
    writeln!(out, "File Type: {file_type}")?;

    if options.headers {
        file_header(out, file)?;
        if let Some(optional) = file.optional_header() {
            optional_header(out, file, optional)?;
        }
    }

    // Like dumpbin, list each directory after the section that holds it,
    // in a fixed order within the section.
    use hexcavator_pe::consts::directory as dir;
    // Symbols from the PDB, for naming functions and addresses.
    let wants_symbols = options.disasm || options.pdata || options.unwindinfo;
    let symbols = (wants_symbols && !options.nopdb && file.kind() == FileKind::Image)
        .then(|| crate::symbols::SymbolMap::for_image(file, std::path::Path::new(path)))
        .flatten();
    let pdata =
        |out: &mut dyn Write, f: &PeFile<'_>| super::unwind::pdata(out, f, symbols.as_ref());
    let unwind_info =
        |out: &mut dyn Write, f: &PeFile<'_>| super::unwind::unwind_info(out, f, symbols.as_ref());
    type Part<'p> = &'p dyn Fn(&mut dyn Write, &PeFile<'_>) -> io::Result<()>;
    let parts: [(bool, usize, Part<'_>); 9] = [
        (options.headers, dir::DEBUG, &super::debug::directories),
        (options.exports, dir::EXPORT, &super::imports::exports),
        (
            options.imports,
            dir::IMPORT,
            &super::imports::static_imports,
        ),
        (
            options.imports,
            dir::DELAY_IMPORT,
            &super::imports::delay_imports,
        ),
        (
            options.loadconfig,
            dir::LOAD_CONFIG,
            &super::load_config::dump,
        ),
        (options.pdata && !options.unwindinfo, dir::EXCEPTION, &pdata),
        (options.unwindinfo, dir::EXCEPTION, &unwind_info),
        (options.tls, dir::TLS, &super::load_config::tls),
        (
            options.relocations,
            dir::BASERELOC,
            &super::imports::relocations,
        ),
    ];
    let homes: Vec<Option<usize>> = parts
        .iter()
        .map(|&(_, d, _)| {
            let rva = file.data_directory(d)?.virtual_address.get();
            section_of(file, rva)
        })
        .collect();
    if options.disasm {
        super::disasm::check_machine(out, file)?;
    }
    for index in 0..file.sections().len() {
        if options.headers {
            section_header(out, file, index)?;
        }
        if options.disasm {
            super::disasm::disassemble_section(
                out,
                file,
                &file.sections()[index],
                symbols.as_ref(),
            )?;
        }
        if (options.pdata || options.unwindinfo) && file.kind() == FileKind::Object {
            super::unwind::object_pdata(out, file, index)?;
        }
        if options.relocations && file.kind() == FileKind::Object {
            super::imports::object_relocations(out, file, index)?;
        }
        for (&(enabled, _, part), home) in parts.iter().zip(&homes) {
            if enabled && *home == Some(index) {
                part(out, file)?;
            }
        }
    }
    // Directories outside every section (such as in the headers).
    for ((enabled, d, part), home) in parts.iter().zip(&homes) {
        if *enabled && home.is_none() && file.data_directory(*d).is_some() {
            part(out, file)?;
        }
    }

    let alignment = file
        .optional_header()
        .map_or(0, hexcavator_pe::OptionalHeader::section_alignment);
    for section in file.sections() {
        let size = match file.kind() {
            FileKind::Object => section.size_of_raw_data.get(),
            FileKind::Image => match section.virtual_size.get() {
                0 => section.size_of_raw_data.get(),
                size => size,
            },
        };
        let size = align_up(u64::from(size), u64::from(alignment));
        let name = file.section_name(section);
        // Linker-only bits (alignment, COMDAT) do not distinguish sections.
        let flags = section.characteristics.get() & !(scn::ALIGN_MASK | scn::LNK_COMDAT);
        let key = (name.to_vec(), flags);
        if !summary.contains_key(&key) && summary.keys().any(|(n, _)| n == name) {
            ereport!(
                "hexc: warning: multiple '{}' sections found with different attributes ({flags:08X})",
                String::from_utf8_lossy(name)
            );
        }
        *summary.entry(key).or_default() += size;
    }
    Ok(())
}

pub fn summary(out: &mut dyn Write, summary: &Summary) -> io::Result<()> {
    writeln!(out, "\n  Summary\n")?;
    for ((name, _), size) in summary {
        writeln!(out, "{size:12X} {}", String::from_utf8_lossy(name))?;
    }
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        value
    } else {
        value.div_ceil(alignment).saturating_mul(alignment)
    }
}

/// Writes one indented line per flag set in `value`, in bit order.
fn flag_lines(
    out: &mut dyn Write,
    indent: usize,
    value: u32,
    names: &[(u32, &str)],
) -> io::Result<()> {
    for bit in (0..32).map(|i| 1u32 << i).filter(|bit| value & bit != 0) {
        let name = names
            .iter()
            .find(|(b, _)| *b == bit)
            .map_or(UNKNOWN_FLAG, |(_, n)| *n);
        writeln!(out, "{:indent$}{name}", "")?;
    }
    Ok(())
}

fn file_header(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    const CHARACTERISTICS: &[(u32, &str)] = &[
        (0x0001, "Relocations stripped"),
        (0x0002, "Executable"),
        (0x0004, "Line numbers stripped"),
        (0x0008, "Symbols stripped"),
        (0x0010, "Aggressively trim working set"),
        (0x0020, "Application can handle large (>2GB) addresses"),
        (0x0080, "Bytes reversed"),
        (0x0100, "32 bit word machine"),
        (0x0200, "Debug information stripped"),
        (0x0400, "CD - run from swapfile"),
        (0x0800, "Net - run from swapfile"),
        (0x1000, "System"),
        (0x2000, "DLL"),
        (0x4000, "Uniprocessor Only"),
        (0x8000, "Bytes reversed"),
    ];

    let h = file.file_header();
    let m = h.machine.get();
    let machine_name = match m {
        machine::CHPE_X86 => "HYBRID_x86_ARM64) (CHPE",
        machine::ARM64X => "ARM64X) (ARM64X",
        _ => machine::name(m).unwrap_or("Unknown"),
    };
    let hybrid = if file.is_arm64ec() { " (ARM64X)" } else { "" };
    let stamp = h.time_date_stamp.get();
    let date = stamp_date(file, stamp);

    writeln!(out, "\nFILE HEADER VALUES")?;
    writeln!(out, "{m:16X} machine ({machine_name}){hybrid}")?;
    writeln!(out, "{:16X} number of sections", h.number_of_sections.get())?;
    writeln!(out, "{stamp:16X} time date stamp{date}")?;
    writeln!(
        out,
        "{:16X} file pointer to symbol table",
        h.pointer_to_symbol_table.get()
    )?;
    writeln!(out, "{:16X} number of symbols", h.number_of_symbols.get())?;
    writeln!(
        out,
        "{:16X} size of optional header",
        h.size_of_optional_header.get()
    )?;
    let characteristics = h.characteristics.get();
    writeln!(out, "{characteristics:16X} characteristics")?;
    flag_lines(out, 19, characteristics.into(), CHARACTERISTICS)
}

fn optional_header(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    h: &OptionalHeader<'_>,
) -> io::Result<()> {
    const DLL_CHARACTERISTICS: &[(u32, &str)] = &[
        (0x0020, "High Entropy Virtual Addresses"),
        (0x0040, "Dynamic base"),
        (0x0080, "Check integrity"),
        (0x0100, "NX compatible"),
        (0x0200, "Isolation disabled"),
        (0x0400, "No structured exception handler"),
        (0x0800, "Do not bind"),
        (0x1000, "App Container"),
        (0x2000, "WDM Driver"),
        (0x4000, "Control Flow Guard"),
        (0x8000, "Terminal Server Aware"),
    ];
    const DIRECTORIES: [&str; 16] = [
        "Export",
        "Import",
        "Resource",
        "Exception",
        "Certificates",
        "Base Relocation",
        "Debug",
        "Architecture",
        "Global Pointer",
        "Thread Storage",
        "Load Configuration",
        "Bound Import",
        "Import Address Table",
        "Delay Import",
        "COM Descriptor",
        "Reserved",
    ];

    // Addresses are shown at the image's natural width.
    let width = if h.is_64() { 16 } else { 8 };
    let base = h.image_base().get();
    let version = |major: u16, minor: u16| format!("{major}.{minor:02}");

    writeln!(out, "\nOPTIONAL HEADER VALUES")?;
    let kind = match h.magic() {
        magic::PE32_PLUS => "PE32+",
        _ => "PE32",
    };
    writeln!(out, "{:16X} magic # ({kind})", h.magic())?;
    let linker = version(
        h.major_linker_version().into(),
        h.minor_linker_version().into(),
    );
    writeln!(out, "{linker:>16} linker version")?;
    writeln!(out, "{:16X} size of code", h.size_of_code())?;
    writeln!(
        out,
        "{:16X} size of initialized data",
        h.size_of_initialized_data()
    )?;
    writeln!(
        out,
        "{:16X} size of uninitialized data",
        h.size_of_uninitialized_data()
    )?;
    let entry = h.address_of_entry_point();
    if entry == 0 {
        writeln!(out, "{entry:16X} entry point")?;
    } else {
        let va = base.wrapping_add(entry.into());
        writeln!(out, "{entry:16X} entry point ({va:0width$X})")?;
    }
    writeln!(out, "{:16X} base of code", h.base_of_code())?;
    if let Some(base_of_data) = h.base_of_data() {
        writeln!(out, "{base_of_data:16X} base of data")?;
    }
    let end = base
        .wrapping_add(u64::from(h.size_of_image()))
        .wrapping_sub(1);
    writeln!(
        out,
        "{base:16X} image base ({base:0width$X} to {end:0width$X})"
    )?;
    writeln!(out, "{:16X} section alignment", h.section_alignment())?;
    writeln!(out, "{:16X} file alignment", h.file_alignment())?;
    let os = version(
        h.major_operating_system_version(),
        h.minor_operating_system_version(),
    );
    writeln!(out, "{os:>16} operating system version")?;
    let image = version(h.major_image_version(), h.minor_image_version());
    writeln!(out, "{image:>16} image version")?;
    let sub = version(h.major_subsystem_version(), h.minor_subsystem_version());
    writeln!(out, "{sub:>16} subsystem version")?;
    writeln!(out, "{:16X} Win32 version", h.win32_version_value())?;
    writeln!(out, "{:16X} size of image", h.size_of_image())?;
    writeln!(out, "{:16X} size of headers", h.size_of_headers())?;
    writeln!(out, "{:16X} checksum", h.check_sum())?;
    writeln!(
        out,
        "{:16X} subsystem ({})",
        h.subsystem(),
        subsystem_name(h.subsystem())
    )?;
    let dll = h.dll_characteristics();
    writeln!(out, "{dll:16X} DLL characteristics")?;
    flag_lines(out, 19, dll.into(), DLL_CHARACTERISTICS)?;
    writeln!(
        out,
        "{:16X} size of stack reserve",
        h.size_of_stack_reserve()
    )?;
    writeln!(out, "{:16X} size of stack commit", h.size_of_stack_commit())?;
    writeln!(out, "{:16X} size of heap reserve", h.size_of_heap_reserve())?;
    writeln!(out, "{:16X} size of heap commit", h.size_of_heap_commit())?;
    writeln!(out, "{:16X} loader flags", h.loader_flags())?;
    writeln!(
        out,
        "{:16X} number of directories",
        h.number_of_rva_and_sizes()
    )?;
    for (i, dir) in file.data_directories().iter().enumerate() {
        let name = DIRECTORIES.get(i).copied().unwrap_or("Unknown");
        writeln!(
            out,
            "{:16X} [{:8X}] RVA [size] of {name} Directory",
            dir.virtual_address.get(),
            dir.size.get()
        )?;
    }
    writeln!(out)
}

fn subsystem_name(value: u16) -> &'static str {
    match value {
        subsystem::NATIVE => "Native",
        subsystem::WINDOWS_GUI => "Windows GUI",
        subsystem::WINDOWS_CUI => "Windows CUI",
        subsystem::OS2_CUI => "OS/2 CUI",
        subsystem::POSIX_CUI => "Posix CUI",
        subsystem::NATIVE_WINDOWS => "Native Windows",
        subsystem::WINDOWS_CE_GUI => "Windows CE GUI",
        subsystem::EFI_APPLICATION => "EFI Application",
        subsystem::EFI_BOOT_SERVICE_DRIVER => "EFI Boot Service Driver",
        subsystem::EFI_RUNTIME_DRIVER => "EFI Runtime Driver",
        subsystem::EFI_ROM => "EFI ROM",
        subsystem::XBOX => "Xbox",
        subsystem::WINDOWS_BOOT_APPLICATION => "Boot Application",
        subsystem::XBOX_CODE_CATALOG => "Xbox Code Catalog",
        _ => "Unknown",
    }
}

fn section_header(out: &mut dyn Write, file: &PeFile<'_>, index: usize) -> io::Result<()> {
    // Bits shown before the alignment/access lines, in bit order. The
    // alignment field and the access bits are handled separately.
    const FLAGS: &[(u32, &str)] = &[
        (scn::TYPE_NO_PAD, "No Pad"),
        (scn::CNT_CODE, "Code"),
        (scn::CNT_INITIALIZED_DATA, "Initialized Data"),
        (scn::CNT_UNINITIALIZED_DATA, "Uninitialized Data"),
        (scn::LNK_OTHER, "Other"),
        (scn::LNK_INFO, "Info"),
        (scn::LNK_REMOVE, "Remove"),
        (scn::LNK_COMDAT, "COMDAT"),
        (scn::NO_DEFER_SPEC_EXC, "No Defer Spec Exc"),
        (scn::GPREL, "Short (GP Relative)"),
        (scn::MEM_PURGEABLE, "Purgeable"),
        (scn::MEM_LOCKED, "Locked"),
        (scn::MEM_PRELOAD, "Preload"),
        (scn::LNK_NRELOC_OVFL, "Extended relocations"),
        (scn::MEM_DISCARDABLE, "Discardable"),
        (scn::MEM_NOT_CACHED, "Not Cached"),
        (scn::MEM_NOT_PAGED, "Not Paged"),
        (scn::MEM_SHARED, "Shared"),
    ];
    const ACCESS: u32 = scn::MEM_EXECUTE | scn::MEM_READ | scn::MEM_WRITE;

    let is_object = file.kind() == FileKind::Object;
    let width = match file.optional_header() {
        Some(h) if h.is_64() => 16,
        _ => 8,
    };
    let base = file.optional_header().map_or(0, |h| h.image_base().get());
    let symbols = if is_object {
        file.symbols().ok().flatten()
    } else {
        None
    };

    {
        let section = &file.sections()[index];
        let number = index + 1;
        let name = String::from_utf8_lossy(file.section_name(section));
        let vsize = section.virtual_size.get();
        let va = section.virtual_address.get();
        let raw = section.size_of_raw_data.get();
        let ptr = section.pointer_to_raw_data.get();
        let flags = section.characteristics.get();

        writeln!(out, "\nSECTION HEADER #{number:X}")?;
        // A long name is a `/offset` into the string table.
        let raw_name = section.name.split(|&b| b == 0).next().unwrap_or(&[]);
        if raw_name.first() == Some(&b'/') {
            let raw_name = String::from_utf8_lossy(raw_name);
            writeln!(out, "{raw_name:>8} name ({name})")?;
        } else {
            writeln!(out, "{name:>8} name")?;
        }
        if is_object {
            writeln!(out, "{vsize:8X} physical address")?;
            writeln!(out, "{va:8X} virtual address")?;
        } else {
            let start = base.wrapping_add(va.into());
            let end = start.wrapping_add(u64::from(vsize)).wrapping_sub(1);
            writeln!(out, "{vsize:8X} virtual size")?;
            writeln!(
                out,
                "{va:8X} virtual address ({start:0width$X} to {end:0width$X})"
            )?;
        }
        writeln!(out, "{raw:8X} size of raw data")?;
        // (Objects' uninitialized sections have a size but no data.)
        if raw == 0 || ptr == 0 {
            writeln!(out, "{ptr:8X} file pointer to raw data")?;
        } else {
            let end = ptr.wrapping_add(raw).wrapping_sub(1);
            writeln!(
                out,
                "{ptr:8X} file pointer to raw data ({ptr:08X} to {end:08X})"
            )?;
        }
        writeln!(
            out,
            "{:8X} file pointer to relocation table",
            section.pointer_to_relocations.get()
        )?;
        writeln!(
            out,
            "{:8X} file pointer to line numbers",
            section.pointer_to_linenumbers.get()
        )?;
        writeln!(
            out,
            "{:8X} number of relocations",
            section.number_of_relocations.get()
        )?;
        writeln!(
            out,
            "{:8X} number of line numbers",
            section.number_of_linenumbers.get()
        )?;
        writeln!(out, "{flags:8X} flags")?;

        // In objects the alignment field gets its own line after the other
        // flags; in images its bits are reserved and listed like any other.
        let listed = flags & !ACCESS & if is_object { !scn::ALIGN_MASK } else { !0 };
        for bit in (0..32).map(|i| 1u32 << i).filter(|bit| listed & bit != 0) {
            let name = FLAGS
                .iter()
                .find(|(b, _)| *b == bit)
                .map_or(UNKNOWN_FLAG, |(_, n)| *n);
            if is_object && bit == scn::LNK_COMDAT {
                let comdat = i32::try_from(number).ok().and_then(|n| {
                    let symbols = symbols.as_ref()?;
                    symbols.name(&symbols.comdat_symbol(n)?)
                });
                match comdat {
                    Some(sym) => {
                        let sym = String::from_utf8_lossy(sym);
                        match super::undecorate(&sym) {
                            Some(u) => writeln!(out, "         COMDAT; sym= \"{u}\" ({sym})")?,
                            None => writeln!(out, "         COMDAT; sym= {sym}")?,
                        }
                    }
                    None => writeln!(out, "         COMDAT (no symbol)")?,
                }
            } else {
                writeln!(out, "         {name}")?;
            }
        }
        if is_object {
            match scn::alignment(flags) {
                Some(align) => writeln!(out, "         {align} byte align")?,
                None => writeln!(out, "         (no align specified)")?,
            }
        }
        let access = match flags & ACCESS {
            0 => None,
            scn::MEM_EXECUTE => Some("Execute Only"),
            scn::MEM_READ => Some("Read Only"),
            scn::MEM_WRITE => Some("Write Only"),
            a if a == scn::MEM_EXECUTE | scn::MEM_READ => Some("Execute Read"),
            a if a == scn::MEM_EXECUTE | scn::MEM_WRITE => Some("Execute Write"),
            a if a == scn::MEM_READ | scn::MEM_WRITE => Some("Read Write"),
            _ => Some("Execute Read Write"),
        };
        if let Some(access) = access {
            writeln!(out, "         {access}")?;
        }
    }
    Ok(())
}

/// The date dumpbin shows after a time stamp: none for reproducible builds
/// (whose stamps are hashes) or for values a signed 32-bit `time_t` cannot
/// represent.
pub fn stamp_date(file: &PeFile<'_>, stamp: u32) -> String {
    if stamp == 0 || stamp > 0x7FFF_FFFF || file.is_reproducible() {
        String::new()
    } else {
        format!(" {} UTC", asctime_utc(stamp.into()))
    }
}

/// The index of the image section that holds `rva`.
pub fn section_of(file: &PeFile<'_>, rva: u32) -> Option<usize> {
    if file.kind() == FileKind::Object {
        return None;
    }
    file.sections().iter().position(|s| {
        let start = s.virtual_address.get();
        let extent = match s.virtual_size.get() {
            0 => s.size_of_raw_data.get(),
            v => v,
        };
        rva >= start && rva - start < extent
    })
}

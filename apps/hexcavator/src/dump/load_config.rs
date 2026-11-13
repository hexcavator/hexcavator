//! `/loadconfig`: the load configuration directory and its tables.

use std::io::{self, Write};

use hexcavator_pe::load_config::{arm64ec, chpe_x86, field, guard_entry, guard_flags as gf};
use hexcavator_pe::reloc::{DynamicRelocationTable, FunctionOverrides, dynamic_symbol};
use hexcavator_pe::{CodeKind, GuardTable, LoadConfig, PeFile};

/// `%016.<digits>X`: right-aligned in 16 columns, zero-padded to `digits`.
fn fixed(value: u64, digits: usize) -> String {
    format!("{:>16}", format!("{value:0digits$X}"))
}

struct Printer<'a, 'd> {
    out: &'a mut dyn Write,
    config: LoadConfig<'d>,
    /// Digits in a pointer: 8 or 16.
    ptr: usize,
}

impl Printer<'_, '_> {
    fn line(
        &mut self,
        f: hexcavator_pe::load_config::Field,
        label: &str,
        style: Style,
    ) -> io::Result<()> {
        let Some(v) = self.config.get(f) else {
            return Ok(());
        };
        let text = match style {
            Style::Hex => format!("{v:16X}"),
            Style::Dec => format!("{v:16}"),
            Style::Ptr => fixed(v, self.ptr),
            Style::Fixed(n) => fixed(v, n),
        };
        writeln!(self.out, "    {text} {label}")
    }
}

#[derive(Clone, Copy)]
enum Style {
    Hex,
    Dec,
    Ptr,
    Fixed(usize),
}

const GUARD_FLAGS: &[(u32, &str)] = &[
    // dumpbin's order, which is not bit order.
    (gf::CF_INSTRUMENTED, "CF instrumented"),
    (gf::CFW_INSTRUMENTED, "CFW instrumented"),
    (gf::XFG_ENABLED, "XFG instrumented"),
    (gf::CF_FUNCTION_TABLE_PRESENT, "FID table present"),
    (gf::SECURITY_COOKIE_UNUSED, "Security cookie unused"),
    (gf::PROTECT_DELAYLOAD_IAT, "Protect delayload IAT"),
    (
        gf::DELAYLOAD_IAT_IN_ITS_OWN_SECTION,
        "Delayload IAT in its own section",
    ),
    (
        gf::CF_EXPORT_SUPPRESSION_INFO_PRESENT,
        "Export suppression info present",
    ),
    (
        gf::CF_ENABLE_EXPORT_SUPPRESSION,
        "Export suppression enabled",
    ),
    (
        gf::CF_LONGJUMP_TABLE_PRESENT,
        "Long jump target table present",
    ),
    (gf::RF_INSTRUMENTED, "RF instrumented"),
    (gf::RF_ENABLE, "RFG enabled"),
    (gf::RF_STRICT, "RFG in strict mode"),
    (
        gf::EH_CONTINUATION_TABLE_PRESENT,
        "EH Continuation table present",
    ),
    (gf::RETPOLINE_PRESENT, "All objects are retpoline-aware"),
    (gf::CASTGUARD_PRESENT, "CastGuard protection present"),
    (gf::MEMCPY_PRESENT, "Guarded Memcpy protection present"),
];

pub fn dump(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(config) = file.load_config() else {
        return Ok(());
    };
    let ptr = if config.is_64() { 16 } else { 8 };
    let base = file.optional_header().map_or(0, |h| h.image_base().get());
    writeln!(out, "\n  Section contains the following load config:\n")?;
    let mut p = Printer { out, config, ptr };
    use Style::*;
    p.line(field::SIZE, "size", Fixed(8))?;
    p.line(field::TIME_DATE_STAMP, "time date stamp", Hex)?;
    if let (Some(major), Some(minor)) = (
        config.get(field::MAJOR_VERSION),
        config.get(field::MINOR_VERSION),
    ) {
        writeln!(p.out, "    {:>16} Version", format!("{major}.{minor:02}"))?;
    }
    p.line(field::GLOBAL_FLAGS_CLEAR, "GlobalFlags Clear", Hex)?;
    p.line(field::GLOBAL_FLAGS_SET, "GlobalFlags Set", Hex)?;
    p.line(
        field::CRITICAL_SECTION_DEFAULT_TIMEOUT,
        "Critical Section Default Timeout",
        Dec,
    )?;
    p.line(
        field::DE_COMMIT_FREE_BLOCK_THRESHOLD,
        "Decommit Free Block Threshold",
        Hex,
    )?;
    p.line(
        field::DE_COMMIT_TOTAL_FREE_THRESHOLD,
        "Decommit Total Free Threshold",
        Hex,
    )?;
    p.line(field::LOCK_PREFIX_TABLE, "Lock Prefix Table", Ptr)?;
    p.line(
        field::MAXIMUM_ALLOCATION_SIZE,
        "Maximum Allocation Size",
        Hex,
    )?;
    p.line(
        field::VIRTUAL_MEMORY_THRESHOLD,
        "Virtual Memory Threshold",
        Hex,
    )?;
    p.line(field::PROCESS_AFFINITY_MASK, "Process Affinity Mask", Hex)?;
    p.line(field::PROCESS_HEAP_FLAGS, "Process Heap Flags", Hex)?;
    p.line(field::CSD_VERSION, "CSD Version", Dec)?;
    p.line(field::DEPENDENT_LOAD_FLAGS, "Dependent Load Flag", Fixed(4))?;
    p.line(field::EDIT_LIST, "Edit List", Ptr)?;
    p.line(field::SECURITY_COOKIE, "Security Cookie", Ptr)?;
    if !config.is_64() {
        p.line(field::SE_HANDLER_TABLE, "Safe Exception Handler Table", Ptr)?;
        p.line(field::SE_HANDLER_COUNT, "Safe Exception Handler Count", Hex)?;
    }
    p.line(
        field::GUARD_CF_CHECK_FUNCTION_POINTER,
        "Guard CF address of check-function pointer",
        Ptr,
    )?;
    p.line(
        field::GUARD_CF_DISPATCH_FUNCTION_POINTER,
        "Guard CF address of dispatch-function pointer",
        Ptr,
    )?;
    p.line(
        field::GUARD_CF_FUNCTION_TABLE,
        "Guard CF function table",
        Ptr,
    )?;
    p.line(
        field::GUARD_CF_FUNCTION_COUNT,
        "Guard CF function count",
        Hex,
    )?;
    if config.has(field::GUARD_FLAGS) {
        p.line(field::GUARD_FLAGS, "Guard Flags", Fixed(8))?;
        let flags = config.guard_flags();
        for (bit, name) in GUARD_FLAGS {
            if flags & bit != 0 {
                writeln!(p.out, "                       {name}")?;
            }
        }
    }
    p.line(
        field::CODE_INTEGRITY_FLAGS,
        "Code Integrity Flags",
        Fixed(4),
    )?;
    p.line(
        field::CODE_INTEGRITY_CATALOG,
        "Code Integrity Catalog",
        Fixed(4),
    )?;
    p.line(
        field::CODE_INTEGRITY_CATALOG_OFFSET,
        "Code Integrity Catalog Offset",
        Fixed(8),
    )?;
    p.line(
        field::CODE_INTEGRITY_RESERVED,
        "Code Integrity Reserved",
        Fixed(8),
    )?;
    p.line(
        field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_TABLE,
        "Guard CF address taken IAT entry table",
        Ptr,
    )?;
    p.line(
        field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_COUNT,
        "Guard CF address taken IAT entry count",
        Hex,
    )?;
    p.line(
        field::GUARD_LONG_JUMP_TARGET_TABLE,
        "Guard CF long jump target table",
        Ptr,
    )?;
    p.line(
        field::GUARD_LONG_JUMP_TARGET_COUNT,
        "Guard CF long jump target count",
        Hex,
    )?;
    p.line(
        field::DYNAMIC_VALUE_RELOC_TABLE,
        "Dynamic value relocation table",
        Ptr,
    )?;
    p.line(field::CHPE_METADATA_POINTER, "Hybrid metadata pointer", Ptr)?;
    p.line(
        field::GUARD_RF_FAILURE_ROUTINE,
        "Guard RF address of failure-function",
        Ptr,
    )?;
    p.line(
        field::GUARD_RF_FAILURE_ROUTINE_FUNCTION_POINTER,
        "Guard RF address of failure-function pointer",
        Ptr,
    )?;
    p.line(
        field::DYNAMIC_VALUE_RELOC_TABLE_OFFSET,
        "Dynamic value relocation table offset",
        Fixed(8),
    )?;
    p.line(
        field::DYNAMIC_VALUE_RELOC_TABLE_SECTION,
        "Dynamic value relocation table section",
        Fixed(4),
    )?;
    p.line(field::RESERVED2, "Reserved2", Fixed(4))?;
    p.line(
        field::GUARD_RF_VERIFY_STACK_POINTER_FUNCTION_POINTER,
        "Guard RF address of stack pointer verification function pointer",
        Ptr,
    )?;
    p.line(
        field::HOT_PATCH_TABLE_OFFSET,
        "Hot patching table offset",
        Fixed(8),
    )?;
    p.line(field::RESERVED3, "Reserved3", Fixed(4))?;
    p.line(
        field::ENCLAVE_CONFIGURATION_POINTER,
        "Enclave configuration pointer",
        Ptr,
    )?;
    p.line(
        field::VOLATILE_METADATA_POINTER,
        "Volatile metadata pointer",
        Ptr,
    )?;
    p.line(
        field::GUARD_EH_CONTINUATION_TABLE,
        "Guard EH continuation table",
        Ptr,
    )?;
    p.line(
        field::GUARD_EH_CONTINUATION_COUNT,
        "Guard EH continuation count",
        Hex,
    )?;
    p.line(
        field::GUARD_XFG_CHECK_FUNCTION_POINTER,
        "Guard XFG address of check-function pointer",
        Ptr,
    )?;
    p.line(
        field::GUARD_XFG_DISPATCH_FUNCTION_POINTER,
        "Guard XFG address of dispatch-function pointer",
        Ptr,
    )?;
    p.line(
        field::GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER,
        "Guard XFG address of dispatch-table-function pointer",
        Ptr,
    )?;
    p.line(
        field::CAST_GUARD_OS_DETERMINED_FAILURE_MODE,
        "CastGuard OS determined failure mode",
        Ptr,
    )?;
    p.line(
        field::GUARD_MEMCPY_FUNCTION_POINTER,
        "Guard memcpy function pointer",
        Ptr,
    )?;
    let out = p.out;

    let va = |rva: u32| base.wrapping_add(u64::from(rva));
    let handlers = config.safe_seh_handlers();
    if !handlers.is_empty() {
        address_header(out, "Safe Exception Handler Table")?;
        for h in handlers {
            writeln!(out, "           {:0ptr$X}", va(h.get()))?;
        }
    }
    guard_table(
        out,
        "Guard CF Function Table",
        config.guard_cf_functions(),
        base,
        ptr,
    )?;
    guard_table(
        out,
        "Guard CF Address Taken IAT Entry Table",
        config.guard_address_taken_iat_entries(),
        base,
        ptr,
    )?;
    guard_table(
        out,
        "Guard CF Long Jump Target Table",
        config.guard_long_jump_targets(),
        base,
        ptr,
    )?;
    guard_table(
        out,
        "Guard EH Continuation Table",
        config.guard_eh_continuations(),
        base,
        ptr,
    )?;

    if let Some(table) = config.dynamic_relocations() {
        dvrt(out, file, table, ptr)?;
    }
    // dumpbin shows the hybrid metadata after the tables above.
    hybrid(out, file, &config, ptr)?;
    if let Some(vm) = config.volatile_metadata() {
        writeln!(out, "\n    Volatile Metadata\n")?;
        let version = vm.version();
        let (min, max) = (version & 0xFFFF, version >> 16);
        writeln!(out, "        {:16X} size", vm.size())?;
        writeln!(out, "        {:16X} min version ({min:X})", min & 0x7FFF)?;
        writeln!(out, "        {:16X} max version ({max:X})", max & 0x7FFF)?;
        let rva = vm.access_table_rva().get();
        writeln!(
            out,
            "        {} volatile access RVA table",
            fixed(rva.into(), ptr)
        )?;
        writeln!(
            out,
            "        {:16X} volatile access RVA table size",
            vm.access_table_size()
        )?;
        let rva = vm.info_range_table_rva().get();
        writeln!(
            out,
            "        {} volatile range info table",
            fixed(rva.into(), ptr)
        )?;
        writeln!(
            out,
            "        {:16X} volatile range info table size",
            vm.info_range_table_size()
        )?;
        let access = vm.access_rvas();
        if !access.is_empty() {
            address_header(out, "Volatile Access RVA Table")?;
            for a in access {
                writeln!(out, "           {:0ptr$X}", va(a.get()))?;
            }
        }
        let mut ranges = vm.info_ranges().peekable();
        if ranges.peek().is_some() {
            writeln!(out, "\n    Volatile Info Range Table\n")?;
            writeln!(out, "          Ranges")?;
            writeln!(out, "          -------")?;
        }
        for (rva, size) in ranges {
            let start = va(rva.get());
            let end = start.wrapping_add(u64::from(size));
            writeln!(out, "          {start:0ptr$X} - {end:0ptr$X}")?;
        }
    }
    if let Some(enclave) = config.enclave_config() {
        enclave_config(out, &enclave, ptr)?;
    }
    Ok(())
}

const X64_REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The dynamic value relocation table.
fn dvrt(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    table: DynamicRelocationTable<'_>,
    ptr: usize,
) -> io::Result<()> {
    let _ = file;
    writeln!(
        out,
        "\n    Dynamic Value Relocation Table (version: {})\n",
        table.version
    )?;
    for reloc in table.iter() {
        let name = dynamic_symbol::name(reloc.symbol)
            .map(|n| format!(" {n}"))
            .unwrap_or_default();
        writeln!(out, "    Symbol VA: {:0ptr$X}{name}", reloc.symbol)?;
        if table.version >= 2 {
            writeln!(out, "    Symbol Group: {:08X}", reloc.symbol_group)?;
            writeln!(out, "    Flags: {:08X}", reloc.flags)?;
        }
        if let Some(overrides) = reloc.function_overrides() {
            writeln!(
                out,
                "    Total function overrides size: {:X} bytes",
                overrides.overrides_size()
            )?;
            writeln!(out, "    BDD data: {:X} bytes", overrides.bdd_size())?;
            for (i, o) in overrides.iter().enumerate() {
                writeln!(out, "\n    Function Override ({:X})\n", i + 1)?;
                writeln!(out, "        Original RVA:    {:08X}", o.original_rva.get())?;
                writeln!(out, "        BDD Offset:      {:8X}", o.bdd_offset)?;
                writeln!(out, "        RVA array size:  {:8X}", o.rvas.len())?;
                writeln!(out, "        Reloc size:      {:8X}", o.fixups.len())?;
                writeln!(out, "\n        RVAs:\n")?;
                for (j, rva) in o.rvas().enumerate() {
                    writeln!(out, "            [{j:08X}] {:08X}", rva.get())?;
                }
                if let Some((version, block)) = overrides.bdd_at(o.bdd_offset) {
                    writeln!(
                        out,
                        "\n        BDD (version: {version:X}, {:X} bytes):\n",
                        block.len()
                    )?;
                    for (j, d) in FunctionOverrides::descriptors(block).enumerate() {
                        writeln!(
                            out,
                            "            [{j:08X}] {:04X}, {:04X}, {:08X}",
                            d.left, d.right, d.value
                        )?;
                    }
                }
                writeln!(out, "\n        Fixup RVAs:\n")?;
                let mut j = 0;
                for block in o.blocks() {
                    for e in block.entries_u16() {
                        let e = e.get();
                        if e == 0 {
                            continue;
                        }
                        let page = block.page.get();
                        writeln!(
                            out,
                            "            [{j:08X}] = page {page:08X} rva {:08X} type {:X}",
                            page + u32::from(e & 0xFFF),
                            e >> 12
                        )?;
                        j += 1;
                    }
                }
            }
            writeln!(out)?;
            continue;
        }
        writeln!(out, "    Fixup RVAs:")?;
        let mut j = 0;
        for block in reloc.blocks() {
            let page = block.page.get();
            match reloc.symbol {
                dynamic_symbol::GUARD_IMPORT_CONTROL_TRANSFER => {
                    for e in block.entries_u32() {
                        if e == 0 {
                            continue;
                        }
                        let kind = if e & 0x1000 != 0 { "call  " } else { "branch" };
                        writeln!(
                            out,
                            "        [{j:08X}] = page {page:08X} rva {:08X} {kind} import index {:05X}",
                            page + (e & 0xFFF),
                            e >> 13
                        )?;
                        j += 1;
                    }
                }
                dynamic_symbol::ARM64_KERNEL_IMPORT_CALL_TRANSFER => {
                    for e in block.entries_u32() {
                        if e == 0 {
                            continue;
                        }
                        let instr = if e & 0x400 != 0 { "blr" } else { "br " };
                        let reg = (e >> 11) & 0x1F;
                        let delay = if e & 0x1_0000 != 0 { "yes" } else { "no" };
                        writeln!(
                            out,
                            "        [{j:08X}] = page ({page:08X}), rva ({:08X}), instr ({instr} x{reg:<2}), delayload ({delay:<3}), IAT index ({:04X})",
                            page + (e & 0x3FF) * 4,
                            e >> 17
                        )?;
                        j += 1;
                    }
                }
                dynamic_symbol::ARM64X => {
                    let entries = block.entries_u16();
                    let mut k = 0;
                    while k < entries.len() {
                        let e = entries[k].get();
                        k += 1;
                        if e == 0 {
                            continue;
                        }
                        let rva = page + u32::from(e & 0xFFF);
                        let kind = (e >> 12) & 3;
                        let meta = e >> 14;
                        let line = format!("        [{j:08x}] page {page:08X} rva {rva:08X}, ");
                        match kind {
                            0 => writeln!(out, "{line}{} bytes, zero fill", 1u32 << meta)?,
                            1 => {
                                let size = 1usize << meta;
                                let mut value = 0u64;
                                for w in 0..size.div_ceil(2) {
                                    let part = entries.get(k + w).map_or(0, |v| v.get());
                                    value |= u64::from(part) << (16 * w);
                                }
                                k += size.div_ceil(2);
                                writeln!(out, "{line}{size} bytes, target value {value:X}")?;
                            }
                            _ => {
                                // dumpbin shows the fields as they are:
                                // the scale (4 or 8) as the size, and
                                // the unscaled delta.
                                let delta = entries.get(k).map_or(0, |v| v.get());
                                k += 1;
                                let scale = if meta & 2 != 0 { 8 } else { 4 };
                                let sign = if meta & 1 != 0 { '-' } else { ' ' };
                                writeln!(out, "{line}{scale} bytes, delta {sign}0x{delta:X}")?;
                            }
                        }
                        j += 1;
                    }
                }
                _ => {
                    for (n, e) in block.entries_u16().iter().enumerate() {
                        let e = e.get();
                        // A trailing zero pads the block to a multiple of 4 bytes.
                        if e == 0 && n + 1 == block.entries_u16().len() {
                            continue;
                        }
                        let rva = page + u32::from(e & 0xFFF);
                        if reloc.symbol == dynamic_symbol::GUARD_SWITCHTABLE_BRANCH {
                            let reg = X64_REGISTERS[usize::from(e >> 12)];
                            writeln!(
                                out,
                                "        [{j:08X}] = page {page:08X} rva {rva:08X} register {reg}"
                            )?;
                        } else {
                            writeln!(
                                out,
                                "        [{j:08X}] = page {page:08X} rva {rva:08X} type {:X}",
                                e >> 12
                            )?;
                        }
                        j += 1;
                    }
                }
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

fn address_header(out: &mut dyn Write, title: &str) -> io::Result<()> {
    writeln!(out, "\n    {title}\n")?;
    writeln!(out, "          Address")?;
    writeln!(out, "          --------")
}

fn guard_table(
    out: &mut dyn Write,
    title: &str,
    table: GuardTable<'_>,
    base: u64,
    ptr: usize,
) -> io::Result<()> {
    if table.is_empty() {
        return Ok(());
    }
    address_header(out, title)?;
    for e in table.iter() {
        let flag = |bit: u8, c: char| if e.flags & bit != 0 { c } else { ' ' };
        writeln!(
            out,
            "       {}{}  {:0ptr$X}",
            flag(guard_entry::EXPORT_SUPPRESSED, 'E'),
            flag(guard_entry::FID_SUPPRESSED, 'S'),
            base.wrapping_add(u64::from(e.rva.get()))
        )?;
    }
    Ok(())
}

/// The ARM64EC or CHPE metadata.
fn hybrid(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    config: &LoadConfig<'_>,
    ptr: usize,
) -> io::Result<()> {
    let Some(h) = config.hybrid_metadata() else {
        return Ok(());
    };
    let base = file.optional_header().map_or(0, |o| o.image_base().get());
    writeln!(out, "\n  Section contains the following hybrid metadata:\n")?;
    writeln!(out, "    {:16X} Version", h.version())?;
    if h.is_x86() {
        use chpe_x86::*;
        let fields: &[(usize, &str)] = &[
            (
                WOWA64_EXCEPTION_HANDLER_FUNCTION_POINTER,
                "exception handler function pointer",
            ),
            (
                WOWA64_DISPATCH_CALL_FUNCTION_POINTER,
                "dispatch call function pointer",
            ),
            (
                WOWA64_DISPATCH_INDIRECT_CALL_FUNCTION_POINTER,
                "dispatch indirect call function pointer",
            ),
            (
                WOWA64_DISPATCH_INDIRECT_CALL_CFG_FUNCTION_POINTER,
                "dispatch indirect call function pointer (with CFG check)",
            ),
            (
                WOWA64_DISPATCH_RET_FUNCTION_POINTER,
                "dispatch return function pointer",
            ),
            (
                WOWA64_DISPATCH_RET_LEAF_FUNCTION_POINTER,
                "dispatch leaf return function pointer",
            ),
            (
                WOWA64_DISPATCH_JUMP_FUNCTION_POINTER,
                "dispatch jump function pointer",
            ),
            (
                COMPILER_IAT_POINTER,
                "auxiliary import address table pointer",
            ),
        ];
        for &(i, name) in fields {
            if i < h.len() {
                writeln!(
                    out,
                    "    {} Address of WowA64 {name}",
                    fixed(u64::from(h.field(i)), ptr)
                )?;
            }
        }
    } else {
        use arm64ec::*;
        enum F {
            Offset(&'static str),
            Count(&'static str),
            Value(&'static str),
        }
        let fields: &[(usize, F)] = &[
            (
                DISPATCH_CALL_NO_REDIRECT,
                F::Offset("dispatch call function pointer (no redirection)"),
            ),
            (DISPATCH_RET, F::Offset("dispatch return function pointer")),
            (
                DISPATCH_ICALL,
                F::Offset("dispatch indirect call function pointer"),
            ),
            (
                DISPATCH_ICALL_CFG,
                F::Offset("dispatch indirect call function pointer (with CFG check)"),
            ),
            (ALTERNATE_ENTRY_POINT, F::Offset("alternative entry point")),
            (AUXILIARY_IAT, F::Offset("auxiliary import address table")),
            (
                CODE_RANGES_TO_ENTRY_POINTS,
                F::Offset("x64 code ranges to entry points table"),
            ),
            (
                CODE_RANGES_TO_ENTRY_POINTS_COUNT,
                F::Count("x64 code ranges to entry point table entries"),
            ),
            (
                REDIRECTION_METADATA,
                F::Offset("arm64x redirection metadata table"),
            ),
            (
                REDIRECTION_METADATA_COUNT,
                F::Count("arm64x redirection metadata table entries"),
            ),
            (EXTRA_RFE_TABLE, F::Offset("extra RFE table")),
            (EXTRA_RFE_TABLE_SIZE, F::Count("extra RFE table size")),
            (DISPATCH_FPTR, F::Offset("dispatch function pointer")),
            (
                AUXILIARY_IAT_COPY,
                F::Offset("copy of auxiliary import address table"),
            ),
            (
                AUXILIARY_DELAYLOAD_IAT,
                F::Offset("auxiliary delayload import address table"),
            ),
            (
                AUXILIARY_DELAYLOAD_IAT_COPY,
                F::Offset("auxiliary delayload import address table copy"),
            ),
            (
                HYBRID_IMAGE_INFO_BITFIELD,
                F::Value("hybrid image info bitfield"),
            ),
        ];
        for (i, f) in fields {
            if *i >= h.len() {
                continue;
            }
            let v = h.field(*i);
            match f {
                F::Offset(name) => {
                    writeln!(out, "    {} Offset of Arm64X {name}", fixed(v.into(), 8))?;
                }
                F::Count(name) => writeln!(out, "    {v:16X}  Count of Arm64X {name}")?,
                F::Value(name) => writeln!(out, "    {v:16X}  Value of Arm64X {name}")?,
            }
        }
    }
    writeln!(out)?;
    let map = h.code_map_rva().get();
    let map_va = if map == 0 {
        0
    } else {
        base.wrapping_add(map.into())
    };
    writeln!(
        out,
        "    {} Hybrid code address range table",
        fixed(map_va, ptr)
    )?;
    writeln!(
        out,
        "    {:16X} Hybrid code address range count",
        h.code_map_count()
    )?;
    writeln!(out, "\n    Hybrid Code Address Range Table\n")?;
    writeln!(out, "                Address Range")?;
    writeln!(out, "          ----------------------")?;
    for r in h.code_ranges() {
        let kind = match r.kind {
            CodeKind::X86 => "            x86  ",
            CodeKind::Arm64 => "          arm64  ",
            CodeKind::X64 => "            x64  ",
            CodeKind::Arm64ec => "        arm64ec  ",
        };
        let start = r.rva.get();
        let end = start.wrapping_add(r.size).wrapping_sub(1);
        let (vs, ve) = (
            base.wrapping_add(start.into()),
            base.wrapping_add(end.into()),
        );
        writeln!(
            out,
            "{kind}{vs:0ptr$X} - {ve:0ptr$X} ({start:08X} - {end:08X})"
        )?;
    }
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!(" {b:02X}")).collect()
}

fn enclave_config(
    out: &mut dyn Write,
    e: &hexcavator_pe::EnclaveConfig<'_>,
    ptr: usize,
) -> io::Result<()> {
    writeln!(out, "\n    Enclave Configuration\n")?;
    let f8 = |v: u32| fixed(v.into(), 8);
    writeln!(out, "        {} size", f8(e.size()))?;
    writeln!(
        out,
        "        {} minimum required config size",
        f8(e.minimum_required_config_size())
    )?;
    writeln!(out, "        {} policy flags", f8(e.policy_flags()))?;
    writeln!(
        out,
        "        {} number of enclave import descriptors",
        f8(e.number_of_imports())
    )?;
    writeln!(
        out,
        "        {} RVA to enclave import descriptors",
        f8(e.import_list().get())
    )?;
    writeln!(
        out,
        "        {} size of an enclave import descriptor",
        f8(e.import_entry_size())
    )?;
    writeln!(out, "        {} image version", f8(e.image_version()))?;
    writeln!(out, "        {} security version", f8(e.security_version()))?;
    writeln!(out, "        {} enclave size", fixed(e.enclave_size(), ptr))?;
    writeln!(
        out,
        "        {} number of threads",
        f8(e.number_of_threads())
    )?;
    writeln!(out, "        {} enclave flags", f8(e.enclave_flags()))?;
    writeln!(
        out,
        "\n                family ID :{}",
        hex_bytes(e.family_id())
    )?;
    writeln!(
        out,
        "                 image ID :{}",
        hex_bytes(e.image_id())
    )?;
    for import in e.imports() {
        let name = import.name.map(String::from_utf8_lossy).unwrap_or_default();
        writeln!(out, "\n      {name}\n")?;
        writeln!(
            out,
            "          {:8X} minimum security version",
            import.minimum_security_version
        )?;
        writeln!(out, "          {:8X} reserved", import.reserved)?;
        let kind = match import.match_type {
            0 => "none",
            1 => "unique ID",
            2 => "author ID",
            3 => "family ID",
            4 => "image ID",
            _ => "unknown",
        };
        writeln!(out, "\n                   match type : {kind}")?;
        writeln!(
            out,
            "                    family ID :{}",
            hex_bytes(import.family_id)
        )?;
        writeln!(
            out,
            "                     image ID :{}",
            hex_bytes(import.image_id)
        )?;
        let id = import.unique_or_author_id;
        writeln!(
            out,
            "             unique/author ID :{}",
            hex_bytes(&id[..16])
        )?;
        writeln!(
            out,
            "                               {}",
            hex_bytes(&id[16..])
        )?;
    }
    Ok(())
}

/// `/tls`: the TLS directory and its callbacks.
pub fn tls(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(t) = file.tls() else {
        return Ok(());
    };
    let ptr = if file
        .optional_header()
        .is_some_and(hexcavator_pe::OptionalHeader::is_64)
    {
        16
    } else {
        8
    };
    writeln!(out, "\n  Section contains the following TLS directory:\n")?;
    for (va, label) in [
        (t.start_of_raw_data, "Start of raw data"),
        (t.end_of_raw_data, "End of raw data"),
        (t.address_of_index, "Address of index"),
        (t.address_of_callbacks, "Address of callbacks"),
    ] {
        writeln!(out, "    {} {label}", fixed(va.get(), ptr))?;
    }
    writeln!(out, "    {:16X} Size of zero fill", t.size_of_zero_fill)?;
    writeln!(
        out,
        "    {} Characteristics",
        fixed(t.characteristics.into(), 8)
    )?;
    if let Some(align) =
        hexcavator_pe::consts::section_characteristics::alignment(t.characteristics)
    {
        writeln!(out, "                       {align} byte align")?;
    }
    writeln!(out, "\n    TLS Callbacks\n")?;
    writeln!(out, "          Address")?;
    writeln!(out, "          {}", "-".repeat(ptr))?;
    for va in file.tls_callbacks() {
        writeln!(out, "          {:0ptr$X}", va.get())?;
    }
    // The list ends with a null entry, which dumpbin shows too.
    writeln!(out, "          {:0ptr$X}", 0)
}

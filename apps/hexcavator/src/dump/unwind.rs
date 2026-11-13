//! `/pdata` and `/unwindinfo`: the exception directory and unwind data.

use std::io::{self, Write};

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::exception::{PdataEntry, RuntimeFunction, X64UnwindCode, unwind_flags};

use crate::symbols::SymbolMap;

const X64_REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

pub fn pdata(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    table(out, file, false, symbols)
}

pub fn unwind_info(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    table(out, file, true, symbols)
}

/// The symbol at `rva`, as dumpbin shows it: decorated, then undecorated.
fn symbol_text(file: &PeFile<'_>, symbols: Option<&SymbolMap>, rva: u32) -> Option<String> {
    let base = file.optional_header().map_or(0, |h| h.image_base().get());
    // (dumpbin names functions only with public symbols.)
    let name = symbols?.public_at(base.wrapping_add(u64::from(rva)))?;
    Some(match super::undecorate(name) {
        Some(u) => format!("{name} ({u})"),
        None => name.to_string(),
    })
}

fn table(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    unwind: bool,
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    let entries: Vec<PdataEntry> = file.runtime_functions().collect();
    if entries.is_empty() {
        return Ok(());
    }
    let hybrid = entries
        .iter()
        .any(|e| matches!(e.function, RuntimeFunction::X64 { .. }))
        && entries
            .iter()
            .any(|e| matches!(e.function, RuntimeFunction::Arm { .. }));
    let pdata_rva = file
        .data_directory(hexcavator_pe::consts::directory::EXCEPTION)
        .map_or(0, |d| d.virtual_address.get());
    if hybrid {
        writeln!(out, "\nFunction Table")?;
    } else {
        writeln!(out, "\nFunction Table ({})", entries.len())?;
    }
    let mut current: Option<bool> = None;
    for entry in &entries {
        let x64 = matches!(entry.function, RuntimeFunction::X64 { .. });
        if current != Some(x64) {
            current = Some(x64);
            writeln!(
                out,
                "\n{}\n",
                match (hybrid, x64) {
                    (false, true) => "           Begin    End      Info      Function Name",
                    (false, false) => "           Begin    Packed  Function Name",
                    (true, true) => "  (AMD64)  Begin    End      Info      Function Name",
                    (true, false) => "  (ARM64)  Begin    Packed Function Name",
                }
            )?;
        }
        match entry.function {
            RuntimeFunction::X64 {
                begin,
                end,
                unwind: info,
            } => {
                // Plain x64 images show the entry's RVA; hybrid ones, its
                // offset in the table.
                let at = if hybrid {
                    entry.offset
                } else {
                    pdata_rva + entry.offset
                };
                write!(
                    out,
                    "  {at:08X} {:08X} {:08X} {:08X}",
                    begin.get(),
                    end.get(),
                    info.get()
                )?;
                match symbol_text(file, symbols, begin.get()) {
                    Some(name) => writeln!(out, "  {name}")?,
                    None => writeln!(out)?,
                }
                if unwind {
                    x64_unwind(out, file, info, symbols)?;
                    writeln!(out)?;
                }
            }
            RuntimeFunction::Arm {
                begin,
                unwind: word,
            } => {
                let packed = if word & 3 != 0 { 'Y' } else { 'N' };
                write!(
                    out,
                    "  {:08X} {:08X}    {packed}   ",
                    entry.offset,
                    begin.get()
                )?;
                match symbol_text(file, symbols, begin.get()) {
                    Some(name) => writeln!(out, "  {name}")?,
                    None => writeln!(out)?,
                }
                if unwind {
                    super::arm64_unwind::unwind(out, file, begin, word, symbols)?;
                    writeln!(out)?;
                }
            }
        }
    }
    Ok(())
}

fn x64_unwind(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    rva: Rva,
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    let Some(info) = file.x64_unwind_info(rva) else {
        return Ok(());
    };
    writeln!(out, "    Unwind version: {}", info.version)?;
    write!(out, "    Unwind flags:")?;
    if info.flags == 0 {
        write!(out, " None")?;
    }
    for (bit, name) in [
        (unwind_flags::EHANDLER, "EHANDLER"),
        (unwind_flags::UHANDLER, "UHANDLER"),
        (unwind_flags::CHAININFO, "CHAININFO"),
    ] {
        if info.flags & bit != 0 {
            write!(out, " {name}")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "    Size of prologue: 0x{:02X}", info.prolog_size)?;
    writeln!(out, "    Count of codes: {}", info.count_of_codes())?;
    let frame = X64_REGISTERS[usize::from(info.frame_register)];
    let frame_offset = u32::from(info.frame_offset) * 16;
    if info.frame_register != 0 {
        writeln!(out, "    Frame register: {frame}")?;
        writeln!(out, "    Frame offset: 0x{frame_offset:X}")?;
    }
    if info.count_of_codes() > 0 {
        writeln!(out, "    Unwind codes:")?;
    }
    for (offset, code) in info.unwind_codes() {
        let reg = |r: u8| X64_REGISTERS[usize::from(r & 0xF)];
        let text = match code {
            X64UnwindCode::PushNonvol { reg: r } => format!("PUSH_NONVOL, register={}", reg(r)),
            X64UnwindCode::AllocLarge { size } => format!("ALLOC_LARGE, size=0x{size:X}"),
            X64UnwindCode::AllocSmall { size } => format!("ALLOC_SMALL, size=0x{size:X}"),
            X64UnwindCode::SetFpreg => {
                format!("SET_FPREG, register={frame}, offset=0x{frame_offset:02X}")
            }
            X64UnwindCode::SaveNonvol { reg: r, offset } => {
                format!("SAVE_NONVOL, register={} offset=0x{offset:X}", reg(r))
            }
            X64UnwindCode::SaveNonvolFar { reg: r, offset } => {
                format!("SAVE_NONVOL_FAR, register={} offset=0x{offset:X}", reg(r))
            }
            X64UnwindCode::EpilogFirst { flags, size } => {
                format!("EPILOG, flags = 0x{flags:X}, size = 0x{size:X}")
            }
            X64UnwindCode::Epilog { offset_from_end } => {
                format!("EPILOG, offset from end = 0x{offset_from_end:X}")
            }
            X64UnwindCode::SaveXmm128 { reg: r, offset } => {
                format!("SAVE_XMM128, register=xmm{r} offset=0x{offset:X}")
            }
            X64UnwindCode::SaveXmm128Far { reg: r, offset } => {
                format!("SAVE_XMM128_FAR, register=xmm{r} offset=0x{offset:X}")
            }
            X64UnwindCode::PushMachframe { error_code: false } => {
                "PUSH_MACHFRAME without error code".to_string()
            }
            X64UnwindCode::PushMachframe { error_code: true } => {
                "PUSH_MACHFRAME with error code".to_string()
            }
            X64UnwindCode::Unknown { op, info } => {
                format!("    Unknown(0x{:02X})", op | info << 4)
            }
        };
        writeln!(out, "      {offset:02X}: {text}")?;
    }
    if let Some(handler) = info.handler() {
        // With symbols, dumpbin names the handler and decodes its data.
        let base = file.optional_header().map_or(0, |h| h.image_base().get());
        let name = symbols.and_then(|s| s.at(base.wrapping_add(u64::from(handler.get()))));
        match name {
            Some(name) => {
                writeln!(out, "    Handler: {:08X} {name}", handler.get())?;
                if let Some(data) = info.handler_data() {
                    super::x64_eh::handler_data(out, file, name, data)?;
                }
            }
            None => writeln!(out, "    Handler: {:08X}", handler.get())?,
        }
    }
    if let Some(RuntimeFunction::X64 { begin, end, unwind }) = info.chained() {
        writeln!(
            out,
            "    Chained: {:08X} {:08X} {:08X}",
            begin.get(),
            end.get(),
            unwind.get()
        )?;
    }
    Ok(())
}

/// An object's `.pdata` section: raw entries, before relocation.
pub fn object_pdata(out: &mut dyn Write, file: &PeFile<'_>, index: usize) -> io::Result<()> {
    use hexcavator_pe::consts::machine;
    let section = &file.sections()[index];
    if !file.section_name(section).starts_with(b".pdata") {
        return Ok(());
    }
    let start = section.pointer_to_raw_data.get() as usize;
    let len = section.size_of_raw_data.get() as usize;
    let Some(data) = file.data().get(start..).and_then(|d| d.get(..len)) else {
        return Ok(());
    };
    let word = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    match file.machine() {
        machine::AMD64 => {
            let n = data.len() / 12;
            writeln!(out, "\nFunction Table #{} ({n})", index + 1)?;
            writeln!(out, "\n           Begin     End       Info\n")?;
            for i in 0..n {
                let o = i * 12;
                writeln!(
                    out,
                    "  {o:08X} {:08X}  {:08X}  {:08X}",
                    word(o),
                    word(o + 4),
                    word(o + 8)
                )?;
            }
        }
        machine::ARM64 | machine::ARM64EC | machine::ARMNT => {
            let n = data.len() / 8;
            writeln!(out, "\nFunction Table #{} ({n})", index + 1)?;
            writeln!(out, "\n           Begin    Packed Fragment\n")?;
            for i in 0..n {
                let o = i * 8;
                let unwind = word(o + 4);
                let yn = |b: bool| if b { 'Y' } else { 'N' };
                writeln!(
                    out,
                    "  {o:08X} {:08X}    {}      {}",
                    word(o),
                    yn(unwind & 3 != 0),
                    yn(unwind & 3 == 2)
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

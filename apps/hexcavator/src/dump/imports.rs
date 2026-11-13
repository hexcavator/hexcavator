//! `/imports`, `/exports`, and `/relocations`.

use std::io::{self, Write};

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::exports::ExportTarget;
use hexcavator_pe::imports::ImportName;
use hexcavator_pe::reloc::base_reloc;

fn lossy(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

pub fn static_imports(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(header) = file.optional_header() else {
        return Ok(());
    };
    let is_64 = header.is_64();
    let base = header.image_base().get();
    let va = |rva: u32| {
        if rva == 0 {
            0
        } else {
            base.wrapping_add(u64::from(rva))
        }
    };
    // Where the hint column ends.
    let hint_end = if is_64 { 28 } else { 21 };

    let mut dlls = file.imports().peekable();
    if dlls.peek().is_some() {
        writeln!(out, "\n  Section contains the following imports:")?;
    }
    for dll in dlls {
        writeln!(out)?;
        let d = dll.descriptor;
        writeln!(out, "    {}", lossy(dll.name))?;
        writeln!(
            out,
            "      {:16X} Import Address Table",
            va(d.import_address_table.get())
        )?;
        writeln!(
            out,
            "      {:16X} Import Name Table",
            va(d.import_name_table.get())
        )?;
        writeln!(out, "      {:16X} time date stamp", d.time_date_stamp.get())?;
        writeln!(
            out,
            "      {:16X} Index of first forwarder reference\n",
            d.forwarder_chain.get()
        )?;
        for thunk in dll.thunks() {
            match thunk.import {
                ImportName::Name { hint, name } => {
                    writeln!(out, "{hint:>hint_end$X} {}", lossy(name))?;
                }
                ImportName::Ordinal(n) => {
                    writeln!(out, "{:>w$}Ordinal {n:5}", "", w = hint_end + 1)?;
                }
            }
        }
    }
    Ok(())
}

pub fn delay_imports(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(header) = file.optional_header() else {
        return Ok(());
    };
    let is_64 = header.is_64();
    let base = header.image_base().get();
    let va = |rva: u32| {
        if rva == 0 {
            0
        } else {
            base.wrapping_add(u64::from(rva))
        }
    };
    let mut dlls = file.delay_imports().peekable();
    if dlls.peek().is_some() {
        writeln!(
            out,
            "\n  Section contains the following delay load imports:"
        )?;
    }
    let ptr = if is_64 { 16 } else { 8 };
    for dll in dlls {
        writeln!(out)?;
        let d = dll.descriptor;
        let field = |v: u32| -> u64 { dll.rva(v).map_or(0, |r| va(r.get())) };
        writeln!(out, "    {}", lossy(dll.name))?;
        writeln!(
            out,
            "      {:>16} Characteristics",
            format!("{:08X}", d.attributes.get())
        )?;
        for (value, label) in [
            (d.module_handle.get(), "Address of HMODULE"),
            (d.import_address_table.get(), "Import Address Table"),
            (d.import_name_table.get(), "Import Name Table"),
            (
                d.bound_import_address_table.get(),
                "Bound Import Name Table",
            ),
            (d.unload_information_table.get(), "Unload Import Name Table"),
        ] {
            writeln!(
                out,
                "      {:>16} {label}",
                format!("{:0ptr$X}", field(value))
            )?;
        }
        writeln!(
            out,
            "      {:16X} time date stamp\n",
            d.time_date_stamp.get()
        )?;
        // Unload-table entries (if any) come first, in a column of their own.
        let (indent, hint_width) = if is_64 { (18, 4) } else { (0, 14) };
        let unload = dll.rva(d.unload_information_table.get());
        let iat = dll.rva(d.import_address_table.get());
        for thunk in dll.thunks() {
            // The unload table parallels the IAT.
            let unload = unload
                .zip(iat)
                .and_then(|(u, iat)| {
                    let slot = thunk.iat_rva.get().checked_sub(iat.get())?;
                    file.thunk(Rva(u.get().checked_add(slot)?))
                })
                .filter(|&v| v != 0);
            match unload {
                Some(b) => write!(out, "{:indent$}{b:0ptr$X}  ", "")?,
                None => write!(out, "{:w$}", "", w = indent + ptr + 2)?,
            }
            write!(out, "{:0ptr$X}  ", thunk.address_thunk)?;
            match thunk.import {
                ImportName::Name { hint, name } => {
                    writeln!(out, "{hint:>hint_width$X} {}", lossy(name))?;
                }
                ImportName::Ordinal(n) => {
                    writeln!(out, "{:>w$}Ordinal {n:5}", "", w = hint_width + 1)?;
                }
            }
        }
    }
    Ok(())
}

pub fn exports(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(exports) = file.exports() else {
        return Ok(());
    };
    let d = exports.directory;
    let name = exports.dll_name().map(lossy).unwrap_or_default();
    writeln!(
        out,
        "\n  Section contains the following exports for {name}\n"
    )?;
    writeln!(out, "    {:08X} characteristics", d.characteristics.get())?;
    let stamp = d.time_date_stamp.get();
    let date = super::pe::stamp_date(file, stamp);
    writeln!(out, "    {stamp:8X} time date stamp{date}")?;
    let version = format!("{}.{:02}", d.major_version.get(), d.minor_version.get());
    writeln!(out, "    {version:>8} version")?;
    writeln!(out, "    {:8} ordinal base", exports.ordinal_base())?;
    writeln!(
        out,
        "    {:8} number of functions",
        d.number_of_functions.get()
    )?;
    writeln!(out, "    {:8} number of names", d.number_of_names.get())?;
    writeln!(out, "\n    ordinal hint RVA      name\n")?;
    // Named exports in name order, then the unnamed ones in ordinal order.
    let mut all: Vec<_> = exports.iter().collect();
    all.sort_by_key(|e| (e.hint.is_none(), e.hint, e.ordinal));
    for e in all {
        match e.hint {
            Some(hint) => write!(out, "      {:5} {hint:4X} ", e.ordinal)?,
            None => write!(out, "      {:5}      ", e.ordinal)?,
        }
        match e.target {
            ExportTarget::Rva(rva) => write!(out, "{:08X} ", rva.get())?,
            ExportTarget::Forwarder(_) => write!(out, "         ")?,
        }
        match e.name {
            Some(name) => write!(out, "{}", lossy(name))?,
            None => write!(out, "[NONAME]")?,
        }
        if let ExportTarget::Forwarder(to) = e.target {
            write!(out, " (forwarded to {})", lossy(to))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn reloc_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        base_reloc::ABSOLUTE => "ABS",
        base_reloc::HIGH => "HIGH",
        base_reloc::LOW => "LOW",
        base_reloc::HIGHLOW => "HIGHLOW",
        base_reloc::HIGHADJ => "HIGHADJ",
        base_reloc::DIR64 => "DIR64",
        _ => return None,
    })
}

pub fn relocations(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let Some(dir) = file.data_directory(hexcavator_pe::consts::directory::BASERELOC) else {
        return Ok(());
    };
    let rva = dir.virtual_address.get();
    let section = file
        .sections()
        .iter()
        .position(|s| {
            let start = s.virtual_address.get();
            rva >= start && rva - start < s.virtual_size.get().max(s.size_of_raw_data.get())
        })
        .map_or(0, |i| i + 1);
    writeln!(out, "\nBASE RELOCATIONS #{section:X}")?;
    for block in file.base_reloc_blocks() {
        writeln!(
            out,
            "{:8X} RVA, {:8X} SizeOfBlock",
            block.page.get(),
            block.size
        )?;
        let entries = block.entries_u16();
        let mut i = 0;
        while i < entries.len() {
            let e = entries[i].get();
            i += 1;
            let kind = (e >> 12) as u8;
            let offset = e & 0xFFF;
            let at = Rva(block.page.get().wrapping_add(u32::from(offset)));
            let read = |n: u32| file.bytes_at_rva(at, n).ok();
            let (name, value) = match reloc_name(kind) {
                Some(name) => {
                    let value = match kind {
                        base_reloc::DIR64 => read(8)
                            .map(|b| format!("{:016X}", u64::from_le_bytes(b.try_into().unwrap()))),
                        base_reloc::HIGHLOW => read(4)
                            .map(|b| format!("{:08X}", u32::from_le_bytes(b.try_into().unwrap()))),
                        base_reloc::HIGH | base_reloc::LOW => read(2)
                            .map(|b| format!("{:04X}", u16::from_le_bytes(b.try_into().unwrap()))),
                        base_reloc::HIGHADJ => {
                            // The next entry holds the low half of the
                            // adjusted value.
                            let low = entries.get(i).map_or(0, |v| v.get());
                            i += 1;
                            read(2).map(|b| {
                                format!(
                                    "{:04X} ({low:04X})",
                                    u16::from_le_bytes(b.try_into().unwrap())
                                )
                            })
                        }
                        _ => Some(String::new()),
                    };
                    (name.to_string(), value.unwrap_or_default())
                }
                None => (format!("UNKNOWN({kind:X})"), String::new()),
            };
            writeln!(out, "{offset:8X}  {name:<8}  {value:>17}")?;
        }
    }
    Ok(())
}

/// An object section's COFF relocations.
pub fn object_relocations(out: &mut dyn Write, file: &PeFile<'_>, index: usize) -> io::Result<()> {
    let section = &file.sections()[index];
    let relocs = file.section_relocations(section);
    if relocs.is_empty() {
        return Ok(());
    }
    let symbols = file.symbols().ok().flatten();
    let machine = file.machine();
    let data = {
        let start = section.pointer_to_raw_data.get() as usize;
        let len = section.size_of_raw_data.get() as usize;
        file.data()
            .get(start..)
            .and_then(|d| d.get(..len))
            .unwrap_or(&[])
    };
    writeln!(out, "\nRELOCATIONS #{:X}", index + 1)?;
    writeln!(
        out,
        "                                                Symbol    Symbol"
    )?;
    writeln!(
        out,
        " Offset    Type              Applied To         Index     Name"
    )?;
    writeln!(
        out,
        " --------  ----------------  -----------------  --------  ------"
    )?;
    for r in relocs {
        let offset = r.virtual_address.get();
        let kind = r.kind.get();
        let name = hexcavator_pe::reloc::coff_reloc_name(machine, kind)
            .map_or_else(|| format!("{kind:X}"), str::to_string);
        let size = hexcavator_pe::reloc::coff_reloc_size(machine, kind);
        let at = offset as usize;
        let applied = match data.get(at..at + size) {
            Some(b) if size == 8 => {
                let v = u64::from_le_bytes(b.try_into().unwrap());
                format!("{:08X} {:08X}", v >> 32, v & 0xFFFF_FFFF)
            }
            Some(b) if size == 4 => format!("{:08X}", u32::from_le_bytes(b.try_into().unwrap())),
            Some(b) if size == 2 => format!("{:04X}", u16::from_le_bytes(b.try_into().unwrap())),
            _ => String::new(),
        };
        let index = r.symbol_table_index.get();
        let symbol = symbols
            .as_ref()
            .and_then(|s| s.get(index as usize).and_then(|sym| s.name(&sym)))
            .map(lossy)
            .unwrap_or_default();
        let shown = match super::undecorate(&symbol) {
            Some(u) => format!("{symbol} ({u})"),
            None => symbol.to_string(),
        };
        writeln!(
            out,
            " {offset:08X}  {name:<16}  {applied:>17}  {index:8X}  {shown}"
        )?;
    }
    Ok(())
}

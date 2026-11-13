//! MS-DOS (and, for now, NE and LE/LX) output. dumpbin refuses these files,
//! so this format is our own, in dumpbin's style.

use std::io::{self, Write};

use hexcavator_mz::{MzFile, NewHeaderKind};

use super::Options;

pub fn dump(out: &mut dyn Write, options: &Options, mz: &MzFile<'_>) -> io::Result<()> {
    let new_header = mz.new_header();
    let file_type = match new_header.map(|h| h.kind) {
        None => "MS-DOS EXECUTABLE",
        Some(NewHeaderKind::Ne) => "NE EXECUTABLE (16-bit Windows or OS/2)",
        Some(NewHeaderKind::Le) => "LE EXECUTABLE (VxD or DOS extender)",
        Some(NewHeaderKind::Lx) => "LX EXECUTABLE (OS/2)",
        Some(NewHeaderKind::Pe) => "PE EXECUTABLE",
    };
    writeln!(out, "File Type: {file_type}")?;
    if !options.headers {
        return Ok(());
    }

    let h = mz.header();
    let seg_off = |seg: u16, off: u16| format!("{seg:04X}:{off:04X}");
    writeln!(out, "\nDOS HEADER VALUES")?;
    writeln!(
        out,
        "{:>16} magic number",
        String::from_utf8_lossy(&h.magic)
    )?;
    writeln!(out, "{:16X} bytes on last page", h.bytes_on_last_page.get())?;
    writeln!(out, "{:16X} pages in file", h.pages.get())?;
    writeln!(out, "{:16X} relocations", h.relocation_count.get())?;
    writeln!(
        out,
        "{:16X} size of header in paragraphs",
        h.header_paragraphs.get()
    )?;
    writeln!(
        out,
        "{:16X} minimum extra paragraphs",
        h.min_extra_paragraphs.get()
    )?;
    writeln!(
        out,
        "{:16X} maximum extra paragraphs",
        h.max_extra_paragraphs.get()
    )?;
    writeln!(
        out,
        "{:>16} initial SS:SP",
        seg_off(h.initial_ss.get(), h.initial_sp.get())
    )?;
    writeln!(out, "{:16X} checksum", h.checksum.get())?;
    writeln!(
        out,
        "{:>16} initial CS:IP",
        seg_off(h.initial_cs.get(), h.initial_ip.get())
    )?;
    writeln!(
        out,
        "{:16X} file pointer to relocation table",
        h.relocation_table.get()
    )?;
    writeln!(out, "{:16X} overlay number", h.overlay.get())?;
    // In a plain DOS program, 0x1C..0x40 is usually code or relocations, not
    // header fields. A relocation table at 0x40 or later is the traditional
    // sign of a "new" executable.
    let has_extended = new_header.is_some() || h.relocation_table.get() >= 0x40;
    if let Some(x) = mz.extended_header().filter(|_| has_extended) {
        writeln!(out, "{:16X} OEM identifier", x.oem_id.get())?;
        writeln!(out, "{:16X} OEM information", x.oem_info.get())?;
        writeln!(out, "{:16X} file pointer to new header", x.new_header.get())?;
    }

    let module = mz.load_module();
    if module.is_empty() {
        writeln!(out, "{:16X} file pointer to load module", module.start)?;
    } else {
        writeln!(
            out,
            "{:16X} file pointer to load module ({:08X} to {:08X})",
            module.start,
            module.start,
            module.end - 1
        )?;
    }
    writeln!(out, "{:16X} size of load module", module.end - module.start)?;
    let file_size = mz.data().len() as u64;
    if mz.image_size() > file_size {
        writeln!(
            out,
            "                 (file is truncated: header declares {:X} bytes)",
            mz.image_size()
        )?;
    }

    if let Some(new_header) = new_header {
        writeln!(
            out,
            "\n  {} header at file offset {:X} is not decoded yet",
            new_header.kind.name(),
            new_header.offset
        )?;
    }
    Ok(())
}

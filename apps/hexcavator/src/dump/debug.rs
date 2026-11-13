//! The debug directory listing that `dumpbin /headers` prints after the
//! section that holds it.

use std::io::{self, Write};

use hexcavator_pe::consts::{debug_type, machine};
use hexcavator_pe::{CodeView, PeFile};

/// dumpbin's short name for each debug entry type.
fn type_name(kind: u32) -> Option<&'static str> {
    Some(match kind {
        debug_type::COFF => "coff",
        debug_type::CODEVIEW => "cv",
        debug_type::FPO => "fpo",
        debug_type::MISC => "misc",
        debug_type::EXCEPTION => "pdata",
        debug_type::FIXUP => "fixup",
        debug_type::OMAP_TO_SRC => "-> src",
        debug_type::OMAP_FROM_SRC => "src ->",
        debug_type::VC_FEATURE => "feat",
        debug_type::POGO => "coffgrp",
        debug_type::ILTCG => "iltcg",
        debug_type::MPX => "mpx",
        debug_type::REPRO => "repro",
        debug_type::EMBEDDED_PDB => "mpdb",
        debug_type::PDB_CHECKSUM => "pdbhash",
        debug_type::EX_DLLCHARACTERISTICS => "dllchar",
        _ => return None,
    })
}

fn guid(g: &[u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn pogo_kind(signature: u32) -> Option<&'static str> {
    Some(match &signature.to_be_bytes() {
        b"PGI\0" => "PGI",
        b"PGO\0" => "PGO",
        b"PGU\0" => "PGU",
        b"LTCG" => "LTCG",
        b"SPGO" => "SPGO",
        b"BBOP" => "BBOPT",
        _ => return None,
    })
}

pub fn directories(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    let entries: Vec<_> = file.debug_entries().collect();
    if entries.is_empty() {
        return Ok(());
    }
    writeln!(out, "\n  Debug Directories\n")?;
    writeln!(out, "        Time Type        Size      RVA  Pointer")?;
    writeln!(out, "    -------- ------- -------- -------- --------")?;
    for entry in &entries {
        let h = entry.header;
        let kind = match type_name(entry.kind()) {
            Some(name) => format!("{name:8}"),
            None => format!("({:4X})  ", entry.kind()),
        };
        write!(
            out,
            "    {:08X} {kind}{:8X} {:08X} {:8X}",
            h.time_date_stamp.get(),
            h.size_of_data.get(),
            h.address_of_raw_data.get(),
            h.pointer_to_raw_data.get()
        )?;
        if let Some(cv) = entry.codeview() {
            match cv {
                CodeView::Rsds { guid: g, age, path } => write!(
                    out,
                    "    Format: RSDS, {}, {age}, {}",
                    guid(&g),
                    String::from_utf8_lossy(path)
                )?,
                CodeView::Nb10 {
                    signature,
                    age,
                    path,
                    ..
                } => write!(
                    out,
                    "    Format: NB10, {signature:X}, {age}, {}",
                    String::from_utf8_lossy(path)
                )?,
                CodeView::Other { signature } => {
                    write!(out, "    Format: {}", String::from_utf8_lossy(&signature))?;
                }
            }
        } else if let Some(pogo) = entry.pogo() {
            if pogo.signature != 0 {
                write!(out, "    {:08X}", pogo.signature)?;
                if let Some(kind) = pogo_kind(pogo.signature) {
                    write!(out, " ({kind})")?;
                }
            }
        } else if let Some(counts) = entry.vc_feature() {
            const NAMES: [&str; 5] = ["Pre-VC++ 11.00", "C/C++", "/GS", "/sdl", "guardN"];
            write!(out, "    Counts:")?;
            for (i, name) in NAMES.iter().enumerate() {
                let sep = if i == 0 { "" } else { "," };
                match counts.get(i) {
                    Some(n) => write!(out, "{sep} {name}={}", n.get())?,
                    None => write!(out, "{sep} {name}=unreported")?,
                }
            }
        } else if type_name(entry.kind()).is_none() {
            // Unknown types show their first dword.
            if let Some(d) = entry.data.and_then(|d| d.get(..4)) {
                write!(out, "    {:08X}", u32::from_le_bytes(d.try_into().unwrap()))?;
            }
        } else if let Some(hash) = entry.repro_hash()
            && !hash.is_empty()
        {
            write!(out, "   ")?;
            for b in hash {
                write!(out, " {b:02X}")?;
            }
        }
        writeln!(out)?;
    }
    for entry in &entries {
        if let Some(flags) = entry.ex_dll_characteristics() {
            ex_dll_characteristics(out, file, flags)?;
        }
    }
    Ok(())
}

fn ex_dll_characteristics(out: &mut dyn Write, file: &PeFile<'_>, flags: u32) -> io::Result<()> {
    let forward_cfi = match file.machine() {
        machine::ARM64 | machine::ARM64EC | machine::ARM64X => "Branch Target Indentification",
        _ => "Indirect Branch Tracking",
    };
    let names: [(u32, &str); 8] = [
        (0x01, "CET compatible"),
        (0x02, "CET compatible strict mode"),
        (0x04, "CET set context IP validation relaxed mode"),
        (0x08, "CET dynamic code APIs allow in-proc callers"),
        (0x10, "CET reserved bit 1"),
        (0x20, "CET reserved bit 2"),
        (0x40, forward_cfi),
        (0x80, "Hotpatch compatible"),
    ];
    writeln!(out, "\n        {flags:08X} extended DLL characteristics")?;
    for (bit, name) in names {
        if flags & bit != 0 {
            writeln!(out, "                   {name}")?;
        }
    }
    Ok(())
}

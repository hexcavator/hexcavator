//! x64 exception handler data for `/unwindinfo`, which dumpbin decodes when
//! it knows (from the PDB) which handler a function uses:
//! `__CxxFrameHandler4`'s compressed C++ EH tables (FH4), the
//! `__C_specific_handler` scope table, and GS cookie data.

use std::io::{self, Write};

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::eh4::{Continuation4, Handler4, TryBlock4, UnwindEntry4};

/// Writes the data for `handler` (by name) at `data`.
pub fn handler_data(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    handler: &str,
    data: Rva,
) -> io::Result<()> {
    let r = Bytes { file };
    match handler {
        "__CxxFrameHandler4" => {
            if let Some(info) = r.u32(data.get()) {
                fh4(out, &r, info)?;
            }
        }
        "__GSHandlerCheck_EH4" => {
            if let Some(info) = r.u32(data.get()) {
                fh4(out, &r, info)?;
            }
            gs(out, &r, data.get() + 4)?;
        }
        "__C_specific_handler" => scope_table(out, &r, data.get())?,
        "__GSHandlerCheck_SEH" => {
            let count = r.u32(data.get()).unwrap_or(0);
            scope_table(out, &r, data.get())?;
            gs(out, &r, data.get() + 4 + 16 * count)?;
        }
        "__GSHandlerCheck" => gs(out, &r, data.get())?,
        _ => {}
    }
    Ok(())
}

struct Bytes<'a, 'data> {
    file: &'a PeFile<'data>,
}

impl Bytes<'_, '_> {
    fn bytes(&self, rva: u32, n: u32) -> Option<&[u8]> {
        self.file.bytes_at_rva(Rva(rva), n).ok()
    }

    fn u32(&self, rva: u32) -> Option<u32> {
        self.bytes(rva, 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }
}

/// `__CxxFrameHandler4` data (FH4) at `info`.
fn fh4(out: &mut dyn Write, r: &Bytes<'_, '_>, info: u32) -> io::Result<()> {
    writeln!(out, "    EH Handler Data (FH4): {info:08X}")?;
    let Some(fi) = r.file.func_info4(Rva(info)) else {
        return Ok(());
    };
    writeln!(out, "    Function Info:")?;
    if fi.is_catch() {
        writeln!(out, "      Catch funclet")?;
    }
    if fi.ehs() {
        writeln!(out, "      EHs flag set")?;
    }
    if fi.noexcept() {
        writeln!(out, "      NoExcept flag set")?;
    }
    if let Some(v) = fi.bbt_flags {
        writeln!(out, "      BBT Flags:                     {v:08X}")?;
    }
    if let Some(v) = fi.unwind_map {
        writeln!(out, "      RVA to Unwind Map:             {:08X}", v.get())?;
    }
    if let Some(v) = fi.try_map {
        writeln!(out, "      RVA to Try Block Map:          {:08X}", v.get())?;
    }
    let ip_map = fi.ip_map.get();
    if fi.is_separated() {
        writeln!(out, "      RVA to Separated Segments Map: {ip_map:08X}")?;
    } else {
        writeln!(out, "      RVA to IP to State Map:        {ip_map:08X}")?;
    }
    if let Some(v) = fi.frame_offset {
        writeln!(
            out,
            "      Disp of Func Frame wrt Establisher Frame: {v:08X}"
        )?;
    }

    if fi.is_separated() {
        let segments = r.file.segment_map4(fi.ip_map);
        let n = segments.as_ref().map_or(0, |t| t.entries.len());
        writeln!(out, "\n   Number of Segment Map Entries:    {n:08X}")?;
        writeln!(out, "    RVA to Segment              RVA to State Map")?;
        for s in segments.iter().flat_map(|t| &t.entries) {
            writeln!(
                out,
                "    RVA to Segment: {:08X}    RVA to State Map: {:08X}",
                s.segment.get(),
                s.ip_map.get()
            )?;
            ip_to_state(out, r, s.ip_map.get())?;
        }
    } else {
        ip_to_state(out, r, ip_map)?;
    }
    if let Some(map) = fi.unwind_map {
        unwind_map_fh4(out, r, map.get())?;
    }
    if let Some(map) = fi.try_map {
        try_blocks(out, r, map.get())?;
    }
    Ok(())
}

/// IPs are relative to the function (or segment) start, delta-encoded.
fn ip_to_state(out: &mut dyn Write, r: &Bytes<'_, '_>, map: u32) -> io::Result<()> {
    let table = r.file.ip_to_state4(Rva(map));
    let n = table.as_ref().map_or(0, |t| t.entries.len());
    writeln!(out, "\n    Number of IP Map Entries:      {n:08X}")?;
    writeln!(
        out,
        "    IP (relative to segment or function start) to State Map:"
    )?;
    writeln!(
        out,
        "            IP      State | Raw Data: IP Offset   State+1"
    )?;
    for e in table.iter().flat_map(|t| &t.entries) {
        writeln!(
            out,
            "      {:08X} {:10} | {:19X} {:9}",
            e.ip,
            i64::from(e.state_plus_one) - 1,
            e.delta,
            e.state_plus_one
        )?;
    }
    Ok(())
}

fn unwind_map_fh4(out: &mut dyn Write, r: &Bytes<'_, '_>, map: u32) -> io::Result<()> {
    let table = r.file.unwind_map4(Rva(map));
    let entries: &[UnwindEntry4] = table.as_ref().map_or(&[], |t| &t.entries);
    writeln!(out, "\n    Number of States: {}", entries.len())?;
    writeln!(out, "    Unwind Map:")?;
    writeln!(
        out,
        "      Current State  Next State | Raw: Offset   Next Offset | Action"
    )?;
    // Entries are found by their offsets from the start of the map.
    for (state, e) in entries.iter().enumerate() {
        let target = e.offset.wrapping_sub(e.next);
        let next_state = entries[..=state]
            .iter()
            .position(|p| p.offset == target)
            .map_or(-1, |i| i64::try_from(i).unwrap_or(-1));
        let rva = e.action.map_or(0, hexcavator_core::Rva::get);
        let object = e.object.unwrap_or(0);
        let action = match e.kind {
            0 => "No unwind state".to_string(),
            1 => format!(
                "Dtor with Object: RVA: {rva:08X} Frame offset for object pointer: {object:08X}"
            ),
            2 => format!(
                "Dtor with Object Pointer: RVA: {rva:08X} Frame offset for object pointer: {object:08X}"
            ),
            _ => format!("Dtor RVA: {rva:08X}"),
        };
        writeln!(
            out,
            "           {state:8}    {next_state:8} |    {:08X}     -{:08X} | {action}",
            e.offset, e.next
        )?;
    }
    Ok(())
}

fn try_blocks(out: &mut dyn Write, r: &Bytes<'_, '_>, map: u32) -> io::Result<()> {
    let table = r.file.try_map4(Rva(map));
    let blocks: &[TryBlock4] = table.as_ref().map_or(&[], |t| &t.entries);
    writeln!(
        out,
        "\n    Number of Try Blocks:          {:08X}",
        blocks.len()
    )?;
    for (i, b) in blocks.iter().enumerate() {
        writeln!(out, "    Try Block Map #{i}:")?;
        writeln!(
            out,
            "      Lowest Try State:                    {}",
            b.try_low
        )?;
        writeln!(
            out,
            "      Highest Try State:                   {}",
            b.try_high
        )?;
        writeln!(
            out,
            "      Highest State of Associated Catches: {}",
            b.catch_high
        )?;
        writeln!(
            out,
            "      RVA to Catch Handler Array:          {:08X}",
            b.handlers.get()
        )?;
        catch_handlers(out, r, b.handlers.get())?;
    }
    Ok(())
}

fn catch_handlers(out: &mut dyn Write, r: &Bytes<'_, '_>, map: u32) -> io::Result<()> {
    let table = r.file.handler_map4(Rva(map));
    let handlers: &[Handler4] = table.as_ref().map_or(&[], |t| &t.entries);
    writeln!(
        out,
        "\n      Number of Associated Catches:        {:08X}",
        handlers.len()
    )?;
    for (i, h) in handlers.iter().enumerate() {
        writeln!(out, "      Catch Handler #{i}:")?;
        if let Some(v) = h.adjectives {
            writeln!(
                out,
                "        Handler Type Adjectives:                {v:08X}"
            )?;
        }
        if let Some(v) = h.type_descriptor {
            writeln!(
                out,
                "        RVA to Type Descriptor:                 {:08X}",
                v.get()
            )?;
        }
        if let Some(v) = h.catch_object {
            writeln!(
                out,
                "        Frame offset of Catch Object:           {v:08X}"
            )?;
        }
        writeln!(
            out,
            "        RVA to Catch Handler:                   {:08X}",
            h.handler.get()
        )?;
        if h.reserved_continuation {
            writeln!(
                out,
                "        ERROR: handler.header.contAddr == FH4::HandlerTypeHeader::contType::Reserved"
            )?;
        }
        for (k, c) in h.continuations.iter().enumerate() {
            match c {
                Continuation4::Rva(v) => writeln!(
                    out,
                    "        RVA to Catch Continuation[{k}]:           {:08X}",
                    v.get()
                )?,
                Continuation4::Offset(v) => writeln!(
                    out,
                    "        Offset from Function Start to Catch Continuation[{k}]: {v:08X}"
                )?,
            }
        }
    }
    Ok(())
}

fn scope_table(out: &mut dyn Write, r: &Bytes<'_, '_>, at: u32) -> io::Result<()> {
    let n = r.u32(at).unwrap_or(0);
    writeln!(out, "\n    Count of scope table entries: {n}")?;
    writeln!(out, "\n      Begin    End      Handler  Target\n")?;
    for i in 0..n.min(0x1_0000) {
        let e = at + 4 + 16 * i;
        let f = |k: u32| r.u32(e + 4 * k).unwrap_or(0);
        writeln!(
            out,
            "      {:08X} {:08X} {:08X} {:08X}",
            f(0),
            f(1),
            f(2),
            f(3)
        )?;
    }
    Ok(())
}

/// `GS_HANDLER_DATA`: the cookie offset, with flags in its low bits, and
/// the alignment fields if it has them.
fn gs(out: &mut dyn Write, r: &Bytes<'_, '_>, at: u32) -> io::Result<()> {
    let Some(word) = r.u32(at) else {
        return Ok(());
    };
    write!(out, "    GS Unwind flags:")?;
    if word & 7 == 0 {
        write!(out, " None")?;
    }
    for (bit, name) in [(1, "EHandler"), (2, "UHandler"), (4, "HasAlignment")] {
        if word & bit != 0 {
            write!(out, " {name}")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "    Cookie Offset: {:08X}", word & !7)?;
    if word & 4 != 0 {
        writeln!(
            out,
            "    Aligned Base Offset: {:08X}",
            r.u32(at + 4).unwrap_or(0)
        )?;
        writeln!(out, "    Alignment: {:08X}", r.u32(at + 8).unwrap_or(0))?;
    }
    Ok(())
}

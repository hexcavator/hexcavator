//! A WebAssembly module, as llvm-readobj shows it (`--file-headers`,
//! `--sections`, `--relocations`, `--symbols`), following LLVM's
//! WasmDumper. A linked module's symbols are its names (the `name`
//! section's functions, globals, and data segments), else its exports, as
//! LLVM's WasmObjectFile makes them; an object's are its `linking`
//! section's symbol table, and its relocations its `reloc.*` sections'.

use hexcavator_wasm::{Module, SegmentOffset};

use super::{Parts, Printer};

const SECTION_TYPES: &[&str] = &[
    "CUSTOM",
    "TYPE",
    "IMPORT",
    "FUNCTION",
    "TABLE",
    "MEMORY",
    "GLOBAL",
    "EXPORT",
    "START",
    "ELEM",
    "CODE",
    "DATA",
    "DATACOUNT",
    "TAG",
];

pub fn dump(out: &mut String, file_name: &str, data: &[u8], parts: &Parts) -> Result<(), String> {
    let m = Module::parse(data).map_err(|e| e.to_string())?;
    let mut p = Printer::new(out);
    p.raw("");
    p.line("File", file_name);
    p.line("Format", "WASM");
    p.line("Arch", if m.is_memory64() { "wasm64" } else { "wasm32" });
    p.line(
        "AddressSize",
        if m.is_memory64() { "64bit" } else { "32bit" },
    );
    if parts.file_headers {
        p.line("Version", format_args!("0x{:X}", m.version));
    }
    if parts.sections {
        sections(&mut p, &m);
    }
    if parts.relocations {
        relocations(&mut p, &m);
    }
    if parts.symbols {
        symbols(&mut p, &m);
    }
    Ok(())
}

fn sections(p: &mut Printer<'_>, m: &Module<'_>) {
    p.open("Sections [");
    for s in m.sections() {
        p.open("Section {");
        p.enumerated(
            "Type",
            SECTION_TYPES.get(usize::from(s.id)).copied(),
            u64::from(s.id),
        );
        // (llvm-readobj's size: a custom section's after its name; its
        // offset: where the contents start, name and all.)
        let size = if s.id == hexcavator_wasm::SECTION_CUSTOM {
            s.contents_size - (s.data_offset - s.contents_offset)
        } else {
            s.contents_size
        };
        let offset = s.contents_offset;
        p.line("Size", size);
        p.line("Offset", offset);
        if s.id == hexcavator_wasm::SECTION_CUSTOM {
            p.line("Name", String::from_utf8_lossy(s.name));
        }
        if s.id == hexcavator_wasm::SECTION_MEMORY {
            p.open("Memories [");
            for (min, max) in memories(m, s) {
                p.open("Memory {");
                p.line("MinPages", min);
                // (LLVM prints the section's offset for the maximum.)
                if max.is_some() {
                    p.line("MaxPages", offset);
                }
                p.close("}");
            }
            p.close("]");
        }
        if s.id == hexcavator_wasm::SECTION_DATA {
            p.open("Segments [");
            let info = m.segment_info();
            for (i, seg) in m.data_segment_details().iter().enumerate() {
                p.open("Segment {");
                // (An object's segments have names: its linking
                // section's.)
                if let Some(n) = info.get(i) {
                    p.line("Name", String::from_utf8_lossy(n.name));
                }
                p.line("Size", seg.size);
                match seg.offset {
                    SegmentOffset::I32(v) => p.line("Offset", v),
                    SegmentOffset::I64(v) => p.line("Offset", v),
                    SegmentOffset::Global(g) => {
                        p.open("Offset [");
                        p.line("Global", g);
                        p.close("]");
                    }
                    SegmentOffset::Other | SegmentOffset::Passive => p.line("Offset", 0),
                }
                p.close("}");
            }
            p.close("]");
        }
        p.close("}");
    }
    p.close("]");
}

/// The memory section's limits: each memory's minimum, and maximum if it
/// has one.
fn memories(m: &Module<'_>, s: &hexcavator_wasm::Section<'_>) -> Vec<(u64, Option<u64>)> {
    let data = m.data();
    let (Ok(start), Ok(len)) = (
        usize::try_from(s.contents_offset),
        usize::try_from(s.contents_size),
    ) else {
        return Vec::new();
    };
    let Some(bytes) = data.get(start..start.saturating_add(len)) else {
        return Vec::new();
    };
    let mut at = 0usize;
    let mut uleb = || -> Option<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let b = *bytes.get(at)?;
            at += 1;
            v |= u64::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    };
    let mut out = Vec::new();
    let Some(count) = uleb() else { return out };
    for _ in 0..count.min(1 << 16) {
        let (Some(flags), Some(min)) = (uleb(), uleb()) else {
            break;
        };
        let max = if flags & 1 != 0 { uleb() } else { None };
        if flags & 1 != 0 && max.is_none() {
            break;
        }
        out.push((min, max));
    }
    out
}

/// An object's symbol, as LLVM's WasmObjectFile makes it: an undefined
/// one without a name of its own named for its import.
struct ObjectSymbol<'d> {
    name: &'d [u8],
    kind: u8,
    flags: u32,
    index: u32,
    data: Option<(u32, u64, u64)>,
    /// An undefined symbol's import: module, and name there.
    import: Option<(&'d [u8], &'d [u8])>,
}

/// An object's symbols, from its `linking` section's table.
fn object_symbols<'d>(m: &Module<'d>) -> Vec<ObjectSymbol<'d>> {
    let imports = m.imports();
    let sections = m.sections();
    m.linking_symbols()
        .into_iter()
        .map(|s| {
            // The import an undefined function's, global's, tag's, or
            // table's index names (imports come first in each space).
            let external = match s.kind {
                hexcavator_wasm::SYMBOL_FUNCTION => Some(0),
                hexcavator_wasm::SYMBOL_TABLE => Some(1),
                hexcavator_wasm::SYMBOL_GLOBAL => Some(3),
                hexcavator_wasm::SYMBOL_TAG => Some(4),
                _ => None,
            };
            let import = (s.flags & hexcavator_wasm::SYMBOL_UNDEFINED != 0)
                .then_some(external)
                .flatten()
                .and_then(|k| imports.iter().filter(|i| i.kind == k).nth(s.index as usize))
                .map(|i| (i.module, i.field));
            let name = match (s.name, s.kind) {
                (Some(n), _) => n,
                (None, hexcavator_wasm::SYMBOL_SECTION) => {
                    sections.get(s.index as usize).map_or(&b""[..], |x| x.name)
                }
                (None, _) => import.map_or(&b""[..], |i| i.1),
            };
            ObjectSymbol {
                name,
                kind: s.kind,
                flags: s.flags,
                index: s.index,
                data: s.data,
                import,
            }
        })
        .collect()
}

/// An object's relocations, by section: offset, type, and the symbol (a
/// type index's number), and the addend of those that have one.
fn relocations(p: &mut Printer<'_>, m: &Module<'_>) {
    p.open("Relocations [");
    let symbols = object_symbols(m);
    let sections = m.sections();
    for (target, relocs) in m.relocations() {
        let Some(section) = sections.get(target as usize) else {
            continue;
        };
        let name = if section.id == hexcavator_wasm::SECTION_CUSTOM {
            String::from_utf8_lossy(section.name).into_owned()
        } else {
            SECTION_TYPES
                .get(usize::from(section.id))
                .copied()
                .unwrap_or("")
                .to_string()
        };
        p.open(&format!("Section ({}) {name} {{", target + 1));
        for r in relocs {
            let kind = hexcavator_wasm::relocation_name(r.kind).unwrap_or("Unknown");
            // (A type index names a type, not a symbol.)
            let what = if r.kind == 6 {
                r.index.to_string()
            } else {
                symbols.get(r.index as usize).map_or_else(
                    || r.index.to_string(),
                    |s| String::from_utf8_lossy(s.name).into_owned(),
                )
            };
            let mut line = format!("0x{:X} {kind} {what}", r.offset);
            if let Some(a) = r.addend {
                line.push_str(&format!(" {a}"));
            }
            p.raw(&line);
        }
        p.close("}");
    }
    p.close("]");
}

const FLAGS: &[(&str, u64)] = &[
    ("BINDING_WEAK", 0x1),
    ("BINDING_LOCAL", 0x2),
    ("VISIBILITY_HIDDEN", 0x4),
    ("UNDEFINED", 0x10),
    ("EXPORTED", 0x20),
    ("EXPLICIT_NAME", 0x40),
    ("NO_STRIP", 0x80),
];

/// A linked module's symbols, as LLVM makes them: from its `name`
/// section if it has one, else from its exports.
fn symbols(p: &mut Printer<'_>, m: &Module<'_>) {
    p.open("Symbols [");
    if m.is_object() {
        for s in object_symbols(m) {
            p.open("Symbol {");
            p.line("Name", String::from_utf8_lossy(s.name));
            p.line(
                "Type",
                match s.kind {
                    hexcavator_wasm::SYMBOL_FUNCTION => "FUNCTION (0x0)",
                    hexcavator_wasm::SYMBOL_DATA => "DATA (0x1)",
                    hexcavator_wasm::SYMBOL_GLOBAL => "GLOBAL (0x2)",
                    hexcavator_wasm::SYMBOL_SECTION => "SECTION (0x3)",
                    hexcavator_wasm::SYMBOL_TAG => "TAG (0x4)",
                    _ => "TABLE (0x5)",
                },
            );
            p.flags("Flags", u64::from(s.flags), FLAGS);
            let undefined = s.flags & hexcavator_wasm::SYMBOL_UNDEFINED != 0;
            if undefined && let Some((module, field)) = s.import {
                if field != s.name {
                    p.line("ImportName", String::from_utf8_lossy(field));
                }
                p.line("ImportModule", String::from_utf8_lossy(module));
            }
            if s.kind != hexcavator_wasm::SYMBOL_DATA {
                p.line("ElementIndex", format_args!("0x{:X}", s.index));
            } else if let Some((segment, offset, size)) = s.data {
                p.line("Offset", format_args!("0x{offset:X}"));
                p.line("Segment", format_args!("0x{segment:X}"));
                p.line("Size", format_args!("0x{size:X}"));
            }
            p.close("}");
        }
        p.close("]");
        return;
    }
    let imported = m.imported();
    let exports = m.exports();
    let names = m.custom(b"name").is_some();
    let segments = m.data_segment_details();
    // (Function names, then globals', then data segments', each in the
    // section's order.)
    let mut any = false;
    for kind in [
        hexcavator_wasm::NAME_FUNCTION,
        hexcavator_wasm::NAME_GLOBAL,
        hexcavator_wasm::NAME_DATA_SEGMENT,
    ] {
        for n in m.names(kind) {
            any = true;
            p.open("Symbol {");
            p.line("Name", String::from_utf8_lossy(n.name));
            let flags: u64 = match kind {
                hexcavator_wasm::NAME_FUNCTION if n.index < imported[0] => 0x10,
                hexcavator_wasm::NAME_FUNCTION
                    if exports.iter().any(|e| e.kind == 0 && e.index == n.index) =>
                {
                    0
                }
                hexcavator_wasm::NAME_FUNCTION => 0x2,
                hexcavator_wasm::NAME_GLOBAL if n.index < imported[3] => 0x10,
                hexcavator_wasm::NAME_GLOBAL => 0,
                _ => 0x2,
            };
            match kind {
                hexcavator_wasm::NAME_FUNCTION => p.line("Type", "FUNCTION (0x0)"),
                hexcavator_wasm::NAME_GLOBAL => p.line("Type", "GLOBAL (0x2)"),
                _ => p.line("Type", "DATA (0x1)"),
            }
            p.flags("Flags", flags, FLAGS);
            if kind == hexcavator_wasm::NAME_DATA_SEGMENT {
                p.line("Offset", "0x0");
                p.line("Segment", format_args!("0x{:X}", n.index));
                p.line(
                    "Size",
                    format_args!(
                        "0x{:X}",
                        segments.get(n.index as usize).map_or(0, |s| s.size)
                    ),
                );
            } else {
                p.line("ElementIndex", format_args!("0x{:X}", n.index));
            }
            p.close("}");
        }
    }
    if !any && !names {
        for e in &exports {
            let kind = match e.kind {
                0 => "FUNCTION (0x0)",
                1 => "TABLE (0x5)",
                3 => "GLOBAL (0x2)",
                4 => "TAG (0x4)",
                _ => continue,
            };
            p.open("Symbol {");
            p.line("Name", String::from_utf8_lossy(e.name));
            p.line("Type", kind);
            p.flags("Flags", 0, FLAGS);
            p.line("ElementIndex", format_args!("0x{:X}", e.index));
            p.close("}");
        }
    }
    p.close("]");
}

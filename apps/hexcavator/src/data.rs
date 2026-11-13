//! `hexc data`: a datum of an image, its bytes and, from its debug information, its
//! value read as its type: each member, element, and pointer (named by
//! the symbol it points into), and the slots the image's base relocations
//! say hold addresses.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use hexcavator_debuginfo::value::{self, Value};
use hexcavator_program::data::AddressNames;
use serde_json::{Value as Json, json};

pub const USAGE: &str = "\
usage: hexc data [options] <image> <name>

A datum of an image (a variable, a string, a table): its bytes, and its
value read as its type (from its PDB or DWARF): each base, member
(bitfields by bit), element, and pointer, with the symbol each pointer
points into; and the slots the loader writes addresses into (base
relocations, dynamic relocations, fixups).

options:
  -pdb <path>   its debug information: a PDB, or a file with its DWARF
                (or -debug; default: its own, or the one it names)
  -max <bytes>  the most of it to read (default 1M)
  -json         as JSON";

/// How much of a datum to read, at most.
const DEFAULT_MAX: u64 = 1 << 20;

struct Options {
    image: PathBuf,
    name: String,
    pdb: Option<PathBuf>,
    max: u64,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut pdb = None;
    let mut max = DEFAULT_MAX;
    let mut json = false;
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.strip_prefix('-') {
            Some("pdb" | "debug") => {
                pdb = Some(PathBuf::from(it.next().ok_or("-pdb needs a path")?));
            }
            Some("max") => {
                let v = it.next().ok_or("-max needs a size")?;
                max = match hexcavator_size::rollup::Threshold::parse(v) {
                    Some(hexcavator_size::rollup::Threshold::Bytes(b)) if b > 0 => b as u64,
                    _ => return Err(format!("-max: a size (4096, 64k, 1M), not '{v}'")),
                };
            }
            Some("json") => json = true,
            Some("help" | "h" | "?") => return Err(String::new()),
            Some(o) if !o.is_empty() => return Err(format!("unknown option -{o}")),
            _ => positional.push(a.clone()),
        }
    }
    let [image, name] = &positional[..] else {
        return Err("an image and a name, please".into());
    };
    Ok(Options {
        image: PathBuf::from(image),
        name: name.clone(),
        pdb,
        max,
        json,
    })
}

pub fn run(args: &[String]) -> ExitCode {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                ereport!("hexc data: {e}\n");
            }
            ereport!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match report(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc data: {e}");
            ExitCode::FAILURE
        }
    }
}

fn report(o: &Options) -> Result<String, String> {
    let opened = hexcavator_program::Opened::open(&o.image, o.pdb.as_deref())?;
    let program = opened.program()?;
    let d = program.datum(&o.name, o.max)?;
    let names = program.address_names()?;
    let read = d.bytes.len() as u64;
    if o.json {
        let mut j = json!({
            "name": d.name,
            "kind": format!("{:?}", d.kind).to_lowercase(),
            "rva": format!("{:#x}", d.rva),
            "address": format!("{:#x}", d.address),
            "section": d.section,
            "size": d.size,
            "fileSize": d.file_size,
            "read": read,
            "bytes": d.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "pointers": d.pointers.iter().map(|p| json!({
                "offset": p.offset,
                "size": p.size,
                "target": format!("{:#x}", p.target),
                "name": p.name,
            })).collect::<Vec<_>>(),
            "value": Json::Null,
        });
        if let Some(v) = &d.value {
            j["value"] = value_json(v, &names);
        }
        let mut s = serde_json::to_string_pretty(&j).unwrap_or_default();
        s.push('\n');
        return Ok(s);
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}  ({} bytes{} at {:#x}, {})",
        d.name,
        d.size,
        if d.file_size < d.size {
            format!(", {} in the file", d.file_size)
        } else {
            String::new()
        },
        d.address,
        d.section
    );
    match &d.value {
        Some(v) => {
            out.push('\n');
            value_text(v, &names, 0, &mut out);
        }
        None => out.push_str("(no type: its bytes only)\n"),
    }
    out.push('\n');
    hex_text(&d.bytes, d.address, &mut out);
    if !d.pointers.is_empty() {
        let _ = writeln!(out, "\npointers (base relocations):");
        for p in &d.pointers {
            let _ = writeln!(
                out,
                "  +{:<6x} {:#x}  {}",
                p.offset,
                p.target,
                p.name.as_deref().unwrap_or("")
            );
        }
    }
    if read < d.size {
        let _ = writeln!(
            out,
            "\n(the first {read} of {} bytes; -max reads more)",
            d.size
        );
    }
    Ok(out)
}

fn value_json(v: &Value, names: &AddressNames) -> Json {
    let mut j = json!({
        "name": v.name,
        "type": v.type_name,
        "kind": v.kind.label(),
        "offset": v.offset,
        "size": v.size,
        "text": v.text,
    });
    if let Some((pos, len)) = v.bits {
        j["bits"] = json!([pos, len]);
    }
    if let Some(p) = v.pointer {
        j["target"] = Json::from(names.name(p));
    }
    if !v.children.is_empty() {
        j["children"] = Json::Array(v.children.iter().map(|c| value_json(c, names)).collect());
    }
    if v.elided > 0 {
        j["elided"] = Json::from(v.elided);
    }
    j
}

fn value_text(v: &Value, names: &AddressNames, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    let label = if v.kind == value::ValueKind::Padding {
        "(padding)".to_string()
    } else if v.name.is_empty() {
        v.type_name.clone()
    } else {
        v.name.clone()
    };
    let mut text = v.text.clone();
    if let Some(p) = v.pointer
        && let Some(n) = names.name(p)
    {
        text = format!("{text} {n}");
    }
    let bits = v.bits.map_or(String::new(), |(p, l)| format!(":{l}@{p}"));
    let ty = if v.name.is_empty() || v.type_name.is_empty() {
        String::new()
    } else {
        format!("  ({})", v.type_name)
    };
    let _ = writeln!(
        out,
        "{:>6x}  {indent}{label}{bits}{}{ty}",
        v.offset,
        if text.is_empty() {
            String::new()
        } else {
            format!(" = {text}")
        }
    );
    for c in &v.children {
        value_text(c, names, depth + 1, out);
    }
    if v.elided > 0 {
        let _ = writeln!(out, "{:>6}  {indent}  … {} more", "", v.elided);
    }
}

/// As a debugger shows memory: 16 bytes a line, their address, and as text.
fn hex_text(bytes: &[u8], address: u64, out: &mut String) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let text: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let (a, b) = hex.split_at(hex.len().min(8));
        let _ = writeln!(
            out,
            "{:016x}  {:<23}  {:<23}  {text}",
            address + i as u64 * 16,
            a.join(" "),
            b.join(" ")
        );
    }
}

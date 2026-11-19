//! `hexc relocations`: what the loader patches when it loads an image,
//! and what that costs (see `hexcavator_size::relocations`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_size::relocations::{
    Relocations, image_symbols, merge_symbols, pointer_tables, relocations,
};
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc relocations [options] <image>

What the loader patches when it loads an image (ELF's dynamic relocations,
packed RELR ones too; PE's base relocations; Mach-O's rebases and binds),
and what each costs: its share of the table it's in. By table, by type,
by the section and the data each patches (the data from the debug
information's symbols, or else the image's own symbol table), and by
what each points to.

options:
  -pdb <path>   its debug information: a PDB, or a file with its DWARF
                (or -debug; default: its own, or the one it names)
  -n <n>        rows of each list (default 20; 0: all)
  -list         every relocation: where, its type, and what it points to
  -json         as JSON";

struct Args {
    image: Option<PathBuf>,
    pdb: Option<PathBuf>,
    rows: usize,
    list: bool,
    json: bool,
}

pub fn run(args: &[String]) -> ExitCode {
    let mut a = Args {
        image: None,
        pdb: None,
        rows: 20,
        list: false,
        json: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-pdb" | "/pdb" | "-debug" | "/debug" => match it.next() {
                Some(p) => a.pdb = Some(PathBuf::from(p)),
                None => return usage("-pdb needs a path"),
            },
            "-n" | "/n" => match it.next().and_then(|n| n.parse::<usize>().ok()) {
                Some(0) => a.rows = usize::MAX,
                Some(n) => a.rows = n,
                None => return usage("-n needs a number"),
            },
            "-list" | "/list" => a.list = true,
            "-json" | "/json" => a.json = true,
            s if a.image.is_none() => a.image = Some(PathBuf::from(s)),
            s => return usage(&format!("unexpected argument '{s}'")),
        }
    }
    let Some(image) = a.image.clone() else {
        return usage("no image given");
    };
    match report(&image, &a) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc relocations: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage(message: &str) -> ExitCode {
    ereport!("hexc relocations: {message}\n\n{USAGE}");
    ExitCode::from(2)
}

/// An image's relocations, summarized.
pub(crate) struct Summary {
    pub relocs: Relocations,
    /// (start, end, name) of the data and code relocations patch and point
    /// to, by start; and whether they're the debug information's.
    pub symbols: Vec<(u64, u64, String)>,
    pub from_debug: bool,
    /// The sections: (start, end, name).
    pub sections: Vec<(u64, u64, String)>,
}

fn report(path: &Path, a: &Args) -> Result<String, String> {
    let show = |p: &Path| p.display().to_string();
    let map = hexcavator_mmap::Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
    let image = hexcavator_image::Image::parse(&map).map_err(|e| format!("{}: {e}", show(path)))?;
    // The debug information's symbols, if any is found; else the image's.
    let debug_symbols = match hexcavator_program::Opened::open(path, a.pdb.as_deref()) {
        Ok(opened) => {
            let program = opened.program()?;
            let syms = program.symbols()?;
            let mut v: Vec<(u64, u64, String)> = syms
                .iter()
                .filter(|s| s.size.vm > 0)
                .map(|s| (s.addr, s.addr + s.size.vm, s.name.clone()))
                .collect();
            v.sort_by_key(|s| s.0);
            // (And the debug file's symbol table, a stripped image's
            // statics among them.)
            Some(merge_symbols(v, debug_file_symbols(&program.debug)))
        }
        Err(hexcavator_program::Error::NoDebug { .. }) if a.pdb.is_none() => None,
        Err(e) => return Err(e.to_string()),
    };
    let s = summarize(&image, debug_symbols);
    Ok(if a.json {
        let mut v = as_json(&s, a.rows);
        if a.list {
            v["list"] = list_json(&s);
        }
        format!("{}\n", serde_json::to_string_pretty(&v).unwrap_or_default())
    } else {
        as_text(&s, a.rows, a.list)
    })
}

/// The relocations of `image`, with the symbols to name where they are
/// (`debug_symbols`, else the image's own).
pub(crate) fn summarize(
    image: &hexcavator_image::Image<'_>,
    debug_symbols: Option<Vec<(u64, u64, String)>>,
) -> Summary {
    let relocs = relocations(image);
    let from_debug = debug_symbols.is_some();
    // (The image's own where the debug information has none.)
    let own = demangled(image_symbols(image), image);
    let symbols = match debug_symbols {
        Some(d) => merge_symbols(d, own),
        None => own,
    };
    let mut sections: Vec<(u64, u64, String)> = image
        .sections()
        .iter()
        .filter(|s| s.vm_size > 0)
        .map(|s| {
            (
                s.addr,
                s.addr + s.vm_size,
                String::from_utf8_lossy(s.name).into_owned(),
            )
        })
        .collect();
    sections.sort_by_key(|s| s.0);
    Summary {
        relocs,
        symbols,
        from_debug,
        sections,
    }
}

/// The symbol table of the file the DWARF is in (a separate debug file's,
/// which keeps what stripping the image removed), demangled.
pub(crate) fn debug_file_symbols(
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
) -> Vec<(u64, u64, String)> {
    let Some(data) = debug
        .dwarf()
        .map(hexcavator_debuginfo::dwarf_backend::DwarfInfo::file_data)
    else {
        return Vec::new();
    };
    match hexcavator_image::Image::parse(data) {
        Ok(file) if file.elf().is_some() => demangled(image_symbols(&file), &file),
        _ => Vec::new(),
    }
}

/// The image's own symbols' names, demangled (Itanium's; Mach-O's less
/// their `_`).
pub(crate) fn demangled(
    mut symbols: Vec<(u64, u64, String)>,
    image: &hexcavator_image::Image<'_>,
) -> Vec<(u64, u64, String)> {
    let macho = image.macho().is_some();
    let mut d = hexcavator_demangle::itanium::Demangler::new();
    let mut out = String::new();
    for s in &mut symbols {
        let raw = if macho {
            s.2.strip_prefix('_').unwrap_or(&s.2)
        } else {
            &s.2
        };
        out.clear();
        if d.demangle_into(raw, &mut out) {
            s.2.clone_from(&out);
        } else if macho {
            s.2 = raw.to_string();
        }
    }
    symbols
}

/// A symbol's name demangled (Itanium's, with or without Mach-O's `_`), or
/// as it is.
fn demangle(name: &str) -> String {
    let mut out = String::new();
    let mut d = hexcavator_demangle::itanium::Demangler::new();
    if d.demangle_into(name, &mut out) {
        return out;
    }
    out.clear();
    if let Some(n) = name.strip_prefix('_')
        && d.demangle_into(n, &mut out)
    {
        return out;
    }
    name.to_string()
}

/// The entry of `ranges` ((start, end, name), by start) holding `at`.
fn within(ranges: &[(u64, u64, String)], at: u64) -> Option<&str> {
    hexcavator_size::relocations::containing(ranges, at).map(|i| ranges[i].2.as_str())
}

/// Bytes (a sum of shares of tables), rounded to whole ones.
#[allow(clippy::cast_possible_truncation)] // (No more than the image's size.)
fn whole(b: f64) -> u64 {
    b.round().max(0.0) as u64
}

/// A breakdown: (name, count, bytes), largest first.
type Rows = Vec<(String, u64, f64)>;

fn breakdown(s: &Summary, key: impl Fn(usize) -> Option<String>) -> Rows {
    let mut by: std::collections::HashMap<String, (u64, f64)> = std::collections::HashMap::new();
    for (i, r) in s.relocs.list.iter().enumerate() {
        let k = key(i).unwrap_or_else(|| "(none)".to_string());
        let e = by.entry(k).or_default();
        e.0 += 1;
        e.1 += s.relocs.share(r);
    }
    let mut rows: Rows = by.into_iter().map(|(k, (n, b))| (k, n, b)).collect();
    rows.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    rows
}

/// The breakdowns: by type, by section, by the data it patches, and by
/// what it points to.
fn breakdowns(s: &Summary) -> [(&'static str, Rows); 4] {
    let list = &s.relocs.list;
    [
        ("type", breakdown(s, |i| Some(list[i].kind.clone()))),
        (
            "section",
            breakdown(s, |i| within(&s.sections, list[i].addr).map(str::to_string)),
        ),
        (
            "symbol",
            breakdown(s, |i| within(&s.symbols, list[i].addr).map(str::to_string)),
        ),
        ("target", breakdown(s, |i| target_name(s, i))),
    ]
}

/// What relocation `i` points to: the symbol it binds, or the symbol (or
/// else section) its target is in.
fn target_name(s: &Summary, i: usize) -> Option<String> {
    let r = &s.relocs.list[i];
    if let Some(sym) = &r.symbol {
        return Some(demangle(sym));
    }
    let t = r.target?;
    within(&s.symbols, t)
        .or_else(|| within(&s.sections, t))
        .map(str::to_string)
}

fn as_text(s: &Summary, rows: usize, list: bool) -> String {
    let r = &s.relocs;
    let mut out = String::new();
    if r.list.is_empty() {
        out.push_str("No relocations: the loader patches nothing.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "{} relocations, {} bytes in {} table{}:",
        r.list.len(),
        r.total(),
        r.tables.len(),
        if r.tables.len() == 1 { "" } else { "s" }
    );
    let _ = writeln!(
        out,
        "  {:>12}  {:>9}  {:>9}  table",
        "bytes", "entries", "each"
    );
    for t in &r.tables {
        let each = if t.entries == 0 {
            0.0
        } else {
            t.size as f64 / t.entries as f64
        };
        let _ = writeln!(
            out,
            "  {:>12}  {:>9}  {:>9.2}  {}",
            t.size, t.entries, each, t.name
        );
    }
    for (what, rows_of) in breakdowns(s) {
        let title = match what {
            "type" => "By type",
            "section" => "By the section each patches",
            "symbol" if s.from_debug => "By the data (or code) each patches",
            "symbol" => "By the data (or code) each patches (the image's symbol table)",
            _ => "By what each points to",
        };
        let _ = writeln!(out, "\n{title}:");
        let _ = writeln!(out, "  {:>12}  {:>9}  name", "bytes", "count");
        for (name, n, b) in rows_of.iter().take(rows) {
            let _ = writeln!(out, "  {b:>12.0}  {n:>9}  {name}");
        }
        if rows_of.len() > rows {
            let _ = writeln!(out, "  ({} more)", rows_of.len() - rows);
        }
    }
    if list {
        let _ = writeln!(out, "\nEvery relocation:");
        for (i, x) in r.list.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {:#012x}  {:<24}  {}{}",
                x.addr,
                x.kind,
                x.target.map_or_else(String::new, |t| format!("{t:#x} ")),
                target_name(s, i).unwrap_or_default()
            );
        }
    }
    out
}

pub(crate) fn as_json(s: &Summary, rows: usize) -> Value {
    let r = &s.relocs;
    let rows_json = |rs: &Rows| -> Value {
        Value::Array(
            rs.iter()
                .take(rows)
                .map(|(name, n, b)| json!({"name": name, "count": n, "bytes": whole(*b)}))
                .collect(),
        )
    };
    let [types, sections, symbols, targets] = breakdowns(s);
    json!({
        "count": r.list.len(),
        "bytes": r.total(),
        "word": r.word,
        "tables": r.tables.iter().map(|t| json!({"name": t.name, "size": t.size, "entries": t.entries})).collect::<Vec<_>>(),
        "symbolsFrom": if s.from_debug { "debug" } else { "image" },
        "types": rows_json(&types.1),
        "sections": rows_json(&sections.1),
        "symbols": rows_json(&symbols.1),
        "targets": rows_json(&targets.1),
        // The data whose pointers offsets could replace.
        "pointerTables": pointer_tables(r, &s.symbols, 2)
            .iter()
            .take(rows)
            .map(|t| json!({"name": t.name, "pointers": t.pointers, "relocationBytes": whole(t.relocations), "narrowerBytes": t.narrower}))
            .collect::<Vec<_>>(),
    })
}

fn list_json(s: &Summary) -> Value {
    Value::Array(
        s.relocs
            .list
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({
                    "addr": r.addr,
                    "type": r.kind,
                    "target": r.target,
                    "symbol": r.symbol,
                    "relative": r.relative,
                    "in": within(&s.symbols, r.addr),
                    "to": target_name(s, i),
                })
            })
            .collect(),
    )
}

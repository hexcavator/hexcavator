//! `hexc inlines` and `hexc sourcefiles`: an image's code by the
//! functions inlined into it, and by the source files (and lines) it came
//! from, from its debug information (a PDB, or DWARF).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_debuginfo::{DebugInfo, InlineSite, SourceLines, exclusive_sizes};
use hexcavator_size::symbols::{Symbol, SymbolKind};
use serde_json::{Value, json};

pub const INLINES_USAGE: &str = "\
usage: hexc inlines [options] <image>

The functions inlined into an image's code (from its PDB or DWARF), by the bytes
their inlined copies take: each with how many copies there are and how
many functions they are in. A copy's bytes are its own code, not that of
functions inlined into it, and a function folded with others (identical
code folding) counts once.

options:
  -pdb <path>       its debug information: a PDB, or a file with its DWARF
                    (or -debug; default: its own, or the one it names)
  -inlinee <name>   one inlined function's copies, by the function each is in
                    (its name, or a regular expression that matches just one)
  -n <n>            rows to list (default 20; 0: all)
  -json             as JSON";

pub const SOURCEFILES_USAGE: &str = "\
usage: hexc sourcefiles [options] <image>

An image's code by the source files it came from (from its debug
information's line tables: a PDB's, or DWARF's): headers too, for the functions defined in them that weren't
inlined (inlined code counts where it was inlined).

options:
  -pdb <path>     its debug information: a PDB, or a file with its DWARF
                  (or -debug; default: its own, or the one it names)
  -file <name>    one file's code, by line (its path, or a regular expression
                  that matches just one)
  -n <n>          rows to list (default 20; 0: all)
  -json           as JSON";

struct Options {
    image: PathBuf,
    pdb: Option<PathBuf>,
    one: Option<String>,
    rows: usize,
    json: bool,
}

fn parse(args: &[String], one: &str) -> Result<Options, String> {
    let mut o = Options {
        image: PathBuf::new(),
        pdb: None,
        one: None,
        rows: 20,
        json: false,
    };
    let mut image = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("-{name} needs a value"))
        };
        match a.strip_prefix('-').or_else(|| a.strip_prefix('/')) {
            Some("pdb" | "debug") => o.pdb = Some(value("pdb")?.into()),
            Some(x) if !one.is_empty() && x == one => o.one = Some(value(one)?),
            Some("n") => {
                o.rows = value("n")?
                    .parse()
                    .map_err(|_| "-n needs a number".to_string())?;
            }
            Some("json") => o.json = true,
            Some(other) if !other.is_empty() && image.is_none() && !Path::new(a).exists() => {
                return Err(format!("unknown option '{other}'"));
            }
            _ if image.is_none() => image = Some(PathBuf::from(a)),
            _ => return Err(format!("unexpected argument '{a}'")),
        }
    }
    o.image = image.ok_or("no image given")?;
    Ok(o)
}

fn run(
    args: &[String],
    command: &str,
    usage: &str,
    one: &str,
    f: fn(&Options) -> Result<String, String>,
) -> ExitCode {
    if args.is_empty() {
        ereport!("{usage}");
        return ExitCode::from(2);
    }
    let o = match parse(args, one) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc {command}: {e}\n\n{usage}");
            return ExitCode::from(2);
        }
    };
    match f(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc {command}: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_inlines(args: &[String]) -> ExitCode {
    run(args, "inlines", INLINES_USAGE, "inlinee", inlines)
}

pub fn run_sourcefiles(args: &[String]) -> ExitCode {
    run(args, "sourcefiles", SOURCEFILES_USAGE, "file", sourcefiles)
}

/// Runs `f` with the debug information of the image at `path` (and its
/// symbols, if `with_symbols`).
fn with_debug<R>(
    path: &Path,
    pdb: Option<&Path>,
    with_symbols: bool,
    f: impl FnOnce(&DebugInfo<'_>, &[Symbol]) -> Result<R, String>,
) -> Result<R, String> {
    let opened = hexcavator_program::Opened::open(path, pdb)?;
    let program = opened.program()?;
    let syms = if with_symbols {
        program.symbols()?
    } else {
        &[]
    };
    f(&program.debug, syms)
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

/// The one of `names` that `name` names: exactly, or by a regular
/// expression that matches just one.
fn pick<'a>(
    names: impl Iterator<Item = &'a str> + Clone,
    name: &str,
    what: &str,
) -> Result<&'a str, String> {
    if let Some(n) = names.clone().find(|n| *n == name) {
        return Ok(n);
    }
    let re = regex::Regex::new(name)
        .map_err(|e| format!("no {what} '{name}', and not a regular expression: {e}"))?;
    let mut found: Vec<&str> = names.filter(|n| re.is_match(n)).collect();
    found.sort_unstable();
    found.dedup();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("no {what} '{name}'")),
        many => Err(format!(
            "'{name}' matches {} {what}s ({}{}); give one exactly",
            many.len(),
            many.iter().take(5).copied().collect::<Vec<_>>().join(", "),
            if many.len() > 5 { ", ..." } else { "" }
        )),
    }
}

/// Per inlinee: its sites' total bytes, and how many sites and functions.
struct Inlinee<'a> {
    name: &'a str,
    bytes: u64,
    sites: usize,
    functions: usize,
}

fn by_inlinee<'a>(sites: &[(InlineSite, u64)], names: &'a [String]) -> Vec<Inlinee<'a>> {
    let mut map: HashMap<&str, (u64, usize, Vec<u64>)> = HashMap::new();
    for (s, own) in sites {
        let e = map.entry(names[s.inlinee as usize].as_str()).or_default();
        e.0 += own;
        e.1 += 1;
        e.2.push(s.function);
    }
    let mut out: Vec<Inlinee<'_>> = map
        .into_iter()
        .map(|(name, (bytes, sites, mut fns))| {
            fns.sort_unstable();
            fns.dedup();
            Inlinee {
                name,
                bytes,
                sites,
                functions: fns.len(),
            }
        })
        .collect();
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(b.name)));
    out
}

/// A function's name by its address, from the symbols.
fn function_names(syms: &[Symbol]) -> HashMap<u64, &str> {
    let mut out = HashMap::new();
    for s in syms
        .iter()
        .filter(|s| matches!(s.kind, SymbolKind::Function | SymbolKind::PrimaryBlock))
    {
        out.entry(s.addr).or_insert(s.name.as_str());
    }
    out
}

fn inlines(o: &Options) -> Result<String, String> {
    with_debug(
        &o.image,
        o.pdb.as_deref(),
        o.one.is_some(),
        |debug, syms| {
            let found = debug.inline_sites().map_err(|e| e.to_string())?;
            let names = found.inlinees;
            let sites = exclusive_sizes(found.sites);
            let all = by_inlinee(&sites, &names);
            let take = |len: usize| if o.rows == 0 { len } else { o.rows.min(len) };
            if let Some(name) = &o.one {
                let name = pick(all.iter().map(|i| i.name), name, "inlined function")?;
                let functions = function_names(syms);
                let mut per: HashMap<u64, (u64, usize)> = HashMap::new();
                for (s, own) in sites.iter().filter(|s| names[s.0.inlinee as usize] == name) {
                    let e = per.entry(s.function).or_default();
                    e.0 += own;
                    e.1 += 1;
                }
                let mut rows: Vec<(String, u64, usize)> = per
                    .into_iter()
                    .map(|(f, (b, n))| {
                        (
                            functions
                                .get(&f)
                                .map_or_else(|| format!("{f:#x}"), |n| (*n).to_string()),
                            b,
                            n,
                        )
                    })
                    .collect();
                rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let total: u64 = rows.iter().map(|r| r.1).sum();
                if o.json {
                    return Ok(pretty(&json!({
                        "inlinee": name,
                        "bytes": total,
                        "functions": rows[..take(rows.len())].iter().map(|(f, b, n)| json!({"function": f, "bytes": b, "copies": n})).collect::<Vec<_>>(),
                    })));
                }
                let mut out = String::new();
                let _ = writeln!(
                    out,
                    "{name}: {total} bytes inlined into {} function{}, most first:",
                    rows.len(),
                    if rows.len() == 1 { "" } else { "s" }
                );
                let _ = writeln!(out, "  {:>8}  {:>6}  function", "bytes", "copies");
                for (f, b, n) in &rows[..take(rows.len())] {
                    let _ = writeln!(out, "  {b:>8}  {n:>6}  {f}");
                }
                if take(rows.len()) < rows.len() {
                    let _ = writeln!(
                        out,
                        "  ({} more; -n 0 lists all)",
                        rows.len() - take(rows.len())
                    );
                }
                return Ok(out);
            }
            let bytes: u64 = all.iter().map(|i| i.bytes).sum();
            if o.json {
                return Ok(pretty(&json!({
                    "sites": sites.len(),
                    "inlinees": all.len(),
                    "bytes": bytes,
                    "list": all[..take(all.len())].iter().map(|i| json!({
                        "name": i.name, "bytes": i.bytes, "copies": i.sites, "functions": i.functions,
                    })).collect::<Vec<_>>(),
                })));
            }
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{} inline sites of {} functions: {bytes} bytes of code, most first:",
                sites.len(),
                all.len()
            );
            let _ = writeln!(
                out,
                "  {:>8}  {:>6}  {:>9}  inlined function",
                "bytes", "copies", "functions"
            );
            for i in &all[..take(all.len())] {
                let _ = writeln!(
                    out,
                    "  {:>8}  {:>6}  {:>9}  {}",
                    i.bytes, i.sites, i.functions, i.name
                );
            }
            if take(all.len()) < all.len() {
                let _ = writeln!(
                    out,
                    "  ({} more; -n 0 lists all)",
                    all.len() - take(all.len())
                );
            }
            Ok(out)
        },
    )
}

/// The spans with code folded into one address counted once: the first
/// span over each byte.
fn distinct_spans(lines: &SourceLines) -> Vec<(u64, u64, u32, u32)> {
    let mut out = Vec::with_capacity(lines.spans.len());
    let mut end = 0u64;
    for s in &lines.spans {
        let start = s.addr.max(end);
        let stop = s.addr + s.size;
        if stop > start {
            out.push((start, stop - start, s.file, s.line));
            end = stop;
        }
    }
    out
}

fn sourcefiles(o: &Options) -> Result<String, String> {
    with_debug(&o.image, o.pdb.as_deref(), false, |debug, _| {
        let lines = debug.source_lines().map_err(|e| e.to_string())?;
        let spans = distinct_spans(&lines);
        let take = |len: usize| if o.rows == 0 { len } else { o.rows.min(len) };
        if let Some(name) = &o.one {
            let path = pick(lines.files.iter().map(String::as_str), name, "source file")?;
            let index = lines
                .files
                .iter()
                .position(|f| f == path)
                .and_then(|i| u32::try_from(i).ok())
                .unwrap_or(0);
            let mut per: HashMap<u32, u64> = HashMap::new();
            for &(_, size, file, line) in &spans {
                if file == index {
                    *per.entry(line).or_default() += size;
                }
            }
            let mut rows: Vec<(u32, u64)> = per.into_iter().collect();
            rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let total: u64 = rows.iter().map(|r| r.1).sum();
            if o.json {
                return Ok(pretty(&json!({
                    "file": path,
                    "bytes": total,
                    "lines": rows[..take(rows.len())].iter().map(|(l, b)| json!({"line": l, "bytes": b})).collect::<Vec<_>>(),
                })));
            }
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{path}: {total} bytes of code from {} lines, most first:",
                rows.len()
            );
            let _ = writeln!(out, "  {:>8}  line", "bytes");
            for (l, b) in &rows[..take(rows.len())] {
                let _ = writeln!(out, "  {b:>8}  {l}");
            }
            if take(rows.len()) < rows.len() {
                let _ = writeln!(
                    out,
                    "  ({} more; -n 0 lists all)",
                    rows.len() - take(rows.len())
                );
            }
            return Ok(out);
        }
        let mut per: HashMap<u32, (u64, std::collections::HashSet<u32>)> = HashMap::new();
        for &(_, size, file, line) in &spans {
            let e = per.entry(file).or_default();
            e.0 += size;
            e.1.insert(line);
        }
        let mut rows: Vec<(&str, u64, usize)> = per
            .into_iter()
            .map(|(f, (b, l))| {
                (
                    lines.files.get(f as usize).map_or("", String::as_str),
                    b,
                    l.len(),
                )
            })
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let total: u64 = rows.iter().map(|r| r.1).sum();
        if o.json {
            return Ok(pretty(&json!({
                "files": rows.len(),
                "bytes": total,
                "list": rows[..take(rows.len())].iter().map(|(f, b, l)| json!({"file": f, "bytes": b, "lines": l})).collect::<Vec<_>>(),
            })));
        }
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} source files: {total} bytes of code, most first:",
            rows.len()
        );
        let _ = writeln!(out, "  {:>8}  {:>6}  file", "bytes", "lines");
        for (f, b, l) in &rows[..take(rows.len())] {
            let _ = writeln!(out, "  {b:>8}  {l:>6}  {f}");
        }
        if take(rows.len()) < rows.len() {
            let _ = writeln!(
                out,
                "  ({} more; -n 0 lists all)",
                rows.len() - take(rows.len())
            );
        }
        Ok(out)
    })
}

pub const ANNOTATIONS_USAGE: &str = "\
usage: hexc annotations [options] <image>

The annotations in a PE image's PDB: strings its code attached to an
address (MSVC's __annotation intrinsic), with the source file and line
there, and whether they are in an inlined copy of a function (or annotate
a call to one). They take no space in the image.

options:
  -pdb <path>   its debug information: a PDB, or a file with its DWARF
                (or -debug; default: its own, or the one it names)
  -json         as JSON";

pub fn run_annotations(args: &[String]) -> ExitCode {
    run(args, "annotations", ANNOTATIONS_USAGE, "", annotations)
}

fn annotations(o: &Options) -> Result<String, String> {
    with_debug(&o.image, o.pdb.as_deref(), false, |debug, _| {
        let list = debug.annotations().map_err(|e| e.to_string())?;
        let lines = debug.source_lines().map_err(|e| e.to_string())?;
        // The source line at an address: the span holding it.
        let line_at = |addr: u64| {
            let i = lines.spans.partition_point(|s| s.addr <= addr);
            let s = lines.spans[..i]
                .iter()
                .rev()
                .find(|s| addr < s.addr + s.size.max(1))?;
            Some((
                lines.files.get(s.file as usize).map_or("", String::as_str),
                s.line,
            ))
        };
        if o.json {
            let v: Vec<Value> = list
                .iter()
                .map(|a| {
                    let (file, line) = line_at(a.addr).unwrap_or(("", 0));
                    json!({
                        "rva": format!("{:#x}", a.addr),
                        "strings": a.strings,
                        "file": file,
                        "line": line,
                        "inlined": a.inlined,
                    })
                })
                .collect();
            return Ok(pretty(&json!({"annotations": v})));
        }
        let mut out = String::new();
        let _ = writeln!(out, "{} annotations:", list.len());
        for a in &list {
            let place = line_at(a.addr).map_or_else(
                || "unknown source".to_string(),
                |(f, l)| format!("{}:{l}", f.rsplit(['\\', '/']).next().unwrap_or(f)),
            );
            let _ = writeln!(
                out,
                "  {:08x}  {place}{}  {}",
                a.addr,
                if a.inlined { " (inlined)" } else { "" },
                a.strings.join(" | ")
            );
        }
        Ok(out)
    })
}

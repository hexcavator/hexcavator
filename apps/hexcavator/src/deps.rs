//! `hexc deps`: what an executable or library loads, found as its loader
//! would find it (see `hexcavator_deps`), and what's missing.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use hexcavator_deps::{DepKind, Graph, ImportStatus, Options, Severity, Status};
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc deps [options] <image>

What an executable or library (PE, ELF, Mach-O) loads, as a tree: each
library it names, where its platform's loader would find it, what that
loads, and what's missing (libraries, and the symbols imported from them).
Nothing is loaded or run: files are read.

  PE: known DLLs, the application's directory, the system directory
      (System32; SysWOW64 or SysArm32 for 32-bit images), System, the
      Windows directory, then the -L directories (and PATH, on Windows);
      API sets by the API set schema; side-by-side assemblies (WinSxS);
      forwarded exports followed.
  ELF: rpath, the -L directories (as LD_LIBRARY_PATH), runpath,
      ld.so.conf, the default directories; $ORIGIN; the interpreter.
  Mach-O: install names, @executable_path, @loader_path, @rpath; system
      libraries in the dyld shared cache.

options:
  -sysroot <dir>   the system: a Windows directory (PE), or the root of a
                   Linux or macOS file system (default: this host's, for
                   its own format)
  -L <dir>         another directory to search (any number)
  -apiset <file>   the API set schema (apisetschema.dll; default: the
                   system's)
  -imports         list each library's imported symbols (missing ones
                   marked)
  -depth <n>       how deep the tree goes (default: all)
  -apisets         list each API set (default: those of one host together)
  -problems        only what's missing
  -system          read what system libraries load too (and report their
                   problems; default: they're leaves, checked only for
                   what they export)
  -nosymbols       don't check imports against exports
  -json            the graph as JSON";

struct Args {
    image: Option<String>,
    options: Options,
    imports: bool,
    depth: usize,
    apisets: bool,
    problems: bool,
    json: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        image: None,
        options: Options::default(),
        imports: false,
        depth: usize::MAX,
        apisets: false,
        problems: false,
        json: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |what: &str| it.next().cloned().ok_or(format!("{arg} needs {what}"));
        match arg.as_str() {
            "-sysroot" | "/sysroot" => {
                a.options.sysroot = Some(PathBuf::from(value("a directory")?));
            }
            "-L" | "/L" => a.options.dirs.push(PathBuf::from(value("a directory")?)),
            "-apiset" | "/apiset" => a.options.apiset = Some(PathBuf::from(value("a file")?)),
            "-depth" | "/depth" => {
                a.depth = value("a number")?
                    .parse()
                    .map_err(|_| "-depth needs a number".to_string())?;
            }
            "-imports" | "/imports" => a.imports = true,
            "-apisets" | "/apisets" => a.apisets = true,
            "-problems" | "/problems" => a.problems = true,
            "-nosymbols" | "/nosymbols" => a.options.symbols = false,
            "-system" | "/system" => a.options.system = true,
            "-json" | "/json" => a.json = true,
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s if a.image.is_none() => a.image = Some(s.to_string()),
            _ => return Err("give one image".into()),
        }
    }
    Ok(a)
}

pub fn run(args: &[String]) -> ExitCode {
    let a = match parse(args) {
        Ok(a) if a.image.is_some() => a,
        Ok(_) => return usage("no image given"),
        Err(e) => return usage(&e),
    };
    let image = a.image.as_deref().unwrap_or_default();
    let graph = match hexcavator_deps::analyze(std::path::Path::new(image), &a.options) {
        Ok(g) => g,
        Err(e) => {
            ereport!("hexc deps: {e}");
            return ExitCode::FAILURE;
        }
    };
    let text = if a.json {
        format!(
            "{}\n",
            serde_json::to_string_pretty(&as_json(&graph)).unwrap_or_default()
        )
    } else {
        as_text(&graph, &a)
    };
    let printed = crate::out::print(text.as_bytes());
    // (Missing what loading needs: a failure, as a check would want.)
    if graph.problems.iter().any(|p| p.severity == Severity::Error) && printed == ExitCode::SUCCESS
    {
        return ExitCode::FAILURE;
    }
    printed
}

fn usage(message: &str) -> ExitCode {
    ereport!("hexc deps: {message}\n\n{USAGE}");
    ExitCode::from(2)
}

/// A path as its platform writes it: `\` for Windows images, `/` for the
/// others.
fn shown(path: &std::path::Path, pe: bool) -> String {
    let s = path.display().to_string();
    if pe {
        s.replace('/', "\\")
    } else {
        s.replace('\\', "/")
    }
}

/// How a module's status reads after its name.
fn where_is(status: &Status, pe: bool) -> String {
    let display = |p: &std::path::Path| shown(p, pe);
    match status {
        Status::Found { path, how } => format!("{}  ({})", display(path), how.describe()),
        Status::Missing { .. } => "NOT FOUND".into(),
        Status::ApiSetHostMissing { host, .. } => format!("API set: its host, {host}, NOT FOUND"),
        Status::WrongArch { path, arch } => {
            format!("WRONG ARCHITECTURE: {} is {arch}", display(path))
        }
        Status::Unreadable { path, why } => format!("UNREADABLE: {}: {why}", display(path)),
        Status::ApiSet {
            host: None,
            known: true,
        } => "API set, NO HOST on this system".into(),
        Status::ApiSet { .. } => {
            "API set (no schema to resolve it: give -sysroot or -apiset)".into()
        }
        Status::SharedCache => "(in the dyld shared cache)".into(),
        Status::Unsearched => "(a system library: not searched)".into(),
        Status::Assembly { dir: Some(d) } => format!("{}  (side-by-side assembly)", display(d)),
        Status::Assembly { dir: None } => "(side-by-side assembly, not found)".into(),
    }
}

/// A dependency's kind, as a tag (none for the usual one).
fn tag(kind: DepKind) -> &'static str {
    match kind {
        DepKind::DelayLoad => "  [delay-load]",
        DepKind::Forwarder => "  [forwarder]",
        DepKind::Interpreter => "  [interpreter]",
        DepKind::WeakDylib => "  [weak]",
        DepKind::ReexportDylib => "  [re-export]",
        DepKind::LazyDylib => "  [lazy]",
        DepKind::UpwardDylib => "  [upward]",
        DepKind::Assembly => "  [assembly]",
        _ => "",
    }
}

/// Whether the graph is of PE images.
fn is_pe(g: &Graph) -> bool {
    g.modules.first().and_then(|m| m.format) == Some(hexcavator_deps::Format::Pe)
}

fn as_text(g: &Graph, a: &Args) -> String {
    let mut out = String::new();
    if !a.problems {
        let root = &g.modules[0];
        let _ = writeln!(
            out,
            "{}  {} {}  {}",
            root.name,
            root.format.map_or("", hexcavator_deps::Format::name),
            root.arch.as_deref().unwrap_or(""),
            root.status
                .path()
                .map(|p| shown(p, is_pe(g)))
                .unwrap_or_default()
        );
        let mut shown = vec![false; g.modules.len()];
        shown[0] = true;
        tree(g, a, 0, 1, &mut shown, &mut out);
    }
    if !g.problems.is_empty() {
        if !a.problems {
            out.push('\n');
        }
        let _ = writeln!(out, "Problems:");
        for p in &g.problems {
            let level = match p.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            let _ = writeln!(out, "  {level}: {}", p.message);
            if let Status::Missing { tried } | Status::ApiSetHostMissing { tried, .. } =
                &g.modules[p.module].status
                && !tried.is_empty()
            {
                let _ = writeln!(out, "    looked in: {}", list_dirs(tried, is_pe(g)));
            }
        }
    } else if a.problems {
        let _ = writeln!(
            out,
            "No problems: everything it loads was found, with what it imports."
        );
    }
    for n in &g.notes {
        let _ = writeln!(out, "note: {n}");
    }
    out
}

/// The directories of paths tried, in order, once each: the first few,
/// and how many more.
fn list_dirs(tried: &[PathBuf], pe: bool) -> String {
    const SHOWN: usize = 6;
    let mut dirs: Vec<String> = Vec::new();
    for t in tried {
        let d = t.parent().map(|d| shown(d, pe)).unwrap_or_default();
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    let more = dirs.len().saturating_sub(SHOWN);
    dirs.truncate(SHOWN);
    let mut s = dirs.join(", ");
    if more > 0 {
        s.push_str(&format!(", and {more} more (PATH)"));
    }
    s
}

/// Module `m`'s dependencies, at `depth`: each once (later, "above"),
/// API sets of one host together.
fn tree(g: &Graph, a: &Args, m: usize, depth: usize, shown: &mut [bool], out: &mut String) {
    if depth > a.depth {
        return;
    }
    let pad = "  ".repeat(depth);
    let module = &g.modules[m];
    let mut grouped: Vec<(usize, Vec<&str>)> = Vec::new();
    for d in &module.deps {
        let t = &g.modules[d.module];
        // An API set whose host was found: with the others of that host.
        let api_set = hexcavator_pe::apiset::is_api_set_name(&d.name) && t.status.path().is_some();
        if api_set && !a.apisets {
            match grouped.iter_mut().find(|(h, _)| *h == d.module) {
                Some((_, names)) => names.push(&d.name),
                None => grouped.push((d.module, vec![&d.name])),
            }
            continue;
        }
        let last = d.name.rsplit(['/', '\\']).next().unwrap_or(&d.name);
        let name = if last.eq_ignore_ascii_case(&t.name) || t.status.path().is_none() {
            d.name.clone()
        } else {
            format!("{} -> {}", d.name, t.name)
        };
        line(g, a, &pad, &name, d.module, d.kind, shown, out);
        imports(a, &pad, d, out);
        if !std::mem::replace(&mut shown[d.module], true) {
            tree(g, a, d.module, depth + 1, shown, out);
        }
    }
    for (host, names) in grouped {
        let label = if names.len() == 1 {
            format!("{} -> {}", names[0], g.modules[host].name)
        } else {
            format!("{} API sets -> {}", names.len(), g.modules[host].name)
        };
        line(g, a, &pad, &label, host, DepKind::Import, shown, out);
        if !std::mem::replace(&mut shown[host], true) {
            tree(g, a, host, depth + 1, shown, out);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn line(
    g: &Graph,
    _a: &Args,
    pad: &str,
    name: &str,
    target: usize,
    kind: DepKind,
    shown: &[bool],
    out: &mut String,
) {
    let t = &g.modules[target];
    let place = if shown[target] && t.status.path().is_some() {
        "(above)".to_string()
    } else {
        where_is(&t.status, is_pe(g))
    };
    let _ = writeln!(out, "{pad}{name}  {place}{}", tag(kind));
}

/// An edge's imported symbols (with -imports).
fn imports(a: &Args, pad: &str, d: &hexcavator_deps::Dep, out: &mut String) {
    if !a.imports {
        return;
    }
    for i in &d.imports {
        let mark = match &i.status {
            ImportStatus::Missing if i.weak => "  (missing, weak)".to_string(),
            ImportStatus::Missing => "  MISSING".to_string(),
            ImportStatus::Forwarded(to) => format!("  -> {to}"),
            ImportStatus::Broken(to) => format!("  MISSING (forwarded to {to}, which isn't there)"),
            _ => String::new(),
        };
        let _ = writeln!(out, "{pad}    {}{mark}", i.label());
    }
}

/// The graph as JSON: modules (by index), each with its dependencies
/// (module indexes, kinds, imports), the problems, and notes.
fn as_json(g: &Graph) -> Value {
    let modules: Vec<Value> = g
        .modules
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let (status, path, how, extra) = match &m.status {
                Status::Found { path, how } => ("found", Some(path.display().to_string()), Some(how.describe()), Value::Null),
                Status::Missing { tried } => (
                    "missing",
                    None,
                    None,
                    json!({ "tried": tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() }),
                ),
                Status::WrongArch { path, arch } => ("wrongArch", Some(path.display().to_string()), None, json!({ "arch": arch })),
                Status::Unreadable { path, why } => ("unreadable", Some(path.display().to_string()), None, json!({ "why": why })),
                Status::ApiSet { host, known } => ("apiSet", None, None, json!({ "host": host, "known": known })),
                Status::SharedCache => ("sharedCache", None, None, Value::Null),
                Status::Unsearched => ("unsearched", None, None, Value::Null),
                Status::ApiSetHostMissing { host, tried } => (
                    "apiSetHostMissing",
                    None,
                    None,
                    json!({ "host": host, "tried": tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() }),
                ),
                Status::Assembly { dir } => ("assembly", dir.as_ref().map(|d| d.display().to_string()), None, Value::Null),
            };
            json!({
                "id": i,
                "name": m.name,
                "status": status,
                "path": path,
                "how": how,
                "detail": extra,
                "format": m.format.map(hexcavator_deps::Format::name),
                "arch": m.arch,
                "depth": m.depth,
                "system": m.system,
                "exports": m.exports,
                "deps": m.deps.iter().map(|d| json!({
                    "name": d.name,
                    "kind": d.kind.name(),
                    "module": d.module,
                    "imports": d.imports.iter().map(import_json).collect::<Vec<_>>(),
                    "missing": d.imports.iter().filter(|x| x.status.is_missing() && !x.weak).count(),
                })).collect::<Vec<_>>(),
                "unresolved": m.unresolved.iter().map(import_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "root": 0,
        "sysroot": g.sysroot.as_ref().map(|p| p.display().to_string()),
        "modules": modules,
        "problems": g.problems.iter().map(|p| json!({
            "severity": match p.severity { Severity::Error => "error", Severity::Warning => "warning" },
            "module": p.module,
            "message": p.message,
        })).collect::<Vec<_>>(),
        "notes": g.notes,
    })
}

fn import_json(i: &hexcavator_deps::Import) -> Value {
    json!({
        "name": i.name,
        "ordinal": i.ordinal,
        "version": i.version,
        "weak": i.weak,
        "status": match &i.status {
            ImportStatus::Unchecked => "unchecked",
            ImportStatus::Found => "found",
            ImportStatus::Forwarded(_) => "forwarded",
            ImportStatus::Missing => "missing",
            ImportStatus::Broken(_) => "brokenForwarder",
        },
        "forwardedTo": match &i.status {
            ImportStatus::Forwarded(to) | ImportStatus::Broken(to) => Some(to.as_str()),
            _ => None,
        },
    })
}

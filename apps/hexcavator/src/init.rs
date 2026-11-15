//! `hexc init`: what runs when an image is loaded, before its `main` (see
//! `hexcavator_size::startup`), with what each function calls.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_size::startup::{self, Startup};
use hexcavator_size::xref::Xref;
use hexcavator_xref::Edge;
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc init [options] <image>

What runs when an image is loaded, before its own code's main (of a
library: when it's loaded), in the order it runs, with what each function
calls (from its PDB or DWARF):

  PE: TLS callbacks, the entry point, then the CRT's lists: runtime
      checks' (.rtc$I*), C initializers (.CRT$XI*), C++ dynamic
      initializers (.CRT$XC*: global objects' constructors); then main,
      wmain, WinMain (or DllMain).
  ELF: .preinit_array, DT_INIT, .ctors, .init_array, the entry point; main.
  Mach-O: __mod_init_func (or __init_offsets), the entry point (main).

A function shown before is shown again as \"(above)\".

options:
  -depth <n>       how many levels of callees to show (default 2; 0: none)
  -json            as JSON (each function's direct callees counted)
  -callees <node>  (with -json) what the function node <node> calls, for an
                   editor's tree
  -pdb <path>      its debug information: a PDB, or a file with its DWARF";

struct Options {
    image: Option<String>,
    pdb: Option<PathBuf>,
    depth: usize,
    json: bool,
    callees: Option<u32>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        image: None,
        pdb: None,
        depth: 2,
        json: false,
        callees: None,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |what: &str| it.next().cloned().ok_or(format!("{a} needs {what}"));
        match a.as_str() {
            "-depth" | "/depth" => {
                o.depth = value("a number")?
                    .parse()
                    .map_err(|_| "-depth needs a number")?;
            }
            "-json" | "/json" => o.json = true,
            "-callees" | "/callees" => {
                o.callees = Some(
                    value("a node")?
                        .parse()
                        .map_err(|_| "-callees needs a node's number")?,
                );
            }
            "-pdb" | "/pdb" | "-debug" | "/debug" => o.pdb = Some(PathBuf::from(value("a path")?)),
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s if o.image.is_none() => o.image = Some(s.to_string()),
            _ => return Err("give one image".into()),
        }
    }
    if o.image.is_none() {
        return Err("no image given".into());
    }
    if o.callees.is_some() && !o.json {
        return Err("-callees is for -json".into());
    }
    Ok(o)
}

pub fn run(args: &[String]) -> ExitCode {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc init: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match report(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc init: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A function's name, place, and source line, as shown.
struct Named<'x> {
    image: &'x hexcavator_image::Image<'x>,
    x: &'x Xref,
    locator: hexcavator_debuginfo::Locator<'x, 'x>,
    /// What the image's tools add to its addresses (a PE image's base).
    base: u64,
}

impl Named<'_> {
    fn name(&self, n: u32) -> &str {
        self.x.names.get(n as usize).map_or("?", String::as_str)
    }

    /// The source file and line of the function `n` starts at.
    fn line(&mut self, n: u32) -> Option<(String, u32)> {
        let start = self.x.graph.nodes().get(n as usize)?.start;
        let frames = self.locator.frames(start);
        let f = frames.last()?;
        Some((f.file.clone()?, f.line))
    }

    fn place(&mut self, n: u32) -> String {
        match self.line(n) {
            Some((file, line)) if line > 0 => format!("  {file}:{line}"),
            Some((file, _)) => format!("  {file}"),
            None => String::new(),
        }
    }
}

fn report(o: &Options) -> Result<String, String> {
    let path = Path::new(o.image.as_deref().unwrap_or_default());
    let opened = hexcavator_program::Opened::open(path, o.pdb.as_deref())?;
    let program = opened.program()?;
    let model = program.model()?;
    let syms = program.symbols()?;
    // (Kept, for an editor's next question: what a function calls.)
    let x = hexcavator_program::cache::remember(&program.files(), "xref", || {
        hexcavator_size::xref::build(&program.image, &program.debug, model, syms)
    })
    .map_err(|e| format!("{}: {e}", path.display()))?;
    let s = startup::startup(&program.image, &x, model);
    let mut named = Named {
        image: &program.image,
        x: &x,
        locator: program.debug.locator(),
        base: program.image.image_base(),
    };
    if let Some(n) = o.callees {
        if n as usize >= x.names.len() {
            return Err(format!("no node {n}"));
        }
        let list: Vec<Value> = startup::callees(&program.image, &x, n)
            .into_iter()
            .map(|(c, e)| function_json(&mut named, c, Some(e)))
            .collect();
        return Ok(format!("{}\n", json!({ "node": n, "callees": list })));
    }
    if o.json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&as_json(&s, &mut named)).unwrap_or_default()
        ));
    }
    let file = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    Ok(as_text(&s, &mut named, &file, o.depth))
}

fn function_json(named: &mut Named<'_>, n: u32, edge: Option<Edge>) -> Value {
    let line = named.line(n);
    let start = named.x.graph.nodes().get(n as usize).map_or(0, |n| n.start);
    json!({
        "node": n,
        "name": named.name(n),
        "address": format!("{:#x}", start.wrapping_add(named.base)),
        "file": line.as_ref().map(|l| l.0.clone()),
        "line": line.as_ref().map(|l| l.1).filter(|&l| l > 0),
        "callees": startup::callees(named.image, named.x, n).len(),
        "jump": edge == Some(Edge::Jump),
    })
}

fn as_json(s: &Startup, named: &mut Named<'_>) -> Value {
    let phases: Vec<Value> = s
        .phases
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "detail": p.detail,
                "entries": p.entries.iter().map(|e| match e.node {
                    Some(n) => {
                        let mut v = function_json(named, n, None);
                        v["slot"] = e.slot.map(|a| format!("{:#x}", a.wrapping_add(named.base))).into();
                        v
                    }
                    None => json!({
                        "node": null,
                        "name": format!("{:#x}", e.addr.wrapping_add(named.base)),
                        "address": format!("{:#x}", e.addr.wrapping_add(named.base)),
                        "callees": 0,
                        "slot": e.slot.map(|a| format!("{:#x}", a.wrapping_add(named.base))),
                    }),
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "library": s.library,
        "phases": phases,
        "main": s.main.map(|m| function_json(named, m, None)),
    })
}

fn as_text(s: &Startup, named: &mut Named<'_>, file: &str, depth: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{file}: {}",
        if s.library {
            "what runs when it is loaded"
        } else {
            "what runs before main"
        }
    );
    if s.phases.is_empty() {
        let _ = writeln!(out, "\nNothing: no initializers, no entry point.");
    }
    let mut seen = HashSet::new();
    for p in &s.phases {
        let _ = writeln!(out, "\n{}: {}", p.name, p.detail);
        for (i, e) in p.entries.iter().enumerate() {
            let number = if p.entries.len() > 1 {
                format!("{:>3}  ", i + 1)
            } else {
                "  ".into()
            };
            match e.node {
                Some(n) => {
                    let place = named.place(n);
                    let again = !seen.insert(n);
                    let _ = writeln!(
                        out,
                        "{number}{}{place}{}",
                        named.name(n),
                        if again { "  (above)" } else { "" }
                    );
                    if !again {
                        let pad = " ".repeat(number.len() + 2);
                        callees(&mut out, named, n, &pad, depth, &mut seen);
                    }
                }
                None => {
                    let _ = writeln!(
                        out,
                        "{number}{:#x}  (no function known there)",
                        e.addr.wrapping_add(named.base)
                    );
                }
            }
        }
    }
    if let Some(m) = s.main {
        let place = named.place(m);
        let _ = writeln!(
            out,
            "\nThen the program's own code: {}{place}",
            named.name(m)
        );
    }
    out
}

/// What `n` calls, `depth` levels down, each function once (later,
/// "(above)").
fn callees(
    out: &mut String,
    named: &mut Named<'_>,
    n: u32,
    pad: &str,
    depth: usize,
    seen: &mut HashSet<u32>,
) {
    if depth == 0 {
        return;
    }
    for (c, e) in startup::callees(named.image, named.x, n) {
        let verb = if e == Edge::Jump { "jumps to" } else { "calls" };
        let again = !seen.insert(c);
        let place = if again {
            "  (above)".to_string()
        } else {
            named.place(c)
        };
        let _ = writeln!(out, "{pad}{verb} {}{place}", named.name(c));
        if !again {
            callees(out, named, c, &format!("{pad}  "), depth - 1, seen);
        }
    }
}

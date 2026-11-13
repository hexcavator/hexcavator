//! `hexc xref`: what refers to what in an image, and why each function and
//! datum is in it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_size::fingerprint::Fingerprints;
use hexcavator_size::xref::{Kept, Xref};
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc xref [options] <image> [-- <base image>]

What each function and datum of an image (PE, ELF, Mach-O, WebAssembly)
refers to (calls, branches, addresses its code uses, pointers in data,
exception data), from its code, relocations, and debug information (a PDB,
or DWARF); and why each is there: the chain of references from
a root (the entry point, an export, a loader directory, a static
initializer). Without -why, -refs, -unreachable, -vtables, -identical, or
a base image: a summary.

options:
  -pdb <path>      its debug information: a PDB, or a file with its DWARF
                   (or -debug; default: its own, or the one it names)
  -why <name>      the chain from a root to the function or datum, or that
                   none reaches it
  -refs <name>     what refers to it, and what it refers to
  -unreachable     what no root reaches, largest first
  -vtables         the vtables no code refers to (no constructor or destructor
                   stores them), largest first, with what does
  -identical       functions the linker could have folded (/OPT:ICF) but
                   didn't: COMDATs with the same code that refer to the same
                   things (by fingerprint), by saving
  -- <base image>  the functions compared with a base build's: by name the
                   same or changed, then by fingerprint renamed (the same
                   code, another name), and the rest added or removed
  -base-pdb <path> the base image's PDB
  -n <n>           rows to list (default 20; 0: all)
  -json            as JSON
names are as the PDB gives them (`Square::area() const`), or without the
parameters if just one function has the name.";

struct Options {
    image: PathBuf,
    pdb: Option<PathBuf>,
    why: Option<String>,
    refs: Option<String>,
    unreachable: bool,
    vtables: bool,
    identical: bool,
    base: Option<PathBuf>,
    base_pdb: Option<PathBuf>,
    rows: usize,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        image: PathBuf::new(),
        pdb: None,
        why: None,
        refs: None,
        unreachable: false,
        vtables: false,
        identical: false,
        base: None,
        base_pdb: None,
        rows: 20,
        json: false,
    };
    let mut image = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            o.base = Some(it.next().ok_or("-- needs a base image")?.into());
            if let Some(extra) = it.next() {
                return Err(format!("unexpected argument '{extra}'"));
            }
            break;
        }
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("-{name} needs a value"))
        };
        match a.strip_prefix('-').or_else(|| a.strip_prefix('/')) {
            Some("pdb" | "debug") => o.pdb = Some(value("pdb")?.into()),
            Some("why") => o.why = Some(value("why")?),
            Some("refs") => o.refs = Some(value("refs")?),
            Some("unreachable") => o.unreachable = true,
            Some("vtables") => o.vtables = true,
            Some("identical") => o.identical = true,
            Some("base-pdb") => o.base_pdb = Some(value("base-pdb")?.into()),
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

pub fn run(args: &[String]) -> ExitCode {
    if args.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc xref: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match report(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc xref: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The graph of the image at `path`, and its nodes' fingerprints in
/// `mode`, if any.
fn build(
    path: &Path,
    pdb: Option<&Path>,
    mode: Option<hexcavator_size::fingerprint::Mode>,
) -> Result<(Xref, Fingerprints), String> {
    let show = |p: &Path| p.display().to_string();
    let opened = hexcavator_program::Opened::open(path, pdb)?;
    let program = opened.program()?;
    let (image, debug) = (&program.image, &program.debug);
    let model = program.model()?;
    let syms = program.symbols()?;
    let x = hexcavator_size::xref::build(image, debug, model, syms)
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let classes = match mode {
        Some(mode) => hexcavator_size::fingerprint::build(image, model, &x, mode),
        None => Fingerprints {
            items: Vec::new(),
            classes: Vec::new(),
            identities: Vec::new(),
        },
    };
    Ok((x, classes))
}

/// The node `name` names: exactly, or (if just one function has it) without
/// its parameters.
pub(crate) fn lookup(x: &Xref, name: &str) -> Result<u32, String> {
    let found = x.find(name);
    if let Some(&n) = found.first() {
        return Ok(n);
    }
    let mut alone = hexcavator_size::disasm::ByNameAlone::new(name);
    for i in x.ids() {
        alone.offer(
            x.graph.nodes()[i as usize].start,
            &x.names[i as usize],
            || i,
        );
    }
    alone
        .take()
        .ok_or_else(|| format!("nothing named '{name}'"))
}

fn report(o: &Options) -> Result<String, String> {
    use hexcavator_size::fingerprint::Mode;
    let mode = if o.base.is_some() {
        Some(Mode::Same)
    } else if o.identical {
        Some(Mode::Foldable)
    } else {
        None
    };
    let (x, classes) = build(&o.image, o.pdb.as_deref(), mode)?;
    if let Some(base) = &o.base {
        let (old, old_classes) = build(base, o.base_pdb.as_deref(), mode)?;
        return Ok(compare(&old, &old_classes, &x, &classes, o.rows, o.json));
    }
    if o.identical {
        return Ok(identical(&x, &classes.classes, o.rows, o.json));
    }
    if let Some(name) = &o.why {
        let n = lookup(&x, name)?;
        return Ok(if o.json {
            pretty(&why_json(&x, n))
        } else {
            why_text(&x, n)
        });
    }
    if o.vtables {
        return Ok(vtables(&x, o.rows, o.json));
    }
    if let Some(name) = &o.refs {
        let n = lookup(&x, name)?;
        return Ok(if o.json {
            pretty(&refs_json(&x, n))
        } else {
            refs_text(&x, n)
        });
    }
    let unreached = unreached(&x);
    let rows = if o.rows == 0 {
        unreached.len()
    } else {
        o.rows.min(unreached.len())
    };
    if o.json {
        let list: Vec<Value> = unreached[..rows]
            .iter()
            .map(|&n| node_json(&x, n))
            .collect();
        let mut v = summary_json(&x, &unreached);
        v["unreachable"] = Value::from(list);
        return Ok(pretty(&v));
    }
    let mut out = String::new();
    if !o.unreachable {
        out.push_str(&summary_text(&x, &unreached));
        if rows > 0 {
            out.push('\n');
        }
    }
    if rows > 0 {
        let _ = writeln!(
            out,
            "Unreachable, largest first (and why the linker kept it):"
        );
        for &n in &unreached[..rows] {
            let _ = writeln!(
                out,
                "  {:>10}  {}  [{}]",
                x.size(n),
                x.names[n as usize],
                kept_short(&x, n)
            );
        }
        if rows < unreached.len() {
            let _ = writeln!(out, "  ({} more; -n 0 lists all)", unreached.len() - rows);
        }
    }
    Ok(out)
}

/// Groups of identical functions the linker didn't fold.
fn identical(x: &Xref, classes: &[u64], rows: usize, json: bool) -> String {
    let groups = hexcavator_size::fingerprint::identical(x, classes);
    let saving: u64 = groups.iter().map(|g| g.1).sum();
    let shown = if rows == 0 {
        groups.len()
    } else {
        rows.min(groups.len())
    };
    if json {
        let list: Vec<Value> = groups[..shown]
            .iter()
            .map(|(g, saved)| {
                json!({
                    "saving": saved,
                    "size": x.size(g[0]),
                    "functions": g.iter().map(|&n| x.names[n as usize].as_str()).collect::<Vec<_>>(),
                })
            })
            .collect();
        return pretty(&json!({"groups": groups.len(), "saving": saving, "list": list}));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} groups of identical functions the linker didn't fold ({saving} bytes would be saved), largest saving first:",
        groups.len()
    );
    for (g, saved) in &groups[..shown] {
        let _ = writeln!(out, "  {saved:>8}  {} x {} bytes:", g.len(), x.size(g[0]));
        for &n in g {
            let _ = writeln!(out, "              {}", x.names[n as usize]);
        }
    }
    if shown < groups.len() {
        let _ = writeln!(out, "  ({} more; -n 0 lists all)", groups.len() - shown);
    }
    out
}

/// The functions of `new` compared with `old`'s: by name, then the rest by
/// fingerprint.
fn compare(
    old: &Xref,
    old_fp: &Fingerprints,
    new: &Xref,
    new_fp: &Fingerprints,
    rows: usize,
    json: bool,
) -> String {
    let d = hexcavator_size::fingerprint::compare(old, old_fp, new, new_fp);
    let (same, changed, renamed, added, removed) =
        (d.unchanged, d.changed, d.renamed, d.added, d.removed);
    let take = |len: usize| if rows == 0 { len } else { rows.min(len) };
    if json {
        let pair = |&(o, n): &(u32, u32)| json!({"old": old.names[o as usize], "new": new.names[n as usize], "oldSize": old.size(o), "newSize": new.size(n)});
        return pretty(&json!({
            "unchanged": same,
            "changed": changed[..take(changed.len())].iter().map(pair).collect::<Vec<_>>(),
            "changedCount": changed.len(),
            "renamed": renamed[..take(renamed.len())].iter().map(pair).collect::<Vec<_>>(),
            "renamedCount": renamed.len(),
            "added": added[..take(added.len())].iter().map(|&n| json!({"name": new.names[n as usize], "size": new.size(n)})).collect::<Vec<_>>(),
            "addedCount": added.len(),
            "removed": removed[..take(removed.len())].iter().map(|&o| json!({"name": old.names[o as usize], "size": old.size(o)})).collect::<Vec<_>>(),
            "removedCount": removed.len(),
        }));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Functions: {} unchanged, {} changed, {} renamed, {} added, {} removed",
        same,
        changed.len(),
        renamed.len(),
        added.len(),
        removed.len()
    );
    let more = |out: &mut String, shown: usize, all: usize| {
        if shown < all {
            let _ = writeln!(out, "  ({} more; -n 0 lists all)", all - shown);
        }
    };
    if !renamed.is_empty() {
        let _ = writeln!(
            out,
            "\nRenamed (the same code, another name), largest first:"
        );
        let k = take(renamed.len());
        for &(o, n) in &renamed[..k] {
            let _ = writeln!(
                out,
                "  {:>8}  {}\n            was {}",
                new.size(n),
                new.names[n as usize],
                old.names[o as usize]
            );
        }
        more(&mut out, k, renamed.len());
    }
    if !changed.is_empty() {
        let _ = writeln!(
            out,
            "\nChanged (the same name, other code), by change in size:"
        );
        let k = take(changed.len());
        for &(o, n) in &changed[..k] {
            let delta = i128::from(new.size(n)) - i128::from(old.size(o));
            let _ = writeln!(out, "  {delta:>+8}  {}", new.names[n as usize]);
        }
        more(&mut out, k, changed.len());
    }
    for (title, list, x) in [("Added", &added, new), ("Removed", &removed, old)] {
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{title}, largest first:");
        let k = take(list.len());
        for &n in &list[..k] {
            let _ = writeln!(out, "  {:>8}  {}", x.size(n), x.names[n as usize]);
        }
        more(&mut out, k, list.len());
    }
    out
}

/// The vtables no code refers to: no constructor or destructor stores
/// them, so no object of the class is made here (or is made in a way the
/// graph doesn't see). Largest first, each with what does refer to it and
/// whether a root reaches it.
fn vtables(x: &Xref, rows: usize, json: bool) -> String {
    let is_vtable = |n: u32| {
        x.names[n as usize].contains("`vftable'")
            || x.aliases[n as usize]
                .iter()
                .any(|a| a.contains("`vftable'"))
    };
    let code = |n: u32| x.graph.nodes()[n as usize].code;
    let all: Vec<u32> = x.ids().filter(|&n| is_vtable(n)).collect();
    let mut lone: Vec<u32> = all
        .iter()
        .copied()
        .filter(|&n| !x.graph.referrers(n).iter().any(|&(f, _)| code(f)))
        .collect();
    lone.sort_by_key(|&n| (std::cmp::Reverse(x.size(n)), n));
    let shown = if rows == 0 {
        lone.len()
    } else {
        rows.min(lone.len())
    };
    if json {
        let list: Vec<Value> = lone[..shown]
            .iter()
            .map(|&n| {
                let mut v = node_json(x, n);
                v["reached"] = Value::from(x.reach.is_reached(n));
                v["referrers"] = x
                    .graph
                    .referrers(n)
                    .iter()
                    .map(|&(f, e)| json!({"edge": e.verb(), "name": x.names[f as usize]}))
                    .collect();
                v
            })
            .collect();
        return pretty(&json!({
            "vtables": all.len(),
            "withoutCode": lone.len(),
            "withoutCodeSize": lone.iter().map(|&n| x.size(n)).sum::<u64>(),
            "list": list,
        }));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} vtables; {} that no code refers to ({} bytes), largest first:",
        all.len(),
        lone.len(),
        lone.iter().map(|&n| x.size(n)).sum::<u64>()
    );
    for &n in &lone[..shown] {
        let _ = writeln!(
            out,
            "  {:>8}  {}{}",
            x.size(n),
            x.names[n as usize],
            if x.reach.is_reached(n) {
                ""
            } else {
                "  (unreachable)"
            }
        );
        for &(f, e) in x.graph.referrers(n) {
            let _ = writeln!(out, "              {} {} it", x.names[f as usize], e.verb());
        }
    }
    if shown < lone.len() {
        let _ = writeln!(out, "  ({} more; -n 0 lists all)", lone.len() - shown);
    }
    out
}

/// The file name of `node`'s object, if known.
fn object_name(x: &Xref, n: u32) -> Option<&str> {
    let path = x.object(n)?;
    Some(path.rsplit(['\\', '/']).next().unwrap_or(path))
}

/// Why the linker kept `n`, briefly: what its section was, and its object.
fn kept_short(x: &Xref, n: u32) -> String {
    let elf = x.linker == hexcavator_size::xref::Linker::Elf;
    let macho = x.linker == hexcavator_size::xref::Linker::MachO;
    let what = match x.kept(n) {
        Kept::Comdat if macho => "maybe its own atom".to_string(),
        Kept::WithSection { .. } if elf => "not alone in its section".to_string(),
        Kept::WithSection { .. } => "not a COMDAT".to_string(),
        Kept::ReferencedBy(by) => format!("from {}", x.names[by as usize]),
        Kept::Comdat if elf => "maybe its own section".to_string(),
        Kept::Comdat => "COMDAT".to_string(),
        Kept::Unknown => "no contribution".to_string(),
    };
    match object_name(x, n) {
        Some(obj) => format!("{what}, {obj}"),
        None => what,
    }
}

/// Why the linker kept `n`, in a sentence.
fn kept_long(x: &Xref, n: u32) -> String {
    let obj = object_name(x, n).map_or_else(String::new, |o| format!(" of {o}"));
    if x.linker == hexcavator_size::xref::Linker::MachO {
        return match x.kept(n) {
            Kept::ReferencedBy(by) => format!(
                "the linker kept it because {} refers to it (directly or not), which the linker kept",
                x.names[by as usize]
            ),
            Kept::Unknown => "no compile unit covers it".to_string(),
            _ => format!(
                "it is in atoms{obj} that -dead_strip drops when unreferenced: the link didn't use -dead_strip or kept it (an export, -u, .no_dead_strip), or refers to it in a way not seen here"
            ),
        };
    }
    if x.linker == hexcavator_size::xref::Linker::Elf {
        return match x.kept(n) {
            Kept::WithSection { code } => format!(
                "the linker kept it with its section{obj}, which has something used in it (compile with {} to let --gc-sections drop it alone)",
                if code {
                    "-ffunction-sections"
                } else {
                    "-fdata-sections"
                }
            ),
            Kept::ReferencedBy(by) => format!(
                "the linker kept it because {} refers to it (directly or not), which the linker kept with its section",
                x.names[by as usize]
            ),
            Kept::Comdat => format!(
                "it may be in a section of its own{obj}, which --gc-sections drops when unreferenced: the link didn't use --gc-sections or kept it (KEEP, --undefined, an export), or refers to it in a way not seen here"
            ),
            Kept::Unknown => "no compile unit covers it".to_string(),
        };
    }
    match x.kept(n) {
        Kept::WithSection { code: true } => format!(
            "the linker kept it with its section{obj}, which is not a COMDAT and has something used in it (compile with /Gy to let /OPT:REF drop it alone)"
        ),
        Kept::WithSection { code: false } => format!(
            "the linker kept it with its section{obj}, which is not a COMDAT and has something used in it (compile with /Gw to let /OPT:REF drop it alone)"
        ),
        Kept::ReferencedBy(by) => format!(
            "the linker kept it because {} refers to it (directly or not), which the linker kept with its section",
            x.names[by as usize]
        ),
        Kept::Comdat => format!(
            "it is a COMDAT{obj}, which /OPT:REF drops when unreferenced: the link used /OPT:NOREF or /INCLUDE, or refers to it in a way not seen here"
        ),
        Kept::Unknown => "no section contribution covers it".to_string(),
    }
}

/// The unreached nodes, largest first (then by address).
fn unreached(x: &Xref) -> Vec<u32> {
    let mut v: Vec<u32> = x
        .ids()
        .filter(|&n| !x.reach.is_reached(n) && x.kinds[n as usize].is_some())
        .collect();
    v.sort_by_key(|&n| (std::cmp::Reverse(x.size(n)), n));
    v
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

fn summary_text(x: &Xref, unreached: &[u32]) -> String {
    let total: u64 = x
        .ids()
        .filter(|&n| x.kinds[n as usize].is_some())
        .map(|n| x.size(n))
        .sum();
    let lost: u64 = unreached.iter().map(|&n| x.size(n)).sum();
    let mut out = format!(
        "{} functions and data, {} references, {} roots\n\
         {} unreachable ({} of {} bytes)\n",
        x.names.len(),
        x.graph.edge_count(),
        x.roots.len(),
        unreached.len(),
        lost,
        total,
    );
    let k = kept_totals(x, unreached);
    let (code, data, comdat, unknown) = if x.linker == hexcavator_size::xref::Linker::MachO {
        (
            "code kept with other code",
            "data kept with other data",
            "maybe unreferenced atoms (no -dead_strip, exports, or references not seen)",
            "in no compile unit",
        )
    } else if x.linker == hexcavator_size::xref::Linker::Elf {
        (
            "code in sections with other code (compile with -ffunction-sections)",
            "data in sections with other data (compile with -fdata-sections)",
            "maybe in sections of their own (no --gc-sections, KEEP, or references not seen)",
            "in no compile unit",
        )
    } else {
        (
            "code in sections that are not COMDATs (compile with /Gy)",
            "data in sections that are not COMDATs (compile with /Gw)",
            "in COMDATs (/OPT:NOREF, /INCLUDE, or references not seen)",
            "with no section contribution",
        )
    };
    for (bytes, what) in [
        (k.code, code),
        (k.data, data),
        (k.referenced, "that those refer to"),
        (k.comdat, comdat),
        (k.unknown, unknown),
    ] {
        if bytes > 0 {
            let _ = writeln!(out, "  {bytes:>10} bytes {what}");
        }
    }
    out
}

/// The bytes of `unreached` by why the linker kept them.
struct KeptTotals {
    code: u64,
    data: u64,
    referenced: u64,
    comdat: u64,
    unknown: u64,
}

fn kept_totals(x: &Xref, unreached: &[u32]) -> KeptTotals {
    let mut t = KeptTotals {
        code: 0,
        data: 0,
        referenced: 0,
        comdat: 0,
        unknown: 0,
    };
    for &n in unreached {
        let size = x.size(n);
        match x.kept(n) {
            Kept::WithSection { code: true } => t.code += size,
            Kept::WithSection { code: false } => t.data += size,
            Kept::ReferencedBy(_) => t.referenced += size,
            Kept::Comdat => t.comdat += size,
            Kept::Unknown => t.unknown += size,
        }
    }
    t
}

fn summary_json(x: &Xref, unreached: &[u32]) -> Value {
    let k = kept_totals(x, unreached);
    json!({
        "nodes": x.names.len(),
        "references": x.graph.edge_count(),
        "roots": x.roots.len(),
        "unreachableCount": unreached.len(),
        "unreachableSize": unreached.iter().map(|&n| x.size(n)).sum::<u64>(),
        "kept": {
            "codeNotComdat": k.code,
            "dataNotComdat": k.data,
            "referencedByThose": k.referenced,
            "comdat": k.comdat,
            "unknown": k.unknown,
        },
    })
}

fn node_json(x: &Xref, n: u32) -> Value {
    let node = x.graph.nodes()[n as usize];
    json!({
        "name": x.names[n as usize],
        "rva": format!("{:#x}", node.start),
        "size": node.end - node.start,
        "code": node.code,
        "object": x.object(n),
        "comdat": x.contribution[n as usize].map(|c| c.1),
    })
}

pub(crate) fn why_text(x: &Xref, n: u32) -> String {
    let mut out = String::new();
    let name = &x.names[n as usize];
    let Some((root, steps)) = x.reach.chain(n) else {
        let _ = writeln!(out, "{name}: no root reaches it");
        if x.kinds[n as usize].is_some() {
            let _ = writeln!(out, "  {}", kept_long(x, n));
        }
        let referrers = x.graph.referrers(n);
        if referrers.is_empty() {
            let _ = writeln!(out, "  and nothing refers to it");
        } else {
            let _ = writeln!(out, "  what refers to it (none reached):");
            for &(f, e) in referrers {
                let _ = writeln!(out, "    {} {} it", x.names[f as usize], e.verb());
            }
        }
        return out;
    };
    let reason = x
        .root_reason(root)
        .map(ToString::to_string)
        .unwrap_or_default();
    let _ = writeln!(out, "{name}:");
    let _ = writeln!(out, "  {}  ({reason})", x.names[root as usize]);
    for (e, to) in steps {
        let _ = writeln!(out, "    {} {}", e.verb(), x.names[to as usize]);
    }
    out
}

pub(crate) fn why_json(x: &Xref, n: u32) -> Value {
    let mut v = node_json(x, n);
    match x.reach.chain(n) {
        Some((root, steps)) => {
            v["reached"] = Value::from(true);
            v["root"] = json!({
                "name": x.names[root as usize],
                "reason": x.root_reason(root).map(ToString::to_string).unwrap_or_default(),
            });
            v["chain"] = steps
                .iter()
                .map(|&(e, to)| json!({"edge": e.verb(), "name": x.names[to as usize]}))
                .collect();
        }
        None => v["reached"] = Value::from(false),
    }
    v
}

fn refs_text(x: &Xref, n: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} ({} bytes{})",
        x.names[n as usize],
        x.size(n),
        if x.reach.is_reached(n) {
            ""
        } else {
            ", unreachable"
        }
    );
    let _ = writeln!(out, "  referred to by:");
    for &(f, e) in x.graph.referrers(n) {
        let _ = writeln!(out, "    {} {} it", x.names[f as usize], e.verb());
    }
    let _ = writeln!(out, "  refers to:");
    for &(t, e) in x.graph.references(n) {
        let _ = writeln!(out, "    {} {}", e.verb(), x.names[t as usize]);
    }
    out
}

fn refs_json(x: &Xref, n: u32) -> Value {
    let mut v = node_json(x, n);
    v["reached"] = Value::from(x.reach.is_reached(n));
    let list = |edges: &[(u32, hexcavator_xref::Edge)]| -> Value {
        edges
            .iter()
            .map(|&(m, e)| json!({"edge": e.verb(), "name": x.names[m as usize]}))
            .collect()
    };
    v["referrers"] = list(x.graph.referrers(n));
    v["references"] = list(x.graph.references(n));
    v
}

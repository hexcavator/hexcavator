//! `hexc types`: the layouts of a program's classes, structures, and unions
//! (from its debug information: a PDB, or DWARF), and the bytes their
//! padding wastes.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_debuginfo::layout::{Layout, Part, PartKind};
use hexcavator_image::Image;
use hexcavator_mmap::Mmap;
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc types [options] <image or debug file> [-- <base image or debug file>]

The classes, structures, and unions of a program (from its PDB or DWARF),
by the bytes their padding wastes; or one type's layout: each base, vfptr,
vbptr, member (bitfields by bit), and hole. With a base: the types whose
layout changed, and those added or removed.

options:
  -pdb <path>      the image's debug information: its PDB, or a file with
                   its DWARF (default: the one it names, or its own)
  -layout <name>   one type's layout (its name, or a regular expression that
                   matches just one)
  -ty <n>          one type's layout, by its reference (a layout's parts
                   give their types' as `expand`, with -json)
  -definition <name>  where one type is defined: its source file and line
                   (with -json: its name, file, and line)
  -refs <name>     what refers to one type: the types it is a base or a
                   member of, and the variables and functions whose types
                   name it
  -n <n>           rows to list (default 20; 0: all)
  -json            as JSON
  -filter <text>   with -json: the types whose name or mangled name has it
                   (any case; -regex: a regular expression), a page of them:
  -sort <by>       name (the default), mangled, size, or waste; -desc for the
                   largest (or last) first
  -from <n>        the first row (with -n, how many)";

struct Options {
    input: PathBuf,
    pdb: Option<PathBuf>,
    base: Option<PathBuf>,
    layout: Option<String>,
    /// `-ty`: one type's layout, by its reference (as `"expand"` gives it).
    ty: Option<u64>,
    refs: Option<String>,
    /// `-definition`: where one type is defined.
    definition: Option<String>,
    /// A page of the list (see [`page`]).
    filter: Option<String>,
    regex: bool,
    sort: Option<String>,
    desc: bool,
    from: usize,
    rows: usize,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        input: PathBuf::new(),
        pdb: None,
        base: None,
        layout: None,
        ty: None,
        refs: None,
        definition: None,
        filter: None,
        regex: false,
        sort: None,
        desc: false,
        from: 0,
        rows: 20,
        json: false,
    };
    let mut input = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            o.base = Some(it.next().ok_or("-- needs a base")?.into());
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
            Some("layout") => o.layout = Some(value("layout")?),
            Some("refs") => o.refs = Some(value("refs")?),
            Some("definition") => o.definition = Some(value("definition")?),
            Some("filter") => o.filter = Some(value("filter")?),
            Some("regex") => o.regex = true,
            Some("sort") => o.sort = Some(value("sort")?),
            Some("desc") => o.desc = true,
            Some("from") => {
                o.from = value("from")?
                    .parse()
                    .map_err(|_| "-from needs a number".to_string())?;
            }
            Some("ty") => {
                o.ty = Some(
                    value("ty")?
                        .parse()
                        .map_err(|_| "-ty needs a number".to_string())?,
                );
            }
            Some("n") => {
                o.rows = value("n")?
                    .parse()
                    .map_err(|_| "-n needs a number".to_string())?;
            }
            Some("json") => o.json = true,
            Some(other) if !other.is_empty() && input.is_none() && !Path::new(a).exists() => {
                return Err(format!("unknown option '{other}'"));
            }
            _ if input.is_none() => input = Some(PathBuf::from(a)),
            _ => return Err(format!("unexpected argument '{a}'")),
        }
    }
    o.input = input.ok_or("no image or PDB given")?;
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
            ereport!("hexc types: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match report(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc types: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs `f` with the debug information of `path` (an image, or a PDB or
/// file with DWARF) and the layouts of every type in it, most waste first.
pub(crate) fn with_layouts<R>(
    path: &Path,
    pdb: Option<&Path>,
    f: impl FnOnce(&DebugInfo<'_>, &Catalog) -> Result<R, String>,
) -> Result<R, String> {
    let show = |p: &Path| p.display().to_string();
    let data = Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
    // An image (but a PDB, or a file of DWARF given as one): its debug
    // information, found.
    let image =
        Image::parse(&data).is_ok() && (pdb.is_some() || hexcavator_pdb::check(&data).is_err());
    if image {
        drop(data);
        let opened = hexcavator_program::Opened::open(path, pdb)?;
        let debug = opened.debug_info()?;
        let mut files = vec![opened.path(), opened.debug_path()];
        files.extend(opened.split_paths());
        return layouts_of(&debug, &files, f);
    }
    let debug = DebugInfo::parse(&data).map_err(|e| format!("{}: {e}", show(path)))?;
    layouts_of(&debug, &[path], f)
}

/// `with_layouts`, the debug information read (from `files`: the image
/// first, then its debug files). The layouts are kept (`hexc serve` keeps
/// them for the next command) until the files change.
fn layouts_of<R>(
    debug: &DebugInfo<'_>,
    files: &[&Path],
    f: impl FnOnce(&DebugInfo<'_>, &Catalog) -> Result<R, String>,
) -> Result<R, String> {
    let show = |p: &Path| p.display().to_string();
    let catalog = hexcavator_program::cache::remember(files, "type catalog", || {
        let mut all = debug.layouts().map_err(|e| {
            format!(
                "{}: {e}",
                show(files.last().copied().unwrap_or(Path::new("")))
            )
        })?;
        all.sort_by(|a, b| b.waste().cmp(&a.waste()).then_with(|| a.name.cmp(&b.name)));
        Ok::<_, String>(Catalog::new(all))
    })?;
    f(debug, &catalog)
}

/// The layouts of a program's types (most waste first), and what a page
/// of them needs, made once: each one's mangled name, and the order of
/// their names (any case).
pub(crate) struct Catalog {
    all: Vec<Layout>,
    mangled: Vec<Option<String>>,
    /// Indexes, by name.
    by_name: Vec<u32>,
    /// Each one's place among them by name.
    rank: Vec<u32>,
}

impl Catalog {
    fn new(all: Vec<Layout>) -> Self {
        let mangled: Vec<Option<String>> = all.iter().map(mangled).collect();
        let lower: Vec<String> = all.iter().map(|l| l.name.to_lowercase()).collect();
        let mut by_name: Vec<u32> = (0..u32::try_from(all.len()).unwrap_or(u32::MAX)).collect();
        by_name.sort_by(|&a, &b| {
            let (a, b) = (a as usize, b as usize);
            lower[a]
                .cmp(&lower[b])
                .then_with(|| all[a].name.cmp(&all[b].name))
        });
        let mut rank = vec![0u32; all.len()];
        for (r, &i) in by_name.iter().enumerate() {
            rank[i as usize] = u32::try_from(r).unwrap_or(u32::MAX);
        }
        Catalog {
            all,
            mangled,
            by_name,
            rank,
        }
    }
}

impl std::ops::Deref for Catalog {
    type Target = [Layout];
    fn deref(&self) -> &[Layout] {
        &self.all
    }
}

fn report(o: &Options) -> Result<String, String> {
    with_layouts(&o.input, o.pdb.as_deref(), |debug, all| {
        if let Some(base) = &o.base {
            let old = with_layouts(base, None, |_, old| Ok(old.to_vec()))?;
            return Ok(diff(&old, all, o.rows, o.json));
        }
        if let Some(name) = &o.refs {
            let found = find(all, name)?;
            return Ok(refs(debug, all, found, o.json));
        }
        if let Some(name) = &o.definition {
            let found = find(all, name)?;
            let (file, line) = debug.type_definition(found.ty).ok_or_else(|| {
                format!(
                    "{}: the debug information doesn't say where it is defined",
                    found.name
                )
            })?;
            return Ok(if o.json {
                pretty(&serde_json::json!({ "name": found.name, "file": file, "line": line }))
            } else {
                format!("{file}:{line}\n")
            });
        }
        // One type's layout: by its name, or (-ty) by its reference.
        let one = match (&o.layout, o.ty) {
            (_, Some(ty)) => Some(
                debug
                    .layout(hexcavator_debuginfo::TypeRef(ty))
                    .ok_or_else(|| format!("type {ty} has no layout here"))?,
            ),
            (Some(name), None) => {
                let found = find(all, name)?;
                Some(debug.layout(found.ty).unwrap_or_else(|| found.clone()))
            }
            (None, None) => None,
        };
        if let Some(l) = one {
            return Ok(if o.json {
                pretty(&layout_json(debug, &l))
            } else {
                layout_text(&l)
            });
        }
        if o.json && (o.filter.is_some() || o.sort.is_some() || o.from > 0) {
            return page(all, o);
        }
        Ok(list(all, o.rows, o.json))
    })
}

/// A row of a page: name, mangled name, size, waste, union, incomplete.
type PageRow<'a> = (&'a str, Option<&'a str>, u64, u64, bool, bool);

/// A page of the list, for a viewer (`-json` with `-filter`, `-sort`, or
/// `-from`): the types whose name or mangled name has `-filter` (any case;
/// a regular expression with `-regex`), sorted by `-sort` (name, mangled,
/// size, or waste; `-desc` for largest or last first), `-n` of them from
/// `-from`: `{"types", "matched", "from", "list": [[name, mangled, size,
/// waste, union, incomplete], ...]}`.
fn page(cat: &Catalog, o: &Options) -> Result<String, String> {
    let all = &cat.all;
    let mangled_names = &cat.mangled;
    // (By name already: the catalog's order.)
    let order = cat.by_name.iter().map(|&i| i as usize);
    let mut kept: Vec<usize> = match o.filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        None => order.collect(),
        Some(f) if o.regex => {
            let re = regex::RegexBuilder::new(f)
                .case_insensitive(true)
                .build()
                .map_err(|e| format!("-filter: {e}"))?;
            order
                .filter(|&i| {
                    re.is_match(&all[i].name)
                        || mangled_names[i].as_deref().is_some_and(|m| re.is_match(m))
                })
                .collect()
        }
        Some(f) => {
            let needle = f.to_lowercase();
            let has = |s: &str| {
                // (ASCII names, the usual: no allocation.)
                if s.is_ascii() && needle.is_ascii() {
                    s.as_bytes()
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
                } else {
                    s.to_lowercase().contains(&needle)
                }
            };
            order
                .filter(|&i| has(&all[i].name) || mangled_names[i].as_deref().is_some_and(has))
                .collect()
        }
    };
    let by = o.sort.as_deref().unwrap_or("name");
    // Ties (and the name order) by the name's rank.
    match by {
        "size" => kept.sort_by_key(|&i| (all[i].size, cat.rank[i])),
        "waste" => kept.sort_by_key(|&i| (all[i].waste(), cat.rank[i])),
        "mangled" => kept.sort_by(|&a, &b| {
            mangled_names[a]
                .cmp(&mangled_names[b])
                .then(cat.rank[a].cmp(&cat.rank[b]))
        }),
        _ => {}
    }
    if o.desc {
        kept.reverse();
    }
    let from = o.from.min(kept.len());
    let to = if o.rows == 0 {
        kept.len()
    } else {
        (from + o.rows).min(kept.len())
    };
    let rows: Vec<PageRow<'_>> = kept[from..to]
        .iter()
        .map(|&i| {
            let l = &all[i];
            (
                l.name.as_str(),
                mangled_names[i].as_deref(),
                l.size,
                l.waste(),
                l.union,
                l.incomplete,
            )
        })
        .collect();
    let waste: u64 = all.iter().map(Layout::waste).sum();
    let mut out = serde_json::to_string(&json!({
        "types": all.len(),
        "waste": waste,
        "matched": kept.len(),
        "from": from,
        "list": rows,
    }))
    .unwrap_or_default();
    out.push('\n');
    Ok(out)
}

fn list(all: &[Layout], rows: usize, json_out: bool) -> String {
    let shown = if rows == 0 {
        all.len()
    } else {
        rows.min(all.len())
    };
    let waste: u64 = all.iter().map(Layout::waste).sum();
    let incomplete = all.iter().filter(|l| l.incomplete).count();
    if json_out {
        let list: Vec<Value> = all[..shown]
            .iter()
            .map(|l| {
                json!({"name": l.name, "mangled": mangled(l), "size": l.size, "union": l.union,
                       "waste": l.waste(), "padding": l.padding,
                       "bitPadding": l.bit_padding, "incomplete": l.incomplete})
            })
            .collect();
        // (Compact: a large program has hundreds of thousands.)
        let mut s = serde_json::to_string(
            &json!({"types": all.len(), "incomplete": incomplete, "waste": waste, "list": list}),
        )
        .unwrap_or_default();
        s.push('\n');
        return s;
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} types; their padding wastes {waste} bytes (per instance), most first:",
        all.len()
    );
    let _ = writeln!(out, "  {:>8}  {:>8}  name", "size", "wasted");
    for l in &all[..shown] {
        let _ = writeln!(out, "  {:>8}  {:>8}  {}", l.size, l.waste(), l.name);
    }
    if shown < all.len() {
        let _ = writeln!(out, "  ({} more; -n 0 lists all)", all.len() - shown);
    }
    if incomplete > 0 {
        let _ = writeln!(
            out,
            "({incomplete} types have a member of a type with no definition in the debug information: their padding isn't known)"
        );
    }
    out
}

/// A type's mangled (decorated) name: its PDB's unique name, or for one
/// from DWARF (which has none for C++ types), its Itanium name where it can
/// be made exactly (see [`itanium`]).
fn mangled(l: &Layout) -> Option<String> {
    if l.key != l.name {
        return Some(l.key.clone());
    }
    itanium(&l.name)
}

/// A C++ type's Itanium mangled name, as a typeinfo name spells it
/// (`N3foo3barE`), for names of identifiers (nested, `std::` first) with
/// template arguments that are built-in types; `None` for any other (one
/// whose mangling would need substitutions, say), rather than a wrong one.
pub(crate) fn itanium(name: &str) -> Option<String> {
    fn builtin(t: &str) -> Option<&'static str> {
        Some(match t {
            "void" => "v",
            "bool" => "b",
            "char" => "c",
            "signed char" => "a",
            "unsigned char" => "h",
            "short" => "s",
            "unsigned short" => "t",
            "int" => "i",
            "unsigned int" => "j",
            "long" => "l",
            "unsigned long" => "m",
            "long long" => "x",
            "unsigned long long" => "y",
            "float" => "f",
            "double" => "d",
            "long double" => "e",
            "wchar_t" => "w",
            "char8_t" => "Du",
            "char16_t" => "Ds",
            "char32_t" => "Di",
            _ => return None,
        })
    }
    fn ident(s: &str) -> bool {
        !s.is_empty()
            && !s.as_bytes()[0].is_ascii_digit()
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }
    // The components, split at `::` outside template arguments.
    let mut parts: Vec<&str> = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                parts.push(&name[start..i]);
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&name[start..]);
    let mut out = String::new();
    let std = parts.first() == Some(&"std") && parts.len() > 1;
    let names = if std { &parts[1..] } else { &parts[..] };
    let mut encoded: Vec<String> = Vec::new();
    for p in names {
        let (id, args) = match p.find('<') {
            Some(at) => {
                let inner = p[at + 1..].strip_suffix('>')?.trim();
                (&p[..at], Some(inner))
            }
            None => (*p, None),
        };
        if !ident(id) {
            return None;
        }
        let mut e = format!("{}{id}", id.len());
        if let Some(inner) = args {
            e.push('I');
            for a in inner.split(',') {
                e.push_str(builtin(a.trim())?);
            }
            e.push('E');
        }
        encoded.push(e);
    }
    // (A repeated component would be a substitution.)
    for (k, e) in encoded.iter().enumerate() {
        if encoded[..k].contains(e) {
            return None;
        }
    }
    match (std, encoded.len()) {
        (false, 1) => out.push_str(&encoded[0]),
        (true, 1) => {
            out.push_str("St");
            out.push_str(&encoded[0]);
        }
        (std, _) => {
            out.push('N');
            if std {
                out.push_str("St");
            }
            for e in &encoded {
                out.push_str(e);
            }
            out.push('E');
        }
    }
    Some(out)
}

/// Whether the type name `hay` names `needle` (as itself: not a longer
/// name, nor a type nested in it), as `Foo`, `Foo *`, `const Foo &`, or a
/// template argument.
fn names_type(hay: &str, needle: &str) -> bool {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let h = hay.as_bytes();
    let mut from = 0;
    while let Some(at) = hay[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before_ok = start == 0 || (!ident(h[start - 1]) && h[start - 1] != b':');
        let after_ok = end == h.len() || (!ident(h[end]) && !hay[end..].starts_with("::"));
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// What refers to the type `target`: the types it is a base or member of
/// (a pointer to it, an array of it, a template argument), and the
/// variables and functions whose types name it.
fn refs(debug: &DebugInfo<'_>, all: &[Layout], target: &Layout, json_out: bool) -> String {
    let name = target.name.as_str();
    let mut types: Vec<(String, String, String)> = Vec::new();
    for l in all {
        // (PDB layouts' parts are named only in a type's own layout.)
        let full = debug.layout(l.ty);
        let l = full.as_ref().unwrap_or(l);
        for p in &l.parts {
            let how = match p.kind {
                PartKind::Base => "base",
                PartKind::VirtualBase => "virtual base",
                PartKind::Member => "member",
                _ => continue,
            };
            if names_type(&p.type_name, name) {
                types.push((
                    l.name.clone(),
                    how.to_string(),
                    if p.kind == PartKind::Member {
                        format!("{} {}", p.type_name, p.name)
                    } else {
                        p.type_name.clone()
                    },
                ));
            }
        }
    }
    types.sort();
    types.dedup();
    let mut symbols: Vec<(String, &'static str, String)> = Vec::new();
    if let Ok(list) = debug.symbols() {
        use hexcavator_debuginfo::{SymbolKind, TypeRef};
        let mut seen = std::collections::HashSet::new();
        for s in &list {
            let kind = match s.kind {
                SymbolKind::Function => "function",
                SymbolKind::Data => "variable",
                _ => continue,
            };
            if s.type_index == 0 || !seen.insert((s.name.clone(), s.type_index)) {
                continue;
            }
            let t = debug.type_name(TypeRef(s.type_index));
            if names_type(&t, name) {
                symbols.push((s.name.clone(), kind, t));
            }
        }
    }
    symbols.sort();
    if json_out {
        return pretty(&json!({
            "name": name,
            "types": types.iter().map(|(t, how, part)| json!({"type": t, "how": how, "part": part})).collect::<Vec<_>>(),
            "symbols": symbols.iter().map(|(n, k, t)| json!({"name": n, "kind": k, "type": t})).collect::<Vec<_>>(),
        }));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{name}: in {} types, {} variables and functions",
        types.len(),
        symbols.len()
    );
    if !types.is_empty() {
        let _ = writeln!(out, "\nTypes it is in:");
        for (t, how, part) in &types {
            let _ = writeln!(out, "  {t}  ({how}: {part})");
        }
    }
    if !symbols.is_empty() {
        let _ = writeln!(out, "\nVariables and functions whose types name it:");
        for (n, k, t) in &symbols {
            let _ = writeln!(out, "  {k:<9} {n}  ({t})");
        }
    }
    out
}

/// The type `name` names: exactly, or the one a regular expression matches.
fn find<'a>(all: &'a [Layout], name: &str) -> Result<&'a Layout, String> {
    if let Some(l) = all.iter().find(|l| l.name == name) {
        return Ok(l);
    }
    let re = regex::Regex::new(name)
        .map_err(|e| format!("'{name}' is no type's name, nor a regular expression: {e}"))?;
    let found: Vec<&Layout> = all.iter().filter(|l| re.is_match(&l.name)).collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("no type named '{name}'")),
        many => Err(format!(
            "'{name}' matches {} types ({}{}); give one exactly",
            many.len(),
            many.iter()
                .take(5)
                .map(|l| l.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            if many.len() > 5 { ", ..." } else { "" }
        )),
    }
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

/// Where a part is: its offset, and for bits, `offset.bit`.
fn at(p: &Part) -> String {
    match p.bits {
        Some((bit, _)) => format!("{}.{bit}", p.offset),
        None => p.offset.to_string(),
    }
}

/// How big a part is: bytes, or for bits, `:n`.
fn extent(p: &Part) -> String {
    match p.bits {
        Some((_, n)) => format!(":{n}"),
        None => p.size.to_string(),
    }
}

fn label(p: &Part) -> String {
    match p.kind {
        PartKind::Member => p.name.clone(),
        k => format!("[{}]", k.label()),
    }
}

fn layout_text(l: &Layout) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}{} ({} bytes; {}{})",
        if l.union { "union " } else { "" },
        l.name,
        l.size,
        if l.incomplete {
            "padding unknown: a member's type has no definition here".to_string()
        } else {
            format!("{} wasted", l.waste())
        },
        if l.bit_padding.is_multiple_of(8) {
            String::new()
        } else {
            format!(", and {} bits", l.bit_padding % 8)
        }
    );
    let rows: Vec<(String, String, String, String)> = l
        .parts
        .iter()
        .map(|p| (at(p), extent(p), label(p), p.type_name.clone()))
        .collect();
    let w0 = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(6);
    let w1 = rows.iter().map(|r| r.1.len()).max().unwrap_or(0).max(4);
    let w2 = rows.iter().map(|r| r.2.chars().count()).max().unwrap_or(0);
    let _ = writeln!(out, "  {:>w0$}  {:>w1$}  part", "offset", "size");
    for (a, s, n, t) in rows {
        let _ = writeln!(
            out,
            "  {a:>w0$}  {s:>w1$}  {}",
            if t.is_empty() {
                n
            } else {
                format!("{n:<w2$}  {t}")
            }
        );
    }
    out
}

/// The class, structure, or union a part's type is (through cv-modifiers
/// and arrays), to show its own layout below the part's.
fn expandable(debug: &DebugInfo<'_>, ty: hexcavator_debuginfo::TypeRef) -> Option<u64> {
    use hexcavator_debuginfo::TypeShape;
    let mut at = ty;
    for _ in 0..32 {
        match debug.type_shape(at) {
            TypeShape::Modified { base, .. } => at = base,
            TypeShape::Array { element, .. } => at = element,
            TypeShape::Udt { .. } => return Some(at.0),
            _ => return None,
        }
    }
    None
}

fn layout_json(debug: &DebugInfo<'_>, l: &Layout) -> Value {
    json!({
        "name": l.name,
        "size": l.size,
        "union": l.union,
        "waste": l.waste(),
        "padding": l.padding,
        "bitPadding": l.bit_padding,
        "incomplete": l.incomplete,
        "parts": l.parts.iter().map(|p| json!({
            "offset": p.offset,
            "size": p.size,
            "bit": p.bits.map(|b| b.0),
            "bits": p.bits.map(|b| b.1),
            "kind": p.kind.label(),
            "name": p.name,
            "type": p.type_name,
            "expand": match p.kind {
                PartKind::Base | PartKind::VirtualBase | PartKind::Member if p.ty.0 != 0 => expandable(debug, p.ty),
                _ => None,
            },
        })).collect::<Vec<_>>(),
    })
}

/// The types whose layout changed between `old` and `new`, and those added
/// or removed.
fn diff(old: &[Layout], new: &[Layout], rows: usize, json_out: bool) -> String {
    let d = hexcavator_debuginfo::layout::compare(old, new);
    let (changed, added, removed) = (d.changed, d.added, d.removed);
    let take = |len: usize| if rows == 0 { len } else { rows.min(len) };
    if json_out {
        return pretty(&json!({
            "changed": changed[..take(changed.len())].iter().map(|(o, n)| json!({
                "name": n.name,
                "oldSize": o.size, "newSize": n.size,
                "oldWaste": o.waste(), "newWaste": n.waste(),
            })).collect::<Vec<_>>(),
            "changedCount": changed.len(),
            "added": added.iter().take(take(added.len())).map(|l| json!({"name": l.name, "size": l.size})).collect::<Vec<_>>(),
            "addedCount": added.len(),
            "removed": removed.iter().take(take(removed.len())).map(|l| json!({"name": l.name, "size": l.size})).collect::<Vec<_>>(),
            "removedCount": removed.len(),
        }));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Types: {} changed layout, {} added, {} removed",
        changed.len(),
        added.len(),
        removed.len()
    );
    if !changed.is_empty() {
        let _ = writeln!(
            out,
            "\nChanged (size, and wasted bytes), largest change first:"
        );
        for (o, n) in &changed[..take(changed.len())] {
            let _ = writeln!(
                out,
                "  {:>+8}  {} ({} -> {} bytes; wasted {} -> {})",
                i128::from(n.size) - i128::from(o.size),
                n.name,
                o.size,
                n.size,
                o.waste(),
                n.waste()
            );
        }
    }
    for (title, list) in [("Added", &added), ("Removed", &removed)] {
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{title}:");
        for l in list.iter().take(take(list.len())) {
            let _ = writeln!(out, "  {:>8}  {}", l.size, l.name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{itanium, names_type};

    #[test]
    fn itanium_type_names_round_trip() {
        for (name, want) in [
            ("Padded", Some("6Padded")),
            ("foo::bar", Some("N3foo3barE")),
            ("std::string_view_like", Some("St16string_view_like")),
            ("std::a::b", Some("NSt1a1bE")),
            ("Pair<int, unsigned long>", Some("4PairIimE")),
            ("ns::Box<char16_t>", Some("N2ns3BoxIDsEE")),
            // (A repeated component, or a class argument: substitutions.)
            ("a::a", None),
            ("Vec<Foo>", None),
            ("(anonymous namespace)::X", None),
            ("Func<int (*)(int)>", None),
        ] {
            let got = itanium(name);
            assert_eq!(got.as_deref(), want, "{name}");
            // As a typeinfo name, our demangler reads it back.
            if let Some(m) = got {
                let back = hexcavator_demangle::itanium::demangle(&format!("_ZTS{m}")).unwrap();
                assert_eq!(back, format!("typeinfo name for {name}"), "{m}");
            }
        }
    }

    #[test]
    fn a_type_named_in_another() {
        assert!(names_type("Foo *", "Foo"));
        assert!(names_type("const Foo &", "Foo"));
        assert!(names_type("std::vector<Foo, std::allocator<Foo> >", "Foo"));
        assert!(!names_type("FooBar", "Foo"));
        assert!(!names_type("Foo::Inner", "Foo"));
        assert!(!names_type("ns::Foo", "Foo"));
        assert!(names_type("ns::Foo", "ns::Foo"));
    }
}

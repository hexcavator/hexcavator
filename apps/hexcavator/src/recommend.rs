//! `hexc recommend`: changes to a build that would make an image smaller,
//! each with the bytes it would save.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_size::findings;
use hexcavator_size::recommend::{Link, Recommendation, Toolchain, recommend};
use serde_json::json;

pub const USAGE: &str = "\
usage: hexc recommend [options] <image>

Changes to the build that would make an image smaller (PE, ELF, or
Mach-O), largest saving first, each measured from the image and its debug
information (what can't be measured isn't recommended), in the terms of
its toolchain (MSVC's, GCC's and Clang's, or Apple's):

- compile an object with /Gy or /Gw (-ffunction-sections or
  -fdata-sections), when it has functions or data nothing reaches that the
  linker kept with the sections they share;
- link with /OPT:REF or /OPT:ICF (--gc-sections or -dead_strip, --icf),
  when the link didn't, by the unreferenced functions and data and the
  identical functions there are (the link's options come from the PDB's
  record of its command line; elsewhere, the image is the evidence);
- define a variable once, when copies of it are in several objects;
- hide exports (ELF shared objects, Mach-O images): template
  instantiations and inline functions (-fvisibility=hidden); a library's
  calls to its own exports through the PLT (-Bsymbolic-functions); and,
  given its importers, what none of them imports (-fvisibility=hidden, a
  version script), or a Mach-O executable's exports, which only plugins
  could use.

Without debug information (none given, and none found), only what the
image's own structure shows: its exports, relative relocations as RELR
and a .hash beside .gnu.hash (ELF), or custom sections (WebAssembly).

options:
  -pdb <path>   its debug information: a PDB, or a file with its DWARF
                (or -debug; default: its own, or the one it names)
  -importers <path>
                an executable or library that loads it, or a directory of
                them (searched, with its subdirectories, for those that do):
                what they import of its exports is kept (more than once
                for more)
  -json         as JSON";

pub fn run(args: &[String]) -> ExitCode {
    let mut pdb = None;
    let mut json = false;
    let mut importers = Vec::new();
    let mut image = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-pdb" | "/pdb" | "-debug" | "/debug" => match it.next() {
                Some(p) => pdb = Some(PathBuf::from(p)),
                None => return usage("-pdb needs a path"),
            },
            "-json" | "/json" => json = true,
            "-importers" | "/importers" => match it.next() {
                Some(p) => importers.push(PathBuf::from(p)),
                None => return usage("-importers needs a path"),
            },
            a if image.is_none() => image = Some(PathBuf::from(a)),
            a => return usage(&format!("unexpected argument '{a}'")),
        }
    }
    let Some(image) = image else {
        return usage("no image given");
    };
    match report(&image, pdb.as_deref(), json, &importers) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc recommend: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage(message: &str) -> ExitCode {
    ereport!("hexc recommend: {message}\n\n{USAGE}");
    ExitCode::from(2)
}

fn report(
    path: &Path,
    pdb: Option<&Path>,
    json: bool,
    importers: &[PathBuf],
) -> Result<String, String> {
    let show = |p: &Path| p.display().to_string();
    let opened = match hexcavator_program::Opened::open(path, pdb) {
        Ok(o) => o,
        // No debug information to be found: what the image's structure
        // shows, which needs none.
        Err(hexcavator_program::Error::NoDebug { .. }) if pdb.is_none() => {
            let map =
                hexcavator_mmap::Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
            let image =
                hexcavator_image::Image::parse(&map).map_err(|e| format!("{}: {e}", show(path)))?;
            let mut r = structural_only(&image);
            with_exports(&mut r, &image, path, importers);
            return Ok(if json { as_json(&r) } else { as_text(&r) });
        }
        Err(e) => return Err(e.to_string()),
    };
    let program = opened.program()?;
    let (image, debug) = (&program.image, &program.debug);
    let model = program.model()?;
    let syms = program.symbols()?;
    let x = hexcavator_size::xref::build(image, debug, model, syms)
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let mut r = recommendations(image, debug, model, &x, syms);
    with_exports(&mut r, image, path, importers);
    Ok(if json { as_json(&r) } else { as_text(&r) })
}

/// Adds what an image's exports recommend ([`hexcavator_size::exports`]),
/// judged by what `importers` (files, or directories of them) import of
/// it, if any are given; largest saving first with the rest.
pub(crate) fn with_exports(
    r: &mut Recommended,
    image: &hexcavator_image::Image<'_>,
    path: &Path,
    importers: &[PathBuf],
) {
    use hexcavator_size::exports;
    let Some(ex) = exports::exports(image) else {
        return;
    };
    let file_name = path.file_name().map(|n| n.as_encoded_bytes().to_vec());
    let name = ex.name.map(<[u8]>::to_vec).or(file_name);
    let imports = (!importers.is_empty()).then(|| scan_importers(importers, name.as_deref()));
    let macho = image.macho().is_some();
    let demangle = |n: &[u8]| -> String {
        let raw = String::from_utf8_lossy(n);
        // (Mach-O's names have a `_` before the mangled name.)
        let mangled = if macho {
            raw.strip_prefix('_').unwrap_or(&raw)
        } else {
            &raw
        };
        let mut out = String::new();
        if hexcavator_demangle::itanium::Demangler::new().demangle_into(mangled, &mut out) {
            out
        } else {
            mangled.to_string()
        }
    };
    r.recs
        .extend(exports::recommend(&ex, imports.as_ref(), &demangle));
    r.recs.sort_by_key(|r| std::cmp::Reverse(r.saving));
    r.importers = imports.map(|i| i.importers);
}

/// What the importers given (files, or directories searched with their
/// subdirectories) import of the image named `name`, read in parallel.
fn scan_importers(paths: &[PathBuf], name: Option<&[u8]>) -> hexcavator_size::exports::Imports {
    let mut files = Vec::new();
    for p in paths {
        gather(p, 0, &mut files);
    }
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(files.len().max(1));
    let chunk = files.len().div_ceil(threads).max(1);
    let found: Vec<Vec<Vec<u8>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = files
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .filter_map(|p| {
                            let map = hexcavator_mmap::Mmap::open(p).ok()?;
                            hexcavator_size::exports::imports_of(&map, name)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    hexcavator_size::exports::Imports {
        importers: found.len(),
        names: found.into_iter().flatten().collect(),
    }
}

/// The most files searched for importers.
const MAX_IMPORTERS: usize = 1 << 16;

/// The files at `path`: it, or those in it and its subdirectories.
fn gather(path: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    if out.len() >= MAX_IMPORTERS {
        return;
    }
    match std::fs::metadata(path) {
        Ok(m) if m.is_dir() && depth < 8 => {
            let Ok(dir) = std::fs::read_dir(path) else {
                return;
            };
            let mut entries: Vec<PathBuf> = dir.filter_map(Result::ok).map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                gather(&e, depth + 1, out);
            }
        }
        Ok(m) if m.is_file() => out.push(path.to_path_buf()),
        _ => {}
    }
}

/// The recommendations for a program, with what they were judged by.
pub(crate) struct Recommended {
    pub recs: Vec<Recommendation>,
    pub toolchain: Toolchain,
    /// The link's options, if its debug information records them.
    pub link: Option<Link>,
    /// What the link did: its options, or else as the image shows it
    /// ([`Link::evidence`]); `None` without debug information, or when the
    /// image can't show it (see `unsectioned`).
    pub judged: Option<Link>,
    /// Whether every object whose options are recorded was compiled without
    /// -ffunction-sections (on ELF): the link could neither collect nor
    /// fold functions, whatever its options.
    pub unsectioned: bool,
    /// Whether there was debug information (else only what the image's
    /// structure shows).
    pub debug: bool,
    /// How many importers of the image were read (`-importers`), if any
    /// were given.
    pub importers: Option<usize>,
}

/// The recommendations for an image without debug information: what its
/// structure shows ([`hexcavator_size::recommend::structural`]).
/// What an image's strings recommend (`hexcavator_size::recommend::strings`),
/// a string in `symbols` (data, by start) being in named data unless the
/// symbol is a string literal's (a PDB's `` `string' ``).
fn string_recommendations(
    image: &hexcavator_image::Image<'_>,
    toolchain: Toolchain,
    symbols: &[(u64, u64, String)],
) -> Vec<Recommendation> {
    let named = |at: u64| {
        hexcavator_size::relocations::containing(symbols, at).is_some_and(|i| {
            let n = symbols[i].2.as_str();
            n != "`string'" && !n.starts_with(".L") && n != "(anonymous)"
        })
    };
    hexcavator_size::recommend::strings(image, toolchain, &named)
}

pub(crate) fn structural_only(image: &hexcavator_image::Image<'_>) -> Recommended {
    let mut recs = hexcavator_size::recommend::structural(image);
    let toolchain = if image.macho().is_some() {
        Toolchain::Apple
    } else if image.pe().is_some() {
        Toolchain::Msvc
    } else {
        Toolchain::Gnu
    };
    let own =
        crate::relocations::demangled(hexcavator_size::relocations::image_symbols(image), image);
    recs.extend(string_recommendations(image, toolchain, &own));
    recs.sort_by_key(|r| std::cmp::Reverse(r.saving));
    Recommended {
        recs,
        toolchain,
        link: None,
        judged: None,
        unsectioned: false,
        debug: false,
        importers: None,
    }
}

pub(crate) fn recommendations(
    image: &hexcavator_image::Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    model: &hexcavator_size::Model,
    x: &hexcavator_size::xref::Xref,
    syms: &[hexcavator_size::symbols::Symbol],
) -> Recommended {
    let toolchain = Toolchain::of(image, debug);
    let link = debug
        .linker_info()
        .ok()
        .and_then(|i| i.command_line().map(Link::from_command_line));
    let compiled = hexcavator_size::compiled::Compiled::of(debug);
    // (Objects compiled without -ffunction-sections leave nothing to judge
    // an ELF link's options by.)
    let unsectioned = link.is_none() && image.elf().is_some() && compiled.no_function_sections();
    let judged = link.unwrap_or_else(|| Link::evidence(image, debug, &compiled));
    let classes = hexcavator_size::fingerprint::build(
        image,
        model,
        x,
        hexcavator_size::fingerprint::Mode::Foldable,
    )
    .classes;
    // Identical functions matter only if the link didn't fold them.
    let foldable = (!judged.opt_icf).then_some(&classes[..]);
    let duplicates = findings::duplicate_data(image, debug, syms);
    let mut recs = recommend(x, toolchain, Some(judged), foldable, &duplicates, &compiled);
    // Functions inlined where calls would cost less.
    if let Ok(sites) = debug.inline_sites() {
        let defined: rustc_hash::FxHashSet<&str> = syms
            .iter()
            .filter(|s| matches!(s.kind, hexcavator_size::symbols::SymbolKind::Function))
            .map(|s| findings::strip_parameters(&s.name))
            .collect();
        let weighed =
            hexcavator_size::inlining::weigh(sites, image.arch(), &|n| defined.contains(n));
        recs.extend(hexcavator_size::recommend::inlining(
            &weighed,
            toolchain,
            image.arch(),
        ));
    }
    // Pointer-heavy data, whose pointers each cost a relocation.
    let mut data: Vec<(u64, u64, String)> = syms
        .iter()
        .filter(|s| {
            s.size.vm > 0 && !matches!(s.kind, hexcavator_size::symbols::SymbolKind::Function)
        })
        .map(|s| (s.addr, s.addr + s.size.vm, s.name.clone()))
        .collect();
    data.sort_by_key(|s| s.0);
    // (The image's own symbols where the debug information has none.)
    let data = hexcavator_size::relocations::merge_symbols(
        hexcavator_size::relocations::merge_symbols(
            data,
            crate::relocations::debug_file_symbols(debug),
        ),
        crate::relocations::demangled(hexcavator_size::relocations::image_symbols(image), image),
    );
    let relocs = hexcavator_size::relocations::relocations(image);
    recs.extend(hexcavator_size::recommend::pointer_tables(
        &relocs, &data, toolchain,
    ));
    // The build's paths, and string literals with copies.
    recs.extend(string_recommendations(image, toolchain, &data));
    // Templates' instantiations alike but for constants, sizes, callees.
    let near = hexcavator_size::fingerprint::near_identical(image, model, x, &classes);
    recs.extend(hexcavator_size::recommend::near_identical(&near));
    // And what the image's structure says, largest saving first with the
    // rest.
    recs.extend(hexcavator_size::recommend::structural(image));
    recs.sort_by_key(|r| std::cmp::Reverse(r.saving));
    Recommended {
        recs,
        toolchain,
        link,
        judged: (!unsectioned).then_some(judged),
        unsectioned,
        debug: true,
        importers: None,
    }
}

fn toolchain_name(t: Toolchain) -> &'static str {
    match t {
        Toolchain::Msvc => "msvc",
        Toolchain::Gnu => "gnu",
        Toolchain::Apple | Toolchain::AppleLd => "apple",
    }
}

pub(crate) fn as_text(r: &Recommended) -> String {
    let recs = &r.recs;
    let mut out = String::new();
    match (r.link, r.judged) {
        (Some(l), _) => {
            let on = |b: bool| if b { "on" } else { "off" };
            let _ = writeln!(
                out,
                "The link: /OPT:REF {}, /OPT:ICF {}.",
                on(l.opt_ref),
                on(l.opt_icf)
            );
        }
        (None, Some(judged)) => {
            let did = |b: bool| if b { "did" } else { "didn't" };
            let _ = writeln!(
                out,
                "The link's options aren't recorded: as the image shows it, the link {} collect unreferenced functions ({}) and {} fold identical ones (ICF).",
                did(judged.opt_ref),
                match r.toolchain {
                    Toolchain::Msvc => "/OPT:REF",
                    Toolchain::Gnu => "--gc-sections",
                    Toolchain::Apple | Toolchain::AppleLd => "-dead_strip",
                },
                did(judged.opt_icf)
            );
            if r.toolchain == Toolchain::AppleLd {
                out.push_str(
                    "(Apple's ld linked it: it folds identical functions unless given -no_deduplicate, which clang gives it when it links at -O0 or -O1.)\n",
                );
            }
        }
        (None, None) if r.unsectioned => out.push_str(
            "The link's options aren't recorded, and its objects were compiled without -ffunction-sections, so the image can't show whether the link collected unreferenced functions (--gc-sections) or folded identical ones (ICF): neither could have.\n",
        ),
        (None, None) if r.debug => {}
        (None, None) => out.push_str(
            "No debug information: only what the image's structure shows (give it with -debug for the rest).\n",
        ),
    }
    if recs.is_empty() {
        out.push_str("No recommendations: nothing measurable to save.\n");
        return out;
    }
    let total: u64 = recs.iter().map(|r| r.saving).sum();
    let _ = writeln!(
        out,
        "{} recommendation{}, saving {total} bytes in all:",
        recs.len(),
        if recs.len() == 1 { "" } else { "s" }
    );
    for r in recs {
        let _ = writeln!(out, "\n  {:>10}  {}", r.saving, r.advice);
        for (name, size) in &r.examples {
            let _ = writeln!(out, "  {size:>10}    {name}");
        }
    }
    out
}

pub(crate) fn as_json(r: &Recommended) -> String {
    let (recs, link) = (&r.recs, r.link);
    let list: Vec<serde_json::Value> = recs
        .iter()
        .map(|r| {
            json!({
                "kind": r.kind,
                "advice": r.advice,
                "saving": r.saving,
                "examples": r.examples.iter().map(|(n, s)| json!({"name": n, "size": s})).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut s = serde_json::to_string_pretty(&json!({
        "toolchain": toolchain_name(r.toolchain),
        "link": link.map(|l| json!({"optRef": l.opt_ref, "optIcf": l.opt_icf})),
        // (What the link did: its options, or as the image shows it.)
        // (Absent without debug information, which has only what the
        // image's structure shows.)
        "judged": r.judged.map(|l| json!({"optRef": l.opt_ref, "optIcf": l.opt_icf})),
        "debug": r.debug,
        // (How many of the importers given load it.)
        "importers": r.importers,
        "saving": recs.iter().map(|r| r.saving).sum::<u64>(),
        "recommendations": list,
    }))
    .unwrap_or_default();
    s.push('\n');
    s
}

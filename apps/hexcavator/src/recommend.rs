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
- define a variable once, when copies of it are in several objects.

options:
  -pdb <path>   its debug information: a PDB, or a file with its DWARF
                (or -debug; default: its own, or the one it names)
  -json         as JSON";

pub fn run(args: &[String]) -> ExitCode {
    let mut pdb = None;
    let mut json = false;
    let mut image = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-pdb" | "/pdb" | "-debug" | "/debug" => match it.next() {
                Some(p) => pdb = Some(PathBuf::from(p)),
                None => return usage("-pdb needs a path"),
            },
            "-json" | "/json" => json = true,
            a if image.is_none() => image = Some(PathBuf::from(a)),
            a => return usage(&format!("unexpected argument '{a}'")),
        }
    }
    let Some(image) = image else {
        return usage("no image given");
    };
    match report(&image, pdb.as_deref(), json) {
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

fn report(path: &Path, pdb: Option<&Path>, json: bool) -> Result<String, String> {
    let show = |p: &Path| p.display().to_string();
    let opened = hexcavator_program::Opened::open(path, pdb)?;
    let program = opened.program()?;
    let (image, debug) = (&program.image, &program.debug);
    let model = program.model()?;
    let syms = program.symbols()?;
    let x = hexcavator_size::xref::build(image, debug, model, syms)
        .map_err(|e| format!("{}: {e}", show(path)))?;
    let r = recommendations(image, debug, model, &x, syms);
    Ok(if json { as_json(&r) } else { as_text(&r) })
}

/// The recommendations for a program, with what they were judged by.
pub(crate) struct Recommended {
    pub recs: Vec<Recommendation>,
    pub toolchain: Toolchain,
    /// The link's options, if its debug information records them.
    pub link: Option<Link>,
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
    let judged = link.unwrap_or_else(Link::judged);
    // Identical functions matter only if the link didn't fold them.
    let foldable = (!judged.opt_icf).then(|| {
        hexcavator_size::fingerprint::build(
            image,
            model,
            x,
            hexcavator_size::fingerprint::Mode::Foldable,
        )
        .classes
    });
    let duplicates = findings::duplicate_data(image, syms);
    let mut recs = recommend(x, toolchain, Some(judged), foldable.as_deref(), &duplicates);
    // And what the image's structure says, largest saving first with the
    // rest.
    recs.extend(hexcavator_size::recommend::structural(image));
    recs.sort_by_key(|r| std::cmp::Reverse(r.saving));
    Recommended {
        recs,
        toolchain,
        link,
    }
}

fn toolchain_name(t: Toolchain) -> &'static str {
    match t {
        Toolchain::Msvc => "msvc",
        Toolchain::Gnu => "gnu",
        Toolchain::Apple => "apple",
    }
}

pub(crate) fn as_text(r: &Recommended) -> String {
    let recs = &r.recs;
    let mut out = String::new();
    match r.link {
        Some(l) => {
            let on = |b: bool| if b { "on" } else { "off" };
            let _ = writeln!(
                out,
                "The link: /OPT:REF {}, /OPT:ICF {}.",
                on(l.opt_ref),
                on(l.opt_icf)
            );
        }
        None => out.push_str(
            "The link's options aren't recorded: what it dropped and folded is judged from the image.\n",
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
        "saving": recs.iter().map(|r| r.saving).sum::<u64>(),
        "recommendations": list,
    }))
    .unwrap_or_default();
    s.push('\n');
    s
}

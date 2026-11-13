//! `hexc linkerlog`: what a link's `/VERBOSE` output says, and why each
//! library member is in the image.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_linkerlog::{LinkerLog, parse};
use hexcavator_mmap::Mmap;
use hexcavator_size::pe;

pub const USAGE: &str = "\
usage: hexc linkerlog [options] <log> [-- <base log>]

Reads what a linker says about a link: which library members were linked
and why, what was discarded, and what was folded. The MSVC linker's
/VERBOSE output (link ... /VERBOSE > log), or the Unix linkers': lld's
--why-extract=<file> table, --why-live=<symbol> chains, and
--print-gc-sections; ld64's (and lld's Mach-O port's) -why_load and
-why_live; GNU ld's map (-Map) and --print-gc-sections. (Several of them
in one file, a linker's output and error together, are read together.)

options:
  -why <member>   why a member (lib(member), or just member.obj) was linked:
                  the symbol it was loaded for, and who referenced it, back
                  to an input on the command line
  -image <image>  rank the image's library members by size (using its PDB),
                  each with why it was linked
  -pdb <path>     the image's PDB (default: the one the image names)
  -top <n>        how many to list (default 20; 0: all)
  -json           as JSON
  -- <base log>   what changed from a base build's log: the members linked
                  now and not then (with why), and those no longer linked";

pub(crate) struct Options {
    pub log: PathBuf,
    pub base: Option<PathBuf>,
    pub why: Option<String>,
    pub image: Option<PathBuf>,
    pub pdb: Option<PathBuf>,
    pub top: usize,
    pub json: bool,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut log = None;
    let mut why = None;
    let mut image = None;
    let mut pdb = None;
    let mut top = 20usize;
    let mut json = false;
    let mut base = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            base = Some(PathBuf::from(args.get(i + 1).ok_or("-- needs a base log")?));
            if i + 2 < args.len() {
                return Err("one base log at a time".into());
            }
            break;
        }
        let option = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'));
        let mut value = |what: &str| {
            i += 1;
            args.get(i).cloned().ok_or(format!("-{what} needs a value"))
        };
        match option {
            Some("why") => why = Some(value("why")?),
            Some("image") => image = Some(PathBuf::from(value("image")?)),
            Some("pdb") => pdb = Some(PathBuf::from(value("pdb")?)),
            Some("top") => {
                let n = value("top")?;
                top = n.parse().map_err(|_| format!("-top: not a number: {n}"))?;
            }
            Some("json") => json = true,
            Some(other) => return Err(format!("unknown option '{other}'")),
            None if log.is_none() => log = Some(PathBuf::from(arg)),
            None => return Err("one log at a time".into()),
        }
        i += 1;
    }
    Ok(Options {
        log: log.ok_or("no log given")?,
        base,
        why,
        image,
        pdb,
        top: if top == 0 { usize::MAX } else { top },
        json,
    })
}

pub fn run(args: &[String]) -> ExitCode {
    let options = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc linkerlog: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match report(&options) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc linkerlog: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Reads a log as text (UTF-8, or the linker's code page, lossily).
fn read_log(path: &Path) -> Result<LinkerLog, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // (UTF-16 logs, from PowerShell's redirection, start with a BOM.)
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Ok(parse(&text))
}

/// One step of why an input was linked, as JSON.
#[derive(serde::Serialize)]
struct Step<'a> {
    input: &'a str,
    symbol: &'a str,
    referenced_in: Vec<&'a str>,
}

fn steps<'a>(log: &'a LinkerLog, input: &str) -> Vec<Step<'a>> {
    log.why(input)
        .into_iter()
        .map(|r| Step {
            input: r.input,
            symbol: r.symbol.shown(),
            referenced_in: r.referenced_in.iter().map(AsRef::as_ref).collect(),
        })
        .collect()
}

/// `v` as one line of JSON.
fn json_line(v: &impl serde::Serialize) -> String {
    let mut s = serde_json::to_string(v).unwrap_or_default();
    s.push('\n');
    s
}

/// The explanation of `input`, as lines.
fn explain(log: &LinkerLog, input: &str) -> Vec<String> {
    let why = log.why(input);
    if why.is_empty() {
        return vec![
            if log.linked.iter().any(|l| l.eq_ignore_ascii_case(input)) {
                format!("{input} was given on the command line (or the log doesn't say why).")
            } else {
                format!("{input} isn't in the log.")
            },
        ];
    }
    why.iter()
        .map(|r| {
            let by = if r.referenced_in.is_empty() {
                "the linker itself (the entry point or load configuration)".to_string()
            } else {
                r.referenced_in.join(", ")
            };
            format!(
                "{} was loaded for {}, referenced in {by}",
                r.input,
                r.symbol.shown()
            )
        })
        .collect()
}

/// The members linked in `new` and not `old`, and in `old` and not
/// `new` (case-insensitively), in log order.
fn member_changes<'a>(new: &'a LinkerLog, old: &'a LinkerLog) -> (Vec<&'a str>, Vec<&'a str>) {
    let members = |log: &'a LinkerLog| -> Vec<&'a str> {
        let mut seen = std::collections::HashSet::new();
        log.loads
            .iter()
            .filter_map(|l| l.loaded.as_deref())
            .filter(|m| seen.insert(m.to_ascii_lowercase()))
            .collect()
    };
    let (n, o) = (members(new), members(old));
    let lower = |v: &[&str]| -> std::collections::HashSet<String> {
        v.iter().map(|m| m.to_ascii_lowercase()).collect()
    };
    let (ln, lo) = (lower(&n), lower(&o));
    (
        n.into_iter()
            .filter(|m| !lo.contains(&m.to_ascii_lowercase()))
            .collect(),
        o.into_iter()
            .filter(|m| !ln.contains(&m.to_ascii_lowercase()))
            .collect(),
    )
}

fn diff(log: &LinkerLog, base: &LinkerLog, options: &Options) -> String {
    let (added, removed) = member_changes(log, base);
    let folded = |l: &LinkerLog| l.folds.iter().map(|f| f.replaced.len()).sum::<usize>();
    let mut out = String::new();
    if options.json {
        #[derive(serde::Serialize)]
        struct Added<'a> {
            member: &'a str,
            why: Vec<Step<'a>>,
        }
        #[derive(serde::Serialize)]
        struct Diff<'a> {
            added: Vec<Added<'a>>,
            removed: &'a [&'a str],
            linked: [usize; 2],
            discarded: [usize; 2],
            folded: [usize; 2],
        }
        out.push_str(&json_line(&Diff {
            added: added
                .iter()
                .map(|m| Added {
                    member: m,
                    why: steps(log, m),
                })
                .collect(),
            removed: &removed,
            linked: [base.linked.len(), log.linked.len()],
            discarded: [base.discarded.len(), log.discarded.len()],
            folded: [folded(base), folded(log)],
        }));
        return out;
    }
    let _ = writeln!(
        out,
        "Inputs linked: {} (was {}); /OPT:REF discarded {} (was {}); /OPT:ICF folded {} (was {}).",
        log.linked.len(),
        base.linked.len(),
        log.discarded.len(),
        base.discarded.len(),
        folded(log),
        folded(base)
    );
    let _ = writeln!(
        out,
        "\n{} library members linked now and not before:",
        added.len()
    );
    for m in added.iter().take(options.top) {
        let _ = writeln!(out, "  {m}");
        for line in explain(log, m) {
            let _ = writeln!(out, "      {line}");
        }
    }
    if added.len() > options.top {
        let _ = writeln!(out, "  ... and {} more", added.len() - options.top);
    }
    let _ = writeln!(out, "\n{} library members no longer linked:", removed.len());
    for m in removed.iter().take(options.top) {
        let _ = writeln!(out, "  {m}");
    }
    if removed.len() > options.top {
        let _ = writeln!(out, "  ... and {} more", removed.len() - options.top);
    }
    out
}

pub(crate) fn report(options: &Options) -> Result<String, String> {
    let log = read_log(&options.log)?;
    if let Some(base) = &options.base {
        let base = read_log(base)?;
        return Ok(diff(&log, &base, options));
    }
    let mut out = String::new();
    if let Some(input) = &options.why {
        let lines = explain(&log, input);
        if options.json {
            #[derive(serde::Serialize)]
            struct Why<'a> {
                input: &'a str,
                why: Vec<Step<'a>>,
            }
            out.push_str(&json_line(&Why {
                input,
                why: steps(&log, input),
            }));
        } else {
            for l in lines {
                let _ = writeln!(out, "{l}");
            }
        }
        return Ok(out);
    }
    if let Some(image_path) = &options.image {
        return largest_members(&log, image_path, options.pdb.as_deref(), options);
    }
    // A summary.
    let by_library = log.members_by_library();
    let folded: usize = log.folds.iter().map(|f| f.replaced.len()).sum();
    if options.json {
        #[derive(serde::Serialize)]
        struct Library<'a> {
            library: &'a str,
            members: usize,
        }
        #[derive(serde::Serialize)]
        struct Summary<'a> {
            linked: usize,
            libraries: Vec<Library<'a>>,
            discarded: usize,
            folds: usize,
            folded: usize,
            unused_libraries: Vec<&'a str>,
            live: Vec<LiveChain<'a>>,
        }
        #[derive(serde::Serialize)]
        struct LiveChain<'a> {
            symbol: &'a str,
            chain: &'a [String],
        }
        out.push_str(&json_line(&Summary {
            linked: log.linked.len(),
            libraries: by_library
                .iter()
                .map(|(l, m)| Library {
                    library: l,
                    members: m.len(),
                })
                .collect(),
            discarded: log.discarded.len(),
            folds: log.folds.len(),
            folded,
            unused_libraries: log.unused_libraries.iter().map(AsRef::as_ref).collect(),
            live: log
                .live
                .iter()
                .map(|l| LiveChain {
                    symbol: &l.symbol,
                    chain: &l.chain,
                })
                .collect(),
        }));
        return Ok(out);
    }
    // (A Unix linker's log names no inputs, ICF, or COMDATs: its own terms.)
    let unix = log.linked.is_empty() && log.folds.is_empty();
    if unix {
        let _ = writeln!(out, "Library members loaded:");
        for (lib, members) in by_library.iter().take(options.top) {
            let _ = writeln!(out, "  {:>6}  {lib}", members.len());
        }
        if !log.discarded.is_empty() {
            let _ = writeln!(
                out,
                "Sections removed as unused (garbage collected): {}",
                log.discarded.len()
            );
            for d in log.discarded.iter().take(options.top) {
                let _ = writeln!(out, "  {}:({})", d.input, d.symbol.name);
            }
            if log.discarded.len() > options.top {
                let _ = writeln!(out, "  ... and {} more", log.discarded.len() - options.top);
            }
        }
        if !log.live.is_empty() {
            let _ = writeln!(out, "Why symbols are live:");
            for l in log.live.iter().take(options.top) {
                let _ = writeln!(out, "  {}", l.symbol);
                for step in &l.chain {
                    let _ = writeln!(out, "    referenced by {step}");
                }
            }
        }
        return Ok(out);
    }
    let _ = writeln!(out, "{} inputs linked.", log.linked.len());
    let _ = writeln!(out, "Library members loaded:");
    for (lib, members) in by_library.iter().take(options.top) {
        let _ = writeln!(out, "  {:>6}  {lib}", members.len());
    }
    let _ = writeln!(
        out,
        "/OPT:REF discarded {} COMDATs; /OPT:ICF folded {} into {} others.",
        log.discarded.len(),
        folded,
        log.folds.len()
    );
    if !log.unused_libraries.is_empty() {
        let _ = writeln!(out, "Unused libraries (searched, nothing taken):");
        for l in &log.unused_libraries {
            let _ = writeln!(out, "  {l}");
        }
    }
    Ok(out)
}

/// The file name of a path.
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The image's library members by size, each with why it was linked.
fn largest_members(
    log: &LinkerLog,
    image_path: &Path,
    pdb: Option<&Path>,
    options: &Options,
) -> Result<String, String> {
    let show = |p: &Path| p.display().to_string();
    let image_map = Mmap::open(image_path).map_err(|e| format!("{}: {e}", show(image_path)))?;
    let image = Image::parse(&image_map).map_err(|e| format!("{}: {e}", show(image_path)))?;
    let (pdb_path, pdb_map) = hexcavator_program::find_debug(image_path, &image, pdb)?;
    let debug = DebugInfo::parse(&pdb_map).map_err(|e| format!("{}: {e}", show(&pdb_path)))?;
    let model = pe::model(&image, &debug).map_err(|e| format!("{}: {e}", show(&pdb_path)))?;
    // Compilands as the linker names library members: `lib(member)`.
    let totals = model.totals(|p| Some(p.compiland));
    let mut rows: Vec<(String, hexcavator_size::Size)> = totals
        .iter()
        .filter_map(|(&c, t)| {
            let comp = &model.compilands[c as usize];
            let lib = &model.libraries[comp.library as usize].name;
            if lib.is_empty() || lib.eq_ignore_ascii_case(&comp.name) {
                return None;
            }
            Some((
                format!("{}({})", file_name(lib), file_name(&comp.name)),
                t.size,
            ))
        })
        .collect();
    rows.sort_by(|a, b| {
        b.1.file
            .max(b.1.vm)
            .cmp(&a.1.file.max(a.1.vm))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut out = String::new();
    if options.json {
        #[derive(serde::Serialize)]
        struct Member<'a> {
            member: &'a str,
            file_size: u64,
            vm_size: u64,
            why: Vec<Step<'a>>,
        }
        #[derive(serde::Serialize)]
        struct Members<'a> {
            members: Vec<Member<'a>>,
        }
        out.push_str(&json_line(&Members {
            members: rows
                .iter()
                .take(options.top)
                .map(|(m, s)| Member {
                    member: m,
                    file_size: s.file,
                    vm_size: s.vm,
                    why: steps(log, m),
                })
                .collect(),
        }));
        return Ok(out);
    }
    let _ = writeln!(
        out,
        "The largest library members of {}, and why each was linked:",
        show(image_path)
    );
    for (m, s) in rows.iter().take(options.top) {
        let _ = writeln!(out, "{:>10} {:>10}  {m}", s.file, s.vm);
        for line in explain(log, m) {
            let _ = writeln!(out, "                        {line}");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        let args = |v: &[&str]| {
            v.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
        };
        let o = parse_args(&args(&["log.txt", "-why", "x.obj", "-json"])).unwrap();
        assert_eq!(o.log, PathBuf::from("log.txt"));
        assert_eq!(o.why.as_deref(), Some("x.obj"));
        assert!(o.json);
        let o = parse_args(&args(&["-image", "a.exe", "-top", "0", "log"])).unwrap();
        assert_eq!(o.image, Some(PathBuf::from("a.exe")));
        assert_eq!(o.top, usize::MAX);
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["a", "b"])).is_err());
        assert!(parse_args(&args(&["-why"])).is_err());
        assert!(parse_args(&args(&["-bogus", "a"])).is_err());
        let o = parse_args(&args(&["new.log", "--", "old.log"])).unwrap();
        assert_eq!(o.base, Some(PathBuf::from("old.log")));
        assert!(parse_args(&args(&["new.log", "--"])).is_err());
        assert!(parse_args(&args(&["new.log", "--", "a", "b"])).is_err());
    }

    #[test]
    fn diffs() {
        let old = hexcavator_linkerlog::parse(
            "Searching libraries\n    Searching a.lib:\n      Found x\n        Referenced in main.obj\n        Loaded a.lib(x.obj)\n      Found y\n        Referenced in main.obj\n        Loaded a.lib(y.obj)\n",
        );
        let new = hexcavator_linkerlog::parse(
            "Searching libraries\n    Searching a.lib:\n      Found x\n        Referenced in main.obj\n        Loaded A.LIB(X.OBJ)\n      Found z\n        Referenced in main.obj\n        Loaded a.lib(z.obj)\n",
        );
        let (added, removed) = member_changes(&new, &old);
        assert_eq!(added, ["a.lib(z.obj)"]);
        assert_eq!(removed, ["a.lib(y.obj)"]);
        let options = Options {
            log: PathBuf::new(),
            base: None,
            why: None,
            image: None,
            pdb: None,
            top: 20,
            json: false,
        };
        let text = diff(&new, &old, &options);
        assert!(text.contains("1 library members linked now and not before:\n  a.lib(z.obj)\n      a.lib(z.obj) was loaded for z, referenced in main.obj"), "{text}");
        assert!(
            text.contains("1 library members no longer linked:\n  a.lib(y.obj)"),
            "{text}"
        );
        let json = diff(
            &new,
            &old,
            &Options {
                json: true,
                ..options
            },
        );
        let v = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        assert_eq!(v.get("removed").unwrap().as_array().unwrap().len(), 1);
    }
}

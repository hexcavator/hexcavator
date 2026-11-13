//! `hexc size`: what the bytes of an image are, by section, COFF group,
//! library, and compiland; or, with `-d`, a bloaty-style report by any
//! data sources, optionally as a diff against a base image.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_image::Image;
use hexcavator_mmap::Mmap;
use hexcavator_size::custom::{Config, CustomSource};
use hexcavator_size::rollup::{self, Domain, Report, Rollup, SortBy};
use hexcavator_size::sources::{self, Source};
use hexcavator_size::{Model, NO_GROUP, Size, report, symbols};

pub const USAGE: &str = "\
usage: hexc size [options] <image>... [-- <base image>...]

Attributes the image's bytes to sections, COFF groups, libraries, and
compilands, using its PDB. For ELF, Mach-O, and WebAssembly files, and
COFF objects, import objects, and libraries (.obj, .lib), reports by data
sources (default: sections), compile units and inlines from their DWARF,
objects and libraries from their linker's map (-map); -sizebench and
-findings read DWARF as they read PDBs.

options:
  -pdb <path>       its debug information: a PDB, or a file with its DWARF
                    (or -debug; default: its own, or the one it names)
  -map <path>       use the linker's map instead of debug information: MSVC's
                    (link /MAP): groups, and symbols attributed to their
                    objects and libraries; lld's, GNU ld's, or ld64's (ELF,
                    Mach-O, WebAssembly): compileunits as the objects each
                    input section came from, libraries as their archives
  -top <n>          how many libraries and compilands to list (default 20; 0: all)
  -sizebench        print SizeBench's view instead, one fact per line, sorted
  -findings         what wastes space (duplicate data, template bloat), with
                    advice; with -json, as JSON; with -- <base image>, what
                    changed from the base (by item, largest change first)

bloaty-style reports (every byte of the file and of memory, labeled once):
  -d <sources>      data sources to report by, comma-separated, a level each
                    (sections, segments, groups, symbols, compileunits,
                    libraries, inputfiles); default: sections
  -n <n>            rows per level (default 20; 0: all)
  -min <size>       fold rows smaller than this into [N Others] too: bytes
                    (512, 4k, 1M) or a percentage of the rows beside it (0.5%)
  -s <vm|file|both> sort by memory size, file size, or the larger (default)
  -domain <vm|file|both>  which sizes to show (default both)
  -csv, -tsv, -json output format (default: a table)
  -base-pdb <path>  the base image's PDB
  -base-map <path>  the base image's map
  -debug-file <path>  separate debug information for compileunits: a dSYM's
                    DWARF file (found next to a Mach-O image by default), an
                    ELF debug file, or a WebAssembly module's source map
                    (found next to it, by its sourceMappingURL, by default)
  -base-debug-file <path>  the base image's
  -source-map <id>=<path>  the source map of the module whose sourceMappingURL
                    or path (as given) is <id> (bloaty's --source-map)
  -mangled          each symbol's shown name and its mangled one, as JSON
  -table            as JSON, the sizes of each distinct section, COFF group,
                    object, library, and symbol (and mangled name), at once:
                    any grouping of them is their rows summed (with -d,
                    of those sources: -d sourcefiles,symbols)
  -disassemble <function>  print the function's disassembly (PE images with
                    their PDBs, ELF and Mach-O: x86, x86-64, ARM32, ARM64;
                    WebAssembly), its name as the PDB, symbol table, or
                    name section has it, or demangled; or, if just one
                    function has it, its name without the parameters.
                    Labels are bloaty's (0:, >0 ahead, <0 behind), except:
  -definition <symbol>  where a function is defined: the source file and
                    line its code starts at (from the line tables; as
                    -disassemble names it); with -json, its name, file, line
  -blocks           with -disassemble: by basic block, each set apart and
                    labeled L1, L2, ... on the line before it
  -json             with -disassemble: the instructions (bytes, text, label,
                    how control leaves each, its target), the basic blocks
                    and the edges between them, and (from a PDB) each
                    instruction's source file and line
  -budget <file>    check a size budget (JSON rules: limits on sizes, and on
                    growth from the base image given with --): prints what
                    exceeds it (with -json, as JSON) and exits 1 if anything
                    does
  -list-sources     list the data sources
  -source-filter <regex>  only regions some label of which matches (bloaty's
                    --source-filter); the rest are counted as omitted
  -c <config>       a bloaty config file (protobuf text): custom_data_source
                    (labels of a base source rewritten by regular expressions),
                    data_source, source_filter, filename, base_filename
  -C, -demangle <none|short|full>  the symbols source's names (bloaty's)
  -w                bloaty's wide output (labels are never cut short here)
  -debug-vmaddr <addr>, -debug-fileoff <offset>  what each source says
                    about an address (repeatable)
  -raw-map, -v      dump the maps after the report
  -version          the version
  -- <base image>   report the difference from the base image
Options also take bloaty's --name=value form. Several images (and several
base images after --) make one bloaty-style report, summed; the inputfiles
source tells them apart.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Pretty,
    Csv,
    Tsv,
    Json,
}

#[derive(Clone)]
struct Options {
    image: PathBuf,
    /// More images, summed with the first (bloaty-style reports only).
    more: Vec<PathBuf>,
    /// More base images, likewise.
    more_bases: Vec<PathBuf>,
    pdb: Option<PathBuf>,
    top: usize,
    sizebench: bool,
    /// bloaty mode: the sources (empty: not bloaty mode, unless `base`).
    sources: Vec<Source>,
    /// Each source's name, and for a custom source its definition (its
    /// entry in `sources` is its base).
    source_names: Vec<String>,
    customs: Vec<Option<CustomSource>>,
    source_filter: Option<regex::Regex>,
    base: Option<PathBuf>,
    base_pdb: Option<PathBuf>,
    map: Option<PathBuf>,
    base_map: Option<PathBuf>,
    debug_file: Option<PathBuf>,
    base_debug_file: Option<PathBuf>,
    /// `-source-map` pairs: a module's ID (its sourceMappingURL or path)
    /// and its source map.
    source_maps: Vec<(String, PathBuf)>,
    rows: usize,
    /// `-min`: rows smaller than this are Others too.
    min: rollup::Threshold,
    sort_by: SortBy,
    domain: Domain,
    format: Format,
    list_sources: bool,
    findings: bool,
    disassemble: Option<String>,
    /// `-definition`: where a function's code starts, in its source.
    definition: Option<String>,
    /// `-mangled`: each symbol's shown name and its mangled one.
    mangled: bool,
    /// `-table`: every source's labels at once, for a viewer to group.
    table: bool,
    /// Whether `-d` was given (else the sources are a default's).
    sources_given: bool,
    /// `-blocks`: the disassembly by basic block.
    blocks: bool,
    budget: Option<PathBuf>,
    /// Addresses (VM, then file offsets) to explain, as bloaty's
    /// `--debug-vmaddr` and `--debug-fileoff`.
    debug_vm: Vec<u64>,
    debug_file_offsets: Vec<u64>,
    /// Dump the maps after the report (`--raw-map`, `-v`).
    raw_map: bool,
    version: bool,
}

/// An address given on the command line: hex with `0x`, else decimal.
fn address(s: &str) -> Result<u64, String> {
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse(),
    };
    parsed.map_err(|_| format!("not an address: {s}"))
}

/// The arguments, with bloaty's `--name=value` as `--name value`.
fn split_values(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for a in args {
        if a == "--" {
            out.push(a.clone());
            continue;
        }
        match a.strip_prefix("--").and_then(|rest| rest.split_once('=')) {
            Some((name, value)) if !name.is_empty() => {
                out.push(format!("--{name}"));
                out.push(value.to_string());
            }
            _ => out.push(a.clone()),
        }
    }
    out
}

fn parse(args: &[String]) -> Result<Options, String> {
    let args = &split_values(args)[..];
    let mut image = None;
    let mut demangle: Option<String> = None;
    let mut debug_vm = Vec::new();
    let mut debug_file_offsets = Vec::new();
    let mut raw_map = false;
    let mut version = false;
    let mut more: Vec<PathBuf> = Vec::new();
    let mut more_bases: Vec<PathBuf> = Vec::new();
    let mut pdb = None;
    let mut top = 20;
    let mut sizebench = false;
    let mut raw_sources: Vec<String> = Vec::new();
    let mut config: Option<Config> = None;
    let mut source_filter: Option<String> = None;
    let mut base = None;
    let mut base_pdb = None;
    let mut map = None;
    let mut base_map = None;
    let mut debug_file = None;
    let mut base_debug_file = None;
    let mut source_maps = Vec::new();
    let mut rows = 20;
    let mut min = rollup::Threshold::None;
    let mut sort_by = SortBy::Both;
    let mut domain = Domain::Both;
    let mut format = Format::Pretty;
    let mut list_sources = false;
    let mut findings = false;
    let mut disassemble = None;
    let mut definition = None;
    let mut mangled = false;
    let mut table = false;
    let mut sources_given = false;
    let mut blocks = false;
    let mut budget = None;
    let mut i = 0;
    let value = |i: &mut usize, what: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or(format!("-{what} needs a value"))
    };
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            base = Some(PathBuf::from(args.get(i).ok_or("-- needs a base image")?));
            more_bases.extend(args[i + 1..].iter().map(PathBuf::from));
            break;
        }
        let option = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .or_else(|| arg.strip_prefix('/').filter(|_| !Path::new(arg).exists()));
        match option {
            Some("pdb" | "debug") => pdb = Some(PathBuf::from(value(&mut i, "pdb")?)),
            Some("base-pdb") => base_pdb = Some(PathBuf::from(value(&mut i, "base-pdb")?)),
            Some("map") => map = Some(PathBuf::from(value(&mut i, "map")?)),
            Some("base-map") => base_map = Some(PathBuf::from(value(&mut i, "base-map")?)),
            Some("debug-file") => debug_file = Some(PathBuf::from(value(&mut i, "debug-file")?)),
            Some("base-debug-file") => {
                base_debug_file = Some(PathBuf::from(value(&mut i, "base-debug-file")?));
            }
            Some("source-map") => {
                let v = value(&mut i, "source-map")?;
                let (id, path) = v
                    .split_once('=')
                    .ok_or(format!("-source-map: expected <id>=<path>, not '{v}'"))?;
                source_maps.push((id.to_string(), PathBuf::from(path)));
            }
            Some("top") => {
                let n = value(&mut i, "top")?;
                top = n.parse().map_err(|_| format!("-top: not a number: {n}"))?;
            }
            Some("min") => {
                let m = value(&mut i, "min")?;
                min = rollup::Threshold::parse(&m).ok_or_else(|| {
                    format!("-min: a size (512, 4k) or a percentage (0.5%), not '{m}'")
                })?;
            }
            Some("n") => {
                let n = value(&mut i, "n")?;
                rows = n.parse().map_err(|_| format!("-n: not a number: {n}"))?;
            }
            Some("d") => {
                sources_given = true;
                raw_sources.extend(
                    value(&mut i, "d")?
                        .split(',')
                        .filter(|n| !n.is_empty())
                        .map(String::from),
                );
            }
            Some("c") => {
                let path = value(&mut i, "c")?;
                let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                config = Some(
                    hexcavator_size::custom::parse_config(&text)
                        .map_err(|e| format!("{path}: {e}"))?,
                );
            }
            Some("source-filter") => source_filter = Some(value(&mut i, "source-filter")?),
            Some("s") => {
                sort_by = match value(&mut i, "s")?.as_str() {
                    "vm" => SortBy::Vm,
                    "file" => SortBy::File,
                    "both" => SortBy::Both,
                    other => return Err(format!("-s: expected vm, file, or both, not '{other}'")),
                }
            }
            Some("domain") => {
                domain = match value(&mut i, "domain")?.as_str() {
                    "vm" => Domain::Vm,
                    "file" => Domain::File,
                    "both" => Domain::Both,
                    other => {
                        return Err(format!(
                            "-domain: expected vm, file, or both, not '{other}'"
                        ));
                    }
                }
            }
            Some("csv") => format = Format::Csv,
            Some("tsv") => format = Format::Tsv,
            Some("json") => format = Format::Json,
            Some("list-sources") => list_sources = true,
            Some("disassemble") => disassemble = Some(value(&mut i, "disassemble")?),
            Some("definition") => definition = Some(value(&mut i, "definition")?),
            Some("mangled") => mangled = true,
            Some("table") => table = true,
            Some("blocks") => blocks = true,
            Some("budget") => budget = Some(PathBuf::from(value(&mut i, "budget")?)),
            Some("sizebench") => sizebench = true,
            Some("findings") => findings = true,
            // bloaty's: how to demangle `symbols` (none, short, full).
            Some("C" | "demangle") => demangle = Some(value(&mut i, "demangle")?),
            // bloaty's wide output: labels are never cut short here.
            Some("w") => {}
            Some("v" | "vv" | "vvv" | "raw-map") => raw_map = true,
            Some("debug-vmaddr") => debug_vm.push(address(&value(&mut i, "debug-vmaddr")?)?),
            Some("debug-fileoff") => {
                debug_file_offsets.push(address(&value(&mut i, "debug-fileoff")?)?);
            }
            Some("version") => version = true,
            Some(other) => return Err(format!("unknown option '{other}'")),
            None if image.is_none() => image = Some(PathBuf::from(arg)),
            None => more.push(PathBuf::from(arg)),
        }
        i += 1;
    }
    // A config file gives what the command line doesn't.
    let config = config.unwrap_or_default();
    if raw_sources.is_empty() {
        raw_sources.clone_from(&config.data_sources);
    }
    if source_filter.is_none() {
        source_filter.clone_from(&config.source_filter);
    }
    if image.is_none() {
        image = config.filenames.first().map(PathBuf::from);
        more.extend(config.filenames.iter().skip(1).map(PathBuf::from));
    }
    if base.is_none() {
        base = config.base_filenames.first().map(PathBuf::from);
        more_bases.extend(config.base_filenames.iter().skip(1).map(PathBuf::from));
    }
    // -C picks the symbols source's names.
    if let Some(mode) = &demangle {
        let symbols = match mode.as_str() {
            "none" => "rawsymbols",
            "short" => "symbols",
            "full" => "fullsymbols",
            other => {
                return Err(format!(
                    "-C/--demangle: none, short, or full, not '{other}'"
                ));
            }
        };
        for s in &mut raw_sources {
            if s == "symbols" || s == "shortsymbols" {
                symbols.clone_into(s);
            }
        }
    }
    let several = !more.is_empty() || !more_bases.is_empty();
    if several && (findings || sizebench || disassemble.is_some() || budget.is_some()) {
        return Err(
            "several images make one bloaty-style report (-d); -findings, -sizebench, -disassemble, and -budget take one".into(),
        );
    }
    let mut sources = Vec::new();
    let mut source_names = Vec::new();
    let mut customs = Vec::new();
    for name in &raw_sources {
        if let Some(s) = Source::parse(name) {
            sources.push(s);
            customs.push(None);
        } else if let Some(c) = config.custom_sources.iter().find(|c| &c.name == name) {
            sources.push(c.base);
            customs.push(Some(c.clone()));
        } else {
            return Err(format!(
                "-d: unknown data source '{name}' (see -list-sources)"
            ));
        }
        source_names.push(name.clone());
    }
    // A diff is bloaty-style (by sections, unless given), except for the
    // findings, which compare their own way; so are several images.
    let debugging = !debug_vm.is_empty() || !debug_file_offsets.is_empty() || raw_map;
    if (base.is_some() || several || debugging) && sources.is_empty() && !findings {
        sources.push(Source::Sections);
        source_names.push("sections".into());
        customs.push(None);
    }
    let source_filter = source_filter
        .map(|f| regex::Regex::new(&f).map_err(|e| format!("-source-filter: {e}")))
        .transpose()?;
    let image = match image {
        Some(i) => i,
        None if list_sources || version => PathBuf::new(),
        None => return Err("no image given".into()),
    };
    Ok(Options {
        image,
        more,
        more_bases,
        pdb,
        top: if top == 0 { usize::MAX } else { top },
        sizebench,
        sources,
        source_names,
        customs,
        source_filter,
        base,
        base_pdb,
        map,
        base_map,
        debug_file,
        base_debug_file,
        source_maps,
        rows: if rows == 0 { usize::MAX } else { rows },
        min,
        sort_by,
        domain,
        format,
        list_sources,
        findings,
        disassemble,
        definition,
        mangled,
        table,
        sources_given,
        blocks,
        budget,
        debug_vm,
        debug_file_offsets,
        raw_map,
        version,
    })
}

/// `-budget`: checks the image (and its growth from the base) against a
/// budget's rules.
fn check_budget(options: &Options, path: &Path, out: &mut impl Write) -> Result<(), String> {
    use hexcavator_size::budget::{Budget, Totals, report};
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let budget = Budget::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let names = budget.sources();
    let mut list = Vec::new();
    for n in &names {
        list.push(Source::parse(n).ok_or_else(|| {
            format!(
                "{}: unknown data source '{n}' (see -list-sources)",
                path.display()
            )
        })?);
    }
    if budget.needs_base() && options.base.is_none() {
        return Err(format!(
            "{}: its growth limits need a base image (-- <base>)",
            path.display()
        ));
    }
    let totals = |image: &Path,
                  pdb: Option<&Path>,
                  map: Option<&Path>,
                  debug: Option<&Path>|
     -> Result<Totals, String> {
        // The sections source at least, for the total.
        let sources = if list.is_empty() {
            vec![Source::Sections]
        } else {
            list.clone()
        };
        let maps = maps_of(image, pdb, map, debug, &sources)?;
        let whole = Rollup::of_sources(&maps, &[0]);
        let mut t = Totals {
            file: whole.file,
            vm: whole.vm,
            ..Totals::default()
        };
        for (k, name) in names.iter().enumerate() {
            let r = Rollup::of_sources(&maps, &[k]);
            let labels = r
                .children
                .iter()
                .map(|(l, c)| (l.to_string(), (c.file, c.vm)))
                .collect();
            t.by_source.insert(name.clone(), labels);
        }
        Ok(t)
    };
    let current = totals(
        &options.image,
        options.pdb.as_deref(),
        options.map.as_deref(),
        options
            .debug_file
            .clone()
            .or_else(|| source_map_option(&options.image, &options.source_maps))
            .as_deref(),
    )?;
    let base = match &options.base {
        Some(b) => Some(totals(
            b,
            options.base_pdb.as_deref(),
            options.base_map.as_deref(),
            options
                .base_debug_file
                .clone()
                .or_else(|| source_map_option(b, &options.source_maps))
                .as_deref(),
        )?),
        None => None,
    };
    let violations = budget
        .check(&current, base.as_ref())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let text = if options.format == Format::Json {
        let json = serde_json::json!({
            "met": violations.is_empty(),
            "rules": budget.rules.len(),
            "violations": violations,
        });
        format!("{json}\n")
    } else {
        report(budget.rules.len(), &violations)
    };
    finish(out.write_all(text.as_bytes()))?;
    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "size budget exceeded ({} limits)",
            violations.len()
        ))
    }
}

/// How `-disassemble` writes a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    /// bloaty's listing.
    Bloaty,
    /// By basic block (`-blocks`).
    Blocks,
    /// As JSON.
    Json,
}

/// `-table`: `{"columns": [source names], "strings": [labels], "rows":
/// [[label index per column..., file, vm]], "file", "vm"}`, the rows those
/// of [`hexcavator_size::rollup::table`] by the sections, groups,
/// compileunits, libraries, and symbols sources (and rawsymbols, where
/// names are mangled: not PE's). A label a source doesn't give is
/// `[None]`.
///
/// With a base (`-- <base>`), a diff's: `"diff": true`, each row a set of
/// labels either build has, `[label index..., file change, vm change, base
/// file, base vm]`, every one (the unchanged too, whose base sizes its
/// groups' need), and the totals' changes and base sizes (`"old_file"`,
/// `"old_vm"`).
fn size_table(options: &Options) -> Result<String, String> {
    let path = &options.image;
    let data = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pe = data.starts_with(b"MZ") || is_object_input(&data);
    let mut sources = vec![
        Source::Sections,
        Source::Groups,
        Source::CompileUnits,
        Source::Libraries,
        Source::Symbols,
    ];
    if !pe {
        sources.push(Source::RawSymbols);
    }
    // (-d names others: the table of those, as the Symbols page's Source
    // grouping asks for apart, it being costly.)
    if options.sources_given && !options.sources.is_empty() {
        sources.clone_from(&options.sources);
    }
    drop(data);
    // Each build's rows: their labels by name (the two builds' labels are
    // matched by name), and their sizes.
    type Rows = Vec<(Vec<String>, i64, i64)>;
    let rows_of = |path: &Path,
                   pdb: Option<&Path>,
                   map: Option<&Path>,
                   debug: Option<&Path>|
     -> Result<Rows, String> {
        let maps = maps_of(path, pdb, map, debug, &sources)?;
        Ok(hexcavator_size::rollup::table(&maps)
            .into_iter()
            .map(|(labels, f, v)| {
                let names = labels
                    .iter()
                    .map(|l| {
                        l.map_or_else(|| "[None]".to_string(), |l| maps.labels.name(l).to_string())
                    })
                    .collect();
                (names, f, v)
            })
            .collect())
    };
    let base = options.base.as_deref();
    // (Both builds at once: each is read apart.)
    let (rows, old) = std::thread::scope(|scope| {
        let old = base.map(|b| {
            scope.spawn(|| {
                rows_of(
                    b,
                    options.base_pdb.as_deref(),
                    options.base_map.as_deref(),
                    options.base_debug_file.as_deref(),
                )
            })
        });
        let rows = rows_of(
            path,
            options.pdb.as_deref(),
            options.map.as_deref(),
            options.debug_file.as_deref(),
        );
        let old = old.map(|h| {
            h.join()
                .unwrap_or_else(|_| Err("reading the base failed".into()))
        });
        (rows, old)
    });
    let rows = rows?;
    let old = old.transpose()?;
    // The labels used, each once, in the order first used; [None] first.
    let mut strings: Vec<String> = vec!["[None]".to_string()];
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    index.insert("[None]".to_string(), 0);
    let mut out = String::with_capacity(rows.len() * 48);
    out.push_str("{\"columns\":");
    out.push_str(
        &serde_json::to_string(&sources.iter().map(|s| s.name()).collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    if old.is_some() {
        out.push_str(",\"diff\":true");
    }
    out.push_str(",\"rows\":[");
    let mut first = true;
    let mut row = |out: &mut String, labels: &[String], nums: &[i64]| {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('[');
        for l in labels {
            let i = match index.get(l) {
                Some(&i) => i,
                None => {
                    strings.push(l.clone());
                    index.insert(l.clone(), strings.len() - 1);
                    strings.len() - 1
                }
            };
            out.push_str(&i.to_string());
            out.push(',');
        }
        for (k, n) in nums.iter().enumerate() {
            if k > 0 {
                out.push(',');
            }
            out.push_str(&n.to_string());
        }
        out.push(']');
    };
    let (mut file, mut vm, mut old_file, mut old_vm) = (0i64, 0i64, 0i64, 0i64);
    match &old {
        None => {
            for (labels, f, v) in &rows {
                row(&mut out, labels, &[*f, *v]);
                file += f;
                vm += v;
            }
        }
        Some(old) => {
            // Every set of labels either build has: the change, then the
            // base's sizes.
            let mut before: std::collections::HashMap<&[String], (i64, i64)> =
                std::collections::HashMap::with_capacity(old.len());
            for (labels, f, v) in old {
                let e = before.entry(labels.as_slice()).or_default();
                e.0 += f;
                e.1 += v;
            }
            let mut now: std::collections::HashMap<&[String], (i64, i64)> =
                std::collections::HashMap::with_capacity(rows.len());
            for (labels, f, v) in &rows {
                let e = now.entry(labels.as_slice()).or_default();
                e.0 += f;
                e.1 += v;
            }
            for (labels, _, _) in &rows {
                let Some(&(nf, nv)) = now.get(labels.as_slice()) else {
                    continue;
                };
                // (Once per set of labels.)
                now.remove(labels.as_slice());
                let (of, ov) = before.remove(labels.as_slice()).unwrap_or((0, 0));

                row(&mut out, labels, &[nf - of, nv - ov, of, ov]);
                file += nf - of;
                vm += nv - ov;
                old_file += of;
                old_vm += ov;
            }
            // What only the base has: removed.
            for (labels, _, _) in old {
                if let Some((of, ov)) = before.remove(labels.as_slice()) {
                    row(&mut out, labels, &[-of, -ov, of, ov]);
                    file -= of;
                    vm -= ov;
                    old_file += of;
                    old_vm += ov;
                }
            }
        }
    }
    out.push_str("],\"strings\":");
    out.push_str(&serde_json::to_string(&strings).unwrap_or_default());
    out.push_str(&format!(",\"file\":{file},\"vm\":{vm}"));
    if old.is_some() {
        out.push_str(&format!(",\"old_file\":{old_file},\"old_vm\":{old_vm}"));
    }
    out.push_str("}\n");
    Ok(out)
}

/// `-mangled`: as JSON, each symbol whose shown name (the `symbols`
/// source's: demangled, shortened) isn't its mangled one, with that:
/// `{"names": [{"name", "mangled"}]}`, a name once (its first symbol's).
/// For ELF, Mach-O, and WebAssembly, the `symbols` and `rawsymbols`
/// sources' labels where they start together; for a PE image, the
/// decorated public symbol at each function's or datum's address.
fn mangled_names(options: &Options) -> Result<String, String> {
    use std::collections::HashMap;
    let path = &options.image;
    let data = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut pairs: Vec<(String, String)> = Vec::new();
    if data.starts_with(b"MZ") {
        let opened = hexcavator_program::Opened::open(path, options.pdb.as_deref())?;
        let program = opened.program()?;
        let mut decorated: HashMap<u64, String> = HashMap::new();
        if let Ok(list) = program.debug.symbols() {
            for s in list {
                if s.kind == hexcavator_debuginfo::SymbolKind::Public
                    && (s.name.starts_with('?')
                        || s.name.starts_with('_')
                        || s.name.starts_with('@'))
                {
                    decorated.entry(s.addr).or_insert(s.name);
                }
            }
        }
        for s in program.symbols()? {
            if let Some(d) = decorated.get(&s.addr)
                && *d != s.name
            {
                pairs.push((s.name.clone(), d.clone()));
            }
        }
    } else {
        let maps = maps_of(
            path,
            None,
            None,
            options.debug_file.as_deref(),
            &[Source::Symbols, Source::RawSymbols],
        )?;
        let shown = &maps.sources[0].1.vm;
        let raw = &maps.sources[1].1.vm;
        let mut at: HashMap<u64, hexcavator_size::rangemap::Label> = HashMap::new();
        for e in shown.iter() {
            at.entry(e.start).or_insert(e.label);
        }
        for e in raw.iter() {
            if let Some(&l) = at.get(&e.start) {
                let (name, mangled) = (maps.labels.name(l), maps.labels.name(e.label));
                if name != mangled && !mangled.starts_with('[') {
                    pairs.push((name.to_string(), mangled.to_string()));
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    pairs.retain(|(n, _)| seen.insert(n.clone()));
    let names: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(n, m)| serde_json::json!({ "name": n, "mangled": m }))
        .collect();
    let mut out = serde_json::to_string(&serde_json::json!({ "names": names })).unwrap_or_default();
    out.push('\n');
    Ok(out)
}

/// `-definition`: where a function is defined: DWARF's declaration of it
/// (`DW_AT_decl_file`, `DW_AT_decl_line`), else the line tables' row its
/// code starts at (a PDB's: its signature's line). A function found by its
/// name as the
/// symbols give it, or without its parameters if just one has it; else, in
/// an ELF or Mach-O image, as -disassemble finds it).
fn definition(options: &Options, name: &str) -> Result<String, String> {
    let path = &options.image;
    let opened = hexcavator_program::Opened::open(path, options.pdb.as_deref())?;
    let program = opened.program()?;
    let syms = program.symbols()?;
    let live = || {
        syms.iter()
            .filter(|s| !s.folded && s.size.vm.max(s.size.file) > 0)
    };
    let extent = |s: &hexcavator_size::symbols::Symbol| (s.addr, s.size.vm.max(s.size.file));
    let mut addr = live().find(|s| s.name == name).map(extent);
    if addr.is_none() {
        let bare = |n: &str| n.split('(').next().unwrap_or(n).trim().to_string();
        let mut found = live().filter(|s| bare(&s.name) == name);
        if let (Some(one), None) = (found.next(), found.next()) {
            addr = Some(extent(one));
        }
    }
    if addr.is_none() {
        let data = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let f = if hexcavator_size::macho::is_macho_input(&data) {
            hexcavator_size::macho::function(&data, name).ok()
        } else if hexcavator_size::elf::is_elf_input(&data) {
            hexcavator_size::elf::function(&data, name).ok()
        } else {
            None
        };
        addr = f.map(|f| (f.address, f.code.len() as u64));
    }
    let (addr, _) = addr.ok_or_else(|| format!("no function '{name}'"))?;
    let files = [path.as_path()];
    let lines = hexcavator_program::cache::remember(&files, "source lines", || {
        program.debug.source_lines()
    })
    .map_err(|e| e.to_string())?;
    let i = lines.spans.partition_point(|s| s.addr <= addr);
    let span = i
        .checked_sub(1)
        .map(|j| &lines.spans[j])
        .filter(|s| addr < s.addr.saturating_add(s.size.max(1)))
        .ok_or_else(|| format!("{name}: the line tables don't cover its code"))?;
    let mut file = lines
        .files
        .get(span.file as usize)
        .cloned()
        .unwrap_or_default();
    let mut line = span.line;
    // DWARF: the function's own declaration (an optimized function's first
    // row may be its body's), its DIE the symbol's reference.
    if matches!(program.debug, hexcavator_debuginfo::DebugInfo::Dwarf(_))
        && let Ok(all) = program.debug.symbols()
    {
        let decl = all
            .iter()
            .find(|s| {
                s.addr == addr
                    && s.kind == hexcavator_debuginfo::SymbolKind::Function
                    && s.type_index != 0
            })
            .and_then(|s| {
                program
                    .debug
                    .type_definition(hexcavator_debuginfo::TypeRef(s.type_index))
            });
        if let Some((f, l)) = decl {
            file = f;
            line = l;
        }
    }
    Ok(if options.format == Format::Json {
        let mut s = serde_json::to_string_pretty(
            &serde_json::json!({ "name": name, "file": file, "line": line }),
        )
        .unwrap_or_default();
        s.push('\n');
        s
    } else {
        format!("{file}:{line}\n")
    })
}

/// `-disassemble`: one function's code.
fn disassemble(
    path: &Path,
    function: &str,
    pdb: Option<&Path>,
    style: Style,
) -> Result<String, String> {
    let data = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if hexcavator_size::wasm::is_wasm_input(&data) {
        let text = hexcavator_size::wasm::listing(&data, function)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // (A module's code is structured already: no blocks to find.)
        return Ok(if style == Style::Json {
            let name = text
                .lines()
                .next()
                .unwrap_or(function)
                .trim_end_matches(':');
            let mut s = serde_json::to_string_pretty(&serde_json::json!({
                "name": name,
                "isa": "wasm",
                "text": text,
            }))
            .unwrap_or_default();
            s.push('\n');
            s
        } else {
            text
        });
    }
    if data.starts_with(b"MZ") {
        return pe_listing(path, &data, function, pdb, style);
    }
    let f = if hexcavator_size::macho::is_macho_input(&data) {
        hexcavator_size::macho::function(&data, function)
    } else if hexcavator_size::elf::is_elf_input(&data) {
        hexcavator_size::elf::function(&data, function)
    } else {
        Err("-disassemble reads PE images, ELF and Mach-O files, and WebAssembly modules".into())
    }
    .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(render(&f, style, None))
}

/// A function's listing, in `style`, with its lines' sources if known.
fn render(
    f: &hexcavator_size::disasm::Function<'_>,
    style: Style,
    sources: Option<&dyn Fn(u64) -> Option<(String, u32)>>,
) -> String {
    use hexcavator_size::disasm::{self, Arch, Edge, Flow, Labels};
    use std::fmt::Write as _;
    let labels = if style == Style::Bloaty {
        Labels::Bloaty
    } else {
        Labels::Blocks
    };
    let l = disasm::decode(f, labels);
    match style {
        Style::Bloaty => disasm::text(&l),
        Style::Blocks => {
            let mut out = String::new();
            let _ = writeln!(out, "{}:", l.name);
            for b in &l.blocks {
                out.push('\n');
                let first = &l.lines[b.first];
                if let Some(n) = first.label {
                    let _ = writeln!(out, "{}:", l.label_name(n));
                }
                for line in &l.lines[b.first..b.first + b.count] {
                    let _ = writeln!(out, " {:>16x}    {}", line.address, line.text);
                }
            }
            if let Some((at, bytes)) = &l.rest {
                let bytes: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(
                    out,
                    "\n {at:>16x}    (not instructions) {}",
                    bytes.join(" ")
                );
            }
            out
        }
        Style::Json => {
            use serde_json::{Value, json};
            let hex = |a: u64| format!("{a:#x}");
            let bytes = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            // The source files, each once.
            let mut files: Vec<String> = Vec::new();
            let mut file_index: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            let mut lines = Vec::with_capacity(l.lines.len());
            for line in &l.lines {
                let mut o = json!({
                    "address": hex(line.address),
                    "bytes": bytes(&line.bytes),
                    "text": line.text,
                    "flow": match line.flow {
                        Flow::Next => "next",
                        Flow::Call => "call",
                        Flow::Jump => "jump",
                        Flow::Branch => "branch",
                        Flow::Return => "return",
                        Flow::Stop => "stop",
                    },
                });
                if let Some(n) = line.label {
                    o["label"] = Value::from(l.label_name(n));
                }
                if let Some(t) = line.target {
                    o["target"] = Value::from(hex(t));
                }
                if let Some((file, number)) = sources.and_then(|s| s(line.address)) {
                    let index = *file_index.entry(file).or_insert_with_key(|f| {
                        files.push(f.clone());
                        files.len() - 1
                    });
                    o["source"] = json!([index, number]);
                }
                lines.push(o);
            }
            let blocks: Vec<Value> = l
                .blocks
                .iter()
                .map(|b| {
                    json!({
                        "label": l.lines[b.first].label.map(|n| l.label_name(n)),
                        "first": b.first,
                        "count": b.count,
                        "successors": b.successors.iter().map(|&(to, edge)| json!({
                            "block": to,
                            "edge": match edge {
                                Edge::Next => "next",
                                Edge::Taken => "taken",
                                Edge::NotTaken => "not-taken",
                                Edge::Jump => "jump",
                            },
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            let mut s = serde_json::to_string_pretty(&json!({
                "name": l.name,
                "isa": match f.isa {
                    Arch::X64 => "x86-64",
                    other => other.name(),
                },
                "address": hex(f.address),
                "size": f.code.len(),
                "files": files,
                "lines": lines,
                "blocks": blocks,
                "rest": l.rest.as_ref().map(|(at, b)| json!({ "address": hex(*at), "bytes": bytes(b) })),
            }))
            .unwrap_or_default();
            s.push('\n');
            s
        }
    }
}

/// `-disassemble` for a PE image: the function from its PDB's symbols (by
/// the name they give it, or that name without its parameters), its code
/// from the image, and every symbol's address for its calls' names.
fn pe_listing(
    path: &Path,
    data: &[u8],
    function: &str,
    pdb: Option<&Path>,
    style: Style,
) -> Result<String, String> {
    use hexcavator_pe::consts::machine;
    use hexcavator_size::disasm::{Arch, Function};
    use hexcavator_size::symbols::SymbolKind;
    let image = Image::parse(data).map_err(|e| format!("{}: {e}", path.display()))?;
    let file = image
        .pe()
        .ok_or_else(|| format!("{}: not a PE image", path.display()))?;
    let isa = match file.machine() {
        machine::AMD64 => Arch::X64,
        machine::I386 | machine::CHPE_X86 => Arch::X86,
        machine::ARM64 | machine::ARM64EC | machine::ARM64X => Arch::Arm64,
        machine::ARMNT | machine::THUMB => Arch::Arm,
        m => {
            return Err(format!(
                "{}: no disassembler for machine {m:#06x}",
                path.display()
            ));
        }
    };
    let opened = hexcavator_program::Opened::open(path, pdb)?;
    let program = opened.program()?;
    let (debug, pdb_path) = (&program.debug, opened.debug_path());
    let syms = program.symbols()?;
    let code = |k: SymbolKind| {
        matches!(
            k,
            SymbolKind::Function
                | SymbolKind::PrimaryBlock
                | SymbolKind::SeparatedBlock
                | SymbolKind::Thunk
        )
    };
    let candidates: Vec<&hexcavator_size::symbols::Symbol> = syms
        .iter()
        .filter(|s| code(s.kind) && !s.folded && s.size.file > 0)
        .collect();
    // The name as given, else the one name that is it with parameters.
    let target = candidates
        .iter()
        .find(|s| s.name == function)
        .copied()
        .or_else(|| {
            let mut alone = hexcavator_size::disasm::ByNameAlone::new(function);
            for s in &candidates {
                alone.offer(s.addr, &s.name, || *s);
            }
            alone.take()
        });
    let target =
        target.ok_or_else(|| format!("{}: no function named '{function}'", path.display()))?;
    let rva = u32::try_from(target.addr).map_err(|_| format!("{}: bad address", path.display()))?;
    let size =
        u32::try_from(target.size.file).map_err(|_| format!("{}: bad size", path.display()))?;
    let bytes = file
        .bytes_at_rva(hexcavator_core::Rva(rva), size)
        .map_err(|e| format!("{}: {}: {e}", path.display(), target.name))?;
    let base = image.image_base();
    let mut names: Vec<(u64, String)> = syms
        .iter()
        .filter(|s| !s.folded)
        .map(|s| (base.wrapping_add(s.addr), s.name.clone()))
        .collect();
    names.sort_by_key(|a| a.0);
    names.dedup_by_key(|n| n.0);
    let f = Function {
        name: target.name.clone(),
        isa,
        // (Windows on ARM: Thumb code only.)
        thumb: isa == Arch::Arm,
        data: None,
        address: base.wrapping_add(target.addr),
        code: bytes,
        symbols: names,
    };
    if style != Style::Json {
        return Ok(render(&f, style, None));
    }
    // Each instruction's source line, from the PDB's line tables.
    let lines = debug
        .source_lines()
        .map_err(|e| format!("{}: {e}", pdb_path.display()))?;
    let source = |address: u64| -> Option<(String, u32)> {
        let rva = address.checked_sub(base)?;
        let i = lines
            .spans
            .partition_point(|s| s.addr <= rva)
            .checked_sub(1)?;
        let span = &lines.spans[i];
        if rva >= span.addr + span.size.max(1) {
            return None;
        }
        Some((lines.files.get(span.file as usize)?.clone(), span.line))
    };
    let text = render(&f, style, Some(&source));
    // Its parameters and locals, with where each lives (from the PDB).
    let mut json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    json["variables"] = variables_json(&program.variables(target.compiland, target.addr, isa));
    let mut s = serde_json::to_string_pretty(&json).unwrap_or_default();
    s.push('\n');
    Ok(s)
}

/// A function's parameters and locals as JSON: each one's name, type,
/// size, fields and its pointee's fields, and where it lives over which
/// addresses.
fn variables_json(vars: &[hexcavator_program::variables::Variable]) -> serde_json::Value {
    use hexcavator_program::variables::Where;
    use serde_json::{Value, json};
    let fields = |f: &[hexcavator_debuginfo::layout::FlatField]| {
        f.iter()
            .map(|f| json!({ "name": f.name, "offset": f.offset, "size": f.size }))
            .collect::<Vec<_>>()
    };
    let hex = |a: u64| format!("{a:#x}");
    Value::Array(
        vars.iter()
            .map(|v| {
                let ranges: Vec<Value> = v
                    .locations
                    .iter()
                    .filter_map(|l| {
                        let mut o = json!({
                            "start": hex(l.start),
                            "end": hex(l.end),
                            "gaps": l.gaps.iter().map(|&(at, n)| json!([hex(at), n])).collect::<Vec<_>>(),
                        });
                        match &l.place {
                            Where::Register(r) => o["register"] = Value::from(r.as_str()),
                            Where::Memory { base, offset } => {
                                o["base"] = Value::from(base.as_str());
                                o["offset"] = Value::from(*offset);
                            }
                            Where::Field { register, field } => {
                                o["register"] = Value::from(register.as_str());
                                o["field"] = Value::from(*field);
                            }
                            _ => return None,
                        }
                        Some(o)
                    })
                    .collect();
                json!({
                    "name": v.name,
                    "type": v.type_name,
                    "size": v.size,
                    "param": v.param,
                    "inlined": v.inlined,
                    "fields": fields(&v.fields),
                    "pointee": fields(&v.pointee),
                    "ranges": ranges,
                })
            })
            .collect(),
    )
}

pub fn run(args: &[String]) -> ExitCode {
    let options = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc size: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match analyze(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ereport!("hexc size: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The rollup of one image by `sources`, loading its PDB if a source
/// needs it.
/// The size model and symbols from a linker map.
fn map_model(
    image: &Image<'_>,
    map_path: &Path,
) -> Result<(Model, Vec<hexcavator_size::symbols::Symbol>), String> {
    let text = std::fs::read(map_path).map_err(|e| format!("{}: {e}", map_path.display()))?;
    let map = hexcavator_linkmap::parse(&String::from_utf8_lossy(&text));
    if map.groups.is_empty() {
        return Err(format!(
            "{}: not a linker map (no COFF groups)",
            map_path.display()
        ));
    }
    hexcavator_size::map::model(image, &map).map_err(|e| format!("{}: {e}", map_path.display()))
}

fn rollup_of(
    path: &Path,
    pdb: Option<&Path>,
    map: Option<&Path>,
    debug_file: Option<&Path>,
    sources: &[Source],
    customs: &[Option<CustomSource>],
    filter: Option<&regex::Regex>,
) -> Result<Rollup, String> {
    let maps = maps_of(path, pdb, map, debug_file, sources)?;
    Ok(finish_rollup(maps, customs, filter))
}

/// Rewrites custom sources' labels, then rolls up (filtered).
fn finish_rollup(
    maps: std::sync::Arc<hexcavator_size::sources::Maps>,
    customs: &[Option<CustomSource>],
    filter: Option<&regex::Regex>,
) -> Rollup {
    let maps = customized(maps, customs);
    Rollup::filtered(&maps, filter)
}

/// `maps` with custom sources' labels rewritten (a copy, if there are any:
/// the maps may be kept).
fn customized(
    maps: std::sync::Arc<hexcavator_size::sources::Maps>,
    customs: &[Option<CustomSource>],
) -> std::sync::Arc<hexcavator_size::sources::Maps> {
    if customs.iter().all(Option::is_none) {
        return maps;
    }
    let mut maps = std::sync::Arc::unwrap_or_clone(maps);
    for (i, c) in customs.iter().enumerate() {
        if let Some(c) = c {
            c.apply(&mut maps, i);
        }
    }
    std::sync::Arc::new(maps)
}

/// The maps of `sources` for the image at `path` (with the files given
/// for it): kept in memory, if what is built is (`hexc serve`), until the
/// files change. (A PDB found, not given, is the image's: the image
/// changes when it is relinked.)
fn maps_of(
    path: &Path,
    pdb: Option<&Path>,
    map: Option<&Path>,
    debug_file: Option<&Path>,
    sources: &[Source],
) -> Result<std::sync::Arc<hexcavator_size::sources::Maps>, String> {
    let mut files = vec![path];
    files.extend(pdb);
    files.extend(map);
    files.extend(debug_file);
    let what = format!(
        "size maps {sources:?} pdb={} map={} debug={}",
        pdb.is_some(),
        map.is_some(),
        debug_file.is_some()
    );
    hexcavator_program::cache::remember(&files, &what, || {
        build_maps(path, pdb, map, debug_file, sources)
    })
}

fn build_maps(
    path: &Path,
    pdb: Option<&Path>,
    map: Option<&Path>,
    debug_file: Option<&Path>,
    sources: &[Source],
) -> Result<hexcavator_size::sources::Maps, String> {
    let show = |p: &Path| p.display().to_string();
    let image_map = Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
    // (-pdb and -debug name an ELF, Mach-O, or WebAssembly file's DWARF
    // too, as -debug-file does.)
    let debug_file = debug_file.or(pdb);
    // The input as given, as bloaty names it (inputfiles, and armembers
    // outside an archive).
    let file_name = show(path);
    // WebAssembly modules: bloaty's sources for them.
    if hexcavator_size::wasm::is_wasm_input(&image_map) {
        let source_map = if sources
            .iter()
            .any(|s| matches!(s, Source::CompileUnits | Source::Inlines))
        {
            wasm_source_map(path, &image_map, debug_file)?
        } else {
            None
        };
        let maps = hexcavator_size::wasm::maps_with_source_map(
            &image_map,
            &file_name,
            sources,
            source_map.as_ref(),
        )
        .map_err(|e| format!("{}: {e}", show(path)))?;
        return Ok(maps);
    }
    // Mach-O and universal files: bloaty's Mach-O sources.
    if hexcavator_size::macho::is_macho_input(&image_map) {
        let debug = match debug_file {
            Some(_) => debug_map(debug_file)?,
            None => found_debug(path, &image_map),
        };
        let mut maps = hexcavator_size::macho::maps_with_debug(
            &image_map,
            &file_name,
            sources,
            debug.as_deref(),
        )
        .map_err(|e| format!("{}: {e}", show(path)))?;
        unix_map(&mut maps, map)?;
        return Ok(maps);
    }
    // ELF files and archives of them: bloaty's ELF sources.
    if hexcavator_size::elf::is_elf_input(&image_map) {
        let debug = match debug_file {
            Some(_) => debug_map(debug_file)?,
            None => found_debug(path, &image_map),
        };
        let mut maps = hexcavator_size::elf::maps_with_debug(
            &image_map,
            &file_name,
            sources,
            debug.as_deref(),
        )
        .map_err(|e| format!("{}: {e}", show(path)))?;
        unix_map(&mut maps, map)?;
        return Ok(maps);
    }
    // Objects, import objects, and libraries have no PDB to read.
    if is_object_input(&image_map) {
        let maps = hexcavator_size::objects::maps(&image_map, &file_name, sources)
            .map_err(|e| format!("{}: {e}", show(path)))?;
        return Ok(maps);
    }
    let image = Image::parse(&image_map).map_err(|e| format!("{}: {e}", show(path)))?;
    let maps = if let Some(map) = map {
        let (model, syms) = map_model(&image, map)?;
        let inputs = sources::Inputs {
            model: Some(&model),
            symbols: Some(&syms),
            file_name: &file_name,
            lines: None,
        };
        sources::maps(&image, inputs, sources)
    } else if sources.iter().any(|s| s.needs_debug_info()) {
        let opened = hexcavator_program::Opened::open(path, pdb)?;
        let program = opened.program()?;
        let model = program.model()?;
        let syms: &[symbols::Symbol] = if sources.iter().any(|s| s.is_symbols()) {
            program.symbols()?
        } else {
            &[]
        };
        // The line tables, for the source files (absent: none labeled).
        let lines = if sources.contains(&Source::SourceFiles) {
            program.debug.source_lines().ok()
        } else {
            None
        };
        let inputs = sources::Inputs {
            model: Some(model),
            symbols: Some(syms),
            file_name: &file_name,
            lines: lines.as_ref(),
        };
        sources::maps(&image, inputs, sources)
    } else {
        let inputs = sources::Inputs {
            model: None,
            symbols: None,
            file_name: &file_name,
            lines: None,
        };
        sources::maps(&image, inputs, sources)
    };
    Ok(maps)
}

/// A WebAssembly module's source map: the one at `explicit`, or else the
/// one its `sourceMappingURL` names, if that is a file beside the module.
pub(crate) fn wasm_source_map(
    module_path: &Path,
    module: &[u8],
    explicit: Option<&Path>,
) -> Result<Option<hexcavator_size::sourcemap::SourceMap>, String> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => {
            let Some(url) = hexcavator_wasm::Module::parse(module)
                .ok()
                .and_then(|m| m.source_mapping_url())
            else {
                return Ok(None);
            };
            let url = String::from_utf8_lossy(url);
            let url = url.strip_prefix("file://").unwrap_or(&url);
            if url.contains("://") {
                return Ok(None);
            }
            // (Named by the module: only beside it, or below; -source-map
            // gives any other.)
            let named = Path::new(url);
            if named.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            }) {
                return Ok(None);
            }
            let p = module_path.parent().unwrap_or(Path::new("")).join(url);
            // (Named by the module: a share or device isn't asked about.)
            if !hexcavator_mmap::is_local_path(&p) || !p.is_file() {
                return Ok(None);
            }
            p
        }
    };
    let text = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    hexcavator_size::sourcemap::parse(&text)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The `-source-map` file for `image`: the one whose ID is the image's path
/// as given, or its sourceMappingURL.
fn source_map_option(image: &Path, maps: &[(String, PathBuf)]) -> Option<PathBuf> {
    if maps.is_empty() {
        return None;
    }
    let given = image.to_string_lossy();
    if let Some((_, p)) = maps.iter().find(|(id, _)| *id == given) {
        return Some(p.clone());
    }
    let data = Mmap::open(image).ok()?;
    let module = hexcavator_wasm::Module::parse(&data).ok()?;
    let url = String::from_utf8_lossy(module.source_mapping_url()?).into_owned();
    maps.iter()
        .find(|(id, _)| *id == url)
        .map(|(_, p)| p.clone())
}

/// The debug file at `path`, mapped.
fn debug_map(path: Option<&Path>) -> Result<Option<Mmap>, String> {
    path.map(|p| Mmap::open(p).map_err(|e| format!("{}: {e}", p.display())))
        .transpose()
}

/// With a Unix linker's map (`-map`: lld's, GNU ld's, ld64's), `maps`'
/// `compileunits` and `libraries` from it (see `hexcavator_size::unixmap`).
fn unix_map(maps: &mut hexcavator_size::sources::Maps, map: Option<&Path>) -> Result<(), String> {
    let Some(path) = map else { return Ok(()) };
    let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let link =
        hexcavator_linkmap::unix::parse(&String::from_utf8_lossy(&text)).ok_or_else(|| {
            format!(
                "{}: not a linker map (lld's, GNU ld's, or ld64's)",
                path.display()
            )
        })?;
    hexcavator_size::unixmap::apply(maps, &link);
    Ok(())
}

/// The separate debug file of the ELF or Mach-O image at `path`, found
/// as every command finds it (see `hexcavator_program::find_debug`): none
/// if the image has its own DWARF, or none is found (its symbol table
/// then serves).
fn found_debug(path: &Path, data: &[u8]) -> Option<Mmap> {
    let image = Image::parse(data).ok()?;
    let (found, map) = hexcavator_program::find_debug(path, &image, None).ok()?;
    (found != path).then_some(map)
}

/// Whether `data` is a COFF object, an import object, or an archive.
pub(crate) fn is_object_input(data: &[u8]) -> bool {
    // (A COFF object's header has no magic: an ELF, Mach-O, or WebAssembly
    // file's start can read as one, and isn't.)
    let other = hexcavator_size::elf::is_elf_input(data)
        || hexcavator_size::macho::is_macho_input(data)
        || hexcavator_size::wasm::is_wasm_input(data);
    hexcavator_archive::Archive::is_archive(data)
        || hexcavator_pe::import_object::ImportObject::is_import_object(data)
        || (!other && !data.starts_with(b"MZ") && hexcavator_pe::PeFile::parse_object(data).is_ok())
}

fn bloaty(options: &Options, out: &mut impl Write) -> Result<(), String> {
    let debug_file = options
        .debug_file
        .clone()
        .or_else(|| source_map_option(&options.image, &options.source_maps));
    let mut rollup = rollup_of(
        &options.image,
        options.pdb.as_deref(),
        options.map.as_deref(),
        debug_file.as_deref(),
        &options.sources,
        &options.customs,
        options.source_filter.as_ref(),
    )?;
    // More images: summed (each finds its own debug information).
    for more in &options.more {
        add_image(&mut rollup, more, options)?;
    }
    let base = match &options.base {
        Some(b) => {
            let mut r = rollup_of(
                b,
                options.base_pdb.as_deref(),
                options.base_map.as_deref(),
                options
                    .base_debug_file
                    .clone()
                    .or_else(|| source_map_option(b, &options.source_maps))
                    .as_deref(),
                &options.sources,
                &options.customs,
                options.source_filter.as_ref(),
            )?;
            for more in &options.more_bases {
                add_image(&mut r, more, options)?;
            }
            Some(r)
        }
        None => None,
    };
    // What every source says about the addresses asked about, and the
    // maps themselves (of the first image).
    if !options.debug_vm.is_empty() || !options.debug_file_offsets.is_empty() || options.raw_map {
        let maps = maps_of(
            &options.image,
            options.pdb.as_deref(),
            options.map.as_deref(),
            debug_file.as_deref(),
            &options.sources,
        )?;
        let mut text = String::new();
        explain(&maps, &options.source_names, options, &mut text);
        out.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    }
    let names: Vec<&str> = options.source_names.iter().map(String::as_str).collect();
    let report_options = rollup::Options {
        max_rows: options.rows,
        min: options.min,
        sort_by: options.sort_by,
        domain: options.domain,
    };
    let report = Report::new(&names, &rollup, base.as_ref(), &report_options);
    let text = match options.format {
        Format::Pretty => report.pretty(&report_options),
        Format::Csv => report.csv(false),
        Format::Tsv => report.csv(true),
        Format::Json => report.json(),
    };
    out.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

/// bloaty's `--debug-vmaddr`, `--debug-fileoff`, and `--raw-map`: each
/// source's label at each address asked about, then (if asked) every map's
/// ranges.
fn explain(
    maps: &hexcavator_size::sources::Maps,
    names: &[String],
    options: &Options,
    out: &mut String,
) {
    use std::fmt::Write as _;
    let name = |l| maps.labels.name(l);
    let mut sources: Vec<(&str, &hexcavator_size::rangemap::DualMap)> =
        vec![("[base]", &maps.base)];
    for (i, (_, m)) in maps.sources.iter().enumerate() {
        sources.push((names.get(i).map_or("?", String::as_str), m));
    }
    for (domain, list) in [
        ("VM address", &options.debug_vm),
        ("file offset", &options.debug_file_offsets),
    ] {
        for &addr in list {
            let _ = writeln!(out, "{domain} {addr:#x}:");
            for (source, m) in &sources {
                let map = if domain == "VM address" {
                    &m.vm
                } else {
                    &m.file
                };
                match map.get(addr) {
                    Some(e) => {
                        let _ = writeln!(
                            out,
                            "  {source:<14} [{:#x}, {:#x})  {}",
                            e.start,
                            e.end,
                            name(e.label)
                        );
                    }
                    None => {
                        let _ = writeln!(out, "  {source:<14} (nothing)");
                    }
                }
            }
        }
    }
    if options.raw_map {
        for (source, m) in &sources {
            for (domain, map) in [("VM", &m.vm), ("file", &m.file)] {
                let _ = writeln!(out, "{source} {domain} map:");
                for e in map.iter() {
                    let _ = writeln!(
                        out,
                        "  [{:#010x}, {:#010x})  {}",
                        e.start,
                        e.end,
                        name(e.label)
                    );
                }
            }
        }
    }
    out.push('\n');
}

/// Adds the image at `path` to `rollup` (one of several given), with its
/// own debug information.
fn add_image(rollup: &mut Rollup, path: &Path, options: &Options) -> Result<(), String> {
    let debug = source_map_option(path, &options.source_maps);
    let maps = maps_of(path, None, None, debug.as_deref(), &options.sources)?;
    let maps = customized(maps, &options.customs);
    rollup.add_maps_filtered(&maps, options.source_filter.as_ref());
    Ok(())
}

fn finish(result: io::Result<()>) -> Result<(), String> {
    result.or_else(|e| {
        // A closed pipe (`| head`) is not an error.
        if e.kind() == io::ErrorKind::BrokenPipe {
            Ok(())
        } else {
            Err(e.to_string())
        }
    })
}

fn analyze(options: &Options) -> Result<(), String> {
    if options.version {
        return finish(writeln!(
            crate::out::stdout(),
            "hexc {}",
            env!("CARGO_PKG_VERSION")
        ));
    }
    if options.list_sources {
        let mut out = crate::out::stdout();
        let text: String = Source::ALL
            .iter()
            .map(|s| format!("{:<15} {}\n", s.name(), s.description()))
            .collect();
        return finish(out.write_all(text.as_bytes()));
    }
    if let Some(budget) = &options.budget {
        let mut out = crate::out::stdout();
        return check_budget(options, budget, &mut out);
    }
    if options.table {
        let text = size_table(options)?;
        return finish(crate::out::stdout().write_all(text.as_bytes()));
    }
    if options.mangled {
        let text = mangled_names(options)?;
        return finish(crate::out::stdout().write_all(text.as_bytes()));
    }
    if let Some(name) = &options.definition {
        let text = definition(options, name)?;
        return finish(crate::out::stdout().write_all(text.as_bytes()));
    }
    if let Some(function) = &options.disassemble {
        let style = if options.format == Format::Json {
            Style::Json
        } else if options.blocks {
            Style::Blocks
        } else {
            Style::Bloaty
        };
        let text = disassemble(&options.image, function, options.pdb.as_deref(), style)?;
        return finish(crate::out::stdout().write_all(text.as_bytes()));
    }
    let object = Mmap::open(&options.image).is_ok_and(|m| {
        is_object_input(&m)
            || hexcavator_size::elf::is_elf_input(&m)
            || hexcavator_size::macho::is_macho_input(&m)
            || hexcavator_size::wasm::is_wasm_input(&m)
    });
    // (-sizebench and -findings read the image's debug information, of any
    // format; without them, the other formats' report is bloaty's.)
    let wants_model = options.sizebench || options.findings;
    if !options.sources.is_empty() || (object && !wants_model) {
        let mut options_with_default;
        let options = if options.sources.is_empty() {
            // Objects, libraries, and ELF, Mach-O, and WebAssembly files
            // report bloaty-style by default.
            options_with_default = Options {
                sources: vec![Source::Sections],
                ..options.clone()
            };
            options_with_default.base = options.base.clone();
            &options_with_default
        } else {
            options
        };
        let mut out = io::BufWriter::new(crate::out::stdout());
        return match bloaty(options, &mut out) {
            Ok(()) => finish(out.flush()),
            Err(e) if e.contains("Broken pipe") || e.contains("pipe is being closed") => Ok(()),
            Err(e) => Err(e),
        };
    }
    let path = &options.image;
    let show = |p: &Path| p.display().to_string();
    let image_map = Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
    if is_object_input(&image_map) {
        return Err(format!(
            "{}: -sizebench and -findings read linked images, not objects or libraries",
            show(path)
        ));
    }
    let image = Image::parse(&image_map).map_err(|e| format!("{}: {e}", show(path)))?;
    if let Some(map_path) = &options.map {
        if options.findings {
            return Err("-findings needs the image's PDB, not its map".into());
        }
        let (model, _) = map_model(&image, map_path)?;
        let mut out = io::BufWriter::new(crate::out::stdout());
        let result = if options.sizebench {
            report::sizebench_lines(&model)
                .iter()
                .try_for_each(|l| writeln!(out, "{l}"))
        } else {
            write_tables(
                &mut out,
                &model,
                path,
                &format!("Map: {}", map_path.display()),
                options.top,
            )
        };
        return finish(result.and_then(|()| out.flush()));
    }
    let debug_option = options.pdb.as_deref().or(options.debug_file.as_deref());
    let opened = hexcavator_program::Opened::open(path, debug_option)?;
    let program = opened.program()?;
    let (debug, pdb_path) = (&program.debug, opened.debug_path());
    let model = program.model()?;

    if options.findings {
        let syms = program.symbols()?;
        let modules = debug.compilands().map_err(|e| e.to_string())?;
        let name = |c: u32| {
            modules
                .get(c as usize)
                .map_or_else(String::new, |m| m.name.clone())
        };
        let limit = if options.top == usize::MAX {
            0
        } else {
            options.top
        };
        if let Some(base_path) = &options.base {
            let base_opened =
                hexcavator_program::Opened::open(base_path, options.base_pdb.as_deref())?;
            let base = base_opened.program()?;
            let (base_image, base_debug) = (&base.image, &base.debug);
            let base_syms = base.symbols()?;
            let new = hexcavator_size::findings::find(&image, debug, syms);
            let old = hexcavator_size::findings::find(base_image, base_debug, base_syms);
            let (text, json) = hexcavator_size::findings::compare(&new, &old, limit);
            let out = if options.format == Format::Json {
                json
            } else {
                text
            };
            return finish(crate::out::stdout().write_all(out.as_bytes()));
        }
        let (text, json) = hexcavator_size::findings::report(
            &image,
            debug,
            syms,
            &name,
            hexcavator_size::findings::ReportOptions { limit },
        );
        let out = if options.format == Format::Json {
            json
        } else {
            text
        };
        return finish(crate::out::stdout().write_all(out.as_bytes()));
    }

    let mut out = io::BufWriter::new(crate::out::stdout());
    let result = if options.sizebench {
        report::sizebench_lines(model)
            .iter()
            .try_for_each(|l| writeln!(out, "{l}"))
    } else {
        write_tables(
            &mut out,
            model,
            path,
            &format!(
                "{}: {}",
                if debug.pdb().is_some() {
                    "PDB"
                } else {
                    "Debug"
                },
                pdb_path.display()
            ),
            options.top,
        )
    };
    finish(result.and_then(|()| out.flush()))
}

/// `n` with thousands separators.
fn num(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn or_unknown(name: &str) -> &str {
    if name.is_empty() { "[unknown]" } else { name }
}

fn write_tables(
    out: &mut impl Write,
    model: &Model,
    image: &Path,
    source: &str,
    top: usize,
) -> io::Result<()> {
    let arch = model.arch.map_or("unknown", |a| a.name());
    writeln!(out, "{} ({arch})", image.display())?;
    writeln!(out, "{source}")?;
    writeln!(out)?;

    let total = model
        .sections
        .iter()
        .fold(Size::default(), |acc, s| acc + s.size);
    writeln!(
        out,
        "{:<32} {:>14} {:>14} {:>12}",
        "Section / COFF group", "File size", "Memory size", "Padding"
    )?;
    for (si, s) in model.sections.iter().enumerate() {
        writeln!(
            out,
            "{:<32} {:>14} {:>14} {:>12}",
            s.name,
            num(s.size.file),
            num(s.size.vm),
            num(s.vm_padding)
        )?;
        for g in model.groups.iter().filter(|g| g.section as usize == si) {
            writeln!(
                out,
                "  {:<30} {:>14} {:>14} {:>12}",
                g.name,
                num(g.size.file),
                num(g.size.vm),
                num(g.padding.vm.min(u64::from(u32::MAX)))
            )?;
        }
    }
    writeln!(
        out,
        "{:<32} {:>14} {:>14}",
        "Total",
        num(total.file),
        num(total.vm)
    )?;

    let by_library = model.totals(|p| Some(model.library_of(p.compiland)));
    let mut libraries: Vec<(u32, Size)> = by_library.iter().map(|(&l, t)| (l, t.size)).collect();
    libraries.sort_by(|a, b| {
        b.1.file
            .cmp(&a.1.file)
            .then(b.1.vm.cmp(&a.1.vm))
            .then(a.0.cmp(&b.0))
    });
    writeln!(out)?;
    writeln!(
        out,
        "Libraries: {} (by file size{})",
        libraries.len(),
        if libraries.len() > top {
            format!(", top {top}")
        } else {
            String::new()
        }
    )?;
    writeln!(out, "{:>14} {:>14}  Library", "File size", "Memory size")?;
    for (l, size) in libraries.iter().take(top) {
        writeln!(
            out,
            "{:>14} {:>14}  {}",
            num(size.file),
            num(size.vm),
            or_unknown(&model.libraries[*l as usize].name)
        )?;
    }

    let by_compiland = model.totals(|p| Some(p.compiland));
    let mut compilands: Vec<(u32, Size)> = by_compiland.iter().map(|(&c, t)| (c, t.size)).collect();
    compilands.sort_by(|a, b| {
        b.1.file
            .cmp(&a.1.file)
            .then(b.1.vm.cmp(&a.1.vm))
            .then(a.0.cmp(&b.0))
    });
    writeln!(out)?;
    writeln!(
        out,
        "Compilands: {} (by file size{})",
        compilands.len(),
        if compilands.len() > top {
            format!(", top {top}")
        } else {
            String::new()
        }
    )?;
    writeln!(out, "{:>14} {:>14}  Compiland", "File size", "Memory size")?;
    for (c, size) in compilands.iter().take(top) {
        writeln!(
            out,
            "{:>14} {:>14}  {}",
            num(size.file),
            num(size.vm),
            or_unknown(&model.compilands[*c as usize].name)
        )?;
    }

    // What the model doesn't attribute yet: bytes of groups no compiland
    // contributed (linker-generated tables, padding, ...).
    let attributed = model.totals(|p| (p.group != NO_GROUP).then_some(()));
    let attributed = attributed.get(&()).map_or(Size::default(), |t| t.size);
    let in_groups = model
        .groups
        .iter()
        .fold(Size::default(), |acc, g| acc + g.size);
    writeln!(out)?;
    writeln!(
        out,
        "Attributed to compilands: {} of {} bytes in COFF groups ({} of {} in memory)",
        num(attributed.file),
        num(in_groups.file),
        num(attributed.vm),
        num(in_groups.vm)
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(num(0), "0");
        assert_eq!(num(999), "999");
        assert_eq!(num(1000), "1,000");
        assert_eq!(num(1_234_567), "1,234,567");
        assert_eq!(num(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn options() {
        let args = |v: &[&str]| {
            v.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
        };
        let o = parse(&args(&["-pdb", "x.pdb", "--top", "5", "a.dll"])).unwrap();
        assert_eq!(o.image, PathBuf::from("a.dll"));
        assert_eq!(o.pdb, Some(PathBuf::from("x.pdb")));
        assert_eq!(o.top, 5);
        assert!(!o.sizebench);
        let o = parse(&args(&["a.dll", "-sizebench", "-top", "0"])).unwrap();
        assert!(o.sizebench);
        assert_eq!(o.top, usize::MAX);
        assert!(parse(&args(&[])).is_err());
        // Two images: summed, bloaty-style (not with -sizebench).
        assert_eq!(
            parse(&args(&["a.dll", "b.dll"])).unwrap().more,
            [PathBuf::from("b.dll")]
        );
        assert!(parse(&args(&["-sizebench", "a.dll", "b.dll"])).is_err());
        assert!(parse(&args(&["-top", "x", "a.dll"])).is_err());
        assert!(parse(&args(&["-pdb"])).is_err());
        assert!(parse(&args(&["-bogus", "a.dll"])).is_err());
    }

    #[test]
    fn bloaty_options() {
        let args = |v: &[&str]| {
            v.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
        };
        let o = parse(&args(&[
            "-d",
            "sections,symbols",
            "-d",
            "armembers",
            "a.dll",
        ]))
        .unwrap();
        assert_eq!(
            o.sources,
            [Source::Sections, Source::Symbols, Source::ArMembers]
        );
        assert_eq!(o.rows, 20);
        assert_eq!(o.format, Format::Pretty);
        let o = parse(&args(&[
            "a.dll", "-n", "0", "-s", "vm", "-domain", "file", "-csv", "--", "b.dll",
        ]))
        .unwrap();
        assert_eq!(o.rows, usize::MAX);
        assert_eq!(o.sort_by, SortBy::Vm);
        assert_eq!(o.domain, Domain::File);
        assert_eq!(o.format, Format::Csv);
        assert_eq!(o.base, Some(PathBuf::from("b.dll")));
        // A diff reports by sections unless told otherwise.
        assert_eq!(o.sources, [Source::Sections]);
        assert!(parse(&args(&["-list-sources"])).unwrap().list_sources);
        assert!(parse(&args(&["-d", "bogus", "a.dll"])).is_err());
        assert!(parse(&args(&["-s", "size", "a.dll"])).is_err());
        assert!(parse(&args(&["-domain", "x", "a.dll"])).is_err());
        assert!(parse(&args(&["a.dll", "--"])).is_err());
        // Several images, and several bases: summed, by sections.
        let o = parse(&args(&["a.o", "b.o", "--", "c.o", "d.o"])).unwrap();
        assert_eq!(o.more, [PathBuf::from("b.o")]);
        assert_eq!(o.more_bases, [PathBuf::from("d.o")]);
        assert_eq!(o.sources, [Source::Sections]);
        assert!(parse(&args(&["-findings", "a.dll", "b.dll"])).is_err());
        assert!(parse(&args(&["-n", "x", "a.dll"])).is_err());
    }
}

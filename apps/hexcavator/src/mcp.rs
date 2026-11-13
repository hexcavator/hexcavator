//! `hexc mcp`: a Model Context Protocol server over stdio, so that LLM
//! agents can ask what the bytes of a binary are.
//!
//! Messages are JSON-RPC 2.0, one per line. Tools:
//!
//! - `size_report`: a bloaty-style report by data sources (sections,
//!   symbols, compilands, ...), optionally as a diff against a base.
//! - `symbols`: the largest symbols, filtered by name, kind, or section.
//! - `findings`: duplicate data and template bloat, with advice.
//! - `lookup`: what is at an address, by every source.
//!
//! Loaded binaries are cached for the session: the first question about a
//! large image reads its PDB; later ones are fast.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use serde_json::Value;

/// An object from members, in order.
fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
use hexcavator_mmap::Mmap;
use hexcavator_size::rollup::{self, Domain, Report, Rollup, SortBy};
use hexcavator_size::sources::{self, Maps, Source};
use hexcavator_size::symbols::Symbol;
use hexcavator_size::{Model, pe, symbols};

pub const USAGE: &str = "\
usage: hexc mcp

Serves the Model Context Protocol on stdin and stdout (JSON-RPC 2.0, one
message per line), with tools that report what the bytes of an executable,
object, or library are: size_report, symbols, findings, and lookup.";

/// The protocol versions this server speaks, newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// A binary, read once per session.
struct Loaded {
    path: PathBuf,
    map: Mmap,
    file_name: String,
    /// An object, library, or ELF file: no PDB, bloaty-style sources only.
    object: bool,
    /// An ELF file, or an archive of them.
    elf: bool,
    /// A Mach-O or universal file.
    macho: bool,
    /// A WebAssembly module.
    wasm: bool,
    /// A module's source map, found beside it.
    source_map: Option<hexcavator_size::sourcemap::SourceMap>,
    pdb: Option<(PathBuf, Mmap)>,
    /// The size model and symbols, built when first needed.
    model: std::cell::OnceCell<Result<Model, String>>,
    symbols: std::cell::OnceCell<Result<Vec<Symbol>, String>>,
    /// The cross-reference graph, built once.
    xref: std::cell::OnceCell<Result<hexcavator_size::xref::Xref, String>>,
    /// Maps built so far, by their sources.
    maps: std::cell::RefCell<HashMap<Vec<Source>, Rc<Maps>>>,
}

impl Loaded {
    fn open(path: &Path, pdb: Option<&Path>) -> Result<Self, String> {
        let show = |p: &Path| p.display().to_string();
        let map = Mmap::open(path).map_err(|e| format!("{}: {e}", show(path)))?;
        let elf = hexcavator_size::elf::is_elf_input(&map);
        let macho = hexcavator_size::macho::is_macho_input(&map);
        let wasm = hexcavator_size::wasm::is_wasm_input(&map);
        let object = elf || macho || wasm || crate::size::is_object_input(&map);
        let pdb = if object {
            None
        } else {
            let image = Image::parse(&map).map_err(|e| format!("{}: {e}", show(path)))?;
            // Without a PDB, only the image's own sources are available.
            hexcavator_program::find_debug(path, &image, pdb).ok()
        };
        let file_name = path
            .file_name()
            .map_or_else(|| show(path), |n| n.to_string_lossy().into_owned());
        let source_map = if wasm {
            crate::size::wasm_source_map(path, &map, None)?
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            map,
            file_name,
            object,
            elf,
            macho,
            wasm,
            source_map,
            pdb,
            model: Default::default(),
            symbols: Default::default(),
            xref: Default::default(),
            maps: Default::default(),
        })
    }

    fn debug(&self) -> Result<DebugInfo<'_>, String> {
        let (path, map) = self
            .pdb
            .as_ref()
            .ok_or("no matching PDB was found; give one with the `pdb` argument")?;
        DebugInfo::parse(map).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn model(&self) -> Result<&Model, String> {
        self.model
            .get_or_init(|| {
                let image = Image::parse(&self.map).map_err(|e| e.to_string())?;
                let debug = self.debug()?;
                pe::check(&image, &debug).map_err(|e| e.to_string())?;
                pe::model(&image, &debug).map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn symbols(&self) -> Result<&[Symbol], String> {
        self.symbols
            .get_or_init(|| {
                let model = self.model()?;
                let image = Image::parse(&self.map).map_err(|e| e.to_string())?;
                let debug = self.debug()?;
                let pdb = self.pdb.as_ref().map(|(p, _)| p.as_path());
                let build = || symbols::build(&image, &debug, model).map_err(|e| e.to_string());
                match pdb {
                    Some(pdb) => hexcavator_program::cache::indexed(&self.path, &[pdb], build),
                    None => build(),
                }
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    /// The cross-reference graph of the image, built once.
    fn xref(&self) -> Result<&hexcavator_size::xref::Xref, String> {
        self.xref
            .get_or_init(|| {
                let syms = self.symbols()?;
                let model = self.model()?;
                let image = Image::parse(&self.map).map_err(|e| e.to_string())?;
                let debug = self.debug()?;
                hexcavator_size::xref::build(&image, &debug, model, syms)
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The maps for `list`, built once.
    fn maps(&self, list: &[Source]) -> Result<Rc<Maps>, String> {
        if let Some(m) = self.maps.borrow().get(list) {
            return Ok(Rc::clone(m));
        }
        let m = Rc::new(self.build_maps(list)?);
        self.maps.borrow_mut().insert(list.to_vec(), Rc::clone(&m));
        Ok(m)
    }

    fn build_maps(&self, list: &[Source]) -> Result<Maps, String> {
        if self.wasm {
            return hexcavator_size::wasm::maps_with_source_map(
                &self.map,
                &self.file_name,
                list,
                self.source_map.as_ref(),
            )
            .map_err(|e| e.to_string());
        }
        if self.macho {
            return hexcavator_size::macho::maps(&self.map, &self.file_name, list)
                .map_err(|e| e.to_string());
        }
        if self.elf {
            return hexcavator_size::elf::maps(&self.map, &self.file_name, list)
                .map_err(|e| e.to_string());
        }
        if self.object {
            return hexcavator_size::objects::maps(&self.map, &self.file_name, list)
                .map_err(|e| e.to_string());
        }
        let image = Image::parse(&self.map).map_err(|e| e.to_string())?;
        let needs = list.iter().any(|s| s.needs_debug_info());
        let model = if needs { Some(self.model()?) } else { None };
        let syms = if list.iter().any(|s| s.is_symbols()) {
            Some(self.symbols()?)
        } else {
            None
        };
        let inputs = sources::Inputs {
            model,
            symbols: syms,
            file_name: &self.file_name,
            lines: None,
        };
        Ok(sources::maps(&image, inputs, list))
    }
}

#[derive(Default)]
struct Server {
    cache: HashMap<(PathBuf, Option<PathBuf>), Rc<Loaded>>,
}

/// A tool's failure, reported to the client as a tool result.
type ToolResult = Result<(String, Value), String>;

fn arg_str<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str)
}

fn arg_path(args: &Value, name: &str) -> Option<PathBuf> {
    arg_str(args, name).map(PathBuf::from)
}

/// Sources from an array of names or a comma-separated string.
fn arg_sources(args: &Value, default: &[Source]) -> Result<Vec<Source>, String> {
    let names: Vec<String> = match args.get("sources") {
        None | Some(Value::Null) => return Ok(default.to_vec()),
        Some(Value::String(s)) => s.split(',').map(|s| s.trim().to_string()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(_) => return Err("`sources` must be an array of names".into()),
    };
    names
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| Source::parse(n).ok_or(format!("unknown data source '{n}'")))
        .collect()
}

fn parse_address(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => s.parse().ok().or_else(|| u64::from_str_radix(s, 16).ok()),
            }
        }
        other => other.as_u64(),
    }
}

impl Server {
    fn load(&mut self, path: &Path, pdb: Option<&Path>) -> Result<Rc<Loaded>, String> {
        let key = (path.to_path_buf(), pdb.map(Path::to_path_buf));
        if let Some(l) = self.cache.get(&key) {
            return Ok(Rc::clone(l));
        }
        let l = Rc::new(Loaded::open(path, pdb)?);
        self.cache.insert(key, Rc::clone(&l));
        Ok(l)
    }

    fn loaded_from(&mut self, args: &Value) -> Result<Rc<Loaded>, String> {
        let path = arg_path(args, "path").ok_or("`path` is required")?;
        let pdb = arg_path(args, "pdb");
        self.load(&path, pdb.as_deref())
    }

    fn size_report(&mut self, args: &Value) -> ToolResult {
        let loaded = self.loaded_from(args)?;
        let list = arg_sources(args, &[Source::Sections])?;
        let rows = args.get("rows").and_then(Value::as_u64).unwrap_or(20);
        let options = rollup::Options {
            max_rows: if rows == 0 {
                usize::MAX
            } else {
                usize::try_from(rows).unwrap_or(usize::MAX)
            },
            min: rollup::Threshold::None,
            sort_by: match arg_str(args, "sort") {
                Some("vm") => SortBy::Vm,
                Some("file") => SortBy::File,
                _ => SortBy::Both,
            },
            domain: match arg_str(args, "domain") {
                Some("vm") => Domain::Vm,
                Some("file") => Domain::File,
                _ => Domain::Both,
            },
        };
        let filter = arg_str(args, "source_filter")
            .map(|f| regex::Regex::new(f).map_err(|e| format!("source_filter: {e}")))
            .transpose()?;
        let rollup = Rollup::filtered(&*loaded.maps(&list)?, filter.as_ref());
        let base = match arg_path(args, "base") {
            Some(b) => {
                let base_pdb = arg_path(args, "base_pdb");
                let l = self.load(&b, base_pdb.as_deref())?;
                Some(Rollup::filtered(&*l.maps(&list)?, filter.as_ref()))
            }
            None => None,
        };
        let names: Vec<&str> = list.iter().map(|s| s.name()).collect();
        let report = Report::new(&names, &rollup, base.as_ref(), &options);
        let structured =
            serde_json::from_str::<Value>(&report.json()).map_err(|e| e.to_string())?;
        Ok((report.pretty(&options), structured))
    }

    fn symbols(&mut self, args: &Value) -> ToolResult {
        let loaded = self.loaded_from(args)?;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(50, |l| usize::try_from(l).unwrap_or(usize::MAX));
        let query = arg_str(args, "query").map(str::to_lowercase);
        let matches = |name: &str| {
            query
                .as_ref()
                .is_none_or(|q| name.to_lowercase().contains(q))
        };
        if loaded.object || loaded.pdb.is_none() {
            // Objects, and images without a PDB: the symbols source's labels.
            let maps = loaded.maps(&[Source::Symbols])?;
            let rollup = Rollup::new(&maps);
            let mut rows: Vec<(&str, i64, i64)> = rollup
                .children
                .iter()
                .filter(|(k, _)| matches(k))
                .map(|(k, r)| (&**k, r.file, r.vm))
                .collect();
            rows.sort_by(|a, b| b.1.max(b.2).cmp(&a.1.max(a.2)).then_with(|| a.0.cmp(b.0)));
            let total = rows.len();
            let list: Vec<Value> = rows
                .iter()
                .take(limit)
                .map(|(n, file, vm)| {
                    object([
                        ("name", Value::from(*n)),
                        ("file_size", Value::from(*file)),
                        ("vm_size", Value::from(*vm)),
                    ])
                })
                .collect();
            let text = rows
                .iter()
                .take(limit)
                .map(|(n, f, v)| format!("{f:>10} {v:>10}  {n}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Ok((
                format!("{total} symbols match; file and memory sizes:\n{text}"),
                object([
                    ("matched", Value::from(total)),
                    ("symbols", Value::Array(list)),
                ]),
            ));
        }
        let all = loaded.symbols()?;
        let model = loaded.model()?;
        let kind = arg_str(args, "kind").map(str::to_lowercase);
        let section = arg_str(args, "section");
        let folded = args
            .get("include_folded")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let section_of = |addr: u64| {
            model
                .sections
                .iter()
                .find(|s| addr >= s.addr && addr < s.addr + s.size.file.max(s.size.vm))
                .map_or("", |s| s.name.as_str())
        };
        let mut found: Vec<&Symbol> = all
            .iter()
            .filter(|s| folded || !s.folded)
            .filter(|s| matches(&s.name))
            .filter(|s| {
                kind.as_ref().is_none_or(|k| {
                    let name = s.kind.sizebench_name().to_lowercase();
                    name == *k
                        || name.starts_with(k.as_str())
                        || format!("{:?}", s.kind).to_lowercase() == *k
                })
            })
            .filter(|s| section.is_none_or(|n| section_of(s.addr) == n))
            .collect();
        match arg_str(args, "sort") {
            Some("address") => found.sort_by_key(|s| s.addr),
            Some("name") => found.sort_by(|a, b| a.name.cmp(&b.name)),
            _ => found.sort_by(|a, b| {
                b.size
                    .vm
                    .max(b.size.file)
                    .cmp(&a.size.vm.max(a.size.file))
                    .then_with(|| a.addr.cmp(&b.addr))
            }),
        }
        let total = found.len();
        let total_size: u64 = found.iter().map(|s| s.size.file).sum();
        let rows: Vec<Value> = found
            .iter()
            .take(limit)
            .map(|s| {
                object([
                    ("name", Value::from(s.name.as_str())),
                    ("kind", Value::from(s.kind.sizebench_name())),
                    ("rva", Value::from(format!("0x{:x}", s.addr))),
                    ("section", Value::from(section_of(s.addr))),
                    ("file_size", Value::from(s.size.file)),
                    ("vm_size", Value::from(s.size.vm)),
                    ("folded", Value::from(s.folded)),
                ])
            })
            .collect();
        let text = found
            .iter()
            .take(limit)
            .map(|s| {
                format!(
                    "{:>10} {:>10}  {:08x}  {}",
                    s.size.file, s.size.vm, s.addr, s.name
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok((
            format!(
                "{total} symbols match ({total_size} file bytes); file size, memory size, RVA, name:\n{text}"
            ),
            object([
                ("matched", Value::from(total)),
                ("matched_file_size", Value::from(total_size)),
                ("symbols", Value::Array(rows)),
            ]),
        ))
    }

    fn pe_only(loaded: &Loaded, what: &str) -> Result<(), String> {
        if loaded.object || loaded.pdb.is_none() || loaded.elf || loaded.macho || loaded.wasm {
            return Err(format!("{what} reads PE images with their PDBs"));
        }
        Ok(())
    }

    fn why(&mut self, args: &Value) -> ToolResult {
        let name = arg_str(args, "name")
            .ok_or("`name` is required")?
            .to_string();
        let loaded = self.loaded_from(args)?;
        Self::pe_only(&loaded, "why")?;
        let x = loaded.xref()?;
        let n = crate::xref::lookup(x, &name)?;
        Ok((crate::xref::why_text(x, n), crate::xref::why_json(x, n)))
    }

    fn recommend(&mut self, args: &Value) -> ToolResult {
        let loaded = self.loaded_from(args)?;
        Self::pe_only(&loaded, "recommend")?;
        let x = loaded.xref()?;
        let model = loaded.model()?;
        let syms = loaded.symbols()?;
        let image = Image::parse(&loaded.map).map_err(|e| e.to_string())?;
        let debug = loaded.debug()?;
        let r = crate::recommend::recommendations(&image, &debug, model, x, syms);
        let structured =
            serde_json::from_str(&crate::recommend::as_json(&r)).map_err(|e| e.to_string())?;
        Ok((crate::recommend::as_text(&r), structured))
    }

    fn query(&mut self, args: &Value) -> ToolResult {
        use hexcavator_size::table::{COLUMNS, SymbolTable};
        let text = arg_str(args, "query").unwrap_or("");
        let mut query = hexcavator_query::parse(text, &COLUMNS).map_err(|e| e.to_string())?;
        if query.limit.is_none() {
            query.limit = Some(50);
        }
        let loaded = self.loaded_from(args)?;
        if loaded.object || loaded.pdb.is_none() {
            return Err("query reads PE images with their PDBs".into());
        }
        let syms = loaded.symbols()?;
        let model = loaded.model()?;
        let modules = loaded.debug()?.compilands().map_err(|e| e.to_string())?;
        let lines = loaded.debug()?.source_lines().map_err(|e| e.to_string())?;
        let out = hexcavator_query::run(
            &query,
            &SymbolTable::new(model, syms, &modules).with_lines(&lines),
        )
        .map_err(|e| e.message)?;
        let rows: Vec<Value> = out
            .rows
            .iter()
            .map(|r| {
                Value::Object(
                    out.columns
                        .iter()
                        .zip(r)
                        .map(|(c, v)| (c.clone(), crate::query::value_json(v)))
                        .collect(),
                )
            })
            .collect();
        Ok((
            crate::query::table_text(&out),
            object([
                ("matched", Value::from(out.matched)),
                ("rows", Value::Array(rows)),
            ]),
        ))
    }

    fn lookup(&mut self, args: &Value) -> ToolResult {
        let loaded = self.loaded_from(args)?;
        let addr = args
            .get("address")
            .and_then(parse_address)
            .ok_or("`address` is required (a number, or a hex string like \"0x1000\")")?;
        let file = arg_str(args, "domain") == Some("file");
        let mut list = vec![Source::Sections];
        if loaded.elf || loaded.macho {
            list.extend([Source::Segments, Source::Symbols, Source::ArMembers]);
        } else if loaded.object || loaded.pdb.is_some() {
            list.extend([
                Source::Groups,
                Source::Symbols,
                Source::CompileUnits,
                Source::Libraries,
            ]);
        }
        let maps = loaded.maps(&list)?;
        let mut by_source = Vec::new();
        let mut text = Vec::new();
        for (source, map) in &maps.sources {
            let m = if file { &map.file } else { &map.vm };
            if let Some(e) = m.get(addr) {
                let label = maps.labels.name(e.label);
                text.push(format!(
                    "{:<13} {label}  [0x{:x}, 0x{:x})",
                    source.name(),
                    e.start,
                    e.end
                ));
                by_source.push((
                    source.name(),
                    object([
                        ("label", Value::from(label)),
                        ("start", Value::from(format!("0x{:x}", e.start))),
                        ("end", Value::from(format!("0x{:x}", e.end))),
                    ]),
                ));
            }
        }
        // Every name at the symbol's address (folded ones too).
        let mut names = Vec::new();
        if !file && !loaded.object && loaded.pdb.is_some() {
            let all = loaded.symbols()?;
            let i = all.partition_point(|s| s.addr <= addr);
            if let Some(start) = all[..i]
                .iter()
                .rev()
                .find(|s| !s.folded && addr < s.addr + s.size.vm.max(s.size.file).max(1))
                .map(|s| s.addr)
            {
                for s in all.iter().filter(|s| s.addr == start) {
                    names.push(object([
                        ("name", Value::from(s.name.as_str())),
                        ("kind", Value::from(s.kind.sizebench_name())),
                        ("folded", Value::from(s.folded)),
                    ]));
                    text.push(format!(
                        "  {}{}",
                        if s.folded { "(folded) " } else { "" },
                        s.name
                    ));
                }
            }
        }
        if by_source.is_empty() {
            return Err(format!(
                "nothing is at 0x{addr:x} in the {}",
                if file { "file" } else { "image" }
            ));
        }
        Ok((
            format!("0x{addr:x}:\n{}", text.join("\n")),
            object([
                ("address", Value::from(format!("0x{addr:x}"))),
                ("domain", Value::from(if file { "file" } else { "vm" })),
                ("sources", object(by_source)),
                ("symbols", Value::Array(names)),
            ]),
        ))
    }

    fn findings(&mut self, args: &Value) -> ToolResult {
        let loaded = self.loaded_from(args)?;
        if loaded.object || loaded.pdb.is_none() {
            return Err("findings need an image and its PDB".into());
        }
        let syms = loaded.symbols()?;
        let image = Image::parse(&loaded.map).map_err(|e| e.to_string())?;
        let debug = loaded.debug()?;
        let modules = debug.compilands().map_err(|e| e.to_string())?;
        let name = |c: u32| {
            modules
                .get(c as usize)
                .map_or_else(String::new, |m| m.name.clone())
        };
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(20, |l| usize::try_from(l).unwrap_or(usize::MAX));
        let (text, json) = hexcavator_size::findings::report(
            &image,
            &debug,
            syms,
            &name,
            hexcavator_size::findings::ReportOptions { limit },
        );
        let structured = serde_json::from_str::<Value>(&json).map_err(|e| e.to_string())?;
        Ok((text, structured))
    }

    fn linker_log(&mut self, args: &Value) -> ToolResult {
        let log = arg_path(args, "log").ok_or("`log` is required")?;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(20, |l| usize::try_from(l).unwrap_or(usize::MAX));
        let options = |json| crate::linkerlog::Options {
            log: log.clone(),
            base: arg_path(args, "base"),
            why: arg_str(args, "why").map(str::to_string),
            image: arg_path(args, "path"),
            pdb: arg_path(args, "pdb"),
            top: if limit == 0 { usize::MAX } else { limit },
            json,
        };
        let text = crate::linkerlog::report(&options(false))?;
        let json = crate::linkerlog::report(&options(true))?;
        let structured = serde_json::from_str::<Value>(&json).map_err(|e| e.to_string())?;
        Ok((text, structured))
    }

    fn call(&mut self, name: &str, args: &Value) -> Option<ToolResult> {
        Some(match name {
            "linker_log" => self.linker_log(args),
            "findings" => self.findings(args),
            "size_report" => self.size_report(args),
            "symbols" => self.symbols(args),
            "lookup" => self.lookup(args),
            "query" => self.query(args),
            "why" => self.why(args),
            "recommend" => self.recommend(args),
            _ => return None,
        })
    }

    /// The response to one message, if it needs one.
    fn handle(&mut self, message: &Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(method) = method else {
            // A response or garbage: nothing to answer.
            return id.map(|id| error(id, -32600, "invalid request"));
        };
        // Notifications get no response.
        let id = id?;
        let result = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                let version = asked
                    .filter(|v| PROTOCOL_VERSIONS.contains(v))
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                object([
                    ("protocolVersion", Value::from(version)),
                    (
                        "capabilities",
                        object([("tools", object([("listChanged", Value::from(false))]))]),
                    ),
                    (
                        "serverInfo",
                        object([
                            ("name", Value::from("hexc")),
                            ("version", Value::from(env!("CARGO_PKG_VERSION"))),
                        ]),
                    ),
                    ("instructions", Value::from(INSTRUCTIONS)),
                ])
            }
            "ping" => object::<&str>([]),
            "tools/list" => tools(),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(object::<&str>([]));
                match self.call(name, &args) {
                    None => return Some(error(id, -32602, &format!("unknown tool '{name}'"))),
                    Some(Ok((text, structured))) => object([
                        (
                            "content",
                            Value::Array(vec![object([
                                ("type", Value::from("text")),
                                ("text", Value::from(text)),
                            ])]),
                        ),
                        ("structuredContent", structured),
                        ("isError", Value::from(false)),
                    ]),
                    Some(Err(e)) => object([
                        (
                            "content",
                            Value::Array(vec![object([
                                ("type", Value::from("text")),
                                ("text", Value::from(e)),
                            ])]),
                        ),
                        ("isError", Value::from(true)),
                    ]),
                }
            }
            other => return Some(error(id, -32601, &format!("method not found: {other}"))),
        };
        Some(object([
            ("jsonrpc", Value::from("2.0")),
            ("id", id),
            ("result", result),
        ]))
    }
}

const INSTRUCTIONS: &str = "hexc reports what the bytes of a Windows executable (PE, with its PDB), COFF object, or library are. Start with size_report on the file (sources: sections; then symbols, compileunits, libraries, or groups, or several for a breakdown). Use symbols to find the largest or a named symbol, findings for what wastes space and how to fix it, and lookup to ask what is at an address. Give `base` to size_report to diff two builds. Sizes are in bytes; `file` is bytes on disk, `vm` bytes in memory.";

fn error(id: Value, code: i64, message: &str) -> Value {
    object([
        ("jsonrpc", Value::from("2.0")),
        ("id", id),
        (
            "error",
            object([
                ("code", Value::from(code)),
                ("message", Value::from(message)),
            ]),
        ),
    ])
}

fn schema(properties: Vec<(&str, Value)>, required: &[&str]) -> Value {
    object([
        ("type", Value::from("object")),
        ("properties", object(properties)),
        (
            "required",
            Value::Array(required.iter().map(|r| Value::from(*r)).collect()),
        ),
    ])
}

fn prop(kind: &str, description: &str) -> Value {
    object([
        ("type", Value::from(kind)),
        ("description", Value::from(description)),
    ])
}

fn tools() -> Value {
    let path = prop(
        "string",
        "Path to an executable or DLL (PE), a COFF object (.obj), or a library (.lib).",
    );
    let pdb = prop(
        "string",
        "Path to the image's PDB, if it isn't found from the image.",
    );
    let sources: Vec<Value> = Source::ALL.iter().map(|s| Value::from(s.name())).collect();
    let tool = |name: &str, description: &str, input: Value| {
        object([
            ("name", Value::from(name)),
            ("description", Value::from(description)),
            ("inputSchema", input),
        ])
    };
    object([(
        "tools",
        Value::Array(vec![
            tool(
                "size_report",
                "Where the bytes of a binary go, rolled up by data sources (one level per source), as bloaty reports them: every byte of the file and of memory is counted once. With `base`, the difference from another build.",
                schema(
                    vec![
                        ("path", path.clone()),
                        ("pdb", pdb.clone()),
                        (
                            "sources",
                            object([
                                ("type", Value::from("array")),
                                (
                                    "items",
                                    object([
                                        ("type", Value::from("string")),
                                        ("enum", Value::Array(sources)),
                                    ]),
                                ),
                                (
                                    "description",
                                    Value::from(
                                        "Data sources, outermost first (default: [\"sections\"]).",
                                    ),
                                ),
                            ]),
                        ),
                        (
                            "rows",
                            prop(
                                "integer",
                                "Rows per level before the rest are folded into [N Others] (default 20; 0 for all).",
                            ),
                        ),
                        (
                            "sort",
                            prop(
                                "string",
                                "Sort by \"vm\", \"file\", or \"both\" (the larger; default).",
                            ),
                        ),
                        (
                            "domain",
                            prop(
                                "string",
                                "Show \"vm\", \"file\", or \"both\" sizes (default both).",
                            ),
                        ),
                        (
                            "base",
                            prop(
                                "string",
                                "A base build to diff against: sizes become differences.",
                            ),
                        ),
                        (
                            "base_pdb",
                            prop("string", "The base build's PDB, if it isn't found."),
                        ),
                        (
                            "source_filter",
                            prop(
                                "string",
                                "A regular expression: only regions some label of which matches are counted (the rest are reported as filtered).",
                            ),
                        ),
                    ],
                    &["path"],
                ),
            ),
            tool(
                "symbols",
                "The largest symbols of a binary (functions, data, strings, and the image's own structures such as imports, resources, and exception data), filtered by name, kind, or section.",
                schema(
                    vec![
                        ("path", path.clone()),
                        ("pdb", pdb.clone()),
                        (
                            "query",
                            prop("string", "A case-insensitive substring of the name."),
                        ),
                        (
                            "kind",
                            prop(
                                "string",
                                "A kind, such as function, data, public, string, pdata, or import (prefixes match).",
                            ),
                        ),
                        (
                            "section",
                            prop("string", "Only symbols in this section (such as .text)."),
                        ),
                        (
                            "sort",
                            prop("string", "\"size\" (default), \"address\", or \"name\"."),
                        ),
                        ("limit", prop("integer", "How many to list (default 50).")),
                        (
                            "include_folded",
                            prop(
                                "boolean",
                                "Include names folded into others by identical COMDAT folding (they have size 0).",
                            ),
                        ),
                    ],
                    &["path"],
                ),
            ),
            tool(
                "findings",
                "What wastes space in an image, with advice: variables duplicated across compilands (file-scope statics and non-extern consts in headers), and template families (instantiations of one template) by total size.",
                schema(
                    vec![
                        ("path", path.clone()),
                        ("pdb", pdb.clone()),
                        (
                            "limit",
                            prop("integer", "Items per finding (default 20; 0 for all)."),
                        ),
                    ],
                    &["path"],
                ),
            ),
            tool(
                "linker_log",
                "What a link's /VERBOSE output (link ... /VERBOSE > log) says: which library members were linked, what /OPT:REF discarded and /OPT:ICF folded; with `why`, why one member was linked (the symbol it was loaded for, and who referenced it, back to the command line); with `path` (the image, with its PDB), its largest library members, each with why it was linked.",
                schema(
                    vec![
                        (
                            "log",
                            prop("string", "Path to the linker's /VERBOSE output."),
                        ),
                        (
                            "why",
                            prop(
                                "string",
                                "A member to explain: lib(member), or just member.obj.",
                            ),
                        ),
                        (
                            "path",
                            prop(
                                "string",
                                "The image the log is of, to rank its library members by size.",
                            ),
                        ),
                        (
                            "base",
                            prop(
                                "string",
                                "A base build's log: what changed (members linked now and not then, with why; members no longer linked).",
                            ),
                        ),
                        ("pdb", pdb.clone()),
                        (
                            "limit",
                            prop(
                                "integer",
                                "How many members to list (default 20; 0 for all).",
                            ),
                        ),
                    ],
                    &["log"],
                ),
            ),
            tool(
                "query",
                "Query a PE image's symbols (from its PDB) as a table: filter, group, sort, and limit. Columns: name, kind (function, data, public, string, thunk, pdata, unwind, import-thunk, ...), file and vm (sizes), rva, section, group (COFF group), compiland, library, folded, static, source and line (where its code starts). The query is a filter (column op value joined by and/or/not and parentheses; ops = != < <= > >= ~ !~, ~ a regular expression; numbers take k, M, G), then any of: group by <columns> (count and summed sizes), sort by <column> [desc], select <columns>, limit <n> (default 50). Examples: \"kind=function file>4k sort by file desc limit 20\", \"name~'^std::' group by library\", \"static group by name sort by count desc\".",
                schema(
                    vec![
                        ("path", path.clone()),
                        ("pdb", pdb.clone()),
                        ("query", prop("string", "The query.")),
                    ],
                    &["path", "query"],
                ),
            ),
            tool(
                "why",
                "Why a function or datum is in a PE image: the chain of references from a root (the entry point, an export, a loader directory, a static initializer) to it (calls, branches, addresses its code uses, pointers in data such as vtable slots, exception data). If nothing reaches it, why the linker kept it anyway (its section isn't a COMDAT, or a kept one refers to it) and what refers to it.",
                schema(
                    vec![
                        ("path", path.clone()),
                        ("pdb", pdb.clone()),
                        (
                            "name",
                            prop(
                                "string",
                                "The name as the PDB gives it (\"Square::area() const\"), or without the parameters if just one function has it.",
                            ),
                        ),
                    ],
                    &["path", "name"],
                ),
            ),
            tool(
                "recommend",
                "Build changes that would make a PE image smaller, each with the bytes it would save, measured from the image and its PDB: compile an object with /Gy or /Gw, link with /OPT:REF or /OPT:ICF (when the link didn't), define a duplicated variable once.",
                schema(
                    vec![("path", path.clone()), ("pdb", pdb.clone())],
                    &["path"],
                ),
            ),
            tool(
                "lookup",
                "What is at an address of a binary, by every data source: section, COFF group, symbol (with every name folded there), compiland, and library.",
                schema(
                    vec![
                        ("path", path),
                        ("pdb", pdb),
                        (
                            "address",
                            prop(
                                "string",
                                "An RVA (or, with domain \"file\", a file offset), as a number or a hex string like \"0x1a2b0\".",
                            ),
                        ),
                        (
                            "domain",
                            prop(
                                "string",
                                "\"vm\" (default: the address is an RVA) or \"file\".",
                            ),
                        ),
                    ],
                    &["path", "address"],
                ),
            ),
        ]),
    )])
}

/// Serves `input` until it ends, writing responses to `output`.
pub fn serve(input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut server = Server::default();
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message) => server.handle(&message),
            Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(r) = response {
            writeln!(output, "{r}")?;
            output.flush()?;
        }
    }
    Ok(())
}

pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    let stdin = io::stdin().lock();
    let stdout = io::stdout().lock();
    match serve(stdin, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ereport!("hexc mcp: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(messages: &[&str]) -> Vec<Value> {
        let input = messages.join("\n");
        let mut out = Vec::new();
        serve(input.as_bytes(), &mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect()
    }

    #[test]
    fn protocol() {
        let r = exchange(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":"two","method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"bogus"}"#,
            r"not json",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"size_report","arguments":{}}}"#,
        ]);
        assert_eq!(r.len(), 7);
        let init = r[0].get("result").unwrap();
        assert_eq!(
            init.get("protocolVersion").unwrap().as_str(),
            Some("2025-03-26")
        );
        assert_eq!(
            init.get("serverInfo")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str(),
            Some("hexc")
        );
        assert_eq!(r[1].get("id").unwrap().as_str(), Some("two"));
        let tools = r[1]
            .get("result")
            .unwrap()
            .get("tools")
            .unwrap()
            .as_array()
            .unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t.get("name").unwrap().as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "size_report",
                "symbols",
                "findings",
                "linker_log",
                "query",
                "why",
                "recommend",
                "lookup"
            ]
        );
        assert!(r[2].get("result").is_some());
        assert_eq!(
            r[3].get("error").unwrap().get("code").unwrap().as_i64(),
            Some(-32601)
        );
        assert_eq!(
            r[4].get("error").unwrap().get("code").unwrap().as_i64(),
            Some(-32700)
        );
        assert_eq!(
            r[5].get("error").unwrap().get("code").unwrap().as_i64(),
            Some(-32602)
        );
        let failed = r[6].get("result").unwrap();
        assert_eq!(failed.get("isError").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_address(&Value::from("0x1A2b")), Some(0x1A2B));
        assert_eq!(parse_address(&Value::from("4096")), Some(4096));
        assert_eq!(parse_address(&Value::from("1a2b")), Some(0x1A2B));
        assert_eq!(parse_address(&Value::from(16)), Some(16));
        assert_eq!(parse_address(&Value::from("zz")), None);
        assert_eq!(parse_address(&Value::from(-1)), None);
    }

    #[test]
    fn source_arguments() {
        let v = serde_json::from_str::<Value>(r#"{"sources":["sections","symbols"]}"#).unwrap();
        assert_eq!(
            arg_sources(&v, &[]).unwrap(),
            [Source::Sections, Source::Symbols]
        );
        let v = serde_json::from_str::<Value>(r#"{"sources":"compileunits, libraries"}"#).unwrap();
        assert_eq!(
            arg_sources(&v, &[]).unwrap(),
            [Source::CompileUnits, Source::Libraries]
        );
        let v = serde_json::from_str::<Value>(r"{}").unwrap();
        assert_eq!(
            arg_sources(&v, &[Source::Groups]).unwrap(),
            [Source::Groups]
        );
        let v = serde_json::from_str::<Value>(r#"{"sources":["bogus"]}"#).unwrap();
        assert!(arg_sources(&v, &[]).is_err());
        let v = serde_json::from_str::<Value>(r#"{"sources":5}"#).unwrap();
        assert!(arg_sources(&v, &[]).is_err());
    }
}

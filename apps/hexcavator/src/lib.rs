//! The `hexc` command-line driver, as a library: [`run`] runs one command
//! (`hexc size ...` is `run(&["size", ...])`). The binary is a thin
//! `main` around it; the fuzzer drives every command through it.

#[macro_use]
mod out;
mod batch;
mod checksec;
mod data;
mod detect;
mod dump;
mod dwarfdump;
mod lines;
mod linkerlog;
mod mcp;
mod pdbdump;
mod query;
mod recommend;
mod serve;
mod signature;
mod size;
mod symbols;
mod time;
mod types;
mod xref;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_mmap::Mmap;

const USAGE: &str = "\
hexc (Hexcavator): explore executables, objects, and libraries, and their
debug information.

usage: hexc [--cache <path>] [--arch <name>] [symbol servers] <command> [args]

commands:
  annotations <image>        the strings code attached to addresses (__annotation)
  batch <files or dirs>...   a JSON line summarizing each image (sections, libraries, ...)
  checksec [-audit] <image>  its exploit mitigations; -audit: its objects' compilers and options
  data [options] <image> <name>  a datum's bytes, and its value read as its type
  dump [options] <file>...   dumpbin-style dump (see `hexc dump` for options)
  dwarf [options] <file>     dump a file's DWARF, as llvm-dwarfdump does (see `hexc dwarf`)
  info <file>...             identify the format of each file
  inlines [options] <image>  the functions inlined into its code, by their copies' bytes
  licenses                   the licenses of Hexcavator and of the code it includes
  linkerlog [options] <log>  the linker's /VERBOSE output: why each library member was linked
  mcp                        serve size, symbol, and reference tools to AI agents (MCP, stdio)
  pdb [options] <file.pdb>   dump a PDB (see `hexc pdb` for options)
  query <image> <query>      the image's symbols, filtered, grouped, and sorted
  recommend <image>          build changes that would make the image smaller, measured
  serve                      run commands for an editor, keeping what they read in memory
  signature [-json] <image>  its code signatures (Authenticode, Apple), verified on any platform
  size [options] <image>     where the bytes go, by section, library, and compiland
  sourcefiles <image>        its code by source file (and line)
  types [options] <image>    the layouts of its classes and structures, and their padding
  xref [options] <image>     what refers to what, and why each function and datum is there
  help                       show this message
  version                    show the version

options:
  --cache <path>             keep an index of each image's symbols, so that the
                             next command on it needn't build them: in <path>
                             if it is a file, or in the directory <path> (as
                             app.exe.<hash>.hexc-index); '--cache .' keeps them
                             in the current directory
  --arch <name>              the image of universal (fat) Mach-O files to read
                             (arm64, x86_64, ...; default: this machine's, else
                             the first)

Debug information is looked for beside the image, then in the symbol
directories (HEXC_SYMBOL_PATH; _NT_SYMBOL_PATH's local directories and
caches; debuginfod's cache), then on symbol servers, if given (nothing is
asked of a server otherwise; files are fetched with curl):
  --symbol-server <url>      a server with Microsoft's layout (SSQP), such as
                             https://msdl.microsoft.com/download/symbols
                             (HEXC_SYMBOL_SERVER: URLs separated by ';')
  --debuginfod <url>         a debuginfod server (HEXC_DEBUGINFOD: URLs
                             separated by spaces)
  --symbol-cache <dir>       where to keep what is fetched (HEXC_SYMBOL_CACHE;
                             else it is kept in memory only)

A Mach-O image with no dSYM found has its DWARF read from the object files
its debug map names (as the linker left them: relative to the image, or
where the linker ran; archive members too).";

/// hexc's own options, wherever they are among a command's.
#[derive(Default)]
struct Global {
    /// `--cache <path>`: the last given.
    cache: Option<PathBuf>,
    /// `--arch <name>`: the last given.
    arch: Option<String>,
    /// `--symbol-server`, `--debuginfod`, `--symbol-cache`.
    servers: hexcavator_program::server::Servers,
}

/// A symbol-server option at `a` (`--symbol-server <url>` or
/// `--symbol-server=<url>`, and `--debuginfod`, `--symbol-cache`) and its
/// value, taking it from `it` if it is the next argument.
fn server_option<'a>(
    a: &str,
    it: &mut impl Iterator<Item = &'a String>,
) -> Result<Option<(&'static str, String)>, String> {
    for option in ["--symbol-server", "--debuginfod", "--symbol-cache"] {
        if a == option {
            let v = it
                .next()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{option}: expected a value"))?;
            return Ok(Some((option, v.clone())));
        }
        if let Some(v) = a.strip_prefix(option).and_then(|r| r.strip_prefix('=')) {
            if v.is_empty() {
                return Err(format!("{option}: expected a value"));
            }
            return Ok(Some((option, v.to_string())));
        }
    }
    Ok(None)
}

/// `args` without hexc's own options (any before a `--`), and those
/// options.
fn global_options(args: &[String]) -> Result<(Vec<String>, Global), String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut global = Global::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            rest.push(a.clone());
            rest.extend(it.cloned());
            break;
        }
        if let Some(path) = a.strip_prefix("--cache=") {
            global.cache = Some(PathBuf::from(path));
        } else if a == "--cache" {
            let path = it.next().ok_or("--cache: expected a file or directory")?;
            global.cache = Some(PathBuf::from(path));
        } else if let Some((option, value)) = server_option(a, &mut it)? {
            let s = &mut global.servers;
            match option {
                "--symbol-server" => s.symbol_servers.push(value),
                "--debuginfod" => s.debuginfod.push(value),
                _ => s.cache = Some(PathBuf::from(value)),
            }
        } else if let Some(name) = a.strip_prefix("--arch=") {
            global.arch = Some(name.to_string());
        } else if a == "--arch" {
            let name = it.next().ok_or("--arch: expected an architecture's name")?;
            global.arch = Some(name.clone());
        } else {
            rest.push(a.clone());
        }
    }
    if global
        .cache
        .as_ref()
        .is_some_and(|p| p.as_os_str().is_empty())
    {
        return Err("--cache: expected a file or directory".into());
    }
    if let Some(name) = &global.arch
        && !hexcavator_macho::set_preferred_arch(Some(name))
    {
        let known: Vec<String> = hexcavator_macho::arch_names().collect();
        return Err(format!(
            "--arch: no architecture named '{name}' (the names are {})",
            known.join(", ")
        ));
    }
    Ok((rest, global))
}

/// Runs the command `args` names (without the program's name), with
/// hexc's own options (`--cache`, `--arch`, the symbol servers') anywhere
/// among them.
pub fn run(args: &[String]) -> ExitCode {
    let (args, global) = match global_options(args) {
        Ok(x) => x,
        Err(e) => {
            ereport!("hexc: {e}");
            return ExitCode::from(2);
        }
    };
    hexcavator_program::cache::set_file(global.cache);
    // Servers given here; else the environment's (if any).
    let mut servers = global.servers;
    if servers.is_empty() {
        let env = hexcavator_program::server::Servers::from_env();
        servers.symbol_servers = env.symbol_servers;
        servers.debuginfod = env.debuginfod;
        servers.cache = servers.cache.or(env.cache);
    }
    hexcavator_program::server::set_servers(servers);
    match args.first().map(String::as_str) {
        Some("mcp") => mcp::run(&args[1..]),
        Some("serve") => serve::run(&args[1..]),
        _ => command(&args),
    }
}

/// Runs the command `args` names: one of those that answer once (not the
/// servers).
fn command(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    };
    match command.as_str() {
        "data" => data::run(rest),
        "dump" => dump::run(rest),
        "pdb" => pdbdump::run(rest),
        "dwarf" => dwarfdump::run(rest),
        "checksec" => checksec::run(rest),
        "signature" => signature::run(rest),
        "size" => size::run(rest),
        "linkerlog" => linkerlog::run(rest),
        "xref" => xref::run(rest),
        "query" => query::run(rest),
        "recommend" => recommend::run(rest),
        "types" => types::run(rest),
        "inlines" => lines::run_inlines(rest),
        "sourcefiles" => lines::run_sourcefiles(rest),
        "annotations" => lines::run_annotations(rest),
        "batch" => batch::run(rest),
        "info" => info(rest),
        "licenses" => {
            // Generated by the licenses test from the crates linked in.
            let notices = include_str!("../THIRD_PARTY_NOTICES.txt");
            out::print(notices.as_bytes())
        }
        "help" | "-h" | "--help" => out::print(format!("{USAGE}\n").as_bytes()),
        "version" | "-V" | "--version" => {
            out::print(format!("hexc {}\n", env!("CARGO_PKG_VERSION")).as_bytes())
        }
        other => {
            ereport!("hexc: unknown command '{other}'\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// What `hexc info` adds for a PE image: whether it is managed, the tools
/// its Rich header names, its certificates, overlay, and bound imports.
fn pe_details(pe: &hexcavator_pe::PeFile<'_>) -> Vec<String> {
    use hexcavator_pe::extras::{
        COMIMAGE_FLAGS_32BITREQUIRED, COMIMAGE_FLAGS_ILONLY, COMIMAGE_FLAGS_STRONGNAMESIGNED,
    };
    let mut out = Vec::new();
    if let Some(clr) = pe.clr() {
        let version = clr
            .version
            .map_or_else(String::new, |v| format!(" {}", String::from_utf8_lossy(v)));
        let mut flags = Vec::new();
        for (bit, what) in [
            (COMIMAGE_FLAGS_ILONLY, "IL only"),
            (COMIMAGE_FLAGS_32BITREQUIRED, "32-bit required"),
            (COMIMAGE_FLAGS_STRONGNAMESIGNED, "strong-name signed"),
        ] {
            if clr.flags & bit != 0 {
                flags.push(what);
            }
        }
        out.push(format!(
            "managed: CLR {}.{}, metadata{version}{}",
            clr.major_runtime_version,
            clr.minor_runtime_version,
            if flags.is_empty() {
                String::new()
            } else {
                format!(" ({})", flags.join(", "))
            }
        ));
    }
    if let Some(r) = pe.rich() {
        let objects: u64 = r.entries.iter().map(|e| u64::from(e.count)).sum();
        out.push(format!(
            "Rich header: {} tool builds, {objects} objects{}",
            r.entries.len(),
            if r.valid {
                ""
            } else {
                " (its checksum doesn't hold)"
            }
        ));
    }
    let certs = pe.certificates();
    if !certs.is_empty() {
        let bytes: usize = certs.iter().map(|c| c.data.len()).sum();
        out.push(format!("{} certificates ({bytes} bytes)", certs.len()));
    }
    if let Some((at, size)) = pe.overlay() {
        out.push(format!("overlay: {size} bytes at file offset {at:#x}"));
    }
    let bound = pe.bound_imports();
    if !bound.is_empty() {
        out.push(format!("{} bound imports", bound.len()));
    }
    out
}

/// What `hexc info` adds for a Mach-O image: its Objective-C metadata,
/// function starts, compact unwind, and code signature.
fn macho_details(m: &hexcavator_macho::MachO<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let objc = m.objc();
    if !objc.classes.is_empty() || !objc.categories.is_empty() || !objc.protocols.is_empty() {
        let methods: usize = objc
            .classes
            .iter()
            .map(|c| c.methods.len() + c.class_methods.len())
            .chain(
                objc.categories
                    .iter()
                    .map(|c| c.methods.len() + c.class_methods.len()),
            )
            .sum();
        let swift = objc.classes.iter().filter(|c| c.swift).count();
        out.push(format!(
            "Objective-C: {} classes{}, {} categories, {} protocols, {methods} methods{}",
            objc.classes.len(),
            if swift > 0 {
                format!(" ({swift} Swift)")
            } else {
                String::new()
            },
            objc.categories.len(),
            objc.protocols.len(),
            if objc.truncated {
                " (and more: too many to read)"
            } else {
                ""
            }
        ));
    }
    let starts = m.function_starts();
    if !starts.is_empty() {
        out.push(format!("{} function starts", starts.len()));
    }
    if let Some(u) = m.unwind_info() {
        out.push(format!(
            "compact unwind: {} entries, {} personalities",
            u.entries.len(),
            u.personalities.len()
        ));
    }
    if let Some(sig) = m.code_signature() {
        match sig.directory {
            Some(d) => out.push(format!(
                "code signature: {} ({} pages){}",
                String::from_utf8_lossy(d.identifier),
                d.code_slots,
                d.team.map_or_else(String::new, |t| format!(
                    ", team {}",
                    String::from_utf8_lossy(t)
                ))
            )),
            None => out.push(format!("code signature: {} blobs", sig.blobs.len())),
        }
    }
    out
}

/// What `hexc info` adds for an ELF file: its kind, interpreter, the
/// libraries it needs and its own name, search paths, and debug links.
fn elf_details(e: &hexcavator_elf::ElfFile<'_>) -> Vec<String> {
    use hexcavator_elf::consts::*;
    let mut out = Vec::new();
    let kind = match e.header().kind {
        ET_REL => "relocatable object",
        ET_EXEC => "executable",
        ET_DYN if e.segments().any(|s| s.kind == PT_INTERP) => "position-independent executable",
        ET_DYN => "shared object",
        ET_CORE => "core dump",
        _ => "unknown kind",
    };
    match e.header().entry {
        0 => out.push(kind.to_string()),
        entry => out.push(format!("{kind}, entry {entry:#x}")),
    }
    if let Some(interp) = e.segments().find(|s| s.kind == PT_INTERP) {
        let data = e.data();
        let path = usize::try_from(interp.offset)
            .ok()
            .and_then(|o| data.get(o..o.checked_add(usize::try_from(interp.filesz).ok()?)?))
            .unwrap_or_default();
        let path = path.split(|&b| b == 0).next().unwrap_or_default();
        out.push(format!("interpreter: {}", String::from_utf8_lossy(path)));
    }
    let dynamic = e.dynamic();
    // Dynamic strings: offsets into the table at DT_STRTAB.
    let strtab = dynamic
        .iter()
        .find(|d| d.tag == DT_STRTAB)
        .and_then(|d| e.vaddr_to_offset(d.value))
        .and_then(|o| usize::try_from(o).ok());
    let string = |offset: u64| -> String {
        let bytes = strtab
            .and_then(|t| t.checked_add(usize::try_from(offset).ok()?))
            .and_then(|o| e.data().get(o..))
            .unwrap_or_default();
        String::from_utf8_lossy(bytes.split(|&b| b == 0).next().unwrap_or_default()).into_owned()
    };
    for (tag, label) in [
        (DT_SONAME, "soname"),
        (DT_RPATH, "rpath"),
        (DT_RUNPATH, "runpath"),
    ] {
        for d in dynamic.iter().filter(|d| d.tag == tag) {
            out.push(format!("{label}: {}", string(d.value)));
        }
    }
    let needed: Vec<String> = dynamic
        .iter()
        .filter(|d| d.tag == DT_NEEDED)
        .map(|d| string(d.value))
        .collect();
    if !needed.is_empty() {
        out.push(format!("needs: {}", needed.join(", ")));
    }
    if let Some(id) = e.build_id() {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        out.push(format!("build ID: {hex}"));
    }
    if let Some(link) = e.debug_link() {
        out.push(format!(
            "debug link: {} (CRC {:08x})",
            String::from_utf8_lossy(link.path),
            link.crc
        ));
    }
    let sections = e.sections().count();
    let symbols = e.all_symbols().len();
    out.push(format!("{sections} sections, {symbols} symbols"));
    out
}

/// What `hexc info` adds for a WebAssembly module: its functions, data,
/// custom sections, and debug links.
fn wasm_details(m: &hexcavator_wasm::Module<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let defined = m.functions().len();
    out.push(format!(
        "{defined} functions ({} imported), {} data segments",
        m.imported_functions(),
        m.data_segments().len()
    ));
    let custom: Vec<String> = m
        .sections()
        .iter()
        .filter(|s| s.id == 0)
        .map(|s| String::from_utf8_lossy(s.name).into_owned())
        .collect();
    if !custom.is_empty() {
        out.push(format!("custom sections: {}", custom.join(", ")));
    }
    if let Some(url) = m.source_mapping_url() {
        out.push(format!("source map: {}", String::from_utf8_lossy(url)));
    }
    if let Some(id) = m.build_id() {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        out.push(format!("build ID: {hex}"));
    }
    if let Some(path) = m.external_debug_info() {
        out.push(format!(
            "debug information: {}",
            String::from_utf8_lossy(path)
        ));
    }
    out
}

/// What `hexc info` adds for a 16-bit NE or a linear (LE/LX) executable:
/// its name, description, and tables' sizes.
fn legacy_details(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let quote = |s: Option<String>| s.map_or_else(String::new, |s| format!(" {s:?}"));
    if let Ok(ne) = hexcavator_ne::NeFile::parse(data) {
        let h = ne.header();
        let os = match h.target_os {
            hexcavator_ne::NE_OS_OS2 => "OS/2",
            hexcavator_ne::NE_OS_WINDOWS => "Windows",
            hexcavator_ne::NE_OS_DOS4 => "DOS 4",
            hexcavator_ne::NE_OS_WIN386 => "Windows/386",
            _ => "an unknown system",
        };
        out.push(format!(
            "{}{}{} for {os} {}.{}",
            if ne.is_library() {
                "library"
            } else {
                "program"
            },
            quote(ne.module_name()),
            quote(ne.description()),
            h.windows_version.0,
            h.windows_version.1
        ));
        let segments = ne.segments();
        let relocations: usize = segments.iter().map(|s| ne.relocations(s).len()).sum();
        out.push(format!(
            "{} segments ({relocations} relocations), {} resources, {} entries, imports from {}",
            segments.len(),
            ne.resources().len(),
            ne.entries().len(),
            match ne.modules() {
                m if m.is_empty() => "nothing".to_string(),
                m => m.join(", "),
            }
        ));
    } else if let Ok(lx) = hexcavator_lx::LxFile::parse(data) {
        let h = lx.header();
        let what = if lx.is_vxd() {
            format!("virtual device driver (ID {:#06x})", h.device_id)
        } else if h.flags & hexcavator_lx::MOD_LIBRARY != 0 {
            "library".to_string()
        } else {
            "program".to_string()
        };
        out.push(format!(
            "{what}{}{}",
            quote(lx.module_name()),
            quote(lx.description())
        ));
        let pages = lx.pages();
        let fixups: usize = (0..h.pages.min(1 << 20)).map(|p| lx.fixups(p).len()).sum();
        out.push(format!(
            "{} objects, {} pages of {} bytes ({fixups} fixups), {} entries, imports from {}",
            lx.objects().len(),
            pages.len(),
            h.page_size,
            lx.entries().len(),
            match lx.import_modules() {
                m if m.is_empty() => "nothing".to_string(),
                m => m.join(", "),
            }
        ));
    }
    out
}

/// What a file is and what hexc does with it, for editors: its format
/// (`pe`, `coff`, `elf`, `macho`, `wasm`, `archive`, `other`), its kind
/// (`linked`, `object`, `dump`, `debug`), its architectures, the debug
/// information found for it (or why none was), and the tools that apply
/// (see [`tools_for`]).
fn info_json(path: &str) -> serde_json::Value {
    use serde_json::json;
    let map = match Mmap::open(path) {
        Ok(m) => m,
        Err(e) => return json!({ "path": path, "error": e.to_string() }),
    };
    let data: &[u8] = &map;
    let description = detect::describe(data);
    let archive = hexcavator_archive::Archive::is_archive(data);
    let fat = hexcavator_macho::fat_archs(data);
    let image = hexcavator_image::Image::parse(data).ok();
    let format = match &image {
        _ if archive => "archive",
        Some(hexcavator_image::Image::Pe(pe)) if pe.kind() == hexcavator_pe::FileKind::Object => {
            "coff"
        }
        Some(hexcavator_image::Image::Pe(_)) => "pe",
        Some(hexcavator_image::Image::Elf(_)) => "elf",
        Some(hexcavator_image::Image::MachO(_)) => "macho",
        Some(hexcavator_image::Image::Wasm(_)) => "wasm",
        Some(_) => "other",
        None if size::is_object_input(data) => "coff",
        None => "other",
    };
    let kind = match image.as_ref().map(hexcavator_image::Image::kind) {
        _ if archive => "object",
        Some(hexcavator_image::Kind::Linked) => "linked",
        Some(hexcavator_image::Kind::Object) => "object",
        Some(hexcavator_image::Kind::Dump) => "dump",
        Some(hexcavator_image::Kind::Debug) => "debug",
        Some(_) => "other",
        None if format == "coff" => "object",
        None => "other",
    };
    let archs: Vec<String> = match (&fat, &image) {
        (Some(archs), _) => archs
            .iter()
            .map(|a| hexcavator_macho::arch_name(a.cputype, a.cpusubtype))
            .collect(),
        (None, Some(i)) => vec![i.arch().name().to_string()],
        (None, None) => Vec::new(),
    };
    let arch = image.as_ref().map(|i| match i {
        hexcavator_image::Image::MachO(m) => {
            hexcavator_macho::arch_name(m.header().cputype, m.header().cpusubtype)
        }
        other => other.arch().name().to_string(),
    });
    // Debug information: linked images only (objects' needs relocating).
    let (debug, debug_error) = match &image {
        Some(i) if kind == "linked" => {
            match hexcavator_program::find_debug(Path::new(path), i, None) {
                Ok((p, m)) => {
                    let what = match hexcavator_debuginfo::DebugInfo::parse(&m) {
                        Ok(hexcavator_debuginfo::DebugInfo::Pdb(_)) => "pdb",
                        Ok(_) => "dwarf",
                        Err(_) => "unreadable",
                    };
                    let own = p == Path::new(path);
                    (
                        Some(json!({ "path": p.display().to_string(), "kind": what, "own": own })),
                        None,
                    )
                }
                Err(e) => match hexcavator_program::Opened::open(Path::new(path), None) {
                    // A Mach-O image's debug map: its objects' DWARF.
                    Ok(o) if o.is_debug_map() => (
                        Some(json!({
                            "path": path,
                            "kind": "debugmap",
                            "own": true,
                            "objects": o.split_paths().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                        })),
                        None,
                    ),
                    _ => (None, Some(e.to_string())),
                },
            }
        }
        _ => (None, None),
    };
    let has_debug = debug.as_ref().is_some_and(|d| d["kind"] != "unreadable");
    // (An object's DWARF, or a debug file's own, is dumped too.)
    let has_dwarf = debug
        .as_ref()
        .is_some_and(|d| d["kind"] == "dwarf" || d["kind"] == "debugmap")
        || (kind != "linked"
            && hexcavator_debuginfo::dwarf_backend::DwarfInfo::parse(data).is_ok());
    json!({
        "path": path,
        "description": description,
        "size": data.len(),
        "format": format,
        "kind": kind,
        "archs": archs,
        "arch": arch,
        "debug": debug,
        "debugError": debug_error,
        "tools": tools_for(format, kind, has_debug, has_dwarf),
    })
}

/// The tools that apply to a file of `format` and `kind` (with debug
/// information or not), by the editor's names for them.
fn tools_for(format: &str, kind: &str, debug: bool, dwarf: bool) -> Vec<&'static str> {
    let mut t = vec!["report", "compare", "info"];
    let dumps = ["pe", "coff", "archive", "elf", "macho", "wasm"].contains(&format);
    if dumps {
        t.push("dump");
    }
    if kind == "linked" && format != "other" {
        t.push("disassemble");
    }
    if kind == "linked" && ["pe", "elf", "macho"].contains(&format) {
        t.push("checksec");
        if debug {
            t.push("audit");
        }
    }
    if kind == "linked" && debug {
        t.extend([
            "findings",
            "recommend",
            "why",
            "refs",
            "xref",
            "unreachable",
            "vtables",
            "identical",
            "query",
            "types",
            "layout",
            "inlines",
            "sourcefiles",
            "data",
            "functionsDiff",
            "findingsDiff",
            "typesDiff",
            "lenses",
        ]);
        if format == "pe" {
            t.push("annotations");
        }
    }
    if dwarf {
        t.push("dwarf");
    }
    t
}

fn info(args: &[String]) -> ExitCode {
    let json = args.iter().any(|a| a == "-json" || a == "/json");
    let paths: Vec<&String> = args
        .iter()
        .filter(|a| *a != "-json" && *a != "/json")
        .collect();
    if paths.is_empty() {
        ereport!("usage: hexc info [-json] <file>...");
        return ExitCode::from(2);
    }
    if json {
        let all: Vec<serde_json::Value> = paths.iter().map(|p| info_json(p)).collect();
        return out::print(format!("{}\n", serde_json::Value::Array(all)).as_bytes());
    }
    let mut status = ExitCode::SUCCESS;
    for path in paths {
        match Mmap::open(path) {
            Ok(map) => {
                use std::fmt::Write as _;
                let mut out = String::new();
                let _ = writeln!(
                    out,
                    "{path}: {}, {} bytes",
                    detect::describe(&map),
                    map.len()
                );
                if let Ok(pe) = hexcavator_pe::PeFile::parse_image(&map) {
                    for line in pe_details(&pe) {
                        let _ = writeln!(out, "  {line}");
                    }
                } else if let Ok(m) = hexcavator_macho::MachO::parse(&map) {
                    for line in macho_details(&m) {
                        let _ = writeln!(out, "  {line}");
                    }
                } else if let Ok(e) = hexcavator_elf::ElfFile::parse(&map) {
                    for line in elf_details(&e) {
                        let _ = writeln!(out, "  {line}");
                    }
                } else if let Ok(m) = hexcavator_wasm::Module::parse(&map) {
                    for line in wasm_details(&m) {
                        let _ = writeln!(out, "  {line}");
                    }
                } else {
                    for line in legacy_details(&map) {
                        let _ = writeln!(out, "  {line}");
                    }
                }
                if !out::printed(out.as_bytes()) {
                    status = ExitCode::FAILURE;
                }
            }
            Err(err) => {
                ereport!("hexc: {path}: {err}");
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}

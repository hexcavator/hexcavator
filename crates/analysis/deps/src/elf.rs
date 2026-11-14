//! ELF: the interpreter, `DT_NEEDED`, the library search (rpath, runpath,
//! `ld.so.conf`, default directories), and undefined symbols against what
//! the loaded objects define (versions too).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hexcavator_elf::ElfFile;
use hexcavator_elf::consts::*;

use crate::search::Reject;
use crate::{Ctx, DepKind, Found, Import, ImportStatus, Resolved, Status, Wanted};

/// The most rpath entries, `ld.so.conf` directories, and symbols read.
const MAX_DIRS: usize = 256;
const MAX_SYMBOLS: usize = 1 << 20;

/// An object's dynamic strings: its needed libraries, rpath, runpath.
struct Dynamic {
    needed: Vec<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
    interp: Option<String>,
}

fn dynamic(elf: &ElfFile<'_>) -> Dynamic {
    let entries = elf.dynamic();
    let strtab = entries
        .iter()
        .find(|d| d.tag == DT_STRTAB)
        .and_then(|d| elf.vaddr_to_offset(d.value))
        .and_then(|o| usize::try_from(o).ok());
    let string = |offset: u64| -> String {
        let bytes = strtab
            .and_then(|t| t.checked_add(usize::try_from(offset).ok()?))
            .and_then(|o| elf.data().get(o..))
            .unwrap_or_default();
        String::from_utf8_lossy(bytes.split(|&b| b == 0).next().unwrap_or_default()).into_owned()
    };
    let list = |tag: u64| -> Vec<String> {
        entries
            .iter()
            .filter(|d| d.tag == tag)
            .flat_map(|d| {
                string(d.value)
                    .split(':')
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|s| !s.is_empty())
            .take(MAX_DIRS)
            .collect()
    };
    let interp = elf.segments().find(|s| s.kind == PT_INTERP).and_then(|s| {
        let start = usize::try_from(s.offset).ok()?;
        let end = start.checked_add(usize::try_from(s.filesz).ok()?)?;
        let bytes = elf.data().get(start..end)?;
        let path = bytes.split(|&b| b == 0).next()?;
        (!path.is_empty()).then(|| String::from_utf8_lossy(path).into_owned())
    });
    Dynamic {
        needed: entries
            .iter()
            .filter(|d| d.tag == DT_NEEDED)
            .map(|d| string(d.value))
            .filter(|s| !s.is_empty())
            .take(1 << 12)
            .collect(),
        rpath: list(DT_RPATH),
        runpath: list(DT_RUNPATH),
        interp,
    }
}

fn parsed<'c>(ctx: &'c Ctx<'_>, m: usize) -> Option<ElfFile<'c>> {
    ElfFile::parse(ctx.loaded.get(m)?.as_ref()?.data()).ok()
}

/// Whether module `m` is an executable (not a shared library).
pub(crate) fn is_executable(ctx: &Ctx<'_>, m: usize) -> bool {
    match ctx.format {
        crate::Format::Elf => parsed(ctx, m).is_some_and(|e| {
            e.header().kind == ET_EXEC || e.segments().any(|s| s.kind == PT_INTERP)
        }),
        crate::Format::MachO => crate::macho::is_executable(ctx, m),
        crate::Format::Pe => true,
    }
}

/// What module `m` loads: its interpreter (the root's), and its needed
/// libraries.
pub(crate) fn wanted(ctx: &mut Ctx<'_>, m: usize) -> Vec<Wanted> {
    let Some(elf) = parsed(ctx, m) else {
        return Vec::new();
    };
    let d = dynamic(&elf);
    let mut out = Vec::new();
    if let Some(i) = d.interp.filter(|_| m == 0) {
        out.push(Wanted {
            name: i,
            kind: DepKind::Interpreter,
            imports: Vec::new(),
        });
    }
    out.extend(d.needed.into_iter().map(|name| Wanted {
        name,
        kind: DepKind::Needed,
        imports: Vec::new(),
    }));
    out
}

/// `path` under the system root (`None` without one).
fn rooted(ctx: &Ctx<'_>, path: &str) -> Option<PathBuf> {
    let root = ctx.sysroot.as_ref()?;
    Some(root.join(path.trim_start_matches('/')))
}

/// The directory module `m` is in.
fn origin(ctx: &Ctx<'_>, m: usize) -> Option<PathBuf> {
    ctx.graph.modules[m]
        .status
        .path()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

/// A search path entry of module `m`, its `$ORIGIN`, `$LIB`, and
/// `$PLATFORM` expanded: a directory (under the system root, unless it's
/// relative to `$ORIGIN`).
fn expand(ctx: &Ctx<'_>, m: usize, entry: &str) -> Option<PathBuf> {
    let wide = ctx
        .search
        .arch
        .as_ref()
        .and_then(crate::search::Arch::elf_wide)
        == Some(true);
    let platform = ctx.search.arch.as_ref().map_or("", |a| a.name.as_str());
    let e = entry
        .replace("${LIB}", if wide { "lib64" } else { "lib" })
        .replace("$LIB", if wide { "lib64" } else { "lib" })
        .replace("${PLATFORM}", platform)
        .replace("$PLATFORM", platform);
    for o in ["${ORIGIN}", "$ORIGIN"] {
        if let Some(rest) = e.strip_prefix(o) {
            let base = origin(ctx, m)?;
            return Some(base.join(rest.trim_start_matches('/')));
        }
    }
    if e.contains('$') {
        return None;
    }
    if e.starts_with('/') {
        return rooted(ctx, &e);
    }
    // (Relative to the current directory: the root's, here.)
    Some(ctx.root_dir.join(e))
}

/// The directories `ld.so.conf` names (its includes too), under the
/// system root.
fn ld_so_conf(ctx: &Ctx<'_>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(conf) = rooted(ctx, "/etc/ld.so.conf") else {
        return out;
    };
    let mut files = vec![(conf, 0)];
    while let Some((file, depth)) = files.pop() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines().take(4096) {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some(pattern) = line.strip_prefix("include").map(str::trim) {
                if depth >= 8 {
                    continue;
                }
                // `dir/*.conf` (a glob of one `*`, in the file name).
                let Some(p) = rooted(ctx, pattern) else {
                    continue;
                };
                let (dir, name) = (
                    p.parent().map(Path::to_path_buf),
                    p.file_name().map(|n| n.to_string_lossy().into_owned()),
                );
                let (Some(dir), Some(name)) = (dir, name) else {
                    continue;
                };
                let (head, tail) = name.split_once('*').unwrap_or((&name, ""));
                let mut matched: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .map(|rd| {
                        rd.flatten()
                            .map(|e| e.path())
                            .filter(|f| {
                                let n = f
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                n.starts_with(head)
                                    && n.ends_with(tail)
                                    && n.len() >= head.len() + tail.len()
                            })
                            .take(256)
                            .collect()
                    })
                    .unwrap_or_default();
                matched.sort();
                files.extend(matched.into_iter().rev().map(|f| (f, depth + 1)));
            } else if line.starts_with('/')
                && out.len() < MAX_DIRS
                && let Some(d) = rooted(ctx, line)
            {
                out.push(d);
            }
        }
    }
    out
}

/// The default directories: multiarch, `lib64` (for 64-bit objects),
/// `lib`; Android's for its linker.
fn default_dirs(ctx: &Ctx<'_>) -> Vec<PathBuf> {
    let wide = ctx
        .search
        .arch
        .as_ref()
        .and_then(crate::search::Arch::elf_wide)
        == Some(true);
    let android = parsed(ctx, 0)
        .and_then(|e| dynamic(&e).interp)
        .is_some_and(|i| i.contains("/system/bin/linker"));
    let mut dirs: Vec<String> = Vec::new();
    if android {
        let lib = if wide { "lib64" } else { "lib" };
        for d in [
            "/system",
            "/vendor",
            "/odm",
            "/apex/com.android.runtime",
            "/apex/com.android.art",
        ] {
            dirs.push(format!("{d}/{lib}"));
        }
        dirs.push(format!("/apex/com.android.runtime/{lib}/bionic"));
    } else {
        let triple = match ctx.search.arch.as_ref().map(|a| a.name.as_str()) {
            Some("x64" | "x86_64") => Some("x86_64-linux-gnu"),
            Some("x86" | "i386") => Some("i386-linux-gnu"),
            Some("arm64" | "aarch64") => Some("aarch64-linux-gnu"),
            Some("arm" | "thumb") => Some("arm-linux-gnueabihf"),
            Some("riscv64") => Some("riscv64-linux-gnu"),
            _ => None,
        };
        if let Some(t) = triple {
            dirs.extend([format!("/lib/{t}"), format!("/usr/lib/{t}")]);
        }
        if wide {
            dirs.extend(["/lib64".to_string(), "/usr/lib64".to_string()]);
        }
        dirs.extend(["/lib".to_string(), "/usr/lib".to_string()]);
    }
    dirs.iter().filter_map(|d| rooted(ctx, d)).collect()
}

/// Where `name` is, as `loader` loads it.
pub(crate) fn resolve(ctx: &mut Ctx<'_>, loader: usize, name: &str, kind: DepKind) -> Resolved {
    if name.contains('\0') {
        return Resolved::Other(Status::Missing { tried: Vec::new() });
    }
    // A path: as named (an absolute one under the system root).
    if kind == DepKind::Interpreter || name.contains('/') {
        let path = if name.starts_with('/') {
            match rooted(ctx, name) {
                Some(p) => p,
                None => return Resolved::Other(Status::Unsearched),
            }
        } else {
            ctx.root_dir.join(name)
        };
        return match ctx.search.open(&path) {
            Ok(loaded) => Resolved::File {
                path,
                how: Found::Path,
                loaded,
            },
            Err(Reject::WrongArch(arch)) => Resolved::Other(Status::WrongArch { path, arch }),
            Err(Reject::Unreadable(why)) => Resolved::Other(Status::Unreadable { path, why }),
            Err(Reject::Absent) => Resolved::Other(Status::Missing { tried: vec![path] }),
        };
    }
    let mut dirs: Vec<(PathBuf, Found)> = Vec::new();
    let runpath = parsed(ctx, loader)
        .map(|e| dynamic(&e).runpath)
        .unwrap_or_default();
    // DT_RPATH: the loader's, then its loaders' (but none if the loader has
    // a DT_RUNPATH; and none of an object that has one).
    if runpath.is_empty() {
        let mut at = Some(loader);
        let mut steps = 0;
        while let Some(o) = at {
            if let Some(e) = parsed(ctx, o) {
                let d = dynamic(&e);
                if d.runpath.is_empty() {
                    for r in d.rpath {
                        if let Some(dir) = expand(ctx, o, &r) {
                            dirs.push((dir, Found::Rpath));
                        }
                    }
                }
            }
            at = ctx.parent[o];
            steps += 1;
            if steps > 64 {
                break;
            }
        }
    }
    for d in &ctx.options.dirs {
        dirs.push((d.clone(), Found::SearchDir));
    }
    for r in runpath {
        if let Some(dir) = expand(ctx, loader, &r) {
            dirs.push((dir, Found::Runpath));
        }
    }
    for d in ld_so_conf(ctx) {
        dirs.push((d, Found::LdSoConf));
    }
    for d in default_dirs(ctx) {
        dirs.push((d, Found::DefaultDir));
    }
    let mut tried = Vec::new();
    let mut other = None;
    for (dir, how) in dirs {
        let path = dir.join(name);
        if tried.contains(&path) {
            continue;
        }
        match ctx.search.open(&path) {
            Ok(loaded) => return Resolved::File { path, how, loaded },
            Err(Reject::Absent) => {}
            Err(Reject::WrongArch(arch)) => {
                other.get_or_insert(Status::WrongArch {
                    path: path.clone(),
                    arch,
                });
            }
            Err(Reject::Unreadable(why)) => {
                other.get_or_insert(Status::Unreadable {
                    path: path.clone(),
                    why,
                });
            }
        }
        tried.push(path);
    }
    Resolved::Other(other.unwrap_or(if ctx.sysroot.is_none() {
        Status::Unsearched
    } else {
        Status::Missing { tried }
    }))
}

/// An object's dynamic symbols: those it defines (each with the versions
/// it defines it at: `None` unversioned, and whether that's the default),
/// and those it doesn't (with the version it needs, and whether weak).
struct Symbols {
    defined: HashMap<String, Vec<(Option<String>, bool)>>,
    undefined: Vec<(String, Option<String>, bool)>,
}

fn symbols(elf: &ElfFile<'_>) -> Symbols {
    let mut s = Symbols {
        defined: HashMap::new(),
        undefined: Vec::new(),
    };
    let Some(table) = elf.sections().find(|t| t.kind == SHT_DYNSYM) else {
        return s;
    };
    let versions = elf.symbol_versions();
    for sym in elf.symbols(&table).into_iter().take(MAX_SYMBOLS) {
        if sym.name.is_empty() || sym.bind == STB_LOCAL {
            continue;
        }
        let name = String::from_utf8_lossy(sym.name).into_owned();
        let v = versions.get(sym.index).copied().flatten();
        if sym.shndx == u32::from(SHN_UNDEF) {
            s.undefined.push((
                name,
                v.map(|v| String::from_utf8_lossy(v.name).into_owned()),
                sym.bind == STB_WEAK,
            ));
        } else {
            // (Hidden ones aren't exported: `STV_HIDDEN`, `STV_INTERNAL`.)
            if matches!(sym.visibility, 1 | 2) {
                continue;
            }
            s.defined.entry(name).or_default().push((
                v.map(|v| String::from_utf8_lossy(v.name).into_owned()),
                v.is_none_or(|v| !v.hidden),
            ));
        }
    }
    s
}

/// Checks each object's undefined symbols against the objects loaded, in
/// load order (the global scope: the program's, then its libraries',
/// breadth first, the interpreter's too).
pub(crate) fn check(ctx: &mut Ctx<'_>) {
    let n = ctx.graph.modules.len();
    // (With a library not found, what it would define isn't known.)
    if ctx.graph.modules.iter().any(|m| m.status.path().is_none()) {
        ctx.graph
            .notes
            .push("symbols weren't checked: not every library was found".into());
        for m in 0..n {
            if let Some(s) = parsed(ctx, m).map(|e| symbols(&e)) {
                ctx.graph.modules[m].exports = s.defined.len();
            }
        }
        return;
    }
    let all: Vec<Option<Symbols>> = (0..n)
        .map(|m| parsed(ctx, m).map(|e| symbols(&e)))
        .collect();
    for m in 0..n {
        let Some(own) = &all[m] else { continue };
        ctx.graph.modules[m].exports = own.defined.len();
        let mut missing = Vec::new();
        for (name, version, weak) in &own.undefined {
            if *weak {
                continue;
            }
            let found = all.iter().enumerate().any(|(o, s)| {
                o != m
                    && s.as_ref().is_some_and(|s| {
                        s.defined.get(name).is_some_and(|defs| match version {
                            Some(v) => defs
                                .iter()
                                .any(|(dv, _)| dv.as_deref() == Some(v.as_str()) || dv.is_none()),
                            None => defs.iter().any(|(_, default)| *default),
                        })
                    })
            });
            if !found {
                missing.push(Import {
                    name: Some(name.clone()),
                    ordinal: None,
                    version: version.clone(),
                    weak: false,
                    status: ImportStatus::Missing,
                });
            }
        }
        ctx.graph.modules[m].unresolved = missing;
    }
}

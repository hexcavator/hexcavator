//! Mach-O: the dylibs an image links, found by install name,
//! `@executable_path`, `@loader_path`, and `@rpath`; and its binds against
//! the export tries of the libraries they name (and the libraries those
//! re-export).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use hexcavator_macho::MachO;
use hexcavator_macho::consts::*;

use crate::search::Reject;
use crate::{Ctx, DepKind, Found, Import, ImportStatus, Resolved, Status, Wanted};

/// The most binds read, and re-exports followed deep.
const MAX_BINDS: usize = 1 << 20;
const MAX_REEXPORT_DEPTH: usize = 8;
/// `MH_EXECUTE`.
const MH_EXECUTE: u32 = 2;

fn parsed<'c>(ctx: &'c Ctx<'_>, m: usize) -> Option<MachO<'c>> {
    MachO::parse(ctx.loaded.get(m)?.as_ref()?.data()).ok()
}

pub(crate) fn is_executable(ctx: &Ctx<'_>, m: usize) -> bool {
    parsed(ctx, m).is_some_and(|i| i.header().filetype == MH_EXECUTE)
}

/// What module `m` links: its dylibs, each with the symbols bound from it.
pub(crate) fn wanted(ctx: &mut Ctx<'_>, m: usize) -> Vec<Wanted> {
    let Some(image) = parsed(ctx, m) else {
        return Vec::new();
    };
    let dylibs = image.dylibs();
    let mut imports: Vec<Vec<Import>> = vec![Vec::new(); dylibs.len()];
    let mut seen: Vec<HashSet<Vec<u8>>> = vec![HashSet::new(); dylibs.len()];
    let mut flat = Vec::new();
    for f in image.fixups().into_iter().take(MAX_BINDS) {
        let hexcavator_macho::FixupKind::Bind {
            symbol,
            library,
            weak,
            ..
        } = f.kind
        else {
            continue;
        };
        let import = || Import {
            name: Some(String::from_utf8_lossy(symbol).into_owned()),
            ordinal: None,
            version: None,
            weak,
            status: ImportStatus::Unchecked,
        };
        match usize::try_from(library) {
            Ok(k) if k >= 1 && k <= dylibs.len() => {
                if seen[k - 1].insert(symbol.to_vec()) {
                    imports[k - 1].push(import());
                }
            }
            // The flat namespace: any library's.
            _ if library == -2 => flat.push(import()),
            _ => {}
        }
    }
    let out: Vec<Wanted> = dylibs
        .iter()
        .zip(imports)
        .map(|(d, imports)| Wanted {
            name: String::from_utf8_lossy(d.name).into_owned(),
            kind: match d.cmd {
                LC_LOAD_WEAK_DYLIB => DepKind::WeakDylib,
                LC_REEXPORT_DYLIB => DepKind::ReexportDylib,
                LC_LAZY_LOAD_DYLIB => DepKind::LazyDylib,
                LC_LOAD_UPWARD_DYLIB => DepKind::UpwardDylib,
                _ => DepKind::Dylib,
            },
            imports,
        })
        .collect();
    ctx.graph.modules[m].unresolved = flat;
    out
}

/// The directory of module `m`'s file.
fn dir_of(ctx: &Ctx<'_>, m: usize) -> Option<PathBuf> {
    ctx.graph.modules[m]
        .status
        .path()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

/// `path` with `@executable_path` and `@loader_path` (of `m`, whose run
/// path or name it is) put for, an absolute one under the system root.
fn expand(ctx: &Ctx<'_>, m: usize, path: &str) -> Option<(PathBuf, Found)> {
    if let Some(rest) = path.strip_prefix("@executable_path") {
        return Some((
            dir_of(ctx, 0)?.join(rest.trim_start_matches('/')),
            Found::ExecutablePath,
        ));
    }
    if let Some(rest) = path.strip_prefix("@loader_path") {
        return Some((
            dir_of(ctx, m)?.join(rest.trim_start_matches('/')),
            Found::LoaderPath,
        ));
    }
    if path.starts_with('@') {
        return None;
    }
    if path.starts_with('/') {
        let root = ctx.sysroot.as_ref()?;
        return Some((root.join(path.trim_start_matches('/')), Found::Path));
    }
    Some((ctx.root_dir.join(path), Found::Path))
}

/// Whether an install name is a system library's (macOS 11 and later keep
/// those only in the dyld shared cache).
pub(crate) fn is_system(name: &str) -> bool {
    name.starts_with("/usr/lib/") || name.starts_with("/System/Library/")
}

/// Where `name` (an install name) is, as `loader` loads it.
pub(crate) fn resolve(ctx: &mut Ctx<'_>, loader: usize, name: &str, _kind: DepKind) -> Resolved {
    if name.is_empty() || name.contains('\0') {
        return Resolved::Other(Status::Missing { tried: Vec::new() });
    }
    let mut candidates: Vec<(PathBuf, Found)> = Vec::new();
    if let Some(rest) = name.strip_prefix("@rpath/") {
        // The loader's run paths, then its loaders'.
        let mut at = Some(loader);
        let mut steps = 0;
        while let Some(o) = at {
            if let Some(image) = parsed(ctx, o) {
                for r in image.rpaths() {
                    let r = String::from_utf8_lossy(r).into_owned();
                    if let Some((dir, _)) = expand(ctx, o, &r) {
                        candidates.push((dir.join(rest), Found::Rpath));
                    }
                }
            }
            at = ctx.parent[o];
            steps += 1;
            if steps > 64 {
                break;
            }
        }
    } else if let Some(c) = expand(ctx, loader, name) {
        candidates.push(c);
    }
    // The directories given, by the file's name (as
    // DYLD_FALLBACK_LIBRARY_PATH).
    if let Some(file) = name.rsplit('/').next().filter(|f| !f.is_empty()) {
        for d in &ctx.options.dirs {
            candidates.push((d.join(file), Found::SearchDir));
        }
    }
    let mut tried = Vec::new();
    let mut other = None;
    for (path, how) in candidates {
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
    if let Some(o) = other {
        return Resolved::Other(o);
    }
    Resolved::Other(if is_system(name) {
        if ctx.sysroot.is_some() {
            Status::SharedCache
        } else {
            Status::Unsearched
        }
    } else if ctx.sysroot.is_none() && name.starts_with('/') {
        Status::Unsearched
    } else {
        Status::Missing { tried }
    })
}

/// Each module's exported names (read once).
fn exports<'e>(
    ctx: &Ctx<'_>,
    cache: &'e mut HashMap<usize, HashSet<Vec<u8>>>,
    m: usize,
) -> &'e HashSet<Vec<u8>> {
    cache.entry(m).or_insert_with(|| {
        parsed(ctx, m)
            .map(|i| i.exports().into_iter().map(|e| e.name).collect())
            .unwrap_or_default()
    })
}

/// Whether module `m` (or a library it re-exports) exports `symbol`;
/// `None` if that can't be told (a library not read).
fn exported(
    ctx: &Ctx<'_>,
    cache: &mut HashMap<usize, HashSet<Vec<u8>>>,
    m: usize,
    symbol: &[u8],
    depth: usize,
) -> Option<bool> {
    ctx.loaded[m].as_ref()?;
    if exports(ctx, cache, m).contains(symbol) {
        return Some(true);
    }
    if depth >= MAX_REEXPORT_DEPTH {
        return Some(false);
    }
    let reexported: Vec<usize> = ctx.graph.modules[m]
        .deps
        .iter()
        .filter(|d| d.kind == DepKind::ReexportDylib)
        .map(|d| d.module)
        .collect();
    let mut unknown = false;
    for r in reexported {
        match exported(ctx, cache, r, symbol, depth + 1) {
            Some(true) => return Some(true),
            None => unknown = true,
            Some(false) => {}
        }
    }
    (!unknown).then_some(false)
}

/// Checks binds against the libraries they name.
pub(crate) fn check(ctx: &mut Ctx<'_>) {
    let mut cache = HashMap::new();
    for m in 0..ctx.graph.modules.len() {
        if ctx.loaded[m].is_none() {
            continue;
        }
        let count = parsed(ctx, m).map_or(0, |i| i.exports().len());
        ctx.graph.modules[m].exports = count;
        for d in 0..ctx.graph.modules[m].deps.len() {
            let target = ctx.graph.modules[m].deps[d].module;
            let mut imports = std::mem::take(&mut ctx.graph.modules[m].deps[d].imports);
            for i in &mut imports {
                let Some(name) = &i.name else { continue };
                i.status = match exported(ctx, &mut cache, target, name.as_bytes(), 0) {
                    Some(true) => ImportStatus::Found,
                    Some(false) => ImportStatus::Missing,
                    None => ImportStatus::Unchecked,
                };
            }
            ctx.graph.modules[m].deps[d].imports = imports;
        }
        // Flat-namespace binds: any library loaded.
        let mut flat = std::mem::take(&mut ctx.graph.modules[m].unresolved);
        let all: Vec<usize> = (0..ctx.graph.modules.len()).filter(|&o| o != m).collect();
        for i in &mut flat {
            let Some(name) = &i.name else { continue };
            let found = all
                .iter()
                .any(|&o| exported(ctx, &mut cache, o, name.as_bytes(), 0) == Some(true));
            i.status = if found {
                ImportStatus::Found
            } else {
                ImportStatus::Missing
            };
        }
        flat.retain(|i| i.status == ImportStatus::Missing && !i.weak);
        ctx.graph.modules[m].unresolved = flat;
    }
}

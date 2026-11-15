//! PE: imports and delay-loads, the DLL search, API sets, side-by-side
//! assemblies, and exports (forwarders followed).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hexcavator_pe::PeFile;
use hexcavator_pe::apiset::{ApiSetSchema, is_api_set_name};
use hexcavator_pe::exports::ExportTarget;
use hexcavator_pe::imports::ImportName;

use crate::manifest::{self, Assembly};
use crate::search::{Reject, is_plain_name};
use crate::{Ctx, DepKind, Found, Import, ImportStatus, Resolved, Status, Wanted};

/// Known DLLs (`HKLM\SYSTEM\CurrentControlSet\Control\Session
/// Manager\KnownDLLs`, Windows 11, with ntdll and kernelbase, which are
/// always the system's): the system's copies are loaded whatever else is
/// found, the application's directory notwithstanding.
const KNOWN_DLLS: &[&str] = &[
    "advapi32.dll",
    "clbcatq.dll",
    "combase.dll",
    "comdlg32.dll",
    "coml2.dll",
    "difxapi.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "imagehlp.dll",
    "imm32.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "msctf.dll",
    "msvcrt.dll",
    "normaliz.dll",
    "nsi.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "setupapi.dll",
    "shcore.dll",
    "shell32.dll",
    "shlwapi.dll",
    "user32.dll",
    "wldap32.dll",
    "wow64.dll",
    "wow64base.dll",
    "wow64con.dll",
    "wow64cpu.dll",
    "wow64win.dll",
    "ws2_32.dll",
    "xtajit.dll",
    "xtajit64.dll",
];

/// The most imports of one DLL read.
const MAX_IMPORTS: usize = 1 << 16;
/// How many forwarders are followed in a chain.
const MAX_FORWARDS: usize = 8;

/// What the PE search keeps.
#[derive(Default)]
pub(crate) struct State {
    /// The system directory.
    system: Option<PathBuf>,
    apiset: Option<ApiSetSchema>,
    /// `WinSxS`, and its entries (lower case), once listed.
    winsxs: Option<(PathBuf, Vec<String>)>,
    /// The assemblies' directories each module's manifest names.
    assemblies: HashMap<usize, Vec<PathBuf>>,
    /// Each module's exports: by name (and its forwarder), by ordinal.
    exports: HashMap<usize, Exports>,
    /// Whether this host's own Windows directory is the system root (then
    /// `PATH` is searched too).
    host: bool,
}

#[derive(Default)]
struct Exports {
    names: HashMap<String, Option<String>>,
    ordinals: HashMap<u16, Option<String>>,
}

impl State {
    pub fn new(ctx: &Ctx<'_>) -> Self {
        let mut s = State::default();
        let Some(root) = &ctx.sysroot else {
            return s;
        };
        s.host = crate::search::host_sysroot(crate::Format::Pe).as_deref() == Some(root.as_path());
        // A 32-bit image's system directory on 64-bit Windows.
        let wow = match ctx
            .search
            .arch
            .as_ref()
            .and_then(crate::search::Arch::pe_32_bit)
        {
            Some(0x14C) => Some("SysWOW64"),
            Some(_) => Some("SysArm32"),
            None => None,
        };
        let system = wow
            .map(|d| root.join(d))
            .filter(|d| d.is_dir())
            .unwrap_or_else(|| root.join("System32"));
        let schema = ctx
            .options
            .apiset
            .clone()
            .unwrap_or_else(|| root.join("System32").join("apisetschema.dll"));
        s.apiset = read_schema(&schema);
        s.system = Some(system);
        s
    }
}

/// The API set schema in the `.apiset` section of the DLL at `path`.
fn read_schema(path: &Path) -> Option<ApiSetSchema> {
    let map = hexcavator_mmap::Mmap::open_named(path).ok()?;
    let pe = PeFile::parse_image(&map).ok()?;
    let section = pe.sections().iter().find(|s| s.raw_name() == b".apiset")?;
    let start = usize::try_from(section.pointer_to_raw_data.get()).ok()?;
    let len = usize::try_from(section.size_of_raw_data.get()).ok()?;
    ApiSetSchema::parse(map.get(start..start.checked_add(len)?.min(map.len()))?)
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The DLLs (and assemblies) module `m` loads.
pub(crate) fn wanted(ctx: &mut Ctx<'_>, m: usize) -> Vec<Wanted> {
    let Some(loaded) = ctx.loaded[m].as_ref() else {
        return Vec::new();
    };
    let Ok(pe) = PeFile::parse_image(loaded.data()) else {
        return Vec::new();
    };
    let imported = |name: ImportName<'_>| match name {
        ImportName::Name { name, .. } => Import {
            name: Some(lossy(name)),
            ordinal: None,
            version: None,
            weak: false,
            status: ImportStatus::Unchecked,
        },
        ImportName::Ordinal(o) => Import {
            name: None,
            ordinal: Some(o),
            version: None,
            weak: false,
            status: ImportStatus::Unchecked,
        },
    };
    let assemblies = manifest_assemblies(&pe);
    let mut out: Vec<Wanted> = assemblies
        .iter()
        .map(|a| Wanted {
            name: a.label(),
            kind: DepKind::Assembly,
            imports: Vec::new(),
        })
        .collect();
    for dll in pe.imports().take(MAX_IMPORTS) {
        out.push(Wanted {
            name: lossy(dll.name),
            kind: DepKind::Import,
            imports: dll
                .thunks()
                .take(MAX_IMPORTS)
                .map(|t| imported(t.import))
                .collect(),
        });
    }
    for dll in pe.delay_imports().take(MAX_IMPORTS) {
        out.push(Wanted {
            name: lossy(dll.name),
            kind: DepKind::DelayLoad,
            imports: dll
                .thunks()
                .take(MAX_IMPORTS)
                .map(|t| imported(t.import))
                .collect(),
        });
    }
    // Its manifest's assemblies' directories: their DLLs come before
    // others'.
    for a in &assemblies {
        if let Some(d) = assembly_dir(ctx, a) {
            ctx.pe.assemblies.entry(m).or_default().push(d);
        }
    }
    out
}

/// The assemblies the image's manifest (`RT_MANIFEST` 1, 2, or 3) depends
/// on.
fn manifest_assemblies(pe: &PeFile<'_>) -> Vec<Assembly> {
    use hexcavator_pe::resources::{ResourceName, ResourceTarget, resource_type};
    let Some(root) = pe.resource_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let types = root
        .iter()
        .filter(|e| e.name == Some(ResourceName::Id(resource_type::MANIFEST)));
    for t in types {
        let ResourceTarget::Directory(names) = t.target else {
            continue;
        };
        let Some(names) = pe.resource_directory(root.base(), names) else {
            continue;
        };
        for n in names.iter().take(4) {
            let ResourceTarget::Directory(langs) = n.target else {
                continue;
            };
            let Some(langs) = pe.resource_directory(root.base(), langs) else {
                continue;
            };
            for l in langs.iter().take(4) {
                let ResourceTarget::Data(entry) = l.target else {
                    continue;
                };
                let Some(entry) = pe.resource_data_entry(entry) else {
                    continue;
                };
                if let Ok(data) =
                    pe.bytes_at_rva(hexcavator_core::Rva(entry.data.get()), entry.size.get())
                {
                    out.extend(manifest::dependencies(data));
                }
            }
        }
    }
    out.dedup();
    out
}

/// The `WinSxS` directory of assembly `a`, if there is one.
fn assembly_dir(ctx: &mut Ctx<'_>, a: &Assembly) -> Option<PathBuf> {
    let root = ctx.sysroot.as_ref()?;
    if ctx.pe.winsxs.is_none() {
        let dir = root.join("WinSxS");
        let entries = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .take(1 << 20)
                    .map(|e| e.file_name().to_string_lossy().to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        ctx.pe.winsxs = Some((dir, entries));
    }
    let arch = match ctx.search.arch.as_ref().map(|a| a.name.as_str()) {
        Some("x86") => "x86",
        Some("arm64" | "arm64ec" | "arm64x") => "arm64",
        Some("arm" | "armnt" | "thumb") => "arm",
        _ => "amd64",
    };
    let (dir, entries) = ctx.pe.winsxs.as_ref()?;
    manifest::find(dir, entries, a, arch)
}

/// Where `name` is, as `loader` loads it.
pub(crate) fn resolve(ctx: &mut Ctx<'_>, loader: usize, name: &str, kind: DepKind) -> Resolved {
    if kind == DepKind::Assembly {
        // (Found when its manifest was read.)
        let dir = ctx.pe.assemblies.get(&loader).and_then(|d| {
            let key = name.split(' ').next().unwrap_or(name).to_ascii_lowercase();
            d.iter()
                .find(|p| p.to_string_lossy().to_ascii_lowercase().contains(&key))
                .cloned()
        });
        return Resolved::Other(Status::Assembly { dir });
    }
    if !is_plain_name(name) {
        return Resolved::Other(Status::Missing { tried: Vec::new() });
    }
    // An API set: its host, as this loader imports it.
    if is_api_set_name(name) {
        let importer = ctx.graph.modules[loader].name.clone();
        let Some(schema) = &ctx.pe.apiset else {
            return Resolved::Other(Status::ApiSet {
                host: None,
                known: false,
            });
        };
        return match schema.resolve(name, &importer) {
            Some(Some(host)) => {
                let host = host.to_string();
                match resolve(ctx, loader, &host, DepKind::ApiSetHost) {
                    Resolved::Other(Status::Missing { tried }) => {
                        Resolved::Other(Status::ApiSetHostMissing { host, tried })
                    }
                    other => other,
                }
            }
            Some(None) => Resolved::Other(Status::ApiSet {
                host: None,
                known: true,
            }),
            // (Not a set this system has.)
            None => Resolved::Other(Status::ApiSet {
                host: None,
                known: true,
            }),
        };
    }
    let file = if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.dll")
    };
    let lower = file.to_ascii_lowercase();
    let mut dirs: Vec<(PathBuf, Found)> = Vec::new();
    // Side-by-side assemblies (the loader's manifest's, then the
    // program's), known DLLs, the application's directory, the system's.
    for m in [loader, 0] {
        for d in ctx.pe.assemblies.get(&m).into_iter().flatten() {
            dirs.push((d.clone(), Found::Assembly));
        }
    }
    let system = ctx.pe.system.clone();
    if let Some(s) = &system
        && KNOWN_DLLS.contains(&lower.as_str())
    {
        dirs.push((s.clone(), Found::KnownDll));
    }
    dirs.push((ctx.root_dir.clone(), Found::AppDir));
    if let (Some(s), Some(root)) = (&system, ctx.sysroot.clone()) {
        dirs.push((s.clone(), Found::SystemDir));
        dirs.push((root.join("System"), Found::WindowsDir));
        dirs.push((root, Found::WindowsDir));
    }
    for d in &ctx.options.dirs {
        dirs.push((d.clone(), Found::SearchDir));
    }
    if ctx.pe.host
        && let Some(path) = std::env::var_os("PATH")
    {
        for d in std::env::split_paths(&path).take(256) {
            dirs.push((d, Found::SearchDir));
        }
    }
    let mut tried = Vec::new();
    let mut other = None;
    let mut seen = std::collections::HashSet::new();
    for (dir, how) in dirs {
        let path = ctx.search.in_dir(&dir, &file);
        // (Windows paths: any case, either separator.)
        if !seen.insert(path.to_string_lossy().replace('/', "\\").to_lowercase()) {
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

/// Module `m`'s exports (read once).
fn exports<'c>(ctx: &'c mut Ctx<'_>, m: usize) -> Option<&'c Exports> {
    if !ctx.pe.exports.contains_key(&m) {
        let mut e = Exports::default();
        if let Some(pe) = ctx.loaded[m]
            .as_ref()
            .and_then(|l| PeFile::parse_image(l.data()).ok())
            && let Some(table) = pe.exports()
        {
            for x in table.iter() {
                let fwd = match x.target {
                    ExportTarget::Forwarder(f) => Some(lossy(f)),
                    ExportTarget::Rva(_) => None,
                };
                if let Some(n) = x.name {
                    e.names.insert(lossy(n), fwd.clone());
                }
                if let Ok(o) = u16::try_from(x.ordinal) {
                    e.ordinals.insert(o, fwd);
                }
            }
        }
        ctx.graph.modules[m].exports = e.ordinals.len().max(e.names.len());
        ctx.pe.exports.insert(m, e);
    }
    ctx.pe.exports.get(&m)
}

/// Checks every import against its DLL's exports, following forwarders
/// (adding the DLLs they name, and what those load).
pub(crate) fn check(ctx: &mut Ctx<'_>) {
    let mut m = 0;
    while m < ctx.graph.modules.len() {
        if ctx.loaded[m].is_some()
            && m != 0
            && ctx.graph.modules[m].deps.is_empty()
            && (ctx.options.system || !ctx.graph.modules[m].system)
        {
            // (A module a forwarder added: what it loads.)
            expand(ctx, m);
        }
        for d in 0..ctx.graph.modules[m].deps.len() {
            let target = ctx.graph.modules[m].deps[d].module;
            if ctx.loaded[target].is_none() {
                continue;
            }
            let imports = std::mem::take(&mut ctx.graph.modules[m].deps[d].imports);
            let mut checked = Vec::with_capacity(imports.len());
            for mut i in imports {
                i.status = lookup(ctx, target, &i, 0);
                checked.push(i);
            }
            ctx.graph.modules[m].deps[d].imports = checked;
        }
        m += 1;
    }
}

/// Reads what module `m` loads (one a forwarder added after the search).
fn expand(ctx: &mut Ctx<'_>, m: usize) {
    for w in wanted(ctx, m) {
        let (target, _) = ctx.find(m, &w.name, w.kind);
        ctx.graph.modules[m].deps.push(crate::Dep {
            name: w.name,
            kind: w.kind,
            module: target,
            imports: w.imports,
        });
    }
}

/// Whether module `m` exports `import`, following forwarders `depth` deep.
fn lookup(ctx: &mut Ctx<'_>, m: usize, import: &Import, depth: usize) -> ImportStatus {
    let Some(e) = exports(ctx, m) else {
        return ImportStatus::Unchecked;
    };
    let found = match (&import.name, import.ordinal) {
        (Some(n), _) => e.names.get(n),
        (None, Some(o)) => e.ordinals.get(&o),
        (None, None) => None,
    };
    let Some(forward) = found.cloned() else {
        return ImportStatus::Missing;
    };
    let Some(forward) = forward else {
        return ImportStatus::Found;
    };
    if depth >= MAX_FORWARDS {
        return ImportStatus::Forwarded(forward);
    }
    // `DLL.Name` or `DLL.#ordinal`: the DLL, a dependency of this one.
    let Some((dll, what)) = forward.rsplit_once('.') else {
        return ImportStatus::Missing;
    };
    let next = match what.strip_prefix('#') {
        Some(o) => Import {
            name: None,
            ordinal: o.parse().ok(),
            ..import.clone()
        },
        None => Import {
            name: Some(what.to_string()),
            ordinal: None,
            ..import.clone()
        },
    };
    let dll_name = format!("{dll}.dll");
    let existing = ctx.graph.modules[m]
        .deps
        .iter()
        .position(|d| d.kind == DepKind::Forwarder && d.name.eq_ignore_ascii_case(&dll_name));
    let target = match existing {
        Some(i) => ctx.graph.modules[m].deps[i].module,
        None => {
            let (t, _) = ctx.find(m, &dll_name, DepKind::Forwarder);
            ctx.graph.modules[m].deps.push(crate::Dep {
                name: dll_name.clone(),
                kind: DepKind::Forwarder,
                module: t,
                imports: Vec::new(),
            });
            t
        }
    };
    let status = if ctx.loaded[target].is_some() {
        lookup(ctx, target, &next, depth + 1)
    } else {
        ImportStatus::Unchecked
    };
    // The forwarder's own edge lists what goes through it.
    if let Some(d) = ctx.graph.modules[m]
        .deps
        .iter_mut()
        .find(|d| d.kind == DepKind::Forwarder && d.name.eq_ignore_ascii_case(&dll_name))
        && d.imports.len() < MAX_IMPORTS
        && !d
            .imports
            .iter()
            .any(|x| x.name == next.name && x.ordinal == next.ordinal)
    {
        d.imports.push(Import {
            status: status.clone(),
            ..next
        });
    }
    if status.is_missing() {
        ImportStatus::Broken(forward)
    } else {
        ImportStatus::Forwarded(forward)
    }
}

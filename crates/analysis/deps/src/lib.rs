//! What an executable or library loads: the libraries it names, found as
//! its platform's loader finds them, the libraries they load in turn, and
//! the imports none of them provide.
//!
//! [`analyze`] builds a [`Graph`] from a root image (PE, ELF, or Mach-O),
//! reading files only: nothing is loaded or run. Each platform's search is
//! the loader's, over a system root ([`Options::sysroot`]: a Windows
//! directory, or the root of a Unix file system; by default this host's,
//! for its own format) and directories given:
//!
//! - PE: known DLLs, then the application's directory, the system
//!   directory (`System32`, or `SysWOW64`/`SysArm32` for 32-bit images),
//!   `System`, the Windows directory, then the directories given; API sets
//!   by the API set schema; side-by-side assemblies its manifest names, in
//!   `WinSxS`; forwarded exports followed.
//! - ELF: `DT_RPATH` (the loading object's, then its loaders'), the
//!   directories given (as `LD_LIBRARY_PATH`), `DT_RUNPATH`, `ld.so.conf`,
//!   then the default directories (multiarch, `lib64`, `lib`); `$ORIGIN`,
//!   `$LIB`, and `$PLATFORM` expanded; the interpreter.
//! - Mach-O: install names, `@executable_path`, `@loader_path`, and
//!   `@rpath` (the loading image's run paths, then its loaders'); a
//!   universal file's slice for the root's architecture; system libraries
//!   that live only in the dyld shared cache.
//!
//! Imports are checked against exports: a PE image's functions (by name or
//! ordinal, following forwarders), an ELF object's undefined symbols (with
//! their versions) against the objects loaded (in load order), a Mach-O
//! image's binds against the export tries of the libraries they name.
//!
//! Names come from the files, so they are hostile: only local regular
//! files are opened, and names that are paths where a name belongs are
//! not searched for.

mod elf;
mod macho;
mod manifest;
mod pe;
mod search;

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use hexcavator_mmap::Mmap;

/// How far the analysis goes.
#[derive(Clone, Debug)]
pub struct Options {
    /// The system root: a Windows directory (for PE: its `System32` and
    /// the rest), or the root of a Unix file system (for ELF and Mach-O:
    /// its `lib` directories, `etc/ld.so.conf`, `/usr/lib`, frameworks).
    /// `None`: this host's, for its own format, and none for the others
    /// (their system libraries aren't searched).
    pub sysroot: Option<PathBuf>,
    /// More directories to search: for PE, after the system's (as `PATH`
    /// is); for ELF, as `LD_LIBRARY_PATH` is; for Mach-O, after all else.
    pub dirs: Vec<PathBuf>,
    /// The API set schema (`apisetschema.dll`); default: the sysroot's.
    pub apiset: Option<PathBuf>,
    /// Whether to check imports against exports.
    pub symbols: bool,
    /// The most modules read.
    pub max_modules: usize,
    /// Whether to read what system libraries load too (and report their
    /// problems). Without, a system library is a leaf, checked only for
    /// what it exports.
    pub system: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sysroot: None,
            dirs: Vec::new(),
            apiset: None,
            symbols: true,
            max_modules: 4096,
            system: false,
        }
    }
}

/// A module's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Pe,
    Elf,
    MachO,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
        }
    }
}

/// Where a module was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Found {
    /// The file analyzed.
    Root,
    /// By the path it is named by (an ELF name with a slash, a Mach-O
    /// install name).
    Path,
    /// A known DLL (the system's own copy, whatever else is found).
    KnownDll,
    /// The application's directory.
    AppDir,
    /// The system directory (`System32`, `SysWOW64`, `SysArm32`).
    SystemDir,
    /// `System`, or the Windows directory.
    WindowsDir,
    /// A side-by-side assembly's directory (`WinSxS`).
    Assembly,
    /// A directory given.
    SearchDir,
    /// `DT_RPATH`, or a Mach-O run path.
    Rpath,
    /// `DT_RUNPATH`.
    Runpath,
    /// A directory `ld.so.conf` names.
    LdSoConf,
    /// A default directory (`/lib`, `/usr/lib`, ...).
    DefaultDir,
    /// `@loader_path`.
    LoaderPath,
    /// `@executable_path`.
    ExecutablePath,
}

impl Found {
    /// Whether a module found so is the system's: a known DLL, one in the
    /// system or Windows directory, or in a default library directory.
    pub fn is_system(self) -> bool {
        matches!(
            self,
            Found::KnownDll
                | Found::SystemDir
                | Found::WindowsDir
                | Found::LdSoConf
                | Found::DefaultDir
        )
    }

    pub fn describe(self) -> &'static str {
        match self {
            Found::Root => "the file given",
            Found::Path => "by its path",
            Found::KnownDll => "known DLL",
            Found::AppDir => "application directory",
            Found::SystemDir => "system directory",
            Found::WindowsDir => "Windows directory",
            Found::Assembly => "side-by-side assembly",
            Found::SearchDir => "directory given",
            Found::Rpath => "rpath",
            Found::Runpath => "runpath",
            Found::LdSoConf => "ld.so.conf",
            Found::DefaultDir => "default directory",
            Found::LoaderPath => "@loader_path",
            Found::ExecutablePath => "@executable_path",
        }
    }
}

/// What became of a module the graph names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Found there, so.
    Found { path: PathBuf, how: Found },
    /// Not found: the paths tried.
    Missing { tried: Vec<PathBuf> },
    /// Only files for another architecture are where it would be.
    WrongArch { path: PathBuf, arch: String },
    /// Found, but not a module this one can load (or not readable).
    Unreadable { path: PathBuf, why: String },
    /// An API set: its host (`None`: none on this system); or the schema
    /// wasn't found to say (`known` false).
    ApiSet { host: Option<String>, known: bool },
    /// An API set whose host (named) isn't found: the paths tried.
    ApiSetHostMissing { host: String, tried: Vec<PathBuf> },
    /// A system library only the dyld shared cache holds (macOS 11 and
    /// later).
    SharedCache,
    /// A system library, not searched for: no system root for its format
    /// on this host (see [`Options::sysroot`]).
    Unsearched,
    /// A side-by-side assembly a manifest names: its directory in
    /// `WinSxS`, if found.
    Assembly { dir: Option<PathBuf> },
}

impl Status {
    /// Whether the module is missing (or unusable).
    pub fn is_problem(&self) -> bool {
        matches!(
            self,
            Status::Missing { .. }
                | Status::WrongArch { .. }
                | Status::Unreadable { .. }
                | Status::ApiSetHostMissing { .. }
        )
    }

    /// Its file, if one was found.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Status::Found { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// How one module comes to load another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DepKind {
    /// A PE import.
    Import,
    /// A PE delay-load import (loaded on its first call).
    DelayLoad,
    /// A forwarded PE export's target.
    Forwarder,
    /// An API set's host.
    ApiSetHost,
    /// A side-by-side assembly.
    Assembly,
    /// `DT_NEEDED`.
    Needed,
    /// The ELF interpreter (`PT_INTERP`).
    Interpreter,
    /// `LC_LOAD_DYLIB`.
    Dylib,
    /// `LC_LOAD_WEAK_DYLIB` (missing is no failure).
    WeakDylib,
    /// `LC_REEXPORT_DYLIB`.
    ReexportDylib,
    /// `LC_LAZY_LOAD_DYLIB`.
    LazyDylib,
    /// `LC_LOAD_UPWARD_DYLIB`.
    UpwardDylib,
}

impl DepKind {
    pub fn name(self) -> &'static str {
        match self {
            DepKind::Import => "import",
            DepKind::DelayLoad => "delay-load",
            DepKind::Forwarder => "forwarder",
            DepKind::ApiSetHost => "api-set-host",
            DepKind::Assembly => "assembly",
            DepKind::Needed => "needed",
            DepKind::Interpreter => "interpreter",
            DepKind::Dylib => "dylib",
            DepKind::WeakDylib => "weak-dylib",
            DepKind::ReexportDylib => "reexport-dylib",
            DepKind::LazyDylib => "lazy-dylib",
            DepKind::UpwardDylib => "upward-dylib",
        }
    }

    /// Whether the module loads without it (missing, it fails only later,
    /// or not at all).
    pub fn optional(self) -> bool {
        matches!(
            self,
            DepKind::DelayLoad | DepKind::WeakDylib | DepKind::LazyDylib
        )
    }
}

/// What became of an import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportStatus {
    /// Not checked (its module wasn't found, or checks are off).
    Unchecked,
    /// Exported there.
    Found,
    /// Exported there as a forwarder, to this (`DLL.Name`), which exists.
    Forwarded(String),
    /// Not exported.
    Missing,
    /// Exported as a forwarder, to this (`DLL.Name`), which isn't there.
    Broken(String),
}

impl ImportStatus {
    /// Whether the import isn't there (missing, or a broken forwarder).
    pub fn is_missing(&self) -> bool {
        matches!(self, ImportStatus::Missing | ImportStatus::Broken(_))
    }
}

/// One symbol a module imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Its name (none: by ordinal).
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// An ELF version it needs.
    pub version: Option<String>,
    /// Whether missing is no failure (weak).
    pub weak: bool,
    pub status: ImportStatus,
}

impl Import {
    /// Its name, or `#ordinal` (and, a broken forwarder, where to).
    pub fn label(&self) -> String {
        if let ImportStatus::Broken(to) = &self.status {
            return format!("{} (forwarded to {to})", self.plain());
        }
        self.plain()
    }

    fn plain(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(n), _) => match &self.version {
                Some(v) => format!("{n}@{v}"),
                None => n.clone(),
            },
            (None, Some(o)) => format!("#{o}"),
            (None, None) => "?".to_string(),
        }
    }
}

/// One module loading another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dep {
    /// The name it's loaded by.
    pub name: String,
    pub kind: DepKind,
    /// The module loaded (an index into [`Graph::modules`]).
    pub module: usize,
    /// What it imports from it.
    pub imports: Vec<Import>,
}

/// A module of the graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Its name: the file's, or the name it was first loaded by.
    pub name: String,
    pub status: Status,
    pub format: Option<Format>,
    /// Its architecture's name.
    pub arch: Option<String>,
    /// What it loads, in order.
    pub deps: Vec<Dep>,
    /// Symbols it imports that no module loaded defines (ELF, and a
    /// Mach-O image's flat-namespace binds).
    pub unresolved: Vec<Import>,
    /// How many symbols it exports.
    pub exports: usize,
    /// How deep it is (the root is 0; its first loader's depth plus one).
    pub depth: usize,
    /// Whether it is the system's (see [`Found::is_system`]; a Mach-O
    /// library in `/usr/lib` or `/System`, or the shared cache).
    pub system: bool,
}

/// How bad a problem is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// The module won't load.
    Error,
    /// It loads, but something may fail later (a delay-loaded DLL, an
    /// API set without a host).
    Warning,
}

/// A problem the graph shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub severity: Severity,
    /// The module it's of.
    pub module: usize,
    pub message: String,
}

/// What a root image loads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    /// The modules, the root first, then in the order they are found
    /// (breadth first: load order).
    pub modules: Vec<Module>,
    pub problems: Vec<Problem>,
    /// What wasn't looked at (system directories without a system root;
    /// the module limit).
    pub notes: Vec<String>,
    /// The system root searched, if any.
    pub sysroot: Option<PathBuf>,
}

/// An image read: its file and, for a universal Mach-O file, the slice's
/// place in it.
pub(crate) struct Loaded {
    pub map: Mmap,
    pub range: std::ops::Range<usize>,
}

impl Loaded {
    pub fn data(&self) -> &[u8] {
        self.map.get(self.range.clone()).unwrap_or(&[])
    }
}

/// The analysis under way.
pub(crate) struct Ctx<'o> {
    pub options: &'o Options,
    pub format: Format,
    pub root_dir: PathBuf,
    pub sysroot: Option<PathBuf>,
    pub graph: Graph,
    pub loaded: Vec<Option<Loaded>>,
    /// Modules by found path (lower case for PE), and by name for those
    /// without one.
    by_path: HashMap<String, usize>,
    by_name: HashMap<String, usize>,
    /// Each module's first loader.
    pub parent: Vec<Option<usize>>,
    pub search: search::Search,
    pub pe: pe::State,
}

/// What a module names, to be found: its name, how it's loaded, and what
/// it imports.
pub(crate) struct Wanted {
    pub name: String,
    pub kind: DepKind,
    pub imports: Vec<Import>,
}

/// Where a wanted module is, as found.
pub(crate) enum Resolved {
    File {
        path: PathBuf,
        how: Found,
        loaded: Loaded,
    },
    Other(Status),
}

/// Analyzes the image at `root`.
///
/// # Errors
///
/// If it can't be read, or isn't a PE, ELF, or Mach-O image.
pub fn analyze(root: &Path, options: &Options) -> Result<Graph, String> {
    let map = Mmap::open(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let (format, range) = search::identify(&map, None)
        .ok_or_else(|| format!("{}: not a PE, ELF, or Mach-O image", root.display()))?;
    let loaded = Loaded { map, range };
    let root_dir = root
        .parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));
    let sysroot = options
        .sysroot
        .clone()
        .or_else(|| search::host_sysroot(format));
    let arch = search::arch_of(format, loaded.data());
    let mut ctx = Ctx {
        options,
        format,
        root_dir,
        sysroot: sysroot.clone(),
        graph: Graph {
            sysroot,
            ..Graph::default()
        },
        loaded: Vec::new(),
        by_path: HashMap::new(),
        by_name: HashMap::new(),
        parent: Vec::new(),
        search: search::Search::new(format, arch),
        pe: pe::State::default(),
    };
    if format == Format::Pe {
        ctx.pe = pe::State::new(&ctx);
    }
    let name = root.file_name().map_or_else(
        || root.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let first = ctx.add(
        name,
        Resolved::File {
            path: root.to_path_buf(),
            how: Found::Root,
            loaded,
        },
        None,
    );
    let mut queue = VecDeque::from([first]);
    while let Some(m) = queue.pop_front() {
        for w in ctx.wanted(m) {
            let (target, new) = ctx.find(m, &w.name, w.kind);
            ctx.graph.modules[m].deps.push(Dep {
                name: w.name,
                kind: w.kind,
                module: target,
                imports: w.imports,
            });
            if new && (options.system || !ctx.graph.modules[target].system) {
                queue.push_back(target);
            }
        }
    }
    if options.symbols {
        match format {
            Format::Pe => pe::check(&mut ctx),
            Format::Elf => elf::check(&mut ctx),
            Format::MachO => macho::check(&mut ctx),
        }
    }
    ctx.problems();
    Ok(ctx.graph)
}

impl Ctx<'_> {
    /// Module `m`'s wanted modules (none if it wasn't read).
    fn wanted(&mut self, m: usize) -> Vec<Wanted> {
        if self.loaded.get(m).is_none_or(Option::is_none) {
            return Vec::new();
        }
        match self.format {
            Format::Pe => pe::wanted(self, m),
            Format::Elf => elf::wanted(self, m),
            Format::MachO => macho::wanted(self, m),
        }
    }

    /// The module `name` is, as `loader` loads it: one already in the
    /// graph, or a new one (and whether it is new: to read its own).
    fn find(&mut self, loader: usize, name: &str, kind: DepKind) -> (usize, bool) {
        let resolved = match self.format {
            Format::Pe => pe::resolve(self, loader, name, kind),
            Format::Elf => elf::resolve(self, loader, name, kind),
            Format::MachO => macho::resolve(self, loader, name, kind),
        };
        // The same file (or the same unfound name) is one module.
        let key = match &resolved {
            Resolved::File { path, .. } => Some(self.path_key(&search::normalize(path))),
            Resolved::Other(_) => None,
        };
        let name_key = self.name_key(name);
        if let Some(k) = &key
            && let Some(&i) = self.by_path.get(k)
        {
            return (i, false);
        }
        if key.is_none()
            && let Some(&i) = self.by_name.get(&name_key)
        {
            return (i, false);
        }
        if self.graph.modules.len() >= self.options.max_modules {
            if !self
                .graph
                .notes
                .iter()
                .any(|n| n.starts_with("only the first"))
            {
                self.graph.notes.push(format!(
                    "only the first {} modules were read",
                    self.options.max_modules
                ));
            }
            let i = self.add(
                name.to_string(),
                Resolved::Other(Status::Unsearched),
                Some(loader),
            );
            return (i, false);
        }
        let new = matches!(resolved, Resolved::File { .. });
        let i = self.add(name.to_string(), resolved, Some(loader));
        (i, new)
    }

    fn path_key(&self, path: &Path) -> String {
        let s = path.to_string_lossy().replace('\\', "/");
        if self.format == Format::Pe {
            s.to_lowercase()
        } else {
            s
        }
    }

    fn name_key(&self, name: &str) -> String {
        if self.format == Format::Pe {
            name.to_lowercase()
        } else {
            name.to_string()
        }
    }

    /// Adds a module.
    fn add(&mut self, name: String, resolved: Resolved, loader: Option<usize>) -> usize {
        let i = self.graph.modules.len();
        let depth = loader.map_or(0, |l| self.graph.modules[l].depth + 1);
        let resolved = match resolved {
            Resolved::File { path, how, loaded } => Resolved::File {
                path: search::normalize(&path),
                how,
                loaded,
            },
            Resolved::Other(Status::Missing { tried }) => Resolved::Other(Status::Missing {
                tried: tried.iter().map(|p| search::normalize(p)).collect(),
            }),
            other => other,
        };
        let (status, loaded) = match resolved {
            Resolved::File { path, how, loaded } => {
                self.by_path.insert(self.path_key(&path), i);
                (Status::Found { path, how }, Some(loaded))
            }
            Resolved::Other(status) => {
                self.by_name.insert(self.name_key(&name), i);
                (status, None)
            }
        };
        let (format, arch) = match &loaded {
            Some(l) => (
                Some(self.format),
                search::arch_of(self.format, l.data()).map(|a| a.name),
            ),
            None => (None, None),
        };
        // (A found module is named by its file.)
        let name = match &status {
            Status::Found { path, how, .. } if *how != Found::Assembly => path
                .file_name()
                .map_or(name.clone(), |n| n.to_string_lossy().into_owned()),
            _ => name,
        };
        let system = match &status {
            Status::Found { how, .. } => {
                how.is_system() || (self.format == Format::MachO && macho::is_system(&name))
            }
            Status::SharedCache => true,
            _ => false,
        };
        self.graph.modules.push(Module {
            name,
            status,
            format,
            arch,
            deps: Vec::new(),
            unresolved: Vec::new(),
            exports: 0,
            depth,
            system,
        });
        self.loaded.push(loaded);
        self.parent.push(loader);
        i
    }

    /// The problems: modules missing, imports missing.
    fn problems(&mut self) {
        let mut problems = Vec::new();
        let modules = &self.graph.modules;
        for (i, m) in modules.iter().enumerate() {
            if m.system && !self.options.system {
                continue;
            }
            for d in &m.deps {
                let t = &modules[d.module];
                let severity = if d.kind.optional() {
                    Severity::Warning
                } else {
                    Severity::Error
                };
                let what = match &t.status {
                    Status::Missing { .. } => "not found".to_string(),
                    Status::ApiSetHostMissing { host, .. } => {
                        format!("an API set whose host, {host}, isn't on this system")
                    }
                    Status::WrongArch { arch, .. } => format!("only found for {arch}"),
                    Status::Unreadable { why, .. } => why.clone(),
                    Status::ApiSet {
                        host: None,
                        known: true,
                    } => {
                        problems.push(Problem {
                            severity: Severity::Warning,
                            module: i,
                            message: format!(
                                "{} imports API set {}, which has no host here",
                                m.name, d.name
                            ),
                        });
                        continue;
                    }
                    _ => {
                        let missing: Vec<String> = d
                            .imports
                            .iter()
                            .filter(|x| x.status.is_missing() && !x.weak)
                            .map(Import::label)
                            .collect();
                        if !missing.is_empty() {
                            problems.push(Problem {
                                severity,
                                module: i,
                                message: format!(
                                    "{} imports {} from {} that it doesn't export: {}",
                                    m.name,
                                    plural(missing.len(), "symbol"),
                                    d.name,
                                    list(&missing)
                                ),
                            });
                        }
                        continue;
                    }
                };
                // (Once a module, not once a loader: the first's.)
                if problems
                    .iter()
                    .any(|p: &Problem| p.module == d.module && p.severity <= severity)
                {
                    continue;
                }
                problems.push(Problem {
                    severity,
                    module: d.module,
                    message: format!(
                        "{} ({} by {}): {what}",
                        d.name,
                        match d.kind {
                            DepKind::DelayLoad => "delay-loaded",
                            DepKind::WeakDylib => "weakly linked",
                            DepKind::LazyDylib => "lazily loaded",
                            _ => "loaded",
                        },
                        m.name
                    ),
                });
            }
            let missing: Vec<String> = m
                .unresolved
                .iter()
                .filter(|x| x.status == ImportStatus::Missing && !x.weak)
                .map(Import::label)
                .collect();
            if !missing.is_empty() {
                // (A library's may come from the program that loads it.)
                let severity = if i == 0 && !elf::is_executable(self, 0) {
                    Severity::Warning
                } else {
                    Severity::Error
                };
                problems.push(Problem {
                    severity,
                    module: i,
                    message: format!(
                        "{} uses {} that nothing loaded defines: {}",
                        m.name,
                        plural(missing.len(), "symbol"),
                        list(&missing)
                    ),
                });
            }
        }
        problems.sort_by_key(|p| (p.severity, p.module));
        self.graph.problems = problems;
        if modules.iter().any(|m| m.status == Status::Unsearched)
            && !self
                .graph
                .notes
                .iter()
                .any(|n| n.starts_with("only the first"))
        {
            self.graph.notes.push(format!(
                "system libraries weren't searched: no system root for {} on this host (give -sysroot)",
                self.format.name()
            ));
        }
    }
}

fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// A list's first items, and how many more.
fn list(items: &[String]) -> String {
    const SHOWN: usize = 8;
    let mut s = items[..items.len().min(SHOWN)].join(", ");
    if items.len() > SHOWN {
        s.push_str(&format!(", and {} more", items.len() - SHOWN));
    }
    s
}

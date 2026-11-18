//! Symbols for an open trace: where they are looked for and downloaded to,
//! which PDBs its stacks need (most wanted first), and `stackrabbit
//! symbols`, which downloads them.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

use hexcavator_symbolize::SymbolPath;
use hexcavator_symbolize::server::{Fetched, MICROSOFT, PdbId, SymbolServers};
use hexcavator_trace::{ImageIx, ProcessIx, StackId, ThreadIx, Trace};
use hexcavator_trace_analysis::Resolver;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::Args;
use crate::store;

/// How many downloads run at once: enough to keep a fast connection busy
/// (each is mostly waiting on the server).
pub const CONCURRENCY: usize = 16;

/// Where symbols are looked for, and where and from where they are
/// downloaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbols {
    /// The symbol path's local directories (from `_NT_SYMBOL_PATH`).
    pub path: SymbolPath,
    /// The servers and the cache they download into.
    pub servers: SymbolServers,
    /// Whether to download.
    pub download: bool,
}

impl Symbols {
    /// The settings for `cache` and `servers` if given, else
    /// `_NT_SYMBOL_PATH`'s, else WinDbg's default cache and Microsoft's
    /// server.
    pub fn new(cache: Option<PathBuf>, servers: Vec<String>, download: bool) -> Self {
        let env = std::env::var("_NT_SYMBOL_PATH").unwrap_or_default();
        let from_env = SymbolServers::from_nt_symbol_path(&env);
        let cache = cache
            .or_else(|| from_env.as_ref().map(|s| s.cache.clone()))
            .unwrap_or_else(default_cache);
        let urls = if servers.is_empty() {
            from_env.map_or_else(|| vec![MICROSOFT.to_string()], |s| s.urls)
        } else {
            servers
        };
        let mut path = SymbolPath::parse(&env);
        if !path.dirs.contains(&cache) {
            path.dirs.push(cache.clone());
        }
        Self {
            path,
            servers: SymbolServers { cache, urls },
            download,
        }
    }
}

/// WinDbg's default symbol cache (so the two share one), or on other
/// systems the user's cache directory.
fn default_cache() -> PathBuf {
    if cfg!(windows) {
        let data = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
        return data.join("Dbg").join("sym");
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("stackrabbit").join("symbols")
}

/// The PDBs `trace`'s stacks need, most wanted first: the images their
/// frames are in, by how many of the stacks' distinct frames each has
/// (images without a PDB identity are left out).
pub fn wanted(trace: &Trace) -> Vec<PdbId> {
    let resolver = Resolver::new(trace);
    let mut hits: FxHashMap<ImageIx, u64> = FxHashMap::default();
    // Each (process, node) once: stacks share their callers.
    let mut seen: FxHashSet<(ProcessIx, StackId)> = FxHashSet::default();
    let mut walk = |thread: ThreadIx, stack: StackId, ip: Option<u64>| {
        let process = trace.thread_process(thread);
        if stack.is_empty() {
            if let Some(ip) = ip
                && let Some(image) = resolver.image(process, ip)
            {
                *hits.entry(image).or_default() += 1;
            }
            return;
        }
        let mut node = stack;
        while !node.is_empty() && seen.insert((process, node)) {
            if let Some(image) = resolver.image(process, trace.stacks.frame(node)) {
                *hits.entry(image).or_default() += 1;
            }
            node = trace.stacks.parent(node);
        }
    };
    let s = &trace.samples;
    for i in 0..s.len() {
        walk(s.thread[i], s.stack[i], Some(s.ip[i]));
    }
    let w = &trace.switches;
    for i in 0..w.len() {
        walk(w.new_thread[i], w.stack[i], None);
    }
    let r = &trace.readies;
    for i in 0..r.len() {
        walk(r.readier[i], r.stack[i], None);
    }
    // By PDB: the same DLL is loaded in many processes.
    let mut by_pdb: FxHashMap<PdbId, u64> = FxHashMap::default();
    for (image, n) in hits {
        let Some(id) = &trace.images[image.index()].debug_id else {
            continue;
        };
        let key = PdbId {
            name: id.pdb_path.clone(),
            guid: id.guid,
            age: id.age,
        };
        *by_pdb.entry(key).or_default() += n;
    }
    let mut out: Vec<(PdbId, u64)> = by_pdb.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));
    out.into_iter().map(|(id, _)| id).collect()
}

/// What downloading a trace's symbols did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Downloaded {
    /// PDBs wanted.
    pub wanted: usize,
    /// Already in the cache.
    pub cached: usize,
    /// Downloaded.
    pub downloaded: usize,
    /// On no server.
    pub missing: usize,
}

/// Downloads `ids` (see [`SymbolServers::fetch_all`]); `progress` hears of
/// each as it finishes, with the counts so far.
pub fn download(
    servers: &SymbolServers,
    ids: &[PdbId],
    progress: impl Fn(&Downloaded) + Sync,
) -> Downloaded {
    let counts = Mutex::new(Downloaded {
        wanted: ids.len(),
        ..Downloaded::default()
    });
    servers.fetch_all(ids, CONCURRENCY, |_, _, fetched| {
        let mut c = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match fetched {
            Fetched::Cached(_) => c.cached += 1,
            Fetched::Downloaded(_) => c.downloaded += 1,
            Fetched::Missing | Fetched::BadName => c.missing += 1,
        }
        progress(&c);
    });
    counts
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

const USAGE: &str = "\
usage: stackrabbit symbols <trace> [options]

Downloads the PDBs a trace's stacks need, most wanted first, many at once, into a symbol cache
laid out as WinDbg's is (so the two can share it). Prints counts and times only.

Options:
  -cache <dir>        The cache (default: _NT_SYMBOL_PATH's, else WinDbg's default cache).
  -server <url>       A symbol server (default: _NT_SYMBOL_PATH's, else Microsoft's); repeat
                      for more, asked in order.
  -list               Only count the PDBs wanted and those already in the cache.";

/// Runs `stackrabbit symbols`.
pub fn run(args: &[String]) -> ExitCode {
    let mut a = Args::new(args);
    let mut trace = None;
    let mut cache = None;
    let mut servers = Vec::new();
    let mut list = false;
    while let Some(arg) = a.next() {
        let r: Result<(), String> = (|| {
            match arg {
                "-h" | "-help" | "--help" => return Err(String::new()),
                "-cache" => cache = Some(PathBuf::from(a.value(arg)?)),
                "-server" => servers.push(a.value(arg)?.trim_end_matches('/').to_string()),
                "-list" => list = true,
                o if o.starts_with('-') => return Err(format!("unknown option '{o}'")),
                p if trace.is_none() => trace = Some(PathBuf::from(p)),
                extra => return Err(format!("unexpected '{extra}'")),
            }
            Ok(())
        })();
        if let Err(e) = r {
            if e.is_empty() {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            eprintln!("stackrabbit symbols: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    }
    let Some(trace) = trace else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match symbols(&trace, Symbols::new(cache, servers, !list)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stackrabbit symbols: {e}");
            ExitCode::FAILURE
        }
    }
}

fn symbols(path: &Path, symbols: Symbols) -> Result<(), String> {
    let loaded = store::open(path, &store::Options::default())?;
    let start = Instant::now();
    let ids = wanted(&loaded.trace);
    println!(
        "{} PDBs wanted ({:.3} s to find); cache {}",
        ids.len(),
        start.elapsed().as_secs_f64(),
        symbols.servers.cache.display()
    );
    if !symbols.download {
        let cached = ids
            .iter()
            .filter(|id| symbols.servers.cached_path(id).is_some_and(|p| p.exists()))
            .count();
        println!("{cached} in the cache");
        return Ok(());
    }
    let start = Instant::now();
    let d = download(&symbols.servers, &ids, |_| {});
    let secs = start.elapsed().as_secs_f64();
    let bytes: u64 = ids
        .iter()
        .filter_map(|id| symbols.servers.cached_path(id))
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    #[allow(clippy::cast_precision_loss)]
    let mb = bytes as f64 / 1e6;
    println!(
        "{} cached, {} downloaded, {} missing, in {secs:.2} s ({mb:.1} MB in the cache for these)",
        d.cached, d.downloaded, d.missing
    );
    Ok(())
}

//! Symbols for an open trace: where they are looked for and downloaded to,
//! which PDBs its stacks need (most wanted first), and `stackrabbit
//! symbols`, which downloads them.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hexcavator_symbolize::server::{Fetched, MICROSOFT, PdbId, SymbolServers};
use hexcavator_symbolize::{FunctionTable, SymbolPath};
use hexcavator_trace::{ImageIx, ProcessIx, StackId, Trace, index};
use hexcavator_trace_analysis::{PdbSymbolizer, Resolver};
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
/// frames are in, by how many distinct addresses the stacks have in each
/// (images without a PDB identity are left out).
pub fn wanted(trace: &Trace) -> Vec<PdbId> {
    frames(trace).wanted
}

/// A PDB's identity: GUID and age.
pub type DebugKey = ([u8; 16], u32);

/// A PDB's function table, with its identity.
pub type Table = (DebugKey, Arc<FunctionTable>);

/// What a trace's stacks need of its PDBs.
#[derive(Clone, Debug, Default)]
pub struct Frames {
    /// The PDBs, most wanted first (see [`wanted`]).
    pub wanted: Vec<PdbId>,
    /// Each PDB's addresses (RVAs) that frames are at, sorted: each
    /// frame's address and the byte before it (where a return address is
    /// looked up).
    pub addresses: FxHashMap<DebugKey, Vec<u32>>,
}

/// Events a worker walks the stacks of at a time.
const FRAMES_CHUNK: usize = 1 << 16;

/// What `trace`'s stacks need of its PDBs: which, and at what addresses.
/// The events are walked on every core, in chunks; each chunk's stacks
/// once each.
pub fn frames(trace: &Trace) -> Frames {
    let resolver = Resolver::new(trace);
    let (s, w, r) = (&trace.samples, &trace.switches, &trace.readies);
    // (Which events: samples, switches, readies; from, to.)
    let mut chunks = Vec::new();
    for (kind, len) in [(0u8, s.len()), (1, w.len()), (2, r.len())] {
        for from in (0..len).step_by(FRAMES_CHUNK) {
            chunks.push((kind, from, (from + FRAMES_CHUNK).min(len)));
        }
    }
    let found = on_every_core(&chunks, |&(kind, from, to)| {
        // Each image's frames' offsets.
        let mut hits: FxHashMap<ImageIx, Vec<u64>> = FxHashMap::default();
        // Each (process, node) once: stacks share their callers.
        let mut seen: FxHashSet<(ProcessIx, StackId)> = FxHashSet::default();
        let mut hit = |process: ProcessIx, address: u64| {
            if let Some(image) = resolver.image(process, address) {
                hits.entry(image)
                    .or_default()
                    .push(address - trace.images[image.index()].base);
            }
        };
        for i in from..to {
            let (thread, stack, ip) = match kind {
                0 => (s.thread[i], s.stack[i], Some(s.ip[i])),
                1 => (w.new_thread[i], w.stack[i], None),
                _ => (r.readier[i], r.stack[i], None),
            };
            let process = trace.thread_process(thread);
            if stack.is_empty() {
                if let Some(ip) = ip {
                    hit(process, ip);
                }
                continue;
            }
            let mut node = stack;
            while !node.is_empty() && seen.insert((process, node)) {
                hit(process, trace.stacks.frame(node));
                node = trace.stacks.parent(node);
            }
        }
        // By PDB: the same DLL is loaded in many processes.
        let mut by_pdb: FxHashMap<DebugKey, (PdbId, Vec<u32>)> = FxHashMap::default();
        for (image, offsets) in hits {
            let Some(id) = &trace.images[image.index()].debug_id else {
                continue;
            };
            let entry = by_pdb.entry((id.guid, id.age)).or_insert_with(|| {
                (
                    PdbId {
                        name: id.pdb_path.clone(),
                        guid: id.guid,
                        age: id.age,
                    },
                    Vec::new(),
                )
            });
            for o in offsets {
                if let Ok(rva) = u32::try_from(o) {
                    entry.1.push(rva);
                }
            }
        }
        by_pdb
    });
    // The chunks' addresses together, then each PDB's sorted (on every
    // core: some have many).
    let mut by_pdb: FxHashMap<DebugKey, (PdbId, Vec<u32>)> = FxHashMap::default();
    for chunk in found {
        for (k, (id, rvas)) in chunk {
            let e = by_pdb.entry(k).or_insert_with(|| (id, Vec::new()));
            // (The first name a PDB was recorded with, by the chunks' order.)
            e.1.extend(rvas);
        }
    }
    let pdbs: Vec<(DebugKey, (PdbId, Vec<u32>))> = by_pdb.into_iter().collect();
    let sorted = on_every_core(&pdbs, |(_, (_, rvas))| {
        let mut a: Vec<u32> = rvas
            .iter()
            .flat_map(|&r| [r, r.saturating_sub(1)])
            .collect();
        a.sort_unstable();
        a.dedup();
        // (How many distinct frame addresses: what the PDB is wanted by.)
        let mut distinct = rvas.clone();
        distinct.sort_unstable();
        distinct.dedup();
        (a, distinct.len())
    });
    let mut wanted: Vec<(PdbId, usize)> = Vec::with_capacity(pdbs.len());
    let mut addresses = FxHashMap::default();
    for ((k, (id, _)), (a, n)) in pdbs.into_iter().zip(sorted) {
        wanted.push((id, n));
        addresses.insert(k, a);
    }
    wanted.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.name.cmp(&b.0.name))
            .then_with(|| a.0.guid.cmp(&b.0.guid))
    });
    Frames {
        wanted: wanted.into_iter().map(|(id, _)| id).collect(),
        addresses,
    }
}

/// Loads `ids`' PDBs (those found), on every core.
pub fn preload(symbolizer: &PdbSymbolizer, ids: &[PdbId]) {
    on_every_core(ids, |id| {
        symbolizer.load(&id.name, &id.guid, id.age);
    });
}

/// The saved symbols file's magic and version.
const SAVED_MAGIC: &[u8; 8] = b"HXSYMS\0\0";
const SAVED_VERSION: u32 = 1;

/// Where a trace's saved symbols go: beside its index
/// (`trace.etl.hxtrace` → `trace.etl.hxsyms`).
pub fn saved_path(index: &Path) -> PathBuf {
    index.with_extension("hxsyms")
}

/// Saves `tables` for the trace `source`, each cut down to the addresses
/// in `frames` (on every core), to `path` (written aside and renamed, so a
/// reader never sees half of it). PDBs no frame is in aren't saved.
pub fn save(
    path: &Path,
    source: index::Source,
    frames: &Frames,
    tables: &[Table],
) -> std::io::Result<()> {
    let tables: Vec<_> = tables
        .iter()
        .filter_map(|(k, t)| Some((k, t, frames.addresses.get(k)?)))
        .collect();
    let cut = on_every_core(&tables, |(_, table, rvas)| table.subset(rvas).to_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(SAVED_MAGIC);
    out.extend_from_slice(&SAVED_VERSION.to_le_bytes());
    out.extend_from_slice(&source.size.to_le_bytes());
    out.extend_from_slice(&source.hash.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(tables.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for ((k, _, _), bytes) in tables.iter().zip(cut) {
        out.extend_from_slice(&k.0);
        out.extend_from_slice(&k.1.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    std::fs::write(&partial, &out)
        .and_then(|()| std::fs::rename(&partial, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&partial);
        })
}

/// The symbols saved for the trace `source` at `path`, read on every
/// core; none if there are none, or they are for another trace, or they
/// are damaged.
pub fn load_saved(path: &Path, source: index::Source) -> Vec<Table> {
    let Ok(data) = std::fs::read(path) else {
        return Vec::new();
    };
    parse_saved(&data, source).unwrap_or_default()
}

fn parse_saved(data: &[u8], source: index::Source) -> Option<Vec<Table>> {
    let mut r = hexcavator_core::Reader::new(data);
    if r.bytes(8).ok()? != SAVED_MAGIC
        || r.u32_le().ok()? != SAVED_VERSION
        || r.u64_le().ok()? != source.size
        || r.u64_le().ok()? != source.hash
    {
        return None;
    }
    let n = r.u32_le().ok()? as usize;
    let mut parts = Vec::with_capacity(n.min(r.remaining().len() / 28));
    for _ in 0..n {
        let guid: [u8; 16] = r.bytes(16).ok()?.try_into().ok()?;
        let age = r.u32_le().ok()?;
        let len = usize::try_from(r.u64_le().ok()?).ok()?;
        parts.push(((guid, age), r.bytes(len).ok()?));
    }
    if !r.is_empty() {
        return None;
    }
    let tables = on_every_core(&parts, |(_, bytes)| FunctionTable::from_bytes(bytes).ok());
    // One damaged table, and none are trusted.
    parts
        .iter()
        .zip(tables)
        .map(|((k, _), t)| Some((*k, Arc::new(t?))))
        .collect()
}

/// `f` of each of `items`, in order, computed on every core.
fn on_every_core<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    std::thread::scope(|scope| {
        for _ in 0..threads.min(items.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { return };
                    let r = f(item);
                    *out[i]
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
                }
            });
        }
    });
    out.into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .expect("every item is done")
        })
        .collect()
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
  -list               Only count the PDBs wanted and those already in the cache.

Then the names of the functions the trace's stacks are in are saved beside its index (as a
.hxsyms), so that it reopens with them, without its PDBs.";

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
    let frames = frames(&loaded.trace);
    let ids = &frames.wanted;
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
    let d = download(&symbols.servers, ids, |_| {});
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
    // The names, saved for next time.
    let Some(index) = loaded.index() else {
        return Ok(());
    };
    let start = Instant::now();
    let symbolizer = PdbSymbolizer::new(symbols.path.clone());
    preload(&symbolizer, ids);
    let tables: Vec<Table> = symbolizer
        .found()
        .into_iter()
        .map(|(guid, age, t)| ((guid, age), t))
        .collect();
    let loaded_secs = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let path = saved_path(index);
    save(&path, loaded.source, &frames, &tables).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = std::fs::metadata(&path).map_or(0, |m| m.len());
    #[allow(clippy::cast_precision_loss)]
    let kb = size as f64 / 1e3;
    println!(
        "{} PDBs loaded in {loaded_secs:.2} s; their names for this trace saved in {:.2} s ({kb:.1} KB)",
        tables.len(),
        start.elapsed().as_secs_f64(),
    );
    Ok(())
}

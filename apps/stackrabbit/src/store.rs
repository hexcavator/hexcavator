//! Opening a trace: from its index (a `.hxtrace` beside it, or in the
//! cache directory) when there is a current one, or else by importing it
//! and saving the index for next time.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hexcavator_etl::Etl;
use hexcavator_mmap::Mmap;
use hexcavator_trace::etw::{self, ImportStats};
use hexcavator_trace::{Trace, index};

/// Reading a trace ahead of its import: one thread, 16 MB at a time.
/// (Measured on a 4 GB/s NVMe drive: this reads at its full speed; more
/// threads or smaller reads gain nothing. See `stackrabbit bench -read`.)
pub const PREFETCH_THREADS: usize = 1;
/// The size of each read ahead.
pub const PREFETCH_CHUNK: usize = 16 << 20;

/// How to open a trace.
#[derive(Clone, Debug)]
pub struct Options {
    /// Whether to use a saved index, and save one after an import.
    pub use_index: bool,
    /// Where indexes go when they can't go beside their traces; `None`
    /// for the user's cache directory.
    pub cache_dir: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            use_index: true,
            cache_dir: None,
        }
    }
}

/// How a trace was opened.
#[derive(Clone, Debug)]
pub enum Opened {
    /// From its index.
    Indexed {
        /// The index's path.
        index: PathBuf,
        /// How long reading the index took.
        read: Duration,
    },
    /// By importing the trace.
    Imported {
        /// What the import counted.
        stats: ImportStats,
        /// How long the import took.
        import: Duration,
        /// Where the index was saved, and how long writing it took (or why
        /// it wasn't).
        index: Result<(PathBuf, Duration), String>,
    },
}

/// An open trace.
pub struct Loaded {
    /// The trace's path.
    pub path: PathBuf,
    /// The trace file's size.
    pub size: u64,
    /// The trace.
    pub trace: Trace,
    /// How it was opened.
    pub opened: Opened,
    /// The trace file's identity (what its index and saved symbols are
    /// checked against).
    pub source: index::Source,
    /// What the recording session lost, as its file's header says.
    pub lost: Lost,
}

/// What a recording session lost: events it had no buffer for, and
/// buffers it couldn't write. (Either means the trace is missing some of
/// what happened: stacks without their events, events without stacks.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lost {
    /// Events lost.
    pub events: u32,
    /// Buffers lost.
    pub buffers: u32,
}

impl Lost {
    /// What the session that wrote `data` (an ETL file) lost; nothing, if
    /// its header can't be read.
    pub fn of(data: &[u8]) -> Self {
        Etl::parse(data).map_or_else(
            |_| Self::default(),
            |etl| Self {
                events: etl.header().events_lost,
                buffers: etl.header().buffers_lost,
            },
        )
    }
}

impl Loaded {
    /// The trace's index: the one it was opened from, or the one saved
    /// after its import (none if indexes are off or it couldn't be saved).
    pub fn index(&self) -> Option<&Path> {
        match &self.opened {
            Opened::Indexed { index, .. } => Some(index),
            Opened::Imported { index, .. } => index.as_ref().ok().map(|(p, _)| p.as_path()),
        }
    }
}

/// Opens the trace at `path`.
pub fn open(path: &Path, options: &Options) -> Result<Loaded, String> {
    let map = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let data = map.as_slice();
    let size = data.len() as u64;
    let source = index::Source::of(data);
    let lost = Lost::of(data);
    if options.use_index {
        for candidate in index_paths(path, options) {
            let Ok(saved) = Mmap::open(&candidate) else {
                continue;
            };
            let start = Instant::now();
            // A stale or damaged index is skipped (and later replaced).
            if let Ok(trace) = index::read(saved.as_slice(), Some(source)) {
                return Ok(Loaded {
                    path: path.to_path_buf(),
                    size,
                    trace,
                    opened: Opened::Indexed {
                        index: candidate,
                        read: start.elapsed(),
                    },
                    source,
                    lost,
                });
            }
        }
    }
    let start = Instant::now();
    // The file is read ahead of the parser at the disk's speed (one
    // thread's large reads saturate a fast drive), so the parser finds its
    // pages in memory.
    let _prefetch = map.prefetch(PREFETCH_THREADS, PREFETCH_CHUNK);
    let etl = Etl::parse(data).map_err(|e| format!("{}: {e}", path.display()))?;
    let (trace, stats) = etw::import(&etl).map_err(|e| format!("{}: {e}", path.display()))?;
    let import = start.elapsed();
    let index = if options.use_index {
        save_index(path, options, &trace, source)
    } else {
        Err("indexes are off".to_string())
    };
    Ok(Loaded {
        path: path.to_path_buf(),
        size,
        trace,
        opened: Opened::Imported {
            stats,
            import,
            index,
        },
        source,
        lost,
    })
}

/// Where a trace's index may be: beside it, then in the cache directory.
pub fn index_paths(trace: &Path, options: &Options) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut beside = trace.as_os_str().to_owned();
    beside.push(".hxtrace");
    out.push(PathBuf::from(beside));
    if let Some(dir) = cache_dir(options) {
        out.push(dir.join(cache_name(trace)));
    }
    out
}

/// Saves `trace`'s index: beside the trace if that can be written, or else
/// in the cache directory.
fn save_index(
    path: &Path,
    options: &Options,
    trace: &Trace,
    source: index::Source,
) -> Result<(PathBuf, Duration), String> {
    let start = Instant::now();
    let bytes = index::write(trace, source);
    let mut why = String::new();
    for candidate in index_paths(path, options) {
        if let Some(dir) = candidate.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Written aside and renamed, so a reader never sees half of one.
        let mut partial = candidate.as_os_str().to_owned();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        match std::fs::write(&partial, &bytes).and_then(|()| std::fs::rename(&partial, &candidate))
        {
            Ok(()) => return Ok((candidate, start.elapsed())),
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                why = format!("{}: {e}", candidate.display());
            }
        }
    }
    Err(why)
}

/// The directory for indexes that can't go beside their traces.
fn cache_dir(options: &Options) -> Option<PathBuf> {
    if let Some(d) = &options.cache_dir {
        return Some(d.clone());
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("Stackrabbit").join("index"))
}

/// A trace's index file name in the cache directory: its file name and a
/// hash of its full path, so traces of the same name don't collide.
fn cache_name(trace: &Path) -> String {
    let full = std::path::absolute(trace).unwrap_or_else(|_| trace.to_path_buf());
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in full.as_os_str().as_encoded_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    let name = trace
        .file_name()
        .map_or_else(|| "trace".into(), |n| n.to_string_lossy().into_owned());
    format!("{name}-{h:016x}.hxtrace")
}

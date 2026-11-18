//! Reading some of a trace's events again, from its file, on every core:
//! the buffers holding the kinds wanted (all of them, without the index's
//! buffer list), a chunk at a time per worker; and what the tables built
//! from them share (property integers, threads by ID at a time).

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hexcavator_etl::event::Event;
use hexcavator_etl::{Buffer, Etl, Guid, merge::for_each_event};
use hexcavator_etw::schema::Property;
use hexcavator_mmap::Mmap;
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
pub use hexcavator_trace_analysis::wpa_query::{Cell, Query};
use rustc_hash::FxHashMap;

/// Buffers a worker reads at a time.
const CHUNK: usize = 32;

/// What the trace file says of its clock.
#[derive(Clone, Copy, Debug)]
pub struct FileInfo {
    /// The performance counter's frequency (ticks a second).
    pub perf_freq: u64,
}

/// The events of `trace` (read from `path`) whose provider and opcode are
/// `wanted`, each given to `read` with its buffer's processor; what it
/// pushes, from every worker, in no particular order.
pub fn events<T: Send>(
    trace: &Trace,
    path: &Path,
    wanted: impl Fn(&Guid, u8) -> bool + Sync,
    read: impl Fn(u16, &Event<'_>, &mut Vec<T>) + Sync,
) -> Result<(Vec<T>, FileInfo), String> {
    let map = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let etl = Etl::parse(map.as_slice()).map_err(|e| format!("{}: {e}", path.display()))?;
    let max = usize::try_from(etl.header().buffer_size)
        .unwrap_or(1 << 20)
        .max(1 << 16);
    let info = FileInfo {
        perf_freq: u64::try_from(etl.header().perf_freq).unwrap_or(0).max(1),
    };
    let kinds: Vec<u32> = trace
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| wanted(&e.provider, e.opcode))
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect();
    let buffers: Vec<Buffer<'_>> = if trace.buffers.is_empty() {
        etl.buffers().flatten().collect()
    } else {
        trace
            .buffers
            .iter()
            .filter(|b| b.kinds.iter().any(|k| kinds.contains(k)))
            .filter_map(|b| etl.buffer_at(b.offset, b.index).ok())
            .collect()
    };
    let next = AtomicUsize::new(0);
    let all: Mutex<Vec<T>> = Mutex::default();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(buffers.len().div_ceil(CHUNK).max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut mine = Vec::new();
                loop {
                    let c = next.fetch_add(1, Ordering::Relaxed);
                    let from = c.saturating_mul(CHUNK);
                    if from >= buffers.len() {
                        break;
                    }
                    for buffer in &buffers[from..(from + CHUNK).min(buffers.len())] {
                        let processor = buffer.header.processor;
                        let _ = for_each_event(buffer, max, &mut scratch, |e| {
                            if wanted(&e.provider, e.descriptor.opcode) {
                                read(processor, e, &mut mine);
                            }
                        });
                    }
                }
                all.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .append(&mut mine);
            });
        }
    });
    let all = all
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok((all, info))
}

/// A property's value as an unsigned integer (its first eight bytes,
/// little-endian; zero if there is none).
pub fn int(p: Option<&Property<'_>>) -> u64 {
    p.map_or(0, |p| {
        let mut a = [0u8; 8];
        let n = p.data.len().min(8);
        a[..n].copy_from_slice(&p.data[..n]);
        u64::from_le_bytes(a)
    })
}

/// A trace's threads by ID.
pub struct Threads<'a> {
    trace: &'a Trace,
    by_tid: FxHashMap<u32, Vec<usize>>,
}

impl<'a> Threads<'a> {
    /// `trace`'s threads by ID.
    pub fn new(trace: &'a Trace) -> Self {
        let mut by_tid: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
        for (i, t) in trace.threads.iter().enumerate() {
            by_tid.entry(t.tid).or_default().push(i);
        }
        Self { trace, by_tid }
    }

    /// The thread `tid` at `time`: the one alive then, else the last with
    /// that ID (none, if no thread had it).
    pub fn at(&self, tid: u32, time: i64) -> ThreadIx {
        let Some(list) = self.by_tid.get(&tid) else {
            return ThreadIx::NONE;
        };
        let alive = list.iter().copied().find(|&i| {
            let t = &self.trace.threads[i];
            t.start.is_none_or(|s| s <= time) && t.end.is_none_or(|e| e >= time)
        });
        let i = alive.or_else(|| list.last().copied()).unwrap_or(usize::MAX);
        ThreadIx(u32::try_from(i).unwrap_or(u32::MAX))
    }
}

/// The process `pid` at `time`: the one alive then, else the last with
/// that ID (none, if no process had it).
pub fn process_at(trace: &Trace, pid: u32, time: i64) -> ProcessIx {
    let mut last = ProcessIx::NONE;
    for (i, p) in trace.processes.iter().enumerate() {
        if p.pid != pid {
            continue;
        }
        let ix = ProcessIx(u32::try_from(i).unwrap_or(u32::MAX));
        if p.start.is_none_or(|s| s <= time) && p.end.is_none_or(|e| e >= time) {
            return ix;
        }
        last = ix;
    }
    last
}

/// Names of things over time, by key (file objects, key control blocks):
/// what events named each, and when.
#[derive(Debug, Default)]
pub struct Names {
    by_key: FxHashMap<u64, Vec<(i64, String)>>,
}

impl Names {
    /// `key` is named `name` from `time`.
    pub fn add(&mut self, key: u64, time: i64, name: String) {
        self.by_key.entry(key).or_default().push((time, name));
    }

    /// Done adding: puts each key's names in time order.
    pub fn finish(&mut self) {
        for v in self.by_key.values_mut() {
            v.sort();
        }
    }

    /// `key`'s name at `time`: its latest by then, else its first after
    /// (a thing named only by a rundown at the end of the trace).
    pub fn at(&self, key: u64, time: i64) -> Option<&str> {
        let v = self.by_key.get(&key)?;
        let i = v.partition_point(|(t, _)| *t <= time);
        Some(if i > 0 { &v[i - 1].1 } else { &v.first()?.1 })
    }

    /// How many keys have names.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether no key has a name.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Strings kept once each, by index.
#[derive(Debug, Default)]
pub struct Interner {
    /// The strings, by index.
    pub strings: Vec<String>,
    ids: FxHashMap<String, u32>,
}

impl Interner {
    /// `s`'s index (added, if new).
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.ids.get(s) {
            return i;
        }
        let i = u32::try_from(self.strings.len()).unwrap_or(u32::MAX);
        self.strings.push(s.to_string());
        self.ids.insert(s.to_string(), i);
        i
    }
}

/// What a summary is asked: of which rows, and how much of it to answer.
#[derive(Clone, Debug, Default)]
pub struct Ask {
    /// The items (the longest, largest or heaviest) to list.
    pub items: usize,
    /// The groups to list (the most first).
    pub groups: usize,
    /// The rows it's of: those that hold this (WPA's query language, on
    /// the table's columns), or all.
    pub filter: Option<Query>,
}

impl Ask {
    /// Whether `row` is one the summary is of: `cell` gives its value of a
    /// column (by WPA's name for it).
    pub fn keeps<T>(&self, row: &T, cell: impl Fn(&T, &str) -> Option<Cell>) -> bool {
        self.filter
            .as_ref()
            .is_none_or(|q| q.holds(&|c: &str| cell(row, c)))
    }
}

/// A request's `filter` (WPA's query language) on a table with `columns`:
/// none, or the query, whose every column is one of them.
pub fn filter(params: &serde_json::Value, columns: &[&str]) -> Result<Option<Query>, String> {
    let Some(text) = params
        .get("filter")
        .and_then(serde_json::Value::as_str)
        .filter(|t| !t.trim().is_empty())
    else {
        return Ok(None);
    };
    let q = Query::parse(text).map_err(|e| format!("filter: {e}"))?;
    for c in q.columns() {
        if !columns.iter().any(|k| k.eq_ignore_ascii_case(c)) {
            return Err(format!(
                "filter: [{c}] isn't a column here (these are: {})",
                columns.join(", ")
            ));
        }
    }
    Ok(Some(q))
}

/// A text cell.
pub fn text(s: &str) -> Option<Cell> {
    Some(Cell::Text(s.to_string()))
}

/// A number cell.
#[allow(clippy::cast_precision_loss)]
pub fn number(n: u64) -> Option<Cell> {
    Some(Cell::Number(n as f64))
}

/// The process columns every table has (by WPA's names).
pub const PROCESS_COLUMNS: [&str; 3] = ["Process Name", "Process", "Process ID"];
/// The thread columns.
pub const THREAD_COLUMNS: [&str; 2] = ["Thread ID", "Thread Name"];

/// A process's cell of `column` (one of `PROCESS_COLUMNS`), if it is one
/// (an unknown process has none).
pub fn process_cell(trace: &Trace, p: ProcessIx, column: &str) -> Option<Option<Cell>> {
    let pr = p.is_some().then(|| &trace.processes[p.index()]);
    Some(match column.to_ascii_lowercase().as_str() {
        "process name" => pr.and_then(|p| text(&p.name)),
        "process" => pr.and_then(|p| text(&format!("{} ({})", p.name, p.pid))),
        "process id" => pr.and_then(|p| number(u64::from(p.pid))),
        _ => return None,
    })
}

/// A thread's cell of `column` (one of `THREAD_COLUMNS`), if it is one.
pub fn thread_cell(trace: &Trace, t: ThreadIx, column: &str) -> Option<Option<Cell>> {
    let th = t.is_some().then(|| &trace.threads[t.index()]);
    Some(match column.to_ascii_lowercase().as_str() {
        "thread id" => th.and_then(|t| number(u64::from(t.tid))),
        "thread name" => th.and_then(|t| t.name.as_deref()).and_then(text),
        _ => return None,
    })
}

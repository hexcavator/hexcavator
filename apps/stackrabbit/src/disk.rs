//! Disk usage: the trace's disk I/Os (DiskIo read, write and flush
//! completions), each with its issuing thread and process, its file (by
//! the FileIo name and create events), its I/O time and its disk service
//! time, read
//! from the trace file and kept; then totals grouped as asked, and the
//! heaviest I/Os.
//!
//! - I/O time: the partition manager's response time, from the I/O's
//!   initiation to its completion (`HighResResponseTime`, in the
//!   performance counter's ticks).
//! - Disk service time: the time the disk spent on the I/O alone: from
//!   the later of its initiation and the disk's previous completion, to
//!   its completion (as WPA computes it).

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hexcavator_etl::{Buffer, Etl, merge::for_each_event};
use hexcavator_etw::guids;
use hexcavator_etw::schema::{Properties, Property};
use hexcavator_mmap::Mmap;
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

/// What an I/O did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IoKind {
    /// A read.
    Read,
    /// A write.
    Write,
    /// A flush.
    Flush,
}

impl IoKind {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Flush => "Flush",
        }
    }
}

/// One disk I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskIo {
    /// What it did.
    pub kind: IoKind,
    /// The disk.
    pub disk: u32,
    /// Its offset on the disk.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u32,
    /// When it completed (clock ticks).
    pub complete: i64,
    /// Its I/O time, in nanoseconds.
    pub io_ns: u64,
    /// Its disk service time, in nanoseconds.
    pub service_ns: u64,
    /// The thread that issued it.
    pub thread: ThreadIx,
    /// That thread's process.
    pub process: ProcessIx,
    /// Its file's path, if known.
    pub file: Option<u32>,
}

/// A trace's disk I/Os, in completion order, and their files' paths.
#[derive(Clone, Debug, Default)]
pub struct DiskTable {
    /// The I/Os.
    pub ios: Vec<DiskIo>,
    /// The paths I/Os name (by index).
    pub files: Vec<String>,
}

/// Buffers a worker reads at a time.
const CHUNK: usize = 32;

/// One event read: a disk I/O's fields, or a file object's name.
enum Read {
    Io {
        kind: IoKind,
        complete: i64,
        disk: u32,
        offset: u64,
        size: u32,
        response: u64,
        file_object: u64,
        thread_id: u32,
    },
    Name {
        time: i64,
        file_object: u64,
        name: String,
    },
}

fn int(p: Option<&Property<'_>>) -> u64 {
    p.map_or(0, |p| {
        let mut a = [0u8; 8];
        let n = p.data.len().min(8);
        a[..n].copy_from_slice(&p.data[..n]);
        u64::from_le_bytes(a)
    })
}

/// The disk I/Os of `trace` (read from `path`): its DiskIo and FileIo name
/// events, from the buffers holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<DiskTable, String> {
    let map = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let etl = Etl::parse(map.as_slice()).map_err(|e| format!("{}: {e}", path.display()))?;
    let max = usize::try_from(etl.header().buffer_size)
        .unwrap_or(1 << 20)
        .max(1 << 16);
    // (Response times are in the performance counter's ticks.)
    let perf_freq = u64::try_from(etl.header().perf_freq).unwrap_or(0).max(1);
    let wanted = |provider: &hexcavator_etl::Guid, opcode: u8| {
        (*provider == guids::DISK_IO && matches!(opcode, 10 | 11 | 14))
            || (*provider == guids::FILE_IO && matches!(opcode, 0 | 32 | 35 | 36 | 64))
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
    let all: Mutex<Vec<Read>> = Mutex::default();
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
                        let _ = for_each_event(buffer, max, &mut scratch, |e| {
                            let op = e.descriptor.opcode;
                            if !wanted(&e.provider, op) {
                                return;
                            }
                            let Some(Ok(p)) = Properties::of(e) else {
                                return;
                            };
                            if e.provider == guids::FILE_IO {
                                // (Names, rundowns and creates: the path
                                // opened.)
                                let name = p
                                    .get("FileName")
                                    .or_else(|| p.get("OpenPath"))
                                    .map_or_else(String::new, |n| {
                                        hexcavator_etw::values::format(
                                            n,
                                            hexcavator_etw::schema::pointer_size(e),
                                        )
                                    });
                                mine.push(Read::Name {
                                    time: e.timestamp,
                                    file_object: int(p.get("FileObject")),
                                    name,
                                });
                                return;
                            }
                            let kind = match op {
                                10 => IoKind::Read,
                                11 => IoKind::Write,
                                _ => IoKind::Flush,
                            };
                            mine.push(Read::Io {
                                kind,
                                complete: e.timestamp,
                                disk: u32::try_from(int(p.get("DiskNumber"))).unwrap_or(u32::MAX),
                                offset: int(p.get("ByteOffset")),
                                size: u32::try_from(int(p.get("TransferSize"))).unwrap_or(u32::MAX),
                                response: int(p.get("HighResResponseTime")),
                                file_object: int(p.get("FileObject")),
                                thread_id: u32::try_from(int(p.get("IssuingThreadId")))
                                    .unwrap_or(u32::MAX),
                            });
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
    Ok(assemble(trace, all, perf_freq))
}

/// The I/Os, in completion order, with their files, threads and times.
fn assemble(trace: &Trace, all: Vec<Read>, perf_freq: u64) -> DiskTable {
    // Each file object's names over time.
    let mut names: FxHashMap<u64, Vec<(i64, String)>> = FxHashMap::default();
    let mut ios = Vec::new();
    for r in all {
        match r {
            Read::Name {
                time,
                file_object,
                name,
            } => {
                if !name.is_empty() {
                    names.entry(file_object).or_default().push((time, name));
                }
            }
            io @ Read::Io { .. } => ios.push(io),
        }
    }
    for v in names.values_mut() {
        v.sort();
    }
    let mut files: Vec<String> = Vec::new();
    let mut file_ids: FxHashMap<String, u32> = FxHashMap::default();
    // Threads by ID at a time: the one alive then, else the last.
    let mut by_tid: FxHashMap<u32, Vec<usize>> = FxHashMap::default();
    for (i, t) in trace.threads.iter().enumerate() {
        by_tid.entry(t.tid).or_default().push(i);
    }
    let thread_at = |tid: u32, time: i64| -> ThreadIx {
        let Some(list) = by_tid.get(&tid) else {
            return ThreadIx::NONE;
        };
        let alive = list.iter().copied().find(|&i| {
            let t = &trace.threads[i];
            t.start.is_none_or(|s| s <= time) && t.end.is_none_or(|e| e >= time)
        });
        let i = alive.or_else(|| list.last().copied()).unwrap_or(usize::MAX);
        ThreadIx(u32::try_from(i).unwrap_or(u32::MAX))
    };
    let mut out: Vec<DiskIo> = ios
        .into_iter()
        .filter_map(|r| {
            let Read::Io {
                kind,
                complete,
                disk,
                offset,
                size,
                response,
                file_object,
                thread_id,
            } = r
            else {
                return None;
            };
            let io_ns = u64::try_from(u128::from(response) * 1_000_000_000 / u128::from(perf_freq))
                .unwrap_or(u64::MAX);
            // The file: its object's latest name by then, else its first
            // after (rundowns come at the end).
            let file = names.get(&file_object).and_then(|v| {
                let i = v.partition_point(|(t, _)| *t <= complete);
                let (_, name) = if i > 0 { &v[i - 1] } else { v.first()? };
                let next = u32::try_from(files.len()).unwrap_or(u32::MAX);
                Some(*file_ids.entry(name.clone()).or_insert_with(|| {
                    files.push(name.clone());
                    next
                }))
            });
            let thread = thread_at(thread_id, complete);
            Some(DiskIo {
                kind,
                disk,
                offset,
                size,
                complete,
                io_ns,
                service_ns: 0,
                thread,
                process: trace.thread_process(thread),
                file,
            })
        })
        .collect();
    out.sort_by_key(|io| (io.complete, io.disk, io.offset));
    // Service time: from the later of the I/O's initiation and the disk's
    // previous completion.
    let tick_ns = |ticks: i64| trace.clock.nanos(trace.clock.origin + ticks);
    let mut last_done: FxHashMap<u32, i64> = FxHashMap::default();
    for io in &mut out {
        let done_ns = tick_ns(io.complete - trace.clock.origin);
        let init_ns = done_ns.saturating_sub(i64::try_from(io.io_ns).unwrap_or(i64::MAX));
        let from = last_done
            .get(&io.disk)
            .map_or(init_ns, |&prev| init_ns.max(prev));
        io.service_ns = u64::try_from(done_ns - from.min(done_ns)).unwrap_or(0);
        last_done.insert(io.disk, done_ns);
    }
    DiskTable { ios: out, files }
}

/// What disk I/Os are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// File.
    File,
    /// Disk.
    Disk,
    /// Read, write or flush.
    Kind,
}

/// `table`'s I/Os completed in `time` (clock ticks; all, if none):
/// totals by `group` (count, bytes, I/O time, service time; heaviest
/// service time first), and the `limit` I/Os with the most service time.
pub fn summary(
    trace: &Trace,
    table: &DiskTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limit: usize,
) -> Value {
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.ios.partition_point(|io| io.complete < start);
    let to = table.ios.partition_point(|io| io.complete < end);
    let ios = &table.ios[from..to];
    let process_label = |p: ProcessIx| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            format!("{} ({})", pr.name, pr.pid)
        } else {
            "Unknown process".to_string()
        }
    };
    let file_label = |f: Option<u32>| {
        f.map_or_else(
            || "Unknown file".to_string(),
            |f| table.files[f as usize].clone(),
        )
    };
    let key = |io: &DiskIo| -> String {
        match group {
            GroupBy::Process => process_label(io.process),
            GroupBy::File => file_label(io.file),
            GroupBy::Disk => format!("Disk {}", io.disk),
            GroupBy::Kind => io.kind.name().to_string(),
        }
    };
    let mut groups: FxHashMap<String, (u64, u64, u64, u64)> = FxHashMap::default();
    for io in ios {
        let g = groups.entry(key(io)).or_default();
        g.0 += 1;
        g.1 += u64::from(io.size);
        g.2 += io.io_ns;
        g.3 += io.service_ns;
    }
    let mut groups: Vec<(String, (u64, u64, u64, u64))> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1.3.cmp(&a.1.3).then_with(|| a.0.cmp(&b.0)));
    let mut heaviest: Vec<&DiskIo> = ios.iter().collect();
    heaviest.sort_by(|a, b| {
        b.service_ns
            .cmp(&a.service_ns)
            .then(a.complete.cmp(&b.complete))
    });
    heaviest.truncate(limit);
    json!({
        "count": ios.len(),
        "bytes": ios.iter().map(|io| u64::from(io.size)).sum::<u64>(),
        "groups": groups.iter().map(|(label, (n, bytes, io_ns, service_ns))| json!({
            "label": label,
            "count": n,
            "bytes": bytes,
            "ioNs": io_ns,
            "serviceNs": service_ns,
        })).collect::<Vec<_>>(),
        "ios": heaviest.iter().map(|io| json!({
            "kind": io.kind.name(),
            "disk": io.disk,
            "offset": io.offset,
            "size": io.size,
            "completeNs": trace.clock.nanos(io.complete),
            "ioNs": io.io_ns,
            "serviceNs": io.service_ns,
            "process": process_label(io.process),
            "tid": io.thread.is_some().then(|| trace.threads[io.thread.index()].tid),
            "file": io.file.map(|f| table.files[f as usize].clone()),
        })).collect::<Vec<_>>(),
    })
}

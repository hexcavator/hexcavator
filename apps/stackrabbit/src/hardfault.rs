//! Hard faults: the page faults the trace's threads waited on the disk
//! for (PageFault HardFault events), each with its thread and process, its
//! file (by the FileIo name and create events of its file object), where
//! in the file and the address space, how much it read, and how long it
//! took; read from the trace file and kept; then totals grouped as asked,
//! and the longest.
//!
//! Each event is logged when its read completes: its timestamp is its
//! end, and its `InitialTime` its start (in the same clock).

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::{Properties, pointer_size};
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use crate::reading::int;

/// `HardFault`.
const HARD_FAULT: u8 = 32;
/// The FileIo events that name a file object: Name, FileCreate,
/// FileDelete, FileRundown; and Create (its open path).
const NAMES: [u8; 5] = [0, 32, 35, 36, 64];

/// One hard fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    /// When it started (clock ticks).
    pub start: i64,
    /// When its read completed (clock ticks).
    pub end: i64,
    /// Where in its file it read.
    pub offset: u64,
    /// The address it faulted at.
    pub address: u64,
    /// How many bytes it read.
    pub size: u32,
    /// Its thread.
    pub thread: ThreadIx,
    /// That thread's process.
    pub process: ProcessIx,
    /// Its file's path (an index of the table's files), if known.
    pub file: Option<u32>,
}

/// A trace's hard faults, in start order, and their files' paths.
#[derive(Clone, Debug, Default)]
pub struct FaultTable {
    /// The faults.
    pub faults: Vec<Fault>,
    /// The paths faults name (by index).
    pub files: Vec<String>,
}

/// One event read.
enum Read {
    Fault {
        start: i64,
        end: i64,
        offset: u64,
        address: u64,
        file_object: u64,
        thread_id: u32,
        size: u32,
    },
    Name {
        time: i64,
        file_object: u64,
        name: String,
    },
}

/// The hard faults of `trace` (read from `path`): its HardFault and FileIo
/// name events, from the buffers holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<FaultTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        (*provider == guids::PAGE_FAULT && op == HARD_FAULT)
            || (*provider == guids::FILE_IO && NAMES.contains(&op))
    };
    let (all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        if e.provider == guids::FILE_IO {
            let name = p
                .get("FileName")
                .or_else(|| p.get("OpenPath"))
                .map_or_else(String::new, |n| {
                    hexcavator_etw::values::format(n, pointer_size(e))
                });
            if !name.is_empty() {
                mine.push(Read::Name {
                    time: e.timestamp,
                    file_object: int(p.get("FileObject")),
                    name,
                });
            }
            return;
        }
        let start = i64::try_from(int(p.get("InitialTime"))).unwrap_or(e.timestamp);
        mine.push(Read::Fault {
            start: start.min(e.timestamp),
            end: e.timestamp,
            offset: int(p.get("ReadOffset")),
            address: int(p.get("VirtualAddress")),
            file_object: int(p.get("FileObject")),
            thread_id: u32::try_from(int(p.get("TThreadId"))).unwrap_or(u32::MAX),
            size: u32::try_from(int(p.get("ByteCount"))).unwrap_or(u32::MAX),
        });
    })?;
    Ok(assemble(trace, all))
}

/// The faults, in start order, with their files, threads and processes.
fn assemble(trace: &Trace, all: Vec<Read>) -> FaultTable {
    let mut names = crate::reading::Names::default();
    let mut faults = Vec::new();
    for r in all {
        match r {
            Read::Name {
                time,
                file_object,
                name,
            } => names.add(file_object, time, name),
            f @ Read::Fault { .. } => faults.push(f),
        }
    }
    names.finish();
    let threads = crate::reading::Threads::new(trace);
    let mut files = crate::reading::Interner::default();
    let mut out: Vec<Fault> = faults
        .into_iter()
        .filter_map(|r| {
            let Read::Fault {
                start,
                end,
                offset,
                address,
                file_object,
                thread_id,
                size,
            } = r
            else {
                return None;
            };
            let thread = threads.at(thread_id, start);
            Some(Fault {
                start,
                end,
                offset,
                address,
                size,
                thread,
                process: trace.thread_process(thread),
                file: names.at(file_object, end).map(|n| files.intern(n)),
            })
        })
        .collect();
    out.sort_by_key(|f| (f.start, f.end, f.offset));
    FaultTable {
        faults: out,
        files: files.strings,
    }
}

/// What hard faults are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// File.
    File,
    /// Thread.
    Thread,
}

/// `table`'s faults started in `time` (clock ticks; all, if none): totals
/// by `group` (count, bytes, total duration; the most time first; the
/// first `group_limit` of them), and the `limit` longest.
pub fn summary(
    trace: &Trace,
    table: &FaultTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limits: crate::reading::Limits,
) -> Value {
    let (limit, group_limit) = (limits.items, limits.groups);
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.faults.partition_point(|f| f.start < start);
    let to = table.faults.partition_point(|f| f.start < end);
    let faults = &table.faults[from..to];
    let ns = |f: &Fault| {
        u64::try_from(trace.clock.nanos(f.end) - trace.clock.nanos(f.start)).unwrap_or(0)
    };
    let process_label = |p: ProcessIx| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            format!("{} ({})", pr.name, pr.pid)
        } else {
            "Unknown process".to_string()
        }
    };
    let file = |f: Option<u32>| f.map(|f| table.files[f as usize].as_str());
    // Totals by what the group is, then by its label.
    let mut by_id: FxHashMap<u32, (u64, u64, u64)> = FxHashMap::default();
    for f in faults {
        let id = match group {
            GroupBy::Process => f.process.0,
            GroupBy::File => f.file.unwrap_or(u32::MAX),
            GroupBy::Thread => f.thread.0,
        };
        let g = by_id.entry(id).or_default();
        g.0 += 1;
        g.1 += u64::from(f.size);
        g.2 += ns(f);
    }
    let mut groups: FxHashMap<String, (u64, u64, u64)> = FxHashMap::default();
    for (id, (n, bytes, d)) in by_id {
        let label = match group {
            GroupBy::Process => process_label(ProcessIx(id)),
            GroupBy::File => file((id != u32::MAX).then_some(id))
                .unwrap_or("Unknown file")
                .to_string(),
            GroupBy::Thread => {
                let t = ThreadIx(id);
                if t.is_some() {
                    let th = &trace.threads[t.index()];
                    format!("{} in {}", th.tid, process_label(th.process))
                } else {
                    "Unknown thread".to_string()
                }
            }
        };
        let g = groups.entry(label).or_default();
        g.0 += n;
        g.1 += bytes;
        g.2 += d;
    }
    let mut groups: Vec<(String, (u64, u64, u64))> = groups.into_iter().collect();
    groups.sort_by(|a, b| {
        b.1.2
            .cmp(&a.1.2)
            .then(b.1.0.cmp(&a.1.0))
            .then_with(|| a.0.cmp(&b.0))
    });
    let groups_total = groups.len();
    groups.truncate(group_limit);
    let mut longest: Vec<(u64, &Fault)> = faults.iter().map(|f| (ns(f), f)).collect();
    let order =
        |a: &(u64, &Fault), b: &(u64, &Fault)| b.0.cmp(&a.0).then(a.1.start.cmp(&b.1.start));
    if longest.len() > limit && limit > 0 {
        longest.select_nth_unstable_by(limit - 1, order);
    }
    longest.truncate(limit);
    longest.sort_by(order);
    json!({
        "count": faults.len(),
        "bytes": faults.iter().map(|f| u64::from(f.size)).sum::<u64>(),
        "durationNs": faults.iter().map(ns).sum::<u64>(),
        "groupsTotal": groups_total,
        "groups": groups.iter().map(|(label, (n, bytes, d))| json!({
            "label": label, "count": n, "bytes": bytes, "durationNs": d,
        })).collect::<Vec<_>>(),
        "faults": longest.iter().map(|(d, f)| json!({
            "startNs": trace.clock.nanos(f.start),
            "durationNs": d,
            "size": f.size,
            "offset": f.offset,
            "address": format!("{:#x}", f.address),
            "process": process_label(f.process),
            "tid": f.thread.is_some().then(|| trace.threads[f.thread.index()].tid),
            "file": file(f.file),
        })).collect::<Vec<_>>(),
    })
}

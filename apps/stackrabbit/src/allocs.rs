//! Heap and pool: allocation lifetimes, each a block allocated at a time
//! and freed at another (or still allocated when the trace ends), read
//! from the trace file and kept; then what was allocated and freed in a
//! time by group, what of what was allocated in it is still allocated at
//! its end (WPA's "allocated inside, freed outside": what the time cost
//! in memory), and the largest blocks.
//!
//! - Heap (Heap events, of the processes heap tracing was on for): an
//!   alloc starts a block (a process's, by address); a free ends it; a
//!   realloc ends the old block and starts the new; a heap's destruction
//!   ends all of its blocks. By process, heap or thread.
//! - Pool (Pool events, the kernel's): an alloc starts a block (by
//!   address), a free ends it. By tag, type (paged or not, and session) or
//!   process.

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::Properties;
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use crate::reading::int;

/// One block's lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// When it was allocated (clock ticks).
    pub start: i64,
    /// When it was freed (clock ticks), if it was in the trace.
    pub end: Option<i64>,
    /// Its size in bytes.
    pub size: u64,
    /// Its address.
    pub address: u64,
    /// The thread that allocated it.
    pub thread: ThreadIx,
    /// Its process (the heap's, or the one the pool allocation was in).
    pub process: ProcessIx,
    /// Its group: its heap or its pool tag (an index of the table's
    /// labels).
    pub group: u32,
    /// Its kind (pool: an index of `POOL_KINDS`; heap: 0).
    pub kind: u8,
}

/// A trace's blocks, in allocation order, and their groups' labels.
#[derive(Clone, Debug, Default)]
pub struct BlockTable {
    /// The blocks.
    pub blocks: Vec<Block>,
    /// The groups' labels (heaps or pool tags), by index.
    pub labels: Vec<String>,
}

/// The pool's kinds: paged or not, in a session or not.
pub const POOL_KINDS: [&str; 4] = ["Nonpaged", "Paged", "Nonpaged (session)", "Paged (session)"];

/// A `POOL_TYPE`'s kind (an index of `POOL_KINDS`): paged types are odd;
/// session types have bit 5.
fn pool_kind(pool_type: u32) -> u8 {
    u8::from(pool_type & 1 != 0) | (u8::from(pool_type & 0x20 != 0) << 1)
}

/// A pool tag's text: its four characters (unprintable ones as `?`; the
/// "protected" high bit ignored).
fn tag_text(tag: u32) -> String {
    (tag & 0x7fff_ffff)
        .to_le_bytes()
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// One event read: what it does to which block.
#[derive(Clone, Debug)]
enum Read {
    /// Starts a block.
    Alloc {
        time: i64,
        pid: u32,
        tid: u32,
        address: u64,
        size: u64,
        group: u64,
        kind: u8,
    },
    /// Ends a block.
    Free { time: i64, pid: u32, address: u64 },
    /// Ends a heap's blocks.
    Destroy { time: i64, pid: u32, heap: u64 },
}

impl Read {
    fn time(&self) -> i64 {
        match self {
            Self::Alloc { time, .. } | Self::Free { time, .. } | Self::Destroy { time, .. } => {
                *time
            }
        }
    }
}

/// Heap: `Alloc`, `ReAlloc`, `Destroy`, `Free`.
const HEAP_OPS: [u8; 4] = [33, 34, 35, 36];
/// Pool: `Alloc`, `Free`.
const POOL_OPS: [u8; 2] = [32, 34];

/// The heap blocks of `trace` (read from `path`), from the buffers holding
/// its Heap events, on every core.
pub fn heap(trace: &Trace, path: &Path) -> Result<BlockTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::HEAP && HEAP_OPS.contains(&op)
    };
    let (all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        let (time, pid, tid) = (e.timestamp, e.process_id, e.thread_id);
        let heap = int(p.get("HeapHandle"));
        match e.descriptor.opcode {
            33 => mine.push(Read::Alloc {
                time,
                pid,
                tid,
                address: int(p.get("AllocAddress")),
                size: int(p.get("AllocSize")),
                group: heap,
                kind: 0,
            }),
            34 => {
                mine.push(Read::Free {
                    time,
                    pid,
                    address: int(p.get("OldAllocAddress")),
                });
                mine.push(Read::Alloc {
                    time,
                    pid,
                    tid,
                    address: int(p.get("NewAllocAddress")),
                    size: int(p.get("NewAllocSize")),
                    group: heap,
                    kind: 0,
                });
            }
            35 => mine.push(Read::Destroy { time, pid, heap }),
            _ => mine.push(Read::Free {
                time,
                pid,
                address: int(p.get("FreeAddress")),
            }),
        }
    })?;
    Ok(assemble(trace, all, true))
}

/// The pool blocks of `trace` (read from `path`), from the buffers holding
/// its Pool events, on every core.
pub fn pool(trace: &Trace, path: &Path) -> Result<BlockTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::POOL && POOL_OPS.contains(&op)
    };
    let (all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        let address = int(p.get("Entry"));
        if e.descriptor.opcode == 32 {
            let pool_type = u32::try_from(int(p.get("Type"))).unwrap_or(0);
            mine.push(Read::Alloc {
                time: e.timestamp,
                pid: e.process_id,
                tid: e.thread_id,
                address,
                size: int(p.get("NumberOfBytes")),
                group: int(p.get("Tag")),
                kind: pool_kind(pool_type),
            });
        } else {
            // (The pool is the kernel's: one address space.)
            mine.push(Read::Free {
                time: e.timestamp,
                pid: 0,
                address,
            });
        }
    })?;
    Ok(assemble(trace, all, false))
}

/// The blocks `all` start and end, in allocation order. `heap`: blocks
/// are each process's (else the kernel's, and groups are pool tags).
fn assemble(trace: &Trace, mut all: Vec<Read>, heap: bool) -> BlockTable {
    // (In time order; at the same time, a realloc's free before its alloc,
    // as read.)
    all.sort_by_key(Read::time);
    let threads = crate::reading::Threads::new(trace);
    let mut labels = crate::reading::Interner::default();
    let mut processes: FxHashMap<u32, ProcessIx> = FxHashMap::default();
    let mut process_at = |pid: u32, time: i64| {
        *processes
            .entry(pid)
            .or_insert_with(|| crate::reading::process_at(trace, pid, time))
    };
    let mut blocks: Vec<Block> = Vec::new();
    // The blocks allocated now, by process (heap; else 0) and address; and
    // each heap's, by process and heap handle.
    let mut live: FxHashMap<(u32, u64), usize> = FxHashMap::default();
    let mut heaps: FxHashMap<(u32, u64), Vec<usize>> = FxHashMap::default();
    for r in all {
        match r {
            Read::Alloc {
                time,
                pid,
                tid,
                address,
                size,
                group,
                kind,
            } => {
                let owner = if heap { pid } else { 0 };
                // (A block at an address still allocated ends there.)
                if let Some(i) = live.remove(&(owner, address)) {
                    blocks[i].end = Some(time);
                }
                let thread = threads.at(tid, time);
                let process = if thread.is_some() {
                    trace.thread_process(thread)
                } else {
                    process_at(pid, time)
                };
                let label = if heap {
                    let p = if process.is_some() {
                        let pr = &trace.processes[process.index()];
                        format!("{} ({})", pr.name, pr.pid)
                    } else if pid == u32::MAX {
                        "Unknown process".to_string()
                    } else {
                        format!("process {pid}")
                    };
                    format!("{group:#x} in {p}")
                } else {
                    tag_text(u32::try_from(group).unwrap_or(0))
                };
                let i = blocks.len();
                live.insert((owner, address), i);
                if heap {
                    heaps.entry((pid, group)).or_default().push(i);
                }
                blocks.push(Block {
                    start: time,
                    end: None,
                    size,
                    address,
                    thread,
                    process,
                    group: labels.intern(&label),
                    kind,
                });
            }
            Read::Free { time, pid, address } => {
                if let Some(i) = live.remove(&(pid, address)) {
                    blocks[i].end = Some(time);
                }
            }
            Read::Destroy { time, pid, heap } => {
                for i in heaps.remove(&(pid, heap)).unwrap_or_default() {
                    if blocks[i].end.is_none() {
                        blocks[i].end = Some(time);
                        live.remove(&(pid, blocks[i].address));
                    }
                }
            }
        }
    }
    BlockTable {
        blocks,
        labels: labels.strings,
    }
}

/// What blocks are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// The thread that allocated them.
    Thread,
    /// Their heap, or pool tag.
    Group,
    /// Their kind (pool: paged or not, session or not).
    Kind,
}

/// `table`'s blocks in `time` (clock ticks; all of the trace, if none): by
/// `group`, what was allocated and freed in it, and what of what was
/// allocated in it is still allocated at its end (`outstanding`: the most
/// first; the first `group_limit`); and the `limit` largest blocks
/// allocated in it. `kinds` names the blocks' kinds.
pub fn summary(
    trace: &Trace,
    table: &BlockTable,
    kinds: &[&str],
    group: GroupBy,
    time: Option<(i64, i64)>,
    limits: crate::reading::Limits,
) -> Value {
    let (limit, group_limit) = (limits.items, limits.groups);
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let within = |t: i64| t >= start && t < end;
    let process_label = |p: ProcessIx| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            format!("{} ({})", pr.name, pr.pid)
        } else {
            "Unknown process".to_string()
        }
    };
    // Per group: allocations (count, bytes), frees (count, bytes), and
    // still allocated at the end (count, bytes).
    let mut by_id: FxHashMap<u32, [u64; 6]> = FxHashMap::default();
    let mut totals = [0u64; 6];
    let mut largest: Vec<&Block> = Vec::new();
    // (Blocks are in allocation order: those allocated after the time
    // can't count, but those allocated before it may be freed in it.)
    let last = table.blocks.partition_point(|b| b.start < end);
    for b in &table.blocks[..last] {
        let allocated = within(b.start);
        let freed = b.end.is_some_and(within);
        if !(allocated || freed) {
            continue;
        }
        let id = match group {
            GroupBy::Process => b.process.0,
            GroupBy::Thread => b.thread.0,
            GroupBy::Group => b.group,
            GroupBy::Kind => u32::from(b.kind),
        };
        let g = by_id.entry(id).or_default();
        let mut add = |i: usize, v: u64| {
            g[i] += v;
            totals[i] += v;
        };
        if allocated {
            add(0, 1);
            add(1, b.size);
            if b.end.is_none_or(|e| e >= end) {
                add(4, 1);
                add(5, b.size);
            }
            largest.push(b);
        }
        if freed {
            add(2, 1);
            add(3, b.size);
        }
    }
    let mut groups: FxHashMap<String, [u64; 6]> = FxHashMap::default();
    for (id, v) in by_id {
        let label = match group {
            GroupBy::Process => process_label(ProcessIx(id)),
            GroupBy::Thread => {
                let t = ThreadIx(id);
                if t.is_some() {
                    let th = &trace.threads[t.index()];
                    format!("{} in {}", th.tid, process_label(th.process))
                } else {
                    "Unknown thread".to_string()
                }
            }
            GroupBy::Group => table.labels[id as usize].clone(),
            GroupBy::Kind => kinds.get(id as usize).copied().unwrap_or("?").to_string(),
        };
        let g = groups.entry(label).or_default();
        for (a, b) in g.iter_mut().zip(v) {
            *a += b;
        }
    }
    let mut groups: Vec<(String, [u64; 6])> = groups.into_iter().collect();
    groups.sort_by(|a, b| {
        b.1[5]
            .cmp(&a.1[5])
            .then(b.1[1].cmp(&a.1[1]))
            .then_with(|| a.0.cmp(&b.0))
    });
    let groups_total = groups.len();
    groups.truncate(group_limit);
    let order = |a: &&Block, b: &&Block| b.size.cmp(&a.size).then(a.start.cmp(&b.start));
    if largest.len() > limit && limit > 0 {
        largest.select_nth_unstable_by(limit - 1, order);
    }
    largest.truncate(limit);
    largest.sort_by(order);
    let counts = |v: &[u64; 6]| {
        json!({
            "allocs": v[0], "allocated": v[1],
            "frees": v[2], "freed": v[3],
            "outstandingCount": v[4], "outstanding": v[5],
        })
    };
    let mut answer = counts(&totals);
    answer["groupsTotal"] = json!(groups_total);
    answer["groups"] = groups
        .iter()
        .map(|(label, v)| {
            let mut g = counts(v);
            g["label"] = json!(label);
            g
        })
        .collect();
    answer["blocks"] = largest
        .iter()
        .map(|b| {
            json!({
                "process": process_label(b.process),
                "tid": b.thread.is_some().then(|| trace.threads[b.thread.index()].tid),
                "group": table.labels[b.group as usize],
                "kind": kinds.get(usize::from(b.kind)).copied().unwrap_or("?"),
                "address": format!("{:#x}", b.address),
                "size": b.size,
                "allocNs": trace.clock.nanos(b.start),
                "freeNs": b.end.map(|e| trace.clock.nanos(e)),
            })
        })
        .collect();
    answer
}

//! Virtual memory: the commit lifetimes of the trace's processes'
//! address spaces (PageFault VirtualAlloc and VirtualFree), each a range
//! committed at a time and decommitted (or released) at another, or
//! still committed when the trace ends; read from the trace file and
//! kept; then what each process (or thread) committed and decommitted in
//! a time, what of it is still committed at that time's end, and the
//! largest lifetimes.
//!
//! An allocation's `MEM_COMMIT` commits the pages of its range that
//! aren't already; a free's `MEM_DECOMMIT` or `MEM_RELEASE` decommits the
//! committed pages of its range (all of its reservation, for a release of
//! no size), ending their lifetimes and splitting those it ends only part
//! of. The process is the one the event names (`VirtualAllocEx` can name
//! another); the thread, its header's.

use std::collections::BTreeMap;
use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::Properties;
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use crate::reading::int;

/// `VirtualAlloc`.
const ALLOC: u8 = 98;
/// `VirtualFree`.
const FREE: u8 = 99;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;

/// A range's commit lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifetime {
    /// Its process.
    pub process: ProcessIx,
    /// The thread that committed it.
    pub thread: ThreadIx,
    /// Its base address.
    pub base: u64,
    /// Its size in bytes.
    pub size: u64,
    /// When it was committed (clock ticks).
    pub commit: i64,
    /// When it was decommitted (clock ticks), if it was in the trace.
    pub decommit: Option<i64>,
    /// The thread that decommitted it.
    pub decommitter: ThreadIx,
}

/// A trace's commit lifetimes, in commit order.
#[derive(Clone, Debug, Default)]
pub struct VmemTable {
    /// The lifetimes.
    pub lifetimes: Vec<Lifetime>,
}

/// One event read.
#[derive(Clone, Copy, Debug)]
struct Read {
    free: bool,
    time: i64,
    base: u64,
    size: u64,
    process_id: u32,
    flags: u32,
    thread_id: u32,
}

/// The commit lifetimes of `trace` (read from `path`): its VirtualAlloc
/// and VirtualFree events, from the buffers holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<VmemTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::PAGE_FAULT && (op == ALLOC || op == FREE)
    };
    let (mut all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        mine.push(Read {
            free: e.descriptor.opcode == FREE,
            time: e.timestamp,
            base: int(p.get("BaseAddress")),
            size: int(p.get("RegionSize")),
            process_id: u32::try_from(int(p.get("ProcessId"))).unwrap_or(u32::MAX),
            flags: u32::try_from(int(p.get("Flags"))).unwrap_or(0),
            thread_id: e.thread_id,
        });
    })?;
    all.sort_by_key(|r| (r.time, r.free));
    Ok(lifetimes(trace, &all))
}

/// A process's committed pieces, by base: their end, when and by whom
/// they were committed.
type Pieces = BTreeMap<u64, (u64, i64, ThreadIx)>;

/// The lifetimes `events` (in time order) make.
fn lifetimes(trace: &Trace, events: &[Read]) -> VmemTable {
    let threads = crate::reading::Threads::new(trace);
    let mut committed: FxHashMap<u32, Pieces> = FxHashMap::default();
    // Each process's reservations, by base: their size.
    let mut reserved: FxHashMap<u32, BTreeMap<u64, u64>> = FxHashMap::default();
    let mut out: Vec<Lifetime> = Vec::new();
    let mut process_of: FxHashMap<u32, ProcessIx> = FxHashMap::default();
    for r in events {
        let thread = threads.at(r.thread_id, r.time);
        let process = *process_of
            .entry(r.process_id)
            .or_insert_with(|| crate::reading::process_at(trace, r.process_id, r.time));
        let pieces = committed.entry(r.process_id).or_default();
        if r.free {
            if r.flags & (MEM_DECOMMIT | MEM_RELEASE) == 0 {
                continue;
            }
            let reservations = reserved.entry(r.process_id).or_default();
            let size = if r.size == 0 && r.flags & MEM_RELEASE != 0 {
                reservations.get(&r.base).copied().unwrap_or(0)
            } else {
                r.size
            };
            if r.flags & MEM_RELEASE != 0 {
                reservations.remove(&r.base);
            }
            let (from, to) = (r.base, r.base.saturating_add(size));
            for (base, end, commit, by) in take(pieces, from, to) {
                // The part freed ends; what's left of it stays.
                let (lo, hi) = (base.max(from), end.min(to));
                out.push(Lifetime {
                    process,
                    thread: by,
                    base: lo,
                    size: hi - lo,
                    commit,
                    decommit: Some(r.time),
                    decommitter: thread,
                });
                if base < lo {
                    pieces.insert(base, (lo, commit, by));
                }
                if hi < end {
                    pieces.insert(hi, (end, commit, by));
                }
            }
        } else {
            if r.flags & MEM_RESERVE != 0 {
                reserved
                    .entry(r.process_id)
                    .or_default()
                    .insert(r.base, r.size);
            }
            if r.flags & MEM_COMMIT == 0 || r.size == 0 {
                continue;
            }
            // Only what isn't committed already.
            let (from, to) = (r.base, r.base.saturating_add(r.size));
            let mut at = from;
            let existing = take(pieces, from, to);
            let mut gaps = Vec::new();
            for &(base, end, _, _) in &existing {
                if base > at {
                    gaps.push((at, base));
                }
                at = at.max(end);
            }
            if at < to {
                gaps.push((at, to));
            }
            for (base, end, commit, by) in existing {
                pieces.insert(base, (end, commit, by));
            }
            for (base, end) in gaps {
                pieces.insert(base, (end, r.time, thread));
            }
        }
    }
    // Still committed at the end.
    for (pid, pieces) in committed {
        let process = process_of.get(&pid).copied().unwrap_or(ProcessIx::NONE);
        for (base, (end, commit, by)) in pieces {
            out.push(Lifetime {
                process,
                thread: by,
                base,
                size: end - base,
                commit,
                decommit: None,
                decommitter: ThreadIx::NONE,
            });
        }
    }
    out.sort_by_key(|l| (l.commit, l.base));
    VmemTable { lifetimes: out }
}

/// Removes and returns the pieces overlapping `[from, to)`: each `(base,
/// end, commit, by)`.
fn take(pieces: &mut Pieces, from: u64, to: u64) -> Vec<(u64, u64, i64, ThreadIx)> {
    let mut found = Vec::new();
    // (One may start before `from` and reach into it.)
    if let Some((&base, &(end, _, _))) = pieces.range(..from).next_back()
        && end > from
    {
        found.push(base);
    }
    found.extend(pieces.range(from..to).map(|(&b, _)| b));
    found
        .into_iter()
        .filter_map(|b| pieces.remove(&b).map(|(e, c, t)| (b, e, c, t)))
        .collect()
}

/// What lifetimes are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// The thread that committed them.
    Thread,
}

/// `table`'s lifetimes in `time` (clock ticks; all of the trace, if
/// none): by `group`, what was committed and decommitted in it, and what
/// of what was committed in it is still committed at its end (the most
/// of that first; the first `group_limit`); and the `limit` largest
/// lifetimes committed in it.
pub fn summary(
    trace: &Trace,
    table: &VmemTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limit: usize,
    group_limit: usize,
) -> Value {
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
    // Per group: commits (count, bytes), decommits (count, bytes), and
    // still committed at the end (bytes).
    let mut by_id: FxHashMap<u32, [u64; 5]> = FxHashMap::default();
    let mut totals = [0u64; 5];
    let mut largest: Vec<&Lifetime> = Vec::new();
    for l in &table.lifetimes {
        let committed = within(l.commit);
        let decommitted = l.decommit.is_some_and(within);
        if !(committed || decommitted) {
            continue;
        }
        let id = match group {
            GroupBy::Process => l.process.0,
            GroupBy::Thread => l.thread.0,
        };
        let g = by_id.entry(id).or_default();
        let mut add = |i: usize, v: u64| {
            g[i] += v;
            totals[i] += v;
        };
        if committed {
            add(0, 1);
            add(1, l.size);
            if l.decommit.is_none_or(|d| d >= end) {
                add(4, l.size);
            }
            largest.push(l);
        }
        if decommitted {
            add(2, 1);
            add(3, l.size);
        }
    }
    let mut groups: FxHashMap<String, [u64; 5]> = FxHashMap::default();
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
        };
        let g = groups.entry(label).or_default();
        for (a, b) in g.iter_mut().zip(v) {
            *a += b;
        }
    }
    let mut groups: Vec<(String, [u64; 5])> = groups.into_iter().collect();
    groups.sort_by(|a, b| {
        b.1[4]
            .cmp(&a.1[4])
            .then(b.1[1].cmp(&a.1[1]))
            .then_with(|| a.0.cmp(&b.0))
    });
    let groups_total = groups.len();
    groups.truncate(group_limit);
    let order = |a: &&Lifetime, b: &&Lifetime| b.size.cmp(&a.size).then(a.commit.cmp(&b.commit));
    if largest.len() > limit && limit > 0 {
        largest.select_nth_unstable_by(limit - 1, order);
    }
    largest.truncate(limit);
    largest.sort_by(order);
    let tid = |t: ThreadIx| t.is_some().then(|| trace.threads[t.index()].tid);
    json!({
        "commits": totals[0],
        "committed": totals[1],
        "decommits": totals[2],
        "decommitted": totals[3],
        "outstanding": totals[4],
        "groupsTotal": groups_total,
        "groups": groups.iter().map(|(label, v)| json!({
            "label": label,
            "commits": v[0],
            "committed": v[1],
            "decommits": v[2],
            "decommitted": v[3],
            "outstanding": v[4],
        })).collect::<Vec<_>>(),
        "lifetimes": largest.iter().map(|l| json!({
            "process": process_label(l.process),
            "tid": tid(l.thread),
            "base": format!("{:#x}", l.base),
            "size": l.size,
            "commitNs": trace.clock.nanos(l.commit),
            "decommitNs": l.decommit.map(|d| trace.clock.nanos(d)),
            "decommitTid": tid(l.decommitter),
        })).collect::<Vec<_>>(),
    })
}

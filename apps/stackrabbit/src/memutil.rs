//! Memory utilization: each process's memory over the trace, from the
//! kernel's periodic snapshots of it (PageFault `ProcessMemInfo`: per
//! process, its working set, commit, virtual size and private working
//! set, and its store and shared commit, in pages); read from the trace
//! file and kept; then, by process or by image name, what each had at the
//! end of a time, its peaks in it, and its commit's change across it; and
//! the snapshots' totals over it.
//!
//! The layout (as TraceEvent reads it, version 2 and later): a `u32`
//! count, then that many `{ProcessId: u32, WorkingSetPageCount,
//! CommitPageCount, VirtualSizeInPages, PrivateWorkingSetPageCount,
//! StoreSizePageCount, StoredPageCount, CommitDebtInPages,
//! SharedCommitInPages}`, the counts pointer-sized. Every such event in
//! the corpus is exactly that long. An event holds at most 256 processes:
//! a snapshot of more is that many, then the rest in the next event (in
//! the corpus, every snapshot is two: 256 processes, then 140-odd, 35 to
//! 45 us later). (The system-wide `MemInfo`, opcode 112, has no layout to
//! check, and isn't read.)

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::pointer_size;
use hexcavator_trace::{ProcessIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

/// `ProcessMemInfo`.
const PROCESS_MEM_INFO: u8 = 125;
/// A page, in bytes.
const PAGE: u64 = 4096;
/// The most processes one event holds: a snapshot of more is split into
/// events of this many, then the rest (tens of microseconds apart, in the
/// corpus).
const PER_EVENT: usize = 256;
/// How soon a snapshot's next event comes, at most (clock-independent:
/// nanoseconds).
const CONTINUED_WITHIN_NS: i64 = 100_000_000;

/// One process's memory in a snapshot, in pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Its working set.
    pub working_set: u64,
    /// Its private working set.
    pub private_working_set: u64,
    /// Its commit.
    pub commit: u64,
    /// Its virtual size.
    pub virtual_size: u64,
    /// Its shared commit.
    pub shared_commit: u64,
}

/// One snapshot: when, and each process's memory then.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// When (clock ticks).
    pub time: i64,
    /// Each process's memory.
    pub processes: Vec<(ProcessIx, u32, Usage)>,
}

/// A trace's snapshots, in time order.
#[derive(Clone, Debug, Default)]
pub struct MemTable {
    /// The snapshots.
    pub snapshots: Vec<Snapshot>,
    /// Payloads that weren't the layout's length.
    pub malformed: u64,
}

/// Reads a `ProcessMemInfo` payload: each `(pid, usage)`; none if it
/// isn't the layout's length.
pub fn parse(data: &[u8], ptr: usize) -> Option<Vec<(u32, Usage)>> {
    let count = usize::try_from(u32::from_le_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    let size = 4 + 8 * ptr;
    if data.len() != count.checked_mul(size)?.checked_add(4)? {
        return None;
    }
    let field = |rec: &[u8], i: usize| {
        let at = 4 + i * ptr;
        let mut a = [0u8; 8];
        a[..ptr].copy_from_slice(&rec[at..at + ptr]);
        u64::from_le_bytes(a)
    };
    Some(
        data[4..]
            .chunks_exact(size)
            .map(|rec| {
                let pid = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                (
                    pid,
                    Usage {
                        working_set: field(rec, 0),
                        commit: field(rec, 1),
                        virtual_size: field(rec, 2),
                        private_working_set: field(rec, 3),
                        shared_commit: field(rec, 7),
                    },
                )
            })
            .collect(),
    )
}

/// The snapshots of `trace` (read from `path`), from the buffers holding
/// them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<MemTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::PAGE_FAULT && op == PROCESS_MEM_INFO
    };
    let (mut all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        // (Version 2 and later: the layout read.)
        if e.descriptor.version < 2 {
            return;
        }
        mine.push((e.timestamp, parse(e.user_data, pointer_size(e))));
    })?;
    all.sort_by_key(|(t, _)| *t);
    let mut table = MemTable::default();
    // Whether the last event was full (its snapshot continues).
    let mut full = false;
    for (time, parsed) in all {
        let Some(list) = parsed else {
            table.malformed += 1;
            full = false;
            continue;
        };
        let continued = full
            && table.snapshots.last().is_some_and(|s| {
                trace.clock.nanos(time) - trace.clock.nanos(s.time) <= CONTINUED_WITHIN_NS
            });
        full = list.len() == PER_EVENT;
        let processes = list
            .into_iter()
            .map(|(pid, usage)| (crate::reading::process_at(trace, pid, time), pid, usage));
        match table.snapshots.last_mut() {
            // (A snapshot's time is its first event's.)
            Some(last) if continued => last.processes.extend(processes),
            _ => table.snapshots.push(Snapshot {
                time,
                processes: processes.collect(),
            }),
        }
    }
    Ok(table)
}

/// What processes are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Each process.
    Process,
    /// Their image's name (svchost.exe's together).
    Name,
}

/// `table`'s snapshots in `time` (clock ticks; all of the trace, if
/// none): by `group`, the memory in the last of them (working set,
/// private working set, commit, in bytes), the peaks in them, and the
/// commit's change from the first to the last (the most commit first; the
/// first `group_limit`); and each snapshot's totals (the first `limit`).
pub fn summary(
    trace: &Trace,
    table: &MemTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limit: usize,
    group_limit: usize,
) -> Value {
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.snapshots.partition_point(|s| s.time < start);
    let to = table.snapshots.partition_point(|s| s.time < end);
    let snapshots = &table.snapshots[from..to];
    let label = |p: ProcessIx, pid: u32| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            match group {
                GroupBy::Process => format!("{} ({})", pr.name, pr.pid),
                GroupBy::Name => pr.name.clone(),
            }
        } else {
            match group {
                GroupBy::Process => format!("Unknown process ({pid})"),
                GroupBy::Name => "Unknown process".to_string(),
            }
        }
    };
    // Per group: [working set, private working set, commit] in the last
    // snapshot; their peaks (over the group's sum in each snapshot); and
    // the commit in the first.
    #[derive(Default)]
    struct Row {
        last: [u64; 3],
        peak: [u64; 3],
        first_commit: Option<u64>,
    }
    let mut rows: FxHashMap<String, Row> = FxHashMap::default();
    let mut series = Vec::with_capacity(snapshots.len());
    for (i, s) in snapshots.iter().enumerate() {
        let mut sums: FxHashMap<String, [u64; 3]> = FxHashMap::default();
        let mut total = [0u64; 3];
        for &(p, pid, u) in &s.processes {
            let v =
                [u.working_set, u.private_working_set, u.commit].map(|n| n.saturating_mul(PAGE));
            let g = sums.entry(label(p, pid)).or_default();
            for k in 0..3 {
                g[k] += v[k];
                total[k] += v[k];
            }
        }
        // (A group absent from the last snapshot has nothing then.)
        if i + 1 == snapshots.len() {
            for r in rows.values_mut() {
                r.last = [0; 3];
            }
        }
        for (l, v) in sums {
            let r = rows.entry(l).or_default();
            for k in 0..3 {
                r.peak[k] = r.peak[k].max(v[k]);
            }
            if i == 0 {
                r.first_commit = Some(v[2]);
            }
            if i + 1 == snapshots.len() {
                r.last = v;
            }
        }
        series.push(json!({
            "timeNs": trace.clock.nanos(s.time),
            "processes": s.processes.len(),
            "workingSet": total[0],
            "privateWorkingSet": total[1],
            "commit": total[2],
        }));
    }
    let mut rows: Vec<(String, Row)> = rows.into_iter().collect();
    rows.sort_by(|a, b| {
        b.1.last[2]
            .cmp(&a.1.last[2])
            .then(b.1.peak[2].cmp(&a.1.peak[2]))
            .then_with(|| a.0.cmp(&b.0))
    });
    let groups_total = rows.len();
    rows.truncate(group_limit);
    series.truncate(limit);
    let last = snapshots.last();
    json!({
        "snapshots": snapshots.len(),
        "malformed": table.malformed,
        "workingSet": last.map_or(0, |s| s.processes.iter().map(|x| x.2.working_set * PAGE).sum::<u64>()),
        "commit": last.map_or(0, |s| s.processes.iter().map(|x| x.2.commit * PAGE).sum::<u64>()),
        "groupsTotal": groups_total,
        "groups": rows.iter().map(|(l, r)| json!({
            "label": l,
            "workingSet": r.last[0],
            "privateWorkingSet": r.last[1],
            "commit": r.last[2],
            "peakWorkingSet": r.peak[0],
            "peakCommit": r.peak[2],
            // (From the first snapshot: from nothing, if it wasn't in
            // it; signed.)
            "commitChange": i64::try_from(i128::from(r.last[2]) - i128::from(r.first_commit.unwrap_or(0)))
                .unwrap_or(0),
        })).collect::<Vec<_>>(),
        "series": series,
    })
}

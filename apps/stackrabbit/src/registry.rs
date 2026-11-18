//! Registry: the trace's registry operations (Registry create, open,
//! query, set, delete, enumerate, flush, close and security requests),
//! each with its thread and process, its key's path, the value it names
//! (value operations), its result and its duration; read from the trace
//! file and kept; then totals grouped as asked, and the longest.
//!
//! Each event is logged when its operation ends: its timestamp is its
//! end, and its `InitialTime` its start. `KeyHandle` is the kernel's key
//! control block (KCB) for the key it acts on, which the KCB create,
//! delete and rundown events name in full; `KeyName` is the path after it
//! (opens and creates: the subkey's, all of it when there is no KCB), or
//! the value's name (value operations).

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::{Properties, pointer_size};
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use crate::reading::int;

/// The operations (Registry opcodes) and their names.
const OPERATIONS: &[(u8, &str)] = &[
    (10, "Create"),
    (11, "Open"),
    (12, "Delete"),
    (13, "Query"),
    (14, "SetValue"),
    (15, "DeleteValue"),
    (16, "QueryValue"),
    (17, "EnumerateKey"),
    (18, "EnumerateValueKey"),
    (19, "QueryMultipleValue"),
    (20, "SetInformation"),
    (21, "Flush"),
    (26, "Virtualize"),
    (27, "Close"),
    (28, "SetSecurity"),
    (29, "QuerySecurity"),
];

/// The operations whose `KeyName` is a value's name.
const VALUE_OPERATIONS: [u8; 3] = [14, 15, 16];

/// The KCB events: KCBCreate, KCBDelete, KCBRundownBegin, KCBRundownEnd.
const KCBS: [u8; 4] = [22, 23, 24, 25];

/// One registry operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegOp {
    /// Its operation (an index of `OPERATIONS`).
    pub op: u8,
    /// When it started (clock ticks).
    pub start: i64,
    /// When it ended (clock ticks).
    pub end: i64,
    /// Its result (`NTSTATUS`).
    pub status: u32,
    /// Its thread.
    pub thread: ThreadIx,
    /// Its process.
    pub process: ProcessIx,
    /// Its key's path (an index of the table's paths), if known.
    pub key: Option<u32>,
    /// The value it names (value operations: an index of the table's
    /// paths).
    pub value: Option<u32>,
}

/// A trace's registry operations, in start order, and the paths and
/// value names they name.
#[derive(Clone, Debug, Default)]
pub struct RegistryTable {
    /// The operations.
    pub ops: Vec<RegOp>,
    /// The paths and value names operations name (by index).
    pub names: Vec<String>,
}

/// One event read.
enum Read {
    Op {
        op: u8,
        start: i64,
        end: i64,
        status: u32,
        kcb: u64,
        name: String,
        thread_id: u32,
        process_id: u32,
    },
    Kcb {
        time: i64,
        kcb: u64,
        name: String,
    },
}

/// The registry operations of `trace` (read from `path`): its Registry
/// events, from the buffers holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<RegistryTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::REGISTRY
            && (KCBS.contains(&op) || OPERATIONS.iter().any(|(o, _)| *o == op))
    };
    let (all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let op = e.descriptor.opcode;
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        let name = p.get("KeyName").map_or_else(String::new, |n| {
            hexcavator_etw::values::format(n, pointer_size(e))
        });
        let kcb = int(p.get("KeyHandle"));
        if KCBS.contains(&op) {
            if !name.is_empty() {
                mine.push(Read::Kcb {
                    time: e.timestamp,
                    kcb,
                    name,
                });
            }
            return;
        }
        let start = i64::try_from(int(p.get("InitialTime"))).unwrap_or(e.timestamp);
        mine.push(Read::Op {
            op,
            start: start.min(e.timestamp),
            end: e.timestamp,
            status: u32::try_from(int(p.get("Status"))).unwrap_or(u32::MAX),
            kcb,
            name,
            thread_id: e.thread_id,
            process_id: e.process_id,
        });
    })?;
    Ok(assemble(trace, all))
}

/// The operations, in start order, with their keys, values, threads and
/// processes.
fn assemble(trace: &Trace, all: Vec<Read>) -> RegistryTable {
    // Each KCB's names over time.
    let mut kcbs: FxHashMap<u64, Vec<(i64, String)>> = FxHashMap::default();
    let mut ops = Vec::new();
    for r in all {
        match r {
            Read::Kcb { time, kcb, name } => kcbs.entry(kcb).or_default().push((time, name)),
            op @ Read::Op { .. } => ops.push(op),
        }
    }
    for v in kcbs.values_mut() {
        v.sort();
    }
    // A KCB's name at a time: the last before, else the first after (a
    // key opened before the trace began, named by the rundown at its end).
    let kcb_at = |kcb: u64, time: i64| -> Option<&String> {
        let v = kcbs.get(&kcb)?;
        let i = v.partition_point(|(t, _)| *t <= time);
        Some(if i > 0 { &v[i - 1].1 } else { &v.first()?.1 })
    };
    let threads = crate::reading::Threads::new(trace);
    let mut names: Vec<String> = Vec::new();
    let mut ids: FxHashMap<String, u32> = FxHashMap::default();
    let mut intern = |s: String| -> u32 {
        if let Some(&i) = ids.get(&s) {
            return i;
        }
        let i = u32::try_from(names.len()).unwrap_or(u32::MAX);
        names.push(s.clone());
        ids.insert(s, i);
        i
    };
    let mut out: Vec<RegOp> = ops
        .into_iter()
        .filter_map(|r| {
            let Read::Op {
                op,
                start,
                end,
                status,
                kcb,
                name,
                thread_id,
                process_id,
            } = r
            else {
                return None;
            };
            let base = if kcb == 0 { None } else { kcb_at(kcb, end) };
            let (key, value) = if VALUE_OPERATIONS.contains(&op) {
                (base.cloned(), Some(name))
            } else {
                let key = match (base, name.is_empty()) {
                    (Some(b), true) => Some(b.clone()),
                    (Some(b), false) => Some(format!("{b}\\{name}")),
                    // (No KCB: the name is the whole path.)
                    (None, false) if kcb == 0 => Some(name),
                    _ => None,
                };
                (key, None)
            };
            let thread = threads.at(thread_id, start);
            let process = if thread.is_some() {
                trace.thread_process(thread)
            } else if process_id != u32::MAX {
                crate::reading::process_at(trace, process_id, start)
            } else {
                ProcessIx::NONE
            };
            let index = OPERATIONS.iter().position(|(o, _)| *o == op).unwrap_or(0);
            Some(RegOp {
                op: u8::try_from(index).unwrap_or(0),
                start,
                end,
                status,
                thread,
                process,
                key: key.map(&mut intern),
                value: value.map(&mut intern),
            })
        })
        .collect();
    out.sort_by_key(|o| (o.start, o.end));
    RegistryTable { ops: out, names }
}

/// What registry operations are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// Key.
    Key,
    /// Operation.
    Operation,
}

/// `table`'s operations started in `time` (clock ticks; all, if none):
/// totals by `group` (count, how many failed, total duration; the most
/// time first; the first `group_limit` of them), and the `limit` longest.
pub fn summary(
    trace: &Trace,
    table: &RegistryTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limit: usize,
    group_limit: usize,
) -> Value {
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.ops.partition_point(|o| o.start < start);
    let to = table.ops.partition_point(|o| o.start < end);
    let ops = &table.ops[from..to];
    let ns = |o: &RegOp| {
        u64::try_from(trace.clock.nanos(o.end) - trace.clock.nanos(o.start)).unwrap_or(0)
    };
    // (NTSTATUS errors and warnings have the high bit set.)
    let failed = |o: &RegOp| o.status & 0x8000_0000 != 0;
    let process_label = |p: ProcessIx| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            format!("{} ({})", pr.name, pr.pid)
        } else {
            "Unknown process".to_string()
        }
    };
    let name = |i: Option<u32>| i.map(|i| table.names[i as usize].as_str());
    // Totals by what the group is (a process, key or operation), then by
    // its label (which two processes may share).
    let mut by_id: FxHashMap<u32, (u64, u64, u64)> = FxHashMap::default();
    for o in ops {
        let id = match group {
            GroupBy::Process => o.process.0,
            GroupBy::Key => o.key.unwrap_or(u32::MAX),
            GroupBy::Operation => u32::from(o.op),
        };
        let g = by_id.entry(id).or_default();
        g.0 += 1;
        g.1 += u64::from(failed(o));
        g.2 += ns(o);
    }
    let mut groups: FxHashMap<String, (u64, u64, u64)> = FxHashMap::default();
    for (id, (n, f, d)) in by_id {
        let label = match group {
            GroupBy::Process => process_label(ProcessIx(id)),
            GroupBy::Key => name((id != u32::MAX).then_some(id))
                .unwrap_or("Unknown key")
                .to_string(),
            GroupBy::Operation => OPERATIONS[id as usize].1.to_string(),
        };
        let g = groups.entry(label).or_default();
        g.0 += n;
        g.1 += f;
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
    let mut longest: Vec<(u64, &RegOp)> = ops.iter().map(|o| (ns(o), o)).collect();
    let order =
        |a: &(u64, &RegOp), b: &(u64, &RegOp)| b.0.cmp(&a.0).then(a.1.start.cmp(&b.1.start));
    if longest.len() > limit && limit > 0 {
        longest.select_nth_unstable_by(limit - 1, order);
    }
    longest.truncate(limit);
    longest.sort_by(order);
    let longest: Vec<&RegOp> = longest.into_iter().map(|(_, o)| o).collect();
    json!({
        "count": ops.len(),
        "failed": ops.iter().filter(|o| failed(o)).count(),
        "durationNs": ops.iter().map(ns).sum::<u64>(),
        "groupsTotal": groups_total,
        "groups": groups.iter().map(|(label, (n, failed, d))| json!({
            "label": label, "count": n, "failed": failed, "durationNs": d,
        })).collect::<Vec<_>>(),
        "ops": longest.iter().map(|o| json!({
            "op": OPERATIONS[usize::from(o.op)].1,
            "startNs": trace.clock.nanos(o.start),
            "durationNs": ns(o),
            "status": format!("0x{:08x}", o.status),
            "process": process_label(o.process),
            "tid": o.thread.is_some().then(|| trace.threads[o.thread.index()].tid),
            "key": name(o.key),
            "value": name(o.value),
        })).collect::<Vec<_>>(),
    })
}

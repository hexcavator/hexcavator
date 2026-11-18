//! File I/O: the trace's file operations (FileIo create, read, write,
//! information, directory, flush, cleanup and close requests), each with
//! its thread and process, its file, its size (reads and writes), and its
//! duration and status (from its OperationEnd, by its IRP); read from the
//! trace file and kept; then totals grouped as asked, and the longest
//! operations.

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::{Properties, pointer_size};
use hexcavator_trace::{ProcessIx, ThreadIx, Trace};
use rustc_hash::FxHashMap;

use crate::reading::int;
use serde_json::{Value, json};

/// The operations (FileIo opcodes, version 3 and later) and their names.
const OPERATIONS: &[(u8, &str)] = &[
    (64, "Create"),
    (65, "Cleanup"),
    (66, "Close"),
    (67, "Read"),
    (68, "Write"),
    (69, "SetInfo"),
    (70, "Delete"),
    (71, "Rename"),
    (72, "DirEnum"),
    (73, "Flush"),
    (74, "QueryInfo"),
    (75, "FSControl"),
    (77, "DirNotify"),
];

/// `OperationEnd`.
const END: u8 = 76;
/// The name events: Name, FileCreate, FileDelete, FileRundown.
const NAMES: [u8; 4] = [0, 32, 35, 36];

/// One file operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOp {
    /// Its operation (an index of `OPERATIONS`).
    pub op: u8,
    /// When it was requested (clock ticks).
    pub start: i64,
    /// How long it took, in nanoseconds (none: it never ended in the
    /// trace).
    pub duration_ns: Option<u64>,
    /// Its result (`NTSTATUS`), if it ended.
    pub status: Option<u32>,
    /// Its size in bytes (reads and writes).
    pub size: u32,
    /// Its thread.
    pub thread: ThreadIx,
    /// That thread's process.
    pub process: ProcessIx,
    /// Its file's path, if known.
    pub file: Option<u32>,
}

/// A trace's file operations, in request order, and their files' paths.
#[derive(Clone, Debug, Default)]
pub struct FileTable {
    /// The operations.
    pub ops: Vec<FileOp>,
    /// The paths operations name (by index).
    pub files: Vec<String>,
}

/// One event read.
enum Read {
    Op {
        op: u8,
        time: i64,
        irp: u64,
        file_key: u64,
        file_object: u64,
        thread_id: u32,
        size: u32,
        path: Option<String>,
    },
    End {
        time: i64,
        irp: u64,
        status: u32,
    },
    Name {
        time: i64,
        file: u64,
        name: String,
    },
}

/// The file operations of `trace` (read from `path`): its FileIo events,
/// from the buffers holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<FileTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::FILE_IO
            && (op == END || NAMES.contains(&op) || OPERATIONS.iter().any(|(o, _)| *o == op))
    };
    let (all, _) = crate::reading::events(trace, path, wanted, |_, e, mine| {
        let op = e.descriptor.opcode;
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        let text = |name: &str| {
            p.get(name)
                .map(|n| hexcavator_etw::values::format(n, pointer_size(e)))
                .filter(|s| !s.is_empty())
        };
        if op == END {
            mine.push(Read::End {
                time: e.timestamp,
                irp: int(p.get("IrpPtr")),
                status: u32::try_from(int(p.get("NtStatus"))).unwrap_or(u32::MAX),
            });
        } else if NAMES.contains(&op) {
            if let Some(name) = text("FileName") {
                mine.push(Read::Name {
                    time: e.timestamp,
                    file: int(p.get("FileObject")),
                    name,
                });
            }
        } else {
            mine.push(Read::Op {
                op,
                time: e.timestamp,
                irp: int(p.get("IrpPtr")),
                file_key: int(p.get("FileKey")),
                file_object: int(p.get("FileObject")),
                thread_id: u32::try_from(int(p.get("TTID"))).unwrap_or(u32::MAX),
                size: u32::try_from(int(p.get("IoSize"))).unwrap_or(0),
                path: if op == 64 { text("OpenPath") } else { None },
            });
        }
    })?;
    Ok(assemble(trace, all))
}

fn time_of(r: &Read) -> i64 {
    match r {
        Read::Op { time, .. } | Read::End { time, .. } | Read::Name { time, .. } => *time,
    }
}

/// The operations, in request order, each ended by the next OperationEnd
/// of its IRP, named by its file.
fn assemble(trace: &Trace, mut all: Vec<Read>) -> FileTable {
    all.sort_by_key(time_of);
    // Each file's names over time (name events key files by what file
    // operations call their file key; a create names its file object).
    let mut names = crate::reading::Names::default();
    for r in &all {
        match r {
            Read::Name { time, file, name } => names.add(*file, *time, name.clone()),
            Read::Op {
                time,
                file_object,
                path: Some(path),
                ..
            } => names.add(*file_object, *time, path.clone()),
            _ => {}
        }
    }
    names.finish();
    let threads = crate::reading::Threads::new(trace);
    let mut files = crate::reading::Interner::default();
    let mut ops: Vec<FileOp> = Vec::new();
    // IRPs in flight: the operation each started.
    let mut open: FxHashMap<u64, usize> = FxHashMap::default();
    for r in all {
        match r {
            Read::Op {
                op,
                time,
                irp,
                file_key,
                file_object,
                thread_id,
                size,
                path,
            } => {
                let name = path
                    .as_deref()
                    .or_else(|| names.at(file_key, time))
                    .or_else(|| names.at(file_object, time));
                let file = name.map(|n| files.intern(n));
                let thread = threads.at(thread_id, time);
                let index = OPERATIONS.iter().position(|(o, _)| *o == op).unwrap_or(0);
                open.insert(irp, ops.len());
                ops.push(FileOp {
                    op: u8::try_from(index).unwrap_or(0),
                    start: time,
                    duration_ns: None,
                    status: None,
                    size,
                    thread,
                    process: trace.thread_process(thread),
                    file,
                });
            }
            Read::End { time, irp, status } => {
                if let Some(i) = open.remove(&irp) {
                    let o = &mut ops[i];
                    o.duration_ns = Some(
                        u64::try_from(trace.clock.nanos(time) - trace.clock.nanos(o.start))
                            .unwrap_or(0),
                    );
                    o.status = Some(status);
                }
            }
            Read::Name { .. } => {}
        }
    }
    FileTable {
        ops,
        files: files.strings,
    }
}

/// What file operations are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Process.
    Process,
    /// File.
    File,
    /// Operation.
    Operation,
}

/// `table`'s operations requested in `time` (clock ticks; all, if none):
/// totals by `group` (count, bytes, total duration; the most time first),
/// and the `limit` longest.
pub fn summary(
    trace: &Trace,
    table: &FileTable,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limits: crate::reading::Limits,
) -> Value {
    let (limit, group_limit) = (limits.items, limits.groups);
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.ops.partition_point(|o| o.start < start);
    let to = table.ops.partition_point(|o| o.start < end);
    let ops = &table.ops[from..to];
    let process_label = |p: ProcessIx| {
        if p.is_some() {
            let pr = &trace.processes[p.index()];
            format!("{} ({})", pr.name, pr.pid)
        } else {
            "Unknown process".to_string()
        }
    };
    let op_name = |o: &FileOp| OPERATIONS[usize::from(o.op)].1;
    let file_label = |f: Option<u32>| {
        f.map_or_else(
            || "Unknown file".to_string(),
            |f| table.files[f as usize].clone(),
        )
    };
    let mut groups: FxHashMap<String, (u64, u64, u64)> = FxHashMap::default();
    for o in ops {
        let label = match group {
            GroupBy::Process => process_label(o.process),
            GroupBy::File => file_label(o.file),
            GroupBy::Operation => op_name(o).to_string(),
        };
        let g = groups.entry(label).or_default();
        g.0 += 1;
        g.1 += u64::from(o.size);
        g.2 += o.duration_ns.unwrap_or(0);
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
    let mut longest: Vec<&FileOp> = ops.iter().collect();
    longest.sort_by(|a, b| {
        b.duration_ns
            .unwrap_or(0)
            .cmp(&a.duration_ns.unwrap_or(0))
            .then(a.start.cmp(&b.start))
    });
    longest.truncate(limit);
    json!({
        "count": ops.len(),
        "unended": ops.iter().filter(|o| o.duration_ns.is_none()).count(),
        "bytes": ops.iter().map(|o| u64::from(o.size)).sum::<u64>(),
        "groupsTotal": groups_total,
        "groups": groups.iter().map(|(label, (n, bytes, ns))| json!({
            "label": label, "count": n, "bytes": bytes, "durationNs": ns,
        })).collect::<Vec<_>>(),
        "ops": longest.iter().map(|o| json!({
            "op": op_name(o),
            "startNs": trace.clock.nanos(o.start),
            "durationNs": o.duration_ns,
            "status": o.status.map(|s| format!("0x{s:08x}")),
            "size": o.size,
            "process": process_label(o.process),
            "tid": o.thread.is_some().then(|| trace.threads[o.thread.index()].tid),
            "file": o.file.map(|f| table.files[f as usize].clone()),
        })).collect::<Vec<_>>(),
    })
}

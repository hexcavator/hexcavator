//! `stackrabbit serve`: the session an editor drives.
//!
//! Requests and responses are [`crate::protocol`] frames on standard input
//! and output. Each open trace has a thread of its own, which owns the
//! trace and its views and answers the requests about them in order;
//! requests about different traces run at once, and opening a trace never
//! holds up the others.
//!
//! Methods (parameters, then result):
//!
//! - `hello` → `{version}`.
//! - `open` `{path, useIndex?, symbolCache?, symbolServers?,
//!   downloadSymbols?, stackTags?}` → `{trace, summary, opened, stackTags,
//!   stackTagsError, savedSymbols}`: `stackTags` is a file of WPA's stack tags, for
//!   grouping by `tag` (its count, or the error that kept it out, comes
//!   back). `trace` names it in
//!   the requests below. Then, if `downloadSymbols` is true, the PDBs its
//!   stacks need are downloaded in the background (into
//!   `symbolCache`, from `symbolServers`; by default `_NT_SYMBOL_PATH`'s,
//!   else WinDbg's cache and Microsoft's server), with notifications
//!   `symbols` `{trace, wanted, cached, downloaded, missing, done}`. Trees
//!   answer at once, with the PDBs loaded so far; they load in the
//!   background, and a note `symbols` `{trace, loaded, wanted}` says when
//!   they have (after the download too): trees made after it name the
//!   functions. Their names for the trace's stacks are saved beside its
//!   index (a `.hxsyms`) each time more are found, and read back when it
//!   reopens (`savedSymbols`: how many PDBs' names were), so that its
//!   trees name its functions from the start, without its PDBs.
//! - `lines` `{trace, source?, time?, file?, limit?}` → `{unit,
//!   ticksPerSecond, total, fileCount, files}` or, with `file`, `{unit,
//!   ticksPerSecond, total, file, lines}`: time by source line, from the
//!   symbols' line tables: the `limit` (200) heaviest source files by
//!   inclusive weight (`{path, exclusive, inclusive, count}`), or a file's
//!   lines (`{line, exclusive, inclusive, count}`, in order). Exclusive:
//!   where the line is the innermost frame; inclusive: where it is on the
//!   stack (a call's line, for a caller).
//! - `disk` `{trace, by?, time?, limit?}` → `{count, bytes, groups, ios}`:
//!   the disk I/Os completed in `time`, totals by `by`
//!   (process, file, disk or type: count, bytes, I/O time, disk service
//!   time, heaviest service time first) and the `limit` (1000) I/Os with
//!   the most service time, each `{kind, disk, offset, size, completeNs,
//!   ioNs, serviceNs, process, tid, file}`. (Read from the trace file the
//!   first time, then kept.)
//! - `dpc` `{trace, by?, time?, limit?}` → `{count, durationNs, groups,
//!   bucketsNs, histogram, runs}`: the DPCs and ISRs started in `time`,
//!   totals by `by` (module, function, processor or type: count, total
//!   and longest duration, the most time first), how many of each type
//!   took how long (`histogram` counts by `bucketsNs` upper bounds, then
//!   any longer), and the `limit` (1000) longest, each `{type, processor,
//!   startNs, durationNs, module, function, vector}`. (Read from the
//!   trace file the first time, then kept.)
//! - `fileio` `{trace, by?, time?, limit?}` → `{count, unended, bytes,
//!   groups, ops}`: the file operations requested in `time`, totals by
//!   `by` (process, file or operation: count, bytes, total duration, the
//!   most time first) and the `limit` (1000) longest, each `{op, startNs,
//!   durationNs, status, size, process, tid, file}`. (Read from the trace
//!   file the first time, then kept.)
//! - `hardfaults` `{trace, by?, time?, limit?, groupLimit?}` → `{count,
//!   bytes, durationNs, groupsTotal, groups, faults}`: the hard faults
//!   started in `time`, totals by `by` (process, file or thread: count,
//!   bytes, total duration, the most time first; the first `groupLimit`
//!   (10,000) of `groupsTotal`) and the `limit` (1000) longest, each
//!   `{startNs, durationNs, size, offset, address, process, tid, file}`.
//!   (Read from the trace file the first time, then kept.)
//! - `heap` `{trace, by?, time?, limit?, groupLimit?}` and `pool` (the
//!   same) → `{allocs, allocated, frees, freed, outstandingCount,
//!   outstanding, groupsTotal, groups, blocks}`: heap (processes heap
//!   tracing was on for) or kernel pool allocations; by `by` (heap:
//!   process, heap or thread; pool: tag, type, process or thread), how
//!   many blocks and bytes were allocated and freed in `time` (all of the
//!   trace if none), and how many of those allocated in it are still
//!   allocated at its end (the most bytes first; the first `groupLimit`
//!   (10,000) of `groupsTotal`); and the `limit` (1000) largest blocks
//!   allocated in it, each `{process, tid, group, kind, address, size,
//!   allocNs, freeNs}`. (Read from the trace file the first time, then
//!   kept.)
//! - `memory` `{trace, by?, time?, limit?, groupLimit?}` → `{snapshots,
//!   malformed, workingSet, commit, groupsTotal, groups, series}`: memory
//!   utilization, from the kernel's snapshots of each process's memory in
//!   `time` (all of the trace if none): by `by` (process or name), the
//!   working set, private working set and commit (bytes) in the last, the
//!   peak working set and commit, and the commit's change from the first
//!   (the most commit first; the first `groupLimit` (10,000) of
//!   `groupsTotal`); and each snapshot's totals (`series`: the first
//!   `limit` (1000), each `{timeNs, processes, workingSet,
//!   privateWorkingSet, commit}`). (Read from the trace file the first
//!   time, then kept.)
//! - `vmem` `{trace, by?, time?, limit?, groupLimit?}` → `{commits,
//!   committed, decommits, decommitted, outstanding, groupsTotal, groups,
//!   lifetimes}`: virtual memory commit lifetimes; by `by` (process or
//!   thread), how many and how many bytes were committed and decommitted
//!   in `time` (all of the trace if none), and how many bytes of what was
//!   committed in it are still committed at its end (`outstanding`; the
//!   most first, the first `groupLimit` (10,000) of `groupsTotal`); and
//!   the `limit` (1000) largest lifetimes committed in it, each
//!   `{process, tid, base, size, commitNs, decommitNs, decommitTid}`.
//!   (Read from the trace file the first time, then kept.)
//! - `registry` `{trace, by?, time?, limit?, groupLimit?}` → `{count,
//!   failed, durationNs, groupsTotal, groups, ops}`: the registry
//!   operations started in `time`, totals by `by` (process, key or
//!   operation: count, how many failed, total duration, the most time
//!   first; the first `groupLimit` (10,000) of `groupsTotal`) and the
//!   `limit` (1000) longest, each `{op, startNs, durationNs, status, process, tid, key,
//!   value}`. (Read from the trace file the first time, then kept.)
//! - `regions` `{trace, file}` → `{regions, instances, truncated}`: the
//!   regions of interest a WPA regions file defines, and their instances
//!   in the trace: each region `{name, displayName, parent, unsupported,
//!   count, totalNs, unpairedStarts, unpairedStops}`; each instance
//!   `{region, name, startNs, stopNs, durationNs, pid, tid}`, in start
//!   order (the first 20,000).
//! - `symbols` `{trace, wait?}` → `{ready, done, cache, rows, noDebug}`:
//!   the PDBs the
//!   trace's stacks need, most wanted first, each `{pdb, path, identity,
//!   frames, status, download}`: `status` "saved" (names from the trace's
//!   saved symbols), "loaded", "not found" or "not looked for yet", and
//!   `download` what the download did; and the modules with no PDB
//!   identity, `{module, frames}`. (`ready` false until the trace's
//!   frames are counted, in the background; `done` once its symbols are
//!   loaded and downloaded. `wait`: answers when `done`.)
//! - `close` `{trace}` → `{}`.
//! - `summary` `{trace}` → the trace's summary (with `eventsLost` and
//!   `buffersLost`: what its recording session lost).
//! - `processes` `{trace, time?}` → `{rows}`: the processes, with their
//!   lifetimes, threads and CPU samples (in `time`), heaviest first; each
//!   row's `index` names it to `threads`.
//! - `functions` `{trace, source?, frames?, time?, limit?}` → `{unit,
//!   ticksPerSecond, total, functionCount, functions, modules}`: the hot
//!   functions (the `limit` heaviest by exclusive and by inclusive weight,
//!   1000 by default; heaviest exclusive first) and every module, each
//!   row `{label, exclusive, inclusive, count}` (functions also have
//!   `module`).
//! - `events` `{trace}` → `{rows}`: every kind of event in the trace
//!   (whether or not it is imported): `{provider, guid, event, id,
//!   version, opcode, task, count, bytes, firstNs, lastNs}`, most numerous
//!   first; `provider` and `event` named where the kernel's schemas or the
//!   provider (TraceLogging) say, else null.
//! - `events.list` `{trace, guid, id?, version?, opcode?, time?, offset?,
//!   limit?, stacks?}` → `{total, offset, columns, rows}`: one kind of event's
//!   occurrences (in `time`), read from the trace file, in time order:
//!   how many, and `limit` (1000) from `offset`, each `{timeNs, cpu, pid,
//!   process, tid, fields, missing, extra}` with its fields as `[name,
//!   value]` (decoded by the description recorded with the trace, else
//!   the kernel's schema, else bytes); `missing`, the properties its
//!   payload ended before, `extra`, the bytes after its last; with
//!   `stacks`, each row's `stack` (its frames, innermost first, named by
//!   the trace's symbols; null for none).
//! - `threads` `{trace, process?, time?}` → `{rows}`: a process's threads
//!   (or all), with their lifetimes, start addresses (named), CPU samples,
//!   switches in and running time (precise, in ms) in `time`, heaviest
//!   first.
//! - `graph` `{trace, source?, buckets?, time?, top?, highlight?, by?,
//!   process?}` → `{source, by, startNs, endNs, buckets, series,
//!   highlight?}`: CPU usage over time, by process (or `by` "thread"; only
//!   one `process`'s, by its index), sampled (`samples`) or precise (`running`, or
//!   `waits`: both from context switches), each series's values the share
//!   of all the processors it used in each bucket. `highlight`, a row's
//!   `fn` (a function's or module's ID), adds a series of the CPU with it
//!   on the stack.
//! - `tree.create` `{trace, source?, groupBy?, frames?, invert?, time?}` →
//!   `{view, unit, root}`: a stack tree and its root row.
//! - `tree.children` `{trace, view, node}` → `{rows}`: a node's children,
//!   heaviest first.
//! - `tree.hotPath` `{trace, view, node, fraction?}` → `{rows}`: the
//!   heaviest path down from a node.
//! - `tree.close` `{trace, view}` → `{}`.
//! - `shutdown` → `{}`, then the engine exits.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use hexcavator_trace_analysis::{NodeId, PdbSymbolizer, Resolver, StackTags};
use rustc_hash::FxHashSet;
use serde_json::{Value, json};

use crate::protocol::{Frame, read_frame, write_frame};
use crate::store::{self, Loaded, Opened};
use crate::symbols::{self, Symbols};
use crate::views::{TreeSpec, TreeView, Unit, summary};
use hexcavator_symbolize::server::Fetched;

const USAGE: &str = "\
usage: stackrabbit serve

Answers an editor's requests: frames on standard input, answers on standard output (see the
protocol module). The Stackrabbit extension starts this.";

/// Where responses go: shared by the threads that answer.
pub type Output = Arc<Mutex<dyn Write + Send>>;

/// Runs `stackrabbit serve`.
pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let out: Output = Arc::new(Mutex::new(io::stdout()));
    match serve(io::stdin().lock(), &out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stackrabbit serve: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A request for a trace's thread.
struct Request {
    id: Value,
    method: String,
    params: Value,
}

/// Answers the requests read from `input` on `out`, until `shutdown` or
/// the end of the input; then waits for the traces' threads to finish.
pub fn serve(mut input: impl Read, out: &Output) -> io::Result<()> {
    let mut traces: HashMap<u64, Sender<Request>> = HashMap::new();
    let mut threads: Vec<JoinHandle<()>> = Vec::new();
    let mut next_trace = 1u64;
    while let Some(frame) = read_frame(&mut input)? {
        let id = frame.header.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = frame.header.get("method").and_then(Value::as_str) else {
            send(out, &json!({"id": id, "error": "a request needs a method"}));
            continue;
        };
        let params = frame.header.get("params").cloned().unwrap_or(json!({}));
        match method {
            "hello" => send(
                out,
                &json!({"id": id, "result": {"version": env!("CARGO_PKG_VERSION")}}),
            ),
            "shutdown" => {
                send(out, &json!({"id": id, "result": {}}));
                break;
            }
            "open" => {
                let Some(path) = params.get("path").and_then(Value::as_str) else {
                    send(out, &json!({"id": id, "error": "open: expected a path"}));
                    continue;
                };
                let options = store::Options {
                    use_index: params
                        .get("useIndex")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                    ..store::Options::default()
                };
                let symbols = Symbols::new(
                    params
                        .get("symbolCache")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from),
                    params
                        .get("symbolServers")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(|s| s.trim_end_matches('/').to_string())
                                .collect()
                        })
                        .unwrap_or_default(),
                    params
                        .get("downloadSymbols")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                );
                let trace = next_trace;
                next_trace += 1;
                let (tx, rx) = channel();
                traces.insert(trace, tx);
                let path = PathBuf::from(path);
                let out = Arc::clone(out);
                let tags = params
                    .get("stackTags")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from);
                threads.push(std::thread::spawn(move || {
                    worker(
                        trace,
                        &path,
                        &options,
                        &symbols,
                        tags.as_deref(),
                        &id,
                        &rx,
                        &out,
                    );
                }));
            }
            "close" => {
                let trace = params.get("trace").and_then(Value::as_u64);
                match trace.and_then(|t| traces.remove(&t)) {
                    // (Dropping the sender ends the trace's thread.)
                    Some(_) => send(out, &json!({"id": id, "result": {}})),
                    None => send(out, &json!({"id": id, "error": "close: no such trace"})),
                }
            }
            _ => {
                let trace = params.get("trace").and_then(Value::as_u64);
                let Some(tx) = trace.and_then(|t| traces.get(&t)) else {
                    send(
                        out,
                        &json!({"id": id, "error": format!("{method}: no such trace")}),
                    );
                    continue;
                };
                let request = Request {
                    id: id.clone(),
                    method: method.to_string(),
                    params,
                };
                if tx.send(request).is_err() {
                    send(
                        out,
                        &json!({"id": id, "error": format!("{method}: the trace is closed")}),
                    );
                }
            }
        }
    }
    traces.clear();
    for t in threads {
        let _ = t.join();
    }
    Ok(())
}

/// `params[name]`: a count (`default` if there is none).
fn count(params: &Value, name: &str, default: usize) -> Result<usize, String> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| format!("{name}: expected a count")),
    }
}

/// A time range in nanoseconds from the trace's start, in its clock's
/// ticks.
fn ticks(trace: &hexcavator_trace::Trace, time: Option<(i64, i64)>) -> Option<(i64, i64)> {
    time.map(|(s, e)| {
        let tps = i128::from(trace.clock.ticks_per_second.max(1));
        let t = |ns: i64| {
            i64::try_from(i128::from(trace.clock.origin) + i128::from(ns) * tps / 1_000_000_000)
                .unwrap_or(i64::MAX)
        };
        (t(s), t(e))
    })
}

/// Writes a response. A response that can't be written means the editor
/// is gone; the session ends when its input does.
///
/// An answer too large for a frame is an error answer instead (else its
/// request would never be answered). (Nothing is written of a frame too
/// large.)
fn send(out: &Output, header: &Value) {
    let mut w = out.lock().unwrap_or_else(PoisonError::into_inner);
    if let Err(e) = write_frame(&mut *w, &Frame::new(header.clone()))
        && e.kind() == std::io::ErrorKind::InvalidData
        && let Some(id) = header.get("id")
    {
        let _ = write_frame(
            &mut *w,
            &Frame::new(json!({
                "id": id,
                "error": format!("the answer is too large to send ({e}): ask for less"),
            })),
        );
    }
}

/// An open trace's state, owned by its thread.
struct State {
    /// Shared with the symbols' background thread.
    loaded: Arc<Loaded>,
    resolver: Resolver,
    /// Shared with the symbols' download, which makes it look again for
    /// what was missing.
    symbols: Arc<PdbSymbolizer>,
    /// The stack tags, if a file of them was given.
    tags: Option<StackTags>,
    views: HashMap<u64, TreeView>,
    next_view: u64,
    /// The trace's disk I/Os, once read.
    disk: Option<Arc<crate::disk::DiskTable>>,
    /// The trace's file operations, once read.
    files: Option<Arc<crate::fileio::FileTable>>,
    /// The trace's heap blocks, once read.
    heap: Option<Arc<crate::allocs::BlockTable>>,
    /// The trace's pool blocks, once read.
    pool: Option<Arc<crate::allocs::BlockTable>>,
    /// The trace's memory snapshots, once read.
    memory: Option<Arc<crate::memutil::MemTable>>,
    /// The trace's commit lifetimes, once read.
    vmem: Option<Arc<crate::vmem::VmemTable>>,
    /// The trace's hard faults, once read.
    faults: Option<Arc<crate::hardfault::FaultTable>>,
    /// The trace's registry operations, once read.
    registry: Option<Arc<crate::registry::RegistryTable>>,
    /// The trace's DPCs and ISRs, once read.
    dpcs: Option<Arc<crate::dpc::DpcTable>>,
    /// The last line totals worked out: for which (source, time), with
    /// what symbols (how many PDBs were loaded).
    lines: Option<(LinesKey, Arc<LinesValue>)>,
    /// The symbols' report: what the stacks need (once the background
    /// thread has found it), the PDBs whose names were saved, what became
    /// of downloads, and where they go.
    report: SymbolsReport,
}

/// What line totals were worked out for: the source, the time range,
/// and how many PDBs were loaded.
type LinesKey = (crate::views::Source, Option<(i64, i64)>, usize);

/// Line totals, their unit, and the total weight.
type LinesValue = (
    hexcavator_trace_analysis::lines::LineTotals,
    crate::views::Unit,
    u64,
);

/// What `symbols` reports from.
struct SymbolsReport {
    frames: Arc<std::sync::OnceLock<symbols::Frames>>,
    saved: FxHashSet<symbols::DebugKey>,
    fetched: Arc<Mutex<rustc_hash::FxHashMap<symbols::DebugKey, Fetched>>>,
    download: bool,
    cache: std::path::PathBuf,
    /// Set when the background thread is done (loading and downloading).
    done: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

/// A trace's thread: opens it, answers `open_id`, then answers the
/// requests about it until the session closes it.
#[allow(clippy::too_many_arguments)]
fn worker(
    trace: u64,
    path: &std::path::Path,
    options: &store::Options,
    symbols: &Symbols,
    tags_path: Option<&std::path::Path>,
    open_id: &Value,
    rx: &Receiver<Request>,
    out: &Output,
) {
    let loaded = match store::open(path, options) {
        Ok(l) => l,
        Err(e) => {
            send(out, &json!({"id": open_id, "error": e}));
            // Requests already sent for it get errors too.
            for r in rx {
                send(out, &json!({"id": r.id, "error": "the trace didn't open"}));
            }
            return;
        }
    };
    let opened = match &loaded.opened {
        Opened::Indexed { index, read } => json!({
            "how": "index",
            "index": index.display().to_string(),
            "seconds": read.as_secs_f64(),
        }),
        Opened::Imported {
            stats,
            import,
            index,
        } => json!({
            "how": "import",
            "seconds": import.as_secs_f64(),
            "events": stats.events,
            "readErrors": stats.read_errors,
            "decodeErrors": stats.decode_errors,
            "stacksUnmatched": stats.stacks_unmatched,
            "index": match index {
                Ok((p, _)) => Value::String(p.display().to_string()),
                Err(_) => Value::Null,
            },
        }),
    };
    // Stack tags: a file that can't be read or parsed is reported, and the
    // trace opens without them.
    let (tags, tags_error) = match tags_path {
        None => (None, None),
        Some(p) => match std::fs::read_to_string(p)
            .map_err(|e| e.to_string())
            .and_then(|text| StackTags::from_xml(&text))
        {
            Ok(t) => (Some(t), None),
            Err(e) => (None, Some(format!("{}: {e}", p.display()))),
        },
    };
    // Trees answer at once with the PDBs loaded so far; the editor hears
    // when more are (a `symbols` note), and asks again. The names saved
    // beside the index the last time are there from the start.
    let symbolizer = PdbSymbolizer::new(symbols.path.clone());
    symbolizer.set_waiting(false);
    let saved_path = loaded.index().map(symbols::saved_path);
    let saved = saved_path
        .as_deref()
        .map(|p| symbols::load_saved(p, loaded.source))
        .unwrap_or_default();
    for ((guid, age), table) in &saved {
        symbolizer.seed(guid, *age, Arc::clone(table));
    }
    let mut state = State {
        tags,
        resolver: Resolver::new(&loaded.trace),
        symbols: Arc::new(symbolizer),
        loaded: Arc::new(loaded),
        views: HashMap::new(),
        next_view: 1,
        lines: None,
        disk: None,
        files: None,
        dpcs: None,
        registry: None,
        faults: None,
        vmem: None,
        memory: None,
        heap: None,
        pool: None,
        report: SymbolsReport {
            frames: Arc::default(),
            saved: saved.iter().map(|(k, _)| *k).collect(),
            fetched: Arc::default(),
            download: symbols.download,
            cache: symbols.servers.cache.clone(),
            done: Arc::default(),
        },
    };
    send(
        out,
        &json!({"id": open_id, "result": {
            "trace": trace,
            "summary": state.summary(),
            "opened": opened,
            "stackTags": state.tags.as_ref().map(StackTags::len),
            "stackTagsError": tags_error,
            "savedSymbols": saved.len(),
        }}),
    );
    let background = symbols_task(
        trace,
        &state,
        symbols,
        saved_path,
        saved.iter().map(|(k, _)| *k).collect(),
        out,
    );
    for r in rx {
        let response = match state.handle(&r.method, &r.params) {
            Ok(result) => json!({"id": r.id, "result": result}),
            Err(e) => json!({"id": r.id, "error": format!("{}: {e}", r.method)}),
        };
        send(out, &response);
    }
    // (The download's last notification is sent before the trace closes.)
    let _ = background.join();
}

/// The trace's symbols, in the background: finds the PDBs its stacks need
/// and loads those here already, telling the editor how many it has (a
/// `symbols` note with `loaded`, so that it asks for trees with their
/// names); meanwhile, if asked to, downloads the rest, telling the editor
/// how that goes, and loads them. Each time it has PDBs it hadn't saved,
/// it saves their names for the trace's stacks at `saved_path` (beside
/// the index), so that the trace reopens with its names.
fn symbols_task(
    trace: u64,
    state: &State,
    symbols: &Symbols,
    saved_path: Option<std::path::PathBuf>,
    saved: FxHashSet<symbols::DebugKey>,
    out: &Output,
) -> JoinHandle<()> {
    let loaded = Arc::clone(&state.loaded);
    let symbolizer = Arc::clone(&state.symbols);
    let out = Arc::clone(out);
    let servers = symbols.download.then(|| symbols.servers.clone());
    let shared_frames = Arc::clone(&state.report.frames);
    let fetched = Arc::clone(&state.report.fetched);
    let done = Arc::clone(&state.report.done);
    std::thread::spawn(move || {
        // (Done, however it ends.)
        struct Done(Arc<(Mutex<bool>, std::sync::Condvar)>);
        impl Drop for Done {
            fn drop(&mut self) {
                *self.0.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
                self.0.1.notify_all();
            }
        }
        let _done = Done(done);
        let frames = shared_frames.get_or_init(|| symbols::frames(&loaded.trace));
        let ids = &frames.wanted;
        let saved = Mutex::new(saved);
        let save = || {
            let Some(path) = &saved_path else { return };
            let mut saved = saved.lock().unwrap_or_else(PoisonError::into_inner);
            let found: Vec<symbols::Table> = symbolizer
                .found()
                .into_iter()
                .map(|(guid, age, t)| ((guid, age), t))
                .filter(|(k, _)| frames.addresses.contains_key(k))
                .collect();
            if found.iter().all(|(k, _)| saved.contains(k)) {
                return;
            }
            // (A trace whose index is read-only keeps what it has.)
            if symbols::save(path, loaded.source, frames, &found).is_ok() {
                *saved = found.iter().map(|(k, _)| *k).collect();
            }
        };
        let loaded_note = || {
            send(
                &out,
                &json!({"method": "symbols", "params": {
                    "trace": trace,
                    "loaded": symbolizer.loaded_count(),
                    "wanted": ids.len(),
                }}),
            );
        };
        std::thread::scope(|scope| {
            // What is here already loads at once; the rest downloads
            // meanwhile.
            scope.spawn(|| {
                symbols::preload(&symbolizer, ids);
                loaded_note();
                save();
            });
            let Some(servers) = &servers else { return };
            scope.spawn(|| {
                let note = |d: &symbols::Downloaded, done: bool| {
                    send(
                        &out,
                        &json!({"method": "symbols", "params": {
                            "trace": trace,
                            "wanted": d.wanted,
                            "cached": d.cached,
                            "downloaded": d.downloaded,
                            "missing": d.missing,
                            "done": done,
                        }}),
                    );
                };
                // (At most a few notes a second.)
                let last = Mutex::new(std::time::Instant::now());
                let d = symbols::download(servers, ids, |d| {
                    let mut l = last.lock().unwrap_or_else(PoisonError::into_inner);
                    if l.elapsed().as_millis() >= 250 {
                        *l = std::time::Instant::now();
                        note(d, false);
                    }
                });
                *fetched.lock().unwrap_or_else(PoisonError::into_inner) = d.fetched.clone();
                symbolizer.forget_missing();
                symbols::preload(&symbolizer, ids);
                note(&d, true);
                loaded_note();
                save();
            });
        });
    })
}

impl State {
    /// The trace's summary, with what its recording lost.
    fn summary(&self) -> Value {
        let mut s = summary(&self.loaded.trace);
        s["eventsLost"] = json!(self.loaded.lost.events);
        s["buffersLost"] = json!(self.loaded.lost.buffers);
        s
    }

    /// The `symbols` report.
    fn symbols_report(&self) -> Value {
        let Some(frames) = self.report.frames.get() else {
            return json!({"ready": false, "done": false});
        };
        let done = *self
            .report
            .done
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let fetched = self
            .report
            .fetched
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let rows: Vec<Value> = frames
            .wanted
            .iter()
            .map(|id| {
                let key = (id.guid, id.age);
                let status = match self.symbols.status(&id.guid, id.age) {
                    Some(true) if self.report.saved.contains(&key) => "saved",
                    Some(true) => "loaded",
                    Some(false) => "not found",
                    None => "not looked for yet",
                };
                let download = match fetched.get(&key) {
                    Some(Fetched::Cached(_)) => "in the cache",
                    Some(Fetched::Downloaded(_)) => "downloaded",
                    Some(Fetched::Missing) => "on no server",
                    Some(Fetched::BadName) => "a name that can't be fetched",
                    None if self.report.download => "",
                    None => "downloads off",
                };
                json!({
                    "pdb": id.name.rsplit(['\\', '/']).next().unwrap_or(&id.name),
                    "path": id.name,
                    "identity": hexcavator_symbolize::symbol_store_key(&id.guid, id.age),
                    "frames": frames.frames.get(&key).copied().unwrap_or(0),
                    "status": status,
                    "download": download,
                })
            })
            .collect();
        json!({
            "ready": true,
            "done": done,
            "cache": self.report.cache.display().to_string(),
            "rows": rows,
            "noDebug": frames.no_debug.iter().map(|(m, n)| json!({"module": m, "frames": n})).collect::<Vec<_>>(),
        })
    }

    fn handle(&mut self, method: &str, params: &Value) -> Result<Value, String> {
        let trace = &self.loaded.trace;
        match method {
            "summary" => Ok(self.summary()),
            "processes" => {
                let time = TreeSpec::from_json(params)?.time;
                Ok(crate::views::processes(trace, time))
            }
            "events" => Ok(crate::views::events(trace)),
            "events.list" => {
                let guid = params
                    .get("guid")
                    .and_then(Value::as_str)
                    .and_then(hexcavator_etl::Guid::parse)
                    .ok_or("guid: expected a provider's GUID")?;
                let small = |name: &str, max: u64| -> Result<u64, String> {
                    match params.get(name) {
                        None | Some(Value::Null) => Ok(0),
                        Some(v) => v
                            .as_u64()
                            .filter(|&n| n <= max)
                            .ok_or_else(|| format!("{name}: expected a number up to {max}")),
                    }
                };
                let kind = crate::generic::Kind {
                    provider: guid,
                    id: u16::try_from(small("id", 0xffff)?).unwrap_or(0),
                    version: u8::try_from(small("version", 0xff)?).unwrap_or(0),
                    opcode: u8::try_from(small("opcode", 0xff)?).unwrap_or(0),
                };
                let time = ticks(trace, TreeSpec::from_json(params)?.time);
                let offset = usize::try_from(small("offset", u64::MAX)?).unwrap_or(usize::MAX);
                let limit = match params.get("limit") {
                    None | Some(Value::Null) => 1000,
                    Some(_) => usize::try_from(small("limit", 100_000)?).unwrap_or(1000),
                };
                let stacks = params.get("stacks").and_then(Value::as_bool) == Some(true);
                crate::generic::list(
                    trace,
                    &self.loaded.path,
                    kind,
                    time,
                    offset,
                    limit,
                    stacks.then_some((
                        &self.resolver,
                        &*self.symbols as &dyn hexcavator_trace_analysis::Symbolizer,
                    )),
                )
            }
            "threads" => {
                let time = TreeSpec::from_json(params)?.time;
                let process = match params.get("process") {
                    None | Some(Value::Null) => None,
                    Some(p) => {
                        let p = p
                            .as_u64()
                            .and_then(|p| usize::try_from(p).ok())
                            .filter(|&p| p < trace.processes.len())
                            .ok_or("process: expected a process's index")?;
                        Some(p)
                    }
                };
                Ok(crate::views::threads(
                    trace,
                    &self.resolver,
                    &*self.symbols,
                    process,
                    time,
                ))
            }
            "graph" => {
                let buckets = params
                    .get("buckets")
                    .and_then(Value::as_u64)
                    .map_or(1000, |b| usize::try_from(b).unwrap_or(10_000));
                let top = params
                    .get("top")
                    .and_then(Value::as_u64)
                    .map_or(8, |t| usize::try_from(t).unwrap_or(8));
                let spec = TreeSpec::from_json(params)?;
                let highlight = match params.get("highlight") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(crate::views::Highlight::new(
                        trace,
                        &self.resolver,
                        &*self.symbols,
                        v.as_str().ok_or("highlight: expected a function's ID")?,
                    )?),
                };
                let series = crate::views::GraphSeries {
                    by_thread: match params.get("by").and_then(Value::as_str) {
                        None | Some("process") => false,
                        Some("thread") => true,
                        Some(other) => return Err(format!("by: not process or thread: {other}")),
                    },
                    process: match params.get("process") {
                        None | Some(Value::Null) => None,
                        Some(p) => Some(
                            p.as_u64()
                                .and_then(|p| usize::try_from(p).ok())
                                .filter(|&p| p < trace.processes.len())
                                .ok_or("process: expected a process's index")?,
                        ),
                    },
                };
                Ok(crate::views::cpu_graph(
                    trace,
                    spec.source,
                    buckets,
                    spec.time,
                    top,
                    highlight.as_ref(),
                    series,
                ))
            }
            "lines" => {
                let spec = TreeSpec::from_json(params)?;
                let limit = count(params, "limit", 200)?;
                let file = match params.get("file") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(v.as_str().ok_or("file: expected a path")?),
                };
                // (Worked out again when the source, the time or the PDBs
                // loaded change.)
                let key = (spec.source, spec.time, self.symbols.loaded_count());
                let value = match &self.lines {
                    Some((k, v)) if *k == key => Arc::clone(v),
                    _ => {
                        let v = Arc::new(crate::views::line_totals(
                            trace,
                            &self.resolver,
                            &*self.symbols,
                            &spec,
                        ));
                        self.lines = Some((key, Arc::clone(&v)));
                        v
                    }
                };
                Ok(crate::views::lines(
                    &value.0,
                    value.1,
                    value.2,
                    trace.clock.ticks_per_second,
                    file,
                    limit,
                ))
            }
            "disk" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::disk::GroupBy::Process,
                    Some("file") => crate::disk::GroupBy::File,
                    Some("disk") => crate::disk::GroupBy::Disk,
                    Some("type") => crate::disk::GroupBy::Kind,
                    Some(other) => {
                        return Err(format!("by: process, file, disk or type, not {other}"));
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let table = match &self.disk {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::disk::table(trace, &self.loaded.path)?);
                        self.disk = Some(Arc::clone(&t));
                        t
                    }
                };
                let time = ticks(trace, spec.time);
                Ok(crate::disk::summary(trace, &table, group, time, limit))
            }
            "dpc" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("module") => crate::dpc::GroupBy::Module,
                    Some("function") => crate::dpc::GroupBy::Function,
                    Some("processor") => crate::dpc::GroupBy::Processor,
                    Some("type") => crate::dpc::GroupBy::Type,
                    Some(other) => {
                        return Err(format!(
                            "by: module, function, processor or type, not {other}"
                        ));
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let table = match &self.dpcs {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::dpc::table(trace, &self.loaded.path)?);
                        self.dpcs = Some(Arc::clone(&t));
                        t
                    }
                };
                let time = ticks(trace, spec.time);
                Ok(crate::dpc::summary(
                    trace,
                    &table,
                    &self.resolver,
                    &*self.symbols,
                    group,
                    time,
                    limit,
                ))
            }
            "hardfaults" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::hardfault::GroupBy::Process,
                    Some("file") => crate::hardfault::GroupBy::File,
                    Some("thread") => crate::hardfault::GroupBy::Thread,
                    Some(other) => {
                        return Err(format!("by: process, file or thread, not {other}"));
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let group_limit = count(params, "groupLimit", 10_000)?;
                let table = match &self.faults {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::hardfault::table(trace, &self.loaded.path)?);
                        self.faults = Some(Arc::clone(&t));
                        t
                    }
                };
                Ok(crate::hardfault::summary(
                    trace,
                    &table,
                    group,
                    ticks(trace, spec.time),
                    limit,
                    group_limit,
                ))
            }
            "heap" | "pool" => {
                let spec = TreeSpec::from_json(params)?;
                let is_heap = method == "heap";
                let by = params.get("by").and_then(Value::as_str);
                let group = match (is_heap, by) {
                    (true, None | Some("process")) | (false, Some("process")) => {
                        crate::allocs::GroupBy::Process
                    }
                    (_, Some("thread")) => crate::allocs::GroupBy::Thread,
                    (true, Some("heap")) | (false, None | Some("tag")) => {
                        crate::allocs::GroupBy::Group
                    }
                    (false, Some("type")) => crate::allocs::GroupBy::Kind,
                    (_, Some(other)) => {
                        return Err(if is_heap {
                            format!("by: process, heap or thread, not {other}")
                        } else {
                            format!("by: tag, type, process or thread, not {other}")
                        });
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let group_limit = count(params, "groupLimit", 10_000)?;
                let slot = if is_heap {
                    &mut self.heap
                } else {
                    &mut self.pool
                };
                let table = match slot {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(if is_heap {
                            crate::allocs::heap(trace, &self.loaded.path)?
                        } else {
                            crate::allocs::pool(trace, &self.loaded.path)?
                        });
                        *slot = Some(Arc::clone(&t));
                        t
                    }
                };
                let kinds: &[&str] = if is_heap {
                    &["Heap"]
                } else {
                    &crate::allocs::POOL_KINDS
                };
                Ok(crate::allocs::summary(
                    trace,
                    &table,
                    kinds,
                    group,
                    ticks(trace, spec.time),
                    limit,
                    group_limit,
                ))
            }
            "memory" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::memutil::GroupBy::Process,
                    Some("name") => crate::memutil::GroupBy::Name,
                    Some(other) => return Err(format!("by: process or name, not {other}")),
                };
                let limit = count(params, "limit", 1000)?;
                let group_limit = count(params, "groupLimit", 10_000)?;
                let table = match &self.memory {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::memutil::table(trace, &self.loaded.path)?);
                        self.memory = Some(Arc::clone(&t));
                        t
                    }
                };
                Ok(crate::memutil::summary(
                    trace,
                    &table,
                    group,
                    ticks(trace, spec.time),
                    limit,
                    group_limit,
                ))
            }
            "vmem" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::vmem::GroupBy::Process,
                    Some("thread") => crate::vmem::GroupBy::Thread,
                    Some(other) => return Err(format!("by: process or thread, not {other}")),
                };
                let limit = count(params, "limit", 1000)?;
                let group_limit = count(params, "groupLimit", 10_000)?;
                let table = match &self.vmem {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::vmem::table(trace, &self.loaded.path)?);
                        self.vmem = Some(Arc::clone(&t));
                        t
                    }
                };
                Ok(crate::vmem::summary(
                    trace,
                    &table,
                    group,
                    ticks(trace, spec.time),
                    limit,
                    group_limit,
                ))
            }
            "registry" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::registry::GroupBy::Process,
                    Some("key") => crate::registry::GroupBy::Key,
                    Some("operation") => crate::registry::GroupBy::Operation,
                    Some(other) => {
                        return Err(format!("by: process, key or operation, not {other}"));
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let table = match &self.registry {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::registry::table(trace, &self.loaded.path)?);
                        self.registry = Some(Arc::clone(&t));
                        t
                    }
                };
                let time = ticks(trace, spec.time);
                let group_limit = count(params, "groupLimit", 10_000)?;
                Ok(crate::registry::summary(
                    trace,
                    &table,
                    group,
                    time,
                    limit,
                    group_limit,
                ))
            }
            "fileio" => {
                let spec = TreeSpec::from_json(params)?;
                let group = match params.get("by").and_then(Value::as_str) {
                    None | Some("process") => crate::fileio::GroupBy::Process,
                    Some("file") => crate::fileio::GroupBy::File,
                    Some("operation") => crate::fileio::GroupBy::Operation,
                    Some(other) => {
                        return Err(format!("by: process, file or operation, not {other}"));
                    }
                };
                let limit = count(params, "limit", 1000)?;
                let table = match &self.files {
                    Some(t) => Arc::clone(t),
                    None => {
                        let t = Arc::new(crate::fileio::table(trace, &self.loaded.path)?);
                        self.files = Some(Arc::clone(&t));
                        t
                    }
                };
                let time = ticks(trace, spec.time);
                Ok(crate::fileio::summary(trace, &table, group, time, limit))
            }
            "regions" => {
                let file = params
                    .get("file")
                    .and_then(Value::as_str)
                    .filter(|f| !f.is_empty())
                    .ok_or("file: expected a regions file")?;
                crate::regions::regions(trace, &self.loaded.path, std::path::Path::new(file))
            }
            "symbols" => {
                // (`wait`: once the background thread is done.)
                if params.get("wait").and_then(Value::as_bool) == Some(true) {
                    let (lock, ready) = &*self.report.done;
                    let mut done = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    while !*done {
                        done = ready.wait(done).unwrap_or_else(PoisonError::into_inner);
                    }
                }
                Ok(self.symbols_report())
            }
            "functions" => {
                let spec = TreeSpec::from_json(params)?;
                let limit = count(params, "limit", 1000)?;
                Ok(crate::views::functions(
                    trace,
                    &self.resolver,
                    &*self.symbols,
                    &spec,
                    limit,
                ))
            }
            "tree.create" => {
                let spec = TreeSpec::from_json(params)?;
                let view = TreeView::build(
                    trace,
                    &self.resolver,
                    &*self.symbols,
                    self.tags.as_ref(),
                    spec,
                );
                let root = view.row(trace, &*self.symbols, NodeId::ROOT);
                let id = self.next_view;
                self.next_view += 1;
                let unit = match view.unit {
                    Unit::Samples => "samples",
                    Unit::Ticks => "ticks",
                };
                self.views.insert(id, view);
                Ok(json!({
                    "view": id,
                    "unit": unit,
                    "ticksPerSecond": trace.clock.ticks_per_second,
                    "sampleIntervalNs": trace.sample_interval_ns(),
                    "root": root.to_json(),
                }))
            }
            "tree.children" | "tree.hotPath" => {
                let (view, node) = self.view_node(params)?;
                let view = self.views.get_mut(&view).expect("checked");
                let rows = if method == "tree.children" {
                    view.children(trace, &*self.symbols, node)
                } else {
                    let fraction = params
                        .get("fraction")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.1);
                    view.hot_path(trace, &*self.symbols, node, fraction)
                };
                Ok(json!({"rows": rows.iter().map(crate::views::Row::to_json).collect::<Vec<_>>()}))
            }
            "tree.close" => {
                let view = params
                    .get("view")
                    .and_then(Value::as_u64)
                    .ok_or("expected a view")?;
                self.views.remove(&view).ok_or("no such view")?;
                Ok(json!({}))
            }
            _ => Err("unknown method".to_string()),
        }
    }

    /// A request's view and node, checked.
    fn view_node(&self, params: &Value) -> Result<(u64, NodeId), String> {
        let view = params
            .get("view")
            .and_then(Value::as_u64)
            .ok_or("expected a view")?;
        let node = params
            .get("node")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("expected a node")?;
        let v = self.views.get(&view).ok_or("no such view")?;
        let node = NodeId(node);
        if !v.has_node(node) {
            return Err("no such node".to_string());
        }
        Ok((view, node))
    }
}

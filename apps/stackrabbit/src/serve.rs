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
//! - `close` `{trace}` → `{}`.
//! - `summary` `{trace}` → the trace's summary.
//! - `processes` `{trace, time?}` → `{rows}`: the processes, with their
//!   lifetimes, threads and CPU samples (in `time`), heaviest first.
//! - `graph` `{trace, source?, buckets?, time?, top?}` → `{source, startNs,
//!   endNs, buckets, series}`: CPU usage over time, by process, sampled
//!   (`samples`) or precise (`running`, or `waits`: both from context
//!   switches), each series's values the share of all the processors it
//!   used in each bucket.
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

/// Writes a response. A response that can't be written means the editor
/// is gone; the session ends when its input does.
fn send(out: &Output, header: &Value) {
    let mut w = out.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = write_frame(&mut *w, &Frame::new(header.clone()));
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
    };
    send(
        out,
        &json!({"id": open_id, "result": {
            "trace": trace,
            "summary": summary(&state.loaded.trace),
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
    std::thread::spawn(move || {
        let frames = symbols::frames(&loaded.trace);
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
            if symbols::save(path, loaded.source, &frames, &found).is_ok() {
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
    fn handle(&mut self, method: &str, params: &Value) -> Result<Value, String> {
        let trace = &self.loaded.trace;
        match method {
            "summary" => Ok(summary(trace)),
            "processes" => {
                let time = TreeSpec::from_json(params)?.time;
                Ok(crate::views::processes(trace, time))
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
                Ok(crate::views::cpu_graph(
                    trace,
                    spec.source,
                    buckets,
                    spec.time,
                    top,
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

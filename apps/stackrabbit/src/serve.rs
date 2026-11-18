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
//!   stackTagsError}`: `stackTags` is a file of WPA's stack tags, for
//!   grouping by `tag` (its count, or the error that kept it out, comes
//!   back). `trace` names it in
//!   the requests below. Then, if `downloadSymbols` is true, the PDBs its
//!   stacks need are downloaded in the background (into
//!   `symbolCache`, from `symbolServers`; by default `_NT_SYMBOL_PATH`'s,
//!   else WinDbg's cache and Microsoft's server), with notifications
//!   `symbols` `{trace, wanted, cached, downloaded, missing, done}`; when
//!   `done`, trees made after it name the new functions.
//! - `close` `{trace}` → `{}`.
//! - `summary` `{trace}` → the trace's summary.
//! - `graph` `{trace, buckets?, time?, top?}` → `{startNs, endNs, buckets,
//!   series}`: CPU usage (sampled) over time, by process, each series's
//!   values the share of all the processors it used in each bucket.
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
    loaded: Loaded,
    resolver: Resolver,
    /// Shared with the symbols' download, which makes it look again for
    /// what was missing.
    symbols: std::sync::Arc<PdbSymbolizer>,
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
    let mut state = State {
        tags,
        resolver: Resolver::new(&loaded.trace),
        symbols: std::sync::Arc::new(PdbSymbolizer::new(symbols.path.clone())),
        loaded,
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
        }}),
    );
    // What is here already loads at once; the rest downloads meanwhile.
    let mut background = vec![preload_symbols(&state)];
    if symbols.download {
        background.push(download_symbols(trace, &state, symbols, out));
    }
    for r in rx {
        let response = match state.handle(&r.method, &r.params) {
            Ok(result) => json!({"id": r.id, "result": result}),
            Err(e) => json!({"id": r.id, "error": format!("{}: {e}", r.method)}),
        };
        send(out, &response);
    }
    // (The download's last notification is sent before the trace closes.)
    for b in background {
        let _ = b.join();
    }
}

/// Downloads the PDBs the trace's stacks need, in the background, telling
/// the editor how it goes; then the symbolizer looks again for what was
/// missing.
fn download_symbols(trace: u64, state: &State, symbols: &Symbols, out: &Output) -> JoinHandle<()> {
    let ids = symbols::wanted(&state.loaded.trace);
    let servers = symbols.servers.clone();
    let symbolizer = std::sync::Arc::clone(&state.symbols);
    let out = std::sync::Arc::clone(out);
    std::thread::spawn(move || {
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
        let last = std::sync::Mutex::new(std::time::Instant::now());
        let d = symbols::download(&servers, &ids, |d| {
            let mut l = last.lock().unwrap_or_else(PoisonError::into_inner);
            if l.elapsed().as_millis() >= 250 {
                *l = std::time::Instant::now();
                note(d, false);
            }
        });
        symbolizer.forget_missing();
        preload(&symbolizer, &ids);
        note(&d, true);
    })
}

/// Loads the PDBs the trace's stacks need that are here already, in the
/// background, so that trees don't wait for them.
fn preload_symbols(state: &State) -> JoinHandle<()> {
    let ids = symbols::wanted(&state.loaded.trace);
    let symbolizer = std::sync::Arc::clone(&state.symbols);
    std::thread::spawn(move || preload(&symbolizer, &ids))
}

/// Loads `ids`' PDBs (those found), on every core.
fn preload(symbolizer: &PdbSymbolizer, ids: &[hexcavator_symbolize::server::PdbId]) {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    std::thread::scope(|scope| {
        for _ in 0..threads.min(ids.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(id) = ids.get(i) else { return };
                    symbolizer.load(&id.name, &id.guid, id.age);
                }
            });
        }
    });
}

impl State {
    fn handle(&mut self, method: &str, params: &Value) -> Result<Value, String> {
        let trace = &self.loaded.trace;
        match method {
            "summary" => Ok(summary(trace)),
            "graph" => {
                let buckets = params
                    .get("buckets")
                    .and_then(Value::as_u64)
                    .map_or(1000, |b| usize::try_from(b).unwrap_or(10_000));
                let top = params
                    .get("top")
                    .and_then(Value::as_u64)
                    .map_or(8, |t| usize::try_from(t).unwrap_or(8));
                let time = TreeSpec::from_json(params)?.time;
                Ok(crate::views::cpu_graph(trace, buckets, time, top))
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

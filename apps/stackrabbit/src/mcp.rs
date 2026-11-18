//! `stackrabbit mcp`: a Model Context Protocol server on standard input
//! and output, for AI assistants and other MCP clients: tools to open
//! traces and ask them any of the session protocol's requests (the same
//! engine and answers the extension gets; see [`crate::serve`]).
//!
//! Messages are JSON-RPC 2.0, one per line. The tools:
//!
//! - `open_trace` `{path, symbols?}`: opens a trace (from its saved index,
//!   when there is one); with `symbols`, downloads the PDBs its stacks need
//!   first. Answers its `trace` number and summary.
//! - `query` `{trace, method, params?}`: one request of the protocol.
//! - `close_trace` `{trace}`.
//! - `protocol`: the protocol's reference (its requests and answers).
//!
//! What a tool answers is what the trace holds (process names, paths,
//! ...): it goes to the client, which may send it elsewhere.

use std::io::{self, BufRead, PipeReader, PipeWriter, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::{Value, json};

use crate::protocol::{Frame, read_frame, write_frame};
use crate::serve::{Output, serve};

const USAGE: &str = "\
usage: stackrabbit mcp

A Model Context Protocol server on standard input and output (JSON-RPC, a
message a line): tools to open traces and query them, for AI assistants and
other MCP clients. Configure a client to run this command.";

/// The protocol versions this server speaks, newest first.
const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// The session protocol's reference: `serve`'s module documentation.
fn reference() -> String {
    include_str!("serve.rs")
        .lines()
        .take_while(|l| l.starts_with("//!"))
        .map(|l| {
            l.strip_prefix("//! ")
                .unwrap_or(l.trim_start_matches("//!"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs `stackrabbit mcp`.
pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut server = match Server::start() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("stackrabbit mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    for line in stdin.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(answer) = server.message(&line) {
            let _ = writeln!(stdout, "{answer}");
            let _ = stdout.flush();
        }
    }
    server.stop();
    ExitCode::SUCCESS
}

/// An MCP server: a session of the protocol, in-process, behind it.
pub struct Server {
    to_session: Option<PipeWriter>,
    from_session: PipeReader,
    session: Option<JoinHandle<()>>,
    next: u64,
}

impl Server {
    /// Starts the session.
    pub fn start() -> io::Result<Self> {
        let (session_in, to_session) = io::pipe()?;
        let (from_session, session_out) = io::pipe()?;
        let out: Output = Arc::new(Mutex::new(session_out));
        let session = std::thread::spawn(move || {
            let _ = serve(session_in, &out);
        });
        Ok(Self {
            to_session: Some(to_session),
            from_session,
            session: Some(session),
            next: 1,
        })
    }

    /// Ends the session.
    pub fn stop(&mut self) {
        let _ = self.ask("shutdown", json!({}));
        self.to_session = None;
        if let Some(s) = self.session.take() {
            let _ = s.join();
        }
    }

    /// One request of the session: its answer (`Err`: its error).
    fn ask(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next;
        self.next += 1;
        let to = self.to_session.as_mut().ok_or("the session has ended")?;
        write_frame(
            to,
            &Frame::new(json!({"id": id, "method": method, "params": params})),
        )
        .map_err(|e| e.to_string())?;
        // (Notifications, and nothing else, come between.)
        loop {
            let frame = read_frame(&mut self.from_session)
                .map_err(|e| e.to_string())?
                .ok_or("the session has ended")?;
            if frame.header.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(e) = frame.header.get("error") {
                return Err(e.as_str().map_or_else(|| e.to_string(), str::to_string));
            }
            return Ok(frame.header.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Answers one JSON-RPC message (a line): its answer, if it has one
    /// (notifications don't).
    pub fn message(&mut self, line: &str) -> Option<Value> {
        let Ok(m) = serde_json::from_str::<Value>(line) else {
            return Some(rpc_error(&Value::Null, -32700, "not JSON"));
        };
        let id = m.get("id").cloned();
        let method = m.get("method").and_then(Value::as_str).unwrap_or("");
        let params = m.get("params").cloned().unwrap_or(json!({}));
        let result = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                let version = asked
                    .filter(|v| VERSIONS.contains(v))
                    .unwrap_or(VERSIONS[0]);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "stackrabbit", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Stackrabbit reads Windows performance traces (.etl): open one with \
                        open_trace, then ask it requests with query (protocol lists them).",
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => Ok(self.call(&params)),
            // (Notifications: initialized, cancelled, ...)
            _ if id.is_none() => return None,
            other => Err((-32601, format!("{other}: unknown method"))),
        };
        let id = id?;
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, e)) => rpc_error(&id, code, &e),
        })
    }

    /// A tool's answer: its text, or its error (`isError`).
    fn call(&mut self, params: &Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let answer = match name {
            "open_trace" => self.open(&args),
            "query" => (|| {
                let trace = args
                    .get("trace")
                    .and_then(Value::as_u64)
                    .ok_or("trace: expected a number")?;
                let method = args
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or("method: expected a name")?;
                if matches!(method, "open" | "close" | "shutdown" | "hello") {
                    return Err(format!("{method}: use open_trace or close_trace"));
                }
                let mut p = match args.get("params") {
                    None | Some(Value::Null) => json!({}),
                    Some(Value::Object(o)) => Value::Object(o.clone()),
                    // (Some clients send objects as JSON text.)
                    Some(Value::String(s)) => serde_json::from_str(s)
                        .ok()
                        .filter(Value::is_object)
                        .ok_or("params: expected an object")?,
                    Some(_) => return Err("params: expected an object".to_string()),
                };
                p["trace"] = json!(trace);
                self.ask(method, p)
            })(),
            "close_trace" => match args.get("trace").and_then(Value::as_u64) {
                Some(t) => self.ask("close", json!({"trace": t})),
                None => Err("trace: expected a number".to_string()),
            },
            "protocol" => Ok(Value::String(reference())),
            other => Err(format!("{other}: no such tool")),
        };
        match answer {
            Ok(Value::String(s)) => json!({"content": [{"type": "text", "text": s}]}),
            Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}]}),
            Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
        }
    }

    /// `open_trace`: the trace opened (and with `symbols`, its PDBs).
    fn open(&mut self, args: &Value) -> Result<Value, String> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or("path: expected a trace's path")?;
        let symbols = args
            .get("symbols")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let opened = self.ask(
            "open",
            json!({"path": path, "useIndex": true, "downloadSymbols": symbols}),
        )?;
        let trace = opened.get("trace").cloned().unwrap_or(Value::Null);
        if symbols {
            self.ask("symbols", json!({"trace": trace, "wait": true}))?;
        }
        Ok(json!({"trace": trace, "summary": opened.get("summary")}))
    }
}

/// A JSON-RPC error.
fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// The tools, as `tools/list` describes them.
fn tools() -> Value {
    json!([
        {
            "name": "open_trace",
            "description": "Open a Windows performance trace (.etl). Answers its trace number (for \
                query) and a summary: duration, processors, processes, threads, samples, events lost.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "The trace file's path."},
                    "symbols": {"type": "boolean", "description": "Download the PDBs its stacks \
                        need first, so functions are named (slower the first time)."},
                },
                "required": ["path"],
            },
        },
        {
            "name": "query",
            "description": "Ask an open trace one request: e.g. processes, threads, functions \
                (hot functions), graph, tree.create, events (event kinds), events.list, disk, \
                fileio, dpc, registry, hardfaults, vmem, heap, pool, memory, regions. Time ranges \
                are [startNs, endNs] from the trace's start. The protocol tool has every request's \
                parameters and answer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace": {"type": "integer", "description": "From open_trace."},
                    "method": {"type": "string", "description": "The request, e.g. \"disk\"."},
                    "params": {"type": "object", "description": "Its parameters, e.g. \
                        {\"by\": \"file\", \"time\": [0, 5000000000]}."},
                },
                "required": ["trace", "method"],
            },
        },
        {
            "name": "close_trace",
            "description": "Close an open trace.",
            "inputSchema": {
                "type": "object",
                "properties": {"trace": {"type": "integer"}},
                "required": ["trace"],
            },
        },
        {
            "name": "protocol",
            "description": "The reference for query: every request, its parameters and its answer.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ])
}

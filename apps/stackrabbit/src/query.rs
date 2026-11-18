//! `stackrabbit query`: one request of the session protocol (see
//! [`crate::serve`]) on a trace, from the command line: the trace opened,
//! the request answered, the answer printed as JSON, or one of its lists
//! as CSV. For scripts, and for comparing with other tools' numbers.

use std::io::{self, Cursor, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use crate::protocol::{Frame, read_frame, write_frame};
use crate::serve::{Output, serve};

const USAGE: &str = "\
usage: stackrabbit query [options] <trace> <method> [name=value]...

Opens <trace>, asks it one request of the session protocol (the methods the
extension uses: disk, fileio, registry, events, threads, ...; see the serve
module's documentation), and prints the answer. Each name=value is one of the
request's parameters; a value that reads as JSON (a number, true, [0, 5000]) is
that, else it's text. The trace's own parameter is filled in.

Options:
  -csv <list>   Print the answer's list <list> (\"groups\", \"rows\", ...; \".\"
                for an answer that is a list) as CSV: a column per field, in
                the order the first row has them; other values as JSON.
  -symbols      Download the PDBs the trace's stacks need (to the symbol cache:
                _NT_SYMBOL_PATH's, else WinDbg's), and wait for them first.
  -no-index     Import the trace rather than open its saved index.";

/// Runs `stackrabbit query`.
pub fn run(args: &[String]) -> ExitCode {
    match query(args) {
        Ok(text) => {
            let mut out = io::stdout().lock();
            let _ = out.write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(Failure::Usage(e)) => {
            eprintln!("stackrabbit query: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Answer(e)) => {
            eprintln!("stackrabbit query: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Why a query failed.
#[derive(Debug)]
pub enum Failure {
    /// The command line was wrong.
    Usage(String),
    /// The trace or the request failed.
    Answer(String),
}

/// What `args` ask, answered: the text to print.
pub fn query(args: &[String]) -> Result<String, Failure> {
    let mut csv = None;
    let mut symbols = false;
    let mut use_index = true;
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-csv" | "--csv" => {
                csv = Some(
                    it.next()
                        .ok_or_else(|| Failure::Usage("-csv: expected a list's name".into()))?
                        .clone(),
                );
            }
            "-symbols" | "--symbols" => symbols = true,
            "-no-index" | "--no-index" => use_index = false,
            "-h" | "-help" | "--help" => return Err(Failure::Usage("help".into())),
            s if s.starts_with('-') && positional.len() < 2 => {
                return Err(Failure::Usage(format!("unknown option {s}")));
            }
            _ => positional.push(a.clone()),
        }
    }
    let [path, method, rest @ ..] = positional.as_slice() else {
        return Err(Failure::Usage("expected a trace and a method".into()));
    };
    let mut params = Map::new();
    for p in rest {
        let (name, value) = p
            .split_once('=')
            .ok_or_else(|| Failure::Usage(format!("'{p}': expected name=value")))?;
        let value = serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.into()));
        params.insert(name.to_string(), value);
    }
    let answer = ask(path, method, Value::Object(params), use_index, symbols)?;
    match csv {
        None => Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&answer).unwrap_or_default()
        )),
        Some(list) => {
            let rows = if list == "." {
                &answer
            } else {
                answer.get(&list).ok_or_else(|| {
                    let lists: Vec<&str> = answer
                        .as_object()
                        .map(|o| {
                            o.iter()
                                .filter(|(_, v)| v.is_array())
                                .map(|(k, _)| k.as_str())
                                .collect()
                        })
                        .unwrap_or_default();
                    Failure::Usage(format!(
                        "-csv: the answer has no list '{list}' (it has: {})",
                        lists.join(", ")
                    ))
                })?
            };
            let rows = rows
                .as_array()
                .ok_or_else(|| Failure::Usage(format!("-csv: '{list}' isn't a list")))?;
            Ok(to_csv(rows))
        }
    }
}

/// A writer the session's answers go to, kept to read back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A session of: open `path`, (with `symbols`, wait for its symbols,)
/// then `method` with `params` (and the trace); its answer.
pub fn ask(
    path: &str,
    method: &str,
    mut params: Value,
    use_index: bool,
    symbols: bool,
) -> Result<Value, Failure> {
    let mut input = Vec::new();
    let mut frame = |id: u64, method: &str, params: Value| {
        let _ = write_frame(
            &mut input,
            &Frame::new(json!({"id": id, "method": method, "params": params})),
        );
    };
    frame(
        1,
        "open",
        json!({"path": path, "useIndex": use_index, "downloadSymbols": symbols}),
    );
    // (The session's first trace is 1.)
    if symbols {
        frame(2, "symbols", json!({"trace": 1, "wait": true}));
    }
    params["trace"] = json!(1);
    frame(3, method, params);
    frame(4, "shutdown", json!({}));
    let captured = Captured::default();
    let out: Output = Arc::new(Mutex::new(captured.clone()));
    serve(Cursor::new(input), &out).map_err(|e| Failure::Answer(e.to_string()))?;
    let bytes = captured
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut reader = Cursor::new(bytes);
    let mut answer = None;
    while let Ok(Some(f)) = read_frame(&mut reader) {
        let id = f.header.get("id").and_then(Value::as_u64);
        if let Some(e) = f.header.get("error").filter(|_| id.is_some()) {
            let what = e.as_str().map_or_else(|| e.to_string(), str::to_string);
            // (Errors name what they're about.)
            return Err(Failure::Answer(what));
        }
        if id == Some(3) {
            answer = f.header.get("result").cloned();
        }
    }
    answer.ok_or_else(|| Failure::Answer(format!("{method}: no answer")))
}

/// `rows` (objects) as CSV: a header of their fields (the first row's, in
/// order, then any others as they appear), then a line per row; text as
/// itself, null as nothing, other values as JSON; quoted where needed.
pub fn to_csv(rows: &[Value]) -> String {
    let mut columns: Vec<String> = Vec::new();
    for r in rows {
        if let Some(o) = r.as_object() {
            for k in o.keys() {
                if !columns.contains(k) {
                    columns.push(k.clone());
                }
            }
        }
    }
    let scalar_rows = columns.is_empty();
    if scalar_rows {
        columns.push("value".to_string());
    }
    let cell = |v: Option<&Value>| -> String {
        let text = match v {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
        };
        if text.contains([',', '"', '\n', '\r']) || text.starts_with(' ') || text.ends_with(' ') {
            format!("\"{}\"", text.replace('"', "\"\""))
        } else {
            text
        }
    };
    let mut out = String::new();
    let header: Vec<String> = columns
        .iter()
        .map(|c| cell(Some(&Value::String(c.clone()))))
        .collect();
    out.push_str(&header.join(","));
    out.push_str("\r\n");
    for r in rows {
        let line: Vec<String> = if scalar_rows {
            vec![cell(Some(r))]
        } else {
            columns.iter().map(|c| cell(r.get(c))).collect()
        };
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
}

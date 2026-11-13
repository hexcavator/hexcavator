//! `hexc serve`: hexc's commands, for an editor, from one process that
//! keeps what they read.
//!
//! Requests come on standard input and responses go to standard output,
//! one JSON object per line. A request is a command line, as hexc would be
//! given it:
//!
//! ```text
//! {"id": 1, "args": ["size", "-d", "symbols", "app.exe"]}
//! ```
//!
//! and its response is what the command printed and its exit code:
//!
//! ```text
//! {"id": 1, "code": 0, "stdout": "...", "stderr": ""}
//! ```
//!
//! or, for a request that isn't one, `{"id": ..., "error": "..."}`.
//! Requests run at once, each on its own thread, and are answered as they
//! finish (in any order). What commands build from a program (its model
//! and symbols) is kept in memory, so that the next command on it starts
//! from there, until its files change (see `hexcavator_program::cache`).
//! At the end of input, the requests running finish and are answered.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc serve

Runs hexc's commands for an editor, keeping what they read from each binary
(its model and symbols) in memory for the next. Requests on standard input,
one JSON object per line: {\"id\": 1, \"args\": [\"size\", \"app.exe\"]}.
Responses on standard output, one per line, as each finishes:
{\"id\": 1, \"code\": 0, \"stdout\": \"...\", \"stderr\": \"...\"}.";

/// The stack each request runs on: as the command line's main thread may
/// have (commands recurse into what files hold, within bounds).
const STACK: usize = 8 << 20;

pub fn run(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    hexcavator_program::cache::keep_in_memory(true);
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let result = serve(io::stdin().lock(), &stdout);
    if let Err(e) = result {
        ereport!("hexc serve: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Answers the requests read from `input` on `output`, then waits for the
/// last to be answered.
fn serve<W: Write + Send + 'static>(input: impl BufRead, output: &Arc<Mutex<W>>) -> io::Result<()> {
    let mut running = Vec::new();
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (id, args) = match request(&line) {
            Ok(r) => r,
            Err((id, e)) => {
                send(output, &json!({ "id": id, "error": e }))?;
                continue;
            }
        };
        let output = Arc::clone(output);
        let spawned = std::thread::Builder::new()
            .name("hexc serve".into())
            .stack_size(STACK)
            .spawn(move || {
                let _ = send(&output, &answer(&id, &args));
            })?;
        running.push(spawned);
        // (Those that have finished needn't wait to be joined.)
        running.retain(|t| !t.is_finished());
    }
    for t in running {
        let _ = t.join();
    }
    Ok(())
}

/// A request's id and arguments; or its id (if it has one) and what is
/// wrong with it.
fn request(line: &str) -> Result<(Value, Vec<String>), (Value, String)> {
    let v: Value =
        serde_json::from_str(line).map_err(|e| (Value::Null, format!("not JSON: {e}")))?;
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let args = v
        .get("args")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter()
                .map(|x| x.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| (id.clone(), "`args` must be an array of strings".to_owned()))?;
    match args.first().map(String::as_str) {
        Some(c @ ("serve" | "mcp")) => Err((id, format!("'{c}' is not a command to serve"))),
        _ => Ok((id, args)),
    }
}

/// Runs the command `args`, and its response to request `id`.
fn answer(id: &Value, args: &[String]) -> Value {
    let (code, out) = crate::out::capture(|| {
        std::panic::catch_unwind(|| crate::command(args)).unwrap_or_else(|_| {
            ereport!("hexc: internal error (a bug: please report it)");
            ExitCode::from(101)
        })
    });
    json!({
        "id": id,
        "code": code_of(code),
        "stdout": String::from_utf8_lossy(&out.stdout),
        "stderr": String::from_utf8_lossy(&out.stderr),
    })
}

/// `code` as a number. (An exit code says only whether it equals another.)
fn code_of(code: ExitCode) -> u8 {
    (0..=u8::MAX)
        .find(|&n| ExitCode::from(n) == code)
        .unwrap_or(1)
}

/// Writes `message`, a line, whole.
fn send<W: Write>(output: &Mutex<W>, message: &Value) -> io::Result<()> {
    let mut line = message.to_string();
    line.push('\n');
    let mut out = output.lock().unwrap_or_else(PoisonError::into_inner);
    out.write_all(line.as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(input: &str) -> Vec<Value> {
        let out = Arc::new(Mutex::new(Vec::new()));
        serve(input.as_bytes(), &out).unwrap();
        let bytes = std::mem::take(&mut *out.lock().unwrap());
        let mut all: Vec<Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // (Answered as they finish: put them in order.)
        all.sort_by_key(|v| v["id"].as_i64().unwrap_or(-1));
        all
    }

    #[test]
    fn commands_answer_with_their_output_and_code() {
        let all = exchange(concat!(
            "{\"id\": 1, \"args\": [\"version\"]}\n",
            "\n",
            "{\"id\": 2, \"args\": [\"nonesuch\"]}\n",
        ));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0]["code"], 0);
        assert_eq!(
            all[0]["stdout"],
            format!("hexc {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(all[0]["stderr"], "");
        assert_eq!(all[1]["code"], 2);
        assert_eq!(all[1]["stdout"], "");
        assert!(
            all[1]["stderr"]
                .as_str()
                .unwrap()
                .starts_with("hexc: unknown command 'nonesuch'")
        );
    }

    #[test]
    fn requests_that_are_not_are_errors() {
        let all = exchange(concat!(
            "not json\n",
            "{\"id\": 3}\n",
            "{\"id\": 4, \"args\": [\"size\", 5]}\n",
            "{\"id\": 5, \"args\": [\"serve\"]}\n",
            "{\"id\": 6, \"args\": [\"mcp\"]}\n",
        ));
        assert_eq!(all.len(), 5);
        assert!(all[0]["id"].is_null());
        for (v, id) in all[1..].iter().zip(3..) {
            assert_eq!(v["id"], id);
            assert!(v["error"].is_string(), "{v}");
            assert!(v.get("code").is_none());
        }
    }

    #[test]
    fn exit_codes_are_numbers() {
        assert_eq!(code_of(ExitCode::SUCCESS), 0);
        assert_eq!(code_of(ExitCode::FAILURE), 1);
        assert_eq!(code_of(ExitCode::from(2)), 2);
        assert_eq!(code_of(ExitCode::from(255)), 255);
    }
}

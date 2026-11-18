//! The command-line tools: synth, tree and bench, through the binary.

use std::process::{Command, Output};

use serde_json::Value;

use crate::common::{scratch, small, write_trace};

fn stackrabbit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stackrabbit"))
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn synth_writes_a_trace_and_its_truth() {
    let dir = scratch("cli-synth");
    let etl = dir.join("s.etl");
    let truth = dir.join("s.json");
    let o = stackrabbit(&[
        "synth",
        etl.to_str().unwrap(),
        "-processors",
        "2",
        "-duration-ms",
        "100",
        "-processes",
        "3",
        "-truth",
        truth.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let expected = hexcavator_trace_synth::generate(&hexcavator_trace_synth::Config {
        processors: 2,
        duration_ms: 100,
        processes: 3,
        ..hexcavator_trace_synth::Config::default()
    });
    assert_eq!(std::fs::read(&etl).unwrap(), expected.etl);
    let t: Value = serde_json::from_slice(&std::fs::read(&truth).unwrap()).unwrap();
    assert_eq!(t["samples"], expected.truth.samples);
    assert_eq!(
        t["functions"].as_array().unwrap().len(),
        expected.truth.functions.len()
    );
    assert_eq!(t["processes"].as_array().unwrap().len(), 3);
}

#[test]
fn synth_refuses_bad_options() {
    for args in [
        &["synth"][..],
        &["synth", "x.etl", "-processors", "0"],
        &["synth", "x.etl", "-pointer-size", "6"],
        &["synth", "x.etl", "-processes", "many"],
        &["synth", "x.etl", "-bogus"],
        &["synth", "x.etl", "y.etl"],
    ] {
        let o = stackrabbit(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn tree_prints_processes_heaviest_first() {
    let dir = scratch("cli-tree");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let o = stackrabbit(&[
        "tree",
        path.to_str().unwrap(),
        "-depth",
        "1",
        "-top",
        "100",
        "-frames",
        "module",
        "-no-index",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = text(&o);
    let mut heaviest = s.truth.processes.clone();
    heaviest.sort_by_key(|p| std::cmp::Reverse(p.samples));
    let top = &heaviest[0];
    assert!(
        out.contains(&format!("{} ({})", top.name, top.pid)),
        "{out}"
    );
    // The header and one line per process with samples (and Idle).
    let with_samples = s.truth.processes.iter().filter(|p| p.samples > 0).count();
    assert_eq!(out.lines().count(), 1 + with_samples + 1, "{out}");
    assert!(
        !dir.join("t.etl.hxtrace").exists(),
        "-no-index writes no index"
    );
}

#[test]
fn tree_prints_a_hot_path() {
    let dir = scratch("cli-hot");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let o = stackrabbit(&[
        "tree",
        path.to_str().unwrap(),
        "-hot",
        "-group",
        "",
        "-frames",
        "module",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // Indented one more level each line.
    let indents: Vec<usize> = text(&o)
        .lines()
        .skip(1)
        .map(|l| l.len() - l.trim_start().len())
        .collect();
    assert!(indents.len() > 1);
    assert!(indents.windows(2).all(|w| w[1] == w[0] + 2), "{indents:?}");
}

#[test]
fn bench_reports_counts_and_timings_as_json() {
    let dir = scratch("cli-bench");
    let (a, sa) = write_trace(&dir, "a.etl", &small());
    let (_, sb) = write_trace(
        &dir,
        "b.etl",
        &hexcavator_trace_synth::Config {
            seed: 3,
            compress: true,
            ..small()
        },
    );
    std::fs::write(dir.join("notes.txt"), "not a trace").unwrap();
    // A file and a directory: the directory's traces, by name.
    let o = stackrabbit(&["bench", a.to_str().unwrap(), dir.to_str().unwrap(), "-json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let lines: Vec<Value> = text(&o)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let names: Vec<&str> = lines.iter().map(|l| l["trace"].as_str().unwrap()).collect();
    assert_eq!(names, ["a.etl", "a.etl", "b.etl"]);
    assert_eq!(lines[0]["samples"], sa.truth.samples);
    assert_eq!(lines[2]["samples"], sb.truth.samples);
    for l in &lines {
        assert_eq!(l["stacksUnmatched"], 0);
        assert!(l["importSeconds"].as_f64().unwrap() >= 0.0);
        assert!(l["indexBytes"].as_u64().unwrap() > 0);
    }
}

#[test]
fn bench_prints_a_table() {
    let dir = scratch("cli-bench-table");
    let (a, _) = write_trace(&dir, "a.etl", &small());
    let o = stackrabbit(&["bench", a.to_str().unwrap()]);
    assert!(o.status.success());
    let out = text(&o);
    assert!(out.lines().next().unwrap().starts_with("trace"));
    assert!(out.lines().nth(1).unwrap().starts_with("a.etl"));
}

#[test]
fn unknown_commands_and_help() {
    assert_eq!(stackrabbit(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(stackrabbit(&[]).status.code(), Some(2));
    let h = stackrabbit(&["help"]);
    assert!(h.status.success());
    assert!(text(&h).contains("serve"));
    let v = stackrabbit(&["version"]);
    assert!(text(&v).starts_with("stackrabbit "));
}

#[test]
fn query_answers_a_request_as_json_or_csv() {
    let dir = scratch("cli-query");
    let (path, _) = write_trace(&dir, "q.etl", &small());
    let path = path.to_str().unwrap();
    // JSON: the answer, the trace filled in.
    let o = stackrabbit(&["query", path, "processes"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let answer: Value = serde_json::from_str(&text(&o)).unwrap();
    let rows = answer["rows"].as_array().unwrap();
    // (Its 4 processes, and the idle and system processes.)
    assert_eq!(rows.len(), 6);
    // CSV: a list of it, a column per field (in the first row's order).
    let o = stackrabbit(&["query", "-csv", "rows", path, "processes"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let csv = text(&o);
    let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), rows.len() + 1);
    let header: Vec<&str> = lines[0].split(',').collect();
    let first: Vec<&str> = rows[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(header, first);
    // Parameters: JSON where they read as it (a time range), else text.
    let o = stackrabbit(&["query", "-no-index", path, "processes", "time=[0, 1000000]"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let narrow: Value = serde_json::from_str(&text(&o)).unwrap();
    let samples = |v: &Value| -> u64 {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["samples"].as_u64().unwrap_or(0))
            .sum()
    };
    assert!(samples(&narrow) < samples(&answer), "1 ms of 300");
    // Errors: the request's, the trace's, the command line's.
    let o = stackrabbit(&["query", path, "nosuch"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("nosuch"));
    let o = stackrabbit(&["query", path, "disk", "by=nonsense"]);
    assert_eq!(o.status.code(), Some(1));
    let missing = dir.join("missing.etl");
    let o = stackrabbit(&["query", missing.to_str().unwrap(), "processes"]);
    assert_eq!(o.status.code(), Some(1));
    let o = stackrabbit(&["query", "-csv", "nolist", path, "processes"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("rows"),
        "names the lists there are"
    );
    let o = stackrabbit(&["query", path, "processes", "novalue"]);
    assert_eq!(o.status.code(), Some(2));
    let o = stackrabbit(&["query", path]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn mcp_serves_tools_to_open_and_query_traces() {
    use std::io::Write as _;
    use std::process::Stdio;
    let dir = scratch("cli-mcp");
    let (path, _) = write_trace(&dir, "m.etl", &small());
    let messages = [
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "open_trace", "arguments": {"path": path}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "query", "arguments": {"trace": 1, "method": "processes"}}}),
        // (Parameters as JSON text, as some clients send them.)
        serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "query", "arguments": {"trace": 1, "method": "processes", "params": "{\"time\": [0, 1000000]}"}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "query", "arguments": {"trace": 1, "method": "nosuch"}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "query", "arguments": {"trace": 1, "method": "shutdown"}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "protocol", "arguments": {}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "nosuch", "arguments": {}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "open_trace", "arguments": {"path": dir.join("missing.etl")}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "close_trace", "arguments": {"trace": 1}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "query", "arguments": {"trace": 1, "method": "processes"}}}),
        serde_json::json!({"jsonrpc": "2.0", "id": 13, "method": "ping"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 14, "method": "resources/list"}),
    ];
    let mut input: String = messages.iter().map(|m| format!("{m}\n")).collect();
    input.push_str("not json\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_stackrabbit"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let answers: Vec<Value> = text(&out)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // An answer to each request, none to the notification, in order.
    let ids: Vec<Value> = answers.iter().map(|a| a["id"].clone()).collect();
    let mut want: Vec<Value> = (1..=14)
        .filter(|&i| i != 0)
        .map(|i| serde_json::json!(i))
        .collect();
    want.push(Value::Null);
    assert_eq!(ids, want);
    let by_id = |i: usize| &answers[i - 1];
    assert_eq!(by_id(1)["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(by_id(1)["result"]["serverInfo"]["name"], "stackrabbit");
    let tools: Vec<&str> = by_id(2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["open_trace", "query", "close_trace", "protocol"]);
    let tool_text = |i: usize| -> String {
        by_id(i)["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let is_error = |i: usize| by_id(i)["result"]["isError"] == true;
    let opened: Value = serde_json::from_str(&tool_text(3)).unwrap();
    assert_eq!(opened["trace"], 1);
    assert!(opened["summary"]["processes"].as_u64().unwrap() > 0);
    let all: Value = serde_json::from_str(&tool_text(4)).unwrap();
    let narrow: Value = serde_json::from_str(&tool_text(5)).unwrap();
    let samples = |v: &Value| -> u64 {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["samples"].as_u64().unwrap_or(0))
            .sum()
    };
    assert!(samples(&narrow) < samples(&all));
    assert!(is_error(6) && tool_text(6).contains("nosuch"));
    assert!(
        is_error(7) && tool_text(7).contains("open_trace"),
        "no shutdown by query"
    );
    assert!(
        tool_text(8).contains("`registry`"),
        "the protocol's reference"
    );
    assert!(is_error(9));
    assert!(is_error(10) && tool_text(10).contains("missing.etl"));
    assert!(!is_error(11));
    assert!(is_error(12), "closed");
    assert_eq!(by_id(13)["result"], serde_json::json!({}));
    assert_eq!(by_id(14)["error"]["code"], -32601);
    assert_eq!(answers[14]["error"]["code"], -32700);
}

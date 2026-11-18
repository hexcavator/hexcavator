//! The session: requests in, answers out, checked against a synthetic
//! trace's exact answers; in process, and through the binary.

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stackrabbit::protocol::{Frame, read_frame, write_frame};
use stackrabbit::serve::{Output, serve};

use crate::common::{scratch, small, write_trace};

/// Runs a session of `requests` (each gets `id` = its index + 1) and
/// returns the answers by ID.
fn session(requests: &[Value]) -> HashMap<u64, Value> {
    let mut input = Vec::new();
    for (i, r) in requests.iter().enumerate() {
        let mut r = r.clone();
        r["id"] = json!(i + 1);
        write_frame(&mut input, &Frame::new(r)).unwrap();
    }
    let sink = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out: Output = sink.clone();
    serve(Cursor::new(input), &out).unwrap();
    let data = sink.lock().unwrap().clone();
    let mut r = Cursor::new(data);
    let mut answers = HashMap::new();
    while let Some(f) = read_frame(&mut r).unwrap() {
        let id = f.header["id"].as_u64().expect("answers have IDs");
        assert!(
            answers.insert(id, f.header).is_none(),
            "one answer per request"
        );
    }
    answers
}

fn result(answers: &HashMap<u64, Value>, id: u64) -> &Value {
    let a = &answers[&id];
    assert!(a.get("error").is_none(), "request {id} failed: {a}");
    &a["result"]
}

fn error(answers: &HashMap<u64, Value>, id: u64) -> String {
    answers[&id]["error"]
        .as_str()
        .unwrap_or_else(|| panic!("request {id} should fail: {}", answers[&id]))
        .to_string()
}

#[test]
fn a_tree_by_process_matches_the_truth() {
    let dir = scratch("serve-tree");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "hello"}),
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.create", "params": {"trace": 1, "groupBy": ["process"], "frames": "module"}}),
        json!({"method": "tree.children", "params": {"trace": 1, "view": 1, "node": 0}}),
        json!({"method": "summary", "params": {"trace": 1}}),
    ]);
    assert_eq!(result(&a, 1)["version"], env!("CARGO_PKG_VERSION"));
    let open = result(&a, 2);
    assert_eq!(open["trace"], 1);
    assert_eq!(open["opened"]["how"], "import");
    assert_eq!(open["opened"]["decodeErrors"], 0);
    assert_eq!(open["opened"]["stacksUnmatched"], 0);
    assert_eq!(open["summary"]["samples"], s.truth.samples);
    assert_eq!(open["summary"]["switches"], s.truth.switches);

    let tree = result(&a, 3);
    assert_eq!(tree["unit"], "samples");
    assert_eq!(tree["root"]["inclusive"], s.truth.samples);
    assert_eq!(tree["root"]["hasChildren"], true);

    // Each process's row: its name and process ID, and its samples.
    let rows = result(&a, 4)["rows"].as_array().unwrap();
    for p in &s.truth.processes {
        let label = format!("{} ({})", p.name, p.pid);
        let row = rows.iter().find(|r| r["label"] == label.as_str());
        let samples = row.map_or(0, |r| r["inclusive"].as_u64().unwrap());
        assert_eq!(samples, p.samples, "{label}");
    }
    let idle = rows.iter().find(|r| r["label"] == "Idle (0)").unwrap();
    assert_eq!(idle["inclusive"], s.truth.idle_samples);
    // Heaviest first, each at depth 1 under the root.
    let weights: Vec<u64> = rows
        .iter()
        .map(|r| r["inclusive"].as_u64().unwrap())
        .collect();
    assert!(weights.windows(2).all(|w| w[0] >= w[1]));
    assert!(rows.iter().all(|r| r["depth"] == 1 && r["parent"] == 0));
    assert_eq!(result(&a, 5)["samples"], s.truth.samples);
}

#[test]
fn the_hot_path_runs_down_the_heaviest_children() {
    let dir = scratch("serve-hot");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.create", "params": {"trace": 1, "groupBy": [], "frames": "module"}}),
        json!({"method": "tree.hotPath", "params": {"trace": 1, "view": 1, "node": 0, "fraction": 0.0}}),
    ]);
    let rows = result(&a, 3)["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    // Each row is the previous one's child, one level deeper, no heavier.
    let mut parent = 0;
    let mut weight = u64::MAX;
    for (depth, r) in rows.iter().enumerate() {
        assert_eq!(r["parent"], parent);
        assert_eq!(r["depth"], depth + 1);
        let w = r["inclusive"].as_u64().unwrap();
        assert!(w <= weight);
        parent = r["id"].as_u64().unwrap();
        weight = w;
    }
    assert_eq!(
        rows.last().unwrap()["hasChildren"],
        false,
        "it ends at a leaf"
    );
}

#[test]
fn an_index_is_saved_and_used_next_time() {
    let dir = scratch("serve-index");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let first = session(&[json!({"method": "open", "params": {"path": path}})]);
    let opened = &result(&first, 1)["opened"];
    assert_eq!(opened["how"], "import");
    let index = opened["index"].as_str().expect("an index was saved");
    assert!(index.ends_with("t.etl.hxtrace"));
    let second = session(&[json!({"method": "open", "params": {"path": path}})]);
    let r = result(&second, 1);
    assert_eq!(r["opened"]["how"], "index");
    assert_eq!(r["summary"]["samples"], s.truth.samples);

    // A changed trace makes its index stale: it is imported again.
    let (_, other) = write_trace(
        &dir,
        "t.etl",
        &hexcavator_trace_synth::Config { seed: 9, ..small() },
    );
    let third = session(&[json!({"method": "open", "params": {"path": path}})]);
    let r = result(&third, 1);
    assert_eq!(r["opened"]["how"], "import");
    assert_eq!(r["summary"]["samples"], other.truth.samples);
}

#[test]
fn trees_of_switches_weigh_ticks() {
    let dir = scratch("serve-waits");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.create", "params": {"trace": 1, "source": "waits"}}),
        json!({"method": "tree.create", "params": {"trace": 1, "source": "running", "invert": true}}),
    ]);
    for id in [2, 3] {
        let r = result(&a, id);
        assert_eq!(r["unit"], "ticks");
        assert!(r["root"]["inclusive"].as_u64().unwrap() > 0);
    }
    assert_eq!(result(&a, 2)["view"], 1);
    assert_eq!(result(&a, 3)["view"], 2);
}

#[test]
fn a_time_range_keeps_only_its_samples() {
    let dir = scratch("serve-time");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.create", "params": {"trace": 1, "time": [0, i64::MAX]}}),
        json!({"method": "tree.create", "params": {"trace": 1, "time": [0, 0]}}),
        json!({"method": "tree.create", "params": {"trace": 1, "time": [0, 150_000_000]}}),
    ]);
    assert_eq!(result(&a, 2)["root"]["inclusive"], s.truth.samples);
    assert_eq!(result(&a, 3)["root"]["inclusive"], 0);
    let half = result(&a, 4)["root"]["inclusive"].as_u64().unwrap();
    assert!(half > 0 && half < s.truth.samples, "{half}");
}

#[test]
fn bad_requests_get_errors_and_the_session_goes_on() {
    let dir = scratch("serve-errors");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {}}),
        json!({"method": "open", "params": {"path": dir.join("missing.etl")}}),
        json!({"method": "summary", "params": {"trace": 99}}),
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.children", "params": {"trace": 2, "view": 7, "node": 0}}),
        json!({"method": "tree.create", "params": {"trace": 2, "source": "nonsense"}}),
        json!({"method": "tree.create", "params": {"trace": 2, "groupBy": ["galaxy"]}}),
        json!({"method": "tree.create", "params": {"trace": 2, "time": [1]}}),
        json!({"method": "tree.create", "params": {"trace": 2}}),
        json!({"method": "tree.children", "params": {"trace": 2, "view": 1, "node": 99999}}),
        json!({"method": "frobnicate", "params": {"trace": 2}}),
        json!({"params": {}}),
        json!({"method": "tree.close", "params": {"trace": 2, "view": 1}}),
        json!({"method": "tree.children", "params": {"trace": 2, "view": 1, "node": 0}}),
        json!({"method": "close", "params": {"trace": 2}}),
        json!({"method": "summary", "params": {"trace": 2}}),
        json!({"method": "close", "params": {"trace": 2}}),
    ]);
    assert!(error(&a, 1).contains("expected a path"));
    assert!(error(&a, 2).contains("missing.etl"));
    assert!(error(&a, 3).contains("no such trace"));
    assert_eq!(result(&a, 4)["trace"], 2);
    assert!(error(&a, 5).contains("no such view"));
    assert!(error(&a, 6).contains("source"));
    assert!(error(&a, 7).contains("groupBy"));
    assert!(error(&a, 8).contains("time"));
    assert_eq!(result(&a, 9)["view"], 1);
    assert!(error(&a, 10).contains("no such node"));
    assert!(error(&a, 11).contains("unknown method"));
    assert!(error(&a, 12).contains("method"));
    assert_eq!(result(&a, 13), &json!({}));
    assert!(error(&a, 14).contains("no such view"));
    assert_eq!(result(&a, 15), &json!({}));
    assert!(error(&a, 16).contains("no such trace"));
    assert!(error(&a, 17).contains("no such trace"));
}

#[test]
fn shutdown_ends_the_session() {
    let a = session(&[json!({"method": "shutdown"}), json!({"method": "hello"})]);
    assert_eq!(result(&a, 1), &json!({}));
    assert!(!a.contains_key(&2), "nothing after shutdown is answered");
}

#[test]
fn the_binary_serves_on_standard_input_and_output() {
    let dir = scratch("serve-binary");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let mut child = Command::new(env!("CARGO_BIN_EXE_stackrabbit"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = Vec::new();
    for (i, r) in [
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "tree.create", "params": {"trace": 1}}),
        json!({"method": "shutdown"}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut r = r;
        r["id"] = json!(i + 1);
        write_frame(&mut input, &Frame::new(r)).unwrap();
    }
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let mut r = Cursor::new(out.stdout);
    let mut answers = HashMap::new();
    while let Some(f) = read_frame(&mut r).unwrap() {
        answers.insert(f.header["id"].as_u64().unwrap(), f.header);
    }
    // (Shutdown can come before the trace's answers: they are on its own
    // thread, which finishes before the engine exits.)
    assert_eq!(result(&answers, 2)["root"]["inclusive"], s.truth.samples);
    assert_eq!(result(&answers, 3), &json!({}));
}

/// A session's answers by ID, and its notifications, in order.
fn session_with_notes(requests: &[Value]) -> (HashMap<u64, Value>, Vec<Value>) {
    let mut input = Vec::new();
    for (i, r) in requests.iter().enumerate() {
        let mut r = r.clone();
        r["id"] = json!(i + 1);
        write_frame(&mut input, &Frame::new(r)).unwrap();
    }
    let sink = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out: Output = sink.clone();
    serve(Cursor::new(input), &out).unwrap();
    let data = sink.lock().unwrap().clone();
    let mut r = Cursor::new(data);
    let (mut answers, mut notes) = (HashMap::new(), Vec::new());
    while let Some(f) = read_frame(&mut r).unwrap() {
        match f.header["id"].as_u64() {
            Some(id) => {
                answers.insert(id, f.header);
            }
            None => notes.push(f.header),
        }
    }
    (answers, notes)
}

#[test]
fn symbols_are_downloaded_when_asked_and_reported() {
    let dir = scratch("serve-symbols");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let cache = dir.join("cache");
    // A server that refuses every connection: every PDB is missing, fast.
    let (a, notes) = session_with_notes(&[
        json!({"method": "open", "params": {
            "path": path, "useIndex": false, "downloadSymbols": true,
            "symbolCache": cache, "symbolServers": ["http://127.0.0.1:9"],
        }}),
        json!({"method": "tree.create", "params": {"trace": 1}}),
    ]);
    assert_eq!(
        result(&a, 2)["view"],
        1,
        "the session goes on while it downloads"
    );
    let last = notes.last().expect("notes on the download");
    assert_eq!(last["method"], "symbols");
    let p = &last["params"];
    assert_eq!(p["trace"], 1);
    assert_eq!(p["done"], true);
    let wanted = p["wanted"].as_u64().unwrap();
    // The synthetic machine's images with samples: its kernel, system DLLs
    // and each process's executable and DLLs.
    assert!(wanted >= 4, "{wanted} PDBs wanted");
    assert_eq!(p["missing"], wanted);
    assert_eq!(p["downloaded"], 0);
}

#[test]
fn symbols_are_not_downloaded_unless_asked() {
    let dir = scratch("serve-no-symbols");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let (_, notes) = session_with_notes(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
    ]);
    assert!(notes.is_empty(), "no download, no notes");
}

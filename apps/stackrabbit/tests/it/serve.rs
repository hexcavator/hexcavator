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
        // (Notifications, such as symbols loaded, are not answers.)
        let Some(id) = f.header["id"].as_u64() else {
            assert!(f.header["method"].is_string(), "a notification");
            continue;
        };
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
        if let Some(id) = f.header["id"].as_u64() {
            answers.insert(id, f.header);
        }
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
    assert!(notes.iter().all(|n| n["method"] == "symbols"));
    let last = notes
        .iter()
        .rfind(|n| n["params"]["done"] == true)
        .expect("the download's last note");
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
    // Only the note that the PDBs here are loaded (none: they are the
    // synthetic machine's): none about a download.
    assert_eq!(notes.len(), 1, "{notes:?}");
    let p = &notes[0]["params"];
    assert_eq!(p["loaded"], 0);
    assert!(p["wanted"].as_u64().unwrap() >= 4);
    assert!(p.get("done").is_none());
}

#[test]
fn the_cpu_graph_adds_up_to_the_samples() {
    let dir = scratch("serve-graph");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "graph", "params": {"trace": 1, "buckets": 100, "top": 100}}),
        json!({"method": "graph", "params": {"trace": 1, "buckets": 50, "top": 2}}),
        json!({"method": "graph", "params": {"trace": 1, "buckets": 10, "time": [0, 100_000_000]}}),
    ]);
    // Every process's samples, Idle aside, in a series of its own.
    let g = result(&a, 2);
    // (About 300 ms at 1 ms a sample: buckets of four samples' time.)
    let buckets = g["buckets"].as_u64().unwrap();
    let span = g["endNs"].as_i64().unwrap() - g["startNs"].as_i64().unwrap();
    assert_eq!(buckets, (span / 4_000_000) as u64);
    let series = g["series"].as_array().unwrap();
    for p in s.truth.processes.iter().filter(|p| p.samples > 0) {
        let label = format!("{} ({})", p.name, p.pid);
        let row = series
            .iter()
            .find(|x| x["label"] == label.as_str())
            .unwrap();
        assert_eq!(row["samples"], p.samples, "{label}");
        assert_eq!(row["values"].as_array().unwrap().len() as u64, buckets);
    }
    assert!(series.iter().all(|x| x["label"] != "Idle (0)"));
    // Shares of the machine, heaviest series first.
    for x in series {
        assert!(
            x["values"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| (0.0..=1.0).contains(&v.as_f64().unwrap()))
        );
    }
    let samples: Vec<u64> = series
        .iter()
        .map(|x| x["samples"].as_u64().unwrap())
        .collect();
    assert!(samples.windows(2).all(|w| w[0] >= w[1]));
    // The top two, and the rest as Other.
    let g = result(&a, 3);
    let series = g["series"].as_array().unwrap();
    assert_eq!(series.len(), 3);
    assert_eq!(series[2]["label"], "Other");
    let total: u64 = series.iter().map(|x| x["samples"].as_u64().unwrap()).sum();
    assert_eq!(total, s.truth.samples - s.truth.idle_samples);
    // A time range: its samples only.
    let g = result(&a, 4);
    assert_eq!(g["startNs"], 0);
    assert_eq!(g["endNs"], 100_000_000);
    let part: u64 = g["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["samples"].as_u64().unwrap())
        .sum();
    assert!(part > 0 && part < total, "{part} of {total}");
}

#[test]
fn stack_tags_group_stacks_by_what_they_do() {
    let dir = scratch("serve-tags");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let tags = dir.join("tags.xml");
    std::fs::write(
        &tags,
        r#"<?xml version="1.0"?>
<Tag Name="">
  <Tag Name="Kernel"><Entrypoint Module="ntoskrnl.exe"/></Tag>
  <Tag Name="System"><Entrypoint Module="ntdll.dll"/></Tag>
</Tag>"#,
    )
    .unwrap();
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false, "stackTags": tags}}),
        json!({"method": "tree.create", "params": {"trace": 1, "groupBy": ["tag"], "frames": "module"}}),
        json!({"method": "tree.children", "params": {"trace": 1, "view": 1, "node": 0}}),
        json!({"method": "open", "params": {"path": path, "useIndex": false, "stackTags": dir.join("missing.xml")}}),
    ]);
    assert_eq!(result(&a, 1)["stackTags"], 2, "two tags");
    let rows = result(&a, 3)["rows"].as_array().unwrap();
    let weight = |name: &str| {
        rows.iter()
            .find(|r| r["label"] == name)
            .map_or(0, |r| r["inclusive"].as_u64().unwrap())
    };
    // A stack's tag is its deepest frame's that matches: in the kernel if
    // it got there (the kernel calls only the kernel), else ntdll's (every
    // user stack starts there).
    let t = &s.truth;
    let kernel_leaf: u64 = t
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f)| t.modules[f.module].name == "ntoskrnl.exe")
        .map(|(i, _)| t.exclusive[i])
        .sum();
    assert_eq!(weight("Kernel"), kernel_leaf + t.idle_samples);
    assert_eq!(weight("System"), t.samples - kernel_leaf - t.idle_samples);
    assert_eq!(weight("Other"), 0);
    // A missing file: reported, and the trace opens.
    let r = result(&a, 4);
    assert!(
        r["stackTagsError"]
            .as_str()
            .unwrap()
            .contains("missing.xml")
    );
    assert!(r["stackTags"].is_null());
}

#[test]
fn the_processes_table_has_lifetimes_threads_and_samples() {
    let dir = scratch("serve-processes");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "processes", "params": {"trace": 1}}),
        json!({"method": "processes", "params": {"trace": 1, "time": [0, 0]}}),
    ]);
    let rows = result(&a, 2)["rows"].as_array().unwrap();
    for p in &s.truth.processes {
        let r = rows.iter().find(|r| r["pid"] == p.pid).unwrap();
        assert_eq!(r["name"], p.name.as_str());
        assert_eq!(r["samples"], p.samples, "{}", p.name);
        let threads = s.truth.threads.iter().filter(|t| t.pid == p.pid).count();
        assert_eq!(r["threads"], threads, "{}", p.name);
    }
    // The second process ends during the trace, the last starts; the rest
    // span it all.
    let n = s.truth.processes.len();
    let row = |i: usize| {
        rows.iter()
            .find(|r| r["pid"] == s.truth.processes[i].pid)
            .unwrap()
    };
    assert!(row(1)["endNs"].is_i64() && row(1)["startNs"].is_null());
    assert!(row(n - 1)["startNs"].is_i64() && row(n - 1)["endNs"].is_null());
    assert!(row(0)["startNs"].is_null() && row(0)["endNs"].is_null());
    let samples: Vec<u64> = rows
        .iter()
        .map(|r| r["samples"].as_u64().unwrap())
        .collect();
    assert!(samples.windows(2).all(|w| w[0] >= w[1]), "heaviest first");
    // An empty range: every process, no samples.
    let empty = result(&a, 3)["rows"].as_array().unwrap();
    assert_eq!(empty.len(), rows.len());
    assert!(empty.iter().all(|r| r["samples"] == 0));
}

#[test]
fn the_precise_cpu_graph_adds_up_to_the_running_time() {
    let dir = scratch("serve-precise-graph");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "graph", "params": {"trace": 1, "source": "running", "buckets": 333, "top": 100}}),
        json!({"method": "tree.create", "params": {"trace": 1, "source": "running", "groupBy": ["process"]}}),
        json!({"method": "tree.children", "params": {"trace": 1, "view": 1, "node": 0}}),
    ]);
    let g = result(&a, 2);
    assert_eq!(g["source"], "running");
    assert_eq!(g["buckets"], 333, "precise: as many buckets as asked");
    let ticks_per_ns = 100; // 100 ns ticks.
    // Each process's running time in the graph is its running time in the
    // tree (the tree counts it by switch, the graph by bucket).
    for row in result(&a, 4)["rows"].as_array().unwrap() {
        let label = row["label"].as_str().unwrap();
        if label == "Idle (0)" {
            continue;
        }
        let series = g["series"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["label"] == label)
            .unwrap_or_else(|| panic!("{label} in the graph"));
        assert_eq!(
            series["ns"].as_u64().unwrap(),
            row["inclusive"].as_u64().unwrap() * ticks_per_ns,
            "{label}"
        );
        let values = series["values"].as_array().unwrap();
        assert_eq!(values.len(), 333);
        assert!(
            values
                .iter()
                .all(|v| (0.0..=1.0).contains(&v.as_f64().unwrap()))
        );
    }
}

#[test]
fn the_threads_table_has_samples_switches_and_running_time() {
    let dir = scratch("serve-threads");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let half = [0, 150_000_000];
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "processes", "params": {"trace": 1}}),
        json!({"method": "threads", "params": {"trace": 1}}),
        json!({"method": "tree.create", "params": {"trace": 1, "source": "running", "groupBy": ["thread"]}}),
        json!({"method": "tree.children", "params": {"trace": 1, "view": 1, "node": 0}}),
        json!({"method": "threads", "params": {"trace": 1, "time": half}}),
        json!({"method": "processes", "params": {"trace": 1, "time": half}}),
        json!({"method": "threads", "params": {"trace": 1, "process": 1_000_000}}),
    ]);
    let all = result(&a, 3)["rows"].as_array().unwrap();
    for t in &s.truth.threads {
        let r = all
            .iter()
            .find(|r| r["tid"] == t.tid && r["pid"] == t.pid)
            .unwrap_or_else(|| panic!("thread {}", t.tid));
        assert_eq!(r["samples"], t.samples, "thread {}", t.tid);
        assert_eq!(r["switches"], t.switch_ins, "thread {}", t.tid);
        assert_eq!(r["name"], json!(t.name), "thread {}", t.tid);
    }
    let samples: Vec<u64> = all.iter().map(|r| r["samples"].as_u64().unwrap()).collect();
    assert!(samples.windows(2).all(|w| w[0] >= w[1]), "heaviest first");
    // Each thread's running time is the precise tree's (ticks of 100 ns;
    // the table's is in ms, to the microsecond).
    let mut compared = 0;
    for row in result(&a, 5)["rows"].as_array().unwrap() {
        let label = row["label"].as_str().unwrap();
        let Some(tid) = label
            .strip_prefix("Thread ")
            .and_then(|l| l.split([' ', '(']).next())
            .and_then(|t| t.parse::<u64>().ok())
        else {
            continue;
        };
        let ms: f64 = all
            .iter()
            .filter(|r| r["tid"] == tid)
            .map(|r| r["runningMs"].as_f64().unwrap())
            .sum();
        let tree_ms = row["inclusive"].as_f64().unwrap() / 10_000.0;
        assert!(
            (ms - tree_ms).abs() < 0.002,
            "thread {tid}: {ms} ms, tree {tree_ms} ms"
        );
        compared += 1;
    }
    assert!(
        compared >= s.truth.threads.len(),
        "{compared} threads compared"
    );
    // Each process's threads, and only them, by its index.
    let processes = result(&a, 2)["rows"].as_array().unwrap().clone();
    let mut requests = vec![json!({"method": "open", "params": {"path": path, "useIndex": false}})];
    for p in &processes {
        requests.push(json!({"method": "threads", "params": {"trace": 1, "process": p["index"]}}));
    }
    let b = session(&requests);
    for (i, p) in processes.iter().enumerate() {
        let rows = result(&b, i as u64 + 2)["rows"].as_array().unwrap();
        assert_eq!(
            rows.len() as u64,
            p["threads"].as_u64().unwrap(),
            "{}",
            p["name"]
        );
        assert!(rows.iter().all(|r| r["processIndex"] == p["index"]));
        let sum: u64 = rows.iter().map(|r| r["samples"].as_u64().unwrap()).sum();
        assert_eq!(sum, p["samples"].as_u64().unwrap(), "{}", p["name"]);
    }
    // In a time range: what the processes table counts there.
    let in_half: u64 = result(&a, 6)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["samples"].as_u64().unwrap())
        .sum();
    let processes_half: u64 = result(&a, 7)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["samples"].as_u64().unwrap())
        .sum();
    assert_eq!(in_half, processes_half);
    assert!(in_half > 0 && in_half < samples.iter().sum::<u64>());
    assert!(error(&a, 8).contains("process"));
}

#[test]
fn hot_functions_over_the_protocol() {
    let dir = scratch("serve-functions");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "functions", "params": {"trace": 1, "frames": "module"}}),
        json!({"method": "functions", "params": {"trace": 1, "source": "running", "limit": 2}}),
        json!({"method": "functions", "params": {"trace": 1, "limit": "all"}}),
    ]);
    let by_module = result(&a, 2);
    assert_eq!(by_module["total"], s.truth.samples);
    let ex: u64 = by_module["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["exclusive"].as_u64().unwrap())
        .sum();
    assert_eq!(ex, s.truth.samples);
    // By module, each "function" is a module.
    assert!(
        by_module["functions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["label"].as_str().unwrap().ends_with("!<module>") || f["label"] == "?")
    );
    let running = result(&a, 3);
    assert_eq!(running["unit"], "ticks");
    assert!(running["functions"].as_array().unwrap().len() <= 4);
    assert!(error(&a, 4).contains("limit"));
}

#[test]
fn the_summary_says_what_the_recording_lost() {
    let dir = scratch("serve-lost");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    // Nothing lost.
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "summary", "params": {"trace": 1}}),
    ]);
    assert_eq!(result(&a, 1)["summary"]["eventsLost"], 0);
    assert_eq!(result(&a, 2)["buffersLost"], 0);
    // The same trace, its header saying 1234 events were lost: the logfile
    // header event's payload, at EventsLost (0x30).
    let etl = hexcavator_etl::Etl::parse(&s.etl).unwrap();
    assert_eq!(etl.header().events_lost, 0);
    let first = etl.buffers().next().unwrap().unwrap();
    let header = first.records().unwrap().next().unwrap().unwrap();
    let at = header.user_data.as_ptr() as usize - s.etl.as_ptr() as usize + 0x30;
    let mut lossy = s.etl.clone();
    lossy[at..at + 4].copy_from_slice(&1234u32.to_le_bytes());
    let lossy_path = dir.join("lossy.etl");
    std::fs::write(&lossy_path, &lossy).unwrap();
    let open = json!({"method": "open", "params": {"path": lossy_path, "useIndex": true}});
    let a = session(std::slice::from_ref(&open));
    assert_eq!(result(&a, 1)["opened"]["how"], "import");
    assert_eq!(result(&a, 1)["summary"]["eventsLost"], 1234);
    // Again, from its index: still said.
    let a = session(&[open]);
    assert_eq!(result(&a, 1)["opened"]["how"], "index");
    assert_eq!(result(&a, 1)["summary"]["eventsLost"], 1234);
}

#[test]
fn the_cpu_graph_by_thread_and_for_one_process() {
    let dir = scratch("serve-graph-threads");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "graph", "params": {"trace": 1, "by": "thread", "top": 1000}}),
        json!({"method": "processes", "params": {"trace": 1}}),
        json!({"method": "graph", "params": {"trace": 1, "by": "nonsense"}}),
        json!({"method": "graph", "params": {"trace": 1, "process": 99999}}),
    ]);
    let g = result(&a, 2);
    assert_eq!(g["by"], "thread");
    let series = g["series"].as_array().unwrap();
    // Each thread's samples (labels "process (pid) / tid name").
    for t in &s.truth.threads {
        let samples: u64 = series
            .iter()
            .filter(|x| {
                let label = x["label"].as_str().unwrap();
                label.contains(&format!("({}) / {}", t.pid, t.tid))
            })
            .map(|x| x["samples"].as_u64().unwrap())
            .sum();
        assert_eq!(samples, t.samples, "thread {}", t.tid);
    }
    assert!(error(&a, 4).contains("by"));
    assert!(error(&a, 5).contains("process"));

    // One process's threads: only its, adding up to it.
    let processes = result(&a, 3)["rows"].as_array().unwrap().clone();
    let busy = processes
        .iter()
        .find(|p| p["pid"] != 0 && p["samples"].as_u64().unwrap() > 0)
        .unwrap();
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "graph", "params": {"trace": 1, "by": "thread", "process": busy["index"], "top": 1000}}),
        json!({"method": "graph", "params": {"trace": 1, "process": busy["index"]}}),
    ]);
    let mine = result(&a, 2)["series"].as_array().unwrap().clone();
    let prefix = format!("{} ({}) / ", busy["name"].as_str().unwrap(), busy["pid"]);
    assert!(
        mine.iter()
            .all(|x| x["label"].as_str().unwrap().starts_with(&prefix)),
        "{mine:?}"
    );
    let sum: u64 = mine.iter().map(|x| x["samples"].as_u64().unwrap()).sum();
    assert_eq!(sum, busy["samples"].as_u64().unwrap());
    let whole = result(&a, 3)["series"].as_array().unwrap().clone();
    assert_eq!(whole.len(), 1, "by process, for one: one series");
    assert_eq!(whole[0]["samples"], busy["samples"]);
}

#[test]
fn every_kind_of_event_over_the_protocol() {
    let dir = scratch("serve-events");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let open = json!({"method": "open", "params": {"path": path, "useIndex": true}});
    let events = json!({"method": "events", "params": {"trace": 1}});
    // Imported, then from the index: the same.
    let a = session(&[open.clone(), events.clone()]);
    let b = session(&[open, events]);
    assert_eq!(result(&b, 1)["opened"]["how"], "index");
    let rows = result(&a, 2)["rows"].as_array().unwrap().clone();
    assert_eq!(&rows, result(&b, 2)["rows"].as_array().unwrap());
    let counts: Vec<u64> = rows.iter().map(|r| r["count"].as_u64().unwrap()).collect();
    assert!(
        counts.windows(2).all(|w| w[0] >= w[1]),
        "most numerous first"
    );
    let total: u64 = counts.iter().sum();
    assert_eq!(total, result(&a, 1)["opened"]["events"].as_u64().unwrap());
    // The samples: named by the kernel's schema.
    let perf_info = hexcavator_etw::guids::PERF_INFO.to_string();
    let samples = rows
        .iter()
        .find(|r| r["guid"] == perf_info.as_str() && r["opcode"] == 46)
        .unwrap();
    assert_eq!(samples["count"], s.truth.samples);
    assert!(
        samples["provider"].is_string() && samples["event"].is_string(),
        "{samples}"
    );
    assert!(samples["firstNs"].as_i64() <= samples["lastNs"].as_i64());
}

#[test]
fn events_are_named_by_the_descriptions_recorded_with_them() {
    use hexcavator_etl::Guid;
    use hexcavator_trace::{Clock, EventStats, Trace};
    let provider = Guid::new(0x1111, 2, 3, [4; 8]);
    // A TRACE_EVENT_INFO for (provider, ID 5, version 1, opcode 0): names
    // only (no properties).
    let info = |event: Option<&str>, task: &str, opcode: &str| {
        let mut b = vec![0u8; 112];
        b[0..16].copy_from_slice(&provider.to_bytes());
        b[32..34].copy_from_slice(&5u16.to_le_bytes());
        b[34] = 1;
        let name = |b: &mut Vec<u8>, at: usize, s: &str| {
            let off = u32::try_from(b.len()).unwrap();
            b[at..at + 4].copy_from_slice(&off.to_le_bytes());
            for u in s.encode_utf16().chain([0]) {
                b.extend_from_slice(&u.to_le_bytes());
            }
        };
        name(&mut b, 52, "Contoso-Widgets");
        name(&mut b, 68, task);
        name(&mut b, 72, opcode);
        if let Some(e) = event {
            name(&mut b, 92, e);
        }
        b
    };
    let stats = |id: u16| EventStats {
        provider,
        id,
        version: 1,
        count: u64::from(id),
        ..EventStats::default()
    };
    let mut trace = Trace::new(
        Clock {
            ticks_per_second: 10_000_000,
            origin: 0,
        },
        1,
    );
    trace.events = vec![stats(5), stats(6)];
    let row = |trace: &Trace, id: u64| {
        let v = stackrabbit::views::events(trace);
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone()
    };
    // Described: the provider's and event's names; not: neither.
    trace.event_infos = vec![info(Some("WidgetMade"), "Make", "Start")];
    let r = row(&trace, 5);
    assert_eq!(
        (
            r["provider"].as_str(),
            r["event"].as_str(),
            r["described"].as_bool()
        ),
        (Some("Contoso-Widgets"), Some("WidgetMade"), Some(true))
    );
    let other = row(&trace, 6);
    assert_eq!(
        other["provider"], "Contoso-Widgets",
        "the provider is named by any of its descriptions"
    );
    assert!(other["event"].is_null() && other["described"] == false);
    // No event name: its task's and opcode's.
    trace.event_infos = vec![info(None, "Make", "Start")];
    assert_eq!(row(&trace, 5)["event"], "Make/Start");
    // A damaged description is passed over.
    trace.event_infos = vec![vec![1, 2, 3]];
    assert!(row(&trace, 5)["provider"].is_null());
}

#[test]
fn one_kind_of_events_listed_and_decoded() {
    let dir = scratch("serve-events-list");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "events", "params": {"trace": 1}}),
    ]);
    let thread = hexcavator_etw::guids::THREAD.to_string();
    let cswitch = result(&a, 2)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["guid"] == thread.as_str() && r["opcode"] == 36)
        .unwrap()
        .clone();
    let list = |extra: Value| {
        let mut p = json!({"trace": 1, "guid": cswitch["guid"], "id": cswitch["id"], "version": cswitch["version"], "opcode": 36});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "events.list", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        list(json!({"limit": 25})),
        list(json!({"limit": 25, "offset": 25})),
        list(json!({"limit": 50})),
        list(json!({"limit": 100000, "time": [0, 100_000_000]})),
        json!({"method": "events.list", "params": {"trace": 1, "guid": "nonsense"}}),
        list(json!({"limit": 1_000_000})),
    ]);
    let first = result(&a, 2);
    assert_eq!(first["total"], s.truth.switches);
    let rows = first["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 25);
    let times = |r: &Value| -> Vec<i64> {
        r["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["timeNs"].as_i64().unwrap())
            .collect()
    };
    let t1 = times(first);
    assert!(t1.windows(2).all(|w| w[0] <= w[1]), "in time order");
    // Pages join up: the first two pages are the first 50.
    let mut both = t1.clone();
    both.extend(times(result(&a, 3)));
    assert_eq!(both, times(result(&a, 4)));
    // Decoded by the kernel's schema: the new thread is the import's.
    assert!(
        first["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "NewThreadId"),
        "{}",
        first["columns"]
    );
    let new_tid = |r: &Value| -> u64 {
        let f = r["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f[0] == "NewThreadId")
            .unwrap();
        f[1].as_str().unwrap().parse().unwrap()
    };
    let loaded = stackrabbit::store::open(
        &path,
        &stackrabbit::store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let t = &loaded.trace;
    for (i, r) in rows.iter().enumerate() {
        let th = t.switches.new_thread[i];
        let tid = if th.is_some() {
            u64::from(t.threads[th.index()].tid)
        } else {
            0
        };
        assert_eq!(new_tid(r), tid, "switch {i}");
        assert_eq!(r["missing"], 0);
    }
    // A time range: only its events, and how many.
    let ranged = result(&a, 5);
    let n = ranged["total"].as_u64().unwrap();
    assert!(n > 0 && n < s.truth.switches);
    assert_eq!(ranged["rows"].as_array().unwrap().len() as u64, n);
    assert!(times(ranged).iter().all(|&t| (0..100_000_000).contains(&t)));
    assert!(error(&a, 6).contains("guid"));
    assert!(error(&a, 7).contains("limit"));
}

#[test]
fn listing_by_the_buffer_index_is_listing_every_buffer() {
    use stackrabbit::generic::{Kind, list};
    let dir = scratch("serve-events-index");
    // (Small buffers: many of them, each with few kinds.)
    let config = hexcavator_trace_synth::Config {
        buffer_size: 4096,
        ..small()
    };
    let (path, _) = write_trace(&dir, "t.etl", &config);
    let loaded = stackrabbit::store::open(
        &path,
        &stackrabbit::store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let trace = &loaded.trace;
    assert!(trace.buffers.len() > 20, "{} buffers", trace.buffers.len());
    let mut whole = trace.clone();
    whole.buffers.clear();
    let span = trace.clock.ticks_per_second as i64 / 10; // 100 ms
    let origin = trace.clock.origin;
    for e in &trace.events {
        let kind = Kind {
            provider: e.provider,
            id: e.id,
            version: e.version,
            opcode: e.opcode,
        };
        for (time, offset, limit) in [
            (None, 0, 1),
            (None, 0, 7),
            (None, 3, 50),
            (None, 0, 100_000),
            (Some((origin + span, origin + 2 * span)), 0, 10),
            (Some((origin, origin + 3 * span)), 5, 100_000),
        ] {
            let a = list(trace, &path, kind, time, offset, limit, None).unwrap();
            let b = list(&whole, &path, kind, time, offset, limit, None).unwrap();
            assert_eq!(a, b, "{kind:?} {time:?} {offset} {limit}");
        }
    }
}

#[test]
fn listed_events_have_their_stacks() {
    let dir = scratch("serve-events-stacks");
    let (path, _) = write_trace(&dir, "t.etl", &small());
    let perf_info = hexcavator_etw::guids::PERF_INFO.to_string();
    let image = hexcavator_etw::guids::IMAGE.to_string();
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        json!({"method": "events.list", "params": {"trace": 1, "guid": perf_info, "version": 2, "opcode": 46, "limit": 300, "stacks": true}}),
        json!({"method": "events.list", "params": {"trace": 1, "guid": image, "version": 3, "opcode": 3, "limit": 5, "stacks": true}}),
        json!({"method": "events.list", "params": {"trace": 1, "guid": perf_info, "version": 2, "opcode": 46, "limit": 3}}),
    ]);
    let loaded = stackrabbit::store::open(
        &path,
        &stackrabbit::store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let t = &loaded.trace;
    let resolver = hexcavator_trace_analysis::Resolver::new(t);
    // (No symbols: a frame is its module and offset, else its address.)
    let label = |process, address: u64, lookup: u64| match resolver.image(process, lookup) {
        Some(image) => format!(
            "{}+{:#x}",
            t.images[image.index()].file_name(),
            address - t.images[image.index()].base
        ),
        None => format!("{address:#x}"),
    };
    let rows = result(&a, 2)["rows"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 300);
    let mut with = 0;
    for (i, r) in rows.iter().enumerate() {
        // The import's stack of the same sample (samples are in time order).
        let stack = t.samples.stack[i];
        if stack.is_empty() {
            assert!(r["stack"].is_null(), "sample {i}: no stack");
            continue;
        }
        let process = t.thread_process(t.samples.thread[i]);
        let want: Vec<String> = t
            .stacks
            .frames(stack)
            .enumerate()
            .map(|(j, f)| label(process, f, if j == 0 { f } else { f - 1 }))
            .collect();
        let got: Vec<String> = r["stack"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, want, "sample {i}");
        with += 1;
    }
    assert!(with > 200, "{with} samples with stacks");
    // A kind that has none; and not asked for.
    assert!(
        result(&a, 3)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["stack"].is_null())
    );
    assert!(
        result(&a, 4)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["stack"].is_null())
    );
}

#[test]
fn regions_of_interest_over_a_trace() {
    use hexcavator_etl::Guid;
    use hexcavator_etl::write::{self, EventFields, Writer, WriterOptions};
    let dir = scratch("serve-regions");
    let provider = Guid::new(0x1234_5678, 1, 2, [3; 8]);
    // TraceLogging events: Start (ID 1: Item, Key) and Stop (ID 2: Key).
    let schema = |name: &str, fields: &[(&str, u8)]| {
        let mut b = vec![0, 0, 0];
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        for (f, t) in fields {
            b.extend_from_slice(f.as_bytes());
            b.push(0);
            b.push(*t);
        }
        let n = u16::try_from(b.len()).unwrap().to_le_bytes();
        b[..2].copy_from_slice(&n);
        b
    };
    let start = schema("Start", &[("Item", 2), ("Key", 8)]);
    let stop = schema("Stop", &[("Key", 8)]);
    let mut w = Writer::new(WriterOptions {
        processors: 1,
        perf_freq: 1_000_000_000, // (ticks are nanoseconds)
        ..WriterOptions::default()
    });
    let mut emit = |ts: i64, id: u16, tid: u32, meta: &[u8], payload: Vec<u8>| {
        let e = EventFields {
            provider,
            id,
            thread_id: tid,
            process_id: 4,
            timestamp: ts,
            ..EventFields::default()
        };
        w.record(
            0,
            &write::event(
                &e,
                true,
                &[(hexcavator_etl::event::ext_type::EVENT_SCHEMA_TL, meta)],
                &payload,
            ),
        );
    };
    let item = |name: &str, key: u32| {
        let mut p = name.as_bytes().to_vec();
        p.push(0);
        p.extend_from_slice(&key.to_le_bytes());
        p
    };
    emit(1_000, 1, 10, &start, item("a", 1));
    emit(2_000, 1, 11, &start, item("b", 2));
    emit(3_000, 2, 12, &stop, 1u32.to_le_bytes().to_vec());
    emit(4_000, 2, 13, &stop, 2u32.to_le_bytes().to_vec());
    emit(5_000, 2, 14, &stop, 9u32.to_le_bytes().to_vec()); // no start
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();
    let regions = dir.join("regions.xml");
    let p = format!("{{{provider}}}");
    std::fs::write(
        &regions,
        format!(
            r#"<InstrumentationManifest><Instrumentation><Regions>
  <RegionRoot Guid="{{0}}" Name="Root">
    <Region Guid="{{1}}" Name="Work" FriendlyName="Work items">
      <Start><Event Provider="{p}" Id="1" Version="0" /></Start>
      <Stop><Event Provider="{p}" Id="2" Version="0" /></Stop>
      <Match><Event><Payload FieldName="Key" /></Event></Match>
      <Naming><PayloadBased NameField="Item" /></Naming>
    </Region>
  </RegionRoot>
</Regions></Instrumentation></InstrumentationManifest>"#
        ),
    )
    .unwrap();
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        json!({"method": "regions", "params": {"trace": 1, "file": regions}}),
        json!({"method": "regions", "params": {"trace": 1, "file": dir.join("none.xml")}}),
        json!({"method": "regions", "params": {"trace": 1}}),
    ]);
    let r = result(&a, 2);
    let defs = r["regions"].as_array().unwrap();
    assert_eq!(defs[1]["displayName"], "Work items");
    assert_eq!(defs[1]["count"], 2);
    assert_eq!(defs[1]["unpairedStops"], 1);
    assert_eq!(defs[1]["totalNs"], 4_000);
    assert_eq!(defs[0]["count"], 1, "the root contains them");
    let inst: Vec<(u64, Option<&str>, i64, i64, u64)> = r["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["region"].as_u64().unwrap(),
                i["name"].as_str(),
                i["startNs"].as_i64().unwrap(),
                i["durationNs"].as_i64().unwrap(),
                i["tid"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    assert_eq!(
        inst,
        [
            (0, None, 1_000, 3_000, 0),
            (1, Some("a"), 1_000, 2_000, 10),
            (1, Some("b"), 2_000, 2_000, 11)
        ]
    );
    assert!(error(&a, 3).contains("none.xml"));
    assert!(error(&a, 4).contains("file"));
}

#[test]
fn disk_usage_by_process_file_disk_and_type() {
    use hexcavator_etl::classic;
    use hexcavator_etl::write::{self, Kernel, Writer, WriterOptions};
    use hexcavator_etw::guids;
    let dir = scratch("serve-disk");
    // A counter at 10 MHz: 10,000 ticks a millisecond.
    let mut w = Writer::new(WriterOptions {
        processors: 1,
        perf_freq: 10_000_000,
        ..WriterOptions::default()
    });
    let mut kernel = |provider, op: u8, version: u16, ts: i64, payload: Vec<u8>| {
        let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
        let k = Kernel {
            hook,
            version,
            thread_id: u32::MAX,
            process_id: u32::MAX,
            timestamp: ts,
            ..Kernel::default()
        };
        w.record(0, &write::system(&k, true, &payload));
    };
    let name = |object: u64, path: &str| {
        let mut p = object.to_le_bytes().to_vec();
        for u in path.encode_utf16().chain([0]) {
            p.extend_from_slice(&u.to_le_bytes());
        }
        p
    };
    // DiskIo v3: disk, flags, size, reserved, offset, file object, IRP,
    // response time (ticks), issuing thread.
    let io = |disk: u32, size: u32, offset: u64, object: u64, response: u64| {
        let mut p = Vec::new();
        for v in [disk, 0, size, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        for v in [offset, object, 0x9999, response] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&77u32.to_le_bytes());
        p
    };
    // File object 1 is a.txt, then b.txt (renamed); object 2 is named only
    // by the rundown at the end.
    kernel(guids::FILE_IO, 32, 2, 10, name(1, r"C:\a.txt"));
    // Disk 0: a read of 4 KB taking 2 ms, completing at 30,000; a write of
    // 8 KB taking 3 ms, completing at 35,000 (it started at 5,000, before
    // the read completed: its service time is from 30,000, 0.5 ms).
    kernel(guids::DISK_IO, 10, 3, 30_000, io(0, 4096, 0, 1, 20_000));
    kernel(guids::DISK_IO, 11, 3, 35_000, io(0, 8192, 4096, 1, 30_000));
    kernel(guids::FILE_IO, 0, 2, 40_000, name(1, r"C:\b.txt"));
    // Disk 1: a read of object 1 (now b.txt), and a flush, and an I/O of
    // object 2.
    kernel(guids::DISK_IO, 10, 3, 60_000, io(1, 512, 0, 1, 10_000));
    kernel(guids::DISK_IO, 14, 3, 70_000, {
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&5_000u64.to_le_bytes());
        p.extend_from_slice(&0x9999u64.to_le_bytes());
        p.extend_from_slice(&77u32.to_le_bytes());
        p
    });
    kernel(guids::DISK_IO, 11, 3, 80_000, io(1, 1024, 0, 2, 1_000));
    kernel(guids::FILE_IO, 36, 2, 90_000, name(2, r"C:\c.log"));
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();

    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "disk", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": false}}),
        req("type", json!({})),
        req("file", json!({})),
        req("disk", json!({})),
        req("process", json!({"limit": 2})),
        req("type", json!({"time": [0, 4_000_000]})),
        req("nonsense", json!({})),
    ]);
    let by = |id: u64| -> std::collections::BTreeMap<String, (u64, u64, u64, u64)> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    (n("count"), n("bytes"), n("ioNs"), n("serviceNs")),
                )
            })
            .collect()
    };
    let types = by(2);
    assert_eq!(result(&a, 2)["count"], 5);
    assert_eq!(result(&a, 2)["bytes"], 4096 + 8192 + 512 + 1024);
    // I/O times: 2 ms + 1 ms reads; service times: the read 2 ms (nothing
    // before it), disk 1's read 1 ms.
    assert_eq!(types["Read"], (2, 4608, 3_000_000, 3_000_000));
    // The write: 3 ms I/O, 0.5 ms service (from the read's completion);
    // disk 1's write: 0.1 ms (it started after the flush completed).
    assert_eq!(types["Write"], (2, 9216, 3_100_000, 600_000));
    assert_eq!(types["Flush"], (1, 0, 500_000, 500_000));
    let files = by(3);
    assert_eq!(files[r"C:\a.txt"].0, 2, "named a.txt then");
    assert_eq!(files[r"C:\b.txt"].0, 1, "renamed by its next I/O");
    assert_eq!(files[r"C:\c.log"].0, 1, "named by the rundown after");
    assert_eq!(files["Unknown file"].0, 1, "the flush names no file");
    let disks = by(4);
    assert_eq!((disks["Disk 0"].0, disks["Disk 1"].0), (2, 3));
    // The heaviest by service time, a limit of them.
    let ios = result(&a, 5)["ios"].as_array().unwrap();
    assert_eq!(ios.len(), 2);
    assert_eq!(
        (ios[0]["kind"].as_str(), ios[0]["serviceNs"].as_u64()),
        (Some("Read"), Some(2_000_000))
    );
    assert_eq!(ios[1]["serviceNs"], 1_000_000);
    assert_eq!(ios[0]["file"], r"C:\a.txt");
    // A time range: the first two only (completed by 4 ms).
    assert_eq!(result(&a, 6)["count"], 2);
    assert!(error(&a, 7).contains("by"), "{}", error(&a, 7));
}

#[test]
fn file_io_by_process_file_and_operation() {
    use hexcavator_etl::classic;
    use hexcavator_etl::write::{self, Kernel, Writer, WriterOptions};
    use hexcavator_etw::guids;
    let dir = scratch("serve-fileio");
    // A counter at 10 MHz: 10,000 ticks a millisecond.
    let mut w = Writer::new(WriterOptions {
        processors: 1,
        perf_freq: 10_000_000,
        ..WriterOptions::default()
    });
    let mut kernel = |provider, op: u8, version: u16, ts: i64, payload: Vec<u8>| {
        let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
        let k = Kernel {
            hook,
            version,
            thread_id: u32::MAX,
            process_id: u32::MAX,
            timestamp: ts,
            ..Kernel::default()
        };
        w.record(0, &write::system(&k, true, &payload));
    };
    let u32s =
        |p: &mut Vec<u8>, v: &[u32]| v.iter().for_each(|v| p.extend_from_slice(&v.to_le_bytes()));
    let u64s =
        |p: &mut Vec<u8>, v: &[u64]| v.iter().for_each(|v| p.extend_from_slice(&v.to_le_bytes()));
    let utf16z = |p: &mut Vec<u8>, s: &str| {
        for u in s.encode_utf16().chain([0]) {
            p.extend_from_slice(&u.to_le_bytes());
        }
    };
    // Process 100 (app.exe), thread 200.
    kernel(guids::PROCESS, 3, 4, 1, {
        let mut p = Vec::new();
        u64s(&mut p, &[0xaaaa]);
        u32s(&mut p, &[100, 4, 1, 0]);
        u64s(&mut p, &[0]);
        u32s(&mut p, &[0, 0]);
        p.extend_from_slice(b"app.exe\0");
        utf16z(&mut p, "app.exe");
        utf16z(&mut p, "");
        utf16z(&mut p, "");
        p
    });
    kernel(guids::THREAD, 3, 3, 2, {
        let mut p = Vec::new();
        u32s(&mut p, &[100, 200]);
        u64s(&mut p, &[0, 0, 0, 0, 0, 0x1234, 0]);
        u32s(&mut p, &[0]);
        p.extend_from_slice(&[8, 5, 2, 0]);
        p
    });
    let create = |irp: u64, object: u64, tid: u32, path: &str| {
        let mut p = Vec::new();
        u64s(&mut p, &[irp, object]);
        u32s(&mut p, &[tid, 0, 0, 0]);
        utf16z(&mut p, path);
        p
    };
    let rw = |irp: u64, object: u64, key: u64, tid: u32, size: u32| {
        let mut p = Vec::new();
        u64s(&mut p, &[0, irp, object, key]);
        u32s(&mut p, &[tid, size, 0]);
        p
    };
    let simple = |irp: u64, object: u64, key: u64, tid: u32| {
        let mut p = Vec::new();
        u64s(&mut p, &[irp, object, key]);
        u32s(&mut p, &[tid]);
        p
    };
    let end = |irp: u64, status: u32| {
        let mut p = Vec::new();
        u64s(&mut p, &[irp, 0]);
        u32s(&mut p, &[status]);
        p
    };
    let name = |key: u64, path: &str| {
        let mut p = Vec::new();
        u64s(&mut p, &[key]);
        utf16z(&mut p, path);
        p
    };
    // Thread 200 creates a.txt (object 1) taking 1 ms; reads 4 KB of it
    // (key 0x11, named by a name event) taking 2 ms; writes 8 KB taking
    // 3 ms (its end comes after another IRP's); and closes it, which never
    // ends in the trace. Thread 999 (unknown) flushes c.log (key 0x22,
    // named by the rundown at the end) taking 0.5 ms, and fails.
    kernel(
        guids::FILE_IO,
        64,
        3,
        10_000,
        create(0xa1, 1, 200, r"C:\a.txt"),
    );
    kernel(guids::FILE_IO, 76, 3, 20_000, end(0xa1, 0));
    kernel(guids::FILE_IO, 0, 3, 20_500, name(0x11, r"C:\a.txt"));
    kernel(guids::FILE_IO, 67, 3, 30_000, rw(0xa2, 1, 0x11, 200, 4096));
    kernel(guids::FILE_IO, 76, 3, 50_000, end(0xa2, 0));
    kernel(guids::FILE_IO, 68, 3, 60_000, rw(0xa2, 1, 0x11, 200, 8192));
    kernel(guids::FILE_IO, 73, 3, 61_000, simple(0xb1, 2, 0x22, 999));
    kernel(guids::FILE_IO, 76, 3, 66_000, end(0xb1, 0xc000_0022));
    kernel(guids::FILE_IO, 76, 3, 90_000, end(0xa2, 0));
    kernel(guids::FILE_IO, 66, 3, 95_000, simple(0xa3, 1, 0x11, 200));
    kernel(guids::FILE_IO, 36, 3, 99_000, name(0x22, r"C:\c.log"));
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();

    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "fileio", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("operation", json!({})),
        req("file", json!({})),
        req("process", json!({"limit": 2})),
        req("operation", json!({"time": [0, 5_000_000]})),
        req("nonsense", json!({})),
    ]);
    let by = |id: u64| -> std::collections::BTreeMap<String, (u64, u64, u64)> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    (n("count"), n("bytes"), n("durationNs")),
                )
            })
            .collect()
    };
    let r = result(&a, 2);
    assert_eq!(r["count"], 5);
    assert_eq!(r["unended"], 1);
    assert_eq!(r["bytes"], 4096 + 8192);
    let ops = by(2);
    assert_eq!(ops["Create"], (1, 0, 1_000_000));
    assert_eq!(ops["Read"], (1, 4096, 2_000_000));
    assert_eq!(
        ops["Write"],
        (1, 8192, 3_000_000),
        "ended by its own IRP's next end"
    );
    assert_eq!(ops["Flush"], (1, 0, 500_000));
    assert_eq!(ops["Close"], (1, 0, 0), "never ended");
    let files = by(3);
    assert_eq!(
        files[r"C:\a.txt"].0, 4,
        "by its create's path, then its key's name"
    );
    assert_eq!(files[r"C:\c.log"].0, 1, "named by the rundown after");
    let r = result(&a, 4);
    let procs = by(4);
    assert_eq!(procs["app.exe (100)"].0, 4);
    assert_eq!(procs["Unknown process"].0, 1);
    // The longest, a limit of them.
    let longest = r["ops"].as_array().unwrap();
    assert_eq!(longest.len(), 2);
    assert_eq!(longest[0]["op"], "Write");
    assert_eq!(longest[0]["durationNs"], 3_000_000);
    assert_eq!(longest[0]["tid"], 200);
    assert_eq!(longest[0]["file"], r"C:\a.txt");
    assert_eq!(longest[1]["op"], "Read");
    let flush = &result(&a, 2)["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["op"] == "Flush")
        .unwrap()
        .clone();
    assert_eq!(flush["status"], "0xc0000022");
    assert_eq!(flush["tid"], Value::Null);
    // A time range: requested by 5 ms (the create and the read).
    assert_eq!(result(&a, 5)["count"], 2);
    assert!(error(&a, 6).contains("by"), "{}", error(&a, 6));
}

#[test]
fn dpcs_and_isrs_by_module_function_processor_and_type() {
    use hexcavator_etl::classic;
    use hexcavator_etl::write::{self, Kernel, Writer, WriterOptions};
    use hexcavator_etw::guids;
    let dir = scratch("serve-dpc");
    // A counter at 10 MHz: 10 ticks a microsecond.
    let mut w = Writer::new(WriterOptions {
        processors: 2,
        perf_freq: 10_000_000,
        ..WriterOptions::default()
    });
    let mut kernel = |cpu: u16, provider, op: u8, version: u16, ts: i64, payload: Vec<u8>| {
        let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
        let k = Kernel {
            hook,
            version,
            thread_id: u32::MAX,
            process_id: u32::MAX,
            timestamp: ts,
            ..Kernel::default()
        };
        w.record(cpu, &write::system(&k, true, &payload));
    };
    let base = 0xffff_f800_0000_0000u64;
    // A driver (an image of no process: the kernel's).
    kernel(0, guids::IMAGE, 3, 3, 1, {
        let mut p = Vec::new();
        for v in [base, 0x1_0000] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0u32, 0, 0x5000, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&base.to_le_bytes());
        p.extend_from_slice(&[0; 16]);
        for u in r"\SystemRoot\drv.sys".encode_utf16().chain([0]) {
            p.extend_from_slice(&u.to_le_bytes());
        }
        p
    });
    let dpc = |start: u64, routine: u64| {
        let mut p = start.to_le_bytes().to_vec();
        p.extend_from_slice(&routine.to_le_bytes());
        p
    };
    let isr = |start: u64, routine: u64, vector: u16, msi: bool| {
        let mut p = dpc(start, routine);
        p.push(1);
        p.extend_from_slice(&vector.to_le_bytes());
        p.push(0);
        if msi {
            p.extend_from_slice(&7u32.to_le_bytes());
        }
        p
    };
    // Processor 0: an ISR of 5 us, a DPC of 20 us, an MSI ISR of 1 us.
    // Processor 1: a timer DPC of 0.5 us in no known module, a DPC of
    // 1 ms.
    kernel(
        0,
        guids::PERF_INFO,
        67,
        2,
        1_050,
        isr(1_000, base + 0x100, 0x51, false),
    );
    kernel(0, guids::PERF_INFO, 68, 2, 1_260, dpc(1_060, base + 0x200));
    kernel(
        0,
        guids::PERF_INFO,
        50,
        2,
        4_010,
        isr(4_000, base + 0x100, 0x60, true),
    );
    kernel(1, guids::PERF_INFO, 69, 2, 2_005, dpc(2_000, 0x1234));
    kernel(1, guids::PERF_INFO, 68, 2, 13_000, dpc(3_000, base + 0x200));
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();

    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "dpc", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("module", json!({})),
        req("function", json!({})),
        req("processor", json!({})),
        req("type", json!({"limit": 2})),
        req("type", json!({"time": [0, 150_000]})),
        req("nonsense", json!({})),
    ]);
    let by = |id: u64| -> std::collections::BTreeMap<String, (u64, u64, u64)> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    (n("count"), n("durationNs"), n("maxNs")),
                )
            })
            .collect()
    };
    let r = result(&a, 2);
    assert_eq!(r["count"], 5);
    assert_eq!(r["durationNs"], 1_026_500);
    let modules = by(2);
    assert_eq!(modules["drv.sys"], (4, 1_026_000, 1_000_000));
    assert_eq!(modules["Unknown module"], (1, 500, 500));
    let functions = by(3);
    assert_eq!(functions["drv.sys+0x200"], (2, 1_020_000, 1_000_000));
    assert_eq!(functions["drv.sys+0x100"], (2, 6_000, 5_000));
    assert_eq!(functions["0x1234"], (1, 500, 500));
    let cpus = by(4);
    assert_eq!(cpus["CPU 0"], (3, 26_000, 20_000));
    assert_eq!(cpus["CPU 1"], (2, 1_000_500, 1_000_000));
    let types = by(5);
    assert_eq!(
        (types["ISR"].0, types["DPC"].0, types["Timer DPC"].0),
        (2, 2, 1)
    );
    let r = result(&a, 5);
    assert_eq!(
        r["bucketsNs"],
        json!([1_000, 10_000, 100_000, 1_000_000, 10_000_000])
    );
    let histogram: Vec<(String, Value)> = r["histogram"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| (h["type"].as_str().unwrap().to_string(), h["counts"].clone()))
        .collect();
    assert_eq!(
        histogram,
        [
            ("ISR".to_string(), json!([0, 2, 0, 0, 0, 0])),
            ("DPC".to_string(), json!([0, 0, 1, 0, 1, 0])),
            ("Timer DPC".to_string(), json!([1, 0, 0, 0, 0, 0])),
        ]
    );
    // The longest, a limit of them.
    let runs = r["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(
        (
            &runs[0]["type"],
            &runs[0]["processor"],
            &runs[0]["durationNs"],
            &runs[0]["startNs"]
        ),
        (&json!("DPC"), &json!(1), &json!(1_000_000), &json!(300_000))
    );
    assert_eq!(runs[0]["function"], "drv.sys+0x200");
    assert_eq!(runs[0]["vector"], Value::Null);
    assert_eq!(runs[1]["type"], "DPC");
    let isr = result(&a, 2)["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["durationNs"] == 5_000)
        .unwrap()
        .clone();
    assert_eq!(
        (isr["type"].as_str(), isr["vector"].as_u64()),
        (Some("ISR"), Some(0x51))
    );
    // A time range: those started by 150 us (the first ISR and DPC).
    assert_eq!(result(&a, 6)["count"], 2);
    assert!(error(&a, 7).contains("by"), "{}", error(&a, 7));
}

/// A trace of registry events: `(opcode, end, start, status, KCB, name,
/// thread, process)` each, after process 100 (app.exe) and its thread 200.
type RegEvent<'a> = (u8, i64, u64, u32, u64, &'a str, u32, u32);

fn registry_trace(dir: &std::path::Path, events: &[RegEvent<'_>]) -> std::path::PathBuf {
    use hexcavator_etl::classic;
    use hexcavator_etl::write::{self, Kernel, Writer, WriterOptions};
    use hexcavator_etw::guids;
    // A counter at 10 MHz: 100 ns a tick.
    let mut w = Writer::new(WriterOptions {
        processors: 1,
        perf_freq: 10_000_000,
        ..WriterOptions::default()
    });
    let mut kernel =
        |provider, op: u8, version: u16, ts: i64, tid: u32, pid: u32, payload: Vec<u8>| {
            let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
            let k = Kernel {
                hook,
                version,
                thread_id: tid,
                process_id: pid,
                timestamp: ts,
                ..Kernel::default()
            };
            w.record(0, &write::system(&k, true, &payload));
        };
    let utf16z = |p: &mut Vec<u8>, s: &str| {
        for u in s.encode_utf16().chain([0]) {
            p.extend_from_slice(&u.to_le_bytes());
        }
    };
    kernel(guids::PROCESS, 3, 4, 1, u32::MAX, u32::MAX, {
        let mut p = 0xaaaau64.to_le_bytes().to_vec();
        for v in [100u32, 4, 1, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&[0; 16]);
        p.extend_from_slice(b"app.exe\0");
        utf16z(&mut p, "app.exe");
        utf16z(&mut p, "");
        utf16z(&mut p, "");
        p
    });
    kernel(guids::THREAD, 3, 3, 2, u32::MAX, u32::MAX, {
        let mut p = Vec::new();
        for v in [100u32, 200] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0u64, 0, 0, 0, 0, 0x1234, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&[0, 0, 0, 0, 8, 5, 2, 0]);
        p
    });
    for &(op, end, start, status, kcb, name, tid, pid) in events {
        let mut p = start.to_le_bytes().to_vec();
        p.extend_from_slice(&status.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&kcb.to_le_bytes());
        utf16z(&mut p, name);
        kernel(guids::REGISTRY, op, 2, end, tid, pid, p);
    }
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();
    path
}

#[test]
fn registry_by_process_key_and_operation() {
    let dir = scratch("serve-registry");
    let (k1, k2) = (0xffff_a000_0000_1000u64, 0xffff_a000_0000_2000u64);
    let none = u32::MAX;
    let path = registry_trace(
        &dir,
        &[
            // KCB 1 is SOFTWARE, then (deleted and made again) \REGISTRY\A.
            (22, 5, 0, 0, k1, r"\REGISTRY\MACHINE\SOFTWARE", none, none),
            // An open by a whole path (no KCB), of 1 us.
            (11, 20, 10, 0, 0, r"\REGISTRY\USER\S-1", 200, 100),
            // An open under KCB 1, of 2 us, that fails.
            (11, 50, 30, 0xc000_0034, k1, r"Vendor\App", 200, 100),
            // A value's query: the key is KCB 1's, the name the value's.
            (16, 70, 60, 0, k1, "Version", 200, 100),
            // A close of KCB 2, named only by the rundown at the end.
            (27, 81, 80, 0, k2, "", 200, 100),
            (23, 100, 0, 0, k1, r"\REGISTRY\MACHINE\SOFTWARE", none, none),
            (22, 110, 0, 0, k1, r"\REGISTRY\A", none, none),
            (13, 130, 120, 0, k1, "", 200, 100),
            // A thread we don't know, of a process we do (by the header).
            (13, 150, 140, 0, k2, "", 999, 100),
            // A KCB never named, by a process we don't know.
            (13, 165, 160, 0, 0xdead, "", 777, 777),
            (25, 200, 0, 0, k2, r"\REGISTRY\MACHINE\SYSTEM", none, none),
        ],
    );
    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "registry", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("operation", json!({})),
        req("key", json!({})),
        req("process", json!({"limit": 1})),
        req("key", json!({"groupLimit": 2})),
        req("operation", json!({"time": [0, 3_500]})),
        req("nonsense", json!({})),
    ]);
    let by = |id: u64| -> std::collections::BTreeMap<String, (u64, u64, u64)> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    (n("count"), n("failed"), n("durationNs")),
                )
            })
            .collect()
    };
    let r = result(&a, 2);
    assert_eq!(
        (r["count"].as_u64(), r["failed"].as_u64()),
        (Some(7), Some(1))
    );
    assert_eq!(
        r["durationNs"],
        1_000 + 2_000 + 1_000 + 100 + 1_000 + 1_000 + 500
    );
    let ops = by(2);
    assert_eq!(ops["Open"], (2, 1, 3_000));
    assert_eq!(ops["QueryValue"], (1, 0, 1_000));
    assert_eq!(ops["Close"], (1, 0, 100));
    assert_eq!(ops["Query"], (3, 0, 2_500));
    let keys = by(3);
    assert_eq!(
        keys.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "Unknown key",
            r"\REGISTRY\A",
            r"\REGISTRY\MACHINE\SOFTWARE",
            r"\REGISTRY\MACHINE\SOFTWARE\Vendor\App",
            r"\REGISTRY\MACHINE\SYSTEM",
            r"\REGISTRY\USER\S-1",
        ]
    );
    assert_eq!(
        keys[r"\REGISTRY\MACHINE\SYSTEM"].0, 2,
        "named by the rundown after"
    );
    assert_eq!(keys[r"\REGISTRY\MACHINE\SOFTWARE"].0, 1, "the value's key");
    assert_eq!(result(&a, 3)["groupsTotal"], 6);
    let procs = by(4);
    assert_eq!(procs["app.exe (100)"].0, 6);
    assert_eq!(procs["Unknown process"].0, 1);
    let longest = result(&a, 4)["ops"].as_array().unwrap().clone();
    assert_eq!(longest.len(), 1);
    assert_eq!(
        (
            &longest[0]["op"],
            &longest[0]["durationNs"],
            &longest[0]["status"],
            &longest[0]["tid"]
        ),
        (
            &json!("Open"),
            &json!(2_000),
            &json!("0xc0000034"),
            &json!(200)
        )
    );
    assert_eq!(longest[0]["key"], r"\REGISTRY\MACHINE\SOFTWARE\Vendor\App");
    let value = result(&a, 2)["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["op"] == "QueryValue")
        .unwrap()
        .clone();
    assert_eq!(
        (value["key"].as_str(), value["value"].as_str()),
        (Some(r"\REGISTRY\MACHINE\SOFTWARE"), Some("Version"))
    );
    // The most time first, and only as many groups as asked for.
    let r = result(&a, 5);
    assert_eq!(
        (
            r["groups"].as_array().unwrap().len(),
            r["groupsTotal"].as_u64()
        ),
        (2, Some(6))
    );
    assert_eq!(
        r["groups"][0]["label"],
        r"\REGISTRY\MACHINE\SOFTWARE\Vendor\App"
    );
    // A time range: those started by 3.5 us (the two opens).
    assert_eq!(result(&a, 6)["count"], 2);
    assert!(error(&a, 7).contains("by"), "{}", error(&a, 7));
}

#[test]
fn answers_too_large_to_send_are_errors() {
    let dir = scratch("serve-too-large");
    // 30,000 keys of 600 characters: grouped by key, about 20 MB of
    // answer, more than a frame's header may hold.
    let names: Vec<String> = (0..30_000)
        .map(|i| format!(r"\REGISTRY\{i:0>590}"))
        .collect();
    let events: Vec<RegEvent<'_>> = names
        .iter()
        .zip(10i64..)
        .map(|(n, t)| (11, t, t.unsigned_abs(), 0, 0, n.as_str(), 200, 100))
        .collect();
    let path = registry_trace(&dir, &events);
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        json!({"method": "registry", "params": {"trace": 1, "by": "key", "groupLimit": 100_000, "limit": 1}}),
        // (And the session goes on.)
        json!({"method": "registry", "params": {"trace": 1, "by": "operation"}}),
    ]);
    assert!(error(&a, 2).contains("too large"), "{}", error(&a, 2));
    assert_eq!(result(&a, 3)["count"], 30_000);
}

/// A kernel event: `(provider, opcode, version, timestamp, payload,
/// thread)`.
type KernelRecord = (hexcavator_etl::Guid, u8, u16, i64, Vec<u8>, u32);

/// A trace (a counter at 10 MHz: 100 ns a tick) of process 100 (app.exe)
/// and its thread 200 (run down at the start), then `events` (those of
/// thread 200 are process 100's, by their headers).
fn app_trace(dir: &std::path::Path, events: Vec<KernelRecord>) -> std::path::PathBuf {
    use hexcavator_etl::classic;
    use hexcavator_etl::write::{self, Kernel, Writer, WriterOptions};
    use hexcavator_etw::guids;
    let mut w = Writer::new(WriterOptions {
        processors: 1,
        perf_freq: 10_000_000,
        buffer_size: 0x10000,
        ..WriterOptions::default()
    });
    let mut process = 0xaaaau64.to_le_bytes().to_vec();
    for v in [100u32, 4, 1, 0] {
        process.extend_from_slice(&v.to_le_bytes());
    }
    process.extend_from_slice(&[0; 16]);
    process.extend_from_slice(b"app.exe\0");
    process.extend_from_slice(&utf16z("app.exe"));
    process.extend_from_slice(&utf16z(""));
    process.extend_from_slice(&utf16z(""));
    let mut thread = Vec::new();
    for v in [100u32, 200] {
        thread.extend_from_slice(&v.to_le_bytes());
    }
    for v in [0u64, 0, 0, 0, 0, 0x1234, 0] {
        thread.extend_from_slice(&v.to_le_bytes());
    }
    thread.extend_from_slice(&[0, 0, 0, 0, 8, 5, 2, 0]);
    let all = [
        (guids::PROCESS, 3, 4, 1, process, u32::MAX),
        (guids::THREAD, 3, 3, 2, thread, u32::MAX),
    ]
    .into_iter()
    .chain(events);
    for (provider, op, version, ts, payload, tid) in all {
        let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
        let k = Kernel {
            hook,
            version,
            thread_id: tid,
            process_id: if tid == 200 { 100 } else { u32::MAX },
            timestamp: ts,
            ..Kernel::default()
        };
        w.record(0, &write::system(&k, true, &payload));
    }
    let path = dir.join("t.etl");
    std::fs::write(&path, w.finish()).unwrap();
    path
}

/// `s` as a NUL-terminated UTF-16 string.
fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[test]
fn hard_faults_by_process_file_and_thread() {
    use hexcavator_etw::guids;
    let dir = scratch("serve-hardfaults");
    // FileIo names: object 1 by a name event, 2 by a create's path, 3 only
    // by the rundown at the end; 9 never.
    let name = |op: u8, ts: i64, object: u64, path: &str| {
        let mut p = object.to_le_bytes().to_vec();
        p.extend_from_slice(&utf16z(path));
        (guids::FILE_IO, op, 2, ts, p, u32::MAX)
    };
    let create = |ts: i64, object: u64, path: &str| {
        let mut p = 0xa1u64.to_le_bytes().to_vec();
        p.extend_from_slice(&object.to_le_bytes());
        for v in [200u32, 0, 0, 0] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&utf16z(path));
        (guids::FILE_IO, 64, 3, ts, p, u32::MAX)
    };
    // HardFault v2: start, offset, address, file object, thread, bytes.
    let fault = |start: u64, end: i64, object: u64, tid: u32, size: u32| {
        let mut p = Vec::new();
        for v in [start, 0x1000, 0x7ff0_0000_1000, object] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p.extend_from_slice(&tid.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        (guids::PAGE_FAULT, 32, 2, end, p, u32::MAX)
    };
    let path = app_trace(
        &dir,
        vec![
            name(0, 10, 1, r"C:\a.dll"),
            create(20, 2, r"C:\b.exe"),
            // 20 us, 10 us, 100 us (a thread we don't know), 1 us.
            fault(100, 300, 1, 200, 4096),
            fault(400, 500, 2, 200, 8192),
            fault(600, 1_600, 3, 999, 16_384),
            fault(700, 710, 9, 200, 4096),
            name(36, 2_000, 3, r"C:\c.dat"),
        ],
    );
    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "hardfaults", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("process", json!({})),
        req("file", json!({})),
        req("thread", json!({"limit": 2})),
        req("file", json!({"groupLimit": 1})),
        req("process", json!({"time": [0, 50_000]})),
        req("nonsense", json!({})),
    ]);
    let by = |id: u64| -> std::collections::BTreeMap<String, (u64, u64, u64)> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    (n("count"), n("bytes"), n("durationNs")),
                )
            })
            .collect()
    };
    let r = result(&a, 2);
    assert_eq!(
        (
            r["count"].as_u64(),
            r["bytes"].as_u64(),
            r["durationNs"].as_u64()
        ),
        (Some(4), Some(32_768), Some(131_000))
    );
    let procs = by(2);
    assert_eq!(procs["app.exe (100)"], (3, 16_384, 31_000));
    assert_eq!(procs["Unknown process"], (1, 16_384, 100_000));
    let files = by(3);
    assert_eq!(files[r"C:\a.dll"], (1, 4096, 20_000), "by a name event");
    assert_eq!(files[r"C:\b.exe"], (1, 8192, 10_000), "by a create's path");
    assert_eq!(files[r"C:\c.dat"].0, 1, "by the rundown after");
    assert_eq!(files["Unknown file"].0, 1);
    let threads = by(4);
    assert_eq!(threads["200 in app.exe (100)"].0, 3);
    assert_eq!(threads["Unknown thread"].0, 1);
    // The longest, a limit of them.
    let longest = result(&a, 4)["faults"].as_array().unwrap().clone();
    assert_eq!(longest.len(), 2);
    assert_eq!(
        (
            &longest[0]["durationNs"],
            &longest[0]["file"],
            &longest[0]["tid"],
            &longest[0]["size"]
        ),
        (
            &json!(100_000),
            &json!(r"C:\c.dat"),
            &Value::Null,
            &json!(16_384)
        )
    );
    assert_eq!(
        (
            &longest[1]["startNs"],
            &longest[1]["offset"],
            &longest[1]["address"]
        ),
        (&json!(10_000), &json!(0x1000), &json!("0x7ff000001000"))
    );
    // The most time first, and only as many groups as asked for.
    let r = result(&a, 5);
    assert_eq!(r["groupsTotal"], 4);
    assert_eq!(r["groups"].as_array().unwrap().len(), 1);
    assert_eq!(r["groups"][0]["label"], r"C:\c.dat");
    // A time range: those started by 50 us.
    assert_eq!(result(&a, 6)["count"], 2);
    assert!(error(&a, 7).contains("by"), "{}", error(&a, 7));
}

#[test]
fn virtual_memory_commit_lifetimes() {
    use hexcavator_etw::guids;
    let dir = scratch("serve-vmem");
    const COMMIT: u32 = 0x1000;
    const RESERVE: u32 = 0x2000;
    const DECOMMIT: u32 = 0x4000;
    const RELEASE: u32 = 0x8000;
    // VirtualAlloc (98) and VirtualFree (99) v2: base, size, process,
    // flags; by thread 200.
    let event = |op: u8, ts: i64, base: u64, size: u64, pid: u32, flags: u32| {
        let mut p = base.to_le_bytes().to_vec();
        p.extend_from_slice(&size.to_le_bytes());
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&flags.to_le_bytes());
        (guids::PAGE_FAULT, op, 2, ts, p, 200)
    };
    let path = app_trace(
        &dir,
        vec![
            // Reserve and commit 64 KB at 0x10000.
            event(98, 10, 0x10000, 0x10000, 100, RESERVE | COMMIT),
            // Commit 64 KB at 0x18000: only its last 32 KB are new.
            event(98, 20, 0x18000, 0x10000, 100, COMMIT),
            // Decommit 16 KB from the middle of the first.
            event(99, 30, 0x14000, 0x4000, 100, DECOMMIT),
            // Release the reservation (of no size: all of it): what's
            // left of the first, not the second's new part.
            event(99, 40, 0x10000, 0, 100, RELEASE),
            // A commit in a process we don't know.
            event(98, 50, 0x50000, 0x1000, 300, COMMIT),
            // A reservation alone, and a decommit of what isn't committed.
            event(98, 60, 0x90000, 0x1000, 100, RESERVE),
            event(99, 70, 0xa0000, 0x1000, 100, DECOMMIT),
        ],
    );
    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "vmem", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("process", json!({})),
        req("thread", json!({"limit": 2})),
        req("process", json!({"time": [0, 3_500]})),
        req("process", json!({"groupLimit": 1})),
        req("nonsense", json!({})),
    ]);
    let totals = |id: u64| {
        let r = result(&a, id);
        let n = |k: &str| r[k].as_u64().unwrap();
        [
            n("commits"),
            n("committed"),
            n("decommits"),
            n("decommitted"),
            n("outstanding"),
        ]
    };
    let by = |id: u64| -> std::collections::BTreeMap<String, [u64; 5]> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_u64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    [
                        n("commits"),
                        n("committed"),
                        n("decommits"),
                        n("decommitted"),
                        n("outstanding"),
                    ],
                )
            })
            .collect()
    };
    // The lifetimes: 16 KB (decommitted at 30), 16 KB and 32 KB (released
    // at 40), 32 KB and 4 KB (still committed).
    assert_eq!(totals(2), [5, 0x19000, 3, 0x10000, 0x9000]);
    let procs = by(2);
    assert_eq!(procs["app.exe (100)"], [4, 0x18000, 3, 0x10000, 0x8000]);
    assert_eq!(procs["Unknown process"], [1, 0x1000, 0, 0, 0x1000]);
    assert_eq!(by(3)["200 in app.exe (100)"][0], 5);
    // The largest, a limit of them (the earlier of two the same size
    // first).
    let largest = result(&a, 3)["lifetimes"].as_array().unwrap().clone();
    assert_eq!(largest.len(), 2);
    assert_eq!(
        (
            &largest[0]["base"],
            &largest[0]["size"],
            &largest[0]["commitNs"],
            &largest[0]["decommitNs"],
            &largest[0]["decommitTid"]
        ),
        (
            &json!("0x18000"),
            &json!(0x8000),
            &json!(1_000),
            &json!(4_000),
            &json!(200)
        )
    );
    assert_eq!(
        (
            &largest[1]["base"],
            &largest[1]["decommitNs"],
            &largest[1]["tid"]
        ),
        (&json!("0x20000"), &Value::Null, &json!(200))
    );
    // To 3.5 us: all of app.exe's commits and the first decommit; at its
    // end, all but that still committed.
    assert_eq!(totals(4), [4, 0x18000, 1, 0x4000, 0x14000]);
    // The most still committed first, and only as many groups as asked.
    let r = result(&a, 5);
    assert_eq!(r["groupsTotal"], 2);
    assert_eq!(r["groups"].as_array().unwrap().len(), 1);
    assert_eq!(r["groups"][0]["label"], "app.exe (100)");
    assert!(error(&a, 6).contains("by"), "{}", error(&a, 6));
}

/// An allocation summary's totals: `[allocs, allocated, frees, freed,
/// outstandingCount, outstanding]`.
fn block_counts(v: &Value) -> [u64; 6] {
    let n = |k: &str| v[k].as_u64().unwrap();
    [
        n("allocs"),
        n("allocated"),
        n("frees"),
        n("freed"),
        n("outstandingCount"),
        n("outstanding"),
    ]
}

/// An allocation summary's groups' counts, by label.
fn block_groups(v: &Value) -> std::collections::BTreeMap<String, [u64; 6]> {
    v["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["label"].as_str().unwrap().to_string(), block_counts(g)))
        .collect()
}

#[test]
fn heap_blocks_by_process_heap_and_thread() {
    use hexcavator_etw::guids;
    let dir = scratch("serve-heap");
    let ptrs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let with_source = |mut p: Vec<u8>| {
        p.extend_from_slice(&0u32.to_le_bytes());
        p
    };
    let (h1, h2, h3) = (0x1000, 0x2000, 0x3000);
    let alloc = |ts: i64, heap: u64, size: u64, address: u64, tid: u32| {
        (
            guids::HEAP,
            33,
            2,
            ts,
            with_source(ptrs(&[heap, size, address])),
            tid,
        )
    };
    let free = |ts: i64, heap: u64, address: u64| {
        (
            guids::HEAP,
            36,
            2,
            ts,
            with_source(ptrs(&[heap, address])),
            200,
        )
    };
    let path = app_trace(
        &dir,
        vec![
            alloc(10, h1, 100, 0xa1, 200),
            alloc(20, h1, 200, 0xa2, 200),
            // A realloc: 0xa2 ends, 0xa3 (300 bytes) starts.
            (
                guids::HEAP,
                34,
                2,
                30,
                with_source(ptrs(&[h1, 0xa3, 0xa2, 300, 200])),
                200,
            ),
            free(40, h1, 0xa1),
            alloc(50, h2, 1000, 0xa4, 200),
            alloc(60, h1, 50, 0xa5, 200),
            // Destroying heap 1 ends its blocks (0xa3, 0xa5).
            (guids::HEAP, 35, 2, 70, ptrs(&[h1]), 200),
            // A free of what we didn't see allocated.
            free(80, h1, 0xa9),
            // A thread (and so process) we don't know.
            alloc(90, h3, 10, 0xa6, 999),
        ],
    );
    let req = |by: Option<&str>, extra: Value| {
        let mut p = json!({"trace": 1});
        if let Some(by) = by {
            p["by"] = json!(by);
        }
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "heap", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req(None, json!({})),
        req(Some("heap"), json!({})),
        req(Some("thread"), json!({"limit": 2})),
        req(Some("process"), json!({"time": [0, 4_500]})),
        req(Some("tag"), json!({})),
    ]);
    // Blocks: 0xa1 (100, freed), 0xa2 (200, realloc'd), 0xa3 (300) and
    // 0xa5 (50) (destroyed), 0xa4 (1000) and 0xa6 (10) still allocated.
    let r = result(&a, 2);
    assert_eq!(block_counts(r), [6, 1660, 4, 650, 2, 1010]);
    let procs = block_groups(r);
    assert_eq!(procs["app.exe (100)"], [5, 1650, 4, 650, 1, 1000]);
    assert_eq!(procs["Unknown process"], [1, 10, 0, 0, 1, 10]);
    let heaps = block_groups(result(&a, 3));
    assert_eq!(heaps["0x1000 in app.exe (100)"], [4, 650, 4, 650, 0, 0]);
    assert_eq!(heaps["0x2000 in app.exe (100)"], [1, 1000, 0, 0, 1, 1000]);
    assert_eq!(heaps["0x3000 in Unknown process"], [1, 10, 0, 0, 1, 10]);
    let r = result(&a, 4);
    assert_eq!(block_groups(r)["200 in app.exe (100)"][0], 5);
    // The largest, a limit of them.
    let blocks = r["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        (
            &blocks[0]["size"],
            &blocks[0]["freeNs"],
            &blocks[0]["group"],
            &blocks[0]["kind"]
        ),
        (
            &json!(1000),
            &Value::Null,
            &json!("0x2000 in app.exe (100)"),
            &json!("Heap")
        )
    );
    assert_eq!(
        (
            &blocks[1]["address"],
            &blocks[1]["allocNs"],
            &blocks[1]["freeNs"],
            &blocks[1]["tid"]
        ),
        (&json!("0xa3"), &json!(3_000), &json!(7_000), &json!(200))
    );
    // To 4.5 us: 0xa1, 0xa2 and 0xa3 allocated; 0xa2 and 0xa1 freed; 0xa3
    // still allocated at its end.
    assert_eq!(block_counts(result(&a, 5)), [3, 600, 2, 300, 1, 300]);
    assert!(error(&a, 6).contains("by"), "{}", error(&a, 6));
}

#[test]
fn pool_blocks_by_tag_type_and_process() {
    use hexcavator_etw::guids;
    let dir = scratch("serve-pool");
    let tag = |t: &[u8; 4]| u32::from_le_bytes(*t);
    // Pool Alloc (32) and Free (34) v2: type, tag, size, address.
    let block = |op: u8, ts: i64, pool_type: u32, tag: u32, size: u64, address: u64| {
        let mut p = pool_type.to_le_bytes().to_vec();
        p.extend_from_slice(&tag.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        p.extend_from_slice(&address.to_le_bytes());
        (guids::POOL, op, 2, ts, p, 200)
    };
    let abcd = tag(b"Abcd");
    let path = app_trace(
        &dir,
        vec![
            block(32, 10, 0, abcd, 64, 0xb1),
            block(32, 20, 1, abcd, 128, 0xb2),
            // Paged session pool; a protected tag, padded with spaces.
            block(32, 30, 33, tag(b"Xy  ") | 0x8000_0000, 32, 0xb3),
            block(34, 40, 0, abcd, 0, 0xb1),
            block(34, 50, 0, abcd, 0, 0xb9),
            // An allocation where one still is: that one ends.
            block(32, 60, 0, abcd, 256, 0xb2),
        ],
    );
    let req = |by: Option<&str>| {
        let mut p = json!({"trace": 1});
        if let Some(by) = by {
            p["by"] = json!(by);
        }
        json!({"method": "pool", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req(None),
        req(Some("type")),
        req(Some("process")),
        req(Some("heap")),
    ]);
    let r = result(&a, 2);
    assert_eq!(block_counts(r), [4, 480, 2, 192, 2, 288]);
    let tags = block_groups(r);
    assert_eq!(tags["Abcd"], [3, 448, 2, 192, 1, 256]);
    assert_eq!(tags["Xy"], [1, 32, 0, 0, 1, 32]);
    let types = block_groups(result(&a, 3));
    assert_eq!(types["Nonpaged"][..2], [2, 320]);
    assert_eq!(types["Paged"][..2], [1, 128]);
    assert_eq!(types["Paged (session)"][..2], [1, 32]);
    assert_eq!(block_groups(result(&a, 4))["app.exe (100)"][0], 4);
    let largest = &result(&a, 2)["blocks"][0];
    assert_eq!(
        (&largest["size"], &largest["kind"], &largest["group"]),
        (&json!(256), &json!("Nonpaged"), &json!("Abcd"))
    );
    assert!(error(&a, 5).contains("by"), "{}", error(&a, 5));
}

#[test]
fn memory_utilization_by_process_and_name() {
    use hexcavator_etw::guids;
    let dir = scratch("serve-memory");
    const P: u64 = 4096;
    // ProcessMemInfo (125) v4: a count, then per process its ID and eight
    // page counts (working set, commit, virtual size, private working
    // set, then four more).
    let info = |ts: i64, records: &[(u32, u64, u64, u64)]| {
        let mut p = u32::try_from(records.len()).unwrap().to_le_bytes().to_vec();
        for &(pid, ws, private, commit) in records {
            p.extend_from_slice(&pid.to_le_bytes());
            for v in [ws, commit, 100, private, 0, 0, 0, 0] {
                p.extend_from_slice(&v.to_le_bytes());
            }
        }
        (guids::PAGE_FAULT, 125, 4, ts, p, u32::MAX)
    };
    // The first snapshot is split: 256 processes (app.exe, 1000 and 254
    // more), then 2 more 100 ns later.
    let mut first = vec![(100, 10, 4, 20), (1000, 1, 1, 1)];
    first.extend((1001..1255).map(|pid| (pid, 1, 1, 1)));
    let path = app_trace(
        &dir,
        vec![
            info(10, &first),
            info(11, &[(4, 1, 1, 1), (5, 1, 1, 1)]),
            // One not the layout's length.
            (
                guids::PAGE_FAULT,
                125,
                4,
                2_000_000,
                vec![1, 0, 0, 0, 9],
                u32::MAX,
            ),
            // Half a second on.
            info(5_000_010, &[(100, 30, 5, 15), (1000, 2, 2, 3)]),
        ],
    );
    let req = |by: &str, extra: Value| {
        let mut p = json!({"trace": 1, "by": by});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "memory", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req("process", json!({})),
        req("name", json!({})),
        req("process", json!({"time": [0, 250_000_000]})),
        req("process", json!({"groupLimit": 1, "limit": 1})),
        req("nonsense", json!({})),
    ]);
    let groups = |id: u64| -> std::collections::BTreeMap<String, [i64; 6]> {
        result(&a, id)["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let n = |k: &str| g[k].as_i64().unwrap();
                (
                    g["label"].as_str().unwrap().to_string(),
                    [
                        n("workingSet"),
                        n("privateWorkingSet"),
                        n("commit"),
                        n("peakWorkingSet"),
                        n("peakCommit"),
                        n("commitChange"),
                    ],
                )
            })
            .collect()
    };
    let p = |v: i64| v * 4096;
    let r = result(&a, 2);
    assert_eq!(
        (&r["snapshots"], &r["malformed"], &r["groupsTotal"]),
        (&json!(2), &json!(1), &json!(258))
    );
    assert_eq!(
        (r["workingSet"].as_u64(), r["commit"].as_u64()),
        (Some(32 * P), Some(18 * P))
    );
    let series: Vec<(i64, u64, u64, u64)> = r["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["timeNs"].as_i64().unwrap(),
                s["processes"].as_u64().unwrap(),
                s["workingSet"].as_u64().unwrap(),
                s["commit"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        series,
        [
            (1_000, 258, 267 * P, 277 * P),
            (500_001_000, 2, 32 * P, 18 * P)
        ],
        "the split snapshot is one, at its first event's time"
    );
    let procs = groups(2);
    assert_eq!(
        procs["app.exe (100)"],
        [p(30), p(5), p(15), p(30), p(20), p(-5)]
    );
    assert_eq!(
        procs["Unknown process (1000)"],
        [p(2), p(2), p(3), p(2), p(3), p(2)]
    );
    assert_eq!(
        procs["Unknown process (1001)"],
        [0, 0, 0, p(1), p(1), p(-1)],
        "gone by the last"
    );
    let names = groups(3);
    assert_eq!(names.len(), 2);
    assert_eq!(names["Unknown process"][2..5], [p(3), p(257), p(257)]);
    // The first quarter second: the first snapshot alone.
    let early = groups(4);
    assert_eq!(
        early["app.exe (100)"],
        [p(10), p(4), p(20), p(10), p(20), 0]
    );
    assert_eq!(result(&a, 4)["snapshots"], 1);
    // The most commit first, and only as many as asked for.
    let r = result(&a, 5);
    assert_eq!(r["groups"].as_array().unwrap().len(), 1);
    assert_eq!(r["groups"][0]["label"], "app.exe (100)");
    assert_eq!(r["series"].as_array().unwrap().len(), 1);
    assert!(error(&a, 6).contains("by"), "{}", error(&a, 6));
}

#[test]
fn csv_quotes_what_needs_it() {
    use stackrabbit::query::to_csv;
    let rows = vec![
        json!({"a": "plain", "b": 1, "c": null}),
        json!({"a": "with, comma", "b": "say \"hi\"", "d": [1, 2]}),
        json!({"a": "two\nlines", "b": " padded"}),
    ];
    assert_eq!(
        to_csv(&rows),
        "a,b,c,d\r\nplain,1,,\r\n\"with, comma\",\"say \"\"hi\"\"\",,\"[1,2]\"\r\n\"two\nlines\",\" padded\",,\r\n"
    );
    assert_eq!(to_csv(&[json!(1), json!("x")]), "value\r\n1\r\nx\r\n");
    assert_eq!(to_csv(&[]), "value\r\n");
}

#[test]
fn profiles_are_mapped_without_a_trace() {
    let dir = scratch("serve-profile");
    let file = dir.join("p.wpaProfile");
    std::fs::write(
        &file,
        r#"<WpaProfileContainer><Content><Views><View Title="Disk"><Graphs><Graph Guid="12C5387C-58CA-45D4-A5C6-450475C30E06"><Preset Name="By Disk" KeyColumnCount="1"><Columns><Column Name="Disk"/></Columns></Preset></Graph></Graphs></View></Views></Content></WpaProfileContainer>"#,
    )
    .unwrap();
    let a = session(&[
        json!({"method": "profile", "params": {"path": file}}),
        json!({"method": "profile", "params": {"path": dir.join("missing.wpaProfile")}}),
        json!({"method": "profile", "params": {}}),
    ]);
    let r = result(&a, 1);
    assert_eq!(
        (r["graphs"].as_u64(), r["shown"].as_u64()),
        (Some(1), Some(1))
    );
    let g = &r["views"][0]["graphs"][0];
    assert_eq!(
        (&g["tab"], &g["params"]),
        (&json!("disk"), &json!({"by": "disk"}))
    );
    assert!(error(&a, 2).contains("missing.wpaProfile"));
    assert!(error(&a, 3).contains("path"));
}

#[test]
fn summaries_take_wpa_filters() {
    use hexcavator_etw::guids;
    // Registry: four operations, two of them opens.
    let dir = scratch("serve-filters");
    let path = registry_trace(
        &dir,
        &[
            (11, 20, 10, 0, 0, r"\REGISTRY\A", 200, 100),
            (11, 40, 30, 0xc000_0034, 0, r"\REGISTRY\B", 200, 100),
            (16, 60, 50, 0, 0, "", 200, 100),
            (27, 80, 70, 0, 0, r"\REGISTRY\A", 999, 777),
        ],
    );
    let req = |params: Value| {
        let mut p = json!({"trace": 1});
        for (k, v) in params.as_object().unwrap() {
            p[k] = v.clone();
        }
        json!({"method": "registry", "params": p})
    };
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        req(json!({"filter": "[Operation]:=Open"})),
        req(json!({"filter": "[Operation]:=open [Status]:<>0x00000000"})),
        req(json!({"filter": r#"[Key]:~>"\a" OR [Process Name]:="app.exe""#})),
        req(json!({"filter": "NOT [Process ID]:=100", "by": "process"})),
        req(json!({"filter": "  "})),
        req(json!({"filter": "[Nonsense]:=1"})),
        req(json!({"filter": "[Operation]:="})),
    ]);
    assert_eq!(result(&a, 2)["count"], 2);
    assert_eq!(result(&a, 3)["count"], 1, "the failed open");
    // (The Close of \REGISTRY\A by an unknown process; the opens and the
    // query by app.exe.)
    assert_eq!(result(&a, 4)["count"], 4);
    let r = result(&a, 5);
    assert_eq!(r["count"], 1);
    assert_eq!(
        r["groups"][0]["label"], "Unknown process",
        "no process: not 100"
    );
    assert_eq!(result(&a, 6)["count"], 4, "a blank filter is none");
    let e = error(&a, 7);
    assert!(e.contains("[Nonsense]") && e.contains("Key Name"), "{e}");
    assert!(error(&a, 8).contains("filter"), "{}", error(&a, 8));

    // Heap: by heap and size.
    let dir = scratch("serve-filters-heap");
    let ptrs = |v: &[u64]| v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let alloc = |ts: i64, heap: u64, size: u64, address: u64| {
        let mut p = ptrs(&[heap, size, address]);
        p.extend_from_slice(&0u32.to_le_bytes());
        (guids::HEAP, 33, 2, ts, p, 200)
    };
    let path = app_trace(
        &dir,
        vec![
            alloc(10, 0x1000, 100, 0xa1),
            alloc(20, 0x1000, 5000, 0xa2),
            alloc(30, 0x2000, 70, 0xa3),
        ],
    );
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        json!({"method": "heap", "params": {"trace": 1, "filter": "[Heap]:~<0x1000 [Size]:>=100"}}),
        json!({"method": "heap", "params": {"trace": 1, "filter": "[Size]:<1000", "by": "heap"}}),
        json!({"method": "hardfaults", "params": {"trace": 1, "filter": "[Heap]:=1"}}),
    ]);
    assert_eq!(result(&a, 2)["allocated"], 5100);
    let r = result(&a, 3);
    assert_eq!(
        (r["allocs"].as_u64(), r["groupsTotal"].as_u64()),
        (Some(2), Some(2))
    );
    assert!(error(&a, 4).contains("[Heap]"), "a column of another table");
}

#[test]
fn event_kinds_take_wpa_filters() {
    let dir = scratch("serve-event-filters");
    let path = registry_trace(
        &dir,
        &[
            (11, 20, 10, 0, 0, r"\REGISTRY\A", 200, 100),
            (11, 40, 30, 0, 0, r"\REGISTRY\B", 200, 100),
            (27, 80, 70, 0, 0, r"\REGISTRY\A", 200, 100),
        ],
    );
    let ask = |filter: &str| json!({"method": "events", "params": {"trace": 1, "filter": filter}});
    let a = session(&[
        json!({"method": "open", "params": {"path": path, "useIndex": true}}),
        ask("[Task Name]:=Registry [Opcode Name]:=Open"),
        ask("[Task Name]:=Registry"),
        ask("[Opcode]:>=27 OR [Provider Name]:=Process"),
        ask("[Field 1]:=x"),
    ]);
    let kinds = |id: u64| -> Vec<(String, u64)> {
        result(&a, id)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["opcodeName"].as_str().unwrap_or("").to_string(),
                    r["count"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    assert_eq!(kinds(2), [("Open".to_string(), 2)]);
    assert_eq!(kinds(3).len(), 2, "the opens and the close");
    let r = kinds(4);
    assert!(
        r.contains(&("Close".to_string(), 1)) && r.contains(&("DCStart".to_string(), 1)),
        "{r:?}"
    );
    assert!(error(&a, 5).contains("[Field 1]"));
}

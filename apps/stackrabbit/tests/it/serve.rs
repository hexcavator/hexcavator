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

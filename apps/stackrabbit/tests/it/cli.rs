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

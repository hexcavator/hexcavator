//! `hexc annotations`, `hexc batch`, `hexc size -findings -- base`, and the
//! query table's source columns, end to end.

use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn hexc(args: &[&std::ffi::OsStr]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The types test program has two annotations: one in `use`, one in an
/// inlined copy of `annotated_inline`. The inlined copy's code folded into
/// `use`'s (its site has no code), and its record is in `use`'s scope: the
/// PDB doesn't say it is inlined, so neither is marked so.
#[test]
fn annotations() {
    let exe = testdata("types/types.exe");
    let (code, out, err) = hexc(&["annotations".as_ref(), exe.as_os_str()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("2 annotations:\n"), "{out}");
    let lines: Vec<&str> = out.lines().skip(1).collect();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("types.cpp:")
                && l.ends_with("Hexcavator | layout test | third string")),
        "{out}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("types.cpp:") && l.ends_with("Hexcavator | in an inlined copy")),
        "{out}"
    );
    let (_, out, _) = hexc(&["annotations".as_ref(), "-json".as_ref(), exe.as_os_str()]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let list = v["annotations"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(
        list.iter()
            .any(|a| a["strings"].as_array().unwrap().len() == 3 && a["inlined"] == false)
    );
    assert!(
        list.iter()
            .all(|a| a["file"].as_str().unwrap().ends_with("types.cpp"))
    );
}

#[test]
fn batch() {
    let dir = testdata("types");
    let (code, out, err) = hexc(&[
        "batch".as_ref(),
        "-top".as_ref(),
        "3".as_ref(),
        dir.as_os_str(),
    ]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(lines[0]["path"].as_str().unwrap().ends_with("types-v2.exe"));
    assert!(lines[1]["path"].as_str().unwrap().ends_with("types.exe"));
    for l in &lines {
        assert!(l["pdb"].as_str().unwrap().ends_with(".pdb"));
        assert!(
            l["sections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == ".text")
        );
        assert_eq!(l["libraries"].as_array().unwrap().len(), 3);
        assert!(l["compilands"].as_array().unwrap().len() <= 3);
        assert!(l.get("findings").is_none());
    }
    // With the findings; and a file that isn't an image: its error, the
    // rest still summarized, and a failing exit.
    // (A stripped image with no debug file to be found.)
    let bad = testdata("elf/program-stripped");
    let exe = testdata("types/types.exe");
    let (code, out, _) = hexc(&[
        "batch".as_ref(),
        "-findings".as_ref(),
        exe.as_os_str(),
        bad.as_os_str(),
    ]);
    assert_eq!(code, 1);
    let lines: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    let err = lines.iter().find(|l| l.get("error").is_some()).unwrap();
    assert!(
        err["error"]
            .as_str()
            .unwrap()
            .contains("no matching debug information found"),
        "{err}"
    );
    let good = lines.iter().find(|l| l.get("error").is_none()).unwrap();
    assert!(good["findings"]["templateFamilies"].as_u64().is_some());
    let (code, _, err) = hexc(&["batch".as_ref()]);
    assert_eq!(code, 2);
    assert!(err.contains("no files or directories given"), "{err}");
}

/// The findings of two builds compared: every finding's totals, and JSON
/// with the same.
#[test]
fn findings_compared() {
    let bin = testdata("sizebench/bin");
    let new = bin.join("SizeBenchV2.AnalysisEngine.Tests.CppTestCasesAfter.dll");
    let old = bin.join("SizeBenchV2.AnalysisEngine.Tests.CppTestCasesBefore.dll");
    let (code, out, err) = hexc(&[
        "size".as_ref(),
        "-findings".as_ref(),
        new.as_os_str(),
        "--".as_ref(),
        old.as_os_str(),
    ]);
    assert_eq!(code, 0, "{err}");
    for title in [
        "Duplicate data (wasted file bytes): ",
        "Template families (bytes): ",
        "Wasteful virtuals (wasted bytes): ",
    ] {
        assert!(out.lines().any(|l| l.starts_with(title)), "{title}: {out}");
    }
    let (_, out, _) = hexc(&[
        "size".as_ref(),
        "-findings".as_ref(),
        "-json".as_ref(),
        new.as_os_str(),
        "--".as_ref(),
        old.as_os_str(),
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    for key in ["duplicate_data", "template_families", "wasteful_virtuals"] {
        let f = &v[key];
        assert!(
            f["base"].as_u64().is_some() && f["new"].as_u64().is_some(),
            "{key}: {v}"
        );
        let delta: i64 = f["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["new"].as_i64().unwrap_or(0) - c["base"].as_i64().unwrap_or(0))
            .sum();
        // The changes (all listed: few) account for the totals' difference.
        assert_eq!(
            delta,
            f["new"].as_i64().unwrap() - f["base"].as_i64().unwrap(),
            "{key}: {v}"
        );
    }
    // A build against itself: nothing changed.
    let (_, out, _) = hexc(&[
        "size".as_ref(),
        "-findings".as_ref(),
        new.as_os_str(),
        "--".as_ref(),
        new.as_os_str(),
    ]);
    assert!(out.lines().all(|l| l.ends_with(", 0 changed")), "{out}");
}

/// The query table knows where each function's code starts.
#[test]
fn query_source_lines() {
    let exe = testdata("lines/lines.exe");
    let (code, out, err) = hexc(&[
        "query".as_ref(),
        "-csv".as_ref(),
        exe.as_os_str(),
        "name='first(int)' select name, source, line".as_ref(),
    ]);
    assert_eq!(code, 0, "{err}");
    let row = out.lines().nth(1).unwrap();
    assert!(
        row.starts_with("first(int),") && row.ends_with(r"tools\lines\lines.cpp,7"),
        "{out}"
    );
    let (_, out, _) = hexc(&[
        "query".as_ref(),
        exe.as_os_str(),
        "source~'lines\\.h$' group by source".as_ref(),
    ]);
    assert!(
        out.lines()
            .nth(1)
            .is_some_and(|l| l.contains(r"tools\lines\lines.h")),
        "{out}"
    );
}

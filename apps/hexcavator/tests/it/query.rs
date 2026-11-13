//! `hexc query` end to end, over the cross-reference test program
//! (testdata/xref).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/xref/xref-x64.exe")
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("query")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn query(q: &str, extra: &[&str]) -> String {
    let image = fixture();
    let mut args = extra.to_vec();
    args.push(image.to_str().unwrap());
    args.push(q);
    let (code, out, err) = hexc(&args);
    assert_eq!(code, 0, "{q}: {err}");
    out
}

#[test]
fn filters_and_selects() {
    assert_eq!(
        query(
            "name~'^(inner|outer)\\(' select name, kind, section sort by name",
            &[]
        ),
        "name        kind      section\n\
         inner(int)  function  .text\n\
         outer(int)  function  .text\n\
         (2 of 2 matching rows)\n"
    );
    // The CSV and JSON forms.
    let csv = query("name='op_add(int)' select name, compiland", &["-csv"]);
    assert!(
        csv.starts_with("name,compiland\nop_add(int),") && csv.ends_with("main.obj\n"),
        "{csv}"
    );
    assert_eq!(csv.lines().count(), 2);
    let v: serde_json::Value = serde_json::from_str(&query(
        "kind=function not folded name~'^Ghost::' sort by name",
        &["-json"],
    ))
    .unwrap();
    assert_eq!(v["matched"], 4);
    let names: Vec<&str> = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "Ghost::Ghost()",
            "Ghost::`scalar deleting destructor'(unsigned int)",
            "Ghost::area() const",
            "Ghost::name() const"
        ]
    );
    assert_eq!(v["rows"][0]["folded"], false);
    assert!(v["rows"][0]["file"].as_u64().unwrap() > 0);
}

#[test]
fn grouping() {
    let v: serde_json::Value = serde_json::from_str(&query(
        "kind=function not folded compiland~'\\\\(main|dead)\\.obj$' group by compiland sort by count desc",
        &["-json"],
    ))
    .unwrap();
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows[0]["compiland"].as_str().unwrap().ends_with("main.obj"),
        "{v}"
    );
    assert!(
        rows[1]["compiland"].as_str().unwrap().ends_with("dead.obj"),
        "{v}"
    );
    // dead.obj: dead_entry, dead_helper, live_in_dead_object, and Ghost's
    // constructor, scalar deleting destructor, and two virtual functions.
    assert_eq!(rows[1]["count"], 7, "{v}");
    let sum: u64 = rows.iter().map(|r| r["count"].as_u64().unwrap()).sum();
    assert_eq!(v["matched"].as_u64().unwrap(), sum);
    for r in rows {
        assert!(r["file"].as_u64().unwrap() > 0 && r["vm"].as_u64().is_some());
    }
    let out = query("section=.text group by section", &[]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(
        lines[0].split_whitespace().collect::<Vec<_>>(),
        ["section", "count", "file", "vm"]
    );
    assert!(lines[1].starts_with(".text "), "{out}");
}

#[test]
fn errors_and_help() {
    let image = fixture();
    let image = image.to_str().unwrap();
    let (code, _, err) = hexc(&[image, "size>1k"]);
    assert_eq!(code, 2);
    assert!(err.contains("no column 'size'"), "{err}");
    assert!(err.contains("\n  size>1k\n  ^\n"), "{err}");
    let (code, _, err) = hexc(&[image, "file>big"]);
    assert_eq!(code, 2);
    assert!(err.contains("\n  file>big\n       ^\n"), "{err}");
    let (code, _, err) = hexc(&[image]);
    assert_eq!(code, 2);
    assert!(err.contains("no query given"), "{err}");
    let (code, _, err) = hexc(&[image, "kind=function", "extra"]);
    assert_eq!(code, 2);
    assert!(err.contains("too many arguments"), "{err}");
    let (code, _, err) = hexc(&[image, "sort by nope"]);
    assert_eq!(code, 2);
    assert!(err.contains("can't sort by 'nope'"), "{err}");
    // A stripped image with no debug file to be found.
    let elf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/elf/program-stripped");
    let (code, _, err) = hexc(&[elf.to_str().unwrap(), "kind=function"]);
    assert_eq!(code, 1);
    assert!(err.contains("no matching debug information found"), "{err}");
    let (code, out, _) = hexc(&["-columns"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("  name       the symbol's name, demangled\n"),
        "{out}"
    );
    assert_eq!(out.lines().count(), 13);
}

/// ELF and Mach-O images, with DWARF: in the image, or given.
#[test]
fn elf_and_macho_with_dwarf() {
    let data = |p: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(p)
            .to_str()
            .unwrap()
            .to_string()
    };
    let elf = data("elf/dwarf5-x86_64-linux-gnu");
    let (code, out, err) = hexc(&[&elf, "kind=function sort by name", "-csv"]);
    assert_eq!(code, 0, "{err}");
    let names: Vec<&str> = out
        .lines()
        .skip(1)
        .map(|l| l.split(',').next().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "_start()",
            "compute(int)",
            "optional_hook()",
            "second_len()",
            "second_sum(int)"
        ]
    );
    // Each in its compile unit and source file.
    assert!(
        out.lines()
            .any(|l| l.starts_with("compute(int),") && l.contains("program.c"))
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with("second_sum(int),") && l.contains("second.c"))
    );
    // A dSYM's DWARF, given.
    let image = data("macho/program-arm64");
    let dwarf = data("macho/program-arm64.dwarf");
    let (code, out, err) = hexc(&[&image, "kind=function", "-pdb", &dwarf, "-csv"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.lines().any(|l| l.starts_with("compute(int),")), "{out}");
    // Not another image's.
    let other = data("macho/program-x86_64.dwarf");
    let (code, _, err) = hexc(&[&image, "kind=function", "-pdb", &other]);
    assert_eq!(code, 1);
    assert!(err.contains("does not match"), "{err}");
}

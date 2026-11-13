//! `hexc inlines` and `hexc sourcefiles` end to end, over the source lines
//! test program (tools/lines: a header's code, and inline sites, one
//! nested in another).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/lines/lines.exe")
}

fn hexc(command: &str, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg(command)
        .args(args)
        .arg(fixture())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn ok(command: &str, args: &[&str]) -> String {
    let (code, out, err) = hexc(command, args);
    assert_eq!(code, 0, "{command} {args:?}: {err}");
    out
}

/// square is inlined into first, and into third through sum_of_squares
/// (twice): three copies in two functions; sum_of_squares's own code is
/// apart from square's within it.
#[test]
fn inlines() {
    let out = ok("inlines", &["-n", "0"]);
    assert!(
        out.starts_with("17 inline sites of 15 functions: 363 bytes of code, most first:\n"),
        "{out}"
    );
    assert!(
        out.contains("\n        14       3          2  square\n"),
        "{out}"
    );
    assert!(
        out.contains("\n         3       1          1  sum_of_squares\n"),
        "{out}"
    );
    assert_eq!(
        ok("inlines", &["-inlinee", "sum_of_squares"]),
        "sum_of_squares: 3 bytes inlined into 1 function, most first:\n\
         \x20    bytes  copies  function\n\
         \x20        3       1  third(int, int)\n"
    );
    let out = ok("inlines", &["-inlinee", "^square$"]);
    assert!(
        out.starts_with("square: 14 bytes inlined into 2 functions, most first:\n"),
        "{out}"
    );
    assert!(out.contains("       2  third(int, int)\n"), "{out}");
    assert!(out.contains("       1  first(int)\n"), "{out}");
    let v: serde_json::Value = serde_json::from_str(&ok("inlines", &["-json", "-n", "3"])).unwrap();
    assert_eq!(v["sites"], 17);
    assert_eq!(v["bytes"], 363);
    assert_eq!(v["list"].as_array().unwrap().len(), 3);
    let v: serde_json::Value =
        serde_json::from_str(&ok("inlines", &["-json", "-inlinee", "square"])).unwrap();
    assert_eq!(v["bytes"], 14);
    assert_eq!(v["functions"][0]["function"], "third(int, int)");
    assert_eq!(v["functions"][0]["copies"], 2);
}

/// The header's code is its non-inlined template's; inlined code counts
/// where it was inlined.
#[test]
fn sourcefiles() {
    let out = ok("sourcefiles", &["-n", "0"]);
    assert!(
        out.starts_with("25 source files: 2822 bytes of code, most first:\n"),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l.ends_with(r"tools\lines\lines.cpp") && l.trim_start().starts_with("155")),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l.ends_with(r"tools\lines\lines.h") && l.trim_start().starts_with("9 ")),
        "{out}"
    );
    assert_eq!(
        ok("sourcefiles", &["-file", r"lines\.h$"])
            .lines()
            .skip(1)
            .collect::<Vec<_>>(),
        ["     bytes  line", "         7  13", "         2  14"]
    );
    let out = ok("sourcefiles", &["-file", r"lines\.cpp$"]);
    assert!(
        out.contains(": 155 bytes of code from 6 lines, most first:\n"),
        "{out}"
    );
    assert!(out.contains("\n        92  14\n"), "{out}");
    let v: serde_json::Value =
        serde_json::from_str(&ok("sourcefiles", &["-json", "-file", r"lines\.h$"])).unwrap();
    assert_eq!(v["bytes"], 9);
    assert_eq!(v["lines"][0]["line"], 13);
    let v: serde_json::Value =
        serde_json::from_str(&ok("sourcefiles", &["-json", "-n", "0"])).unwrap();
    let sum: u64 = v["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["bytes"].as_u64().unwrap())
        .sum();
    assert_eq!(v["bytes"].as_u64().unwrap(), sum);
}

#[test]
fn errors() {
    let (code, _, err) = hexc("inlines", &["-inlinee", "nope"]);
    assert_eq!(code, 1);
    assert!(err.contains("no inlined function 'nope'"), "{err}");
    let (code, _, err) = hexc("sourcefiles", &["-file", r"\.(h|cpp)$"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("source files") && err.contains("give one exactly"),
        "{err}"
    );
    let (code, _, err) = hexc("sourcefiles", &["-bogus"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown option 'bogus'"), "{err}");
    // A stripped image with no debug file to be found.
    let elf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/elf/program-stripped");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("inlines")
        .arg(elf)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no matching debug information found"), "{err}");
}

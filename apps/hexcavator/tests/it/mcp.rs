//! `hexc mcp` end to end: a client's session over stdio.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// An object from members, in order.
fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

/// Sends `requests` (with ids 1, 2, ...) after initializing; returns the
/// responses by id.
fn session(requests: &[(&str, Value)]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = String::new();
    input.push_str(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#);
    input.push('\n');
    input.push_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    input.push('\n');
    for (i, (tool, args)) in requests.iter().enumerate() {
        let call = object([
            ("jsonrpc", Value::from("2.0")),
            ("id", Value::from(i as u64 + 1)),
            ("method", Value::from("tools/call")),
            (
                "params",
                object([("name", Value::from(*tool)), ("arguments", args.clone())]),
            ),
        ]);
        input.push_str(&call.to_string());
        input.push('\n');
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let mut responses: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect();
    assert_eq!(responses.len(), requests.len() + 1);
    responses.remove(0);
    responses
}

fn result(r: &Value) -> &Value {
    let result = r.get("result").unwrap_or_else(|| panic!("{r}"));
    assert_eq!(
        result.get("isError").and_then(Value::as_bool),
        Some(false),
        "{r}"
    );
    result.get("structuredContent").unwrap()
}

#[test]
fn image_session() {
    let dll = testdata("sizebench/bin/PEParser.Tests.Dllx64.dll");
    let path = || Value::from(dll.to_string_lossy().into_owned());
    let len = std::fs::metadata(&dll).unwrap().len() as i64;
    let r = session(&[
        ("size_report", object([("path", path())])),
        (
            "size_report",
            object([
                ("path", path()),
                ("sources", Value::from(vec!["sections", "compileunits"])),
                ("rows", Value::from(3u32)),
            ]),
        ),
        (
            "symbols",
            object([("path", path()), ("limit", Value::from(5u32))]),
        ),
        (
            "symbols",
            object([
                ("path", path()),
                ("query", Value::from("dllmain")),
                ("kind", Value::from("function")),
            ]),
        ),
        (
            "lookup",
            object([("path", path()), ("address", Value::from("0x1000"))]),
        ),
        (
            "lookup",
            object([("path", path()), ("address", Value::from("0xFFFFFFF"))]),
        ),
        (
            "size_report",
            object([
                ("path", path()),
                (
                    "base",
                    Value::from(
                        testdata("sizebench/bin/PEParser.Tests.Dllx86.dll")
                            .to_string_lossy()
                            .into_owned(),
                    ),
                ),
            ]),
        ),
    ]);
    // Sections: every file byte.
    let report = result(&r[0]);
    assert_eq!(
        report.get("total").unwrap().get("file").unwrap().as_i64(),
        Some(len)
    );
    // By section then compiland, three rows a level.
    let report = result(&r[1]);
    let sections = report
        .get("total")
        .unwrap()
        .get("children")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(sections.len() <= 4);
    assert!(sections.iter().any(|s| s.get("children").is_some()));
    // The largest symbols, largest first.
    let symbols = result(&r[2]).get("symbols").unwrap().as_array().unwrap();
    assert_eq!(symbols.len(), 5);
    let sizes: Vec<u64> = symbols
        .iter()
        .map(|s| s.get("file_size").unwrap().as_u64().unwrap())
        .collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{sizes:?}");
    // A name search.
    let found = result(&r[3]);
    assert!(found.get("matched").unwrap().as_u64().unwrap() >= 1);
    let first = &found.get("symbols").unwrap().as_array().unwrap()[0];
    assert!(
        first
            .get("name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("dllmain")
    );
    // What's at the start of .text.
    let at = result(&r[4]);
    assert_eq!(
        at.get("sources")
            .unwrap()
            .get("sections")
            .unwrap()
            .get("label")
            .unwrap()
            .as_str(),
        Some(".text")
    );
    assert!(!at.get("symbols").unwrap().as_array().unwrap().is_empty());
    // Nothing is mapped far away: a tool error, not a protocol error.
    let nothing = r[5].get("result").unwrap();
    assert_eq!(nothing.get("isError").unwrap().as_bool(), Some(true));
    // A diff.
    let diff = result(&r[6]);
    assert_eq!(diff.get("diff").unwrap().as_bool(), Some(true));
}

#[test]
fn library_session() {
    let lib = testdata("coff/objects.lib");
    let path = || Value::from(lib.to_string_lossy().into_owned());
    let r = session(&[
        (
            "size_report",
            object([
                ("path", path()),
                ("sources", Value::from("armembers,symbols")),
            ]),
        ),
        (
            "symbols",
            object([("path", path()), ("query", Value::from("use_statics"))]),
        ),
        (
            "lookup",
            object([
                ("path", path()),
                ("address", Value::from(8u32)),
                ("domain", Value::from("file")),
            ]),
        ),
    ]);
    let report = result(&r[0]);
    let members: Vec<&str> = report
        .get("total")
        .unwrap()
        .get("children")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.get("name").unwrap().as_str().unwrap())
        .collect();
    assert!(
        members.contains(&"objects.obj") && members.contains(&"objects-big.obj"),
        "{members:?}"
    );
    assert!(result(&r[1]).get("matched").unwrap().as_u64().unwrap() >= 1);
    let at = result(&r[2]);
    assert_eq!(
        at.get("sources")
            .unwrap()
            .get("sections")
            .unwrap()
            .get("label")
            .unwrap()
            .as_str(),
        Some("[AR Headers]")
    );
}

#[test]
fn elf_session() {
    let exe = testdata("elf/unwind-x86_64-linux-gnu");
    let path = || Value::from(exe.to_string_lossy().into_owned());
    let r = session(&[
        (
            "size_report",
            object([("path", path()), ("sources", Value::from("segments"))]),
        ),
        (
            "symbols",
            object([("path", path()), ("query", Value::from("comp"))]),
        ),
        // `_start`'s address, from the fixture's symbol table.
        (
            "lookup",
            object([("path", path()), ("address", Value::from("0x201350"))]),
        ),
    ]);
    let report = result(&r[0]);
    let names: Vec<&str> = report
        .get("total")
        .unwrap()
        .get("children")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.get("name").unwrap().as_str().unwrap())
        .collect();
    assert!(names.contains(&"LOAD #2 [RX]"), "{names:?}");
    let symbols = result(&r[1]);
    assert_eq!(symbols.get("matched").unwrap().as_u64(), Some(1));
    let at = result(&r[2]);
    let sources = at.get("sources").unwrap();
    let label = |s: &str| {
        sources
            .get(s)
            .unwrap()
            .get("label")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(label("sections"), ".text");
    assert_eq!(label("segments"), "LOAD #2 [RX]");
    assert_eq!(label("symbols"), "_start");
}

#[test]
fn findings_session() {
    let dll = testdata("sizebench/bin/CppTestCases_BasicDiffObjectsAfter.dll");
    let r = session(&[(
        "findings",
        object([("path", Value::from(dll.to_string_lossy().into_owned()))]),
    )]);
    let f = result(&r[0]);
    let dups = f.get("duplicate_data").unwrap();
    assert_eq!(dups.get("count").unwrap().as_i64(), Some(2));
    assert!(f.get("template_families").is_some());
    let virtuals = f.get("wasteful_virtuals").unwrap();
    assert_eq!(virtuals.get("count").unwrap().as_i64(), Some(6));
    let text = r[0]
        .get("result")
        .unwrap()
        .get("content")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(text.contains("inline constexpr"), "{text}");
}

/// The query tool: the query language over an image's symbols; a bad query
/// is an error result, not a failed session.
#[test]
fn query_tool() {
    let exe = testdata("xref/xref-x64.exe");
    let path = || Value::from(exe.to_string_lossy().into_owned());
    let r = session(&[
        (
            "query",
            object([
                ("path", path()),
                (
                    "query",
                    Value::from(r"name~'^(inner|outer)\(' select name sort by name"),
                ),
            ]),
        ),
        (
            "query",
            object([
                ("path", path()),
                ("query", Value::from("kind=function group by kind")),
            ]),
        ),
        (
            "query",
            object([("path", path()), ("query", Value::from("size>1"))]),
        ),
    ]);
    let v = result(&r[0]);
    assert_eq!(v["matched"], 2);
    assert_eq!(v["rows"][0]["name"], "inner(int)");
    assert_eq!(v["rows"][1]["name"], "outer(int)");
    let v = result(&r[1]);
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    assert_eq!(v["rows"][0]["kind"], "function");
    assert!(v["rows"][0]["count"].as_u64().unwrap() > 10);
    let e = r[2].get("result").unwrap();
    assert_eq!(e["isError"], true, "{e}");
    assert!(e.to_string().contains("no column 'size'"), "{e}");
}

/// The why and recommend tools, over one cached graph.
#[test]
fn why_and_recommend_tools() {
    let exe = testdata("xref/xref-x64.exe");
    let path = || Value::from(exe.to_string_lossy().into_owned());
    let r = session(&[
        (
            "why",
            object([("path", path()), ("name", Value::from("Square::area"))]),
        ),
        (
            "why",
            object([("path", path()), ("name", Value::from("dead_helper"))]),
        ),
        ("recommend", object([("path", path())])),
        (
            "why",
            object([("path", path()), ("name", Value::from("nope"))]),
        ),
    ]);
    let v = result(&r[0]);
    assert_eq!(v["reached"], true);
    assert_eq!(v["root"]["reason"], "the entry point");
    assert_eq!(
        v["chain"].as_array().unwrap().last().unwrap()["name"],
        "Square::area() const"
    );
    let v = result(&r[1]);
    assert_eq!(v["reached"], false);
    assert_eq!(v["comdat"], false);
    let v = result(&r[2]);
    assert_eq!(v["saving"], 308);
    assert_eq!(v["link"]["optIcf"], true);
    let e = r[3].get("result").unwrap();
    assert_eq!(e["isError"], true, "{e}");
    assert!(e.to_string().contains("nothing named 'nope'"), "{e}");
}

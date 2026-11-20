//! `hexc relocations`: what the loader patches, by table, type, section,
//! data, and target; and the pointer tables `hexc recommend` finds.

use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn hexc(args: &[&str], file: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .arg(file)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn text_and_json() {
    // libptrs.so: color_names's 8 string pointers and Shape's vtable's 6
    // function pointers (RELATIVE), and a call through the PLT.
    let lib = testdata("linkopts/libptrs.so");
    let (ok, out, err) = hexc(&["relocations"], &lib);
    assert!(ok, "{err}");
    assert!(
        out.starts_with("15 relocations, 360 bytes in 2 tables:"),
        "{out}"
    );
    assert!(out.contains("By the data (or code) each patches:"), "{out}");
    assert!(out.contains("color_names"), "{out}");
    assert!(out.contains("vtable for Shape"), "{out}");
    assert!(out.contains("Shape::area() const"), "{out}");
    let (ok, out, _) = hexc(&["relocations", "-json", "-list"], &lib);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["count"], 15);
    assert_eq!(v["bytes"], 360);
    assert_eq!(v["symbolsFrom"], "debug");
    let types: Vec<(&str, u64)> = v["types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap(), t["count"].as_u64().unwrap()))
        .collect();
    assert_eq!(
        types,
        [("R_X86_64_RELATIVE", 14), ("R_X86_64_JUMP_SLOT", 1)]
    );
    let sym = |name: &str| {
        v["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .map(|s| (s["count"].as_u64().unwrap(), s["bytes"].as_u64().unwrap()))
    };
    assert_eq!(sym("color_names"), Some((8, 192)));
    assert_eq!(sym("vtable for Shape"), Some((6, 144)));
    let tables: Vec<&str> = v["pointerTables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(tables, ["color_names", "vtable for Shape"]);
    let list = v["list"].as_array().unwrap();
    assert_eq!(list.len(), 15);
    assert_eq!(list[0]["in"], "color_names");
    assert!(list.iter().any(|r| r["to"] == "Shape::area() const"));
    // -n: rows of each list.
    let (_, out, _) = hexc(&["relocations", "-n", "1"], &lib);
    assert!(out.contains("(1 more)"), "{out}");
}

#[test]
fn other_formats() {
    // A PE image's base relocations, and its symbols from its PDB.
    let (ok, out, err) = hexc(&["relocations"], &testdata("xref/xref-x64.exe"));
    assert!(ok, "{err}");
    assert!(
        out.starts_with("62 relocations, 144 bytes in 1 table:"),
        "{out}"
    );
    assert!(out.contains("DIR64"), "{out}");
    assert!(out.contains("Circle::`vftable'"), "{out}");
    // Mach-O fixups, chained; no debug information (the image's symbols).
    let (ok, out, err) = hexc(
        &["relocations", "-json"],
        &testdata("macho/pointers-arm64.dylib"),
    );
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["count"], 10);
    assert_eq!(v["symbolsFrom"], "image");
    assert_eq!(v["tables"][0]["name"], "chained fixups");
    assert!(
        v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "_imported"),
        "{v}"
    );
    // Without relocations: said so.
    let (ok, out, _) = hexc(&["relocations"], &testdata("linkopts/funcs-plain"));
    assert!(ok);
    assert_eq!(out, "No relocations: the loader patches nothing.\n");
    // Debug information given but not found: an error.
    let (ok, _, err) = hexc(
        &["relocations", "-debug", "nope"],
        &testdata("linkopts/libptrs.so"),
    );
    assert!(!ok && err.contains("nope"), "{err}");
}

#[test]
fn pointer_tables_recommended() {
    let (ok, out, err) = hexc(&["recommend", "-json"], &testdata("linkopts/libptrs.so"));
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rec = |kind: &str| {
        v["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind)
            .cloned()
            .unwrap_or_else(|| panic!("{kind}: {v}"))
    };
    // 8 pointers: 24-byte relocations and 4 bytes each.
    let t = rec("pointer-tables");
    assert_eq!(t["saving"], 8 * (24 + 4));
    assert!(
        t["advice"]
            .as_str()
            .unwrap()
            .contains("a table of data holds 8 pointers"),
        "{t}"
    );
    assert_eq!(t["examples"][0]["name"], "color_names (8 pointers)");
    let vt = rec("relative-vtables");
    assert_eq!(vt["saving"], 6 * (24 + 4));
    assert!(
        vt["advice"]
            .as_str()
            .unwrap()
            .starts_with("compile with -fexperimental-relative-c++-abi-vtables"),
        "{vt}"
    );
    // MSVC has no relative vtables: none for a PE image with its PDB.
    let (_, out, _) = hexc(&["recommend", "-json"], &testdata("xref/xref-x64.exe"));
    assert!(!out.contains("relative-vtables"), "{out}");
}

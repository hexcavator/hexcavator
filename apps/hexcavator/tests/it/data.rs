//! `hexc data` end to end: the globals of the type layout test program
//! (tools/types) read as their types, and the xref program's tables.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixture(dir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(dir)
        .join(name)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("data")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn json(image: &Path, name: &str) -> Value {
    let (code, out, err) = hexc(&["-json", image.to_str().unwrap(), name]);
    assert_eq!(code, 0, "{name}: {err}");
    serde_json::from_str(&out).unwrap()
}

/// The child of `v` named `name`.
fn child<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["children"]
        .as_array()
        .and_then(|c| c.iter().find(|c| c["name"] == name))
        .unwrap_or_else(|| panic!("no {name} in {v}"))
}

#[test]
fn a_structure_read_as_its_type() {
    let exe = fixture("types", "types.exe");
    let j = json(&exe, "g_sample");
    assert_eq!(j["section"], ".data");
    assert_eq!(j["size"], 72);
    assert_eq!(j["bytes"].as_str().unwrap().len(), 144);
    let v = &j["value"];
    assert_eq!(v["type"], "Sample");
    assert_eq!(v["kind"], "struct");
    let padded = child(v, "padded");
    assert_eq!(child(padded, "a")["text"], "97 'a'");
    assert_eq!(child(padded, "b")["text"], "42");
    assert_eq!(child(padded, "b")["offset"], 4);
    // The hole between a and b, shown as padding.
    let kinds: Vec<&str> = padded["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["char", "padding", "integer", "char", "padding"]);
    // Bitfields by their bits.
    let bits = child(v, "bits");
    assert_eq!(child(bits, "a")["text"], "5");
    assert_eq!(child(bits, "a")["bits"], serde_json::json!([0, 3]));
    assert_eq!(child(bits, "b")["text"], "17");
    assert_eq!(child(bits, "c")["text"], "-3");
    assert_eq!(child(v, "color")["text"], "Green (2)");
    assert_eq!(child(v, "ratio")["text"], "1.5");
    // A pointer, named by what it points to (a string literal).
    let text = child(v, "text");
    assert_eq!(text["kind"], "pointer");
    assert!(text["target"].as_str().unwrap().contains("hello"), "{text}");
    // A character array as its string, and its elements.
    let name = child(v, "name");
    assert_eq!(name["text"], "\"abc\"");
    assert_eq!(name["children"].as_array().unwrap().len(), 8);
    let numbers = child(v, "numbers");
    let ns: Vec<&str> = numbers["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap())
        .collect();
    assert_eq!(ns, ["1", "-2", "3"]);
    assert_eq!(child(v, "flag")["text"], "true");
    // A union: each member at 0.
    let either = child(v, "either");
    assert_eq!(either["kind"], "union");
    assert_eq!(child(either, "c")["text"], "101 'e'");
    assert_eq!(child(either, "d")["offset"], 64);
    // The relocated slot: the string pointer.
    let pointers = j["pointers"].as_array().unwrap();
    assert_eq!(pointers.len(), 1);
    assert_eq!(pointers[0]["offset"], 0x20);
}

#[test]
fn a_class_with_a_vtable() {
    let exe = fixture("types", "types.exe");
    let v = json(&exe, "g_derived")["value"].clone();
    let base = child(&v, "Base");
    assert_eq!(base["kind"], "base");
    let vfptr = child(base, "vfptr");
    assert_eq!(vfptr["kind"], "vfptr");
    assert_eq!(vfptr["target"], "Derived::`vftable'");
    assert_eq!(child(base, "x")["text"], "1");
    assert_eq!(child(&v, "y")["text"], "2");
}

#[test]
fn tables_and_text() {
    let exe = fixture("xref", "xref-x64.exe");
    // An array of function pointers, each named.
    let j = json(&exe, "ops");
    let targets: Vec<&str> = j["value"]["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["target"].as_str().unwrap())
        .collect();
    assert_eq!(targets, ["op_add(int)", "op_sub(int)"]);
    // A vtable: the slots the image has, though its type counts more.
    let j = json(&exe, "Circle::`vftable'");
    let v = &j["value"];
    assert_eq!(v["text"], "(3 of 4 elements in the data)");
    assert_eq!(v["children"].as_array().unwrap().len(), 3);
    assert_eq!(j["pointers"].as_array().unwrap().len(), 3);
    // Text: the tree, the bytes as a debugger shows them, the pointers.
    let (code, out, err) = hexc(&[exe.to_str().unwrap(), "ops"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("ops  (16 bytes at 0x"), "{out}");
    assert!(out.contains("[1] = 0x"), "{out}");
    assert!(out.contains("op_sub(int)"), "{out}");
    assert!(out.contains("pointers (base relocations):"), "{out}");
    // Code isn't data; nothing named so isn't anything.
    let (code, _, err) = hexc(&[exe.to_str().unwrap(), "main(int, char**)"]);
    assert!(code != 0 && err.contains("is code"), "{err}");
    let (code, _, err) = hexc(&[exe.to_str().unwrap(), "nope"]);
    assert!(code != 0 && err.contains("no datum named 'nope'"), "{err}");
    let (code, _, _) = hexc(&[exe.to_str().unwrap()]);
    assert_eq!(code, 2);
    // -max: the first bytes only.
    let (code, out, _) = hexc(&["-json", "-max", "8", exe.to_str().unwrap(), "ops"]);
    assert_eq!(code, 0);
    let j: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (j["read"].as_u64(), j["size"].as_u64()),
        (Some(8), Some(16))
    );
}

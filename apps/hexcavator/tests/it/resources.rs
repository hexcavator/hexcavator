//! `hexc resources` end to end, over the resource test images
//! (tools/resources): a PE program with one of each kind of resource rc
//! makes (some in two languages), an ELF program's notes, a Mach-O
//! program's Info.plist and entitlements, a WebAssembly module's producers,
//! and a 16-bit program's resources.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("resources")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn ok(args: &[&str]) -> String {
    let (code, out, err) = hexc(args);
    assert_eq!(code, 0, "{args:?}: {err}");
    out
}

fn json(args: &[&str]) -> Value {
    let mut all = vec!["-json"];
    all.extend(args);
    serde_json::from_str(&ok(&all)).unwrap()
}

fn exe() -> String {
    testdata("resources/resources.exe")
        .to_str()
        .unwrap()
        .to_string()
}

fn show(id: &str) -> Value {
    json(&["-show", id, &exe()])
}

/// The base64 a JSON item holds, decoded.
fn unbase64(s: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for c in bytes.chunks(4) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &c)| n | u32::from(value(c)) << (18 - 6 * i));
        out.extend(&n.to_be_bytes()[1..c.len()]);
    }
    out
}

#[test]
fn pe_list() {
    let v = json(&[&exe()]);
    let items = v["items"].as_array().unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    for id in [
        "VERSION/#1/1033",
        "MANIFEST/#1/1033",
        "GROUP_ICON/#1/1033",
        "GROUP_CURSOR/#2/1033",
        "BITMAP/STRIPES/1033",
        "MENU/#1/1033",
        "MENU/#2/1033",
        "DIALOG/#100/1033",
        "DIALOG/#101/1033",
        "STRING/#1/1033",
        "STRING/#1/1031",
        "STRING/#2/1033",
        "ACCELERATOR/#1/1033",
        "MESSAGETABLE/#1/1033",
        "HTML/README/1033",
        "RCDATA/CONFIG/1033",
        "RCDATA/BLOB/1033",
        "DATA/CUSTOM/1033",
    ] {
        assert!(ids.contains(&id), "{id} not in {ids:?}");
    }
    let item = |id: &str| items.iter().find(|i| i["id"] == id).unwrap();
    assert_eq!(
        item("VERSION/#1/1033")["summary"],
        "Hexcavator tests 1.2.3.4 (Hexcavator)"
    );
    assert_eq!(
        item("MANIFEST/#1/1033")["summary"],
        "needs Microsoft.Windows.Common-Controls; runs asInvoker"
    );
    assert_eq!(
        item("GROUP_ICON/#1/1033")["summary"],
        "2 images: 16×16, 32×32 PNG"
    );
    assert_eq!(item("GROUP_CURSOR/#2/1033")["summary"], "1 cursor: 32×32");
    assert_eq!(item("BITMAP/STRIPES/1033")["summary"], "8×4, 24 bits");
    assert_eq!(item("MENU/#1/1033")["summary"], "File Help");
    // (A shortcut menu: its one unnamed popup's items.)
    assert_eq!(item("MENU/#2/1033")["summary"], "Copy - Open");
    assert_eq!(item("STRING/#1/1031")["summary"], "1 string: Ressourcen");
    assert_eq!(item("STRING/#1/1031")["language"], "German (Germany)");
    assert_eq!(
        item("MESSAGETABLE/#1/1033")["summary"],
        "2 messages: Hello, %1."
    );
    assert_eq!(item("RCDATA/CONFIG/1033")["view"], "text");
    assert_eq!(item("RCDATA/BLOB/1033")["view"], "hex");
    assert_eq!(item("ICON/#2/1033")["summary"], "32×32, 32 bits, PNG");
}

#[test]
fn pe_decoded() {
    let v = show("VERSION/#1/1033");
    assert_eq!(v["fixed"]["fileVersion"], "1.2.3.4");
    assert_eq!(v["fixed"]["productVersion"], "1.2.0.0");
    assert_eq!(v["fixed"]["type"], "application");
    let strings = &v["tables"][0]["strings"];
    assert!(
        strings
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p[0] == "CompanyName" && p[1] == "Hexcavator")
    );
    // Strings by their IDs (16 to a block: 17 is block 2's second).
    assert_eq!(
        show("STRING/#1/1033")["strings"],
        serde_json::json!([[1, "Resources"], [2, "A test program"]])
    );
    assert_eq!(
        show("STRING/#2/1033")["strings"],
        serde_json::json!([[17, "Seventeen"]])
    );
    assert_eq!(
        show("MESSAGETABLE/#1/1033")["messages"],
        serde_json::json!([[1, "Hello, %1."], [256, "Goodbye."]])
    );
    let d = &show("DIALOG/#100/1033")["dialog"];
    assert_eq!(d["title"], "About Resources");
    assert_eq!(d["rect"], serde_json::json!([10, 20, 200, 80]));
    assert_eq!(d["font"]["face"], "MS Shell Dlg");
    let controls = d["controls"].as_array().unwrap();
    assert_eq!(controls.len(), 4);
    assert_eq!(controls[1]["class"], "Static");
    assert_eq!(controls[1]["text"], "Resources, a test program.");
    assert_eq!(controls[3]["class"], "Button");
    assert_eq!(controls[3]["id"], 1);
    // A classic dialog, with a control of a class by name.
    let d = &show("DIALOG/#101/1033")["dialog"];
    assert_eq!(d["controls"][1]["class"], "SysListView32");
    let m = &show("MENU/#1/1033")["menu"];
    assert_eq!(m[0]["text"], "&File");
    assert_eq!(
        m[0]["items"][0],
        serde_json::json!({ "text": "&Open...\tCtrl+O", "id": 101 })
    );
    assert_eq!(m[0]["items"][1]["separator"], true);
    assert_eq!(m[1]["items"][0]["text"], "&About");
    let m = &show("MENU/#2/1033")["menu"];
    assert_eq!(
        m[0]["items"][0],
        serde_json::json!({ "text": "&Copy", "id": 201 })
    );
    let a = &show("ACCELERATOR/#1/1033")["accelerators"];
    assert_eq!(
        *a,
        serde_json::json!([
            { "keys": "Ctrl+O", "id": 101 },
            { "keys": "F1", "id": 103 },
            { "keys": "Alt+'x'", "id": 102 },
        ])
    );
    assert!(
        show("HTML/README/1033")["text"]
            .as_str()
            .unwrap()
            .starts_with("<html>")
    );
}

/// Icons, cursors, and bitmaps: as files of their own, the same from -show
/// -json (base64) and -save.
#[test]
fn pe_images() {
    let group = show("GROUP_ICON/#1/1033");
    let file = unbase64(group["file"].as_str().unwrap());
    // An .ico file: two images, the second a PNG.
    assert_eq!(&file[..6], &[0, 0, 1, 0, 2, 0]);
    let at = u32::from_le_bytes(file[6 + 16 + 12..6 + 16 + 16].try_into().unwrap()) as usize;
    assert_eq!(&file[at..at + 4], b"\x89PNG");
    assert_eq!(group["images"][0]["width"], 16);
    let dir = std::env::temp_dir().join(format!("hexc-resources-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let saved = dir.join("icon.ico");
    let out = ok(&[
        "-save",
        "GROUP_ICON/#1/1033",
        saved.to_str().unwrap(),
        &exe(),
    ]);
    assert!(
        out.starts_with(&format!("GROUP_ICON/#1/1033: {} bytes to ", file.len())),
        "{out}"
    );
    assert_eq!(std::fs::read(&saved).unwrap(), file);
    // A cursor: its hot spot (5, 7) where an icon's planes and bits are.
    let cur = unbase64(show("GROUP_CURSOR/#2/1033")["file"].as_str().unwrap());
    assert_eq!(&cur[..6], &[0, 0, 2, 0, 1, 0]);
    assert_eq!(&cur[10..14], &[5, 0, 7, 0]);
    // A bitmap: a .bmp file, its pixels after its header.
    let bmp = unbase64(show("BITMAP/STRIPES/1033")["file"].as_str().unwrap());
    assert_eq!(&bmp[..2], b"BM");
    assert_eq!(
        u32::from_le_bytes(bmp[2..6].try_into().unwrap()) as usize,
        bmp.len()
    );
    assert_eq!(u32::from_le_bytes(bmp[10..14].try_into().unwrap()), 54);
    // Raw data as stored.
    let saved = dir.join("blob.bin");
    ok(&["-save", "RCDATA/BLOB/1033", saved.to_str().unwrap(), &exe()]);
    assert_eq!(std::fs::read(&saved).unwrap(), [1, 2, 3, 4, 0xFE, 0xFF]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn text() {
    let out = ok(&[&exe()]);
    assert!(out.starts_with("resources.exe: "), "{out}");
    assert!(out.contains("\nVERSION (1)\n  VERSION/#1/1033 "), "{out}");
    let out = ok(&["-show", "ACCELERATOR/#1/1033", &exe()]);
    assert!(out.contains("\n  Ctrl+O               101\n"), "{out}");
    let out = ok(&["-show", "DIALOG/#100/1033", &exe()]);
    assert!(
        out.contains("\"About Resources\"  at [10,20,200,80]"),
        "{out}"
    );
    assert!(
        out.contains("\n      -1  Static       \"Resources, a test program.\""),
        "{out}"
    );
    let out = ok(&["-show", "MENU/#2/1033", &exe()]);
    assert!(
        out.contains("\n(popup)\n  &Copy  (201)\n  --------\n"),
        "{out}"
    );
    // Ids match without regard to case.
    let out = ok(&["-show", "html/readme/1033", &exe()]);
    assert!(out.contains("<html>"), "{out}");
    let out = ok(&["-show", "RCDATA/BLOB/1033", &exe()]);
    assert!(out.contains("\n00000000  01 02 03 04 fe ff "), "{out}");
}

#[test]
fn elf() {
    let path = testdata("resources/resources-x86_64-linux-gnu");
    let v = json(&[path.to_str().unwrap()]);
    let items = v["items"].as_array().unwrap();
    let summary = |id: &str| items.iter().find(|i| i["id"] == id).unwrap()["summary"].clone();
    assert_eq!(
        summary(".note.ABI-tag#0"),
        "OS: Linux; Minimum kernel: 3.2.0"
    );
    assert!(
        summary(".note.gnu.build-id#0")
            .as_str()
            .unwrap()
            .starts_with("Build ID: ")
    );
    assert_eq!(
        summary(".note.package#0"),
        "JSON: {\"type\":\"deb\",\"name\":\"resources\",\"version\":\"1.2.3\"}"
    );
    assert!(
        summary(".comment")
            .as_str()
            .unwrap()
            .starts_with("Linker: LLD ")
    );
    // A hardened program's properties.
    for (file, says) in [
        ("elf/hardened-x86_64-linux-gnu", "x86 features: IBT, SHSTK"),
        (
            "elf/hardened-aarch64-linux-gnu",
            "AArch64 features: BTI, PAC, GCS",
        ),
    ] {
        let path = testdata(file);
        let out = ok(&[path.to_str().unwrap()]);
        assert!(out.contains(says), "{file}: {out}");
    }
}

#[test]
fn macho() {
    let path = testdata("resources/resources-arm64");
    let path = path.to_str().unwrap();
    let v = json(&[path]);
    let items = v["items"].as_array().unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["Info.plist", "Entitlements", "Versions"]);
    assert_eq!(
        items[0]["summary"],
        "CFBundleIdentifier, CFBundleName, CFBundleShortVersionString, CFBundleVersion"
    );
    assert_eq!(
        items[1]["summary"],
        "com.apple.security.cs.allow-jit, com.apple.security.get-task-allow"
    );
    let plist = json(&["-show", "Info.plist", path]);
    assert!(
        plist["text"]
            .as_str()
            .unwrap()
            .contains("<string>dev.hexcavator.resources</string>")
    );
    let pairs = &json(&["-show", "Versions", path])["pairs"];
    let get = |k: &str| {
        pairs
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p[0] == k)
            .map(|p| p[1].clone())
    };
    assert_eq!(get("Platform").unwrap(), "macOS");
    assert_eq!(get("Minimum OS").unwrap(), "12.0.0");
    assert_eq!(get("SDK").unwrap(), "14.0.0");
    assert_eq!(
        get("Bundle identifier").unwrap(),
        "dev.hexcavator.resources"
    );
    assert_eq!(get("UUID").unwrap().as_str().unwrap().len(), 36);
}

#[test]
fn wasm_and_ne() {
    let path = testdata("wasm/sample-dwarf.wasm");
    let v = json(&[path.to_str().unwrap()]);
    let items = v["items"].as_array().unwrap();
    let producers = items.iter().find(|i| i["id"] == "producers").unwrap();
    assert!(
        producers["summary"]
            .as_str()
            .unwrap()
            .starts_with("language: Rust; processed-by: rustc ")
    );
    assert!(items.iter().any(|i| i["id"] == "target_features"));
    // (Debug information isn't listed: hexc dwarf shows it.)
    assert!(
        !items
            .iter()
            .any(|i| i["id"].as_str().unwrap().starts_with(".debug"))
    );
    let path = testdata("legacy/sample.ne");
    let v = json(&[path.to_str().unwrap()]);
    let ids: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["FONT/#1", "BLOB/ONE"]);
}

#[test]
fn nothing_and_bad_arguments() {
    // An image with none.
    let path = testdata("elf/names.o");
    let (code, out, _) = hexc(&[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.starts_with("names.o: "), "{out}");
    for args in [
        &[][..],
        &["-nonesuch", "x"],
        &["-show"],
        &["-save", "x"],
        &["a", "b"],
    ] {
        let (code, _, err) = hexc(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains("usage: hexc resources"), "{err}");
    }
    let (code, _, err) = hexc(&["-show", "NOPE/#1/1033", &exe()]);
    assert_eq!(code, 1);
    assert!(
        err.contains("resources.exe has no resource 'NOPE/#1/1033'"),
        "{err}"
    );
    let (code, _, _) = hexc(&["no-such-file.exe"]);
    assert_eq!(code, 1);
    let readme = testdata("resources/../../README.md");
    let (code, _, err) = hexc(&[readme.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        err.contains("not a PE, Mach-O, ELF, WebAssembly, or NE image"),
        "{err}"
    );
}

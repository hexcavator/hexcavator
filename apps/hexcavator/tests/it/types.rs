//! `hexc types` end to end, over the type layout test program
//! (tools/types: one structure for each kind of part and hole).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/types")
        .join(name)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("types")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn layout(name: &str) -> String {
    let exe = fixture("types.exe");
    let (code, out, err) = hexc(&["-layout", name, exe.to_str().unwrap()]);
    assert_eq!(code, 0, "{name}: {err}");
    out
}

#[test]
fn layouts() {
    assert_eq!(
        layout("Padded"),
        "Padded (12 bytes; 6 wasted)\n\
         \x20 offset  size  part\n\
         \x20      0     1  a               char\n\
         \x20      1     3  [padding]\n\
         \x20      4     4  b               int\n\
         \x20      8     1  c               char\n\
         \x20      9     3  [tail padding]\n"
    );
    assert_eq!(
        layout("Bits"),
        "Bits (8 bytes; 3 wasted)\n\
         \x20 offset  size  part\n\
         \x20    0.0    :3  a              unsigned int\n\
         \x20    0.3    :5  b              unsigned int\n\
         \x20    0.8   :24  [bit padding]\n\
         \x20      4     4  c              int\n"
    );
    assert_eq!(
        layout("Base"),
        "Base (16 bytes; 4 wasted)\n\
         \x20 offset  size  part\n\
         \x20      0     8  [vfptr]\n\
         \x20      8     4  x               int\n\
         \x20     12     4  [tail padding]\n"
    );
    assert!(layout("Derived").contains("       0    16  [base]          Base\n      16     1  y               char\n      17     7  [tail padding]\n"));
    // The empty base takes nothing.
    assert!(layout("WithEmpty").starts_with("WithEmpty (4 bytes; 0 wasted)\n"));
    assert!(layout("WithEmpty").contains("       0     0  [base]  Empty\n"));
    // The virtual base after the rest, aligned.
    assert_eq!(
        layout("Diamond"),
        "Diamond (24 bytes; 8 wasted)\n\
         \x20 offset  size  part\n\
         \x20      0     8  [vbptr]\n\
         \x20      8     4  d               int\n\
         \x20     12     4  [padding]\n\
         \x20     16     4  [virtual base]  VBase\n\
         \x20     20     4  [tail padding]\n"
    );
    assert!(layout("Either").starts_with("union Either (8 bytes; 0 wasted)\n"));
    // A regular expression that matches one type.
    assert_eq!(layout("^Padd"), layout("Padded"));
}

#[test]
fn list_and_json() {
    let exe = fixture("types.exe");
    let exe = exe.to_str().unwrap();
    let (code, out, _) = hexc(&["-n", "0", exe]);
    assert_eq!(code, 0);
    let rows: Vec<&str> = out.lines().skip(2).collect();
    for (name, size, wasted) in [
        ("Diamond", 24, 8),
        ("Derived", 24, 7),
        ("Padded", 12, 6),
        ("Base", 16, 4),
        ("Bits", 8, 3),
    ] {
        let row = format!("  {size:>8}  {wasted:>8}  {name}");
        assert!(rows.contains(&row.as_str()), "{name}: {out}");
    }
    // Most waste first.
    let wastes: Vec<u64> = rows
        .iter()
        .filter_map(|r| r.split_whitespace().nth(1).and_then(|w| w.parse().ok()))
        .collect();
    assert!(wastes.windows(2).all(|w| w[0] >= w[1]), "{out}");
    let (_, out, _) = hexc(&["-json", "-layout", "Bits", exe]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["bitPadding"], 24);
    assert_eq!(v["parts"][1]["name"], "b");
    assert_eq!(v["parts"][1]["bit"], 3);
    assert_eq!(v["parts"][1]["bits"], 5);
    assert_eq!(v["parts"][2]["kind"], "bit padding");
    let (_, out, _) = hexc(&["-json", "-n", "2", exe]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["list"].as_array().unwrap().len(), 2);
    assert_eq!(v["list"][0]["name"], "Diamond");
    // A PDB directly.
    let pdb = fixture("types.pdb");
    let (code, out, _) = hexc(&["-layout", "Padded", pdb.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(out, layout("Padded"));
}

#[test]
fn diff() {
    let (new, old) = (fixture("types-v2.exe"), fixture("types.exe"));
    let (code, out, err) = hexc(&[new.to_str().unwrap(), "--", old.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        "Types: 3 changed layout, 0 added, 0 removed\n\
         \n\
         Changed (size, and wasted bytes), largest change first:\n\
         \x20       +4  Grows (4 -> 8 bytes; wasted 0 -> 0)\n\
         \x20       -4  Padded (12 -> 8 bytes; wasted 6 -> 2)\n\
         \x20       +0  Sample (72 -> 72 bytes; wasted 3 -> 7)\n"
    );
    let (_, out, _) = hexc(&["-json", new.to_str().unwrap(), "--", old.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    // (Sample holds a Padded: its padding moved with Padded's.)
    assert_eq!(v["changedCount"], 3);
    assert_eq!(v["addedCount"], 0);
}

#[test]
fn errors() {
    let exe = fixture("types.exe");
    let exe = exe.to_str().unwrap();
    let (code, _, err) = hexc(&["-layout", "Nope", exe]);
    assert_eq!(code, 1);
    assert!(err.contains("no type named 'Nope'"), "{err}");
    let (code, _, err) = hexc(&["-layout", "^(Padded|Bits)$", exe]);
    assert_eq!(code, 1);
    assert!(
        err.contains("matches 2 types (Bits, Padded); give one exactly")
            || err.contains("matches 2 types"),
        "{err}"
    );
    let (code, _, err) = hexc(&["-bogus", exe]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown option 'bogus'"), "{err}");
    // An image with no debug information to be found.
    let elf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/elf/program-stripped");
    let (code, _, err) = hexc(&[elf.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("no matching debug information found"), "{err}");
}

/// DWARF: the same source built by clang (see tools/types/build-dwarf.cmd),
/// its layouts as the Itanium ABI has them, and two builds compared.
#[test]
fn dwarf() {
    let image = fixture("types-x86_64-linux-gnu");
    let image = image.to_str().unwrap();
    let (code, out, err) = hexc(&[image]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with("11 types; their padding wastes 17 bytes"),
        "{out}"
    );
    let (code, out, _) = hexc(&["-layout", "Diamond", image]);
    assert_eq!(code, 0);
    assert!(out.contains("12     4  [virtual base]  VBase"), "{out}");
    assert!(!out.contains("vbptr"), "{out}");
    let v2 = fixture("types-x86_64-linux-gnu-v2");
    let (code, out, _) = hexc(&[image, "--", v2.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("Types: 3 changed layout, 0 added, 0 removed"),
        "{out}"
    );
}

/// Each type's mangled name (a PDB's unique name; DWARF's made, Itanium),
/// and what refers to one type.
#[test]
fn mangled_names_and_references() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("types")
            .args(args)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let list = |v: &serde_json::Value| v["list"].as_array().unwrap().clone();
    let pe = list(&run(&["-json", "-n", "0", "types/types.exe"]));
    let diamond = pe.iter().find(|t| t["name"] == "Diamond").unwrap();
    assert_eq!(diamond["mangled"], ".?AUDiamond@@");
    let elf = list(&run(&["-json", "-n", "0", "types/types-x86_64-linux-gnu"]));
    let diamond = elf.iter().find(|t| t["name"] == "Diamond").unwrap();
    assert_eq!(diamond["mangled"], "7Diamond");
    // Diamond derives from what Derived does: Base is a base of several.
    for file in ["types/types.exe", "types/types-x86_64-linux-gnu"] {
        let refs = run(&["-refs", "Base", "-json", file]);
        let types: Vec<&str> = refs["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"Derived"), "{file}: {refs}");
    }
}

/// A page of the types, for a viewer: filtered (name or mangled name, any
/// case, or a regular expression), sorted, from a row; and a layout by
/// reference, as a part's `expand` gives it.
#[test]
fn pages_of_types_and_layouts_by_reference() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("types")
            .args(args)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let json = |args: &[&str]| serde_json::from_str::<serde_json::Value>(&run(args)).unwrap();
    let file = "xref/xref-x64.exe";
    let names = |v: &serde_json::Value| -> Vec<String> {
        v["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r[0].as_str().unwrap().to_string())
            .collect()
    };
    let all = json(&["-json", "-sort", "name", "-n", "0", file]);
    let total = all["types"].as_u64().unwrap();
    assert_eq!(all["matched"].as_u64(), Some(total));
    let by_name = names(&all);
    let mut sorted = by_name.clone();
    sorted.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then(a.cmp(b)));
    assert_eq!(by_name, sorted);
    // A page from a row.
    let page = json(&["-json", "-sort", "name", "-from", "10", "-n", "5", file]);
    assert_eq!(names(&page), by_name[10..15]);
    // By size, largest first.
    let sizes: Vec<u64> = json(&["-json", "-sort", "size", "-desc", "-n", "0", file])["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r[2].as_u64().unwrap())
        .collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]));
    // Filtered: any case; a mangled name too; a regular expression.
    let except = json(&["-json", "-filter", "EXCEPT", "-n", "0", file]);
    assert!(
        names(&except)
            .iter()
            .all(|n| n.to_lowercase().contains("except"))
    );
    assert!(except["matched"].as_u64().unwrap() > 0);
    let mangled = json(&[
        "-json",
        "-filter",
        ".?AU_EXCEPTION_RECORD@@",
        "-n",
        "0",
        file,
    ]);
    assert_eq!(names(&mangled), ["_EXCEPTION_RECORD"]);
    let re = json(&[
        "-json",
        "-filter",
        "^_EXCEPTION_(RECORD|POINTERS)$",
        "-regex",
        "-n",
        "0",
        file,
    ]);
    assert_eq!(names(&re), ["_EXCEPTION_POINTERS", "_EXCEPTION_RECORD"]);
    // A member that is a structure: its layout by reference.
    let layout = json(&["-layout", "EHExceptionRecord", "-json", file]);
    let params = layout["parts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "params")
        .unwrap();
    let ty = params["expand"].as_u64().unwrap().to_string();
    let inner = run(&["-ty", &ty, file]);
    assert!(
        inner.starts_with("EHExceptionRecord::EHParameters"),
        "{inner}"
    );
}

#[test]
fn type_definitions() {
    // From the PDB's LF_UDT_SRC_LINE records, and DWARF's declarations
    // (split DWARF too): the struct's line in types.cpp.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/types");
    for image in ["types.exe", "types-x86_64-linux-gnu", "types-split5"] {
        for (name, line) in [("Derived", 43), ("Diamond", 57)] {
            let out = std::process::Command::new(env!("CARGO_BIN_EXE_hexc"))
                .args(["types", "-definition", name, "-json"])
                .arg(root.join(image))
                .output()
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
                panic!(
                    "{image} {name}: {e}: {}",
                    String::from_utf8_lossy(&out.stderr)
                )
            });
            assert!(
                v["file"].as_str().unwrap().ends_with("types.cpp"),
                "{image}: {v}"
            );
            assert_eq!(v["line"], line, "{image} {name}");
        }
    }
}

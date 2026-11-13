//! A Mach-O image without a dSYM: its DWARF read from the objects its
//! debug map names (testdata/macho/oso: one object given whole, one a
//! member of an archive; see tools/macho/build.cmd), against dsymutil's
//! dSYM of the same image (`oso-<arch>.dsymutil`): each command's output
//! the same either way.

use std::path::{Path, PathBuf};
use std::process::Command;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/macho/oso")
}

fn hexc(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .current_dir(dir())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const QUERY: &str = "select name, kind, file, vm, rva, section, compiland, static, source, line";

#[test]
fn the_debug_map_reads_as_dsymutil_s_dsym() {
    for arch in ["arm64", "x86_64"] {
        let image = format!("oso-{arch}");
        let dsym = format!("oso-{arch}.dsymutil");
        let commands: [&[&str]; 9] = [
            &["query", QUERY],
            &["sourcefiles", "-n", "0"],
            &["sourcefiles", "-file", "program.c"],
            &["sourcefiles", "-file", "second.c"],
            &["inlines", "-n", "0"],
            &["xref", "-n", "0"],
            &["size", "-sizebench"],
            &["checksec", "-audit"],
            &["data"],
        ];
        for c in commands {
            let (cmd, rest) = c.split_first().unwrap();
            // (`query` takes its text after the image; `data` a name.)
            let tail: Vec<&str> = match *cmd {
                "query" => vec![&image, rest[0]],
                "data" => vec![&image, "counter"],
                _ => rest.iter().copied().chain([image.as_str()]).collect(),
            };
            let mut mapped = vec![*cmd];
            mapped.extend(&tail);
            let mut oracle = vec![*cmd, "-pdb", &dsym];
            oracle.extend(&tail);
            let (ok, got, err) = hexc(&mapped);
            assert!(ok, "{arch} {c:?}: {err}");
            let (ok, want, err) = hexc(&oracle);
            assert!(ok, "{arch} {c:?} (dSYM): {err}");
            assert_eq!(got, want, "{arch} {c:?}");
            assert!(!got.trim().is_empty(), "{arch} {c:?}: nothing");
        }
        // Each object's code is there, by source line.
        let (_, q, _) = hexc(&["query", &image, QUERY]);
        for name in [
            "compute(int)",
            "second_sum(int)",
            "second_table",
            "hidden_state",
        ] {
            assert!(q.contains(name), "{arch}: {name} in\n{q}");
        }
        assert!(q.contains("program.c") && q.contains("second.c"), "{q}");
    }
}

#[test]
fn objects_of_an_archive_name_it_and_info_lists_them() {
    let (ok, q, err) = hexc(&["query", "oso-arm64", "select name, library"]);
    assert!(ok, "{err}");
    let line = q.lines().find(|l| l.starts_with("second_sum")).unwrap();
    assert!(line.contains("libsecond-arm64.a"), "{line}");
    let line = q.lines().find(|l| l.starts_with("compute")).unwrap();
    assert!(!line.contains(".a"), "{line}");
    let (ok, info, err) = hexc(&["info", "-json", "oso-arm64"]);
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&info).unwrap();
    let debug = &v[0]["debug"];
    assert_eq!(debug["kind"], "debugmap", "{v}");
    let objects: Vec<&str> = debug["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_str().unwrap())
        .collect();
    assert_eq!(objects.len(), 2, "{objects:?}");
    assert!(objects.iter().any(|o| o.ends_with("program-arm64.o")));
    assert!(objects.iter().any(|o| o.ends_with("libsecond-arm64.a")));
    let tools: Vec<&str> = v[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(tools.contains(&"dwarf"), "{tools:?}");
    // hexc dwarf: each object's, in turn.
    let (ok, out, err) = hexc(&["dwarf", "-summary", "oso-arm64"]);
    assert!(ok, "{err}");
    assert!(out.contains("program-arm64.o: DWARF"), "{out}");
    assert!(
        out.contains("libsecond-arm64.a(second-arm64.o): DWARF"),
        "{out}"
    );
}

#[test]
fn without_its_objects_an_image_has_no_debug_information() {
    let tmp = std::env::temp_dir().join(format!("hexc-debugmap-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let image = tmp.join("oso-arm64");
    std::fs::copy(dir().join("oso-arm64"), &image).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["query"])
        .arg(&image)
        .arg("select name")
        .current_dir(&tmp)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no matching debug information"), "{err}");
}

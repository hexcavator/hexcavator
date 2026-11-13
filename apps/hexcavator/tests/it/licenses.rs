//! Licensing: our crates are Apache-2.0, plus the licenses of the parts
//! derived from others' work (each part's license file in the crate says
//! which); every third-party crate in the `hexc` binary has a permissive
//! license; and `THIRD_PARTY_NOTICES.txt` (which `hexc licenses` prints)
//! has our license and all of their notices. After a dependency or a
//! license file changes, regenerate the notices with
//! `HEXC_UPDATE_NOTICES=1 cargo test -p hexcavator --test it licenses::`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The license files our crates may have, for the parts of them derived
/// from others' work: (file, whose work, the license term the crate's
/// `license` then has besides Apache-2.0).
const DERIVED: &[(&str, &str, &str)] = &[
    (
        "LICENSE-LLVM",
        "the LLVM Project",
        "Apache-2.0 WITH LLVM-exception",
    ),
    (
        "LICENSE-SWIFT",
        "the Swift Project",
        "Apache-2.0 WITH Swift-exception",
    ),
    ("LICENSE-ARM", "Arm's AARCHMRS", "BSD-3-Clause"),
    ("NOTICE-XED", "Intel XED", "Apache-2.0"),
];

fn derived(file: &str) -> (&'static str, &'static str) {
    DERIVED.iter().find(|(f, _, _)| *f == file).map_or_else(
        || panic!("{file}: not a license file we know (see DERIVED)"),
        |&(_, who, term)| (who, term),
    )
}

fn package_dir(p: &Value) -> PathBuf {
    Path::new(p["manifest_path"].as_str().unwrap())
        .parent()
        .unwrap()
        .to_path_buf()
}

/// `text` wrapped at 76 columns.
fn wrap(text: &str) -> String {
    let mut out = String::new();
    let mut col = 0;
    for word in text.split(' ') {
        if col > 0 && col + 1 + word.len() > 76 {
            out.push('\n');
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}

/// Licenses a third-party crate in the binary may have (any expression of
/// them). Never GPL, LGPL, AGPL, or anything not on this list.
const ALLOWED: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "LLVM-exception",
    "Swift-exception",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "ISC",
    "Zlib",
    "Unlicense",
    "BSL-1.0",
    "Unicode-3.0",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn metadata() -> Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--offline",
            "--manifest-path",
        ])
        .arg(root().join("Cargo.toml"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The packages linked into `hexc`: normal dependencies, not build or dev
/// ones, and not proc macros (or what only they use), which run at
/// compile time.
fn linked(m: &Value) -> Vec<&Value> {
    let packages: BTreeMap<&str, &Value> = m["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["id"].as_str().unwrap(), p))
        .collect();
    let nodes: BTreeMap<&str, &Value> = m["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["id"].as_str().unwrap(), n))
        .collect();
    let proc_macro = |p: &Value| {
        p["targets"].as_array().unwrap().iter().any(|t| {
            t["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k == "proc-macro")
        })
    };
    let root = packages
        .values()
        .find(|p| p["name"] == "hexcavator")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        for d in nodes[id]["deps"].as_array().unwrap() {
            // A normal dependency, on a platform we build for (not one
            // only UEFI firmware links: getrandom's r-efi).
            let normal = d["dep_kinds"].as_array().unwrap().iter().any(|k| {
                k["kind"].is_null()
                    && !k["target"]
                        .as_str()
                        .is_some_and(|t| t.contains("target_os = \"uefi\""))
            });
            let pkg = d["pkg"].as_str().unwrap();
            if normal && !proc_macro(packages[pkg]) {
                stack.push(pkg);
            }
        }
    }
    let mut out: Vec<&Value> = seen.into_iter().map(|id| packages[id]).collect();
    out.sort_by_key(|p| p["name"].as_str().unwrap().to_string());
    out
}

#[test]
fn our_crates_licenses() {
    let m = metadata();
    for p in m["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["source"].is_null())
    {
        let name = p["name"].as_str().unwrap();
        let license = p["license"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no license"));
        // Apache-2.0, AND the terms of the parts its license files are for.
        let mut want = BTreeSet::from(["Apache-2.0"]);
        for (file, _) in license_files(&package_dir(p)) {
            want.insert(derived(&file).1);
        }
        let have: BTreeSet<&str> = license.split(" AND ").collect();
        assert_eq!(have, want, "{name}: {license}");
    }
    let read = |p: &str| {
        std::fs::read_to_string(root().join(p))
            .unwrap_or_default()
            .replace("\r\n", "\n")
    };
    let license = read("LICENSE");
    assert!(
        license.trim_start().starts_with("Apache License\n")
            && license.contains("Version 2.0, January 2004"),
        "LICENSE is the Apache License 2.0"
    );
    assert!(read("NOTICE").starts_with("Hexcavator\n"), "NOTICE");
    let package: Value =
        serde_json::from_str(&read("editors/vscode/hexcavator/package.json")).unwrap();
    assert_eq!(
        package["license"], "Apache-2.0",
        "editors/vscode/hexcavator"
    );
}

#[test]
fn third_party_licenses_are_permissive() {
    let m = metadata();
    for p in linked(&m).into_iter().filter(|p| !p["source"].is_null()) {
        let name = p["name"].as_str().unwrap();
        let license = p["license"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no license"));
        // (Old manifests write "MIT/Apache-2.0" for "MIT OR Apache-2.0".)
        for id in license.split(|c: char| "() /".contains(c)) {
            if id.is_empty() || matches!(id, "AND" | "OR" | "WITH") {
                continue;
            }
            assert!(ALLOWED.contains(&id), "{name}: {license}");
        }
    }
}

/// A package's license files (`LICENSE*`, `COPYING*`, `NOTICE*`,
/// `UNLICENSE`), each with its text (line endings made `\n`).
fn license_files(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let upper = name.to_ascii_uppercase();
            let wanted = ["LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE"]
                .iter()
                .any(|p| upper.starts_with(p));
            if !wanted || !e.path().is_file() {
                return None;
            }
            let text = std::fs::read_to_string(e.path())
                .ok()?
                .replace("\r\n", "\n");
            Some((name, text.trim_end().to_string()))
        })
        .collect();
    out.sort();
    out
}

fn notices() -> String {
    let m = metadata();
    let mut out = String::from(
        "Hexcavator is licensed under the Apache License 2.0, below. Parts of it\n\
         are derived from others' work and carry those works' licenses too, and\n\
         the hexc program includes the third-party crates below; their notices\n\
         follow.\n",
    );
    let section = |out: &mut String, title: &str, text: &str| {
        out.push_str(&format!(
            "\n{}\n{title}\n{}\n\n{text}\n",
            "=".repeat(76),
            "=".repeat(76)
        ));
    };
    let read = |p: &str| {
        std::fs::read_to_string(root().join(p))
            .unwrap()
            .replace("\r\n", "\n")
    };
    let license = read("LICENSE").trim_end().to_string();
    section(
        &mut out,
        "Hexcavator (Apache-2.0)",
        &format!("{}\n\n{license}", read("NOTICE").trim_end()),
    );
    // Identical texts (the same Apache License) are given once.
    let mut given: BTreeMap<String, String> = BTreeMap::new();
    given.insert(license, "Hexcavator (LICENSE)".into());
    let linked = linked(&m);
    // Our crates' parts derived from others' work: each license file's
    // text once, with the crates in the binary that have it.
    let mut parts: Vec<(String, String, Vec<&str>)> = Vec::new();
    for p in linked.iter().filter(|p| p["source"].is_null()) {
        let name = p["name"].as_str().unwrap();
        for (file, text) in license_files(&package_dir(p)) {
            match parts.iter_mut().find(|(t, _, _)| *t == text) {
                Some((_, _, crates)) => crates.push(name),
                None => parts.push((text, file, vec![name])),
            }
        }
    }
    for (text, file, crates) in parts {
        let (who, term) = derived(&file);
        let title = wrap(&format!(
            "{}: derived in part from {who} ({term})",
            crates.join(", ")
        ));
        section(&mut out, &title, &text);
    }
    for p in linked.into_iter().filter(|p| !p["source"].is_null()) {
        let name = p["name"].as_str().unwrap();
        let title = format!(
            "{name} {} ({})",
            p["version"].as_str().unwrap(),
            p["license"].as_str().unwrap_or("?")
        );
        let dir = package_dir(p);
        let mut files = license_files(&dir);
        if files.is_empty() {
            // A package without its license text: ours for it.
            let supplied =
                Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("notices/{name}.txt"));
            let text = std::fs::read_to_string(&supplied).unwrap_or_else(|_| {
                panic!(
                    "{name}: no license file in {}; add {}",
                    dir.display(),
                    supplied.display()
                )
            });
            files.push((
                format!("{name}.txt"),
                text.replace("\r\n", "\n").trim_end().to_string(),
            ));
        }
        let mut body = String::new();
        for (file, text) in files {
            match given.get(&text) {
                Some(first) => body.push_str(&format!("{file}: as for {first}\n")),
                None => {
                    body.push_str(&format!("--- {file} ---\n{text}\n"));
                    given.insert(text, format!("{name} ({file})"));
                }
            }
        }
        section(&mut out, &title, body.trim_end());
    }
    out
}

#[test]
fn notices_are_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("THIRD_PARTY_NOTICES.txt");
    let want = notices();
    if std::env::var_os("HEXC_UPDATE_NOTICES").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        have == want,
        "THIRD_PARTY_NOTICES.txt is out of date: HEXC_UPDATE_NOTICES=1 cargo test -p hexcavator --test it licenses::"
    );
    // And the program prints them.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("licenses")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().replace("\r\n", "\n"),
        want
    );
}

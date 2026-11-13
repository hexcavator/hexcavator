//! Compares `hexc pdb -diaformat` with Microsoft's DIA SDK (via
//! tools/diadump): modules, publics, functions, global data, UDTs, and line
//! records must match exactly.
//!
//! `pdb_matches_snapshot` checks a committed PDB against a committed DIA
//! snapshot (tools/fixtures/snapshots.cmd refreshes both). Running DIA
//! itself, on every architecture's fixture, is an extended test
//! (hexcavator-private's `hexc_pdb`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const KINDS: [&str; 6] = ["MODULE", "PUBLIC", "FUNC", "DATA", "UDT", "LINE"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn hexc_lines(pdb: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["pdb", "-diaformat"])
        .arg(pdb)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "hexc failed on {}: {}",
        pdb.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Compares two outputs category by category, as sets.
fn compare(name: &str, expected: &str, actual: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for kind in KINDS {
        let set = |text: &str| -> BTreeSet<String> {
            text.lines()
                .filter(|l| l.starts_with(kind) && l.as_bytes().get(kind.len()) == Some(&b' '))
                .map(str::to_string)
                .collect()
        };
        let (e, a) = (set(expected), set(actual));
        if e != a {
            let missing: Vec<_> = e.difference(&a).take(5).collect();
            let extra: Vec<_> = a.difference(&e).take(5).collect();
            problems.push(format!(
                "{name} {kind}: {} vs {} (missing {missing:?}, extra {extra:?})",
                e.len(),
                a.len()
            ));
        }
    }
    problems
}

#[test]
fn pdb_matches_snapshot() {
    let data = root().join("crates/symbols/pdb/tests/data");
    let expected = std::fs::read_to_string(data.join("test-x64.dia.txt"))
        .unwrap()
        .replace('\r', "");
    let actual = hexc_lines(&data.join("test-x64.pdb"));
    let problems = compare("test-x64", &expected, &actual);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

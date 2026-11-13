//! A target whose unit tests are off (`test = false` in its manifest, so
//! that `cargo test` doesn't build the crate a second time for nothing)
//! has none: no `#[test]` or `#[cfg(test)]` in its sources, which would
//! otherwise never run.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether the sources under `dir` hold a unit test.
fn has_unit_tests(dir: &Path) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            has_unit_tests(&p)
        } else {
            p.extension().is_some_and(|x| x == "rs")
                && std::fs::read_to_string(&p)
                    .is_ok_and(|s| s.contains("#[test]") || s.contains("#[cfg(test)]"))
        }
    })
}

#[test]
fn targets_without_unit_tests_have_none() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for layer in ["crates", "apps"] {
        let mut dirs: Vec<PathBuf> = Vec::new();
        for e in std::fs::read_dir(root().join(layer)).unwrap().flatten() {
            if layer == "crates" {
                dirs.extend(
                    std::fs::read_dir(e.path())
                        .unwrap()
                        .flatten()
                        .map(|c| c.path()),
                );
            } else {
                dirs.push(e.path());
            }
        }
        for dir in dirs {
            let Ok(manifest) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
                continue;
            };
            if !manifest.lines().any(|l| l.trim() == "test = false") {
                continue;
            }
            checked += 1;
            if has_unit_tests(&dir.join("src")) {
                wrong.push(dir.display().to_string());
            }
        }
    }
    assert!(checked > 0, "no target has its unit tests off");
    assert!(
        wrong.is_empty(),
        "unit tests in targets marked `test = false` (they would never run):\n{}",
        wrong.join("\n")
    );
}

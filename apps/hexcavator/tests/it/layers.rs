//! The crates' layering: each crate depends only on crates in its own layer
//! or an earlier one.
//!
//! | Rank | Layers |
//! |---|---|
//! | 0 | `crates/base` |
//! | 1 | `crates/formats` |
//! | 2 | `crates/symbols`, `crates/isa` |
//! | 3 | `crates/debug`, `crates/analysis`, `crates/trace` |
//! | 4 | `apps` |
//!
//! Layers of the same rank are peers and don't depend on each other.
//! Dev-dependencies (tests and examples) may use anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const LAYERS: &[(&str, u32)] = &[
    ("crates/base", 0),
    ("crates/formats", 1),
    ("crates/symbols", 2),
    ("crates/isa", 2),
    ("crates/debug", 3),
    ("crates/analysis", 3),
    ("crates/trace", 3),
    ("apps", 4),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A crate's package name and its normal dependencies on our crates.
fn manifest(path: &Path) -> (String, Vec<String>) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut name = String::new();
    let mut deps = Vec::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section == "[package]"
            && let Some(v) = line.strip_prefix("name = ")
        {
            name = v.trim_matches('"').to_string();
        }
        // Normal dependencies, unconditional or per target.
        let normal = section == "[dependencies]"
            || (section.starts_with("[target.") && section.ends_with(".dependencies]"));
        if normal {
            let dep = line.split(['=', '.', ' ']).next().unwrap_or("");
            if dep.starts_with("hexcavator") {
                deps.push(dep.to_string());
            }
        }
    }
    (name, deps)
}

#[test]
fn crates_depend_only_on_earlier_layers() {
    let root = root();
    // Every crate: its layer and rank, and its dependencies.
    let mut crates: BTreeMap<String, (&str, u32, Vec<String>)> = BTreeMap::new();
    for &(layer, rank) in LAYERS {
        let dir = root.join(layer);
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{layer}: {e}"))
            .map(|e| e.unwrap().path())
            .filter(|p| p.join("Cargo.toml").exists())
            .collect();
        entries.sort();
        assert!(!entries.is_empty(), "{layer} has no crates");
        for p in entries {
            let (name, deps) = manifest(&p.join("Cargo.toml"));
            assert!(!name.is_empty(), "{}: no package name", p.display());
            crates.insert(name, (layer, rank, deps));
        }
    }
    // No crate outside the layers.
    for e in std::fs::read_dir(root.join("crates")).unwrap() {
        let p = e.unwrap().path();
        let layer = format!("crates/{}", p.file_name().unwrap().to_string_lossy());
        assert!(
            LAYERS.iter().any(|(l, _)| *l == layer),
            "{layer} isn't a known layer (add it to LAYERS)"
        );
    }
    // The manifests were read: known edges are there.
    let deps_of = |c: &str| &crates.get(c).unwrap_or_else(|| panic!("{c}")).2;
    assert!(deps_of("hexcavator-unwind").contains(&"hexcavator-pe".to_string()));
    assert!(deps_of("hexcavator").contains(&"hexcavator-size".to_string()));
    let mut violations = Vec::new();
    for (name, (layer, rank, deps)) in &crates {
        for dep in deps {
            let Some((dep_layer, dep_rank, _)) = crates.get(dep) else {
                violations.push(format!("{name} depends on {dep}, which isn't in any layer"));
                continue;
            };
            let ok = dep_rank < rank || dep_layer == layer;
            if !ok {
                violations.push(format!("{name} ({layer}) depends on {dep} ({dep_layer})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "layering violations:\n  {}",
        violations.join("\n  ")
    );
}

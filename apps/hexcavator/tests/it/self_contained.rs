//! The repository is self-contained: `cargo test` reads nothing outside
//! it, and nothing in it points into a machine.
//!
//! - No test, example, benchmark, or build script names what is outside
//!   the repository: an installed tool (Visual Studio, the Windows SDK,
//!   LLVM, XED, swift-demangle), the system's own files, or the
//!   environment variables that locate them or a local corpus. Tests that
//!   need those are the extended tests, in `hexcavator-private`.
//! - No file holds a path into someone's home directory (`C:\Users\name`,
//!   `/Users/name`, `/home/name`): what is committed comes from a build
//!   made with its paths mapped, or names placeholders (`me`, `you`).
//!
//! Only the repository's own files are read: build output, the
//! machine-local corpus, and other ignored directories are skipped.

use std::path::{Path, PathBuf};

use regex::Regex;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Directories that hold no source: build output and what `.gitignore`
/// keeps out.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "__pycache__",
    "corpus",
    "external",
];

/// Others' files, as they published them (and what their tools say of
/// them): SizeBench's test binaries hold its authors' build paths.
const THIRD_PARTY: &[&str] = &["testdata/sizebench/"];

/// Every file of the repository, by its path relative to the root (with
/// `/`).
fn files() -> Vec<(String, PathBuf)> {
    let root = root();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let Ok(kind) = e.file_type() else { continue };
            if kind.is_dir() {
                // (A tool's build output: `tools/*/out`, `bin`, `obj`.)
                let tool_output = rel.starts_with("tools/")
                    && matches!(name.as_str(), "out" | "bin" | "obj" | "build");
                if !SKIP_DIRS.contains(&name.as_str()) && !tool_output {
                    stack.push(path);
                }
            } else if kind.is_file() {
                out.push((rel, path));
            }
        }
    }
    out.sort();
    out
}

/// Whether `rel` is a cargo target that `cargo test` builds or runs: a
/// test, an example, a benchmark, or a build script.
fn is_cargo_target(rel: &str) -> bool {
    rel.ends_with(".rs")
        && (rel.contains("/tests/")
            || rel.contains("/examples/")
            || rel.contains("/benches/")
            || rel.ends_with("/build.rs"))
}

#[test]
fn tests_read_nothing_outside_the_repository() {
    let outside = Regex::new(concat!(
        r"vswhere|Microsoft Visual Studio|Windows Kits|System32|SysWOW64",
        r#"|env::var(_os)?\("(WINDIR|SystemRoot|ProgramFiles[^"]*|LLVM_[A-Z_]+|XED_DIR"#,
        r#"|SWIFT_DEMANGLE|HEXC_CORPUS|HEXC_DUMPBIN|HEXC_SIZEBENCH_DIR|HEXC_LLVM_BUILD)""#,
    ))
    .unwrap();
    let mut found = Vec::new();
    for (rel, path) in files() {
        if !is_cargo_target(&rel) || rel == "apps/hexcavator/tests/it/self_contained.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            if let Some(m) = outside.find(line) {
                found.push(format!("{rel}:{}: {}", n + 1, m.as_str()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "tests that reach outside the repository (move them to the extended \
         tests, in hexcavator-private):\n{}",
        found.join("\n")
    );
}

#[test]
fn nothing_names_a_home_directory() {
    // A drive's Users directory, macOS's, or Linux's, then a name that isn't
    // a placeholder or a system profile.
    let home = regex::bytes::Regex::new(
        r"(?i)(?:\b[a-z]:[\\/]{1,2}users|/users|/home)[\\/]{1,2}([a-z0-9._-]+)",
    )
    .unwrap();
    let placeholders = [
        "me", "you", "user", "username", "name", "runner", "public", "default", "all",
    ];
    let mut found = Vec::new();
    for (rel, path) in files() {
        if THIRD_PARTY.iter().any(|p| rel.starts_with(p)) {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let hit = home.captures_iter(&data).find_map(|c| {
            let name = String::from_utf8_lossy(&c[1]).to_ascii_lowercase();
            (!placeholders.contains(&name.as_str()))
                .then(|| String::from_utf8_lossy(&c[0]).into_owned())
        });
        if let Some(h) = hit {
            found.push(format!("{rel}: {h}"));
        }
    }
    assert!(
        found.is_empty(),
        "paths into a home directory (build through tools/neutral.cmd, map \
         the paths, or use a placeholder):\n{}",
        found.join("\n")
    );
}

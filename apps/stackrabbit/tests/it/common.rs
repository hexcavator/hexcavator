//! What the tests share: synthetic traces on disk, in a directory of
//! their own.

use std::path::{Path, PathBuf};

use hexcavator_trace_synth::{Config, Synthetic, generate};

/// A directory for one test's files, emptied first.
pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("stackrabbit-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small synthetic trace's configuration.
pub fn small() -> Config {
    Config {
        duration_ms: 300,
        processes: 4,
        threads_per_process: 3,
        ..Config::default()
    }
}

/// Writes a synthetic trace of `config` into `dir`.
pub fn write_trace(dir: &Path, name: &str, config: &Config) -> (PathBuf, Synthetic) {
    let s = generate(config);
    let path = dir.join(name);
    std::fs::write(&path, &s.etl).unwrap();
    (path, s)
}

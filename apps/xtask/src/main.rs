//! Hexcavator's development tasks.
//!
//! `cargo xtask test [cargo test options] [-- test options]`: builds every
//! test binary (one `cargo test --no-run`), then runs them all at once,
//! the longest first (by the last run's times), with the doc tests beside
//! them; prints what failed, in full, and the slowest. `cargo test` runs
//! the binaries one after another, which leaves most cores idle while the
//! slowest few run.
//!
//! With no `-p`/`--package`, it is the whole workspace.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

const USAGE: &str = "\
usage: cargo xtask test [cargo test options] [-- test binary options]

Builds every test (cargo test --no-run; not the examples), then runs all the test binaries at
once, and the doc tests beside them. Without -p, the whole workspace.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("test") => test(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// A test binary to run.
struct Binary {
    exe: PathBuf,
    /// Its package's directory: the working directory cargo runs it in.
    dir: PathBuf,
    package: String,
    /// The test target's name (the package's for unit tests).
    name: String,
}

impl Binary {
    fn label(&self) -> String {
        if self.name.replace('-', "_") == self.package.replace('-', "_") {
            format!("{} (unit)", self.package)
        } else {
            format!("{} {}", self.package, self.name)
        }
    }
}

/// What running one took and said.
struct Outcome {
    label: String,
    ok: bool,
    took: Duration,
    output: String,
    passed: u64,
    failed: u64,
    ignored: u64,
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

/// The root of the workspace it was run in: Hexcavator's, or another that
/// runs it (hexcavator-private's `cargo xtask` alias does).
fn root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        Command::new(cargo())
            .args(["locate-project", "--workspace", "--message-format", "plain"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| Path::new(s.trim()).parent().map(Path::to_path_buf))
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
    })
    .clone()
}

fn test(args: &[String]) -> ExitCode {
    let (cargo_args, test_args) = match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[][..]),
    };
    let mut cargo_args = cargo_args.to_vec();
    if !cargo_args
        .iter()
        .any(|a| a == "-p" || a.starts_with("--package") || a == "--workspace")
    {
        cargo_args.push("--workspace".into());
    }
    // What has tests to run: not the examples and benchmarks, which
    // `cargo test` builds only to see that they compile (clippy's
    // --all-targets, in CI, does that), unless targets are named.
    let targets = [
        "--lib",
        "--bins",
        "--bin",
        "--tests",
        "--test",
        "--examples",
        "--example",
        "--benches",
        "--bench",
        "--all-targets",
        "--doc",
    ];
    if !cargo_args.iter().any(|a| targets.contains(&a.as_str())) {
        cargo_args.extend(["--lib", "--bins", "--tests"].map(String::from));
    }
    let started = Instant::now();
    let Some(binaries) = build(&cargo_args) else {
        return ExitCode::FAILURE;
    };
    let built = started.elapsed();

    // Longest first, by the last run's times: the slowest start at once
    // and the short ones fill in around them.
    let times_path = root().join("target/xtask-test-times.json");
    let last: HashMap<String, f64> = std::fs::read(&times_path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    let mut binaries = binaries;
    binaries.sort_by(|a, b| {
        let t = |x: &Binary| last.get(&x.label()).copied().unwrap_or(f64::MAX);
        t(b).total_cmp(&t(a))
    });

    let run_started = Instant::now();
    // The doc tests: cargo builds and runs them itself, beside the binaries;
    // only for the packages that have any (rustdoc takes a second or two a
    // crate even with none).
    let with_examples = packages_with_doc_examples(&binaries);
    let doc = std::thread::spawn({
        let test_args = test_args.to_vec();
        move || doc_tests(&with_examples, &test_args)
    });
    let outcomes = run_all(binaries, test_args);
    let doc = doc.join().unwrap_or_else(|_| Outcome {
        label: "doc tests".into(),
        ok: false,
        took: Duration::ZERO,
        output: "the doc test thread panicked".into(),
        passed: 0,
        failed: 0,
        ignored: 0,
    });
    let ran = run_started.elapsed();

    let mut times: HashMap<String, f64> = last;
    for o in &outcomes {
        times.insert(o.label.clone(), o.took.as_secs_f64());
    }
    if let Ok(json) = serde_json::to_vec_pretty(&times) {
        let _ = std::fs::write(&times_path, json);
    }

    let mut all = outcomes;
    all.push(doc);
    report(&all, built, ran)
}

/// Builds the tests; the binaries cargo made.
fn build(cargo_args: &[String]) -> Option<Vec<Binary>> {
    let mut child = Command::new(cargo())
        .args([
            "test",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .args(cargo_args)
        .current_dir(root())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| eprintln!("xtask: cargo: {e}"))
        .ok()?;
    let mut binaries = Vec::new();
    let stdout = child.stdout.take()?;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if v["reason"] != "compiler-artifact" || v["profile"]["test"] != true {
            continue;
        }
        let Some(exe) = v["executable"].as_str() else {
            continue;
        };
        let manifest = PathBuf::from(v["manifest_path"].as_str().unwrap_or_default());
        let package = v["package_id"]
            .as_str()
            .and_then(package_name)
            .unwrap_or_default();
        binaries.push(Binary {
            exe: PathBuf::from(exe),
            dir: manifest.parent().map(Path::to_path_buf).unwrap_or_default(),
            package,
            name: v["target"]["name"].as_str().unwrap_or_default().to_owned(),
        });
    }
    let status = child.wait().ok()?;
    if !status.success() {
        eprintln!("xtask: the build failed");
        return None;
    }
    Some(binaries)
}

/// A package's name from its id: `path+file:///...#name@0.1.0`, or
/// `...#0.1.0` when the directory is the name.
fn package_name(id: &str) -> Option<String> {
    let (before, after) = id.rsplit_once('#')?;
    match after.split_once('@') {
        Some((name, _)) => Some(name.to_owned()),
        None => before.rsplit(['/', '\\']).next().map(str::to_owned),
    }
}

/// Runs every binary, as many at once as there are cores.
fn run_all(binaries: Vec<Binary>, test_args: &[String]) -> Vec<Outcome> {
    let workers = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
    let queue = Arc::new(Mutex::new(binaries.into_iter()));
    let results = Arc::new(Mutex::new(Vec::new()));
    let cargo = cargo();
    let threads: Vec<_> = (0..workers)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);
            let test_args = test_args.to_vec();
            let cargo = cargo.clone();
            std::thread::spawn(move || {
                loop {
                    let next = queue
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .next();
                    let Some(b) = next else { break };
                    let o = run_one(&b, &test_args, &cargo);
                    if !o.ok {
                        eprintln!("FAILED: {}", o.label);
                    }
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(o);
                }
            })
        })
        .collect();
    for t in threads {
        let _ = t.join();
    }
    Arc::try_unwrap(results)
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .unwrap_or_default()
}

fn run_one(b: &Binary, test_args: &[String], cargo: &str) -> Outcome {
    let started = Instant::now();
    // As cargo runs it: in the package's directory, with its variables.
    let result = Command::new(&b.exe)
        .args(test_args)
        .current_dir(&b.dir)
        .env("CARGO", cargo)
        .env("CARGO_MANIFEST_DIR", &b.dir)
        .env("CARGO_PKG_NAME", &b.package)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            // (Both pipes drained at once: a full one would stall the child.)
            let mut err = child.stderr.take();
            let err_thread = std::thread::spawn(move || {
                let mut s = Vec::new();
                if let Some(e) = err.as_mut() {
                    let _ = e.read_to_end(&mut s);
                }
                s
            });
            let mut out = Vec::new();
            if let Some(o) = child.stdout.as_mut() {
                o.read_to_end(&mut out)?;
            }
            let status = child.wait()?;
            let err = err_thread.join().unwrap_or_default();
            out.extend_from_slice(&err);
            Ok((status.success(), out))
        });
    let took = started.elapsed();
    let (ok, output) = match result {
        Ok((ok, out)) => (ok, String::from_utf8_lossy(&out).into_owned()),
        Err(e) => (false, format!("{}: {e}", b.exe.display())),
    };
    let (passed, failed, ignored) = counts(&output);
    Outcome {
        label: b.label(),
        ok,
        took,
        output,
        passed,
        failed,
        ignored,
    }
}

/// The packages (of those built) whose sources have a Rust example in a
/// doc comment: a code block whose language is Rust's (none, `rust`,
/// `no_run`, `should_panic`, `compile_fail`, `ignore`, `editionNNNN`).
fn packages_with_doc_examples(binaries: &[Binary]) -> Vec<String> {
    let mut seen = std::collections::BTreeMap::new();
    for b in binaries {
        seen.entry(b.package.clone())
            .or_insert_with(|| b.dir.clone());
    }
    seen.into_iter()
        .filter(|(_, dir)| has_doc_example(&dir.join("src")))
        .map(|(p, _)| p)
        .collect()
}

fn has_doc_example(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            return has_doc_example(&p);
        }
        if p.extension().is_none_or(|x| x != "rs") {
            return false;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            return false;
        };
        let mut open = false;
        text.lines().any(|line| {
            let line = line.trim_start();
            let Some(doc) = line
                .strip_prefix("///")
                .or_else(|| line.strip_prefix("//!"))
            else {
                return false;
            };
            let Some(info) = doc.trim().strip_prefix("```") else {
                return false;
            };
            open = !open;
            open && info.split(',').all(|w| {
                let w = w.trim();
                w.is_empty()
                    || matches!(
                        w,
                        "rust" | "no_run" | "should_panic" | "compile_fail" | "ignore"
                    )
                    || w.starts_with("edition")
            })
        })
    })
}

/// The doc tests of `packages`, through cargo (which compiles each).
fn doc_tests(packages: &[String], test_args: &[String]) -> Outcome {
    let started = Instant::now();
    if packages.is_empty() {
        return Outcome {
            label: "doc tests".into(),
            ok: true,
            took: Duration::ZERO,
            output: String::new(),
            passed: 0,
            failed: 0,
            ignored: 0,
        };
    }
    let out = Command::new(cargo())
        .args(["test", "--doc", "--quiet"])
        .args(packages.iter().flat_map(|p| ["-p", p.as_str()]))
        .arg("--")
        .args(test_args)
        .current_dir(root())
        .output();
    let took = started.elapsed();
    let (ok, output) = match out {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s)
        }
        Err(e) => (false, format!("cargo test --doc: {e}")),
    };
    let (passed, failed, ignored) = counts(&output);
    Outcome {
        label: "doc tests".into(),
        ok,
        took,
        output,
        passed,
        failed,
        ignored,
    }
}

/// The totals of libtest's `test result:` lines.
fn counts(output: &str) -> (u64, u64, u64) {
    let mut totals = (0, 0, 0);
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("test result: ") else {
            continue;
        };
        for part in rest.split([';', '.']) {
            let mut words = part.split_whitespace();
            let (Some(n), Some(what)) = (words.next(), words.next()) else {
                continue;
            };
            let Ok(n) = n.parse::<u64>() else { continue };
            match what {
                "passed" => totals.0 += n,
                "failed" => totals.1 += n,
                "ignored" => totals.2 += n,
                _ => {}
            }
        }
    }
    totals
}

fn report(all: &[Outcome], built: Duration, ran: Duration) -> ExitCode {
    let failed: Vec<&Outcome> = all.iter().filter(|o| !o.ok).collect();
    for o in &failed {
        eprintln!("\n==== {} ====\n{}", o.label, o.output.trim_end());
    }
    let mut slowest: Vec<&Outcome> = all.iter().collect();
    slowest.sort_by_key(|o| std::cmp::Reverse(o.took));
    println!("\nslowest:");
    for o in slowest.iter().take(8) {
        println!("  {:6.1} s  {}", o.took.as_secs_f64(), o.label);
    }
    let passed: u64 = all.iter().map(|o| o.passed).sum();
    let ignored: u64 = all.iter().map(|o| o.ignored).sum();
    let tests_failed: u64 = all.iter().map(|o| o.failed).sum();
    println!(
        "\n{} binaries: {passed} passed, {tests_failed} failed, {ignored} ignored; \
         built in {:.1} s, ran in {:.1} s",
        all.len() - 1,
        built.as_secs_f64(),
        ran.as_secs_f64()
    );
    if failed.is_empty() {
        println!("ok");
        ExitCode::SUCCESS
    } else {
        println!(
            "FAILED: {}",
            failed
                .iter()
                .map(|o| o.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        ExitCode::FAILURE
    }
}

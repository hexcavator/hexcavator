//! `hexc serve`: each request answered as the command line would answer
//! it, from what is kept in memory, until the binary changes.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sizebench/bin")
        .join(name)
}

fn hexc(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A `hexc serve`, asked one request at a time.
struct Server {
    child: std::process::Child,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
    next: u64,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self {
            child,
            lines,
            next: 1,
        }
    }

    fn ask(&mut self, args: &[&str]) -> Value {
        let id = self.next;
        self.next += 1;
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", json!({ "id": id, "args": args })).unwrap();
        stdin.flush().unwrap();
        let v: Value = serde_json::from_str(&self.lines.next().unwrap().unwrap()).unwrap();
        assert_eq!(v["id"], id);
        v
    }

    fn stdout(&mut self, args: &[&str]) -> String {
        let v = self.ask(args);
        assert_eq!(v["code"], 0, "{}", v["stderr"]);
        v["stdout"].as_str().unwrap().to_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

#[test]
fn answers_as_the_command_line_does() {
    let dll = bin("CppTestCases_BasicDiffObjectsAfter.dll");
    let dll = dll.to_str().unwrap();
    let mut s = Server::start();
    for args in [
        &["size", "-d", "symbols", "-n", "0", "-csv", dll][..],
        &["size", "-d", "compileunits", "-csv", dll],
        &[
            "query",
            dll,
            "kind=function sort by file desc limit 20",
            "-json",
        ],
    ] {
        let want = hexc(args);
        // Built, then kept: the same both times.
        assert_eq!(s.stdout(args), want, "{args:?}");
        assert_eq!(s.stdout(args), want, "{args:?}");
    }
    // A failure: its code and message.
    let v = s.ask(&["size", "nonesuch.dll"]);
    assert_ne!(v["code"], 0);
    assert!(
        v["stderr"].as_str().unwrap().contains("nonesuch.dll"),
        "{v}"
    );
    assert_eq!(v["stdout"], "");
}

/// A binary rebuilt (replaced) while the server runs is read again.
#[test]
fn a_changed_binary_is_read_again() {
    let dir = std::env::temp_dir().join(format!("hexc-serve-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("app.dll");
    let pdb = dir.join("app.pdb");
    // (Rewritten in place, as a linker would: the server must not hold
    // them open between requests.)
    let put = |which: &str| {
        std::fs::copy(
            bin(&format!("CppTestCases_BasicDiffObjects{which}.dll")),
            &image,
        )
        .unwrap();
        std::fs::copy(
            bin(&format!("CppTestCases_BasicDiffObjects{which}.pdb")),
            &pdb,
        )
        .unwrap();
    };
    let (image, pdb) = (image.to_str().unwrap(), pdb.to_str().unwrap());
    let args = [
        "size", "-d", "symbols", "-n", "0", "-csv", image, "-pdb", pdb,
    ];
    let mut s = Server::start();
    put("Before");
    let before = s.stdout(&args);
    assert_eq!(before, hexc(&args));
    put("After");
    let after = s.stdout(&args);
    assert_eq!(after, hexc(&args));
    assert_ne!(before, after);
    drop(s);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Requests sent together are all answered, each with its id.
#[test]
fn requests_run_together() {
    let dll = bin("CppTestCases_BasicDiffObjectsAfter.dll");
    let dll = dll.to_str().unwrap();
    let want = hexc(&["size", "-d", "symbols", "-n", "0", "-csv", dll]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for id in 0..8 {
            let args = ["size", "-d", "symbols", "-n", "0", "-csv", dll];
            writeln!(stdin, "{}", json!({ "id": id, "args": args })).unwrap();
        }
    }
    // At the end of input, all are answered, then it exits.
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let mut ids: Vec<i64> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["stdout"], want.as_str());
            v["id"].as_i64().unwrap()
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (0..8).collect::<Vec<_>>());
}

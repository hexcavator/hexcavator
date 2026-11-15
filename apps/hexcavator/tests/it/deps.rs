//! `hexc deps` end to end, over the dependency test's images
//! (tools/deps): each with a system root of stand-ins, so the search is
//! the loader's over known files.
//!
//! - PE: known DLLs over the application's directory (a planted
//!   kernel32), imports by name and ordinal, exports missing, forwarders
//!   (one broken), an API set (by the schema), Common Controls 6 (by the
//!   manifest, in WinSxS), a DLL missing and one delay-loaded, and a 32-bit
//!   program's SysWOW64.
//! - ELF: the interpreter, rpath, runpath, an inherited rpath, ld.so.conf
//!   (and its include), a default directory, another architecture's
//!   library, symbols missing and at a version not there.
//! - Mach-O: @rpath (the program's and a library's), @loader_path, a
//!   re-export, a symbol a library lost, a weak library missing, libSystem
//!   (the shared cache's).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/deps")
        .join(rel)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("deps")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The graph (with -json) of `image` with the system root `sysroot`.
fn graph(image: &str, sysroot: &str, more: &[&str]) -> Value {
    let image = testdata(image);
    let sysroot = testdata(sysroot);
    let mut args = vec!["-json", "-sysroot", sysroot.to_str().unwrap()];
    args.extend(more);
    args.push(image.to_str().unwrap());
    let (_, out, err) = hexc(&args);
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}{err}"))
}

/// A module's index.
fn id(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap()).unwrap()
}

/// The module `from` loads by `name` (case aside).
fn dep<'g>(g: &'g Value, from: usize, name: &str) -> (&'g Value, &'g Value) {
    let d = g["modules"][from]["deps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"].as_str().unwrap().eq_ignore_ascii_case(name))
        .unwrap_or_else(|| panic!("{name} not loaded by {}", g["modules"][from]["name"]));
    let m = &g["modules"][id(&d["module"])];
    (d, m)
}

/// Where a module was found (its path's last two components, with /).
fn place(m: &Value) -> String {
    let p = m["path"].as_str().unwrap_or("").replace('\\', "/");
    let parts: Vec<&str> = p.rsplitn(3, '/').collect();
    format!("{}/{}", parts.get(1).unwrap_or(&""), parts[0])
}

/// The status of import `name` of an edge.
fn import<'d>(d: &'d Value, name: &str) -> &'d Value {
    d["imports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| {
            i["name"] == name
                || i["ordinal"].as_u64().map(|o| format!("#{o}")).as_deref() == Some(name)
        })
        .unwrap_or_else(|| panic!("no import {name} in {d}"))
}

#[test]
fn pe() {
    let g = graph("pe/app/app.exe", "pe/windows", &[]);
    // A known DLL is the system's, whatever the application's directory has.
    let (d, k32) = dep(&g, 0, "kernel32.dll");
    assert_eq!(place(k32), "System32/kernel32.dll");
    assert_eq!(k32["how"], "known DLL");
    assert_eq!(import(d, "Sleep")["status"], "found");
    // The helper, by name and by ordinal; what it imports and lacks.
    let (d, helper) = dep(&g, 0, "helper.dll");
    assert_eq!(helper["how"], "application directory");
    assert_eq!(import(d, "helper_add")["status"], "found");
    assert_eq!(import(d, "#5")["status"], "found");
    let h = id(&helper["id"]);
    let (d, _) = dep(&g, h, "kernel32.dll");
    assert_eq!(import(d, "NoSuchFunction")["status"], "missing");
    assert_eq!(import(d, "FwdTarget")["status"], "forwarded");
    assert_eq!(import(d, "FwdTarget")["forwardedTo"], "apihost.Target");
    assert_eq!(import(d, "FwdMissing")["status"], "brokenForwarder");
    let (_, gone) = dep(&g, h, "gone.dll");
    assert_eq!(gone["status"], "missing");
    // The API set's host, by the schema.
    let (d, host) = dep(&g, 0, "api-ms-win-test-l1-1-0.dll");
    assert_eq!(place(host), "System32/apihost.dll");
    assert_eq!(import(d, "ApiFunc")["status"], "found");
    // Common Controls: the manifest's version 6, from WinSxS (which has
    // TaskDialogIndirect; System32's 5 doesn't).
    let (d, comctl) = dep(&g, 0, "comctl32.dll");
    assert!(
        place(comctl).ends_with("_6.0.1.0_none_test/comctl32.dll"),
        "{comctl}"
    );
    assert_eq!(comctl["how"], "side-by-side assembly");
    assert_eq!(import(d, "TaskDialogIndirect")["status"], "found");
    let (_, assembly) = dep(&g, 0, "Microsoft.Windows.Common-Controls 6.0.0.0");
    assert_eq!(assembly["status"], "assembly");
    // Delay-loaded, not shipped: a warning.
    let (d, missing) = dep(&g, 0, "missing.dll");
    assert_eq!(d["kind"], "delay-load");
    assert_eq!(missing["status"], "missing");
    let problems: Vec<(String, String)> = g["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["severity"].as_str().unwrap().to_string(),
                p["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        problems,
        [
            ("error".to_string(), "helper.dll imports 2 symbols from kernel32.dll that it doesn't export: FwdMissing (forwarded to apihost.NotThere), NoSuchFunction".to_string()),
            ("error".to_string(), "gone.dll (loaded by helper.dll): not found".to_string()),
            ("warning".to_string(), "missing.dll (delay-loaded by app.exe): not found".to_string()),
        ]
    );
    // A 32-bit program: SysWOW64's (System32's is x64).
    let g = graph("pe/app32/app32.exe", "pe/windows", &[]);
    let (_, k32) = dep(&g, 0, "kernel32.dll");
    assert_eq!(place(k32), "SysWOW64/kernel32.dll");
    assert!(g["problems"].as_array().unwrap().is_empty());
}

/// The text form: the tree, then the problems; exit 1 when something the
/// program needs is missing.
#[test]
fn text() {
    let image = testdata("pe/app/app.exe");
    let sysroot = testdata("pe/windows");
    let (code, out, _) = hexc(&[
        "-sysroot",
        sysroot.to_str().unwrap(),
        image.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("app.exe  PE x64  "), "{out}");
    assert!(out.contains("\n  helper.dll  "), "{out}");
    assert!(out.contains("\n    gone.dll  NOT FOUND\n"), "{out}");
    assert!(
        out.contains("\n  missing.dll  NOT FOUND  [delay-load]\n"),
        "{out}"
    );
    assert!(
        out.contains("\n  api-ms-win-test-l1-1-0.dll -> apihost.dll  "),
        "{out}"
    );
    assert!(
        out.contains("\nProblems:\n  error: helper.dll imports 2 symbols"),
        "{out}"
    );
    // -problems: only those; the 32-bit program has none (exit 0).
    let (code, out, _) = hexc(&[
        "-problems",
        "-sysroot",
        sysroot.to_str().unwrap(),
        testdata("pe/app32/app32.exe").to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "No problems: everything it loads was found, with what it imports.\n"
    );
}

#[test]
fn elf() {
    let g = graph("elf/app/app-ok", "elf/sysroot", &[]);
    let (d, interp) = dep(&g, 0, "/lib64/ld-linux-x86-64.so.2");
    assert_eq!(d["kind"], "interpreter");
    assert_eq!(place(interp), "lib64/ld-linux-x86-64.so.2");
    let (_, a) = dep(&g, 0, "liba.so");
    assert_eq!(
        (place(a).as_str(), a["how"].as_str()),
        ("lib/liba.so", Some("rpath"))
    );
    let ai = id(&a["id"]);
    let (_, b) = dep(&g, ai, "libb.so");
    assert_eq!(
        (place(b).as_str(), b["how"].as_str()),
        ("libb/libb.so", Some("runpath"))
    );
    // libb has neither: the program's rpath (liba's runpath stops only
    // liba's own rpath).
    let (_, inh) = dep(&g, id(&b["id"]), "libinh.so");
    assert_eq!(
        (place(inh).as_str(), inh["how"].as_str()),
        ("lib/libinh.so", Some("rpath"))
    );
    let (_, opt) = dep(&g, ai, "libopt.so");
    assert_eq!(
        (place(opt).as_str(), opt["how"].as_str()),
        ("lib/libopt.so", Some("ld.so.conf"))
    );
    let (_, libc) = dep(&g, 0, "libc.so.6");
    assert_eq!(
        (place(libc).as_str(), libc["how"].as_str()),
        ("x86_64-linux-gnu/libc.so.6", Some("default directory"))
    );
    // Symbols: one at a version libc doesn't have; one nothing defines.
    let unresolved = |m: &Value| -> Vec<String> {
        m["unresolved"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                format!(
                    "{}@{}",
                    i["name"].as_str().unwrap(),
                    i["version"].as_str().unwrap_or("")
                )
            })
            .collect()
    };
    assert_eq!(unresolved(&g["modules"][0]), ["vers_fn@GLIBC_2.99"]);
    assert_eq!(unresolved(&g["modules"][ai]), ["nowhere@"]);
    // Another architecture's library: found, and refused (and so symbols
    // aren't checked).
    let g = graph("elf/app/app", "elf/sysroot", &[]);
    let (_, wrong) = dep(&g, 0, "libwrong.so");
    assert_eq!(wrong["status"], "wrongArch");
    assert_eq!(wrong["detail"]["arch"], "arm64");
    assert!(
        g["notes"][0]
            .as_str()
            .unwrap()
            .contains("symbols weren't checked")
    );
}

#[test]
fn macho() {
    let g = graph("macho/app/main", "macho/sysroot", &[]);
    let (d, a) = dep(&g, 0, "@rpath/liba.dylib");
    assert_eq!(
        (place(a).as_str(), a["how"].as_str()),
        ("lib/liba.dylib", Some("rpath"))
    );
    assert_eq!(import(d, "_a_fn")["status"], "found");
    // Re-exported by liba, from libre.
    assert_eq!(import(d, "_re_fn")["status"], "found");
    // liba had it when the program was linked; no longer.
    assert_eq!(import(d, "_gone_fn")["status"], "missing");
    let ai = id(&a["id"]);
    // libb by liba's own run path (@loader_path); libre by @loader_path.
    let (_, b) = dep(&g, ai, "@rpath/libb.dylib");
    assert_eq!(place(b), "lib/libb.dylib");
    let (d, re) = dep(&g, ai, "@loader_path/libre.dylib");
    assert_eq!(
        (d["kind"].as_str(), re["how"].as_str()),
        (Some("reexport-dylib"), Some("@loader_path"))
    );
    let (d, weak) = dep(&g, 0, "@rpath/libweak.dylib");
    assert_eq!(
        (d["kind"].as_str(), weak["status"].as_str()),
        (Some("weak-dylib"), Some("missing"))
    );
    let (_, system) = dep(&g, 0, "/usr/lib/libSystem.B.dylib");
    assert_eq!(system["status"], "sharedCache");
    let severities: Vec<&str> = g["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["severity"].as_str().unwrap())
        .collect();
    assert_eq!(severities, ["error", "warning"]);
}

/// Without a system root for the image's format (none on this host, for
/// another platform's): system libraries aren't searched, and say so.
#[test]
fn no_system_root() {
    let image = testdata("macho/app/main");
    let (code, out, _) = hexc(&[image.to_str().unwrap()]);
    if cfg!(target_os = "macos") {
        return;
    }
    assert!(
        out.contains("/usr/lib/libSystem.B.dylib  (a system library: not searched)"),
        "{out}"
    );
    assert!(
        out.contains("note: system libraries weren't searched"),
        "{out}"
    );
    // (liba lost a symbol: still an error.)
    assert_eq!(code, 1);
}

#[test]
fn bad_arguments() {
    for args in [
        &[][..],
        &["-nonesuch", "x"],
        &["-depth"],
        &["-depth", "x", "y"],
        &["a", "b"],
    ] {
        let (code, _, err) = hexc(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains("usage: hexc deps"), "{err}");
    }
    let (code, _, err) = hexc(&["no-such-file.exe"]);
    assert_eq!(code, 1, "{err}");
    let readme = testdata("macho/sysroot/README");
    let (code, _, err) = hexc(&[readme.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("not a PE, ELF, or Mach-O image"), "{err}");
}

/// Names that are paths where a name belongs (a hostile image's): not
/// searched, opened, or connected to (a UNC name would make Windows
/// offer the user's credentials to a server).
#[test]
fn hostile_names() {
    let original = std::fs::read(testdata("pe/app/app.exe")).unwrap();
    let at = original
        .windows(10)
        .position(|w| w == b"helper.dll")
        .expect("the import's name");
    let dir = std::env::temp_dir().join(format!("hexc-deps-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        &b"..\\x\\y.dll"[..],
        b"\\\\a\\b.dll\0",
        b"C:\\x\\y.dll",
        b"a\0b.dll\0\0\0",
    ] {
        let mut data = original.clone();
        data[at..at + 10].copy_from_slice(&name[..10]);
        let path = dir.join("app.exe");
        std::fs::write(&path, &data).unwrap();
        let sysroot = testdata("pe/windows");
        let (code, out, err) = hexc(&[
            "-json",
            "-sysroot",
            sysroot.to_str().unwrap(),
            path.to_str().unwrap(),
        ]);
        assert_eq!(code, 1, "{err}");
        let g: Value = serde_json::from_str(&out).unwrap();
        let named: Vec<&Value> = g["modules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["name"].as_str().unwrap().contains(['\\', '/', ':']))
            .collect();
        for m in named {
            assert_eq!(m["status"], "missing", "{m}");
            assert!(m["detail"]["tried"].as_array().unwrap().is_empty(), "{m}");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

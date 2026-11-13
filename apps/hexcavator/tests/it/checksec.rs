//! `hexc checksec`: each mitigation on or off as the fixtures were built
//! (the hardened ELF images of tools/elf/hardened.c against the plain
//! program; the xref PE image, built without /guard:cf but with CRT code
//! that has it; a Mach-O image signed ad hoc), and `-audit` naming the
//! objects built differently.

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn checks(file: &str) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["checksec", "-json"])
        .arg(root().join(file))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The state of check `name`.
fn state(v: &serde_json::Value, name: &str) -> String {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no check {name}: {v}"))["state"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn elf_on_and_off() {
    let h = checks("testdata/elf/hardened-x86_64-linux-gnu");
    for name in [
        "PIE",
        "RELRO",
        "NX stack",
        "Stack canaries",
        "CET IBT",
        "CET shadow stack",
        "No text relocations",
    ] {
        assert_eq!(state(&h, name), "on", "{name}");
    }
    let a = checks("testdata/elf/hardened-aarch64-linux-gnu");
    for name in ["PIE", "RELRO", "BTI", "PAC", "Stack canaries"] {
        assert_eq!(state(&a, name), "on", "{name}");
    }
    let p = checks("testdata/elf/program-x86_64-linux-gnu");
    for name in ["PIE", "Stack canaries", "CET IBT", "CET shadow stack"] {
        assert_eq!(state(&p, name), "off", "{name}");
    }
    // Static: RELRO with nothing bound at run time.
    assert_eq!(state(&p, "RELRO"), "on");
    // A shared library is position-independent, whatever its flags.
    assert_eq!(state(&checks("testdata/elf/program.so"), "PIE"), "n/a");
    // Lazily bound: partial RELRO.
    assert_eq!(state(&checks("testdata/elf/relr.so"), "RELRO"), "partial");
}

#[test]
fn pe_and_macho() {
    let pe = checks("testdata/xref/xref-x64.exe");
    for name in [
        "ASLR",
        "High-entropy ASLR",
        "DEP (NX)",
        "Stack cookies (/GS)",
        "No W+X sections",
    ] {
        assert_eq!(state(&pe, name), "on", "{name}");
    }
    for name in [
        "Control Flow Guard",
        "CET shadow stack",
        "EH continuation",
        "Authenticode",
    ] {
        assert_eq!(state(&pe, name), "off", "{name}");
    }
    assert_eq!(state(&pe, "SafeSEH"), "n/a");
    let m = checks("testdata/macho/program-arm64");
    assert_eq!(state(&m, "PIE"), "on");
    assert_eq!(state(&m, "Code signature"), "partial");
    assert_eq!(state(&m, "Pointer authentication"), "off");
}

#[test]
fn audit_names_the_objects_built_differently() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["checksec", "-audit", "-json"])
        .arg(root().join("testdata/xref/xref-x64.exe"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let options = v["audit"]["options"].as_array().unwrap();
    let option = |name: &str| {
        options
            .iter()
            .find(|o| o["option"] == name)
            .unwrap_or_else(|| panic!("{name}: {v}"))
    };
    // The fixture's own objects were built without /guard:cf, the CRT's
    // with it.
    let cf = option("/guard:cf");
    assert_eq!(cf["severity"], "weakens");
    let off = cf["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["value"] == "off")
        .unwrap();
    let objs: Vec<&str> = off["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_str().unwrap())
        .collect();
    assert!(objs.iter().any(|o| o.ends_with("main.obj")), "{objs:?}");
    // Every compiled object has /GS and the same runtime library.
    for (name, value) in [("/GS", "on"), ("runtime library", "/MD")] {
        let o = option(name);
        let values = o["values"].as_array().unwrap();
        assert_eq!(values.len(), 1, "{name}: {o}");
        assert_eq!(values[0]["value"], value);
    }
    // Each object: its command line, tool, directory, source, and library
    // (none for the linker's own inputs); and the linker's command line.
    let builds = v["audit"]["builds"].as_array().unwrap();
    let main = builds
        .iter()
        .find(|b| b["object"].as_str().unwrap().ends_with("main.obj"))
        .unwrap();
    assert_eq!(main["library"], "");
    assert!(main["tool"].as_str().unwrap().ends_with("cl.exe"), "{main}");
    assert!(main["source"].as_str().unwrap().ends_with(".cpp"), "{main}");
    assert!(main["command"].as_str().unwrap().contains("-c"), "{main}");
    assert!(!main["cwd"].as_str().unwrap().is_empty(), "{main}");
    assert!(builds.iter().any(|b| {
        b["library"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .ends_with(".lib")
    }));
    let linker = &v["audit"]["linker"];
    assert!(
        linker["exe"].as_str().unwrap().ends_with("link.exe"),
        "{linker}"
    );
    assert!(
        linker["cmd"].as_str().unwrap().contains("/OUT:"),
        "{linker}"
    );
    // Text: the same, readable.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["checksec", "-audit"])
        .arg(root().join("testdata/xref/xref-x64.exe"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("/guard:cf (weakens):") && text.contains("main.obj"),
        "{text}"
    );
}

#[test]
fn not_an_image() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["checksec"])
        .arg(root().join("testdata/wasm/module.wasm"))
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn audit_of_a_debug_map_names_archives_members() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["checksec", "-audit", "-json"])
        .arg(root().join("testdata/macho/oso/oso-arm64"))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let builds = v["audit"]["builds"].as_array().unwrap();
    let member = builds
        .iter()
        .find(|b| b["object"] == "second-arm64.o")
        .unwrap_or_else(|| panic!("{v}"));
    assert!(
        member["library"]
            .as_str()
            .unwrap()
            .ends_with("libsecond-arm64.a"),
        "{member}"
    );
    assert!(member["source"].as_str().unwrap().ends_with("second.c"));
    let program = builds
        .iter()
        .find(|b| b["object"].as_str().unwrap().ends_with("program-arm64.o"))
        .unwrap();
    assert_eq!(program["library"], "");
    assert_eq!(program["source"], "program.c");
}

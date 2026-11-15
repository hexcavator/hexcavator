//! `hexc init` end to end, over the initialization test program
//! (tools/init): as a PE program and DLL (a TLS callback, a C initializer,
//! a global object's constructor), an ELF program and library
//! (.preinit_array, DT_INIT, .ctors, .init_array with a priority), and a
//! Mach-O program (__mod_init_func, LC_MAIN): the phases in the order they
//! run, their functions in order, and what each calls.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/init")
        .join(rel)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("init")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn json(image: &str, more: &[&str]) -> Value {
    let path = testdata(image);
    let mut args = vec!["-json"];
    args.extend(more);
    args.push(path.to_str().unwrap());
    let (code, out, err) = hexc(&args);
    assert_eq!(code, 0, "{err}");
    serde_json::from_str(&out).unwrap()
}

/// Each phase's name, with its functions' names.
fn phases(v: &Value) -> Vec<(String, Vec<String>)> {
    v["phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_string(),
                p["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e["name"].as_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

/// The names of what node `n` of `image` calls.
fn callees(image: &str, n: &Value) -> Vec<String> {
    let v = json(image, &["-callees", &n.as_u64().unwrap().to_string()]);
    v["callees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect()
}

/// The entry of the phase named `phase` named `name`.
fn entry<'v>(v: &'v Value, phase: &str, name: &str) -> &'v Value {
    v["phases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == phase)
        .and_then(|p| {
            p["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["name"] == name)
        })
        .unwrap_or_else(|| panic!("no {name} in {phase}"))
}

#[test]
fn pe_program() {
    let v = json("init.exe", &[]);
    assert_eq!(v["library"], false);
    let p = phases(&v);
    let names: Vec<&str> = p.iter().map(|(n, _)| n.as_str()).collect();
    // The loader's, then the CRT's lists in the order it calls them (the
    // CRT's own groups, and the program's).
    assert_eq!(names[0], "TLS callbacks");
    assert_eq!(names[1], "the entry point");
    let xi = names.iter().position(|n| *n == ".CRT$XIU").unwrap();
    let xc = names.iter().position(|n| *n == ".CRT$XCU").unwrap();
    assert!(
        names[2..xi].iter().all(|n| n.starts_with(".CRT$XI")),
        "{names:?}"
    );
    assert!(xi < xc && names[xc - 1].starts_with(".CRT$XC"), "{names:?}");
    assert_eq!(p[0].1, ["tls_callback(void*, unsigned long, void*)"]);
    assert_eq!(p[1].1, ["mainCRTStartup(void*)"]);
    assert_eq!(p[xi].1, ["c_initializer()"]);
    assert_eq!(p[xc].1, ["`dynamic initializer for 'widget''()"]);
    let tls = entry(
        &v,
        "TLS callbacks",
        "tls_callback(void*, unsigned long, void*)",
    );
    assert!(tls["file"].as_str().unwrap().ends_with("init.cpp"));
    assert_eq!(tls["line"], 11);
    // What the constructor's initializer calls, and what that calls.
    let init = entry(&v, ".CRT$XCU", "`dynamic initializer for 'widget''()");
    assert!(init["slot"].as_str().unwrap().starts_with("0x14000"));
    assert_eq!(callees("init.exe", &init["node"]), ["Widget::Widget()"]);
    let ctor = json("init.exe", &["-callees", &init["node"].to_string()])["callees"][0].clone();
    assert_eq!(ctor["jump"], true, "a tail call");
    assert_eq!(callees("init.exe", &ctor["node"]), ["Widget::prepare()"]);
    // The entry point's calls, in the order its code makes them.
    let start = entry(&v, "the entry point", "mainCRTStartup(void*)");
    assert_eq!(
        callees("init.exe", &start["node"]),
        ["__security_init_cookie()", "__scrt_common_main_seh()"]
    );
    assert_eq!(v["main"]["name"], "main()");
}

#[test]
fn pe_dll() {
    let v = json("initdll.dll", &[]);
    assert_eq!(v["library"], true);
    let p = phases(&v);
    assert_eq!(
        p[0],
        (
            "TLS callbacks".to_string(),
            vec!["tls_callback(void*, unsigned long, void*)".to_string()]
        )
    );
    assert_eq!(
        p[1].1,
        ["_DllMainCRTStartup(HINSTANCE__* const, const unsigned long, void* const)"]
    );
    assert!(
        p.iter()
            .any(|(n, f)| n == ".CRT$XCU" && f == &["`dynamic initializer for 'widget''()"])
    );
    assert_eq!(
        v["main"]["name"],
        "DllMain(HINSTANCE__*, unsigned long, void*)"
    );
}

#[test]
fn elf() {
    let v = json("init-x86_64-linux-gnu", &[]);
    assert_eq!(v["library"], false);
    assert_eq!(
        phases(&v),
        [
            (".preinit_array".to_string(), vec!["preinit()".to_string()]),
            ("DT_INIT".to_string(), vec!["init_function()".to_string()]),
            (".ctors".to_string(), vec!["old_constructor()".to_string()]),
            // (The one with a priority first: the linker sorts them so.)
            (
                ".init_array".to_string(),
                vec!["first()".to_string(), "second()".to_string()]
            ),
            ("the entry point".to_string(), vec!["_start()".to_string()]),
        ]
    );
    let second = entry(&v, ".init_array", "second()");
    assert_eq!(
        callees("init-x86_64-linux-gnu", &second["node"]),
        ["prepare()"]
    );
    assert_eq!(second["file"], "./init-unix.c");
    assert_eq!(v["main"]["name"], "main()");
    // The library: no program's phases.
    let v = json("libinit-x86_64-linux-gnu.so", &[]);
    assert_eq!(v["library"], true);
    let names: Vec<String> = phases(&v).into_iter().map(|p| p.0).collect();
    assert_eq!(names, ["DT_INIT", ".ctors", ".init_array"]);
    assert!(v["main"].is_null());
}

#[test]
fn macho() {
    let v = json("init-arm64", &[]);
    assert_eq!(
        phases(&v),
        [
            (
                "__mod_init_func".to_string(),
                vec!["first()".to_string(), "second()".to_string()]
            ),
            ("the entry point".to_string(), vec!["main()".to_string()]),
        ]
    );
    // (main is the entry point itself: not again.)
    assert!(v["main"].is_null());
    let second = entry(&v, "__mod_init_func", "second()");
    assert_eq!(callees("init-arm64", &second["node"]), ["prepare()"]);
}

/// The text form: phases with what they're for, functions numbered where
/// a list has several, callees indented (each once: later, "(above)").
#[test]
fn text() {
    let image = testdata("init-x86_64-linux-gnu");
    let (code, out, _) = hexc(&[image.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("init-x86_64-linux-gnu: what runs before main\n"),
        "{out}"
    );
    assert!(out.contains("\n.init_array: the loader (or, in a static program, __libc_start_main) calls these in order, before main\n"), "{out}");
    assert!(out.contains("\n  1  first()  ./init-unix.c:25\n"), "{out}");
    assert!(
        out.contains(
            "\n  2  second()  ./init-unix.c:27\n       jumps to prepare()  ./init-unix.c:26\n"
        ),
        "{out}"
    );
    assert!(
        out.ends_with("\nThen the program's own code: main()  ./init-unix.c:35\n"),
        "{out}"
    );
    // -depth 0: no callees.
    let (_, out, _) = hexc(&["-depth", "0", image.to_str().unwrap()]);
    assert!(!out.contains("prepare()"), "{out}");
    // A library says what runs when it's loaded.
    let lib = testdata("initdll.dll");
    let (_, out, _) = hexc(&[lib.to_str().unwrap()]);
    assert!(
        out.starts_with("initdll.dll: what runs when it is loaded\n"),
        "{out}"
    );
    assert!(
        out.contains("Then the program's own code: DllMain("),
        "{out}"
    );
}

#[test]
fn bad_arguments() {
    for args in [
        &[][..],
        &["-nonesuch", "x"],
        &["-depth", "x", "y"],
        &["-callees", "1", "x"],
        &["a", "b"],
    ] {
        let (code, _, err) = hexc(args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains("usage: hexc init"), "{err}");
    }
    let image = testdata("init.exe");
    let (code, _, err) = hexc(&["-json", "-callees", "999999", image.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("no node 999999"), "{err}");
    let (code, _, err) = hexc(&["no-such-file.exe"]);
    assert_eq!(code, 1, "{err}");
}

/// A damaged image whose data sections claim far more than the file holds
/// (as fuzzing found): what's read stops at the file's end, so it ends
/// quickly rather than walking the claimed sizes a word at a time. One
/// image with relocations (its lists read through them), one without (its
/// data scanned for addresses).
#[test]
fn sections_larger_than_the_file() {
    for image in ["init/init-x86_64-linux-gnu", "elf/program-x86_64-linux-gnu"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(image);
        let mut data = std::fs::read(&path).unwrap();
        let u16_at = |d: &[u8], at: usize| usize::from(u16::from_le_bytes([d[at], d[at + 1]]));
        let shoff =
            usize::try_from(u64::from_le_bytes(data[0x28..0x30].try_into().unwrap())).unwrap();
        let (size, count) = (u16_at(&data, 0x3A), u16_at(&data, 0x3C));
        let mut damaged = 0;
        for i in 0..count {
            let h = shoff + i * size;
            let kind = u32::from_le_bytes(data[h + 4..h + 8].try_into().unwrap());
            let flags = u64::from_le_bytes(data[h + 8..h + 16].try_into().unwrap());
            // Allocated data (not code): PROGBITS and the loader's lists.
            if flags & 2 != 0 && flags & 4 == 0 && matches!(kind, 1 | 14 | 15 | 16) {
                data[h + 0x20..h + 0x28].copy_from_slice(&(1u64 << 40).to_le_bytes());
                damaged += 1;
            }
        }
        assert!(damaged > 0, "{image}");
        let dir = std::env::temp_dir().join(format!("hexc-init-damaged-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(path.file_name().unwrap());
        std::fs::write(&file, &data).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .args(["init", "-json", file.to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let finished = loop {
            if child.try_wait().unwrap().is_some() {
                break true;
            }
            if started.elapsed() > std::time::Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(finished, "{image}: hexc init still running after 20 s");
    }
}

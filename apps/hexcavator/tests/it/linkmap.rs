//! The Unix linkers' maps and logs (testdata/linkmap, from
//! tools/linkmap/build.cmd: ld.lld and ld64.lld): `size -map` attributes
//! an ELF or Mach-O image's bytes to the objects and libraries the map
//! names, and `linkerlog` says why each library member was loaded, what
//! was garbage-collected, and why symbols are live.

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkmap")
}

fn hexc(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A CSV report's rows: label to VM size.
fn rows(csv: &str) -> std::collections::HashMap<String, u64> {
    csv.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            Some((f.first()?.to_string(), f.get(1)?.parse().ok()?))
        })
        .collect()
}

#[test]
fn size_by_object_and_library() {
    let r = root();
    let elf = r.join("program-elf");
    let map = r.join("elf.map");
    let units = rows(&hexc(&[
        "size",
        "-d",
        "compileunits",
        "-n",
        "0",
        "-csv",
        "-map",
        map.to_str().unwrap(),
        elf.to_str().unwrap(),
    ]));
    // _start (0x22) and shared_table (0x40) from main.o; used_helper (0xa)
    // from lib.a's used.o.
    assert_eq!(units.get("main.o"), Some(&(0x22 + 0x40)), "{units:?}");
    assert_eq!(units.get("lib.a(used.o)"), Some(&0xa), "{units:?}");
    let libs = rows(&hexc(&[
        "size",
        "-d",
        "libraries",
        "-n",
        "0",
        "-csv",
        "-map",
        map.to_str().unwrap(),
        elf.to_str().unwrap(),
    ]));
    assert_eq!(libs.get("lib.a"), Some(&0xa), "{libs:?}");
    assert_eq!(libs.get("[no library]"), Some(&(0x22 + 0x40)), "{libs:?}");
    // Mach-O: ld64's map, by symbol and file.
    let macho = r.join("program-macho");
    let map = r.join("macho.map");
    let units = rows(&hexc(&[
        "size",
        "-d",
        "compileunits",
        "-n",
        "0",
        "-csv",
        "-map",
        map.to_str().unwrap(),
        macho.to_str().unwrap(),
    ]));
    assert_eq!(units.get("lib.a(used.o)"), Some(&0xc), "{units:?}");
    assert_eq!(units.get("main.o"), Some(&(0x2c + 0x40)), "{units:?}");
    // Not a map.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["size", "-d", "compileunits", "-map"])
        .arg(r.join("elf.why"))
        .arg(&elf)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn why_members_and_symbols() {
    let r = root();
    let why = hexc(&[
        "linkerlog",
        "-why",
        "lib.a(used.o)",
        r.join("elf.why").to_str().unwrap(),
    ]);
    assert!(
        why.contains("lib.a(used.o) was loaded for used_helper, referenced in main.o"),
        "{why}"
    );
    let log = hexc(&["linkerlog", r.join("elf.log").to_str().unwrap()]);
    assert!(
        log.contains("Sections removed as unused (garbage collected): 5"),
        "{log}"
    );
    assert!(log.contains("main.o:(.text.unused_here)"), "{log}");
    assert!(
        log.contains(
            "lib.a(used.o):(used_helper)\n    referenced by main.o:(_start) (entry point)"
        ),
        "{log}"
    );
    let macho = hexc(&["linkerlog", r.join("macho.log").to_str().unwrap()]);
    assert!(
        macho.contains("lib.a(used.o):(_used_helper)\n    referenced by main.o:(__start)"),
        "{macho}"
    );
    let json: serde_json::Value = serde_json::from_str(&hexc(&[
        "linkerlog",
        "-json",
        r.join("macho.log").to_str().unwrap(),
    ]))
    .unwrap();
    assert_eq!(json["live"].as_array().unwrap().len(), 2);
}

//! `hexc dwarf` against llvm-dwarfdump: `-info` on every fixture with
//! llvm-dwarfdump's output beside it (testdata/elf and testdata/types:
//! C and C++, DWARF 4 and 5, x86-64 and big-endian AArch64) is the same,
//! line for line. The one difference allowed: paths, which llvm-dwarfdump
//! joins with the separator of the machine it ran on (the fixtures'
//! output was made on Windows), are compared with `/`.
//!
//! (On .NET's coreclr, 14.5 million lines from its ELF debug file and 16.2
//! million from its Mach-O DWARF were the same too: an extended test.)
//!
//! Then the other sections and options, and damaged inputs: every one
//! ends, none panics.

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn hexc(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Lines to compare: trailing space dropped, `\` as `/`.
fn lines(text: &str) -> Vec<String> {
    text.trim()
        .lines()
        .map(|l| l.trim_end().replace('\\', "/"))
        .collect()
}

/// llvm-dwarfdump's `.debug_info` part.
fn debug_info(dump: &str) -> &str {
    let start = dump
        .find(".debug_info contents:")
        .expect("a .debug_info section");
    let rest = &dump[start..];
    let end = [
        ".debug_aranges contents:",
        ".debug_line contents:",
        ".debug_names contents:",
        ".debug_str contents:",
    ]
    .iter()
    .filter_map(|m| rest.find(m))
    .min()
    .unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn info_is_llvm_dwarfdumps() {
    let fixtures = [
        "testdata/elf/dwarf4-x86_64-linux-gnu",
        "testdata/elf/dwarf5-x86_64-linux-gnu",
        "testdata/elf/dwarf4-aarch64_be-linux-gnu",
        "testdata/elf/dwarf5-aarch64_be-linux-gnu",
        "testdata/types/types-x86_64-linux-gnu",
        "testdata/types/types-x86_64-linux-gnu-v2",
        "testdata/types/types-x86_64-linux-gnu-names",
        // DWARF in a WebAssembly module (rustc's): 32-bit addresses, code
        // section offsets, DW_OP_WASM_location, Rust's templates.
        "testdata/wasm/sample-dwarf.wasm",
    ];
    for f in fixtures {
        let path = root().join(f);
        let oracle = std::fs::read_to_string(format!("{}.dwarfdump.txt", path.display())).unwrap();
        let (ok, ours, err) = hexc(&["dwarf", "-info", path.to_str().unwrap()]);
        assert!(ok, "{f}: {err}");
        let (want, got) = (lines(debug_info(&oracle)), lines(&ours));
        for (i, (w, g)) in want.iter().zip(&got).enumerate() {
            assert_eq!(w, g, "{f}: line {}", i + 1);
        }
        assert_eq!(want.len(), got.len(), "{f}: line count");
    }
}

#[test]
fn every_section_and_option() {
    let f = root().join("testdata/elf/dwarf5-x86_64-linux-gnu");
    let f = f.to_str().unwrap();
    let (ok, out, err) = hexc(&["dwarf", f]);
    assert!(ok, "{err}");
    assert!(
        out.contains("2 units:") && out.contains("program.c") && out.contains("second.c"),
        "{out}"
    );
    let (ok, out, _) = hexc(&["dwarf", "-lines", f]);
    assert!(
        ok && out.contains("0x0000000000201210     15     23      0 is_stmt"),
        "{out}"
    );
    let (ok, out, _) = hexc(&["dwarf", "-aranges", f]);
    assert!(
        ok && out.contains("[0x0000000000201210, 0x0000000000201280)"),
        "{out}"
    );
    let (ok, out, _) = hexc(&["dwarf", "-abbrev", f]);
    assert!(
        ok && out.contains("[1] DW_TAG_compile_unit\tDW_CHILDREN_yes"),
        "{out}"
    );
    let (ok, out, _) = hexc(&["dwarf", "-str", f]);
    assert!(ok && out.contains("\"counter\""), "{out}");
    let (ok, out, _) = hexc(&["dwarf", "-find", "compute", f]);
    assert!(
        ok && out.contains("DW_AT_name\t(\"compute\")") && !out.contains("optional_hook"),
        "{out}"
    );
    let (ok, out, _) = hexc(&["dwarf", "-lookup", "0x201245", f]);
    assert!(
        ok && out.contains("DW_TAG_inlined_subroutine helper") && out.contains("program.c:11:37"),
        "{out}"
    );
    let unwind = root().join("testdata/elf/unwind-x86_64-linux-gnu");
    let (ok, out, _) = hexc(&["dwarf", "-frames", unwind.to_str().unwrap()]);
    assert!(ok && out.contains("CFA=RSP+8: RIP=[CFA-8]"), "{out}");
    let (ok, out, _) = hexc(&["dwarf", "-all", f]);
    assert!(ok && out.contains(".debug_info contents:") && out.contains(".debug_line contents:"));
    // A Mach-O image's DWARF, found beside it.
    let mach = root().join("testdata/macho/program-arm64");
    let (ok, out, err) = hexc(&["dwarf", mach.to_str().unwrap()]);
    assert!(ok && out.contains("program-arm64.dwarf"), "{out}{err}");
    // Not DWARF.
    let pe = root().join("testdata/xref/xref-x64.exe");
    let (ok, _, err) = hexc(&["dwarf", pe.to_str().unwrap()]);
    assert!(!ok && err.contains("PDB"), "{err}");
    let (ok, _, _) = hexc(&["dwarf", "-nonsense", f]);
    assert!(!ok);
}

/// Damaged DWARF: each truncation of a fixture, and a byte changed every
/// few: every dump ends, and none panics.
#[test]
fn damaged_inputs_end() {
    let data = std::fs::read(root().join("testdata/elf/dwarf5-x86_64-linux-gnu")).unwrap();
    let dir = std::env::temp_dir().join(format!("hexc-dwarf-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("damaged");
    let p = path.to_str().unwrap();
    let mut cases: Vec<Vec<u8>> = (0..data.len())
        .step_by(97)
        .map(|n| data[..n].to_vec())
        .collect();
    for at in (64..data.len()).step_by(37) {
        let mut d = data.clone();
        d[at] ^= 0xA5;
        cases.push(d);
    }
    for d in cases {
        std::fs::write(&path, &d).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .args(["dwarf", "-all", p])
            .output()
            .unwrap();
        // (Exit code 101 is a panic.)
        assert_ne!(
            out.status.code(),
            Some(101),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// DWARF in a WebAssembly module serves every command that reads debug
/// information: its source files, inlined functions, and types.
#[test]
fn wasm_dwarf_serves_the_other_commands() {
    let f = root().join("testdata/wasm/sample-dwarf.wasm");
    let f = f.to_str().unwrap();
    let (ok, out, err) = hexc(&["sourcefiles", "-n", "0", f]);
    assert!(ok, "{err}");
    assert!(
        out.contains("sample.rs") && out.contains("bytes of code"),
        "{out}"
    );
    let (ok, out, err) = hexc(&["inlines", "-n", "0", f]);
    assert!(ok, "{err}");
    assert!(out.contains("inline sites"), "{out}");
    let (ok, out, err) = hexc(&["types", "-n", "0", f]);
    assert!(ok, "{err}");
    assert!(out.contains("types;"), "{out}");
    // Cross-references: calls between functions, exports as roots.
    let (ok, out, err) = hexc(&["xref", f]);
    assert!(ok && out.contains("roots"), "{out}{err}");
    let (ok, out, err) = hexc(&["xref", "-why", "sample::sum", f]);
    assert!(ok && out.contains("exported as sum"), "{out}{err}");
    // Recommendations: the custom sections it needn't ship, measured.
    let (ok, out, err) = hexc(&["recommend", f]);
    assert!(
        ok && out.contains("strip its custom sections") && out.contains(".debug_info"),
        "{out}{err}"
    );
    let (ok, out, _) = hexc(&["info", "-json", f]);
    assert!(
        ok && out.contains("\"kind\":\"dwarf\"") && out.contains("\"sourcefiles\""),
        "{out}"
    );
}

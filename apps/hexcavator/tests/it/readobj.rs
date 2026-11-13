//! `hexc dump` of ELF, Mach-O, and WebAssembly files against
//! llvm-readobj's output beside the fixtures (testdata/elf, macho, wasm):
//! the same, line for line, with the options each was made with. (On
//! .NET's coreclr, libcoreclr.so's 15,412 lines with every ELF part and
//! libcoreclr.dylib's 180,166 with every Mach-O part were the same too.)
//!
//! Then damaged inputs: every dump ends, and none panics.

use std::path::{Path, PathBuf};
use std::process::Command;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// hexc's dump of `name` in `dir` (named as llvm-readobj was given it).
fn dump(dir: &Path, name: &str, options: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("dump")
        .args(options)
        .arg(name)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn same(oracle: &Path, ours: &str) {
    let theirs = std::fs::read_to_string(oracle).unwrap();
    let a: Vec<&str> = theirs.trim().lines().map(str::trim_end).collect();
    let b: Vec<&str> = ours.trim().lines().map(str::trim_end).collect();
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{}: line {}", oracle.display(), i + 1);
    }
    assert_eq!(a.len(), b.len(), "{}: line count", oracle.display());
}

/// Every `*<suffix>` oracle in `dir`, dumped with `options`.
fn each(dir: &str, suffix: &str, options: &[&str], skip: &[&str]) -> usize {
    let dir = testdata().join(dir);
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(file) = name.strip_suffix(suffix) else {
            continue;
        };
        if skip.iter().any(|s| name.contains(s)) {
            continue;
        }
        same(&path, &dump(&dir, file, options));
        n += 1;
    }
    n
}

#[test]
fn elf_is_llvm_readobjs() {
    let all = [
        "--file-headers",
        "--sections",
        "--program-headers",
        "--symbols",
        "--dyn-symbols",
        "--notes",
    ];
    let n = each("elf", ".readobj.txt", &all, &["relr"]);
    assert!(n >= 12, "{n}");
    for name in ["relr.so", "relr-rela.so"] {
        let dir = testdata().join("elf");
        same(
            &dir.join(format!("{name}.readobj.txt")),
            &dump(&dir, name, &["--dynamic-table", "--relocations"]),
        );
    }
    for name in ["relr-android.so", "relr-android-rela.so"] {
        let dir = testdata().join("elf");
        same(
            &dir.join(format!("{name}.readobj.txt")),
            &dump(&dir, name, &["--relocations"]),
        );
    }
    assert_eq!(each("elf", ".relocs.txt", &["--relocations"], &[]), 3);
}

#[test]
fn macho_is_llvm_readobjs() {
    let n = each(
        "macho",
        ".readobj.txt",
        &[
            "--file-headers",
            "--sections",
            "--symbols",
            "--macho-segment",
            "--macho-dysymtab",
            "--macho-version-min",
        ],
        &[],
    );
    assert_eq!(n, 5);
}

#[test]
fn wasm_is_llvm_readobjs() {
    assert_eq!(
        each(
            "wasm",
            ".readobj.txt",
            &["--sections", "--symbols"],
            &["sample.o"]
        ),
        1
    );
    // An object (rustc's, tools/wasm/build.cmd): its linking section's
    // symbol table, its segments' names, and its reloc.CODE relocations.
    let dir = testdata().join("wasm");
    same(
        &dir.join("sample.o.readobj.txt"),
        &dump(
            &dir,
            "sample.o",
            &["--file-headers", "--sections", "--relocations", "--symbols"],
        ),
    );
}

/// The dumpbin-style names choose the usual parts.
#[test]
fn dumpbin_names_choose_parts() {
    let dir = testdata().join("elf");
    let headers = dump(&dir, "program.so", &["-headers"]);
    assert!(
        headers.contains("ElfHeader {")
            && headers.contains("Sections [")
            && headers.contains("ProgramHeaders [")
    );
    let all = dump(&dir, "program.so", &["-all"]);
    for part in [
        "DynamicSection [",
        "Relocations [",
        "Symbols [",
        "DynamicSymbols [",
        "NoteSections [",
    ] {
        assert!(all.contains(part), "{part}");
    }
    // The default: the file header and sections.
    let plain = dump(&dir, "program.so", &[]);
    assert!(
        plain.contains("ElfHeader {")
            && plain.contains("Sections [")
            && !plain.contains("Symbols [")
    );
    // An archive: each member.
    let ar = dump(&dir, "program.a", &["--file-headers"]);
    assert!(
        ar.contains("File: program.a(program-x86_64-linux-gnu.o)"),
        "{ar}"
    );
}

#[test]
fn damaged_inputs_end() {
    let dir = std::env::temp_dir().join(format!("hexc-readobj-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (sub, name) in [
        ("elf", "program.so"),
        ("macho", "program-arm64"),
        ("wasm", "module.wasm"),
        ("macho", "program-universal"),
    ] {
        let data = std::fs::read(testdata().join(sub).join(name)).unwrap();
        let path = dir.join("damaged");
        let step = (data.len() / 40).max(1);
        let mut cases: Vec<Vec<u8>> = (0..data.len())
            .step_by(step)
            .map(|n| data[..n].to_vec())
            .collect();
        for at in (0..data.len()).step_by(step) {
            let mut d = data.clone();
            d[at] ^= 0xA5;
            cases.push(d);
        }
        for d in cases {
            std::fs::write(&path, &d).unwrap();
            let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
                .args(["dump", "-all"])
                .arg(&path)
                .output()
                .unwrap();
            assert_ne!(
                out.status.code(),
                Some(101),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

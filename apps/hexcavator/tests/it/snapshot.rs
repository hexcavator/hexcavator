//! Compares `hexc dump` with a committed `dumpbin` snapshot, so that the
//! PE structure dumps are checked on every host, not only where Visual
//! Studio is installed.
//!
//! To refresh the snapshot (Windows, with Visual Studio):
//!
//!     dumpbin /nologo /nopdb /headers /exports /imports /loadconfig /relocations /unwindinfo
//!         crates\pdb\tests\data\test-x64.exe > crates\hexcavator\tests\data\test-x64.dumpbin.txt

use std::path::Path;
use std::process::Command;

use crate::common::normalize;

#[test]
fn dump_matches_dumpbin_snapshot() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../../crates/symbols/pdb/tests/data/test-x64.exe");
    let expected = std::fs::read_to_string(root.join("tests/data/test-x64.dumpbin.txt")).unwrap();
    let actual = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "dump",
            "-nopdb",
            "-headers",
            "-exports",
            "-imports",
            "-loadconfig",
            "-relocations",
            "-unwindinfo",
        ])
        .arg(&image)
        .output()
        .unwrap();
    assert!(actual.status.success());
    let expected = normalize(&expected);
    let actual = normalize(&String::from_utf8(actual.stdout).unwrap());
    for (i, (e, a)) in expected.iter().zip(&actual).enumerate() {
        assert_eq!(e, a, "line {}", i + 1);
    }
    assert_eq!(expected.len(), actual.len());
}

/// `/disasm` with the image's PDB beside it: function labels, symbolic
/// operands, and linker padding shown as data. To refresh (with the
/// image and PDB copied together somewhere):
///
///     dumpbin /nologo /disasm test-x64.exe > crates\hexcavator\tests\data\test-x64.disasm.txt
#[test]
fn disasm_with_pdb_matches_dumpbin_snapshot() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../../crates/symbols/pdb/tests/data/test-x64.exe");
    let expected = std::fs::read_to_string(root.join("tests/data/test-x64.disasm.txt")).unwrap();
    let actual = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["dump", "-disasm"])
        .arg(&image)
        .output()
        .unwrap();
    assert!(actual.status.success());
    let expected = normalize(&expected);
    let actual = normalize(&String::from_utf8(actual.stdout).unwrap());
    for (i, (e, a)) in expected.iter().zip(&actual).enumerate() {
        assert_eq!(e, a, "line {}", i + 1);
    }
    assert_eq!(expected.len(), actual.len());
}

/// `/unwindinfo` with the image's PDB: function and handler names, and the
/// handler data (C++ EH tables, SEH scopes, GS cookies). To refresh:
///
///     dumpbin /nologo /unwindinfo crates\pdb\tests\data\test-x64.exe > crates\hexcavator\tests\data\test-x64.unwind.txt
#[test]
fn unwind_with_pdb_matches_dumpbin_snapshot() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let image = root.join("../../crates/symbols/pdb/tests/data/test-x64.exe");
    let expected = std::fs::read_to_string(root.join("tests/data/test-x64.unwind.txt")).unwrap();
    let actual = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["dump", "-unwindinfo"])
        .arg(&image)
        .output()
        .unwrap();
    assert!(actual.status.success());
    let expected = normalize(&expected);
    let actual = normalize(&String::from_utf8(actual.stdout).unwrap());
    for (i, (e, a)) in expected.iter().zip(&actual).enumerate() {
        assert_eq!(e, a, "line {}", i + 1);
    }
    assert_eq!(expected.len(), actual.len());
}

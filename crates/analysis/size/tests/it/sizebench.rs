//! The size model against SizeBench, over SizeBench's own test binaries:
//! `testdata/sizebench/oracle` holds what SizeBench's engine reports for
//! each binary in `testdata/sizebench/bin` (see `tools/sizebench-oracle`).

use std::collections::BTreeSet;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::pe::{self, Unsupported};
use hexcavator_size::report;

fn root() -> String {
    format!("{}/../../../testdata/sizebench", env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn image_path(name: &str) -> String {
    let dir = format!("{}/bin", root());
    ["dll", "exe"]
        .iter()
        .map(|ext| format!("{dir}/{name}.{ext}"))
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or_else(|| panic!("{name}: no image"))
}

/// The binaries SizeBench analyzed.
fn oracle_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(format!("{}/oracle", root()))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .map(|p| p.file_stem().unwrap().to_str().unwrap().to_string())
        .collect();
    names.sort();
    assert!(names.len() >= 20);
    names
}

/// The line kinds the model covers so far.
const KINDS: &[&str] = &[
    "SECTION",
    "COFFGROUP",
    "LIB",
    "LIBSECTION",
    "LIBCOFFGROUP",
    "COMPILAND",
    "COMPILANDSECTION",
    "COMPILANDCOFFGROUP",
    "RANGE",
];

fn kind_of(line: &str) -> &str {
    line.split(' ').next().unwrap()
}

/// Compares our lines for `name` with SizeBench's; returns a description
/// of the differences.
fn compare(name: &str) -> Option<String> {
    let image_data = read(&image_path(name));
    let pdb_data = read(&format!("{}/bin/{name}.pdb", root()));
    let image = Image::parse(&image_data).unwrap();
    let debug = DebugInfo::parse(&pdb_data).unwrap();
    pe::check(&image, &debug).unwrap();
    let model = pe::model(&image, &debug).unwrap();
    let ours: BTreeSet<String> = report::sizebench_lines(&model).into_iter().collect();
    let text = std::fs::read_to_string(format!("{}/oracle/{name}.txt", root())).unwrap();
    let theirs: BTreeSet<String> = text
        .lines()
        .filter(|l| KINDS.contains(&kind_of(l)))
        .map(str::to_string)
        .collect();
    if ours == theirs {
        return None;
    }
    let mut out = format!("{name}:\n");
    for l in theirs.difference(&ours).take(15) {
        out += &format!("  - {l}\n");
    }
    for l in ours.difference(&theirs).take(15) {
        out += &format!("  + {l}\n");
    }
    let missing = theirs.difference(&ours).count();
    let extra = ours.difference(&theirs).count();
    out += &format!("  ({missing} missing, {extra} extra)\n");
    Some(out)
}

#[test]
fn matches_sizebench() {
    let failures: Vec<String> = oracle_names().iter().filter_map(|n| compare(n)).collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn rejects_what_sizebench_rejects() {
    let check = |name: &str| {
        let image_data = read(&image_path(name));
        let pdb_data = read(&format!("{}/bin/{name}.pdb", root()));
        let image = Image::parse(&image_data).unwrap();
        let debug = DebugInfo::parse(&pdb_data).unwrap();
        pe::check(&image, &debug)
    };
    assert_eq!(
        check("SizeBenchV2.AnalysisEngine.Tests.Dllx64Managed"),
        Err(Unsupported::Managed)
    );
    assert_eq!(
        check("SizeBenchV2.AnalysisEngine.Tests.Dllx64MinimalPDB"),
        Err(Unsupported::MinimalPdb)
    );
    // An image with another binary's PDB.
    let image_data = read(&image_path("PEParser.Tests.Dllx64"));
    let pdb_data = read(&format!("{}/bin/PEParser.Tests.Dllx86.pdb", root()));
    let image = Image::parse(&image_data).unwrap();
    let debug = DebugInfo::parse(&pdb_data).unwrap();
    assert_eq!(pe::check(&image, &debug), Err(Unsupported::PdbMismatch));
}

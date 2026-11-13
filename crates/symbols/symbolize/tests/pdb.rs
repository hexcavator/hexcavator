//! Function tables and PDB discovery, on a PDB in testdata.

use std::path::Path;

use hexcavator_pdb::Pdb;
use hexcavator_symbolize::{FunctionTable, SymbolPath, symbol_store_key};

fn testdata() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/lines")
}

#[test]
fn reads_functions() {
    let data = std::fs::read(testdata().join("lines.pdb")).unwrap();
    let table = FunctionTable::from_pdb(&data).unwrap();
    assert!(table.len() > 10);
    let functions: Vec<(u32, u32, &str)> = table.iter().collect();
    assert!(
        functions.windows(2).all(|w| w[0].1 <= w[1].0),
        "sorted, not overlapping"
    );
    assert!(functions.iter().all(|f| f.0 < f.1), "non-empty");
    let &(main, end, _) = functions
        .iter()
        .find(|f| f.2 == "main")
        .expect("lines.pdb has main");
    assert_eq!(table.function(main).map(|f| f.0), Some(main));
    assert_eq!(table.function(end - 1).map(|f| f.0), Some(main));
    assert_ne!(table.function(end).map(|f| f.0), Some(main));
}

#[test]
fn finds_a_pdb_by_identity() {
    let dir = testdata();
    let data = std::fs::read(dir.join("lines.pdb")).unwrap();
    let pdb = Pdb::parse(&data).unwrap();
    let (guid, age) = (pdb.info().guid(), pdb.info().age());
    let path = SymbolPath {
        dirs: vec![dir.clone()],
    };
    // Recorded at a path that no longer exists: found in the directory.
    let found = path.find_pdb(r"Z:\gone\lines.pdb", &guid, age).unwrap();
    assert_eq!(found, dir.join("lines.pdb"));
    // A different GUID, or a newer age than the file's, is not a match.
    let mut other = guid;
    other[0] ^= 1;
    assert_eq!(path.find_pdb(r"Z:\gone\lines.pdb", &other, age), None);
    assert_eq!(path.find_pdb(r"Z:\gone\lines.pdb", &guid, age + 1), None);
    // The symbol store layout.
    assert!(symbol_store_key(&guid, age).len() >= 33);
}

#[test]
fn garbage_is_an_error() {
    assert!(FunctionTable::from_pdb(&[]).is_err());
    assert!(FunctionTable::from_pdb(&[0u8; 4096]).is_err());
    let data = std::fs::read(testdata().join("lines.pdb")).unwrap();
    for len in (0..data.len()).step_by(97) {
        let _ = FunctionTable::from_pdb(&data[..len]);
    }
}

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

/// Every lookup a subset is made for: function, its start, inlines (with
/// their names) and line.
type Answers = (
    Option<(u32, String)>,
    Option<(u32, String)>,
    Vec<String>,
    Option<(String, u32)>,
);

fn answers(t: &FunctionTable, rva: u32) -> Answers {
    let f = t.function(rva).map(|(s, n)| (s, n.to_string()));
    let start = f
        .as_ref()
        .and_then(|(s, _)| t.function(*s))
        .map(|(s, n)| (s, n.to_string()));
    let inlines = t
        .inlines(rva)
        .into_iter()
        .map(|(site, name)| {
            assert_eq!(t.site_name(site), Some(name));
            name.to_string()
        })
        .collect();
    let line = t.line(rva).map(|(f, l)| (f.to_string(), l));
    (f, start, inlines, line)
}

#[test]
fn a_subset_answers_as_the_whole_table_does() {
    let data = std::fs::read(testdata().join("lines.pdb")).unwrap();
    let table = FunctionTable::from_pdb(&data).unwrap();
    let last = table.iter().last().unwrap().0.saturating_add(4096);
    // Every few addresses, and every function's first and last bytes and
    // the byte after.
    let mut rvas: Vec<u32> = (0..last).step_by(37).collect();
    for (s, e, _) in table.iter() {
        rvas.extend([s, e - 1, e.saturating_add(1) - 1]);
    }
    for pick in [
        rvas.clone(),
        rvas.iter().copied().step_by(5).collect(),
        vec![],
        vec![u32::MAX],
    ] {
        let sub = table.subset(&pick);
        assert!(sub.len() <= table.len());
        for &rva in &pick {
            assert_eq!(answers(&sub, rva), answers(&table, rva), "{rva:#x}");
        }
        // A subset of itself is itself, and it saves and reads back.
        assert_eq!(sub.subset(&pick), sub);
        assert_eq!(FunctionTable::from_bytes(&sub.to_bytes()).unwrap(), sub);
    }
    // A few addresses keep few functions.
    let main = table.iter().find(|f| f.2 == "main").unwrap().0;
    let one = table.subset(&[main]);
    assert_eq!(one.len(), 1);
    assert_eq!(one.function(main).map(|f| f.1), Some("main"));
    assert!(one.to_bytes().len() < 1000);
    assert!(table.iter().any(|f| f.0 > main), "a later function to miss");
}

#[test]
fn the_whole_table_saves_and_reads_back() {
    let data = std::fs::read(testdata().join("lines.pdb")).unwrap();
    let table = FunctionTable::from_pdb(&data).unwrap();
    let bytes = table.to_bytes();
    assert_eq!(FunctionTable::from_bytes(&bytes).unwrap(), table);
    assert_eq!(
        FunctionTable::from_bytes(&FunctionTable::default().to_bytes()).unwrap(),
        FunctionTable::default()
    );
}

#[test]
fn a_damaged_saved_table_is_an_error() {
    let data = std::fs::read(testdata().join("lines.pdb")).unwrap();
    let table = FunctionTable::from_pdb(&data).unwrap();
    let bytes = table.to_bytes();
    assert!(FunctionTable::from_bytes(&[]).is_err());
    assert!(
        FunctionTable::from_bytes(b"HXFT\x02\0\0\0").is_err(),
        "a later version"
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(FunctionTable::from_bytes(&extra).is_err(), "trailing bytes");
    // Every truncation is an error; any damage is an error or a table, and
    // never a panic.
    for len in 0..bytes.len() {
        assert!(FunctionTable::from_bytes(&bytes[..len]).is_err(), "{len}");
    }
    for i in (0..bytes.len()).step_by(7) {
        for flip in [0x01, 0x80, 0xff] {
            let mut b = bytes.clone();
            b[i] ^= flip;
            if let Ok(t) = FunctionTable::from_bytes(&b) {
                for (s, e, _) in t.iter() {
                    let _ = answers(&t, s);
                    let _ = answers(&t, e.wrapping_sub(1));
                }
            }
        }
    }
}

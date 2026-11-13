//! Programs kept in memory: opened again, the same model and symbols (not
//! built again); with their files changed, built again.

use std::path::{Path, PathBuf};

use hexcavator_program::{Opened, cache};

fn bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/sizebench/bin")
        .join(name)
}

/// Where `path`'s program's symbols and model are; and its symbols' names.
fn built(path: &Path, pdb: &Path) -> (usize, usize, Vec<String>) {
    let o = Opened::open(path, Some(pdb)).unwrap();
    let p = o.program().unwrap();
    let s = p.symbols().unwrap();
    let m: *const _ = p.model().unwrap();
    let names = s.iter().map(|s| s.name.clone()).collect();
    (s.as_ptr() as usize, m as usize, names)
}

#[test]
fn kept_until_the_files_change() {
    let dir = std::env::temp_dir().join(format!("hexc-kept-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (image, pdb) = (dir.join("app.dll"), dir.join("app.pdb"));
    let put = |which: &str| {
        std::fs::copy(
            bin(&format!("CppTestCases_BasicDiffObjects{which}.dll")),
            &image,
        )
        .unwrap();
        std::fs::copy(
            bin(&format!("CppTestCases_BasicDiffObjects{which}.pdb")),
            &pdb,
        )
        .unwrap();
    };
    put("Before");

    // Not kept unless asked.
    let a = built(&image, &pdb);
    let b = built(&image, &pdb);
    assert_eq!(a.2, b.2);

    cache::keep_in_memory(true);
    let first = built(&image, &pdb);
    let again = built(&image, &pdb);
    assert_eq!(first, again);

    // Rebuilt: read again.
    put("After");
    let changed = built(&image, &pdb);
    assert_ne!(changed.2, first.2);
    assert_eq!(built(&image, &pdb), changed);

    // Off: forgotten.
    cache::keep_in_memory(false);
    let off = built(&image, &pdb);
    assert_eq!(off.2, changed.2);
    std::fs::remove_dir_all(&dir).unwrap();
}

//! `DebugInfo` over SizeBench's test PDBs (in `testdata`), cross-checked
//! against SizeBench's own analysis of them, and over malformed input.

use std::collections::BTreeSet;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;

fn root() -> String {
    format!("{}/../../../testdata/sizebench", env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every test binary with a PDB: (name, image file, PDB file).
fn binaries() -> Vec<(String, String, String)> {
    let dir = format!("{}/bin", root());
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "pdb") {
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            for ext in ["dll", "exe"] {
                let image = format!("{dir}/{stem}.{ext}");
                if std::path::Path::new(&image).exists() {
                    out.push((stem.clone(), image, path.to_str().unwrap().to_string()));
                }
            }
        }
    }
    out.sort();
    assert!(out.len() >= 20, "test binaries missing from {dir}");
    out
}

/// Lines of SizeBench's output for `name` starting with `kind `.
fn oracle(name: &str, kind: &str) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(format!("{}/oracle/{name}.txt", root())).ok()?;
    let prefix = format!("{kind} ");
    Some(
        text.lines()
            .filter_map(|l| l.strip_prefix(&prefix))
            .map(str::to_string)
            .collect(),
    )
}

#[test]
fn every_image_matches_its_pdb_and_no_other() {
    let all = binaries();
    let pdbs: Vec<Vec<u8>> = all.iter().map(|(_, _, p)| read(p)).collect();
    for (i, (name, image_path, _)) in all.iter().enumerate() {
        let data = read(image_path);
        let image = Image::parse(&data).unwrap();
        let ids = image.debug_ids();
        assert!(!ids.is_empty(), "{name}: no debug id");
        for (j, pdb) in pdbs.iter().enumerate() {
            let info = DebugInfo::parse(pdb).unwrap();
            let matched = ids.iter().any(|id| info.matches(id));
            // The before/after diff pairs are distinct builds.
            assert_eq!(matched, i == j, "{name} vs {}", all[j].0);
        }
    }
}

#[test]
fn compilands_and_groups_agree_with_sizebench() {
    let mut checked = 0;
    for (name, _, pdb_path) in binaries() {
        let Some(oracle_compilands) = oracle(&name, "COMPILAND") else {
            continue;
        };
        let data = read(&pdb_path);
        let info = DebugInfo::parse(&data).unwrap();
        let compilands = info.compilands().unwrap();
        // SizeBench lists the compilands that contribute to a COFF group, as
        // "<library> | <name> size=..."; an empty library or name is shown
        // as "...no name found...".
        let ours: BTreeSet<String> = compilands
            .iter()
            .map(|c| {
                let shown = |s: &str| {
                    if s.is_empty() {
                        "...no name found...".to_string()
                    } else {
                        s.to_string()
                    }
                };
                format!("{} | {}", shown(&c.library), shown(&c.name)).to_lowercase()
            })
            .collect();
        for line in &oracle_compilands {
            let id = line.rsplit_once(" size=").unwrap().0.to_lowercase();
            assert!(
                ours.contains(&id),
                "{name}: SizeBench compiland {id} not found"
            );
        }

        // Every contribution names a real compiland.
        let contributions = info.contributions().unwrap();
        assert!(!contributions.is_empty(), "{name}");
        for c in &contributions {
            assert!((c.compiland as usize) < compilands.len(), "{name}: {c:?}");
        }
        assert!(contributions.windows(2).all(|w| w[0].addr <= w[1].addr));

        // SizeBench's COFF groups are ours (the non-empty ones), plus some
        // it synthesizes; names it had to make unique get a suffix.
        let groups = info.groups().unwrap();
        assert!(groups.windows(2).all(|w| w[0].addr <= w[1].addr));
        let ours: BTreeSet<(String, u64)> = groups
            .iter()
            .filter(|g| g.size > 0)
            .map(|g| (g.name.clone(), g.addr))
            .collect();
        for line in oracle(&name, "COFFGROUP").unwrap() {
            // "<section> <group> rva=<hex> ..."
            let mut words = line.split(' ');
            let _section = words.next();
            let group = words.next().unwrap();
            let rva = u64::from_str_radix(words.next().unwrap().strip_prefix("rva=").unwrap(), 16)
                .unwrap();
            if group.starts_with(".sizebench-synthesized")
                || group.contains(" (")
                || group.ends_with("<all>")
            {
                continue;
            }
            assert!(
                ours.contains(&(group.to_string(), rva)),
                "{name}: group {group} at {rva:x}"
            );
        }
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} binaries had oracle data");
}

#[test]
fn linker_info() {
    for (name, _, pdb_path) in binaries() {
        let data = read(&pdb_path);
        let info = DebugInfo::parse(&data).unwrap();
        let linker = info.linker_info().unwrap();
        if name.ends_with("Dllx64MinimalPDB") {
            assert!(linker.minimal, "{name}");
        } else if name.ends_with("Dllx64Managed") {
            // A managed image's PDB has no modules, so no linker module.
            assert!(info.compilands().unwrap().is_empty(), "{name}");
            assert!(linker.environment.is_empty(), "{name}");
            assert!(!linker.minimal, "{name}");
        } else {
            assert!(!linker.minimal, "{name}");
            // Every full PDB here records how the linker was run (SizeBench
            // rejects PDBs that don't).
            let cmd = linker
                .command_line()
                .unwrap_or_else(|| panic!("{name}: no command line"));
            assert!(!cmd.is_empty(), "{name}");
            assert!(linker.get("exe").is_some(), "{name}");
        }
    }
}

#[test]
fn rejects_non_pdbs_without_panicking() {
    assert!(DebugInfo::parse(b"").is_err());
    assert!(DebugInfo::parse(b"MZ\x90\0").is_err());
    assert!(DebugInfo::parse(b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0").is_err());
    assert!(DebugInfo::parse(&[0xFF; 4096]).is_err());
}

#[test]
fn truncated_and_corrupted_pdbs_do_not_panic() {
    let (_, _, pdb_path) = binaries()
        .into_iter()
        .find(|(n, _, _)| n == "PEParser.Tests.Dllx64")
        .unwrap();
    let data = read(&pdb_path);
    let exercise = |bytes: &[u8]| {
        if let Ok(info) = DebugInfo::parse(bytes) {
            let _ = info.compilands();
            let _ = info.contributions();
            let _ = info.groups();
            let _ = info.linker_info();
        }
    };
    // Truncated at a range of lengths, including mid-directory.
    for len in (0..data.len()).step_by(data.len() / 97 + 1) {
        exercise(&data[..len]);
    }
    // Corrupt a spread of bytes, including the superblock and the stream
    // directory (the first few blocks).
    let mut copy = data.clone();
    let positions: Vec<usize> = (0..0x2000)
        .step_by(7)
        .chain((0..data.len()).step_by(4093))
        .collect();
    for &i in &positions {
        if i >= copy.len() {
            continue;
        }
        let original = copy[i];
        for value in [0x00, 0xFF, original ^ 0x55] {
            copy[i] = value;
            exercise(&copy);
        }
        copy[i] = original;
    }
}

#[test]
fn candidate_paths() {
    use hexcavator_debuginfo::candidate_paths;
    use hexcavator_image::DebugId;
    use std::path::{Path, PathBuf};
    let id = |path: &'static [u8]| DebugId::Pdb {
        guid: [0; 16],
        age: 1,
        path,
    };
    let image = Path::new("out/bin/app.exe");
    assert_eq!(
        candidate_paths(image, &id(br"D:\build\obj\app.pdb")),
        [
            PathBuf::from(r"D:\build\obj\app.pdb"),
            Path::new("out/bin").join("app.pdb")
        ]
    );
    assert_eq!(
        candidate_paths(image, &id(b"/home/me/build/app.pdb")),
        [
            PathBuf::from("/home/me/build/app.pdb"),
            Path::new("out/bin").join("app.pdb")
        ]
    );
    // A bare file name: it is both the recorded path (relative to the
    // current directory) and a name to look for beside the image.
    assert_eq!(
        candidate_paths(image, &id(b"app.pdb")),
        [
            PathBuf::from("app.pdb"),
            Path::new("out/bin").join("app.pdb")
        ]
    );
    // Beside an image given without a directory is the same as the
    // recorded name, so it appears once.
    assert_eq!(
        candidate_paths(Path::new("app.exe"), &id(b"app.pdb")),
        [PathBuf::from("app.pdb")]
    );
    assert!(candidate_paths(image, &id(b"")).is_empty());
    assert_eq!(
        candidate_paths(image, &id(br"C:\dir\")),
        [PathBuf::from(r"C:\dir\")]
    );
}

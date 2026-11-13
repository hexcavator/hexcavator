//! Opening a program built with split DWARF (testdata/elf, from
//! tools/elf/split.cmd) finds its `.dwp` package, or else its `.dwo` files,
//! and reads as the same program built without it.

use std::path::{Path, PathBuf};

use hexcavator_program::Opened;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/elf")
        .join(name)
}

/// A directory of its own for a test, emptied.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("hexcavator-program-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What a program's symbols and compilands are, by name and address.
fn account(o: &Opened) -> Vec<String> {
    let p = o.program().unwrap();
    let mut out: Vec<String> = p
        .debug
        .compilands()
        .unwrap()
        .into_iter()
        .map(|c| format!("compiland {}", c.name))
        .collect();
    for s in p.symbols().unwrap() {
        out.push(format!("{} {:#x} {:?}", s.name, s.addr, s.size));
    }
    out
}

fn names(o: &Opened) -> Vec<String> {
    o.split_paths()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn split_files_are_found() {
    for v in [4, 5] {
        let plain = Opened::open(&testdata(&format!("split-dwarf{v}-plain")), None).unwrap();
        let want = account(&plain);
        assert!(want.iter().any(|l| l == "compiland program.c"), "{want:?}");

        // Beside the image: its package.
        let o = Opened::open(&testdata(&format!("split-dwarf{v}")), None).unwrap();
        assert_eq!(names(&o), [format!("split-dwarf{v}.dwp")]);
        assert_eq!(account(&o), want);

        // Without one: the .dwo files, by the compilation directory (.)
        // relative to the image's.
        let dir = scratch(&format!("dwo{v}"));
        let image = dir.join("app");
        std::fs::copy(testdata(&format!("split-dwarf{v}")), &image).unwrap();
        for s in ["program", "second"] {
            let n = format!("sd{v}-{s}.dwo");
            std::fs::copy(testdata(&n), dir.join(&n)).unwrap();
        }
        let o = Opened::open(&image, None).unwrap();
        assert_eq!(
            names(&o),
            [format!("sd{v}-program.dwo"), format!("sd{v}-second.dwo")]
        );
        assert_eq!(account(&o), want);

        // One missing: its compiland is its skeleton (named by its file).
        // (Mapped files can't be removed, on Windows.)
        drop(o);
        std::fs::remove_file(dir.join(format!("sd{v}-second.dwo"))).unwrap();
        let o = Opened::open(&image, None).unwrap();
        assert_eq!(names(&o), [format!("sd{v}-program.dwo")]);
        let got = account(&o);
        assert!(
            got.contains(&format!("compiland sd{v}-second.dwo")),
            "{got:?}"
        );
        assert!(got.contains(&"compiland program.c".to_string()), "{got:?}");

        // A package by the image's name wins.
        std::fs::copy(
            testdata(&format!("split-dwarf{v}.dwp")),
            dir.join("app.dwp"),
        )
        .unwrap();
        let o = Opened::open(&image, None).unwrap();
        assert_eq!(names(&o), ["app.dwp"]);
        assert_eq!(account(&o), want);
        drop(o);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn where_split_files_are_looked_for() {
    use hexcavator_debuginfo::dwarf_backend::{SplitFile, package_paths, split_paths};
    let f = |name: &str, comp_dir: &str| SplitFile {
        name: name.into(),
        comp_dir: comp_dir.into(),
        dwo_id: 1,
    };
    let image = Path::new("bin/app");
    let debug = Path::new("dbg/app.debug");
    assert_eq!(
        package_paths(image, debug),
        [
            PathBuf::from("dbg/app.debug.dwp"),
            PathBuf::from("dbg/app.dwp"),
            PathBuf::from("bin/app.dwp")
        ]
    );
    assert_eq!(
        split_paths(image, debug, &f("obj/a.dwo", "build")),
        [
            Path::new("dbg").join("build").join("obj/a.dwo"),
            Path::new("dbg").join("obj/a.dwo"),
            Path::new("dbg").join("a.dwo"),
            Path::new("bin").join("build").join("obj/a.dwo"),
            Path::new("bin").join("obj/a.dwo"),
            Path::new("bin").join("a.dwo"),
        ]
    );
    // An absolute compilation directory, first.
    let root = if cfg!(windows) { "C:/src" } else { "/src" };
    let got = split_paths(image, debug, &f("a.dwo", root));
    assert_eq!(got[0], Path::new(root).join("a.dwo"));
    // Only .dwo files; never a UNC or device path.
    assert!(split_paths(image, debug, &f("a.o", ".")).is_empty());
    assert!(split_paths(image, debug, &f("a.dwo\0", ".")).is_empty());
    assert!(split_paths(image, debug, &f(r"\\server\share\a.dwo", ".")).is_empty());
    assert!(split_paths(image, debug, &f("//server/share/a.dwo", ".")).is_empty());
    assert!(split_paths(image, debug, &f(r"\\?\C:\a.dwo", ".")).is_empty());
    let got = split_paths(image, debug, &f("a.dwo", r"\\server\share"));
    assert!(
        got.iter().all(|p| !p.to_string_lossy().contains("server")),
        "{got:?}"
    );
    assert!(!got.is_empty());
}

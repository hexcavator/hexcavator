//! Split DWARF (testdata/elf, from tools/elf/split.cmd): a program built
//! with `-gsplit-dwarf` (DWARF 5, and GNU's DWARF 4 extension), read with
//! its `.dwo` files or its `.dwp` package, reads as the same program built
//! without it (whose code is the same): compilands, code, lines, symbols,
//! inline sites, and every function's variables, types by name.

use hexcavator_debuginfo::dwarf_backend::SplitFile;
use hexcavator_debuginfo::{DebugInfo, TypeRef};

fn testdata(name: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/elf")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// What the debug information says, types by name (their references are
/// offsets, which differ).
fn account(d: &DebugInfo<'_>) -> Vec<String> {
    let name = |t: u64| d.type_name(TypeRef(t));
    let mut out = Vec::new();
    for c in d.compilands().unwrap() {
        out.push(format!("compiland {}", c.name));
    }
    for c in d.contributions().unwrap() {
        out.push(format!("contribution {c:?}"));
    }
    let lines = d.source_lines().unwrap();
    for l in &lines.spans {
        out.push(format!(
            "line {:#x}+{} {}:{} in {}",
            l.addr, l.size, lines.files[l.file as usize], l.line, l.compiland
        ));
    }
    let mut functions = Vec::new();
    for mut s in d.symbols().unwrap() {
        let ty = name(s.type_index);
        s.type_index = 0;
        if let Some(f) = &mut s.function {
            let params: Vec<String> = f
                .params
                .iter()
                .map(|(n, t)| format!("{n}: {}", d.type_name(*t)))
                .collect();
            out.push(format!(
                "  in {} {} ({})",
                f.name,
                d.type_name(f.ty),
                params.join(", ")
            ));
            f.ty = TypeRef(0);
            f.params.clear();
        }
        if s.kind == hexcavator_debuginfo::SymbolKind::Function {
            functions.push((s.compiland, s.addr));
        }
        out.push(format!("symbol {s:?}: {ty}"));
    }
    let inlines = d.inline_sites().unwrap();
    for s in &inlines.sites {
        out.push(format!(
            "inline {} {s:?}",
            inlines.inlinees[s.inlinee as usize]
        ));
    }
    for (compiland, addr) in functions {
        let Some(mut v) = d.variables(compiland, addr).unwrap() else {
            out.push(format!("variables {addr:#x}: none"));
            continue;
        };
        for x in &mut v.variables {
            out.push(format!("  {}: {}", x.name, name(x.type_index)));
            x.type_index = 0;
        }
        out.push(format!("variables {addr:#x}: {v:?}"));
    }
    out
}

fn assert_same(what: &str, got: &[String], want: &[String]) {
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        assert_eq!(g, w, "{what}: line {i}");
    }
    assert_eq!(got.len(), want.len(), "{what}: lengths");
}

#[test]
fn split_programs_read_as_unsplit_ones() {
    for v in [4, 5] {
        let image = testdata(&format!("split-dwarf{v}"));
        let plain = testdata(&format!("split-dwarf{v}-plain"));
        let want = account(&DebugInfo::parse(&plain).unwrap());
        assert!(
            want.iter()
                .any(|l| l.starts_with("variables") && !l.ends_with("none"))
        );
        assert!(want.iter().any(|l| l.starts_with("inline")));

        let dwos = [
            testdata(&format!("sd{v}-program.dwo")),
            testdata(&format!("sd{v}-second.dwo")),
        ];
        let mut d = DebugInfo::parse(&image).unwrap();
        let names: Vec<String> = d
            .dwarf()
            .unwrap()
            .split_files()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(
            names,
            [format!("sd{v}-program.dwo"), format!("sd{v}-second.dwo")]
        );
        for dwo in &dwos {
            d.dwarf_mut().unwrap().add_split(dwo).unwrap();
        }
        assert_same(&format!("DWARF {v}, .dwo files"), &account(&d), &want);

        // In the other order: units are matched by ID.
        let mut d = DebugInfo::parse(&image).unwrap();
        for dwo in dwos.iter().rev() {
            d.dwarf_mut().unwrap().add_split(dwo).unwrap();
        }
        assert_same(
            &format!("DWARF {v}, .dwo files reversed"),
            &account(&d),
            &want,
        );

        let dwp = testdata(&format!("split-dwarf{v}.dwp"));
        let mut d = DebugInfo::parse(&image).unwrap();
        d.dwarf_mut().unwrap().add_split(&dwp).unwrap();
        assert_same(&format!("DWARF {v}, .dwp"), &account(&d), &want);

        // A unit is read once, whatever has it; files without the
        // skeletons' units add nothing.
        d.dwarf_mut().unwrap().add_split(&dwos[0]).unwrap();
        let other = testdata(&format!("sd{}-program.dwo", 9 - v));
        d.dwarf_mut().unwrap().add_split(&other).unwrap();
        assert_same(&format!("DWARF {v}, .dwp and more"), &account(&d), &want);
    }
}

#[test]
fn skeletons_alone_are_compilands_named_by_their_files() {
    for v in [4, 5] {
        let image = testdata(&format!("split-dwarf{v}"));
        let d = DebugInfo::parse(&image).unwrap();
        let names: Vec<String> = d
            .compilands()
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(
            names,
            [format!("sd{v}-program.dwo"), format!("sd{v}-second.dwo")]
        );
        // Their code and lines are the skeletons'.
        let plain = testdata(&format!("split-dwarf{v}-plain"));
        let p = DebugInfo::parse(&plain).unwrap();
        assert_eq!(d.contributions().unwrap(), p.contributions().unwrap());
        assert_eq!(d.source_lines().unwrap(), p.source_lines().unwrap());
        let ids = d.dwarf().unwrap().split_files();
        assert!(
            ids.iter()
                .all(|f: &SplitFile| f.comp_dir == "." && f.dwo_id != 0)
        );
    }
}

#[test]
fn damaged_split_files_do_not_panic() {
    for v in [4, 5] {
        let image = testdata(&format!("split-dwarf{v}"));
        for name in [format!("sd{v}-program.dwo"), format!("split-dwarf{v}.dwp")] {
            let file = testdata(&name);
            // Every byte of the file's first 4 KiB, changed.
            for at in 0..file.len().min(4096) {
                for x in [0x01, 0x80, 0xFF] {
                    let mut bad = file.clone();
                    bad[at] ^= x;
                    let mut d = DebugInfo::parse(&image).unwrap();
                    if d.dwarf_mut().unwrap().add_split(&bad).is_ok() {
                        let _ = account(&d);
                    }
                }
            }
            // And cut short.
            for len in (0..file.len()).step_by(7) {
                let mut d = DebugInfo::parse(&image).unwrap();
                if d.dwarf_mut().unwrap().add_split(&file[..len]).is_ok() {
                    let _ = account(&d);
                }
            }
        }
    }
}

#[test]
fn files_without_split_dwarf_are_refused() {
    let image = testdata("split-dwarf5");
    let mut d = DebugInfo::parse(&image).unwrap();
    let dwarf = d.dwarf_mut().unwrap();
    assert!(dwarf.add_split(b"not an object").is_err());
    // An object, but no .debug_info.dwo.
    assert!(dwarf.add_split(&testdata("program-stripped")).is_err());
}

fn types_file(name: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/types")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// C++ classes, as type units (tools/types/build-dwarf.cmd: types.cpp with
/// `-fdebug-types-section`): in the `.dwo` (DWARF 5's split type units, and
/// DWARF 4's `.debug_types.dwo`) and the `.dwp` (its `.debug_tu_index`),
/// read as in the unsplit build.
#[test]
fn split_type_units_read_as_unsplit_ones() {
    let classes = |d: &DebugInfo<'_>| -> Vec<String> {
        let mut out: Vec<String> = d
            .classes()
            .unwrap()
            .into_iter()
            .map(|c| {
                let bases: Vec<String> = c.bases.iter().map(|&b| d.type_name(b)).collect();
                let methods: Vec<String> = c
                    .methods
                    .iter()
                    .map(|m| format!("{} {:?} {}", m.name, m.kind, d.type_name(m.ty)))
                    .collect();
                format!(
                    "{} ({:?} bytes) : {} {{ {} }}",
                    c.name,
                    d.type_size(c.ty),
                    bases.join(", "),
                    methods.join("; ")
                )
            })
            .collect();
        out.sort();
        out
    };
    for v in [4, 5] {
        let plain = types_file(&format!("types-split{v}-plain"));
        let p = DebugInfo::parse(&plain).unwrap();
        let want_classes = classes(&p);
        assert!(want_classes.len() >= 9, "{want_classes:?}");
        let want_layouts = p.layouts().unwrap();
        let want = account(&p);
        let image = types_file(&format!("types-split{v}"));
        for split in [format!("types-split{v}.dwo"), format!("types-split{v}.dwp")] {
            let file = types_file(&split);
            let mut d = DebugInfo::parse(&image).unwrap();
            // Without it: no classes.
            assert!(d.classes().unwrap().is_empty(), "{split}");
            d.dwarf_mut().unwrap().add_split(&file).unwrap();
            assert_eq!(classes(&d), want_classes, "{split}");
            let layouts = d.layouts().unwrap();
            let diff = hexcavator_debuginfo::layout::compare(&want_layouts, &layouts);
            assert!(
                diff.changed.is_empty() && diff.added.is_empty() && diff.removed.is_empty(),
                "{split}: {diff:?}"
            );
            assert_eq!(layouts.len(), want_layouts.len(), "{split}");
            assert_same(&split, &account(&d), &want);
        }
    }
}

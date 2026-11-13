//! bloaty-style data sources over SizeBench's test binaries: every source
//! labels every byte of the file exactly once and the same memory as the
//! base map, and sources that mirror the size model agree with it.

use std::collections::BTreeMap;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::rangemap::RangeMap;
use hexcavator_size::rollup::{Options, Report, Rollup};
use hexcavator_size::sources::{self, Inputs, Source};
use hexcavator_size::{pe, symbols};

fn root() -> String {
    format!("{}/../../../testdata/sizebench", env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The corpus binaries that have PDBs (by their oracle files).
fn corpus() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut names: Vec<String> = std::fs::read_dir(format!("{}/oracle", root()))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            p.file_stem().unwrap().to_str().unwrap().to_string()
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|n| {
            let bin = format!("{}/bin", root());
            let image = ["dll", "exe"]
                .iter()
                .map(|e| format!("{bin}/{n}.{e}"))
                .find(|p| std::path::Path::new(p).exists())?;
            Some((n.clone(), read(&image), read(&format!("{bin}/{n}.pdb"))))
        })
        .collect()
}

/// Whether `map` labels exactly the bytes `base` labels.
fn same_domain(map: &RangeMap, base: &RangeMap) -> bool {
    let covered = |m: &RangeMap| {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for e in m.iter() {
            match out.last_mut() {
                Some(last) if last.1 == e.start => last.1 = e.end,
                _ => out.push((e.start, e.end)),
            }
        }
        out
    };
    covered(map) == covered(base)
}

#[test]
fn every_byte_is_labeled_once() {
    let corpus = corpus();
    assert!(corpus.len() >= 15, "{}", corpus.len());
    for (name, image_data, pdb_data) in &corpus {
        let image = Image::parse(image_data).unwrap();
        let debug = DebugInfo::parse(pdb_data).unwrap();
        let model = pe::model(&image, &debug).unwrap();
        let syms = symbols::build(&image, &debug, &model).unwrap();
        let inputs = Inputs {
            model: Some(&model),
            symbols: Some(&syms),
            file_name: name,
            lines: None,
        };
        let maps = sources::maps(&image, inputs, Source::ALL);
        let len = image_data.len() as u64;
        assert_eq!(maps.base.file.total(), len, "{name}");
        assert!(maps.base.file.covers(0, len), "{name}");
        for (source, map) in &maps.sources {
            assert!(
                same_domain(&map.file, &maps.base.file),
                "{name}: {source:?} file domain"
            );
            assert!(
                same_domain(&map.vm, &maps.base.vm),
                "{name}: {source:?} memory domain"
            );
            // Translations agree in both directions.
            for e in map.vm.iter() {
                if let Some(o) = e.other {
                    assert_eq!(map.file.translate(o), Some(e.start), "{name}: {source:?}");
                }
            }
        }
        let rollup = Rollup::new(&maps);
        assert_eq!(rollup.file, len as i64, "{name}");
        assert_eq!(rollup.vm, maps.base.vm.total() as i64, "{name}");
    }
}

#[test]
fn compilands_and_groups_agree_with_the_model() {
    for (name, image_data, pdb_data) in &corpus() {
        let image = Image::parse(image_data).unwrap();
        let debug = DebugInfo::parse(pdb_data).unwrap();
        let model = pe::model(&image, &debug).unwrap();
        let inputs = Inputs {
            model: Some(&model),
            symbols: None,
            file_name: name,
            lines: None,
        };
        let maps = sources::maps(&image, inputs, &[Source::CompileUnits, Source::Groups]);
        let rollup = Rollup::new(&maps);
        // Memory sizes per compiland, summed over the sections and groups
        // they span; the model's pieces don't overlap across compilands
        // in these binaries.
        let mut ours: BTreeMap<&str, i64> = BTreeMap::new();
        for (label, r) in &rollup.children {
            ours.insert(label, r.vm);
        }
        // Compilands with the same name merge in the report.
        let by_name = model.totals(|p| Some(model.compilands[p.compiland as usize].name.as_str()));
        for (n, t) in &by_name {
            let n = if n.is_empty() {
                "[unknown compiland]"
            } else {
                n
            };
            assert_eq!(ours.get(n).copied(), Some(t.size.vm as i64), "{name}: {n}");
        }
        // Groups, at the second level.
        let mut by_group: BTreeMap<&str, i64> = BTreeMap::new();
        for r in rollup.children.values() {
            for (g, gr) in &r.children {
                *by_group.entry(g).or_default() += gr.vm;
            }
        }
        for g in &model.groups {
            if model.groups.iter().filter(|h| h.name == g.name).count() == 1 && g.extent() > 0 {
                assert_eq!(
                    by_group.get(g.name.as_str()).copied(),
                    Some(g.extent() as i64),
                    "{name}: {}",
                    g.name
                );
            }
        }
    }
}

#[test]
fn a_diff_against_itself_is_empty() {
    let (name, image_data, pdb_data) = &corpus()[0];
    let image = Image::parse(image_data).unwrap();
    let debug = DebugInfo::parse(pdb_data).unwrap();
    let model = pe::model(&image, &debug).unwrap();
    let inputs = Inputs {
        model: Some(&model),
        symbols: None,
        file_name: name,
        lines: None,
    };
    let maps = sources::maps(&image, inputs, &[Source::Sections, Source::CompileUnits]);
    let rollup = Rollup::new(&maps);
    let options = Options::default();
    let report = Report::new(
        &["sections", "compileunits"],
        &rollup,
        Some(&rollup),
        &options,
    );
    assert!(report.total.children.is_empty());
    assert_eq!((report.total.vm, report.total.file), (0, 0));
    let plain = Report::new(&["sections", "compileunits"], &rollup, None, &options);
    assert!(!plain.total.children.is_empty());
    assert_eq!(plain.total.file, image_data.len() as i64);
}

/// The symbols source charges a function's exception data (`.pdata`
/// entries, unwind data, C++ EH tables) to the function, as ELF's unwind
/// entries are: no label is a `[pdata] f`-style name, and each such
/// symbol's bytes go to the function it describes.
#[test]
fn exception_data_is_charged_to_its_function() {
    let mut checked = 0;
    for (name, image_data, pdb_data) in &corpus() {
        let image = Image::parse(image_data).unwrap();
        let debug = DebugInfo::parse(pdb_data).unwrap();
        let model = pe::model(&image, &debug).unwrap();
        let syms = symbols::build(&image, &debug, &model).unwrap();
        let inputs = Inputs {
            model: Some(&model),
            symbols: Some(&syms),
            file_name: name,
            lines: None,
        };
        let maps = sources::maps(&image, inputs, &[Source::Symbols]);
        let map = &maps.sources[0].1;
        for e in map.vm.iter() {
            let label = maps.labels.name(e.label);
            assert!(
                !["[pdata] ", "[unwind] ", "[chain-unwind] ", "[cppxdata] "]
                    .iter()
                    .any(|p| label.starts_with(p)),
                "{name}: {label}"
            );
        }
        for s in syms.iter().filter(|s| !s.folded && s.size.vm > 0) {
            let Some(p) = s.kind.prefix() else { continue };
            let function = &s.name[p.len() + 1..];
            let got = map.vm.get(s.addr).map(|e| maps.labels.name(e.label));
            // (Bytes some other symbol claimed first keep its name.)
            if got == Some(function) {
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "{checked}");
}

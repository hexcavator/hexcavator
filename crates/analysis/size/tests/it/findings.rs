//! Findings against SizeBench's analyses (`testdata/sizebench/findings`,
//! from `tools/sizebench-oracle --findings`).

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::{findings, pe, symbols};

fn root() -> String {
    format!("{}/../../../testdata/sizebench", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn duplicate_data_matches_sizebench() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(format!("{}/findings", root())).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let bin = format!("{}/bin", root());
        let Some(image_path) = ["dll", "exe"]
            .iter()
            .map(|e| format!("{bin}/{name}.{e}"))
            .find(|p| std::path::Path::new(p).exists())
        else {
            continue;
        };
        let image_data = std::fs::read(&image_path).unwrap();
        let pdb_data = std::fs::read(format!("{bin}/{name}.pdb")).unwrap();
        let image = Image::parse(&image_data).unwrap();
        let debug = DebugInfo::parse(&pdb_data).unwrap();
        let model = pe::model(&image, &debug).unwrap();
        let syms = symbols::build(&image, &debug, &model).unwrap();
        // (Symbols name the debug information's modules.)
        let modules = debug.compilands().unwrap();
        // SizeBench counts only copies in compilands with section
        // contributions; the object that built a precompiled header has
        // none, but its copies are as real as the others. (A classified
        // divergence: ours, without those copies, must be SizeBench's.)
        let contributing: std::collections::HashSet<u32> = debug
            .contributions()
            .unwrap()
            .iter()
            .map(|c| c.compiland)
            .collect();
        let mut ours: Vec<String> = findings::duplicate_data(&image, &syms)
            .into_iter()
            .filter_map(|mut d| {
                d.copies.retain(|c| contributing.contains(&c.1));
                (d.copies.len() > 1).then_some(d)
            })
            .map(|d| {
                let mut compilands: Vec<&str> = d
                    .copies
                    .iter()
                    .map(|c| modules[c.1 as usize].name.as_str())
                    .collect();
                compilands.sort_unstable();
                format!(
                    "DUPDATA {} size={} vsize={} copies={} wasted={} | {}",
                    d.name,
                    d.size.file,
                    d.size.vm,
                    d.copies.len(),
                    d.wasted().file,
                    compilands.join(" | ")
                )
            })
            .collect();
        ours.sort();
        let theirs: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("DUPDATA "))
            .map(str::to_string)
            .collect();
        checked += theirs.len();
        for l in theirs.iter().filter(|l| !ours.contains(l)) {
            failures.push(format!("{name}: missing {l}"));
        }
        for l in ours.iter().filter(|l| !theirs.contains(l)) {
            failures.push(format!("{name}: extra {l}"));
        }
    }
    assert!(checked > 50, "{checked}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn wasteful_virtuals_match_sizebench() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(format!("{}/findings", root())).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let bin = format!("{}/bin", root());
        let Some(image_path) = ["dll", "exe"]
            .iter()
            .map(|e| format!("{bin}/{name}.{e}"))
            .find(|p| std::path::Path::new(p).exists())
        else {
            continue;
        };
        let image_data = std::fs::read(&image_path).unwrap();
        let pdb_data = std::fs::read(format!("{bin}/{name}.pdb")).unwrap();
        let image = Image::parse(&image_data).unwrap();
        let debug = DebugInfo::parse(&pdb_data).unwrap();
        let word = u64::from(image.arch().pointer_size().unwrap_or(8));
        let classes = debug.classes().unwrap();
        let mut namer = hexcavator_size::names::Namer::new(&debug);
        let mut ours: Vec<String> = findings::wasteful_virtuals(&classes, &mut namer, word)
            .iter()
            .map(|w| {
                let functions: Vec<String> = w
                    .pure_with_one_override
                    .iter()
                    .map(|f| format!("pure:{f}"))
                    .chain(w.unoverridden.iter().map(|f| format!("unoverridden:{f}")))
                    .collect();
                format!(
                    "WASTEFUL {} wasted={} perslot={} | {}",
                    w.class,
                    w.wasted(),
                    w.per_slot,
                    functions.join(" | ")
                )
            })
            .collect();
        ours.sort();
        let theirs: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("WASTEFUL "))
            .map(str::to_string)
            .collect();
        checked += theirs.len();
        for l in theirs.iter().filter(|l| !ours.contains(l)) {
            failures.push(format!("{name}: missing {l}"));
        }
        for l in ours.iter().filter(|l| !theirs.contains(l)) {
            failures.push(format!("{name}: extra {l}"));
        }
    }
    assert!(checked > 30, "{checked}");
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

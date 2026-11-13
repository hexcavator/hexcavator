//! The size model from an image and its linker map
//! (`testdata/linkerlog`, built by `tools/linkerlog/build.cmd`).

use hexcavator_image::Image;
use hexcavator_size::sources::{self, Inputs, Source};
use hexcavator_size::{map, rollup::Rollup};

fn testdata(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../../../testdata/linkerlog/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

#[test]
fn model_from_a_map() {
    let image_data = testdata("main.exe");
    let image = Image::parse(&image_data).unwrap();
    let text = String::from_utf8(testdata("main.map")).unwrap();
    let linkmap = hexcavator_linkmap::parse(&text);
    let (model, symbols) = map::model(&image, &linkmap).unwrap();
    // Sections are the image's; groups are the map's (those with bytes).
    assert_eq!(model.sections.len(), image.sections().len());
    let named: Vec<&str> = model.groups.iter().map(|g| g.name.as_str()).collect();
    for g in linkmap.groups.iter().filter(|g| g.length > 0) {
        assert!(named.contains(&g.name.as_str()), "{}", g.name);
    }
    // Every piece lies in its group.
    for p in &model.pieces {
        if p.group != hexcavator_size::NO_GROUP {
            let g = &model.groups[p.group as usize];
            assert!(
                p.range.addr >= g.addr && p.range.end() <= g.addr + g.extent(),
                "{p:?} {g:?}"
            );
        }
    }
    // Libraries and compilands as the map names them.
    let libs: Vec<&str> = model.libraries.iter().map(|l| l.name.as_str()).collect();
    assert!(libs.contains(&"libucrt.lib"), "{libs:?}");
    assert!(libs.contains(&"main.obj"), "{libs:?}");
    assert!(model.compilands.iter().any(|c| c.name == "main.obj"));
    // Symbols: functions and data, sized to the next, within their groups.
    let main = symbols.iter().find(|s| s.name == "main").unwrap();
    assert_eq!(main.kind, hexcavator_size::symbols::SymbolKind::Function);
    assert!(main.size.file > 0);
    assert!(symbols.windows(2).all(|w| w[0].addr < w[1].addr));
    assert!(
        symbols.iter().any(|s| s.name.contains("operator new")),
        "undecorated"
    );
    // Every data source labels every file byte.
    let inputs = Inputs {
        model: Some(&model),
        symbols: Some(&symbols),
        file_name: "main.exe",
        lines: None,
    };
    let maps = sources::maps(&image, inputs, Source::ALL);
    let rollup = Rollup::new(&maps);
    assert_eq!(rollup.file, image_data.len() as i64);
    // The compilands' bytes are most of the code and data.
    let attributed: u64 = model
        .totals(|p| Some(p.compiland))
        .values()
        .map(|t| t.size.file)
        .sum();
    let in_groups: u64 = model.groups.iter().map(|g| g.size.file).sum();
    assert!(
        attributed * 10 > in_groups * 9,
        "{attributed} of {in_groups}"
    );
}

#[test]
fn damaged_maps_do_not_panic() {
    let image_data = testdata("main.exe");
    let image = Image::parse(&image_data).unwrap();
    let text = String::from_utf8(testdata("main.map")).unwrap();
    // Truncations, and section numbers past the image's.
    for len in (0..text.len()).step_by(text.len() / 50) {
        let cut = &text[..text.floor_char_boundary(len)];
        let _ = map::model(&image, &hexcavator_linkmap::parse(cut));
    }
    let shifted = text.replace(" 0001:", " 0099:");
    let (model, _) = map::model(&image, &hexcavator_linkmap::parse(&shifted)).unwrap();
    assert!(model.groups.iter().all(|g| !g.name.starts_with(".text")));
}

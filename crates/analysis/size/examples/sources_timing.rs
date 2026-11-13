//! Times each step of a bloaty-style report: `sources_timing <image> <pdb>
//! [sources]` (default `symbols`).

use std::time::Instant;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::rollup::{Options, Report, Rollup};
use hexcavator_size::sources::{self, Inputs, Source};
use hexcavator_size::{pe, symbols};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, image_path, pdb_path, rest @ ..] = args.as_slice() else {
        eprintln!("usage: sources_timing <image> <pdb> [sources]");
        std::process::exit(2);
    };
    let list: Vec<Source> = rest
        .first()
        .map_or("symbols", String::as_str)
        .split(',')
        .map(|s| Source::parse(s).expect("a data source"))
        .collect();
    let image_map = hexcavator_mmap::Mmap::open(image_path).unwrap();
    let pdb_map = hexcavator_mmap::Mmap::open(pdb_path).unwrap();
    let mut t = Instant::now();
    let mut lap = |what: &str| {
        eprintln!("{what:>10}: {:7.3} s", t.elapsed().as_secs_f64());
        t = Instant::now();
    };
    let image = Image::parse(&image_map).unwrap();
    let debug = DebugInfo::parse(&pdb_map).unwrap();
    let model = pe::model(&image, &debug).unwrap();
    lap("model");
    let syms = symbols::build(&image, &debug, &model).unwrap();
    lap("symbols");
    let inputs = Inputs {
        model: Some(&model),
        symbols: Some(&syms),
        file_name: "image",
        lines: None,
    };
    let maps = sources::maps(&image, inputs, &list);
    lap("maps");
    let rollup = Rollup::new(&maps);
    lap("rollup");
    let names: Vec<&str> = list.iter().map(|s| s.name()).collect();
    let report = Report::new(&names, &rollup, None, &Options::default());
    let text = report.pretty(&Options::default());
    lap("report");
    eprintln!(
        "{} lines, {} labels",
        text.lines().count(),
        maps.labels.len()
    );
}

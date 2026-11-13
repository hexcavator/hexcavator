//! Times the phases of a symbols report on one image and its PDB:
//! `cargo run --release -p hexcavator-size --example phases -- <image> <pdb>`.

use std::time::Instant;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::sources::{self, Inputs, Source};
use hexcavator_size::{pe, rollup, symbols};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let t = Instant::now();
    let image_map = hexcavator_mmap::Mmap::open(&args[1]).unwrap();
    let pdb_map = hexcavator_mmap::Mmap::open(&args[2]).unwrap();
    let image = Image::parse(&image_map).unwrap();
    let debug = DebugInfo::parse(&pdb_map).unwrap();
    println!("open+parse   {:>8.3}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let model = pe::model(&image, &debug).unwrap();
    println!("model        {:>8.3}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let syms = symbols::build(&image, &debug, &model).unwrap();
    println!(
        "symbols      {:>8.3}s  ({} symbols)",
        t.elapsed().as_secs_f64(),
        syms.len()
    );
    let t = Instant::now();
    let inputs = Inputs {
        model: Some(&model),
        symbols: Some(&syms),
        file_name: "x",
        lines: None,
    };
    let maps = sources::maps(&image, inputs, &[Source::Symbols]);
    println!("maps         {:>8.3}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let r = rollup::Rollup::new(&maps);
    println!(
        "rollup       {:>8.3}s  ({} rows)",
        t.elapsed().as_secs_f64(),
        r.children.len()
    );
}

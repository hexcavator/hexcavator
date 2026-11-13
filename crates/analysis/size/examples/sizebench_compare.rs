//! Compares the size model of a binary with SizeBench's, and times it.
//!
//!     cargo run --release -p hexcavator-size --example sizebench_compare -- <image> <pdb> [oracle.txt]
//!
//! The oracle file is `tools/sizebench-oracle`'s output for the same image.
//! Without one, prints our lines (in the oracle's format) to stdout.

use std::collections::BTreeSet;
use std::time::Instant;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::{pe, report};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: sizebench_compare <image> <pdb> [oracle.txt]");
        std::process::exit(2);
    }
    let start = Instant::now();
    let image_map = hexcavator_mmap::Mmap::open(std::path::Path::new(&args[0])).expect("image");
    let pdb_map = hexcavator_mmap::Mmap::open(std::path::Path::new(&args[1])).expect("pdb");
    let image = Image::parse(&image_map).expect("parse image");
    let debug = DebugInfo::parse(&pdb_map).expect("parse pdb");
    if let Err(e) = pe::check(&image, &debug) {
        eprintln!("cannot analyze: {e}");
        std::process::exit(1);
    }
    let inputs = pe::extract(&image, &debug).expect("extract");
    let extracted = start.elapsed();
    let model = pe::build(&inputs);
    let built = start.elapsed();
    let lines = report::sizebench_lines(&model);
    let reported = start.elapsed();
    eprintln!(
        "{} contributions, {} pieces; extract {:?}, build {:?}, report {:?}",
        inputs.contributions.len(),
        model.pieces.len(),
        extracted,
        built - extracted,
        reported - built
    );
    let Some(oracle) = args.get(2) else {
        for l in &lines {
            println!("{l}");
        }
        return;
    };
    let kinds: BTreeSet<&str> = lines.iter().map(|l| l.split(' ').next().unwrap()).collect();
    let text = std::fs::read_to_string(oracle).expect("oracle");
    let theirs: BTreeSet<&str> = text
        .lines()
        .filter(|l| kinds.contains(l.split(' ').next().unwrap()))
        .collect();
    let ours: BTreeSet<&str> = lines.iter().map(String::as_str).collect();
    let missing: Vec<_> = theirs.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&theirs).collect();
    for l in missing.iter().take(20) {
        println!("- {l}");
    }
    for l in extra.iter().take(20) {
        println!("+ {l}");
    }
    println!(
        "{} lines; {} missing, {} extra",
        theirs.len(),
        missing.len(),
        extra.len()
    );
}

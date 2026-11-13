//! Compares the symbols the debug information has with SizeBench's
//! `SYMBOL` lines, by address and size (not name).
//!
//!     cargo run --release -p hexcavator-size --example symdiff -- <image> <pdb> <oracle.txt> [kind...]

use std::collections::BTreeMap;
use std::time::Instant;

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::{pe, symbols};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let image_map = hexcavator_mmap::Mmap::open(std::path::Path::new(&args[0])).expect("image");
    let pdb_map = hexcavator_mmap::Mmap::open(std::path::Path::new(&args[1])).expect("pdb");
    let image = Image::parse(&image_map).expect("parse image");
    let debug = DebugInfo::parse(&pdb_map).expect("parse pdb");
    // HEXC_PROBE=<hex address>: show the debug symbols there.
    if let Ok(probe) = std::env::var("HEXC_PROBE") {
        let addr = u64::from_str_radix(&probe, 16).expect("hex address");
        let comps = debug.compilands().unwrap();
        let contribs = debug.contributions().unwrap();
        for s in debug.symbols().unwrap().iter().filter(|s| s.addr == addr) {
            let m = s.compiland.map(|c| comps[c as usize].name.as_str());
            let contributes = s
                .compiland
                .is_some_and(|c| contribs.iter().any(|x| x.compiland == c));
            println!("probe: {s:?} module={m:?} contributes={contributes}");
        }
    }
    let start = Instant::now();
    let model = pe::model(&image, &debug).expect("model");
    let syms = symbols::build(&image, &debug, &model).expect("symbols");
    eprintln!("{} symbols in {:?}", syms.len(), start.elapsed());
    // HEXC_PROBE_OURS=<file>: write our names at the probed address there.
    if let (Ok(probe), Ok(out)) = (
        std::env::var("HEXC_PROBE"),
        std::env::var("HEXC_PROBE_OURS"),
    ) {
        let addr = u64::from_str_radix(&probe, 16).expect("hex address");
        let names: Vec<String> = syms
            .iter()
            .filter(|s| s.addr == addr)
            .map(|s| {
                format!(
                    "{} {} {}",
                    s.kind.sizebench_name(),
                    u8::from(s.folded),
                    s.name
                )
            })
            .collect();
        std::fs::write(out, names.join("\n")).expect("write");
    }

    let filter: Vec<&str> = args[3..].iter().map(String::as_str).collect();
    let names_too = std::env::var("HEXC_NAMES").is_ok();
    let keep = |k: &str| filter.is_empty() || filter.contains(&k);
    // (kind, rva, size, vsize, folded) -> count
    let mut theirs: BTreeMap<(String, u64, u64, u64, bool), i64> = BTreeMap::new();
    let mut names: BTreeMap<(String, u64, u64, u64, bool), Vec<String>> = BTreeMap::new();
    for line in std::fs::read_to_string(&args[2]).expect("oracle").lines() {
        let Some(rest) = line.strip_prefix("SYMBOL ") else {
            continue;
        };
        let mut w = rest.splitn(6, ' ');
        let rva = u64::from_str_radix(w.next().unwrap(), 16).unwrap();
        let size: u64 = w
            .next()
            .unwrap()
            .strip_prefix("size=")
            .unwrap()
            .parse()
            .unwrap();
        let vsize: u64 = w
            .next()
            .unwrap()
            .strip_prefix("vsize=")
            .unwrap()
            .parse()
            .unwrap();
        let kind = w.next().unwrap().to_string();
        let folded = w.next().unwrap() == "1";
        let name = w.next().unwrap_or("").to_string();
        if !keep(&kind) {
            continue;
        }
        let kind = if names_too {
            format!("{kind} {name}")
        } else {
            kind
        };
        let key = (kind, rva, size, vsize, folded);
        *theirs.entry(key.clone()).or_default() += 1;
        names.entry(key).or_default().push(name);
    }
    let mut ours: BTreeMap<(String, u64, u64, u64, bool), i64> = BTreeMap::new();
    let mut our_names: BTreeMap<(String, u64, u64, u64, bool), Vec<String>> = BTreeMap::new();
    for s in &syms {
        let kind = s.kind.sizebench_name().to_string();
        if !keep(&kind) {
            continue;
        }
        let kind = if names_too {
            format!("{kind} {}", s.name)
        } else {
            kind
        };
        let key = (kind, s.addr, s.size.file, s.size.vm, s.folded);
        *ours.entry(key.clone()).or_default() += 1;
        our_names.entry(key).or_default().push(s.name.clone());
    }
    let mut by_kind: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    let mut shown = 0;
    let keys: std::collections::BTreeSet<_> = theirs.keys().chain(ours.keys()).cloned().collect();
    for key in keys {
        let t = theirs.get(&key).copied().unwrap_or(0);
        let o = ours.get(&key).copied().unwrap_or(0);
        let e = by_kind
            .entry(key.0.split(" ").next().unwrap().to_string())
            .or_default();
        e.0 += t;
        if t > o {
            e.1 += t - o;
        } else {
            e.2 += o - t;
        }
        if t != o && shown < 40 {
            shown += 1;
            println!(
                "{} {:08x} size={} vsize={} folded={}: theirs {t} {:?}, ours {o} {:?}",
                key.0,
                key.1,
                key.2,
                key.3,
                key.4,
                names.get(&key).map(|v| &v[..v.len().min(2)]),
                our_names.get(&key).map(|v| &v[..v.len().min(2)]),
            );
        }
    }
    for (kind, (total, missing, extra)) in by_kind {
        println!("{kind:32} {total:8} theirs, {missing:7} missing, {extra:7} extra");
    }
}

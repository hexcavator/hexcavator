//! Lists every word of the golden file (tests/data/golden.txt, dumpbin's
//! output) that hexcavator-arm64 decodes differently, with the encoding it chose,
//! and a count by encoding, largest first:
//! `cargo run -p hexcavator-arm64 --example golden_report [filter]`.

use std::collections::BTreeMap;

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let text = include_str!("../tests/data/golden.txt");
    let mut by_encoding: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0;
    let mut wrong = 0;
    for line in text.lines() {
        let (address, rest) = line.split_once(' ').unwrap();
        let (word, expected) = rest.split_once(' ').unwrap_or((rest, ""));
        let w = u32::from_str_radix(word, 16).unwrap();
        total += 1;
        let address = if address == "-" {
            0
        } else {
            u64::from_str_radix(address, 16).unwrap()
        };
        let inst = hexcavator_arm64::decode(w, address);
        let ours = inst
            .map(|i| hexcavator_arm64::format(&i))
            .unwrap_or_default();
        let name = inst.map_or("(invalid)", |i| i.encoding_name());
        let same = if line.starts_with("- ") {
            // (FMININM postdates dumpbin: see tests/golden.rs.)
            inst.is_none() || name == "FMININM_D_floatdp2"
        } else {
            ours.split_whitespace().eq(expected.split_whitespace())
        };
        if same {
            continue;
        }
        wrong += 1;
        *by_encoding.entry(name.to_string()).or_default() += 1;
        if name.contains(&filter) {
            let expected = if line.starts_with("- ") {
                "(invalid)"
            } else {
                expected
            };
            println!("{word} {name:<28} expected {expected:<44} got {ours}");
        }
    }
    let mut counts: Vec<(usize, String)> = by_encoding.into_iter().map(|(k, v)| (v, k)).collect();
    counts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    println!("\n{wrong} of {total} differ; by encoding:");
    for (n, name) in counts.iter().take(60) {
        println!("{n:6} {name}");
    }
}

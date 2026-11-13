//! Times demangling a file of names (the first tab-separated field of each
//! line) with the Rust or Swift demangler, best of five passes:
//!
//!     bench_names rust|swift <names.txt>

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (kind, path) = match &args[..] {
        [_, kind, path] => (kind.as_str(), path),
        _ => panic!("usage: bench_names rust|swift <names.txt>"),
    };
    let text = std::fs::read_to_string(path).unwrap();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split('\t').next())
        .filter(|n| !n.is_empty() && !n.starts_with('#'))
        .collect();
    let mut out = String::new();
    let mut swift = hexcavator_demangle::swift::Demangler::new();
    let mut f = |n: &str| {
        out.clear();
        let ok = match kind {
            "rust" => hexcavator_demangle::rust::demangle_into(n, &mut out),
            "swift" => swift.demangle_into(n, &mut out),
            _ => panic!("rust or swift"),
        };
        if ok { out.len() } else { 0 }
    };
    let mut best = f64::MAX;
    let mut check = 0;
    for _ in 0..5 {
        let t = Instant::now();
        check = 0;
        for _ in 0..4 {
            for n in &names {
                check += f(n);
            }
        }
        best = best.min(t.elapsed().as_secs_f64());
    }
    let count = names.len() * 4;
    println!(
        "{kind:>10}: {:6.0} ns/name, {:6.2} M names/s ({check})",
        best * 1e9 / count as f64,
        count as f64 / best / 1e6,
    );
}

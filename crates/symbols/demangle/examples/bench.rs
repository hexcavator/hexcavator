//! Times parsing and undecorating a file of names:
//!
//!     bench <names.txt>

use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("usage: bench <names.txt>");
    let text = std::fs::read_to_string(path).unwrap();
    let names: Vec<&str> = text.lines().collect();
    let bytes: usize = names.iter().map(|n| n.len()).sum();
    let rounds = 10;
    let mb = (bytes * rounds) as f64 / 1e6;

    let mut d = hexcavator_demangle::msvc::Demangler::new();
    let t = Instant::now();
    let mut ok = 0usize;
    for _ in 0..rounds {
        for n in &names {
            ok += usize::from(d.parse_name(n).is_some());
        }
    }
    report("parse_name", t, names.len() * rounds, mb, ok);

    let t = Instant::now();
    let mut ok = 0usize;
    for _ in 0..rounds {
        for n in &names {
            ok += usize::from(d.parse(n).is_some());
        }
    }
    report("parse", t, names.len() * rounds, mb, ok);

    let t = Instant::now();
    let mut len = 0usize;
    for _ in 0..rounds {
        for n in &names {
            if let Some(s) = d.demangle(n, hexcavator_demangle::msvc::flags::NO_PTR64) {
                len += s.len();
            }
        }
    }
    report("demangle", t, names.len() * rounds, mb, len);
}

fn report(what: &str, t: Instant, count: usize, mb: f64, check: usize) {
    let s = t.elapsed().as_secs_f64();
    println!(
        "{what:>10}: {:6.0} ns/name, {:6.2} M names/s, {:6.0} MB/s ({check})",
        s * 1e9 / count as f64,
        count as f64 / s / 1e6,
        mb / s
    );
}

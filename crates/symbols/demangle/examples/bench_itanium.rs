//! Times parsing and printing a file of Itanium names (one per line), best
//! of five passes each:
//!
//!     bench_itanium <names.txt>

use std::time::Instant;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: bench_itanium <names.txt>");
    let text = std::fs::read_to_string(path).unwrap();
    let names: Vec<&str> = text.lines().collect();
    let mut d = hexcavator_demangle::itanium::Demangler::new();
    let mut out = String::new();

    best("parse", &names, |n| {
        d.parse(n).map_or(0, |ast| {
            d.recycle(ast);
            1
        })
    });
    let mut d = hexcavator_demangle::itanium::Demangler::new();
    best("demangle", &names, |n| {
        out.clear();
        if d.demangle_into(n, &mut out) {
            out.len()
        } else {
            0
        }
    });
    let mut out = String::new();
    best("short", &names, |n| {
        out.clear();
        if d.demangle_short_into(n, &mut out) {
            out.len()
        } else {
            0
        }
    });
}

/// Times `f` over `names` (twice per pass), reporting the best of five.
fn best(what: &str, names: &[&str], mut f: impl FnMut(&str) -> usize) {
    let mut best = f64::MAX;
    let mut check = 0;
    for _ in 0..5 {
        let t = Instant::now();
        check = 0;
        for _ in 0..2 {
            for n in names {
                check += f(n);
            }
        }
        best = best.min(t.elapsed().as_secs_f64());
    }
    report(what, best, names.len() * 2, check);
}

fn report(what: &str, s: f64, count: usize, check: usize) {
    println!(
        "{what:>10}: {:6.0} ns/name, {:6.2} M names/s ({check})",
        s * 1e9 / count as f64,
        count as f64 / s / 1e6,
    );
}

//! Writes `tests/data/golden.txt` from `undname` outputs: a sample of the
//! names hexc undecorates as undname does, with flags 0 and `NO_PTR64`.
//!
//!     golden <names.txt> <undname-0.txt> <undname-20000.txt> <every-nth>

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let read = |p: &str| std::fs::read_to_string(p).unwrap();
    let names = read(&args[1]);
    let complete = read(&args[2]);
    let no_ptr64 = read(&args[3]);
    let every: usize = args[4].parse().unwrap();
    let lines = |s: &str| -> Vec<String> {
        s.trim_start_matches('\u{feff}')
            .lines()
            .map(String::from)
            .collect()
    };
    let (complete, no_ptr64) = (lines(&complete), lines(&no_ptr64));
    let mut d = hexcavator_demangle::msvc::Demangler::new();
    println!("# name<TAB>undname<TAB>undname 0x20000 (NO_PTR64); from examples/golden");
    for (i, name) in names.lines().enumerate() {
        if i % every != 0 {
            continue;
        }
        let (want0, want2) = (&complete[i], &no_ptr64[i]);
        let mut ok = |flags, want: &str| d.demangle(name, flags).as_deref() == Some(want);
        if ok(0, want0) && ok(hexcavator_demangle::msvc::flags::NO_PTR64, want2) {
            println!("{name}\t{want0}\t{want2}");
        }
    }
}

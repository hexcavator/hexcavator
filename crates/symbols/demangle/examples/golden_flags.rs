//! Writes `tests/data/golden-flags.txt`: names hexc undecorates as undname
//! does under each of several flags, for the hermetic test.
//!
//!     golden_flags <per-flag> <names.txt> <undname-0.txt> <flags>=<undname-flags.txt>...
//!
//! For each flag it keeps up to `per-flag` names whose output the flag
//! changes (evenly spread through the list), and names that use rarer parts
//! of the grammar, wherever hexc and undname agree.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let per_flag: usize = args[1].parse().unwrap();
    let read = |p: &str| -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap()
            .trim_start_matches('\u{feff}')
            .lines()
            .map(String::from)
            .collect()
    };
    let names = read(&args[2]);
    let complete = read(&args[3]);
    // Grammar worth keeping examples of whatever the flags.
    let features = [
        "$$Y", "$M", "$H?", "$$A8", "AY0", "$$QEAP8", "??__F", "??__E",
    ];
    let mut d = hexcavator_demangle::msvc::Demangler::new();
    println!("# flags<TAB>name<TAB>undname <flags> name; from examples/golden_flags");
    for spec in &args[4..] {
        let (flags, path) = spec.split_once('=').unwrap();
        let bits = u32::from_str_radix(flags, 16).unwrap();
        let wanted = read(path);
        let changed: Vec<usize> = (0..names.len())
            .filter(|&i| wanted[i] != complete[i])
            .collect();
        let step = (changed.len() / per_flag.max(1)).max(1);
        let mut picked: Vec<usize> = changed.iter().step_by(step).copied().collect();
        for f in features {
            picked.extend(
                names
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| n.contains(f))
                    .map(|(i, _)| i)
                    .take(3),
            );
        }
        picked.sort_unstable();
        picked.dedup();
        for i in picked {
            if d.demangle(&names[i], bits).as_deref() == Some(wanted[i].as_str()) {
                println!("{flags}\t{}\t{}", names[i], wanted[i]);
            }
        }
    }
}

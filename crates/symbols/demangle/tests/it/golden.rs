//! Hermetic checks against a sample of `undname` outputs, and robustness
//! on mangled names that have been damaged.

#![allow(clippy::cast_possible_truncation)]

use hexcavator_demangle::msvc::{Demangler, flags};

fn golden() -> Vec<(&'static str, &'static str, &'static str)> {
    include_str!("../data/golden.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let mut f = l.split('\t');
            (f.next().unwrap(), f.next().unwrap(), f.next().unwrap())
        })
        .collect()
}

/// Names under other flags (`data/golden-flags.txt`, from
/// `examples/golden_flags` over Microsoft.UI.Xaml's and clang's publics):
/// each flag alone, and SizeBench's thunk-name combination.
#[test]
fn matches_undname_under_flags() {
    let mut d = Demangler::new();
    let mut bad = Vec::new();
    let mut flags_seen = std::collections::BTreeSet::new();
    let lines: Vec<&str> = include_str!("../data/golden-flags.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(lines.len() > 500);
    for l in lines {
        let mut f = l.split('\t');
        let (bits, name, want) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        let bits = u32::from_str_radix(bits, 16).unwrap();
        flags_seen.insert(bits);
        let got = d.demangle(name, bits).unwrap_or_default();
        if got != want {
            bad.push(format!("{bits:#x} {name}\n  want {want}\n  got  {got}"));
        }
    }
    assert!(flags_seen.len() >= 12, "{flags_seen:?}");
    assert!(
        bad.is_empty(),
        "{} differences:\n{}",
        bad.len(),
        bad[..bad.len().min(10)].join("\n")
    );
}

#[test]
fn matches_undname() {
    let mut d = Demangler::new();
    let mut bad = Vec::new();
    let all = golden();
    assert!(all.len() > 1000);
    for (name, complete, no_ptr64) in &all {
        for (f, want) in [(flags::COMPLETE, complete), (flags::NO_PTR64, no_ptr64)] {
            let got = d.demangle(name, f).unwrap_or_default();
            if got != *want {
                bad.push(format!("{name}\n  want {want}\n  got  {got}"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} differences:\n{}",
        bad.len(),
        bad[..bad.len().min(10)].join("\n")
    );
}

/// Truncated and corrupted names must fail cleanly, never panic.
#[test]
fn damaged_names_do_not_panic() {
    let mut d = Demangler::new();
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let alphabet: Vec<char> = "?@$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcxyz<>"
        .chars()
        .collect();
    // The names of both golden files, damaged under several flags.
    let flagged = include_str!("../data/golden-flags.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split('\t').nth(1));
    let names: Vec<&str> = golden()
        .into_iter()
        .map(|(n, _, _)| n)
        .chain(flagged)
        .collect();
    let all_flags = [flags::COMPLETE, flags::NAME_ONLY, 0x2E6, 0xFFFF_FFFF];
    for name in names {
        let chars: Vec<char> = name.chars().collect();
        for cut in [1, chars.len() / 3, chars.len() / 2, chars.len() - 1] {
            let s: String = chars[..cut.min(chars.len())].iter().collect();
            let _ = d.demangle(&s, flags::COMPLETE);
        }
        for _ in 0..4 {
            let mut c = chars.clone();
            let i = (next() as usize) % c.len();
            c[i] = alphabet[(next() as usize) % alphabet.len()];
            let s: String = c.into_iter().collect();
            for f in all_flags {
                let _ = d.demangle(&s, f);
            }
        }
    }
}

/// The parser's recursive descent (which parses the first levels of
/// nesting, handing the rest to its machine) builds exactly the trees the
/// machine alone does: for every name here, and for damaged versions of
/// them.
#[test]
fn recursive_descent_builds_what_the_machine_builds() {
    let mut names: Vec<String> = golden().iter().map(|(n, _, _)| (*n).to_string()).collect();
    names.extend(
        include_str!("../data/golden-flags.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split('\t').nth(1).unwrap().to_string()),
    );
    let mut variants = Vec::new();
    for n in &names {
        let b = n.as_bytes();
        for i in (1..b.len()).step_by(3) {
            variants.push(String::from_utf8_lossy(&b[..i]).into_owned());
            for c in *b"@?$H" {
                let mut v = b.to_vec();
                v[i] = c;
                variants.push(String::from_utf8_lossy(&v).into_owned());
            }
        }
    }
    names.extend(variants);
    let mut bad = 0;
    for n in &names {
        let (a1, a2) = (
            hexcavator_demangle::msvc::Arena::new(),
            hexcavator_demangle::msvc::Arena::new(),
        );
        let both = hexcavator_demangle::msvc::parse_in(&a1, n);
        let machine = hexcavator_demangle::msvc::parse_slowly_in(&a2, n);
        if both != machine {
            bad += 1;
            if bad < 10 {
                eprintln!("{n}\n  both    {both:?}\n  machine {machine:?}");
            }
        }
    }
    assert!(names.len() > 100_000, "{}", names.len());
    assert_eq!(bad, 0);
}

/// The recursive printer (which writes the first levels of nesting) writes
/// what the printer's machine alone does, under every flag.
#[test]
fn recursive_printer_writes_what_the_machine_writes() {
    let names: Vec<&str> = golden()
        .iter()
        .map(|(n, _, _)| *n)
        .chain(
            include_str!("../data/golden-flags.txt")
                .lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.split('\t').nth(1).unwrap()),
        )
        .collect();
    let mut bad = 0;
    let mut d = Demangler::new();
    for n in &names {
        let Some(sym) = d.parse(n) else { continue };
        for bit in 0..18 {
            let f = if bit == 17 { 0 } else { 1 << bit };
            let (a, b) = (sym.display(f), sym.display_by_machine(f));
            if a != b {
                bad += 1;
                if bad < 10 {
                    eprintln!("{n} {f:#x}\n  recursive {a}\n  machine   {b}");
                }
            }
        }
    }
    assert_eq!(bad, 0);
}

//! The Swift demangler: hermetic checks against `swift-demangle`'s output
//! for the Swift project's test inputs, and robustness on damaged and
//! hostile names.

use std::fmt::Write as _;

use hexcavator_demangle::swift::{Demangler, Options, demangle_symbol_as_string};

/// What `swift-demangle` does with a name: one `_` of a leading `__` goes.
fn tool(name: &str, options: Options) -> String {
    let name = if name.starts_with("__") {
        &name[1..]
    } else {
        name
    };
    demangle_symbol_as_string(name, options)
}

/// The `input ---> output` pairs of a test file.
fn cases(text: &'static str) -> Vec<(&'static str, &'static str)> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split_once(" ---> ").unwrap())
        .collect()
}

fn check(text: &'static str, options: Options, min: usize) {
    let cases = cases(text);
    assert!(cases.len() >= min);
    let mut bad = String::new();
    for (input, want) in &cases {
        let got = tool(input, options);
        if got != *want {
            let _ = writeln!(bad, "{input}\n  want: {want}\n  got:  {got}");
        }
    }
    assert!(bad.is_empty(), "{bad}");
}

#[test]
fn matches_swift_demangle() {
    check(
        include_str!("../data/swift-manglings.txt"),
        Options::swift_demangle(),
        500,
    );
}

#[test]
fn matches_swift_demangle_simplified() {
    check(
        include_str!("../data/swift-simplified-manglings.txt"),
        Options::simplified(),
        200,
    );
}

#[test]
fn matches_swift_demangle_with_clang_types() {
    check(
        include_str!("../data/swift-manglings-with-clang-types.txt"),
        Options::swift_demangle(),
        2,
    );
}

#[test]
fn api() {
    let mut d = Demangler::new();
    let mut out = String::new();
    assert!(d.demangle_into("$sSiN", &mut out));
    assert_eq!(out, "type metadata for Swift.Int");
    // Mach-O's extra underscore.
    out.clear();
    assert!(d.demangle_into("_$sSiN", &mut out));
    assert_eq!(out, "type metadata for Swift.Int");
    out.clear();
    assert!(d.demangle_into("__TtSi", &mut out));
    assert_eq!(out, "Swift.Int");
    // Not Swift names: nothing appended.
    out.clear();
    for name in [
        "",
        "main",
        "_ZN3foo3barEv",
        "?f@@YAXXZ",
        "$s",
        "_T",
        "$sXYZ",
    ] {
        assert!(!d.demangle_into(name, &mut out), "{name}");
        assert!(out.is_empty(), "{name}");
    }
    // The short form.
    assert!(d.demangle_short_into("$s4main3fooyySiF", &mut out));
    assert_eq!(out, "foo(_:)");
    assert_eq!(
        hexcavator_demangle::swift::demangle("$sSaySiGD").as_deref(),
        Some("[Swift.Int]")
    );
    // Through the Itanium demangler, as ELF and Mach-O symbols go.
    let mut it = hexcavator_demangle::itanium::Demangler::new();
    assert_eq!(
        it.demangle("_$sSiN").as_deref(),
        Some("type metadata for Swift.Int")
    );
}

/// Every truncation and many one-byte changes of every test name: no
/// panics, and each name demangles quickly into bounded output.
#[test]
fn damaged_names() {
    let mut d = Demangler::new();
    let mut out = String::new();
    let all: Vec<&str> = cases(include_str!("../data/swift-manglings.txt"))
        .into_iter()
        .chain(cases(include_str!(
            "../data/swift-simplified-manglings.txt"
        )))
        .map(|(i, _)| i)
        .collect();
    let start = std::time::Instant::now();
    let mut n = 0;
    for name in all {
        let b = name.as_bytes();
        let mut variants: Vec<Vec<u8>> = (0..b.len()).map(|i| b[..i].to_vec()).collect();
        for i in 0..b.len() {
            for c in [b'0', b'9', b'_', b'S', b'G', b'y', b'X', b'Q', b'z', 0xFF] {
                let mut v = b.to_vec();
                v[i] = c;
                variants.push(v);
            }
            let mut v = b.to_vec();
            v.insert(i, b[i]);
            variants.push(v);
        }
        for v in variants {
            let s = String::from_utf8_lossy(&v);
            out.clear();
            let _ = d.demangle_into(&s, &mut out);
            assert!(out.len() < 1 << 20);
            let _ = d.demangle_short_into(&s, &mut out);
            n += 1;
        }
    }
    assert!(n > 100_000, "{n}");
    // (Generous: a few microseconds a name in release builds.)
    assert!(start.elapsed().as_secs() < 120, "{:?}", start.elapsed());
}

/// Deeply nested names reach the bounds rather than the stack's end.
#[test]
fn deep_names() {
    let mut d = Demangler::new();
    let mut out = String::new();
    let deep = |prefix: &str, open: &str, middle: &str, close: &str, n: usize| {
        format!("{prefix}{}{middle}{}", open.repeat(n), close.repeat(n))
    };
    for n in [10, 100, 500, 1000, 5000, 50_000] {
        for name in [
            // Optional of Optional of ... Int (new and old manglings).
            deep("$s", "", "Si", "SgSg", n),
            deep("$s", "", "Si", "XSq", n),
            deep("_Tt", "GSq", "Si", "_", n),
            // Tuples, functions, and metatypes in tuples.
            deep("$s", "", "Si", "_tm", n),
            deep("$s", "", "yt", "ycm", n),
            deep("_Tt", "T", "Si", "_", n),
            deep("_Tt", "F", "T_", "T_", n),
            // Nested generic contexts and protocol compositions.
            deep("$s", "", "1a1bV", "1cV", n),
            deep("_Tt", "", "C1a1b", "1c", n),
            deep("_TtP", "", "", "_", n),
        ] {
            out.clear();
            let _ = d.demangle_into(&name, &mut out);
            assert!(out.len() < 1 << 21);
        }
    }
}

/// Substitutions that refer to earlier ones share nodes, so a short name
/// can describe a tree whose printing is exponentially long: the output
/// bound stops it.
#[test]
fn shared_subtrees() {
    let mut d = Demangler::new();
    let mut out = String::new();
    // Each `(A, A)` tuple doubles: `(Int, Int)`, then a pair of those, ...
    for n in [10, 20, 40, 80] {
        let mut name = String::from("$sSi");
        for i in 0..n {
            name.push_str(if i == 0 { "Si_t" } else { "AA_t" });
        }
        name.push('D');
        out.clear();
        let start = std::time::Instant::now();
        let _ = d.demangle_into(&name, &mut out);
        assert!(out.len() <= 1 << 21, "{n}: {}", out.len());
        assert!(start.elapsed().as_secs() < 5, "{n}: {:?}", start.elapsed());
    }
}

/// Trees nested past the levels the printer recurses through on the
/// thread's stack print exactly what printing on the stack alone does,
/// whatever the levels: every name of the corpus (in both forms), damaged
/// ones, and nested ones.
#[test]
fn deep_trees_print_what_recursion_prints() {
    let mut names: Vec<String> = [
        include_str!("../data/swift-manglings.txt"),
        include_str!("../data/swift-simplified-manglings.txt"),
        include_str!("../data/swift-manglings-with-clang-types.txt"),
    ]
    .into_iter()
    .flat_map(cases)
    .map(|(name, _)| name.to_string())
    .collect();
    let mut variants = Vec::new();
    for n in &names {
        let b = n.as_bytes();
        for i in (2..b.len()).step_by(4) {
            variants.push(String::from_utf8_lossy(&b[..i]).into_owned());
            for c in *b"SgyT_" {
                let mut v = b.to_vec();
                v[i] = c;
                variants.push(String::from_utf8_lossy(&v).into_owned());
            }
        }
    }
    names.extend(variants);
    let deep = |prefix: &str, open: &str, middle: &str, close: &str, n: usize| {
        format!("{prefix}{}{middle}{}", open.repeat(n), close.repeat(n))
    };
    for n in [10, 30, 60, 100] {
        names.extend([
            deep("$s", "", "Si", "SgSg", n),
            deep("$s", "", "Si", "XSq", n),
            deep("$s", "", "Si", "_tm", n),
            deep("$s", "", "yt", "ycm", n),
            deep("$s", "", "1a1bV", "1cV", n),
            deep("_Tt", "GSq", "Si", "_", n.min(30)),
            deep("_Tt", "T", "Si", "_", n.min(30)),
        ]);
    }
    let mut d = Demangler::new();
    let mut bad = 0;
    for (i, n) in names.iter().enumerate() {
        let levels = [1, 2, 3, 12][i % 4];
        for options in [Options::swift_demangle(), Options::simplified()] {
            let (mut a, mut b) = (String::new(), String::new());
            let x = d.demangle_with_native_depth(n, options, 768, &mut a);
            let y = d.demangle_with_native_depth(n, options, levels, &mut b);
            if (x, &a) != (y, &b) {
                bad += 1;
                if bad < 10 {
                    eprintln!("{n} (levels {levels})\n  native {a}\n  deep   {b}");
                }
            }
        }
    }
    assert!(names.len() > 20_000, "{}", names.len());
    assert_eq!(bad, 0);
}

//! The Rust demangler: v0 names against llvm-cxxfilt (tests/data/rust-v0.txt,
//! from tools/rust/build.cmd: a corpus program and Hexcavator itself built with
//! the v0 mangling), legacy names by rustc-demangle's rules, and hostile
//! names.

use hexcavator_demangle::rust::{demangle_into, is_rust};

fn demangle(name: &str) -> Option<String> {
    let mut out = String::new();
    demangle_into(name, &mut out).then_some(out)
}

#[test]
fn v0_names_match_llvm() {
    let text = include_str!("../data/rust-v0.txt");
    let mut n = 0;
    let mut failures = Vec::new();
    for line in text.lines() {
        let (mangled, want) = line.split_once('\t').unwrap();
        n += 1;
        assert!(is_rust(mangled), "{mangled}");
        let got = demangle(mangled);
        if got.as_deref() != Some(want) {
            failures.push(format!("{mangled}\n  want {want}\n  got  {got:?}"));
        }
    }
    assert!(n > 10_000, "{n}");
    assert!(
        failures.is_empty(),
        "{} of {n} differ:\n{}",
        failures.len(),
        failures[..failures.len().min(20)].join("\n")
    );
}

#[test]
fn v0_forms() {
    let cases = [
        // Crate roots, nested paths, and special namespaces.
        ("_RNvCs1234_7mycrate3foo", "mycrate::foo"),
        ("_RNvNvC7mycrate3foo3bar", "mycrate::foo::bar"),
        ("_RNCNvC7mycrate3foo0", "mycrate::foo::{closure#0}"),
        ("_RNCNvC7mycrate3foos_0", "mycrate::foo::{closure#1}"),
        (
            "_RNSNvC7mycrate3foo6vtable",
            "mycrate::foo::{shim:vtable#0}",
        ),
        // Mach-O's extra underscore, and the bare `R`.
        ("__RNvC7mycrate3foo", "mycrate::foo"),
        ("RNvC7mycrate3foo", "mycrate::foo"),
        // Generic arguments, and basic types.
        (
            "_RINvC7mycrate3fooahlmxsEB2_",
            "mycrate::foo::<i8, u8, i32, u32, i64, i16>",
        ),
        // Inherent and trait impls.
        ("_RNvMC7mycrateNtB2_3Foo3new", "<mycrate::Foo>::new"),
        (
            "_RNvXC7mycrateNtB2_3FooNtB2_5Trait3run",
            "<mycrate::Foo as mycrate::Trait>::run",
        ),
        (
            "_RNvYNtC7mycrate3FooNtB4_5Trait3run",
            "<mycrate::Foo as mycrate::Trait>::run",
        ),
        // References, pointers, slices, arrays, tuples.
        (
            "_RINvC1a1fRhQhPhOhShAhj4_EB2_",
            "a::f::<&u8, &mut u8, *const u8, *mut u8, [u8], [u8; 4]>",
        ),
        ("_RINvC1a1fTEThETheEEB2_", "a::f::<(), (u8,), (u8, str)>"),
        // Function pointers, unsafe, extern ABIs, and !.
        (
            "_RINvC1a1fFEuFUKCEuFKCEzFhEmEB2_",
            "a::f::<fn(), unsafe extern \"C\" fn(), extern \"C\" fn() -> !, fn(u8) -> u32>",
        ),
        (
            "_RINvC1a1fFK6sysv64EuEB2_",
            "a::f::<extern \"sysv64\" fn()>",
        ),
        (
            "_RINvC1a1fFK9rust_callEuEB2_",
            "a::f::<extern \"rust-call\" fn()>",
        ),
        // dyn traits, with associated types and lifetimes.
        ("_RINvC1a1fDNtB2_5TraitEL_EB2_", "a::f::<dyn a::Trait>"),
        (
            "_RINvC1a1fDNtB2_5Traitp4UnithEL_EB2_",
            "a::f::<dyn a::Trait<Unit = u8>>",
        ),
        // Higher-ranked lifetimes.
        ("_RINvC1a1fFG_RL0_eEuEB2_", "a::f::<for<'a> fn(&'a str)>"),
        // Constants: integers, negative, bool, char, placeholder.
        (
            "_RINvC1a1fKj2a_Kxn1_Kb1_Kc61_KpEB2_",
            "a::f::<42, -1, true, 'a', _>",
        ),
        (
            "_RINvC1a1fKc27_Kc5c_Kca_Kc1f600_EB2_",
            "a::f::<'\\'', '\\\\', '\\n', '\\u{1f600}'>",
        ),
        (
            "_RINvC1a1fKo123456789abcdef0123456789abcdef_EB2_",
            "a::f::<0x123456789abcdef0123456789abcdef>",
        ),
        // Vendor suffixes.
        ("_RNvC7mycrate3foo.llvm.123", "mycrate::foo (.llvm.123)"),
        // Punycode identifiers.
        ("_RNvC7mycrateu9gre_6ka8l", "mycrate::grüße"),
    ];
    for (mangled, want) in cases {
        assert_eq!(demangle(mangled).as_deref(), Some(want), "{mangled}");
    }
}

#[test]
fn legacy_names() {
    let cases = [
        ("_ZN4test1a2bc17h0123456789abcdefE", "test::a::bc"),
        ("_ZN3foo17h05af221e174051e9E", "foo"),
        ("__ZN3foo17h05af221e174051e9E", "foo"),
        ("ZN3foo17h05af221e174051e9E", "foo"),
        // Escapes.
        ("_ZN4$RP$17h0123456789abcdefE", ")"),
        ("_ZN8$RF$test17h0123456789abcdefE", "&test"),
        ("_ZN8$BP$test4foob17h0123456789abcdefE", "*test::foob"),
        ("_ZN9$u20$test4foob17h0123456789abcdefE", " test::foob"),
        (
            "_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$17h0123456789abcdefE",
            "Bar<[u32; 4]>",
        ),
        (
            "_ZN13test$u20$test4foob17h0123456789abcdefE",
            "test test::foob",
        ),
        (
            "_ZN12test$BP$test4foob17h0123456789abcdefE",
            "test*test::foob",
        ),
        (
            "_ZN3std2rt10lang_start28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE",
            "std::rt::lang_start::{{closure}}",
        ),
        (
            "_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3bar17h0123456789abcdefE",
            "<Test + 'static as foo::Bar<Test>>::bar",
        ),
        (
            "_ZN4core3ptr4drop17h0123456789abcdefE.llvm.4BC83ACF",
            "core::ptr::drop",
        ),
        ("_ZN4testE.exit.i.i", ""),
        // A malformed escape is shown as is, from there.
        ("_ZN7a$b$cde17h0123456789abcdefE", "a$b$cde"),
    ];
    for (mangled, want) in cases {
        if want.is_empty() {
            // No hash: not Rust (a C++ name would read the same way).
            assert!(!is_rust(mangled), "{mangled}");
            continue;
        }
        assert!(is_rust(mangled), "{mangled}");
        assert_eq!(demangle(mangled).as_deref(), Some(want), "{mangled}");
    }
    // C++ names are not Rust.
    for cpp in [
        "_ZN3foo3barEv",
        "_ZN3foo3barE",
        "_Z3foov",
        "_ZN3foo17h0123456789abcdefEv",
    ] {
        assert!(!is_rust(cpp), "{cpp}");
    }
}

/// Malformed, truncated, and hostile names fail cleanly; backrefs that
/// multiply output are cut off.
#[test]
fn hostile_names() {
    let text = include_str!("../data/rust-v0.txt");
    for line in text.lines().step_by(97) {
        let mangled = line.split_once('\t').unwrap().0;
        for n in 0..mangled.len() {
            if mangled.is_char_boundary(n) {
                let _ = demangle(&mangled[..n]);
            }
        }
        // Each byte changed to some others.
        let bytes = mangled.as_bytes();
        for i in (0..bytes.len()).step_by(3) {
            for c in *b"B_0IEz" {
                let mut b = bytes.to_vec();
                b[i] = c;
                if let Ok(s) = std::str::from_utf8(&b) {
                    let _ = demangle(s);
                }
            }
        }
    }
    for bad in [
        "_R",
        "_RX",
        "_RNvC",
        "_RC3foo3",
        "_RB_",
        "_RNvB_3foo",
        "_RCu3a_b",
        "_RINvC1a1fKj_EB2_",
        "_RINvC1a1fKb2_EB2_",
        "_RINvC1a1fKc1234567_EB2_",
        "_RINvC1a1fFGzzzzzzzzzzz_EuEB2_",
    ] {
        assert_eq!(demangle(bad), None, "{bad}");
    }
    // Deep nesting stops at the depth limit.
    let deep = format!("_RINvC1a1f{}hEB2_", "R".repeat(100_000));
    assert_eq!(demangle(&deep), None);
    // Generic arguments each a tuple of the one before, twice (by backref):
    // the output doubles with each. A few levels print (as llvm-cxxfilt
    // prints them); forty would be terabytes, and stop at the limit.
    let doubling = |levels: usize| {
        let mut body = String::from("INvC1a1f");
        let mut prev = body.len();
        body.push('h');
        for _ in 0..levels {
            let at = body.len();
            let r = format!("B{}", base62(prev as u64));
            body.push_str(&format!("T{r}{r}E"));
            prev = at;
        }
        format!("_R{body}E")
    };
    assert_eq!(
        demangle(&doubling(2)).as_deref(),
        Some("a::f::<u8, (u8, u8), ((u8, u8), (u8, u8))>")
    );
    assert!(demangle(&doubling(12)).is_some_and(|o| o.len() > 10_000));
    let start = std::time::Instant::now();
    assert_eq!(demangle(&doubling(40)), None);
    assert!(start.elapsed().as_secs() < 5);
}

fn base62(n: u64) -> String {
    if n == 0 {
        return "_".into();
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut v = n - 1;
    let mut s = Vec::new();
    loop {
        s.push(digits[(v % 62) as usize]);
        v /= 62;
        if v == 0 {
            break;
        }
    }
    s.reverse();
    s.push(b'_');
    String::from_utf8(s).unwrap()
}

/// Names nested past the levels the printer recurses through on the
/// thread's stack print exactly what printing on the stack alone does,
/// whatever the levels: every name here, damaged ones, and names nested
/// around the depth limit.
#[test]
fn deep_names_print_what_recursion_prints() {
    use hexcavator_demangle::rust::demangle_with_native_depth;
    let print = |name: &str, levels| {
        let mut out = String::new();
        demangle_with_native_depth(name, &mut out, levels).then_some(out)
    };
    let mut names: Vec<String> = include_str!("../data/rust-v0.txt")
        .lines()
        .map(|l| l.split_once('\t').unwrap().0.to_string())
        .collect();
    let mut variants = Vec::new();
    for n in names.iter().step_by(7) {
        let b = n.as_bytes();
        for i in (2..b.len()).step_by(5) {
            variants.push(String::from_utf8_lossy(&b[..i]).into_owned());
            for c in *b"B_IE" {
                let mut v = b.to_vec();
                v[i] = c;
                variants.push(String::from_utf8_lossy(&v).into_owned());
            }
        }
    }
    names.extend(variants);
    for n in [20, 100, 249, 250, 251, 498, 499, 500, 501] {
        for (prefix, open, middle, close) in [
            ("_RINvC1a1f", "INtC1a1S", "u", "EE"),
            ("_RINvC1a1f", "R", "u", "E"),
            ("_RINvC1a1f", "F", "u", "Eu"),
            ("_RINvC1a1f", "AA", "u", "Kj1_Kj2_"),
        ] {
            names.push(format!(
                "{prefix}{}{middle}{}",
                open.repeat(n),
                close.repeat(n)
            ));
        }
    }
    let mut bad = 0;
    for (i, n) in names.iter().enumerate() {
        let native = print(n, 500);
        let levels = [1, 2, 3, 24][i % 4];
        let deep = print(n, levels);
        if native != deep {
            bad += 1;
            if bad < 10 {
                eprintln!("{n} (levels {levels})\n  native {native:?}\n  deep   {deep:?}");
            }
        }
    }
    assert!(names.len() > 50_000, "{}", names.len());
    assert_eq!(bad, 0);
}

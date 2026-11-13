//! libc++abi's demangler test cases (`tests/data/itanium-cases.inc`, from
//! `libcxxabi/test/DemangleTestCases.inc` of the LLVM Project, under the
//! Apache License v2.0 with LLVM Exceptions; see the crate's `LICENSE-LLVM`), and
//! hostile inputs.
#![allow(clippy::cast_possible_truncation, reason = "test data")]

extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::println;

use super::*;

const CASES: &str = include_str!("../../tests/data/itanium-cases.inc");

/// The `{"mangled", "demangled"}` entries of a C array initializer:
/// string literals unescaped, adjacent ones joined, `//` comments skipped.
fn cases() -> Vec<(String, String)> {
    let b = CASES.as_bytes();
    let mut out = Vec::new();
    let mut entry: Vec<Vec<u8>> = Vec::new();
    let mut in_entry = false;
    let mut joinable = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'{' => {
                in_entry = true;
                entry.clear();
                joinable = false;
            }
            b'}' if in_entry => {
                in_entry = false;
                if entry.len() == 2 {
                    let d = String::from_utf8_lossy(&entry[1]).into_owned();
                    out.push((String::from_utf8_lossy(&entry[0]).into_owned(), d));
                }
            }
            b',' => joinable = false,
            b'"' if in_entry => {
                i += 1;
                let mut s = Vec::new();
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                        match b[i] {
                            b'n' => s.push(b'\n'),
                            b't' => s.push(b'\t'),
                            b'x' => {
                                let mut v = 0u8;
                                while i + 1 < b.len() && b[i + 1].is_ascii_hexdigit() {
                                    i += 1;
                                    v = v
                                        .wrapping_mul(16)
                                        .wrapping_add((b[i] as char).to_digit(16).unwrap() as u8);
                                }
                                s.push(v);
                            }
                            c => s.push(c),
                        }
                    } else {
                        s.push(b[i]);
                    }
                    i += 1;
                }
                if joinable && let Some(last) = entry.last_mut() {
                    last.extend(s);
                } else {
                    entry.push(s);
                }
                joinable = true;
            }
            _ => {}
        }
        i += 1;
    }
    out
}
#[test]
fn matches_libcxxabi() {
    let cases = cases();
    // Every entry of the file (all but a commented-out one).
    assert_eq!(
        cases.len(),
        CASES.lines().filter(|l| l.starts_with("{\"")).count()
    );
    println!("{} cases", cases.len());
    let mut d = Demangler::new();
    let mut failures = Vec::new();
    for (mangled, want) in &cases {
        let got = d.demangle(mangled);
        if got.as_deref() != Some(want.as_str()) {
            failures.push(format!("{mangled}\n  want {want}\n  got  {got:?}"));
        }
    }
    let n = failures.len();
    for f in failures
        .iter()
        .take(if std::env::var_os("HEXC_ALL_FAILURES").is_some() {
            usize::MAX
        } else {
            40
        })
    {
        println!("{f}");
    }
    assert_eq!(n, 0, "{n} of {} cases differ", cases.len());
}

#[test]
fn basics() {
    assert_eq!(demangle("_Z1fv").as_deref(), Some("f()"));
    assert_eq!(demangle("_ZN3foo3barEi").as_deref(), Some("foo::bar(int)"));
    assert_eq!(
        demangle("_ZNKSt6vectorIiSaIiEE4sizeEv").as_deref(),
        Some("std::vector<int, std::allocator<int>>::size() const")
    );
    assert_eq!(demangle("_ZTV3Foo").as_deref(), Some("vtable for Foo"));
    assert_eq!(demangle("_Z3foov.cold").as_deref(), Some("foo() (.cold)"));
    assert_eq!(demangle("i").as_deref(), Some("int"));
    assert_eq!(demangle(""), None);
    assert_eq!(demangle("main"), None);
    assert_eq!(demangle("_Z"), None);
    assert!(is_mangled("_ZN1a1bEv") && is_mangled("__Z1fv") && !is_mangled("main"));
}

#[test]
fn floats() {
    assert_eq!(
        demangle("_ZN5test01gIfEEvRAszplcvT__ELf40a00000E_c").as_deref(),
        Some("void test0::g<float>(char (&) [sizeof ((float)() + 0x1.4p+2f)])")
    );
    assert_eq!(
        demangle("_ZN5test01hIfEEvRAszplcvT__ELd4014000000000000E_c").as_deref(),
        Some("void test0::h<float>(char (&) [sizeof ((float)() + 0x1.4p+2)])")
    );
    assert_eq!(
        demangle("_ZN5test01hIfEEvRAcvjplstT_Le4001a000000000000000E_c").as_deref(),
        Some("void test0::h<float>(char (&) [(unsigned int)(sizeof (float) + 0x1.4p+2L)])")
    );
}

/// The invalid names of libc++abi's tests fail to parse.
#[test]
fn invalid() {
    for name in [
        "_ZIPPreEncode",
        "Agentt",
        "NSoERj5E=Y1[uM:ga",
        "_ZNSt16allocator_traitsISaIN4llvm3sys2fs18directory_iteratorEEE9constructIS3_IS3_EEEDTcl12_S_constructfp_fp0_spcl7forwardIT0_Efp1_EEERS4_PT_DpOS7_",
        "3FooILdaaaaaaaaaaAAAAaaEE",
        "3FooILdaaaaaaaaaaaaaaEE",
        "_ZcvCiIJEEDvT__FFFFT_vT_v",
        "Z1JIJ1_T_EE3o00EUlT_E0",
        "___Z2i_D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D",
        "Z1 Z1 IJEEAcvZcvT_EcvT_T_",
        "T_IZaaIJEEAnaaaT_T__",
        "PT_IJPNT_IJEET_T_T_T_)J)JKE",
        "1 IJEVNT_T_T_EE",
        "AT__ZSiIJEEAnwscT_T__",
        "FSiIJEENT_IoE ",
        "ZTVSiIZTVSiIZTVSiIZTVSiINIJEET_T_T_T_T_ ",
        "Ana_T_E_T_IJEffffffffffffffersfffffrsrsffffffbgE",
        "_ZN3TPLS_E",
        "_ZN3CLSIiEIiEE",
        "_ZN3CLSDtLi0EEE",
        "_ZN3CLSIiEEvNS_T_Ev",
        "_ZN1fIiEEvNTUt_E",
        "_ZNDTUt_Ev",
        "_Z1fIXfLpt1x1yEEvv",
        "_Z1fIXfLdt1x1yEEvv",
        "_ZN1fIXawLi0EEEEvv",
        "_ZNWUt_3FOOEv",
        "_ZWDC3FOOEv",
        "_ZGI3Foo",
        "_ZGIW3Foov",
        "W1x",
    ] {
        assert_eq!(demangle(name), None, "{name}");
    }
}

/// Deep nesting and exponential substitution fail instead of exhausting
/// the stack or memory.
#[test]
fn hostile_inputs() {
    // A long chain of pointers.
    let mut s = String::from("_Z1f");
    for _ in 0..100_000 {
        s.push('P');
    }
    s.push('i');
    assert_eq!(demangle(&s), None);
    // Each parameter a pointer to the previous one: deep only through
    // substitutions.
    let mut s = String::from("_Z1fPi");
    for i in 0..5000 {
        if i == 0 {
            s.push_str("PS_");
        } else {
            s.push_str(&format!("PS{}_", seq_id(i - 1)));
        }
    }
    let _ = demangle(&s);
    // A function type taking itself twice, nested: output doubles.
    let mut s = String::from("_Z1fFvvE");
    for i in 0..40 {
        let prev = if i == 0 {
            String::from("S_")
        } else {
            format!("S{}_", seq_id(i - 1))
        };
        s.push_str(&format!("FvS{0}{0}E", &prev[1..]));
    }
    assert_eq!(demangle(&s), None);
    // Every prefix and single-byte corruption of a real name terminates.
    let real = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm";
    let mut d = Demangler::new();
    for n in 0..real.len() {
        let _ = d.demangle(&real[..n]);
    }
    for i in 0..real.len() {
        for c in *b"S_T0EIZ" {
            let mut b = real.as_bytes().to_vec();
            b[i] = c;
            let _ = d.demangle(core::str::from_utf8(&b).unwrap());
        }
    }
}

/// Parsing a name nested past the levels the parser recurses through on
/// the thread's stack builds exactly the tree parsing on the stack alone
/// does: node for node, whatever the levels (1, which sends every nested
/// call to the parser's driver, up to all of them), on every case and on
/// damaged versions of them.
#[test]
fn deep_parses_build_what_recursion_builds() {
    let mut names: Vec<String> = cases().into_iter().map(|(m, _)| m).collect();
    let mut variants = Vec::new();
    for n in names.iter().step_by(5) {
        let b = n.as_bytes();
        for i in (2..b.len()).step_by(4) {
            variants.push(String::from_utf8_lossy(&b[..i]).into_owned());
            for c in *b"EIS_T" {
                let mut v = b.to_vec();
                v[i] = c;
                variants.push(String::from_utf8_lossy(&v).into_owned());
            }
        }
    }
    names.extend(variants);
    let (mut native, mut deep) = (Demangler::new(), Demangler::new());
    let mut bad = 0;
    let mut parsed = 0;
    for (i, n) in names.iter().enumerate() {
        let a = native.parse_with_native_depth(n, 256);
        let levels = [1, 2, 3][i % 3];
        let b = deep.parse_with_native_depth(n, levels);
        let same = match (&a, &b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.root == b.root
                    && a.nodes == b.nodes
                    && a.meta == b.meta
                    && a.lists == b.lists
                    && a.forward == b.forward
            }
            _ => false,
        };
        parsed += usize::from(a.is_some());
        if !same {
            bad += 1;
            if bad < 10 {
                println!(
                    "{n} (levels {levels}): native {:?}, deep {:?}",
                    a.as_ref().map(|a| a.nodes.len()),
                    b.as_ref().map(|b| b.nodes.len())
                );
            }
        }
        if let Some(a) = a {
            native.recycle(a);
        }
        if let Some(b) = b {
            deep.recycle(b);
        }
    }
    println!("{} names, {parsed} parsed", names.len());
    assert!(names.len() > 100_000);
    assert_eq!(bad, 0);
}

/// Printing a tree nested past the levels the printer recurses through on
/// the thread's stack writes exactly what printing on the stack alone
/// does, in full and short, whatever the levels.
#[test]
fn deep_prints_write_what_recursion_writes() {
    let mut d = Demangler::new();
    let mut bad = 0;
    let mut printed = 0;
    for (i, (n, _)) in cases().iter().enumerate() {
        let Some(ast) = d.parse(n) else { continue };
        let levels = [1, 2, 3][i % 3];
        for short in [false, true] {
            let a = d.print_with_native_depth(&ast, 384, short);
            let b = d.print_with_native_depth(&ast, levels, short);
            printed += usize::from(a.is_some());
            if a != b {
                bad += 1;
                if bad < 10 {
                    println!(
                        "{n} (levels {levels}, short {short})\n  native {a:?}\n  deep   {b:?}"
                    );
                }
            }
        }
        d.recycle(ast);
    }
    println!("{printed} printed");
    assert!(printed > 50_000);
    assert_eq!(bad, 0);
}

/// Names nested around the depth limits demangle (or fail) as they do on
/// the thread's stack alone.
#[test]
fn deep_names_match_recursion_at_the_limits() {
    let shapes = [
        ("_Z1fI1A", "I1A", "i", "EE"),
        ("_Z1f", "PFv", "i", "E"),
        ("_Z1f", "P", "i", ""),
        ("_Z1fIXpl", "pl", "Li1E", "Li1EEEv"),
        ("_Z1fIXcl1g", "cl1g", "Li1E", "EEEv"),
    ];
    let mut d = Demangler::new();
    let mut some = 0;
    for n in [
        20, 47, 48, 49, 50, 100, 127, 128, 129, 200, 254, 255, 256, 257, 300,
    ] {
        for (prefix, open, middle, close) in shapes {
            let name = format!("{prefix}{}{middle}{}", open.repeat(n), close.repeat(n));
            let print = |d: &mut Demangler, parse_levels, print_levels, short| {
                let ast = d.parse_with_native_depth(&name, parse_levels)?;
                let s = d.print_with_native_depth(&ast, print_levels, short);
                d.recycle(ast);
                s
            };
            for short in [false, true] {
                let native = print(&mut d, 256, 384, short);
                some += usize::from(native.is_some());
                for (pl, rl) in [
                    (super::parse::NATIVE_DEPTH, super::print::NATIVE_DEPTH),
                    (5, 5),
                    (13, 7),
                ] {
                    let deep = print(&mut d, pl, rl, short);
                    assert_eq!(native, deep, "{name} levels {pl}/{rl} short {short}");
                }
            }
        }
    }
    assert!(some >= 30, "{some}");
}

fn seq_id(mut n: usize) -> String {
    let mut digits = Vec::new();
    loop {
        let d = (n % 36) as u8;
        digits.push(if d < 10 { b'0' + d } else { b'A' + d - 10 });
        n /= 36;
        if n == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap()
}

/// abseil's short form, on pairs from its tests
/// (`absl/debugging/internal/demangle_test.cc`, Copyright 2018 The Abseil
/// Authors, Apache License 2.0).
#[test]
fn short_form_matches_abseil() {
    for (mangled, want) in [
        ("_Z1fv", "f()"),
        ("_Z1fi", "f()"),
        ("_Z3foo3bar", "foo()"),
        ("_Z1fIiEvi", "f<>()"),
        ("_ZN1N1fE", "N::f"),
        ("_ZN3Foo3BarEv", "Foo::Bar()"),
        ("_ZN3FooC1Ev", "Foo::Foo()"),
        ("_Z1fSs", "f()"),
        ("_Z3fooIiEiT_", "foo<>()"),
        ("_Z3fooI7WrapperIiEEiT_", "foo<>()"),
        ("_ZN2ns1YIiEF1yES1_QLb1E", "ns::Y<>::friend y()"),
        ("_Z3foou17__my_builtin_type", "foo()"),
        (
            "_ZN5FooerIiE3fooIiEEvNS0_UlTL0__TL0_0_E_E",
            "Fooer<>::foo<>()",
        ),
        ("_ZNK3$_0clIiEEDaT_QLb1E", "$_0::operator()<>()"),
        (
            "_ZZ1fIiET_S0_ENKUlTyS0_E_clIiEEDaS0_",
            "f<>()::{lambda()#1}::operator()<>()",
        ),
        ("_ZUt_", "{unnamed type#1}"),
        ("_ZUlvE_", "{lambda()#1}"),
        ("_ZL3Foov.clone.3", "Foo()"),
        ("_ZL3Foov.isra.2.constprop.18", "Foo()"),
        ("_ZZ1fvEN1S1gE_0v", "f()::S::g()"),
        ("_ZZ1fvEN1S1gE__10_v", "f()::S::g()"),
        ("_Z1fILDnEEvv", "f<>()"),
        ("_ZNK1ScvPiEv", "S::operator int*()"),
        ("_ZNK1ScvRiEv", "S::operator int&()"),
        ("_ZNK1ScvPKPKiEv", "S::operator int const* const*()"),
        ("_ZNK1ScvDF16bEv", "S::operator std::bfloat16_t()"),
        ("_ZGR1v_", "reference temporary for v"),
        ("_Z1aB3abc", "a[abi:abc]"),
        ("_ZN1BC2B3xyzEv", "B::B[abi:xyz]()"),
        ("_Z1CB3barB3foov", "C[abi:bar][abi:foo]()"),
        ("_Z1fDv8_i", "f()"),
        ("_Z1fUa9enable_ifIXgefL0p_Li0EEEl", "f()"),
        ("_ZTWN2ns3varE", "thread-local wrapper routine for ns::var"),
        (
            "_ZTHN2ns3varE",
            "thread-local initialization routine for ns::var",
        ),
        ("_Zli4_lity", "operator\"\" _lit()"),
        ("_ZNK1SssERKS_", "S::operator<=>()"),
        (
            "_ZNK2ns9AwaitableawEv",
            "ns::Awaitable::operator co_await()",
        ),
        ("_Z1fIiEDTtlT_EEv", "f<>()"),
        ("_Z1fPFvvOEi", "f()"),
    ] {
        assert_eq!(demangle_short(mangled).as_deref(), Some(want), "{mangled}");
    }
    // Classified: abseil accepts a substitution with template arguments
    // after `sr` (`W<>::f<>()`); LLVM's grammar, which we follow, doesn't.
    assert_eq!(demangle_short("_ZN1WI1SE1fIiEEDTclsrS0_IT_EE1mEEv"), None);
}

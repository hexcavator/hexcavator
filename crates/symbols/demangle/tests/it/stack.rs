//! Hostile nesting doesn't consume the thread's stack: every demangler is
//! run on names nested far past its depth limits, on a thread with a small
//! stack (in debug builds, whose frames are largest). A demangler that
//! recursed on the thread's stack per level of nesting would overflow it
//! (and abort the test process).

use hexcavator_demangle::{itanium, msvc::Demangler, rust, swift};

/// The stack each case runs on.
const STACK: usize = 128 << 10;

/// Runs `f` on a thread with a [`STACK`]-byte stack.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// `open` `n` times, then `middle`, then `close` `n` times.
fn nest(prefix: &str, open: &str, middle: &str, close: &str, n: usize) -> String {
    format!("{prefix}{}{middle}{}", open.repeat(n), close.repeat(n))
}

const DEPTHS: [usize; 4] = [10, 100, 1000, 20_000];

fn names_for(cases: &[(&str, &str, &str, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for &n in &DEPTHS {
        for &(prefix, open, middle, close) in cases {
            out.push(nest(prefix, open, middle, close, n));
        }
    }
    out
}

#[test]
fn msvc() {
    // (Each shape demangles up to the parser's depth limit, which the
    // longer ones pass.)
    let mut names = Vec::new();
    for &n in &[10, 60, 63, 100, 126, 127, 1000, 20_000] {
        for (prefix, open, middle, close, suffix) in [
            // Pointers to functions taking pointers to functions ...
            ("?f@@YAX", "P6AX", "H", "@Z", "@Z"),
            // Templates of templates.
            ("?f@@YAX", "V?$A@", "H", "@@", "@Z"),
            // Pointers to templates of pointers ...
            ("?f@@YAX", "PEAV?$A@", "H", "@@", "@Z"),
            // Pointers to pointers.
            ("?x@@3", "PEA", "H", "", "EA"),
            // Pointers to members.
            ("?f@@YAX", "P8A@@EAAX", "H", "@Z", "@Z"),
        ] {
            names.push(format!(
                "{prefix}{}{middle}{}{suffix}",
                open.repeat(n),
                close.repeat(n)
            ));
        }
    }
    on_small_stack(move || {
        let mut d = Demangler::new();
        for name in &names {
            let _ = d.demangle(name, 0);
        }
    });
}

#[test]
fn itanium() {
    let names = names_for(&[
        // Templates of templates.
        ("_Z1fI1A", "I1A", "i", "EE"),
        // Function pointers taking function pointers.
        ("_Z1f", "PFv", "i", "E"),
        // Pointers.
        ("_Z1f", "P", "i", ""),
        // Nested names.
        ("_ZN", "1a", "1bE", ""),
        // Expressions.
        ("_Z1fIXpl", "pl", "Li1E", "Li1EEEv"),
        // Lambdas' closures in lambdas.
        ("_ZZ1fvE", "UlvE_", "", ""),
    ]);
    on_small_stack(move || {
        let mut d = itanium::Demangler::new();
        for name in &names {
            let _ = d.demangle(name);
            let _ = d.demangle_short(name);
        }
    });
}

#[test]
fn rust_v0_and_legacy() {
    let names = names_for(&[
        // Generic arguments of generic arguments.
        ("_RINvC1a1f", "INtC1a1S", "u", "EE"),
        // References to references.
        ("_RINvC1a1f", "R", "u", "E"),
        // Function pointers taking function pointers.
        ("_RINvC1a1f", "F", "u", "Eu"),
        // Nested paths.
        ("_R", "Nv", "C1a", "1b"),
    ]);
    on_small_stack(move || {
        let mut out = String::new();
        for name in &names {
            out.clear();
            let _ = rust::demangle_into(name, &mut out);
        }
    });
}

#[test]
fn swift_names() {
    let names = names_for(&[
        ("$s", "", "Si", "SgSg"),
        ("$s", "", "Si", "XSq"),
        ("_Tt", "GSq", "Si", "_"),
        ("$s", "", "Si", "_tm"),
        ("$s", "", "yt", "ycm"),
        ("_Tt", "T", "Si", "_"),
        ("_Tt", "F", "T_", "T_"),
        ("$s", "", "1a1bV", "1cV"),
        ("_Tt", "", "C1a1b", "1c"),
        ("_TtP", "", "", "_"),
    ]);
    on_small_stack(move || {
        let mut d = swift::Demangler::new();
        let mut out = String::new();
        for name in &names {
            out.clear();
            let _ = d.demangle_into(name, &mut out);
            let _ = d.demangle_short_into(name, &mut out);
        }
    });
}

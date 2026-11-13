//! Compares `hexcavator_demangle::msvc::demangle` with `undname` outputs:
//!
//!     compare <names.txt> <undname-output.txt> <flags-hex> [max]
//!
//! (`undname <flags> names.txt > output.txt` makes the second file.)

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let names = std::fs::read_to_string(&args[1]).unwrap();
    let expected = std::fs::read_to_string(&args[2]).unwrap();
    let flags = u32::from_str_radix(args[3].trim_start_matches("0x"), 16).unwrap();
    let max: usize = args.get(4).map_or(30, |a| a.parse().unwrap());
    let expected: Vec<&str> = expected.trim_start_matches('\u{feff}').lines().collect();
    let mut demangler = hexcavator_demangle::msvc::Demangler::new();
    let mut bad = 0usize;
    let mut total = 0usize;
    let mut failed = 0usize;
    let mut undname_failed = 0usize;
    let mut anonymous = 0usize;
    let mut variable_templates = 0usize;
    for (name, want) in names.lines().zip(&expected) {
        total += 1;
        let got = demangler.demangle(name, flags);
        if got.is_none() {
            failed += 1;
        }
        let got = got.unwrap_or_else(|| name.to_string());
        // undname cannot read names with `<...>` in them (lambdas, unnamed
        // types): it writes ` ?? ` or leaves decorations in.
        if got != *want && got != name && (want.contains(" ??") || want.contains('@')) {
            undname_failed += 1;
            continue;
        }

        // undname spells a back-referenced anonymous namespace by its tag.
        if got != *want && anonymous_tags(want) == got {
            anonymous += 1;
            continue;
        }
        // undname does not count a variable template's own name as a
        // back-reference, so a reference to it names the type itself
        // (`X<char>::X<char>`).
        // Nor does it in the variable's type, which it then resolves to the
        // wrong name (`struct guid::guid const` for `winrt::guid const`).
        if got != *want && (self_qualified(want) || is_variable_template(name)) {
            variable_templates += 1;
            continue;
        }
        if got != *want {
            bad += 1;
            if bad <= max {
                println!("NAME {name}\nWANT {want}\nGOT  {got}\n");
            }
            // Context around the first difference, for grouping.
            let w: Vec<char> = want.chars().collect();
            let g: Vec<char> = got.chars().collect();
            let i = w.iter().zip(&g).take_while(|(a, b)| a == b).count();
            let ctx = |v: &[char]| -> String {
                v[i.saturating_sub(12)..(i + 12).min(v.len())]
                    .iter()
                    .collect()
            };
            if got == name {
                let at = hexcavator_demangle::msvc::failure_position(name)
                    .unwrap_or(0)
                    .min(name.len());
                let before: String = name[..at]
                    .chars()
                    .rev()
                    .take(6)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let after: String = name[at..].chars().take(6).collect();
                eprintln!("CTX unparsed {before}^{after}");
            } else {
                eprintln!("CTX {} | {}", ctx(&w), ctx(&g));
            }
        }
    }
    println!(
        "{bad} of {total} differ ({failed} not parsed; undname failed on {undname_failed}; anonymous namespace tags {anonymous}; variable templates {variable_templates})"
    );
}

/// Whether `name` is a variable whose own name is a template (`??$x@...`).
fn is_variable_template(name: &str) -> bool {
    let mut d = hexcavator_demangle::msvc::Demangler::new();
    d.parse(name).is_some_and(|s| {
        matches!(
            s.kind,
            hexcavator_demangle::msvc::SymbolKind::Variable { .. }
        ) && matches!(
            s.name.last(),
            Some(hexcavator_demangle::msvc::Name::Template { .. })
        )
    })
}

/// `A0x1234abcd::` back to `` `anonymous namespace'::``.
fn anonymous_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let at_start = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if at_start && s[i..].starts_with("A0x") {
            let hex = s[i + 3..].bytes().take_while(u8::is_ascii_hexdigit).count();
            if hex > 0 && s[i + 3 + hex..].starts_with("::") {
                out.push_str("`anonymous namespace'");
                i += 3 + hex;
                continue;
            }
        }
        out.push(char::from(b[i]));
        i += 1;
    }
    out
}

/// Whether `s` has a component qualified by itself (`X<a>::X<a>` in a
/// type, not a constructor).
fn self_qualified(s: &str) -> bool {
    s.split(['(', ',', ' ']).any(|word| {
        let parts: Vec<&str> = word.split("::").collect();
        parts.windows(2).any(|w| w[0] == w[1] && w[0].contains('<')) && !word.ends_with(')')
    })
}

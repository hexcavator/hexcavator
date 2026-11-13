//! Helpers shared by the dumpbin comparison tests.

#![allow(dead_code)]

/// Parts of dumpbin's output that hexc does not produce yet, or produces
/// differently on purpose. Each is removed from both outputs before comparing.
pub fn normalize(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        // dumpbin writes linker diagnostics (such as LNK4078, for sections
        // that share a name but not attributes) to stdout.
        if line.starts_with("LINK : warning") {
            continue;
        }
        // The path is whatever the caller passed.
        if line.starts_with("Dump of file ") {
            continue;
        }
        let mut line = line.to_string();
        // Dates: dumpbin shows local time; hexc shows UTC.
        if let Some(i) = line.find(" time date stamp") {
            line.truncate(i + " time date stamp".len());
        }
        // Not implemented yet: the entry point's symbol name (from the PDB).
        if line.contains(" entry point (")
            && let Some(i) = line.find(')')
        {
            line.truncate(i + 1);
        }
        strip_symbol(&mut line);
        undecoration_divergence(&mut line);
        // dumpbin cannot disassemble `udf` (hexc follows the architecture).
        if let Some(i) = line.find("; Actual=udf ") {
            line.truncate(i + "; Actual=".len());
        }
        lines.push(line);
    }
    // dumpbin orders same-named summary entries (sections with different
    // attributes) arbitrarily; hexc orders them by attributes. Compare the
    // summary as a sorted list.
    if let Some(start) = lines.iter().position(|l| l == "  Summary") {
        lines[start..].sort();
    }
    lines
}

/// Undecorated names where dumpbin's undecorator is wrong: names it cannot
/// read (it writes ` ?? `), and variable templates, whose own name it does
/// not count as a back-reference. Such names are reduced to the decorated
/// name alone, in both the `name (undecorated)` and the COMDAT
/// `sym= "undecorated" (name)` forms.
fn undecoration_divergence(line: &mut String) {
    let wrong = |decorated: &str, undecorated: &str| {
        undecorated.contains("??") || is_variable_template(decorated)
    };
    if let Some(i) = line.find("COMDAT; sym= \"") {
        let rest = &line[i + 14..];
        if let Some((undecorated, tail)) = rest.split_once("\" (") {
            let decorated = tail.trim_end_matches(')');
            if wrong(decorated, undecorated) {
                *line = format!("{}{decorated}", &line[..i + 13]);
            }
        }
        return;
    }
    if !line.ends_with(')') {
        return;
    }
    let Some(open) = line.find(" (") else { return };
    let start = line[..open].rfind(' ').map_or(0, |s| s + 1);
    let decorated = &line[start..open];
    if decorated.contains('?') && wrong(decorated, &line[open + 2..line.len() - 1]) {
        line.truncate(open);
    }
}

fn is_variable_template(decorated: &str) -> bool {
    let name = decorated.strip_prefix("__imp_").unwrap_or(decorated);
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

/// Not implemented yet: the symbol names (from the PDB) that dumpbin appends
/// to addresses in load config tables and relocations: `<address>  <name>`.
fn strip_symbol(line: &mut String) {
    let bytes = line.as_bytes();
    let Some(i) = (1..bytes.len().saturating_sub(2))
        .rev()
        .find(|&i| bytes[i] == b' ' && bytes[i + 1] == b' ' && bytes[i + 2] != b' ')
    else {
        return;
    };
    let token = line[..i].rsplit(' ').next().unwrap_or("");
    let tail = &line[i + 2..];
    if matches!(token.len(), 8 | 16)
        && token.bytes().all(|b| b.is_ascii_hexdigit())
        && !tail.contains("  ")
    {
        line.truncate(i);
    }
}

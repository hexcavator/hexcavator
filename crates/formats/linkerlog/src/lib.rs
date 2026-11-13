//! What a link's log says: the MSVC linker's `/VERBOSE` output, or the
//! Unix linkers' (see [`unix`]: lld's `--why-extract`, `--why-live`, and
//! `--print-gc-sections`; ld64's `-why_load` and `-why_live`; GNU ld's
//! map and `--print-gc-sections`).
//!
//! MSVC's `/VERBOSE` output (`/VERBOSE:LIB`, `/VERBOSE:REF`,
//! `/VERBOSE:ICF`, and the rest of what `/VERBOSE` prints), as facts:
//!
//! - **Loads**: each library member the linker pulled in, the symbol it
//!   was searched for, and the inputs that referenced that symbol, so
//!   [`LinkerLog::why`] can say why any member is in the image.
//! - **Discards**: what `/OPT:REF` removed, and from which input.
//! - **Folds**: what `/OPT:ICF` folded into what.
//! - The inputs of pass 2 (everything linked), unused libraries, and
//!   default libraries.
//!
//! Inputs are named as the linker names them: `main.obj`, or
//! `LIBCMT.lib(gshandler.obj)` for a library member (library names as
//! given, without their search paths). Lines the parser doesn't know are
//! skipped; damaged logs give fewer facts, never a panic.

#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};

pub mod unix;

/// A symbol as the log names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogSymbol {
    /// The decorated name (or the only name, for C symbols).
    pub name: String,
    /// The undecorated name, if the log gives one.
    pub display: Option<String>,
}

impl LogSymbol {
    /// The name to show: the undecorated one, if any.
    pub fn shown(&self) -> &str {
        self.display.as_deref().unwrap_or(&self.name)
    }
}

/// A symbol in an input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InputSymbol {
    /// The symbol.
    pub symbol: LogSymbol,
    /// The input (an object, or a library member) it is in.
    pub input: String,
}

/// A library search that found a symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Load {
    /// The library searched, as the log gives it (a path).
    pub library: String,
    /// The symbol the search found.
    pub symbol: LogSymbol,
    /// The inputs whose references to the symbol caused the search.
    pub referenced_in: Vec<String>,
    /// The member loaded for it (`lib(member)`); `None` if the log
    /// doesn't say (the member was already loaded, say).
    pub loaded: Option<String>,
}

/// One `/OPT:ICF` fold: the symbol kept and those folded into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fold {
    /// The symbol kept.
    pub selected: InputSymbol,
    /// Those folded into it.
    pub replaced: Vec<InputSymbol>,
}

/// What a `/VERBOSE` log says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkerLog {
    /// The library searches that loaded members, in order.
    pub loads: Vec<Load>,
    /// What `/OPT:REF` discarded.
    pub discarded: Vec<InputSymbol>,
    /// What `/OPT:ICF` folded.
    pub folds: Vec<Fold>,
    /// The inputs pass 2 lists: everything linked, in order.
    pub linked: Vec<String>,
    /// The libraries nothing was loaded from.
    pub unused_libraries: Vec<String>,
    /// `/DEFAULTLIB` directives processed, in order.
    pub default_libraries: Vec<String>,
    /// Why symbols are live (lld's `--why-live`, ld64's `-why_live`):
    /// each symbol, and the chain of what keeps it, nearest first.
    pub live: Vec<Live>,
}

/// Why a symbol is live: what refers to it, then what refers to that, to
/// a root (the entry point, an export).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live {
    /// The symbol, as the linker names it (`file:(symbol)`).
    pub symbol: String,
    /// What keeps it, nearest first (`file:(symbol) (entry point)`).
    pub chain: Vec<String>,
}

/// One step of an explanation of why an input was linked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason<'a> {
    /// The member loaded.
    pub input: &'a str,
    /// The symbol it was loaded for.
    pub symbol: &'a LogSymbol,
    /// The inputs that referenced the symbol.
    pub referenced_in: &'a [String],
}

/// Parses `"undecorated" (decorated)` or a bare name at the start of `s`;
/// returns the symbol and the rest.
fn symbol_at(s: &str) -> Option<(LogSymbol, &str)> {
    if let Some(rest) = s.strip_prefix('"') {
        // The undecorated name can hold quotes (string literals' names
        // don't, but templates over string literals might); the end is
        // the last `" (` before the decorated name.
        let close = rest.find("\" (")?;
        let display = &rest[..close];
        let after = &rest[close + 3..];
        // The decorated name ends at the `)` that balances it.
        let mut depth = 1i32;
        let mut end = None;
        for (i, c) in after.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end?;
        Some((
            LogSymbol {
                name: after[..end].to_string(),
                display: Some(display.to_string()),
            },
            &after[end + 1..],
        ))
    } else {
        let end = s.find(" from ").unwrap_or(s.len());
        let name = s[..end].trim_end();
        (!name.is_empty()).then(|| {
            (
                LogSymbol {
                    name: name.to_string(),
                    display: None,
                },
                &s[end..],
            )
        })
    }
}

/// A `<symbol> from <input>` line's parts.
fn symbol_from(s: &str) -> Option<InputSymbol> {
    let (symbol, rest) = symbol_at(s)?;
    let input = rest.trim_start().strip_prefix("from ")?.trim();
    Some(InputSymbol {
        symbol,
        input: input.to_string(),
    })
}

/// A library's name without its directory.
fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    None,
    Searching,
    Unused,
    Pass2,
    Selected,
    Replaced,
}

/// Parses a log: MSVC's `/VERBOSE` output, or a Unix linker's (see
/// [`unix`]).
pub fn parse(text: &str) -> LinkerLog {
    if unix::looks_unix(text) {
        return unix::parse(text);
    }
    parse_msvc(text)
}

/// Parses MSVC's `/VERBOSE` output.
fn parse_msvc(text: &str) -> LinkerLog {
    let mut log = LinkerLog::default();
    let mut state = State::None;
    let mut library = String::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.is_empty() {
            if matches!(state, State::Replaced | State::Unused) {
                state = State::None;
            }
            continue;
        }
        if indent == 0 {
            // (Directives processed during a library search don't end it.)
            if let Some(lib) = trimmed.strip_prefix("Processed /DEFAULTLIB:") {
                log.default_libraries.push(lib.to_string());
                continue;
            }
            if trimmed.starts_with("Processed ") {
                continue;
            }
            state = match trimmed {
                "Searching libraries" => State::Searching,
                "Unused libraries:" => State::Unused,
                "Starting pass 2" => State::Pass2,
                _ => State::None,
            };
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Discarded ") {
            if let Some(s) = symbol_from(rest) {
                log.discarded.push(s);
            }
            continue;
        }
        if trimmed == "Selected symbol:" {
            state = State::Selected;
            continue;
        }
        if trimmed == "Replaced symbol(s):" {
            state = State::Replaced;
            continue;
        }
        match state {
            State::Searching => {
                if let Some(lib) = trimmed
                    .strip_prefix("Searching ")
                    .and_then(|l| l.strip_suffix(':'))
                {
                    library = lib.to_string();
                } else if let Some(rest) = trimmed.strip_prefix("Found ") {
                    if let Some((symbol, _)) = symbol_at(rest) {
                        log.loads.push(Load {
                            library: library.clone(),
                            symbol,
                            referenced_in: Vec::new(),
                            loaded: None,
                        });
                    }
                } else if let Some(input) = trimmed.strip_prefix("Referenced in ") {
                    if let Some(l) = log.loads.last_mut() {
                        l.referenced_in.push(input.to_string());
                    }
                } else if let Some(member) = trimmed.strip_prefix("Loaded ")
                    && let Some(l) = log.loads.last_mut()
                {
                    l.loaded = Some(member.to_string());
                }
            }
            State::Unused => log.unused_libraries.push(trimmed.to_string()),
            State::Pass2 => log.linked.push(trimmed.to_string()),
            State::Selected => {
                if let Some(s) = symbol_from(trimmed) {
                    log.folds.push(Fold {
                        selected: s,
                        replaced: Vec::new(),
                    });
                }
            }
            State::Replaced => {
                if let (Some(s), Some(f)) = (symbol_from(trimmed), log.folds.last_mut()) {
                    f.replaced.push(s);
                }
            }
            State::None => {}
        }
    }
    log
}

impl LinkerLog {
    /// Why `input` (`lib(member)`, or just `member`) was linked: the chain
    /// of loads from it back to an input given on the command line, each
    /// with the symbol it was loaded for and who referenced it (the first
    /// referrer is followed). Empty if the log doesn't say (the input was
    /// on the command line, or isn't in the log).
    pub fn why(&self, input: &str) -> Vec<Reason<'_>> {
        let by_member: HashMap<&str, &Load> = self
            .loads
            .iter()
            .filter_map(|l| l.loaded.as_deref().map(|m| (m, l)))
            .collect();
        // Accept `member` for `lib(member)`.
        let start = by_member.keys().copied().find(|k| {
            *k == input || member_of(k).eq_ignore_ascii_case(input) || k.eq_ignore_ascii_case(input)
        });
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut current = start;
        while let Some(m) = current {
            if !seen.insert(m) {
                break;
            }
            let Some(load) = by_member.get(m) else { break };
            out.push(Reason {
                input: m,
                symbol: &load.symbol,
                referenced_in: &load.referenced_in,
            });
            current = load
                .referenced_in
                .first()
                .and_then(|r| by_member.get_key_value(r.as_str()).map(|(k, _)| *k));
        }
        out
    }

    /// The members loaded from each library (by its file name), in order.
    pub fn members_by_library(&self) -> Vec<(&str, Vec<&str>)> {
        let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
        for l in &self.loads {
            let Some(m) = l.loaded.as_deref() else {
                continue;
            };
            let lib = file_name(&l.library);
            match out.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(lib)) {
                Some((_, v)) => {
                    if !v.contains(&m) {
                        v.push(m);
                    }
                }
                None => out.push((lib, vec![m])),
            }
        }
        out
    }
}

/// The member of `lib(member)`, or the whole name.
fn member_of(input: &str) -> &str {
    match (input.find('('), input.strip_suffix(')')) {
        (Some(open), Some(body)) => &body[open + 1..],
        _ => input,
    }
}

#[cfg(test)]
mod tests;

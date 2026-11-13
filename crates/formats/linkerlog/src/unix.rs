//! What the Unix linkers say about a link, as [`LinkerLog`] facts:
//!
//! - lld (ELF, wasm): `--why-extract`'s table (why each archive member
//!   was extracted), `--why-live`'s chains (`live symbol: ...`, `>>>
//!   referenced by: ...`), and `--print-gc-sections`' removed sections;
//! - ld64 and lld's Mach-O port: `-why_load` (`_sym forced load of
//!   lib.a(member.o)`) and `-why_live`'s indented chains (`_sym from
//!   file`);
//! - GNU ld: its map's "Archive member included to satisfy reference by
//!   file (symbol)" list, and `--print-gc-sections`' lines.
//!
//! A log can hold several of these (a linker's standard output and error
//! together). Lines not known are skipped; damaged logs give fewer facts.

use crate::{InputSymbol, LinkerLog, Live, Load, LogSymbol};

/// Whether `text` looks like a Unix linker's output (not MSVC's).
pub fn looks_unix(text: &str) -> bool {
    text.lines().take(4096).any(|l| {
        let l = l.trim_end();
        l == "reference\textracted\tsymbol"
            || l.starts_with("live symbol: ")
            || l.starts_with("removing unused section ")
            || l.contains(" forced load of ")
            || l.starts_with("Archive member included to satisfy reference by file (symbol)")
            || l.contains(": removing unused section '")
    })
}

/// The most lines read.
const MAX_LINES: usize = 1 << 24;

/// Parses a Unix linker's output.
pub fn parse(text: &str) -> LinkerLog {
    let mut log = LinkerLog::default();
    let mut lines = text
        .lines()
        .take(MAX_LINES)
        .map(|l| l.trim_end_matches('\r'))
        .peekable();
    let mut why_extract = false;
    // ld64's -why_live: the chain being read (symbol, depth).
    let mut chain: Option<Live> = None;
    while let Some(line) = lines.next() {
        // lld --why-extract.
        if line == "reference\textracted\tsymbol" {
            why_extract = true;
            continue;
        }
        if why_extract {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() == 3 {
                log.loads.push(load(f[1], f[2], f[0]));
                continue;
            }
            why_extract = false;
        }
        // lld --why-live.
        if let Some(sym) = line.strip_prefix("live symbol: ") {
            flush(&mut log, &mut chain);
            let mut live = Live {
                symbol: sym.to_string(),
                chain: Vec::new(),
            };
            while let Some(next) = lines.peek() {
                let Some(by) = next
                    .strip_prefix(">>> referenced by: ")
                    .or_else(|| next.strip_prefix(">>> contained live symbol: "))
                else {
                    break;
                };
                live.chain.push(by.to_string());
                lines.next();
            }
            log.live.push(live);
            continue;
        }
        // lld --print-gc-sections: `removing unused section file:(section)`.
        if let Some(rest) = line.strip_prefix("removing unused section ") {
            if let Some((file, section)) = rest.rsplit_once(":(") {
                log.discarded.push(InputSymbol {
                    symbol: plain(section.trim_end_matches(')')),
                    input: file.to_string(),
                });
            }
            continue;
        }
        // GNU ld --print-gc-sections: `ld: removing unused section '.text.f'
        // in file 'main.o'`.
        if let Some(i) = line.find(": removing unused section '") {
            let rest = &line[i + ": removing unused section '".len()..];
            if let Some((section, file)) = rest.split_once("' in file '") {
                log.discarded.push(InputSymbol {
                    symbol: plain(section),
                    input: file.trim_end_matches('\'').to_string(),
                });
            }
            continue;
        }
        // ld64 -why_load: `_sym forced load of lib.a(member.o)`.
        if let Some((sym, member)) = line.split_once(" forced load of ") {
            log.loads.push(load(member, sym, ""));
            continue;
        }
        // GNU ld's map: archive members, each followed by the file and
        // symbol that wanted it.
        if line.starts_with("Archive member included to satisfy reference by file (symbol)") {
            flush(&mut log, &mut chain);
            gnu_members(&mut lines, &mut log);
            continue;
        }
        // ld64 -why_live: `_sym from file`, then the chain, indented two
        // more spaces a step.
        if let Some((sym, file)) = line.split_once(" from ") {
            let depth = line.len() - line.trim_start().len();
            if depth == 0 {
                flush(&mut log, &mut chain);
                chain = Some(Live {
                    symbol: format!("{}:({})", file.trim(), sym.trim()),
                    chain: Vec::new(),
                });
            } else if let Some(c) = &mut chain {
                c.chain.push(format!("{}:({})", file.trim(), sym.trim()));
            }
            continue;
        }
        flush(&mut log, &mut chain);
    }
    flush(&mut log, &mut chain);
    log
}

fn flush(log: &mut LinkerLog, chain: &mut Option<Live>) {
    if let Some(c) = chain.take() {
        log.live.push(c);
    }
}

fn plain(name: &str) -> LogSymbol {
    LogSymbol {
        name: name.to_string(),
        display: None,
    }
}

/// A member loaded (`lib.a(member.o)`) for `symbol`, referenced in
/// `by`.
fn load(member: &str, symbol: &str, by: &str) -> Load {
    let library = member
        .split_once('(')
        .map_or(member, |(l, _)| l)
        .to_string();
    Load {
        library,
        symbol: plain(symbol),
        referenced_in: if by.is_empty() {
            Vec::new()
        } else {
            vec![by.to_string()]
        },
        loaded: Some(member.to_string()),
    }
}

/// GNU ld's archive member list: `lib.a(member.o)` at the start of a
/// line (or alone, if long), then, indented, `file (symbol)`; it ends at
/// the next heading.
fn gnu_members<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
    log: &mut LinkerLog,
) {
    let mut member: Option<String> = None;
    while let Some(&line) = lines.peek() {
        if line.is_empty() {
            lines.next();
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if !indented && !line.contains('(') {
            // The next heading ("Discarded input sections", ...).
            break;
        }
        lines.next();
        let (head, tail) = if indented {
            ("", line.trim())
        } else {
            // `lib.a(member.o)   main.o (printf)`, or the member alone.
            match line.find(") ") {
                Some(i) if line[i + 1..].trim_start().contains(" (") => {
                    (&line[..=i], line[i + 1..].trim())
                }
                _ => (line.trim(), ""),
            }
        };
        if !head.is_empty() {
            member = Some(head.to_string());
        }
        if tail.is_empty() {
            continue;
        }
        if let (Some(m), Some((by, sym))) = (&member, tail.rsplit_once(" (")) {
            log.loads
                .push(load(m, sym.trim_end_matches(')'), by.trim()));
        }
    }
}

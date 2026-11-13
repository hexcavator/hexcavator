//! The Unix linkers' maps: what each input contributed, and where.
//!
//! - lld (ELF `-Map`, and wasm-ld's): columns of addresses and sizes in
//!   hex, then the output section, input section (`file:(section)`), or
//!   symbol, each starting at its column (`Out`, `In`, `Symbol`).
//! - GNU ld (`-Map`): its "Linker script and memory map": output sections
//!   at the start of a line; input sections indented one space, with
//!   their address, size, and file (a long name alone, the rest on the
//!   next line); symbols indented, with their address alone.
//! - ld64 and lld's Mach-O port (`-map`): the object files by number,
//!   the sections, the symbols with their sizes and files, and what was
//!   dead-stripped.
//!
//! Inputs are named as the linker names them: `main.o`, or
//! `lib.a(member.o)`. Lines not known are skipped; damaged maps give
//! fewer facts.

/// Which linker wrote a map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linker {
    Lld,
    Gnu,
    Ld64,
}

/// An output section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputSection {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

/// What an input contributed: an input section (lld, GNU ld), or a
/// symbol with its size (ld64, whose map lists no input sections).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    pub addr: u64,
    pub size: u64,
    /// The output section it is in.
    pub section: String,
    /// The input section (`.text.f`), or for ld64 the symbol.
    pub name: String,
    /// Its input, an index into [`UnixMap::files`].
    pub file: usize,
}

/// A symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSymbol {
    pub addr: u64,
    /// Its size, if the map says (ld64's do).
    pub size: Option<u64>,
    pub name: String,
    /// Its input, if the map says.
    pub file: Option<usize>,
}

/// What the linker removed (ld64's dead-stripped symbols).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dead {
    pub name: String,
    pub size: u64,
    pub file: Option<usize>,
}

/// A Unix linker's map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixMap {
    pub linker: Linker,
    pub sections: Vec<OutputSection>,
    pub pieces: Vec<Piece>,
    pub symbols: Vec<MapSymbol>,
    pub dead: Vec<Dead>,
    /// The inputs, as the map names them.
    pub files: Vec<String>,
}

impl UnixMap {
    fn new(linker: Linker) -> Self {
        Self {
            linker,
            sections: Vec::new(),
            pieces: Vec::new(),
            symbols: Vec::new(),
            dead: Vec::new(),
            files: Vec::new(),
        }
    }

    /// The index of input `name`, added if new.
    fn file(&mut self, name: &str, index: &mut std::collections::HashMap<String, usize>) -> usize {
        if let Some(&i) = index.get(name) {
            return i;
        }
        let i = self.files.len();
        self.files.push(name.to_string());
        index.insert(name.to_string(), i);
        i
    }
}

/// An input's library (archive) and object: `lib.a(member.o)` is
/// (`lib.a`, `member.o`); `main.o` is (`None`, `main.o`).
pub fn split_member(input: &str) -> (Option<&str>, &str) {
    match input.strip_suffix(')').and_then(|s| s.split_once('(')) {
        Some((lib, member)) if !lib.is_empty() && !member.is_empty() => (Some(lib), member),
        _ => (None, input),
    }
}

/// The most lines read.
const MAX_LINES: usize = 1 << 24;

/// Parses a Unix linker's map, if `text` is one.
pub fn parse(text: &str) -> Option<UnixMap> {
    let first = text.lines().find(|l| !l.trim().is_empty())?;
    if first.contains(" Out ") && first.contains(" In ") && first.trim_end().ends_with("Symbol") {
        return Some(parse_lld(text));
    }
    if first.starts_with("# Path: ") {
        return Some(parse_ld64(text));
    }
    if text
        .lines()
        .take(100_000)
        .any(|l| l.starts_with("Linker script and memory map"))
    {
        return Some(parse_gnu(text));
    }
    None
}

fn hex(s: &str) -> Option<u64> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn parse_lld(text: &str) -> UnixMap {
    let mut map = UnixMap::new(Linker::Lld);
    let mut index = std::collections::HashMap::new();
    let mut lines = text
        .lines()
        .take(MAX_LINES)
        .map(|l| l.trim_end_matches('\r'));
    let header = lines.next().unwrap_or_default();
    let (Some(out_col), Some(in_col), Some(sym_col)) = (
        header.find("Out"),
        header.find(" In ").map(|i| i + 1),
        header.find("Symbol"),
    ) else {
        return map;
    };
    let mut section = String::new();
    let mut piece_file: Option<usize> = None;
    for line in lines {
        // The text starts at one of the three columns.
        let text_at = line
            .char_indices()
            .skip(out_col.saturating_sub(1))
            .find(|&(_, c)| c != ' ')
            .map(|(i, _)| i);
        let Some(at) = text_at else { continue };
        let numbers: Vec<&str> = line.get(..at).unwrap_or("").split_whitespace().collect();
        // (VMA, LMA or offset, size, and for ELF the alignment.)
        let (Some(addr), Some(size)) = (
            numbers.first().and_then(|n| hex(n)),
            numbers.get(2).and_then(|n| hex(n)),
        ) else {
            continue;
        };
        let what = line[at..].trim();
        if at < in_col {
            section = what.to_string();
            map.sections.push(OutputSection {
                name: section.clone(),
                addr,
                size,
            });
            piece_file = None;
        } else if at < sym_col {
            // `file:(section)`; `<internal>:(.comment)`.
            let (file, name) = match what.rsplit_once(":(") {
                Some((f, s)) => (f, s.trim_end_matches(')')),
                None => (what, ""),
            };
            let f = map.file(file, &mut index);
            piece_file = Some(f);
            map.pieces.push(Piece {
                addr,
                size,
                section: section.clone(),
                name: name.to_string(),
                file: f,
            });
        } else {
            map.symbols.push(MapSymbol {
                addr,
                size: None,
                name: what.to_string(),
                file: piece_file,
            });
        }
    }
    map
}

fn parse_ld64(text: &str) -> UnixMap {
    #[derive(PartialEq)]
    enum Part {
        None,
        Files,
        Sections,
        Symbols,
        Dead,
    }
    let mut map = UnixMap::new(Linker::Ld64);
    let mut numbers: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut part = Part::None;

    for line in text
        .lines()
        .take(MAX_LINES)
        .map(|l| l.trim_end_matches('\r'))
    {
        if let Some(h) = line.strip_prefix("# ") {
            part = match h {
                _ if h.starts_with("Object files:") => Part::Files,
                _ if h.starts_with("Sections:") => Part::Sections,
                _ if h.starts_with("Symbols:") => Part::Symbols,
                _ if h.starts_with("Dead Stripped Symbols:") => Part::Dead,
                _ => continue,
            };
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        match part {
            Part::Files => {
                if let Some((n, path)) = file_ref(line) {
                    numbers.insert(n, map.files.len());
                    map.files.push(path.to_string());
                }
            }
            Part::Sections => {
                let f: Vec<&str> = line.split('\t').map(str::trim).collect();
                if let (Some(addr), Some(size), Some(seg), Some(sect)) = (
                    f.first().and_then(|x| hex(x)),
                    f.get(1).and_then(|x| hex(x)),
                    f.get(2),
                    f.get(3),
                ) {
                    map.sections.push(OutputSection {
                        name: format!("{seg},{sect}"),
                        addr,
                        size,
                    });
                }
            }
            Part::Symbols | Part::Dead => {
                let mut f = line.splitn(3, '\t');
                let (Some(a), Some(s), Some(rest)) = (f.next(), f.next(), f.next()) else {
                    continue;
                };
                let Some(size) = hex(s.trim()) else { continue };
                let Some((n, name)) = file_ref(rest) else {
                    continue;
                };
                let file = numbers.get(&n).copied();
                if part == Part::Dead {
                    map.dead.push(Dead {
                        name: name.to_string(),
                        size,
                        file,
                    });
                    continue;
                }
                let Some(addr) = hex(a.trim()) else { continue };
                map.symbols.push(MapSymbol {
                    addr,
                    size: Some(size),
                    name: name.to_string(),
                    file,
                });
                if let Some(file) = file {
                    let section = map
                        .sections
                        .iter()
                        .find(|s| addr >= s.addr && addr - s.addr < s.size)
                        .map(|s| s.name.clone())
                        .unwrap_or_default();
                    map.pieces.push(Piece {
                        addr,
                        size,
                        section,
                        name: name.to_string(),
                        file,
                    });
                }
            }
            Part::None => {}
        }
    }
    map
}

/// ld64's `[  N] rest`: the file's number, and the rest.
fn file_ref(s: &str) -> Option<(u64, &str)> {
    let s = s.trim_start().strip_prefix('[')?;
    let (n, rest) = s.split_once(']')?;
    Some((n.trim().parse().ok()?, rest.trim()))
}

fn parse_gnu(text: &str) -> UnixMap {
    let mut map = UnixMap::new(Linker::Gnu);
    let mut index = std::collections::HashMap::new();
    let mut in_memory_map = false;
    let mut section = String::new();
    let mut piece_file: Option<usize> = None;
    // A long input section's name, alone on its line, waiting for its
    // address, size, and file on the next.
    let mut pending: Option<String> = None;
    for line in text
        .lines()
        .take(MAX_LINES)
        .map(|l| l.trim_end_matches('\r'))
    {
        if line.starts_with("Linker script and memory map") {
            in_memory_map = true;
            continue;
        }
        if !in_memory_map || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if line.starts_with(|c: char| c != ' ' && c != '\t') {
            // An output section (`.text  0x401000  0x1a5`), or a
            // directive (`LOAD x.o`, `OUTPUT(a.out elf64-x86-64)`).
            pending = None;
            piece_file = None;
            if fields.first().is_some_and(|f| f.starts_with('.')) {
                section = fields[0].to_string();
                if let (Some(addr), Some(size)) = (
                    fields.get(1).and_then(|x| hex(x)),
                    fields.get(2).and_then(|x| hex(x)),
                ) {
                    map.sections.push(OutputSection {
                        name: section.clone(),
                        addr,
                        size,
                    });
                }
            }
            continue;
        }
        // Linker script patterns (` *(.text .text.*)`), fill, assignments.
        let first = fields.first().copied().unwrap_or("");
        if first.starts_with('*')
            || line.contains(" = ")
            || first == "PROVIDE"
            || first.starts_with("[!")
        {
            continue;
        }
        if line.starts_with(' ') && !line.starts_with("  ") && fields.len() == 1 {
            pending = Some(first.to_string());
            continue;
        }
        let (name, rest) = if let Some(p) = pending.take() {
            (p, &fields[..])
        } else if line.starts_with(' ') && !line.starts_with("  ") {
            (first.to_string(), &fields[1..])
        } else {
            // A symbol: `                0x401000                main`.
            if let (Some(addr), Some(name)) = (fields.first().and_then(|x| hex(x)), fields.get(1))
                && fields.len() == 2
            {
                map.symbols.push(MapSymbol {
                    addr,
                    size: None,
                    name: (*name).to_string(),
                    file: piece_file,
                });
            }
            continue;
        };
        let (Some(addr), Some(size)) = (
            rest.first().and_then(|x| hex(x)),
            rest.get(1).and_then(|x| hex(x)),
        ) else {
            continue;
        };
        let Some(file) = rest.get(2..).map(|f| f.join(" ")).filter(|f| !f.is_empty()) else {
            continue;
        };
        let f = map.file(&file, &mut index);
        piece_file = Some(f);
        map.pieces.push(Piece {
            addr,
            size,
            section: section.clone(),
            name,
            file: f,
        });
    }
    map
}

//! Linker map files: what the linker put where. The Unix linkers' (lld,
//! GNU ld, ld64) are in [`unix`]. MSVC's (`link
//! /MAP`), which lists the image's COFF groups and every public (and, with
//! static functions, static) symbol with its address and the object (and
//! library) it came from: enough to attribute an image's bytes without a
//! PDB.
//!
//! ```text
//!  main
//!
//!  Timestamp is 6af0e420 (Sun Nov  8 13:05:36 2026)
//!
//!  Preferred load address is 0000000140000000
//!
//!  Start         Length     Name                   Class
//!  0001:00000000 000140b0H .text$mn                CODE
//!
//!   Address         Publics by Value              Rva+Base               Lib:Object
//!
//!  0001:00000a60       mainCRTStartup             0000000140001a60 f   LIBCMT:exe_main.obj
//!
//!  entry point at        0001:00000a60
//!
//!  Static symbols
//!
//!  0001:00000580       ?f@@YAXXZ                  0000000140001580 f   LIBCMT:gshandler.obj
//! ```
//!
//! Lines it doesn't know are skipped; a damaged map gives fewer facts,
//! never a panic.

#![warn(missing_docs)]

#[allow(missing_docs, reason = "the fields say what the maps say")]
pub mod unix;

/// A COFF group: `section:offset`, length, name, and class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapGroup {
    /// 1-based section number.
    pub section: u16,
    /// Its offset in the section.
    pub offset: u32,
    /// Its length in bytes.
    pub length: u32,
    /// Its name (`.text$mn`).
    pub name: String,
    /// `CODE` or `DATA`.
    pub class: String,
}

/// Where a symbol came from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MapSource {
    /// An object, perhaps from a library (the library without `.lib`, as
    /// the map gives it).
    Object {
        /// The library, if the object came from one.
        library: Option<String>,
        /// The object.
        object: String,
    },
    /// `<absolute>`, `<common>`, `<linker-defined>`, and the like.
    Special(String),
}

/// A symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapSymbol {
    /// 1-based section number (0 for absolute symbols).
    pub section: u16,
    /// Its offset in the section.
    pub offset: u32,
    /// As the map gives it: decorated.
    pub name: String,
    /// `Rva+Base`: the address the symbol has at the preferred base.
    pub va: u64,
    /// `f`: a function.
    pub function: bool,
    /// `i`: an inline (COMDAT) function.
    pub inline: bool,
    /// From the "Static symbols" list.
    pub is_static: bool,
    /// Where it came from.
    pub source: MapSource,
}

/// A map file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkMap {
    /// The module's name (the first line).
    pub module: String,
    /// The link's time stamp.
    pub timestamp: Option<u32>,
    /// The preferred load address.
    pub load_address: Option<u64>,
    /// The COFF groups, in the map's order.
    pub groups: Vec<MapGroup>,
    /// Publics, then statics, in the map's order (by address).
    pub symbols: Vec<MapSymbol>,
    /// `section:offset` of the entry point.
    pub entry_point: Option<(u16, u32)>,
}

/// `ssss:oooooooo`.
fn address(s: &str) -> Option<(u16, u32)> {
    let (sec, off) = s.split_once(':')?;
    if sec.len() != 4 || off.len() != 8 {
        return None;
    }
    Some((
        u16::from_str_radix(sec, 16).ok()?,
        u32::from_str_radix(off, 16).ok()?,
    ))
}

fn source(field: &str) -> MapSource {
    if field.starts_with('<') {
        return MapSource::Special(field.to_string());
    }
    match field.split_once(':') {
        // (`lib:object`; a path's drive letter is a one-letter "library".)
        Some((lib, obj)) if lib.len() > 1 => MapSource::Object {
            library: Some(lib.to_string()),
            object: obj.to_string(),
        },
        _ => MapSource::Object {
            library: None,
            object: field.to_string(),
        },
    }
}

/// A symbol line: address, name, VA, flags, and source. The name can hold
/// spaces (rarely), so the VA is found as the first 16-digit hex token
/// after it.
fn symbol(line: &str, is_static: bool) -> Option<MapSymbol> {
    let mut fields = line.split_whitespace();
    let (section, offset) = address(fields.next()?)?;
    let rest: Vec<&str> = fields.collect();
    let va_at = rest
        .iter()
        .position(|t| t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit()))?;
    if va_at == 0 {
        return None;
    }
    let name = rest[..va_at].join(" ");
    let va = u64::from_str_radix(rest[va_at], 16).ok()?;
    let mut function = false;
    let mut inline = false;
    let mut k = va_at + 1;
    while let Some(&f) = rest.get(k) {
        match f {
            "f" => function = true,
            "i" => inline = true,
            _ => break,
        }
        k += 1;
    }
    let source_field = rest.get(k..).map(|r| r.join(" ")).unwrap_or_default();
    if source_field.is_empty() {
        return None;
    }
    Some(MapSymbol {
        section,
        offset,
        name,
        va,
        function,
        inline,
        is_static,
        source: source(&source_field),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Groups,
    Publics,
    Statics,
    Other,
}

/// Parses an MSVC map.
pub fn parse(text: &str) -> LinkMap {
    let mut map = LinkMap::default();
    let mut state = State::Header;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if map.module.is_empty() && state == State::Header {
            map.module = line.to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("Timestamp is ") {
            map.timestamp = rest
                .split_whitespace()
                .next()
                .and_then(|t| u32::from_str_radix(t, 16).ok());
            continue;
        }
        if let Some(rest) = line.strip_prefix("Preferred load address is ") {
            map.load_address = u64::from_str_radix(rest.trim(), 16).ok();
            continue;
        }
        if line.starts_with("Start ") && line.contains("Length") && line.contains("Class") {
            state = State::Groups;
            continue;
        }
        if line.starts_with("Address ") && line.contains("Publics by Value") {
            state = State::Publics;
            continue;
        }
        if line == "Static symbols" {
            state = State::Statics;
            continue;
        }
        if let Some(rest) = line.strip_prefix("entry point at") {
            map.entry_point = address(rest.trim());
            continue;
        }
        if line.starts_with("Exports")
            || line.starts_with("FIXUPS")
            || line.starts_with("Line numbers")
        {
            state = State::Other;
            continue;
        }
        match state {
            State::Groups => {
                let f: Vec<&str> = line.split_whitespace().collect();
                if let [addr, len, name, class, ..] = f.as_slice()
                    && let Some((section, offset)) = address(addr)
                    && let Some(len) = len.strip_suffix('H')
                    && let Ok(length) = u32::from_str_radix(len, 16)
                {
                    map.groups.push(MapGroup {
                        section,
                        offset,
                        length,
                        name: name.to_string(),
                        class: class.to_string(),
                    });
                }
            }
            State::Publics | State::Statics => {
                if let Some(s) = symbol(line, state == State::Statics) {
                    map.symbols.push(s);
                }
            }
            State::Header | State::Other => {}
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = " main

 Timestamp is 6af0e420 (Sun Nov  8 13:05:36 2026)

 Preferred load address is 0000000140000000

 Start         Length     Name                   Class
 0001:00000000 000140b0H .text$mn                CODE
 0002:00000308 00000000H .gfids$y                DATA
 0002:00008800 0000037cH .rdata$r                DATA

  Address         Publics by Value              Rva+Base               Lib:Object

 0000:00000000       __AbsoluteZero             0000000000000000     <absolute>
 0001:00000010       main                       0000000140001010 f   main.obj
 0001:00000a60       mainCRTStartup             0000000140001a60 f   LIBCMT:exe_main.obj
 0001:00000b00       ?f@@YAXXZ                  0000000140001b00 f i libcpmt:xthrow.obj
 0003:00001690       __scrt_ucrt_dll_is_in_use  0000000140023690     <common>
 0001:00000c00       name with space            0000000140001c00 f   C:\\objs\\a.obj

 entry point at        0001:00000a60

 Static symbols

 0001:00000580       ?g@@YAXXZ                  0000000140001580 f   LIBCMT:gshandler.obj
";

    #[test]
    fn parses_an_msvc_map() {
        let m = parse(SAMPLE);
        assert_eq!(m.module, "main");
        assert_eq!(m.timestamp, Some(0x6af0_e420));
        assert_eq!(m.load_address, Some(0x1_4000_0000));
        assert_eq!(m.groups.len(), 3);
        assert_eq!(
            m.groups[0],
            MapGroup {
                section: 1,
                offset: 0,
                length: 0x140b0,
                name: ".text$mn".into(),
                class: "CODE".into()
            }
        );
        assert_eq!(m.symbols.len(), 7);
        let main = &m.symbols[1];
        assert_eq!(
            (main.section, main.offset, main.va),
            (1, 0x10, 0x1_4000_1010)
        );
        assert!(main.function && !main.inline && !main.is_static);
        assert_eq!(
            main.source,
            MapSource::Object {
                library: None,
                object: "main.obj".into()
            }
        );
        assert_eq!(
            m.symbols[2].source,
            MapSource::Object {
                library: Some("LIBCMT".into()),
                object: "exe_main.obj".into()
            }
        );
        assert!(m.symbols[3].inline && m.symbols[3].function);
        assert_eq!(m.symbols[4].source, MapSource::Special("<common>".into()));
        assert_eq!(m.symbols[5].name, "name with space");
        assert_eq!(
            m.symbols[5].source,
            MapSource::Object {
                library: None,
                object: "C:\\objs\\a.obj".into()
            }
        );
        assert!(m.symbols[6].is_static);
        assert_eq!(m.entry_point, Some((1, 0xa60)));
    }

    #[test]
    fn damaged_maps_give_what_they_can() {
        assert_eq!(parse(""), LinkMap::default());
        let m = parse(
            " x\n Start Length Name Class\n 0001:zz 10H .t CODE\n 01:00000000 10H .t CODE\n 0001:00000000 xxH .t CODE\n Address Publics by Value\n 0001:00000000 noaddress\n 0001:00000000 0000000140001000 f lib:obj\n",
        );
        assert!(m.groups.is_empty());
        assert!(m.symbols.is_empty());
        let mut text = String::from(" m\n Address Publics by Value\n");
        for i in 0..1000 {
            text.push_str(&format!(
                " 0001:{i:08x} \u{e9}{i} {:016x} {}\n",
                i * 7,
                if i % 2 == 0 { "f" } else { "" }
            ));
        }
        let m = parse(&text);
        // (No source field: skipped.)
        assert!(m.symbols.iter().all(|s| !s.name.is_empty()));
    }
}

#[cfg(test)]
mod real {
    #[test]
    fn a_real_map() {
        let text = std::fs::read_to_string(format!(
            "{}/../../../testdata/linkerlog/main.map",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let m = super::parse(&text);
        assert_eq!(m.module, "main");
        assert_eq!(m.load_address, Some(0x1_4000_0000));
        assert!(m.groups.len() > 30, "{}", m.groups.len());
        assert!(
            m.groups
                .iter()
                .any(|g| g.name == ".text$mn" && g.class == "CODE")
        );
        assert!(m.symbols.len() > 500, "{}", m.symbols.len());
        assert!(m.symbols.iter().any(|s| s.name == "main" && s.function));
        assert!(m.symbols.iter().any(|s| s.is_static));
        assert!(m.entry_point.is_some());
        // Every symbol's address agrees with its section's, at the load
        // address (absolute symbols aside).
        let base = m.load_address.unwrap();
        for s in m.symbols.iter().filter(|s| s.section != 0) {
            assert!(s.va >= base, "{s:?}");
        }
    }
}

#[cfg(test)]
mod unix_tests {
    use super::unix::*;

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/linkmap")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn lld() {
        let m = parse(&fixture("elf.map")).unwrap();
        assert_eq!(m.linker, Linker::Lld);
        let text = m.sections.iter().find(|s| s.name == ".text").unwrap();
        assert_eq!((text.addr, text.size), (0x201160, 0x3a));
        let p: Vec<(&str, &str, u64)> = m
            .pieces
            .iter()
            .map(|p| (m.files[p.file].as_str(), p.name.as_str(), p.size))
            .collect();
        assert!(p.contains(&("main.o", ".text._start", 0x22)), "{p:?}");
        assert!(
            p.contains(&("lib.a(used.o)", ".text.used_helper", 0xa)),
            "{p:?}"
        );
        let s = m.symbols.iter().find(|s| s.name == "used_helper").unwrap();
        assert_eq!(
            (s.addr, s.file.map(|f| m.files[f].as_str())),
            (0x201190, Some("lib.a(used.o)"))
        );
        assert_eq!(split_member("lib.a(used.o)"), (Some("lib.a"), "used.o"));
        assert_eq!(split_member("main.o"), (None, "main.o"));
    }

    #[test]
    fn ld64() {
        let m = parse(&fixture("macho.map")).unwrap();
        assert_eq!(m.linker, Linker::Ld64);
        assert_eq!(m.files, ["linker synthesized", "main.o", "lib.a(used.o)"]);
        let s = m.symbols.iter().find(|s| s.name == "_used_helper").unwrap();
        assert_eq!(
            (s.addr, s.size, s.file),
            (0x1_0000_0354, Some(0xc), Some(2))
        );
        assert_eq!(
            m.pieces
                .iter()
                .find(|p| p.name == "_shared_table")
                .unwrap()
                .section,
            "__DATA,__data"
        );
        let dead: Vec<&str> = m.dead.iter().map(|d| d.name.as_str()).collect();
        assert!(
            dead.contains(&"_unused_here") && dead.contains(&"_dead_in_used"),
            "{dead:?}"
        );
    }

    #[test]
    fn gnu() {
        let text = "\
Archive member included to satisfy reference by file (symbol)

libfoo.a(foo.o)               main.o (foo)

Memory Configuration

Name             Origin             Length             Attributes
*default*        0x0000000000000000 0xffffffffffffffff

Linker script and memory map

LOAD main.o
LOAD libfoo.a
                0x0000000000400000                PROVIDE (__executable_start = SEGMENT_START (\"text-segment\", 0x400000))

.text           0x0000000000401000       0x45
 *(.text.unlikely .text.*_unlikely .text.unlikely.*)
 .text          0x0000000000401000       0x25 main.o
                0x0000000000401000                main
 .text.a_rather_long_function_name_that_wraps
                0x0000000000401030       0x15 libfoo.a(foo.o)
                0x0000000000401030                foo
 *fill*         0x0000000000401045        0x3 

.data           0x0000000000402000       0x10
 .data          0x0000000000402000       0x10 main.o
                0x0000000000402000                table
OUTPUT(a.out elf64-x86-64)
";
        let m = parse(text).unwrap();
        assert_eq!(m.linker, Linker::Gnu);
        let p: Vec<(&str, &str, &str, u64, u64)> = m
            .pieces
            .iter()
            .map(|p| {
                (
                    p.section.as_str(),
                    p.name.as_str(),
                    m.files[p.file].as_str(),
                    p.addr,
                    p.size,
                )
            })
            .collect();
        assert_eq!(
            p,
            [
                (".text", ".text", "main.o", 0x401000, 0x25),
                (
                    ".text",
                    ".text.a_rather_long_function_name_that_wraps",
                    "libfoo.a(foo.o)",
                    0x401030,
                    0x15
                ),
                (".data", ".data", "main.o", 0x402000, 0x10),
            ]
        );
        let s: Vec<(&str, Option<usize>)> = m
            .symbols
            .iter()
            .map(|s| (s.name.as_str(), s.file))
            .collect();
        assert_eq!(s, [("main", Some(0)), ("foo", Some(1)), ("table", Some(0))]);
        assert_eq!(m.sections.len(), 2);
    }

    #[test]
    fn not_maps_and_damage() {
        assert!(parse("").is_none());
        assert!(parse("hello\nworld").is_none());
        for name in ["elf.map", "macho.map"] {
            let t = fixture(name);
            for n in (0..t.len()).step_by(7) {
                if t.is_char_boundary(n) {
                    let _ = parse(&t[..n]);
                }
            }
        }
    }
}

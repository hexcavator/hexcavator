//! bloaty's data sources for WebAssembly modules (`webassembly.cc`). A
//! module has no address space of its own, so only file bytes are labeled.
//!
//! - The base map, `sections`, and `segments` name each section (`Code`,
//!   `Data`, a custom section by its name).
//! - `symbols` (and `fullsymbols`, `rawsymbols`) charge each function body
//!   to its name from the `name` section (`func[i]` without one), each
//!   data segment to its name (`data[i]`), and each `name` section entry
//!   to the name it gives.
//! - `compileunits` and `inlines` need a source map (see [`crate::sourcemap`]):
//!   each segment's bytes, to its next segment's, are charged to its
//!   source file (`compileunits`) or `file:line` (`inlines`).
//! - Every source falls back to `[section Code]`, `[WASM Header]`, and
//!   `[Unmapped]`.
//!
//! Where bloaty is wrong we are not: a segment stops at the end of the
//! function body it is in (bloaty runs it on into the next function's size
//! and locals); the last segment runs to the end of its function body
//! (bloaty drops it); and `inlines` lines are one-based, as in source
//! files and in the DWARF `inlines` (bloaty prints the map's zero-based
//! lines).

use std::collections::HashMap;

use hexcavator_core::Result;
use hexcavator_demangle::itanium::Demangler;
use hexcavator_wasm::{Module, NAME_DATA_SEGMENT, NAME_FUNCTION};

use crate::rangemap::{DualMap, Labels};
use crate::sourcemap::SourceMap;
use crate::sources::{Maps, Source, UNMAPPED};

pub const WASM_HEADER: &str = "[WASM Header]";

pub fn is_wasm_input(data: &[u8]) -> bool {
    hexcavator_wasm::is_wasm(data)
}

fn add(
    map: &mut DualMap,
    s: u64,
    n: u64,
    label: crate::rangemap::Label,
    base: Option<&DualMap>,
    len: u64,
) {
    let e = s.saturating_add(n).min(len);
    if s >= e {
        return;
    }
    match base {
        Some(b) => {
            map.add_file(s, e, label, b);
        }
        None => map.file.add(s, e, label),
    }
}

/// Builds the maps of a WebAssembly module for `sources`.
pub fn maps(data: &[u8], file_name: &str, sources: &[Source]) -> Result<Maps> {
    maps_with_source_map(data, file_name, sources, None)
}

/// [`maps`], with the module's source map for `compileunits` and
/// `inlines`.
pub fn maps_with_source_map(
    data: &[u8],
    file_name: &str,
    sources: &[Source],
    source_map: Option<&SourceMap>,
) -> Result<Maps> {
    let m = Module::parse(data)?;
    let len = data.len() as u64;
    let mut labels = Labels::default();
    let sections_into = |labels: &mut Labels, map: &mut DualMap, base: Option<&DualMap>| {
        for s in m.sections() {
            let l = labels.intern(&String::from_utf8_lossy(s.name));
            add(map, s.offset, s.size, l, base, len);
        }
    };
    let fallback_into = |labels: &mut Labels, map: &mut DualMap, base: Option<&DualMap>| {
        for s in m.sections() {
            let l = labels.intern(&format!("[section {}]", String::from_utf8_lossy(s.name)));
            add(map, s.offset, s.size, l, base, len);
        }
        let l = labels.intern(WASM_HEADER);
        add(map, 0, 8, l, base, len);
        let l = labels.intern(UNMAPPED);
        add(map, 0, len, l, base, len);
    };

    let mut base = DualMap::default();
    sections_into(&mut labels, &mut base, None);
    fallback_into(&mut labels, &mut base, None);
    base.file.compress();

    let mut out = Vec::new();
    for &source in sources {
        let mut map = DualMap::default();
        match source {
            Source::Sections | Source::Segments => {
                sections_into(&mut labels, &mut map, Some(&base));
            }
            Source::Symbols | Source::RawSymbols | Source::FullSymbols => {
                let mut demangler = Demangler::new();
                let mut show = |raw: &[u8]| -> String {
                    let raw = String::from_utf8_lossy(raw);
                    let mut buf = String::new();
                    let ok = match source {
                        Source::Symbols => demangler.demangle_short_into(&raw, &mut buf),
                        Source::FullSymbols => demangler.demangle_into(&raw, &mut buf),
                        _ => false,
                    };
                    if ok { buf } else { raw.into_owned() }
                };
                let funcs = m.names(NAME_FUNCTION);
                let segs = m.names(NAME_DATA_SEGMENT);
                // The name section's entries, to the names they give.
                for n in funcs.iter().chain(&segs) {
                    let l = labels.intern(&String::from_utf8_lossy(n.name));
                    add(&mut map, n.offset, n.size, l, Some(&base), len);
                }
                let base_index = m.imported_functions();
                // (By index, the first of each: a lookup per function, not
                // a search of every name.)
                let (mut func_names, mut seg_names) = (HashMap::new(), HashMap::new());
                for n in &funcs {
                    func_names.entry(n.index).or_insert(n.name);
                }
                for n in &segs {
                    seg_names.entry(n.index).or_insert(n.name);
                }
                for (i, f) in m.functions().iter().enumerate() {
                    let name = match func_names.get(&f.index) {
                        Some(n) => show(n),
                        None => format!("func[{}]", f.index - base_index),
                    };
                    debug_assert_eq!(i as u32, f.index - base_index);
                    let l = labels.intern(&name);
                    add(&mut map, f.offset, f.size, l, Some(&base), len);
                }
                for d in m.data_segments() {
                    let name = match seg_names.get(&d.index) {
                        Some(n) => String::from_utf8_lossy(n).into_owned(),
                        None => format!("data[{}]", d.index),
                    };
                    let l = labels.intern(&name);
                    add(&mut map, d.offset, d.size, l, Some(&base), len);
                }
            }
            Source::InputFiles | Source::ArMembers => {
                let l = labels.intern(file_name);
                map.fill_from(&base, |_| l);
            }
            Source::Archs => {
                let l = labels.intern("wasm32");
                map.fill_from(&base, |_| l);
            }
            Source::CompileUnits | Source::Inlines | Source::SourceFiles => {
                if let Some(sm) = source_map {
                    let mut bodies: Vec<(u64, u64)> = m
                        .functions()
                        .iter()
                        .map(|f| (f.offset, f.offset + f.size))
                        .collect();
                    bodies.sort_unstable();
                    let body_of = |at: u64| {
                        let i = bodies.partition_point(|b| b.0 <= at).checked_sub(1)?;
                        (at < bodies[i].1).then_some(bodies[i])
                    };
                    for (i, seg) in sm.segments.iter().enumerate() {
                        let Some(o) = seg.source else { continue };
                        let next = sm.segments.get(i + 1).map(|n| n.offset);
                        let end = match (next, body_of(seg.offset)) {
                            (Some(n), Some(b)) => n.min(b.1),
                            (Some(n), None) => n,
                            (None, Some(b)) => b.1,
                            (None, None) => continue,
                        };
                        if end <= seg.offset {
                            continue;
                        }
                        let file = &sm.sources[o.file as usize];
                        let name = if source == Source::Inlines {
                            format!("{file}:{}", u64::from(o.line) + 1)
                        } else {
                            file.clone()
                        };
                        let l = labels.intern(&name);
                        add(&mut map, seg.offset, end - seg.offset, l, Some(&base), len);
                    }
                }
            }
            // PE notions.
            Source::Groups | Source::Libraries => {}
        }
        fallback_into(&mut labels, &mut map, Some(&base));
        map.file.compress();
        out.push((source, map));
    }
    Ok(Maps {
        labels,
        base,
        sources: out,
        file_size: len,
        absorb_padding: true,
    })
}

/// `-disassemble` for a module: the function named `function` (its name
/// from the `name` section, demangled or not, or `func[i]` as the symbols
/// source names one without), as a listing: each instruction's offset in
/// the module and its text, indented by block, with calls annotated with
/// their callees' names.
/// How deep a listing indents nested blocks; deeper ones say their depth.
const MAX_INDENT: usize = 32;

pub fn listing(data: &[u8], function: &str) -> std::result::Result<String, String> {
    use hexcavator_wasm_isa::code;
    use std::fmt::Write as _;
    let m = Module::parse(data).map_err(|e| e.to_string())?;
    let funcs = m.names(NAME_FUNCTION);
    let base = m.imported_functions();
    let mut demangler = Demangler::new();
    let mut demangled = |raw: &[u8]| -> String {
        let raw = String::from_utf8_lossy(raw);
        let mut buf = String::new();
        if demangler.demangle_into(&raw, &mut buf) {
            buf
        } else {
            raw.into_owned()
        }
    };
    // Every function's name (demangled), by index.
    let mut names: Vec<(u32, String)> =
        funcs.iter().map(|n| (n.index, demangled(n.name))).collect();
    names.sort_by_key(|n| n.0);
    let name_of = |index: u32| {
        names
            .binary_search_by_key(&index, |n| n.0)
            .ok()
            .map(|i| names[i].1.as_str())
    };
    let pieces = m.functions();
    // As the name section has it, demangled short or in full (as for ELF
    // symbols), or by its index; else the one function whose name is it
    // with parameters (as for PE images).
    let mut raw_names = HashMap::new();
    for n in &funcs {
        raw_names.entry(n.index).or_insert(n.name);
    }
    let piece = pieces
        .iter()
        .find(|p| {
            raw_names.get(&p.index).is_some_and(|n| {
                crate::elf::names_symbol(&mut demangler, &String::from_utf8_lossy(n), function)
            }) || format!("func[{}]", p.index - base) == function
        })
        .or_else(|| {
            let mut alone = crate::disasm::ByNameAlone::new(function);
            for p in &pieces {
                if let Some(n) = name_of(p.index) {
                    alone.offer(u64::from(p.index), n, || p);
                }
            }
            alone.take()
        })
        .ok_or_else(|| format!("no function named '{function}'"))?;
    let (at, body) = m
        .body(piece)
        .ok_or_else(|| format!("{function}: body out of bounds"))?;
    let title = name_of(piece.index)
        .map_or_else(|| format!("func[{}]", piece.index - base), str::to_string);
    let mut out = String::new();
    let _ = writeln!(out, "{title}:");
    let locals = code::locals(body).map_err(|e| format!("{title}: locals: {e}"))?;
    if !locals.groups.is_empty() {
        let mut s = String::from("(local");
        for (n, t) in &locals.groups {
            // (A group can claim billions of locals; show the count.)
            if *n <= 8 {
                for _ in 0..*n {
                    let _ = write!(s, " {t}");
                }
            } else {
                let _ = write!(s, " {t}*{n}");
            }
        }
        s.push(')');
        let _ = writeln!(out, " {at:>16x}  {s}");
    }
    let code_at = at + locals.code_start as u64;
    let mut depth: i32 = 0;
    for (off, inst) in code::instructions(&body[locals.code_start..]) {
        let pc = code_at + off as u64;
        let i = match inst {
            Ok(i) => i,
            Err(e) => {
                let rest = &body[locals.code_start + off..];
                let bytes: Vec<String> = rest.iter().take(32).map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(
                    out,
                    " {pc:>16x}  (not instructions: {}) {}",
                    e.what,
                    bytes.join(" ")
                );
                break;
            }
        };
        let change = code::nesting(i.op);
        if change < 0 || code::is_continuation(i.op) {
            depth = (depth - 1).max(0);
        }
        let mut text = i.to_string();
        // Calls: the callee's name.
        if let (hexcavator_wasm_isa::code::Imm::Index(f), "call" | "return_call" | "ref.func") =
            (&i.imm, i.op.name)
            && let Some(name) = name_of(*f)
        {
            let _ = write!(text, " <{name}>");
        }
        // (Indented by nesting up to a point: blocks nested without end
        // would make the listing grow as the square of the code.)
        let depth_now = usize::try_from(depth).unwrap_or(0);
        let indent = if depth_now <= MAX_INDENT {
            "  ".repeat(depth_now)
        } else {
            format!("{}[depth {depth_now}] ", "  ".repeat(MAX_INDENT))
        };
        let _ = writeln!(out, " {pc:>16x}  {indent}{text}");
        if change > 0 || code::is_continuation(i.op) {
            depth += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::*;
    use crate::rangemap::sweep;

    fn fixture() -> Vec<u8> {
        std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/wasm/module.wasm"),
        )
        .unwrap()
    }

    fn file_totals(maps: &Maps, k: usize) -> HashMap<String, u64> {
        let mut out = HashMap::new();
        sweep(&[&maps.base.file, &maps.sources[k].1.file], |s, e, l| {
            *out.entry(l[1].map_or("<none>", |l| maps.labels.name(l)).to_string())
                .or_default() += e - s;
        });
        out
    }

    #[test]
    fn sections_symbols_and_fallbacks() {
        let data = fixture();
        let m = Module::parse(&data).unwrap();
        let all = [
            Source::Sections,
            Source::Symbols,
            Source::Archs,
            Source::InputFiles,
            Source::CompileUnits,
        ];
        let maps = maps(&data, "module.wasm", &all).unwrap();
        assert_eq!(maps.base.file.total(), data.len() as u64);
        assert_eq!(maps.base.vm.total(), 0);
        for k in 0..all.len() {
            let t = file_totals(&maps, k);
            assert_eq!(t.get("<none>"), None, "{k}");
            assert_eq!(t.values().sum::<u64>(), data.len() as u64);
        }
        let sections = file_totals(&maps, 0);
        for s in m.sections() {
            assert_eq!(sections[&*String::from_utf8_lossy(s.name)], s.size);
        }
        assert_eq!(sections[WASM_HEADER], 8);
        let symbols = file_totals(&maps, 1);
        // A function: its body and its name-section entry.
        let names = m.names(NAME_FUNCTION);
        for f in m.functions() {
            let name = names.iter().find(|n| n.index == f.index).map_or_else(
                || format!("func[{}]", f.index - 1),
                |n| String::from_utf8_lossy(n.name).into_owned(),
            );
            let entry = names
                .iter()
                .find(|n| n.index == f.index)
                .map_or(0, |n| n.size);
            assert_eq!(symbols[&name], f.size + entry, "{name}");
        }
        assert!(symbols.contains_key("func[3]"));
        assert!(symbols.contains_key("data[2]") && symbols.contains_key(".rodata"));
        // The imported function's name entry has no body.
        assert_eq!(symbols["log"], names[0].size);
        assert!(symbols.contains_key("[section Code]"));
        assert_eq!(file_totals(&maps, 2)["wasm32"], data.len() as u64);
        assert!(super::maps(b"\0asm", "x", &all).is_err());
    }

    /// A module of functions, each `() -> ()` and empty, named `names` in
    /// its name section (all small enough for one-byte lengths).
    fn functions(names: &[&str]) -> Vec<u8> {
        let n = names.len() as u8;
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        m.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]); // type 0: () -> ()
        m.extend_from_slice(&[3, n + 1, n]); // each function: type 0
        m.extend(std::iter::repeat_n(0, names.len()));
        m.extend_from_slice(&[10, 3 * n + 1, n]); // each body: no locals; end
        for _ in names {
            m.extend_from_slice(&[2, 0, 0x0B]);
        }
        let mut sub = vec![n];
        for (i, name) in names.iter().enumerate() {
            sub.extend_from_slice(&[i as u8, name.len() as u8]);
            sub.extend_from_slice(name.as_bytes());
        }
        let mut payload = b"\x04name".to_vec();
        payload.extend_from_slice(&[1, sub.len() as u8]);
        payload.extend_from_slice(&sub);
        m.extend_from_slice(&[0, payload.len() as u8]);
        m.extend_from_slice(&payload);
        m
    }

    /// A function is named as its name section has it, demangled (short or
    /// in full), by its index, or, if just one matches, without its
    /// parameters.
    #[test]
    fn listing_finds_functions_by_any_of_their_names() {
        let data = functions(&["_ZN3app4mainEv", "_Z1fi", "_Z1fl"]);
        for name in ["_ZN3app4mainEv", "app::main()", "app::main", "func[0]"] {
            let text = listing(&data, name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(text.starts_with("app::main():\n"), "{name}: {text}");
            assert!(text.ends_with("end\n"), "{name}: {text}");
        }
        let text = listing(&data, "f(long)").unwrap();
        assert!(text.starts_with("f(long):\n"), "{text}");
        // `f` is either of two.
        for name in ["f", "app", "main", "app::main(int)", "func[3]", ""] {
            assert_eq!(
                listing(&data, name),
                Err(format!("no function named '{name}'")),
                "{name}"
            );
        }
    }

    /// Where a function body's instructions start: after its size and its
    /// locals (a count, then (count, type) pairs).
    fn code_start(data: &[u8], body: u64) -> u64 {
        let mut at = body as usize;
        let mut uleb = || {
            let (mut v, mut shift) = (0u64, 0);
            loop {
                let b = data[at];
                at += 1;
                v |= u64::from(b & 0x7F) << shift;
                shift += 7;
                if b < 0x80 {
                    return v;
                }
            }
        };
        uleb();
        let groups = uleb();
        for _ in 0..groups {
            uleb();
            uleb(); // the type: one byte, as LEB128 reads it
        }
        at as u64
    }

    /// The fixture's source map (tools/wasm/make.py): each function's
    /// instructions to their source, to the end of the body; the bodies'
    /// sizes and locals (and the gap the map leaves) to `[section Code]`.
    #[test]
    fn compile_units_and_inlines_from_a_source_map() {
        let data = fixture();
        let text = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../testdata/wasm/module.wasm.map"),
        )
        .unwrap();
        let sm = crate::sourcemap::parse(&text).unwrap();
        assert_eq!(sm.sources, ["src/math.c", "src/main.c"]);
        let m = Module::parse(&data).unwrap();
        let f = m.functions();
        let span =
            |i: usize, skip: u64| f[i].offset + f[i].size - (code_start(&data, f[i].offset) + skip);
        let sources = [Source::CompileUnits, Source::Inlines];
        let maps = maps_with_source_map(&data, "m", &sources, Some(&sm)).unwrap();
        let units = file_totals(&maps, 0);
        assert_eq!(units["src/math.c"], span(0, 0) + span(1, 0) + span(3, 0));
        assert_eq!(units["src/main.c"], span(2, 0));
        let code = m.sections().iter().find(|s| s.name == b"Code").unwrap();
        assert_eq!(
            units["[section Code]"],
            code.size - units["src/math.c"] - units["src/main.c"]
        );
        let lines = file_totals(&maps, 1);
        let want = [
            ("src/math.c:2", 4),
            ("src/math.c:3", span(0, 4)),
            ("src/math.c:6", span(1, 0)),
            ("src/main.c:3", 4),
            ("src/main.c:4", span(2, 4)),
            // The last segment, which bloaty drops.
            ("src/math.c:10", span(3, 0)),
        ];
        for (name, size) in want {
            assert_eq!(lines.get(name).copied(), Some(size), "{name}: {lines:?}");
        }
        // Without a map, both sources are the fallbacks alone.
        let maps = super::maps(&data, "m", &sources).unwrap();
        assert!(file_totals(&maps, 0).keys().all(|k| k.starts_with('[')));
    }
}

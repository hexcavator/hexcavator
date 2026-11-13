//! The ELF sources on the clang/lld fixtures in testdata/elf: every source
//! labels every byte the base map does, and the charges are what the
//! file's own structures (read through hexcavator-elf) say they should be.

use std::collections::HashMap;
use std::path::PathBuf;

use super::*;
use crate::rangemap::sweep;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/elf")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const FILES: &[&str] = &[
    "program-x86_64-linux-gnu",
    "program-x86_64-linux-gnu.o",
    "program-i386-linux-gnu",
    "program-i386-linux-gnu.o",
    "program-aarch64-linux-gnu",
    "program-aarch64_be-linux-gnu",
    "program-aarch64_be-linux-gnu.o",
    "program-armeb-linux-gnueabi",
    "program-armeb-linux-gnueabi.o",
    "program.so",
    "program-stripped",
    "program-minidebug",
    "program.a",
    "unwind-x86_64-linux-gnu",
    "unwind-x86_64-linux-gnu.o",
    "unwind-aarch64_be-linux-gnu",
    "unwind-i386-linux-gnu",
    "dwarf4-x86_64-linux-gnu",
    "dwarf5-aarch64_be-linux-gnu",
    "names.o",
    "refs-x86_64-linux-gnu",
    "refs-aarch64-linux-gnu",
    "rust-v0.o",
    "rust-legacy.o",
];

const SOURCES: &[Source] = &[
    Source::Segments,
    Source::Sections,
    Source::Symbols,
    Source::ArMembers,
    Source::InputFiles,
    Source::CompileUnits,
];

/// Bytes per label of source `k` (VM, file), over what the base labels.
fn totals(maps: &Maps, k: usize) -> (HashMap<String, u64>, HashMap<String, u64>) {
    let map = &maps.sources[k].1;
    let mut out = (HashMap::new(), HashMap::new());
    for (domain, base, m) in [
        (&mut out.0, &maps.base.vm, &map.vm),
        (&mut out.1, &maps.base.file, &map.file),
    ] {
        sweep(&[base, m], |s, e, labels| {
            let name = labels[1]
                .map_or("<none>", |l| maps.labels.name(l))
                .to_string();
            *domain.entry(name).or_default() += e - s;
        });
    }
    out
}

fn get(t: &HashMap<String, u64>, k: &str) -> u64 {
    t.get(k).copied().unwrap_or(0)
}

#[test]
fn every_source_labels_every_byte() {
    for f in FILES {
        let data = fixture(f);
        assert!(is_elf_input(&data), "{f}");
        let maps = maps(&data, f, SOURCES).unwrap();
        assert_eq!(
            maps.base.file.total(),
            data.len() as u64,
            "{f}: base covers the file"
        );
        assert!(maps.base.file.covers(0, data.len() as u64));
        for (k, (source, _)) in maps.sources.iter().enumerate() {
            let (vm, file) = totals(&maps, k);
            assert_eq!(get(&vm, "<none>"), 0, "{f} {source:?}: unlabeled memory");
            assert_eq!(
                get(&file, "<none>"),
                0,
                "{f} {source:?}: unlabeled file bytes"
            );
            assert_eq!(
                file.values().sum::<u64>(),
                data.len() as u64,
                "{f} {source:?}"
            );
            assert_eq!(
                vm.values().sum::<u64>(),
                maps.base.vm.total(),
                "{f} {source:?}"
            );
        }
    }
}

#[test]
fn not_elf() {
    assert!(!is_elf_input(b"MZ"));
    assert!(!is_elf_input(b""));
    assert!(maps(b"\x7fELF", "x", &[Source::Sections]).is_err());
    // An archive of COFF objects isn't ELF input.
    let lib = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/coff/objects.lib"),
    )
    .unwrap();
    assert!(!is_elf_input(&lib));
}

#[test]
fn segments_and_sections_of_an_executable() {
    for f in [
        "program-x86_64-linux-gnu",
        "program-armeb-linux-gnueabi",
        "program.so",
    ] {
        let data = fixture(f);
        let elf = ElfFile::parse(&data).unwrap();
        let maps = maps(&data, f, &[Source::Segments, Source::Sections]).unwrap();
        let (seg_vm, seg_file) = totals(&maps, 0);
        // Load segments don't overlap: each gets its whole extent.
        let loads: Vec<_> = elf.segments().filter(|p| p.kind == PT_LOAD).collect();
        assert!(loads.len() >= 2, "{f}");
        for p in &loads {
            let name = segment_label(p.index, p.flags, false);
            assert_eq!(get(&seg_vm, &name), p.memsz, "{f} {name}");
            assert_eq!(get(&seg_file, &name), p.filesz, "{f} {name}");
        }
        // Memory outside load segments: none (the base is the segments).
        assert_eq!(
            seg_vm.values().sum::<u64>(),
            loads.iter().map(|p| p.memsz).sum::<u64>()
        );
        // The headers are in the first load segment, not labeled apart.
        assert_eq!(get(&seg_file, ELF_HEADER), 0);

        let (sec_vm, sec_file) = totals(&maps, 1);
        for s in elf.sections().skip(1) {
            let name = String::from_utf8_lossy(s.name).into_owned();
            if elf.sections().filter(|t| t.name == s.name).count() > 1 {
                continue;
            }
            // `.tbss` overlaps the sections after it in memory.
            if s.flags & SHF_TLS != 0 && s.kind == SHT_NOBITS {
                continue;
            }
            assert_eq!(get(&sec_file, &name), s.file_size(), "{f} {name}");
            assert_eq!(
                get(&sec_vm, &name),
                if s.is_alloc() { s.size } else { 0 },
                "{f} {name}"
            );
        }
        let (_, ss) = elf.section_headers_range();
        assert_eq!(get(&sec_file, ELF_SECTION_HEADERS), ss, "{f}");
        let (_, eh) = elf.header_range();
        assert_eq!(get(&sec_file, ELF_HEADER), eh, "{f}");
    }
}

#[test]
fn object_segments_are_section_flags() {
    let data = fixture("program-x86_64-linux-gnu.o");
    let elf = ElfFile::parse(&data).unwrap();
    let maps = maps(&data, "x.o", &[Source::Segments, Source::Sections]).unwrap();
    let (vm, file) = totals(&maps, 0);
    let mut want_vm: HashMap<String, u64> = HashMap::new();
    let mut want_file: HashMap<String, u64> = HashMap::new();
    for s in elf.sections().skip(1) {
        *want_file.entry(flags_label(s.flags)).or_default() += s.file_size();
        if s.is_alloc() {
            *want_vm.entry(flags_label(s.flags)).or_default() += s.size;
        }
    }
    for (k, v) in &want_vm {
        assert_eq!(get(&vm, k), *v, "{k}");
    }
    for (k, v) in &want_file {
        assert_eq!(get(&file, k), *v, "{k}");
    }
    assert!(want_vm.contains_key("Section [AX]") && want_vm.contains_key("Section [AW]"));
    // Each section is at its own synthetic address.
    let text = elf.section_by_name(b".text").unwrap();
    let at = (text.index as u64) << 40;
    let e = maps.base.vm.get(at).unwrap();
    assert_eq!(maps.labels.name(e.label), "Section [AX]");
    assert_eq!((e.start, e.end), (at, at + text.size));
    assert_eq!(e.other, Some(text.offset));
}

/// The bytes the symbols source should charge `name` beyond its own
/// range, as the file's tables say: (in memory, in the file). Entries in
/// loaded sections (unwind tables) count in both.
fn table_charges(elf: &ElfFile<'_>, name: &[u8]) -> (u64, u64) {
    let syms = elf.all_symbols();
    let sym = syms.iter().find(|s| s.name == name).unwrap();
    let entry = if elf.class() == hexcavator_elf::Class::Elf64 {
        24
    } else {
        16
    };
    let mut total = 0;
    let mut loaded = 0;
    // The symbol's unwind entries' addresses: relocations there are its too.
    let mut ranges = vec![(sym.value, sym.value + sym.size)];
    for s in elf.sections() {
        let unwind = match s.name {
            b".eh_frame" => elf.eh_frame(&s),
            b".eh_frame_hdr" => elf.eh_frame_hdr(&s),
            _ => Vec::new(),
        };
        for e in unwind.iter().filter(|e| e.pc == sym.value) {
            ranges.push((s.addr + e.offset, s.addr + e.offset + e.size));
        }
    }
    let within = |a: u64| ranges.iter().any(|&(s, e)| a >= s && a < e);
    for s in elf.sections() {
        if s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM {
            // Every defined symbol pointing into it (mapping symbols such
            // as `$x` too), and its name.
            for t in elf.symbols(&s).iter().skip(1) {
                if t.kind != STT_SECTION && t.shndx != 0 && within(t.value) {
                    total += entry
                        + if t.name.is_empty() {
                            0
                        } else {
                            t.name.len() as u64 + 1
                        };
                }
            }
        }
        if s.kind == SHT_RELA || s.kind == SHT_REL {
            total += elf
                .relocations(&s)
                .iter()
                .filter(|r| within(r.offset))
                .map(|r| r.size)
                .sum::<u64>();
        }
        let unwind = match s.name {
            b".eh_frame" => elf.eh_frame(&s),
            b".eh_frame_hdr" => elf.eh_frame_hdr(&s),
            _ => Vec::new(),
        };
        let n: u64 = unwind
            .iter()
            .filter(|e| e.pc == sym.value)
            .map(|e| e.size)
            .sum();
        total += n;
        loaded += n;
    }
    (loaded, total)
}

#[test]
fn symbols_take_their_table_entries() {
    for f in [
        "program-x86_64-linux-gnu",
        "unwind-x86_64-linux-gnu",
        "unwind-aarch64_be-linux-gnu",
        "unwind-i386-linux-gnu",
    ] {
        let data = fixture(f);
        let elf = ElfFile::parse(&data).unwrap();
        let maps = maps(&data, f, &[Source::Symbols]).unwrap();
        let (vm, file) = totals(&maps, 0);
        for name in ["compute", "_start", "buffer", "message", "counter"] {
            let sym = elf
                .all_symbols()
                .into_iter()
                .find(|s| s.name == name.as_bytes())
                .unwrap();
            let (in_vm, in_tables) = table_charges(&elf, name.as_bytes());
            assert_eq!(get(&vm, name), sym.size + in_vm, "{f} {name}");
            let in_file = if sym.shndx as usize == elf.section_by_name(b".bss").unwrap().index {
                0
            } else {
                sym.size
            };
            assert_eq!(get(&file, name), in_file + in_tables, "{f} {name}");
            if f.starts_with("unwind") && name == "compute" {
                assert!(in_vm > 0, "{f}: compute has unwind entries");
            }
        }
        if f.starts_with("unwind") {
            // The unwind tables were charged: compute has an FDE.
            let frame = elf.section_by_name(b".eh_frame").unwrap();
            assert!(!elf.eh_frame(&frame).is_empty());
            let fde_bytes: u64 = elf.eh_frame(&frame).iter().map(|e| e.size).sum();
            assert!(
                get(&file, "[section .eh_frame]") < frame.size - fde_bytes + 1,
                "{f}"
            );
        }
    }
}

#[test]
fn object_symbols() {
    let data = fixture("unwind-x86_64-linux-gnu.o");
    let elf = ElfFile::parse(&data).unwrap();
    let maps = maps(&data, "x.o", &[Source::Symbols]).unwrap();
    let (vm, file) = totals(&maps, 0);
    let syms = elf.all_symbols();
    let compute = syms.iter().find(|s| s.name == b"compute").unwrap();
    assert_eq!(get(&vm, "compute"), compute.size);
    // In an object, relocations patch offsets in their target section.
    let text = elf.section_by_name(b".text").unwrap();
    let rela = elf
        .sections()
        .find(|s| s.kind == SHT_RELA && s.info as usize == text.index)
        .unwrap();
    let relocs: u64 = elf
        .relocations(&rela)
        .iter()
        .filter(|r| r.offset >= compute.value && r.offset < compute.value + compute.size)
        .map(|r| r.size)
        .sum();
    assert!(relocs > 0);
    assert_eq!(get(&file, "compute"), compute.size + 24 + 8 + relocs);
    // Local symbols with no name in .symtab (section symbols) charge nothing.
    assert!(!vm.keys().any(|k| k.starts_with("[Anonymous")));
}

#[test]
fn archives() {
    let data = fixture("program.a");
    let maps = maps(
        &data,
        "program.a",
        &[Source::ArMembers, Source::Sections, Source::Segments],
    )
    .unwrap();
    let (vm, file) = totals(&maps, 0);
    let ar = Archive::parse(&data).unwrap();
    let mut headers = 8;
    let mut symbols = 0;
    for m in ar.members() {
        headers +=
            m.end() - m.data_offset - m.data.len() as u64 + (m.data_offset - m.header_offset);
        match m.kind {
            MemberKind::File => {
                let name = String::from_utf8_lossy(&m.name).into_owned();
                assert_eq!(get(&file, &name), m.data.len() as u64, "{name}");
                let elf = ElfFile::parse(m.data).unwrap();
                let alloc: u64 = elf
                    .sections()
                    .filter(hexcavator_elf::Section::is_alloc)
                    .map(|s| s.size)
                    .sum();
                assert_eq!(get(&vm, &name), alloc, "{name}");
            }
            MemberKind::SymbolTable => symbols += m.data.len() as u64,
            _ => headers += m.data.len() as u64,
        }
    }
    assert_eq!(get(&file, AR_HEADERS), headers);
    assert_eq!(get(&file, AR_SYMBOLS), symbols);
    assert!(symbols > 0);
    // Two members' .text sections, at distinct synthetic addresses.
    let (sec_vm, _) = totals(&maps, 1);
    assert!(get(&sec_vm, ".text") > 300);
}

#[test]
fn labels() {
    assert_eq!(flags_label(SHF_ALLOC | SHF_EXECINSTR), "Section [AX]");
    assert_eq!(
        flags_label(SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR),
        "Section [AWX]"
    );
    assert_eq!(flags_label(0), "Section []");
    assert_eq!(segment_label(3, PF_R | PF_W, false), "LOAD #3 [RW]");
    assert_eq!(segment_label(0, PF_R | PF_X, true), "[LOAD #0 [RX]]");
    assert_eq!(to_vm(0x10, 3, true), Some((3 << 40) | 0x10));
    assert_eq!(to_vm(0x10, 3, false), Some(0x10));
    assert_eq!(to_vm(1 << 40, 3, true), None);
    assert_eq!(to_vm(0, 1 << 24, true), None);
}

/// Truncated and corrupted inputs give errors or maps, never panics.
#[test]
fn hostile_inputs() {
    for f in [
        "unwind-x86_64-linux-gnu",
        "program-i386-linux-gnu.o",
        "program.a",
    ] {
        let clean = fixture(f);
        let step = (clean.len() / 300).max(1);
        for n in (0..clean.len()).step_by(step) {
            let _ = maps(&clean[..n], f, SOURCES);
        }
        for i in (0..clean.len()).step_by(step) {
            for v in [0x00, 0xFF, 0x7F] {
                let mut d = clean.clone();
                d[i] = v;
                if let Ok(m) = maps(&d, f, SOURCES) {
                    assert!(m.base.file.covers(0, d.len() as u64));
                }
            }
        }
    }
}

/// `fullsymbols` names are llvm-nm's demangled names; `symbols` the short
/// forms; `rawsymbols` the mangled names.
#[test]
fn symbol_names_by_source() {
    let data = fixture("names.o");
    let maps = maps(
        &data,
        "names.o",
        &[Source::FullSymbols, Source::Symbols, Source::RawSymbols],
    )
    .unwrap();
    let names = |k: usize| -> std::collections::HashSet<String> {
        totals(&maps, k).1.into_keys().collect()
    };
    let (full, short, raw) = (names(0), names(1), names(2));
    let nm = |file: &str| -> Vec<String> {
        let text = String::from_utf8(fixture(file)).unwrap();
        text.lines()
            .map(|l| l.splitn(3, ' ').nth(2).unwrap().to_string())
            .collect()
    };
    let mangled = nm("names.o.nm.txt");
    let demangled = nm("names.o.nm-demangled.txt");
    assert!(mangled.len() >= 8);
    for (m, d) in mangled.iter().zip(&demangled) {
        assert!(raw.contains(m), "{m}");
        assert!(full.contains(d), "{d}");
    }
    for s in [
        "use_points()",
        "geometry::Point<>::dot()",
        "geometry::Point<>::Point()",
        "geometry::operator+<>()",
        "use_points()::$_0::operator()()",
        "table",
    ] {
        assert!(short.contains(s), "{s}: {short:?}");
    }
    assert!(!short.iter().any(|s| s.contains("<int>")));
}

/// Compile units from DWARF: each function and variable goes to the unit
/// that defines it, and every byte of the debug information to some unit.
#[test]
fn compile_units_from_dwarf() {
    for f in [
        "dwarf4-x86_64-linux-gnu",
        "dwarf5-x86_64-linux-gnu",
        "dwarf4-aarch64_be-linux-gnu",
        "dwarf5-aarch64_be-linux-gnu",
    ] {
        let data = fixture(f);
        let elf = ElfFile::parse(&data).unwrap();
        let maps = maps(&data, f, &[Source::CompileUnits]).unwrap();
        let unit_of = |addr: u64| {
            maps.sources[0]
                .1
                .vm
                .get(addr)
                .map(|e| maps.labels.name(e.label).to_string())
        };
        for (sym, unit) in [
            ("compute", "program.c"),
            ("_start", "program.c"),
            ("buffer", "program.c"),
            ("counter", "program.c"),
            ("second_sum", "second.c"),
            ("second_len", "second.c"),
            ("second_table", "second.c"),
        ] {
            let s = elf
                .all_symbols()
                .into_iter()
                .find(|s| s.name == sym.as_bytes())
                .unwrap();
            for a in [s.value, s.value + s.size - 1] {
                assert_eq!(unit_of(a).as_deref(), Some(unit), "{f} {sym} at {a:#x}");
            }
        }
        let (_, file) = totals(&maps, 0);
        for sec in [
            ".debug_info",
            ".debug_abbrev",
            ".debug_line",
            ".debug_aranges",
            ".debug_str",
            ".debug_loc",
            ".debug_ranges",
            ".debug_rnglists",
            ".debug_loclists",
            ".debug_addr",
            ".debug_str_offsets",
        ] {
            assert_eq!(
                get(&file, &format!("[section {sec}]")),
                0,
                "{f}: {sec} unattributed"
            );
        }
        assert!(
            get(&file, "program.c") > 1000 && get(&file, "second.c") > 500,
            "{f}"
        );
    }
    // Objects keep the fallbacks (their DWARF needs relocating).
    let data = fixture("program-x86_64-linux-gnu.o");
    let maps = maps(&data, "x.o", &[Source::CompileUnits]).unwrap();
    let (_, file) = totals(&maps, 0);
    assert!(file.keys().all(|k| k.starts_with('[')), "{file:?}");
}

/// `compileunits` of a stripped image from its debug file, as objcopy
/// splits them.
#[test]
fn compile_units_from_a_debug_file() {
    let data = fixture("program-split");
    let debug = fixture("program-split.debug");
    let elf = ElfFile::parse(&debug).unwrap();
    assert!(
        ElfFile::parse(&data).unwrap().all_symbols().is_empty(),
        "stripped"
    );
    let maps = maps_with_debug(&data, "s", &[Source::CompileUnits], Some(&debug)).unwrap();
    for sym in ["compute", "_start", "buffer"] {
        let s = elf
            .all_symbols()
            .into_iter()
            .find(|s| s.name == sym.as_bytes())
            .unwrap();
        let e = maps.sources[0].1.vm.get(s.value).unwrap();
        assert_eq!(maps.labels.name(e.label), "program.c", "{sym}");
    }
    let (_, file) = totals(&maps, 0);
    assert_eq!(file.values().sum::<u64>(), data.len() as u64);
    assert!(maps_with_debug(&data, "s", &[Source::CompileUnits], Some(b"junk")).is_err());
    // A debug file of another build is refused.
    let other = fixture("program-aarch64-linux-gnu");
    assert!(maps_with_debug(&data, "s", &[Source::CompileUnits], Some(&other)).is_err());
}

/// A stripped image's symbols, from its separate debug file or its
/// MiniDebugInfo (`.gnu_debugdata`, as tools/elf/minidebuginfo.py makes
/// it): each at its address in the image, as the unstripped image has it.
#[test]
fn symbols_from_a_debug_file_or_mini_debug_info() {
    let full = fixture("program-x86_64-linux-gnu");
    let elf = ElfFile::parse(&full).unwrap();
    let mini = fixture("program-minidebug");
    assert!(mini_debug_info(&mini).is_some());
    assert!(mini_debug_info(&full).is_none());
    let split = fixture("program-split");
    let debug = fixture("program-split.debug");
    for (data, debug) in [(&mini, None), (&split, Some(&debug[..]))] {
        let maps = maps_with_debug(data, "s", &[Source::Symbols], debug).unwrap();
        for sym in ["compute", "_start", "buffer"] {
            let s = elf
                .all_symbols()
                .into_iter()
                .find(|s| s.name == sym.as_bytes())
                .unwrap();
            let e = maps.sources[0].1.vm.get(s.value).unwrap();
            assert_eq!(maps.labels.name(e.label), sym);
        }
    }
    // Damaged MiniDebugInfo is as none.
    let mut bad = mini.clone();
    let at = bad.len() / 2;
    bad[at] ^= 0xFF;
    let _ = maps_with_debug(&bad, "s", &[Source::Symbols], None);
}

/// `inlines`: code is labeled `file:line`, and the spans cover exactly
/// the line tables' sequences.
#[test]
fn inlines_from_line_tables() {
    for f in ["dwarf4-x86_64-linux-gnu", "dwarf5-aarch64_be-linux-gnu"] {
        let data = fixture(f);
        let elf = ElfFile::parse(&data).unwrap();
        let maps = maps(&data, f, &[Source::Inlines]).unwrap();
        let (vm, _) = totals(&maps, 0);
        // Code, by line (data the code refers to is charged to lines too).
        let map = &maps.sources[0].1;
        let mut lines = 0;
        for sec in elf.sections().filter(|s| s.flags & SHF_EXECINSTR != 0) {
            for e in map.vm.overlapping(sec.addr, sec.addr + sec.size) {
                if !maps.labels.name(e.label).starts_with('[') {
                    lines += e.end.min(sec.addr + sec.size) - e.start.max(sec.addr);
                }
            }
        }
        // The zero-filled buffer the code writes is charged to a line.
        let bss = elf.sections().find(|s| s.name == b".bss").unwrap();
        let owner = map.vm.get(bss.addr).map(|e| maps.labels.name(e.label));
        assert!(owner.is_some_and(|o| o.contains(".c:")), "{f}: {owner:?}");
        let mut s = hexcavator_dwarf::Sections::new(elf.endian());
        for sec in elf.sections() {
            if let Some(n) = sec.name.strip_prefix(b".debug_") {
                s.set(n, elf.section_data(&sec));
            }
        }
        let mut expected = 0;
        let mut offset = 0;
        while let Some(p) = hexcavator_dwarf::line_program(&s, offset, 8) {
            let mut start = None;
            for r in &p.rows {
                if start.is_none() {
                    start = Some(r.address);
                }
                if r.end_sequence {
                    expected += r.address - start.take().unwrap();
                }
            }
            offset += hexcavator_dwarf::line_program_len(s.line, offset, s.endian).unwrap();
        }
        assert!(expected > 200, "{f}");
        assert_eq!(lines, expected, "{f}");
        assert!(
            vm.keys().filter(|k| !k.starts_with('[')).all(|k| k
                .rsplit_once(':')
                .is_some_and(|(file, n)| file.ends_with(".c") && n.parse::<u64>().is_ok())),
            "{f}: {vm:?}"
        );
        let compute = elf
            .all_symbols()
            .into_iter()
            .find(|s| s.name == b"compute")
            .unwrap();
        let e = maps.sources[0].1.vm.get(compute.value).unwrap();
        assert!(maps.labels.name(e.label).contains("program.c:"), "{f}");
    }
}

/// Compressed debug sections (gABI zlib and zstd, GNU .zdebug) give the
/// same compile units and lines as the uncompressed original.
#[test]
fn compressed_debug_sections() {
    let plain = fixture("dwarf5-x86_64-linux-gnu");
    let vm_of = |data: &[u8], s: Source| -> Vec<(u64, u64, String)> {
        let maps = maps(data, "x", &[s]).unwrap();
        maps.sources[0]
            .1
            .vm
            .iter()
            .map(|e| (e.start, e.end, maps.labels.name(e.label).to_string()))
            .filter(|(_, _, n)| !n.starts_with('['))
            .collect()
    };
    let want_units = vm_of(&plain, Source::CompileUnits);
    let want_lines = vm_of(&plain, Source::Inlines);
    assert!(want_units.iter().any(|(_, _, n)| n == "program.c"));
    assert!(want_lines.len() > 10);
    for v in ["zlib", "zstd", "zdebug"] {
        let data = fixture(&format!("dwarf5-x86_64-linux-gnu.{v}"));
        let elf = ElfFile::parse(&data).unwrap();
        let input = crate::decompress::elf_dwarf_sections(&elf, Some(0));
        assert!(
            input.iter().all(|(_, _, at)| at.is_none()),
            "{v}: compressed bytes aren't the file's"
        );
        assert!(input.iter().any(|(n, _, _)| *n == b"info"), "{v}");
        assert_eq!(vm_of(&data, Source::CompileUnits), want_units, "{v}");
        assert_eq!(vm_of(&data, Source::Inlines), want_lines, "{v}");
        let (_, file) = totals(&maps(&data, v, &[Source::CompileUnits]).unwrap(), 0);
        assert_eq!(file.values().sum::<u64>(), data.len() as u64);
    }
}

/// The symbols source charges data no symbol covers to the first function
/// (in symbol table order) whose code refers to it, as llvm-objdump finds
/// the references; our disassembly finds the same ones. Every byte of the
/// fixture's `.rodata` (string literals, a lookup table, a jump table)
/// then belongs to a function.
#[test]
fn referenced_data_goes_to_the_first_referrer() {
    for t in ["x86_64", "aarch64"] {
        let name = format!("refs-{t}-linux-gnu");
        let data = fixture(&name);
        let listing = String::from_utf8(fixture(&format!("{name}.objdump.txt"))).unwrap();
        let oracle = crate::disasm::oracle::objdump_references(&listing);
        let elf = ElfFile::parse(&data).unwrap();
        let sections: Vec<_> = elf.sections().collect();
        let symtab = sections.iter().find(|s| s.kind == SHT_SYMTAB).unwrap();
        let syms = elf.symbols(symtab);
        let arch = if t == "x86_64" {
            crate::disasm::Arch::X64
        } else {
            crate::disasm::Arch::Arm64
        };
        let covered = |a: u64| {
            syms.iter()
                .any(|s| s.size > 0 && a >= s.value && a - s.value < s.size)
        };
        let mut first: Vec<(u64, String)> = Vec::new();
        for s in syms.iter().filter(|s| s.kind == STT_FUNC && s.size > 0) {
            let fname = String::from_utf8_lossy(s.name).into_owned();
            let want = &oracle.iter().find(|(n, _)| *n == fname).unwrap().1;
            // Our references are llvm-objdump's.
            let sec = &sections[s.shndx as usize];
            let at = (s.value - sec.addr) as usize;
            let code = &elf.section_data(sec)[at..at + s.size as usize];
            let mut ours = Vec::new();
            crate::disasm::references(arch, code, s.value, &mut ours);
            let ours: Vec<u64> = ours.iter().map(|r| r.to).collect();
            assert_eq!(&ours, want, "{name} {fname}");
            for &a in want {
                if !covered(a) && !first.iter().any(|f| f.0 == a) {
                    first.push((a, fname.clone()));
                }
            }
        }
        assert!(first.len() >= 4, "{name}: {first:x?}");
        let maps = maps(&data, &name, &[Source::RawSymbols]).unwrap();
        let map = &maps.sources[0].1;
        for (a, f) in &first {
            let got = map.vm.get(*a).map(|e| maps.labels.name(e.label));
            assert_eq!(got, Some(f.as_str()), "{name} {a:#x}");
        }
        let rodata = sections.iter().find(|s| s.name == b".rodata").unwrap();
        let mut owners = std::collections::BTreeSet::new();
        for e in map.vm.overlapping(rodata.addr, rodata.addr + rodata.size) {
            owners.insert(maps.labels.name(e.label).to_string());
        }
        assert!(
            map.vm.covers(rodata.addr, rodata.addr + rodata.size),
            "{name}"
        );
        assert!(
            owners.iter().all(|o| !o.starts_with('[')),
            "{name}: {owners:?}"
        );
        // The literal both functions use goes to the one listed first.
        assert!(owners.contains("shared_first") && !owners.contains("shared_second"));
    }
}

/// Rust objects, in the v0 mangling and the legacy one: every symbol is
/// demangled (none is left as `_R...` or `_ZN...`), legacy hashes dropped.
#[test]
fn rust_symbols() {
    for (f, closure) in [
        ("rust-v0.o", "std::rt::lang_start::<()>::{closure#0}"),
        ("rust-legacy.o", "std::rt::lang_start::{{closure}}"),
    ] {
        let data = fixture(f);
        let maps = maps(&data, f, &[Source::Symbols, Source::FullSymbols]).unwrap();
        for k in 0..2 {
            let (vm, _) = totals(&maps, k);
            assert!(vm.contains_key("corpus::closures"), "{f}: {vm:?}");
            assert!(vm.contains_key(closure), "{f}: {vm:?}");
            let raw: Vec<&String> = vm
                .keys()
                .filter(|k| k.starts_with("_R") || k.starts_with("_ZN"))
                .collect();
            assert!(raw.is_empty(), "{f}: {raw:?}");
            // (Section names are as the file has them.)
            assert!(
                !vm.keys().any(|k| !k.starts_with('[') && k.contains("17h")),
                "{f}"
            );
        }
    }
}

/// Structural recommendations: RELR, as lld would encode it (the same
/// object linked with -z pack-relative-relocs has exactly that table), and
/// .hash beside .gnu.hash.
#[test]
fn structural_recommendations() {
    use crate::recommend::{relr_size, structural};
    let rela = fixture("relr-rela.so");
    let relr = fixture("relr.so");
    let packed = ElfFile::parse(&relr).unwrap();
    let table = packed
        .sections()
        .find(|s| s.kind == hexcavator_elf::consts::SHT_RELR)
        .unwrap();
    let image = hexcavator_image::Image::parse(&rela).unwrap();
    let recs = structural(&image);
    let r = recs
        .iter()
        .find(|r| r.advice.contains("pack-relative-relocs"));
    // (A small fixture: its saving may be under the minimum; the table's
    // size is what is checked.)
    let elf = ElfFile::parse(&rela).unwrap();
    let mut offsets: Vec<u64> = elf
        .sections()
        .filter(|s| s.kind == hexcavator_elf::consts::SHT_RELA)
        .flat_map(|s| elf.relocations(&s))
        .filter(|r| r.kind == 8)
        .map(|r| r.offset)
        .collect();
    offsets.sort_unstable();
    assert_eq!(relr_size(&offsets, 8), table.size, "{r:?} {offsets:x?}");
    // Already packed: nothing to recommend.
    let image = hexcavator_image::Image::parse(&relr).unwrap();
    assert!(
        !structural(&image)
            .iter()
            .any(|r| r.advice.contains("pack-relative-relocs"))
    );
    // RELR's encoding: one address entry and a bitmap for 63 more words.
    assert_eq!(relr_size(&[0x1000], 8), 8);
    assert_eq!(relr_size(&[0x1000, 0x1008, 0x1010], 8), 16);
    // The bitmap's last word, and the one past it (a new address).
    assert_eq!(relr_size(&[0x1000, 0x1000 + 63 * 8], 8), 16);
    assert_eq!(relr_size(&[0x1000, 0x1000 + 64 * 8], 8), 16);
    // A second bitmap: words past the first's, within the next's.
    assert_eq!(relr_size(&[0x1000, 0x1008, 0x1000 + 64 * 8], 8), 24);
    assert_eq!(relr_size(&[0x1000, 0x9000], 8), 16);
    // Both hash tables.
    let both = fixture("libversions.so");
    let image = hexcavator_image::Image::parse(&both).unwrap();
    let hash = ElfFile::parse(&both)
        .unwrap()
        .sections()
        .find(|s| s.kind == hexcavator_elf::consts::SHT_HASH)
        .unwrap();
    let recs = structural(&image);
    let h = recs.iter().find(|r| r.advice.contains("--hash-style=gnu"));
    assert!(
        hash.size < crate::recommend::MIN_SAVING || h.is_some_and(|h| h.saving == hash.size),
        "{recs:?}"
    );
}

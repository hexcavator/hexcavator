//! The Mach-O sources on the fixtures in testdata/macho: every source
//! labels every byte the base does, and segments, sections, link-edit
//! tables, symbols, and architectures get what the file says they span.

use std::collections::HashMap;
use std::path::PathBuf;

use super::*;
use crate::rangemap::sweep;
use hexcavator_archive::{Archive, MemberKind};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/macho")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const FILES: &[&str] = &[
    "program-arm64",
    "program-x86_64",
    "program-arm64.o",
    "program-x86_64.o",
    "libsecond-arm64.dylib",
    "libsecond-x86_64.dylib",
    "program-universal",
    "libprogram-arm64.a",
    "libprogram-x86_64.a",
    "libprogram-universal.a",
    "refs-x86_64",
    "refs-arm64",
];

const SOURCES: &[Source] = &[
    Source::Segments,
    Source::Sections,
    Source::Symbols,
    Source::FullSymbols,
    Source::Archs,
    Source::InputFiles,
    Source::CompileUnits,
];

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
        assert!(is_macho_input(&data), "{f}");
        let maps = maps(&data, f, SOURCES).unwrap();
        assert_eq!(maps.base.file.total(), data.len() as u64, "{f}");
        for (k, (source, _)) in maps.sources.iter().enumerate() {
            let (vm, file) = totals(&maps, k);
            assert_eq!(get(&vm, "<none>"), 0, "{f} {source:?}");
            assert_eq!(get(&file, "<none>"), 0, "{f} {source:?}");
            assert_eq!(
                file.values().sum::<u64>(),
                data.len() as u64,
                "{f} {source:?}"
            );
        }
    }
    assert!(!is_macho_input(b"\x7fELF\x02\x01\x01\0"));
    assert!(maps(b"\xcf\xfa\xed\xfe", "x", &[Source::Sections]).is_err());
}

#[test]
fn segments_sections_and_tables() {
    for f in ["program-arm64", "program-x86_64", "libsecond-arm64.dylib"] {
        let data = fixture(f);
        let m = MachO::parse(&data).unwrap();
        let maps = maps(&data, f, &[Source::Segments, Source::Sections]).unwrap();
        let (seg_vm, seg_file) = totals(&maps, 0);
        for s in m.segments() {
            let name = String::from_utf8_lossy(s.name).into_owned();
            if s.maxprot == VM_PROT_NONE {
                assert_eq!(get(&seg_vm, &name), 0, "{f} {name}");
                continue;
            }
            assert_eq!(get(&seg_vm, &name), s.vmsize, "{f} {name}");
            if s.name != b"__TEXT" {
                assert_eq!(get(&seg_file, &name), s.filesize, "{f} {name}");
            }
        }
        // The Mach header and the load commands before __TEXT's claim the
        // headers; __TEXT has the rest of its pages.
        let text = m
            .segments()
            .into_iter()
            .find(|s| s.name == b"__TEXT")
            .unwrap()
            .command;
        let before: u64 = m
            .load_commands()
            .iter()
            .take_while(|c| c.index < text)
            .map(|c| u64::from(c.size))
            .sum();
        assert_eq!(
            get(&seg_file, MACHO_HEADERS),
            m.header().size + before,
            "{f}"
        );
        let (sec_vm, sec_file) = totals(&maps, 1);
        for s in m.sections() {
            let name = format!(
                "{},{}",
                String::from_utf8_lossy(s.segname),
                String::from_utf8_lossy(s.sectname)
            );
            assert_eq!(get(&sec_vm, &name), s.size, "{f} {name}");
            assert_eq!(get(&sec_file, &name), s.file_size(), "{f} {name}");
        }
        let st = m.symtab().unwrap();
        assert_eq!(
            get(&sec_file, "Symbol Table"),
            u64::from(st.nsyms) * 16,
            "{f}"
        );
        assert_eq!(get(&sec_file, "String Table"), u64::from(st.strsize), "{f}");
        let cmds: u64 = m.load_commands().iter().map(|c| u64::from(c.size)).sum();
        assert_eq!(get(&sec_file, MACHO_HEADERS), m.header().size + cmds, "{f}");
        for c in m.load_commands() {
            let name = match c.cmd {
                LC_CODE_SIGNATURE => "Code Signature",
                LC_FUNCTION_STARTS => "Function Start Addresses",
                LC_DYLD_CHAINED_FIXUPS => "Chained Fixups",
                LC_DYLD_EXPORTS_TRIE => "Exports Trie",
                _ => continue,
            };
            let (_, size) = m.linkedit_data(&c).unwrap();
            assert_eq!(get(&sec_file, name), u64::from(size), "{f} {name}");
        }
    }
}

#[test]
fn symbols_run_to_the_next() {
    let data = fixture("program-arm64");
    let m = MachO::parse(&data).unwrap();
    let maps = maps(&data, "p", &[Source::Symbols, Source::RawSymbols]).unwrap();
    let (vm, file) = totals(&maps, 0);
    let syms: Vec<_> = m
        .symbols()
        .into_iter()
        .filter(|s| !s.is_stab() && s.n_value != 0)
        .collect();
    let compute = syms.iter().find(|s| s.name == b"_compute").unwrap();
    let next = syms
        .iter()
        .map(|s| s.n_value)
        .filter(|&a| a > compute.n_value)
        .min()
        .unwrap();
    // Its code, its symbol table entry, and its name (in __LINKEDIT,
    // which is mapped: memory too).
    let tables = 16 + b"_compute\0".len() as u64;
    assert_eq!(get(&vm, "_compute"), next - compute.n_value + tables);
    assert_eq!(get(&file, "_compute"), next - compute.n_value + tables);
    // The 4 KiB zero-fill buffer: memory only, plus its table entries.
    assert!(get(&vm, "_buffer") >= 4096);
    let (raw, _) = totals(&maps, 1);
    assert_eq!(raw.get("_compute"), vm.get("_compute"));
}

#[test]
fn universal_files_by_arch() {
    let data = fixture("program-universal");
    let archs = hexcavator_macho::fat_archs(&data).unwrap();
    let maps = maps(&data, "u", &[Source::Archs, Source::Segments]).unwrap();
    let (_, file) = totals(&maps, 0);
    for (a, name) in archs.iter().zip(["x86_64", "arm64"]) {
        assert_eq!(get(&file, name), a.size, "{name}");
    }
    // Thin files are one architecture.
    let thin = fixture("program-x86_64");
    let maps = super::maps(&thin, "t", &[Source::Archs]).unwrap();
    let (_, file) = totals(&maps, 0);
    assert_eq!(get(&file, "x86_64"), thin.len() as u64);
}

/// The members of a static library, as `llvm-ar tv` lists them.
fn ar_members(listing: &str) -> Vec<(String, u64)> {
    listing
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f[f.len() - 1].to_string(), f[2].parse().unwrap())
        })
        .collect()
}

/// A static library: its members by name (each its own bytes, as llvm-ar
/// lists them), the archive's headers and symbol table, and the members'
/// sections and symbols as in the objects themselves.
#[test]
fn static_libraries() {
    let data = fixture("libprogram-arm64.a");
    assert!(is_macho_input(&data));
    let listing = String::from_utf8(fixture("libprogram-arm64.a.members.txt")).unwrap();
    let members = ar_members(&listing);
    assert_eq!(members.len(), 2);
    let sources = [Source::ArMembers, Source::Sections, Source::Symbols];
    let maps = maps(&data, "lib.a", &sources).unwrap();
    let (vm, file) = totals(&maps, 0);
    let ar = Archive::parse(&data).unwrap();
    let mut overhead = 8;
    let mut symdef = 0;
    for m in ar.members() {
        overhead +=
            m.data_offset - m.header_offset + (m.end() - m.data_offset - m.data.len() as u64);
        if m.kind == MemberKind::SymbolTable {
            symdef += m.data.len() as u64;
        }
    }
    for (name, size) in &members {
        assert_eq!(get(&file, name), *size, "{name}");
    }
    assert_eq!(get(&file, AR_HEADERS), overhead);
    assert!(symdef > 0);
    assert_eq!(get(&file, AR_SYMBOLS), symdef);
    assert_eq!(
        members.iter().map(|m| m.1).sum::<u64>() + overhead + symdef,
        data.len() as u64
    );

    // The program object's member has what the object alone has.
    let object = fixture("program-arm64.o");
    let alone = super::maps(&object, "o", &sources).unwrap();
    let m = MachO::parse(&object).unwrap();
    let text: u64 = m.sections().iter().map(|s| s.size).sum();
    assert!(get(&vm, "program-arm64.o") >= text);
    let (ar_sec_vm, _) = totals(&maps, 1);
    let (o_sec_vm, _) = totals(&alone, 1);
    for (name, size) in &o_sec_vm {
        if name.starts_with('[') {
            continue;
        }
        // The other member has some of the same sections.
        assert!(get(&ar_sec_vm, name) >= *size, "{name}");
    }
    let (ar_sym_vm, ar_sym_file) = totals(&maps, 2);
    let (o_sym_vm, o_sym_file) = totals(&alone, 2);
    for name in [
        "_compute",
        "_start",
        "__tlv_bootstrap",
        "_buffer",
        "_counter",
    ] {
        assert!(get(&o_sym_vm, name) > 0, "{name}");
        assert_eq!(get(&ar_sym_vm, name), get(&o_sym_vm, name), "{name}");
        assert_eq!(get(&ar_sym_file, name), get(&o_sym_file, name), "{name}");
    }
    // Neither DWARF source reads an archive's unrelocated objects.
    let maps = super::maps(&data, "lib.a", &[Source::CompileUnits]).unwrap();
    let (_, file) = totals(&maps, 0);
    assert!(
        file.keys()
            .all(|k| k.starts_with('[') || !k.ends_with(".c")),
        "{file:?}"
    );
}

/// A universal static library: each architecture's archive, and its
/// members.
#[test]
fn universal_static_libraries() {
    let data = fixture("libprogram-universal.a");
    let archs = hexcavator_macho::fat_archs(&data).unwrap();
    let maps = maps(&data, "u.a", &[Source::Archs, Source::ArMembers]).unwrap();
    let (_, file) = totals(&maps, 0);
    let mut names: Vec<String> = Vec::new();
    for a in &archs {
        let name = hexcavator_macho::arch_name(a.cputype, a.cpusubtype);
        assert_eq!(get(&file, &name), a.size, "{name}");
        names.push(name);
    }
    names.sort();
    assert_eq!(names, ["arm64", "x86_64"]);
    let (_, members) = totals(&maps, 1);
    for name in [
        "program-arm64.o",
        "second-arm64.o",
        "program-x86_64.o",
        "second-x86_64.o",
    ] {
        assert!(get(&members, name) > 0, "{name}");
    }
}

/// An object's first function is at address 0: it is a symbol all the
/// same (bloaty drops it), and it, not the assembler's `ltmp0` label at
/// the same address, gets the bytes.
#[test]
fn symbols_at_zero_in_objects() {
    let data = fixture("program-arm64.o");
    let m = MachO::parse(&data).unwrap();
    let first = m
        .symbols()
        .into_iter()
        .find(|s| s.is_section_defined() && !s.is_stab() && s.n_value == 0 && s.name[0] == b'_')
        .expect("a symbol at 0");
    let name = String::from_utf8_lossy(first.name).into_owned();
    let maps = maps(&data, "o", &[Source::RawSymbols]).unwrap();
    let (vm, _) = totals(&maps, 0);
    assert!(get(&vm, &name) > 0, "{name}");
    assert_eq!(get(&vm, "ltmp0"), 0);
}

/// Truncated and corrupted inputs give errors or maps, never panics.
#[test]
fn hostile_inputs() {
    for f in [
        "program-x86_64",
        "program-universal",
        "libprogram-universal.a",
    ] {
        let clean = fixture(f);
        let step = (clean.len() / 400).max(1);
        for n in (0..clean.len()).step_by(step) {
            let _ = maps(&clean[..n], f, SOURCES);
        }
        // Corrupt the headers and load commands thoroughly.
        for i in (0..1536.min(clean.len())).step_by(5) {
            for v in [0x00, 0xFF] {
                let mut d = clean.clone();
                d[i] = v;
                if let Ok(m) = maps(&d, f, SOURCES) {
                    assert!(m.base.file.covers(0, d.len() as u64));
                }
            }
        }
    }
}

/// `compileunits` from a dSYM's DWARF (matched by UUID, also within a
/// universal file), and from an object's own `__DWARF`.
#[test]
fn compile_units_from_debug_files() {
    let unit_at = |maps: &Maps, addr: u64| {
        maps.sources[0]
            .1
            .vm
            .get(addr)
            .map(|e| maps.labels.name(e.label).to_string())
    };
    for arch in ["arm64", "x86_64"] {
        let data = fixture(&format!("program-{arch}"));
        let dwarf = fixture(&format!("program-{arch}.dwarf"));
        let m = MachO::parse(&data).unwrap();
        let maps = maps_with_debug(&data, "p", &[Source::CompileUnits], Some(&dwarf)).unwrap();
        for (sym, unit) in [
            ("_compute", "program.c"),
            ("_start", "program.c"),
            ("_counter", "program.c"),
            ("_second_sum", "second.c"),
            ("_second_table", "second.c"),
        ] {
            let s = m
                .symbols()
                .into_iter()
                .find(|s| s.name == sym.as_bytes() && !s.is_stab())
                .unwrap();
            let got = unit_at(&maps, s.n_value).unwrap_or_default();
            assert!(got.ends_with(unit), "{arch} {sym}: {got}");
        }
        // The DWARF is not in the file: none of its bytes are charged, and
        // every byte is still labeled.
        let (_, file) = totals(&maps, 0);
        assert_eq!(file.values().sum::<u64>(), data.len() as u64);
        // Without the debug file: only the fallbacks.
        let plain = maps_with_debug(&data, "p", &[Source::CompileUnits], None).unwrap();
        assert!(totals(&plain, 0).0.keys().all(|k| k.starts_with('[')));
        // Another image's debug information is not used.
        let other = fixture(if arch == "arm64" {
            "program-x86_64.dwarf"
        } else {
            "program-arm64.dwarf"
        });
        let wrong = maps_with_debug(&data, "p", &[Source::CompileUnits], Some(&other)).unwrap();
        assert!(
            totals(&wrong, 0).0.keys().all(|k| k.starts_with('[')),
            "{arch}"
        );
    }
    // A universal file: each slice finds its own DWARF in a universal
    // debug file... or the one thin file that matches.
    let fat = fixture("program-universal");
    let dwarf = fixture("program-arm64.dwarf");
    let maps = maps_with_debug(&fat, "u", &[Source::CompileUnits], Some(&dwarf)).unwrap();
    assert!(totals(&maps, 0).0.contains_key("program.c"));
    // An object's own DWARF: its code and its debug sections, to the unit.
    let data = fixture("program-x86_64.o");
    let m = MachO::parse(&data).unwrap();
    let maps = super::maps(&data, "o", &[Source::CompileUnits]).unwrap();
    let compute = m
        .symbols()
        .into_iter()
        .find(|s| s.name == b"_compute")
        .unwrap();
    assert_eq!(
        unit_at(&maps, compute.n_value).as_deref(),
        Some("program.c")
    );
    let (_, file) = totals(&maps, 0);
    assert_eq!(get(&file, "[__DWARF,__debug_info]"), 0);
    assert!(get(&file, "program.c") > 1000);
}

/// Data no symbol covers goes to the first code symbol (in symbol table
/// order) that refers to it, as llvm-objdump finds the references; ours are
/// the same. Every byte of the fixture's literals and constants then
/// belongs to a function (bloaty reads none of this for Mach-O).
#[test]
fn referenced_data_goes_to_the_first_referrer() {
    for a in ["x86_64", "arm64"] {
        let name = format!("refs-{a}");
        let data = fixture(&name);
        let listing = String::from_utf8(fixture(&format!("{name}.objdump.txt"))).unwrap();
        let oracle = crate::disasm::oracle::objdump_references(&listing);
        let m = MachO::parse(&data).unwrap();
        let arch = if a == "x86_64" {
            crate::disasm::Arch::X64
        } else {
            crate::disasm::Arch::Arm64
        };
        let sections = m.sections();
        let ext = extents(&m);
        let covered = |t: u64| ext.iter().any(|(s, e)| t >= s.n_value && t < *e);
        let mut first: Vec<(u64, String)> = Vec::new();
        for (s, end) in &ext {
            let sec = sections
                .iter()
                .find(|x| s.n_value >= x.addr && s.n_value - x.addr < x.size)
                .unwrap();
            if sec.sectname != b"__text" {
                continue;
            }
            let fname = String::from_utf8_lossy(s.name).into_owned();
            let want = &oracle.iter().find(|(n, _)| *n == fname).unwrap().1;
            let at = (u64::from(sec.offset) + s.n_value - sec.addr) as usize;
            let code = &data[at..at + (end - s.n_value) as usize];
            let mut ours = Vec::new();
            crate::disasm::references(arch, code, s.n_value, &mut ours);
            let ours: Vec<u64> = ours.iter().map(|r| r.to).collect();
            assert_eq!(&ours, want, "{name} {fname}");
            for &t in want {
                if !covered(t) && !first.iter().any(|f| f.0 == t) {
                    first.push((t, fname.clone()));
                }
            }
        }
        assert!(first.len() >= 4, "{name}: {first:x?}");
        let maps = maps(&data, &name, &[Source::RawSymbols]).unwrap();
        let map = &maps.sources[0].1;
        for (t, f) in &first {
            let got = map.vm.get(*t).map(|e| maps.labels.name(e.label));
            assert_eq!(got, Some(f.as_str()), "{name} {t:#x}");
        }
        for sect in [&b"__cstring"[..], b"__const"] {
            let s = sections.iter().find(|s| s.sectname == sect).unwrap();
            assert!(map.vm.covers(s.addr, s.addr + s.size), "{name}");
            let owners: Vec<String> = map
                .vm
                .overlapping(s.addr, s.addr + s.size)
                .map(|e| maps.labels.name(e.label).to_string())
                .collect();
            assert!(
                owners.iter().all(|o| !o.starts_with('[')),
                "{name}: {owners:?}"
            );
            if sect == b"__cstring" {
                assert!(owners.iter().any(|o| o == "_shared_first"));
                assert!(!owners.iter().any(|o| o == "_shared_second"));
            }
        }
    }
}

//! The testdata/macho fixtures (built by tools/macho/build.cmd with clang
//! and ld64.lld: arm64 and x86_64 executables, objects, a dylib, and a
//! universal file) against llvm-readobj's and llvm-objdump's dumps: the
//! header, every segment, section, and symbol, the dynamic symbol table
//! command, and the universal headers.
#![allow(clippy::cast_possible_truncation, reason = "small test files")]

use std::collections::HashMap;
use std::path::PathBuf;

use hexcavator_macho::consts::*;
use hexcavator_macho::{MachO, fat_archs};

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/macho")
        .join(name)
}

type Block = HashMap<String, String>;

/// Top-level blocks (`MachHeader {`, `Segment {`, `Dysymtab {`) and the
/// blocks of top-level arrays (`Sections [`, `Symbols [`), by name.
fn parse_dump(text: &str) -> HashMap<String, Vec<Block>> {
    let mut out: HashMap<String, Vec<Block>> = HashMap::new();
    let mut array: Option<String> = None;
    let mut block: Option<(String, usize)> = None;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if indent == 0 {
            if let Some(a) = t.strip_suffix(" [") {
                array = Some(a.to_string());
                block = None;
            } else if let Some(b) = t.strip_suffix(" {") {
                array = None;
                out.entry(b.to_string()).or_default().push(Block::new());
                block = Some((b.to_string(), 2));
            }
            continue;
        }
        if indent == 2 && t.ends_with('{') && array.is_some() {
            let a = array.clone().unwrap();
            out.entry(a.clone()).or_default().push(Block::new());
            block = Some((a, 4));
            continue;
        }
        let Some((name, depth)) = &block else {
            continue;
        };
        if indent != *depth {
            continue;
        }
        if t == "Extern" || t == "PrivateExtern" {
            out.get_mut(name)
                .unwrap()
                .last_mut()
                .unwrap()
                .insert(t.to_string(), String::new());
        } else if let Some(k) = t.strip_suffix(':') {
            out.get_mut(name)
                .unwrap()
                .last_mut()
                .unwrap()
                .insert(k.to_string(), String::new());
        } else if let Some((k, v)) = t.split_once(": ").or_else(|| t.split_once(" [")) {
            out.get_mut(name)
                .unwrap()
                .last_mut()
                .unwrap()
                .insert(k.to_string(), v.to_string());
        }
    }
    out
}

/// A number, or the last parenthesized number.
fn num(v: &str) -> u64 {
    let v = v.trim();
    let v = match (v.rfind('('), v.ends_with(')')) {
        (Some(i), true) => &v[i + 1..v.len() - 1],
        _ => v,
    };
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => v.parse().unwrap_or_else(|_| panic!("number {v:?}")),
    }
}

fn name_of(v: &str) -> &str {
    v.rfind(" (").map_or(v, |i| &v[..i]).trim()
}

fn get<'b>(b: &'b Block, k: &str) -> &'b str {
    b.get(k).unwrap_or_else(|| panic!("no {k} in {b:?}"))
}

fn prot(v: &str) -> u32 {
    let b = v.as_bytes();
    u32::from(b[0] == b'r') * VM_PROT_READ
        + u32::from(b[1] == b'w') * VM_PROT_WRITE
        + u32::from(b[2] == b'x') * VM_PROT_EXECUTE
}

fn check(file: &str) {
    let data = std::fs::read(testdata(file)).unwrap();
    let dump =
        parse_dump(&std::fs::read_to_string(testdata(&format!("{file}.readobj.txt"))).unwrap());
    let m = MachO::parse(&data).unwrap();
    let h = m.header();
    let hd = &dump["MachHeader"][0];
    assert_eq!(u64::from(h.cputype), num(get(hd, "CpuType")), "{file}");
    assert_eq!(u64::from(h.filetype), num(get(hd, "FileType")), "{file}");
    assert_eq!(
        u64::from(h.ncmds),
        num(get(hd, "NumOfLoadCommands")),
        "{file}"
    );
    assert_eq!(
        u64::from(h.sizeofcmds),
        num(get(hd, "SizeOfLoadCommands")),
        "{file}"
    );
    assert_eq!(u64::from(h.flags), num(get(hd, "Flags")), "{file}");
    assert_eq!(m.load_commands().len(), h.ncmds as usize, "{file}");

    let segs = m.segments();
    let theirs = &dump["Segment"];
    assert_eq!(segs.len(), theirs.len(), "{file} segments");
    for (s, b) in segs.iter().zip(theirs) {
        let ctx = format!("{file} {}", String::from_utf8_lossy(s.name));
        assert_eq!(String::from_utf8_lossy(s.name), get(b, "Name"), "{ctx}");
        assert_eq!(s.vmaddr, num(get(b, "vmaddr")), "{ctx}");
        assert_eq!(s.vmsize, num(get(b, "vmsize")), "{ctx}");
        assert_eq!(s.fileoff, num(get(b, "fileoff")), "{ctx}");
        assert_eq!(s.filesize, num(get(b, "filesize")), "{ctx}");
        assert_eq!(s.maxprot, prot(get(b, "maxprot")), "{ctx}");
        assert_eq!(s.initprot, prot(get(b, "initprot")), "{ctx}");
        assert_eq!(s.sections.len() as u64, num(get(b, "nsects")), "{ctx}");
        assert_eq!(u64::from(s.flags), num(get(b, "flags")), "{ctx}");
    }

    let sections = m.sections();
    let theirs = &dump["Sections"];
    assert_eq!(sections.len(), theirs.len(), "{file} sections");
    for (s, b) in sections.iter().zip(theirs) {
        let ctx = format!("{file} section {}", s.index);
        assert_eq!(s.index as u64, num(get(b, "Index")), "{ctx}");
        assert_eq!(
            String::from_utf8_lossy(s.sectname),
            name_of(get(b, "Name")),
            "{ctx}"
        );
        assert_eq!(
            String::from_utf8_lossy(s.segname),
            name_of(get(b, "Segment")),
            "{ctx}"
        );
        assert_eq!(s.addr, num(get(b, "Address")), "{ctx}");
        assert_eq!(s.size, num(get(b, "Size")), "{ctx}");
        assert_eq!(u64::from(s.offset), num(get(b, "Offset")), "{ctx}");
        assert_eq!(u64::from(s.align), num(get(b, "Alignment")), "{ctx}");
        assert_eq!(
            u64::from(s.reloff),
            num(get(b, "RelocationOffset")),
            "{ctx}"
        );
        assert_eq!(u64::from(s.nreloc), num(get(b, "RelocationCount")), "{ctx}");
        assert_eq!(u64::from(s.kind()), num(get(b, "Type")), "{ctx}");
        // readobj shows the attribute bits shifted down past the type.
        assert_eq!(u64::from(s.flags >> 8), num(get(b, "Attributes")), "{ctx}");
        assert_eq!(u64::from(s.reserved1), num(get(b, "Reserved1")), "{ctx}");
        assert_eq!(u64::from(s.reserved2), num(get(b, "Reserved2")), "{ctx}");
    }

    let syms = m.symbols();
    let theirs = dump.get("Symbols").map_or(&[][..], Vec::as_slice);
    assert_eq!(syms.len(), theirs.len(), "{file} symbols");
    assert!(!syms.is_empty());
    for (s, b) in syms.iter().zip(theirs) {
        let ctx = format!("{file} symbol {}", s.index);
        assert_eq!(
            String::from_utf8_lossy(s.name),
            name_of(get(b, "Name")),
            "{ctx}"
        );
        assert_eq!(u64::from(s.strx), num(get(b, "Name")), "{ctx}");
        // readobj shows the type bits (and STABS whole), and the external
        // and private-external bits as words.
        let ty = if s.is_stab() {
            s.n_type
        } else {
            s.n_type & (N_TYPE | 0xE0)
        };
        assert_eq!(u64::from(ty), num(get(b, "Type")), "{ctx}");
        if !s.is_stab() {
            assert_eq!(s.n_type & N_EXT != 0, b.contains_key("Extern"), "{ctx}");
            assert_eq!(
                s.n_type & N_PEXT != 0,
                b.contains_key("PrivateExtern"),
                "{ctx}"
            );
        }
        assert_eq!(u64::from(s.n_sect), num(get(b, "Section")), "{ctx}");
        assert_eq!(s.n_value, num(get(b, "Value")), "{ctx}");
        // readobj splits n_desc into a reference type (low bits) and flags.
        let desc = num(get(b, "RefType")) | num(get(b, "Flags"));
        assert_eq!(u64::from(s.n_desc), desc, "{file} {ctx}");
    }

    if let Some(d) = dump.get("Dysymtab") {
        let ours = m.dysymtab().unwrap();
        let b = &d[0];
        for (k, v) in [
            ("ilocalsym", ours.ilocalsym),
            ("nlocalsym", ours.nlocalsym),
            ("iextdefsym", ours.iextdefsym),
            ("nextdefsym", ours.nextdefsym),
            ("iundefsym", ours.iundefsym),
            ("nundefsym", ours.nundefsym),
            ("indirectsymoff", ours.indirectsymoff),
            ("nindirectsyms", ours.nindirectsyms),
            ("locreloff", ours.locreloff),
            ("nlocrel", ours.nlocrel),
        ] {
            assert_eq!(u64::from(v), num(get(b, k)), "{file} {k}");
        }
    }
}

#[test]
fn matches_llvm_readobj() {
    for f in [
        "program-arm64",
        "program-x86_64",
        "program-arm64.o",
        "program-x86_64.o",
        "libsecond-arm64.dylib",
    ] {
        check(f);
    }
}

#[test]
fn load_commands_match_llvm_objdump() {
    let data = std::fs::read(testdata("program-arm64")).unwrap();
    let m = MachO::parse(&data).unwrap();
    let text = std::fs::read_to_string(testdata("program-arm64.loadcmds.txt")).unwrap();
    let mut theirs = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(l) = lines.next() {
        if l.starts_with("Load command ") {
            let cmd = lines
                .next()
                .unwrap()
                .trim()
                .strip_prefix("cmd ")
                .unwrap()
                .to_string();
            let size: u32 = lines
                .next()
                .unwrap()
                .trim()
                .strip_prefix("cmdsize ")
                .unwrap()
                .parse()
                .unwrap();
            theirs.push((cmd, size));
        }
    }
    let names: HashMap<u32, &str> = [
        (LC_SEGMENT_64, "LC_SEGMENT_64"),
        (LC_SYMTAB, "LC_SYMTAB"),
        (LC_DYSYMTAB, "LC_DYSYMTAB"),
        (LC_LOAD_DYLINKER, "LC_LOAD_DYLINKER"),
        (LC_UUID, "LC_UUID"),
        (LC_BUILD_VERSION, "LC_BUILD_VERSION"),
        (LC_MAIN, "LC_MAIN"),
        (LC_FUNCTION_STARTS, "LC_FUNCTION_STARTS"),
        (LC_DATA_IN_CODE, "LC_DATA_IN_CODE"),
        (LC_CODE_SIGNATURE, "LC_CODE_SIGNATURE"),
        (LC_DYLD_CHAINED_FIXUPS, "LC_DYLD_CHAINED_FIXUPS"),
        (LC_DYLD_EXPORTS_TRIE, "LC_DYLD_EXPORTS_TRIE"),
        (LC_SOURCE_VERSION, "LC_SOURCE_VERSION"),
        (LC_DYLD_INFO_ONLY, "LC_DYLD_INFO_ONLY"),
    ]
    .into_iter()
    .collect();
    let ours: Vec<(String, u32)> = m
        .load_commands()
        .iter()
        .map(|c| {
            (
                names
                    .get(&c.cmd)
                    .map_or_else(|| format!("{:#x}", c.cmd), std::string::ToString::to_string),
                c.size,
            )
        })
        .collect();
    assert_eq!(ours, theirs);
    assert!(m.uuid().is_some());
    // Every link-edit table lies within __LINKEDIT.
    let le = m
        .segments()
        .into_iter()
        .find(|s| s.name == b"__LINKEDIT")
        .unwrap();
    for c in m.load_commands() {
        if let Some((off, size)) = matches!(
            c.cmd,
            LC_FUNCTION_STARTS
                | LC_DATA_IN_CODE
                | LC_CODE_SIGNATURE
                | LC_DYLD_CHAINED_FIXUPS
                | LC_DYLD_EXPORTS_TRIE
        )
        .then(|| m.linkedit_data(&c))
        .flatten()
        {
            assert!(
                u64::from(off) >= le.fileoff && u64::from(off + size) <= le.fileoff + le.filesize
            );
        }
    }
}

#[test]
fn universal_headers_match_llvm_objdump() {
    let data = std::fs::read(testdata("program-universal")).unwrap();
    let archs = fat_archs(&data).unwrap();
    let text = std::fs::read_to_string(testdata("program-universal.fat.txt")).unwrap();
    let field = |k: &str| -> Vec<u64> {
        text.lines()
            .filter_map(|l| l.trim().strip_prefix(k))
            .map(|v| v.split_whitespace().next().unwrap().parse().unwrap())
            .collect()
    };
    assert_eq!(
        archs.iter().map(|a| a.offset).collect::<Vec<_>>(),
        field("offset ")
    );
    assert_eq!(
        archs.iter().map(|a| a.size).collect::<Vec<_>>(),
        field("size ")
    );
    let names: Vec<String> = archs
        .iter()
        .map(|a| hexcavator_macho::arch_name(a.cputype, a.cpusubtype))
        .collect();
    assert_eq!(names, ["x86_64", "arm64"]);
    // Each slice is the thin file.
    for (a, thin) in archs.iter().zip(["program-x86_64", "program-arm64"]) {
        let t = std::fs::read(testdata(thin)).unwrap();
        assert_eq!(
            &data[a.offset as usize..(a.offset + a.size) as usize],
            &t[..]
        );
    }
}

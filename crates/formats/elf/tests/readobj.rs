//! Every fixture in testdata/elf (built by tools/elf/build.cmd with clang
//! and ld.lld for x86-64, i386, AArch64 in both byte orders, and big-endian
//! ARM) against llvm-readobj's dump of it: the file header, every section,
//! program header, symbol, and dynamic symbol, and the build ID.

use std::collections::HashMap;
use std::path::PathBuf;

use hexcavator_elf::{Class, ElfFile, consts::*};

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/elf")
}

/// One `Name {` block of llvm-readobj's output: its `key: value` lines.
type Block = HashMap<String, String>;

/// The blocks of each top-level array (`Sections`, `ProgramHeaders`,
/// `Symbols`, `DynamicSymbols`), and the `ElfHeader` block's fields.
struct Dump {
    header: Block,
    arrays: HashMap<String, Vec<Block>>,
    build_id: Option<String>,
}

fn parse_dump(text: &str) -> Dump {
    let mut header = Block::new();
    let mut arrays: HashMap<String, Vec<Block>> = HashMap::new();
    let mut array: Option<String> = None;
    let mut in_header = false;
    let mut build_id = None;
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if indent == 0 {
            in_header = t == "ElfHeader {";
            array = t.strip_suffix(" [").map(str::to_string);
            continue;
        }
        if let Some(id) = t.strip_prefix("Build ID: ") {
            build_id = Some(id.to_string());
        }
        let Some((k, v)) = t.split_once(": ").or_else(|| t.split_once(" [")) else {
            if indent == 2
                && t.ends_with('{')
                && let Some(a) = &array
            {
                arrays.entry(a.clone()).or_default().push(Block::new());
            }
            continue;
        };
        if in_header && indent == 2 {
            header.insert(k.to_string(), v.to_string());
        } else if indent == 4
            && let Some(b) = array
                .as_ref()
                .and_then(|a| arrays.get_mut(a))
                .and_then(|v| v.last_mut())
        {
            b.insert(k.to_string(), v.to_string());
        }
    }
    Dump {
        header,
        arrays,
        build_id,
    }
}

/// A number, or the last parenthesized number: `0x40`, `560`,
/// `PT_LOAD (0x1)`, `.bss (0x11)`, `(0x32)`.
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

/// The text before the last ` (`: `hidden_state (11)` is `hidden_state`.
fn name(v: &str) -> &str {
    v.rfind(" (").map_or(v, |i| &v[..i]).trim()
}

fn get<'b>(b: &'b Block, k: &str) -> &'b str {
    b.get(k).unwrap_or_else(|| panic!("no {k} in {b:?}"))
}

fn check(file: &str) {
    let path = testdata().join(file);
    let data = std::fs::read(&path).unwrap();
    let dump = parse_dump(
        &std::fs::read_to_string(testdata().join(format!("{file}.readobj.txt"))).unwrap(),
    );
    let elf = ElfFile::parse(&data).unwrap();
    let h = elf.header();
    let class = match elf.class() {
        Class::Elf32 => "32-bit (0x1)",
        Class::Elf64 => "64-bit (0x2)",
    };
    assert!(
        std::fs::read_to_string(testdata().join(format!("{file}.readobj.txt")))
            .unwrap()
            .contains(&format!("Class: {class}")),
        "{file} class"
    );
    let hd = &dump.header;
    assert_eq!(u64::from(h.kind), num(get(hd, "Type")), "{file} type");
    assert_eq!(
        u64::from(h.machine),
        num(get(hd, "Machine")),
        "{file} machine"
    );
    assert_eq!(h.entry, num(get(hd, "Entry")), "{file} entry");
    assert_eq!(h.phoff, num(get(hd, "ProgramHeaderOffset")), "{file}");
    assert_eq!(h.shoff, num(get(hd, "SectionHeaderOffset")), "{file}");
    assert_eq!(u64::from(h.flags), num(get(hd, "Flags")), "{file} flags");
    assert_eq!(u64::from(h.ehsize), num(get(hd, "HeaderSize")), "{file}");
    assert_eq!(
        u64::from(h.phnum),
        num(get(hd, "ProgramHeaderCount")),
        "{file}"
    );
    assert_eq!(
        u64::from(h.shnum),
        num(get(hd, "SectionHeaderCount")),
        "{file}"
    );
    assert_eq!(
        u64::from(h.shstrndx),
        num(get(hd, "StringTableSectionIndex")),
        "{file}"
    );

    let sections: Vec<_> = elf.sections().collect();
    let theirs = &dump.arrays["Sections"];
    assert_eq!(sections.len(), theirs.len(), "{file} section count");
    for (s, b) in sections.iter().zip(theirs) {
        let ctx = format!("{file} section {}", s.index);
        assert_eq!(s.index as u64, num(get(b, "Index")), "{ctx}");
        assert_eq!(
            String::from_utf8_lossy(s.name),
            name(get(b, "Name")),
            "{ctx}"
        );
        assert_eq!(u64::from(s.kind), num(get(b, "Type")), "{ctx}");
        assert_eq!(s.flags, num(get(b, "Flags")), "{ctx}");
        assert_eq!(s.addr, num(get(b, "Address")), "{ctx}");
        assert_eq!(s.offset, num(get(b, "Offset")), "{ctx}");
        assert_eq!(s.size, num(get(b, "Size")), "{ctx}");
        assert_eq!(u64::from(s.link), num(get(b, "Link")), "{ctx}");
        assert_eq!(u64::from(s.info), num(get(b, "Info")), "{ctx}");
        assert_eq!(s.addralign, num(get(b, "AddressAlignment")), "{ctx}");
        assert_eq!(s.entsize, num(get(b, "EntrySize")), "{ctx}");
        let first = sections.iter().find(|x| x.name == s.name).unwrap().index;
        assert_eq!(elf.section_by_name(s.name).unwrap().index, first, "{ctx}");
    }

    let segments: Vec<_> = elf.segments().collect();
    let theirs = dump
        .arrays
        .get("ProgramHeaders")
        .map_or(&[][..], Vec::as_slice);
    assert_eq!(segments.len(), theirs.len(), "{file} segment count");
    for (p, b) in segments.iter().zip(theirs) {
        let ctx = format!("{file} segment {}", p.index);
        assert_eq!(u64::from(p.kind), num(get(b, "Type")), "{ctx}");
        assert_eq!(p.offset, num(get(b, "Offset")), "{ctx}");
        assert_eq!(p.vaddr, num(get(b, "VirtualAddress")), "{ctx}");
        assert_eq!(p.paddr, num(get(b, "PhysicalAddress")), "{ctx}");
        assert_eq!(p.filesz, num(get(b, "FileSize")), "{ctx}");
        assert_eq!(p.memsz, num(get(b, "MemSize")), "{ctx}");
        assert_eq!(u64::from(p.flags), num(get(b, "Flags")), "{ctx}");
        assert_eq!(p.align, num(get(b, "Alignment")), "{ctx}");
    }

    for (kind, array) in [(SHT_SYMTAB, "Symbols"), (SHT_DYNSYM, "DynamicSymbols")] {
        let ours = sections
            .iter()
            .find(|s| s.kind == kind)
            .map(|t| elf.symbols(t))
            .unwrap_or_default();
        let theirs = dump.arrays.get(array).map_or(&[][..], Vec::as_slice);
        assert_eq!(ours.len(), theirs.len(), "{file} {array} count");
        for (s, b) in ours.iter().zip(theirs) {
            let ctx = format!("{file} {array} {}", s.index);
            // Dynamic symbol names carry a version (`name@VER`).
            let their_name = name(get(b, "Name"));
            let their_name = if kind == SHT_DYNSYM {
                their_name.split('@').next().unwrap()
            } else {
                their_name
            };
            // A section symbol with no name is shown with its section's.
            let their_name = if s.kind == STT_SECTION && num(get(b, "Name")) == 0 {
                ""
            } else {
                their_name
            };
            assert_eq!(String::from_utf8_lossy(s.name), their_name, "{ctx}");
            assert_eq!(s.value, num(get(b, "Value")), "{ctx}");
            assert_eq!(s.size, num(get(b, "Size")), "{ctx}");
            assert_eq!(u64::from(s.bind), num(get(b, "Binding")), "{ctx}");
            assert_eq!(u64::from(s.kind), num(get(b, "Type")), "{ctx}");
            let other = b.get("Other").map_or(0, |v| num(v));
            assert_eq!(u64::from(s.visibility), other & 3, "{ctx}");
            assert_eq!(u64::from(s.shndx), num(get(b, "Section")), "{ctx}");
        }
    }

    let ours = elf
        .build_id()
        .map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(ours, dump.build_id, "{file} build id");
}

const FILES: &[&str] = &[
    "program-x86_64-linux-gnu",
    "program-x86_64-linux-gnu.o",
    "program-i386-linux-gnu",
    "program-i386-linux-gnu.o",
    "program-aarch64-linux-gnu",
    "program-aarch64-linux-gnu.o",
    "program-aarch64_be-linux-gnu",
    "program-aarch64_be-linux-gnu.o",
    "program-armeb-linux-gnueabi",
    "program-armeb-linux-gnueabi.o",
    "program.so",
    "program-stripped",
];

#[test]
fn matches_llvm_readobj() {
    for f in FILES {
        check(f);
    }
}

#[test]
fn fixtures_cover_classes_and_byte_orders() {
    let mut seen = std::collections::HashSet::new();
    for f in FILES {
        let data = std::fs::read(testdata().join(f)).unwrap();
        let elf = ElfFile::parse(&data).unwrap();
        seen.insert((elf.class(), elf.endian(), elf.is_object()));
    }
    use hexcavator_core::Endian::{Big, Little};
    for want in [
        (Class::Elf64, Little, true),
        (Class::Elf64, Little, false),
        (Class::Elf64, Big, true),
        (Class::Elf64, Big, false),
        (Class::Elf32, Little, true),
        (Class::Elf32, Little, false),
        (Class::Elf32, Big, true),
        (Class::Elf32, Big, false),
    ] {
        assert!(seen.contains(&want), "{want:?}");
    }
}

/// Relocations by section index, as `llvm-readobj --relocs` lists them:
/// each entry's `r_offset`.
fn their_relocations(text: &str) -> HashMap<usize, Vec<u64>> {
    let mut out: HashMap<usize, Vec<u64>> = HashMap::new();
    let mut section = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Section (") {
            section = rest.split(')').next().and_then(|n| n.parse().ok());
            out.entry(section.unwrap()).or_default();
        } else if t == "}" {
            section = None;
        } else if let (Some(s), Some(first)) = (section, t.split_whitespace().next()) {
            out.get_mut(&s).unwrap().push(num(first));
        }
    }
    out
}

fn check_relocations(elf: &ElfFile<'_>, text: &str, file: &str) {
    let theirs = their_relocations(text);
    let mut seen = 0;
    for s in elf.sections() {
        let ours: Vec<u64> = elf.relocations(&s).iter().map(|r| r.offset).collect();
        if s.kind != SHT_REL && s.kind != SHT_RELA {
            assert!(ours.is_empty());
            continue;
        }
        seen += 1;
        assert_eq!(
            Some(&ours),
            theirs.get(&s.index),
            "{file} relocations of section {}",
            s.index
        );
        for r in elf.relocations(&s) {
            assert!(r.file_offset >= s.offset && r.file_offset + r.size <= s.offset + s.size);
        }
    }
    assert_eq!(seen, theirs.len(), "{file}");
    assert!(seen > 0, "{file}");
    check_relocation_fields(elf, text, file);
}

/// Each relocation's symbol and addend as llvm-readobj has them (a section
/// symbol by its section's name), and its type: one number for each of the
/// file's type names, and one name for each number.
fn check_relocation_fields(elf: &ElfFile<'_>, text: &str, file: &str) {
    // Theirs, by section: (type name, symbol name, addend).
    let mut theirs: HashMap<usize, Vec<(String, String, Option<u64>)>> = HashMap::new();
    let mut section = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Section (") {
            section = rest.split(')').next().and_then(|n| n.parse().ok());
        } else if t == "}" {
            section = None;
        } else if let Some(s) = section {
            let f: Vec<&str> = t.split_whitespace().collect();
            if f.len() >= 2 {
                theirs.entry(s).or_default().push((
                    f[1].to_string(),
                    f.get(2).map_or(String::new(), |n| (*n).to_string()),
                    f.get(3).map(|a| num(a)),
                ));
            }
        }
    }
    let sections: Vec<_> = elf.sections().collect();
    let mut names: HashMap<u32, String> = HashMap::new();
    let mut numbers: HashMap<String, u32> = HashMap::new();
    for s in &sections {
        let Some(want) = theirs.get(&s.index) else {
            continue;
        };
        let symbols = sections
            .get(s.link as usize)
            .map(|t| elf.symbols(t))
            .unwrap_or_default();
        let ours = elf.relocations(s);
        assert_eq!(ours.len(), want.len(), "{file}");
        for (r, (kind, symbol, addend)) in ours.iter().zip(want) {
            let sym = symbols.get(r.symbol as usize);
            let name = match sym {
                Some(x) if x.kind == STT_SECTION => {
                    sections.get(x.shndx as usize).map_or(String::new(), |t| {
                        String::from_utf8_lossy(t.name).into_owned()
                    })
                }
                Some(x) => String::from_utf8_lossy(x.name).into_owned(),
                None => String::new(),
            };
            assert_eq!(&name, symbol, "{file} {r:?}");
            assert_eq!(r.addend.map(|a| a as u64), *addend, "{file} {r:?}");
            assert_eq!(r.addend.is_some(), s.kind == SHT_RELA, "{file}");
            let n = names.entry(r.kind).or_insert_with(|| kind.clone());
            assert_eq!(n, kind, "{file}: type {} is two names", r.kind);
            let k = numbers.entry(kind.clone()).or_insert(r.kind);
            assert_eq!(*k, r.kind, "{file}: {kind} is two types");
        }
    }
    assert!(names.len() >= 2, "{file}");
}

#[test]
fn unwind_tables_and_relocations_match_llvm_readobj() {
    for t in ["x86_64-linux-gnu", "aarch64_be-linux-gnu", "i386-linux-gnu"] {
        let file = format!("unwind-{t}");
        let data = std::fs::read(testdata().join(&file)).unwrap();
        let elf = ElfFile::parse(&data).unwrap();
        let text = std::fs::read_to_string(testdata().join(format!("{file}.unwind.txt"))).unwrap();

        // FDEs: `[0xADDR] FDE length=N`, then `initial_location: 0xPC`.
        let mut their_fdes = Vec::new();
        let mut their_table = Vec::new();
        let mut pending: Option<(u64, u64)> = None;
        let mut in_header = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("EHFrameHeader") {
                in_header = true;
            } else if t.contains(" section at offset ") {
                in_header = false;
            }
            if let Some(rest) = t.strip_prefix('[')
                && let Some((addr, rest)) = rest.split_once("] FDE length=")
            {
                let len: u64 = rest.split_whitespace().next().unwrap().parse().unwrap();
                pending = Some((num(addr), len + 4));
            }
            if let Some(pc) = t.strip_prefix("initial_location: ") {
                if in_header {
                    their_table.push(num(pc));
                } else {
                    let (addr, size) = pending.take().unwrap();
                    their_fdes.push((addr, size, num(pc)));
                }
            }
        }
        let frame = elf.section_by_name(b".eh_frame").unwrap();
        let ours: Vec<(u64, u64, u64)> = elf
            .eh_frame(&frame)
            .iter()
            .map(|f| (frame.addr + f.offset, f.size, f.pc))
            .collect();
        assert_eq!(ours, their_fdes, "{file}");
        assert_eq!(ours.len(), 3, "{file}");
        let hdr = elf.section_by_name(b".eh_frame_hdr").unwrap();
        let table: Vec<u64> = elf.eh_frame_hdr(&hdr).iter().map(|e| e.pc).collect();
        assert_eq!(table, their_table, "{file}");
        // Each FDE describes a function symbol.
        let funcs: Vec<u64> = elf
            .all_symbols()
            .iter()
            .filter(|s| s.kind == STT_FUNC)
            .map(|s| s.value)
            .collect();
        assert!(ours.iter().all(|f| funcs.contains(&f.2)), "{file}");

        check_relocations(&elf, &text, &file);
        let object = format!("unwind-{t}.o");
        let data = std::fs::read(testdata().join(&object)).unwrap();
        let elf = ElfFile::parse(&data).unwrap();
        let text =
            std::fs::read_to_string(testdata().join(format!("{object}.relocs.txt"))).unwrap();
        check_relocations(&elf, &text, &object);
    }
}

#[test]
fn reads_section_contents() {
    let data = std::fs::read(testdata().join("program-x86_64-linux-gnu")).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    let rodata = elf.section_by_name(b".rodata").unwrap();
    let bytes = elf.section_data(&rodata);
    assert!(bytes.windows(15).any(|w| w == b"hello from rbat"));
    // `.bss` occupies no file bytes; `.tbss`, if any, neither.
    let bss = elf.section_by_name(b".bss").unwrap();
    assert!(elf.section_data(&bss).is_empty());
    assert_eq!(bss.file_size(), 0);
    assert!(bss.size >= 4096);
    // Addresses in `.rodata` map back to its file offset.
    assert_eq!(elf.vaddr_to_offset(rodata.addr), Some(rodata.offset));
    let sym = elf
        .all_symbols()
        .into_iter()
        .find(|s| s.name == b"compute")
        .unwrap();
    assert_eq!(sym.kind, STT_FUNC);
    assert_eq!(sym.bind, STB_GLOBAL);
    let weak = elf
        .all_symbols()
        .into_iter()
        .find(|s| s.name == b"optional_hook")
        .unwrap();
    assert_eq!(weak.bind, STB_WEAK);
    let tls = elf
        .all_symbols()
        .into_iter()
        .find(|s| s.name == b"per_thread")
        .unwrap();
    assert_eq!(tls.kind, STT_TLS);
}

#[test]
fn section_groups_match_llvm_readobj() {
    let data = std::fs::read(testdata().join("names.o")).unwrap();
    let text = std::fs::read_to_string(testdata().join("names.o.groups.txt")).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    // Theirs: (index, flags, signature, member section indexes).
    let mut theirs: Vec<(usize, u32, String, Vec<u32>)> = Vec::new();
    let mut members = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "Group {" {
            theirs.push((0, 0, String::new(), Vec::new()));
        } else if t.starts_with("Section(s) in group [") {
            members = true;
        } else if t == "]" {
            members = false;
        } else if let Some(g) = theirs.last_mut() {
            if members {
                // `.text._Z... (5)`.
                let i = t.rsplit_once(" (").unwrap().1.trim_end_matches(')');
                g.3.push(i.parse().unwrap());
            } else if let Some(v) = t.strip_prefix("Index: ") {
                g.0 = v.parse().unwrap();
            } else if let Some(v) = t.strip_prefix("Type: ") {
                g.1 = u32::try_from(num(v)).unwrap();
            } else if let Some(v) = t.strip_prefix("Signature: ") {
                g.2 = v.to_string();
            }
        }
    }
    assert!(theirs.len() >= 5);
    let ours: Vec<(usize, u32, String, Vec<u32>)> = elf
        .groups()
        .into_iter()
        .map(|g| {
            (
                g.section,
                g.flags,
                String::from_utf8_lossy(g.signature).into_owned(),
                g.members,
            )
        })
        .collect();
    assert_eq!(ours, theirs);
    assert!(ours.iter().all(|g| g.1 == GRP_COMDAT));
}

/// Symbol versions and hash lookups: a shared object versioned by a
/// script (tools/elf/versions.map) and one that needs its versions, as
/// llvm-readobj --version-info has them.
#[test]
fn symbol_versions_and_hash_lookups() {
    use hexcavator_elf::versions::VER_FLG_BASE;
    let read = |n: &str| std::fs::read(testdata().join(n)).unwrap();
    let lib = read("libversions.so");
    let elf = ElfFile::parse(&lib).unwrap();
    let defs = elf.version_definitions();
    let names: Vec<&[u8]> = defs.iter().map(|d| d.name).collect();
    assert_eq!(names, [&b"libversions.so"[..], b"VERS_1", b"VERS_2"]);
    assert_eq!(defs[0].flags & VER_FLG_BASE, VER_FLG_BASE);
    // (ld.lld records no predecessors, as readobj shows.)
    assert!(defs.iter().all(|d| d.predecessors.is_empty()));
    // The hashes are the SysV hashes of the names.
    for d in &defs {
        assert_eq!(d.hash, hexcavator_elf::versions::sysv_hash(d.name));
    }
    let text = std::fs::read_to_string(testdata().join("libversions.so.versions.txt")).unwrap();
    assert!(text.contains("Hash: 95058209") && text.contains("Name: VERS_1"));
    let dynsym = elf.sections().find(|s| s.kind == SHT_DYNSYM).unwrap();
    let symbols = elf.symbols(&dynsym);
    let versions = elf.symbol_versions();
    assert_eq!(versions.len(), symbols.len());
    let version_of = |name: &[u8]| {
        let i = symbols.iter().position(|s| s.name == name).unwrap();
        versions[i].map(|v| (v.name, v.hidden, v.file))
    };
    assert_eq!(version_of(b"table"), Some((&b"VERS_1"[..], false, None)));
    assert_eq!(version_of(b"far"), Some((&b"VERS_2"[..], false, None)));
    // Every dynamic symbol found through both hash tables.
    for (i, s) in symbols.iter().enumerate().skip(1) {
        assert_eq!(elf.gnu_lookup(s.name), Some(i), "{:?}", s.name);
        assert_eq!(elf.sysv_lookup(s.name), Some(i), "{:?}", s.name);
        assert_eq!(elf.lookup(s.name), Some(i));
    }
    assert_eq!(elf.lookup(b"no_such_symbol"), None);
    assert_eq!(elf.sysv_lookup(b"tablex"), None);

    // The consumer needs VERS_1 and VERS_2 of libversions.so.
    let user = read("consumer.so");
    let elf = ElfFile::parse(&user).unwrap();
    let needs = elf.version_needs();
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].file, b"libversions.so");
    let needed: Vec<(&[u8], u16)> = needs[0]
        .versions
        .iter()
        .map(|v| (v.name, v.index))
        .collect();
    assert_eq!(needed, [(&b"VERS_1"[..], 3), (&b"VERS_2"[..], 2)]);
    let dynsym = elf.sections().find(|s| s.kind == SHT_DYNSYM).unwrap();
    let symbols = elf.symbols(&dynsym);
    let versions = elf.symbol_versions();
    let i = symbols.iter().position(|s| s.name == b"table").unwrap();
    let v = versions[i].unwrap();
    assert_eq!(
        (v.name, v.file),
        (&b"VERS_1"[..], Some(&b"libversions.so"[..]))
    );
    // Damaged: no panics.
    let mut d = lib.clone();
    for at in (0..d.len()).step_by(5) {
        let was = d[at];
        d[at] = was ^ 0xFF;
        if let Ok(e) = ElfFile::parse(&d) {
            let _ = (
                e.version_definitions(),
                e.version_needs(),
                e.symbol_versions(),
            );
            let _ = (e.lookup(b"table"), e.sysv_lookup(b"far"));
        }
        d[at] = was;
    }
}

/// Arm's exception index (big-endian Arm): every entry's function is a
/// function symbol's address, in order; each unwinds one of the three ways.
#[test]
fn arm_exception_index() {
    use hexcavator_elf::arm::ExidxUnwind;
    let data = std::fs::read(testdata().join("program-armeb-linux-gnueabi")).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    let s = elf.sections().find(|s| s.kind == SHT_ARM_EXIDX).unwrap();
    let entries = elf.arm_exidx(&s);
    assert_eq!(entries.len(), (s.size / 8) as usize);
    assert!(entries.windows(2).all(|w| w[0].function < w[1].function));
    let functions: Vec<u64> = elf
        .all_symbols()
        .iter()
        .filter(|s| s.kind == STT_FUNC)
        // (Thumb functions' addresses have the low bit set.)
        .map(|s| s.value & !1)
        .collect();
    let text = elf.sections().find(|s| s.name == b".text").unwrap();
    for e in &entries {
        // A function's, or the end of the code (the last entry, to bound
        // the one before).
        assert!(
            functions.contains(&e.function) || e.function == text.addr + text.size,
            "{e:?}"
        );
        match e.unwind {
            ExidxUnwind::CantUnwind => {}
            ExidxUnwind::Inline(v) => assert_eq!(v >> 28, 8, "{e:?}"),
            ExidxUnwind::Table(at) => {
                let extab = elf.sections().find(|s| s.name == b".ARM.extab").unwrap();
                assert!(at >= extab.addr && at < extab.addr + extab.size, "{e:?}");
            }
        }
    }
    // (Built with -fno-asynchronous-unwind-tables: none can unwind.)
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|e| e.unwind == ExidxUnwind::CantUnwind));
}

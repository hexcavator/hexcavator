//! `Image` over ELF, Mach-O, and WebAssembly files, against what
//! `llvm-readobj --sections` says of each (the `*.readobj.txt` beside them
//! in `testdata`): every section's name, address, size, and file offset,
//! and the file's architecture.

#![allow(clippy::cast_possible_truncation, reason = "small test files")]

use hexcavator_image::{Arch, Format, Image, Kind, SectionFlags};

/// A section as `llvm-readobj` lists it.
#[derive(Debug, Default)]
struct Listed {
    index: Option<usize>,
    name: String,
    kind: String,
    address: u64,
    size: u64,
    offset: u64,
    flags: Vec<String>,
}

fn number(s: &str) -> u64 {
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

/// The file's `Arch:` and its sections.
fn listing(text: &str) -> (String, Vec<Listed>) {
    let mut arch = String::new();
    let mut out = Vec::new();
    let mut cur: Option<Listed> = None;
    let mut in_flags = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(a) = t.strip_prefix("Arch: ") {
            arch = a.to_string();
        }
        if line == "  Section {" {
            cur = Some(Listed::default());
            continue;
        }
        let Some(c) = cur.as_mut() else { continue };
        if line == "  }" {
            out.push(cur.take().unwrap());
            continue;
        }
        if in_flags {
            if t == "]" {
                in_flags = false;
            } else if let Some(f) = t.split_whitespace().next() {
                c.flags.push(f.to_string());
            }
            continue;
        }
        // (Only the section's own fields: its symbols and relocations,
        // where listed, are indented further.)
        if !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let Some((key, value)) = t.split_once(':') else {
            if t.starts_with("Flags [") || t.starts_with("Attributes [") {
                in_flags = !t.ends_with(']');
            }
            continue;
        };
        let value = value.trim();
        match key {
            "Index" => c.index = Some(number(value) as usize),
            // `Name: .text (28)`, `Name: __text (5F 5F ...)`.
            "Name" => {
                c.name = match value.rfind(" (") {
                    Some(i) => value[..i].to_string(),
                    None if value.starts_with('(') => String::new(),
                    None => value.to_string(),
                }
            }
            "Type" => c.kind = value.to_string(),
            "Address" => c.address = number(value),
            "Size" => c.size = number(value),
            "Offset" => c.offset = number(value),
            _ => {}
        }
    }
    (arch, out)
}

fn arch_of(readobj: &str) -> Arch {
    match readobj {
        "x86_64" => Arch::X64,
        "i386" => Arch::X86,
        "aarch64" | "aarch64_be" => Arch::Arm64,
        "arm" | "armeb" => Arch::Arm,
        "wasm32" => Arch::Wasm32,
        a => panic!("arch {a}"),
    }
}

fn load(dir: &str, name: &str) -> (Vec<u8>, String) {
    let base = format!(
        "{}/../../../testdata/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&base).unwrap_or_else(|e| panic!("{base}: {e}"));
    let text = std::fs::read_to_string(format!("{base}.readobj.txt")).unwrap();
    (data, text)
}

const ELF: &[&str] = &[
    "program-aarch64-linux-gnu",
    "program-aarch64-linux-gnu.o",
    "program-aarch64_be-linux-gnu",
    "program-aarch64_be-linux-gnu.o",
    "program-armeb-linux-gnueabi",
    "program-armeb-linux-gnueabi.o",
    "program-i386-linux-gnu",
    "program-i386-linux-gnu.o",
    "program-stripped",
    "program-x86_64-linux-gnu",
    "program-x86_64-linux-gnu.o",
    "program.so",
];

#[test]
fn elf_sections_are_readobjs() {
    for name in ELF {
        let (data, text) = load("elf", name);
        let (arch, listed) = listing(&text);
        let image = Image::parse(&data).unwrap();
        assert_eq!(image.format(), Format::Elf, "{name}");
        assert_eq!(image.arch(), arch_of(&arch), "{name}");
        let object = name.ends_with(".o");
        assert_eq!(
            image.kind(),
            if object { Kind::Object } else { Kind::Linked }
        );
        assert_eq!(image.image_base(), 0);
        let sections = image.sections();
        // (`Image` leaves out the null section.)
        let listed: Vec<&Listed> = listed.iter().filter(|l| l.index != Some(0)).collect();
        assert_eq!(sections.len(), listed.len(), "{name}");
        for (s, l) in sections.iter().zip(&listed) {
            let what = format!("{name} {}", l.name);
            assert_eq!(Some(s.index), l.index, "{what}");
            assert_eq!(String::from_utf8_lossy(s.name), l.name, "{what}");
            assert_eq!(s.addr, l.address, "{what}");
            assert_eq!(s.file_offset, l.offset, "{what}");
            let nobits = l.kind.starts_with("SHT_NOBITS");
            assert_eq!(s.file_size, if nobits { 0 } else { l.size }, "{what}");
            let alloc = l.flags.iter().any(|f| f == "SHF_ALLOC");
            assert_eq!(
                s.vm_size,
                if alloc || object { l.size } else { 0 },
                "{what}"
            );
            let has = |f: &str| l.flags.iter().any(|x| x == f);
            assert_eq!(
                s.flags.contains(SectionFlags::CODE),
                has("SHF_EXECINSTR"),
                "{what}"
            );
            assert_eq!(
                s.flags.contains(SectionFlags::WRITE),
                has("SHF_WRITE"),
                "{what}"
            );
            assert_eq!(s.flags.contains(SectionFlags::NOT_LOADED), !alloc, "{what}");
            assert_eq!(s.flags.contains(SectionFlags::ZERO_FILL), nobits, "{what}");
            // What the file says is there, is there.
            if alloc && !nobits && l.size > 0 && !object {
                let bytes = image.bytes_at(s.addr, l.size).expect(&what);
                let at = l.offset as usize;
                assert_eq!(bytes, &data[at..at + l.size as usize], "{what}");
            }
        }
    }
}

const MACHO: &[&str] = &[
    "libsecond-arm64.dylib",
    "program-arm64",
    "program-arm64.o",
    "program-x86_64",
    "program-x86_64.o",
];

#[test]
fn macho_sections_are_readobjs() {
    for name in MACHO {
        let (data, text) = load("macho", name);
        let (arch, listed) = listing(&text);
        let image = Image::parse(&data).unwrap();
        assert_eq!(image.format(), Format::MachO, "{name}");
        assert_eq!(image.arch(), arch_of(&arch), "{name}");
        let object = name.ends_with(".o");
        assert_eq!(
            image.kind(),
            if object { Kind::Object } else { Kind::Linked }
        );
        let sections = image.sections();
        assert_eq!(sections.len(), listed.len(), "{name}");
        for (s, l) in sections.iter().zip(&listed) {
            let what = format!("{name} {}", l.name);
            assert_eq!(Some(s.index), l.index, "{what}");
            assert_eq!(String::from_utf8_lossy(s.name), l.name, "{what}");
            assert_eq!((s.addr, s.vm_size), (l.address, l.size), "{what}");
            assert_eq!(s.file_offset, l.offset, "{what}");
            let zero = l.kind.contains("ZeroFill");
            assert_eq!(s.flags.contains(SectionFlags::ZERO_FILL), zero, "{what}");
            assert_eq!(s.file_size, if zero { 0 } else { l.size }, "{what}");
            let code = l.flags.iter().any(|f| f.ends_with("Instructions"));
            assert_eq!(s.flags.contains(SectionFlags::CODE), code, "{what}");
            if !zero && l.size > 0 {
                let bytes = image.bytes_at(s.addr, l.size).expect(&what);
                let at = l.offset as usize;
                assert_eq!(bytes, &data[at..at + l.size as usize], "{what}");
            }
        }
        // Linked images name their dSYM by UUID.
        if !object {
            assert!(
                matches!(image.debug_ids()[..], [hexcavator_image::DebugId::Uuid(_)]),
                "{name}"
            );
        }
    }
}

#[test]
fn wasm_sections_are_readobjs() {
    let (data, text) = load("wasm", "module.wasm");
    let (arch, listed) = listing(&text);
    let image = Image::parse(&data).unwrap();
    assert_eq!(image.format(), Format::Wasm);
    assert_eq!(image.arch(), arch_of(&arch));
    assert_eq!(image.kind(), Kind::Linked);
    let sections = image.sections();
    assert_eq!(sections.len(), listed.len());
    for (s, l) in sections.iter().zip(&listed) {
        assert_eq!(s.file_size, l.size, "{l:?}");
        if l.kind.starts_with("CUSTOM") {
            // (readobj's offset is where a custom section's name starts;
            // its data follows the name.)
            let at = s.file_offset as usize;
            assert_eq!(&data[at - s.name.len()..at], s.name, "{l:?}");
            assert_eq!(s.file_offset - l.offset, s.name.len() as u64 + 1, "{l:?}");
        } else {
            assert_eq!(s.file_offset, l.offset, "{l:?}");
        }
        let code = l.kind.starts_with("CODE");
        assert_eq!(s.flags.contains(SectionFlags::CODE), code, "{l:?}");
        // Only code has addresses: offsets into the code section.
        assert_eq!(s.addr, 0);
        assert_eq!(s.vm_size, if code { l.size } else { 0 }, "{l:?}");
        if code {
            let at = l.offset as usize;
            assert_eq!(
                image.bytes_at(0, l.size),
                Some(&data[at..at + l.size as usize])
            );
            assert_eq!(image.bytes_at(1, l.size), None);
        }
    }
}

#[test]
fn elf_debug_identities() {
    let (data, _) = load("elf", "program-x86_64-linux-gnu");
    let image = Image::parse(&data).unwrap();
    let ids = image.debug_ids();
    assert!(matches!(ids[..], [hexcavator_image::DebugId::BuildId(id)] if id.len() == 20));
    // A stripped program links its debug file by name and CRC (and keeps
    // its build ID).
    let read = |name: &str| {
        std::fs::read(format!(
            "{}/../../../testdata/elf/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    let linked = read("program-linked");
    let image = Image::parse(&linked).unwrap();
    let ids = image.debug_ids();
    assert!(matches!(ids[0], hexcavator_image::DebugId::BuildId(_)));
    let link = ids.iter().find_map(|id| match *id {
        hexcavator_image::DebugId::DebugLink { path, crc } => Some((path, crc)),
        _ => None,
    });
    let (path, crc) = link.expect("a debug link");
    assert_eq!(path, b"program-split.debug");
    assert_eq!(crc, Some(crc32(&read("program-split.debug"))));
}

/// The CRC-32 `.gnu_debuglink` has (zlib's, ISO 3309).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A universal file parses as the image of the architecture chosen
/// (`hexcavator_macho::set_preferred_arch`), else the host's, else the
/// first; one without the architecture chosen is refused.
#[test]
fn universal_files_parse_as_the_image_chosen() {
    let data = std::fs::read(format!(
        "{}/../../../testdata/macho/program-universal",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let arch_of = |i: &Image<'_>| {
        let h = i.macho().unwrap().header();
        hexcavator_macho::arch_name(h.cputype, h.cpusubtype)
    };
    // The default: the host's (both of the fixture's are x86_64 and arm64).
    let image = Image::parse(&data).unwrap();
    let host = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };
    assert_eq!(arch_of(&image), host);
    for want in ["arm64", "x86_64"] {
        assert!(hexcavator_macho::set_preferred_arch(Some(want)));
        assert_eq!(arch_of(&Image::parse(&data).unwrap()), want);
    }
    assert!(hexcavator_macho::set_preferred_arch(Some("i386")));
    let e = Image::parse(&data).unwrap_err();
    assert_eq!(e.kind, hexcavator_core::ErrorKind::Unsupported);
    assert!(!hexcavator_macho::set_preferred_arch(Some("no-such-arch")));
    assert!(hexcavator_macho::set_preferred_arch(None));
    // Each of its images parses.
    for a in hexcavator_macho::fat_archs(&data).unwrap() {
        let at = a.offset as usize;
        let image = Image::parse(&data[at..at + a.size as usize]).unwrap();
        assert_eq!(image.format(), Format::MachO);
    }
}

#[test]
fn truncated_and_corrupt_files_do_not_panic() {
    for (dir, name) in [
        ("elf", "program-x86_64-linux-gnu"),
        ("elf", "program-aarch64_be-linux-gnu.o"),
        ("macho", "program-arm64"),
        ("macho", "program-x86_64.o"),
        ("wasm", "module.wasm"),
    ] {
        let (data, _) = load(dir, name);
        let exercise = |d: &[u8]| {
            if let Ok(i) = Image::parse(d) {
                let _ = (i.sections(), i.debug_ids(), i.arch(), i.kind());
                let _ = i.bytes_at(0x1000, 16);
            }
        };
        for len in (0..data.len()).step_by(7) {
            exercise(&data[..len]);
        }
        // Every byte of the headers, flipped to each of a few values.
        let mut d = data.clone();
        for at in 0..d.len().min(0x400) {
            let was = d[at];
            for v in [0, 0xFF, was ^ 0x80] {
                d[at] = v;
                exercise(&d);
            }
            d[at] = was;
        }
    }
}

/// The relocations llvm-readobj lists (RELR decoded): offset, type name.
fn listed_relocations(text: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("Section (") {
            inside = true;
        } else if t == "}" {
            inside = false;
        } else if inside {
            let f: Vec<&str> = t.split_whitespace().collect();
            if f.len() >= 2 {
                out.push((number(f[0]), f[1].to_string()));
            }
        }
    }
    out
}

/// Pointer slots: RELR and RELA builds of the same object (tools/elf/relr.c)
/// hold the same pointers, each to one of its objects; readobj lists
/// them.
#[test]
fn elf_pointer_slots() {
    let mut targets = Vec::new();
    for name in ["relr.so", "relr-rela.so"] {
        let (data, text) = load("elf", name);
        let image = Image::parse(&data).unwrap();
        let slots = image.pointer_slots();
        let want: Vec<u64> = listed_relocations(&text)
            .into_iter()
            .filter(|(_, k)| k == "R_X86_64_RELATIVE")
            .map(|(a, _)| a)
            .collect();
        assert_eq!(
            slots.iter().map(|s| s.addr).collect::<Vec<_>>(),
            want,
            "{name}"
        );
        assert_eq!(want.len(), 9, "{name}");
        assert!(slots.iter().all(|s| s.width == 8));
        // Each points to a, b, c, or f (its symbols).
        let elf = image.elf().unwrap();
        let named = |n: &[u8]| {
            elf.all_symbols()
                .into_iter()
                .find(|s| s.name == n)
                .unwrap()
                .value
        };
        let objects = [named(b"a"), named(b"b"), named(b"c"), named(b"f")];
        let pointed: Vec<usize> = slots
            .iter()
            .map(|s| objects.iter().position(|&o| Some(o) == s.target).unwrap())
            .collect();
        targets.push(pointed);
        // The dynamic table says where the RELR table is.
        let dynamic = elf.dynamic();
        let relr = dynamic
            .iter()
            .any(|d| d.tag == hexcavator_elf::consts::DT_RELR);
        assert_eq!(relr, name == "relr.so");
    }
    // The same pointers, packed or not: table (a b c a _ b c), handlers
    // (f f), far (c).
    assert_eq!(targets[0], targets[1]);
    assert_eq!(targets[0], [0, 1, 2, 0, 1, 2, 3, 3, 2]);
}

#[test]
fn pointer_slots_of_other_files() {
    // A shared object's GOT and PLT entries: its own symbols' addresses.
    let (data, _) = load("elf", "program.so");
    let image = Image::parse(&data).unwrap();
    let slots = image.pointer_slots();
    assert!(!slots.is_empty());
    let elf = image.elf().unwrap();
    let compute = elf
        .all_symbols()
        .into_iter()
        .find(|s| s.name == b"compute")
        .unwrap()
        .value;
    assert!(slots.iter().any(|s| s.target == Some(compute)));
    // A static executable has none; an object, none (the linker's).
    for name in ["program-x86_64-linux-gnu", "program-x86_64-linux-gnu.o"] {
        let (data, _) = load("elf", name);
        assert!(
            Image::parse(&data).unwrap().pointer_slots().is_empty(),
            "{name}"
        );
    }
    // PE: the base relocations, each holding an address in the image.
    let data = std::fs::read(format!(
        "{}/../../../testdata/types/types.exe",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let image = Image::parse(&data).unwrap();
    let slots = image.pointer_slots();
    assert!(slots.len() > 10);
    let end = image
        .sections()
        .iter()
        .filter_map(hexcavator_image::Section::end)
        .max()
        .unwrap();
    assert!(
        slots
            .iter()
            .all(|s| s.width == 8 && s.target.is_some_and(|t| t < end))
    );
}

/// Android's packed relocations (APS2), and the same unpacked: the slots
/// and what they hold as llvm-readobj's decoding says. (The two are laid
/// out apart: their relocation sections differ in size.)
#[test]
fn android_packed_relocations() {
    for name in ["relr-android.so", "relr-android-rela.so"] {
        let (data, text) = load("elf", name);
        let image = Image::parse(&data).unwrap();
        // readobj: `0x304C0 R_AARCH64_RELATIVE - 0x30740`.
        let want: Vec<(u64, u64)> = text
            .lines()
            .filter(|l| l.contains("R_AARCH64_RELATIVE"))
            .map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (number(f[0]), number(f[3]))
            })
            .collect();
        assert_eq!(want.len(), 9, "{name}");
        let slots: Vec<(u64, u64)> = image
            .pointer_slots()
            .iter()
            .map(|s| (s.addr, s.target.unwrap()))
            .collect();
        assert_eq!(slots, want, "{name}");
    }
    // Damaged: an APS2 stream cut anywhere, or overwritten.
    let (clean, _) = load("elf", "relr-android.so");
    let elf = hexcavator_elf::ElfFile::parse(&clean).unwrap();
    let s = elf
        .sections()
        .find(|s| s.kind == hexcavator_elf::consts::SHT_ANDROID_RELA)
        .unwrap();
    let mut d = clean.clone();
    for at in s.offset as usize..(s.offset + s.size) as usize {
        let was = d[at];
        for v in [0x00, 0x7F, 0xFF] {
            d[at] = v;
            if let Ok(i) = Image::parse(&d) {
                let _ = i.pointer_slots();
            }
        }
        d[at] = was;
    }
}

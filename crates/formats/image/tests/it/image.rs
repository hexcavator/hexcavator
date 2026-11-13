//! `Image` over real binaries (SizeBench's test binaries, in `testdata`) and
//! over synthetic and malformed input.

use hexcavator_core::ErrorKind;
use hexcavator_image::{Arch, DebugId, Format, Image, Kind, SectionFlags};

fn testdata(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../../testdata/sizebench/bin/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn x64_dll() {
    let data = testdata("PEParser.Tests.Dllx64.dll");
    let image = Image::parse(&data).unwrap();
    assert_eq!(image.format(), Format::Pe);
    assert_eq!(image.kind(), Kind::Linked);
    assert_eq!(image.arch(), Arch::X64);
    assert_eq!(image.image_base(), 0x1_8000_0000);
    assert_eq!(image.section_alignment(), Some(0x1000));
    assert_eq!(image.file_alignment(), Some(0x200));

    // Expected values are SizeBench's (testdata/sizebench/oracle).
    let sections = image.sections();
    let names: Vec<&[u8]> = sections.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        [
            &b".text"[..],
            b".rdata",
            b".data",
            b".pdata",
            b".gfids",
            b".rsrc",
            b".reloc"
        ]
    );
    let text = &sections[0];
    assert_eq!(text.index, 0);
    assert_eq!(
        (text.addr, text.vm_size, text.file_size),
        (0x1000, 9270, 9728)
    );
    assert_eq!(text.raw_flags, 0x6000_0020);
    assert!(
        text.flags
            .contains(SectionFlags::CODE | SectionFlags::EXECUTE | SectionFlags::READ)
    );
    assert!(!text.flags.contains(SectionFlags::WRITE));
    let data_section = &sections[2];
    assert_eq!(
        (
            data_section.addr,
            data_section.vm_size,
            data_section.file_size
        ),
        (0x6000, 1768, 512)
    );
    assert!(
        data_section
            .flags
            .contains(SectionFlags::WRITE | SectionFlags::DATA)
    );
    let reloc = &sections[6];
    assert_eq!((reloc.addr, reloc.vm_size), (0xED000, 60));
    assert!(reloc.flags.contains(SectionFlags::NOT_LOADED));

    // Sections are laid out in the file in order.
    for pair in sections.windows(2) {
        assert!(pair[0].file_offset + pair[0].file_size <= pair[1].file_offset);
        assert!(pair[0].end().unwrap() <= pair[1].addr);
    }
}

#[test]
fn debug_id_matches_pdb_reference() {
    let data = testdata("PEParser.Tests.Dllx64.dll");
    let image = Image::parse(&data).unwrap();
    let ids = image.debug_ids();
    assert_eq!(ids.len(), 1);
    match ids[0] {
        DebugId::Pdb { age, path, .. } => {
            assert!(age >= 1);
            assert!(path.ends_with(b"PEParser.Tests.Dllx64.pdb"), "{path:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn bytes_at() {
    let data = testdata("PEParser.Tests.Dllx64.dll");
    let image = Image::parse(&data).unwrap();
    let text = image.sections()[0];
    let bytes = image.bytes_at(text.addr, 16).unwrap();
    let offset = usize::try_from(text.file_offset).unwrap();
    assert_eq!(bytes, &data[offset..offset + 16]);
    // The headers are mapped at address 0.
    assert_eq!(image.bytes_at(0, 2), Some(&b"MZ"[..]));
    // The zero-fill tail of .data has no file bytes.
    let data_section = image.sections()[2];
    assert_eq!(
        image.bytes_at(data_section.addr + data_section.file_size, 1),
        None
    );
    // Ranges must not run past their section's file data.
    assert_eq!(image.bytes_at(text.addr, text.file_size + 1), None);
    // Out-of-range addresses and lengths.
    assert_eq!(image.bytes_at(u64::MAX, 1), None);
    assert_eq!(image.bytes_at(text.addr, u64::MAX), None);
    assert_eq!(image.bytes_at(0x10_0000_0000, 1), None);
}

#[test]
fn architectures() {
    for (name, arch, pointer) in [
        ("PEParser.Tests.Dllx86.dll", Arch::X86, 4),
        ("PEParser.Tests.Dllarm32.dll", Arch::Arm, 4),
        ("PEParser.Tests.Dllx64.dll", Arch::X64, 8),
    ] {
        let data = testdata(name);
        let image = Image::parse(&data).unwrap();
        assert_eq!(image.arch(), arch, "{name}");
        assert_eq!(image.arch().pointer_size(), Some(pointer), "{name}");
    }
}

#[test]
fn custom_alignment() {
    // Linked with /ALIGN:512 (and the default /FILEALIGN:512).
    let data = testdata("SizeBenchV2.AnalysisEngine.Tests.Dllx64CustomAlign.dll");
    let image = Image::parse(&data).unwrap();
    assert_eq!(image.section_alignment(), Some(0x200));
    assert_eq!(image.file_alignment(), Some(0x200));
    let text = image.sections()[0];
    assert_eq!(
        (text.addr, text.vm_size, text.file_size),
        (0x400, 6253, 6656)
    );
}

/// A COFF object with a `.text` section holding `code` and a `.bss`
/// section of `bss` bytes.
fn object(machine: u16, code: &[u8], bss: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&machine.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes()); // sections
    b.extend_from_slice(&0u32.to_le_bytes()); // time stamp
    b.extend_from_slice(&0u32.to_le_bytes()); // symbol table
    b.extend_from_slice(&0u32.to_le_bytes()); // symbols
    b.extend_from_slice(&0u16.to_le_bytes()); // optional header size
    b.extend_from_slice(&0u16.to_le_bytes()); // characteristics
    let data_offset = 20 + 2 * 40;
    let section = |b: &mut Vec<u8>, name: &[u8; 8], size: u32, ptr: u32, flags: u32| {
        b.extend_from_slice(name);
        b.extend_from_slice(&[0; 8]); // virtual size, address
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&ptr.to_le_bytes());
        b.extend_from_slice(&[0; 12]); // relocations, line numbers, counts
        b.extend_from_slice(&flags.to_le_bytes());
    };
    let code_len = u32::try_from(code.len()).unwrap();
    section(&mut b, b".text\0\0\0", code_len, data_offset, 0x6050_1020);
    section(&mut b, b".bss\0\0\0\0", bss, 0, 0xC030_0080);
    b.extend_from_slice(code);
    b
}

#[test]
fn coff_object() {
    let data = object(0x8664, &[0xC3], 64);
    let image = Image::parse(&data).unwrap();
    assert_eq!(image.format(), Format::Coff);
    assert_eq!(image.kind(), Kind::Object);
    assert_eq!(image.arch(), Arch::X64);
    assert_eq!(image.image_base(), 0);
    assert_eq!(image.section_alignment(), None);
    assert_eq!(image.file_alignment(), None);
    assert!(image.debug_ids().is_empty());
    let sections = image.sections();
    assert_eq!(sections.len(), 2);
    assert_eq!(sections[0].name, b".text");
    assert_eq!(
        (sections[0].addr, sections[0].vm_size, sections[0].file_size),
        (0, 1, 1)
    );
    assert_eq!(sections[0].file_offset, 100);
    assert!(
        sections[0]
            .flags
            .contains(SectionFlags::COMDAT | SectionFlags::CODE)
    );
    assert_eq!(sections[1].name, b".bss");
    assert_eq!((sections[1].vm_size, sections[1].file_size), (64, 0));
    assert!(sections[1].flags.contains(SectionFlags::ZERO_FILL));
    // Objects have no address space.
    assert_eq!(image.bytes_at(0, 1), None);
}

#[test]
fn rejects_unknown_formats() {
    assert_eq!(Image::parse(b"").unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(Image::parse(b"M").unwrap_err().kind, ErrorKind::Truncated);
    // An ELF header, cut short.
    assert_eq!(
        Image::parse(b"\x7FELF\x02\x01\x01").unwrap_err().kind,
        ErrorKind::Truncated
    );
    assert_eq!(
        Image::parse(&[0; 64]).unwrap_err().kind,
        ErrorKind::BadMagic
    );
    assert_eq!(
        Image::parse(&[0x34, 0x12, 0, 0]).unwrap_err().kind,
        ErrorKind::BadMagic
    );
}

#[test]
fn truncated_inputs_are_errors_not_panics() {
    let data = testdata("PEParser.Tests.Dllx64.dll");
    // Every prefix of the headers, and of a COFF object, fails cleanly or
    // parses; nothing panics.
    for len in 0..0x400 {
        let _ = Image::parse(&data[..len]).map(|i| (i.sections(), i.debug_ids()));
    }
    let obj = object(0x14C, &[0x90; 8], 0);
    for len in 0..obj.len() {
        let _ = Image::parse(&obj[..len]).map(|i| i.sections());
    }
    // A header that claims many sections, cut short.
    let mut short = obj.clone();
    short[2..4].copy_from_slice(&0xFFFEu16.to_le_bytes());
    assert!(Image::parse(&short).is_err());
}

#[test]
fn corrupted_images_do_not_panic() {
    let data = testdata("PEParser.Tests.Dllx64.dll");
    // Flip each byte of the headers in turn; every accessor must survive.
    let headers = 0x400.min(data.len());
    let mut copy = data.clone();
    for i in 0..headers {
        for value in [0x00, 0xFF, copy[i] ^ 0x80] {
            let original = copy[i];
            copy[i] = value;
            if let Ok(image) = Image::parse(&copy) {
                for s in image.sections() {
                    let _ = image.bytes_at(s.addr, s.file_size.min(64));
                }
                let _ = image.debug_ids();
                let _ = (image.arch(), image.image_base(), image.section_alignment());
            }
            copy[i] = original;
        }
    }
}

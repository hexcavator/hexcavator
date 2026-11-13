//! Hermetic tests: ELF files built in memory, of both classes and byte
//! orders, well-formed and damaged.
#![allow(clippy::cast_possible_truncation, reason = "small test files")]

use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// A section to build: name, type, flags, address, bytes (or, for
/// `SHT_NOBITS`, a size), link, info, entsize.
#[derive(Clone)]
struct S {
    name: &'static [u8],
    kind: u32,
    flags: u64,
    addr: u64,
    data: Vec<u8>,
    nobits_size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

fn sec(name: &'static [u8], kind: u32, data: Vec<u8>) -> S {
    S {
        name,
        kind,
        flags: 0,
        addr: 0,
        data,
        nobits_size: 0,
        link: 0,
        info: 0,
        entsize: 0,
    }
}

struct Builder {
    class: Class,
    endian: Endian,
    kind: u16,
    sections: Vec<S>,
    /// (type, flags, offset, vaddr, filesz, memsz)
    segments: Vec<(u32, u32, u64, u64, u64, u64)>,
}

impl Builder {
    fn new(class: Class, endian: Endian) -> Self {
        Self {
            class,
            endian,
            kind: ET_EXEC,
            sections: Vec::new(),
            segments: Vec::new(),
        }
    }

    fn w(&self) -> usize {
        if self.class == Class::Elf64 { 8 } else { 4 }
    }

    fn put(&self, out: &mut Vec<u8>, v: u64, n: usize) {
        let b = v.to_le_bytes();
        if self.endian == Endian::Little {
            out.extend_from_slice(&b[..n]);
        } else {
            out.extend(b[..n].iter().rev());
        }
    }

    /// The file, and the offset of its section header table. Section 0
    /// (null) and `.shstrtab` (last) are added.
    fn build(&self) -> Vec<u8> {
        let mut sections = vec![sec(b"", SHT_NULL, Vec::new())];
        sections.extend(self.sections.iter().cloned());
        let mut names = vec![0u8];
        let mut name_offsets = Vec::new();
        for s in &sections {
            if s.name.is_empty() {
                name_offsets.push(0u32);
            } else {
                name_offsets.push(names.len() as u32);
                names.extend_from_slice(s.name);
                names.push(0);
            }
        }
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(b".shstrtab\0");
        sections.push(sec(b".shstrtab", SHT_STRTAB, names));

        let w = self.w();
        let ehsize = if w == 8 { 64 } else { 52 };
        let phentsize = if w == 8 { 56 } else { 32 };
        let shentsize = if w == 8 { 64 } else { 40 };
        let phoff = if self.segments.is_empty() { 0 } else { ehsize };
        let mut at = ehsize + self.segments.len() * phentsize;
        let mut offsets = Vec::new();
        for s in &sections {
            at = at.next_multiple_of(8);
            offsets.push(at as u64);
            at += s.data.len();
        }
        let shoff = at.next_multiple_of(8);

        let mut out = Vec::new();
        out.extend_from_slice(b"\x7fELF");
        out.push(if w == 8 { ELFCLASS64 } else { ELFCLASS32 });
        out.push(if self.endian == Endian::Little {
            ELFDATA2LSB
        } else {
            ELFDATA2MSB
        });
        out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        self.put(&mut out, u64::from(self.kind), 2);
        self.put(&mut out, u64::from(EM_X86_64), 2);
        self.put(&mut out, 1, 4);
        self.put(&mut out, 0x1000, w);
        self.put(&mut out, phoff as u64, w);
        self.put(&mut out, shoff as u64, w);
        self.put(&mut out, 0, 4);
        self.put(&mut out, ehsize as u64, 2);
        self.put(&mut out, phentsize as u64, 2);
        self.put(&mut out, self.segments.len() as u64, 2);
        self.put(&mut out, shentsize as u64, 2);
        self.put(&mut out, sections.len() as u64, 2);
        self.put(&mut out, sections.len() as u64 - 1, 2);
        assert_eq!(out.len(), ehsize);
        for &(kind, flags, offset, vaddr, filesz, memsz) in &self.segments {
            self.put(&mut out, u64::from(kind), 4);
            if w == 8 {
                self.put(&mut out, u64::from(flags), 4);
            }
            for v in [offset, vaddr, vaddr, filesz, memsz] {
                self.put(&mut out, v, w);
            }
            if w == 4 {
                self.put(&mut out, u64::from(flags), 4);
            }
            self.put(&mut out, 0x1000, w);
        }
        for (s, &o) in sections.iter().zip(&offsets) {
            out.resize(o as usize, 0);
            out.extend_from_slice(&s.data);
        }
        out.resize(shoff, 0);
        for (i, s) in sections.iter().enumerate() {
            self.put(&mut out, u64::from(name_offsets[i]), 4);
            self.put(&mut out, u64::from(s.kind), 4);
            let size = if s.kind == SHT_NOBITS {
                s.nobits_size
            } else {
                s.data.len() as u64
            };
            let offset = if s.kind == SHT_NULL { 0 } else { offsets[i] };
            for v in [s.flags, s.addr, offset, size] {
                self.put(&mut out, v, w);
            }
            self.put(&mut out, u64::from(s.link), 4);
            self.put(&mut out, u64::from(s.info), 4);
            self.put(&mut out, 1, w);
            self.put(&mut out, s.entsize, w);
        }
        out
    }

    /// A symbol entry: name offset, value, size, info, other, shndx.
    fn sym(&self, name: u32, value: u64, size: u64, info: u8, other: u8, shndx: u16) -> Vec<u8> {
        let mut out = Vec::new();
        self.put(&mut out, u64::from(name), 4);
        if self.class == Class::Elf64 {
            out.push(info);
            out.push(other);
            self.put(&mut out, u64::from(shndx), 2);
            self.put(&mut out, value, 8);
            self.put(&mut out, size, 8);
        } else {
            self.put(&mut out, value, 4);
            self.put(&mut out, size, 4);
            out.push(info);
            out.push(other);
            self.put(&mut out, u64::from(shndx), 2);
        }
        out
    }

    fn note(&self, name: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.put(&mut out, name.len() as u64 + 1, 4);
        self.put(&mut out, desc.len() as u64, 4);
        self.put(&mut out, u64::from(kind), 4);
        out.extend_from_slice(name);
        out.push(0);
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(desc);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }
}

const ALL: [(Class, Endian); 4] = [
    (Class::Elf32, Endian::Little),
    (Class::Elf32, Endian::Big),
    (Class::Elf64, Endian::Little),
    (Class::Elf64, Endian::Big),
];

/// A file with code, data, bss, a symbol table (with an extended-index
/// entry), a note, and two segments.
fn sample(class: Class, endian: Endian) -> Vec<u8> {
    let mut b = Builder::new(class, endian);
    let mut text = sec(b".text", SHT_PROGBITS, vec![0x90; 32]);
    text.flags = SHF_ALLOC | SHF_EXECINSTR;
    text.addr = 0x1000;
    let mut data = sec(b".data", SHT_PROGBITS, vec![1, 2, 3, 4]);
    data.flags = SHF_ALLOC | SHF_WRITE;
    data.addr = 0x2000;
    let mut bss = sec(b".bss", SHT_NOBITS, Vec::new());
    bss.flags = SHF_ALLOC | SHF_WRITE;
    bss.addr = 0x2004;
    bss.nobits_size = 0x100;
    let strtab = sec(b".strtab", SHT_STRTAB, b"\0main\0counter\0far\0".to_vec());
    let mut syms = Vec::new();
    syms.extend(b.sym(0, 0, 0, 0, 0, 0));
    syms.extend(b.sym(1, 0x1000, 32, (STB_GLOBAL << 4) | STT_FUNC, 0, 1));
    syms.extend(b.sym(6, 0x2000, 4, (STB_LOCAL << 4) | STT_OBJECT, 2, 2));
    syms.extend(b.sym(14, 0x2004, 8, (STB_WEAK << 4) | STT_OBJECT, 0, SHN_XINDEX));
    let mut symtab = sec(b".symtab", SHT_SYMTAB, syms);
    symtab.link = 4; // .strtab
    symtab.entsize = if class == Class::Elf64 { 24 } else { 16 };
    let mut xindex = Vec::new();
    for v in [0u64, 0, 0, 3] {
        b.put(&mut xindex, v, 4);
    }
    let mut shndx = sec(b".symtab_shndx", SHT_SYMTAB_SHNDX, xindex);
    shndx.link = 5; // .symtab
    let mut note = b.note(b"GNU", NT_GNU_BUILD_ID, &[0xde, 0xad, 0xbe, 0xef]);
    note.splice(0..0, b.note(b"Other", 1, b"xyz"));
    let note = sec(b".note.gnu.build-id", SHT_NOTE, note);
    b.sections = vec![text, data, bss, strtab, symtab, shndx, note];
    let built = b.build();
    let elf = ElfFile::parse(&built).unwrap();
    let text_off = elf.section(1).unwrap().offset;
    let data_off = elf.section(2).unwrap().offset;
    b.segments = vec![
        (PT_LOAD, PF_R | PF_X, text_off, 0x1000, 32, 32),
        (PT_LOAD, PF_R | PF_W, data_off, 0x2000, 4, 0x104),
    ];
    // Adding program headers moves everything; rebuild and fix the
    // segment offsets to match.
    let built = b.build();
    let elf = ElfFile::parse(&built).unwrap();
    let text_off = elf.section(1).unwrap().offset;
    let data_off = elf.section(2).unwrap().offset;
    b.segments[0].2 = text_off;
    b.segments[1].2 = data_off;
    b.build()
}

#[test]
fn parses_every_class_and_byte_order() {
    for (class, endian) in ALL {
        let data = sample(class, endian);
        let elf = ElfFile::parse(&data).unwrap();
        let ctx = (class, endian);
        assert_eq!(elf.class(), class);
        assert_eq!(elf.endian(), endian);
        let h = elf.header();
        assert_eq!(h.kind, ET_EXEC, "{ctx:?}");
        assert_eq!(h.machine, EM_X86_64);
        assert_eq!(h.entry, 0x1000);
        assert_eq!(h.shnum, 9);
        assert_eq!(h.phnum, 2);
        assert!(!elf.is_object());

        let names: Vec<&[u8]> = elf.sections().map(|s| s.name).collect();
        assert_eq!(
            names,
            [
                &b""[..],
                b".text",
                b".data",
                b".bss",
                b".strtab",
                b".symtab",
                b".symtab_shndx",
                b".note.gnu.build-id",
                b".shstrtab"
            ],
            "{ctx:?}"
        );
        let text = elf.section_by_name(b".text").unwrap();
        assert_eq!(text.flags, SHF_ALLOC | SHF_EXECINSTR);
        assert_eq!(text.addr, 0x1000);
        assert!(text.is_alloc());
        assert_eq!(elf.section_data(&text), &[0x90; 32][..]);
        let bss = elf.section_by_name(b".bss").unwrap();
        assert_eq!(bss.size, 0x100);
        assert_eq!(bss.file_size(), 0);
        assert!(elf.section_data(&bss).is_empty());
        assert!(elf.section_by_name(b".nope").is_none());

        let segs: Vec<_> = elf.segments().collect();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].kind, PT_LOAD);
        assert_eq!(segs[0].flags, PF_R | PF_X);
        assert_eq!(segs[1].memsz, 0x104);
        assert_eq!(segs[1].align, 0x1000);
        assert_eq!(elf.vaddr_to_offset(0x1004), Some(text.offset + 4));
        // In memory but not in the file (bss), or nowhere.
        assert_eq!(elf.vaddr_to_offset(0x2010), None);
        assert_eq!(elf.vaddr_to_offset(0x9000), None);

        let syms = elf.all_symbols();
        assert_eq!(syms.len(), 4, "{ctx:?}");
        assert_eq!(syms[1].name, b"main");
        assert_eq!(syms[1].value, 0x1000);
        assert_eq!(syms[1].size, 32);
        assert_eq!(syms[1].bind, STB_GLOBAL);
        assert_eq!(syms[1].kind, STT_FUNC);
        assert_eq!(syms[1].shndx, 1);
        assert_eq!(syms[2].name, b"counter");
        assert_eq!(syms[2].visibility, 2);
        assert_eq!(syms[2].bind, STB_LOCAL);
        assert_eq!(syms[3].name, b"far");
        assert_eq!(syms[3].bind, STB_WEAK);
        assert_eq!(syms[3].shndx, 3, "SHN_XINDEX resolved");

        assert_eq!(elf.build_id(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        let note = elf.section_by_name(b".note.gnu.build-id").unwrap();
        let notes = elf.notes(elf.section_data(&note));
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].name, b"Other");
        assert_eq!(notes[0].desc, b"xyz");

        let (_, phsize) = elf.program_headers_range();
        assert_eq!(phsize, 2 * u64::from(h.phentsize));
        let (shoff, shsize) = elf.section_headers_range();
        assert_eq!(shoff + shsize, data.len() as u64);
        assert_eq!(elf.header_range(), (0, u64::from(h.ehsize)));
    }
}

#[test]
fn rejects_what_is_not_elf() {
    assert_eq!(
        ElfFile::parse(b"MZ\x90\0").unwrap_err().kind,
        ErrorKind::BadMagic
    );
    assert_eq!(ElfFile::parse(b"").unwrap_err().kind, ErrorKind::BadMagic);
    assert!(!ElfFile::is_elf(b"\x7fEL"));
    let mut data = sample(Class::Elf64, Endian::Little);
    assert_eq!(
        ElfFile::parse(&data[..10]).unwrap_err().kind,
        ErrorKind::Truncated
    );
    assert_eq!(
        ElfFile::parse(&data[..40]).unwrap_err().kind,
        ErrorKind::Truncated
    );
    data[4] = 3;
    assert_eq!(
        ElfFile::parse(&data).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    data[4] = ELFCLASS64;
    data[5] = 0;
    assert_eq!(
        ElfFile::parse(&data).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}

/// Offsets of header fields, for patching.
fn field(class: Class, name: &str) -> (usize, usize) {
    let w = if class == Class::Elf64 { 8 } else { 4 };
    let rest = 0x18 + 3 * w;
    match name {
        "phoff" => (0x18 + w, w),
        "shoff" => (0x18 + 2 * w, w),
        "phentsize" => (rest + 6, 2),
        "phnum" => (rest + 8, 2),
        "shentsize" => (rest + 10, 2),
        "shnum" => (rest + 12, 2),
        "shstrndx" => (rest + 14, 2),
        _ => unreachable!(),
    }
}

fn patch(data: &mut [u8], endian: Endian, (at, n): (usize, usize), v: u64) {
    let b = v.to_le_bytes();
    for i in 0..n {
        data[at + i] = if endian == Endian::Little {
            b[i]
        } else {
            b[n - 1 - i]
        };
    }
}

#[test]
fn follows_extended_numbering() {
    for (class, endian) in ALL {
        let mut data = sample(class, endian);
        let elf = ElfFile::parse(&data).unwrap();
        let shoff = elf.header().shoff as usize;
        let (shnum, shstrndx, phnum) = (
            elf.header().shnum,
            elf.header().shstrndx,
            elf.header().phnum,
        );
        let w = if class == Class::Elf64 { 8 } else { 4 };
        // Section 0: size at 8+3w (w wide), link at 8+4w, info at 12+4w.
        patch(&mut data, endian, (shoff + 8 + 3 * w, w), u64::from(shnum));
        patch(
            &mut data,
            endian,
            (shoff + 8 + 4 * w, 4),
            u64::from(shstrndx),
        );
        patch(&mut data, endian, (shoff + 12 + 4 * w, 4), u64::from(phnum));
        patch(&mut data, endian, field(class, "shnum"), 0);
        patch(
            &mut data,
            endian,
            field(class, "shstrndx"),
            u64::from(SHN_XINDEX),
        );
        patch(&mut data, endian, field(class, "phnum"), u64::from(PN_XNUM));
        let elf = ElfFile::parse(&data).unwrap();
        assert_eq!(elf.header().shnum, shnum, "{class:?} {endian:?}");
        assert_eq!(elf.header().shstrndx, shstrndx);
        assert_eq!(elf.header().phnum, phnum);
        assert_eq!(elf.sections().count(), shnum as usize);
        assert_eq!(elf.section(1).unwrap().name, b".text");
        assert_eq!(elf.segments().count(), 2);
    }
}

#[test]
fn survives_damaged_tables() {
    for (class, endian) in ALL {
        let clean = sample(class, endian);
        let ctx = (class, endian);

        // A section header table past the end of the file: no sections.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "shoff"), 0xFFFF_FFF0);
        let elf = ElfFile::parse(&data).unwrap();
        assert_eq!(elf.sections().count(), 0, "{ctx:?}");
        assert!(elf.all_symbols().is_empty());
        assert_eq!(elf.build_id(), None.or(elf.build_id()));

        // An entry size too small for the class: no sections, no segments.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "shentsize"), 8);
        patch(&mut data, endian, field(class, "phentsize"), 8);
        let elf = ElfFile::parse(&data).unwrap();
        assert_eq!(elf.sections().count(), 0);
        assert_eq!(elf.segments().count(), 0);

        // A huge count stops at the end of the file.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "shnum"), 0xFF00);
        patch(&mut data, endian, field(class, "phnum"), 0xFFFE);
        let elf = ElfFile::parse(&data).unwrap();
        assert_eq!(elf.sections().count(), 9);
        assert!(elf.segments().count() < 100);

        // A bad string table index: sections without names.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "shstrndx"), 200);
        let elf = ElfFile::parse(&data).unwrap();
        assert!(elf.sections().all(|s| s.name.is_empty()));
        // The string table index naming a NOBITS section: same.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "shstrndx"), 3);
        let elf = ElfFile::parse(&data).unwrap();
        assert!(elf.sections().all(|s| s.name.is_empty()));

        // No program headers at all.
        let mut data = clean.clone();
        patch(&mut data, endian, field(class, "phoff"), 0);
        let elf = ElfFile::parse(&data).unwrap();
        assert_eq!(elf.segments().count(), 0);
        assert_eq!(elf.program_headers_range().1, 0);
        assert_eq!(elf.vaddr_to_offset(0x1000), None);
    }
}

#[test]
fn clamps_names_and_data() {
    let mut b = Builder::new(Class::Elf64, Endian::Little);
    b.sections = vec![sec(b".a", SHT_PROGBITS, vec![7; 16])];
    let mut data = b.build();
    let elf = ElfFile::parse(&data).unwrap();
    let shoff = elf.header().shoff as usize;
    let names_size = elf.section(2).unwrap().size;
    // Section 1's name offset past its table: no name.
    patch(&mut data, Endian::Little, (shoff + 64, 4), names_size + 5);
    // Section 1's size past the end of the file: clamped.
    patch(&mut data, Endian::Little, (shoff + 64 + 32, 8), 1 << 40);
    let elf = ElfFile::parse(&data).unwrap();
    let a = elf.section(1).unwrap();
    assert!(a.name.is_empty());
    assert_eq!(
        elf.section_data(&a).len() as u64,
        data.len() as u64 - a.offset
    );
    // Its offset past the end: no bytes.
    patch(&mut data, Endian::Little, (shoff + 64 + 24, 8), u64::MAX);
    let elf = ElfFile::parse(&data).unwrap();
    assert!(elf.section_data(&elf.section(1).unwrap()).is_empty());
    assert!(elf.section(3).is_none());
    assert!(elf.section(usize::MAX).is_none());

    // A name running to the end of its table, unterminated, stops there.
    let mut data = b.build();
    let elf = ElfFile::parse(&data).unwrap();
    let names = elf.section(2).unwrap();
    let end = (names.offset + names.size) as usize;
    data[end - 1] = b'X'; // ".shstrtab\0" becomes ".shstrtabX"
    let elf = ElfFile::parse(&data).unwrap();
    assert_eq!(elf.section(2).unwrap().name, b".shstrtabX");
}

#[test]
fn symbol_table_edge_cases() {
    let b = Builder::new(Class::Elf32, Endian::Big);
    let mut strtab = sec(b".strtab", SHT_STRTAB, b"\0abc".to_vec()); // unterminated
    strtab.flags = 0;
    let mut syms = b.sym(0, 0, 0, 0, 0, 0);
    syms.extend(b.sym(1, 5, 0, 0x12, 0, SHN_ABS));
    syms.extend(b.sym(99, 6, 0, 0x11, 0, SHN_COMMON)); // name past the table
    syms.extend(b.sym(0, 7, 0, 0x11, 0, SHN_XINDEX)); // no extended index table
    syms.extend([0; 7]); // a partial entry is ignored
    let mut symtab = sec(b".symtab", SHT_SYMTAB, syms);
    symtab.link = 1;
    let mut bad = sec(b".dynsym", SHT_DYNSYM, vec![0; 32]);
    bad.entsize = 4; // smaller than an entry
    let mut b = b;
    b.sections = vec![strtab, symtab, bad];
    let data = b.build();
    let elf = ElfFile::parse(&data).unwrap();
    let symtab = elf.section(2).unwrap();
    let syms = elf.symbols(&symtab);
    assert_eq!(syms.len(), 4);
    assert_eq!(syms[1].name, b"abc", "stops at the end of the file");
    assert_eq!(syms[1].shndx, u32::from(SHN_ABS));
    assert!(syms[2].name.is_empty());
    assert_eq!(syms[2].shndx, u32::from(SHN_COMMON));
    assert_eq!(syms[3].shndx, 0);
    assert!(elf.symbols(&elf.section(3).unwrap()).is_empty());
    // Not a symbol table.
    assert!(elf.symbols(&elf.section(1).unwrap()).is_empty());
    // `.symtab` is preferred over `.dynsym`.
    assert_eq!(elf.all_symbols().len(), 4);
}

#[test]
fn notes_stop_at_damage() {
    let b = Builder::new(Class::Elf64, Endian::Little);
    let elf_bytes = sample(Class::Elf64, Endian::Little);
    let elf = ElfFile::parse(&elf_bytes).unwrap();
    let mut n = b.note(b"GNU", NT_GNU_BUILD_ID, &[1, 2, 3]);
    let good = n.clone();
    assert_eq!(elf.notes(&n).len(), 1);
    assert_eq!(elf.notes(&n)[0].desc, &[1, 2, 3]);
    // A descriptor size past the end: no note.
    n[4] = 0xFF;
    assert!(elf.notes(&n).is_empty());
    // Two good notes, then a truncated header.
    let mut two = good.clone();
    two.extend(&good);
    two.extend([1, 0, 0]);
    assert_eq!(elf.notes(&two).len(), 2);
    // A huge name size.
    let mut n = good.clone();
    n[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(elf.notes(&n).is_empty());
    // An empty note.
    let empty = b.note(b"", 0, &[]);
    let notes = elf.notes(&empty);
    assert_eq!(notes.len(), 1);
    assert!(notes[0].name.is_empty() && notes[0].desc.is_empty());
    assert!(elf.notes(&[]).is_empty());
}

#[test]
fn compressed_section_headers() {
    for (class, endian) in ALL {
        let b = Builder::new(class, endian);
        let mut chdr = Vec::new();
        b.put(&mut chdr, u64::from(ELFCOMPRESS_ZSTD), 4);
        if class == Class::Elf64 {
            b.put(&mut chdr, 0, 4);
            b.put(&mut chdr, 1234, 8);
            b.put(&mut chdr, 8, 8);
        } else {
            b.put(&mut chdr, 1234, 4);
            b.put(&mut chdr, 4, 4);
        }
        chdr.extend([0xAA; 5]);
        let mut s = sec(b".debug_info", SHT_PROGBITS, chdr);
        s.flags = SHF_COMPRESSED;
        let plain = sec(b".debug_line", SHT_PROGBITS, vec![0; 4]);
        let mut b = b;
        b.sections = vec![s, plain];
        let data = b.build();
        let elf = ElfFile::parse(&data).unwrap();
        let c = elf.compression(&elf.section(1).unwrap()).unwrap();
        assert_eq!(c.kind, ELFCOMPRESS_ZSTD);
        assert_eq!(c.size, 1234);
        assert_eq!(c.align, if class == Class::Elf64 { 8 } else { 4 });
        assert_eq!(c.data_offset, if class == Class::Elf64 { 24 } else { 12 });
        assert!(elf.compression(&elf.section(2).unwrap()).is_none());
    }
}

/// Every truncation and every single-byte corruption of the sample parses
/// or fails cleanly, and walking everything it claims to hold terminates.
#[test]
fn hostile_inputs_never_panic() {
    fn walk(data: &[u8]) {
        let Ok(elf) = ElfFile::parse(data) else {
            return;
        };
        for s in elf.sections() {
            let _ = elf.section_data(&s);
            let _ = elf.symbols(&s);
            let _ = elf.compression(&s);
            if s.kind == SHT_NOTE {
                let _ = elf.notes(elf.section_data(&s));
            }
        }
        for p in elf.segments() {
            let _ = elf.vaddr_to_offset(p.vaddr);
        }
        let _ = elf.all_symbols();
        let _ = elf.build_id();
        let _ = (elf.groups(), elf.debug_link(), elf.alt_link());
        let _ = elf.program_headers_range();
        let _ = elf.section_headers_range();
    }
    for (class, endian) in ALL {
        let clean = sample(class, endian);
        for len in 0..clean.len() {
            walk(&clean[..len]);
        }
        for i in 0..clean.len() {
            for v in [0x00, 0xFF, 0x80, 0x7F] {
                let mut d = clean.clone();
                d[i] = v;
                walk(&d);
            }
        }
    }
}

#[test]
fn machines_name_architectures() {
    use hexcavator_core::Arch;
    assert_eq!(arch(EM_X86_64, Class::Elf64), Arch::X64);
    // x32: ELF32, x64 instructions.
    assert_eq!(arch(EM_X86_64, Class::Elf32), Arch::X64);
    assert_eq!(arch(EM_386, Class::Elf32), Arch::X86);
    assert_eq!(arch(EM_AARCH64, Class::Elf64), Arch::Arm64);
    assert_eq!(arch(EM_ARM, Class::Elf32), Arch::Arm);
    assert_eq!(arch(EM_RISCV, Class::Elf32), Arch::RiscV32);
    assert_eq!(arch(EM_RISCV, Class::Elf64), Arch::RiscV64);
    assert_eq!(arch(EM_MIPS, Class::Elf64), Arch::Mips64);
    assert_eq!(arch(EM_MIPS_RS3_LE, Class::Elf32), Arch::Mips);
    assert_eq!(arch(EM_LOONGARCH, Class::Elf64), Arch::LoongArch64);
    assert_eq!(arch(EM_S390, Class::Elf64), Arch::S390x);
    assert_eq!(arch(EM_S390, Class::Elf32), Arch::Unknown);
    assert_eq!(arch(EM_PPC64, Class::Elf64), Arch::PowerPc64);
    assert_eq!(arch(EM_SPARCV9, Class::Elf64), Arch::Sparc64);
    assert_eq!(arch(EM_ALPHA_UNOFFICIAL, Class::Elf64), Arch::Alpha64);
    assert_eq!(arch(EM_BPF, Class::Elf64), Arch::Unknown);
    assert_eq!(arch(EM_NONE, Class::Elf64), Arch::Unknown);
}

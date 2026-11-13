//! Hermetic tests: Mach-O files built in memory, 32- and 64-bit, both byte
//! orders, universal, and damaged.
#![allow(clippy::cast_possible_truncation, reason = "small test files")]

use alloc::vec;
use alloc::vec::Vec;

use super::*;

struct B {
    out: Vec<u8>,
    endian: Endian,
}

impl B {
    fn u(&mut self, v: u64, n: usize) -> &mut Self {
        let b = v.to_le_bytes();
        if self.endian == Endian::Little {
            self.out.extend_from_slice(&b[..n]);
        } else {
            self.out.extend(b[..n].iter().rev());
        }
        self
    }
    fn name(&mut self, s: &[u8]) -> &mut Self {
        let mut b = [0u8; 16];
        b[..s.len()].copy_from_slice(s);
        self.out.extend_from_slice(&b);
        self
    }
}

/// An executable: a `__TEXT` segment with `__text` and `__bss`
/// (zero-fill) sections, `LC_UUID`, and `LC_SYMTAB` with two symbols.
fn sample(is64: bool, endian: Endian) -> Vec<u8> {
    let w = if is64 { 8 } else { 4 };
    let header = if is64 { 32 } else { 28 };
    let seg_cmd = if is64 { 72 } else { 56 } + 2 * if is64 { 80 } else { 68 };
    let cmds = seg_cmd + 24 + 24;
    let text_off = (header + cmds) as u64;
    let nl = if is64 { 16 } else { 12 };
    let symoff = text_off + 16;
    let stroff = symoff + 2 * nl;
    let strings = b"\0_main\0_x\0";
    let mut b = B {
        out: Vec::new(),
        endian,
    };
    let magic = if is64 { MH_MAGIC_64 } else { MH_MAGIC };
    b.u(u64::from(magic), 4)
        .u(u64::from(CPU_TYPE_ARM64), 4)
        .u(0, 4)
        .u(u64::from(MH_EXECUTE), 4);
    b.u(3, 4).u(cmds as u64, 4).u(0, 4);
    if is64 {
        b.u(0, 4);
    }
    // The segment.
    b.u(u64::from(if is64 { LC_SEGMENT_64 } else { LC_SEGMENT }), 4)
        .u(seg_cmd as u64, 4)
        .name(b"__TEXT");
    b.u(0x1000, w)
        .u(0x2000, w)
        .u(0, w)
        .u(stroff + strings.len() as u64, w);
    b.u(5, 4).u(5, 4).u(2, 4).u(0, 4);
    for (sect, addr, size, off, flags) in [
        (
            &b"__text"[..],
            0x1000 + text_off,
            16u64,
            text_off,
            0x8000_0400u32,
        ),
        (b"__bss", 0x1800, 0x100, 0, S_ZEROFILL),
    ] {
        b.name(sect).name(b"__TEXT").u(addr, w).u(size, w);
        b.u(off, 4)
            .u(2, 4)
            .u(0, 4)
            .u(0, 4)
            .u(u64::from(flags), 4)
            .u(0, 4)
            .u(0, 4);
        if is64 {
            b.u(0, 4);
        }
    }
    b.u(u64::from(LC_UUID), 4).u(24, 4);
    b.out.extend_from_slice(&[7; 16]);
    b.u(u64::from(LC_SYMTAB), 4)
        .u(24, 4)
        .u(symoff, 4)
        .u(2, 4)
        .u(stroff, 4)
        .u(strings.len() as u64, 4);
    assert_eq!(b.out.len() as u64, text_off);
    b.out.extend_from_slice(&[0xAA; 16]);
    for (strx, value) in [(1u64, 0x1000 + text_off), (7, 0x1800)] {
        b.u(strx, 4)
            .u(u64::from(N_SECT | N_EXT), 1)
            .u(1, 1)
            .u(0, 2)
            .u(value, w);
    }
    b.out.extend_from_slice(strings);
    b.out
}

#[test]
fn parses_every_width_and_byte_order() {
    for is64 in [false, true] {
        for endian in [Endian::Little, Endian::Big] {
            let data = sample(is64, endian);
            assert!(is_macho(&data));
            let m = MachO::parse(&data).unwrap();
            let ctx = (is64, endian);
            assert_eq!(m.header().is64, is64);
            assert_eq!(m.endian(), endian);
            assert_eq!(m.header().filetype, MH_EXECUTE);
            assert!(!m.is_object());
            assert_eq!(m.load_commands().len(), 3, "{ctx:?}");
            let segs = m.segments();
            assert_eq!(segs.len(), 1);
            assert_eq!(segs[0].name, b"__TEXT");
            assert_eq!((segs[0].vmaddr, segs[0].vmsize), (0x1000, 0x2000));
            assert_eq!(segs[0].maxprot, 5);
            let s = &segs[0].sections;
            assert_eq!(s.len(), 2);
            assert_eq!(s[0].sectname, b"__text");
            assert_eq!(s[0].segname, b"__TEXT");
            assert_eq!(s[0].size, 16);
            assert_eq!(s[0].file_size(), 16);
            assert_eq!(s[0].flags, 0x8000_0400);
            assert!(s[1].is_zerofill());
            assert_eq!(s[1].file_size(), 0);
            assert_eq!((s[0].index, s[1].index), (0, 1));
            assert_eq!(m.uuid(), Some([7; 16]));
            let st = m.symtab().unwrap();
            assert_eq!(st.nsyms, 2);
            let syms = m.symbols();
            assert_eq!(syms[0].name, b"_main");
            assert_eq!(syms[1].name, b"_x");
            assert_eq!(syms[1].n_value, 0x1800);
            assert!(syms[0].is_section_defined() && !syms[0].is_stab());
            assert_eq!(m.nlist_size(), if is64 { 16 } else { 12 });
            assert!(m.dysymtab().is_none());
        }
    }
}

#[test]
fn universal_files() {
    let a = sample(true, Endian::Little);
    let mut fat = Vec::new();
    fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
    fat.extend_from_slice(&1u32.to_be_bytes());
    for v in [CPU_TYPE_ARM64, 0, 64, a.len() as u32, 6] {
        fat.extend_from_slice(&v.to_be_bytes());
    }
    fat.resize(64, 0);
    fat.extend_from_slice(&a);
    assert!(is_fat(&fat) && !is_macho(&fat));
    let archs = fat_archs(&fat).unwrap();
    assert_eq!(
        archs,
        [FatArch {
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            offset: 64,
            size: a.len() as u64,
            align: 6
        }]
    );
    assert_eq!(fat_header_size(&fat), 28);
    let m = MachO::parse(&fat[64..]).unwrap();
    assert_eq!(m.segments().len(), 1);
    // A Java class file has the same magic and a large second word.
    let java = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
    assert!(!is_fat(&java));
    assert!(fat_archs(&java).is_none());
    // Truncated headers give fewer archs.
    assert!(fat_archs(&fat[..20]).unwrap().is_empty());
    assert_eq!(arch_name(CPU_TYPE_X86_64, 3), "x86_64");
    assert_eq!(arch_name(CPU_TYPE_ARM64, 0x8000_0002), "arm64e");
    assert_eq!(arch_name(99, 0), "cpu_99");
}

#[test]
fn rejects_and_survives_damage() {
    assert_eq!(MachO::parse(b"").unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(
        MachO::parse(b"\x7fELF\0\0\0\0").unwrap_err().kind,
        ErrorKind::BadMagic
    );
    let clean = sample(true, Endian::Little);
    // A zero command size stops the walk.
    let mut d = clean.clone();
    d[36..40].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(MachO::parse(&d).unwrap().load_commands().len(), 0);
    // A section count past the command's size reads only what fits.
    let mut d = clean.clone();
    d[32 + 64..32 + 68].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(MachO::parse(&d).unwrap().segments()[0].sections.len(), 2);
    // A huge symbol count stops at the end of the file.
    let mut d = clean.clone();
    let st = clean.len() - 10 - 2 * 16 - 16 - 24 + 12;
    d[st..st + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let m = MachO::parse(&d).unwrap();
    assert!(m.symbols().len() < 10);
    // Every truncation and single-byte corruption parses or fails cleanly.
    let walk = |d: &[u8]| {
        let Ok(m) = MachO::parse(d) else { return };
        for c in m.load_commands() {
            let _ = m.dyld_info(&c);
            let _ = m.linkedit_data(&c);
        }
        let _ = m.segments();
        let _ = m.symbols();
        let _ = m.dysymtab();
        let _ = m.uuid();
    };
    for is64 in [false, true] {
        for endian in [Endian::Little, Endian::Big] {
            let clean = sample(is64, endian);
            for n in 0..clean.len() {
                walk(&clean[..n]);
            }
            for i in 0..clean.len() {
                for v in [0u8, 0xFF, 0x80] {
                    let mut d = clean.clone();
                    d[i] = v;
                    walk(&d);
                }
            }
        }
    }
    let _ = vec![0u8; 0];
}

#[test]
fn cpu_types_name_architectures() {
    use hexcavator_core::Arch;
    assert_eq!(arch(CPU_TYPE_X86_64), Arch::X64);
    assert_eq!(arch(CPU_TYPE_X86), Arch::X86);
    assert_eq!(arch(CPU_TYPE_ARM64), Arch::Arm64);
    assert_eq!(arch(CPU_TYPE_ARM64_32), Arch::Arm64);
    assert_eq!(arch(CPU_TYPE_ARM), Arch::Arm);
    assert_eq!(arch(CPU_TYPE_POWERPC64), Arch::PowerPc64);
    assert_eq!(arch(CPU_TYPE_MC680X0), Arch::M68k);
    assert_eq!(arch(CPU_TYPE_HPPA), Arch::Unknown);
}

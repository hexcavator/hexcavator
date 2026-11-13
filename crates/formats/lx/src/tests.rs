use super::*;

use alloc::vec;

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

fn pascal(v: &mut Vec<u8>, s: &str) {
    v.push(u8::try_from(s.len()).unwrap());
    v.extend_from_slice(s.as_bytes());
}

fn len32(v: &[u8]) -> u32 {
    u32::try_from(v.len()).unwrap()
}

/// The tables after a 0xC4-byte header (offsets from the header), for
/// `lx` (else LE), and the header's fields that locate them.
struct Built {
    file: Vec<u8>,
}

/// An LX (or LE) module: an MZ stub, the header at 0x80, its tables,
/// then (from 0x400) the data pages (page size 0x100).
fn module(lx: bool) -> Built {
    let mut f = vec![0u8; 0x80];
    f[0..2].copy_from_slice(b"MZ");
    f[0x18] = 0x40;
    put32(&mut f, 0x3C, 0x80);
    let mut h = vec![0u8; 0xC4];
    h[0..2].copy_from_slice(if lx { b"LX" } else { b"LE" });
    let mut t: Vec<u8> = Vec::new();
    let off = |t: &Vec<u8>| 0xC4 + len32(t);
    // Objects: code (2 pages from 1), data (1 page, 3).
    let objtab = off(&t);
    for (size, base, flags, first, count) in [
        (
            0x180u32,
            0x1_0000u32,
            OBJ_READ | OBJ_EXEC | OBJ_BIG,
            1u32,
            2u32,
        ),
        (0x100, 0x2_0000, OBJ_READ | OBJ_WRITE | OBJ_BIG, 3, 1),
    ] {
        for w in [size, base, flags, first, count, 0] {
            t.extend_from_slice(&w.to_le_bytes());
        }
    }
    // The page map: pages 1 and 2 (legal), 3 (LX: zero-filled; LE: legal).
    let pagemap = off(&t);
    if lx {
        for (o, s, k) in [(0u32, 0x100u16, 0u16), (1, 0x80, 0), (0, 0, 3)] {
            t.extend_from_slice(&o.to_le_bytes());
            t.extend_from_slice(&s.to_le_bytes());
            t.extend_from_slice(&k.to_le_bytes());
        }
    } else {
        for n in 1u8..=3 {
            t.extend_from_slice(&[0, 0, n, 0]);
        }
    }
    // A resource: type 1, ID 7, 0x10 bytes at 0x20 of object 2.
    let rsrctab = off(&t);
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&7u16.to_le_bytes());
    t.extend_from_slice(&0x10u32.to_le_bytes());
    t.extend_from_slice(&2u16.to_le_bytes());
    t.extend_from_slice(&0x20u32.to_le_bytes());
    // Resident names.
    let restab = off(&t);
    pascal(&mut t, "SAMPLE");
    t.extend_from_slice(&0u16.to_le_bytes());
    pascal(&mut t, "Start");
    t.extend_from_slice(&1u16.to_le_bytes());
    t.push(0);
    // Entries: @1 32-bit in object 1 at 0x10; @2-3 unused; @4 16-bit in
    // object 2 at 8; @5 a forwarder to DOSCALLS @233.
    let enttab = off(&t);
    t.extend_from_slice(&[1, 3, 1, 0, 0x01]);
    t.extend_from_slice(&0x10u32.to_le_bytes());
    t.extend_from_slice(&[2, 0]);
    t.extend_from_slice(&[1, 1, 2, 0, 0x03, 0x08, 0x00]);
    t.extend_from_slice(&[1, 4, 0, 0, 0x01, 1, 0]);
    t.extend_from_slice(&233u32.to_le_bytes());
    t.push(0);
    // Fixups for page 1 (0-based 0): an internal 32-bit offset at 4 (to
    // object 2 + 0x10); an import by ordinal at 0x20 (DOSCALLS @1); an
    // import by name, additive 4, at two places (0x30, 0x40); an
    // internal selector at 0x50. Page 2: none.
    let fpagetab = off(&t);
    let frec: Vec<u8> = {
        let mut r = Vec::new();
        r.extend_from_slice(&[0x07, 0x10, 0x04, 0x00, 2]);
        r.extend_from_slice(&0x10u32.to_le_bytes());
        r.extend_from_slice(&[0x07, 0x01, 0x20, 0x00, 1, 0x01, 0x00]);
        r.extend_from_slice(&[
            0x27, 0x06, 2, 1, 0x01, 0x00, 0x04, 0x00, 0x30, 0x00, 0x40, 0x00,
        ]);
        r.extend_from_slice(&[0x02, 0x00, 0x50, 0x00, 1]);
        r
    };
    for w in [0u32, len32(&frec), len32(&frec), len32(&frec)] {
        t.extend_from_slice(&w.to_le_bytes());
    }
    let frectab = off(&t);
    t.extend_from_slice(&frec);
    // Imports: modules DOSCALLS, VIOCALLS; a procedure name, DosWrite.
    let impmod = off(&t);
    pascal(&mut t, "DOSCALLS");
    pascal(&mut t, "VIOCALLS");
    let impproc = off(&t);
    t.push(0);
    pascal(&mut t, "DosWrite"); // at 1
    // The nonresident names (file offset).
    let nres = 0x80 + 0xC4 + len32(&t);
    let n0 = t.len();
    pascal(&mut t, "A sample module");
    t.extend_from_slice(&0u16.to_le_bytes());
    t.push(0);
    let nressize = len32(&t[n0..]);
    // The header.
    h[8] = 2; // (cpu: 386)
    h[0x0A] = if lx { 1 } else { 4 }; // (os: OS/2, or Windows 386)
    put32(&mut h, 0x10, if lx { MOD_LIBRARY } else { 0 });
    put32(&mut h, 0x14, 3);
    put32(&mut h, 0x18, 1);
    put32(&mut h, 0x1C, 0x10);
    put32(&mut h, 0x20, 2);
    put32(&mut h, 0x24, 0xF0);
    put32(&mut h, 0x28, 0x100);
    put32(&mut h, 0x2C, if lx { 0 } else { 0x40 });
    put32(&mut h, 0x40, objtab);
    put32(&mut h, 0x44, 2);
    put32(&mut h, 0x48, pagemap);
    put32(&mut h, 0x50, rsrctab);
    put32(&mut h, 0x54, 1);
    put32(&mut h, 0x58, restab);
    put32(&mut h, 0x5C, enttab);
    put32(&mut h, 0x68, fpagetab);
    put32(&mut h, 0x6C, frectab);
    put32(&mut h, 0x70, impmod);
    put32(&mut h, 0x74, 2);
    put32(&mut h, 0x78, impproc);
    put32(&mut h, 0x80, 0x400);
    put32(&mut h, 0x88, nres);
    put32(&mut h, 0x8C, nressize);
    put32(&mut h, 0xA8, 0x1000);
    if lx {
        put32(&mut h, 0xAC, 0x2000);
    } else {
        put32(&mut h, 0xB8, 0x700);
        put32(&mut h, 0xBC, 0x20);
        h[0xC0..0xC2].copy_from_slice(&0x1234u16.to_le_bytes());
        h[0xC2..0xC4].copy_from_slice(&0x030Au16.to_le_bytes());
    }
    f.extend_from_slice(&h);
    f.extend_from_slice(&t);
    assert!(f.len() <= 0x400);
    f.resize(0x400, 0);
    for page in 0..3u8 {
        f.extend(core::iter::repeat_n(0xA0 + page, 0x100));
    }
    Built { file: f }
}

#[test]
fn lx_module() {
    let b = module(true);
    let lx = LxFile::parse(&b.file).unwrap();
    let h = lx.header();
    assert!(h.lx);
    assert_eq!((h.cpu, h.os, h.pages, h.page_size), (2, 1, 3, 0x100));
    assert_eq!(
        (h.eip, h.esp, h.heap, h.stack),
        ((1, 0x10), (2, 0xF0), 0x1000, 0x2000)
    );
    assert!(!lx.is_vxd());
    let o = lx.objects();
    assert_eq!(o.len(), 2);
    assert_eq!(
        (o[0].size, o[0].base, o[0].first_page, o[0].page_count),
        (0x180, 0x1_0000, 1, 2)
    );
    assert_eq!(o[1].flags & OBJ_WRITE, OBJ_WRITE);
    let p = lx.pages();
    assert_eq!(
        p,
        [
            Page {
                offset: 0x400,
                size: 0x100,
                kind: PageKind::Legal
            },
            Page {
                offset: 0x401,
                size: 0x80,
                kind: PageKind::Legal
            },
            Page {
                offset: 0x400,
                size: 0,
                kind: PageKind::Zeroed
            },
        ]
    );
    assert_eq!(lx.page_data(&p[0]), &[0xA0; 0x100][..]);
    assert!(lx.page_data(&p[2]).is_empty());
    assert_eq!(
        lx.resources(),
        [Resource {
            kind: 1,
            id: 7,
            size: 0x10,
            object: 2,
            offset: 0x20
        }]
    );
    assert_eq!(lx.module_name().as_deref(), Some("SAMPLE"));
    assert_eq!(lx.description().as_deref(), Some("A sample module"));
    assert_eq!(lx.resident_names()[1].ordinal, 1);
    assert_eq!(lx.import_modules(), ["DOSCALLS", "VIOCALLS"]);
    assert_eq!(lx.import_name(1).as_deref(), Some("DosWrite"));
    assert_eq!(
        lx.entries(),
        [
            Entry {
                ordinal: 1,
                flags: 1,
                kind: EntryKind::Offset32 {
                    object: 1,
                    offset: 0x10
                }
            },
            Entry {
                ordinal: 4,
                flags: 3,
                kind: EntryKind::Offset16 {
                    object: 2,
                    offset: 8
                }
            },
            Entry {
                ordinal: 5,
                flags: 1,
                kind: EntryKind::Forwarder {
                    module: 1,
                    by_ordinal: true,
                    value: 233
                }
            },
        ]
    );
    assert_eq!(
        lx.fixups(0),
        [
            Fixup {
                source: 7,
                offsets: vec![4],
                target: FixupTarget::Internal {
                    object: 2,
                    offset: Some(0x10)
                },
                additive: None
            },
            Fixup {
                source: 7,
                offsets: vec![0x20],
                target: FixupTarget::ImportOrdinal {
                    module: 1,
                    ordinal: 1
                },
                additive: None
            },
            Fixup {
                source: 7,
                offsets: vec![0x30, 0x40],
                target: FixupTarget::ImportName { module: 1, name: 1 },
                additive: Some(4)
            },
            Fixup {
                source: 2,
                offsets: vec![0x50],
                target: FixupTarget::Internal {
                    object: 1,
                    offset: None
                },
                additive: None
            },
        ]
    );
    assert!(lx.fixups(1).is_empty());
    assert!(lx.fixups(3).is_empty());
}

#[test]
fn le_vxd() {
    let b = module(false);
    let le = LxFile::parse(&b.file).unwrap();
    let h = le.header();
    assert!(!h.lx);
    assert!(le.is_vxd());
    assert_eq!(
        (h.device_id, h.ddk_version, h.vxd_resources),
        (0x1234, 0x030A, (0x700, 0x20))
    );
    // LE's page map: page numbers; the last page is the last page size.
    let p = le.pages();
    assert_eq!(
        p.iter().map(|p| (p.offset, p.size)).collect::<Vec<_>>(),
        [(0x400, 0x100), (0x500, 0x100), (0x600, 0x40)]
    );
    assert_eq!(le.page_data(&p[1]), &[0xA1; 0x100][..]);
    assert_eq!(le.page_data(&p[2]), &[0xA2; 0x40][..]);
    assert_eq!(le.fixups(0).len(), 4);
}

#[test]
fn not_lx() {
    assert!(LxFile::parse(b"MZ").is_err());
    let mut b = module(true);
    b.file[0x80] = b'N';
    b.file[0x81] = b'E';
    assert_eq!(
        LxFile::parse(&b.file).unwrap_err().kind,
        ErrorKind::BadMagic
    );
    let b = module(true);
    assert_eq!(
        LxFile::parse(&b.file[..0x100]).unwrap_err().kind,
        ErrorKind::Truncated
    );
    let mut b = module(true);
    b.file[0x82] = 1;
    assert_eq!(
        LxFile::parse(&b.file).unwrap_err().kind,
        ErrorKind::Unsupported
    );
}

#[test]
fn damage_does_not_panic() {
    for lx in [true, false] {
        let f = module(lx).file;
        for at in 0x80..0x400 {
            for x in [0x01, 0x80, 0xFF] {
                let mut bad = f.clone();
                bad[at] ^= x;
                let Ok(m) = LxFile::parse(&bad) else { continue };
                let _ = (m.objects(), m.resources(), m.entries(), m.import_modules());
                let _ = (m.resident_names(), m.nonresident_names());
                for (i, p) in m.pages().iter().enumerate().take(64) {
                    let _ = (m.page_data(p), m.fixups(u32::try_from(i).unwrap()));
                }
            }
        }
        for len in 0..f.len() {
            if let Ok(m) = LxFile::parse(&f[..len]) {
                let _ = (m.objects(), m.pages(), m.entries(), m.fixups(0));
            }
        }
    }
}

/// The sample, in testdata/legacy (for the fuzzer's seeds, and readers'
/// reference): kept current; `HEXC_BLESS=1` rewrites it.
fn check_sample(name: &str, bytes: &[u8]) {
    extern crate std;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/legacy")
        .join(name);
    if std::env::var_os("HEXC_BLESS").is_some() {
        std::fs::write(&path, bytes).unwrap();
    }
    let have = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (HEXC_BLESS=1 writes it)", path.display()));
    assert!(
        have == bytes,
        "{} is stale (HEXC_BLESS=1 rewrites it)",
        path.display()
    );
}

#[test]
fn samples_are_current() {
    check_sample("sample.lx", &module(true).file);
    check_sample("sample-vxd.le", &module(false).file);
}

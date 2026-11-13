use super::*;

use alloc::vec;

fn put16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}

fn pascal(v: &mut Vec<u8>, s: &str) {
    v.push(u8::try_from(s.len()).unwrap());
    v.extend_from_slice(s.as_bytes());
}

/// An NE library, laid out as the format says: an MZ stub, the NE header
/// at 0x40, its tables, then (from 0x200, alignment 2^4) two segments'
/// data, the code segment's relocations, and a resource.
fn library() -> Vec<u8> {
    let mut f = vec![0u8; 0x40];
    f[0..2].copy_from_slice(b"MZ");
    put16(&mut f, 0x18, 0x40); // (relocation table at 0x40: a new header)
    f[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    // The tables, after the 64-byte header (offsets from the NE header).
    let mut t: Vec<u8> = Vec::new();
    let at = |t: &Vec<u8>| u16::try_from(0x40 + t.len()).unwrap();
    // Segments: code (0x200, 0x20 bytes, relocations), data (0x240, 8).
    let segtab = at(&t);
    for (sector, size, flags, min) in [
        (
            0x20u16,
            0x20u16,
            NE_SEGFLAGS_RELOCINFO | NE_SEGFLAGS_MOVEABLE,
            0x20u16,
        ),
        (0x24, 8, NE_SEGFLAGS_DATA, 0),
    ] {
        for w in [sector, size, flags, min] {
            t.extend_from_slice(&w.to_le_bytes());
        }
    }
    // Resources (shift 4): an RT_FONT with ID 1, and a named type "BLOB"
    // with a named resource "ONE".
    let rsrc = at(&t);
    let r0 = t.len();
    t.extend_from_slice(&4u16.to_le_bytes());
    t.extend_from_slice(&(0x8000 | RT_FONT).to_le_bytes());
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&[0; 4]);
    for w in [0x26u16, 1, 0x30, 0x8001, 0, 0] {
        t.extend_from_slice(&w.to_le_bytes());
    }
    let blob_type = t.len();
    t.extend_from_slice(&[0, 0]); // (the type's name: patched below)
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&[0; 4]);
    let one_id = t.len() + 6;
    for w in [0x26u16, 1, 0x30, 0, 0, 0] {
        t.extend_from_slice(&w.to_le_bytes());
    }
    t.extend_from_slice(&[0, 0]);
    let blob_name = u16::try_from(t.len() - r0).unwrap();
    pascal(&mut t, "BLOB");
    let one_name = u16::try_from(t.len() - r0).unwrap();
    pascal(&mut t, "ONE");
    t.push(0);
    put16(&mut t, blob_type, blob_name);
    put16(&mut t, one_id, one_name);
    // Resident names: the module's, then Exported @1.
    let restab = at(&t);
    pascal(&mut t, "SAMPLE");
    t.extend_from_slice(&0u16.to_le_bytes());
    pascal(&mut t, "EXPORTED");
    t.extend_from_slice(&1u16.to_le_bytes());
    t.push(0);
    // Module references (offsets into the imported names), then the
    // imported names: KERNEL and GDI, and an imported name, GETVERSION.
    let modtab = at(&t);
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&8u16.to_le_bytes());
    let imptab = at(&t);
    t.push(0);
    pascal(&mut t, "KERNEL"); // 1
    pascal(&mut t, "GDI"); // 8
    pascal(&mut t, "GETVERSION"); // 12
    // Entries: @1 fixed in segment 1 at 0x10, @2 unused, @3 moveable in
    // segment 2 at 4.
    let enttab = at(&t);
    let e0 = t.len();
    t.extend_from_slice(&[1, 1, 0x01, 0x10, 0x00]);
    t.extend_from_slice(&[1, 0]);
    t.extend_from_slice(&[1, 0xFF, 0x03, 0xCD, 0x3F, 2, 0x04, 0x00]);
    t.push(0);
    let entsize = u16::try_from(t.len() - e0).unwrap();
    // The nonresident names: the description, then Other @3.
    let nres = 0x40 + 0x40 + t.len();
    let n0 = t.len();
    pascal(&mut t, "A sample library");
    t.extend_from_slice(&0u16.to_le_bytes());
    pascal(&mut t, "OTHER");
    t.extend_from_slice(&3u16.to_le_bytes());
    t.push(0);
    let nressize = u16::try_from(t.len() - n0).unwrap();
    // The header.
    let mut h = vec![0u8; 0x40];
    h[0..2].copy_from_slice(b"NE");
    h[2] = 5;
    h[3] = 10;
    put16(&mut h, 0x04, enttab);
    put16(&mut h, 0x06, entsize);
    put16(&mut h, 0x0C, NE_FFLAGS_LIBMODULE | NE_FFLAGS_SINGLEDATA);
    put16(&mut h, 0x0E, 2);
    put16(&mut h, 0x10, 0x400);
    put16(&mut h, 0x14, 0x10); // IP
    put16(&mut h, 0x16, 1); // CS
    put16(&mut h, 0x1C, 2);
    put16(&mut h, 0x1E, 2);
    put16(&mut h, 0x20, nressize);
    put16(&mut h, 0x22, segtab);
    put16(&mut h, 0x24, rsrc);
    put16(&mut h, 0x26, restab);
    put16(&mut h, 0x28, modtab);
    put16(&mut h, 0x2A, imptab);
    h[0x2C..0x30].copy_from_slice(&u32::try_from(nres).unwrap().to_le_bytes());
    put16(&mut h, 0x32, 4);
    h[0x36] = NE_OS_WINDOWS;
    h[0x3E] = 0x0A; // Windows 3.10
    h[0x3F] = 3;
    f.extend_from_slice(&h);
    f.extend_from_slice(&t);
    // Segment 1's data (0x20 bytes of code) and its relocations: a far
    // call to KERNEL.GETVERSION by name at 1, one to GDI @5 at 6, a
    // selector of segment 2 at 0x0B (chained on to 0x0E), and an OS fixup.
    f.resize(0x200, 0);
    f.extend_from_slice(&[0x90; 0x20]);
    f.extend_from_slice(&4u16.to_le_bytes());
    f.extend_from_slice(&[3, 2, 1, 0, 1, 0, 12, 0]);
    f.extend_from_slice(&[3, 1, 6, 0, 2, 0, 5, 0]);
    f.extend_from_slice(&[2, 0, 0x0B, 0, 2, 0, 0, 0]);
    f.extend_from_slice(&[5, 7, 0x10, 0, 1, 0, 0, 0]);
    // Segment 2 (0x240): data. The resources (0x260): 16 bytes each.
    f.resize(0x240, 0);
    f.extend_from_slice(b"DATADATA");
    f.resize(0x260, 0);
    f.extend_from_slice(b"FONT-RESOURCE...");
    f
}

#[test]
fn header() {
    let f = library();
    let ne = NeFile::parse(&f).unwrap();
    let h = ne.header();
    assert_eq!(ne.header_offset(), 0x40);
    assert_eq!(h.linker, (5, 10));
    assert!(ne.is_library());
    assert_eq!(h.cs_ip, (1, 0x10));
    assert_eq!((h.segments, h.modules, h.alignment_shift), (2, 2, 4));
    assert_eq!(h.target_os, NE_OS_WINDOWS);
    assert_eq!(h.windows_version, (3, 10));
    assert_eq!(h.heap, 0x400);
}

#[test]
fn segments_and_relocations() {
    let f = library();
    let ne = NeFile::parse(&f).unwrap();
    let s = ne.segments();
    assert_eq!(s.len(), 2);
    assert_eq!(
        (s[0].number, s[0].offset, s[0].size, s[0].is_data()),
        (1, 0x200, 0x20, false)
    );
    assert_eq!(
        (s[1].offset, s[1].size, s[1].min_alloc, s[1].is_data()),
        (0x240, 8, 0x10000, true)
    );
    assert_eq!(ne.segment_data(&s[1]), b"DATADATA");
    assert!(ne.relocations(&s[1]).is_empty());
    let r = ne.relocations(&s[0]);
    assert_eq!(
        r,
        [
            Relocation {
                source: 3,
                additive: false,
                offset: 1,
                target: Target::ImportName {
                    module: 1,
                    name: 12
                }
            },
            Relocation {
                source: 3,
                additive: false,
                offset: 6,
                target: Target::ImportOrdinal {
                    module: 2,
                    ordinal: 5
                }
            },
            Relocation {
                source: 2,
                additive: false,
                offset: 0x0B,
                target: Target::Internal {
                    segment: 2,
                    offset: 0
                }
            },
            Relocation {
                source: 5,
                additive: true,
                offset: 0x10,
                target: Target::OsFixup(1)
            },
        ]
    );
    assert_eq!(ne.modules(), ["KERNEL", "GDI"]);
    assert_eq!(ne.imported_name(12).as_deref(), Some("GETVERSION"));
}

#[test]
fn resources() {
    let f = library();
    let ne = NeFile::parse(&f).unwrap();
    let r = ne.resources();
    assert_eq!(r.len(), 2);
    assert_eq!((&r[0].kind, &r[0].id), (&Id::Int(RT_FONT), &Id::Int(1)));
    assert_eq!((r[0].offset, r[0].size, r[0].flags), (0x260, 16, 0x30));
    assert_eq!(ne.resource_data(&r[0]), b"FONT-RESOURCE...");
    assert_eq!(
        (&r[1].kind, &r[1].id),
        (&Id::Name("BLOB".into()), &Id::Name("ONE".into()))
    );
}

#[test]
fn names_and_entries() {
    let f = library();
    let ne = NeFile::parse(&f).unwrap();
    assert_eq!(ne.module_name().as_deref(), Some("SAMPLE"));
    assert_eq!(ne.description().as_deref(), Some("A sample library"));
    let res: Vec<(String, u16)> = ne
        .resident_names()
        .into_iter()
        .map(|n| (n.name, n.ordinal))
        .collect();
    assert_eq!(res, [("SAMPLE".into(), 0), ("EXPORTED".into(), 1)]);
    let nres: Vec<u16> = ne.nonresident_names().iter().map(|n| n.ordinal).collect();
    assert_eq!(nres, [0, 3]);
    assert_eq!(
        ne.entries(),
        [
            Entry {
                ordinal: 1,
                segment: 1,
                offset: 0x10,
                flags: 1,
                moveable: false
            },
            Entry {
                ordinal: 3,
                segment: 2,
                offset: 4,
                flags: 3,
                moveable: true
            },
        ]
    );
}

#[test]
fn not_ne() {
    assert!(NeFile::parse(b"MZ").is_err());
    let mut f = library();
    f[0x40] = b'P';
    assert_eq!(NeFile::parse(&f).unwrap_err().kind, ErrorKind::BadMagic);
    let f = library();
    assert_eq!(
        NeFile::parse(&f[..0x60]).unwrap_err().kind,
        ErrorKind::Truncated
    );
}

#[test]
fn damage_does_not_panic() {
    let f = library();
    for at in 0..f.len() {
        for x in [0x01, 0x80, 0xFF] {
            let mut bad = f.clone();
            bad[at] ^= x;
            let Ok(ne) = NeFile::parse(&bad) else {
                continue;
            };
            for s in ne.segments() {
                let _ = (ne.segment_data(&s), ne.relocations(&s));
            }
            for r in ne.resources() {
                let _ = ne.resource_data(&r);
            }
            let _ = (
                ne.resident_names(),
                ne.nonresident_names(),
                ne.modules(),
                ne.entries(),
            );
        }
    }
    for len in 0..f.len() {
        if let Ok(ne) = NeFile::parse(&f[..len]) {
            let _ = (
                ne.segments(),
                ne.resources(),
                ne.entries(),
                ne.nonresident_names(),
            );
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
fn sample_is_current() {
    check_sample("sample.ne", &library());
}

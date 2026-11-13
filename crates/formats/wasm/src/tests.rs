//! Hermetic tests: modules built in memory, and damaged.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn uleb(n: u64, out: &mut Vec<u8>) {
    let mut n = n;
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn section(id: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(id);
    uleb(body.len() as u64, out);
    out.extend_from_slice(body);
}

/// Two functions (no imports), a data segment, and names for both.
fn sample() -> Vec<u8> {
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    section(SECTION_TYPE, &[1, 0x60, 0, 0], &mut m);
    section(SECTION_FUNCTION, &[2, 0, 0], &mut m);
    section(SECTION_CODE, &[2, 2, 0, 0x0B, 3, 0, 0x01, 0x0B], &mut m);
    section(
        SECTION_DATA,
        &[1, 0, 0x41, 8, 0x0B, 3, b'a', b'b', b'c'],
        &mut m,
    );
    let mut names = vec![4];
    names.extend_from_slice(b"name");
    names.extend_from_slice(&[1, 9, 2, 0, 2, b'f', b'0', 1, 2, b'f', b'1']);
    names.extend_from_slice(&[9, 5, 1, 0, 2, b'd', b'0']);
    section(SECTION_CUSTOM, &names, &mut m);
    m
}

#[test]
fn parses_a_module() {
    let data = sample();
    let m = Module::parse(&data).unwrap();
    let ids: Vec<u8> = m.sections().iter().map(|s| s.id).collect();
    assert_eq!(ids, [1, 3, 10, 11, 0]);
    assert_eq!(m.sections()[2].name, b"Code");
    assert_eq!(m.sections()[4].name, b"name");
    let f = m.functions();
    assert_eq!(f.len(), 2);
    assert_eq!((f[0].index, f[0].size), (0, 3));
    assert_eq!((f[1].index, f[1].size), (1, 4));
    let d = m.data_segments();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].size, 8);
    let n = m.names(NAME_FUNCTION);
    assert_eq!(
        n.iter().map(|n| n.name).collect::<Vec<_>>(),
        [&b"f0"[..], b"f1"]
    );
    assert_eq!(m.names(NAME_DATA_SEGMENT)[0].name, b"d0");
    assert_eq!(m.imported_functions(), 0);
    assert_eq!(m.source_mapping_url(), None);
}

#[test]
fn rejects_and_survives_damage() {
    assert!(Module::parse(b"\x7fELF").is_err());
    assert!(Module::parse(b"\0asm").is_err());
    let clean = sample();
    // An unknown section id ends the list.
    let mut d = clean.clone();
    d[8] = 99;
    assert!(Module::parse(&d).unwrap().sections().is_empty());
    for n in 0..clean.len() {
        if let Ok(m) = Module::parse(&clean[..n]) {
            let _ = (
                m.functions(),
                m.data_segments(),
                m.names(NAME_FUNCTION),
                m.imported_functions(),
            );
        }
    }
    for i in 0..clean.len() {
        for v in [0u8, 0xFF, 0x80, 0x7F] {
            let mut d = clean.clone();
            d[i] = v;
            if let Ok(m) = Module::parse(&d) {
                let _ = (
                    m.functions(),
                    m.data_segments(),
                    m.names(NAME_FUNCTION),
                    m.names(NAME_DATA_SEGMENT),
                    m.imported_functions(),
                    m.source_mapping_url(),
                );
            }
        }
    }
}

fn custom(name: &[u8], payload: &[u8], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    uleb(name.len() as u64, &mut body);
    body.extend_from_slice(name);
    body.extend_from_slice(payload);
    section(SECTION_CUSTOM, &body, out);
}

#[test]
fn debug_identities_and_object_files() {
    let mut data = sample();
    let m = Module::parse(&data).unwrap();
    assert_eq!((m.build_id(), m.external_debug_info()), (None, None));
    assert!(!m.is_object());
    custom(b"build_id", &[4, 0xDE, 0xAD, 0xBE, 0xEF], &mut data);
    custom(b"external_debug_info", b"\x0Amodule.dbg", &mut data);
    custom(b"linking", &[2], &mut data);
    let m = Module::parse(&data).unwrap();
    assert_eq!(m.build_id(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    assert_eq!(m.external_debug_info(), Some(&b"module.dbg"[..]));
    assert!(m.is_object());
    // A custom section's data follows its name; a standard one's is its
    // contents.
    let s = m.custom(b"build_id").unwrap();
    assert_eq!(s.data_offset, s.contents_offset + 9);
    let code = &m.sections()[2];
    assert_eq!(code.data_offset, code.contents_offset);
}

#[test]
fn memory64_defined_or_imported() {
    let module = |sections: &[(u8, &[u8])]| {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        for (id, body) in sections {
            section(*id, body, &mut m);
        }
        m
    };
    // A memory of 1 page; with the memory64 flag, and without.
    let m32 = module(&[(SECTION_MEMORY, &[1, 0, 1])]);
    let m64 = module(&[(SECTION_MEMORY, &[1, 0x04, 1])]);
    assert!(!Module::parse(&m32).unwrap().is_memory64());
    assert!(Module::parse(&m64).unwrap().is_memory64());
    // Imported: a function first (skipped), then the memory.
    let import = |flags: u8| {
        let mut b = vec![2];
        b.extend_from_slice(&[1, b'e', 1, b'f', 0, 0]);
        b.extend_from_slice(&[1, b'e', 1, b'm', 2, flags, 1]);
        b
    };
    let i64 = module(&[(SECTION_IMPORT, &import(0x04))]);
    let i32 = module(&[(SECTION_IMPORT, &import(0))]);
    assert!(Module::parse(&i64).unwrap().is_memory64());
    assert!(!Module::parse(&i32).unwrap().is_memory64());
    // No memory at all, or a damaged import: 32-bit.
    assert!(!Module::parse(&sample()).unwrap().is_memory64());
    let damaged = module(&[(SECTION_IMPORT, &[5, 1, b'e'])]);
    assert!(!Module::parse(&damaged).unwrap().is_memory64());
}

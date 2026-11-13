// Test archives are small: offsets fit in 32 bits.
#![allow(clippy::cast_possible_truncation)]

extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use std::format;

use super::*;

/// Builds an archive from (header name, data) members.
fn archive(magic: &[u8], members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = magic.to_vec();
    for (name, data) in members {
        let h = format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "0",
            "0",
            "0",
            "644",
            data.len()
        );
        assert_eq!(h.len(), 60, "{h}");
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(data);
        if out.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[test]
fn gnu_archive() {
    // Long names, and a symbol table naming members by header offset.
    let long = b"a_very_long_object_name.o/\nanother_long_name.o/\n".to_vec();
    let a = b"AAAA".to_vec();
    let b = b"BBB".to_vec();
    // Offsets: magic 8; symtab header 8, data len to be computed.
    let names = b"f\0g\0h\0";
    let sym_len = 4 + 3 * 4 + names.len();
    let long_at = 8 + 60 + sym_len + (sym_len & 1);
    let a_at = long_at + 60 + long.len() + (long.len() & 1);
    let b_at = a_at + 60 + a.len();
    let mut symtab = be32(3).to_vec();
    for o in [a_at, a_at, b_at] {
        symtab.extend_from_slice(&be32(o as u32));
    }
    symtab.extend_from_slice(names);
    let data = archive(
        MAGIC,
        &[
            ("/", symtab),
            ("//", long),
            ("/0", a.clone()),
            ("/27", b.clone()),
        ],
    );
    let ar = Archive::parse(&data).unwrap();
    assert!(!ar.is_thin());
    let kinds: Vec<MemberKind> = ar.members().map(|m| m.kind).collect();
    assert_eq!(
        kinds,
        [
            MemberKind::SymbolTable,
            MemberKind::LongNames,
            MemberKind::File,
            MemberKind::File
        ]
    );
    let files: Vec<Member<'_>> = ar.files().collect();
    assert_eq!(&*files[0].name, b"a_very_long_object_name.o");
    assert_eq!(files[0].data, b"AAAA");
    assert_eq!(files[0].header_offset, a_at as u64);
    assert_eq!(&*files[1].name, b"another_long_name.o");
    assert_eq!(files[1].data, b"BBB");
    let symbols = ar.symbols();
    assert_eq!(symbols.len(), 3);
    assert_eq!(
        (symbols[2].name, symbols[2].member),
        (&b"h"[..], b_at as u64)
    );
    assert_eq!(
        &*ar.member_at_offset(b_at as u64).unwrap().name,
        b"another_long_name.o"
    );
    assert!(ar.member_at_offset(1).is_none());
}

#[test]
fn microsoft_archive() {
    // Two linker members, long names ending with NUL, short names with `/`.
    let long = b"long\\path\\to\\object.obj\0".to_vec();
    let one = b"1111".to_vec();
    let two = b"22".to_vec();
    let first_len = 4 + 2 * 4 + 4;
    let names = b"x\0y\0";
    let second_len = 4 + 2 * 4 + 4 + 2 * 2 + names.len();
    let long_at = 8 + 60 + first_len + 60 + second_len;
    let one_at = long_at + 60 + long.len() + (long.len() & 1);
    let two_at = one_at + 60 + one.len();
    let mut first = be32(2).to_vec();
    first.extend_from_slice(&be32(one_at as u32));
    first.extend_from_slice(&be32(two_at as u32));
    first.extend_from_slice(b"x\0y\0");
    let mut second = 2u32.to_le_bytes().to_vec();
    second.extend_from_slice(&(one_at as u32).to_le_bytes());
    second.extend_from_slice(&(two_at as u32).to_le_bytes());
    second.extend_from_slice(&2u32.to_le_bytes());
    second.extend_from_slice(&2u16.to_le_bytes()); // x in member 2
    second.extend_from_slice(&1u16.to_le_bytes()); // y in member 1
    second.extend_from_slice(names);
    let data = archive(
        MAGIC,
        &[
            ("/", first),
            ("/", second),
            ("//", long),
            ("/0", one),
            ("short.obj/", two),
        ],
    );
    let ar = Archive::parse(&data).unwrap();
    let files: Vec<Member<'_>> = ar.files().collect();
    assert_eq!(&*files[0].name, b"long\\path\\to\\object.obj");
    assert_eq!(&*files[1].name, b"short.obj");
    let symbols = ar.symbols();
    assert_eq!(
        symbols,
        [
            ArchiveSymbol {
                name: b"x",
                member: two_at as u64
            },
            ArchiveSymbol {
                name: b"y",
                member: one_at as u64
            },
        ]
    );
}

#[test]
fn bsd_archive() {
    // `#1/len` names, and a __.SYMDEF table (little-endian, 4-byte).
    let strings = b"_main\0_f\0";
    let mut symdef = 16u32.to_le_bytes().to_vec();
    let mut name = b"__.SYMDEF\0\0\0".to_vec(); // padded to 12
    let symdef_len = name.len() + 4 + 16 + 4 + strings.len();
    let obj_at = 8 + 60 + symdef_len + (symdef_len & 1);
    for (n, m) in [(0u32, obj_at as u32), (6, obj_at as u32)] {
        symdef.extend_from_slice(&n.to_le_bytes());
        symdef.extend_from_slice(&m.to_le_bytes());
    }
    symdef.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    symdef.extend_from_slice(strings);
    name.extend_from_slice(&symdef);
    let mut obj = b"long_object_name.o\0\0".to_vec(); // 20
    obj.extend_from_slice(b"DATA");
    let data = archive(MAGIC, &[("#1/12", name), ("#1/20", obj)]);
    let ar = Archive::parse(&data).unwrap();
    let members: Vec<Member<'_>> = ar.members().collect();
    assert_eq!(members[0].kind, MemberKind::SymbolTable);
    assert_eq!(&*members[1].name, b"long_object_name.o");
    assert_eq!(members[1].data, b"DATA");
    assert_eq!(members[1].data_offset, members[1].header_offset + 60 + 20);
    let symbols = ar.symbols();
    assert_eq!(symbols.len(), 2);
    assert_eq!(symbols[1].name, b"_f");
    assert_eq!(symbols[1].member, obj_at as u64);
}

#[test]
fn thin_archive() {
    let mut data = THIN_MAGIC.to_vec();
    // A thin member's header gives its size, but its data is elsewhere.
    let h = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        "dir/a.o/", "0", "0", "0", "644", 1234
    );
    data.extend_from_slice(h.as_bytes());
    let h = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        "b.o/", "0", "0", "0", "644", 7
    );
    data.extend_from_slice(h.as_bytes());
    let ar = Archive::parse(&data).unwrap();
    assert!(ar.is_thin());
    let files: Vec<Member<'_>> = ar.files().collect();
    assert_eq!(files.len(), 2);
    assert_eq!(&*files[0].name, b"dir/a.o");
    assert_eq!(files[0].size, 1234);
    assert!(files[0].data.is_empty());
    assert_eq!(&*files[1].name, b"b.o");
}

#[test]
fn damaged_archives() {
    assert!(Archive::parse(b"not an archive").is_err());
    assert!(Archive::is_archive(MAGIC));
    // An empty archive.
    assert_eq!(Archive::parse(MAGIC).unwrap().members().count(), 0);
    // A bad header terminator ends the members.
    let mut data = archive(MAGIC, &[("a.o/", vec![1, 2]), ("b.o/", vec![3])]);
    data[8 + 58] = b'x';
    assert_eq!(Archive::parse(&data).unwrap().members().count(), 0);
    // A size beyond the archive: the member keeps what there is, and is
    // the last.
    let mut data = archive(MAGIC, &[("a.o/", vec![1, 2, 3, 4])]);
    data[8 + 48..8 + 58].copy_from_slice(b"99999999  ");
    let members: Vec<Member<'_>> = Archive::parse(&data).unwrap().members().collect();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].data, [1, 2, 3, 4]);
    // A non-numeric size ends the members.
    let mut data = archive(MAGIC, &[("a.o/", vec![1])]);
    data[8 + 48] = b'z';
    assert_eq!(Archive::parse(&data).unwrap().members().count(), 0);
    // A long name past the long-name table is empty.
    let data = archive(MAGIC, &[("//", b"x/\n".to_vec()), ("/999", vec![1])]);
    let ar = Archive::parse(&data).unwrap();
    assert_eq!(&*ar.files().next().unwrap().name, b"");
    // A BSD name longer than the member: the member is dropped.
    let data = archive(MAGIC, &[("#1/50", vec![b'n'; 4])]);
    assert_eq!(Archive::parse(&data).unwrap().members().count(), 0);
    // Symbol tables that claim too much give no symbols.
    let data = archive(
        MAGIC,
        &[("/", be32(0xFFFF_FFFF).to_vec()), ("a.o/", vec![0])],
    );
    assert!(Archive::parse(&data).unwrap().symbols().is_empty());
    let data = archive(
        MAGIC,
        &[("__.SYMDEF", 0xFFFF_FFF0u32.to_le_bytes().to_vec())],
    );
    assert!(Archive::parse(&data).unwrap().symbols().is_empty());
    // Every truncation of a valid archive parses without panicking.
    let full = archive(
        MAGIC,
        &[
            ("/", {
                let mut v = be32(1).to_vec();
                v.extend_from_slice(&be32(8));
                v.extend_from_slice(b"s\0");
                v
            }),
            ("//", b"long_name_here.o/\n".to_vec()),
            ("/0", vec![9; 9]),
            ("#1/4", b"name".to_vec()),
        ],
    );
    for len in 0..full.len() {
        if let Ok(ar) = Archive::parse(&full[..len]) {
            let _ = ar.members().count();
            let _ = ar.symbols();
        }
    }
}

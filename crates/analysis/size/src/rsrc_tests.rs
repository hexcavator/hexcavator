use super::*;
use crate::testimage::{Buf, SECTION_RVA, image};

#[derive(Clone, Copy)]
enum Key {
    Id(u16),
    Name(&'static str),
}

/// A resource: type, name, language, and where its data goes (an offset in
/// the section) with its contents.
struct Res {
    kind: Key,
    name: Key,
    lang: Key,
    at: u32,
    data: Vec<u8>,
}

fn key(k: Key) -> String {
    match k {
        Key::Id(i) => format!("#{i}"),
        Key::Name(n) => n.to_string(),
    }
}

/// (named, ID) entry counts.
fn count(keys: impl Iterator<Item = Key>) -> (u16, u16) {
    keys.fold((0, 0), |(n, i), k| match k {
        Key::Name(_) => (n + 1, i),
        Key::Id(_) => (n, i + 1),
    })
}

/// A name and the indexes of its resources (one per language).
type Names = (Key, Vec<usize>);

/// Lays out a three-level resource tree at the section's start, as resource
/// compilers do: tables, then data entries, then strings; the data goes
/// where each resource says.
fn tree(resources: &[Res]) -> Vec<u8> {
    // Group by type, then name, in order of first appearance.
    let mut types: Vec<(Key, Vec<Names>)> = Vec::new();
    for (i, r) in resources.iter().enumerate() {
        let t = match types.iter().position(|(k, _)| key(*k) == key(r.kind)) {
            Some(t) => t,
            None => {
                types.push((r.kind, Vec::new()));
                types.len() - 1
            }
        };
        let names = &mut types[t].1;
        match names.iter().position(|(k, _)| key(*k) == key(r.name)) {
            Some(n) => names[n].1.push(i),
            None => names.push((r.name, vec![i])),
        }
    }
    let table = |n: usize| 16 + 8 * n as u32;
    let mut next = table(types.len());
    let mut type_at = Vec::new();
    for (_, names) in &types {
        type_at.push(next);
        next += table(names.len());
    }
    let mut name_at = Vec::new();
    for (_, names) in &types {
        for (_, langs) in names {
            name_at.push(next);
            next += table(langs.len());
        }
    }
    let mut entry_at = vec![0; resources.len()];
    for (_, names) in &types {
        for (_, langs) in names {
            for &i in langs {
                entry_at[i] = next;
                next += 16;
            }
        }
    }
    let mut b = Buf::default();
    // Writes a name's field, and its string after the tree.
    fn name_field(b: &mut Buf, next: &mut u32, k: Key) -> u32 {
        match k {
            Key::Id(i) => u32::from(i),
            Key::Name(s) => {
                let at = *next;
                let units: Vec<u16> = s.encode_utf16().collect();
                b.u16(at as usize, units.len() as u16);
                for (i, u) in units.iter().enumerate() {
                    b.u16(at as usize + 2 + 2 * i, *u);
                }
                *next += 2 + 2 * units.len() as u32;
                0x8000_0000 | at
            }
        }
    }
    fn header(b: &mut Buf, at: u32, (named, ids): (u16, u16)) {
        b.u16(at as usize + 12, named).u16(at as usize + 14, ids);
    }
    header(&mut b, 0, count(types.iter().map(|t| t.0)));
    let mut name_index = 0;
    for (t, (kind, names)) in types.iter().enumerate() {
        let e = 16 + 8 * t;
        let f = name_field(&mut b, &mut next, *kind);
        b.u32(e, f).u32(e + 4, 0x8000_0000 | type_at[t]);
        header(&mut b, type_at[t], count(names.iter().map(|n| n.0)));
        for (j, (name, langs)) in names.iter().enumerate() {
            let e = (type_at[t] + 16 + 8 * j as u32) as usize;
            let f = name_field(&mut b, &mut next, *name);
            let at = name_at[name_index];
            name_index += 1;
            b.u32(e, f).u32(e + 4, 0x8000_0000 | at);
            header(&mut b, at, count(langs.iter().map(|&l| resources[l].lang)));
            for (k, &l) in langs.iter().enumerate() {
                let e = (at + 16 + 8 * k as u32) as usize;
                let f = name_field(&mut b, &mut next, resources[l].lang);
                b.u32(e, f).u32(e + 4, entry_at[l]);
                let r = &resources[l];
                b.u32(entry_at[l] as usize, SECTION_RVA + r.at)
                    .u32(entry_at[l] as usize + 4, r.data.len() as u32);
                b.bytes(r.at as usize, &r.data);
            }
        }
    }
    assert!(
        resources.iter().all(|r| r.at >= next),
        "data overlaps the tree"
    );
    b.0
}

type Sym = (u64, u64, SymbolKind, String);

fn symbols_of(resources: &[Res]) -> Vec<Sym> {
    let contents = tree(resources);
    let size = contents.len() as u32;
    let data = image(true, &contents, &[(2, SECTION_RVA, size)]);
    let pe = PeFile::parse(&data).unwrap();
    symbols(&pe)
        .into_iter()
        .map(|s| (s.addr - u64::from(SECTION_RVA), s.size.file, s.kind, s.name))
        .collect()
}

/// A group directory listing images (bytes in the image, ID).
fn group(entries: &[(u32, u16)]) -> Vec<u8> {
    let mut b = Buf::default();
    b.u16(2, 1).u16(4, entries.len() as u16);
    for (i, &(bytes, id)) in entries.iter().enumerate() {
        let e = 6 + 14 * i;
        b.u16(e + 4, 1)
            .u16(e + 6, 32)
            .u32(e + 8, bytes)
            .u16(e + 12, id);
    }
    b.0
}

const EN_US: Key = Key::Id(0x409);

fn res(kind: u16, name: Key, at: u32, data: Vec<u8>) -> Res {
    Res {
        kind: Key::Id(kind),
        name,
        lang: EN_US,
        at,
        data,
    }
}

/// (offset, size, name) of the symbols of `kind`.
fn find(symbols: &[Sym], kind: SymbolKind) -> Vec<(u64, u64, &str)> {
    symbols
        .iter()
        .filter(|s| s.2 == kind)
        .map(|s| (s.0, s.1, s.3.as_str()))
        .collect()
}

#[test]
fn tables_entries_and_data() {
    let s = symbols_of(&[
        res(rt::MANIFEST, Key::Id(2), 0x400, vec![1; 10]),
        Res {
            kind: Key::Name("CUSTOM"),
            name: Key::Name("THING"),
            lang: Key::Id(0x411),
            at: 0x410,
            data: vec![2; 4],
        },
    ]);
    assert_eq!(
        find(&s, SymbolKind::RsrcDirectory),
        [
            (0, 32, "[rsrc directory] L0 (Root)"),
            (32, 24, "[rsrc directory] L1 (MANIFEST)"),
            (56, 24, "[rsrc directory] L1 (CUSTOM)"),
            (80, 24, "[rsrc directory] L2 (MANIFEST, #2)"),
            (104, 24, "[rsrc directory] L2 (CUSTOM, THING)"),
        ]
    );
    assert_eq!(
        find(&s, SymbolKind::RsrcDataEntry),
        [
            (
                128,
                16,
                "[rsrc data entry] L2 (MANIFEST, #2, English (United States))"
            ),
            (
                144,
                16,
                "[rsrc data entry] L2 (CUSTOM, THING, Japanese (Japan))"
            ),
        ]
    );
    assert_eq!(
        find(&s, SymbolKind::RsrcString),
        [
            (160, 14, "[rsrc string] \"CUSTOM\""),
            (174, 12, "[rsrc string] \"THING\"")
        ]
    );
    assert_eq!(
        find(&s, SymbolKind::RsrcData),
        [
            (
                0x400,
                10,
                "Resource '#2' (MANIFEST, English (United States))"
            ),
            (0x410, 4, "Resource 'THING' (CUSTOM, Japanese (Japan))"),
        ]
    );
}

#[test]
fn languages_by_name_and_unknown_types() {
    let s = symbols_of(&[Res {
        kind: Key::Id(99),
        name: Key::Id(1),
        lang: Key::Name("Klingon"),
        at: 0x400,
        data: vec![0; 4],
    }]);
    assert!(s.iter().any(|x| x.3 == "Resource '#1' (#99, Klingon)"));
    assert!(s.iter().any(|x| x.3 == "[rsrc directory] L1 (#99)"));
    let s = symbols_of(&[Res {
        kind: Key::Id(rt::RCDATA),
        name: Key::Id(1),
        lang: Key::Id(0x800),
        at: 0x400,
        data: vec![0; 4],
    }]);
    assert!(
        s.iter()
            .any(|x| x.3 == "Resource '#1' (RCDATA, Unknown language)")
    );
}

#[test]
fn icon_groups_hold_their_icons() {
    // Icons of 20 and 16 bytes at 8-byte boundaries, then the group.
    let s = symbols_of(&[
        res(rt::ICON, Key::Id(1), 0x400, vec![0; 20]),
        res(rt::ICON, Key::Id(2), 0x418, vec![0; 16]),
        res(
            rt::GROUP_ICON,
            Key::Id(101),
            0x428,
            group(&[(20, 1), (16, 2)]),
        ),
    ]);
    assert_eq!(
        find(&s, SymbolKind::RsrcGroupIcon),
        [(
            0x400,
            24 + 16 + 6 + 28,
            "Resource '#101' (GROUP_ICON, English (United States))"
        )]
    );
    assert!(find(&s, SymbolKind::RsrcData).is_empty());
}

#[test]
fn icons_elsewhere_are_shown_on_their_own() {
    // The group lists icons 1 and 2, but icon 2 isn't just before the
    // group; icon 3 is in no group.
    let s = symbols_of(&[
        res(rt::ICON, Key::Id(1), 0x400, vec![0; 20]),
        res(rt::ICON, Key::Id(2), 0x500, vec![0; 16]),
        res(rt::ICON, Key::Id(3), 0x600, vec![0; 8]),
        res(
            rt::GROUP_ICON,
            Key::Id(101),
            0x428,
            group(&[(20, 1), (16, 2)]),
        ),
    ]);
    assert_eq!(
        find(&s, SymbolKind::RsrcGroupIcon),
        [(
            0x428,
            34,
            "Resource '#101' (GROUP_ICON, English (United States))"
        )]
    );
    assert_eq!(
        find(&s, SymbolKind::RsrcData),
        [
            (0x400, 20, "Resource '#1' (ICON, English (United States))"),
            (0x500, 16, "Resource '#2' (ICON, English (United States))"),
            (0x600, 8, "Resource '#3' (ICON, English (United States))"),
        ]
    );
}

#[test]
fn cursor_groups_and_empty_groups() {
    let s = symbols_of(&[
        res(rt::CURSOR, Key::Id(1), 0x400, vec![0; 12]),
        res(
            rt::GROUP_CURSOR,
            Key::Name("ARROW"),
            0x410,
            group(&[(12, 1)]),
        ),
        res(rt::GROUP_ICON, Key::Id(7), 0x430, group(&[])),
    ]);
    assert_eq!(
        find(&s, SymbolKind::RsrcGroupCursor),
        [(
            0x400,
            16 + 20,
            "Resource 'ARROW' (GROUP_CURSOR, English (United States))"
        )]
    );
    assert_eq!(
        find(&s, SymbolKind::RsrcGroupIcon),
        [(
            0x430,
            6,
            "Resource '#7' (GROUP_ICON, English (United States))"
        )]
    );
}

#[test]
fn string_tables_in_runs() {
    // 20 and 17 bytes, adjacent (the second at the next 8-byte boundary,
    // 0x418; then 0x430); a gap; two more; and one in another language.
    let s = symbols_of(&[
        res(rt::STRING, Key::Id(1), 0x400, vec![0; 20]),
        res(rt::STRING, Key::Id(2), 0x418, vec![0; 17]),
        res(rt::STRING, Key::Id(3), 0x430, vec![0; 8]),
        res(rt::STRING, Key::Id(4), 0x500, vec![0; 8]),
        res(rt::STRING, Key::Id(5), 0x508, vec![0; 8]),
        Res {
            kind: Key::Id(rt::STRING),
            name: Key::Id(6),
            lang: Key::Id(0x809),
            at: 0x510,
            data: vec![0; 8],
        },
    ]);
    let us = "Resource '<strings>' (STRINGTABLE, English (United States))";
    let uk = "Resource '<strings>' (STRINGTABLE, English (United Kingdom))";
    assert_eq!(
        find(&s, SymbolKind::RsrcStringTables),
        [(0x400, 45, us), (0x500, 16, us), (0x510, 8, uk)]
    );
}

#[test]
fn cycles_and_garbage_end() {
    // A root whose only entry points back at the root.
    let mut b = Buf::default();
    b.u16(14, 1).u32(16, 1).u32(20, 0x8000_0000);
    b.bytes(0x100, &[0]);
    let data = image(true, &b.0, &[(2, SECTION_RVA, 0x100)]);
    let s = symbols(&PeFile::parse(&data).unwrap());
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].kind, SymbolKind::RsrcDirectory);
    // A data entry whose data lies outside the image: shown by its
    // claimed place and size.
    let mut b = Buf::default();
    b.u16(14, 1).u32(16, 1).u32(20, 0x8000_0018);
    b.u16(0x18 + 14, 1)
        .u32(0x18 + 16, 1)
        .u32(0x18 + 20, 0x8000_0030);
    b.u16(0x30 + 14, 1)
        .u32(0x30 + 16, 0x409)
        .u32(0x30 + 20, 0x48);
    b.u32(0x48, 0xFFFF_0000).u32(0x4C, 0x10);
    let data = image(true, &b.0, &[(2, SECTION_RVA, 0x58)]);
    let s = symbols(&PeFile::parse(&data).unwrap());
    assert!(s.iter().any(|x| x.kind == SymbolKind::RsrcDataEntry));
    assert!(
        s.iter()
            .any(|x| x.kind == SymbolKind::RsrcData && x.size.file == 0x10)
    );
    // A tree deeper than three levels stops at the third.
    let mut b = Buf::default();
    for level in 0..5u32 {
        let at = (level * 0x18) as usize;
        b.u16(at + 14, 1)
            .u32(at + 16, 1)
            .u32(at + 20, 0x8000_0000 | ((level + 1) * 0x18));
    }
    let data = image(true, &b.0, &[(2, SECTION_RVA, 0x90)]);
    let s = symbols(&PeFile::parse(&data).unwrap());
    assert_eq!(s.len(), 3);
    // No resource directory.
    let data = image(true, &b.0, &[]);
    assert!(symbols(&PeFile::parse(&data).unwrap()).is_empty());
}

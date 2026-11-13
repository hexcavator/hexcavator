use std::collections::BTreeMap;

use super::*;
use crate::rollup::Rollup;
use crate::testimage::Buf;
use hexcavator_pe::consts::storage_class;

const AMD64: u16 = 0x8664;

/// A section header.
#[allow(clippy::too_many_arguments)]
fn section(b: &mut Buf, i: usize, name: &[u8], raw: u32, ptr: u32, relocs: (u32, u16), flags: u32) {
    let o = 20 + 40 * i;
    b.bytes(o, name)
        .u32(o + 16, raw)
        .u32(o + 20, ptr)
        .u32(o + 24, relocs.0)
        .u16(o + 32, relocs.1)
        .u32(o + 36, flags);
}

/// A symbol record (18 bytes) at index `i` of the table at `table`.
#[allow(clippy::too_many_arguments)]
fn symbol(
    b: &mut Buf,
    table: usize,
    i: usize,
    name: &[u8],
    value: u32,
    section: i16,
    class: u8,
    aux: u8,
) {
    let o = table + 18 * i;
    b.bytes(o, name)
        .u32(o + 8, value)
        .u16(o + 12, section as u16)
        .bytes(o + 16, &[class, aux]);
}

/// A section definition aux record.
fn definition(
    b: &mut Buf,
    table: usize,
    i: usize,
    length: u32,
    relocs: u16,
    number: u16,
    selection: u8,
) {
    let o = table + 18 * i;
    b.u32(o, length)
        .u16(o + 4, relocs)
        .u16(o + 12, number)
        .bytes(o + 14, &[selection]);
}

const TEXT: u32 = scn::CNT_CODE | scn::MEM_EXECUTE | scn::MEM_READ | 0x0050_0000 | scn::LNK_COMDAT;
const PDATA: u32 = scn::CNT_INITIALIZED_DATA | scn::MEM_READ | 0x0030_0000 | scn::LNK_COMDAT;
const DATA: u32 = scn::CNT_INITIALIZED_DATA | scn::MEM_READ | scn::MEM_WRITE | 0x0040_0000;
const BSS: u32 = scn::CNT_UNINITIALIZED_DATA | scn::MEM_READ | scn::MEM_WRITE | 0x0050_0000;
const DEBUG: u32 = scn::CNT_INITIALIZED_DATA | scn::MEM_DISCARDABLE | scn::MEM_READ | 0x0010_0000;

/// An object: a COMDAT function `f` with two relocations and an
/// associative `.pdata` with three; `.data` with `a` and `b`; `.bss`
/// with `big` at 0x10; and `.debug$S`.
fn object() -> Vec<u8> {
    let mut b = Buf::default();
    b.u16(0, AMD64).u16(2, 5).u32(8, 0x290).u32(12, 15);
    section(&mut b, 0, b".text$mn", 0x20, 0x200, (0x220, 2), TEXT);
    section(&mut b, 1, b".pdata", 12, 0x240, (0x24C, 3), PDATA);
    section(&mut b, 2, b".data", 0x10, 0x270, (0, 0), DATA);
    section(&mut b, 3, b".bss", 0x40, 0, (0, 0), BSS);
    section(&mut b, 4, b".debug$S", 0x10, 0x280, (0, 0), DEBUG);
    b.bytes(0x200, &[0xCC; 0x20]);
    // Relocations: at 4 and 0x10 in f; three in .pdata.
    for (k, va) in [4u32, 0x10].iter().enumerate() {
        b.u32(0x220 + 10 * k, *va)
            .u32(0x220 + 10 * k + 4, 2)
            .u16(0x220 + 10 * k + 8, 3);
    }
    for k in 0..3 {
        b.u32(0x24C + 10 * k, 4 * k as u32)
            .u32(0x24C + 10 * k + 4, 2)
            .u16(0x24C + 10 * k + 8, 3);
    }
    let t = 0x290;
    symbol(&mut b, t, 0, b".text$mn", 0, 1, storage_class::STATIC, 1);
    definition(&mut b, t, 1, 0x20, 2, 0, comdat_select::ANY);
    symbol(
        &mut b,
        t,
        2,
        &[0, 0, 0, 0, 4, 0, 0, 0],
        0,
        1,
        storage_class::EXTERNAL,
        0,
    );
    symbol(&mut b, t, 3, b".pdata", 0, 2, storage_class::STATIC, 1);
    definition(&mut b, t, 4, 12, 3, 1, comdat_select::ASSOCIATIVE);
    symbol(&mut b, t, 5, b"$pdata$f", 0, 2, storage_class::STATIC, 0);
    symbol(&mut b, t, 6, b".data", 0, 3, storage_class::STATIC, 1);
    definition(&mut b, t, 7, 0x10, 0, 0, 0);
    symbol(&mut b, t, 8, b"a", 0, 3, storage_class::EXTERNAL, 0);
    symbol(&mut b, t, 9, b"b", 8, 3, storage_class::STATIC, 0);
    symbol(&mut b, t, 10, b"$LN3", 4, 1, storage_class::STATIC, 0);
    symbol(&mut b, t, 11, b".bss", 0, 4, storage_class::STATIC, 1);
    definition(&mut b, t, 12, 0x40, 0, 0, 0);
    symbol(&mut b, t, 13, b"big", 0x10, 4, storage_class::EXTERNAL, 0);
    symbol(
        &mut b,
        t,
        14,
        b"undefined",
        0,
        0,
        storage_class::EXTERNAL,
        0,
    );
    let strings = t + 18 * 15;
    let names = b"\0\0\0\0?f@@YAXXZ\0";
    b.bytes(strings, names).u32(strings, names.len() as u32);
    b.0
}

/// File and memory bytes by label, for one source.
fn totals(maps: &Maps, source: usize) -> BTreeMap<String, (u64, u64)> {
    let (_, m) = &maps.sources[source];
    let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for e in m.file.iter() {
        out.entry(maps.labels.name(e.label).to_string())
            .or_default()
            .0 += e.end - e.start;
    }
    for e in m.vm.iter() {
        out.entry(maps.labels.name(e.label).to_string())
            .or_default()
            .1 += e.end - e.start;
    }
    out
}

fn get(t: &BTreeMap<String, (u64, u64)>, k: &str) -> (u64, u64) {
    t.get(k)
        .copied()
        .unwrap_or_else(|| panic!("{k} not in {t:?}"))
}

#[test]
fn object_sources() {
    let data = object();
    let maps = maps(
        &data,
        "x.obj",
        &[
            Source::Sections,
            Source::Groups,
            Source::Symbols,
            Source::ArMembers,
            Source::Libraries,
        ],
    )
    .unwrap();
    let len = data.len() as u64;
    assert_eq!(maps.base.file.total(), len);
    // Memory: .text$mn (0x20) at 0x1000, .pdata (12) at 0x1020, .data
    // (0x10) at 0x1030, .bss (0x40) at 0x1040; not .debug$S.
    assert_eq!(maps.base.vm.total(), 0x20 + 12 + 0x10 + 0x40);
    assert_eq!(
        maps.base.vm.get(0x1000).map(|e| maps.labels.name(e.label)),
        Some(".text$mn")
    );
    assert_eq!(
        maps.base.vm.get(0x1040).map(|e| maps.labels.name(e.label)),
        Some(".bss")
    );

    let sections = totals(&maps, 0);
    assert_eq!(get(&sections, ".text"), (0x20, 0x20));
    assert_eq!(get(&sections, ".pdata"), (12, 12));
    assert_eq!(get(&sections, ".bss"), (0, 0x40));
    assert_eq!(get(&sections, ".debug$S"), (0x10, 0));
    assert_eq!(get(&sections, COFF_RELOCATIONS), (50, 0));
    assert_eq!(get(&sections, COFF_HEADER), (20, 0));
    assert_eq!(get(&sections, COFF_SECTION_HEADERS), (200, 0));
    assert_eq!(get(&sections, COFF_SYMBOLS), (18 * 15, 0));
    assert_eq!(get(&sections, COFF_STRINGS), (14, 0));

    let groups = totals(&maps, 1);
    assert_eq!(get(&groups, ".text$mn"), (0x20, 0x20));

    let symbols = totals(&maps, 2);
    // f: its code, its pdata, and both sections' relocations.
    assert_eq!(
        get(&symbols, "void __cdecl f(void)"),
        (0x20 + 12 + 50, 0x20 + 12)
    );
    assert_eq!(get(&symbols, "a"), (8, 8));
    assert_eq!(get(&symbols, "b"), (8, 8));
    assert_eq!(get(&symbols, "big"), (0, 0x30));
    assert_eq!(get(&symbols, "[section .bss]"), (0, 0x10));
    assert_eq!(get(&symbols, "[section .debug$S]"), (0x10, 0));
    assert!(!symbols.contains_key("$LN3") && !symbols.contains_key("undefined"));

    let members = totals(&maps, 3);
    assert_eq!(get(&members, "x.obj"), (len, maps.base.vm.total()));
    let libraries = totals(&maps, 4);
    assert_eq!(get(&libraries, "[no library]").0, len);

    let rollup = Rollup::new(&maps);
    assert_eq!(rollup.file, len as i64);
}

/// An archive of the object, an import object, and a member that is
/// neither.
fn library() -> Vec<u8> {
    let member = |name: &str, data: &[u8]| {
        let mut v = format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "0",
            "0",
            "0",
            "644",
            data.len()
        )
        .into_bytes();
        v.extend_from_slice(data);
        if v.len() % 2 == 1 {
            v.push(b'\n');
        }
        v
    };
    let mut import = vec![0, 0, 0xFF, 0xFF, 0, 0];
    import.extend_from_slice(&AMD64.to_le_bytes());
    import.extend_from_slice(&0u32.to_le_bytes());
    let names = b"Sleep\0KERNEL32.dll\0";
    import.extend_from_slice(&(names.len() as u32).to_le_bytes());
    import.extend_from_slice(&0u16.to_le_bytes());
    import.extend_from_slice(&(1u16 << 2).to_le_bytes());
    import.extend_from_slice(names);
    let mut out = hexcavator_archive::MAGIC.to_vec();
    out.extend(member("x.obj/", &object()));
    out.extend(member("k.dll/", &import));
    out.extend(member("junk/", b"not an object"));
    out
}

#[test]
fn archive_sources() {
    let data = library();
    let maps = maps(
        &data,
        "x.lib",
        &[
            Source::ArMembers,
            Source::Symbols,
            Source::Sections,
            Source::Libraries,
        ],
    )
    .unwrap();
    let len = data.len() as u64;
    assert_eq!(maps.base.file.total(), len);
    let members = totals(&maps, 0);
    let object_len = object().len() as u64;
    assert_eq!(get(&members, "x.obj").0, object_len);
    assert_eq!(get(&members, "k.dll").0, 39);
    assert_eq!(get(&members, "junk").0, 13);
    // The signature, three headers, and two padding bytes.
    assert_eq!(get(&members, AR_HEADERS).0, 8 + 3 * 60 + 2);
    let symbols = totals(&maps, 1);
    assert_eq!(get(&symbols, "[import] Sleep (KERNEL32.dll)").0, 39);
    assert_eq!(get(&symbols, UNPARSED_MEMBER).0, 13);
    assert_eq!(get(&symbols, "void __cdecl f(void)").0, 0x20 + 12 + 50);
    let sections = totals(&maps, 2);
    assert_eq!(get(&sections, IMPORT_OBJECT).0, 39);
    let libraries = totals(&maps, 3);
    assert_eq!(get(&libraries, "x.lib").0, len);
}

#[test]
fn damaged_objects_do_not_panic() {
    let data = library();
    for len in (0..data.len()).step_by(7) {
        let _ = maps(&data[..len], "x.lib", Source::ALL);
    }
    let obj = object();
    let mut seed = 0x1234_5678_9ABC_DEF1u64;
    for _ in 0..2000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut copy = obj.clone();
        for _ in 0..4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = (seed % copy.len() as u64) as usize;
            copy[at] = (seed >> 40) as u8;
        }
        if let Ok(m) = maps(&copy, "x.obj", Source::ALL) {
            assert_eq!(m.base.file.total(), copy.len() as u64);
        }
    }
    assert!(maps(b"", "empty", Source::ALL).is_ok());
}

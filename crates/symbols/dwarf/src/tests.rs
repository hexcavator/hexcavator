//! Hermetic tests: units built by hand, DWARF 4 and 5, 32- and 64-bit,
//! both byte orders, and damaged.
#![allow(clippy::cast_possible_truncation, reason = "small test data")]

use alloc::vec;
use alloc::vec::Vec;

use super::*;

struct W {
    out: Vec<u8>,
    endian: Endian,
}

impl W {
    fn new(endian: Endian) -> Self {
        Self {
            out: Vec::new(),
            endian,
        }
    }
    fn u(&mut self, v: u64, n: usize) -> &mut Self {
        let b = v.to_le_bytes();
        if self.endian == Endian::Little {
            self.out.extend_from_slice(&b[..n]);
        } else {
            self.out.extend(b[..n].iter().rev());
        }
        self
    }
    fn uleb(&mut self, mut v: u64) -> &mut Self {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.out.push(b);
                return self;
            }
            self.out.push(b | 0x80);
        }
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.out.extend_from_slice(b);
        self
    }
}

/// A unit: version, 64-bit, address size, and its DIE bytes.
fn unit(endian: Endian, version: u16, dwarf64: bool, dies: &[u8]) -> Vec<u8> {
    let mut h = W::new(endian);
    h.u(u64::from(version), 2);
    let w = if dwarf64 { 8 } else { 4 };
    if version >= 5 {
        h.u(u64::from(DW_UT_COMPILE), 1).u(8, 1).u(0, w);
    } else {
        h.u(0, w).u(8, 1);
    }
    h.bytes(dies);
    let mut u = W::new(endian);
    if dwarf64 {
        u.u(0xFFFF_FFFF, 4).u(h.out.len() as u64, 8);
    } else {
        u.u(h.out.len() as u64, 4);
    }
    u.bytes(&h.out);
    u.out
}

/// An abbreviation table: code 1 = a compile unit with children and the
/// given attribute specs; code 2 = a childless variable with a name
/// (`DW_FORM_string`) and a location (`DW_FORM_exprloc`).
fn abbrevs(cu: &[(u16, u16)]) -> Vec<u8> {
    let mut a = W::new(Endian::Little);
    a.uleb(1).uleb(u64::from(DW_TAG_COMPILE_UNIT)).u(1, 1);
    for &(n, f) in cu {
        a.uleb(u64::from(n)).uleb(u64::from(f));
    }
    a.uleb(0).uleb(0);
    a.uleb(2).uleb(u64::from(DW_TAG_VARIABLE)).u(0, 1);
    a.uleb(u64::from(DW_AT_NAME))
        .uleb(u64::from(DW_FORM_STRING));
    a.uleb(u64::from(DW_AT_LOCATION))
        .uleb(u64::from(DW_FORM_EXPRLOC));
    a.uleb(0).uleb(0);
    a.uleb(0);
    a.out
}

fn read_all<'d>(s: Sections<'d>) -> Vec<(u64, Vec<Attr<'d>>, Unit<'d>)> {
    let mut out = Vec::new();
    for mut u in Unit::iter(s, UnitSection::Info, 0) {
        let Some(ab) = Abbrevs::parse(s.abbrev, u.abbrev_offset, s.endian) else {
            continue;
        };
        let mut d = u.dies();
        let mut first = true;
        while let Some(a) = d.next(&ab) {
            let mut attrs = Vec::new();
            if d.attrs(&u, a, &mut attrs).is_none() {
                break;
            }
            if first {
                u.set_bases(&attrs);
                first = false;
            }
            out.push((d.offset, attrs, u));
        }
    }
    out
}

#[test]
fn dwarf4_strings_ranges_and_locations() {
    for endian in [Endian::Little, Endian::Big] {
        for dwarf64 in [false, true] {
            let w = if dwarf64 { 8 } else { 4 };
            let ab = abbrevs(&[
                (DW_AT_NAME, DW_FORM_STRP),
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_RANGES, DW_FORM_SEC_OFFSET),
            ]);
            let mut d = W::new(endian);
            d.uleb(1).u(3, w).u(0x1000, 8).u(0, w);
            d.uleb(2)
                .bytes(b"v\0")
                .uleb(9)
                .u(u64::from(DW_OP_ADDR), 1)
                .u(0x5000, 8);
            d.u(0, 1);
            let info = unit(endian, 4, dwarf64, &d.out);
            let mut ranges = W::new(endian);
            ranges
                .u(0x10, 8)
                .u(0x20, 8)
                .u(u64::MAX, 8)
                .u(0x9000, 8)
                .u(0, 8)
                .u(4, 8)
                .u(0, 8)
                .u(0, 8);
            let mut s = Sections::new(endian);
            s.info = &info;
            s.abbrev = &ab;
            s.str = b"xx\0a.c\0";
            s.ranges = &ranges.out;
            let dies = read_all(s);
            assert_eq!(dies.len(), 2);
            let (_, attrs, u) = &dies[0];
            assert_eq!(u.version, 4);
            assert_eq!(u.dwarf64, dwarf64);
            let name = u.string(&attrs[0].value).unwrap();
            assert_eq!(name.bytes, b"a.c");
            assert_eq!(name.at, Some((StrSection::Str, 3)));
            assert_eq!(u.low_pc, 0x1000);
            let (list, len) = u.range_list(0, u.low_pc).unwrap();
            assert_eq!(list, [(0x1010, 0x10), (0x9000, 4)]);
            assert_eq!(len, 64);
            let (_, attrs, u) = &dies[1];
            assert_eq!(u.string(&attrs[0].value).unwrap().bytes, b"v");
            assert_eq!(u.location_address(&attrs[1].value), Some(0x5000));
        }
    }
}

#[test]
fn dwarf5_indexed_strings_addresses_and_rnglists() {
    for endian in [Endian::Little, Endian::Big] {
        let ab = abbrevs(&[
            (DW_AT_STR_OFFSETS_BASE, DW_FORM_SEC_OFFSET),
            (DW_AT_ADDR_BASE, DW_FORM_SEC_OFFSET),
            (DW_AT_RNGLISTS_BASE, DW_FORM_SEC_OFFSET),
            (DW_AT_NAME, DW_FORM_STRX1),
            (DW_AT_LOW_PC, DW_FORM_ADDRX),
            (DW_AT_RANGES, DW_FORM_RNGLISTX),
        ]);
        let mut d = W::new(endian);
        d.uleb(1).u(8, 4).u(8, 4).u(12, 4).u(1, 1).uleb(0).uleb(0);
        d.uleb(2)
            .bytes(b"g\0")
            .uleb(2)
            .u(u64::from(DW_OP_ADDRX), 1)
            .uleb(1);
        d.u(0, 1);
        let info = unit(endian, 5, false, &d.out);
        // .debug_str_offsets: header (8 bytes), then offsets.
        let mut so = W::new(endian);
        so.u(12, 4).u(5, 2).u(0, 2).u(0, 4).u(3, 4);
        let mut addr = W::new(endian);
        addr.u(20, 4)
            .u(5, 2)
            .u(8, 1)
            .u(0, 1)
            .u(0x4000, 8)
            .u(0x7000, 8);
        // .debug_rnglists: header (12 bytes), one offset, then the list:
        // an offset pair from the base, a start-length, the end.
        let mut rl = W::new(endian);
        rl.u(0, 4).u(5, 2).u(8, 1).u(0, 1).u(1, 4).u(4, 4);
        rl.u(u64::from(DW_RLE_OFFSET_PAIR), 1).uleb(0x10).uleb(0x30);
        rl.u(u64::from(DW_RLE_START_LENGTH), 1)
            .u(0x8000, 8)
            .uleb(0x40);
        rl.u(u64::from(DW_RLE_STARTX_LENGTH), 1).uleb(1).uleb(8);
        rl.u(u64::from(DW_RLE_END_OF_LIST), 1);
        let mut s = Sections::new(endian);
        s.info = &info;
        s.abbrev = &ab;
        s.str = b"zz\0b.c\0";
        s.str_offsets = &so.out;
        s.addr = &addr.out;
        s.rnglists = &rl.out;
        let dies = read_all(s);
        let (_, attrs, u) = &dies[0];
        assert_eq!(u.version, 5);
        assert_eq!(u.string(&attrs[3].value).unwrap().bytes, b"b.c");
        assert_eq!(u.low_pc, 0x4000);
        let Value::ListIndex(i) = attrs[5].value else {
            panic!()
        };
        let off = u.rnglist_offset(i).unwrap();
        assert_eq!(off, 16);
        let (list, len) = u.rnglist(off).unwrap();
        assert_eq!(list, [(0x4010, 0x20), (0x8000, 0x40), (0x7000, 8)]);
        assert_eq!(len as usize, rl.out.len() - 16);
        let (_, attrs, u) = &dies[1];
        assert_eq!(u.location_address(&attrs[1].value), Some(0x7000));
    }
}

#[test]
fn skips_children_and_nulls() {
    let ab = abbrevs(&[]);
    // The compile unit, two variables as children, then a third after the
    // unit's null.
    let mut d = W::new(Endian::Little);
    d.uleb(1);
    d.uleb(2).bytes(b"a\0").uleb(0);
    d.uleb(2).bytes(b"b\0").uleb(0);
    d.u(0, 1);
    let info = unit(Endian::Little, 4, false, &d.out);
    let mut s = Sections::new(Endian::Little);
    s.info = &info;
    s.abbrev = &ab;
    let u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
    let t = Abbrevs::parse(&ab, 0, Endian::Little).unwrap();
    assert_eq!(t.len as usize, ab.len());
    let mut r = u.dies();
    let a = r.next(&t).unwrap();
    assert_eq!(r.depth, 1);
    let mut attrs = Vec::new();
    r.attrs(&u, a, &mut attrs).unwrap();
    r.skip_children(&u, &t, a).unwrap();
    assert!(r.next(&t).is_none());
    assert_eq!(r.depth, 0);
}

#[test]
fn aranges_name_sets_and_line_programs() {
    for endian in [Endian::Little, Endian::Big] {
        let mut a = W::new(endian);
        // 4 + 2 + 4 + 1 + 1 = 12 bytes of header, padded to 16.
        let body_len = 2 + 4 + 1 + 1 + 4 + 2 * 16 + 16;
        a.u(body_len, 4).u(2, 2).u(0x40, 4).u(8, 1).u(0, 1).u(0, 4);
        a.u(0x1000, 8)
            .u(0x10, 8)
            .u(0x2000, 8)
            .u(0x20, 8)
            .u(0, 8)
            .u(0, 8);
        let e = aranges(&a.out, endian);
        assert_eq!(e.len(), 2);
        assert_eq!(
            (
                e[0].info_offset,
                e[0].address,
                e[0].length,
                e[0].offset,
                e[0].size
            ),
            (0x40, 0x1000, 0x10, 16, 16)
        );
        assert_eq!(e[1].address, 0x2000);
        for n in 0..a.out.len() {
            assert!(aranges(&a.out[..n], endian).len() <= 2);
        }
        let mut p = W::new(endian);
        p.u(10, 4).u(2, 2).u(0x80, 4).u(0, 4);
        p.u(6, 4).u(2, 2).u(0x90, 4);
        let sets = name_sets(&p.out, endian);
        assert_eq!(sets.len(), 2);
        assert_eq!(
            (sets[1].info_offset, sets[1].offset, sets[1].size),
            (0x90, 14, 10)
        );
        assert_eq!(line_program_len(&p.out, 0, endian), Some(14));
        assert_eq!(line_program_len(&p.out, 100, endian), None);
    }
}

#[test]
fn rejects_malformed_data() {
    // Duplicate abbreviation codes.
    let dup = [1u8, 0x11, 0, 0, 0, 1, 0x11, 0, 0, 0, 0];
    assert!(Abbrevs::parse(&dup, 0, Endian::Little).is_none());
    // An unknown version, or address size.
    let mut s = Sections::new(Endian::Little);
    let v9 = unit(Endian::Little, 9, false, &[]);
    s.info = &v9;
    assert_eq!(Unit::iter(s, UnitSection::Info, 0).count(), 0);
    // A length past the end.
    let mut long = unit(Endian::Little, 4, false, &[]);
    long[0] = 0xF0;
    s.info = &long;
    assert_eq!(Unit::iter(s, UnitSection::Info, 0).count(), 0);
    // Overlong LEB128.
    let mut r = Reader::new(&[0xFF; 20], 0, Endian::Little);
    assert_eq!(r.uleb(), None);
    let mut r = Reader::new(&[0x80, 0x80, 0x01], 0, Endian::Little);
    assert_eq!(r.uleb(), Some(1 << 14));
    let mut r = Reader::new(&[0x7F], 0, Endian::Little);
    assert_eq!(r.sleb(), Some(-1));
    // DW_FORM_indirect to DW_FORM_indirect.
    let u = Unit::iter(
        {
            let mut s = Sections::new(Endian::Little);
            s.info = Box::leak(unit(Endian::Little, 4, false, &[0]).into_boxed_slice());
            s
        },
        UnitSection::Info,
        0,
    )
    .next()
    .unwrap();
    let mut r = Reader::new(&[0x16, 0x16], 0, Endian::Little);
    assert_eq!(u.read_value(&mut r, DW_FORM_INDIRECT, 0), None);
    let mut r = Reader::new(&[0x0B, 7], 0, Endian::Little);
    assert_eq!(
        u.read_value(&mut r, DW_FORM_INDIRECT, 0),
        Some(Value::Data(&[7]))
    );
}

/// Every truncation and corruption of a real unit terminates cleanly.
#[test]
fn hostile_inputs() {
    let ab = abbrevs(&[
        (DW_AT_NAME, DW_FORM_STRP),
        (DW_AT_LOW_PC, DW_FORM_ADDR),
        (DW_AT_RANGES, DW_FORM_SEC_OFFSET),
    ]);
    let mut d = W::new(Endian::Little);
    d.uleb(1).u(0, 4).u(0x1000, 8).u(0, 4);
    d.uleb(2).bytes(b"v\0").uleb(9).u(3, 1).u(0x5000, 8);
    d.u(0, 1);
    let info = unit(Endian::Little, 4, false, &d.out);
    let ranges = vec![0xFFu8; 40];
    let walk = |info: &[u8], ab: &[u8]| {
        let mut s = Sections::new(Endian::Little);
        s.info = info;
        s.abbrev = ab;
        s.str = b"a\0";
        s.ranges = &ranges;
        for (_, attrs, u) in read_all(s) {
            for a in &attrs {
                let _ = u.string(&a.value);
                let _ = u.uint(&a.value);
                let _ = u.location_address(&a.value);
            }
            let _ = u.range_list(0, 0);
            let _ = u.rnglist(0);
            let _ = u.location_list_len(0);
        }
    };
    for n in 0..info.len() {
        walk(&info[..n], &ab);
    }
    for i in 0..info.len() {
        for v in [0u8, 0xFF, 0x80] {
            let mut c = info.clone();
            c[i] = v;
            walk(&c, &ab);
        }
    }
    for i in 0..ab.len() {
        for v in [0u8, 0xFF, 0x80, 0x16] {
            let mut c = ab.clone();
            c[i] = v;
            walk(&info, &c);
        }
    }
}

extern crate std;
use std::boxed::Box;

/// A DWARF 3 line program exercising the opcodes clang's don't: a
/// discarded (address 0) sequence, define_file, const_add_pc,
/// fixed_advance_pc, advance_line down, and an unknown extended opcode.
fn line_program_v3(endian: Endian) -> Vec<u8> {
    let mut hdr = W::new(endian);
    hdr.u(1, 1).u(1, 1).u(0xFB, 1).u(14, 1).u(13, 1); // min_inst 1, is_stmt, line_base -5, range 14, opcode_base 13
    hdr.bytes(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
    hdr.bytes(b"src\0\0");
    hdr.bytes(b"a.c\0").uleb(1).uleb(0).uleb(0).bytes(b"\0");
    let mut prog = W::new(endian);
    // Sequence 1, discarded: set_address 0, a row, end.
    prog.u(0, 1)
        .uleb(9)
        .u(2, 1)
        .u(0, 8)
        .u(1, 1)
        .u(0, 1)
        .uleb(1)
        .u(1, 1);
    // Sequence 2 at 0x1000: a special-opcode row (address +1, line +1).
    prog.u(0, 1).uleb(9).u(2, 1).u(0x1000, 8);
    prog.u(13 + 6 + 14, 1);
    // define_file b.c, set_file 2, const_add_pc (+17), copy.
    prog.u(0, 1)
        .uleb(8)
        .u(3, 1)
        .bytes(b"b.c\0")
        .uleb(0)
        .uleb(0)
        .uleb(0);
    prog.u(4, 1).uleb(2).u(8, 1).u(1, 1);
    // fixed_advance_pc 0x100, advance_line -1, copy.
    prog.u(9, 1).u(0x100, 2).u(3, 1).bytes(&[0x7F]).u(1, 1);
    // An unknown extended opcode (skipped), then end_sequence.
    prog.u(0, 1).uleb(3).u(0x80, 1).u(0xAA, 2);
    prog.u(0, 1).uleb(1).u(1, 1);
    let mut unit = W::new(endian);
    unit.u(3, 2)
        .u(hdr.out.len() as u64, 4)
        .bytes(&hdr.out)
        .bytes(&prog.out);
    let mut out = W::new(endian);
    out.u(unit.out.len() as u64, 4).bytes(&unit.out);
    out.out
}

#[test]
fn line_program_opcodes() {
    for endian in [Endian::Little, Endian::Big] {
        let data = line_program_v3(endian);
        let mut s = Sections::new(endian);
        s.line = &data;
        let p = line_program(&s, 0, 8).unwrap();
        assert_eq!(p.version, 3);
        assert_eq!(p.directories, [&b""[..], b"src"]);
        assert_eq!(p.files.len(), 3, "a.c and the defined b.c");
        assert_eq!(p.file_name(1).as_deref(), Some("src/a.c"));
        assert_eq!(p.file_name(2).as_deref(), Some("b.c"));
        let rows: Vec<_> = p
            .rows
            .iter()
            .map(|r| (r.address, r.line, r.file, r.end_sequence, r.discarded))
            .collect();
        assert_eq!(
            rows,
            [
                (0, 1, 1, false, true),
                (0, 1, 1, true, true),
                (0x1001, 2, 1, false, false),
                (0x1012, 2, 2, false, false),
                (0x1112, 1, 2, false, false),
                (0x1112, 1, 2, true, false),
            ]
        );
        for n in 0..data.len() {
            if let Some(p) = line_program(&s_with(&data[..n], endian), 0, 8) {
                assert!(p.rows.len() <= 6);
            }
        }
        for i in 0..data.len() {
            for v in [0u8, 0xFF, 0x80] {
                let mut d = data.clone();
                d[i] = v;
                let _ = line_program(&s_with(&d, endian), 0, 8);
            }
        }
    }
}

fn s_with(line: &[u8], endian: Endian) -> Sections<'_> {
    let mut s = Sections::new(endian);
    s.line = line;
    s
}

#[test]
fn entries_children_and_references() {
    // 1: a compile unit; 2: a variable (name, type); 3: a structure
    // (name, children); 4: a member (name).
    let mut a = W::new(Endian::Little);
    a.uleb(1)
        .uleb(u64::from(DW_TAG_COMPILE_UNIT))
        .u(1, 1)
        .uleb(0)
        .uleb(0);
    a.uleb(2).uleb(u64::from(DW_TAG_VARIABLE)).u(0, 1);
    a.uleb(u64::from(DW_AT_NAME))
        .uleb(u64::from(DW_FORM_STRING));
    a.uleb(u64::from(DW_AT_TYPE)).uleb(u64::from(DW_FORM_REF4));
    a.uleb(0).uleb(0);
    a.uleb(3).uleb(u64::from(DW_TAG_STRUCTURE_TYPE)).u(1, 1);
    a.uleb(u64::from(DW_AT_NAME))
        .uleb(u64::from(DW_FORM_STRING));
    a.uleb(0).uleb(0);
    a.uleb(4).uleb(u64::from(DW_TAG_MEMBER)).u(0, 1);
    a.uleb(u64::from(DW_AT_NAME))
        .uleb(u64::from(DW_FORM_STRING));
    a.uleb(0).uleb(0);
    a.uleb(0);
    let ab = a.out;
    for endian in [Endian::Little, Endian::Big] {
        for (version, dwarf64) in [(4, false), (4, true), (5, false), (5, true)] {
            let header = |v: u16, d64: bool| {
                let w = if d64 { 12 + 8 } else { 4 + 4 };
                2 + w + 2 - usize::from(v < 5)
            };
            let first = header(version, dwarf64) as u64;
            // CU { struct S { x; y; }; v: S }, the struct at first + 1.
            let s_at = first + 1;
            let mut d = W::new(endian);
            d.uleb(1);
            d.uleb(3).bytes(b"S\0");
            d.uleb(4).bytes(b"x\0");
            d.uleb(4).bytes(b"y\0");
            d.u(0, 1);
            d.uleb(2).bytes(b"v\0").u(s_at, 4);
            d.u(0, 1);
            let info = unit(endian, version, dwarf64, &d.out);
            let mut s = Sections::new(endian);
            s.info = &info;
            s.abbrev = &ab;
            let u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
            assert_eq!(u.dies, first, "{version} {dwarf64}");
            let t = Abbrevs::parse(&ab, 0, Endian::Little).unwrap();
            let cu = u.entry(&t, u.dies).unwrap();
            assert_eq!(cu.tag, DW_TAG_COMPILE_UNIT);
            let top = u.children(&t, &cu);
            let tags: Vec<u16> = top.iter().map(|d| d.tag).collect();
            assert_eq!(tags, [DW_TAG_STRUCTURE_TYPE, DW_TAG_VARIABLE]);
            let st = &top[0];
            assert_eq!(st.offset, s_at);
            let names: Vec<_> = u
                .children(&t, st)
                .iter()
                .map(|m| m.attr(DW_AT_NAME).unwrap().value)
                .collect();
            assert_eq!(names, [Value::Str(b"x"), Value::Str(b"y")]);
            // The variable's type is the structure.
            let v = &top[1];
            assert_eq!(u.reference(v.attr(DW_AT_TYPE).unwrap()), Some(s_at));
            assert_eq!(u.entry(&t, s_at).unwrap(), *st);
            assert!(u.children(&t, v).is_empty());
            // Not DIEs: a null entry, the header, past the unit.
            assert_eq!(u.entry(&t, v.next), None);
            assert_eq!(u.entry(&t, 0), None);
            assert_eq!(u.entry(&t, u.end), None);
            assert!(!u.contains(u.end) && u.contains(u.dies));
            assert_eq!(u.type_signature(), None);
        }
    }
}

#[test]
fn damaged_children_end_cleanly() {
    let ab = abbrevs(&[]);
    // A compile unit whose children run off the unit's end (no nulls),
    // then one with an unknown abbreviation among them.
    for tail in [&[][..], &[9][..]] {
        let mut d = W::new(Endian::Little);
        d.uleb(1);
        d.uleb(2).bytes(b"a\0").uleb(0);
        d.bytes(tail);
        let info = unit(Endian::Little, 4, false, &d.out);
        let mut s = Sections::new(Endian::Little);
        s.info = &info;
        s.abbrev = &ab;
        let u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
        let t = Abbrevs::parse(&ab, 0, Endian::Little).unwrap();
        let cu = u.entry(&t, u.dies).unwrap();
        assert_eq!(u.children(&t, &cu).len(), 1);
    }
}

#[test]
fn location_lists_dwarf4_and_5() {
    let ab = abbrevs(&[]);
    let mut d = W::new(Endian::Little);
    d.uleb(1).u(0, 1);
    for endian in [Endian::Little, Endian::Big] {
        // DWARF 4: a pair (relative to the unit's base), a base address
        // entry, a pair after it, the end.
        let info4 = unit(endian, 4, false, &d.out);
        let mut loc = W::new(endian);
        loc.u(0x10, 8).u(0x20, 8).u(1, 2).u(0x50, 1);
        loc.u(u64::MAX, 8).u(0x9000, 8);
        loc.u(0, 8).u(4, 8).u(2, 2).u(0x91, 1).u(0x7C, 1);
        loc.u(0, 8).u(0, 8);
        let mut s = Sections::new(endian);
        s.info = &info4;
        s.abbrev = &ab;
        s.loc = &loc.out;
        let mut u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
        u.low_pc = 0x1000;
        let list = u.location_list(0).unwrap();
        assert_eq!(
            list,
            [
                (0x1010, 0x1020, &[0x50][..]),
                (0x9000, 0x9004, &[0x91, 0x7C][..])
            ]
        );
        assert_eq!(u.location_list_len(0), Some(loc.out.len() as u64));

        // DWARF 5: an offset table (one list), then an offset pair, a base
        // address, a start and length, a default location, the end.
        let info5 = unit(endian, 5, false, &d.out);
        let mut ll = W::new(endian);
        ll.u(4, 4);
        ll.u(u64::from(DW_LLE_OFFSET_PAIR), 1)
            .uleb(0x10)
            .uleb(0x18)
            .uleb(1)
            .u(0x51, 1);
        ll.u(u64::from(DW_LLE_BASE_ADDRESS), 1).u(0x7000, 8);
        ll.u(u64::from(DW_LLE_OFFSET_PAIR), 1)
            .uleb(0)
            .uleb(2)
            .uleb(1)
            .u(0x52, 1);
        ll.u(u64::from(DW_LLE_START_LENGTH), 1)
            .u(0x8000, 8)
            .uleb(8)
            .uleb(1)
            .u(0x53, 1);
        ll.u(u64::from(DW_LLE_DEFAULT_LOCATION), 1)
            .uleb(1)
            .u(0x54, 1);
        ll.u(u64::from(DW_LLE_END_OF_LIST), 1);
        let mut s = Sections::new(endian);
        s.info = &info5;
        s.abbrev = &ab;
        s.loclists = &ll.out;
        let mut u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
        u.low_pc = 0x1000;
        u.loclists_base = 0;
        let at = u.loclist_offset(0).unwrap();
        assert_eq!(at, 4);
        let list = u.location_list(at).unwrap();
        assert_eq!(
            list,
            [
                (0x1010, 0x1018, &[0x51][..]),
                (0x7000, 0x7002, &[0x52][..]),
                (0x8000, 0x8008, &[0x53][..]),
                (0, u64::MAX, &[0x54][..]),
            ]
        );
        // Damaged: cut anywhere, an unknown entry kind.
        for len in 0..ll.out.len() {
            s.loclists = &ll.out[..len];
            let mut u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
            u.loclists_base = 0;
            assert!(u.location_list(4).is_none(), "{len}");
        }
        let bad = [0x63u8];
        s.loclists = &bad;
        let u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
        assert!(u.location_list(0).is_none());
    }
}

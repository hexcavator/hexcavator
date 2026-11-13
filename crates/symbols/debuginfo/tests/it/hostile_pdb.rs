//! Hostile type records in a PDB, read through the format-independent
//! layer: every type query, layouts, and values must give an answer (or
//! none), never hang or overflow the stack. (A PDB is read as found beside
//! an image: anyone who can put a file there can write these.)

use std::time::{Duration, Instant};

use hexcavator_debuginfo::value::{self, Limits};
use hexcavator_debuginfo::{DebugInfo, TypeRef};

const LF_MODIFIER: u16 = 0x1001;
const LF_POINTER: u16 = 0x1002;
const LF_PROCEDURE: u16 = 0x1008;
const LF_ARGLIST: u16 = 0x1201;
const LF_FIELDLIST: u16 = 0x1203;
const LF_ARRAY: u16 = 0x1503;
const LF_STRUCTURE: u16 = 0x1505;
const LF_ENUM: u16 = 0x1507;
const LF_MEMBER: u16 = 0x150D;

fn u32s(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A type stream (TPI) of `records` (kind, body), the first at 0x1000.
fn tpi(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (kind, body) in records {
        let mut rec = kind.to_le_bytes().to_vec();
        rec.extend_from_slice(body);
        while (rec.len() + 2) % 4 != 0 {
            rec.push(0xF0 | u8::try_from(3 - ((rec.len() + 2) % 4)).unwrap());
        }
        bytes.extend_from_slice(&u16::try_from(rec.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&rec);
    }
    let end = 0x1000 + u32::try_from(records.len()).unwrap();
    let mut s = u32s(&[
        20_040_203,
        56,
        0x1000,
        end,
        u32::try_from(bytes.len()).unwrap(),
    ]);
    s.resize(56, 0);
    s.extend_from_slice(&bytes);
    s
}

/// An MSF 7.0 file of `streams`, each in blocks of its own.
fn msf(streams: &[Vec<u8>]) -> Vec<u8> {
    const BS: usize = 4096;
    // Block 0: the superblock; 1: the free block map; then the streams'
    // blocks, the directory's, and the block map's.
    let mut blocks: Vec<Vec<u8>> = vec![vec![0; BS], vec![0xFF; BS]];
    let mut lists = Vec::new();
    for s in streams {
        let mut list = Vec::new();
        for chunk in s.chunks(BS) {
            let mut b = chunk.to_vec();
            b.resize(BS, 0);
            list.push(u32::try_from(blocks.len()).unwrap());
            blocks.push(b);
        }
        lists.push(list);
    }
    let mut dir = u32s(&[u32::try_from(streams.len()).unwrap()]);
    for s in streams {
        dir.extend_from_slice(&u32s(&[u32::try_from(s.len()).unwrap()]));
    }
    for l in &lists {
        dir.extend_from_slice(&u32s(l));
    }
    assert!(dir.len() <= BS);
    let dir_block = u32::try_from(blocks.len()).unwrap();
    let mut d = dir.clone();
    d.resize(BS, 0);
    blocks.push(d);
    let map_block = u32::try_from(blocks.len()).unwrap();
    let mut m = u32s(&[dir_block]);
    m.resize(BS, 0);
    blocks.push(m);
    let mut sb = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0".to_vec();
    sb.extend_from_slice(&u32s(&[
        u32::try_from(BS).unwrap(),
        1,
        u32::try_from(blocks.len()).unwrap(),
        u32::try_from(dir.len()).unwrap(),
        0,
        map_block,
    ]));
    sb.resize(BS, 0);
    blocks[0] = sb;
    blocks.concat()
}

/// A PDB whose types are `records`: an info stream, the type stream, and
/// an empty DBI stream.
fn pdb(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    // Version 20000404, signature, age, GUID; then no named streams.
    let mut info = u32s(&[20_000_404, 0, 1]);
    info.extend_from_slice(&[0; 16]);
    info.extend_from_slice(&u32s(&[0, 0, 0, 0, 0]));
    let mut dbi = vec![0u8; 64];
    dbi[..4].copy_from_slice(&(-1i32).to_le_bytes());
    msf(&[Vec::new(), info, tpi(records), dbi])
}

/// Everything that reads a type, on each of the PDB's types, in time.
fn read_all(records: &[(u16, Vec<u8>)]) {
    let data = pdb(records);
    let d = DebugInfo::parse(&data).expect("a PDB");
    let started = Instant::now();
    for i in 0..records.len() {
        let ty = TypeRef(0x1000 + i as u64);
        let _ = (d.type_name(ty), d.type_size(ty), d.type_shape(ty));
        let _ = (d.layout(ty), d.enumerators(ty));
        let _ = hexcavator_debuginfo::layout::flat_fields(&d, ty);
        let _ = hexcavator_debuginfo::layout::pointer_target(&d, ty);
        for bytes in [&[0x5A; 64][..], &[]] {
            let _ = value::read(&d, ty, bytes, Limits::default());
        }
    }
    let _ = d.layouts();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_modifier_of_itself() {
    let mut body = u32s(&[0x1000]);
    body.extend_from_slice(&1u16.to_le_bytes());
    let records = [(LF_MODIFIER, body)];
    let data = pdb(&records);
    let d = DebugInfo::parse(&data).unwrap();
    assert_eq!(d.type_size(TypeRef(0x1000)), None);
    assert!(d.type_name(TypeRef(0x1000)).ends_with("..."));
    read_all(&records);
}

#[test]
fn modifiers_in_a_cycle() {
    let mut a = u32s(&[0x1001]);
    a.extend_from_slice(&1u16.to_le_bytes());
    let mut b = u32s(&[0x1000]);
    b.extend_from_slice(&2u16.to_le_bytes());
    read_all(&[(LF_MODIFIER, a), (LF_MODIFIER, b)]);
}

#[test]
fn an_enum_of_itself_and_arrays_of_themselves() {
    let mut e = Vec::new();
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&u32s(&[0x1000, 0]));
    e.extend_from_slice(b"E\0");
    let mut arr = u32s(&[0x1001, 0x0074]);
    arr.extend_from_slice(&16u16.to_le_bytes());
    arr.extend_from_slice(b"\0");
    let p = u32s(&[0x1002, 0x0001_000C]);
    read_all(&[(LF_ENUM, e), (LF_ARRAY, arr), (LF_POINTER, p)]);
}

#[test]
fn a_structure_that_holds_itself() {
    let mut list = LF_MEMBER.to_le_bytes().to_vec();
    list.extend_from_slice(&3u16.to_le_bytes());
    list.extend_from_slice(&u32s(&[0x1001]));
    list.extend_from_slice(&0u16.to_le_bytes());
    list.extend_from_slice(b"s\0");
    let mut s = Vec::new();
    s.extend_from_slice(&1u16.to_le_bytes());
    s.extend_from_slice(&0u16.to_le_bytes());
    s.extend_from_slice(&u32s(&[0x1000, 0, 0]));
    s.extend_from_slice(&8u16.to_le_bytes());
    s.extend_from_slice(b"S\0");
    read_all(&[(LF_FIELDLIST, list), (LF_STRUCTURE, s)]);
}

#[test]
fn a_procedure_whose_arguments_are_itself() {
    let mut proc_ = u32s(&[0x0074]);
    proc_.extend_from_slice(&[0, 0]);
    proc_.extend_from_slice(&2u16.to_le_bytes());
    proc_.extend_from_slice(&u32s(&[0x1001]));
    let args = u32s(&[2, 0x1000, 0x1000]);
    read_all(&[(LF_PROCEDURE, proc_), (LF_ARGLIST, args)]);
}

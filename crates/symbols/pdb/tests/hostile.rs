//! Hostile type records: each must give an answer (or none), never hang or
//! overflow the stack. (Values and layouts' holes, which are read above
//! this crate, have the same tests in hexcavator-debuginfo's
//! tests/hostile_pdb.rs.) (A PDB is read as found beside an image: anyone who
//! can put a file there can write these.)

use hexcavator_codeview::layout;
use hexcavator_codeview::{TypeFormatter, TypeIndex};
use hexcavator_pdb::{StreamData, TypeStream};

const LF_MODIFIER: u16 = 0x1001;
const LF_POINTER: u16 = 0x1002;
const LF_FIELDLIST: u16 = 0x1203;
const LF_ARRAY: u16 = 0x1503;
const LF_STRUCTURE: u16 = 0x1505;
const LF_ENUM: u16 = 0x1507;
const LF_MEMBER: u16 = 0x150D;

/// A type stream of `records` (kind, body), the first at 0x1000.
fn stream(records: &[(u16, Vec<u8>)]) -> TypeStream<'static> {
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
    let mut s = Vec::new();
    let end = 0x1000 + u32::try_from(records.len()).unwrap();
    for v in [
        20_040_203u32,
        56,
        0x1000,
        end,
        u32::try_from(bytes.len()).unwrap(),
    ] {
        s.extend_from_slice(&v.to_le_bytes());
    }
    s.resize(56, 0);
    s.extend_from_slice(&bytes);
    TypeStream::parse(StreamData::Owned(s), StreamData::Borrowed(&[])).unwrap()
}

fn u32s(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Everything that reads a type, on each of the stream's types.
fn read_all(types: &TypeStream<'_>) {
    let f = TypeFormatter { types };
    for i in 0..types.len() {
        let ti = TypeIndex(0x1000 + u32::try_from(i).unwrap());
        let _ = f.name(ti);
        let _ = f.size_of(ti);
        let _ = layout::layout(types, ti);
    }
    let _ = layout::all(types);
}

#[test]
fn a_modifier_of_itself() {
    // const (itself)
    let mut body = u32s(&[0x1000]);
    body.extend_from_slice(&1u16.to_le_bytes());
    let types = stream(&[(LF_MODIFIER, body)]);
    let f = TypeFormatter { types: &types };
    assert_eq!(f.size_of(TypeIndex(0x1000)), None);
    assert!(f.name(TypeIndex(0x1000)).ends_with("..."));
    read_all(&types);
}

#[test]
fn modifiers_in_a_cycle() {
    // 0x1000: const 0x1001; 0x1001: volatile 0x1000.
    let mut a = u32s(&[0x1001]);
    a.extend_from_slice(&1u16.to_le_bytes());
    let mut b = u32s(&[0x1000]);
    b.extend_from_slice(&2u16.to_le_bytes());
    let types = stream(&[(LF_MODIFIER, a), (LF_MODIFIER, b)]);
    assert_eq!(
        TypeFormatter { types: &types }.size_of(TypeIndex(0x1000)),
        None
    );
    read_all(&types);
}

#[test]
fn an_enum_of_itself_and_arrays_of_themselves() {
    // An enum whose underlying type is itself: count, properties,
    // underlying, field list, name.
    let mut e = Vec::new();
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&u32s(&[0x1000, 0]));
    e.extend_from_slice(b"E\0");
    // An array of itself (element 0x1001), 16 bytes.
    let mut arr = u32s(&[0x1001, 0x0074]);
    arr.extend_from_slice(&16u16.to_le_bytes());
    arr.extend_from_slice(b"\0");
    // A pointer to itself.
    let p = u32s(&[0x1002, 0x0001_000C]);
    read_all(&stream(&[(LF_ENUM, e), (LF_ARRAY, arr), (LF_POINTER, p)]));
}

#[test]
fn a_structure_that_holds_itself() {
    // struct S { S s; } (8 bytes): its field list, then it.
    let mut list = LF_MEMBER.to_le_bytes().to_vec();
    list.extend_from_slice(&3u16.to_le_bytes()); // attributes
    list.extend_from_slice(&u32s(&[0x1001])); // type: S
    list.extend_from_slice(&0u16.to_le_bytes()); // offset 0
    list.extend_from_slice(b"s\0");
    let mut s = Vec::new();
    s.extend_from_slice(&1u16.to_le_bytes()); // count
    s.extend_from_slice(&0u16.to_le_bytes()); // properties
    s.extend_from_slice(&u32s(&[0x1000, 0, 0])); // fields, derived, vshape
    s.extend_from_slice(&8u16.to_le_bytes()); // size
    s.extend_from_slice(b"S\0");
    read_all(&stream(&[(LF_FIELDLIST, list), (LF_STRUCTURE, s)]));
}

#[test]
fn a_procedure_whose_arguments_are_itself() {
    // 0x1000: int (0x1001), a procedure whose argument list is 0x1001;
    // 0x1001: (0x1000, 0x1000). Named naively, each level doubles.
    const LF_PROCEDURE: u16 = 0x1008;
    const LF_ARGLIST: u16 = 0x1201;
    let mut proc_ = u32s(&[0x0074]); // returns int
    proc_.extend_from_slice(&[0, 0]); // call convention, attributes
    proc_.extend_from_slice(&2u16.to_le_bytes()); // parameter count
    proc_.extend_from_slice(&u32s(&[0x1001])); // argument list
    let args = u32s(&[2, 0x1000, 0x1000]);
    let types = stream(&[(LF_PROCEDURE, proc_), (LF_ARGLIST, args)]);
    let started = std::time::Instant::now();
    let name = TypeFormatter { types: &types }.name(TypeIndex(0x1000));
    assert!(
        name.len() <= hexcavator_codeview::types::MAX_NAME_LEN + 512,
        "{} bytes",
        name.len()
    );
    assert!(name.contains("..."), "{name}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    read_all(&types);
}

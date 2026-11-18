//! TraceLogging schemas: read from bytes laid out as
//! `TraceLoggingProvider.h` lays them out, and payloads decoded by them.

use hexcavator_etw::manifest::{Size, decode};
use hexcavator_etw::tracelogging::Schema;

/// A schema: its size, tags, name, then `fields` (already encoded).
fn schema(tags: &[u8], name: &str, fields: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend_from_slice(tags);
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    for f in fields {
        b.extend_from_slice(f);
    }
    let size = u16::try_from(b.len()).unwrap().to_le_bytes();
    b[..2].copy_from_slice(&size);
    b
}

/// A field: name, input type, then whatever follows it in the schema.
fn field(name: &str, in_type: u8, rest: &[u8]) -> Vec<u8> {
    let mut b = name.as_bytes().to_vec();
    b.push(0);
    b.push(in_type);
    b.extend_from_slice(rest);
    b
}

#[test]
fn reads_a_schema_and_decodes_by_it() {
    let s = schema(
        &[0x81, 0x02], // tags over two bytes
        "Widget.Made",
        &[
            field("Id", 7, &[]),                        // INT32
            field("Who", 2, &[]),                       // ANSISTRING (UTF-8)
            field("Sizes", 0x40 | 6, &[]),              // UINT16[], counted
            field("Blob", 14, &[]),                     // BINARY
            field("Three", 0x20 | 4, &[3, 0]),          // UINT8[3]
            field("Ok", 0x80 | 13, &[0x80 | 13, 0x05]), // BOOL32, out BOOLEAN, field tags
            field("Pair", 0x80 | 24, &[2]),             // a struct of two
            field("A", 8, &[]),                         //   UINT32
            field("Names", 0x40 | 1, &[]),              //   UNICODESTRING[]
            field("Pairs", 0x80 | 0x40 | 24, &[1]),     // an array of structs of one
            field("B", 6, &[]),                         //   UINT16
        ],
    );
    let sc = Schema::parse(&s).unwrap();
    assert_eq!(sc.name, "Widget.Made");
    assert_eq!(sc.tags, (1 << 21) | (2 << 14));
    let names: Vec<&str> = sc.template.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Id",
            "Who",
            "Sizes.Count",
            "Sizes",
            "Blob.Length",
            "Blob",
            "Three",
            "Ok",
            "Pair",
            "Pairs.Count",
            "Pairs"
        ]
    );
    let items = &sc.template.items;
    assert_eq!(items[3].count, Size::Property(2));
    assert_eq!(items[5].length, Size::Property(4));
    assert_eq!(items[6].count, Size::Fixed(3));
    assert_eq!(items[7].out_type, 13);
    assert_eq!(
        items[8]
            .members
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        ["A", "Names.Count", "Names"]
    );
    assert_eq!(
        items[8].members[2].count,
        Size::Property(1),
        "within the struct"
    );
    assert_eq!(items[10].count, Size::Property(9));
    assert_eq!(items[10].members[0].name, "B");

    // A payload by it.
    let mut p = Vec::new();
    p.extend_from_slice(&(-3i32).to_le_bytes());
    p.extend_from_slice(b"me\0");
    p.extend_from_slice(&2u16.to_le_bytes());
    p.extend_from_slice(&[10, 0, 20, 0]);
    p.extend_from_slice(&3u16.to_le_bytes());
    p.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    p.extend_from_slice(&[1, 2, 3]);
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(&7u32.to_le_bytes()); // Pair.A
    p.extend_from_slice(&1u16.to_le_bytes()); // Pair.Names: one
    for u in "x".encode_utf16().chain([0]) {
        p.extend_from_slice(&u.to_le_bytes());
    }
    p.extend_from_slice(&2u16.to_le_bytes()); // two Pairs
    p.extend_from_slice(&[5, 0, 6, 0]);
    let props = decode(&sc.template, &p, 8).unwrap();
    let sizes: Vec<usize> = props.iter().map(|x| x.data.len()).collect();
    assert_eq!(sizes, [4, 3, 2, 4, 2, 3, 3, 4, 4 + 2 + 4, 2, 4]);
    assert_eq!(
        sizes.iter().sum::<usize>(),
        p.len(),
        "every byte a property's"
    );
    assert_eq!(props[5].data, &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn custom_fields_and_damage_are_errors() {
    // A custom-serialized field: its protocol and schema, then nothing we
    // can decode.
    let custom = schema(&[0], "E", &[field("X", 0x60 | 14, &[1, 0, 2, 0, 9, 9])]);
    assert!(Schema::parse(&custom).is_err());
    // An event with no fields; one with too many tag bytes; a size past
    // the end; a name without its NUL; a constant count cut short.
    assert!(
        Schema::parse(&schema(&[0], "Empty", &[]))
            .unwrap()
            .template
            .items
            .is_empty()
    );
    assert!(Schema::parse(&schema(&[0x80, 0x80, 0x80, 0x80, 0], "E", &[])).is_err());
    let mut big = schema(&[0], "E", &[]);
    big[0] = 0xff;
    assert!(Schema::parse(&big).is_err());
    assert!(Schema::parse(&[5, 0, 0, b'E', b'x']).is_err());
    assert!(Schema::parse(&schema(&[0], "E", &[field("C", 0x20 | 4, &[3])])).is_err());
    // A struct that says it has more fields than follow.
    assert!(
        Schema::parse(&schema(
            &[0],
            "E",
            &[field("S", 0x80 | 24, &[3]), field("A", 7, &[])]
        ))
        .is_err()
    );
    // Every truncation and byte flip: an error or a schema, never a panic.
    let s = schema(
        &[0x81, 0x02],
        "W",
        &[
            field("Id", 7, &[]),
            field("Pair", 0x80 | 24, &[2]),
            field("A", 0x40 | 1, &[]),
            field("B", 14, &[]),
        ],
    );
    for len in 0..s.len() {
        let _ = Schema::parse(&s[..len]);
    }
    for i in 0..s.len() {
        for flip in [0x01, 0x20, 0x40, 0x80, 0xff] {
            let mut x = s.clone();
            x[i] ^= flip;
            if let Ok(sc) = Schema::parse(&x) {
                let _ = hexcavator_etw::manifest::decode_partial(
                    &sc.template,
                    &[1, 0, 2, 0, 3, 0, 4, 0],
                    8,
                );
            }
        }
    }
}

//! Event descriptions (`TRACE_EVENT_INFO`): read from bytes laid out as
//! TDH lays them out, and payloads decoded by them.

use hexcavator_etl::Guid;
use hexcavator_etw::event_info::{EventInfo, EventInfos};
use hexcavator_etw::manifest::{Size, decode, decode_partial};

/// One property to describe: name, flags, in and out types (or a struct's
/// first member and member count), count and length.
struct P {
    name: &'static str,
    flags: u32,
    a: u16,
    b: u16,
    count: u16,
    length: u16,
}

const fn p(name: &'static str, in_type: u16) -> P {
    P {
        name,
        flags: 0,
        a: in_type,
        b: 0,
        count: 1,
        length: 0,
    }
}

const PROVIDER: Guid = Guid::new(0x1234_5678, 0x9abc, 0xdef0, [1, 2, 3, 4, 5, 6, 7, 8]);

/// A `TRACE_EVENT_INFO`: the header (provider, event 7 version 2, opcode
/// 11, task 13, a manifest's), names, then `props` (the first `top` the
/// top level).
fn info(props: &[P], top: u32) -> Vec<u8> {
    let mut b = vec![0u8; 112 + 24 * props.len()];
    b[0..16].copy_from_slice(&PROVIDER.to_bytes());
    b[32..34].copy_from_slice(&7u16.to_le_bytes()); // ID
    b[34] = 2; // version
    b[35] = 16; // channel
    b[36] = 4; // level
    b[37] = 11; // opcode
    b[38..40].copy_from_slice(&13u16.to_le_bytes()); // task
    b[40..48].copy_from_slice(&0x8000_0000_0000_0010u64.to_le_bytes());
    let name = |b: &mut Vec<u8>, at: usize, s: &str| {
        let off = u32::try_from(b.len()).unwrap();
        b[at..at + 4].copy_from_slice(&off.to_le_bytes());
        for u in s.encode_utf16().chain([0]) {
            b.extend_from_slice(&u.to_le_bytes());
        }
    };
    name(&mut b, 52, "My-Provider");
    name(&mut b, 56, "Information");
    name(&mut b, 68, "Work");
    name(&mut b, 72, "Start");
    name(&mut b, 92, "WorkStarted");
    b[100..104].copy_from_slice(&u32::try_from(props.len()).unwrap().to_le_bytes());
    b[104..108].copy_from_slice(&top.to_le_bytes());
    for (i, q) in props.iter().enumerate() {
        let at = 112 + 24 * i;
        b[at..at + 4].copy_from_slice(&q.flags.to_le_bytes());
        name(&mut b, at + 4, q.name);
        b[at + 8..at + 10].copy_from_slice(&q.a.to_le_bytes());
        b[at + 10..at + 12].copy_from_slice(&q.b.to_le_bytes());
        b[at + 16..at + 18].copy_from_slice(&q.count.to_le_bytes());
        b[at + 18..at + 20].copy_from_slice(&q.length.to_le_bytes());
    }
    b
}

/// A rich event: an int32, a counted array of uint16s (its count the
/// int32), a struct of two members (a string and a fixed-length binary
/// whose length is a sibling), a fixed-count array of 3 bytes, and a
/// pointer.
fn rich() -> Vec<u8> {
    info(
        &[
            p("Count", 7),
            P {
                flags: 0x4,
                count: 0,
                ..p("Values", 6)
            }, // count: property 0
            P {
                name: "Pair",
                flags: 0x1,
                a: 5,
                b: 3,
                count: 1,
                length: 0,
            },
            P {
                flags: 0x20,
                count: 3,
                ..p("Three", 4)
            },
            p("Where", 16),
            // The struct's members (5, 6, 7): a length, a string, binary.
            p("Size", 5),
            p("Text", 1),
            P {
                flags: 0x2,
                length: 5,
                ..p("Blob", 14)
            }, // length: property 5
        ],
        5,
    )
}

#[test]
fn reads_names_and_the_descriptor() {
    let i = EventInfo::parse(&info(&[p("A", 7)], 1)).unwrap();
    assert_eq!(i.provider, PROVIDER);
    assert_eq!(
        (i.id, i.version, i.channel, i.level, i.opcode, i.task),
        (7, 2, 16, 4, 11, 13)
    );
    assert_eq!(i.keywords, 0x8000_0000_0000_0010);
    assert_eq!(i.decoding_source, 0);
    assert_eq!(i.provider_name.as_deref(), Some("My-Provider"));
    assert_eq!(i.level_name.as_deref(), Some("Information"));
    assert_eq!(i.task_name.as_deref(), Some("Work"));
    assert_eq!(i.opcode_name.as_deref(), Some("Start"));
    assert_eq!(i.event_name.as_deref(), Some("WorkStarted"));
    assert_eq!(i.channel_name, None, "offset 0: no name");
    assert_eq!(i.template.items.len(), 1);
    assert_eq!(i.template.items[0].name, "A");
    assert_eq!(i.template.items[0].in_type, 7);
}

#[test]
fn reads_structs_counts_and_lengths() {
    // (The blob's length names property 5, the struct's first member:
    // relative to the struct, member 0.)
    let i = EventInfo::parse(&rich()).unwrap();
    let items = &i.template.items;
    assert_eq!(
        items.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
        ["Count", "Values", "Pair", "Three", "Where"]
    );
    assert_eq!(items[0].count, Size::None, "a scalar");
    assert_eq!(items[1].count, Size::Property(0));
    assert_eq!(items[3].count, Size::Fixed(3));
    let pair = &items[2];
    assert_eq!(pair.in_type, 0);
    assert_eq!(
        pair.members
            .iter()
            .map(|x| x.name.as_str())
            .collect::<Vec<_>>(),
        ["Size", "Text", "Blob"]
    );
    assert_eq!(
        pair.members[2].length,
        Size::Property(0),
        "its sibling, by its place in the struct"
    );
    assert_eq!(pair.members[1].length, Size::None);

    // A payload by it: 2 values, the struct (a 3-byte blob), 3 bytes, a
    // 64-bit pointer.
    let mut payload = Vec::new();
    payload.extend_from_slice(&2i32.to_le_bytes());
    payload.extend_from_slice(&[1, 0, 2, 0]);
    payload.extend_from_slice(&3u16.to_le_bytes());
    for u in "hi".encode_utf16().chain([0]) {
        payload.extend_from_slice(&u.to_le_bytes());
    }
    payload.extend_from_slice(&[9, 9, 9]);
    payload.extend_from_slice(&[7, 7, 7]);
    payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let props = decode(&i.template, &payload, 8).unwrap();
    let sizes: Vec<usize> = props.iter().map(|x| x.data.len()).collect();
    assert_eq!(sizes, [4, 4, 2 + 6 + 3, 3, 8]);
    assert_eq!(
        sizes.iter().sum::<usize>(),
        payload.len(),
        "every byte a property's"
    );

    // As far as it goes: cut inside the struct, the struct and after
    // missing; with more, the rest left.
    let d = decode_partial(&i.template, &payload[..10], 8);
    assert_eq!((d.properties.len(), d.missing), (2, 3));
    assert_eq!(d.rest, &payload[8..10]);
    let mut more = payload.clone();
    more.extend_from_slice(&[0xaa, 0xbb]);
    let d = decode_partial(&i.template, &more, 8);
    assert_eq!((d.properties.len(), d.missing), (5, 0));
    assert_eq!(d.rest, &[0xaa, 0xbb]);
    assert!(decode(&i.template, &payload[..10], 8).is_err());
}

#[test]
fn a_fixed_length_string() {
    let i = EventInfo::parse(&info(
        &[
            P {
                flags: 0x10,
                length: 4,
                ..p("Tag", 2)
            },
            p("N", 7),
        ],
        2,
    ))
    .unwrap();
    assert_eq!(i.template.items[0].length, Size::Fixed(4));
    let props = decode(&i.template, b"ABCD\x05\0\0\0", 8).unwrap();
    assert_eq!(props[0].data, b"ABCD");
    assert_eq!(props[1].data, &[5, 0, 0, 0]);
}

#[test]
fn damage_is_an_error_never_a_panic() {
    let b = rich();
    assert!(EventInfo::parse(&[]).is_err());
    for len in 0..b.len() {
        let _ = EventInfo::parse(&b[..len]);
    }
    assert!(
        EventInfo::parse(&b[..111]).is_err(),
        "no room for the header"
    );
    // Too many properties for the bytes; more top-level than in all.
    let mut bad = b.clone();
    bad[100..104].copy_from_slice(&1000u32.to_le_bytes());
    assert!(EventInfo::parse(&bad).is_err());
    let mut bad = b.clone();
    bad[104..108].copy_from_slice(&9u32.to_le_bytes());
    assert!(EventInfo::parse(&bad).is_err());
    // A struct whose members aren't after it, or past the end; a name
    // offset past the end.
    let mut bad = b.clone();
    let pair = 112 + 24 * 2;
    bad[pair + 8..pair + 10].copy_from_slice(&1u16.to_le_bytes());
    assert!(EventInfo::parse(&bad).is_err());
    let mut bad = b.clone();
    bad[pair + 10..pair + 12].copy_from_slice(&50u16.to_le_bytes());
    assert!(EventInfo::parse(&bad).is_err());
    let mut bad = b;
    bad[52..56].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(EventInfo::parse(&bad).is_err());
    // Every byte flipped: an error or a description, and decoding by it
    // never panics.
    let b = rich();
    for i in 0..b.len() {
        let mut x = b.clone();
        x[i] ^= 0xff;
        if let Ok(info) = EventInfo::parse(&x) {
            let _ = decode_partial(&info.template, &[1, 2, 3, 4, 5, 6, 7, 8, 9], 8);
        }
    }
}

#[test]
fn descriptions_by_kind() {
    let mut infos = EventInfos::default();
    assert!(infos.is_empty());
    infos.add(EventInfo::parse(&info(&[p("A", 7)], 1)).unwrap());
    let mut other = info(&[p("B", 9)], 1);
    other[37] = 12; // another opcode: another kind
    infos.add(EventInfo::parse(&other).unwrap());
    infos.add(EventInfo::parse(&info(&[p("C", 7)], 1)).unwrap()); // the first again
    assert_eq!(infos.len(), 2);
    let names: std::collections::BTreeSet<String> = infos
        .iter()
        .map(|i| i.template.items[0].name.clone())
        .collect();
    assert_eq!(
        names,
        ["B".to_string(), "C".to_string()].into_iter().collect()
    );
}

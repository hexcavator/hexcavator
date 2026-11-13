//! Instrumentation manifests, on `WEVT_TEMPLATE` resources built here.

// Test inputs are small: their offsets fit any integer type.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_etl::Guid;
use hexcavator_etw::manifest::{Item, Manifest, Size, decode};

/// One template item: name, input type, output type, flags, the count
/// field and the length field (or a struct's first member and member
/// count, in `in_out`).
struct It {
    name: &'static str,
    in_out: [u8; 4],
    flags: u8,
    count: u16,
    length: u16,
}

fn it(name: &'static str, in_type: u8, flags: u8, count: u16, length: u16) -> It {
    It {
        name,
        in_out: [in_type, in_type, 0, 0],
        flags,
        count,
        length,
    }
}

fn structure(name: &'static str, first: u16, members: u16, flags: u8, count: u16) -> It {
    let f = first.to_le_bytes();
    let m = members.to_le_bytes();
    It {
        name,
        in_out: [f[0], f[1], m[0], m[1]],
        flags: flags | 0x01,
        count,
        length: 0,
    }
}

fn u32le(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

fn string(out: &mut Vec<u8>, s: &str) -> u32 {
    let at = out.len() as u32;
    let mut units: Vec<u8> = s
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    while !(4 + units.len()).is_multiple_of(8) {
        units.push(0);
    }
    out.extend_from_slice(&((4 + units.len()) as u32).to_le_bytes());
    out.extend_from_slice(&units);
    at
}

/// A manifest with one provider, events `(id, version, template)`, and
/// templates `(top-level count, items)`.
fn build(guid: Guid, events: &[(u16, u8, Option<usize>)], templates: &[(u32, Vec<It>)]) -> Vec<u8> {
    let mut v = vec![0u8; 36];
    v[..4].copy_from_slice(b"CRIM");
    v[8..10].copy_from_slice(&3u16.to_le_bytes());
    v[10..12].copy_from_slice(&1u16.to_le_bytes());
    u32le(&mut v, 12, 1);
    v[16..32].copy_from_slice(&guid.to_bytes());
    u32le(&mut v, 32, 36);
    // WEVT with two elements.
    let wevt = v.len();
    v.extend_from_slice(b"WEVT");
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    let descs = v.len();
    v.extend_from_slice(&[0; 16]);
    // TTBL first, so events can point at templates.
    let ttbl = v.len();
    u32le(&mut v, descs, ttbl as u32);
    v.extend_from_slice(b"TTBL");
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&(templates.len() as u32).to_le_bytes());
    let mut temp_at = Vec::new();
    for (top, items) in templates {
        let t = v.len();
        temp_at.push(t);
        v.extend_from_slice(b"TEMP");
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&top.to_le_bytes());
        v.extend_from_slice(&(items.len() as u32).to_le_bytes());
        v.extend_from_slice(&[0; 4]); // items offset, below
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&[0; 16]);
        let items_at = v.len();
        u32le(&mut v, t + 16, items_at as u32);
        v.resize(items_at + 20 * items.len(), 0);
        for (k, i) in items.iter().enumerate() {
            let name = string(&mut v, i.name);
            let d = items_at + 20 * k;
            v[d] = i.flags;
            v[d + 4..d + 8].copy_from_slice(&i.in_out);
            v[d + 12..d + 14].copy_from_slice(&i.count.to_le_bytes());
            v[d + 14..d + 16].copy_from_slice(&i.length.to_le_bytes());
            u32le(&mut v, d + 16, name);
        }
        let size = (v.len() - t) as u32;
        u32le(&mut v, t + 4, size);
    }
    let size = (v.len() - ttbl) as u32;
    u32le(&mut v, ttbl + 4, size);
    // EVNT.
    let evnt = v.len();
    u32le(&mut v, descs + 8, evnt as u32);
    v.extend_from_slice(b"EVNT");
    v.extend_from_slice(&((16 + 48 * events.len()) as u32).to_le_bytes());
    v.extend_from_slice(&(events.len() as u32).to_le_bytes());
    v.extend_from_slice(&[0; 4]);
    for &(id, version, template) in events {
        let mut d = [0u8; 48];
        d[..2].copy_from_slice(&id.to_le_bytes());
        d[2] = version;
        d[5] = 7; // opcode
        d[6..8].copy_from_slice(&9u16.to_le_bytes()); // task
        if let Some(t) = template {
            d[20..24].copy_from_slice(&(temp_at[t] as u32).to_le_bytes());
        }
        v.extend_from_slice(&d);
    }
    let size = (v.len() - wevt) as u32;
    u32le(&mut v, wevt + 4, size);
    let size = v.len() as u32;
    u32le(&mut v, 4, size);
    v
}

fn guid() -> Guid {
    Guid::parse("331c3b3a-2005-44c2-ac5e-77220c37d6b4").unwrap()
}

fn sample() -> Vec<u8> {
    build(
        guid(),
        &[(63, 2, Some(0)), (185, 0, Some(1)), (5, 0, None)],
        &[
            (
                5,
                vec![
                    it("Pid", 8, 0, 0, 0),
                    it("NameLength", 6, 0, 0, 0),
                    // Unicode string, length (characters) from property 1.
                    it("Name", 1, 0x04, 0, 1),
                    // Four UInt64s.
                    it("Fixed", 10, 0x08, 4, 0),
                    // Three bytes of binary.
                    it("Blob", 14, 0x02, 0, 3),
                ],
            ),
            (
                3,
                vec![
                    it("GroupCount", 6, 0, 0, 0),
                    // A struct of two members, counted by property 0.
                    structure("Group", 3, 2, 0x10, 0),
                    it("Tail", 1, 0, 0, 0),
                    it("Number", 6, 0, 0, 0),
                    it("Affinity", 10, 0, 0, 0),
                ],
            ),
        ],
    )
}

#[test]
fn parses_events_and_templates() {
    let m = Manifest::parse(&sample()).unwrap();
    let p = m.provider(&guid()).unwrap();
    assert_eq!(p.events.len(), 3);
    let e = p.event(63, 2).unwrap();
    assert_eq!((e.opcode, e.task), (7, 9));
    let t = p.template(e).unwrap();
    let names: Vec<&str> = t.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["Pid", "NameLength", "Name", "Fixed", "Blob"]);
    assert_eq!(t.items[2].length, Size::Property(1));
    assert_eq!(t.items[3].count, Size::Fixed(4));
    assert_eq!(t.items[4].length, Size::Fixed(3));
    let t = p.template(p.event(185, 0).unwrap()).unwrap();
    assert_eq!(t.items.len(), 3);
    let group: &Item = &t.items[1];
    assert_eq!(group.count, Size::Property(0));
    let members: Vec<&str> = group.members.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(members, ["Number", "Affinity"]);
    assert!(p.template(p.event(5, 0).unwrap()).is_none());
    assert!(p.event(63, 1).is_none());
}

#[test]
fn decodes_payloads() {
    let m = Manifest::parse(&sample()).unwrap();
    let p = m.provider(&guid()).unwrap();
    let t = p.template(p.event(63, 2).unwrap()).unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&42u32.to_le_bytes());
    payload.extend_from_slice(&3u16.to_le_bytes());
    payload.extend_from_slice(&[b'a', 0, b'b', 0, b'c', 0]);
    for v in 1u64..=4 {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    payload.extend_from_slice(&[7, 8, 9]);
    let props = decode(t, &payload, 8).unwrap();
    let sizes: Vec<(&str, usize)> = props
        .iter()
        .map(|p| (p.name.as_str(), p.data.len()))
        .collect();
    assert_eq!(
        sizes,
        [
            ("Pid", 4),
            ("NameLength", 2),
            ("Name", 6),
            ("Fixed", 32),
            ("Blob", 3)
        ]
    );
    assert_eq!(props[4].data, [7, 8, 9]);

    // Two groups of (u16, u64), then a NUL-terminated string.
    let t = p.template(p.event(185, 0).unwrap()).unwrap();
    let mut payload = 2u16.to_le_bytes().to_vec();
    for g in 0..2u16 {
        payload.extend_from_slice(&g.to_le_bytes());
        payload.extend_from_slice(&u64::from(g).to_le_bytes());
    }
    payload.extend_from_slice(&[b'x', 0, 0, 0]);
    let props = decode(t, &payload, 8).unwrap();
    let sizes: Vec<usize> = props.iter().map(|p| p.data.len()).collect();
    assert_eq!(sizes, [2, 20, 4]);

    // Too short: an error, not a panic.
    assert!(decode(t, &payload[..10], 8).is_err());
}

#[test]
fn hostile_manifests_never_panic() {
    let data = sample();
    for len in 0..data.len() {
        let _ = Manifest::parse(&data[..len]);
    }
    let mut copy = data.clone();
    for i in 0..data.len() {
        for v in [0x00, 0xff, 0x01, 0x10, data[i].wrapping_add(1)] {
            copy[i] = v;
            if let Ok(m) = Manifest::parse(&copy) {
                for p in &m.providers {
                    for e in &p.events {
                        if let Some(t) = p.template(e) {
                            let _ = decode(t, &[0xff; 64], 8);
                            let _ = decode(t, &[], 4);
                        }
                    }
                }
            }
        }
        copy[i] = data[i];
    }
}

//! The session protocol's framing, on good frames and hostile ones.

use std::io::{Cursor, ErrorKind};

use serde_json::json;
use stackrabbit::protocol::{Frame, MAX_HEADER, MAX_PAYLOAD, read_frame, write_frame};

fn bytes(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        write_frame(&mut out, f).unwrap();
    }
    out
}

fn prefix(header: u32, payload: u32) -> Vec<u8> {
    let mut p = header.to_le_bytes().to_vec();
    p.extend_from_slice(&payload.to_le_bytes());
    p
}

#[test]
fn frames_round_trip() {
    let frames = [
        Frame::new(json!({"id": 1, "method": "hello"})),
        Frame {
            header: json!({"id": 2, "result": {"rows": [1, 2, 3]}}),
            payload: (0..=255).collect(),
        },
        Frame::new(json!({"method": "progress", "params": {"done": 0.5, "text": "ü✓"}})),
    ];
    let data = bytes(&frames);
    let mut r = Cursor::new(data);
    for f in &frames {
        assert_eq!(read_frame(&mut r).unwrap().as_ref(), Some(f));
    }
    assert_eq!(read_frame(&mut r).unwrap(), None, "a clean end");
}

#[test]
fn the_prefix_is_two_little_endian_lengths() {
    let f = Frame {
        header: json!({"a": 1}),
        payload: vec![9, 8, 7],
    };
    let data = bytes(&[f]);
    assert_eq!(&data[..8], &prefix(7, 3)[..]);
    assert_eq!(&data[8..15], br#"{"a":1}"#);
    assert_eq!(&data[15..], &[9, 8, 7]);
}

#[test]
fn a_frame_cut_short_is_an_error() {
    let data = bytes(&[Frame {
        header: json!({"id": 1}),
        payload: vec![1, 2, 3, 4],
    }]);
    // Every cut but at the end, and before the start, is an error.
    for cut in 1..data.len() {
        let e = read_frame(&mut Cursor::new(&data[..cut])).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData, "cut at {cut}");
    }
    assert_eq!(read_frame(&mut Cursor::new(&data[..0])).unwrap(), None);
}

#[test]
fn huge_lengths_are_refused_without_allocating() {
    let e = read_frame(&mut Cursor::new(prefix(MAX_HEADER + 1, 0))).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
    let e = read_frame(&mut Cursor::new(prefix(2, MAX_PAYLOAD + 1))).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
    // A length in bounds whose bytes never come: an error, not a 1 GB
    // buffer.
    let mut data = prefix(2, MAX_PAYLOAD);
    data.extend_from_slice(b"{}");
    let e = read_frame(&mut Cursor::new(data)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
}

#[test]
fn headers_must_be_json_objects() {
    for header in [&b"not json"[..], b"[1,2]", b"42", b"\"text\"", b"\xff\xfe"] {
        let mut data = prefix(u32::try_from(header.len()).unwrap(), 0);
        data.extend_from_slice(header);
        let e = read_frame(&mut Cursor::new(data)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
    }
}

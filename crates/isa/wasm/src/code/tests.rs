use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn text(bytes: &[u8]) -> String {
    let i = decode(bytes).unwrap();
    assert_eq!(i.len, bytes.len(), "{bytes:02x?}: length");
    i.to_string()
}

fn error(bytes: &[u8]) -> ErrorKind {
    decode(bytes).unwrap_err().kind
}

#[test]
fn the_table_is_sorted_and_unique() {
    for w in ops::OPS.windows(2) {
        assert!(
            (w[0].prefix, w[0].code) < (w[1].prefix, w[1].code),
            "{} before {}",
            w[0].name,
            w[1].name
        );
    }
    assert!(ops::OPS.len() > 600);
    assert_eq!(
        ops::lookup(0xFD, 0x100).unwrap().name,
        "i8x16.relaxed_swizzle"
    );
    assert!(ops::lookup(0, 0xFF).is_none());
}

#[test]
fn control() {
    assert_eq!(text(&[0x00]), "unreachable");
    assert_eq!(text(&[0x02, 0x40]), "block");
    assert_eq!(text(&[0x03, 0x7F]), "loop (result i32)");
    assert_eq!(text(&[0x04, 0x63, 0x70]), "if (result funcref)");
    assert_eq!(text(&[0x04, 0x64, 0x05]), "if (result (ref 5))");
    assert_eq!(text(&[0x02, 0x05]), "block (type 5)");
    assert_eq!(text(&[0x02, 0x80, 0x01]), "block (type 128)");
    assert_eq!(text(&[0x0C, 0x02]), "br 2");
    assert_eq!(text(&[0x0E, 0x02, 0x00, 0x01, 0x02]), "br_table 0 1 2");
    assert_eq!(text(&[0x0E, 0x00, 0x07]), "br_table 7");
    assert_eq!(text(&[0x10, 0x81, 0x01]), "call 129");
    assert_eq!(text(&[0x11, 0x01, 0x00]), "call_indirect (type 1)");
    assert_eq!(text(&[0x11, 0x01, 0x02]), "call_indirect 2 (type 1)");
    assert_eq!(text(&[0x12, 0x03]), "return_call 3");
    assert_eq!(text(&[0x1B]), "select");
    assert_eq!(text(&[0x1C, 0x01, 0x7F]), "select (result i32)");
    assert_eq!(
        text(&[
            0x1F, 0x40, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x02, 0x04, 0x03, 0x05
        ]),
        "try_table (catch 1 0) (catch_ref 2 3) (catch_all 4) (catch_all_ref 5)"
    );
    assert_eq!(text(&[0x1F, 0x7E, 0x00]), "try_table (result i64)");
}

#[test]
fn variables_and_memory() {
    assert_eq!(text(&[0x20, 0x03]), "local.get 3");
    assert_eq!(text(&[0x23, 0x01]), "global.get 1");
    // Natural alignment isn't shown; an offset of 0 isn't either.
    assert_eq!(text(&[0x28, 0x02, 0x10]), "i32.load offset=16");
    assert_eq!(text(&[0x28, 0x02, 0x00]), "i32.load");
    assert_eq!(text(&[0x28, 0x00, 0x00]), "i32.load align=1");
    assert_eq!(text(&[0x29, 0x03, 0x08]), "i64.load offset=8");
    assert_eq!(text(&[0x31, 0x00, 0x00]), "i64.load8_u");
    assert_eq!(text(&[0x3B, 0x01, 0x02]), "i32.store16 offset=2");
    // Another memory: bit 6 of the alignment, then its index.
    assert_eq!(text(&[0x28, 0x42, 0x01, 0x04]), "i32.load 1 offset=4");
    assert_eq!(
        text(&[0x28, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
        "i32.load offset=4294967295"
    );
    assert_eq!(text(&[0x3F, 0x00]), "memory.size");
    assert_eq!(text(&[0x40, 0x01]), "memory.grow 1");
    assert_eq!(text(&[0xFC, 0x08, 0x03, 0x00]), "memory.init 3");
    assert_eq!(text(&[0xFC, 0x08, 0x03, 0x01]), "memory.init 1 3");
    assert_eq!(text(&[0xFC, 0x09, 0x03]), "data.drop 3");
    assert_eq!(text(&[0xFC, 0x0A, 0x00, 0x00]), "memory.copy");
    assert_eq!(text(&[0xFC, 0x0A, 0x01, 0x00]), "memory.copy 1 0");
    assert_eq!(text(&[0xFC, 0x0B, 0x00]), "memory.fill");
    assert_eq!(text(&[0xFC, 0x0C, 0x02, 0x00]), "table.init 2");
    assert_eq!(text(&[0xFC, 0x0E, 0x00, 0x00]), "table.copy");
    assert_eq!(text(&[0xFC, 0x10, 0x01]), "table.size 1");
}

#[test]
fn numbers() {
    assert_eq!(text(&[0x41, 0x7B]), "i32.const -5");
    assert_eq!(
        text(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x78]),
        "i32.const -2147483648"
    );
    assert_eq!(text(&[0x42, 0xAC, 0x02]), "i64.const 300");
    let f32c = |v: u32| {
        let mut b = vec![0x43];
        b.extend_from_slice(&v.to_le_bytes());
        text(&b)
    };
    assert_eq!(f32c(1.5f32.to_bits()), "f32.const 1.5");
    assert_eq!(f32c((-0.0f32).to_bits()), "f32.const -0");
    assert_eq!(f32c(1e30f32.to_bits()), "f32.const 1e30");
    assert_eq!(f32c(1e-7f32.to_bits()), "f32.const 1e-7");
    assert_eq!(f32c(f32::INFINITY.to_bits()), "f32.const inf");
    assert_eq!(f32c(f32::NEG_INFINITY.to_bits()), "f32.const -inf");
    assert_eq!(f32c(0x7FC0_0000), "f32.const nan");
    assert_eq!(f32c(0xFFC0_0000), "f32.const -nan");
    assert_eq!(f32c(0x7F80_0001), "f32.const nan:0x1");
    let f64c = |v: u64| {
        let mut b = vec![0x44];
        b.extend_from_slice(&v.to_le_bytes());
        text(&b)
    };
    assert_eq!(f64c((-2.25f64).to_bits()), "f64.const -2.25");
    assert_eq!(f64c(0.1f64.to_bits()), "f64.const 0.1");
    assert_eq!(f64c(0x7FF8_0000_0000_0000), "f64.const nan");
    assert_eq!(f64c(0x7FF0_0000_0000_0002), "f64.const nan:0x2");
}

#[test]
fn vectors() {
    let mut b = vec![0xFD, 0x0C];
    b.extend(0..16u8);
    assert_eq!(
        text(&b),
        "v128.const i32x4 0x03020100 0x07060504 0x0b0a0908 0x0f0e0d0c"
    );
    let mut b = vec![0xFD, 0x0D];
    b.extend([0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31]);
    assert_eq!(
        text(&b),
        "i8x16.shuffle 0 17 2 19 4 21 6 23 8 25 10 27 12 29 14 31"
    );
    assert_eq!(text(&[0xFD, 0x15, 0x03]), "i8x16.extract_lane_s 3");
    assert_eq!(text(&[0xFD, 0x00, 0x04, 0x00]), "v128.load");
    assert_eq!(text(&[0xFD, 0x01, 0x03, 0x00]), "v128.load8x8_s");
    assert_eq!(
        text(&[0xFD, 0x54, 0x00, 0x10, 0x03]),
        "v128.load8_lane offset=16 3"
    );
    assert_eq!(
        text(&[0xFD, 0x57, 0x02, 0x00, 0x01]),
        "v128.load64_lane align=4 1"
    );
    // Sub-opcodes past 127 take two bytes.
    assert_eq!(text(&[0xFD, 0x80, 0x02]), "i8x16.relaxed_swizzle");
    assert_eq!(text(&[0xFD, 0xA1, 0x02, 0x07]), "f16x8.extract_lane 7");
}

#[test]
fn references_gc_and_atomics() {
    assert_eq!(text(&[0xD0, 0x70]), "ref.null func");
    assert_eq!(text(&[0xD0, 0x69]), "ref.null exn");
    assert_eq!(text(&[0xD0, 0x05]), "ref.null 5");
    assert_eq!(text(&[0xD2, 0x02]), "ref.func 2");
    assert_eq!(text(&[0xD5, 0x01]), "br_on_null 1");
    assert_eq!(text(&[0xFB, 0x00, 0x03]), "struct.new 3");
    assert_eq!(text(&[0xFB, 0x02, 0x03, 0x01]), "struct.get 3 1");
    assert_eq!(text(&[0xFB, 0x08, 0x03, 0x04]), "array.new_fixed 3 4");
    assert_eq!(text(&[0xFB, 0x14, 0x6E]), "ref.test (ref any)");
    assert_eq!(text(&[0xFB, 0x15, 0x03]), "ref.test (ref null 3)");
    assert_eq!(text(&[0xFB, 0x17, 0x71]), "ref.cast nullref");
    assert_eq!(
        text(&[0xFB, 0x18, 0x01, 0x00, 0x6E, 0x6B]),
        "br_on_cast 0 anyref (ref struct)"
    );
    assert_eq!(text(&[0xFB, 0x1C]), "ref.i31");
    assert_eq!(text(&[0xFE, 0x03, 0x00]), "atomic.fence");
    assert_eq!(text(&[0xFE, 0x10, 0x02, 0x00]), "i32.atomic.load");
    assert_eq!(text(&[0xFE, 0x20, 0x00, 0x00]), "i32.atomic.rmw8.add_u");
    assert_eq!(
        text(&[0xFE, 0x00, 0x02, 0x08]),
        "memory.atomic.notify offset=8"
    );
    assert_eq!(text(&[0xFE, 0x02, 0x03, 0x00]), "memory.atomic.wait64");
}

#[test]
fn locals_and_listing() {
    let body = [0x02, 0x01, 0x7F, 0x02, 0x7E, 0x20, 0x00, 0x1A, 0x0B];
    let l = locals(&body).unwrap();
    assert_eq!(l.groups, vec![(1, ValType::I32), (2, ValType::I64)]);
    assert_eq!(l.code_start, 5);
    let listing: Vec<(usize, String)> = instructions(&body[l.code_start..])
        .map(|(at, i)| (at, i.unwrap().to_string()))
        .collect();
    assert_eq!(
        listing,
        vec![
            (0, "local.get 0".into()),
            (2, "drop".into()),
            (3, "end".into())
        ]
    );
    assert_eq!(locals(&[0x00]).unwrap().groups, vec![]);
    assert_eq!(
        locals(&[0x01, 0x05]).unwrap_err().kind,
        ErrorKind::Truncated
    );
    assert_eq!(
        locals(&[0x01, 0x01, 0x00]).unwrap_err().kind,
        ErrorKind::Malformed
    );
}

#[test]
fn nesting_for_indentation() {
    let op = |b: &[u8]| decode(b).unwrap().op;
    assert_eq!(nesting(op(&[0x02, 0x40])), 1);
    assert_eq!(nesting(op(&[0x0B])), -1);
    assert_eq!(nesting(op(&[0x01])), 0);
    assert!(is_continuation(op(&[0x05])));
    assert!(!is_continuation(op(&[0x0B])));
}

#[test]
fn natural_alignments() {
    for (name, align) in [
        ("i32.load", 2),
        ("i64.store", 3),
        ("i64.load32_u", 2),
        ("i32.store8", 0),
        ("f64.load", 3),
        ("f32.load_f16", 1),
        ("v128.load", 4),
        ("v128.load16x4_u", 3),
        ("v128.load32_splat", 2),
        ("v128.load64_zero", 3),
        ("v128.store16_lane", 1),
        ("i64.atomic.rmw16.cmpxchg_u", 1),
        ("i64.atomic.rmw.add", 3),
        ("i32.atomic.store", 2),
        ("memory.atomic.wait64", 3),
    ] {
        assert_eq!(natural_align(name), align, "{name}");
    }
}

#[test]
fn malformed_code_is_an_error() {
    assert_eq!(error(&[]), ErrorKind::Truncated);
    assert_eq!(error(&[0xFF]), ErrorKind::Malformed);
    assert_eq!(error(&[0xFC, 0x7F]), ErrorKind::Malformed);
    assert_eq!(error(&[0x41, 0x80]), ErrorKind::Truncated);
    // Too many bits for a u32, and an i32 out of range.
    assert_eq!(
        error(&[0x20, 0x80, 0x80, 0x80, 0x80, 0x10]),
        ErrorKind::Malformed
    );
    assert_eq!(
        error(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
        ErrorKind::Malformed
    );
    assert_eq!(error(&[0x43, 0x00, 0x00]), ErrorKind::Truncated);
    assert_eq!(error(&[0xFE, 0x03, 0x01]), ErrorKind::Malformed);
    assert_eq!(error(&[0x1C, 0x01, 0x00]), ErrorKind::Malformed);
    assert_eq!(error(&[0x1F, 0x40, 0x01, 0x09]), ErrorKind::Malformed);
    assert_eq!(error(&[0x28, 0x80, 0x01, 0x00]), ErrorKind::Malformed);
    // A huge count with nothing after it fails at once (nothing is
    // allocated for it).
    assert_eq!(
        error(&[0x0E, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
        ErrorKind::Truncated
    );
    // The listing stops at the error, which says where it is.
    let code = [0x01, 0x01, 0x41];
    let all: Vec<_> = instructions(&code).collect();
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].0, 2);
    let e = all[2].1.as_ref().unwrap_err();
    assert_eq!((e.kind, e.offset), (ErrorKind::Truncated, 3));
}

#[test]
fn random_bytes_never_panic() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut buf = [0u8; 24];
    let mut decoded = 0;
    for round in 0..200_000 {
        for b in &mut buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x.to_le_bytes()[0];
        }
        // Prefixed opcodes half the time, so their tables get exercised.
        if round % 2 == 0 {
            buf[0] = 0xFB + (buf[0] % 4);
        }
        let n = 1 + (round % buf.len());
        if let Ok(i) = decode(&buf[..n]) {
            assert!(i.len <= n);
            let _ = i.to_string();
            decoded += 1;
        }
        let _ = locals(&buf[..n]);
    }
    assert!(decoded > 10_000);
}

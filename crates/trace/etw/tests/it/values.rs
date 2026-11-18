//! Properties' values as text.

use hexcavator_etw::schema::{Field, Property};
use hexcavator_etw::values::format;

#[test]
fn values() {
    let t = |in_type, out_type, d: &[u8]| {
        format(
            &Property {
                name: String::new(),
                field: Field::Typed { in_type, out_type },
                data: d,
            },
            8,
        )
    };
    assert_eq!(t(7, 0, &(-5i32).to_le_bytes()), "-5");
    assert_eq!(t(3, 0, &[0xff]), "-1");
    assert_eq!(t(8, 0, &7u32.to_le_bytes()), "7");
    assert_eq!(t(8, 20, &255u32.to_le_bytes()), "0x000000ff", "hex output");
    assert_eq!(t(20, 0, &255u32.to_le_bytes()), "0x000000ff", "hex input");
    assert_eq!(t(13, 0, &1u32.to_le_bytes()), "true");
    assert_eq!(t(4, 13, &[0]), "false");
    assert_eq!(t(8, 30, &[10, 0, 0, 1]), "10.0.0.1");
    assert_eq!(t(6, 32, &[0x1f, 0x90]), "8080", "a port, big-endian");
    assert_eq!(
        t(16, 0, &0x7ff0_1234u64.to_le_bytes()),
        "0x000000007ff01234"
    );
    assert_eq!(t(1, 0, b"h\0i\0\0\0"), "hi");
    assert_eq!(t(2, 0, b"abc\0"), "abc");
    assert_eq!(t(22, 0, b"\x04\0h\0i\0"), "hi", "counted");
    assert_eq!(t(11, 0, &1.5f32.to_le_bytes()), "1.5");
    assert_eq!(t(12, 0, &(-2.25f64).to_le_bytes()), "-2.25");
    assert_eq!(t(14, 0, &[1, 0xab]), "01ab");
    assert!(t(14, 0, &[0; 100]).ends_with("… (100 bytes)"));
    assert_eq!(
        t(19, 0, &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]),
        "S-1-5-32-544"
    );
    // An array of three uint16s; a long one shows its first 16.
    assert_eq!(t(6, 0, &[1, 0, 2, 0, 3, 0]), "[1, 2, 3]");
    assert!(t(4, 0, &[1; 20]).ends_with(", … 4 more]"));
    // A FILETIME: 2026-11-18 00:00:00 UTC.
    let ft: u64 = (20_775 + 134_774) * 86_400 * 10_000_000;
    assert_eq!(t(17, 0, &ft.to_le_bytes()), "2026-11-18 00:00:00.0000000Z");
    assert_eq!(
        t(17, 0, &0u64.to_le_bytes()),
        "1601-01-01 00:00:00.0000000Z"
    );
    assert_eq!(
        t(17, 0, &(134_774u64 * 86_400 * 10_000_000).to_le_bytes()),
        "1970-01-01 00:00:00.0000000Z"
    );
    // Too short: shown as bytes, never a panic.
    for i in 0..=31u8 {
        for o in [0u8, 13, 20, 30, 31, 32] {
            for len in 0..20 {
                let _ = t(i, o, &vec![0xff; len]);
            }
        }
    }
}

//! `__unwind_info` from a synthetic section: a regular page, a compressed
//! one (with an encoding of its own), LSDAs, and personalities.

use alloc::vec;
use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::unwind_info::{Entry, Found, UnwindInfo};

fn section() -> Vec<u8> {
    let mut b = vec![0u8; 168];
    let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    // Header: version, common encodings (28, 2), personalities (36, 1),
    // index (40, 3).
    for (i, v) in [1, 28, 2, 36, 1, 40, 3].into_iter().enumerate() {
        put(4 * i, v);
    }
    put(28, 0x0100_0000);
    put(32, 0x0200_0000);
    put(36, 0x5000);
    // Index: (function, page, LSDA index); the last only marks the end.
    for (i, (f, p, l)) in [(0x1000, 100, 76), (0x2000, 140, 84), (0x3000, 0, 84)]
        .into_iter()
        .enumerate()
    {
        put(40 + 12 * i, f);
        put(44 + 12 * i, p);
        put(48 + 12 * i, l);
    }
    // LSDAs.
    put(76, 0x1010);
    put(80, 0x6000);
    // A regular page: kind 2, entries at +8, two of them.
    put(100, 2);
    put(104, 8 | 2 << 16);
    put(108, 0x1000);
    put(112, 0x0100_0000);
    put(116, 0x1010);
    put(120, 0x4100_0000);
    // A compressed page: kind 3, entries at +12 (3), encodings at +24 (1).
    put(140, 3);
    put(144, 12 | 3 << 16);
    put(148, 24 | 1 << 16);
    put(152, 0);
    put(156, 1 << 24 | 0x100);
    put(160, 2 << 24 | 0x200);
    put(164, 0x0300_0000);
    b
}

#[test]
fn entries_and_lookups() {
    let data = section();
    let info = UnwindInfo::parse(&data, Endian::Little).unwrap();
    let e = |function, encoding| Entry { function, encoding };
    assert_eq!(
        info.entries(),
        [
            e(0x1000, 0x0100_0000),
            e(0x1010, 0x4100_0000),
            e(0x2000, 0x0100_0000),
            e(0x2100, 0x0200_0000),
            e(0x2200, 0x0300_0000)
        ]
    );
    assert_eq!(
        info.common_encodings().collect::<Vec<_>>(),
        [0x0100_0000, 0x0200_0000]
    );
    assert_eq!(info.personalities().collect::<Vec<_>>(), [0x5000]);
    let found = |entry, end| Some(Found { entry, end });
    assert_eq!(info.lookup(0x1000), found(e(0x1000, 0x0100_0000), 0x1010));
    assert_eq!(info.lookup(0x1FFF), found(e(0x1010, 0x4100_0000), 0x2000));
    assert_eq!(info.lookup(0x2150), found(e(0x2100, 0x0200_0000), 0x2200));
    assert_eq!(info.lookup(0x2FFF), found(e(0x2200, 0x0300_0000), 0x3000));
    for at in [0, 0xFFF, 0x3000, u32::MAX] {
        assert_eq!(info.lookup(at), None, "{at:#x}");
    }
    assert_eq!(info.lsda(0x1010), Some(0x6000));
    assert_eq!(info.lsda(0x1000), None);
    assert_eq!(info.lsda(0x2000), None);
}

#[test]
fn malformed() {
    let data = section();
    assert!(UnwindInfo::parse(&data[..27], Endian::Little).is_none());
    let mut v2 = data.clone();
    v2[0] = 2;
    assert!(UnwindInfo::parse(&v2, Endian::Little).is_none());
    // Every truncation and byte corruption: no panics.
    for n in 28..data.len() {
        let info = UnwindInfo::parse(&data[..n], Endian::Little).unwrap();
        assert!(info.entries().len() <= 5);
        let _ = (info.lookup(0x2150), info.lsda(0x1010));
    }
    for i in 4..data.len() {
        for v in [0x00, 0x7F, 0xFF] {
            let mut b = data.clone();
            b[i] = v;
            if let Some(info) = UnwindInfo::parse(&b, Endian::Little) {
                let _ = (
                    info.entries(),
                    info.lookup(0x2150),
                    info.lookup(0x1005),
                    info.lsda(0x1010),
                );
                let _ = (
                    info.common_encodings().count(),
                    info.personalities().count(),
                );
            }
        }
    }
    // A compressed entry naming a page encoding that isn't there ends the
    // page.
    let mut b = data.clone();
    b[163] = 9;
    let info = UnwindInfo::parse(&b, Endian::Little).unwrap();
    assert_eq!(info.entries().len(), 4);
    assert_eq!(info.lookup(0x2250), None);
}

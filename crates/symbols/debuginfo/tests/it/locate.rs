//! [`Locator`]: the frames at addresses of the source lines test program
//! (tools/lines), from its PDB and its DWARF (plain and split); and
//! damaged debug information, which must give frames or none, never a
//! panic or a hang.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use hexcavator_debuginfo::{DebugInfo, Frame};

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/lines")
        .join(name)
}

/// Each frame as (function, line, inlined).
fn brief(frames: &[Frame]) -> Vec<(&str, u32, bool)> {
    frames
        .iter()
        .map(|f| (f.function.as_str(), f.line, f.inlined))
        .collect()
}

#[test]
fn pdb() {
    let data = std::fs::read(testdata("lines.pdb")).unwrap();
    let debug = DebugInfo::parse(&data).unwrap();
    let mut l = debug.locator();
    // third: sum_of_squares inlined, square inlined twice in it (the
    // second copy's code in two ranges).
    let third = [
        ("square", 5, true),
        ("sum_of_squares", 8, true),
        ("third", 11, false),
    ];
    for rva in [0x1040, 0x1043, 0x1047, 0x104A] {
        assert_eq!(brief(&l.frames(rva)), third, "{rva:#x}");
    }
    let frames = l.frames(0x1043);
    assert_eq!(frames[2].start, Some(0x1040));
    assert_eq!(frames[0].start, None);
    assert_eq!(frames[0].file.as_deref(), Some("R:\\tools\\lines\\lines.h"));
    assert_eq!(
        frames[2].file.as_deref(),
        Some("R:\\tools\\lines\\lines.cpp")
    );
    // Past sum_of_squares: third's own code.
    assert_eq!(brief(&l.frames(0x104B)), [("third", 11, false)]);
    // twice<int>: its opening line at its first byte (DIA's), then its
    // statement's.
    assert_eq!(brief(&l.frames(0x1000)), [("twice<int>", 12, false)]);
    assert_eq!(brief(&l.frames(0x1001)), [("twice<int>", 13, false)]);
    // Nothing (padding after a function, no section, past 32 bits).
    for rva in [0x1004, 0, 0x10_0000, 1 << 40] {
        assert!(l.frames(rva).is_empty(), "{rva:#x}");
    }
}

#[test]
fn dwarf() {
    for (image, split) in [
        ("lines-x86_64-linux-gnu", false),
        ("lines-split-x86_64-linux-gnu", true),
    ] {
        let dwo = std::fs::read(testdata("lines-split.dwo")).unwrap();
        let data = std::fs::read(testdata(image)).unwrap();
        let mut debug = DebugInfo::parse(&data).unwrap();
        if split {
            debug.dwarf_mut().unwrap().add_split(&dwo).unwrap();
        }
        let mut l = debug.locator();
        let frames = l.frames(0x2011C0);
        assert_eq!(
            brief(&frames),
            [("square", 5, true), ("first", 6, false)],
            "{image}"
        );
        assert_eq!(frames[0].file.as_deref(), Some("./lines.h"));
        assert_eq!(frames[1].file.as_deref(), Some("./lines-elf.cpp"));
        assert_eq!(frames[1].start, Some(0x2011C0));
        // Padding: nothing.
        assert!(l.frames(0x2011C7).is_empty());
        assert!(l.frames(0).is_empty());
        assert!(l.frames(u64::MAX).is_empty());
    }
}

/// Damage: the files cut short anywhere and with bytes flipped (the same
/// pseudo-random ones each run). Every lookup answers, quickly.
#[test]
fn damaged() {
    for (name, addrs) in [
        (
            "lines.pdb",
            &[0x1000u64, 0x1043, 0x1062, 0x10E5, 0x1300][..],
        ),
        (
            "lines-x86_64-linux-gnu",
            &[0x2011C0, 0x2011D2, 0x201200, 0x201234][..],
        ),
    ] {
        let data = std::fs::read(testdata(name)).unwrap();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut damaged: Vec<Vec<u8>> = (1..32)
            .map(|i| data[..data.len() * i / 32].to_vec())
            .collect();
        for _ in 0..48 {
            let mut d = data.clone();
            for _ in 0..16 {
                let at = usize::try_from(next() % d.len() as u64).unwrap();
                d[at] = next().to_le_bytes()[0];
            }
            damaged.push(d);
        }
        for d in &damaged {
            let Ok(debug) = DebugInfo::parse(d) else {
                continue;
            };
            let start = Instant::now();
            let mut l = debug.locator();
            for &a in addrs {
                let _ = l.frames(a);
            }
            assert!(start.elapsed() < Duration::from_secs(5), "{name}: too slow");
        }
    }
}

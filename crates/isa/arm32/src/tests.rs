//! Hermetic decoding tests: known words and their encodings.

#![allow(clippy::cast_possible_truncation)]

use crate::{decode_a32, decode_t32};

#[test]
fn known_a32() {
    for (word, name) in [
        (0xE52D_E004u32, "STR_i_A1_pre"), // str lr, [sp, #-4]!
        (0xE291_0010, "ADDS_i_A1"),       // adds r0, r1, #16
        (0xE320_F000, "NOP_A1"),          // nop
        (0xE12F_FF1E, "BX_A1"),           // bx lr
        (0xE8BD_8010, "LDM_A1"),          // pop {r4, pc} (ldm sp!, ...)
    ] {
        let i = decode_a32(word).unwrap_or_else(|| panic!("{word:#x}"));
        assert_eq!(i.encoding.name, name, "{word:#x}");
        assert_eq!(i.size, 4);
    }
    assert!(decode_a32(0xFFFF_FFFF).is_none());
}

#[test]
fn known_t32() {
    for (first, second, name) in [
        (0xE92Du16, Some(0x41F0u16), "STMDB_T1"), // push.w {r4-r8, lr}
        (0x3001, None, "ADD_i_T2"),               // adds r0, #1
        (0xF3BF, Some(0x8F2F), "CLREX_T1"),
        (0x4770, None, "BX_T1"), // bx lr
    ] {
        let i = decode_t32(first, second).unwrap_or_else(|| panic!("{first:#x}"));
        assert_eq!(i.encoding.name, name, "{first:#x}");
        assert_eq!(usize::from(i.size), if second.is_some() { 4 } else { 2 });
    }
    // A 32-bit instruction without its second halfword.
    assert!(decode_t32(0xE92D, None).is_none());
}

#[test]
fn every_halfword_and_many_words() {
    // Every 16-bit Thumb halfword (and each with a second halfword when it
    // starts a 32-bit one), and a sweep of 32-bit words: no panics, and
    // the right sizes.
    let mut decoded = 0;
    for hw in 0..=u16::MAX {
        for second in [None, Some(0x0000), Some(0xFFFF), Some(hw.rotate_left(5))] {
            if let Some(i) = decode_t32(hw, second) {
                assert_eq!(
                    usize::from(i.size),
                    if crate::is_t32_wide(hw) { 4 } else { 2 }
                );
                decoded += 1;
            }
        }
    }
    assert!(decoded > 100_000, "{decoded}");
    let mut x = 0x1234_5678u32;
    for _ in 0..1_000_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        if let Some(i) = decode_a32(x) {
            assert_eq!(i.size, 4);
            assert!(!i.encoding.mnemonic().is_empty(), "{x:#x}");
        }
        let _ = decode_t32((x >> 16) as u16, Some(x as u16));
    }
    let (a32, t16, t32) = crate::counts();
    assert!(a32 > 1000 && t16 > 80 && t32 > 1000, "{a32} {t16} {t32}");
}

#[test]
fn modified_immediates() {
    use crate::format::{a32_expand_imm, t32_expand_imm};
    assert_eq!(a32_expand_imm(0x0ff), 0xff);
    assert_eq!(a32_expand_imm(0x4ff), 0xff00_0000);
    assert_eq!(a32_expand_imm(0x1ff), 0xc000_003f);
    assert_eq!(t32_expand_imm(0x0ab), 0xab);
    assert_eq!(t32_expand_imm(0x1ab), 0x00ab_00ab);
    assert_eq!(t32_expand_imm(0x2ab), 0xab00_ab00);
    assert_eq!(t32_expand_imm(0x3ab), 0xabab_abab);
    // (Rotated: 1:imm8<6:0> right by i:imm3:imm8<7>.)
    assert_eq!(t32_expand_imm(0x47f), 0xff00_0000);
}

#[test]
fn texts_of_known_words() {
    use crate::format::{Targets, format};
    let a = |w| format(&decode_a32(w).unwrap(), 0x1000, Targets::Addresses);
    assert_eq!(a(0xE52D_E004), "str lr, [sp, #-4]!");
    assert_eq!(a(0xE92D_4010), "push {r4, lr}");
    assert_eq!(a(0xE8BD_8010), "pop {r4, pc}");
    assert_eq!(a(0xEB00_0010), "bl 0x1048");
    assert_eq!(a(0xE1A0_1102), "lsl r1, r2, #2");
    assert_eq!(a(0xE7FF_DEFE), "trap");
    let t = |a: u16, b: Option<u16>| format(&decode_t32(a, b).unwrap(), 0x1000, Targets::Addresses);
    assert_eq!(t(0xB510, None), "push {r4, lr}");
    assert_eq!(t(0x1C48, None), "adds r0, r1, #1");
    assert_eq!(t(0xBF18, None), "it ne");
    assert_eq!(t(0xF7FF, Some(0xFFFE)), "bl 0x1000");
    assert_eq!(t(0xF8D1, Some(0x0004)), "ldr.w r0, [r1, #4]");
    assert_eq!(
        format(&decode_a32(0xF420_070F).unwrap(), 0, Targets::Addresses),
        "vld1.8 {d0}, [r0]"
    );
    // Offsets, as LLVM writes them without addresses.
    assert_eq!(
        format(&decode_a32(0xEAFF_FFFE).unwrap(), 0x1000, Targets::Offsets),
        "b #-8"
    );
}

#[test]
fn every_word_formats_without_panicking() {
    use crate::format::{Targets, format};
    // A sample of each set (all of T16), at an address near the top.
    let mut w = 0x1234_5678u32;
    for _ in 0..200_000 {
        w = w.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        if let Some(i) = decode_a32(w) {
            let _ = format(&i, u64::from(u32::MAX - 4), Targets::Addresses);
        }
        if let Some(i) = decode_t32((w >> 16) as u16, Some(w as u16)) {
            let _ = format(&i, 0, Targets::Offsets);
        }
    }
    for h in 0..=u16::MAX {
        if let Some(i) = decode_t32(h, Some(0)) {
            let _ = format(&i, 0, Targets::Addresses);
        }
    }
}

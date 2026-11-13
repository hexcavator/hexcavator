//! ARM EHABI: index entries and opcodes, from the specification.

// Synthetic test data: small values, casts are exact.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_core::Endian;

use crate::support::{STACK, Stack};
use hexcavator_unwind::Error;
use hexcavator_unwind::arm_ehabi::{self, Entry, Exidx, Model};
use hexcavator_unwind::dwarf_cfi::Registers;

const SP: u16 = 13;
const LR: u16 = 14;
const PC: u16 = 15;

fn compact(opcodes: &[u8]) -> Entry {
    Entry {
        function: 0x1000,
        table: None,
        model: Model::Compact {
            personality: 0,
            inline: true,
        },
        opcodes: opcodes.to_vec(),
    }
}

/// A stack of 32-bit words: word `i` at STACK + 4i holds 0x100 + i.
fn words() -> Stack {
    let mut s = Stack::new();
    for i in 0..256u64 {
        let lo = 0x100 + 2 * i;
        s.set(STACK + 8 * i, (lo + 1) << 32 | lo);
    }
    s
}

fn regs() -> Registers {
    let mut r = Registers::default();
    for n in 0..16u16 {
        r.set(n, Some(0xC0DE_0000 + u64::from(n)));
    }
    r.set(SP, Some(STACK));
    r
}

fn run(
    opcodes: &[u8],
) -> (
    Registers,
    hexcavator_unwind::Result<hexcavator_unwind::dwarf_cfi::Frame>,
) {
    let mut r = regs();
    let result = arm_ehabi::unwind(&compact(opcodes), Endian::Little, &mut r, &words());
    (r, result)
}

#[test]
fn stack_adjustments() {
    let (r, f) = run(&[0x02, 0xB0]);
    assert_eq!(r.get(SP), Some(STACK + 12));
    // PC is lr when nothing pops it.
    assert_eq!(
        (r.get(PC), f.unwrap().return_address),
        (Some(0xC0DE_000E), Some(0xC0DE_000E))
    );
    let (r, _) = run(&[0x3F, 0x41, 0xB0]);
    assert_eq!(r.get(SP), Some(STACK + 256 - 8));
    // vsp = r7; uleb: 0x204 + (0x81 0x01 = 129) << 2.
    let (r, _) = run(&[0x97, 0xB0]);
    assert_eq!(r.get(SP), Some(0xC0DE_0007));
    let (r, _) = run(&[0xB2, 0x81, 0x01]);
    assert_eq!(r.get(SP), Some(STACK + 0x204 + (129 << 2)));
}

#[test]
fn core_register_pops() {
    // pop {r4-r6, lr} (10101 010), then the words follow in order.
    let (r, f) = run(&[0xAA, 0xB0]);
    assert_eq!(
        (r.get(4), r.get(5), r.get(6), r.get(LR)),
        (Some(0x100), Some(0x101), Some(0x102), Some(0x103))
    );
    assert_eq!((r.get(SP), r.get(PC)), (Some(STACK + 16), Some(0x103)));
    assert_eq!(
        f.unwrap().saved,
        [(4, STACK), (5, STACK + 4), (6, STACK + 8), (LR, STACK + 12)]
    );
    // pop under mask {r4, r11, pc} (1000 1000 0000 1001... r4 = bit 0 of
    // the 12-bit mask): PC comes from the stack, not lr.
    let (r, f) = run(&[0x88, 0x81, 0xB0]);
    assert_eq!(
        (r.get(4), r.get(11), r.get(PC)),
        (Some(0x100), Some(0x101), Some(0x102))
    );
    assert_eq!(f.unwrap().return_address, Some(0x102));
    // pop {r0, r3}.
    let (r, _) = run(&[0xB1, 0x09, 0xB0]);
    assert_eq!(
        (r.get(0), r.get(3), r.get(SP)),
        (Some(0x100), Some(0x101), Some(STACK + 8))
    );
    // Popping sp sets it from the stack.
    let (r, _) = run(&[0x82, 0x00]);
    assert_eq!(r.get(SP), Some(0x100));
}

#[test]
fn vfp_pops() {
    // FSTMFDX d8-d9 (10111 001): 16 bytes plus a pad word.
    let (r, _) = run(&[0xB9]);
    assert_eq!(r.get(256 + 8), Some(0x101 << 32 | 0x100));
    assert_eq!(r.get(SP), Some(STACK + 20));
    // VPUSH d8-d10 (11010 010): no pad.
    let (r, _) = run(&[0xD2]);
    assert_eq!(
        (r.get(256 + 10), r.get(SP)),
        (Some(0x105 << 32 | 0x104), Some(STACK + 24))
    );
    // FSTMFDX d2-d3 (0xB3 0x21); VPUSH d16-d17 (0xC8 0x01); d4 (0xC9 0x40).
    let (r, _) = run(&[0xB3, 0x21]);
    assert_eq!(
        (r.get(256 + 3), r.get(SP)),
        (Some(0x103 << 32 | 0x102), Some(STACK + 20))
    );
    let (r, _) = run(&[0xC8, 0x01]);
    assert_eq!(
        (r.get(256 + 17), r.get(SP)),
        (Some(0x103 << 32 | 0x102), Some(STACK + 16))
    );
    let (r, _) = run(&[0xC9, 0x40]);
    assert_eq!(
        (r.get(256 + 4), r.get(SP)),
        (Some(0x101 << 32 | 0x100), Some(STACK + 8))
    );
    // Big-endian: the high word first.
    let mut regs = regs();
    arm_ehabi::unwind(&compact(&[0xD0]), Endian::Big, &mut regs, &words()).unwrap();
    assert_eq!(
        regs.get(256 + 8),
        Some(0x100_u64.swap_bytes() >> 32 << 32 | u64::from(0x101_u32.swap_bytes()))
    );
}

#[test]
fn iwmmx_is_skipped() {
    let (r, _) = run(&[0xC6, 0x12, 0xB0]);
    assert_eq!(r.get(SP), Some(STACK + 24));
    let (r, _) = run(&[0xC7, 0x05]);
    assert_eq!(r.get(SP), Some(STACK + 8));
    let (r, _) = run(&[0xC2]);
    assert_eq!(r.get(SP), Some(STACK + 24));
}

#[test]
fn finish_and_refusals() {
    // `finish` ends the opcodes, even with more after it.
    let (r, _) = run(&[0xB0, 0x02]);
    assert_eq!(r.get(SP), Some(STACK));
    for bad in [
        &[0x80, 0x00][..],
        &[0x9D],
        &[0x9F],
        &[0xB1, 0x00],
        &[0xB1, 0x10],
        &[0xB4],
        &[0xC7, 0x00],
        &[0xCA],
        &[0xD8],
        &[0xFF],
        &[0x80],
        &[0xB2, 0x80],
    ] {
        let (_, f) = run(bad);
        assert!(matches!(f, Err(Error::Encoding { .. })), "{bad:02x?}");
    }
    let mut r = regs();
    let cant = Entry {
        model: Model::CantUnwind,
        ..compact(&[])
    };
    assert!(arm_ehabi::unwind(&cant, Endian::Little, &mut r, &words()).is_err());
    // Memory and registers that aren't there.
    let mut r = Registers::default();
    assert_eq!(
        arm_ehabi::unwind(&compact(&[0xB0]), Endian::Little, &mut r, &words()),
        Err(Error::Register { register: SP })
    );
    let mut r = regs();
    r.set(SP, Some(0x10));
    assert_eq!(
        arm_ehabi::unwind(&compact(&[0xA8]), Endian::Little, &mut r, &words()),
        Err(Error::Memory { address: 0x10 })
    );
}

/// An `.ARM.exidx` at 0x8000 (its table entries are [`Table`]'s).
fn exidx_section() -> Vec<u8> {
    let prel31 = |target: u64, place: u64| (target.wrapping_sub(place) as u32) & 0x7FFF_FFFF;
    let mut exidx = Vec::new();
    let mut entry = |function: u64, word: u32| {
        let place = 0x8000 + exidx.len() as u64;
        exidx.extend(prel31(function, place).to_le_bytes());
        exidx.extend(word.to_le_bytes());
    };
    // Inline (pr0: 0x80 then three opcodes); a table entry (pr1, one extra
    // word); a generic one; and one that can't be unwound. The second
    // function is before the table (a negative offset).
    entry(0x1000, 0x80A8_B0B0);
    entry(0x1100, prel31(0x9000, 0x800C));
    entry(0x1200, prel31(0x9008, 0x8014));
    entry(0x1300, 1);
    exidx
}

/// Memory with the table at 0x9000.
struct Table;

impl hexcavator_unwind::Memory for Table {
    fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        let words: [(u64, u32); 5] = [
            // pr1: one more word, opcodes 97 41, then 84 0D B0 B0.
            (0x9000, 0x8101_9741),
            (0x9004, 0x840D_B0B0),
            // Generic: a personality at 0x9100, then GNU's layout.
            (0x9008, 0x0000_00F8),
            (0x900C, 0x00A8_B0B0),
            (0x9010, 0),
        ];
        for (i, b) in buf.iter_mut().enumerate() {
            let a = address + i as u64;
            let Some(&(at, w)) = words.iter().find(|(at, _)| a >= *at && a < at + 4) else {
                return false;
            };
            *b = w.to_le_bytes()[(a - at) as usize];
        }
        true
    }
}

#[test]
fn index_entries() {
    let data = exidx_section();
    let exidx = Exidx {
        data: &data,
        address: 0x8000,
        endian: Endian::Little,
    };
    assert_eq!(exidx.len(), 4);
    let e = |i| exidx.entry(i, &Table).unwrap();
    assert_eq!(
        e(0),
        Entry {
            function: 0x1000,
            table: None,
            model: Model::Compact {
                personality: 0,
                inline: true
            },
            opcodes: vec![0xA8, 0xB0, 0xB0],
        }
    );
    assert_eq!(
        e(1),
        Entry {
            function: 0x1100,
            table: Some(0x9000),
            model: Model::Compact {
                personality: 1,
                inline: false
            },
            opcodes: vec![0x97, 0x41, 0x84, 0x0D, 0xB0, 0xB0],
        }
    );
    assert_eq!(
        e(2),
        Entry {
            function: 0x1200,
            table: Some(0x9008),
            model: Model::Generic {
                personality: 0x9100
            },
            opcodes: vec![0xA8, 0xB0, 0xB0],
        }
    );
    assert_eq!(e(3).model, Model::CantUnwind);
    for (pc, expected) in [
        (0x1000, Some(0)),
        (0x10FF, Some(0)),
        (0x1100, Some(1)),
        (0x1350, Some(3)),
        (0xFFF, None),
    ] {
        assert_eq!(exidx.lookup(pc), expected, "{pc:#x}");
    }
    // Table entries that aren't there; a truncated index.
    struct Nothing;
    impl hexcavator_unwind::Memory for Nothing {
        fn read(&self, _: u64, _: &mut [u8]) -> bool {
            false
        }
    }
    assert!(exidx.entry(1, &Nothing).is_none());
    assert!(exidx.entry(0, &Nothing).is_some());
    let short = Exidx {
        data: &data[..12],
        ..exidx
    };
    assert_eq!(short.len(), 1);
    assert!(short.entry(1, &Table).is_none());
    assert_eq!(Exidx { data: &[], ..exidx }.lookup(0x1000), None);
}

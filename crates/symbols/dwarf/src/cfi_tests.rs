//! Hermetic call frame information tests: synthetic `.eh_frame` and
//! `.debug_frame` sections. (`tests/cfi.rs` compares real ones with
//! llvm-dwarfdump.)

extern crate std;

use alloc::vec;
use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::cfi::{self, CfaRule, Cfi, CfiKind, Entry, RegisterRule};

const SECTION: u64 = 0x40_0000;

/// Builds an `.eh_frame` (little-endian, 64-bit): entries with their
/// length fields filled in.
struct EhFrame {
    bytes: Vec<u8>,
}

impl EhFrame {
    fn new() -> Self {
        EhFrame { bytes: Vec::new() }
    }

    /// A CIE ("zR", pcrel|sdata4, code 1, data -8, RA 16) with these
    /// initial instructions; returns its offset.
    fn cie(&mut self, augmentation: &[u8], aug_data: &[u8], instructions: &[u8]) -> usize {
        let at = self.bytes.len();
        let mut body = vec![0, 0, 0, 0, 1];
        body.extend(augmentation);
        body.push(0);
        body.extend([0x01, 0x78, 16]);
        if augmentation.first() == Some(&b'z') {
            body.push(aug_data.len() as u8);
            body.extend(aug_data);
        }
        body.extend(instructions);
        self.bytes.extend((body.len() as u32).to_le_bytes());
        self.bytes.extend(body);
        at
    }

    /// An FDE for `[begin, begin + len)` (pcrel sdata4), with `aug` bytes
    /// of augmentation data.
    fn fde(&mut self, cie: usize, begin: u64, len: u32, aug: &[u8], instructions: &[u8]) -> usize {
        let at = self.bytes.len();
        let pointer_at = at + 4;
        let pc_at = at + 8;
        let mut body = Vec::new();
        body.extend(((pointer_at - cie) as u32).to_le_bytes());
        let rel = begin.wrapping_sub(SECTION + pc_at as u64) as u32;
        body.extend(rel.to_le_bytes());
        body.extend(len.to_le_bytes());
        body.push(aug.len() as u8);
        body.extend(aug);
        body.extend(instructions);
        self.bytes.extend((body.len() as u32).to_le_bytes());
        self.bytes.extend(body);
        at
    }

    fn cfi(&self) -> Cfi<'_> {
        Cfi {
            data: &self.bytes,
            kind: CfiKind::EhFrame,
            endian: Endian::Little,
            address: SECTION,
            address_size: 8,
            text_base: None,
            data_base: None,
        }
    }
}

/// def_cfa rsp+8; rip at cfa-8.
const X64_INITIAL: [u8; 5] = [0x0C, 0x07, 0x08, 0x90, 0x01];

/// push rbp; mov rbp, rsp: the classic frame.
const PUSH_RBP: [u8; 7] = [0x41, 0x0E, 0x10, 0x86, 0x02, 0x43, 0x0D];

fn classic() -> EhFrame {
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    let mut ins = PUSH_RBP.to_vec();
    ins.push(0x06);
    e.fde(cie, 0x1000, 0x40, &[], &ins);
    e
}

#[test]
fn entries_and_pointers() {
    let e = classic();
    let cfi = e.cfi();
    let entries: Vec<_> = cfi.entries().collect();
    assert_eq!(entries.len(), 2);
    let Entry::Cie(cie) = &entries[0] else {
        panic!()
    };
    assert_eq!(
        (
            cie.version,
            cie.augmentation,
            cie.code_alignment,
            cie.data_alignment
        ),
        (1, &b"zR"[..], 1, -8)
    );
    assert_eq!(
        (
            cie.return_address_register,
            cie.fde_encoding,
            cie.address_size
        ),
        (16, 0x1B, 8)
    );
    assert_eq!(cie.instructions, &X64_INITIAL);
    let Entry::Fde(fde) = &entries[1] else {
        panic!()
    };
    assert_eq!(
        (fde.pc_begin, fde.pc_range, fde.cie, fde.lsda),
        (0x1000, 0x40, 0, None)
    );
    assert!(
        fde.contains(0x1000)
            && fde.contains(0x103F)
            && !fde.contains(0x1040)
            && !fde.contains(0xFFF)
    );
    let (c, f) = cfi.find(0x1020).unwrap();
    assert_eq!((c.offset, f.offset), (0, fde.offset));
    assert!(cfi.find(0x2000).is_none());
}

#[test]
fn rows_and_lookups() {
    let e = classic();
    let cfi = e.cfi();
    let (cie, fde) = cfi.find(0x1000).unwrap();
    let rows = cfi::rows(&cfi, &cie, &fde).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.address).collect::<Vec<_>>(),
        [0x1000, 0x1001, 0x1004]
    );
    assert_eq!(
        rows[0].cfa,
        CfaRule::RegisterOffset {
            register: 7,
            offset: 8
        }
    );
    assert_eq!(rows[0].registers, [(16, RegisterRule::Offset(-8))]);
    assert_eq!(
        rows[1].cfa,
        CfaRule::RegisterOffset {
            register: 7,
            offset: 16
        }
    );
    assert_eq!(
        rows[1].registers,
        [
            (6, RegisterRule::Offset(-16)),
            (16, RegisterRule::Offset(-8))
        ]
    );
    assert_eq!(
        rows[2].cfa,
        CfaRule::RegisterOffset {
            register: 6,
            offset: 16
        }
    );
    for (pc, expected) in [
        (0x1000, 0),
        (0x1001, 1),
        (0x1003, 1),
        (0x1004, 2),
        (0x103F, 2),
    ] {
        assert_eq!(
            cfi::row_at(&cfi, &cie, &fde, pc).unwrap(),
            rows[expected],
            "{pc:#x}"
        );
    }
}

#[test]
fn every_rule() {
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    let ins = [
        0x0A, // remember_state
        0x07, 0x0D, // undefined r13
        0x08, 0x0E, // same_value r14
        0x09, 0x03, 0x0C, // register rbx <- r12
        0x14, 0x0F, 0x03, // val_offset r15, 3 * -8
        0x15, 0x05, 0x7F, // val_offset_sf rdi, -1 * -8
        0x11, 0x04, 0x7E, // offset_extended_sf rsi, -2 * -8
        0x05, 0x02, 0x04, // offset_extended rcx, 4 * -8
        0x2F, 0x01, 0x02, // GNU_negative_offset_extended rdx, -(2) * -8
        0x10, 0x00, 0x02, 0x76, 0x10, // expression rax: breg6 +16
        0x16, 0x08, 0x01, 0x30, // val_expression r8: lit0
        0x2E, 0x20, // GNU_args_size 32
        0x41, // advance 1
        0x0F, 0x02, 0x77, 0x00, // def_cfa_expression breg7 0
        0x42, // advance 2
        0x0B, // restore_state
        0x12, 0x06, 0x7E, // def_cfa_sf rbp, -2 * -8
        0x13, 0x7C, // def_cfa_offset_sf -4 * -8
        0xC6, // restore rbp (none in the CIE: unset)
        0x06, 0x10, // restore_extended rip (the CIE's rule)
        0x43, // advance 3
    ];
    e.fde(cie, 0x1000, 0x10, &[], &ins);
    let cfi = e.cfi();
    let (cie, fde) = cfi.find(0x1000).unwrap();
    let rows = cfi::rows(&cfi, &cie, &fde).unwrap();
    assert_eq!(rows.len(), 4);
    let r0 = &rows[0];
    let rule = |r: u16| r0.rule(r);
    assert_eq!(rule(13), Some(RegisterRule::Undefined));
    assert_eq!(rule(14), Some(RegisterRule::SameValue));
    assert_eq!(rule(3), Some(RegisterRule::Register(12)));
    assert_eq!(rule(15), Some(RegisterRule::ValOffset(-24)));
    assert_eq!(rule(5), Some(RegisterRule::ValOffset(8)));
    assert_eq!(rule(4), Some(RegisterRule::Offset(16)));
    assert_eq!(rule(2), Some(RegisterRule::Offset(-32)));
    assert_eq!(rule(1), Some(RegisterRule::Offset(16)));
    assert_eq!(rule(0), Some(RegisterRule::Expression(&[0x76, 0x10])));
    assert_eq!(rule(8), Some(RegisterRule::ValExpression(&[0x30])));
    assert_eq!(r0.args_size, 32);
    assert_eq!(rows[1].cfa, CfaRule::Expression(&[0x77, 0x00]));
    // Restored: back to the CIE's rules, then rbp+32.
    let r2 = &rows[3];
    assert_eq!(
        r2.cfa,
        CfaRule::RegisterOffset {
            register: 6,
            offset: 32
        }
    );
    assert_eq!(r2.registers, [(16, RegisterRule::Offset(-8))]);
    assert_eq!((r2.address, rows[2].address), (0x1006, 0x1003));
}

#[test]
fn return_address_signing_and_augmentations() {
    let mut e = EhFrame::new();
    // "zPLRSB": personality (indirect pcrel sdata4), LSDA encoding,
    // FDE encoding, a signal frame, the B key.
    let cie = e.cie(
        b"zPLRSB",
        &[0x9B, 0x10, 0, 0, 0, 0x1B, 0x1B],
        &[0x0C, 0x1F, 0x00],
    );
    // (Augmentation data: an LSDA pointer of 0x10 relative to itself.)
    e.fde(
        cie,
        0x2000,
        0x10,
        &0x10u32.to_le_bytes(),
        &[0x2D, 0x41, 0x2D, 0x41, 0x2C],
    );
    let cfi = e.cfi();
    let (cie, fde) = cfi.find(0x2000).unwrap();
    assert!(cie.signal_frame && cie.b_key);
    assert_eq!(cie.lsda_encoding, Some(0x1B));
    assert!(cie.personality.is_some());
    let lsda_field = SECTION + fde.offset + 4 + 4 + 4 + 4 + 1;
    assert_eq!(fde.lsda, Some(lsda_field + 0x10));
    let rows = cfi::rows(&cfi, &cie, &fde).unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r.return_address_signed)
            .collect::<Vec<_>>(),
        [Some(true), Some(false), Some(true)]
    );
}

#[test]
fn debug_frame_v4_big_endian_dwarf64() {
    // A 64-bit DWARF CIE (version 4, address size 4) and FDE, big-endian.
    let mut d = Vec::new();
    let mut cie = vec![];
    cie.extend(u64::MAX.to_be_bytes()); // CIE id
    cie.extend([4, 0, 4, 0, 0x02, 0x7C, 14]); // v4, "", addr 4, seg 0, code 2, data -4, RA 14
    cie.extend([0x0C, 13, 0]); // def_cfa sp+0
    d.extend(0xFFFF_FFFFu32.to_be_bytes());
    d.extend((cie.len() as u64).to_be_bytes());
    d.extend(cie);
    let mut fde = vec![];
    fde.extend(0u64.to_be_bytes()); // CIE offset
    fde.extend(0x8000u32.to_be_bytes());
    fde.extend(0x20u32.to_be_bytes());
    fde.extend([0x42, 0x0E, 0x08, 0x8E, 0x01]); // advance 2*2; cfa sp+8; lr at cfa-4
    d.extend(0xFFFF_FFFFu32.to_be_bytes());
    d.extend((fde.len() as u64).to_be_bytes());
    d.extend(fde);
    let cfi = Cfi {
        data: &d,
        kind: CfiKind::DebugFrame,
        endian: Endian::Big,
        address: 0,
        address_size: 8,
        text_base: None,
        data_base: None,
    };
    let (cie, fde) = cfi.find(0x8010).unwrap();
    assert_eq!(
        (
            cie.version,
            cie.address_size,
            cie.code_alignment,
            cie.data_alignment
        ),
        (4, 4, 2, -4)
    );
    assert_eq!((fde.pc_begin, fde.pc_range), (0x8000, 0x20));
    let row = cfi::row_at(&cfi, &cie, &fde, 0x8010).unwrap();
    assert_eq!(row.address, 0x8004);
    assert_eq!(
        row.cfa,
        CfaRule::RegisterOffset {
            register: 13,
            offset: 8
        }
    );
    assert_eq!(row.registers, [(14, RegisterRule::Offset(-4))]);
}

#[test]
fn pointer_encodings() {
    // FDE pointers as udata8 absolute, udata2, sleb128 (datarel), and an
    // aligned absolute pointer.
    for (enc, begin_bytes, data_base, expected) in [
        (0x04u8, 0x3000u64.to_le_bytes().to_vec(), None, Some(0x3000)),
        (0x02, 0x3000u16.to_le_bytes().to_vec(), None, Some(0x3000)),
        (0x39, vec![0x80, 0x20], Some(0x1000), Some(0x1000 + 0x1000)),
        (0x39, vec![0x80, 0x20], None, None),
    ] {
        let mut e = EhFrame::new();
        let cie = e.cie(b"zR", &[enc], &X64_INITIAL);
        // Build the FDE by hand: id, begin, range (same format), aug len.
        let at = e.bytes.len();
        let mut body = Vec::new();
        body.extend(((at + 4 - cie) as u32).to_le_bytes());
        body.extend(&begin_bytes);
        let mut range = begin_bytes.clone();
        range.iter_mut().for_each(|b| *b = 0);
        range[0] = 0x10;
        body.extend(range);
        body.push(0);
        e.bytes.extend((body.len() as u32).to_le_bytes());
        e.bytes.extend(body);
        let mut cfi = e.cfi();
        cfi.data_base = data_base;
        let begin = cfi.entries().find_map(|en| match en {
            Entry::Fde(f) => Some(f.pc_begin),
            Entry::Cie(_) => None,
        });
        assert_eq!(begin, expected, "{enc:#x}");
    }
}

#[test]
fn malformed_sections() {
    let base = classic();
    let ok = base.cfi().entries().count();
    assert_eq!(ok, 2);
    // Every truncation: no panics, and never more entries than before.
    for n in 0..base.bytes.len() {
        let cfi = Cfi {
            data: &base.bytes[..n],
            ..base.cfi()
        };
        assert!(cfi.entries().count() <= ok);
        let _ = cfi.find(0x1000);
    }
    // Every single-byte corruption: no panics.
    for i in 0..base.bytes.len() {
        for v in [0x00, 0x7F, 0x80, 0xFF] {
            let mut b = base.bytes.clone();
            b[i] = v;
            let cfi = Cfi {
                data: &b,
                ..base.cfi()
            };
            for entry in cfi.entries() {
                if let Entry::Fde(f) = entry
                    && let Some(Entry::Cie(c)) = cfi.entry_at(f.cie as usize).map(|e| e.0)
                {
                    let _ = cfi::rows(&cfi, &c, &f);
                }
            }
        }
    }
    // A zero-length terminator ends .eh_frame.
    let mut e = classic();
    let fde_entry = e.bytes[0x18..].to_vec();
    e.bytes.truncate(0x18);
    e.bytes.extend([0, 0, 0, 0]);
    e.bytes.extend(fde_entry);
    assert_eq!(e.cfi().entries().count(), 1);
}

#[test]
fn malformed_entries() {
    // Unknown versions and augmentations without `z`.
    for (version, augmentation) in [(2u8, &b""[..]), (5, b""), (1, b"xyz")] {
        let mut e = EhFrame::new();
        e.cie(b"", &[], &X64_INITIAL);
        e.bytes[8] = version;
        if !augmentation.is_empty() {
            let mut body = vec![0, 0, 0, 0, version];
            body.extend(augmentation);
            body.extend([0, 1, 0x78, 16]);
            e.bytes.clear();
            e.bytes.extend((body.len() as u32).to_le_bytes());
            e.bytes.extend(body);
        }
        assert!(
            e.cfi().entries().next().is_none(),
            "{version} {augmentation:?}"
        );
    }
    // An FDE whose CIE pointer points nowhere, or at an FDE.
    let mut e = classic();
    let fde = 0x18 + 4;
    e.bytes[fde..fde + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    assert_eq!(e.cfi().entries().count(), 1);
    let mut e = classic();
    let second = e.bytes.len();
    let ins = [0x00];
    e.fde(0x18, 0x5000, 4, &[], &ins);
    assert!(e.cfi().entry_at(second).is_none());
}

#[test]
fn malformed_instructions() {
    for (instructions, why) in [
        (&[0x0B][..], "restore_state with nothing remembered"),
        (
            &[0x0F, 0x01, 0x96, 0x0E, 0x08],
            "def_cfa_offset on an expression",
        ),
        (&[0x3F][..], "unknown opcode"),
        (&[0x0C, 0x07], "truncated operand"),
        (&[0x10, 0x00, 0x10, 0x01], "expression running off the end"),
        (
            &[0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00],
            "register number too big",
        ),
    ] {
        let mut e = EhFrame::new();
        let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
        e.fde(cie, 0x1000, 0x10, &[], instructions);
        let cfi = e.cfi();
        let (c, f) = cfi.find(0x1000).unwrap();
        assert!(cfi::rows(&cfi, &c, &f).is_none(), "{why}");
    }
    // Remembered states nest at most 64 deep.
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    e.fde(cie, 0x1000, 0x10, &[], &[0x0A; 65]);
    let cfi = e.cfi();
    let (c, f) = cfi.find(0x1000).unwrap();
    assert!(cfi::rows(&cfi, &c, &f).is_none());
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    e.fde(cie, 0x1000, 0x10, &[], &[0x0A; 64]);
    let cfi = e.cfi();
    let (c, f) = cfi.find(0x1000).unwrap();
    assert!(cfi::rows(&cfi, &c, &f).is_some());
}

#[test]
fn set_loc_and_long_advances() {
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    // advance_loc1 0x10, advance_loc2 0x100, advance_loc4 0x1000.
    e.fde(
        cie,
        0x1000,
        0x2000,
        &[],
        &[
            0x02, 0x10, 0x0E, 0x10, 0x03, 0x00, 0x01, 0x0E, 0x18, 0x04, 0x00, 0x10, 0, 0, 0x0E,
            0x20,
        ],
    );
    let cfi = e.cfi();
    let (c, f) = cfi.find(0x1000).unwrap();
    let rows = cfi::rows(&cfi, &c, &f).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.address).collect::<Vec<_>>(),
        [0x1000, 0x1010, 0x1110, 0x2110]
    );
    // set_loc (pcrel sdata4: relative to the operand itself).
    let mut e = EhFrame::new();
    let cie = e.cie(b"zR", &[0x1B], &X64_INITIAL);
    let fde = e.fde(cie, 0x1000, 0x100, &[], &[0x01, 0, 0, 0, 0, 0x0E, 0x10]);
    let operand = fde + 4 + 4 + 4 + 4 + 1 + 1;
    let rel = (0x1080u64.wrapping_sub(SECTION + operand as u64)) as u32;
    e.bytes[operand..operand + 4].copy_from_slice(&rel.to_le_bytes());
    let cfi = e.cfi();
    let (c, f) = cfi.find(0x1000).unwrap();
    let rows = cfi::rows(&cfi, &c, &f).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.address).collect::<Vec<_>>(),
        [0x1000, 0x1080]
    );
}

/// An FDE whose CIE pointer leads to an FDE (itself, or the next of a long
/// chain of them) is malformed: it fails, without following the chain.
#[test]
fn fdes_naming_fdes_fail_without_recursing() {
    // Each FDE's pointer names the one before it; the first names itself.
    let mut bytes = Vec::new();
    for i in 0..100_000u32 {
        let at = bytes.len() as u32;
        let pointer: u32 = if i == 0 { 4 } else { 4 + 16 };
        bytes.extend(12u32.to_le_bytes());
        bytes.extend(pointer.to_le_bytes());
        bytes.extend([0u8; 8]);
        assert_eq!(bytes.len() as u32, at + 16);
    }
    let handle = std::thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || {
            let last = bytes.len() - 16;
            let frame = EhFrame { bytes };
            let cfi = frame.cfi();
            assert!(cfi.entry_at(0).is_none());
            assert!(cfi.entry_at(last).is_none());
            cfi.entries().count()
        })
        .unwrap();
    assert_eq!(handle.join().unwrap(), 0);
}

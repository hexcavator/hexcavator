//! DWARF expression evaluation.

use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::expr::{ExprContext, ExprError, evaluate, registers_read};

/// Registers r = 0x1000 * (r + 1); memory holds each address plus 1.
struct Machine;

impl ExprContext for Machine {
    fn register(&self, register: u16) -> Option<u64> {
        (register < 32).then(|| 0x1000 * (u64::from(register) + 1))
    }
    fn memory(&self, address: u64, size: u8) -> Option<u64> {
        if address == 0xDEAD {
            return None;
        }
        let v = address + 1;
        Some(if size >= 8 {
            v
        } else {
            v & ((1 << (8 * u32::from(size))) - 1)
        })
    }
    fn cfa(&self) -> Option<u64> {
        Some(0x7000)
    }
}

fn eval(expr: &[u8]) -> Result<u64, ExprError> {
    evaluate(expr, Endian::Little, 8, &[], &Machine)
}

fn eval32(expr: &[u8]) -> Result<u64, ExprError> {
    evaluate(expr, Endian::Little, 4, &[], &Machine)
}

#[test]
fn constants() {
    assert_eq!(eval(&[0x30]), Ok(0));
    assert_eq!(eval(&[0x4F]), Ok(31));
    assert_eq!(eval(&[0x08, 0xFF]), Ok(0xFF));
    assert_eq!(eval(&[0x09, 0xFF]), Ok(u64::MAX));
    assert_eq!(eval(&[0x0A, 0x34, 0x12]), Ok(0x1234));
    assert_eq!(eval(&[0x0B, 0xFE, 0xFF]), Ok(-2i64 as u64));
    assert_eq!(eval(&[0x0C, 0x78, 0x56, 0x34, 0x12]), Ok(0x1234_5678));
    assert_eq!(eval(&[0x0D, 0xFF, 0xFF, 0xFF, 0xFF]), Ok(u64::MAX));
    assert_eq!(
        eval(&[0x0E, 1, 2, 3, 4, 5, 6, 7, 8]),
        Ok(0x0807_0605_0403_0201)
    );
    assert_eq!(eval(&[0x10, 0xE5, 0x8E, 0x26]), Ok(624_485));
    assert_eq!(eval(&[0x11, 0x7F]), Ok(u64::MAX));
    assert_eq!(eval(&[0x03, 1, 0, 0, 0, 0, 0, 0, 0]), Ok(1));
    assert_eq!(
        evaluate(&[0x03, 1, 0, 0, 0], Endian::Little, 4, &[], &Machine),
        Ok(1)
    );
    assert_eq!(
        evaluate(&[0x0A, 0x12, 0x34], Endian::Big, 8, &[], &Machine),
        Ok(0x1234)
    );
}

#[test]
fn stack_operations() {
    // dup, drop, over, pick, swap, rot.
    assert_eq!(eval(&[0x31, 0x12, 0x22]), Ok(2));
    assert_eq!(eval(&[0x31, 0x32, 0x13]), Ok(1));
    assert_eq!(eval(&[0x31, 0x32, 0x14]), Ok(1));
    assert_eq!(eval(&[0x31, 0x32, 0x33, 0x15, 0x02]), Ok(1));
    assert_eq!(eval(&[0x31, 0x32, 0x16]), Ok(1));
    // rot: (1, 2, 3) -> (3, 1, 2): top is 2.
    assert_eq!(eval(&[0x31, 0x32, 0x33, 0x17]), Ok(2));
    assert_eq!(eval(&[0x31, 0x32, 0x33, 0x17, 0x13]), Ok(1));
    // An initial value (the CFA, for CFI).
    assert_eq!(
        evaluate(&[0x23, 0x10], Endian::Little, 8, &[0x100], &Machine),
        Ok(0x110)
    );
    assert_eq!(evaluate(&[], Endian::Little, 8, &[5], &Machine), Ok(5));
}

#[test]
fn arithmetic() {
    let bin = |a: u8, b: u8, op: u8| eval(&[0x08, a, 0x08, b, op]);
    assert_eq!(bin(12, 10, 0x1A), Ok(8)); // and
    assert_eq!(bin(12, 10, 0x21), Ok(14)); // or
    assert_eq!(bin(12, 10, 0x27), Ok(6)); // xor
    assert_eq!(bin(12, 10, 0x22), Ok(22)); // plus
    assert_eq!(bin(12, 10, 0x1C), Ok(2)); // minus
    assert_eq!(bin(10, 12, 0x1C), Ok(-2i64 as u64));
    assert_eq!(bin(12, 10, 0x1E), Ok(120)); // mul
    assert_eq!(bin(12, 5, 0x1B), Ok(2)); // div
    assert_eq!(bin(12, 5, 0x1D), Ok(2)); // mod
    assert_eq!(bin(1, 4, 0x24), Ok(16)); // shl
    assert_eq!(bin(16, 4, 0x25), Ok(1)); // shr
    assert_eq!(bin(1, 64, 0x24), Ok(0));
    assert_eq!(eval(&[0x11, 0x70, 0x31, 0x26]), Ok(-8i64 as u64)); // -16 shra 1
    assert_eq!(eval(&[0x11, 0x70, 0x31, 0x25]), Ok(u64::MAX >> 1 & !7)); // -16 shr 1
    assert_eq!(eval(&[0x11, 0x7D, 0x19]), Ok(3)); // abs -3
    assert_eq!(eval(&[0x33, 0x1F]), Ok(-3i64 as u64)); // neg
    assert_eq!(eval(&[0x30, 0x20]), Ok(u64::MAX)); // not
    // Signed division and comparisons.
    assert_eq!(eval(&[0x11, 0x74, 0x32, 0x1B]), Ok(-6i64 as u64)); // -12 / 2
    assert_eq!(eval(&[0x11, 0x7F, 0x31, 0x2D]), Ok(1)); // -1 < 1
    for (op, expected) in [
        (0x29, 0),
        (0x2A, 0),
        (0x2B, 0),
        (0x2C, 1),
        (0x2D, 1),
        (0x2E, 1),
    ] {
        assert_eq!(bin(1, 2, op), Ok(expected), "{op:#x}");
    }
    assert_eq!(bin(1, 0, 0x1B), Err(ExprError::DivisionByZero));
    assert_eq!(bin(1, 0, 0x1D), Err(ExprError::DivisionByZero));
}

#[test]
fn address_size_wraps() {
    // 32-bit: values wrap to 32 bits, and signs are read at bit 31.
    assert_eq!(eval32(&[0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0x22]), Ok(0));
    assert_eq!(
        eval32(&[0x0C, 0xFE, 0xFF, 0xFF, 0xFF, 0x32, 0x1B]),
        Ok(0xFFFF_FFFF)
    ); // -2 / 2
    assert_eq!(eval32(&[0x11, 0x7F]), Ok(0xFFFF_FFFF));
    assert_eq!(eval32(&[0x0C, 0, 0, 0, 0x80, 0x30, 0x2D]), Ok(1)); // 0x80000000 < 0
}

#[test]
fn registers_and_memory() {
    assert_eq!(eval(&[0x77, 0x08]), Ok(0x8008)); // breg7 +8
    assert_eq!(eval(&[0x70, 0x7F]), Ok(0x0FFF)); // breg0 -1
    assert_eq!(eval(&[0x92, 0x05, 0x10]), Ok(0x6010)); // bregx 5, +16
    assert_eq!(eval(&[0x92, 0x40, 0x00]), Err(ExprError::Register(64)));
    assert_eq!(eval(&[0x77, 0x00, 0x06]), Ok(0x8001)); // deref
    assert_eq!(eval(&[0x0A, 0xFF, 0x12, 0x94, 0x01]), Ok(0x00)); // deref_size 1 of 0x12FF+1
    assert_eq!(
        eval(&[0x0A, 0xAD, 0xDE, 0x06]),
        Err(ExprError::Memory(0xDEAD))
    );
    assert_eq!(eval(&[0x31, 0x94, 0x09]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x9C]), Ok(0x7000)); // call_frame_cfa
}

#[test]
fn branches() {
    // skip over a lit5: lit1.
    assert_eq!(eval(&[0x31, 0x2F, 0x01, 0x00, 0x35]), Ok(1));
    // bra taken (lit1): lit7; not taken (lit0): lit5 then skip.
    assert_eq!(
        eval(&[0x31, 0x28, 0x04, 0x00, 0x35, 0x2F, 0x01, 0x00, 0x37]),
        Ok(7)
    );
    assert_eq!(
        eval(&[0x30, 0x28, 0x04, 0x00, 0x35, 0x2F, 0x01, 0x00, 0x37]),
        Ok(5)
    );
    // A loop: count down from 3 to 0 (dup; bra back while nonzero).
    // lit3; L: lit1; minus; dup; bra L
    assert_eq!(eval(&[0x33, 0x31, 0x1C, 0x12, 0x28, 0xFA, 0xFF]), Ok(0));
    // Branches outside the expression.
    assert_eq!(eval(&[0x2F, 0x10, 0x00]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x2F, 0xF0, 0xFF]), Err(ExprError::Malformed));
    // An endless loop ends.
    assert_eq!(eval(&[0x2F, 0xFD, 0xFF]), Err(ExprError::TooComplex));
    // A stack that grows without bound.
    assert_eq!(
        eval(&[0x30, 0x12, 0x2F, 0xFC, 0xFF]),
        Err(ExprError::TooComplex)
    );
}

#[test]
fn malformed_and_unsupported() {
    assert_eq!(eval(&[]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x22]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x31, 0x16]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x31, 0x32, 0x17]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x31, 0x15, 0x05]), Err(ExprError::Malformed));
    assert_eq!(eval(&[0x0C, 0x01]), Err(ExprError::Malformed));
    for op in [0x50u8, 0x90, 0x91, 0x93, 0x9F, 0xE0, 0xF3, 0xFF] {
        assert_eq!(eval(&[op]), Err(ExprError::Unsupported(op)), "{op:#x}");
    }
    // Every truncation of a long expression: no panics.
    let long = [
        0x77, 0x08, 0x06, 0x0E, 1, 2, 3, 4, 5, 6, 7, 8, 0x22, 0x28, 0x01, 0x00, 0x30, 0x94, 0x04,
    ];
    for n in 0..long.len() {
        let _ = eval(&long[..n]);
    }
}

#[test]
fn registers_read_lists_bregs() {
    let regs = registers_read(
        &[0x77, 0x08, 0x76, 0x7F, 0x22, 0x92, 0x21, 0x00, 0x77, 0x00],
        Endian::Little,
        8,
    );
    assert_eq!(regs, Vec::from([6, 7, 33]));
    // It stops at what it can't step over.
    assert_eq!(
        registers_read(&[0x76, 0x00, 0xE0, 0x77, 0x00], Endian::Little, 8),
        Vec::from([6])
    );
}

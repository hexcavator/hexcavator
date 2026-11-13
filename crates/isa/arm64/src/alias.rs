//! Functions from ARM's pseudocode that the alias conditions and operand
//! formatting need.

/// `DecodeBitMasks`: the (wmask, tmask) of a logical or bitfield
/// immediate, or `None` if the encoding is reserved.
pub(crate) fn decode_bit_masks(
    n: u64,
    imms: u64,
    immr: u64,
    immediate: bool,
    datasize: u32,
) -> Option<(u64, u64)> {
    // The element size is the position of the highest set bit of N:NOT(imms).
    let combined = (n << 6) | (!imms & 0x3F);
    if combined == 0 {
        return None;
    }
    let len = 63 - combined.leading_zeros();
    if len < 1 {
        return None;
    }
    let levels = (1u64 << len) - 1;
    if immediate && (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let diff = s.wrapping_sub(r) & levels;
    let esize = 1u32 << len;
    if esize > datasize {
        return None;
    }
    let ones = |k: u64| if k >= 64 { u64::MAX } else { (1u64 << k) - 1 };
    let welem = ones(s + 1);
    let telem = ones(diff + 1);
    let emask = ones(u64::from(esize));
    let ror = |x: u64, r: u64| {
        let r = r % u64::from(esize);
        if r == 0 {
            x
        } else {
            ((x >> r) | (x << (u64::from(esize) - r))) & emask
        }
    };
    let welem = ror(welem & emask, r);
    let replicate = |e: u64| {
        let mut v = 0u64;
        let mut i = 0;
        while i < datasize {
            v |= e << i;
            i += esize;
        }
        if datasize == 64 {
            v
        } else {
            v & ((1u64 << datasize) - 1)
        }
    };
    Some((replicate(welem), replicate(telem & emask)))
}

pub(crate) fn bfx_preferred(sf: u64, uns: u64, imms: u64, immr: u64) -> bool {
    let _ = uns;
    if imms < immr {
        return false;
    }
    if imms == (sf << 5) | 0x1F {
        return false;
    }
    if immr == 0 {
        if sf == 0 && (imms == 0b000111 || imms == 0b001111) {
            return false;
        }
        if sf == 1 && uns == 0 && matches!(imms, 0b000111 | 0b001111 | 0b011111) {
            return false;
        }
    }
    true
}

pub(crate) fn move_wide_preferred(sf: u64, imm_n: u64, imms: u64, immr: u64) -> bool {
    let s = imms as i64;
    let r = immr as i64;
    let width = if sf == 1 { 64 } else { 32 };
    if sf == 1 && imm_n != 1 {
        return false;
    }
    if sf == 0 && (imm_n != 0 || imms & 0x20 != 0) {
        return false;
    }
    if s < 16 {
        return (-r).rem_euclid(16) <= 15 - s;
    }
    if s >= width - 15 {
        return r.rem_euclid(16) <= s - (width - 15);
    }
    false
}

pub(crate) fn sve_move_mask_preferred(imm13: u64) -> bool {
    let Some((imm, _)) = decode_bit_masks(
        (imm13 >> 12) & 1,
        imm13 & 0x3F,
        (imm13 >> 6) & 0x3F,
        true,
        64,
    ) else {
        return false;
    };
    let bits = |hi: u32, lo: u32| {
        let n = hi - lo + 1;
        (imm >> lo) & if n == 64 { u64::MAX } else { (1u64 << n) - 1 }
    };
    let zero = |hi: u32, lo: u32| bits(hi, lo) == 0;
    let ones = |hi: u32, lo: u32| {
        let n = hi - lo + 1;
        bits(hi, lo) == if n == 64 { u64::MAX } else { (1u64 << n) - 1 }
    };
    let halves = bits(63, 32) == bits(31, 0);
    let quarters = halves && bits(31, 16) == bits(15, 0);
    if zero(7, 0) {
        if zero(63, 15) || ones(63, 15) {
            return false;
        }
        if halves && (zero(31, 7) || ones(31, 7)) {
            return false;
        }
        if quarters {
            return false;
        }
    } else {
        if zero(63, 7) || ones(63, 7) {
            return false;
        }
        if halves && (zero(31, 7) || ones(31, 7)) {
            return false;
        }
        if quarters && (zero(15, 7) || ones(15, 7)) {
            return false;
        }
        if quarters && bits(15, 8) == bits(7, 0) {
            return false;
        }
    }
    true
}

/// `SysOp`: which kind of operation a SYS instruction performs. The
/// values match the constants `build.rs` substitutes: 0 SYS, 1 AT, 2 DC,
/// 3 IC, 4 TLBI.
pub(crate) fn sys_op(op1: u64, crn: u64, crm: u64, op2: u64) -> i64 {
    match (crn, crm) {
        // Address translation.
        (7, 8 | 9) => match (op1, crm, op2) {
            (0, 8, 0..=3) | (0, 9, 0..=1) | (4 | 6, 8, 0..=1) | (4, 8, 4..=7) => 1,
            _ => 0,
        },
        // Instruction cache.
        (7, 1) if op1 == 0 && op2 == 0 => 3,
        (7, 5) if (op1 == 0 && op2 == 0) || (op1 == 3 && op2 == 1) => 3,
        // Data cache.
        (7, 4) if op1 == 3 && op2 == 1 => 2,
        (7, 6) if op1 == 0 && (1..=6).contains(&op2) => 2,
        (7, 10)
            if (op1 == 0 && matches!(op2, 2 | 4 | 6)) || (op1 == 3 && (1..=5).contains(&op2)) =>
        {
            2
        }
        (7, 11..=13) if op1 == 3 => 2,
        (7, 14)
            if (op1 == 0 && matches!(op2, 2 | 4 | 6)) || (op1 == 3 && (1..=5).contains(&op2)) =>
        {
            2
        }
        // TLB maintenance.
        (8 | 9, _) if matches!(op1, 0 | 4 | 6) => 4,
        _ => 0,
    }
}

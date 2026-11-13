//! Little-endian reads at fixed offsets of a slice the caller has already
//! checked is long enough. Each panics on a short slice, so callers check
//! lengths first (and the fuzzer holds them to it).

#[inline]
pub(crate) fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

#[inline]
pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

#[inline]
pub(crate) fn i64_at(b: &[u8], at: usize) -> i64 {
    u64_at(b, at) as i64
}

#[inline]
pub(crate) fn guid_at(b: &[u8], at: usize) -> crate::Guid {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    crate::Guid::from_bytes(&a)
}

/// Rounds `n` up to a multiple of 8, or `None` on overflow.
#[inline]
pub(crate) fn align8(n: usize) -> Option<usize> {
    n.checked_add(7).map(|n| n & !7)
}

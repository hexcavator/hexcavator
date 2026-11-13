//! Arm's exception handling ABI (EHABI) tables: `.ARM.exidx`, each
//! function's entry (its address, and how it unwinds: not at all, by
//! opcodes inline, or by an `.ARM.extab` entry), in a linked image.
//!
//! Bounded: at most 2^20 entries.

use alloc::vec::Vec;

use crate::consts::*;
use crate::{ElfFile, Section, read_u32};

/// How an exception index entry's function unwinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExidxUnwind {
    /// `EXIDX_CANTUNWIND`: it doesn't.
    CantUnwind,
    /// By up to three opcodes inline, with personality routine
    /// `__aeabi_unwind_cpp_pr0` (its index, 0 to 2, is in the word).
    Inline(u32),
    /// By the `.ARM.extab` entry at this address.
    Table(u64),
}

/// An exception index entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExidxEntry {
    /// Its function's address.
    pub function: u64,
    pub unwind: ExidxUnwind,
}

pub const EXIDX_CANTUNWIND: u32 = 1;

/// A prel31 value at `place`: a 31-bit signed offset from it.
fn prel31(place: u64, word: u32) -> u64 {
    let offset = i64::from(((word << 1) as i32) >> 1);
    place.wrapping_add(offset as u64)
}

impl ElfFile<'_> {
    /// The entries of `.ARM.exidx` (`s`, an `SHT_ARM_EXIDX` section), by
    /// function. (In an object, the function offsets are relocations'
    /// to fill: these are of linked images.)
    pub fn arm_exidx(&self, s: &Section<'_>) -> Vec<ExidxEntry> {
        let mut out = Vec::new();
        if s.kind != SHT_ARM_EXIDX || !s.has_file_data() {
            return out;
        }
        let data = self.section_data(s);
        let e = self.endian();
        let count = (data.len() / 8).min(1 << 20);
        for i in 0..count as u64 {
            let (Some(f), Some(v)) = (read_u32(data, i * 8, e), read_u32(data, i * 8 + 4, e))
            else {
                break;
            };
            let place = s.addr.wrapping_add(i * 8);
            let unwind = if v == EXIDX_CANTUNWIND {
                ExidxUnwind::CantUnwind
            } else if v & 0x8000_0000 != 0 {
                ExidxUnwind::Inline(v)
            } else {
                ExidxUnwind::Table(prel31(place + 4, v))
            };
            out.push(ExidxEntry {
                function: prel31(place, f & 0x7FFF_FFFF),
                unwind,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prel31_offsets() {
        assert_eq!(prel31(0x1000, 0x10), 0x1010);
        // Negative: the 31st bit is the sign.
        assert_eq!(prel31(0x1000, 0x7FFF_FFF0), 0x0FF0);
        assert_eq!(prel31(0, 0x4000_0000), (-0x4000_0000i64) as u64);
    }
}

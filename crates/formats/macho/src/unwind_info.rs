//! `__TEXT,__unwind_info`: the linker's two-level index of each
//! function's compact unwind encoding (Darwin's alternative to DWARF call
//! frame information; the encodings' meaning is the unwinder's business).
//!
//! The first level lists pages by their first function; each second-level
//! page is either regular (function offset, encoding) or compressed (a
//! 24-bit offset from the page's first function and an 8-bit index into
//! the common encodings or the page's own). Function offsets are from the
//! image's base (its `__TEXT` segment). Malformed data gives `None` or
//! fewer entries, never a panic.

use alloc::vec::Vec;

use hexcavator_core::Endian;

/// `UNWIND_IS_NOT_FUNCTION_START`, `UNWIND_HAS_LSDA`,
/// `UNWIND_PERSONALITY_MASK`.
pub const IS_NOT_FUNCTION_START: u32 = 0x8000_0000;
pub const HAS_LSDA: u32 = 0x4000_0000;
pub const PERSONALITY_MASK: u32 = 0x3000_0000;

const REGULAR: u32 = 2;
const COMPRESSED: u32 = 3;

/// A function's entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its start, from the image base.
    pub function: u32,
    pub encoding: u32,
}

/// The entry for an address, and where its function (as the index sees
/// it) ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub entry: Entry,
    pub end: u32,
}

/// A parsed `__unwind_info` section.
#[derive(Clone, Copy, Debug)]
pub struct UnwindInfo<'d> {
    data: &'d [u8],
    endian: Endian,
    common: (u32, u32),
    personalities: (u32, u32),
    index: (u32, u32),
}

impl<'d> UnwindInfo<'d> {
    /// Parses the section's header (version 1 only).
    pub fn parse(data: &'d [u8], endian: Endian) -> Option<Self> {
        let u = Self {
            data,
            endian,
            common: (0, 0),
            personalities: (0, 0),
            index: (0, 0),
        };
        if u.u32(0)? != 1 {
            return None;
        }
        Some(Self {
            common: (u.u32(4)?, u.u32(8)?),
            personalities: (u.u32(12)?, u.u32(16)?),
            index: (u.u32(20)?, u.u32(24)?),
            ..u
        })
    }

    fn u32(&self, at: u32) -> Option<u32> {
        let at = usize::try_from(at).ok()?;
        let b: [u8; 4] = self.data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    fn u16(&self, at: u32) -> Option<u16> {
        let at = usize::try_from(at).ok()?;
        let b: [u8; 2] = self.data.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    /// The common encodings.
    pub fn common_encodings(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.common.1)
            .map_while(move |i| self.u32(self.common.0.checked_add(i.checked_mul(4)?)?))
    }

    /// The personality routines: each the offset (from the image base) of
    /// the pointer to one. An encoding's `PERSONALITY_MASK` bits, if not
    /// zero, are an index here plus one.
    pub fn personalities(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.personalities.1)
            .map_while(move |i| self.u32(self.personalities.0.checked_add(i.checked_mul(4)?)?))
    }

    /// First-level entry `i`: (first function, page offset, LSDA index
    /// offset).
    fn first(&self, i: u32) -> Option<(u32, u32, u32)> {
        let at = self.index.0.checked_add(i.checked_mul(12)?)?;
        Some((
            self.u32(at)?,
            self.u32(at.checked_add(4)?)?,
            self.u32(at.checked_add(8)?)?,
        ))
    }

    /// Page `i`'s entries (`i` below the index count minus one: the last
    /// first-level entry only marks the end).
    fn page(&self, i: u32) -> Option<Page> {
        let (base, offset, _) = self.first(i)?;
        if offset == 0 {
            return None;
        }
        let kind = self.u32(offset)?;
        let entries = offset.checked_add(u32::from(self.u16(offset.checked_add(4)?)?))?;
        let count = u32::from(self.u16(offset.checked_add(6)?)?);
        match kind {
            REGULAR => Some(Page {
                compressed: false,
                base,
                entries,
                count,
                encodings: 0,
                encoding_count: 0,
            }),
            COMPRESSED => Some(Page {
                compressed: true,
                base,
                entries,
                count,
                encodings: offset.checked_add(u32::from(self.u16(offset.checked_add(8)?)?))?,
                encoding_count: u32::from(self.u16(offset.checked_add(10)?)?),
            }),
            _ => None,
        }
    }

    fn page_entry(&self, page: &Page, j: u32) -> Option<Entry> {
        if page.compressed {
            let word = self.u32(page.entries.checked_add(j.checked_mul(4)?)?)?;
            let index = word >> 24;
            let encoding = if index < self.common.1 {
                self.u32(self.common.0.checked_add(index * 4)?)?
            } else {
                let k = index - self.common.1;
                if k >= page.encoding_count {
                    return None;
                }
                self.u32(page.encodings.checked_add(k * 4)?)?
            };
            Some(Entry {
                function: page.base.checked_add(word & 0x00FF_FFFF)?,
                encoding,
            })
        } else {
            let at = page.entries.checked_add(j.checked_mul(8)?)?;
            Some(Entry {
                function: self.u32(at)?,
                encoding: self.u32(at.checked_add(4)?)?,
            })
        }
    }

    /// Every entry, in order.
    pub fn entries(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        for i in 0..self.index.1.saturating_sub(1) {
            // (An index entry that isn't there ends the index: a hostile
            // count can't make this loop for long.)
            if self.first(i).is_none() {
                break;
            }
            let Some(page) = self.page(i) else { continue };
            for j in 0..page.count {
                match self.page_entry(&page, j) {
                    Some(e) => out.push(e),
                    None => break,
                }
            }
        }
        out
    }

    /// The entry covering `function_offset` (from the image base).
    pub fn lookup(&self, function_offset: u32) -> Option<Found> {
        let pages = self.index.1.checked_sub(1)?;
        // The last page starting at or before it.
        let (mut lo, mut hi) = (0u32, pages);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.first(mid)?.0 <= function_offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let i = lo.checked_sub(1)?;
        let page_end = self.first(i + 1)?.0;
        if function_offset >= page_end {
            return None;
        }
        let page = self.page(i)?;
        let (mut lo, mut hi) = (0u32, page.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.page_entry(&page, mid)?.function <= function_offset {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let j = lo.checked_sub(1)?;
        let entry = self.page_entry(&page, j)?;
        let end = if j + 1 < page.count {
            self.page_entry(&page, j + 1)?.function
        } else {
            page_end
        };
        Some(Found { entry, end })
    }

    /// The LSDA of the function starting at `function` (from the image
    /// base), if the index lists one.
    pub fn lsda(&self, function: u32) -> Option<u32> {
        let pages = self.index.1.checked_sub(1)?;
        let (start, end) = (self.first(0)?.2, self.first(pages)?.2);
        let count = end.checked_sub(start)? / 8;
        let (mut lo, mut hi) = (0u32, count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let at = start.checked_add(mid * 8)?;
            let f = self.u32(at)?;
            if f == function {
                return self.u32(at.checked_add(4)?);
            }
            if f < function {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
struct Page {
    compressed: bool,
    /// The page's first function (compressed offsets are from it).
    base: u32,
    entries: u32,
    count: u32,
    encodings: u32,
    encoding_count: u32,
}

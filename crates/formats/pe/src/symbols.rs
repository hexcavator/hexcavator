//! The COFF symbol table and string table.
//!
//! Records are 18 bytes (`IMAGE_SYMBOL`), or 20 in `/bigobj` objects
//! (`IMAGE_SYMBOL_EX`, with a 32-bit section number); auxiliary records are
//! the same size as the symbols they follow.

use hexcavator_core::{U32Le, bytes_at, cstr_at, read_at};

use crate::consts::storage_class;

/// The COFF string table, which holds long section and symbol names.
///
/// Offsets into it count from the start of its 4-byte size field.
#[derive(Clone, Copy, Debug, Default)]
pub struct StringTable<'data> {
    data: &'data [u8],
}

impl<'data> StringTable<'data> {
    /// Locates the string table at `offset` in `file`. A missing or
    /// malformed table yields an empty one, since it is only consulted for
    /// names that refer to it.
    pub fn parse(file: &'data [u8], offset: u64) -> Self {
        let data = read_at::<U32Le>(file, offset)
            .ok()
            .and_then(|size| {
                // Clamp a truncated table rather than discarding it.
                let size = u64::from(size.get()).min((file.len() as u64).saturating_sub(offset));
                bytes_at(file, offset, size).ok()
            })
            .unwrap_or_default();
        Self { data }
    }

    /// The NUL-terminated string at `offset`.
    pub fn get(&self, offset: u32) -> Option<&'data [u8]> {
        if offset < 4 {
            return None;
        }
        cstr_at(self.data, u64::from(offset)).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() <= 4
    }

    /// The table's size, its size field included.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// One primary symbol record and its auxiliary records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoffSymbol<'data> {
    /// Its index in the table (counting auxiliary records).
    pub index: usize,
    /// The name field: the name (padded with NULs), or four zero bytes and
    /// an offset into the string table.
    pub raw_name: &'data [u8],
    pub value: u32,
    /// 1-based section number, or 0 (undefined), -1 (absolute), -2 (debug).
    pub section: i32,
    pub kind: u16,
    pub storage_class: u8,
    /// The auxiliary records, each the size of a symbol record.
    aux: &'data [u8],
    stride: usize,
}

/// A section definition's auxiliary record (`IMAGE_AUX_SYMBOL.Section`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionDefinition {
    pub length: u32,
    pub relocations: u16,
    pub line_numbers: u16,
    pub checksum: u32,
    /// For an associative COMDAT, the 1-based number of the section it is
    /// associated with (its high 16 bits from `HighNumber` in `/bigobj`).
    pub number: u32,
    /// `IMAGE_COMDAT_SELECT_*`, for COMDAT sections.
    pub selection: u8,
}

/// `IMAGE_COMDAT_SELECT_*` values.
pub mod comdat_select {
    pub const NODUPLICATES: u8 = 1;
    pub const ANY: u8 = 2;
    pub const SAME_SIZE: u8 = 3;
    pub const EXACT_MATCH: u8 = 4;
    pub const ASSOCIATIVE: u8 = 5;
    pub const LARGEST: u8 = 6;
}

impl<'data> CoffSymbol<'data> {
    /// The number of auxiliary records.
    pub fn aux_count(&self) -> usize {
        self.aux.len() / self.stride
    }

    /// The auxiliary records' bytes, one record each.
    pub fn aux(&self) -> impl Iterator<Item = &'data [u8]> + 'data {
        self.aux.chunks_exact(self.stride)
    }

    /// The section definition, if this is a section's symbol (static, value
    /// 0, with an auxiliary record).
    pub fn section_definition(&self) -> Option<SectionDefinition> {
        if self.storage_class != storage_class::STATIC || self.value != 0 || self.section <= 0 {
            return None;
        }
        let a = self.aux().next()?;
        let u16_at = |o: usize| u16::from_le_bytes([a[o], a[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([a[o], a[o + 1], a[o + 2], a[o + 3]]);
        Some(SectionDefinition {
            length: u32_at(0),
            relocations: u16_at(4),
            line_numbers: u16_at(6),
            checksum: u32_at(8),
            number: u32::from(u16_at(12)) | (u32::from(u16_at(16)) << 16),
            selection: a[14],
        })
    }
}

/// The COFF symbol table of an object (or, rarely, an image).
#[derive(Clone, Copy, Debug, Default)]
pub struct SymbolTable<'data> {
    /// The records (`count` × `stride` bytes, or fewer if truncated).
    data: &'data [u8],
    stride: usize,
    strings: StringTable<'data>,
}

impl<'data> SymbolTable<'data> {
    /// The table at `offset` in `file` of `count` records of 18 bytes, or
    /// 20 if `big`. A truncated table keeps the records that fit; the
    /// string table follows the records.
    pub(crate) fn parse(
        file: &'data [u8],
        offset: u64,
        count: u64,
        big: bool,
    ) -> hexcavator_core::Result<Self> {
        let stride: usize = if big { 20 } else { 18 };
        let size = count.saturating_mul(stride as u64);
        let data = bytes_at(file, offset, size)?;
        let strings = StringTable::parse(file, offset.saturating_add(size));
        Ok(Self {
            data,
            stride,
            strings,
        })
    }

    /// The number of records, auxiliary records included.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len() / self.stride.max(1)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The size of each record (18, or 20 for `/bigobj`).
    pub fn record_size(&self) -> usize {
        self.stride
    }

    #[inline]
    pub fn strings(&self) -> StringTable<'data> {
        self.strings
    }

    /// The record at `index` (counting auxiliary records), read as a
    /// primary symbol, with the auxiliary records it claims (as many as
    /// remain).
    pub fn get(&self, index: usize) -> Option<CoffSymbol<'data>> {
        let s = self.stride;
        let r = self.data.get(index.checked_mul(s)?..)?.get(..s)?;
        let section = if s == 20 {
            i32::from_le_bytes([r[12], r[13], r[14], r[15]])
        } else {
            i32::from(i16::from_le_bytes([r[12], r[13]]))
        };
        let tail = s - 4; // kind (2), storage class, aux count
        let aux_count = usize::from(r[tail + 3]);
        let aux_start = (index + 1) * s;
        let aux_end = aux_start
            .saturating_add(aux_count * s)
            .min(self.data.len() / s * s);
        Some(CoffSymbol {
            index,
            raw_name: &r[..8],
            value: u32::from_le_bytes([r[8], r[9], r[10], r[11]]),
            section,
            kind: u16::from_le_bytes([r[tail], r[tail + 1]]),
            storage_class: r[tail + 2],
            aux: self.data.get(aux_start..aux_end).unwrap_or(&[]),
            stride: s,
        })
    }

    /// The primary symbols, skipping auxiliary records.
    pub fn iter(&self) -> impl Iterator<Item = CoffSymbol<'data>> + 'data {
        let table = *self;
        let mut index = 0;
        core::iter::from_fn(move || {
            let symbol = table.get(index)?;
            index = index + 1 + symbol.aux_count();
            Some(symbol)
        })
    }

    /// A symbol's name.
    pub fn name(&self, symbol: &CoffSymbol<'data>) -> Option<&'data [u8]> {
        let n = symbol.raw_name;
        if n[..4] == [0; 4] {
            self.strings
                .get(u32::from_le_bytes([n[4], n[5], n[6], n[7]]))
        } else {
            let len = n.iter().position(|&b| b == 0).unwrap_or(8);
            Some(&n[..len])
        }
    }

    /// The COMDAT symbol of the 1-based section `section`: the first symbol
    /// defined in that section after its section-definition symbol.
    pub fn comdat_symbol(&self, section: i32) -> Option<CoffSymbol<'data>> {
        let mut seen_definition = false;
        for symbol in self.iter() {
            if symbol.section != section {
                continue;
            }
            if !seen_definition && symbol.section_definition().is_some() {
                seen_definition = true;
            } else if seen_definition {
                return Some(symbol);
            }
        }
        None
    }

    /// The COMDAT symbols of every section, by 1-based section number, in
    /// one pass (index 0 unused).
    pub fn comdat_symbols(&self, sections: usize) -> alloc::vec::Vec<Option<CoffSymbol<'data>>> {
        let mut out = alloc::vec![None; sections + 1];
        let mut defined = alloc::vec![false; sections + 1];
        for symbol in self.iter() {
            let Ok(n) = usize::try_from(symbol.section) else {
                continue;
            };
            if n == 0 || n > sections {
                continue;
            }
            if !defined[n] && symbol.section_definition().is_some() {
                defined[n] = true;
            } else if defined[n] && out[n].is_none() {
                out[n] = Some(symbol);
            }
        }
        out
    }
}

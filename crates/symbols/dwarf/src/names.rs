//! Name indexes (`.debug_names`, DWARF 5): for each name, the DIEs that
//! have it (their tags, units, offsets, and parents), as an accelerator
//! table for finding a DIE by name without reading the units.
//!
//! Bounded: at most 2^20 names, entries, and abbreviations per index.
//! Damage ends an index (or a list).

use alloc::vec::Vec;

use crate::consts::*;
use crate::{Reader, Sections};

const MAX: usize = 1 << 20;

/// One entry of an index: a DIE with the name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexEntry {
    pub tag: u16,
    /// The DIE's offset in `.debug_info` (its unit's offset added).
    pub die_offset: Option<u64>,
    /// The unit's index in the index's compile units (or type units).
    pub compile_unit: Option<u64>,
    pub type_unit: Option<u64>,
    /// The parent's entry (its offset in the entry pool), if indexed.
    pub parent: Option<u64>,
    pub type_hash: Option<u64>,
}

/// A name, and its entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedName<'d> {
    pub name: &'d [u8],
    /// Its hash, if the index has a hash table (the DJB hash).
    pub hash: Option<u32>,
    pub entries: Vec<IndexEntry>,
}

/// A name index: its units, and its names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameIndex<'d> {
    pub version: u16,
    /// The compile units' and local type units' `.debug_info` offsets,
    /// and the foreign type units' signatures.
    pub compile_units: Vec<u64>,
    pub local_type_units: Vec<u64>,
    pub foreign_type_units: Vec<u64>,
    pub augmentation: &'d [u8],
    pub names: Vec<IndexedName<'d>>,
}

/// The hash `.debug_names` hashes names with: DJB's, of the name case
/// folded (DWARF 5's section 7.33, so that case-insensitive languages'
/// names can be looked up): each character's simple lowercase, and the
/// Turkish dotted and dotless capital and small i as `i` (as LLVM folds
/// them). Bytes that aren't UTF-8 are hashed as they are.
pub fn names_hash(name: &[u8]) -> u32 {
    let mut h = 5381u32;
    let mut add = |b: u8| h = h.wrapping_mul(33).wrapping_add(u32::from(b));
    let mut rest = name;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(s) => {
                fold(s, &mut add);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                fold(core::str::from_utf8(good).unwrap_or(""), &mut add);
                let n = e.error_len().unwrap_or(bad.len()).max(1);
                for &b in &bad[..n] {
                    add(b);
                }
                rest = &bad[n..];
            }
        }
    }
    h
}

fn fold(s: &str, add: &mut impl FnMut(u8)) {
    let mut buf = [0u8; 4];
    for c in s.chars() {
        let folded = match c {
            '\u{130}' | '\u{131}' => 'i',
            c => {
                let mut l = c.to_lowercase();
                match (l.next(), l.next()) {
                    (Some(one), None) => one,
                    _ => c,
                }
            }
        };
        for &b in folded.encode_utf8(&mut buf).as_bytes() {
            add(b);
        }
    }
}

/// An index abbreviation: its tag, and its attributes' (index, form).
struct Abbrev {
    code: u64,
    tag: u16,
    attrs: Vec<(u16, u16)>,
}

/// Every name index of `.debug_names`.
pub fn name_indexes<'d>(s: &Sections<'d>) -> Vec<NameIndex<'d>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < s.names.len() && out.len() < 1 << 16 {
        let Some((index, next)) = name_index(s, pos) else {
            break;
        };
        out.push(index);
        if next <= pos {
            break;
        }
        pos = next;
    }
    out
}

fn name_index<'d>(s: &Sections<'d>, pos: usize) -> Option<(NameIndex<'d>, usize)> {
    let mut r = Reader::new(s.names, pos, s.endian);
    let (_, end, dwarf64) = r.initial_length()?;
    let data = s.names.get(..end)?;
    r.data = data;
    let w: usize = if dwarf64 { 8 } else { 4 };
    let version = u16::try_from(r.uint(2)?).ok()?;
    r.uint(2)?;
    let counts: Vec<usize> = (0..7)
        .map(|_| r.uint(4).and_then(|v| usize::try_from(v).ok()))
        .collect::<Option<_>>()?;
    let [cus, ltus, ftus, buckets, names, abbrev_size, aug_size] = counts[..] else {
        return None;
    };
    let augmentation = r.bytes(aug_size as u64)?;
    // (The augmentation string is padded to four bytes.)
    r.bytes(((4 - aug_size % 4) % 4) as u64)?;
    let list = |r: &mut Reader<'d>, n: usize, width: usize| -> Option<Vec<u64>> {
        (0..n.min(MAX)).map(|_| r.uint(width)).collect()
    };
    let compile_units = list(&mut r, cus, w)?;
    let local_type_units = list(&mut r, ltus, w)?;
    let foreign_type_units = list(&mut r, ftus, 8)?;
    let names_n = names.min(MAX);
    // The hash table: buckets, then a hash for each name.
    r.bytes((buckets as u64).checked_mul(4)?)?;
    let hashes = if buckets > 0 {
        Some(list(&mut r, names_n, 4)?)
    } else {
        None
    };
    let strings = list(&mut r, names_n, w)?;
    let entry_offsets = list(&mut r, names_n, w)?;
    // The abbreviations.
    let abbrev_end = r.pos.checked_add(abbrev_size)?;
    let mut abbrevs = Vec::new();
    while r.pos < abbrev_end && abbrevs.len() < MAX {
        let code = r.uleb()?;
        if code == 0 {
            break;
        }
        let tag = u16::try_from(r.uleb()?).ok()?;
        let mut attrs = Vec::new();
        loop {
            let (index, form) = (r.uleb()?, r.uleb()?);
            if index == 0 && form == 0 {
                break;
            }
            attrs.push((u16::try_from(index).ok()?, u16::try_from(form).ok()?));
            if attrs.len() > 64 {
                return None;
            }
        }
        abbrevs.push(Abbrev { code, tag, attrs });
    }
    let pool = abbrev_end;
    let mut out_names = Vec::with_capacity(names_n);
    for i in 0..names_n {
        let name = Reader::new(s.str, usize::try_from(strings[i]).ok()?, s.endian)
            .cstr()
            .unwrap_or(&[]);
        let mut e = Reader::new(
            data,
            pool.checked_add(usize::try_from(entry_offsets[i]).ok()?)?,
            s.endian,
        );
        let mut entries = Vec::new();
        while entries.len() < MAX {
            let Some(code) = e.uleb() else { break };
            if code == 0 {
                break;
            }
            let Some(a) = abbrevs.iter().find(|a| a.code == code) else {
                break;
            };
            let mut entry = IndexEntry {
                tag: a.tag,
                ..IndexEntry::default()
            };
            let mut ok = true;
            for &(index, form) in &a.attrs {
                let value = match form {
                    DW_FORM_FLAG_PRESENT => Some(u64::MAX),
                    DW_FORM_DATA1 | DW_FORM_REF1 | DW_FORM_FLAG => e.uint(1),
                    DW_FORM_DATA2 | DW_FORM_REF2 => e.uint(2),
                    DW_FORM_DATA4 | DW_FORM_REF4 => e.uint(4),
                    DW_FORM_DATA8 | DW_FORM_REF8 | DW_FORM_REF_SIG8 => e.uint(8),
                    DW_FORM_UDATA | DW_FORM_REF_UDATA => e.uleb(),
                    _ => None,
                };
                let Some(value) = value else {
                    ok = false;
                    break;
                };
                match index {
                    DW_IDX_COMPILE_UNIT => entry.compile_unit = Some(value),
                    DW_IDX_TYPE_UNIT => entry.type_unit = Some(value),
                    DW_IDX_DIE_OFFSET => entry.die_offset = Some(value),
                    // (A flag: the parent isn't indexed.)
                    DW_IDX_PARENT if form != DW_FORM_FLAG_PRESENT => entry.parent = Some(value),
                    DW_IDX_TYPE_HASH => entry.type_hash = Some(value),
                    _ => {}
                }
            }
            if !ok {
                break;
            }
            // With one compile unit (and no type unit named), it's that one;
            // offsets are from the unit's start.
            if entry.compile_unit.is_none() && entry.type_unit.is_none() && compile_units.len() == 1
            {
                entry.compile_unit = Some(0);
            }
            let unit = match (entry.type_unit, entry.compile_unit) {
                (Some(t), _) => local_type_units.get(usize::try_from(t).ok()?).copied(),
                (None, Some(c)) => compile_units.get(usize::try_from(c).ok()?).copied(),
                _ => None,
            };
            entry.die_offset = match (entry.die_offset, unit) {
                (Some(d), Some(u)) => u.checked_add(d),
                (d, _) => d,
            };
            entries.push(entry);
        }
        out_names.push(IndexedName {
            name,
            hash: hashes.as_ref().and_then(|h| u32::try_from(h[i]).ok()),
            entries,
        });
    }
    Some((
        NameIndex {
            version,
            compile_units,
            local_type_units,
            foreign_type_units,
            augmentation,
            names: out_names,
        },
        end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_fold_case() {
        // Values from llvm-dwarfdump's listing of clang's index.
        assert_eq!(names_hash(b"int"), 0x0B88_8030);
        assert_eq!(names_hash(b"_ZN7DerivedD0Ev"), 0xF168_8595);
        assert_eq!(names_hash(b"Padded"), names_hash(b"padded"));
        assert_eq!(names_hash("\u{130}".as_bytes()), names_hash(b"i"));
        assert_eq!(
            names_hash("\u{C9}t\u{C9}".as_bytes()),
            names_hash("\u{E9}t\u{E9}".as_bytes())
        );
        assert_eq!(names_hash(b""), 5381);
        // Not UTF-8: as bytes.
        let _ = names_hash(&[0xFF, b'A', 0xC3]);
    }
}

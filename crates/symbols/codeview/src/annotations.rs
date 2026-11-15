//! Inline sites' binary annotations: the code an inlined copy of a function
//! occupies (as offsets from its enclosing function's start) and the source
//! lines it came from.
//!
//! Each annotation is an opcode and one or two compressed integers (one to
//! four bytes, by their first byte's top bits; signed ones keep their sign
//! in the low bit). The code offset starts at 0 and moves by them, and each
//! move starts a line entry: its code runs to the next entry's start, or
//! for a length an annotation gives (cvinfo.h: "length of code, default
//! next start"). A length given after an entry moves the code offset to its
//! end; one given with a jump (`BA_OP_ChangeCodeLengthAndCodeOffset`, which
//! MSVC emits) leaves it at the entry's start. A site's code is its
//! entries'; a nested site's code is within its caller's (DIA's reading).

use hexcavator_core::Reader;

/// The opcodes (`BinaryAnnotationOpcode`: `BA_OP_*`).
pub mod op {
    pub const BA_OP_INVALID: u32 = 0;
    pub const BA_OP_CODE_OFFSET: u32 = 1;
    pub const BA_OP_CHANGE_CODE_OFFSET_BASE: u32 = 2;
    pub const BA_OP_CHANGE_CODE_OFFSET: u32 = 3;
    pub const BA_OP_CHANGE_CODE_LENGTH: u32 = 4;
    pub const BA_OP_CHANGE_FILE: u32 = 5;
    pub const BA_OP_CHANGE_LINE_OFFSET: u32 = 6;
    pub const BA_OP_CHANGE_LINE_END_DELTA: u32 = 7;
    pub const BA_OP_CHANGE_RANGE_KIND: u32 = 8;
    pub const BA_OP_CHANGE_COLUMN_START: u32 = 9;
    pub const BA_OP_CHANGE_COLUMN_END_DELTA: u32 = 10;
    pub const BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET: u32 = 11;
    pub const BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET: u32 = 12;
    pub const BA_OP_CHANGE_COLUMN_END: u32 = 13;
}

/// The compressed integer encoding (cvinfo.h's `CVUncompressData`): the
/// first byte's top bits say how many bytes follow, and its other bits are
/// the value's top bits.
mod compressed {
    /// `0xxxxxxx`: one byte, 7 bits.
    pub const ONE_BYTE_PREFIX_MASK: u32 = 0x80;
    pub const ONE_BYTE_PREFIX: u32 = 0x00;
    /// `10xxxxxx` and a byte: 14 bits.
    pub const TWO_BYTE_PREFIX_MASK: u32 = 0xC0;
    pub const TWO_BYTE_PREFIX: u32 = 0x80;
    pub const TWO_BYTE_VALUE_MASK: u32 = 0x3F;
    /// `110xxxxx` and three bytes: 29 bits.
    pub const FOUR_BYTE_PREFIX_MASK: u32 = 0xE0;
    pub const FOUR_BYTE_PREFIX: u32 = 0xC0;
    pub const FOUR_BYTE_VALUE_MASK: u32 = 0x1F;
}

/// `BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET`'s operand: the code delta in
/// its low four bits, the source line delta above them.
const CODE_DELTA_MASK: u32 = 0xF;
const LINE_DELTA_SHIFT: u32 = 4;

/// A compressed unsigned integer, or `None` at the end or for a bad prefix.
fn uncompress(r: &mut Reader<'_>) -> Option<u32> {
    use compressed::*;
    let b = u32::from(r.u8().ok()?);
    if b & ONE_BYTE_PREFIX_MASK == ONE_BYTE_PREFIX {
        return Some(b);
    }
    if b & TWO_BYTE_PREFIX_MASK == TWO_BYTE_PREFIX {
        return Some(((b & TWO_BYTE_VALUE_MASK) << 8) | u32::from(r.u8().ok()?));
    }
    if b & FOUR_BYTE_PREFIX_MASK == FOUR_BYTE_PREFIX {
        let (b1, b2, b3) = (r.u8().ok()?, r.u8().ok()?, r.u8().ok()?);
        return Some(
            ((b & FOUR_BYTE_VALUE_MASK) << 24)
                | u32::from(b1) << 16
                | u32::from(b2) << 8
                | u32::from(b3),
        );
    }
    None
}

/// A signed value as compressed: its magnitude, shifted, with the sign in
/// the low bit.
fn signed(u: u32) -> i32 {
    let magnitude = (u >> 1) as i32;
    if u & 1 != 0 { -magnitude } else { magnitude }
}

/// What an inline site's annotations say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Site {
    /// Code ranges, as (offset from the enclosing function's start,
    /// length), in order.
    pub ranges: Vec<(u32, u32)>,
    /// Where each line's code starts (an offset as above), its line (from
    /// the inlinee's first line, a delta), and its file (a file checksum
    /// offset, if the annotations change it from the inlinee's).
    pub lines: Vec<(u32, i32, Option<u32>)>,
}

/// Decodes `annotations`, stopping at the first that doesn't decode.
pub fn decode(annotations: &[u8]) -> Site {
    let mut r = Reader::new(annotations);
    let mut site = Site::default();
    // Each line entry's start, and its length if one is given (else it
    // runs to the next entry's start).
    let mut entries: Vec<(u32, Option<u32>)> = Vec::new();
    let mut offset: u32 = 0;
    let mut line: i32 = 0;
    let mut file: Option<u32> = None;
    // (Offsets never wrap: a hostile one is clamped.)
    fn entry(
        site: &mut Site,
        entries: &mut Vec<(u32, Option<u32>)>,
        at: u32,
        len: Option<u32>,
        (line, file): (i32, Option<u32>),
    ) {
        entries.push((at, len));
        site.lines.push((at, line, file));
    }
    while let Some(code) = uncompress(&mut r) {
        match code {
            op::BA_OP_INVALID => break,
            op::BA_OP_CODE_OFFSET => {
                let Some(v) = uncompress(&mut r) else { break };
                offset = v;
                entry(&mut site, &mut entries, offset, None, (line, file));
            }
            op::BA_OP_CHANGE_CODE_OFFSET => {
                let Some(d) = uncompress(&mut r) else { break };
                offset = offset.saturating_add(d);
                entry(&mut site, &mut entries, offset, None, (line, file));
            }
            op::BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET => {
                let Some(v) = uncompress(&mut r) else { break };
                offset = offset.saturating_add(v & CODE_DELTA_MASK);
                line = line.saturating_add(signed(v >> LINE_DELTA_SHIFT));
                entry(&mut site, &mut entries, offset, None, (line, file));
            }
            op::BA_OP_CHANGE_CODE_LENGTH => {
                let Some(len) = uncompress(&mut r) else { break };
                // The last entry's length; the code offset moves to its end
                // (the next jump is from there).
                match entries.last_mut() {
                    Some((at, l @ None)) => {
                        *l = Some(len);
                        offset = at.saturating_add(len);
                    }
                    _ => offset = offset.saturating_add(len),
                }
            }
            op::BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET => {
                let (Some(len), Some(d)) = (uncompress(&mut r), uncompress(&mut r)) else {
                    break;
                };
                // An entry of its length, after a jump. The code offset
                // stays at its start: the next jump is from there (MSVC's
                // nested sites tile their caller's code so: `0C 03 00`
                // then `0C 05 06` are [0, 3) and [6, 0xB)).
                offset = offset.saturating_add(d);
                entry(&mut site, &mut entries, offset, Some(len), (line, file));
            }
            op::BA_OP_CHANGE_LINE_OFFSET => {
                let Some(v) = uncompress(&mut r) else { break };
                line = line.saturating_add(signed(v));
            }
            op::BA_OP_CHANGE_FILE => {
                let Some(v) = uncompress(&mut r) else { break };
                file = Some(v);
            }
            op::BA_OP_CHANGE_CODE_OFFSET_BASE
            | op::BA_OP_CHANGE_LINE_END_DELTA
            | op::BA_OP_CHANGE_RANGE_KIND
            | op::BA_OP_CHANGE_COLUMN_START
            | op::BA_OP_CHANGE_COLUMN_END_DELTA
            | op::BA_OP_CHANGE_COLUMN_END => {
                if uncompress(&mut r).is_none() {
                    break;
                }
            }
            _ => break,
        }
    }
    // The entries' code: each to its length, or to the next's start (the
    // last, without one, has none); touching ones joined.
    for (i, &(at, len)) in entries.iter().enumerate() {
        let end = match len {
            Some(n) => at.saturating_add(n),
            None => entries.get(i + 1).map_or(at, |n| n.0),
        };
        if end <= at {
            continue;
        }
        match site.ranges.last_mut() {
            Some((s, n)) if s.saturating_add(*n) == at => *n = end - *s,
            _ => site.ranges.push((at, end - at)),
        }
    }
    site
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_integers() {
        let u = |b: &[u8]| uncompress(&mut Reader::new(b));
        assert_eq!(u(&[0x05]), Some(5));
        assert_eq!(u(&[0x7F]), Some(0x7F));
        assert_eq!(u(&[0x80, 0x80]), Some(0x80));
        assert_eq!(u(&[0xBF, 0xFF]), Some(0x3FFF));
        assert_eq!(u(&[0xC0, 0x00, 0x40, 0x00]), Some(0x4000));
        assert_eq!(u(&[0xDF, 0xFF, 0xFF, 0xFF]), Some(0x1FFF_FFFF));
        assert_eq!(u(&[0xE0]), None);
        assert_eq!(u(&[0x80]), None);
        assert_eq!(u(&[]), None);
        assert_eq!((signed(6), signed(7), signed(0)), (3, -3, 0));
    }

    #[test]
    fn ranges_and_lines() {
        // Code at 0x10 (line +0), 0x14 (line +2), 0x18 (line -1); 8 bytes
        // more: one range [0x10, 0x20). Then 0x10 further on, a range of
        // its own of 6 bytes.
        let a = [
            op::BA_OP_CHANGE_CODE_OFFSET as u8,
            0x10,
            op::BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET as u8,
            0x44, // code +4, line +2
            op::BA_OP_CHANGE_CODE_OFFSET_AND_LINE_OFFSET as u8,
            0x34, // code +4, line -1
            op::BA_OP_CHANGE_CODE_LENGTH as u8,
            0x08,
            op::BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET as u8,
            0x06,
            0x10,
        ];
        let s = decode(&a);
        assert_eq!(s.ranges, [(0x10, 0x10), (0x30, 6)]);
        assert_eq!(
            s.lines,
            [
                (0x10, 0, None),
                (0x14, 2, None),
                (0x18, 1, None),
                (0x30, 1, None)
            ]
        );
    }

    /// MSVC's nested sites (lines.exe's `square` in `sum_of_squares`): a
    /// jump after a range is from the range's start.
    #[test]
    fn length_and_offset_jumps_from_the_range_start() {
        let op = op::BA_OP_CHANGE_CODE_LENGTH_AND_CODE_OFFSET as u8;
        let s = decode(&[op, 0x03, 0x00, op, 0x05, 0x06, 0]);
        assert_eq!(s.ranges, [(0, 3), (6, 5)]);
        assert_eq!(s.lines, [(0, 0, None), (6, 0, None)]);
    }

    /// Entries without lengths run to the next's start (clang.pdb's sites,
    /// as DIA reads them).
    #[test]
    fn entries_run_to_the_next() {
        // An entry at 0xA48, then one of 6 bytes 0xA further on.
        let s = decode(&[
            0x06, 0x02, 0x03, 0x8A, 0x48, 0x06, 0x02, 0x0C, 0x06, 0x0A, 0, 0,
        ]);
        assert_eq!(s.ranges, [(0xA48, 0x10)]);
        assert_eq!(s.lines, [(0xA48, 1, None), (0xA52, 2, None)]);
        // 0x979 to 0x980 (the next), 0x980 to 0x983, 0x983 for 0x13; then
        // 0x9A0 for 0x25.
        let s = decode(&[
            0x06, 0x04, 0x03, 0x89, 0x79, 0x0B, 0x37, 0x06, 0x02, 0x0C, 0x13, 0x03, 0x06, 0x02,
            0x0C, 0x25, 0x1D, 0, 0, 0,
        ]);
        assert_eq!(s.ranges, [(0x979, 0x1D), (0x9A0, 0x25)]);
        // The last entry, without a length, has no code.
        let s = decode(&[op::BA_OP_CODE_OFFSET as u8, 0x10]);
        assert!(s.ranges.is_empty());
        assert_eq!(s.lines, [(0x10, 0, None)]);
    }

    #[test]
    fn files_and_other_annotations() {
        let a = [
            op::BA_OP_CHANGE_FILE as u8,
            0x18,
            op::BA_OP_CHANGE_LINE_OFFSET as u8,
            0x0A, // +5
            op::BA_OP_CHANGE_COLUMN_START as u8,
            3,
            op::BA_OP_CODE_OFFSET as u8,
            0x20,
            op::BA_OP_CHANGE_CODE_LENGTH as u8,
            4,
        ];
        let s = decode(&a);
        assert_eq!(s.ranges, [(0x20, 4)]);
        assert_eq!(s.lines, [(0x20, 5, Some(0x18))]);
    }

    /// Hostile input: truncated or nonsense annotations stop, never panic.
    #[test]
    fn hostile() {
        assert_eq!(decode(&[]), Site::default());
        assert_eq!(
            decode(&[op::BA_OP_CHANGE_CODE_LENGTH as u8]),
            Site::default()
        );
        assert_eq!(decode(&[0x7E, 1, 2]), Site::default());
        // Offsets that would wrap are clamped, not wrapped.
        let a = [
            op::BA_OP_CODE_OFFSET as u8,
            0xDF,
            0xFF,
            0xFF,
            0xFF,
            op::BA_OP_CHANGE_CODE_OFFSET as u8,
            0xDF,
            0xFF,
            0xFF,
            0xFF,
            op::BA_OP_CHANGE_CODE_LENGTH as u8,
            0xDF,
            0xFF,
            0xFF,
            0xFF,
        ];
        let s = decode(&a);
        assert!(s.ranges.iter().all(|&(o, l)| o.checked_add(l).is_some()));
        let mut x = 0x1234_5678u32;
        let mut bytes = vec![0u8; 4096];
        for b in &mut bytes {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x.to_le_bytes()[0];
        }
        decode(&bytes);
    }
}

//! `.eh_frame` and `.eh_frame_hdr`: which function each frame description
//! entry (FDE), and each entry of the binary-search table, describes.
//!
//! The format is the LSB's (DWARF call frame information with GCC's
//! pointer encodings and augmentations). Each FDE's `pc_begin` is read
//! with the encoding its CIE's `R` augmentation names; `pcrel` pointers
//! are relative to the pointer's own address, `datarel` ones (in the
//! header) to the header's.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::{Class, read_u16, read_u32, read_u64};

/// One entry and the address it describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The function's start address (FDE `pc_begin`, or the table's
    /// `initial_location`).
    pub pc: u64,
    /// Where the entry starts, relative to the section.
    pub offset: u64,
    pub size: u64,
}

pub const DW_EH_PE_OMIT: u8 = 0xFF;
const DW_EH_PE_INDIRECT: u8 = 0x80;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl Cursor<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn fixed(&mut self, n: usize) -> Option<u64> {
        let at = self.pos as u64;
        let v = match n {
            2 => u64::from(read_u16(self.data, at, self.endian)?),
            4 => u64::from(read_u32(self.data, at, self.endian)?),
            8 => read_u64(self.data, at, self.endian)?,
            _ => return None,
        };
        self.pos += n;
        Some(v)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
        }
    }

    fn cstr(&mut self) -> Option<&[u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        self.pos += n + 1;
        Some(&rest[..n])
    }
}

/// How to read pointers: the file's class and byte order, the address
/// of the section's first byte, the base for `datarel`, and (for
/// `indirect` pointers) how to read the word at an address.
struct Pointers<'f> {
    word: usize,
    addr: u64,
    data_base: Option<u64>,
    deref: &'f dyn Fn(u64) -> Option<u64>,
}

impl Pointers<'_> {
    fn read(&self, c: &mut Cursor<'_>, encoding: u8) -> Option<u64> {
        if encoding == DW_EH_PE_OMIT {
            return None;
        }
        let at = self.addr.wrapping_add(c.pos as u64);
        let sign = |v: u64, bits: u32| -> u64 {
            let shift = 64 - bits;
            (((v << shift) as i64) >> shift) as u64
        };
        let value = match encoding & 0x0F {
            0x00 => c.fixed(self.word)?,
            0x01 => c.uleb()?,
            0x02 => c.fixed(2)?,
            0x03 => c.fixed(4)?,
            0x04 => c.fixed(8)?,
            0x08 => {
                let w = self.word;
                sign(c.fixed(w)?, if w == 8 { 64 } else { 32 })
            }
            0x09 => c.sleb()? as u64,
            0x0A => sign(c.fixed(2)?, 16),
            0x0B => sign(c.fixed(4)?, 32),
            0x0C => c.fixed(8)?,
            _ => return None,
        };
        let value = match encoding & 0x70 {
            0x00 => value,
            0x10 => value.wrapping_add(at),
            0x30 => value.wrapping_add(self.data_base?),
            // textrel, funcrel, aligned: not used by GNU tools in these
            // sections.
            _ => return None,
        };
        if encoding & DW_EH_PE_INDIRECT != 0 {
            return (self.deref)(value);
        }
        Some(value)
    }
}

/// What an FDE needs from its CIE.
#[derive(Clone, Copy, Default)]
struct Cie {
    fde_encoding: u8,
}

fn parse_cie(c: &mut Cursor<'_>, p: &Pointers<'_>) -> Option<Cie> {
    let version = c.u8()?;
    let aug = c.cstr()?.to_vec();
    if aug.contains(&b'e') {
        // "eh": GCC 2.x's EH data pointer. Not produced in decades.
        return None;
    }
    c.uleb()?; // code alignment
    c.sleb()?; // data alignment
    if version == 1 {
        c.u8()?;
    } else {
        c.uleb()?;
    }
    let mut cie = Cie::default();
    let mut chars = aug.iter();
    if aug.first() == Some(&b'z') {
        chars.next();
        c.uleb()?;
    }
    for &ch in chars {
        match ch {
            b'L' => {
                c.u8()?;
            }
            b'R' => cie.fde_encoding = c.u8()?,
            b'P' => {
                let e = c.u8()?;
                // The personality routine's pointer may be indirect through
                // memory we can't read; its size is all that matters.
                let skip = Pointers {
                    deref: &|_| Some(0),
                    ..*p
                };
                skip.read(c, e & !DW_EH_PE_INDIRECT)?;
            }
            b'S' | b'B' | b'G' => {}
            _ => break,
        }
    }
    Some(cie)
}

/// The FDEs of an `.eh_frame` section (`data`, loaded at `addr`), each
/// with the function it describes. `deref` reads the word at an address,
/// for indirect pointers. Parsing stops at the first malformed entry.
pub fn fdes(
    data: &[u8],
    addr: u64,
    class: Class,
    endian: Endian,
    deref: &dyn Fn(u64) -> Option<u64>,
) -> Vec<Entry> {
    let p = Pointers {
        word: if class == Class::Elf64 { 8 } else { 4 },
        addr,
        data_base: None,
        deref,
    };
    let mut cies: BTreeMap<usize, Option<Cie>> = BTreeMap::new();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let mut c = Cursor { data, pos, endian };
        let Some(len) = c.fixed(4) else { break };
        let len = if len == 0xFFFF_FFFF {
            match c.fixed(8) {
                Some(l) => l,
                None => break,
            }
        } else {
            len
        };
        if len == 0 {
            // A terminator (or padding).
            pos = c.pos;
            continue;
        }
        let body = c.pos;
        let Some(end) = usize::try_from(len).ok().and_then(|l| body.checked_add(l)) else {
            break;
        };
        if end > data.len() {
            break;
        }
        let mut c = Cursor {
            data: &data[..end],
            pos: body,
            endian,
        };
        let Some(id) = c.fixed(4) else { break };
        if id == 0 {
            let cie = parse_cie(&mut c, &p);
            cies.insert(pos, cie);
        } else {
            // The CIE pointer counts back from itself.
            let cie_at = usize::try_from(id).ok().and_then(|id| body.checked_sub(id));
            let cie = cie_at.and_then(|at| {
                if let Some(c) = cies.get(&at) {
                    return *c;
                }
                // A CIE after its FDE (allowed, if unusual).
                let mut c = Cursor {
                    data,
                    pos: at,
                    endian,
                };
                let len = c.fixed(4)?;
                let end = c.pos.checked_add(usize::try_from(len).ok()?)?;
                let mut c = Cursor {
                    data: data.get(..end)?,
                    pos: c.pos,
                    endian,
                };
                (c.fixed(4)? == 0).then_some(())?;
                parse_cie(&mut c, &p)
            });
            if let Some(cie) = cie
                && let Some(pc) = p.read(&mut c, cie.fde_encoding)
            {
                out.push(Entry {
                    pc,
                    offset: pos as u64,
                    size: (end - pos) as u64,
                });
            }
        }
        pos = end;
    }
    out
}

/// The binary-search table of an `.eh_frame_hdr` section (`data`, loaded
/// at `addr`): each entry, with the function it indexes.
pub fn hdr_entries(
    data: &[u8],
    addr: u64,
    class: Class,
    endian: Endian,
    deref: &dyn Fn(u64) -> Option<u64>,
) -> Vec<Entry> {
    let p = Pointers {
        word: if class == Class::Elf64 { 8 } else { 4 },
        addr,
        data_base: Some(addr),
        deref,
    };
    let mut out = Vec::new();
    let mut c = Cursor {
        data,
        pos: 0,
        endian,
    };
    let (Some(1), Some(frame_enc), Some(count_enc), Some(table_enc)) =
        (c.u8(), c.u8(), c.u8(), c.u8())
    else {
        return out;
    };
    if p.read(&mut c, frame_enc).is_none() && frame_enc != DW_EH_PE_OMIT {
        return out;
    }
    let Some(count) = p.read(&mut c, count_enc) else {
        return out;
    };
    if table_enc == DW_EH_PE_OMIT {
        return out;
    }
    for _ in 0..count.min(data.len() as u64) {
        let start = c.pos;
        let (Some(pc), Some(_fde)) = (p.read(&mut c, table_enc), p.read(&mut c, table_enc)) else {
            break;
        };
        out.push(Entry {
            pc,
            offset: start as u64,
            size: (c.pos - start) as u64,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn put(out: &mut Vec<u8>, v: u64, n: usize, e: Endian) {
        let b = v.to_le_bytes();
        if e == Endian::Little {
            out.extend_from_slice(&b[..n]);
        } else {
            out.extend(b[..n].iter().rev());
        }
    }

    /// A CIE with augmentation `zR` (FDE encoding `enc`), then FDEs whose
    /// `pc_begin` fields hold `pcs` (written as `enc` says, relative to
    /// `addr`).
    fn frame(addr: u64, enc: u8, pcs: &[u64], e: Endian, word: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cie = Vec::new();
        put(&mut cie, 0, 4, e);
        cie.push(1);
        cie.extend_from_slice(b"zR\0");
        cie.extend([1, 0x78, 16]); // code align 1, data align -8, ra 16
        cie.push(1); // augmentation length
        cie.push(enc);
        cie.resize(cie.len().next_multiple_of(4), 0);
        put(&mut out, cie.len() as u64, 4, e);
        out.extend(&cie);
        for &pc in pcs {
            let start = out.len();
            let mut fde = Vec::new();
            put(&mut fde, (start + 4) as u64, 4, e); // CIE pointer: back to 0
            let field = addr + (start + 8) as u64;
            match enc {
                0x1B => put(&mut fde, pc.wrapping_sub(field) & 0xFFFF_FFFF, 4, e),
                0x00 => put(&mut fde, pc, word, e),
                0x03 => put(&mut fde, pc, 4, e),
                _ => unreachable!(),
            }
            put(&mut fde, 0x10, 4, e); // pc_range
            fde.push(0); // augmentation length
            fde.resize(fde.len().next_multiple_of(4), 0);
            put(&mut out, fde.len() as u64, 4, e);
            out.extend(&fde);
        }
        put(&mut out, 0, 4, e);
        out
    }

    const NO_DEREF: &dyn Fn(u64) -> Option<u64> = &|_| None;

    #[test]
    fn reads_fdes_in_each_encoding() {
        for e in [Endian::Little, Endian::Big] {
            for (enc, class, word) in [
                (0x1B, Class::Elf64, 8),
                (0x00, Class::Elf64, 8),
                (0x00, Class::Elf32, 4),
                (0x03, Class::Elf32, 4),
            ] {
                let addr = 0x40_0000;
                let data = frame(addr, enc, &[0x40_1000, 0x40_2000, 0x3F_0000], e, word);
                let fdes = fdes(&data, addr, class, e, NO_DEREF);
                let pcs: Vec<u64> = fdes.iter().map(|f| f.pc).collect();
                assert_eq!(pcs, [0x40_1000, 0x40_2000, 0x3F_0000], "{enc:#x} {e:?}");
                // Entries tile the section after the CIE, up to the
                // terminator.
                for w in fdes.windows(2) {
                    assert_eq!(w[0].offset + w[0].size, w[1].offset);
                }
                let last = fdes.last().unwrap();
                assert_eq!(last.offset + last.size, data.len() as u64 - 4);
            }
        }
    }

    #[test]
    fn stops_at_damage() {
        let addr = 0x1000;
        let data = frame(addr, 0x1B, &[0x2000, 0x3000], Endian::Little, 8);
        // Truncations never panic, and yield a prefix of the FDEs.
        for n in 0..data.len() {
            let f = fdes(&data[..n], addr, Class::Elf64, Endian::Little, NO_DEREF);
            assert!(f.len() <= 2);
        }
        // An FDE whose CIE pointer points nowhere is skipped.
        let mut bad = data.clone();
        let fde = 4 + u32::from_le_bytes(bad[0..4].try_into().unwrap()) as usize;
        bad[fde + 4..fde + 8].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(
            fdes(&bad, addr, Class::Elf64, Endian::Little, NO_DEREF).len(),
            1
        );
        // A length past the end stops parsing.
        let mut bad = data.clone();
        bad[fde..fde + 4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(fdes(&bad, addr, Class::Elf64, Endian::Little, NO_DEREF).is_empty());
        // Every single-byte corruption parses or stops cleanly.
        for i in 0..data.len() {
            for v in [0, 0xFF, 0x80] {
                let mut d = data.clone();
                d[i] = v;
                let _ = fdes(&d, addr, Class::Elf64, Endian::Little, NO_DEREF);
            }
        }
    }

    #[test]
    fn indirect_and_unknown_encodings() {
        let addr = 0x1000;
        // Indirect absolute: the word at 0x5000 holds the address.
        let data = frame(addr, 0x00, &[0x5000], Endian::Little, 8);
        let mut d = data.clone();
        let cie_len = u32::from_le_bytes(d[0..4].try_into().unwrap()) as usize;
        // The CIE's encoding byte is the last byte of augmentation data.
        let enc_at = 4 + 4 + 1 + 3 + 3 + 1;
        assert!(enc_at < 4 + cie_len);
        d[enc_at] = 0x80;
        let deref = |a: u64| (a == 0x5000).then_some(0x9000);
        let f = fdes(&d, addr, Class::Elf64, Endian::Little, &deref);
        assert_eq!(f[0].pc, 0x9000);
        // textrel: unsupported, the FDE is skipped.
        d[enc_at] = 0x20;
        assert!(fdes(&d, addr, Class::Elf64, Endian::Little, NO_DEREF).is_empty());
    }

    #[test]
    fn reads_the_search_table() {
        for e in [Endian::Little, Endian::Big] {
            let addr = 0x2000;
            let mut hdr = vec![1, 0x1B, 0x03, 0x3B];
            put(&mut hdr, 0x100, 4, e); // eh_frame_ptr (pcrel)
            put(&mut hdr, 2, 4, e); // count
            for (pc, fde) in [(0x3000u64, 0x2100u64), (0x3100, 0x2120)] {
                put(&mut hdr, pc.wrapping_sub(addr), 4, e);
                put(&mut hdr, fde.wrapping_sub(addr), 4, e);
            }
            let entries = hdr_entries(&hdr, addr, Class::Elf64, e, NO_DEREF);
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].pc, 0x3000);
            assert_eq!(entries[1].pc, 0x3100);
            assert_eq!(entries[0].offset, 12);
            assert_eq!(entries[0].size, 8);
            for n in 0..hdr.len() {
                assert!(hdr_entries(&hdr[..n], addr, Class::Elf64, e, NO_DEREF).len() <= 2);
            }
            // Another version, or no table: nothing.
            let mut v2 = hdr.clone();
            v2[0] = 2;
            assert!(hdr_entries(&v2, addr, Class::Elf64, e, NO_DEREF).is_empty());
            let mut omit = hdr.clone();
            omit[3] = DW_EH_PE_OMIT;
            assert!(hdr_entries(&omit, addr, Class::Elf64, e, NO_DEREF).is_empty());
        }
        // A huge count stops at the end of the data.
        let mut hdr = vec![1, 0x1B, 0x03, 0x3B];
        hdr.extend(0u32.to_le_bytes());
        hdr.extend(u32::MAX.to_le_bytes());
        hdr.extend([0; 16]);
        assert_eq!(
            hdr_entries(&hdr, 0, Class::Elf64, Endian::Little, NO_DEREF).len(),
            2
        );
    }

    #[test]
    fn leb128() {
        let mut c = Cursor {
            data: &[0xE5, 0x8E, 0x26, 0x7F, 0x80, 0x7F],
            pos: 0,
            endian: Endian::Little,
        };
        assert_eq!(c.uleb(), Some(624_485));
        assert_eq!(c.sleb(), Some(-1));
        assert_eq!(c.sleb(), Some(-128));
        assert_eq!(c.uleb(), None);
        // Overlong encodings don't overflow.
        let long = [0xFF; 20];
        let mut c = Cursor {
            data: &long,
            pos: 0,
            endian: Endian::Little,
        };
        assert_eq!(c.uleb(), None);
        let mut long = vec![0x80; 12];
        long.push(1);
        let mut c = Cursor {
            data: &long,
            pos: 0,
            endian: Endian::Little,
        };
        assert_eq!(c.uleb(), Some(0));
    }
}

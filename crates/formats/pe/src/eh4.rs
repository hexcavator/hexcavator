//! `__CxxFrameHandler4` (FH4) C++ exception tables: the compressed form of
//! `FuncInfo` and the maps it points to.
//!
//! Integers are compressed (see [`compressed`]) except RVAs, which are
//! plain 32-bit values. Each table here records where it is and how many
//! bytes it occupies, so that analyses can account for them.

use alloc::vec::Vec;

use hexcavator_core::Rva;

use crate::PeFile;

/// Bounds the entries read from one table (input is untrusted).
const MAX_ENTRIES: u32 = 0x10_0000;

/// Decodes an FH4 compressed unsigned integer at the start of `bytes`:
/// the low bits of the first byte give its length (1 to 5 bytes). Returns
/// the value and its length.
pub fn compressed(bytes: &[u8]) -> Option<(u32, u32)> {
    let first = *bytes.first()?;
    let (len, shift) = match first & 0x0F {
        l if l & 1 == 0 => (1, 1),
        l if l & 3 == 1 => (2, 2),
        l if l & 7 == 3 => (3, 3),
        7 => (4, 4),
        _ => (5, 0),
    };
    let value = if len == 5 {
        u32::from_le_bytes(bytes.get(1..5)?.try_into().ok()?)
    } else {
        let mut v = 0u32;
        for (i, b) in bytes.get(..len as usize)?.iter().enumerate() {
            v |= u32::from(*b) << (8 * i);
        }
        v >> shift
    };
    Some((value, len))
}

/// A cursor over image bytes by RVA.
struct Cursor<'a, 'data> {
    file: &'a PeFile<'data>,
    start: u32,
    at: u32,
}

impl Cursor<'_, '_> {
    fn u8(&mut self) -> Option<u8> {
        let b = self.file.bytes_at_rva(Rva(self.at), 1).ok()?[0];
        self.at = self.at.checked_add(1)?;
        Some(b)
    }

    fn int(&mut self) -> Option<u32> {
        let b = self.file.bytes_at_rva(Rva(self.at), 4).ok()?;
        self.at = self.at.checked_add(4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    fn compressed(&mut self) -> Option<u32> {
        // At most 5 bytes, but no more than the section has.
        let bytes = (1..=5u32)
            .rev()
            .find_map(|n| self.file.bytes_at_rva(Rva(self.at), n).ok())?;
        let (value, len) = compressed(bytes)?;
        self.at = self.at.checked_add(len)?;
        Some(value)
    }

    /// Bytes read so far.
    fn size(&self) -> u32 {
        self.at - self.start
    }
}

/// A table: where it is, how many bytes it occupies, and its entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table<T> {
    pub rva: Rva,
    pub size: u32,
    pub entries: Vec<T>,
}

/// `FuncInfo4`: a function's (or catch funclet's) C++ EH tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuncInfo4 {
    pub rva: Rva,
    /// Bytes the record occupies.
    pub size: u32,
    pub header: u8,
    pub bbt_flags: Option<u32>,
    pub unwind_map: Option<Rva>,
    pub try_map: Option<Rva>,
    /// The IP-to-state map, or (for separated functions) the segment map.
    pub ip_map: Rva,
    /// For catch funclets: the function frame's displacement from the
    /// establisher frame.
    pub frame_offset: Option<u32>,
}

impl FuncInfo4 {
    pub fn is_catch(&self) -> bool {
        self.header & 1 != 0
    }

    /// The function's code is in separate segments, each with its own
    /// IP-to-state map; `ip_map` is then a [`Segment4`] table.
    pub fn is_separated(&self) -> bool {
        self.header & 2 != 0
    }

    pub fn is_bbt(&self) -> bool {
        self.header & 4 != 0
    }

    pub fn ehs(&self) -> bool {
        self.header & 0x20 != 0
    }

    pub fn noexcept(&self) -> bool {
        self.header & 0x40 != 0
    }
}

/// One unwind map entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwindEntry4 {
    /// The entry's offset from the start of the map.
    pub offset: u32,
    /// How far back (in bytes, from this entry's offset) the next state's
    /// entry is.
    pub next: u32,
    /// 0: no action; 1: destructor with object; 2: destructor with object
    /// pointer; 3: a destructor (RVA) to call.
    pub kind: u8,
    pub action: Option<Rva>,
    /// The object's (or object pointer's) frame offset, for kinds 1 and 2.
    pub object: Option<u32>,
}

/// One try block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TryBlock4 {
    pub try_low: u32,
    pub try_high: u32,
    pub catch_high: u32,
    pub handlers: Rva,
}

/// A continuation address of a catch handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continuation4 {
    Rva(Rva),
    /// An offset from the function's start.
    Offset(u32),
}

/// One catch handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handler4 {
    pub header: u8,
    pub adjectives: Option<u32>,
    pub type_descriptor: Option<Rva>,
    pub catch_object: Option<u32>,
    pub handler: Rva,
    pub continuations: Vec<Continuation4>,
    /// The header names the reserved continuation type.
    pub reserved_continuation: bool,
}

/// One IP-to-state entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpState4 {
    /// The IP's offset from the previous entry's (as stored).
    pub delta: u32,
    /// The IP's offset from the start of the function or segment.
    pub ip: u32,
    /// The state plus one (as stored): 0 is state -1.
    pub state_plus_one: u32,
}

/// One segment of a separated function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment4 {
    pub segment: Rva,
    pub ip_map: Rva,
}

impl<'data> PeFile<'data> {
    fn cursor(&self, rva: Rva) -> Cursor<'_, 'data> {
        Cursor {
            file: self,
            start: rva.get(),
            at: rva.get(),
        }
    }

    /// The `FuncInfo4` at `rva`.
    pub fn func_info4(&self, rva: Rva) -> Option<FuncInfo4> {
        let mut c = self.cursor(rva);
        let header = c.u8()?;
        let has = |bit: u8| header & (1 << bit) != 0;
        let bbt_flags = if has(2) { Some(c.compressed()?) } else { None };
        let unwind_map = if has(3) { Some(Rva(c.int()?)) } else { None };
        let try_map = if has(4) { Some(Rva(c.int()?)) } else { None };
        let ip_map = Rva(c.int()?);
        let frame_offset = if has(0) { Some(c.compressed()?) } else { None };
        Some(FuncInfo4 {
            rva,
            size: c.size(),
            header,
            bbt_flags,
            unwind_map,
            try_map,
            ip_map,
            frame_offset,
        })
    }

    /// Reads a count, then up to that many entries with `entry` (stopping
    /// at the first that can't be read).
    fn table4<T>(
        &self,
        rva: Rva,
        mut entry: impl FnMut(&mut Cursor<'_, 'data>) -> Option<T>,
    ) -> Option<Table<T>> {
        let mut c = self.cursor(rva);
        let n = c.compressed()?;
        let mut entries = Vec::new();
        for _ in 0..n.min(MAX_ENTRIES) {
            let Some(e) = entry(&mut c) else { break };
            entries.push(e);
        }
        Some(Table {
            rva,
            size: c.size(),
            entries,
        })
    }

    /// The unwind map at `rva`.
    pub fn unwind_map4(&self, rva: Rva) -> Option<Table<UnwindEntry4>> {
        let start = rva.get();
        self.table4(rva, |c| {
            // Offsets are from the map's start (its count included), which
            // is how entries refer to each other.
            let offset = c.at - start;
            let packed = c.compressed()?;
            let (next, kind) = (packed >> 2, (packed & 3) as u8);
            let (action, object) = match kind {
                0 => (None, None),
                3 => (Some(Rva(c.int()?)), None),
                _ => (Some(Rva(c.int()?)), Some(c.compressed()?)),
            };
            Some(UnwindEntry4 {
                offset,
                next,
                kind,
                action,
                object,
            })
        })
    }

    /// The try block map at `rva`.
    pub fn try_map4(&self, rva: Rva) -> Option<Table<TryBlock4>> {
        self.table4(rva, |c| {
            Some(TryBlock4 {
                try_low: c.compressed()?,
                try_high: c.compressed()?,
                catch_high: c.compressed()?,
                handlers: Rva(c.int()?),
            })
        })
    }

    /// The catch handler array at `rva`.
    pub fn handler_map4(&self, rva: Rva) -> Option<Table<Handler4>> {
        self.table4(rva, |c| {
            let header = c.u8()?;
            let adjectives = if header & 1 != 0 {
                Some(c.compressed()?)
            } else {
                None
            };
            let type_descriptor = if header & 2 != 0 {
                Some(Rva(c.int()?))
            } else {
                None
            };
            let catch_object = if header & 4 != 0 {
                Some(c.compressed()?)
            } else {
                None
            };
            let handler = Rva(c.int()?);
            let as_rva = header & 8 != 0;
            let (count, reserved_continuation) = match (header >> 4) & 3 {
                1 => (1, false),
                2 => (2, false),
                3 => (0, true),
                _ => (0, false),
            };
            let mut continuations = Vec::new();
            for _ in 0..count {
                continuations.push(if as_rva {
                    Continuation4::Rva(Rva(c.int()?))
                } else {
                    Continuation4::Offset(c.compressed()?)
                });
            }
            Some(Handler4 {
                header,
                adjectives,
                type_descriptor,
                catch_object,
                handler,
                continuations,
                reserved_continuation,
            })
        })
    }

    /// The IP-to-state map at `rva`.
    pub fn ip_to_state4(&self, rva: Rva) -> Option<Table<IpState4>> {
        let mut ip = 0u32;
        self.table4(rva, |c| {
            let delta = c.compressed()?;
            let state_plus_one = c.compressed()?;
            ip = ip.wrapping_add(delta);
            Some(IpState4 {
                delta,
                ip,
                state_plus_one,
            })
        })
    }

    /// The segment map of a separated function at `rva`.
    pub fn segment_map4(&self, rva: Rva) -> Option<Table<Segment4>> {
        self.table4(rva, |c| {
            Some(Segment4 {
                segment: Rva(c.int()?),
                ip_map: Rva(c.int()?),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_integers() {
        // One byte: value << 1.
        assert_eq!(compressed(&[0x08]), Some((4, 1)));
        assert_eq!(compressed(&[0xFE]), Some((127, 1)));
        // Two bytes: (value << 2) | 1.
        assert_eq!(
            compressed(&[0x21, 0x03]), // (200 << 2) | 1
            Some((200, 2))
        );
        // Three: (value << 3) | 3.
        let v = 0x1_2345u32;
        let e = (v << 3) | 3;
        assert_eq!(compressed(&e.to_le_bytes()[..3]), Some((v, 3)));
        // Four: (value << 4) | 7.
        let v = 0x00AB_CDEF_u32;
        let e = (v << 4) | 7;
        assert_eq!(compressed(&e.to_le_bytes()), Some((v, 4)));
        // Five: 0xF, then the value.
        assert_eq!(
            compressed(&[0x0F, 0x78, 0x56, 0x34, 0x12]),
            Some((0x1234_5678, 5))
        );
        // Truncated.
        assert_eq!(compressed(&[]), None);
        assert_eq!(compressed(&[0x01]), None);
        assert_eq!(compressed(&[0x0F, 0, 0]), None);
    }
}

//! Moving an object file's addresses to an image's, by the image's debug
//! map (see [`hexcavator_macho::debugmap`]): each of the object's
//! functions and variables the map names is where the map says, and the
//! bytes after it (to the object's next symbol, or a function's end) with
//! it. Bytes of nothing the map names (code the linker dropped) are
//! nowhere.

use hexcavator_macho::MachO;
use hexcavator_macho::debugmap::DebugMapSymbol;

/// Where an object file's pieces are in the image.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddrMap {
    /// (start, end, image address), sorted, not overlapping.
    pieces: Vec<(u64, u64, u64)>,
}

impl AddrMap {
    /// The map for `object`, whose functions and variables the image has
    /// at `symbols`.
    pub fn new(object: &MachO<'_>, symbols: &[DebugMapSymbol<'_>]) -> Self {
        let sections = object.sections();
        let mut defined: Vec<(u8, u64, &[u8])> = object
            .symbols()
            .into_iter()
            .filter(hexcavator_macho::Nlist::is_section_defined)
            .map(|s| (s.n_sect, s.n_value, s.name))
            .collect();
        defined.sort_unstable();
        let mut by_name: std::collections::HashMap<&[u8], &DebugMapSymbol<'_>> =
            std::collections::HashMap::with_capacity(symbols.len());
        for s in symbols {
            by_name.entry(s.name).or_insert(s);
        }
        let mut pieces = Vec::new();
        for (i, &(sect, start, name)) in defined.iter().enumerate() {
            let Some(to) = by_name.get(name) else {
                continue;
            };
            // To the next symbol at a higher address in the section, or
            // the section's end.
            let section_end = usize::from(sect)
                .checked_sub(1)
                .and_then(|j| sections.get(j))
                .map_or(u64::MAX, |s| s.addr.saturating_add(s.size));
            let next = defined[i + 1..]
                .iter()
                .take_while(|d| d.0 == sect)
                .find(|d| d.1 > start)
                .map_or(section_end, |d| d.1);
            let mut end = next.min(section_end).max(start);
            if let Some(size) = to.size {
                end = start.saturating_add(size).min(section_end.max(start));
            }
            if end > start {
                pieces.push((start, end, to.addr));
            }
        }
        pieces.sort_unstable();
        // (Two names for one place: the first.)
        let mut last_end = 0;
        pieces.retain(|p| {
            let keep = p.0 >= last_end;
            if keep {
                last_end = p.1;
            }
            keep
        });
        Self { pieces }
    }

    /// Where the object's address `addr` is in the image.
    pub fn addr(&self, addr: u64) -> Option<u64> {
        let i = self
            .pieces
            .partition_point(|p| p.0 <= addr)
            .checked_sub(1)?;
        let (start, end, to) = self.pieces[i];
        (addr < end).then(|| to.wrapping_add(addr - start))
    }

    /// The object's `size` bytes at `at`, where they are in the image (in
    /// pieces, if they span more than one).
    pub fn range(&self, at: u64, size: u64, out: &mut Vec<(u64, u64)>) {
        let end = at.saturating_add(size);
        let mut i = self.pieces.partition_point(|p| p.1 <= at);
        while let Some(&(start, stop, to)) = self.pieces.get(i) {
            if start >= end {
                break;
            }
            let lo = start.max(at);
            let hi = stop.min(end);
            if hi > lo {
                out.push((to.wrapping_add(lo - start), hi - lo));
            }
            i += 1;
        }
    }

    /// Whether nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pieces: &[(u64, u64, u64)]) -> AddrMap {
        AddrMap {
            pieces: pieces.to_vec(),
        }
    }

    #[test]
    fn addresses_move_with_their_piece() {
        let m = map(&[
            (0, 0x10, 0x1000),
            (0x10, 0x30, 0x5000),
            (0x40, 0x48, 0x9000),
        ]);
        assert_eq!(m.addr(0), Some(0x1000));
        assert_eq!(m.addr(0xf), Some(0x100f));
        assert_eq!(m.addr(0x10), Some(0x5000));
        assert_eq!(m.addr(0x30), None);
        assert_eq!(m.addr(0x47), Some(0x9007));
        assert_eq!(m.addr(u64::MAX), None);
        assert_eq!(map(&[]).addr(0), None);
    }

    #[test]
    fn ranges_split_at_pieces_and_drop_the_unmapped() {
        let m = map(&[
            (0, 0x10, 0x1000),
            (0x10, 0x30, 0x5000),
            (0x40, 0x48, 0x9000),
        ]);
        let mut out = Vec::new();
        m.range(0x8, 0x40, &mut out);
        assert_eq!(out, [(0x1008, 8), (0x5000, 0x20), (0x9000, 8)]);
        out.clear();
        m.range(0x30, 0x10, &mut out);
        assert!(out.is_empty());
        // Hostile: running past the address space.
        out.clear();
        m.range(0x44, u64::MAX, &mut out);
        assert_eq!(out, [(0x9004, 4)]);
    }
}

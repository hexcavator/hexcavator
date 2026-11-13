//! Address ranges, and merging them.

/// A half-open address range `[addr, addr + len)`, which either occupies
/// bytes in the file or (`zero_fill`) only in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Range {
    pub addr: u64,
    pub len: u64,
    pub zero_fill: bool,
}

impl Range {
    pub const fn new(addr: u64, len: u64, zero_fill: bool) -> Self {
        Self {
            addr,
            len,
            zero_fill,
        }
    }

    /// The end of the range (saturating).
    pub const fn end(&self) -> u64 {
        self.addr.saturating_add(self.len)
    }

    /// How many bytes of the file the range occupies.
    pub const fn file_len(&self) -> u64 {
        if self.zero_fill { 0 } else { self.len }
    }

    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr - self.addr < self.len
    }

    /// Whether `next`, which starts at or after `self`, can be merged into
    /// `self`: both occupy the file or neither does, and `next` starts at
    /// most `max_gap` bytes after `self` ends (0: touching or overlapping).
    pub fn can_absorb(&self, next: &Range, max_gap: u64) -> bool {
        if self.zero_fill != next.zero_fill {
            return false;
        }
        if next.addr == self.addr {
            // Two empty ranges at the same address stay separate (as
            // SizeBench keeps them); anything else at one address overlaps.
            return self.len > 0 || next.len > 0;
        }
        next.addr <= self.end().saturating_add(max_gap)
    }

    /// `self` extended to cover `next`.
    pub fn absorb(&mut self, next: &Range) {
        let start = self.addr.min(next.addr);
        let end = self.end().max(next.end());
        self.addr = start;
        self.len = end - start;
    }
}

/// An index for finding which of a list of ranges, sorted by address,
/// contain an address, in O(log n) plus the number of ranges that start
/// before it and end after it: each range's prefix maximum end bounds the
/// backward scan, so overlapping ranges are found exactly.
#[derive(Clone, Debug, Default)]
pub struct Lookup {
    /// `max_end[i]`: the greatest end among ranges `0..=i`.
    max_end: Vec<u64>,
}

impl Lookup {
    /// Indexes `ranges`, which must be sorted by address.
    pub fn new(ranges: &[Range]) -> Self {
        let mut max = 0;
        Self {
            max_end: ranges
                .iter()
                .map(|r| {
                    max = max.max(r.end());
                    max
                })
                .collect(),
        }
    }

    /// The indexes of the ranges containing `addr`, from last to first.
    pub fn all_containing<'r>(
        &'r self,
        ranges: &'r [Range],
        addr: u64,
    ) -> impl Iterator<Item = usize> + 'r {
        let start = ranges.partition_point(|r| r.addr <= addr);
        (0..start)
            .rev()
            .take_while(move |&i| self.max_end[i] > addr)
            .filter(move |&i| ranges[i].contains(addr))
    }

    /// The first (lowest-index) range containing `addr`.
    pub fn first_containing(&self, ranges: &[Range], addr: u64) -> Option<usize> {
        self.all_containing(ranges, addr).last()
    }
}

/// Sorts `ranges` by address and merges those that touch or overlap, or
/// are at most `max_gap` bytes apart, keeping ranges that occupy the file
/// apart from zero-fill ones. Each range is only merged into the one before
/// it in address order, so a zero-fill range between two file ranges keeps
/// them apart.
pub fn coalesce(ranges: &mut Vec<Range>, max_gap: u64) {
    ranges.sort_by_key(|r| (r.addr, r.len, r.zero_fill));
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        match out.last_mut() {
            Some(last) if last.can_absorb(&r, max_gap) => last.absorb(&r),
            _ => out.push(r),
        }
    }
    *ranges = out;
}

/// Merges `next` into the last range of `ranges`, which is sorted by
/// address and has `next.addr` at or after its last range, or appends it.
pub fn push_coalescing(ranges: &mut Vec<Range>, next: Range, max_gap: u64) {
    match ranges.last_mut() {
        Some(last) if next.addr >= last.addr && last.can_absorb(&next, max_gap) => {
            last.absorb(&next);
        }
        _ => ranges.push(next),
    }
}

/// The total (file bytes, memory bytes) of `ranges`.
pub fn totals(ranges: &[Range]) -> (u64, u64) {
    ranges.iter().fold((0, 0), |(file, vm), r| {
        (file.saturating_add(r.file_len()), vm.saturating_add(r.len))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(addr: u64, len: u64) -> Range {
        Range::new(addr, len, false)
    }

    fn z(addr: u64, len: u64) -> Range {
        Range::new(addr, len, true)
    }

    fn merged(mut v: Vec<Range>, gap: u64) -> Vec<Range> {
        coalesce(&mut v, gap);
        v
    }

    #[test]
    fn basics() {
        let a = r(0x10, 0x10);
        assert_eq!(a.end(), 0x20);
        assert!(a.contains(0x10) && a.contains(0x1F));
        assert!(!a.contains(0x20) && !a.contains(0xF));
        assert!(!r(5, 0).contains(5));
        assert_eq!(a.file_len(), 0x10);
        assert_eq!(z(0, 7).file_len(), 0);
        assert_eq!(r(u64::MAX - 1, 10).end(), u64::MAX);
    }

    #[test]
    fn touching_and_overlapping_merge() {
        assert_eq!(merged(vec![r(0, 10), r(10, 5)], 0), [r(0, 15)]);
        assert_eq!(merged(vec![r(10, 5), r(0, 10)], 0), [r(0, 15)]);
        assert_eq!(merged(vec![r(0, 10), r(5, 2)], 0), [r(0, 10)]);
        assert_eq!(merged(vec![r(0, 10), r(5, 20)], 0), [r(0, 25)]);
        assert_eq!(merged(vec![r(0, 10), r(0, 3)], 0), [r(0, 10)]);
    }

    #[test]
    fn gaps() {
        assert_eq!(merged(vec![r(0, 10), r(11, 5)], 0), [r(0, 10), r(11, 5)]);
        assert_eq!(merged(vec![r(0, 10), r(11, 5)], 1), [r(0, 16)]);
        assert_eq!(merged(vec![r(0, 10), r(17, 5)], 7), [r(0, 22)]);
        assert_eq!(merged(vec![r(0, 10), r(18, 5)], 7), [r(0, 10), r(18, 5)]);
    }

    #[test]
    fn zero_fill_stays_apart() {
        assert_eq!(merged(vec![r(0, 10), z(10, 5)], 0), [r(0, 10), z(10, 5)]);
        // A zero-fill range between two file ranges keeps them apart.
        assert_eq!(
            merged(vec![r(0, 10), z(10, 5), r(15, 5)], 8),
            [r(0, 10), z(10, 5), r(15, 5)]
        );
        assert_eq!(merged(vec![z(0, 4), z(4, 4)], 0), [z(0, 8)]);
    }

    #[test]
    fn empty_ranges() {
        assert_eq!(merged(vec![r(5, 0), r(5, 3)], 0), [r(5, 3)]);
        assert_eq!(merged(vec![r(5, 0), r(5, 0)], 0), [r(5, 0), r(5, 0)]);
        assert_eq!(merged(vec![r(0, 5), r(5, 0)], 0), [r(0, 5)]);
        assert_eq!(merged(vec![r(5, 0), r(6, 1)], 0), [r(5, 0), r(6, 1)]);
        assert_eq!(merged(vec![], 0), []);
    }

    #[test]
    fn extremes_do_not_overflow() {
        let top = u64::MAX - 4;
        assert_eq!(
            merged(vec![r(top, 4), r(top + 4, 0)], u64::MAX),
            [r(top, 4)]
        );
        assert_eq!(merged(vec![r(0, u64::MAX), r(10, 10)], 0), [r(0, u64::MAX)]);
    }

    #[test]
    fn push_coalescing_matches_coalesce() {
        let input = [r(0, 4), r(4, 4), r(9, 1), z(10, 2), z(12, 1), r(13, 1)];
        let mut pushed = Vec::new();
        for x in input {
            push_coalescing(&mut pushed, x, 0);
        }
        assert_eq!(pushed, merged(input.to_vec(), 0));
        // Out-of-order input is appended rather than merged backwards.
        let mut v = vec![r(10, 5)];
        push_coalescing(&mut v, r(0, 20), 0);
        assert_eq!(v, [r(10, 5), r(0, 20)]);
    }

    #[test]
    fn lookup_matches_a_scan() {
        // Disjoint, nested, overlapping, empty, and adjacent ranges.
        let ranges = [
            r(0, 10),
            r(5, 2),
            r(5, 20),
            r(8, 0),
            r(30, 5),
            r(35, 5),
            r(36, 1),
            r(100, 1000),
            r(200, 10),
        ];
        let lookup = Lookup::new(&ranges);
        for addr in 0..1200 {
            let want: Vec<usize> = (0..ranges.len())
                .rev()
                .filter(|&i| ranges[i].contains(addr))
                .collect();
            let got: Vec<usize> = lookup.all_containing(&ranges, addr).collect();
            assert_eq!(got, want, "{addr}");
            assert_eq!(lookup.first_containing(&ranges, addr), want.last().copied());
        }
        let empty = Lookup::new(&[]);
        assert_eq!(empty.first_containing(&[], 5), None);
    }

    #[test]
    fn totals_split_file_and_memory() {
        assert_eq!(totals(&[r(0, 10), z(10, 6), r(100, 1)]), (11, 17));
        assert_eq!(totals(&[]), (0, 0));
        assert_eq!(totals(&[r(0, u64::MAX), r(0, 5)]), (u64::MAX, u64::MAX));
    }
}

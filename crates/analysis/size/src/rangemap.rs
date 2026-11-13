//! Labelings of an address space, as bloaty builds them: every byte gets
//! at most one label, the first one given (later labels fill only what is
//! still unlabeled), and ranges may record the address they translate to
//! in another domain (memory address to file offset, or back).
//!
//! An image's [`DualMap`]s, one per *data source* (sections, symbols,
//! compilands, ...), are combined by [`sweep`] into runs of bytes that
//! have one label in each.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustc_hash::FxHashMap;

/// Interned labels.
#[derive(Clone, Debug, Default)]
pub struct Labels {
    names: Vec<Arc<str>>,
    index: FxHashMap<Arc<str>, u32>,
}

/// A label's index in its [`Labels`].
pub type Label = u32;

impl Labels {
    pub fn intern(&mut self, name: &str) -> Label {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let i = u32::try_from(self.names.len()).expect("fewer than 2^32 labels");
        let name: Arc<str> = name.into();
        self.names.push(name.clone());
        self.index.insert(name, i);
        i
    }

    pub fn name(&self, label: Label) -> &str {
        &self.names[label as usize]
    }

    /// The label's name, shared.
    pub fn shared(&self, label: Label) -> &Arc<str> {
        &self.names[label as usize]
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// One labeled range of a [`RangeMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub start: u64,
    pub end: u64,
    pub label: Label,
    /// Where `start` lies in the other domain, if the range maps there
    /// (byte for byte).
    pub other: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Value {
    end: u64,
    label: Label,
    other: Option<u64>,
}

/// Disjoint labeled ranges of one address space.
#[derive(Clone, Debug, Default)]
pub struct RangeMap {
    map: BTreeMap<u64, Value>,
    /// A buffer for gaps, kept to save allocations.
    scratch: Vec<(u64, u64)>,
}

impl PartialEq for RangeMap {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Eq for RangeMap {}

impl RangeMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Labels what is still unlabeled of `[start, end)`.
    pub fn add(&mut self, start: u64, end: u64, label: Label) {
        self.add_dual(start, end, None, label);
    }

    /// Labels what is still unlabeled of `[start, end)`, recording that it
    /// maps to `[other, other + (end - start))` in the other domain.
    pub fn add_dual(&mut self, start: u64, end: u64, other: Option<u64>, label: Label) {
        let mut gaps = std::mem::take(&mut self.scratch);
        self.gaps_into(start, end, &mut gaps);
        for &(s, e) in &gaps {
            let other = other.map(|o| o.wrapping_add(s - start));
            self.map.insert(
                s,
                Value {
                    end: e,
                    label,
                    other,
                },
            );
        }
        self.scratch = gaps;
    }

    /// The unlabeled parts of `[start, end)`.
    pub fn gaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        self.gaps_into(start, end, &mut out);
        out
    }

    /// Replaces `out` with the unlabeled parts of `[start, end)`.
    fn gaps_into(&self, start: u64, end: u64, out: &mut Vec<(u64, u64)>) {
        out.clear();
        let mut cur = start;
        if let Some((_, v)) = self.map.range(..=cur).next_back()
            && v.end > cur
        {
            cur = v.end;
        }
        while cur < end {
            match self.map.range(cur..end).next() {
                Some((&s, v)) => {
                    if s > cur {
                        out.push((cur, s));
                    }
                    cur = v.end;
                }
                None => {
                    out.push((cur, end));
                    break;
                }
            }
        }
    }

    /// The entry containing `addr`.
    pub fn get(&self, addr: u64) -> Option<Entry> {
        let (&start, v) = self.map.range(..=addr).next_back()?;
        (addr < v.end).then_some(Entry {
            start,
            end: v.end,
            label: v.label,
            other: v.other,
        })
    }

    /// `addr` in the other domain.
    pub fn translate(&self, addr: u64) -> Option<u64> {
        let e = self.get(addr)?;
        Some(e.other?.wrapping_add(addr - e.start))
    }

    /// Whether every byte of `[start, end)` is labeled.
    pub fn covers(&self, start: u64, end: u64) -> bool {
        self.gaps(start, end).is_empty()
    }

    /// The entries overlapping `[start, end)`, in order.
    pub fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = Entry> + '_ {
        let first = match self.map.range(..=start).next_back() {
            Some((&s, v)) if v.end > start => s,
            _ => start,
        };
        self.map
            .range(first..end.max(first))
            .map(|(&start, v)| Entry {
                start,
                end: v.end,
                label: v.label,
                other: v.other,
            })
    }

    /// Labels what is still unlabeled of `[start, end)` within the ranges
    /// of `base`, and the same bytes, where `base` translates them, in
    /// `other` (this map's counterpart in the other domain). Returns how
    /// many bytes of the range `base` covers.
    pub fn add_translated(
        &mut self,
        start: u64,
        end: u64,
        label: Label,
        base: &RangeMap,
        other: &mut RangeMap,
    ) -> u64 {
        let mut covered = 0;
        let mut gaps = std::mem::take(&mut self.scratch);
        for b in base.overlapping(start, end) {
            let (s, e) = (start.max(b.start), end.min(b.end));
            if s >= e {
                continue;
            }
            covered += e - s;
            // Only the newly labeled bytes go to the other domain, so that
            // both domains agree on who owns what.
            self.gaps_into(s, e, &mut gaps);
            for &(gs, ge) in &gaps {
                let translated = b.other.map(|o| o.wrapping_add(gs - b.start));
                self.map.insert(
                    gs,
                    Value {
                        end: ge,
                        label,
                        other: translated,
                    },
                );
                if let Some(t) = translated {
                    other.add_dual(t, t.wrapping_add(ge - gs), Some(gs), label);
                }
            }
        }
        self.scratch = gaps;
        covered
    }

    pub fn iter(&self) -> impl Iterator<Item = Entry> + '_ {
        self.map.iter().map(|(&start, v)| Entry {
            start,
            end: v.end,
            label: v.label,
            other: v.other,
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The number of bytes labeled.
    pub fn total(&self) -> u64 {
        self.map.iter().map(|(&s, v)| v.end - s).sum()
    }

    /// Gives every entry the label `f` maps its label to.
    pub fn relabel(&mut self, mut f: impl FnMut(Label) -> Label) {
        for v in self.map.values_mut() {
            v.label = f(v.label);
        }
    }

    /// Merges touching entries with the same label (and, if they have
    /// one, a contiguous translation).
    /// bloaty's padding rule (`RangeMap::Compress`): a range of at most 16
    /// bytes with a fallback label (`[section .text]`, `[Unmapped]`: one
    /// that `is_fallback` says starts with `[`) right after a range with
    /// another label is taken to be that range's padding, and labeled as
    /// it. bloaty adds a range a piece at a time, one per range of the base
    /// map it covers, so ranges are cut at `base`'s boundaries first. For
    /// rolling up only: translations are not kept.
    pub fn with_padding_absorbed(
        &self,
        base: &RangeMap,
        is_fallback: impl Fn(Label) -> bool,
    ) -> RangeMap {
        let mut out = RangeMap::new();
        let mut last: Option<(u64, Value)> = None;
        let mut pieces = Vec::new();
        for (&start, &whole) in &self.map {
            // The entry, cut where base ranges begin or end within it.
            pieces.clear();
            let mut at = start;
            for b in base.overlapping(start, whole.end) {
                for cut in [b.start, b.end] {
                    if cut > at && cut < whole.end {
                        pieces.push((at, cut));
                        at = cut;
                    }
                }
            }
            pieces.push((at, whole.end));
            for &(s, e) in &pieces {
                let v = Value {
                    end: e,
                    label: whole.label,
                    other: None,
                };
                if let Some((_, lv)) = &mut last
                    && lv.end == s
                    && (lv.label == v.label
                        || (!is_fallback(lv.label) && is_fallback(v.label) && e - s <= 16))
                {
                    lv.end = e;
                    lv.other = None;
                    continue;
                }
                if let Some((ls, lv)) = last.take() {
                    out.map.insert(ls, lv);
                }
                last = Some((s, v));
            }
        }
        if let Some((ls, lv)) = last {
            out.map.insert(ls, lv);
        }
        out
    }

    pub fn compress(&mut self) {
        let mut out: BTreeMap<u64, Value> = BTreeMap::new();
        let mut last: Option<(u64, Value)> = None;
        for (&s, &v) in &self.map {
            if let Some((ls, lv)) = &mut last
                && lv.end == s
                && lv.label == v.label
                && match (lv.other, v.other) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.wrapping_add(s - *ls) == b,
                    _ => false,
                }
            {
                lv.end = v.end;
                continue;
            }
            if let Some((ls, lv)) = last.take() {
                out.insert(ls, lv);
            }
            last = Some((s, v));
        }
        if let Some((ls, lv)) = last {
            out.insert(ls, lv);
        }
        self.map = out;
    }
}

/// A labeling of both domains: memory addresses and file offsets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DualMap {
    pub vm: RangeMap,
    pub file: RangeMap,
}

impl DualMap {
    /// A range in memory and in the file: the first `min(vm_size,
    /// file_size)` bytes map to each other, the rest of each is labeled in
    /// its own domain only (zero fill in memory, or file padding).
    pub fn add_range(&mut self, vm: u64, vm_size: u64, file: u64, file_size: u64, label: Label) {
        let common = vm_size.min(file_size);
        self.vm.add_dual(vm, vm + common, Some(file), label);
        self.file.add_dual(file, file + common, Some(vm), label);
        self.vm.add(vm + common, vm + vm_size, label);
        self.file.add(file + common, file + file_size, label);
    }

    /// A memory range, labeled in the file too where `base` maps it there;
    /// only the parts `base` covers are labeled.
    pub fn add_vm(&mut self, start: u64, end: u64, label: Label, base: &DualMap) -> u64 {
        self.vm
            .add_translated(start, end, label, &base.vm, &mut self.file)
    }

    /// A file range, labeled in memory too where `base` maps it there;
    /// only the parts `base` covers are labeled.
    pub fn add_file(&mut self, start: u64, end: u64, label: Label, base: &DualMap) -> u64 {
        self.file
            .add_translated(start, end, label, &base.file, &mut self.vm)
    }

    /// Labels everything `base` labels that this map doesn't, with the
    /// label `fallback` gives `base`'s label (bloaty's `[section .text]`).
    pub fn fill_from(&mut self, base: &DualMap, mut fallback: impl FnMut(Label) -> Label) {
        for e in base.vm.iter() {
            let label = fallback(e.label);
            self.vm.add_dual(e.start, e.end, e.other, label);
        }
        for e in base.file.iter() {
            let label = fallback(e.label);
            self.file.add_dual(e.start, e.end, e.other, label);
        }
    }
}

/// Calls `f(start, end, labels)` for each run of bytes that `maps` label
/// alike, in address order, over the bytes the first map (the base)
/// labels; `labels[i]` is `maps[i]`'s label, or `None` where it has none.
pub fn sweep(maps: &[&RangeMap], mut f: impl FnMut(u64, u64, &[Option<Label>])) {
    let Some(base) = maps.first() else {
        return;
    };
    let entries: Vec<Vec<Entry>> = maps.iter().map(|m| m.iter().collect()).collect();
    let mut index = vec![0usize; maps.len()];
    let mut labels = vec![None; maps.len()];
    for b in base.iter() {
        let mut cur = b.start;
        while cur < b.end {
            let mut next = b.end;
            for (k, list) in entries.iter().enumerate() {
                let i = &mut index[k];
                while *i < list.len() && list[*i].end <= cur {
                    *i += 1;
                }
                match list.get(*i) {
                    Some(e) if e.start <= cur => {
                        labels[k] = Some(e.label);
                        next = next.min(e.end);
                    }
                    Some(e) => {
                        labels[k] = None;
                        next = next.min(e.start);
                    }
                    None => labels[k] = None,
                }
            }
            f(cur, next, &labels);
            cur = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(m: &RangeMap) -> Vec<(u64, u64, Label, Option<u64>)> {
        m.iter()
            .map(|e| (e.start, e.end, e.label, e.other))
            .collect()
    }

    #[test]
    fn first_label_wins() {
        let mut m = RangeMap::new();
        m.add(10, 20, 1);
        m.add(0, 30, 2);
        m.add(15, 25, 3);
        m.add(5, 5, 4);
        assert_eq!(
            entries(&m),
            [(0, 10, 2, None), (10, 20, 1, None), (20, 30, 2, None)]
        );
        assert_eq!(m.total(), 30);
        assert!(m.covers(0, 30));
        assert!(!m.covers(0, 31));
        assert_eq!(m.gaps(25, 40), [(30, 40)]);
        assert_eq!(m.get(10).unwrap().label, 1);
        assert_eq!(m.get(30), None);
    }

    #[test]
    fn gaps_between_many_entries() {
        let mut m = RangeMap::new();
        for i in 0..10 {
            m.add(i * 10, i * 10 + 5, 1);
        }
        m.add(3, 97, 2);
        assert_eq!(m.total(), 97 - 3 + 3);
        for i in 0..10 {
            assert_eq!(m.get(i * 10 + 2).unwrap().label, 1);
        }
        assert_eq!(m.get(7).unwrap().label, 2);
        assert_eq!(m.get(96).unwrap().label, 2);
        assert_eq!(m.get(97), None);
    }

    #[test]
    fn dual_ranges_translate() {
        let mut m = RangeMap::new();
        m.add_dual(0x1000, 0x2000, Some(0x400), 1);
        m.add_dual(0x800, 0x1800, Some(0), 2);
        assert_eq!(m.translate(0x1234), Some(0x634));
        // The second range's unlabeled part keeps its own translation.
        assert_eq!(m.translate(0x900), Some(0x100));
        assert_eq!(m.translate(0x2000), None);
    }

    #[test]
    fn dual_map_ranges_and_padding() {
        let mut d = DualMap::default();
        // 0x30 bytes in memory, 0x20 in the file: 0x10 of zero fill.
        d.add_range(0x1000, 0x30, 0x400, 0x20, 1);
        // 0x10 in memory, 0x20 in the file: 0x10 of file padding.
        d.add_range(0x2000, 0x10, 0x600, 0x20, 2);
        assert_eq!(
            entries(&d.vm),
            [
                (0x1000, 0x1020, 1, Some(0x400)),
                (0x1020, 0x1030, 1, None),
                (0x2000, 0x2010, 2, Some(0x600)),
            ]
        );
        assert_eq!(
            entries(&d.file),
            [
                (0x400, 0x420, 1, Some(0x1000)),
                (0x600, 0x610, 2, Some(0x2000)),
                (0x610, 0x620, 2, None),
            ]
        );
    }

    #[test]
    fn translated_ranges_follow_the_base() {
        let mut base = DualMap::default();
        base.add_range(0x1000, 0x100, 0x400, 0x80, 1);
        base.add_range(0x2000, 0x100, 0x600, 0x100, 2);
        let mut d = DualMap::default();
        // Straddles the zero fill of the first range and the gap before
        // the second; only covered bytes are labeled.
        let covered = d.add_vm(0x1070, 0x2010, 5, &base);
        assert_eq!(covered, 0x90 + 0x10);
        assert_eq!(
            entries(&d.vm),
            [
                (0x1070, 0x1080, 5, Some(0x470)),
                (0x1080, 0x1100, 5, None),
                (0x2000, 0x2010, 5, Some(0x600)),
            ]
        );
        assert_eq!(
            entries(&d.file),
            [
                (0x470, 0x480, 5, Some(0x1070)),
                (0x600, 0x610, 5, Some(0x2000))
            ]
        );
        // A file range labels memory too.
        d.add_file(0x400, 0x480, 6, &base);
        assert_eq!(d.vm.get(0x1000).unwrap().label, 6);
        assert_eq!(d.vm.get(0x1075).unwrap().label, 5);
        // Outside the base: nothing.
        assert_eq!(d.add_vm(0x5000, 0x6000, 7, &base), 0);
    }

    #[test]
    fn fill_from_the_base() {
        let mut base = DualMap::default();
        base.add_range(0x1000, 0x100, 0x400, 0x100, 1);
        let mut d = DualMap::default();
        d.add_vm(0x1010, 0x1020, 5, &base);
        d.fill_from(&base, |l| l + 100);
        assert_eq!(
            entries(&d.vm),
            [
                (0x1000, 0x1010, 101, Some(0x400)),
                (0x1010, 0x1020, 5, Some(0x410)),
                (0x1020, 0x1100, 101, Some(0x420)),
            ]
        );
        assert_eq!(d.file.total(), 0x100);
    }

    #[test]
    fn compress_merges_alike_neighbors() {
        let mut m = RangeMap::new();
        m.add_dual(0, 10, Some(100), 1);
        m.add_dual(10, 20, Some(110), 1);
        m.add_dual(20, 30, Some(200), 1);
        m.add(30, 40, 1);
        m.add(40, 50, 1);
        m.add(50, 60, 2);
        m.compress();
        assert_eq!(
            entries(&m),
            [
                (0, 20, 1, Some(100)),
                (20, 30, 1, Some(200)),
                (30, 50, 1, None),
                (50, 60, 2, None)
            ]
        );
    }

    #[test]
    fn sweeps_split_at_every_boundary() {
        let mut a = RangeMap::new();
        a.add(0, 100, 0);
        a.add(200, 250, 1);
        let mut b = RangeMap::new();
        b.add(0, 40, 10);
        b.add(40, 120, 11);
        b.add(210, 250, 12);
        let mut c = RangeMap::new();
        c.add(20, 60, 20);
        let mut runs = Vec::new();
        sweep(&[&a, &b, &c], |s, e, l| runs.push((s, e, l.to_vec())));
        assert_eq!(
            runs,
            [
                (0, 20, vec![Some(0), Some(10), None]),
                (20, 40, vec![Some(0), Some(10), Some(20)]),
                (40, 60, vec![Some(0), Some(11), Some(20)]),
                (60, 100, vec![Some(0), Some(11), None]),
                (200, 210, vec![Some(1), None, None]),
                (210, 250, vec![Some(1), Some(12), None]),
            ]
        );
        let mut n = 0;
        sweep(&[], |_, _, _| n += 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn labels_intern() {
        let mut l = Labels::default();
        let a = l.intern(".text");
        let b = l.intern(".data");
        assert_eq!(l.intern(".text"), a);
        assert_ne!(a, b);
        assert_eq!(l.name(b), ".data");
        assert_eq!(l.len(), 2);
    }
}

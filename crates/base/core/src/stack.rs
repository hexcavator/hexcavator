//! A stack that keeps its first items inline and the rest on the heap: for
//! work lists that replace recursion over untrusted data, which are
//! usually shallow (no allocation) but must not be bounded by the thread's
//! stack when they aren't.

use alloc::vec::Vec;

/// A stack (and, by index, a list) whose first `N` items are stored
/// inline; more go to the heap. Items are `Copy` (frames, tasks, and
/// indices), which keeps it free of `unsafe`.
#[derive(Clone, Debug)]
pub struct SmallStack<T: Copy + Default, const N: usize> {
    inline: [T; N],
    /// How many of `inline` are in use.
    len: usize,
    /// The items after the first `N`.
    spill: Vec<T>,
}

impl<T: Copy + Default, const N: usize> Default for SmallStack<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> SmallStack<T, N> {
    /// An empty stack.
    pub fn new() -> Self {
        Self {
            inline: [T::default(); N],
            len: 0,
            spill: Vec::new(),
        }
    }

    /// How many items it holds.
    pub fn len(&self) -> usize {
        self.len + self.spill.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pushes `item`; returns its index.
    pub fn push(&mut self, item: T) -> usize {
        let index = self.len();
        if self.len < N {
            self.inline[self.len] = item;
            self.len += 1;
        } else {
            self.spill.push(item);
        }
        index
    }

    /// Removes and returns the last item.
    pub fn pop(&mut self) -> Option<T> {
        if let Some(item) = self.spill.pop() {
            return Some(item);
        }
        let i = self.len.checked_sub(1)?;
        self.len = i;
        Some(self.inline[i])
    }

    /// The last item.
    pub fn last(&self) -> Option<T> {
        match self.spill.last() {
            Some(&item) => Some(item),
            None => self.len.checked_sub(1).map(|i| self.inline[i]),
        }
    }

    /// The item at `index`.
    pub fn get(&self, index: usize) -> Option<T> {
        if index < self.len {
            Some(self.inline[index])
        } else {
            self.spill.get(index.checked_sub(N)?).copied()
        }
    }

    /// Keeps the first `len` items (the heap's memory is kept for reuse).
    pub fn truncate(&mut self, len: usize) {
        if len < N {
            self.spill.clear();
            self.len = self.len.min(len);
        } else {
            self.spill.truncate(len - N);
        }
    }

    /// Removes every item (the heap's memory is kept for reuse).
    pub fn clear(&mut self) {
        self.truncate(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_then_heap() {
        let mut s: SmallStack<u32, 4> = SmallStack::new();
        assert!(s.is_empty());
        assert_eq!(s.pop(), None);
        assert_eq!(s.last(), None);
        for i in 0..10 {
            assert_eq!(s.push(i * 10), usize::try_from(i).unwrap());
            assert_eq!(s.last(), Some(i * 10));
        }
        assert_eq!(s.len(), 10);
        for i in 0..10 {
            assert_eq!(s.get(i), Some(u32::try_from(i).unwrap() * 10));
        }
        assert_eq!(s.get(10), None);
        for i in (0..10).rev() {
            assert_eq!(s.pop(), Some(i * 10));
        }
        assert_eq!(s.pop(), None);
        assert!(s.is_empty());
    }

    #[test]
    fn truncate() {
        let mut s: SmallStack<u8, 3> = SmallStack::new();
        for i in 0..8 {
            s.push(i);
        }
        s.truncate(5);
        assert_eq!(s.len(), 5);
        assert_eq!(s.last(), Some(4));
        s.truncate(2);
        assert_eq!(s.len(), 2);
        assert_eq!(s.last(), Some(1));
        s.push(9);
        s.push(10);
        assert_eq!(s.get(3), Some(10));
        assert_eq!(s.get(2), Some(9));
        s.truncate(7);
        assert_eq!(s.len(), 4);
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.get(0), None);
    }
}

//! Interned stacks.
//!
//! Every distinct stack is a path in a trie whose root is the empty stack:
//! a node is a frame and its parent is the frame that called it, so a
//! stack's outermost frame (the thread's start) is nearest the root. A
//! [`StackId`] names the node of a stack's innermost frame. Stacks that
//! share callers share nodes, so a trace's millions of stacks take little
//! space, and the top-down call tree is the trie itself.

use rustc_hash::FxHashMap;

/// A stack: the trie node of its innermost frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct StackId(pub u32);

impl StackId {
    /// The empty stack.
    pub const EMPTY: StackId = StackId(0);

    /// Whether this is the empty stack.
    pub fn is_empty(self) -> bool {
        self == Self::EMPTY
    }
}

/// The trie of a trace's stacks.
#[derive(Clone, Debug)]
pub struct StackStore {
    parent: Vec<StackId>,
    frame: Vec<u64>,
    depth: Vec<u32>,
    children: FxHashMap<(StackId, u64), StackId>,
}

impl Default for StackStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StackStore {
    /// A store holding only the empty stack.
    pub fn new() -> Self {
        Self {
            parent: vec![StackId::EMPTY],
            frame: vec![0],
            depth: vec![0],
            children: FxHashMap::default(),
        }
    }

    /// The number of nodes, the empty stack included.
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// Whether the store holds only the empty stack.
    pub fn is_empty(&self) -> bool {
        self.len() == 1
    }

    /// The stack `parent` with `frame` called from its innermost frame.
    pub fn push(&mut self, parent: StackId, frame: u64) -> StackId {
        if let Some(&id) = self.children.get(&(parent, frame)) {
            return id;
        }
        let id = StackId(u32::try_from(self.parent.len()).expect("fewer than 4G stack nodes"));
        self.parent.push(parent);
        self.frame.push(frame);
        self.depth.push(self.depth[parent.0 as usize] + 1);
        self.children.insert((parent, frame), id);
        id
    }

    /// The stack of `frames`, given innermost first (as traces log them).
    pub fn intern_innermost_first(&mut self, frames: &[u64]) -> StackId {
        frames
            .iter()
            .rev()
            .fold(StackId::EMPTY, |s, &f| self.push(s, f))
    }

    /// The stack of `frames`, given outermost first, using and updating
    /// `cache`: the path of a recent stack, as (frame, node) pairs from the
    /// outermost. Frames shared with it are found without hashing, which is
    /// most of them when the cache holds the same thread's previous stack.
    pub fn intern_outermost_first(&mut self, frames: &[u64], cache: &mut PathCache) -> StackId {
        let path = &mut cache.path;
        let shared = path
            .iter()
            .zip(frames)
            .take_while(|((f, _), g)| f == *g)
            .count();
        path.truncate(shared);
        let mut id = path.last().map_or(StackId::EMPTY, |&(_, id)| id);
        for &f in &frames[shared..] {
            id = self.push(id, f);
            path.push((f, id));
        }
        id
    }

    /// The frames of `id`, outermost first, into `out` (cleared first).
    pub fn frames_outermost_first(&self, id: StackId, out: &mut Vec<u64>) {
        out.clear();
        out.extend(self.frames(id));
        out.reverse();
    }

    /// The stack `inner` called from `outer`: `outer`'s frames, then
    /// `inner`'s. (A split stack: the user part is the outer one.)
    pub fn join(&mut self, outer: StackId, inner: StackId) -> StackId {
        let mut frames: Vec<u64> = self.frames(inner).collect();
        frames.reverse();
        frames.into_iter().fold(outer, |s, f| self.push(s, f))
    }

    /// The caller of the innermost frame: the stack without it.
    pub fn parent(&self, id: StackId) -> StackId {
        self.parent[id.0 as usize]
    }

    /// The innermost frame's address (0 for the empty stack).
    pub fn frame(&self, id: StackId) -> u64 {
        self.frame[id.0 as usize]
    }

    /// The number of frames.
    pub fn depth(&self, id: StackId) -> u32 {
        self.depth[id.0 as usize]
    }

    /// The frames, innermost first.
    pub fn frames(&self, id: StackId) -> impl Iterator<Item = u64> + '_ {
        let mut cur = id;
        std::iter::from_fn(move || {
            if cur.is_empty() {
                return None;
            }
            let f = self.frame(cur);
            cur = self.parent(cur);
            Some(f)
        })
    }
}

/// A recent stack's path, for [`StackStore::intern_outermost_first`].
#[derive(Clone, Debug, Default)]
pub struct PathCache {
    path: Vec<(u64, StackId)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_callers() {
        let mut s = StackStore::new();
        let a = s.intern_innermost_first(&[3, 2, 1]);
        let b = s.intern_innermost_first(&[4, 2, 1]);
        assert_ne!(a, b);
        assert_eq!(s.parent(a), s.parent(b));
        assert_eq!(s.len(), 5); // empty, 1, 2, 3, 4
        assert_eq!(s.frames(a).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(s.depth(b), 3);
        assert_eq!(s.intern_innermost_first(&[3, 2, 1]), a);
        assert_eq!(s.intern_innermost_first(&[]), StackId::EMPTY);
    }

    #[test]
    fn cached_interning_agrees() {
        let mut s = StackStore::new();
        let mut cache = PathCache::default();
        let stacks: [&[u64]; 5] = [&[1, 2, 3], &[1, 2, 4], &[1, 5], &[], &[1, 2, 3, 6]];
        for frames in stacks {
            let cached = s.intern_outermost_first(frames, &mut cache);
            let inner_first: Vec<u64> = frames.iter().rev().copied().collect();
            assert_eq!(cached, s.intern_innermost_first(&inner_first));
            let mut out = Vec::new();
            s.frames_outermost_first(cached, &mut out);
            assert_eq!(out, frames);
        }
    }

    #[test]
    fn joins_split_stacks() {
        let mut s = StackStore::new();
        let kernel = s.intern_innermost_first(&[0xfff1, 0xfff2]);
        let user = s.intern_innermost_first(&[0x11, 0x12]);
        let whole = s.join(user, kernel);
        assert_eq!(
            s.frames(whole).collect::<Vec<_>>(),
            [0xfff1, 0xfff2, 0x11, 0x12]
        );
        assert_eq!(
            whole,
            s.intern_innermost_first(&[0xfff1, 0xfff2, 0x11, 0x12])
        );
    }
}

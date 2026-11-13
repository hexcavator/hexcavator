// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Follows the Swift project's demangler (see LICENSE-SWIFT at the crate root).

//! The demangling tree: nodes in an arena, addressed by index.
//!
//! Swift's `Node` is a pointer-linked tree from a bump allocator; here the
//! nodes live in a vector and refer to their children by index, and all
//! their text lives in one buffer. A tree is bounded ([`MAX_NODES`]), so a
//! hostile name can't make it grow without limit.

use alloc::string::String;
use alloc::vec::Vec;

use super::kinds::Kind;

/// A node in a [`Tree`].
pub type NodeId = u32;

/// The most nodes one tree may hold.
pub const MAX_NODES: usize = 1 << 20;
/// The most text one tree may hold.
pub const MAX_TEXT: usize = 1 << 24;

/// What a node carries besides its children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload {
    /// Nothing.
    None,
    /// Text, in the tree's text buffer.
    Text { start: u32, len: u32 },
    /// A number.
    Index(u64),
    /// A remote address and its address space.
    RemoteAddress(u64, u8),
}

/// A node: its kind, payload, and children.
#[derive(Clone, Debug)]
pub struct Node {
    pub kind: Kind,
    pub payload: Payload,
    pub children: Vec<NodeId>,
}

/// A demangling tree's nodes.
#[derive(Default, Debug)]
pub struct Tree {
    nodes: Vec<Node>,
    text: String,
    /// Set when a bound was reached: the tree is incomplete.
    pub overflow: bool,
}

impl Tree {
    /// Empties the tree, keeping its memory.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.text.clear();
        self.overflow = false;
    }

    fn push(&mut self, kind: Kind, payload: Payload) -> Option<NodeId> {
        if self.nodes.len() >= MAX_NODES {
            self.overflow = true;
            return None;
        }
        let id = self.nodes.len() as NodeId;
        self.nodes.push(Node {
            kind,
            payload,
            children: Vec::new(),
        });
        Some(id)
    }

    /// A node with no payload.
    pub fn create(&mut self, kind: Kind) -> Option<NodeId> {
        self.push(kind, Payload::None)
    }

    /// A node with text.
    pub fn create_text(&mut self, kind: Kind, text: &str) -> Option<NodeId> {
        if self.text.len() + text.len() > MAX_TEXT {
            self.overflow = true;
            return None;
        }
        let start = self.text.len() as u32;
        self.text.push_str(text);
        self.push(
            kind,
            Payload::Text {
                start,
                len: text.len() as u32,
            },
        )
    }

    /// A node with a number.
    pub fn create_index(&mut self, kind: Kind, index: u64) -> Option<NodeId> {
        self.push(kind, Payload::Index(index))
    }

    /// A node with a remote address.
    pub fn create_remote_address(&mut self, kind: Kind, address: u64, space: u8) -> Option<NodeId> {
        self.push(kind, Payload::RemoteAddress(address, space))
    }

    /// A node with `child`.
    pub fn create_with_child(&mut self, kind: Kind, child: Option<NodeId>) -> Option<NodeId> {
        let child = child?;
        let n = self.create(kind)?;
        self.add_child(n, child);
        Some(n)
    }

    /// A node with `children` (all of which must be present).
    pub fn create_with_children(
        &mut self,
        kind: Kind,
        children: &[Option<NodeId>],
    ) -> Option<NodeId> {
        if children.iter().any(Option::is_none) {
            return None;
        }
        let n = self.create(kind)?;
        for c in children.iter().flatten() {
            self.add_child(n, *c);
        }
        Some(n)
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    pub fn kind(&self, id: NodeId) -> Kind {
        self.nodes[id as usize].kind
    }

    pub fn set_kind(&mut self, id: NodeId, kind: Kind) {
        self.nodes[id as usize].kind = kind;
    }

    pub fn num_children(&self, id: NodeId) -> usize {
        self.nodes[id as usize].children.len()
    }

    pub fn has_children(&self, id: NodeId) -> bool {
        !self.nodes[id as usize].children.is_empty()
    }

    /// Child `i`, if there is one.
    pub fn child(&self, id: NodeId, i: usize) -> Option<NodeId> {
        self.nodes[id as usize].children.get(i).copied()
    }

    pub fn first_child(&self, id: NodeId) -> Option<NodeId> {
        self.child(id, 0)
    }

    pub fn last_child(&self, id: NodeId) -> Option<NodeId> {
        self.nodes[id as usize].children.last().copied()
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        &self.nodes[id as usize].children
    }

    /// The kind of child `i` (if there is one).
    pub fn child_kind(&self, id: NodeId, i: usize) -> Option<Kind> {
        self.child(id, i).map(|c| self.kind(c))
    }

    pub fn has_text(&self, id: NodeId) -> bool {
        matches!(self.nodes[id as usize].payload, Payload::Text { .. })
    }

    /// The node's text (empty if it has none).
    pub fn text(&self, id: NodeId) -> &str {
        match self.nodes[id as usize].payload {
            Payload::Text { start, len } => &self.text[start as usize..(start + len) as usize],
            _ => "",
        }
    }

    pub fn has_index(&self, id: NodeId) -> bool {
        matches!(self.nodes[id as usize].payload, Payload::Index(_))
    }

    /// The node's number (0 if it has none).
    pub fn index(&self, id: NodeId) -> u64 {
        match self.nodes[id as usize].payload {
            Payload::Index(i) => i,
            _ => 0,
        }
    }

    pub fn payload(&self, id: NodeId) -> Payload {
        self.nodes[id as usize].payload
    }

    pub fn add_child(&mut self, parent: NodeId, child: NodeId) {
        self.nodes[parent as usize].children.push(child);
    }

    /// Adds `child` (if present) to `parent` (if present); Swift's
    /// `Demangler::addChild`, which returns null if either is.
    pub fn add_child_opt(
        &mut self,
        parent: Option<NodeId>,
        child: Option<NodeId>,
    ) -> Option<NodeId> {
        let (p, c) = (parent?, child?);
        self.add_child(p, c);
        Some(p)
    }

    pub fn remove_child_at(&mut self, id: NodeId, i: usize) {
        let c = &mut self.nodes[id as usize].children;
        if i < c.len() {
            c.remove(i);
        }
    }

    pub fn replace_child(&mut self, id: NodeId, i: usize, child: NodeId) {
        if let Some(c) = self.nodes[id as usize].children.get_mut(i) {
            *c = child;
        }
    }

    pub fn insert_child(&mut self, id: NodeId, i: usize, child: NodeId) {
        let c = &mut self.nodes[id as usize].children;
        let i = i.min(c.len());
        c.insert(i, child);
    }

    /// Reverses the children from `start` on.
    pub fn reverse_children(&mut self, id: NodeId, start: usize) {
        let c = &mut self.nodes[id as usize].children;
        if start < c.len() {
            c[start..].reverse();
        }
    }

    /// The first node of `kind` in `id`'s subtree, depth-first (searching at
    /// most `max_depth` levels).
    pub fn find_by_kind(&self, id: NodeId, kind: Kind, max_depth: u32) -> Option<NodeId> {
        let mut stack = alloc::vec![(id, max_depth)];
        while let Some((id, depth)) = stack.pop() {
            if self.kind(id) == kind {
                return Some(id);
            }
            if depth > 0 {
                let at = stack.len();
                stack.extend(self.children(id).iter().map(|&c| (c, depth - 1)));
                stack[at..].reverse();
            }
        }
        None
    }

    /// Whether two subtrees are equal (Swift's `Node::isEqual`), to `depth`.
    pub fn is_equal(&self, a: NodeId, b: NodeId, depth: u32) -> bool {
        let mut stack = alloc::vec![(a, b, depth)];
        while let Some((a, b, depth)) = stack.pop() {
            if depth == 0 {
                return false;
            }
            let (x, y) = (self.node(a), self.node(b));
            if x.kind != y.kind || x.children.len() != y.children.len() {
                return false;
            }
            let same_payload = match (x.payload, y.payload) {
                (Payload::Text { .. }, Payload::Text { .. }) => self.text(a) == self.text(b),
                (p, q) => p == q,
            };
            if !same_payload {
                return false;
            }
            stack.extend(
                x.children
                    .iter()
                    .zip(&y.children)
                    .map(|(&c, &d)| (c, d, depth - 1)),
            );
        }
        true
    }
}

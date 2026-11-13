//! Cross-references: a graph of what each function and datum of an image
//! refers to, and why each is reachable.
//!
//! The nodes are address ranges (functions, data, tables), given by the
//! caller from symbols. The edges come from the code ([`scan`]: direct
//! calls and branches, and the addresses operands compute), from pointers
//! in data (an image's relocations say where they are), and from what the
//! caller knows about the format (a function owns its unwind data, unwind
//! data names its handler). [`Graph::reach`] walks the edges from roots
//! (entry points, exports, initializer tables); [`Reach::chain`] is the
//! shortest path to a node, which says why it is there.
//!
//! A virtual function needs no special case: a vtable points to it, and a
//! constructor or destructor (which store the vtable's address in the
//! object) refers to the vtable, so the chain to it runs through whoever
//! constructs or destroys an object of the class.

#![warn(missing_docs)]

mod scan;

pub use scan::{Arch, CodeRef, Via, scan, scan_image};

/// One node: `[start, end)`, and whether it is code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    /// Where it starts.
    pub start: u64,
    /// Where it ends (exclusive).
    pub end: u64,
    /// Whether it is code (its references are found by disassembly).
    pub code: bool,
}

/// Why one node refers to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Edge {
    /// Its code calls the other.
    Call,
    /// Its code branches to the other (a tail call, or a jump table's
    /// target).
    Jump,
    /// Its code computes or accesses the other's address.
    Address,
    /// It holds a pointer to the other (a vtable's slot, a table of
    /// functions, an initializer list).
    Pointer,
    /// The other belongs to it (a function's unwind data, exception
    /// handling tables, a vtable's RTTI).
    Attached,
}

impl Edge {
    /// How the edge reads in a chain: "`a` calls `b`".
    pub fn verb(self) -> &'static str {
        match self {
            Edge::Call => "calls",
            Edge::Jump => "jumps to",
            Edge::Address => "refers to",
            Edge::Pointer => "points to",
            Edge::Attached => "owns",
        }
    }
}

/// A node's index, from its position ([`Builder::new`] holds the count
/// below `u32::MAX - 1`, which the reach markers use).
fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

/// How far before a node an address in no node may be and still mean it.
pub const NEAR: u64 = 16;

/// Builds a [`Graph`] from nodes, then edges given by address.
pub struct Builder {
    nodes: Vec<Node>,
    edges: Vec<(u32, u32, Edge)>,
    refs: Vec<CodeRef>,
    image_base: Option<u64>,
    /// Which nodes to split where they are referred to (empty: none).
    split: Vec<bool>,
    /// The edges to or from a node to split, by address.
    addressed: Vec<Addressed>,
}

/// An edge to or from a node to split: from (and its address), to (and its
/// address), and its kind.
type Addressed = (u32, u64, u32, u64, Edge);

/// The nodes after splitting, each one's origin, and each builder node's
/// pieces (first, count).
type Pieces = (Vec<Node>, Vec<u32>, Vec<(u32, u32)>);

impl Builder {
    /// A builder of the graph of `nodes`, which are sorted by start, outer
    /// before inner (by [`Builder::new`]); a node's index is its position in
    /// that order. Empty nodes are kept (as places a name points), but
    /// nothing is inside them.
    ///
    /// # Panics
    ///
    /// If there are `u32::MAX` nodes or more (indexes are `u32`).
    pub fn new(mut nodes: Vec<Node>) -> Self {
        assert!(
            u32::try_from(nodes.len()).is_ok_and(|n| n < u32::MAX - 1),
            "too many nodes"
        );
        nodes.sort_by_key(|n| (n.start, std::cmp::Reverse(n.end)));
        Builder {
            nodes,
            edges: Vec::new(),
            refs: Vec::new(),
            image_base: None,
            split: Vec::new(),
            addressed: Vec::new(),
        }
    }

    /// Splits node `node` (unlabeled data, say, which may hold several
    /// objects) where it is referred to: each address an edge reaches in it
    /// starts a piece, which runs to the next. Edges from it come from the
    /// piece holding their address. Call it before adding edges.
    pub fn split(&mut self, node: u32) {
        if self.split.is_empty() {
            self.split = vec![false; self.nodes.len()];
        }
        self.split[node as usize] = true;
    }

    fn is_split(&self, node: u32) -> bool {
        self.split.get(node as usize).copied().unwrap_or(false)
    }

    /// Adds an edge from `from` (at `from_at`) to `to` (at `to_at`); the
    /// addresses matter only for nodes to split.
    fn add(&mut self, from: u32, from_at: u64, to: u32, to_at: u64, kind: Edge) {
        if self.is_split(from) || self.is_split(to) {
            self.addressed.push((from, from_at, to, to_at, kind));
        } else if from != to {
            self.edges.push((from, to, kind));
        }
    }

    /// Where the image starts, in the nodes' address space, for references
    /// relative to it (see [`scan_image`]).
    pub fn image_base(&mut self, base: u64) {
        self.image_base = Some(base);
    }

    /// The nodes, in the builder's order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The node `address` is in: the last starting at or before it that
    /// extends past it.
    pub fn node_at(&self, address: u64) -> Option<u32> {
        node_at(&self.nodes, address)
    }

    /// The node starting at `address`.
    pub fn node_starting_at(&self, address: u64) -> Option<u32> {
        let i = self.nodes.partition_point(|n| n.start < address);
        (self.nodes.get(i)?.start == address).then_some(index(i))
    }

    /// The node starting at most [`NEAR`] bytes after `address`: the one
    /// code means by an address just before it (compilers fold a constant
    /// offset into an address, `table - 1` for a table indexed from 1).
    fn node_just_after(&self, address: u64) -> Option<u32> {
        let i = self.nodes.partition_point(|n| n.start <= address);
        let n = self.nodes.get(i)?;
        (n.start - address <= NEAR).then_some(index(i))
    }

    /// Adds an edge from node `from` to node `to`. An edge from a node to
    /// itself is dropped.
    pub fn edge(&mut self, from: u32, to: u32, kind: Edge) {
        let (f, t) = (
            self.nodes[from as usize].start,
            self.nodes[to as usize].start,
        );
        self.add(from, f, to, t, kind);
    }

    /// Adds an edge from the node containing `from` to the node containing
    /// `to`, if both are in nodes. A pointer to the first byte past a node
    /// (a table's end) is not to it.
    pub fn edge_at(&mut self, from: u64, to: u64, kind: Edge) {
        if let (Some(f), Some(t)) = (self.node_at(from), self.node_at(to)) {
            self.add(f, from, t, to, kind);
        }
    }

    /// Scans the code of node `node` (`code`, its bytes) and adds the edges
    /// it makes. A call or branch counts only to the start of a node (to
    /// within one, it is the node's own control flow, or a decoding of data
    /// as code); an address counts anywhere in a node, or in no node but
    /// just before one (see [`NEAR`]), and a computed one ([`Via::AddressOf`])
    /// just before a node counts for it too, even inside another (`table - 1`
    /// where tables are packed back to back).
    pub fn code(&mut self, node: u32, arch: Arch, code: &[u8]) {
        let mut refs = std::mem::take(&mut self.refs);
        refs.clear();
        scan_image(
            arch,
            code,
            self.nodes[node as usize].start,
            self.image_base,
            &mut refs,
        );
        for r in &refs {
            let (to, kind) = match r.via {
                Via::Call | Via::Jump => {
                    let Some(to) = self.node_starting_at(r.to) else {
                        continue;
                    };
                    (
                        to,
                        if r.via == Via::Call {
                            Edge::Call
                        } else {
                            Edge::Jump
                        },
                    )
                }
                Via::Address | Via::AddressOf => {
                    // A computed address just before a node may mean it
                    // even inside another (tables packed back to back).
                    let next = self.node_just_after(r.to);
                    let at = self.node_at(r.to);
                    // (Not when the address is its own node's start: that
                    // is the node it means.)
                    if r.via == Via::AddressOf
                        && let (Some(a), Some(n)) = (at, next)
                        && a != n
                        && r.to != self.nodes[a as usize].start
                    {
                        self.edge(node, n, Edge::Address);
                    }
                    let Some(to) = at.or(next) else {
                        continue;
                    };
                    (to, Edge::Address)
                }
            };
            // (An address just before a node is its start.)
            let at = r.to.max(self.nodes[to as usize].start);
            self.add(node, r.from, to, at, kind);
        }
        self.refs = refs;
    }

    /// The graph: edges deduplicated, keeping the first kind (in [`Edge`]'s
    /// order) of each pair's.
    pub fn finish(mut self) -> Graph {
        let (nodes, origin, pieces) = self.pieces();
        let mut edges = std::mem::take(&mut self.edges);
        if !self.split.is_empty() {
            // Renumber: a node not split is one piece; edges by address go
            // to and from the piece holding the address.
            for e in &mut edges {
                e.0 = pieces[e.0 as usize].0;
                e.1 = pieces[e.1 as usize].0;
            }
            let piece = |old: u32, at: u64| {
                let (first, count) = pieces[old as usize];
                let run = &nodes[first as usize..(first + count) as usize];
                first + index(run.partition_point(|n| n.start <= at).max(1) - 1)
            };
            for &(f, fa, t, ta, k) in &self.addressed {
                let (f, t) = (piece(f, fa), piece(t, ta));
                if f != t {
                    edges.push((f, t, k));
                }
            }
        }
        edges.sort_unstable();
        edges.dedup_by_key(|e| (e.0, e.1));
        let n = nodes.len();
        let out = Csr::new(n, edges.iter().map(|&(f, t, k)| (f, t, k)));
        let inn = Csr::new(n, edges.iter().map(|&(f, t, k)| (t, f, k)));
        Graph {
            nodes,
            origin,
            pieces,
            out,
            inn,
        }
    }

    /// The nodes after splitting, each one's origin (the builder's index),
    /// and each builder node's pieces (first, count), which are contiguous
    /// (nothing is inside a node to split).
    fn pieces(&mut self) -> Pieces {
        let n = self.nodes.len();
        if self.split.is_empty() {
            let ids = (0..n).map(index).collect();
            let pieces = (0..n).map(|i| (index(i), 1)).collect();
            return (std::mem::take(&mut self.nodes), ids, pieces);
        }
        // Where each node to split is cut: its start, and every address an
        // edge reaches in it.
        let mut cuts: Vec<(u32, u64)> = (0..n)
            .filter(|&i| self.split[i])
            .map(|i| (index(i), self.nodes[i].start))
            .collect();
        cuts.extend(
            self.addressed
                .iter()
                .filter(|e| self.split[e.2 as usize])
                .map(|e| (e.2, e.3)),
        );
        cuts.sort_unstable();
        cuts.dedup();
        let mut out: Vec<(Node, u32)> = Vec::with_capacity(n + cuts.len());
        let mut c = 0;
        for (i, &node) in self.nodes.iter().enumerate() {
            let start = c;
            while c < cuts.len() && cuts[c].0 as usize == i {
                c += 1;
            }
            if !self.split[i] {
                out.push((node, index(i)));
                continue;
            }
            let at = &cuts[start..c];
            for (k, &(_, from)) in at.iter().enumerate() {
                let to = at.get(k + 1).map_or(node.end, |x| x.1);
                out.push((
                    Node {
                        start: from,
                        end: to.max(from),
                        code: node.code,
                    },
                    index(i),
                ));
            }
        }
        out.sort_by_key(|(n, o)| (n.start, std::cmp::Reverse(n.end), *o));
        assert!(index(out.len()) < u32::MAX - 1, "too many nodes");
        let mut pieces = vec![(0u32, 0u32); n];
        for (j, &(_, o)) in out.iter().enumerate() {
            let p = &mut pieces[o as usize];
            if p.1 == 0 {
                p.0 = index(j);
            }
            p.1 += 1;
        }
        let (nodes, origin): (Vec<Node>, Vec<u32>) = out.into_iter().unzip();
        (nodes, origin, pieces)
    }
}

fn node_at(nodes: &[Node], address: u64) -> Option<u32> {
    let i = nodes.partition_point(|n| n.start <= address);
    // The nearest starts at or before the address; a nested node (one
    // inside another) starts later than its container, so it is found
    // first. Look back past empty and ended nodes a little way.
    nodes[..i]
        .iter()
        .enumerate()
        .rev()
        .take(8)
        .find(|(_, n)| address < n.end)
        .map(|(j, _)| index(j))
}

/// Adjacency in compressed rows: each node's edges, contiguous.
struct Csr {
    start: Vec<u32>,
    edges: Vec<(u32, Edge)>,
}

impl Csr {
    fn new(n: usize, edges: impl Iterator<Item = (u32, u32, Edge)> + Clone) -> Csr {
        let mut start = vec![0u32; n + 1];
        for (f, _, _) in edges.clone() {
            start[f as usize + 1] += 1;
        }
        for i in 0..n {
            start[i + 1] += start[i];
        }
        let mut fill = start.clone();
        let mut out = vec![(0u32, Edge::Call); start[n] as usize];
        for (f, t, k) in edges {
            let slot = &mut fill[f as usize];
            out[*slot as usize] = (t, k);
            *slot += 1;
        }
        // Each node's edges in order of target, then kind.
        for i in 0..n {
            out[start[i] as usize..start[i + 1] as usize].sort_unstable();
        }
        Csr { start, edges: out }
    }

    fn of(&self, node: u32) -> &[(u32, Edge)] {
        &self.edges[self.start[node as usize] as usize..self.start[node as usize + 1] as usize]
    }
}

/// The reference graph of an image.
pub struct Graph {
    nodes: Vec<Node>,
    /// Each node's index in the builder (they differ where nodes split).
    origin: Vec<u32>,
    /// Each builder node's pieces: (first, count), contiguous.
    pieces: Vec<(u32, u32)>,
    out: Csr,
    inn: Csr,
}

impl Graph {
    /// The nodes, by index.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The builder's index of the node `node` is (or is a piece of).
    pub fn origin(&self, node: u32) -> u32 {
        self.origin[node as usize]
    }

    /// The nodes the builder's node `node` became: itself, or its pieces.
    pub fn pieces(&self, node: u32) -> std::ops::Range<u32> {
        let (first, count) = self.pieces[node as usize];
        first..first + count
    }

    /// The node `address` is in (see [`Builder::node_at`]).
    pub fn node_at(&self, address: u64) -> Option<u32> {
        node_at(&self.nodes, address)
    }

    /// The node starting at `address` (the outermost, if several do).
    pub fn node_starting_at(&self, address: u64) -> Option<u32> {
        let i = self.nodes.partition_point(|n| n.start < address);
        (self.nodes.get(i)?.start == address).then_some(index(i))
    }

    /// What `node` refers to: (node, how), by node.
    pub fn references(&self, node: u32) -> &[(u32, Edge)] {
        self.out.of(node)
    }

    /// What refers to `node`: (node, how), by node.
    pub fn referrers(&self, node: u32) -> &[(u32, Edge)] {
        self.inn.of(node)
    }

    /// The edge count.
    pub fn edge_count(&self) -> usize {
        self.out.edges.len()
    }

    /// Which nodes `roots` reach, each by a shortest chain (breadth first;
    /// among a node's referrers at the same depth, the first found, which
    /// is the earliest root's).
    pub fn reach(&self, roots: &[u32]) -> Reach {
        let n = self.nodes.len();
        let mut parent = vec![UNREACHED; n];
        let mut via = vec![Edge::Call; n];
        let mut queue = std::collections::VecDeque::new();
        for &r in roots {
            if parent[r as usize] == UNREACHED {
                parent[r as usize] = ROOT;
                queue.push_back(r);
            }
        }
        while let Some(f) = queue.pop_front() {
            for &(t, k) in self.out.of(f) {
                if parent[t as usize] == UNREACHED {
                    parent[t as usize] = f;
                    via[t as usize] = k;
                    queue.push_back(t);
                }
            }
        }
        Reach { parent, via }
    }
}

const UNREACHED: u32 = u32::MAX;
const ROOT: u32 = u32::MAX - 1;

/// What [`Graph::reach`] found.
pub struct Reach {
    parent: Vec<u32>,
    via: Vec<Edge>,
}

impl Reach {
    /// Whether a root reaches `node` (or it is one).
    pub fn is_reached(&self, node: u32) -> bool {
        self.parent[node as usize] != UNREACHED
    }

    /// Whether `node` is a root.
    pub fn is_root(&self, node: u32) -> bool {
        self.parent[node as usize] == ROOT
    }

    /// The chain from a root to `node`: the root, then each node with the
    /// edge that reached it. `None` if `node` is unreached.
    pub fn chain(&self, node: u32) -> Option<(u32, Vec<(Edge, u32)>)> {
        if !self.is_reached(node) {
            return None;
        }
        let mut steps = Vec::new();
        let mut at = node;
        while self.parent[at as usize] != ROOT {
            steps.push((self.via[at as usize], at));
            at = self.parent[at as usize];
        }
        steps.reverse();
        Some((at, steps))
    }
}

#[cfg(test)]
mod tests;

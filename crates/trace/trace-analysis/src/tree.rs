//! The stack tree: WPA's drill-down view, computed as it is expanded.
//!
//! A query's data is a set of weighted [`Instances`]: each a sequence of
//! keys (the grouping columns, then frames from the outermost) and a weight
//! (samples, or nanoseconds). A [`Tree`] node is a prefix of those
//! sequences. Expanding a node partitions the instances it holds by their
//! next key, so a level costs only what its parent holds, and nothing is
//! computed for nodes nobody opens.
//!
//! Inverting the tree (callers instead of callees) and focusing on one
//! function (its callers or its callees) are transformations of the
//! instances, so every view is the same tree.

use rustc_hash::FxHashMap;

use crate::keys::KeyId;

/// Weighted key sequences.
#[derive(Clone, Debug, Default)]
pub struct Instances {
    keys: Vec<KeyId>,
    /// `keys[starts[i]..starts[i + 1]]` is instance `i`.
    starts: Vec<u32>,
    weights: Vec<u64>,
    /// How many events each instance stands for.
    counts: Vec<u64>,
    /// How many leading keys of each instance are grouping columns.
    groups: usize,
}

impl Instances {
    /// No instances, each to start with `groups` grouping keys.
    pub fn new(groups: usize) -> Self {
        Self {
            keys: Vec::new(),
            starts: vec![0],
            weights: Vec::new(),
            counts: Vec::new(),
            groups,
        }
    }

    /// Adds an instance that stands for one event.
    pub fn push(&mut self, keys: &[KeyId], weight: u64) {
        self.push_counted(keys, weight, 1);
    }

    /// Adds an instance that stands for `count` events.
    pub fn push_counted(&mut self, keys: &[KeyId], weight: u64, count: u64) {
        self.keys.extend_from_slice(keys);
        self.starts
            .push(u32::try_from(self.keys.len()).expect("fewer than 4G keys"));
        self.weights.push(weight);
        self.counts.push(count);
    }

    /// Instance `i`'s event count.
    pub fn count(&self, i: usize) -> u64 {
        self.counts[i]
    }

    /// The same instances with only their grouping keys (no frames),
    /// merged where those are equal.
    pub fn without_frames(&self) -> Self {
        let mut merged: rustc_hash::FxHashMap<&[KeyId], (u64, u64)> =
            rustc_hash::FxHashMap::default();
        let mut order: Vec<&[KeyId]> = Vec::new();
        for i in 0..self.len() {
            let k = self.keys(i);
            let g = &k[..self.groups.min(k.len())];
            let e = merged.entry(g).or_insert_with(|| {
                order.push(g);
                (0, 0)
            });
            e.0 += self.weight(i);
            e.1 += self.count(i);
        }
        let mut out = Self::new(self.groups);
        for g in order {
            let (w, c) = merged[g];
            out.push_counted(g, w, c);
        }
        out
    }

    /// The number of instances.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    /// Instance `i`'s keys.
    pub fn keys(&self, i: usize) -> &[KeyId] {
        &self.keys[self.starts[i] as usize..self.starts[i + 1] as usize]
    }

    /// Instance `i`'s weight.
    pub fn weight(&self, i: usize) -> u64 {
        self.weights[i]
    }

    /// How many leading keys are grouping columns.
    pub fn groups(&self) -> usize {
        self.groups
    }

    /// The total weight.
    pub fn total(&self) -> u64 {
        self.weights.iter().sum()
    }

    /// The same instances with the frames reversed: innermost first, so
    /// the tree's first level is where time was spent and each level below
    /// is a caller.
    pub fn inverted(&self) -> Self {
        let mut out = Self::new(self.groups);
        let mut buf = Vec::new();
        for i in 0..self.len() {
            let k = self.keys(i);
            let g = self.groups.min(k.len());
            buf.clear();
            buf.extend_from_slice(&k[..g]);
            buf.extend(k[g..].iter().rev());
            out.push_counted(&buf, self.weight(i), self.count(i));
        }
        out
    }

    /// The callees of `focus`: for each instance whose frames include it,
    /// `focus` and the frames it called, from its outermost appearance
    /// (merging recursion). Grouping columns are dropped.
    pub fn callees(&self, focus: KeyId) -> Self {
        let mut out = Self::new(0);
        for i in 0..self.len() {
            let frames = &self.keys(i)[self.groups..];
            if let Some(at) = frames.iter().position(|&k| k == focus) {
                out.push_counted(&frames[at..], self.weight(i), self.count(i));
            }
        }
        out
    }

    /// The callers of `focus`: for each instance whose frames include it,
    /// `focus` and its callers, outward from its innermost appearance
    /// (merging recursion). Grouping columns are dropped.
    pub fn callers(&self, focus: KeyId) -> Self {
        let mut out = Self::new(0);
        let mut buf = Vec::new();
        for i in 0..self.len() {
            let frames = &self.keys(i)[self.groups..];
            if let Some(at) = frames.iter().rposition(|&k| k == focus) {
                buf.clear();
                buf.extend(frames[..=at].iter().rev());
                out.push_counted(&buf, self.weight(i), self.count(i));
            }
        }
        out
    }

    /// Only the instances for which `keep(keys)` holds.
    pub fn filtered(&self, mut keep: impl FnMut(&[KeyId]) -> bool) -> Self {
        let mut out = Self::new(self.groups);
        for i in 0..self.len() {
            if keep(self.keys(i)) {
                out.push_counted(self.keys(i), self.weight(i), self.count(i));
            }
        }
        out
    }
}

/// A node of a [`Tree`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    /// The root: everything.
    pub const ROOT: NodeId = NodeId(0);
}

/// A child being built: inclusive and exclusive weight, inclusive count,
/// and members.
type Child = (u64, u64, u64, Vec<u32>);

#[derive(Clone, Debug)]
struct Node {
    key: Option<KeyId>,
    parent: NodeId,
    depth: u32,
    inclusive: u64,
    exclusive: u64,
    count: u64,
    /// The instances under the node, until it's expanded.
    members: Vec<u32>,
    children: Option<Vec<NodeId>>,
}

/// A stack tree over [`Instances`], expanded on demand.
#[derive(Clone, Debug)]
pub struct Tree {
    instances: Instances,
    nodes: Vec<Node>,
}

impl Tree {
    /// The tree of `instances`.
    pub fn new(instances: Instances) -> Self {
        let members: Vec<u32> =
            (0..u32::try_from(instances.len()).expect("fewer than 4G instances")).collect();
        let exclusive = (0..instances.len())
            .filter(|&i| instances.keys(i).is_empty())
            .map(|i| instances.weight(i))
            .sum();
        let count = (0..instances.len()).map(|i| instances.count(i)).sum();
        let root = Node {
            key: None,
            parent: NodeId::ROOT,
            depth: 0,
            inclusive: instances.total(),
            exclusive,
            count,
            members,
            children: None,
        };
        Self {
            instances,
            nodes: vec![root],
        }
    }

    /// How many nodes have been made (node IDs are below this).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The instances.
    pub fn instances(&self) -> &Instances {
        &self.instances
    }

    /// The node's key (`None` for the root).
    pub fn key(&self, node: NodeId) -> Option<KeyId> {
        self.nodes[node.0 as usize].key
    }

    /// The node's parent (the root's is itself).
    pub fn parent(&self, node: NodeId) -> NodeId {
        self.nodes[node.0 as usize].parent
    }

    /// The node's depth: 0 for the root.
    pub fn depth(&self, node: NodeId) -> u32 {
        self.nodes[node.0 as usize].depth
    }

    /// The weight of everything under the node.
    pub fn inclusive(&self, node: NodeId) -> u64 {
        self.nodes[node.0 as usize].inclusive
    }

    /// The number of events under the node.
    pub fn count(&self, node: NodeId) -> u64 {
        self.nodes[node.0 as usize].count
    }

    /// Whether the node has children (without expanding it).
    pub fn has_children(&self, node: NodeId) -> bool {
        let n = &self.nodes[node.0 as usize];
        match &n.children {
            Some(c) => !c.is_empty(),
            None => {
                let depth = n.depth as usize;
                n.members
                    .iter()
                    .any(|&m| self.instances.keys(m as usize).len() > depth)
            }
        }
    }

    /// The weight of instances that end at the node.
    pub fn exclusive(&self, node: NodeId) -> u64 {
        self.nodes[node.0 as usize].exclusive
    }

    /// The node's children, heaviest first, expanding it if it hasn't
    /// been.
    pub fn children(&mut self, node: NodeId) -> &[NodeId] {
        if self.nodes[node.0 as usize].children.is_none() {
            self.expand(node);
        }
        self.nodes[node.0 as usize]
            .children
            .as_deref()
            .unwrap_or(&[])
    }

    fn expand(&mut self, node: NodeId) {
        let n = &mut self.nodes[node.0 as usize];
        let depth = n.depth as usize;
        let members = std::mem::take(&mut n.members);
        let mut groups: FxHashMap<KeyId, Child> = FxHashMap::default();
        for &m in &members {
            let keys = self.instances.keys(m as usize);
            let Some(&k) = keys.get(depth) else { continue };
            let w = self.instances.weight(m as usize);
            let e = groups.entry(k).or_default();
            e.0 += w;
            if keys.len() == depth + 1 {
                e.1 += w;
            }
            e.2 += self.instances.count(m as usize);
            e.3.push(m);
        }
        let mut children: Vec<(KeyId, Child)> = groups.into_iter().collect();
        // Heaviest first; ties by key, so the order is deterministic.
        children.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(&b.0)));
        let mut ids = Vec::with_capacity(children.len());
        for (key, (inclusive, exclusive, count, members)) in children {
            let id = NodeId(u32::try_from(self.nodes.len()).expect("fewer than 4G nodes"));
            self.nodes.push(Node {
                key: Some(key),
                parent: node,
                depth: u32::try_from(depth + 1).expect("shallow"),
                inclusive,
                exclusive,
                count,
                members,
                children: None,
            });
            ids.push(id);
        }
        self.nodes[node.0 as usize].children = Some(ids);
    }

    /// The hot path from `node`: the heaviest child, its heaviest child, and
    /// so on, while a child holds at least `fraction` of its parent's weight.
    pub fn hot_path(&mut self, node: NodeId, fraction: f64) -> Vec<NodeId> {
        let mut path = Vec::new();
        let mut cur = node;
        loop {
            let parent_weight = self.inclusive(cur);
            let Some(&first) = self.children(cur).first() else {
                break;
            };
            #[allow(clippy::cast_precision_loss)]
            if (self.inclusive(first) as f64) < fraction * parent_weight as f64 {
                break;
            }
            path.push(first);
            cur = first;
        }
        path
    }

    /// The keys from the root to `node`.
    pub fn path(&self, node: NodeId) -> Vec<KeyId> {
        let mut out = Vec::new();
        let mut cur = node;
        while let Some(k) = self.key(cur) {
            out.push(k);
            cur = self.parent(cur);
        }
        out.reverse();
        out
    }
}

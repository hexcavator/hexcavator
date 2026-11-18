//! Queries over an open trace, and the rows they show.
//!
//! A [`TreeSpec`] says what a stack tree weighs and how it groups; a
//! [`TreeView`] is the tree, expanded as rows are asked for. Rows carry
//! everything a table shows for a node: its label, weights and whether it
//! has children.

use hexcavator_trace::Trace;
use hexcavator_trace_analysis::{
    Filter, FrameMode, Framer, GroupBy, Keys, NodeId, Precise, Resolver, SwitchWeight, Symbolizer,
    Tree, label, sources,
};
use serde_json::{Value, json};

/// What a tree weighs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// CPU usage (sampled): samples.
    Samples,
    /// CPU usage (precise): how long threads ran after being switched in.
    Running,
    /// Waits: how long threads waited before being switched in.
    Waits,
}

impl Source {
    /// The source named `name` (`samples`, `running`, `waits`).
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "samples" => Self::Samples,
            "running" => Self::Running,
            "waits" => Self::Waits,
            _ => return None,
        })
    }
}

/// A grouping column, by name (`process`, `thread`, `cpu`).
pub fn parse_group(name: &str) -> Option<GroupBy> {
    Some(match name {
        "process" => GroupBy::Process,
        "thread" => GroupBy::Thread,
        "cpu" => GroupBy::Cpu,
        _ => return None,
    })
}

/// How frames are told apart, by name (`function`, `module`, `address`).
pub fn parse_frames(name: &str) -> Option<FrameMode> {
    Some(match name {
        "function" => FrameMode::Function,
        "module" => FrameMode::Module,
        "address" => FrameMode::Address,
        _ => return None,
    })
}

/// A stack tree's definition.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeSpec {
    /// What it weighs.
    pub source: Source,
    /// The grouping columns, outermost first.
    pub groups: Vec<GroupBy>,
    /// How frames are told apart.
    pub frames: FrameMode,
    /// Callers instead of callees: innermost frames first.
    pub invert: bool,
    /// Only events in `[start, end)` nanoseconds from the trace's start.
    pub time: Option<(i64, i64)>,
}

impl Default for TreeSpec {
    fn default() -> Self {
        Self {
            source: Source::Samples,
            groups: vec![GroupBy::Process],
            frames: FrameMode::Function,
            invert: false,
            time: None,
        }
    }
}

impl TreeSpec {
    /// The spec a request's parameters give: `source`, `groupBy` (a list),
    /// `frames`, `invert` and `time` (`[start, end]` in nanoseconds), each
    /// optional.
    pub fn from_json(params: &Value) -> Result<Self, String> {
        let mut spec = Self::default();
        if let Some(s) = params.get("source") {
            let name = s.as_str().ok_or("source: expected a string")?;
            spec.source = Source::parse(name).ok_or_else(|| format!("source: unknown '{name}'"))?;
        }
        if let Some(g) = params.get("groupBy") {
            let list = g.as_array().ok_or("groupBy: expected a list")?;
            spec.groups = list
                .iter()
                .map(|v| {
                    let name = v.as_str().ok_or("groupBy: expected names")?;
                    parse_group(name).ok_or_else(|| format!("groupBy: unknown '{name}'"))
                })
                .collect::<Result<_, String>>()?;
        }
        if let Some(f) = params.get("frames") {
            let name = f.as_str().ok_or("frames: expected a string")?;
            spec.frames = parse_frames(name).ok_or_else(|| format!("frames: unknown '{name}'"))?;
        }
        if let Some(i) = params.get("invert") {
            spec.invert = i.as_bool().ok_or("invert: expected true or false")?;
        }
        if let Some(t) = params.get("time")
            && !t.is_null()
        {
            let pair = t
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or("time: expected [start, end]")?;
            let n = |v: &Value| v.as_i64().ok_or("time: expected nanoseconds");
            spec.time = Some((n(&pair[0])?, n(&pair[1])?));
        }
        Ok(spec)
    }
}

/// The unit of a tree's weights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Samples.
    Samples,
    /// Clock ticks.
    Ticks,
}

/// A stack tree over an open trace.
pub struct TreeView {
    /// Its definition.
    pub spec: TreeSpec,
    /// The tree.
    pub tree: Tree,
    /// Its nodes' keys.
    pub keys: Keys,
    /// Its weights' unit.
    pub unit: Unit,
}

/// One row of a tree: a node and what a table shows for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The node.
    pub id: u32,
    /// Its parent.
    pub parent: u32,
    /// Its depth (the root's children are at 1).
    pub depth: u32,
    /// What it is.
    pub label: String,
    /// Its weight, children included.
    pub inclusive: u64,
    /// Its weight without its children's.
    pub exclusive: u64,
    /// The events under it.
    pub count: u64,
    /// Whether it has children.
    pub has_children: bool,
}

impl Row {
    /// The row as JSON.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "parent": self.parent,
            "depth": self.depth,
            "label": self.label,
            "inclusive": self.inclusive,
            "exclusive": self.exclusive,
            "count": self.count,
            "hasChildren": self.has_children,
        })
    }
}

/// Clock ticks of `ns` nanoseconds from the trace's start.
fn ticks(trace: &Trace, ns: i64) -> i64 {
    let tps = i128::from(trace.clock.ticks_per_second.max(1));
    let t = i128::from(trace.clock.origin) + i128::from(ns) * tps / 1_000_000_000;
    i64::try_from(t).unwrap_or(if t < 0 { i64::MIN } else { i64::MAX })
}

impl TreeView {
    /// The tree `spec` defines over `trace`.
    pub fn build(
        trace: &Trace,
        resolver: &Resolver,
        symbols: &dyn Symbolizer,
        spec: TreeSpec,
    ) -> Self {
        let mut framer = Framer::new(trace, resolver, symbols, spec.frames);
        let mut keys = Keys::default();
        let filter = Filter {
            time: spec.time.map(|(s, e)| (ticks(trace, s), ticks(trace, e))),
            ..Filter::default()
        };
        let (instances, unit) = match spec.source {
            Source::Samples => (
                sources::samples(trace, &mut framer, &mut keys, &spec.groups, &filter),
                Unit::Samples,
            ),
            Source::Running | Source::Waits => {
                let precise = Precise::new(trace);
                let weight = if spec.source == Source::Running {
                    SwitchWeight::Running
                } else {
                    SwitchWeight::Waited
                };
                (
                    sources::switches(
                        trace,
                        &precise,
                        &mut framer,
                        &mut keys,
                        &spec.groups,
                        &filter,
                        weight,
                    ),
                    Unit::Ticks,
                )
            }
        };
        let instances = if spec.invert {
            instances.inverted()
        } else {
            instances
        };
        Self {
            spec,
            tree: Tree::new(instances),
            keys,
            unit,
        }
    }

    /// The row of `node`.
    pub fn row(&self, trace: &Trace, symbols: &dyn Symbolizer, node: NodeId) -> Row {
        let t = &self.tree;
        Row {
            id: node.0,
            parent: t.parent(node).0,
            depth: t.depth(node),
            label: t.key(node).map_or_else(
                || "All".to_string(),
                |k| label(trace, self.keys.get(k), symbols),
            ),
            inclusive: t.inclusive(node),
            exclusive: t.exclusive(node),
            count: t.count(node),
            has_children: t.has_children(node),
        }
    }

    /// Whether `node` is one of the tree's nodes.
    pub fn has_node(&self, node: NodeId) -> bool {
        (node.0 as usize) < self.tree.node_count()
    }

    /// The rows of `node`'s children, heaviest first (expanding it).
    pub fn children(&mut self, trace: &Trace, symbols: &dyn Symbolizer, node: NodeId) -> Vec<Row> {
        let ids = self.tree.children(node).to_vec();
        ids.into_iter()
            .map(|c| self.row(trace, symbols, c))
            .collect()
    }

    /// The hot path from `node`: the heaviest child, its heaviest child,
    /// and so on, while each holds at least `fraction` of its parent.
    pub fn hot_path(
        &mut self,
        trace: &Trace,
        symbols: &dyn Symbolizer,
        node: NodeId,
        fraction: f64,
    ) -> Vec<Row> {
        let ids = self.tree.hot_path(node, fraction);
        ids.into_iter()
            .map(|c| self.row(trace, symbols, c))
            .collect()
    }
}

/// A trace's summary, as JSON: its size, time span, and what it holds.
pub fn summary(trace: &Trace) -> Value {
    let times = trace
        .samples
        .time
        .iter()
        .chain(&trace.switches.time)
        .chain(&trace.readies.time);
    let (first, last) = times.fold((i64::MAX, i64::MIN), |(a, b), &t| (a.min(t), b.max(t)));
    let span = if first <= last {
        trace.clock.nanos(last) - trace.clock.nanos(first)
    } else {
        0
    };
    json!({
        "processors": trace.processors,
        "durationNs": span,
        "startNs": if first <= last { trace.clock.nanos(first) } else { 0 },
        "sampleIntervalNs": trace.sample_interval_ns(),
        "processes": trace.processes.len(),
        "threads": trace.threads.len(),
        "images": trace.images.len(),
        "samples": trace.samples.len(),
        "switches": trace.switches.len(),
        "readies": trace.readies.len(),
    })
}

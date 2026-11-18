//! Queries over an open trace, and the rows they show.
//!
//! A [`TreeSpec`] says what a stack tree weighs and how it groups; a
//! [`TreeView`] is the tree, expanded as rows are asked for. Rows carry
//! everything a table shows for a node: its label, weights and whether it
//! has children.

use hexcavator_trace::{ProcessIx, Trace};
use hexcavator_trace_analysis::{
    Filter, FrameMode, Framer, GroupBy, Key, Keys, NodeId, Precise, Resolver, StackTags,
    SwitchWeight, Symbolizer, Tree, label, sources,
};
use rustc_hash::FxHashMap;
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

/// A grouping column, by name (`process`, `thread`, `cpu`, `tag`).
pub fn parse_group(name: &str) -> Option<GroupBy> {
    Some(match name {
        "process" => GroupBy::Process,
        "thread" => GroupBy::Thread,
        "cpu" => GroupBy::Cpu,
        "tag" => GroupBy::StackTag,
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
    /// The stack tags' names, by tag.
    tag_names: Vec<String>,
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
        tags: Option<&StackTags>,
        spec: TreeSpec,
    ) -> Self {
        let mut framer = Framer::new(trace, resolver, symbols, spec.frames);
        if let Some(t) = tags {
            framer = framer.with_tags(t.clone());
        }
        let tag_names = tags.map_or_else(Vec::new, |t| {
            (0..u32::try_from(t.len()).expect("few tags"))
                .map(|i| t.name(i).to_string())
                .collect()
        });
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
            tag_names,
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
                |k| match self.keys.get(k) {
                    Key::Tag(Key::NO_TAG) => "Other".to_string(),
                    Key::Tag(i) => self
                        .tag_names
                        .get(i as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("Tag {i}")),
                    key => label(trace, key, symbols),
                },
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

/// The time a trace's events span: from its first sample, switch or ready
/// event to its last, in clock ticks.
pub fn span(trace: &Trace) -> Option<(i64, i64)> {
    let times = trace
        .samples
        .time
        .iter()
        .chain(&trace.switches.time)
        .chain(&trace.readies.time);
    let (first, last) = times.fold((i64::MAX, i64::MIN), |(a, b), &t| (a.min(t), b.max(t)));
    (first <= last).then_some((first, last))
}

/// CPU usage over time, by process, from `source`: sampled (each sample
/// a sampling interval of CPU) or precise (`Source::Running`: each
/// switch-in's running time, split across the buckets it overlaps). Each
/// series's values are the share of all the processors the process used,
/// in `buckets` equal intervals of `[start, end)` nanoseconds from the
/// trace's start (by default, all of it). The `top` heaviest processes are
/// series of their own, the rest one ("Other"); the idle process isn't in
/// it. (Sampled: fewer buckets, if fewer hold four sampling intervals
/// each.) Each series also says its weight: `samples` (sampled) or `ns`
/// (precise).
pub fn cpu_graph(
    trace: &Trace,
    source: Source,
    buckets: usize,
    time: Option<(i64, i64)>,
    top: usize,
) -> Value {
    let buckets = buckets.clamp(1, 10_000);
    let (first, last) = span(trace).unwrap_or((trace.clock.origin, trace.clock.origin));
    let (start, end) = match time {
        Some((s, e)) => (ticks(trace, s), ticks(trace, e)),
        None => (first, last + 1),
    };
    let width = (end - start).max(1);
    let span_ns = (trace.clock.nanos(end) - trace.clock.nanos(start)).max(1);
    let precise = source != Source::Samples;
    // Sampled: at least four sampling intervals a bucket; fewer, and each
    // bucket holds a sample or none, and the graph is all spikes.
    let buckets = if precise {
        buckets
    } else {
        let fit = usize::try_from(
            span_ns / (4 * i64::try_from(trace.sample_interval_ns()).unwrap_or(i64::MAX)).max(1),
        )
        .unwrap_or(usize::MAX)
        .max(1);
        buckets.min(fit)
    };
    let is_idle = |p: ProcessIx| p.is_some() && trace.processes[p.index()].pid == 0;
    let bucket_of = |t: i64| {
        usize::try_from(i128::from(t - start) * buckets as i128 / i128::from(width))
            .unwrap_or(0)
            .min(buckets - 1)
    };
    // Each process's weight per bucket: samples, or clock ticks running.
    let mut by_process: FxHashMap<ProcessIx, Vec<u64>> = FxHashMap::default();
    if precise {
        let p = Precise::new(trace);
        let sw = &trace.switches;
        let to = sw.time.partition_point(|&t| t < end);
        // A bucket's first tick.
        let edge = |b: usize| {
            start
                + i64::try_from(i128::from(width) * b as i128 / buckets as i128).unwrap_or(i64::MAX)
        };
        for i in 0..to {
            let run = i64::try_from(p.running[i]).unwrap_or(i64::MAX);
            let (a, z) = (
                sw.time[i].max(start),
                sw.time[i].saturating_add(run).min(end),
            );
            let process = trace.thread_process(sw.new_thread[i]);
            if a >= z || is_idle(process) {
                continue;
            }
            let v = by_process
                .entry(process)
                .or_insert_with(|| vec![0; buckets]);
            let mut b = bucket_of(a);
            let mut t = a;
            while t < z {
                let next = if b + 1 < buckets {
                    edge(b + 1).min(z)
                } else {
                    z
                };
                v[b] += u64::try_from(next - t).unwrap_or(0);
                t = next;
                b += 1;
            }
        }
    } else {
        let s = &trace.samples;
        // The samples in range: they are in time order.
        let from = s.time.partition_point(|&t| t < start);
        let to = s.time.partition_point(|&t| t < end);
        for i in from..to {
            let process = trace.thread_process(s.thread[i]);
            if is_idle(process) {
                continue;
            }
            by_process
                .entry(process)
                .or_insert_with(|| vec![0; buckets])[bucket_of(s.time[i])] +=
                u64::from(s.weight[i]);
        }
    }
    let mut totals: Vec<(ProcessIx, u64)> = by_process
        .iter()
        .map(|(&p, v)| (p, v.iter().sum()))
        .collect();
    totals.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    // A bucket's weight as a share of all the processors' time in it.
    let bucket_ns = span_ns as f64 / buckets as f64;
    let capacity = bucket_ns * f64::from(trace.processors.max(1));
    let unit_ns = if precise {
        1e9 / trace.clock.ticks_per_second.max(1) as f64
    } else {
        trace.sample_interval_ns() as f64
    };
    let share = |v: &[u64]| -> Vec<f64> {
        v.iter()
            .map(|&n| ((n as f64 * unit_ns / capacity).min(1.0) * 10_000.0).round() / 10_000.0)
            .collect()
    };
    let weight = |v: &[u64]| {
        let sum: u64 = v.iter().sum();
        if precise {
            // (In integers: exactly the ticks' nanoseconds.)
            let ns =
                u128::from(sum) * 1_000_000_000 / u128::from(trace.clock.ticks_per_second.max(1));
            json!({"ns": u64::try_from(ns).unwrap_or(u64::MAX)})
        } else {
            json!({"samples": sum})
        }
    };
    let series_of = |label: String, v: &[u64]| {
        let mut o = weight(v);
        o["label"] = json!(label);
        o["values"] = json!(share(v));
        o
    };
    let mut series = Vec::new();
    let mut other = vec![0u64; buckets];
    for (i, (p, _)) in totals.iter().enumerate() {
        let v = &by_process[p];
        if i < top {
            let label = if p.is_some() {
                let pr = &trace.processes[p.index()];
                format!("{} ({})", pr.name, pr.pid)
            } else {
                "Unknown process".to_string()
            };
            series.push(series_of(label, v));
        } else {
            for (o, &x) in other.iter_mut().zip(v) {
                *o += x;
            }
        }
    }
    if totals.len() > top {
        series.push(series_of("Other".to_string(), &other));
    }
    json!({
        "source": if precise { "running" } else { "samples" },
        "startNs": trace.clock.nanos(start),
        "endNs": trace.clock.nanos(end),
        "buckets": buckets,
        "series": series,
    })
}

/// The trace's processes, as a table: each one's ID, name, command line,
/// start and end (nanoseconds from the trace's start, or null for before
/// and after it), threads, and CPU samples in `[start, end)` (all of the
/// trace by default); heaviest first.
pub fn processes(trace: &Trace, time: Option<(i64, i64)>) -> Value {
    let filter = time.map(|(s, e)| (ticks(trace, s), ticks(trace, e)));
    let s = &trace.samples;
    let (from, to) = match filter {
        Some((a, b)) => (
            s.time.partition_point(|&t| t < a),
            s.time.partition_point(|&t| t < b),
        ),
        None => (0, s.len()),
    };
    let mut samples = vec![0u64; trace.processes.len()];
    for i in from..to {
        let p = trace.thread_process(s.thread[i]);
        if p.is_some() {
            samples[p.index()] += u64::from(s.weight[i]);
        }
    }
    let mut threads = vec![0u32; trace.processes.len()];
    for t in &trace.threads {
        if t.process.is_some() {
            threads[t.process.index()] += 1;
        }
    }
    let interval = trace.sample_interval_ns();
    let mut rows: Vec<(usize, Value)> = trace
        .processes
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                i,
                json!({
                    "pid": p.pid,
                    "parentPid": p.parent_pid,
                    "name": p.name,
                    "commandLine": p.command_line,
                    "startNs": p.start.map(|t| trace.clock.nanos(t)),
                    "endNs": p.end.map(|t| trace.clock.nanos(t)),
                    "exitStatus": p.exit_status,
                    "threads": threads[i],
                    "samples": samples[i],
                    "cpuMs": (samples[i] * interval) as f64 / 1e6,
                }),
            )
        })
        .collect();
    rows.sort_by(|a, b| samples[b.0].cmp(&samples[a.0]).then(a.0.cmp(&b.0)));
    json!({"rows": rows.into_iter().map(|(_, v)| v).collect::<Vec<_>>()})
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

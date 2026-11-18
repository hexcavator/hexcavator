//! Queries over an open trace, and the rows they show.
//!
//! A [`TreeSpec`] says what a stack tree weighs and how it groups; a
//! [`TreeView`] is the tree, expanded as rows are asked for. Rows carry
//! everything a table shows for a node: its label, weights and whether it
//! has children.

use hexcavator_trace::{ImageIx, ProcessIx, StackId, ThreadIx, Trace};
use hexcavator_trace_analysis::{
    BinTotals, Filter, FrameMode, Framer, GroupBy, Instances, Key, KeyId, Keys, NO_BIN, NodeId,
    Precise, Resolver, StackTags, SwitchWeight, Symbolizer, Tree, label, sources,
};
use rustc_hash::{FxHashMap, FxHashSet};
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
    /// Its function's (or module's) ID, if it is one (see
    /// [`function_id`]).
    pub function: Option<String>,
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
            "fn": self.function,
        })
    }
}

/// The instances `spec` weighs (not inverted: [`TreeView::build`] inverts
/// them for callers), their keys, their unit, and the stack tags' names.
fn weighed(
    trace: &Trace,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    tags: Option<&StackTags>,
    spec: &TreeSpec,
) -> (Instances, Keys, Unit, Vec<String>) {
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
    (instances, keys, unit, tag_names)
}

/// The hot functions and modules: every function (by `spec`'s frames, so
/// by module or address too) and every module, with how much of `spec`'s
/// weight is in it (exclusive: where it is the innermost frame) and under
/// it (inclusive: in its callees too, counted once in a recursion), in
/// `spec`'s time range; its grouping columns and inversion don't matter.
/// The `limit` heaviest functions by each, heaviest exclusive first; all
/// the modules.
pub fn functions(
    trace: &Trace,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    spec: &TreeSpec,
    limit: usize,
) -> Value {
    let spec = TreeSpec {
        groups: Vec::new(),
        invert: false,
        ..spec.clone()
    };
    let (instances, keys, unit, _) = weighed(trace, resolver, symbols, None, &spec);
    let total = instances.total();
    let key_of = |k: usize| keys.get(KeyId(u32::try_from(k).expect("a key")));
    // Functions: by module file name and place in it (a DLL is an image
    // in each process it is in: its functions are one row each), and
    // modules by file name; addresses in no image are one of each.
    let mut function_ids: FxHashMap<(&str, u8, u64), u32> = FxHashMap::default();
    let mut function_key: Vec<usize> = Vec::new();
    let mut module_ids: FxHashMap<&str, u32> = FxHashMap::default();
    let mut module_names: Vec<&str> = Vec::new();
    let mut function_bins = vec![NO_BIN; keys.len()];
    let mut module_bins = vec![NO_BIN; keys.len()];
    for k in 0..keys.len() {
        let (module, kind, place) = match key_of(k) {
            Key::Frame { image, offset } => (trace.images[image.index()].file_name(), 0, offset),
            Key::Inline { image, site } => {
                (trace.images[image.index()].file_name(), 1, u64::from(site))
            }
            Key::Unknown(a) => ("?", 2, a),
            _ => continue,
        };
        let next = u32::try_from(function_key.len()).expect("fewer than 4G functions");
        function_bins[k] = *function_ids
            .entry((module, kind, place))
            .or_insert_with(|| {
                function_key.push(k);
                next
            });
        let next = u32::try_from(module_names.len()).expect("fewer than 4G modules");
        module_bins[k] = *module_ids.entry(module).or_insert_with(|| {
            module_names.push(module);
            next
        });
    }
    let by_function = instances.totals(&function_bins, function_key.len());
    let by_module = instances.totals(&module_bins, module_names.len());
    let row = |label: String, t: &BinTotals| {
        json!({
            "label": label,
            "exclusive": t.exclusive,
            "inclusive": t.inclusive,
            "count": t.count,
        })
    };
    // The heaviest by each measure.
    let mut order: Vec<usize> = (0..function_key.len())
        .filter(|&f| by_function[f].inclusive > 0)
        .collect();
    let mut keep = vec![false; function_key.len()];
    order.sort_by(|&a, &b| {
        by_function[b]
            .inclusive
            .cmp(&by_function[a].inclusive)
            .then(a.cmp(&b))
    });
    for &f in order.iter().take(limit) {
        keep[f] = true;
    }
    order.sort_by(|&a, &b| {
        by_function[b]
            .exclusive
            .cmp(&by_function[a].exclusive)
            .then(by_function[b].inclusive.cmp(&by_function[a].inclusive))
            .then(a.cmp(&b))
    });
    for &f in order.iter().take(limit) {
        keep[f] = true;
    }
    let functions: Vec<Value> = order
        .iter()
        .filter(|&&f| keep[f])
        .map(|&f| {
            let key = key_of(function_key[f]);
            let mut r = row(label(trace, key, symbols), &by_function[f]);
            r["fn"] = json!(function_id(trace, key, spec.frames));
            r["module"] = match key {
                Key::Frame { image, .. } | Key::Inline { image, .. } => {
                    json!(trace.images[image.index()].file_name())
                }
                _ => json!("?"),
            };
            r
        })
        .collect();
    let mut modules: Vec<(usize, &BinTotals)> = by_module
        .iter()
        .enumerate()
        .filter(|(_, t)| t.inclusive > 0)
        .collect();
    modules.sort_by(|a, b| {
        b.1.exclusive
            .cmp(&a.1.exclusive)
            .then(b.1.inclusive.cmp(&a.1.inclusive))
            .then(a.0.cmp(&b.0))
    });
    let modules: Vec<Value> = modules
        .into_iter()
        .map(|(i, t)| row(module_names[i].to_string(), t))
        .collect();
    json!({
        "unit": match unit {
            Unit::Samples => "samples",
            Unit::Ticks => "ticks",
        },
        "ticksPerSecond": trace.clock.ticks_per_second,
        "total": total,
        "functionCount": order.len(),
        "functions": functions,
        "modules": modules,
    })
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
        let (instances, keys, unit, tag_names) = weighed(trace, resolver, symbols, tags, &spec);
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
            function: t
                .key(node)
                .and_then(|k| function_id(trace, self.keys.get(k), self.spec.frames)),
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
    highlight: Option<&Highlight<'_>>,
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
    // Each process's weight per bucket: samples, or clock ticks running;
    // and the highlighted function's (idle or not).
    let mut by_process: FxHashMap<ProcessIx, Vec<u64>> = FxHashMap::default();
    let mut lit = vec![0u64; buckets];
    if precise {
        let p = Precise::new(trace);
        let sw = &trace.switches;
        let to = sw.time.partition_point(|&t| t < end);
        let marked = highlight.map(|h| {
            h.marks(0..to, |i| {
                (trace.thread_process(sw.new_thread[i]), sw.stack[i], 0)
            })
        });
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
            let lit_too = marked.as_ref().is_some_and(|m| m[i]);
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
                let n = u64::try_from(next - t).unwrap_or(0);
                v[b] += n;
                if lit_too {
                    lit[b] += n;
                }
                t = next;
                b += 1;
            }
        }
    } else {
        let s = &trace.samples;
        // The samples in range: they are in time order.
        let from = s.time.partition_point(|&t| t < start);
        let to = s.time.partition_point(|&t| t < end);
        let marked = highlight.map(|h| {
            h.marks(from..to, |i| {
                (trace.thread_process(s.thread[i]), s.stack[i], s.ip[i])
            })
        });
        for i in from..to {
            let process = trace.thread_process(s.thread[i]);
            if is_idle(process) {
                continue;
            }
            let b = bucket_of(s.time[i]);
            by_process
                .entry(process)
                .or_insert_with(|| vec![0; buckets])[b] += u64::from(s.weight[i]);
            if marked.as_ref().is_some_and(|m| m[i - from]) {
                lit[b] += u64::from(s.weight[i]);
            }
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
    let mut out = json!({
        "source": if precise { "running" } else { "samples" },
        "startNs": trace.clock.nanos(start),
        "endNs": trace.clock.nanos(end),
        "buckets": buckets,
        "series": series,
    });
    if let Some(h) = highlight {
        out["highlight"] = series_of(h.id.clone(), &lit);
    }
    out
}

/// A function or module to highlight in a graph: the events with it on
/// their stacks. (See [`function_id`] for its ID.)
pub struct Highlight<'a> {
    trace: &'a Trace,
    resolver: &'a Resolver,
    symbols: &'a dyn Symbolizer,
    /// Its ID.
    pub id: String,
    /// The images of its module (one in each process it is in).
    images: FxHashSet<ImageIx>,
    target: Target,
}

/// What a [`Highlight`] looks for in its module's images.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Any frame.
    Module,
    /// A frame in the function starting at this offset.
    Function(u64),
    /// A call inlined at this site.
    Inline(u32),
}

/// A function's or module's ID, as rows and [`Highlight`]s name it (the
/// same in every process): `module|m` for a module, `module|<offset>`
/// (hex) for a function, `module|i<site>` for an inlined call. Frames by
/// address have none.
pub fn function_id(trace: &Trace, key: Key, mode: FrameMode) -> Option<String> {
    let file = |image: ImageIx| trace.images[image.index()].file_name().to_string();
    match key {
        Key::Frame { image, offset } if offset == Key::MODULE => Some(format!("{}|m", file(image))),
        Key::Frame { image, offset } if mode == FrameMode::Function => {
            Some(format!("{}|{offset:x}", file(image)))
        }
        Key::Inline { image, site } => Some(format!("{}|i{site}", file(image))),
        _ => None,
    }
}

impl<'a> Highlight<'a> {
    /// The function or module `id` names (see [`function_id`]).
    pub fn new(
        trace: &'a Trace,
        resolver: &'a Resolver,
        symbols: &'a dyn Symbolizer,
        id: &str,
    ) -> Result<Self, String> {
        let bad = || format!("highlight: not a function's ID: {id}");
        let (module, what) = id.rsplit_once('|').ok_or_else(bad)?;
        let target = if what == "m" {
            Target::Module
        } else if let Some(site) = what.strip_prefix('i') {
            Target::Inline(site.parse().map_err(|_| bad())?)
        } else {
            Target::Function(u64::from_str_radix(what, 16).map_err(|_| bad())?)
        };
        let images = (0..trace.images.len())
            .filter(|&i| trace.images[i].file_name() == module)
            .map(|i| ImageIx(u32::try_from(i).expect("fewer than 4G images")))
            .collect();
        Ok(Self {
            trace,
            resolver,
            symbols,
            id: id.to_string(),
            images,
            target,
        })
    }

    /// Whether the frame at `address` in `process` is it.
    fn is(
        &self,
        framer: &mut Framer<'_>,
        process: ProcessIx,
        address: u64,
        return_address: bool,
    ) -> bool {
        let (key, inlined) = framer.frame(process, address, return_address);
        match (self.target, key) {
            (Target::Module, Key::Frame { image, .. }) => self.images.contains(&image),
            (Target::Function(f), Key::Frame { image, offset }) => {
                offset == f && self.images.contains(&image)
            }
            (Target::Inline(s), _) => inlined.iter().any(|k| {
                matches!(*k, Key::Inline { image, site } if site == s && self.images.contains(&image))
            }),
            _ => false,
        }
    }

    /// Which of the events `rows` (each one's process, stack, and
    /// instruction pointer for one without a stack, by `event`) have it on
    /// their stacks: by row, from the range's start. On every core, in
    /// chunks; each stack's callers looked at once a chunk.
    pub fn marks(
        &self,
        rows: std::ops::Range<usize>,
        event: impl Fn(usize) -> (ProcessIx, StackId, u64) + Sync,
    ) -> Vec<bool> {
        const CHUNK: usize = 1 << 15;
        if self.images.is_empty() {
            return vec![false; rows.len()];
        }
        let mode = if self.target == Target::Module {
            FrameMode::Module
        } else {
            FrameMode::Function
        };
        let chunks: Vec<std::ops::Range<usize>> = rows
            .clone()
            .step_by(CHUNK)
            .map(|from| from..(from + CHUNK).min(rows.end))
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let done: Vec<std::sync::Mutex<Vec<bool>>> =
            chunks.iter().map(|_| std::sync::Mutex::default()).collect();
        let threads = std::thread::available_parallelism()
            .map_or(4, std::num::NonZero::get)
            .min(chunks.len());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let mut framer = Framer::new(self.trace, self.resolver, self.symbols, mode);
                    // Whether a node's frame or a caller's is it (its frame
                    // a return address).
                    let mut callers: FxHashMap<(ProcessIx, StackId), bool> = FxHashMap::default();
                    let mut walk: Vec<StackId> = Vec::new();
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(range) = chunks.get(c) else { return };
                        let mut out = Vec::with_capacity(range.len());
                        for i in range.clone() {
                            let (process, stack, ip) = event(i);
                            let stacks = &self.trace.stacks;
                            if stack.is_empty() {
                                out.push(ip != 0 && self.is(&mut framer, process, ip, false));
                                continue;
                            }
                            // The innermost frame (not a return address),
                            // then its callers: up to one known, and back.
                            if self.is(&mut framer, process, stacks.frame(stack), false) {
                                out.push(true);
                                continue;
                            }
                            walk.clear();
                            let mut at = stacks.parent(stack);
                            let mut known = false;
                            while !at.is_empty() {
                                if let Some(&k) = callers.get(&(process, at)) {
                                    known = k;
                                    break;
                                }
                                walk.push(at);
                                at = stacks.parent(at);
                            }
                            while let Some(n) = walk.pop() {
                                known =
                                    known || self.is(&mut framer, process, stacks.frame(n), true);
                                callers.insert((process, n), known);
                            }
                            out.push(known);
                        }
                        *done[c]
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = out;
                    }
                });
            }
        });
        done.into_iter()
            .flat_map(|m| {
                m.into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            })
            .collect()
    }
}

/// Rows of events a worker counts at a time.
const COUNT_CHUNK: usize = 1 << 16;

/// For each of `n` items, the sum over `0..len` of `weigh(i)` for the
/// item `item(i)` says (if any), on every core, in chunks.
fn count_on_every_core(
    n: usize,
    len: usize,
    item: impl Fn(usize) -> Option<usize> + Sync,
    weigh: impl Fn(usize) -> u64 + Sync,
) -> Vec<u64> {
    let chunks = len.div_ceil(COUNT_CHUNK);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(chunks);
    let partials: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut sums = vec![0u64; n];
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= chunks {
                            return sums;
                        }
                        for i in c * COUNT_CHUNK..((c + 1) * COUNT_CHUNK).min(len) {
                            if let Some(k) = item(i) {
                                sums[k] += weigh(i);
                            }
                        }
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().expect("a counting worker"))
            .collect()
    });
    let mut out = vec![0u64; n];
    for p in partials {
        for (o, x) in out.iter_mut().zip(p) {
            *o += x;
        }
    }
    out
}

/// A process's threads (`process`, an index in the trace's processes; or
/// all of them), as a table: each one's lifetime, start address (named,
/// with `symbols`), and in `time` (by default, all of the trace) its CPU
/// samples, its switches in, and how long it ran after them (precise CPU),
/// heaviest (by samples, then running time) first.
pub fn threads(
    trace: &Trace,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    process: Option<usize>,
    time: Option<(i64, i64)>,
) -> Value {
    let filter = time.map(|(s, e)| (ticks(trace, s), ticks(trace, e)));
    let (start, end) = filter.unwrap_or((i64::MIN, i64::MAX));
    let n = trace.threads.len();
    let s = &trace.samples;
    let (from, to) = (
        s.time.partition_point(|&t| t < start),
        s.time.partition_point(|&t| t < end),
    );
    let thread_of = |t: ThreadIx| t.is_some().then(|| t.index());
    let samples = count_on_every_core(
        n,
        to - from,
        |i| thread_of(s.thread[from + i]),
        |i| u64::from(s.weight[from + i]),
    );
    // Switches in, and running time, clipped to the range.
    let w = &trace.switches;
    let precise = Precise::new(trace);
    let to_switch = w.time.partition_point(|&t| t < end);
    let in_range = |i: usize| {
        let run = i64::try_from(precise.running[i]).unwrap_or(i64::MAX);
        let (a, z) = (w.time[i].max(start), w.time[i].saturating_add(run).min(end));
        (a, z)
    };
    let switches = count_on_every_core(
        n,
        to_switch,
        |i| thread_of(w.new_thread[i]).filter(|_| w.time[i] >= start),
        |_| 1,
    );
    let running = count_on_every_core(
        n,
        to_switch,
        |i| thread_of(w.new_thread[i]),
        |i| {
            let (a, z) = in_range(i);
            u64::try_from(z - a).unwrap_or(0)
        },
    );
    let interval = trace.sample_interval_ns();
    let tick_ns = 1e9 / trace.clock.ticks_per_second.max(1) as f64;
    let mut rows: Vec<(usize, Value)> = trace
        .threads
        .iter()
        .enumerate()
        .filter(|(_, t)| process.is_none_or(|p| t.process.is_some() && t.process.index() == p))
        .map(|(i, t)| {
            let p = t
                .process
                .is_some()
                .then(|| &trace.processes[t.process.index()]);
            let start_address = (t.start_address != 0).then(|| {
                let key = match resolver.image(t.process, t.start_address) {
                    Some(image) => {
                        let offset = t.start_address - trace.images[image.index()].base;
                        let offset = symbols
                            .function_start(trace, image, offset)
                            .filter(|&f| f == offset)
                            .unwrap_or(offset);
                        Key::Frame { image, offset }
                    }
                    None => Key::Unknown(t.start_address),
                };
                label(trace, key, symbols)
            });
            (
                i,
                json!({
                    "tid": t.tid,
                    "name": t.name,
                    "pid": p.map(|p| p.pid),
                    "process": p.map(|p| p.name.clone()),
                    "processIndex": t.process.is_some().then(|| t.process.index()),
                    "startAddress": start_address,
                    "startNs": t.start.map(|t| trace.clock.nanos(t)),
                    "endNs": t.end.map(|t| trace.clock.nanos(t)),
                    "samples": samples[i],
                    "cpuMs": (samples[i] * interval) as f64 / 1e6,
                    "switches": switches[i],
                    "runningMs": ((running[i] as f64 * tick_ns) / 1e3).round() / 1e3,
                }),
            )
        })
        .collect();
    rows.sort_by(|a, b| {
        samples[b.0]
            .cmp(&samples[a.0])
            .then(running[b.0].cmp(&running[a.0]))
            .then(a.0.cmp(&b.0))
    });
    json!({"rows": rows.into_iter().map(|(_, v)| v).collect::<Vec<_>>()})
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
    let samples = count_on_every_core(
        trace.processes.len(),
        to - from,
        |i| {
            let p = trace.thread_process(s.thread[from + i]);
            p.is_some().then(|| p.index())
        },
        |i| u64::from(s.weight[from + i]),
    );
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
                    "index": i,
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

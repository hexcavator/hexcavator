//! DPCs and ISRs: the trace's interrupt service routines (PerfInfo ISR
//! and ISR-MSI events) and deferred procedure calls (DPC and TimerDPC),
//! each with its processor, its start and end, and its routine; read from
//! the trace file and kept; then totals grouped as asked (by the
//! routine's module or function, its processor or its type), a histogram
//! of their durations, and the longest.
//!
//! Each event is logged when its routine returns: its timestamp is its
//! end, and its `InitialTime` its start (in the same clock). An ISR that
//! interrupts a DPC is in that DPC's time too (as WPA counts them).

use std::path::Path;

use hexcavator_etw::guids;
use hexcavator_etw::schema::Properties;
use hexcavator_trace::{ProcessIx, Trace};
use hexcavator_trace_analysis::{Resolver, Symbolizer};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use crate::reading::int;

/// What a routine was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    /// An interrupt service routine.
    Isr,
    /// A deferred procedure call.
    Dpc,
    /// A timer's deferred procedure call.
    TimerDpc,
}

impl Type {
    fn name(self) -> &'static str {
        match self {
            Self::Isr => "ISR",
            Self::Dpc => "DPC",
            Self::TimerDpc => "Timer DPC",
        }
    }

    /// The type of a PerfInfo event (by its opcode): ISR, ISR-MSI, DPC
    /// or TimerDPC.
    fn of(opcode: u8) -> Option<Self> {
        match opcode {
            50 | 67 => Some(Self::Isr),
            68 => Some(Self::Dpc),
            69 => Some(Self::TimerDpc),
            _ => None,
        }
    }
}

/// One routine's run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    /// What it was.
    pub kind: Type,
    /// The processor it ran on.
    pub processor: u16,
    /// When it started (clock ticks).
    pub start: i64,
    /// When it returned (clock ticks).
    pub end: i64,
    /// Its routine's address.
    pub routine: u64,
    /// Its interrupt vector (ISRs).
    pub vector: Option<u16>,
}

/// A trace's DPCs and ISRs, in start order.
#[derive(Clone, Debug, Default)]
pub struct DpcTable {
    /// The runs.
    pub runs: Vec<Run>,
}

/// The DPCs and ISRs of `trace` (read from `path`), from the buffers
/// holding them, on every core.
pub fn table(trace: &Trace, path: &Path) -> Result<DpcTable, String> {
    let wanted = |provider: &hexcavator_etl::Guid, op: u8| {
        *provider == guids::PERF_INFO && Type::of(op).is_some()
    };
    let (mut runs, _) = crate::reading::events(trace, path, wanted, |processor, e, mine| {
        let Some(kind) = Type::of(e.descriptor.opcode) else {
            return;
        };
        let Some(Ok(p)) = Properties::of(e) else {
            return;
        };
        let start = i64::try_from(int(p.get("InitialTime"))).unwrap_or(e.timestamp);
        mine.push(Run {
            kind,
            processor,
            // (Never after its end.)
            start: start.min(e.timestamp),
            end: e.timestamp,
            routine: int(p.get("Routine")),
            vector: p
                .get("Vector")
                .map(|v| u16::try_from(int(Some(v))).unwrap_or(u16::MAX)),
        });
    })?;
    runs.sort_by_key(|r| (r.start, r.processor, r.end));
    Ok(DpcTable { runs })
}

/// What runs are grouped by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    /// Their routine's module.
    Module,
    /// Their routine's function.
    Function,
    /// Their processor.
    Processor,
    /// Their type.
    Type,
}

/// The upper bounds (nanoseconds) of the duration histogram's buckets;
/// the last is unbounded.
const BUCKETS: [u64; 6] = [1_000, 10_000, 100_000, 1_000_000, 10_000_000, u64::MAX];

/// `table`'s runs started in `time` (clock ticks; all, if none): totals
/// by `group` (count, total and longest duration; the most time first),
/// how many of each type took how long, and the `limit` longest; their
/// routines named by `symbols` where it can.
pub fn summary(
    trace: &Trace,
    table: &DpcTable,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    group: GroupBy,
    time: Option<(i64, i64)>,
    limit: usize,
) -> Value {
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let from = table.runs.partition_point(|r| r.start < start);
    let to = table.runs.partition_point(|r| r.start < end);
    let runs = &table.runs[from..to];
    let ns =
        |r: &Run| u64::try_from(trace.clock.nanos(r.end) - trace.clock.nanos(r.start)).unwrap_or(0);
    // Each routine's module and function, once.
    let mut names: FxHashMap<u64, (String, String)> = FxHashMap::default();
    let mut name = |routine: u64| -> (String, String) {
        names
            .entry(routine)
            .or_insert_with(|| match resolver.image(ProcessIx::NONE, routine) {
                None => ("Unknown module".to_string(), format!("{routine:#x}")),
                Some(image) => {
                    let i = &trace.images[image.index()];
                    let file = i.file_name().to_string();
                    let offset = routine - i.base;
                    let function = match symbols.function(trace, image, offset) {
                        Some((start, f)) if start == offset => format!("{file}!{f}"),
                        Some((start, f)) => format!("{file}!{f}+{:#x}", offset - start),
                        None => format!("{file}+{offset:#x}"),
                    };
                    (file, function)
                }
            })
            .clone()
    };
    let mut groups: FxHashMap<String, (u64, u64, u64)> = FxHashMap::default();
    let mut histogram: FxHashMap<Type, [u64; BUCKETS.len()]> = FxHashMap::default();
    let mut total = 0u64;
    for r in runs {
        let d = ns(r);
        total += d;
        let label = match group {
            GroupBy::Module => name(r.routine).0,
            GroupBy::Function => name(r.routine).1,
            GroupBy::Processor => format!("CPU {}", r.processor),
            GroupBy::Type => r.kind.name().to_string(),
        };
        let g = groups.entry(label).or_default();
        g.0 += 1;
        g.1 += d;
        g.2 = g.2.max(d);
        let b = BUCKETS
            .iter()
            .position(|&b| d < b)
            .unwrap_or(BUCKETS.len() - 1);
        histogram.entry(r.kind).or_default()[b] += 1;
    }
    let mut groups: Vec<(String, (u64, u64, u64))> = groups.into_iter().collect();
    groups.sort_by(|a, b| {
        b.1.1
            .cmp(&a.1.1)
            .then(b.1.0.cmp(&a.1.0))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut histogram: Vec<(Type, [u64; BUCKETS.len()])> = histogram.into_iter().collect();
    histogram.sort_by_key(|(t, _)| *t);
    let mut longest: Vec<&Run> = runs.iter().collect();
    longest.sort_by(|a, b| ns(b).cmp(&ns(a)).then(a.start.cmp(&b.start)));
    longest.truncate(limit);
    json!({
        "count": runs.len(),
        "durationNs": total,
        "groups": groups.iter().map(|(label, (n, d, max))| json!({
            "label": label, "count": n, "durationNs": d, "maxNs": max,
        })).collect::<Vec<_>>(),
        "bucketsNs": BUCKETS[..BUCKETS.len() - 1],
        "histogram": histogram.iter().map(|(t, counts)| json!({
            "type": t.name(), "counts": counts,
        })).collect::<Vec<_>>(),
        "runs": longest.iter().map(|r| {
            let (module, function) = name(r.routine);
            json!({
                "type": r.kind.name(),
                "processor": r.processor,
                "startNs": trace.clock.nanos(r.start),
                "durationNs": ns(r),
                "module": module,
                "function": function,
                "vector": r.vector,
            })
        }).collect::<Vec<_>>(),
    })
}

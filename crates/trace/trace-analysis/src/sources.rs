//! Instances from a trace's events: what each view weighs.
//!
//! - [`samples`]: CPU usage (sampled), weighted by samples;
//! - [`switches`]: CPU usage (precise), weighted by how long each thread
//!   ran after being switched in, or by how long it had waited before.
//!
//! Each aggregates its events by (thread, stack) first, so the instances
//! are the distinct stacks, not the events.

use rustc_hash::{FxHashMap, FxHashSet};

use hexcavator_trace::{ProcessIx, StackId, ThreadIx, Trace};

use crate::keys::{FrameMode, Framer, Key, KeyId, Keys};
use crate::tree::Instances;

/// A grouping column, above the stacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroupBy {
    /// By process.
    Process,
    /// By thread.
    Thread,
    /// By processor.
    Cpu,
    /// By stack tag (needs [`Framer::with_tags`]).
    StackTag,
}

/// Which events a view counts.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    /// Only events in `[start, end)`, in clock ticks.
    pub time: Option<(i64, i64)>,
    /// Only these processes.
    pub processes: Option<FxHashSet<ProcessIx>>,
    /// Only these threads.
    pub threads: Option<FxHashSet<ThreadIx>>,
}

impl Filter {
    /// The rows of a time-ordered column (`times`) that can be in range: by
    /// binary search, so a short range costs little in a long trace.
    fn rows(&self, times: &[i64]) -> std::ops::Range<usize> {
        match self.time {
            Some((start, end)) => {
                times.partition_point(|&t| t < start)..times.partition_point(|&t| t < end)
            }
            None => 0..times.len(),
        }
    }

    fn keeps(&self, trace: &Trace, time: i64, thread: ThreadIx) -> bool {
        if let Some((start, end)) = self.time
            && (time < start || time >= end)
        {
            return false;
        }
        if let Some(threads) = &self.threads
            && !threads.contains(&thread)
        {
            return false;
        }
        if let Some(processes) = &self.processes
            && !processes.contains(&trace.thread_process(thread))
        {
            return false;
        }
        true
    }
}

/// A distinct thing to weigh: a thread, a processor (when grouping by it),
/// a stack, and for a sample without a stack, its instruction pointer.
pub type Bucket = (ThreadIx, u16, StackId, u64);

/// Buckets, each with its weight and count, sorted by bucket.
pub type Run = Vec<(Bucket, (u64, u64))>;

/// How many buckets a thread turns into instances at a time. (Fixed, not
/// by the number of threads, so that keys are numbered the same on any
/// machine.)
const CHUNK: usize = 4096;

/// Events a worker aggregates at a time.
const ROWS: usize = 1 << 16;

/// The events `rows` (each one's bucket and weight, by `event`; or none,
/// for an event left out), aggregated: each bucket's weight and count,
/// sorted by bucket. On every core: each chunk of rows aggregated and
/// sorted on its own, then the chunks merged.
fn aggregate(
    rows: std::ops::Range<usize>,
    event: impl Fn(usize) -> Option<(Bucket, u64)> + Sync,
) -> Run {
    let chunks: Vec<std::ops::Range<usize>> = rows
        .clone()
        .step_by(ROWS)
        .map(|from| from..(from + ROWS).min(rows.end))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done: Vec<std::sync::Mutex<Run>> =
        chunks.iter().map(|_| std::sync::Mutex::default()).collect();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(chunks.len());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut map: FxHashMap<Bucket, (u64, u64)> = FxHashMap::default();
                loop {
                    let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(range) = chunks.get(c) else { return };
                    for i in range.clone() {
                        if let Some((bucket, weight)) = event(i) {
                            let e = map.entry(bucket).or_default();
                            e.0 += weight;
                            e.1 += 1;
                        }
                    }
                    let mut sorted: Run = map.drain().collect();
                    sorted.sort_unstable_by_key(|&(b, _)| b);
                    *done[c]
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = sorted;
                }
            });
        }
    });
    let mut runs: Vec<Run> = done
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
        .collect();
    // Merged in pairs (each pass's pairs on every core), adding up the
    // buckets in more than one.
    while runs.len() > 1 {
        let mut pairs = Vec::with_capacity(runs.len().div_ceil(2));
        let mut it = runs.into_iter();
        while let Some(a) = it.next() {
            pairs.push((a, it.next().unwrap_or_default()));
        }
        runs = std::thread::scope(|scope| {
            let merging: Vec<_> = pairs
                .into_iter()
                .map(|(a, b)| scope.spawn(move || merge_runs(a, b)))
                .collect();
            merging
                .into_iter()
                .map(|m| m.join().expect("a merge"))
                .collect()
        });
    }
    runs.pop().unwrap_or_default()
}

/// Two sorted runs of buckets as one, a bucket in both added up.
fn merge_runs(a: Run, b: Run) -> Run {
    if b.is_empty() {
        return a;
    }
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut a, mut b) = (a.into_iter().peekable(), b.into_iter().peekable());
    loop {
        match (a.peek(), b.peek()) {
            (Some(x), Some(y)) => match x.0.cmp(&y.0) {
                std::cmp::Ordering::Less => out.extend(a.next()),
                std::cmp::Ordering::Greater => out.extend(b.next()),
                std::cmp::Ordering::Equal => {
                    let (k, (w1, c1)) = a.next().expect("peeked");
                    let (_, (w2, c2)) = b.next().expect("peeked");
                    out.push((k, (w1 + w2, c1 + c2)));
                }
            },
            (Some(_), None) => out.extend(a.by_ref()),
            (None, Some(_)) => out.extend(b.by_ref()),
            (None, None) => return out,
        }
    }
}

/// Turns aggregated buckets (sorted, for a deterministic order) into
/// instances: in chunks, on every core, each with a framer and keys of its
/// own; the chunks' keys are then numbered in chunk order, so the result
/// is the same on any number of threads.
fn instances(
    trace: &Trace,
    framer: &mut Framer<'_>,
    keys: &mut Keys,
    groups: &[GroupBy],
    buckets: &[(Bucket, (u64, u64))],
) -> Instances {
    if buckets.len() <= CHUNK {
        return chunk_instances(trace, framer, keys, groups, buckets);
    }
    let chunks: Vec<&[(Bucket, (u64, u64))]> = buckets.chunks(CHUNK).collect();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(chunks.len());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done: Vec<std::sync::Mutex<Option<(Instances, Keys)>>> =
        chunks.iter().map(|_| std::sync::Mutex::new(None)).collect();
    let template = &*framer;
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut framer = template.fork();
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(chunk) = chunks.get(i) else { return };
                    let mut local = Keys::default();
                    let inst = chunk_instances(trace, &mut framer, &mut local, groups, chunk);
                    *done[i]
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((inst, local));
                }
            });
        }
    });
    let mut out = Instances::new(groups.len());
    for slot in done {
        let (inst, local) = slot
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("every chunk is done");
        let rename: Vec<KeyId> = (0..local.len())
            .map(|k| keys.intern(local.get(KeyId(u32::try_from(k).expect("a key")))))
            .collect();
        out.append_renamed(&inst, &rename);
    }
    out
}

/// Turns buckets into instances.
fn chunk_instances(
    trace: &Trace,
    framer: &mut Framer<'_>,
    keys: &mut Keys,
    groups: &[GroupBy],
    buckets: &[(Bucket, (u64, u64))],
) -> Instances {
    let mut out = Instances::new(groups.len());
    let mut seq: Vec<KeyId> = Vec::new();
    let mut frames: Vec<u64> = Vec::new();
    let by_tag = groups.contains(&GroupBy::StackTag) && framer.has_tags();
    let folding = framer.has_folds();
    let by_module = framer.mode() == FrameMode::Module;
    for &((thread, cpu, stack, ip), (weight, count)) in buckets {
        let process = trace.thread_process(thread);
        frames.clear();
        if stack.is_empty() {
            if ip != 0 {
                frames.push(ip);
            }
        } else {
            frames.extend(trace.stacks.frames(stack));
        }
        // The stack's tag: that of its deepest tagged frame. (Every frame
        // but the innermost is a return address: the instruction after a
        // call, which may be past its function.)
        let tag = if by_tag {
            frames
                .iter()
                .enumerate()
                .find_map(|(i, &f)| framer.classify(process, f, i > 0).0)
                .unwrap_or(Key::NO_TAG)
        } else {
            Key::NO_TAG
        };
        seq.clear();
        for g in groups {
            seq.push(keys.intern(match g {
                GroupBy::Process => Key::Process(process),
                GroupBy::Thread => Key::Thread(thread),
                GroupBy::Cpu => Key::Cpu(cpu),
                GroupBy::StackTag => Key::Tag(tag),
            }));
        }
        for (i, &f) in frames.iter().enumerate().rev() {
            let fold = if folding {
                framer.classify(process, f, i > 0).1
            } else {
                None
            };
            // The frame's key, and the calls inlined at it (its callees in
            // the tree).
            let (key, inlined) = match fold {
                Some(rule) => (Key::Fold(rule), &[][..]),
                None => framer.frame(process, f, i > 0),
            };
            let k = keys.intern(key);
            // A run of frames in one folded group, or (by image) in one
            // image, is one node.
            let collapses = fold.is_some() || by_module;
            if collapses && seq.len() > groups.len() && seq.last() == Some(&k) {
                continue;
            }
            seq.push(k);
            for &inline in inlined {
                seq.push(keys.intern(inline));
            }
        }
        out.push_counted(&seq, weight, count);
    }
    out
}

/// CPU samples, weighted by sample count.
pub fn samples(
    trace: &Trace,
    framer: &mut Framer<'_>,
    keys: &mut Keys,
    groups: &[GroupBy],
    filter: &Filter,
) -> Instances {
    let buckets = sample_buckets(trace, filter, groups.contains(&GroupBy::Cpu));
    instances(trace, framer, keys, groups, &buckets)
}

/// CPU samples, aggregated: each distinct (thread, processor if
/// `by_cpu`, stack, and instruction pointer for a sample without a stack)
/// with its samples' weight and count, sorted. On every core.
pub fn sample_buckets(trace: &Trace, filter: &Filter, by_cpu: bool) -> Run {
    let s = &trace.samples;
    aggregate(filter.rows(&s.time), |i| {
        if !filter.keeps(trace, s.time[i], s.thread[i]) {
            return None;
        }
        let stack = s.stack[i];
        let ip = if stack.is_empty() { s.ip[i] } else { 0 };
        let cpu = if by_cpu { s.cpu[i] } else { 0 };
        Some(((s.thread[i], cpu, stack, ip), u64::from(s.weight[i])))
    })
}

/// Each context switch's derived times, in clock ticks.
#[derive(Clone, Debug, Default)]
pub struct Precise {
    /// How long the thread switched in ran: until the next switch on that
    /// processor (0 for the last).
    pub running: Vec<u64>,
    /// How long the thread switched in had waited: since it was last
    /// switched out (0 when the trace doesn't show it).
    pub waited: Vec<u64>,
}

impl Precise {
    /// The times of `trace`'s switches.
    #[allow(clippy::needless_range_loop)] // the loop writes earlier rows
    pub fn new(trace: &Trace) -> Self {
        let sw = &trace.switches;
        let n = sw.len();
        let mut running = vec![0u64; n];
        let mut waited = vec![0u64; n];
        let mut last_on_cpu: FxHashMap<u16, usize> = FxHashMap::default();
        let mut switched_out: FxHashMap<ThreadIx, i64> = FxHashMap::default();
        for i in 0..n {
            let t = sw.time[i];
            if let Some(prev) = last_on_cpu.insert(sw.cpu[i], i) {
                running[prev] = u64::try_from(t - sw.time[prev]).unwrap_or(0);
            }
            if let Some(out) = switched_out.remove(&sw.new_thread[i]) {
                waited[i] = u64::try_from(t - out).unwrap_or(0);
            }
            switched_out.insert(sw.old_thread[i], t);
        }
        Self { running, waited }
    }
}

/// What a context switch weighs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchWeight {
    /// How long the new thread then ran (CPU usage).
    Running,
    /// How long the new thread had waited (waits).
    Waited,
}

/// Context switches, weighted by running or waiting time (clock ticks), by
/// the new thread's stack: where it waited.
pub fn switches(
    trace: &Trace,
    precise: &Precise,
    framer: &mut Framer<'_>,
    keys: &mut Keys,
    groups: &[GroupBy],
    filter: &Filter,
    weight: SwitchWeight,
) -> Instances {
    let buckets = switch_buckets(
        trace,
        precise,
        filter,
        groups.contains(&GroupBy::Cpu),
        weight,
    );
    instances(trace, framer, keys, groups, &buckets)
}

/// Context switches, aggregated as [`sample_buckets`] aggregates samples,
/// weighted by `weight` (switches that weigh nothing left out).
pub fn switch_buckets(
    trace: &Trace,
    precise: &Precise,
    filter: &Filter,
    by_cpu: bool,
    weight: SwitchWeight,
) -> Run {
    let sw = &trace.switches;
    aggregate(filter.rows(&sw.time), |i| {
        let thread = sw.new_thread[i];
        if !filter.keeps(trace, sw.time[i], thread) {
            return None;
        }
        let w = match weight {
            SwitchWeight::Running => precise.running[i],
            SwitchWeight::Waited => precise.waited[i],
        };
        if w == 0 {
            return None;
        }
        let cpu = if by_cpu { sw.cpu[i] } else { 0 };
        Some(((thread, cpu, sw.stack[i], 0), w))
    })
}

#[cfg(test)]
mod tests {
    use super::{Bucket, ROWS, aggregate};
    use hexcavator_trace::{StackId, ThreadIx};
    use rustc_hash::FxHashMap;

    /// Aggregating in chunks on every core, and merging, is aggregating
    /// all at once: many chunks, buckets in several of them, events left
    /// out, and a range not starting at 0.
    #[test]
    fn aggregates_in_chunks_as_all_at_once() {
        let n = ROWS * 9 + 1234;
        let event = |i: usize| -> Option<(Bucket, u64)> {
            let x = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40;
            if x.is_multiple_of(7) {
                return None;
            }
            let bucket = (
                ThreadIx(u32::try_from(x % 13).unwrap()),
                u16::try_from(x % 3).unwrap(),
                StackId(u32::try_from(x % 5000).unwrap()),
                x % 2,
            );
            Some((bucket, x % 100 + 1))
        };
        for range in [0..n, 17..n - 3, 5..5, 100..200] {
            let mut want: FxHashMap<Bucket, (u64, u64)> = FxHashMap::default();
            for i in range.clone() {
                if let Some((b, w)) = event(i) {
                    let e = want.entry(b).or_default();
                    e.0 += w;
                    e.1 += 1;
                }
            }
            let mut want: Vec<_> = want.into_iter().collect();
            want.sort_unstable_by_key(|&(b, _)| b);
            assert_eq!(aggregate(range.clone(), event), want, "{range:?}");
        }
    }
}

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
type Bucket = (ThreadIx, u16, StackId, u64);

/// How many buckets a thread turns into instances at a time. (Fixed, not
/// by the number of threads, so that keys are numbered the same on any
/// machine.)
const CHUNK: usize = 4096;

/// Turns aggregated buckets into instances: in chunks, on every core, each
/// with a framer and keys of its own; the chunks' keys are then numbered
/// in chunk order, so the result is the same on any number of threads.
fn instances(
    trace: &Trace,
    framer: &mut Framer<'_>,
    keys: &mut Keys,
    groups: &[GroupBy],
    buckets: FxHashMap<Bucket, (u64, u64)>,
) -> Instances {
    // Deterministic order: by bucket.
    let mut buckets: Vec<(Bucket, (u64, u64))> = buckets.into_iter().collect();
    buckets.sort_unstable_by_key(|&(b, _)| b);
    if buckets.len() <= CHUNK {
        return chunk_instances(trace, framer, keys, groups, &buckets);
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
    let by_cpu = groups.contains(&GroupBy::Cpu);
    let s = &trace.samples;
    let mut buckets: FxHashMap<Bucket, (u64, u64)> = FxHashMap::default();
    for i in filter.rows(&s.time) {
        if !filter.keeps(trace, s.time[i], s.thread[i]) {
            continue;
        }
        let stack = s.stack[i];
        let ip = if stack.is_empty() { s.ip[i] } else { 0 };
        let cpu = if by_cpu { s.cpu[i] } else { 0 };
        let e = buckets.entry((s.thread[i], cpu, stack, ip)).or_default();
        e.0 += u64::from(s.weight[i]);
        e.1 += 1;
    }
    instances(trace, framer, keys, groups, buckets)
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
    let by_cpu = groups.contains(&GroupBy::Cpu);
    let sw = &trace.switches;
    let mut buckets: FxHashMap<Bucket, (u64, u64)> = FxHashMap::default();
    for i in filter.rows(&sw.time) {
        let thread = sw.new_thread[i];
        if !filter.keeps(trace, sw.time[i], thread) {
            continue;
        }
        let w = match weight {
            SwitchWeight::Running => precise.running[i],
            SwitchWeight::Waited => precise.waited[i],
        };
        if w == 0 {
            continue;
        }
        let cpu = if by_cpu { sw.cpu[i] } else { 0 };
        let e = buckets.entry((thread, cpu, sw.stack[i], 0)).or_default();
        e.0 += w;
        e.1 += 1;
    }
    instances(trace, framer, keys, groups, buckets)
}

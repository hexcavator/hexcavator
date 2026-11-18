//! Building a [`Trace`] from a Windows ETL file.
//!
//! The import runs in stages, each spread over every core but one short
//! one:
//!
//! 1. **Decode, in parallel.** Workers take the file's buffers in turn and
//!    decode each into the few things the trace keeps (samples, switches,
//!    lifetimes, ...) and the timestamps of all its events. Each stack is
//!    interned on the spot into one of [`SHARDS`] tries, chosen by its
//!    thread and outermost frames, each behind a lock of its own (and each
//!    worker remembers each thread's last stack, which mostly repeats).
//! 2. **Order.** One thread walks the buffers' timestamps in the order
//!    [`hexcavator_etl::EventCursor`] reads them (by timestamp, ties broken
//!    as `ProcessTrace` breaks them: [`Order`]), as runs of events from one
//!    buffer, while the workers decode. It touches only timestamps.
//! 3. **Build, in parts, in parallel.** The ordered events are cut into
//!    parts by time, and each part is built on its own: its samples,
//!    switches and ready events as rows, and its stacks matched to them,
//!    starting from which thread ran on each processor when it began (from
//!    a quick look at the earlier parts' switches). A part names threads
//!    by ID and position in the trace, since which thread an ID is depends
//!    on everything before.
//! 4. **Stitch, in order.** One thread does what spans parts, which is
//!    little: it matches the stacks whose events are in earlier parts
//!    ([`Stitch`]), and replays the processes, threads and images coming
//!    and going, with the first use of each thread ID in each part, to
//!    learn which thread each ID is at each position.
//! 5. **Finish, in parallel.** Rows get their threads (by ID and
//!    position) and switches their ready events (thread by thread); split
//!    stacks are joined (a user-mode part to its kernel-mode part); each
//!    trie is numbered in a canonical order (so the result doesn't depend
//!    on which worker got there first); and the tries are laid end to end
//!    as the trace's stack store.
//!
//! The result is the same as reading the events one by one in order, on
//! any number of threads and parts.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};

use rustc_hash::{FxHashMap, FxHashSet, FxHasher};

use hexcavator_core::Result;
use hexcavator_etl::{Buffer, Etl, Event, Order, for_each_event, streams};
use hexcavator_etw::kernel::{
    ContextSwitch, KernelEvent, Lifetime, ReadyThread, Sample, ThreadEvent, decode,
};
use hexcavator_etw::stacks::{StackMatcher, Stitch};

use crate::model::{
    Clock, DebugId, Image, ImageIx, Process, ProcessIx, ReadyIx, Thread, ThreadIx, Trace,
};
use crate::stacks::{PathCache, StackId, StackStore};

/// What an import did, in counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Events read.
    pub events: u64,
    /// Buffers the reader found malformed (each one's later events are
    /// skipped).
    pub read_errors: u64,
    /// Kernel events whose payloads were malformed.
    pub decode_errors: u64,
    /// Stacks paired with an event we keep.
    pub stacks: u64,
    /// Second (user-mode) parts of split stacks joined to their first.
    pub stack_continuations: u64,
    /// Stacks whose event we didn't keep or couldn't find.
    pub stacks_unmatched: u64,
}

// Tags in the stack matcher's IDs: which table the row is in.
const SAMPLE: u64 = 1 << 56;
const SWITCH: u64 = 2 << 56;
const READY: u64 = 3 << 56;
const ROW: u64 = (1 << 56) - 1;

/// How many tries stacks are interned into while decoding.
pub const SHARDS: usize = 64;

/// How many of a stack's outermost frames choose its trie (with its
/// thread).
const SHARD_FRAMES: usize = 3;

/// Reads `etl` into a [`Trace`], on all of the machine's cores.
pub fn import(etl: &Etl<'_>) -> Result<(Trace, ImportStats)> {
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    import_with(etl, threads)
}

/// Reads `etl` into a [`Trace`] on `threads` threads. The result is the
/// same for any number.
pub fn import_with(etl: &Etl<'_>, threads: usize) -> Result<(Trace, ImportStats)> {
    import_parts(etl, threads, None)
}

/// The fewest events worth a part of their own.
const MIN_PART_EVENTS: u64 = 1 << 18;

/// [`import_with`], building in `parts` parts (by default, as many as the
/// trace's size and the threads call for). The result is the same for any
/// number of threads and parts; tests check that with this.
#[doc(hidden)]
pub fn import_parts(
    etl: &Etl<'_>,
    threads: usize,
    parts: Option<usize>,
) -> Result<(Trace, ImportStats)> {
    let threads = threads.max(1);
    let header = etl.header();
    let ticks = header.ticks_per_second().unwrap_or(10_000_000);
    // Wait up to five seconds for the user part of a split stack.
    let window = i64::try_from(ticks.saturating_mul(5)).unwrap_or(i64::MAX);
    let max_buffer = header.buffer_size as usize;
    let streams = streams(etl)?;
    // Every buffer, in file order, with its stream.
    let mut buffers: Vec<(Buffer<'_>, usize)> = Vec::new();
    for (s, list) in streams.iter().enumerate() {
        for b in list {
            buffers.push((*b, s));
        }
    }
    buffers.sort_by_key(|(b, _)| b.index);
    // Each stream's buffers, as positions in `buffers`.
    let mut stream_buffers: Vec<Vec<usize>> = vec![Vec::new(); streams.len()];
    for (i, (_, s)) in buffers.iter().enumerate() {
        stream_buffers[*s].push(i);
    }

    let shards: Vec<Mutex<Shard>> = (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect();
    let slots = Slots::new(buffers.len());
    let next = AtomicUsize::new(0);
    let runs = std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut local = Local::default();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((buffer, _)) = buffers.get(i) else {
                        return;
                    };
                    let decoded =
                        decode_buffer(buffer, max_buffer, &mut scratch, &mut local, &shards);
                    slots.put(i, decoded);
                }
            });
        }
        order(&stream_buffers, &slots)
    });
    let decoded = slots.into_inner();

    let mut stats = ImportStats::default();
    for d in &decoded {
        stats.events += d.times.len() as u64;
        stats.read_errors += u64::from(d.error);
        stats.decode_errors += d.decode_errors;
    }
    let origin = runs
        .first()
        .map_or(0, |r| decoded[r.buffer as usize].times[r.first as usize]);
    let count = parts.unwrap_or_else(|| {
        let by_size = usize::try_from(stats.events / MIN_PART_EVENTS).unwrap_or(usize::MAX);
        (threads * 4).min(by_size).max(1)
    });
    let spans = cut(&runs, &decoded, count);
    let starts = running_at_starts(&spans, &runs, &decoded, threads);
    let built: Vec<Part<'_>> = parallel(&spans, threads, |k, span| {
        build_part(span, &runs, &decoded, &starts[k], window)
    });
    let shards: Vec<Shard> = shards
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner))
        .collect();
    Ok(assemble(
        built,
        shards,
        Clock {
            ticks_per_second: ticks,
            origin,
        },
        header.number_of_processors,
        stats,
        window,
        threads,
    ))
}

/// `f` of each of `items` (with its index), on up to `threads` threads at
/// once, in order.
fn parallel<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(usize, &T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..threads.min(items.len()).max(1) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else {
                        return;
                    };
                    let r = f(i, item);
                    *results[i].lock().unwrap_or_else(PoisonError::into_inner) = Some(r);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .expect("every item is done")
        })
        .collect()
}

/// Decoded buffers, as workers finish them.
struct Slots {
    slots: Vec<OnceLock<Decoded>>,
    lock: Mutex<()>,
    ready: Condvar,
}

impl Slots {
    fn new(n: usize) -> Self {
        Self {
            slots: (0..n).map(|_| OnceLock::new()).collect(),
            lock: Mutex::new(()),
            ready: Condvar::new(),
        }
    }

    fn put(&self, i: usize, d: Decoded) {
        let _ = self.slots[i].set(d);
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.ready.notify_all();
    }

    /// Buffer `i`, once decoded.
    fn get(&self, i: usize) -> &Decoded {
        if let Some(d) = self.slots[i].get() {
            return d;
        }
        let mut held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(d) = self.slots[i].get() {
                return d;
            }
            held = self
                .ready
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn into_inner(self) -> Vec<Decoded> {
        self.slots
            .into_iter()
            .map(|s| s.into_inner().expect("every buffer is decoded"))
            .collect()
    }
}

/// Events of one buffer that come one after another in the trace's order.
#[derive(Clone, Copy, Debug)]
struct Run {
    buffer: u32,
    first: u32,
    count: u32,
}

/// The trace's events in the cursor's order, as runs.
fn order(stream_buffers: &[Vec<usize>], slots: &Slots) -> Vec<Run> {
    struct Stream<'a> {
        buffers: &'a [usize],
        next: usize,
        buffer: usize,
        times: &'a [i64],
        event: usize,
    }
    impl<'a> Stream<'a> {
        /// The next event's timestamp, taking buffers as needed.
        fn head(&mut self, slots: &'a Slots) -> Option<i64> {
            loop {
                if let Some(&t) = self.times.get(self.event) {
                    return Some(t);
                }
                let &b = self.buffers.get(self.next)?;
                self.next += 1;
                self.buffer = b;
                self.times = &slots.get(b).times;
                self.event = 0;
            }
        }
    }
    let mut streams: Vec<Stream<'_>> = stream_buffers
        .iter()
        .map(|b| Stream {
            buffers: b,
            next: 0,
            buffer: 0,
            times: &[],
            event: 0,
        })
        .collect();
    let mut order = Order::new();
    // Queued last to first, as the cursor does.
    for i in (0..streams.len()).rev() {
        if let Some(t) = streams[i].head(slots) {
            order.push(i, t);
        }
    }
    let mut runs = Vec::new();
    while let Some((i, _)) = order.pop() {
        // The stream's events while they come first: until one is later
        // than the next queued event. (On a tie the stream that gave the
        // last event goes first, so it keeps going; and queueing it again
        // only after its run orders later ties as queueing it after each
        // event would: no other stream is queued in between.)
        let limit = order.peek().unwrap_or(i64::MAX);
        let s = &mut streams[i];
        loop {
            let first = s.event;
            s.event += 1;
            while s.times.get(s.event).is_some_and(|&t| t <= limit) {
                s.event += 1;
            }
            runs.push(Run {
                buffer: u32::try_from(s.buffer).expect("fewer than 4G buffers"),
                first: u32::try_from(first).expect("fewer than 4G events in a buffer"),
                count: u32::try_from(s.event - first).expect("fewer than 4G events in a buffer"),
            });
            match s.head(slots) {
                Some(next) if next <= limit => {}
                Some(next) => {
                    order.push(i, next);
                    break;
                }
                None => break,
            }
        }
    }
    runs
}

/// A part of the trace: its runs, its first event's position in the
/// trace, and its first timestamp.
#[derive(Clone, Debug)]
struct Span {
    runs: std::ops::Range<usize>,
    position: u64,
    start: i64,
}

/// The ordered runs cut into about `n` parts of as many events each, each
/// starting at a later timestamp than the one before ends (so that every
/// event a stack can belong to, by its timestamp, is in one part).
fn cut(runs: &[Run], decoded: &[Decoded], n: usize) -> Vec<Span> {
    if runs.is_empty() {
        return Vec::new();
    }
    let first_t = |r: &Run| decoded[r.buffer as usize].times[r.first as usize];
    let last_t = |r: &Run| decoded[r.buffer as usize].times[(r.first + r.count - 1) as usize];
    let mut positions = Vec::with_capacity(runs.len() + 1);
    let mut p = 0u64;
    for r in runs {
        positions.push(p);
        p += u64::from(r.count);
    }
    let total = p;
    let mut cuts = vec![0usize];
    for k in 1..n as u64 {
        let target = total * k / n as u64;
        let mut i = positions.partition_point(|&q| q < target);
        while i < runs.len() && i > 0 && first_t(&runs[i]) <= last_t(&runs[i - 1]) {
            i += 1;
        }
        if i < runs.len() && i > *cuts.last().expect("a first cut") {
            cuts.push(i);
        }
    }
    cuts.push(runs.len());
    cuts.windows(2)
        .map(|w| Span {
            runs: w[0]..w[1],
            position: positions[w[0]],
            start: first_t(&runs[w[0]]),
        })
        .collect()
}

/// The kept items of a run: (position in the trace, item), in order.
fn run_items<'a>(
    run: &Run,
    position: u64,
    decoded: &'a [Decoded],
) -> impl Iterator<Item = (u64, u16, i64, &'a Item)> + 'a {
    let d = &decoded[run.buffer as usize];
    let first = run.first;
    let end = run.first + run.count;
    let from = d.items.partition_point(|(i, _)| *i < first);
    d.items[from..]
        .iter()
        .take_while(move |(i, _)| *i < end)
        .map(move |(i, item)| {
            (
                position + u64::from(i - first),
                d.processor,
                d.times[*i as usize],
                item,
            )
        })
}

/// A processor's running thread: its ID, and the position of the switch
/// that ran it.
type Running = Option<(u32, u64)>;

/// Which thread runs on each processor as each part starts: from the
/// earlier parts' last switch on it.
fn running_at_starts(
    spans: &[Span],
    runs: &[Run],
    decoded: &[Decoded],
    threads: usize,
) -> Vec<Vec<Running>> {
    let lasts: Vec<Vec<Running>> = parallel(spans, threads, |_, span| {
        let mut last: Vec<Running> = Vec::new();
        let mut position = span.position;
        for run in &runs[span.runs.clone()] {
            for (pos, cpu, _, item) in run_items(run, position, decoded) {
                if let Item::Switch(c) = item {
                    let c_ix = usize::from(cpu);
                    if last.len() <= c_ix {
                        last.resize(c_ix + 1, None);
                    }
                    last[c_ix] = Some((c.new_thread_id, pos));
                }
            }
            position += u64::from(run.count);
        }
        last
    });
    let mut starts = Vec::with_capacity(spans.len());
    let mut running: Vec<Running> = Vec::new();
    for last in lasts {
        starts.push(running.clone());
        if running.len() < last.len() {
            running.resize(last.len(), None);
        }
        for (c, r) in last.into_iter().enumerate() {
            if r.is_some() {
                running[c] = r;
            }
        }
    }
    starts
}

/// A sample, by thread ID.
struct SampleRow {
    time: i64,
    cpu: u16,
    tid: u32,
    ip: u64,
    weight: u16,
    position: u64,
}

/// A context switch, by thread IDs.
struct SwitchRow {
    time: i64,
    cpu: u16,
    new_tid: u32,
    old_tid: u32,
    new_priority: i8,
    old_priority: i8,
    wait_reason: i8,
    old_state: i8,
    position: u64,
}

/// A ready event, by thread IDs; the readier as the switch that ran it
/// left it.
struct ReadyRow {
    time: i64,
    cpu: u16,
    tid: u32,
    readier: Running,
    position: u64,
}

/// A stack whose event is in an earlier part.
struct Orphan {
    position: u64,
    cpu: u16,
    now: i64,
    event_timestamp: i64,
    thread_id: u32,
    piece: Piece,
    /// The part's matcher's recent events per processor then.
    counts: Vec<u8>,
}

/// A part, built.
#[derive(Default)]
struct Part<'a> {
    samples: Vec<SampleRow>,
    switches: Vec<SwitchRow>,
    readies: Vec<ReadyRow>,
    sample_pieces: Vec<Piece>,
    switch_pieces: Vec<Piece>,
    ready_pieces: Vec<Piece>,
    /// User-mode parts to join, by the part's own row names.
    joins: Vec<(u64, Piece, u32)>,
    orphans: Vec<Orphan>,
    /// The first use of each thread ID: position, order within the event,
    /// ID.
    refs: Vec<(u64, u8, u32)>,
    /// Processes, threads and images coming and going (and other events
    /// about them), with position and time.
    lifetimes: Vec<(u64, i64, &'a Item)>,
    snapshot: hexcavator_etw::stacks::Snapshot,
    /// The part's first timestamp.
    start: i64,
    stacks: u64,
    continuations: u64,
    unmatched: u64,
}

/// Builds a part (see the module's notes).
fn build_part<'a>(
    span: &Span,
    runs: &[Run],
    decoded: &'a [Decoded],
    start: &[Running],
    window: i64,
) -> Part<'a> {
    let tids: Vec<u32> = start
        .iter()
        .map(|r| r.map_or(u32::MAX, |(t, _)| t))
        .collect();
    let mut matcher = StackMatcher::starting_with(window, &tids);
    let mut running: Vec<Running> = start.to_vec();
    let mut seen: FxHashSet<u32> = FxHashSet::default();
    let mut p = Part::default();
    let mut refer = |p: &mut Part<'a>, position: u64, sub: u8, tid: u32| {
        if seen.insert(tid) {
            p.refs.push((position, sub, tid));
        }
    };
    let mut position = span.position;
    for run in &runs[span.runs.clone()] {
        for (pos, cpu, t, item) in run_items(run, position, decoded) {
            match item {
                Item::Sample(s) => {
                    refer(&mut p, pos, 0, s.thread_id);
                    let r = p.samples.len() as u64;
                    p.samples.push(SampleRow {
                        time: t,
                        cpu,
                        tid: s.thread_id,
                        ip: s.instruction_pointer,
                        weight: s.count.max(1),
                        position: pos,
                    });
                    p.sample_pieces.push(0);
                    matcher.event_at(SAMPLE | r, cpu, t, u32::MAX, Some(&KernelEvent::Sample(*s)));
                }
                Item::Switch(c) => {
                    refer(&mut p, pos, 0, c.new_thread_id);
                    refer(&mut p, pos, 1, c.old_thread_id);
                    let r = p.switches.len() as u64;
                    p.switches.push(SwitchRow {
                        time: t,
                        cpu,
                        new_tid: c.new_thread_id,
                        old_tid: c.old_thread_id,
                        new_priority: c.new_thread_priority,
                        old_priority: c.old_thread_priority,
                        wait_reason: c.old_thread_wait_reason,
                        old_state: c.old_thread_state,
                        position: pos,
                    });
                    p.switch_pieces.push(0);
                    matcher.event_at(
                        SWITCH | r,
                        cpu,
                        t,
                        u32::MAX,
                        Some(&KernelEvent::ContextSwitch(*c)),
                    );
                    let i = usize::from(cpu);
                    if running.len() <= i {
                        running.resize(i + 1, None);
                    }
                    running[i] = Some((c.new_thread_id, pos));
                }
                Item::Ready(rt) => {
                    refer(&mut p, pos, 0, rt.thread_id);
                    let r = p.readies.len() as u64;
                    p.readies.push(ReadyRow {
                        time: t,
                        cpu,
                        tid: rt.thread_id,
                        readier: running.get(usize::from(cpu)).copied().flatten(),
                        position: pos,
                    });
                    p.ready_pieces.push(0);
                    matcher.event_at(
                        READY | r,
                        cpu,
                        t,
                        u32::MAX,
                        Some(&KernelEvent::ReadyThread(*rt)),
                    );
                }
                Item::Stack {
                    event_timestamp,
                    thread_id,
                    piece,
                } => {
                    if *event_timestamp < span.start {
                        p.orphans.push(Orphan {
                            position: pos,
                            cpu,
                            now: t,
                            event_timestamp: *event_timestamp,
                            thread_id: *thread_id,
                            piece: *piece,
                            counts: matcher.recent_counts(),
                        });
                        continue;
                    }
                    let Some(m) = matcher.stack_at(cpu, t, *event_timestamp, *thread_id) else {
                        p.unmatched += 1;
                        continue;
                    };
                    let r = (m.id & ROW) as usize;
                    if m.continuation {
                        // The user part: the callers of the part the row has.
                        p.continuations += 1;
                        p.joins.push((m.id, *piece, *thread_id));
                    } else {
                        p.stacks += 1;
                        match m.id & !ROW {
                            SAMPLE => p.sample_pieces[r] = *piece,
                            SWITCH => p.switch_pieces[r] = *piece,
                            _ => p.ready_pieces[r] = *piece,
                        }
                    }
                    // A ready event whose readier wasn't known (before its
                    // processor's first switch): the stack's thread.
                    if m.id & !ROW == READY
                        && let Some(tid) = m.thread
                        && p.readies[r].readier.is_none()
                    {
                        refer(&mut p, pos, 0, tid);
                        p.readies[r].readier = Some((tid, pos));
                    }
                }
                _ => p.lifetimes.push((pos, t, item)),
            }
        }
        position += u64::from(run.count);
    }
    p.snapshot = matcher.snapshot();
    p.start = span.start;
    p
}

/// A place in the trace's order: an event's position, and an order within
/// the event (a switch names two threads).
type At = (u64, u8);

/// Which thread each thread ID is, from each position on.
#[derive(Default)]
struct Timeline {
    by_tid: FxHashMap<u32, Vec<(At, ThreadIx)>>,
}

impl Timeline {
    /// Notes that `tid` is `thread` from `at` on, if it wasn't already.
    fn note(&mut self, tid: u32, at: (u64, u8), thread: Option<ThreadIx>) {
        let Some(thread) = thread else { return };
        let list = self.by_tid.entry(tid).or_default();
        if list.last().is_none_or(|&(_, t)| t != thread) {
            list.push((at, thread));
        }
    }

    /// The thread `tid` is at `at`.
    fn at(&self, tid: u32, at: (u64, u8)) -> ThreadIx {
        let Some(list) = self.by_tid.get(&tid) else {
            return ThreadIx::NONE;
        };
        let i = list.partition_point(|&(when, _)| when <= at);
        i.checked_sub(1).map_or(ThreadIx::NONE, |i| list[i].1)
    }
}

/// Puts the parts together (see the module's notes).
#[allow(clippy::too_many_lines)]
fn assemble(
    mut parts: Vec<Part<'_>>,
    shards: Vec<Shard>,
    clock: Clock,
    processors: u32,
    mut stats: ImportStats,
    window: i64,
    threads: usize,
) -> (Trace, ImportStats) {
    // Each part's rows' place among all the rows.
    let mut bases = Vec::with_capacity(parts.len());
    let (mut s, mut w, mut r) = (0u64, 0u64, 0u64);
    for p in &parts {
        bases.push((s, w, r));
        s += p.samples.len() as u64;
        w += p.switches.len() as u64;
        r += p.readies.len() as u64;
    }
    let rename = |k: usize, id: u64| {
        let (s, w, r) = bases[k];
        let base = match id & !ROW {
            SAMPLE => s,
            SWITCH => w,
            _ => r,
        };
        (id & !ROW) | (base + (id & ROW))
    };
    let mut stacks = Stacks::default();
    for p in &mut parts {
        stacks.sample_pieces.append(&mut p.sample_pieces);
        stacks.switch_pieces.append(&mut p.switch_pieces);
        stacks.ready_pieces.append(&mut p.ready_pieces);
    }

    // Stacks across parts, in order; and the first uses of thread IDs
    // that matching them adds.
    let mut stitch = Stitch::new(window);
    let mut readier_fixes: Vec<(usize, u32, u64)> = Vec::new();
    for (k, p) in parts.iter_mut().enumerate() {
        for o in &p.orphans {
            let Some(m) = stitch.stack(o.cpu, o.now, o.event_timestamp, o.thread_id, &o.counts)
            else {
                stats.stacks_unmatched += 1;
                continue;
            };
            if m.continuation {
                stats.stack_continuations += 1;
                stacks.joins.push((m.id, o.piece, o.thread_id));
            } else {
                stats.stacks += 1;
                *stacks.piece_mut(m.id) = o.piece;
            }
            if m.id & !ROW == READY
                && let Some(tid) = m.thread
            {
                readier_fixes.push(((m.id & ROW) as usize, tid, o.position));
                p.refs.push((o.position, 0, tid));
            }
        }
        for &(id, piece, thread) in &p.joins {
            stacks.joins.push((rename(k, id), piece, thread));
        }
        stats.stacks += p.stacks;
        stats.stack_continuations += p.continuations;
        stats.stacks_unmatched += p.unmatched;
        let snapshot = std::mem::take(&mut p.snapshot);
        let (bs, bw, br) = bases[k];
        stitch.absorb(
            p.start,
            snapshot,
            Box::new(move |id| {
                let base = match id & !ROW {
                    SAMPLE => bs,
                    SWITCH => bw,
                    _ => br,
                };
                (id & !ROW) | (base + (id & ROW))
            }),
        );
    }

    // Processes, threads and images, in order, with each part's first uses
    // of thread IDs: which thread each ID is from where on.
    let mut tables = Tables::new(clock, processors);
    let mut timeline = Timeline::default();
    for p in &mut parts {
        p.refs.sort_unstable();
        let mut refs = p.refs.iter().peekable();
        let mut lives = p.lifetimes.iter().peekable();
        loop {
            let next_ref = refs.peek().map(|&&(pos, sub, _)| (pos, sub));
            let next_life = lives.peek().map(|&&(pos, _, _)| (pos, 0u8));
            match (next_ref, next_life) {
                (None, None) => break,
                (Some(a), b) if b.is_none_or(|b| a < b) => {
                    let &(_, _, tid) = refs.next().expect("peeked");
                    tables.thread(tid);
                    timeline.note(tid, a, tables.live_threads.get(&tid).copied());
                }
                (_, Some(b)) => {
                    let &(_, t, item) = lives.next().expect("peeked");
                    if let Some(tid) = tables.life(t, item) {
                        timeline.note(tid, b, tables.live_threads.get(&tid).copied());
                    }
                }
                (Some(_), None) => unreachable!("the guard takes a lone reference"),
            }
        }
    }

    // The rows, with their threads; in parallel by part.
    let timeline = &timeline;
    let columns: Vec<Columns> = parallel(&parts, threads, |_, p| Columns::of(p, timeline));
    let mut trace = tables.trace;
    for mut c in columns {
        let s = &mut trace.samples;
        s.time.append(&mut c.sample_time);
        s.cpu.append(&mut c.sample_cpu);
        s.thread.append(&mut c.sample_thread);
        s.ip.append(&mut c.sample_ip);
        s.weight.append(&mut c.sample_weight);
        let w = &mut trace.switches;
        w.time.append(&mut c.switch_time);
        w.cpu.append(&mut c.switch_cpu);
        w.new_thread.append(&mut c.switch_new);
        w.old_thread.append(&mut c.switch_old);
        w.new_priority.append(&mut c.switch_new_priority);
        w.old_priority.append(&mut c.switch_old_priority);
        w.wait_reason.append(&mut c.switch_wait_reason);
        w.old_state.append(&mut c.switch_old_state);
        let r = &mut trace.readies;
        r.time.append(&mut c.ready_time);
        r.cpu.append(&mut c.ready_cpu);
        r.thread.append(&mut c.ready_thread);
        r.readier.append(&mut c.ready_readier);
    }
    // Readiers from stacks matched across parts, where none was known.
    for (row, tid, position) in readier_fixes {
        if !trace.readies.readier[row].is_some() {
            trace.readies.readier[row] = timeline.at(tid, (position, 0));
        }
    }
    trace.samples.stack = vec![StackId::EMPTY; trace.samples.time.len()];
    trace.switches.stack = vec![StackId::EMPTY; trace.switches.time.len()];
    trace.readies.stack = vec![StackId::EMPTY; trace.readies.time.len()];
    // Each switch's ready event: its thread's latest one since it last
    // ran. In order (rows of both tables are in it).
    let positions: (Vec<u64>, Vec<u64>) = (
        parts
            .iter()
            .flat_map(|p| p.switches.iter().map(|w| w.position))
            .collect(),
        parts
            .iter()
            .flat_map(|p| p.readies.iter().map(|r| r.position))
            .collect(),
    );
    let mut ready = vec![ReadyIx::NONE; trace.switches.time.len()];
    let mut last_ready: FxHashMap<ThreadIx, ReadyIx> = FxHashMap::default();
    let (mut i, mut j) = (0, 0);
    while i < positions.0.len() {
        if j < positions.1.len() && positions.1[j] < positions.0[i] {
            last_ready.insert(trace.readies.thread[j], ReadyIx(row(j)));
            j += 1;
        } else {
            ready[i] = last_ready
                .remove(&trace.switches.new_thread[i])
                .unwrap_or(ReadyIx::NONE);
            i += 1;
        }
    }
    trace.switches.ready = ready;
    drop(parts);

    let trace = stacks.finish(trace, shards, threads);
    (trace, stats)
}

/// A part's rows as the trace's columns.
#[derive(Default)]
struct Columns {
    sample_time: Vec<i64>,
    sample_cpu: Vec<u16>,
    sample_thread: Vec<ThreadIx>,
    sample_ip: Vec<u64>,
    sample_weight: Vec<u16>,
    switch_time: Vec<i64>,
    switch_cpu: Vec<u16>,
    switch_new: Vec<ThreadIx>,
    switch_old: Vec<ThreadIx>,
    switch_new_priority: Vec<i8>,
    switch_old_priority: Vec<i8>,
    switch_wait_reason: Vec<i8>,
    switch_old_state: Vec<i8>,
    ready_time: Vec<i64>,
    ready_cpu: Vec<u16>,
    ready_thread: Vec<ThreadIx>,
    ready_readier: Vec<ThreadIx>,
}

impl Columns {
    fn of(p: &Part<'_>, timeline: &Timeline) -> Self {
        let mut c = Self::default();
        for s in &p.samples {
            c.sample_time.push(s.time);
            c.sample_cpu.push(s.cpu);
            c.sample_thread.push(timeline.at(s.tid, (s.position, 0)));
            c.sample_ip.push(s.ip);
            c.sample_weight.push(s.weight);
        }
        for w in &p.switches {
            c.switch_time.push(w.time);
            c.switch_cpu.push(w.cpu);
            c.switch_new.push(timeline.at(w.new_tid, (w.position, 0)));
            c.switch_old.push(timeline.at(w.old_tid, (w.position, 1)));
            c.switch_new_priority.push(w.new_priority);
            c.switch_old_priority.push(w.old_priority);
            c.switch_wait_reason.push(w.wait_reason);
            c.switch_old_state.push(w.old_state);
        }
        for r in &p.readies {
            c.ready_time.push(r.time);
            c.ready_cpu.push(r.cpu);
            c.ready_thread.push(timeline.at(r.tid, (r.position, 0)));
            c.ready_readier.push(
                r.readier
                    .map_or(ThreadIx::NONE, |(tid, at)| timeline.at(tid, (at, 0))),
            );
        }
        c
    }
}

/// Rows' stacks, as pieces until the end, and the user-mode parts to join
/// to them.
#[derive(Default)]
struct Stacks {
    sample_pieces: Vec<Piece>,
    switch_pieces: Vec<Piece>,
    ready_pieces: Vec<Piece>,
    /// In order: the row (its table's tag and index), the part, and its
    /// thread.
    joins: Vec<(u64, Piece, u32)>,
}

fn row(n: usize) -> u32 {
    u32::try_from(n).expect("fewer than 4G rows")
}

impl Stacks {
    /// The piece of the row tagged `id`.
    fn piece(&self, id: u64) -> Piece {
        let r = (id & ROW) as usize;
        match id & !ROW {
            SAMPLE => self.sample_pieces[r],
            SWITCH => self.switch_pieces[r],
            _ => self.ready_pieces[r],
        }
    }

    fn piece_mut(&mut self, id: u64) -> &mut Piece {
        let r = (id & ROW) as usize;
        match id & !ROW {
            SAMPLE => &mut self.sample_pieces[r],
            SWITCH => &mut self.switch_pieces[r],
            _ => &mut self.ready_pieces[r],
        }
    }

    /// Joins split stacks, then lays the shards' tries end to end as the
    /// trace's stack store and points the rows at their stacks.
    fn finish(mut self, mut trace: Trace, shards: Vec<Shard>, threads: usize) -> Trace {
        let shards: Vec<Mutex<Shard>> = shards.into_iter().map(Mutex::new).collect();
        self.join(&shards, threads);
        let shards: Vec<Shard> = shards
            .into_iter()
            .map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner))
            .collect();

        // Each shard's nodes in canonical order, in parallel.
        let canon: Vec<Canonical> = parallel(&shards, threads, |_, s| Canonical::of(&s.store));
        // Laid end to end after the empty stack.
        let mut base = Vec::with_capacity(canon.len());
        let mut total = 1usize;
        for c in &canon {
            base.push(total);
            total += c.parents.len();
        }
        let mut parents = Vec::with_capacity(total);
        let mut frames = Vec::with_capacity(total);
        parents.push(StackId::EMPTY);
        frames.push(0);
        for (s, c) in canon.iter().enumerate() {
            for (&p, &f) in c.parents.iter().zip(&c.frames) {
                parents.push(global(base[s], p));
                frames.push(f);
            }
        }
        let resolve = |p: Piece| {
            let (s, id) = piece_parts(p);
            global(base[s], canon[s].number[id.0 as usize])
        };
        for (stack, &p) in trace.samples.stack.iter_mut().zip(&self.sample_pieces) {
            *stack = resolve(p);
        }
        for (stack, &p) in trace.switches.stack.iter_mut().zip(&self.switch_pieces) {
            *stack = resolve(p);
        }
        for (stack, &p) in trace.readies.stack.iter_mut().zip(&self.ready_pieces) {
            *stack = resolve(p);
        }
        trace.stacks = StackStore::from_nodes(parents, frames).expect("parents precede children");
        trace
    }

    /// Joins each user-mode part to its row's stack: the part's frames
    /// (the callers) then the row's.
    fn join(&mut self, shards: &[Mutex<Shard>], threads: usize) {
        if self.joins.is_empty() {
            return;
        }
        // A row's parts are joined in the order they came: in rounds of at
        // most one part per row. In a round the same join (the same stack,
        // part and thread) recurs over and over; each distinct one is done
        // once, the distinct ones spread over `threads` threads.
        let mut pending = std::mem::take(&mut self.joins);
        while !pending.is_empty() {
            let mut seen: FxHashMap<u64, ()> = FxHashMap::default();
            let mut round = Vec::new();
            let mut later = Vec::new();
            for j in pending {
                if seen.insert(j.0, ()).is_none() {
                    round.push(j);
                } else {
                    later.push(j);
                }
            }
            pending = later;
            let mut distinct: Vec<(Piece, Piece, u32)> = round
                .iter()
                .map(|&(id, user, thread)| (self.piece(id), user, thread))
                .collect();
            distinct.sort_unstable();
            distinct.dedup();
            let chunk = distinct.len().div_ceil(threads).max(1);
            let joined: Vec<Vec<Piece>> = std::thread::scope(|scope| {
                let handles: Vec<_> = distinct
                    .chunks(chunk)
                    .map(|part| {
                        scope.spawn(move || {
                            let mut inner = Vec::new();
                            let mut whole = Vec::new();
                            part.iter()
                                .map(|&(stack, user, thread)| {
                                    frames_of(shards, stack, &mut inner);
                                    frames_of(shards, user, &mut whole);
                                    whole.extend_from_slice(&inner);
                                    intern(shards, thread, &whole)
                                })
                                .collect()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("joining doesn't panic"))
                    .collect()
            });
            let result: FxHashMap<(Piece, Piece, u32), Piece> = distinct
                .into_iter()
                .zip(joined.into_iter().flatten())
                .collect();
            for (id, user, thread) in round {
                let p = result[&(self.piece(id), user, thread)];
                *self.piece_mut(id) = p;
            }
        }
    }
}

/// The trace's processes, threads and images, as their events are replayed
/// in order; and which thread each ID is now.
struct Tables {
    trace: Trace,
    live_processes: FxHashMap<u32, ProcessIx>,
    live_threads: FxHashMap<u32, ThreadIx>,
    live_images: FxHashMap<(u32, u64), ImageIx>,
}

impl Tables {
    fn new(clock: Clock, processors: u32) -> Self {
        Self {
            trace: Trace::new(clock, processors),
            live_processes: FxHashMap::default(),
            live_threads: FxHashMap::default(),
            live_images: FxHashMap::default(),
        }
    }

    /// Replays a lifetime event (or another event about processes, threads
    /// and images) at `t`; returns the thread ID it may have changed.
    fn life(&mut self, t: i64, item: &Item) -> Option<u32> {
        match item {
            Item::Interval(ns) => self.trace.sample_interval = Some(*ns),
            Item::Process(p) => self.process(t, p),
            Item::Thread(th) => {
                self.thread_event(t, th);
                return Some(th.thread_id);
            }
            Item::ThreadName { thread_id, name } => {
                let thread = self.thread(*thread_id);
                self.trace.threads[thread.index()].name = Some(name.clone());
                return Some(*thread_id);
            }
            Item::Image(im) => self.image(t, im),
            Item::ImageId {
                process_id,
                base,
                time_date_stamp,
            } => {
                if let Some(&ix) = self.live_images.get(&(*process_id, *base)) {
                    let image = &mut self.trace.images[ix.index()];
                    if image.time_date_stamp == 0 {
                        image.time_date_stamp = *time_date_stamp;
                    }
                }
            }
            Item::DbgId(d) => {
                if let Some(&ix) = self.live_images.get(&(d.process_id, d.base)) {
                    self.trace.images[ix.index()].debug_id = Some(DebugId {
                        guid: d.guid,
                        age: d.age,
                        pdb_path: d.pdb.clone(),
                    });
                }
            }
            Item::Sample(_) | Item::Switch(_) | Item::Ready(_) | Item::Stack { .. } => {}
        }
        None
    }

    /// The live thread with `tid`, or a new one of unknown process.
    fn thread(&mut self, tid: u32) -> ThreadIx {
        if let Some(&t) = self.live_threads.get(&tid) {
            return t;
        }
        let process = if tid == 0 {
            // The idle threads belong to the idle process.
            self.live_processes
                .get(&0)
                .copied()
                .unwrap_or(ProcessIx::NONE)
        } else {
            ProcessIx::NONE
        };
        let ix = ThreadIx(row(self.trace.threads.len()));
        self.trace.threads.push(Thread {
            tid,
            process,
            name: None,
            start_address: 0,
            start: None,
            end: None,
        });
        self.live_threads.insert(tid, ix);
        ix
    }

    fn process(&mut self, t: i64, p: &ProcessItem) {
        let existing = self.live_processes.get(&p.process_id).copied();
        let same = existing.filter(|ix| {
            let q = &self.trace.processes[ix.index()];
            q.unique_key == p.unique_key || q.unique_key == 0
        });
        match p.lifetime {
            Lifetime::Start | Lifetime::RundownStart => {
                if p.lifetime == Lifetime::RundownStart && same.is_some() {
                    return;
                }
                let ix = ProcessIx(row(self.trace.processes.len()));
                self.trace.processes.push(Process {
                    pid: p.process_id,
                    parent_pid: p.parent_id,
                    unique_key: p.unique_key,
                    name: p.name.clone(),
                    command_line: p.command_line.clone(),
                    start: (p.lifetime == Lifetime::Start).then_some(t),
                    end: None,
                    exit_status: None,
                });
                self.live_processes.insert(p.process_id, ix);
            }
            Lifetime::End => {
                if let Some(ix) = same {
                    let q = &mut self.trace.processes[ix.index()];
                    q.end = Some(t);
                    q.exit_status = Some(p.exit_status);
                }
            }
            Lifetime::RundownEnd => {
                if same.is_none() {
                    let ix = ProcessIx(row(self.trace.processes.len()));
                    self.trace.processes.push(Process {
                        pid: p.process_id,
                        parent_pid: p.parent_id,
                        unique_key: p.unique_key,
                        name: p.name.clone(),
                        command_line: p.command_line.clone(),
                        ..Process::default()
                    });
                    self.live_processes.insert(p.process_id, ix);
                }
            }
            Lifetime::Defunct => {}
        }
    }

    fn thread_event(&mut self, t: i64, th: &ThreadEvent) {
        let process = self
            .live_processes
            .get(&th.process_id)
            .copied()
            .unwrap_or(ProcessIx::NONE);
        match th.lifetime {
            Lifetime::Start | Lifetime::RundownStart => {
                if let Some(&ix) = self.live_threads.get(&th.thread_id) {
                    let existing = &mut self.trace.threads[ix.index()];
                    // A rundown for a thread we only knew by its ID fills it in.
                    if th.lifetime == Lifetime::RundownStart
                        || (existing.process == ProcessIx::NONE && existing.start.is_none())
                    {
                        if existing.process == ProcessIx::NONE {
                            existing.process = process;
                            existing.start_address = th.win32_start_address;
                        }
                        if th.lifetime == Lifetime::RundownStart {
                            return;
                        }
                        existing.start = Some(t);
                        return;
                    }
                }
                let ix = ThreadIx(row(self.trace.threads.len()));
                self.trace.threads.push(Thread {
                    tid: th.thread_id,
                    process,
                    name: None,
                    start_address: th.win32_start_address,
                    start: (th.lifetime == Lifetime::Start).then_some(t),
                    end: None,
                });
                self.live_threads.insert(th.thread_id, ix);
            }
            Lifetime::End => {
                let ix = self.thread(th.thread_id);
                let thread = &mut self.trace.threads[ix.index()];
                thread.end = Some(t);
                if thread.process == ProcessIx::NONE {
                    thread.process = process;
                }
            }
            Lifetime::RundownEnd => {
                let ix = self.thread(th.thread_id);
                let thread = &mut self.trace.threads[ix.index()];
                if thread.process == ProcessIx::NONE {
                    thread.process = process;
                    thread.start_address = th.win32_start_address;
                }
            }
            Lifetime::Defunct => {}
        }
    }

    fn image(&mut self, t: i64, im: &ImageItem) {
        let key = (im.process_id, im.base);
        let process = if im.process_id == 0 {
            ProcessIx::NONE
        } else {
            self.live_processes
                .get(&im.process_id)
                .copied()
                .unwrap_or(ProcessIx::NONE)
        };
        match im.lifetime {
            Lifetime::End => {
                if let Some(ix) = self.live_images.remove(&key) {
                    self.trace.images[ix.index()].unload = Some(t);
                }
            }
            Lifetime::RundownEnd if self.live_images.contains_key(&key) => {}
            Lifetime::RundownStart if self.live_images.contains_key(&key) => {}
            _ => {
                let ix = ImageIx(row(self.trace.images.len()));
                self.trace.images.push(Image {
                    process,
                    base: im.base,
                    size: im.size,
                    path: im.path.clone(),
                    time_date_stamp: im.time_date_stamp,
                    checksum: im.checksum,
                    debug_id: None,
                    load: (im.lifetime == Lifetime::Start).then_some(t),
                    unload: None,
                });
                self.live_images.insert(key, ix);
            }
        }
    }
}

/// One trie of stacks, and its threads' recent paths.
#[derive(Default)]
struct Shard {
    store: StackStore,
    caches: FxHashMap<u32, PathCache>,
}

/// A stack in a shard: the shard in the high half, the node in the low.
type Piece = u64;

fn piece(shard: usize, id: StackId) -> Piece {
    (shard as u64) << 32 | u64::from(id.0)
}

fn piece_parts(p: Piece) -> (usize, StackId) {
    (
        usize::try_from(p >> 32).expect("a shard"),
        StackId(u32::try_from(p & 0xffff_ffff).expect("a node")),
    )
}

/// The shard of a stack of `thread` whose frames, outermost first, are
/// `frames`.
fn shard_of(thread: u32, frames: &[u64]) -> usize {
    let mut h = FxHasher::default();
    thread.hash(&mut h);
    frames[..frames.len().min(SHARD_FRAMES)].hash(&mut h);
    usize::try_from(h.finish() % SHARDS as u64).expect("a shard")
}

/// Interns `frames` (outermost first) of `thread`'s stack.
fn intern(shards: &[Mutex<Shard>], thread: u32, frames: &[u64]) -> Piece {
    if frames.is_empty() {
        return piece(0, StackId::EMPTY);
    }
    let s = shard_of(thread, frames);
    let mut shard = shards[s].lock().unwrap_or_else(PoisonError::into_inner);
    let Shard { store, caches } = &mut *shard;
    let id = store.intern_outermost_first(frames, caches.entry(thread).or_default());
    piece(s, id)
}

/// A decoding worker's own state: scratch space, and each thread's last
/// stack and its piece, so that a thread's stack that repeats (as stacks
/// do: a thread sampled in the same place, switched out at the same wait)
/// is found without taking a shard's lock.
#[derive(Default)]
struct Local {
    frames: Vec<u64>,
    last: FxHashMap<u32, (Vec<u64>, Piece)>,
}

impl Local {
    /// Interns `self.frames` (outermost first) of `thread`'s stack.
    fn intern(&mut self, shards: &[Mutex<Shard>], thread: u32) -> Piece {
        if let Some((frames, piece)) = self.last.get(&thread)
            && *frames == self.frames
        {
            return *piece;
        }
        let piece = intern(shards, thread, &self.frames);
        let entry = self.last.entry(thread).or_default();
        entry.0.clone_from(&self.frames);
        entry.1 = piece;
        piece
    }
}

/// `piece`'s frames, outermost first, into `out`.
fn frames_of(shards: &[Mutex<Shard>], piece: Piece, out: &mut Vec<u64>) {
    let (s, id) = piece_parts(piece);
    let shard = shards[s].lock().unwrap_or_else(PoisonError::into_inner);
    shard.store.frames_outermost_first(id, out);
}

/// What the import keeps of an event.
enum Item {
    /// The CPU sampling interval, in nanoseconds.
    Interval(u64),
    Sample(Sample),
    Switch(ContextSwitch),
    Ready(ReadyThread),
    /// A stack, interned.
    Stack {
        event_timestamp: i64,
        thread_id: u32,
        piece: Piece,
    },
    Process(Box<ProcessItem>),
    Thread(ThreadEvent),
    ThreadName {
        thread_id: u32,
        name: String,
    },
    Image(Box<ImageItem>),
    ImageId {
        process_id: u32,
        base: u64,
        time_date_stamp: u32,
    },
    DbgId(Box<DbgItem>),
}

/// A process event's fields the trace keeps.
struct ProcessItem {
    lifetime: Lifetime,
    unique_key: u64,
    process_id: u32,
    parent_id: u32,
    exit_status: i32,
    name: String,
    command_line: String,
}

/// An image event's fields the trace keeps.
struct ImageItem {
    lifetime: Lifetime,
    base: u64,
    size: u64,
    process_id: u32,
    checksum: u32,
    time_date_stamp: u32,
    path: String,
}

/// An image's PDB identity.
struct DbgItem {
    process_id: u32,
    base: u64,
    guid: [u8; 16],
    age: u32,
    pdb: String,
}

/// A decoded buffer.
#[derive(Default)]
struct Decoded {
    /// The buffer's processor.
    processor: u16,
    /// Every event's timestamp, in the buffer's order.
    times: Vec<i64>,
    /// The events the import keeps: each with its index in `times`.
    items: Vec<(u32, Item)>,
    /// Whether the buffer was malformed (and its later events skipped).
    error: bool,
    /// Kernel events whose payloads were malformed.
    decode_errors: u64,
}

/// Decodes `buffer`, interning its stacks in `shards`.
fn decode_buffer(
    buffer: &Buffer<'_>,
    max_buffer: usize,
    scratch: &mut Vec<u8>,
    local: &mut Local,
    shards: &[Mutex<Shard>],
) -> Decoded {
    let mut out = Decoded {
        processor: buffer.context().processor,
        ..Decoded::default()
    };
    let result = for_each_event(buffer, max_buffer, scratch, |e| {
        let index = u32::try_from(out.times.len()).expect("fewer than 4G events in a buffer");
        out.times.push(e.timestamp);
        if let Some(item) = keep(e, local, shards, &mut out.decode_errors) {
            out.items.push((index, item));
        }
    });
    out.error = result.is_err();
    out
}

/// What the import keeps of `e`, if anything.
fn keep(
    e: &Event<'_>,
    local: &mut Local,
    shards: &[Mutex<Shard>],
    decode_errors: &mut u64,
) -> Option<Item> {
    // The sampling interval: PerfInfo's CollectionStart for the profile
    // source (0), in 100 ns units.
    if e.provider == hexcavator_etw::guids::PERF_INFO && e.descriptor.opcode == 73 {
        let p = hexcavator_etw::Properties::of(e)?.ok()?;
        let field = |n: &str| {
            p.get(n)
                .and_then(|f| f.data.get(..4))
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        return (field("Source") == Some(0))
            .then(|| field("NewInterval"))
            .flatten()
            .map(|i| Item::Interval(u64::from(i) * 100));
    }
    let Ok(decoded) = decode(e)? else {
        *decode_errors += 1;
        return None;
    };
    Some(match decoded {
        KernelEvent::Stack(s) => {
            // The frames, outermost first.
            local.frames.clear();
            local.frames.extend(s.frames.iter());
            local.frames.reverse();
            Item::Stack {
                event_timestamp: s.event_timestamp,
                thread_id: s.thread_id,
                piece: local.intern(shards, s.thread_id),
            }
        }
        KernelEvent::Sample(s) => Item::Sample(s),
        KernelEvent::ContextSwitch(c) => Item::Switch(c),
        KernelEvent::ReadyThread(r) => Item::Ready(r),
        KernelEvent::Process(p) => Item::Process(Box::new(ProcessItem {
            lifetime: p.lifetime,
            unique_key: p.unique_key,
            process_id: p.process_id,
            parent_id: p.parent_id,
            exit_status: p.exit_status,
            name: String::from_utf8_lossy(p.image_file_name).into_owned(),
            command_line: p.command_line.to_string_lossy(),
        })),
        KernelEvent::Thread(t) => Item::Thread(t),
        KernelEvent::ThreadName(n) => Item::ThreadName {
            thread_id: n.thread_id,
            name: n.name.to_string_lossy(),
        },
        KernelEvent::Image(im) => Item::Image(Box::new(ImageItem {
            lifetime: im.lifetime,
            base: im.base,
            size: im.size,
            process_id: im.process_id,
            checksum: im.checksum,
            time_date_stamp: im.time_date_stamp,
            path: im.file_name.to_string_lossy(),
        })),
        KernelEvent::ImageId(id) => Item::ImageId {
            process_id: id.process_id,
            base: id.base,
            time_date_stamp: id.time_date_stamp,
        },
        KernelEvent::DbgId(d) if !d.il => Item::DbgId(Box::new(DbgItem {
            process_id: d.process_id,
            base: d.base,
            guid: d.guid.to_bytes(),
            age: d.age,
            pdb: String::from_utf8_lossy(d.pdb_file_name).into_owned(),
        })),
        _ => return None,
    })
}

/// A node's number in the store: the shard's base, then its canonical
/// number there (0, the empty stack, is the store's 0).
fn global(base: usize, number: u32) -> StackId {
    if number == 0 {
        StackId::EMPTY
    } else {
        StackId(u32::try_from(base + number as usize - 1).expect("fewer than 4G stack nodes"))
    }
}

/// A shard's nodes in a canonical order, which depends only on which
/// stacks it holds: by depth, then by parent (in this order) and frame.
struct Canonical {
    /// Each node's number in this order (the empty stack's is 0).
    number: Vec<u32>,
    /// The nodes after the empty stack, in this order: parents (numbers in
    /// this order) and frames.
    parents: Vec<u32>,
    frames: Vec<u64>,
}

impl Canonical {
    fn of(store: &StackStore) -> Self {
        let n = store.len();
        let parent = store.parents();
        let frame = store.frame_column();
        let node = |i: usize| u32::try_from(i).expect("fewer than 4G nodes");
        // Nodes by depth.
        let mut by_depth: Vec<Vec<u32>> = Vec::new();
        for i in 1..n {
            let d = store.depth(StackId(node(i))) as usize;
            if by_depth.len() < d {
                by_depth.resize_with(d, Vec::new);
            }
            by_depth[d - 1].push(node(i));
        }
        let mut number = vec![0u32; n];
        let mut parents = Vec::with_capacity(n.saturating_sub(1));
        let mut frames = Vec::with_capacity(n.saturating_sub(1));
        let mut next = 1u32;
        for level in &mut by_depth {
            // (A shard's nodes are distinct by parent and frame.)
            level.sort_unstable_by_key(|&i| {
                (number[parent[i as usize].0 as usize], frame[i as usize])
            });
            for &i in level.iter() {
                number[i as usize] = next;
                parents.push(number[parent[i as usize].0 as usize]);
                frames.push(frame[i as usize]);
                next += 1;
            }
        }
        Self {
            number,
            parents,
            frames,
        }
    }
}

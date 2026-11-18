//! Building a [`Trace`] from a Windows ETL file.
//!
//! The import runs in three stages, so that it uses every core:
//!
//! 1. **Decode, in parallel.** Workers take the file's buffers in turn and
//!    decode each into the few things the trace keeps (samples, switches,
//!    lifetimes, ...) and the timestamps of all its events. Each stack is
//!    interned on the spot into one of [`SHARDS`] tries, chosen by its
//!    thread and outermost frames, each behind a lock of its own: so a
//!    thread's same stack always lands in the same trie, and workers
//!    rarely wait for each other.
//! 2. **Merge, in order.** One thread walks the decoded buffers in the
//!    order [`hexcavator_etl::EventCursor`] reads them (by timestamp, ties
//!    broken as `ProcessTrace` breaks them: [`Order`]) and does what needs
//!    that order: processes, threads and images coming and going, which
//!    thread runs where, and which event each stack belongs to. It starts
//!    as soon as the first buffers are decoded.
//! 3. **Finish, in parallel.** Split stacks are joined (a user-mode part to
//!    its kernel-mode part), each trie is numbered in a canonical order
//!    (so the result doesn't depend on which worker got there first), and
//!    the tries are laid end to end as the trace's stack store.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use rustc_hash::{FxHashMap, FxHasher};

use hexcavator_core::Result;
use hexcavator_etl::{Buffer, Etl, Event, Order, for_each_event, streams};
use hexcavator_etw::kernel::{
    ContextSwitch, KernelEvent, Lifetime, ReadyThread, Sample, ThreadEvent, decode,
};
use hexcavator_etw::stacks::StackMatcher;

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

/// Reads `etl` into a [`Trace`], decoding on `threads` threads (besides
/// the one that merges). The result is the same for any number.
pub fn import_with(etl: &Etl<'_>, threads: usize) -> Result<(Trace, ImportStats)> {
    let header = etl.header();
    let ticks = header.ticks_per_second().unwrap_or(10_000_000);
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
    let slots = Slots {
        slots: Mutex::new((0..buffers.len()).map(|_| None).collect()),
        ready: Condvar::new(),
    };
    let next = AtomicUsize::new(0);

    let mut builder = Builder::new(ticks, header.number_of_processors);
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut frames = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((buffer, _)) = buffers.get(i) else {
                        return;
                    };
                    let decoded =
                        decode_buffer(buffer, max_buffer, &mut scratch, &mut frames, &shards);
                    slots.put(i, decoded);
                }
            });
        }
        merge(&mut builder, &stream_buffers, &slots);
    });

    let shards: Vec<Shard> = shards
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner))
        .collect();
    Ok(builder.finish(shards, threads.max(1)))
}

/// Decoded buffers, as workers finish them, for the merge to take.
struct Slots {
    slots: Mutex<Vec<Option<Decoded>>>,
    ready: Condvar,
}

impl Slots {
    fn put(&self, i: usize, d: Decoded) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots[i] = Some(d);
        self.ready.notify_all();
    }

    /// Waits for buffer `i` and takes it.
    fn take(&self, i: usize) -> Decoded {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(d) = slots[i].take() {
                return d;
            }
            slots = self
                .ready
                .wait(slots)
                .unwrap_or_else(PoisonError::into_inner);
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
    frames: &mut Vec<u64>,
    shards: &[Mutex<Shard>],
) -> Decoded {
    let mut out = Decoded {
        processor: buffer.context().processor,
        ..Decoded::default()
    };
    let result = for_each_event(buffer, max_buffer, scratch, |e| {
        let index = u32::try_from(out.times.len()).expect("fewer than 4G events in a buffer");
        out.times.push(e.timestamp);
        if let Some(item) = keep(e, frames, shards, &mut out.decode_errors) {
            out.items.push((index, item));
        }
    });
    out.error = result.is_err();
    out
}

/// What the import keeps of `e`, if anything.
fn keep(
    e: &Event<'_>,
    frames: &mut Vec<u64>,
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
            frames.clear();
            frames.extend(s.frames.iter());
            frames.reverse();
            Item::Stack {
                event_timestamp: s.event_timestamp,
                thread_id: s.thread_id,
                piece: intern(shards, s.thread_id, frames),
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

/// A stream's place in the merge.
struct Cursor {
    /// Its buffers (positions in the file's list), and the next to take.
    buffers: Vec<usize>,
    next: usize,
    current: Decoded,
    /// The next event and the next kept item in `current`.
    event: usize,
    item: usize,
}

impl Cursor {
    /// The timestamp of the stream's next event, taking buffers as needed;
    /// `None` at its end.
    fn head(&mut self, slots: &Slots, stats: &mut ImportStats) -> Option<i64> {
        loop {
            if let Some(&t) = self.current.times.get(self.event) {
                return Some(t);
            }
            let &b = self.buffers.get(self.next)?;
            self.next += 1;
            self.current = slots.take(b);
            self.event = 0;
            self.item = 0;
            stats.events += self.current.times.len() as u64;
            stats.read_errors += u64::from(self.current.error);
            stats.decode_errors += self.current.decode_errors;
        }
    }
}

/// Walks the decoded buffers in the cursor's order, building as it goes.
fn merge(builder: &mut Builder, stream_buffers: &[Vec<usize>], slots: &Slots) {
    let mut cursors: Vec<Cursor> = stream_buffers
        .iter()
        .map(|b| Cursor {
            buffers: b.clone(),
            next: 0,
            current: Decoded::default(),
            event: 0,
            item: 0,
        })
        .collect();
    let mut order = Order::new();
    // Queued last to first, as the cursor does.
    for i in (0..cursors.len()).rev() {
        if let Some(t) = cursors[i].head(slots, &mut builder.stats) {
            order.push(i, t);
        }
    }
    let mut first = true;
    while let Some((i, mut t)) = order.pop() {
        if first {
            builder.trace.clock.origin = t;
            first = false;
        }
        // The stream's events while they come first: until one is later
        // than the next queued event. (On a tie the stream that gave the
        // last event goes first, so it keeps going; and queueing it again
        // only after its run orders later ties as queueing it after each
        // event would: no other stream is queued in between.)
        let limit = order.peek().unwrap_or(i64::MAX);
        loop {
            let c = &mut cursors[i];
            let event = c.event;
            c.event += 1;
            if let Some((index, _)) = c.current.items.get(c.item)
                && *index as usize == event
            {
                let cpu = c.current.processor;
                let item = std::mem::replace(&mut c.current.items[c.item].1, Item::Interval(0));
                c.item += 1;
                builder.item(cpu, t, item);
            }
            match cursors[i].head(slots, &mut builder.stats) {
                Some(next) if next <= limit => t = next,
                Some(next) => {
                    order.push(i, next);
                    break;
                }
                None => break,
            }
        }
    }
}

struct Builder {
    trace: Trace,
    stats: ImportStats,
    live_processes: FxHashMap<u32, ProcessIx>,
    live_threads: FxHashMap<u32, ThreadIx>,
    live_images: FxHashMap<(u32, u64), ImageIx>,
    /// The thread running on each processor.
    running: Vec<ThreadIx>,
    /// Each thread's latest ready event not yet followed by its switch-in.
    last_ready: FxHashMap<ThreadIx, ReadyIx>,
    matcher: StackMatcher,
    /// Each table's rows' stacks, as pieces (resolved at the end).
    sample_pieces: Vec<Piece>,
    switch_pieces: Vec<Piece>,
    ready_pieces: Vec<Piece>,
    /// User-mode parts to join to rows' stacks, in order: the row (its
    /// table's tag and index), the part, and its thread.
    joins: Vec<(u64, Piece, u32)>,
}

fn row(n: usize) -> u32 {
    u32::try_from(n).expect("fewer than 4G rows")
}

impl Builder {
    fn new(ticks: u64, processors: u32) -> Self {
        Self {
            trace: Trace::new(
                Clock {
                    ticks_per_second: ticks,
                    origin: 0,
                },
                processors,
            ),
            stats: ImportStats::default(),
            live_processes: FxHashMap::default(),
            live_threads: FxHashMap::default(),
            live_images: FxHashMap::default(),
            running: Vec::new(),
            last_ready: FxHashMap::default(),
            // Wait up to five seconds for the user part of a split stack.
            matcher: StackMatcher::new(i64::try_from(ticks.saturating_mul(5)).unwrap_or(i64::MAX)),
            sample_pieces: Vec::new(),
            switch_pieces: Vec::new(),
            ready_pieces: Vec::new(),
            joins: Vec::new(),
        }
    }

    fn item(&mut self, cpu: u16, t: i64, item: Item) {
        match item {
            Item::Interval(ns) => self.trace.sample_interval = Some(ns),
            Item::Stack {
                event_timestamp,
                thread_id,
                piece,
            } => {
                let Some(m) = self.matcher.stack_at(cpu, t, event_timestamp, thread_id) else {
                    self.stats.stacks_unmatched += 1;
                    return;
                };
                let r = (m.id & ROW) as usize;
                if m.continuation {
                    // The user part: the callers of the part the row has.
                    self.stats.stack_continuations += 1;
                    self.joins.push((m.id, piece, thread_id));
                } else {
                    self.stats.stacks += 1;
                    *self.piece_mut(m.id) = piece;
                }
                // A ready event whose readier wasn't known (before its
                // processor's first switch): the stack's thread.
                if m.id & !ROW == READY
                    && let Some(tid) = m.thread
                    && !self.trace.readies.readier[r].is_some()
                {
                    let readier = self.thread(tid);
                    self.trace.readies.readier[r] = readier;
                }
            }
            Item::Sample(s) => {
                let thread = self.thread(s.thread_id);
                let samples = &mut self.trace.samples;
                let r = samples.len();
                samples.time.push(t);
                samples.cpu.push(cpu);
                samples.thread.push(thread);
                samples.ip.push(s.instruction_pointer);
                samples.stack.push(StackId::EMPTY);
                samples.weight.push(s.count.max(1));
                self.sample_pieces.push(0);
                self.matcher.event_at(
                    SAMPLE | r as u64,
                    cpu,
                    t,
                    u32::MAX,
                    Some(&KernelEvent::Sample(s)),
                );
            }
            Item::Switch(c) => {
                let new = self.thread(c.new_thread_id);
                let old = self.thread(c.old_thread_id);
                let ready = self.last_ready.remove(&new).unwrap_or(ReadyIx::NONE);
                let sw = &mut self.trace.switches;
                let r = sw.len();
                sw.time.push(t);
                sw.cpu.push(cpu);
                sw.new_thread.push(new);
                sw.old_thread.push(old);
                sw.new_priority.push(c.new_thread_priority);
                sw.old_priority.push(c.old_thread_priority);
                sw.wait_reason.push(c.old_thread_wait_reason);
                sw.old_state.push(c.old_thread_state);
                sw.stack.push(StackId::EMPTY);
                sw.ready.push(ready);
                self.switch_pieces.push(0);
                self.matcher.event_at(
                    SWITCH | r as u64,
                    cpu,
                    t,
                    u32::MAX,
                    Some(&KernelEvent::ContextSwitch(c)),
                );
                let i = usize::from(cpu);
                if i >= self.running.len() {
                    self.running.resize(i + 1, ThreadIx::NONE);
                }
                self.running[i] = new;
            }
            Item::Ready(rt) => {
                let thread = self.thread(rt.thread_id);
                let readier = self
                    .running
                    .get(usize::from(cpu))
                    .copied()
                    .unwrap_or(ThreadIx::NONE);
                let rd = &mut self.trace.readies;
                let r = rd.len();
                rd.time.push(t);
                rd.cpu.push(cpu);
                rd.thread.push(thread);
                rd.readier.push(readier);
                rd.stack.push(StackId::EMPTY);
                self.ready_pieces.push(0);
                self.last_ready.insert(thread, ReadyIx(row(r)));
                self.matcher.event_at(
                    READY | r as u64,
                    cpu,
                    t,
                    u32::MAX,
                    Some(&KernelEvent::ReadyThread(rt)),
                );
            }
            Item::Process(p) => self.process(t, &p),
            Item::Thread(th) => self.thread_event(t, &th),
            Item::ThreadName { thread_id, name } => {
                let thread = self.thread(thread_id);
                self.trace.threads[thread.index()].name = Some(name);
            }
            Item::Image(im) => self.image(t, &im),
            Item::ImageId {
                process_id,
                base,
                time_date_stamp,
            } => {
                if let Some(&ix) = self.live_images.get(&(process_id, base)) {
                    let image = &mut self.trace.images[ix.index()];
                    if image.time_date_stamp == 0 {
                        image.time_date_stamp = time_date_stamp;
                    }
                }
            }
            Item::DbgId(d) => {
                if let Some(&ix) = self.live_images.get(&(d.process_id, d.base)) {
                    self.trace.images[ix.index()].debug_id = Some(DebugId {
                        guid: d.guid,
                        age: d.age,
                        pdb_path: d.pdb,
                    });
                }
            }
        }
    }

    /// Joins split stacks, then lays the shards' tries end to end as the
    /// trace's stack store and points the rows at their stacks.
    fn finish(mut self, shards: Vec<Shard>, threads: usize) -> (Trace, ImportStats) {
        let shards: Vec<Mutex<Shard>> = shards.into_iter().map(Mutex::new).collect();
        self.join(&shards, threads);
        let shards: Vec<Shard> = shards
            .into_iter()
            .map(|m| m.into_inner().unwrap_or_else(PoisonError::into_inner))
            .collect();

        // Each shard's nodes in canonical order, in parallel.
        let canon: Vec<Canonical> = std::thread::scope(|scope| {
            let handles: Vec<_> = shards
                .iter()
                .map(|s| scope.spawn(|| Canonical::of(&s.store)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("numbering doesn't panic"))
                .collect()
        });
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
        let t = &mut self.trace;
        for (stack, &p) in t.samples.stack.iter_mut().zip(&self.sample_pieces) {
            *stack = resolve(p);
        }
        for (stack, &p) in t.switches.stack.iter_mut().zip(&self.switch_pieces) {
            *stack = resolve(p);
        }
        for (stack, &p) in t.readies.stack.iter_mut().zip(&self.ready_pieces) {
            *stack = resolve(p);
        }
        t.stacks = StackStore::from_nodes(parents, frames).expect("parents precede children");
        (self.trace, self.stats)
    }

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

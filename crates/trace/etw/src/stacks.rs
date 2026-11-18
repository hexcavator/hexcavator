//! Which event each stack belongs to.
//!
//! The kernel logs a stack as a separate `StackWalk` event that names the
//! timestamp and thread of the event it belongs to. Usually it follows that
//! event on the same processor. A stack that reaches user mode is often
//! split: the kernel part comes at once, and the user part is logged when
//! the thread next returns to user mode, perhaps on another processor, with
//! the same timestamp and thread. [`StackMatcher`] pairs each piece with its
//! event.
//!
//! An event's "stack thread" is the thread in its header. Kernel events
//! with no thread in the header use the thread they're about:
//!
//! - a CPU sample: the sampled thread;
//! - a context switch: the thread switched in (the stack shows where it was
//!   waiting);
//! - a ready-thread event: the thread running on that processor, which is
//!   the one doing the readying (the stack shows why). Before the
//!   processor's first context switch that thread is unknown; the event
//!   then takes a stack of any thread with its timestamp, and the stack
//!   names the readying thread ([`StackMatch::thread`]).

//!
//! # Matching in parts
//!
//! An importer may cut a trace into parts by time and match each part's
//! stacks with a matcher of its own, in parallel. A part's matcher starts
//! knowing which thread runs on each processor
//! ([`StackMatcher::starting_with`]), so it matches what a matcher that
//! had read the whole trace would, except stacks whose event is in an
//! earlier part (whose event timestamp is before the part's start). Those
//! are matched afterwards, in order, by a [`Stitch`]: it holds what the
//! earlier parts' matchers ended with ([`StackMatcher::snapshot`]) and
//! matches as one matcher would have at that point.

use std::collections::VecDeque;

use rustc_hash::FxHashMap;

use hexcavator_etl::Event;

use crate::kernel::{KernelEvent, StackWalk};

/// How many recent events per processor are candidates for its next
/// stacks.
const RING: usize = 32;

/// What a stack piece belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackMatch {
    /// The caller's ID for the event.
    pub id: u64,
    /// Whether the event already had a piece (this is the user-mode part
    /// of a split stack).
    pub continuation: bool,
    /// The stack's thread, when the event's own thread wasn't known (a
    /// ready-thread event before its processor's first context switch):
    /// the thread the event is about.
    pub thread: Option<u32>,
}

/// One candidate: an event that may get a stack.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    timestamp: i64,
    thread: u32,
    id: u64,
}

/// Pairs stacks with the events they belong to. Feed it every event in
/// timestamp order: [`StackMatcher::event`] for events, and
/// [`StackMatcher::stack`] for stacks.
#[derive(Debug)]
pub struct StackMatcher {
    /// Recent events on each processor.
    recent: Vec<VecDeque<Candidate>>,
    /// The thread running on each processor, by its context switches.
    running: Vec<u32>,
    /// Events that got a piece, by (timestamp, thread), for continuations:
    /// the event, whether it took any thread's stack, and when.
    matched: FxHashMap<(i64, u32), (u64, bool, i64)>,
    /// `matched`'s keys in the order they were added, to forget old ones.
    matched_order: VecDeque<(i64, (i64, u32))>,
    /// How long (in clock ticks) to wait for a continuation.
    window: i64,
}

impl StackMatcher {
    /// A matcher that waits up to `window` clock ticks for the user part of
    /// a split stack (a few seconds' worth is plenty).
    pub fn new(window: i64) -> Self {
        Self {
            recent: Vec::new(),
            running: Vec::new(),
            matched: FxHashMap::default(),
            matched_order: VecDeque::new(),
            window,
        }
    }

    /// A matcher for a part of a trace, starting with `running[c]` running
    /// on processor `c` (`u32::MAX`: not known; see the module's notes).
    pub fn starting_with(window: i64, running: &[u32]) -> Self {
        let mut m = Self::new(window);
        if !running.is_empty() {
            let last = u16::try_from(running.len() - 1).expect("processors fit in u16");
            m.cpu(last);
            m.running.copy_from_slice(running);
        }
        m
    }

    /// How many recent events (at most the ring's size) each processor has.
    pub fn recent_counts(&self) -> Vec<u8> {
        self.recent
            .iter()
            .map(|r| u8::try_from(r.len()).expect("a ring holds few events"))
            .collect()
    }

    /// What later stacks may refer to: each processor's recent events, and
    /// the events that got a stack, with when.
    pub fn snapshot(self) -> Snapshot {
        Snapshot {
            recent: self.recent,
            matched: self.matched,
        }
    }

    fn cpu(&mut self, cpu: u16) -> usize {
        let i = usize::from(cpu);
        if i >= self.recent.len() {
            self.recent.resize_with(i + 1, VecDeque::new);
            self.running.resize(i + 1, u32::MAX);
        }
        i
    }

    /// Notes an event (anything but a stack) that may get a stack; `id` is
    /// the caller's name for it. `decoded` is its decoding, if it's a kernel
    /// event.
    pub fn event(&mut self, id: u64, event: &Event<'_>, decoded: Option<&KernelEvent<'_>>) {
        self.event_at(
            id,
            event.context.processor,
            event.timestamp,
            event.thread_id,
            decoded,
        );
    }

    /// [`StackMatcher::event`], given the event's processor, timestamp and
    /// header thread (for a reader that keeps those rather than events).
    pub fn event_at(
        &mut self,
        id: u64,
        processor: u16,
        timestamp: i64,
        header_thread: u32,
        decoded: Option<&KernelEvent<'_>>,
    ) {
        let cpu = self.cpu(processor);
        let thread = match decoded {
            Some(KernelEvent::Sample(s)) => s.thread_id,
            Some(KernelEvent::ContextSwitch(c)) => c.new_thread_id,
            // (Unknown before the first switch: any thread's stack.)
            Some(KernelEvent::ReadyThread(_)) if self.running[cpu] == u32::MAX => ANY,
            Some(KernelEvent::ReadyThread(_)) => self.running[cpu],
            _ => header_thread,
        };
        if let Some(KernelEvent::ContextSwitch(c)) = decoded {
            self.running[cpu] = c.new_thread_id;
        }
        if thread == u32::MAX {
            return;
        }
        let ring = &mut self.recent[cpu];
        if ring.len() == RING {
            ring.pop_front();
        }
        ring.push_back(Candidate {
            timestamp,
            thread,
            id,
        });
    }

    /// The event a stack piece belongs to, if any; `processor` is the
    /// processor that logged the stack and `now` its timestamp.
    pub fn stack(&mut self, processor: u16, now: i64, stack: &StackWalk<'_>) -> Option<StackMatch> {
        self.stack_at(processor, now, stack.event_timestamp, stack.thread_id)
    }

    /// [`StackMatcher::stack`], given the stack's event timestamp and
    /// thread (for a reader that keeps those rather than events).
    pub fn stack_at(
        &mut self,
        processor: u16,
        now: i64,
        event_timestamp: i64,
        thread_id: u32,
    ) -> Option<StackMatch> {
        self.forget_before(now.saturating_sub(self.window));
        let key = (event_timestamp, thread_id);
        if let Some(&(id, any, _)) = self.matched.get(&key) {
            return Some(StackMatch {
                id,
                continuation: true,
                thread: any.then_some(thread_id),
            });
        }
        let cpu = self.cpu(processor);
        let (found, any) = find(&self.recent[cpu], key).or_else(|| {
            self.recent
                .iter()
                .enumerate()
                .filter(|&(i, _)| i != cpu)
                .find_map(|(_, ring)| find(ring, key))
        })?;
        self.matched.insert(key, (found, any, now));
        self.matched_order.push_back((now, key));
        Some(StackMatch {
            id: found,
            continuation: false,
            thread: any.then_some(thread_id),
        })
    }

    fn forget_before(&mut self, t: i64) {
        while let Some(&(when, key)) = self.matched_order.front() {
            if when >= t {
                break;
            }
            self.matched_order.pop_front();
            self.matched.remove(&key);
        }
    }
}

/// A candidate's thread when any thread's stack goes with it.
const ANY: u32 = u32::MAX - 1;

/// The newest candidate in `ring` with the stack's timestamp and thread,
/// or else with its timestamp and any thread; and whether it was the
/// latter.
fn find(ring: &VecDeque<Candidate>, (timestamp, thread): (i64, u32)) -> Option<(u64, bool)> {
    let newest = |want: u32| {
        ring.iter()
            .rev()
            .find(|c| c.timestamp == timestamp && c.thread == want)
            .map(|c| c.id)
    };
    newest(thread)
        .map(|id| (id, false))
        .or_else(|| newest(ANY).map(|id| (id, true)))
}

/// A matcher's state at the end of a part of a trace (see the module's
/// notes).
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Each processor's recent events, oldest first.
    recent: Vec<VecDeque<Candidate>>,
    /// The events that got a stack: key to (event, any thread's, when).
    matched: FxHashMap<(i64, u32), (u64, bool, i64)>,
}

/// Events that got a stack: key to (event, any thread's, when).
type Matched = FxHashMap<(i64, u32), (u64, bool, i64)>;

/// A part a [`Stitch`] took in: its first event timestamp, its matched
/// events, and how to rename its events.
type AbsorbedPart = (i64, Matched, Box<dyn Fn(u64) -> u64 + Send>);

/// Matches the stacks that parts' matchers couldn't: those whose events
/// are in earlier parts. Feed it each part's leftover stacks in order
/// ([`Stitch::stack`]), then the part's [`Snapshot`] ([`Stitch::absorb`]).
pub struct Stitch {
    /// Each processor's recent events as of the current part's start
    /// (with the trace's names for them).
    recent: Vec<VecDeque<Candidate>>,
    /// The parts absorbed: each one's first event timestamp, matched
    /// events, and how to rename its events.
    parts: Vec<AbsorbedPart>,
    /// Events that got a stack here: key to (event, any thread's, when).
    matched: FxHashMap<(i64, u32), (u64, bool, i64)>,
    window: i64,
}

impl Stitch {
    /// A stitch waiting up to `window` clock ticks for continuations, as
    /// the parts' matchers do.
    pub fn new(window: i64) -> Self {
        Self {
            recent: Vec::new(),
            parts: Vec::new(),
            matched: FxHashMap::default(),
            window,
        }
    }

    /// The event a leftover stack of the current part belongs to, as one
    /// matcher would have found it: `processor` logged it at `now`, when
    /// the part's matcher had `counts[c]` recent events of its own on
    /// processor `c` (none of them its event: they are later).
    pub fn stack(
        &mut self,
        processor: u16,
        now: i64,
        event_timestamp: i64,
        thread_id: u32,
        counts: &[u8],
    ) -> Option<StackMatch> {
        let key = (event_timestamp, thread_id);
        let horizon = now.saturating_sub(self.window);
        // Matched before: here, or in the part the event is in (by its
        // timestamp), whichever is later.
        let here = self.matched.get(&key).copied();
        let i = self.parts.partition_point(|p| p.0 <= event_timestamp);
        let there = i.checked_sub(1).and_then(|i| {
            let (_, map, rename) = &self.parts[i];
            map.get(&key)
                .map(|&(id, any, when)| (rename(id), any, when))
        });
        let matched = match (here, there) {
            (Some(a), Some(b)) => Some(if a.2 >= b.2 { a } else { b }),
            (a, b) => a.or(b),
        };
        if let Some((id, any, when)) = matched
            && when >= horizon
        {
            return Some(StackMatch {
                id,
                continuation: true,
                thread: any.then_some(thread_id),
            });
        }
        // Each processor's ring then: the part's own events (none of them
        // this one), after the newest of the earlier parts' that fit.
        let older = |c: usize| {
            let ring = self.recent.get(c)?;
            let own = counts.get(c).map_or(0, |&n| usize::from(n));
            let keep = RING.saturating_sub(own).min(ring.len());
            Some(
                ring.range(ring.len() - keep..)
                    .copied()
                    .collect::<VecDeque<_>>(),
            )
        };
        let cpu = usize::from(processor);
        let found = older(cpu).and_then(|r| find(&r, key)).or_else(|| {
            (0..self.recent.len())
                .filter(|&c| c != cpu)
                .find_map(|c| older(c).and_then(|r| find(&r, key)))
        });
        let (id, any) = found?;
        self.matched.insert(key, (id, any, now));
        Some(StackMatch {
            id,
            continuation: false,
            thread: any.then_some(thread_id),
        })
    }

    /// Takes in a finished part, whose first event is at `start`: its
    /// recent events after the earlier parts' (keeping the newest), and its
    /// matched events. `rename` gives its events' names in the whole trace.
    pub fn absorb(&mut self, start: i64, part: Snapshot, rename: Box<dyn Fn(u64) -> u64 + Send>) {
        if self.recent.len() < part.recent.len() {
            self.recent.resize_with(part.recent.len(), VecDeque::new);
        }
        for (c, ring) in part.recent.into_iter().enumerate() {
            let all = &mut self.recent[c];
            all.extend(ring.into_iter().map(|mut e| {
                e.id = rename(e.id);
                e
            }));
            while all.len() > RING {
                all.pop_front();
            }
        }
        self.parts.push((start, part.matched, rename));
    }
}

impl std::fmt::Debug for Stitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stitch")
            .field("parts", &self.parts.len())
            .field("matched", &self.matched.len())
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

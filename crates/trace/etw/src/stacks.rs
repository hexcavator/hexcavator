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
    /// the event, and whether it took any thread's stack.
    matched: FxHashMap<(i64, u32), (u64, bool)>,
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
        if let Some(&(id, any)) = self.matched.get(&key) {
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
        self.matched.insert(key, (found, any));
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

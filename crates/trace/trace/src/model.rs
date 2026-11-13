//! The trace model: what happened, independent of the format it was
//! recorded in.
//!
//! Processes, threads and images are rows with lifetimes; their IDs are
//! reused by the OS, so the model refers to them by row index ([`ProcessIx`],
//! [`ThreadIx`], [`ImageIx`]). High-volume events (samples, context switches,
//! ready threads) are columns: one vector per field, in time order, so that
//! queries scan only what they read.

use crate::stacks::{StackId, StackStore};

macro_rules! index {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u32);

        impl $name {
            /// No row.
            pub const NONE: $name = $name(u32::MAX);

            /// Whether this names a row.
            pub fn is_some(self) -> bool {
                self != Self::NONE
            }

            /// The row's index.
            pub fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

index!(
    /// A row of [`Trace::processes`].
    ProcessIx
);
index!(
    /// A row of [`Trace::threads`].
    ThreadIx
);
index!(
    /// A row of [`Trace::images`].
    ImageIx
);
index!(
    /// A row of [`ReadyThreads`].
    ReadyIx
);

/// How timestamps count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    /// Clock ticks per second.
    pub ticks_per_second: u64,
    /// The timestamp of the trace's first event.
    pub origin: i64,
}

impl Clock {
    /// Nanoseconds from the trace's start to `t`.
    pub fn nanos(&self, t: i64) -> i64 {
        let ticks = i128::from(t) - i128::from(self.origin);
        let ns = ticks * 1_000_000_000 / i128::from(self.ticks_per_second.max(1));
        i64::try_from(ns).unwrap_or(if ns < 0 { i64::MIN } else { i64::MAX })
    }
}

/// A process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Process {
    /// The OS's ID for it.
    pub pid: u32,
    /// The parent's ID.
    pub parent_pid: u32,
    /// A key that tells apart processes with the same ID (on Windows, the
    /// kernel's address of the process object).
    pub unique_key: u64,
    /// The image name.
    pub name: String,
    /// The command line.
    pub command_line: String,
    /// When it started, if during the trace.
    pub start: Option<i64>,
    /// When it ended, if during the trace.
    pub end: Option<i64>,
    /// The exit status, if it ended.
    pub exit_status: Option<i32>,
}

/// A thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    /// The OS's ID for it.
    pub tid: u32,
    /// Its process.
    pub process: ProcessIx,
    /// Its name, if it was given one.
    pub name: Option<String>,
    /// Its start address.
    pub start_address: u64,
    /// When it started, if during the trace.
    pub start: Option<i64>,
    /// When it ended, if during the trace.
    pub end: Option<i64>,
}

/// The debug information an image was built with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugId {
    /// The PDB's GUID, or an ELF build ID's first 16 bytes.
    pub guid: [u8; 16],
    /// The PDB's age.
    pub age: u32,
    /// The PDB's path when the image was built.
    pub pdb_path: String,
}

/// An image (executable or library) mapped into a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// The process, or [`ProcessIx::NONE`] for kernel-mode images, which
    /// every process shares.
    pub process: ProcessIx,
    /// Where it's mapped.
    pub base: u64,
    /// Its size in memory.
    pub size: u64,
    /// Its path.
    pub path: String,
    /// The PE timestamp.
    pub time_date_stamp: u32,
    /// The PE checksum.
    pub checksum: u32,
    /// Its debug information's identity, when the trace has it.
    pub debug_id: Option<DebugId>,
    /// When it was loaded, if during the trace.
    pub load: Option<i64>,
    /// When it was unloaded, if during the trace.
    pub unload: Option<i64>,
}

impl Image {
    /// Whether `address` is in the image.
    pub fn contains(&self, address: u64) -> bool {
        address.wrapping_sub(self.base) < self.size
    }

    /// The file name: the path after its last separator.
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['\\', '/']).next().unwrap_or(&self.path)
    }
}

/// CPU samples, in time order.
#[derive(Clone, Debug, Default)]
pub struct Samples {
    /// When.
    pub time: Vec<i64>,
    /// On which processor.
    pub cpu: Vec<u16>,
    /// Which thread was running.
    pub thread: Vec<ThreadIx>,
    /// The instruction pointer.
    pub ip: Vec<u64>,
    /// The stack (empty when none was recorded).
    pub stack: Vec<StackId>,
    /// How many samples each stands for.
    pub weight: Vec<u16>,
}

impl Samples {
    /// The number of samples.
    pub fn len(&self) -> usize {
        self.time.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.time.is_empty()
    }
}

/// Context switches, in time order.
#[derive(Clone, Debug, Default)]
pub struct ContextSwitches {
    /// When.
    pub time: Vec<i64>,
    /// On which processor.
    pub cpu: Vec<u16>,
    /// The thread switched in.
    pub new_thread: Vec<ThreadIx>,
    /// The thread switched out.
    pub old_thread: Vec<ThreadIx>,
    /// The new thread's priority.
    pub new_priority: Vec<i8>,
    /// The old thread's priority.
    pub old_priority: Vec<i8>,
    /// Why the old thread waits (`KWAIT_REASON` on Windows).
    pub wait_reason: Vec<i8>,
    /// The old thread's state (`KTHREAD_STATE` on Windows).
    pub old_state: Vec<i8>,
    /// The new thread's stack when it was switched in: where it waited.
    pub stack: Vec<StackId>,
    /// The event that made the new thread ready, if the trace has it.
    pub ready: Vec<ReadyIx>,
}

impl ContextSwitches {
    /// The number of switches.
    pub fn len(&self) -> usize {
        self.time.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.time.is_empty()
    }
}

/// Threads made ready to run, in time order.
#[derive(Clone, Debug, Default)]
pub struct ReadyThreads {
    /// When.
    pub time: Vec<i64>,
    /// On which processor.
    pub cpu: Vec<u16>,
    /// The thread made ready.
    pub thread: Vec<ThreadIx>,
    /// The thread that made it ready (running on `cpu`), if known.
    pub readier: Vec<ThreadIx>,
    /// The readier's stack: why it readied the thread.
    pub stack: Vec<StackId>,
}

impl ReadyThreads {
    /// The number of events.
    pub fn len(&self) -> usize {
        self.time.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.time.is_empty()
    }
}

/// A trace.
#[derive(Clone, Debug)]
pub struct Trace {
    /// The clock.
    pub clock: Clock,
    /// The number of processors.
    pub processors: u32,
    /// The CPU sampling interval in nanoseconds, if the trace says.
    pub sample_interval: Option<u64>,
    /// Processes, in the order they appeared.
    pub processes: Vec<Process>,
    /// Threads, in the order they appeared.
    pub threads: Vec<Thread>,
    /// Images, in the order they appeared.
    pub images: Vec<Image>,
    /// CPU samples.
    pub samples: Samples,
    /// Context switches.
    pub switches: ContextSwitches,
    /// Ready-thread events.
    pub readies: ReadyThreads,
    /// Every stack.
    pub stacks: StackStore,
}

impl Trace {
    /// An empty trace with `clock`.
    pub fn new(clock: Clock, processors: u32) -> Self {
        Self {
            clock,
            processors,
            sample_interval: None,
            processes: Vec::new(),
            threads: Vec::new(),
            images: Vec::new(),
            samples: Samples::default(),
            switches: ContextSwitches::default(),
            readies: ReadyThreads::default(),
            stacks: StackStore::new(),
        }
    }

    /// The CPU sampling interval in nanoseconds: the trace's, or 1 ms.
    pub fn sample_interval_ns(&self) -> u64 {
        self.sample_interval.filter(|&i| i > 0).unwrap_or(1_000_000)
    }

    /// The process of a thread.
    pub fn thread_process(&self, thread: ThreadIx) -> ProcessIx {
        if thread.is_some() {
            self.threads[thread.index()].process
        } else {
            ProcessIx::NONE
        }
    }
}

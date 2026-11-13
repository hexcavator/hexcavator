//! A platform-neutral model of performance traces.
//!
//! [`Trace`] holds what a trace recorded: processes, threads and images with
//! their lifetimes; CPU samples, context switches and ready-thread events as
//! columns; and every stack, interned in a [`StackStore`]. Importers build
//! it from each recording format: [`etw::import`] from Windows ETL files.
//! [`index`] saves one, so reopening a trace skips the import.

pub mod etw;
pub mod index;
pub mod model;
pub mod stacks;

pub use model::{
    Clock, ContextSwitches, DebugId, Image, ImageIx, Process, ProcessIx, ReadyIx, ReadyThreads,
    Samples, Thread, ThreadIx, Trace,
};
pub use stacks::{PathCache, StackId, StackStore};

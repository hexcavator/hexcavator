//! Decoders for the events in Windows traces.
//!
//! [`hexcavator_etl`] reads an ETL file's events; this crate reads their
//! payloads:
//!
//! - [`kernel::decode`]: typed decoders for the events trace analysis is
//!   built on (processes, threads, images, CPU samples, context switches,
//!   ready threads, stacks, image identities);
//! - [`schema`]: the layouts of the kernel's classic events and of the
//!   trace-control events, for any event, by name;
//! - [`stacks`]: which event each stack belongs to.
//!
//! The layouts are those TDH reports for the kernel's MOF classes, and the
//! tests check them against TDH on real traces (see `tools/etwdump`).

pub mod guids;
pub mod kernel;
pub mod manifest;
pub mod schema;
pub mod stacks;

pub use kernel::{KernelEvent, decode};
pub use schema::{Properties, Property, Schema};

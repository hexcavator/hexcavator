//! Queries over traces.
//!
//! The central view is the stack tree ([`Tree`]), as in WPA: grouping
//! columns (process, thread, processor) above call stacks, expanded on
//! demand, with inclusive and exclusive weights; inverted (callers); or
//! focused on one function's callers or callees. Its data comes from
//! [`sources`]: CPU samples, or context switches weighted by running or
//! waiting time.
//!
//! Frames become tree keys through [`keys::Framer`]: by function (with a
//! [`Symbolizer`]), by image, or by address.

pub mod keys;
pub mod pdb;
pub mod shape;
pub mod sources;
pub mod tree;
pub mod xml;

pub use keys::{FrameMode, Framer, Key, KeyId, Keys, NoSymbols, Resolver, Symbolizer, label};
pub use pdb::PdbSymbolizer;
pub use shape::{Folds, Glob, StackTags};
pub use sources::{Filter, GroupBy, Precise, SwitchWeight};
pub use tree::{Instances, NodeId, Tree};

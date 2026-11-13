//! CodeView: Microsoft's debug record formats, as cvinfo.h defines them.
//!
//! - [`symbols`]: symbol records (`S_*`): procedures, data, frames, inline
//!   sites, ...;
//! - [`types`]: type records (leaves, `LF_*`), type indexes and the
//!   built-in (simple) types, and a formatter that prints C++-style names;
//! - [`lines`]: C13 subsections (`DEBUG_S_*`): line numbers and file
//!   checksums;
//! - [`annotations`]: inline sites' binary annotations;
//! - [`registers`]: register numbers (`CV_REG_*`, `CV_AMD64_*`, ...);
//! - [`layout`]: where each part of a class or structure lies.
//!
//! The records live in containers: a PDB's streams (`hexcavator-pdb`), or a
//! COFF object's `.debug$S` and `.debug$T` sections. Type records refer to
//! each other by index; a container supplies them through [`TypeSource`].

// CodeView sizes and offsets are 32-bit, so positions within a record or
// stream fit in u32.
#![allow(clippy::cast_possible_truncation)]

pub mod annotations;
pub mod layout;
pub mod lines;
pub mod registers;
pub mod symbols;
pub mod types;

pub use symbols::{Symbol, SymbolIter, SymbolRecord};
pub use types::{TypeFormatter, TypeIndex, TypeRecord, TypeSource};

//! Byte-level primitives shared by every Hexcavator crate.
//!
//! Everything here is host-independent: on-disk integers carry an explicit
//! byte order, on-disk structures have alignment 1 so they can be overlaid at
//! any offset, and target-derived offsets and sizes are `u64` until they are
//! checked against the host buffer.

#![no_std]
#![warn(missing_docs)]
// The only unsafe code in this crate is the `Pod` reinterpretation in
// `pod.rs`.
#![allow(unsafe_code)]

extern crate alloc;

mod addr;
mod arch;
mod endian;
mod error;
mod pod;
mod reader;
pub mod stack;

pub use addr::{FileOffset, Rva, Va};
pub use arch::Arch;
pub use endian::{
    Endian, I16Be, I16E, I16Le, I32Be, I32E, I32Le, I64Be, I64E, I64Le, U16Be, U16E, U16Le, U32Be,
    U32E, U32Le, U64Be, U64E, U64Le,
};
pub use error::{Error, ErrorKind, Result};
pub use pod::{Pod, as_bytes, from_bytes, slice_from_bytes};
pub use reader::{Reader, bytes_at, cstr_at, read_at, read_slice_at, to_usize};

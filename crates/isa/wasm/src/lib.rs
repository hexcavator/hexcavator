//! The WebAssembly instruction set: [`code`] decodes a function body's
//! instructions and their immediates, and [`ops`] lists every instruction
//! (through GC, threads and relaxed SIMD).
//!
//! Finding the function bodies in a module is `hexcavator-wasm`'s job.
//! Malformed code gives errors, never a panic.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod code;
pub mod ops;

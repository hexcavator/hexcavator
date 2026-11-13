//! An x86 and x86-64 instruction decoder.
//!
//! [`decode`] turns bytes into an [`Instruction`]: a compact, `Copy` value
//! holding the mnemonic, up to five [`Operand`]s, and the prefixes and
//! EVEX decorations that matter. Nothing is allocated, and an instruction
//! refers to nothing outside itself, so callers can decode on demand and
//! discard the results.
//!
//! The opcode tables live in `tables/*.txt`, in a compact notation based on
//! the Intel SDM's opcode maps; `build.rs` compiles them.
//!
//! [`format`] renders instructions in the MASM-style syntax of Microsoft's
//! `dumpbin /disasm`.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod decode;
pub mod format;
mod instruction;
mod operand;
mod register;
#[allow(dead_code)]
mod spec;

#[allow(clippy::all)]
mod tables {
    use crate::spec::{Entry, Loc, OpSpec, Size, Tuple, attr};
    include!(concat!(env!("OUT_DIR"), "/tables.rs"));

    impl Mnemonic {
        /// The mnemonic's name, in lowercase.
        pub fn name(self) -> &'static str {
            MNEMONIC_NAMES[self as usize]
        }
    }
}

pub use decode::{DecodeError, MAX_LENGTH, Mode, decode};
pub use instruction::{Encoding, Flow, Instruction, Rounding, prefix};
pub use operand::{Immediate, MemSize, Memory, Operand};
pub use register::{RegClass, Register};
pub use tables::Mnemonic;

//! Demangling: Microsoft C++ names ([`msvc`]), the Itanium C++ ABI's
//! ([`itanium`], whose demangler also takes Rust and Swift names), Rust's
//! v0 and legacy manglings ([`rust`]), and Swift's ([`swift`]).

#![no_std]

extern crate alloc;

pub mod itanium;
pub mod msvc;
pub mod rust;
pub mod swift;

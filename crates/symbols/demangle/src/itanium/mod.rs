// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Follows the LLVM Project's demangler (see LICENSE-LLVM at the crate root).

//! Itanium C++ ABI demangling (the mangling of GCC, Clang, and every
//! non-Microsoft C++ toolchain: `_ZN3foo3barEv`).
//!
//! [`Demangler::parse`] builds an [`Ast`] of a mangled name; printing it
//! gives exactly what LLVM's `llvm::itaniumDemangle` (and so `llvm-cxxfilt`
//! and libc++abi's `__cxa_demangle`) gives, which the tests check against
//! libc++abi's test cases. The grammar and printing rules follow LLVM's
//! `ItaniumDemangle.h` (part of the LLVM Project, under the Apache License
//! v2.0 with LLVM Exceptions; see `LICENSE-LLVM` at the crate root);
//! the code is our own, with bounded recursion and output for hostile
//! names.
//!
//! The one deliberate difference: `long double` literals are read as x87
//! 80-bit values (as on x86 Linux) whatever the host, and floating literals
//! print in normalized `%a` form (`0x1.4p+2`), which libc++abi's tests
//! accept among the forms C libraries print.

mod ast;
mod parse;
mod print;

use alloc::string::String;
use alloc::vec::Vec;

pub use ast::{Ast, Node, NodeId};

/// Demangles names, reusing its buffers from one name to the next.
#[derive(Default)]
pub struct Demangler {
    buffers: Option<parse::Buffers>,
    out: Vec<u8>,
    swift: crate::swift::Demangler,
}

/// Whether `name` looks like an Itanium-mangled name (`_Z...`, or with the
/// extra underscores of Mach-O and blocks).
pub fn is_mangled(name: &str) -> bool {
    let b = name.as_bytes();
    let b = b.strip_prefix(b"__alloc_token_").unwrap_or(b);
    b.starts_with(b"_Z")
        || b.starts_with(b"__Z")
        || b.starts_with(b"___Z")
        || b.starts_with(b"____Z")
}

impl Demangler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses `name`, or returns `None` if it is not a mangled name (or is
    /// malformed). Give the tree back with [`Demangler::recycle`] to reuse
    /// its memory.
    pub fn parse<'a>(&mut self, name: &'a str) -> Option<Ast<'a>> {
        self.parse_with_native_depth(name, parse::NATIVE_DEPTH)
    }

    /// [`Demangler::parse`], recursing at most `levels` levels on the
    /// thread's stack (for testing the parser's handling of deeper names:
    /// the tree is the same, whatever the levels).
    #[doc(hidden)]
    pub fn parse_with_native_depth<'a>(&mut self, name: &'a str, levels: u32) -> Option<Ast<'a>> {
        let mut p = parse::Parser::new(name.as_bytes(), self.buffers.take().unwrap_or_default());
        if levels != parse::NATIVE_DEPTH {
            p.set_native_depth(levels);
        }
        let root = p.parse();
        let (mut ast, rest) = p.finish();
        match root {
            Some(r) => {
                ast.root = Some(r);
                self.buffers = Some(rest);
                Some(ast)
            }
            None => {
                self.buffers = Some(parse::Parser::buffers_of(ast, rest));
                None
            }
        }
    }

    /// Takes back a tree's memory for the next parse.
    pub fn recycle(&mut self, ast: Ast<'_>) {
        let rest = self.buffers.take().unwrap_or_default();
        self.buffers = Some(parse::Parser::buffers_of(ast, rest));
    }

    /// Appends the demangled form of `name` to `out`; returns `false`
    /// (appending nothing) if it is not a mangled name.
    pub fn demangle_into(&mut self, name: &str, out: &mut String) -> bool {
        if name.is_empty() {
            return false;
        }
        // Rust's manglings (legacy ones look like Itanium's), and Swift's.
        if crate::rust::demangle_into(name, out) || self.swift.demangle_into(name, out) {
            return true;
        }
        let Some(ast) = self.parse(name) else {
            return false;
        };
        let ok = self.print_into(&ast, out);
        self.recycle(ast);
        ok
    }

    /// Demangles `name`, or returns `None` if it is not a mangled name.
    pub fn demangle(&mut self, name: &str) -> Option<String> {
        let mut out = String::new();
        self.demangle_into(name, &mut out).then_some(out)
    }

    /// Prints a tree (from [`Demangler::parse`]) as C++.
    pub fn print_into(&mut self, ast: &Ast<'_>, out: &mut String) -> bool {
        let Some(root) = ast.root else {
            return false;
        };
        let mut buf = core::mem::take(&mut self.out);
        buf.clear();
        let mut p = print::Printer::new(ast, buf);
        p.print_all(root);
        let ok = !p.failed;
        if ok {
            out.push_str(&String::from_utf8_lossy(&p.out));
        }
        self.out = p.out;
        ok
    }

    /// The tree printed in full (or `short`), recursing at most `levels`
    /// levels on the thread's stack (for testing the printer's handling
    /// of deeper trees: the text is the same, whatever the levels).
    #[doc(hidden)]
    pub fn print_with_native_depth(
        &mut self,
        ast: &Ast<'_>,
        levels: u32,
        short: bool,
    ) -> Option<String> {
        let root = ast.root?;
        let mut p = print::Printer::new(ast, Vec::new());
        p.set_native_depth(levels);
        if short {
            p.short_all(root);
        } else {
            p.print_all(root);
        }
        (!p.failed).then(|| String::from_utf8_lossy(&p.out).into_owned())
    }
}

impl Demangler {
    /// Appends the short form of `name` to `out` (see [`demangle_short`]);
    /// returns `false` if it is not a mangled name.
    pub fn demangle_short_into(&mut self, name: &str, out: &mut String) -> bool {
        if name.is_empty() {
            return false;
        }
        // Rust names have one form: the generic arguments are what tell
        // instantiations apart, which a size report wants.
        if crate::rust::demangle_into(name, out) || self.swift.demangle_short_into(name, out) {
            return true;
        }
        let Some(ast) = self.parse(name) else {
            return false;
        };
        let ok = match ast.root {
            Some(root) => {
                let mut buf = core::mem::take(&mut self.out);
                buf.clear();
                let mut p = print::Printer::new(&ast, buf);
                p.short_all(root);
                let ok = !p.failed;
                if ok {
                    out.push_str(&String::from_utf8_lossy(&p.out));
                }
                self.out = p.out;
                ok
            }
            None => false,
        };
        self.recycle(ast);
        ok
    }

    pub fn demangle_short(&mut self, name: &str) -> Option<String> {
        let mut out = String::new();
        self.demangle_short_into(name, &mut out).then_some(out)
    }
}

/// The short form of a mangled name, as abseil's demangler (bloaty's
/// `shortsymbols`) gives it: `foo::bar<>()` for
/// `foo::bar<int>(int, char const*)`.
pub fn demangle_short(name: &str) -> Option<String> {
    Demangler::new().demangle_short(name)
}

/// Demangles `name` (with a fresh [`Demangler`]; keep one to demangle many
/// names quickly).
pub fn demangle(name: &str) -> Option<String> {
    Demangler::new().demangle(name)
}

#[cfg(test)]
mod tests;

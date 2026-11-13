// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Follows the Swift project's demangler (see LICENSE-SWIFT at the crate root).

//! Swift symbol demangling: the current mangling (`$s`, and `$S`, `_T0`,
//! `$e`, `@__swiftmacro_`) and the old one (`_T`).
//!
//! A translation of the Swift project's `lib/Demangling` (Apache License
//! v2.0 with Runtime Library Exception; see the crate's `LICENSE-SWIFT`):
//! the demangler builds Swift's node tree, and the printer renders it as
//! `swift-demangle` does, which the tests check against.
//!
//! Bounded like the other demanglers: the tree ([`node::MAX_NODES`]), the
//! demangler's and printer's recursion, and the output.

// The translation keeps C++'s narrowing conversions where Swift's output
// depends on them (an index printed as an `int`, say).
#![allow(clippy::cast_possible_truncation)]

mod demangler;
pub mod kinds;
pub mod node;
mod old;
pub mod print;
mod punycode;

pub use demangler::{is_swift_symbol, mangling_prefix_length};
pub use kinds::Kind;
pub use node::{NodeId, Tree};
pub use print::Options;

use alloc::string::String;

/// Demangles `name` into `tree` (cleared first): Swift's
/// `Context::demangleSymbolAsNode`. Returns the root (a `Global`), or
/// `None` if `name` doesn't demangle.
pub fn demangle_symbol_as_node(tree: &mut Tree, name: &str) -> Option<NodeId> {
    tree.clear();
    let bytes = name.as_bytes();
    if demangler::mangling_prefix_length(bytes) != 0
        || demangler::async_main_entry_point_name_length(bytes) != 0
    {
        let mut d = demangler::Demangler::new(tree, bytes);
        return d.demangle_symbol();
    }
    old::demangle_old_symbol_as_node(tree, bytes)
}

/// Demangles a type's mangling (without a prefix: `SaySiG`) into `tree`
/// (cleared first): Swift's `Context::demangleTypeAsNode`.
pub fn demangle_type_as_node(tree: &mut Tree, name: &str) -> Option<NodeId> {
    tree.clear();
    demangler::Demangler::new(tree, name.as_bytes()).demangle_type()
}

/// Demangles `name` and prints it with `options`: Swift's
/// `Context::demangleSymbolAsString`. Gives `name` itself if it doesn't
/// demangle (or prints as nothing), as Swift does.
pub fn demangle_symbol_as_string(name: &str, options: Options) -> String {
    demangle_symbol_as_string_nested(name, options, 0, print::NATIVE_DEPTH)
}

pub(crate) fn demangle_symbol_as_string_nested(
    name: &str,
    options: Options,
    nesting: u32,
    levels: u32,
) -> String {
    let mut tree = Tree::default();
    let Some(root) = demangle_symbol_as_node(&mut tree, name) else {
        return String::from(name);
    };
    let mut printer = print::Printer::new(&tree, options);
    printer.nesting = nesting;
    printer.set_native_depth(levels);
    let s = printer.print_root(root);
    if s.is_empty() { String::from(name) } else { s }
}

/// Demangles Swift names, reusing its memory from one name to the next.
#[derive(Default)]
pub struct Demangler {
    tree: Tree,
}

impl Demangler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `name` demangled as `swift-demangle` prints it to `out`;
    /// returns `false` (appending nothing) if it is not a Swift name. As
    /// `swift-demangle` does, one `_` of a leading `__` (Mach-O's) goes.
    pub fn demangle_into(&mut self, name: &str, out: &mut String) -> bool {
        self.demangle_with(name, Options::swift_demangle(), out)
    }

    /// Appends the short form of `name` (`swift-demangle -simplified`'s:
    /// no modules, argument types, or specialization details) to `out`.
    pub fn demangle_short_into(&mut self, name: &str, out: &mut String) -> bool {
        self.demangle_with(name, Options::simplified(), out)
    }

    /// Appends `name` demangled and printed with `options` to `out`.
    pub fn demangle_with(&mut self, name: &str, options: Options, out: &mut String) -> bool {
        let name = if name.starts_with("__") {
            &name[1..]
        } else {
            name
        };
        if !is_swift_symbol(name.as_bytes()) {
            return false;
        }
        let Some(root) = demangle_symbol_as_node(&mut self.tree, name) else {
            return false;
        };
        let s = print::Printer::new(&self.tree, options).print_root(root);
        if s.is_empty() {
            return false;
        }
        out.push_str(&s);
        true
    }

    /// [`Demangler::demangle_with`], the printer recursing at most `levels`
    /// levels on the thread's stack (for testing its handling of deeper
    /// trees: the output is the same, whatever the levels).
    #[doc(hidden)]
    pub fn demangle_with_native_depth(
        &mut self,
        name: &str,
        options: Options,
        levels: u32,
        out: &mut String,
    ) -> bool {
        let name = name
            .strip_prefix('_')
            .filter(|n| n.starts_with('_'))
            .unwrap_or(name);
        if !is_swift_symbol(name.as_bytes()) {
            return false;
        }
        let Some(root) = demangle_symbol_as_node(&mut self.tree, name) else {
            return false;
        };
        let mut p = print::Printer::new(&self.tree, options);
        p.set_native_depth(levels);
        let s = p.print_root(root);
        out.push_str(&s);
        !s.is_empty()
    }
}

/// Demangles `name` as `swift-demangle` does, or returns `None` if it is
/// not a Swift name.
pub fn demangle(name: &str) -> Option<String> {
    let mut out = String::new();
    Demangler::new()
        .demangle_into(name, &mut out)
        .then_some(out)
}

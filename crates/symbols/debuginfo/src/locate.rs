//! What code is at an address: its function, the functions inlined there,
//! and the source line of each ([`Locator`]).
//!
//! A lookup reads only what holds the address: a PDB's module (found by the
//! section contributions), or a DWARF compile unit (found by its ranges).
//! What it reads of each is kept for the next lookup, so many addresses in
//! one module or unit cost about one read of it.

use crate::{DebugInfo, dwarf_backend, pdb_locate};

/// One function the code at an address is part of: the function itself,
/// or a copy of a function inlined there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    /// Its qualified name (`ns::Class::function`), or, for a frame from a
    /// public symbol only, its name as linked (see `decorated`). Empty if
    /// unknown.
    pub function: String,
    /// Whether `function` is a linker (decorated, mangled) name.
    pub decorated: bool,
    /// The address its code starts at: for the outermost frame (the
    /// function, not an inlined copy), its first address.
    pub start: Option<u64>,
    /// The source file of the address's code in this frame: where it is,
    /// for the innermost frame; where the call inlined into it is, for the
    /// others.
    pub file: Option<String>,
    /// The line in `file` (0: unknown).
    pub line: u32,
    /// Whether this is an inlined copy of a function.
    pub inlined: bool,
}

/// Finds the frames at addresses, keeping what it reads (see the module's
/// documentation).
pub struct Locator<'a, 'data> {
    inner: Inner<'a, 'data>,
}

enum Inner<'a, 'data> {
    Pdb(pdb_locate::PdbLocator<'a, 'data>),
    Dwarf(dwarf_backend::frames::DwarfLocator<'a, 'data>),
}

impl<'a, 'data> Locator<'a, 'data> {
    pub(crate) fn new(debug: &'a DebugInfo<'data>) -> Self {
        let inner = match debug {
            DebugInfo::Pdb(p) => Inner::Pdb(pdb_locate::PdbLocator::new(p)),
            DebugInfo::Dwarf(d) => Inner::Dwarf(dwarf_backend::frames::DwarfLocator::new(d)),
        };
        Self { inner }
    }

    /// The frames of the code at `addr` (in the debug information's
    /// addresses: see the crate's documentation), innermost first: the
    /// functions inlined there, deepest first, then the function. Empty if
    /// no function or symbol is there.
    pub fn frames(&mut self, addr: u64) -> Vec<Frame> {
        match &mut self.inner {
            Inner::Pdb(p) => p.frames(addr),
            Inner::Dwarf(d) => d.frames(addr),
        }
    }
}

/// How many inline frames an address has at most: deeper chains (a
/// hostile file's) are cut to their innermost.
pub(crate) const MAX_FRAMES: usize = 256;

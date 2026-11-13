//! The debug map: what a linker leaves in an image whose DWARF stays in
//! its object files (no dSYM made): debugger (STABS) entries naming each
//! object (`N_OSO`) and, for each, its functions' and variables' addresses
//! in the image, by name. A debugger (or `dsymutil`) reads the objects'
//! DWARF, moving each address from the object's place to the image's.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::MachO;
use crate::consts::{N_FUN, N_GSYM, N_LCSYM, N_OSO, N_SO, N_STSYM};

/// An object file the debug map names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugMapObject<'d> {
    /// Its path, as the linker wrote it: absolute, relative to where it
    /// ran (or to `-oso_prefix`), or `library.a(member.o)`.
    pub path: &'d [u8],
    /// Its modification time when linked (seconds since 1970; 0 if not
    /// given).
    pub mtime: u64,
    /// Its functions and variables, as the image has them.
    pub symbols: Vec<DebugMapSymbol<'d>>,
}

/// A function or variable of an object file, in the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugMapSymbol<'d> {
    /// Its (mangled) name.
    pub name: &'d [u8],
    /// Its address in the image.
    pub addr: u64,
    /// Its size, for a function.
    pub size: Option<u64>,
}

impl<'d> MachO<'d> {
    /// The debug map's objects, in order (empty if there is none: a
    /// stripped image, say, or one with a dSYM's worth of DWARF of its
    /// own). Globals the map gives no address (ld64 writes 0) have the
    /// symbol table's.
    pub fn debug_map(&self) -> Vec<DebugMapObject<'d>> {
        let symbols = self.symbols();
        let mut out: Vec<DebugMapObject<'d>> = Vec::new();
        let mut current: Option<DebugMapObject<'d>> = None;
        // A function's entry waits for the nameless one with its size.
        let mut function: Option<usize> = None;
        let mut globals: Option<BTreeMap<&'d [u8], u64>> = None;
        for s in &symbols {
            if !s.is_stab() {
                continue;
            }
            match s.n_type {
                N_OSO => {
                    out.extend(current.take());
                    current = Some(DebugMapObject {
                        path: s.name,
                        mtime: s.n_value,
                        symbols: Vec::new(),
                    });
                    function = None;
                }
                N_SO if s.name.is_empty() => {
                    out.extend(current.take());
                    function = None;
                }
                N_FUN => {
                    let Some(o) = current.as_mut() else { continue };
                    if s.name.is_empty() {
                        if let Some(f) = function.take().and_then(|i| o.symbols.get_mut(i)) {
                            f.size = Some(s.n_value);
                        }
                    } else {
                        function = Some(o.symbols.len());
                        o.symbols.push(DebugMapSymbol {
                            name: s.name,
                            addr: s.n_value,
                            size: None,
                        });
                    }
                }
                N_STSYM | N_LCSYM | N_GSYM => {
                    let Some(o) = current.as_mut() else { continue };
                    if s.name.is_empty() {
                        continue;
                    }
                    let mut addr = s.n_value;
                    if addr == 0 && s.n_type == N_GSYM {
                        let g = globals.get_or_insert_with(|| {
                            symbols
                                .iter()
                                .filter(|s| s.is_section_defined())
                                .map(|s| (s.name, s.n_value))
                                .collect()
                        });
                        match g.get(s.name) {
                            Some(&a) => addr = a,
                            None => continue,
                        }
                    }
                    o.symbols.push(DebugMapSymbol {
                        name: s.name,
                        addr,
                        size: None,
                    });
                }
                _ => {}
            }
        }
        out.extend(current);
        out
    }
}

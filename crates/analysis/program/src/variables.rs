//! A function's parameters and locals, with where each lives over which
//! addresses (registers named for the architecture), and the fields that
//! make sense of the memory around them: a structure's members, for its
//! fields in registers and its bytes on the stack, and a pointer's target's
//! members, for memory reached through it.

use hexcavator_codeview::registers;
use hexcavator_core::Arch;
use hexcavator_debuginfo::layout::{self, FlatField};
use hexcavator_debuginfo::{Place, TypeRef};

use crate::Program;

/// Where a variable lives, its registers named.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Where {
    /// In a register.
    Register(String),
    /// In memory, at an offset from a register.
    Memory {
        /// The register (or `cfa`, the canonical frame address).
        base: String,
        /// The offset from it.
        offset: i32,
    },
    /// A field (at `field` bytes into the variable) in a register.
    Field {
        /// The register.
        register: String,
        /// The field's offset in the variable.
        field: u32,
    },
}

/// A variable's place over a range of addresses (virtual, at the image's
/// preferred base), but for its gaps (address, length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// The first address it holds at.
    pub start: u64,
    /// The address it stops holding at (exclusive).
    pub end: u64,
    /// Ranges within that it doesn't hold over: (address, length).
    pub gaps: Vec<(u64, u64)>,
    /// Where the variable is.
    pub place: Where,
}

/// A parameter or local.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable {
    /// Its name.
    pub name: String,
    /// Its type's name, as C++.
    pub type_name: String,
    /// Its type's size.
    pub size: u64,
    /// Whether it is a parameter (else a local).
    pub param: bool,
    /// Declared in a function inlined here.
    pub inlined: bool,
    /// Its fields, if it is a structure.
    pub fields: Vec<FlatField>,
    /// Its target's fields, if it is a pointer to a structure.
    pub pointee: Vec<FlatField>,
    /// Where it lives, over which addresses.
    pub locations: Vec<Location>,
}

impl Program<'_> {
    /// The parameters and locals of the function at `rva` (in `compiland`,
    /// if known), for code of `arch`.
    pub fn variables(&self, compiland: Option<u32>, rva: u64, arch: Arch) -> Vec<Variable> {
        let Ok(Some(vars)) = self.debug.variables(compiland, rva) else {
            return Vec::new();
        };
        let base = self.image.image_base();
        let reg = |n: u16| {
            self.debug
                .register_name(arch, n)
                .unwrap_or_else(|| format!("reg{n}"))
        };
        vars.variables
            .iter()
            .map(|v| {
                let ty = TypeRef(v.type_index);
                let d = &self.debug;
                let pointee = layout::pointer_target(d, ty)
                    .map(|p| layout::flat_fields(d, p))
                    .unwrap_or_default();
                let (type_name, size, fields) = (
                    d.type_name(ty),
                    d.type_size(ty).unwrap_or(0),
                    layout::flat_fields(d, ty),
                );
                let frame = if v.param { vars.frame.1 } else { vars.frame.0 };
                let locations = v
                    .ranges
                    .iter()
                    .filter_map(|r| {
                        let place = match r.place {
                            Place::Register(n) => Where::Register(reg(n)),
                            Place::Relative { register, offset } => Where::Memory {
                                base: reg(register),
                                offset,
                            },
                            Place::Frame { offset, .. } => Where::Memory {
                                base: registers::frame_pointer(arch, frame)?.to_string(),
                                offset,
                            },
                            Place::Field { register, field } => Where::Field {
                                register: reg(register),
                                field,
                            },
                            Place::Cfa { offset } => Where::Memory {
                                base: "cfa".to_string(),
                                offset,
                            },
                            // (Places other debug formats will add.)
                            _ => return None,
                        };
                        Some(Location {
                            start: base + r.start,
                            end: base + r.end,
                            gaps: r.gaps.iter().map(|&(at, n)| (base + at, n)).collect(),
                            place,
                        })
                    })
                    .collect();
                Variable {
                    name: v.name.clone(),
                    type_name,
                    size,
                    param: v.param,
                    inlined: v.inlined,
                    fields,
                    pointee,
                    locations,
                }
            })
            .collect()
    }
}

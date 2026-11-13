//! Type names and layouts, from DWARF's type DIEs.
//!
//! Names are C++, in the style of the PDB backend's (`const char *`,
//! `int[3]`, `int (int, char)`), but keep typedefs' names (`uint32_t`),
//! which DWARF records and PDB doesn't.
//!
//! Layouts: a structure's bases (an empty one takes no space),
//! members (bitfields by DWARF 4's `DW_AT_data_bit_offset`, or DWARF 2 and
//! 3's `DW_AT_bit_offset` from the storage unit's most significant bit),
//! its vtable pointer (clang's and GCC's artificial `_vptr` member), and
//! its virtual bases, whose offsets are computed at run time and are
//! placed here after the rest of the object, aligned, in order.

use std::collections::HashMap;
use std::collections::HashSet;

use hexcavator_core::Endian;
use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Die, Unit, Value};

use super::{DwarfInfo, VOID, Walk};
use crate::TypeRef;
use crate::layout::{Layout, Part, PartKind, fill};

/// How deep a name is written, and how long it grows.
const MAX_NAME_DEPTH: u32 = 20;
const MAX_NAME_LEN: usize = 4096;
/// How deep empty-base checks go.
const MAX_BASE_DEPTH: u32 = 64;

impl DwarfInfo<'_> {
    /// The type's name, as C++.
    pub fn type_name(&self, ty: TypeRef) -> String {
        let mut out = String::new();
        self.write_name(ty, &mut out, 0);
        out
    }

    fn write_name(&self, ty: TypeRef, out: &mut String, depth: u32) {
        if out.len() > MAX_NAME_LEN || depth > MAX_NAME_DEPTH {
            if !out.ends_with("...") {
                out.push_str("...");
            }
            return;
        }
        if ty == VOID {
            out.push_str("void");
            return;
        }
        let Some((u, a, d)) = self.die(ty) else {
            out.push_str(&format!("<type {:#x}>", ty.0));
            return;
        };
        let target = self.type_of(&u, &d);
        match d.tag {
            DW_TAG_BASE_TYPE | DW_TAG_UNSPECIFIED_TYPE => {
                out.push_str(&Self::string(&u, &d, DW_AT_NAME).unwrap_or_else(|| "void".into()));
            }
            DW_TAG_TYPEDEF
            | DW_TAG_STRUCTURE_TYPE
            | DW_TAG_CLASS_TYPE
            | DW_TAG_UNION_TYPE
            | DW_TAG_INTERFACE_TYPE
            | DW_TAG_ENUMERATION_TYPE => out.push_str(&self.qualified_name(ty)),
            DW_TAG_CONST_TYPE | DW_TAG_VOLATILE_TYPE | DW_TAG_ATOMIC_TYPE => {
                let word = match d.tag {
                    DW_TAG_CONST_TYPE => "const",
                    DW_TAG_VOLATILE_TYPE => "volatile",
                    _ => "_Atomic",
                };
                // A qualified pointer: `T * const`; anything else: `const T`.
                if self.is_pointer(target) {
                    self.write_name(target, out, depth + 1);
                    out.push(' ');
                    out.push_str(word);
                } else {
                    out.push_str(word);
                    out.push(' ');
                    self.write_name(target, out, depth + 1);
                }
            }
            DW_TAG_RESTRICT_TYPE => {
                self.write_name(target, out, depth + 1);
                out.push_str(" __restrict");
            }
            DW_TAG_POINTER_TYPE | DW_TAG_REFERENCE_TYPE | DW_TAG_RVALUE_REFERENCE_TYPE => {
                self.write_name(target, out, depth + 1);
                out.push_str(match d.tag {
                    DW_TAG_POINTER_TYPE => " *",
                    DW_TAG_REFERENCE_TYPE => " &",
                    _ => " &&",
                });
            }
            DW_TAG_PTR_TO_MEMBER_TYPE => {
                self.write_name(target, out, depth + 1);
                out.push(' ');
                if let Some(c) = d
                    .attr(DW_AT_CONTAINING_TYPE)
                    .and_then(|a| self.reference(&u, a))
                {
                    self.write_name(c, out, depth + 1);
                }
                out.push_str("::*");
            }
            DW_TAG_ARRAY_TYPE => {
                self.write_name(target, out, depth + 1);
                let dims: Vec<Die<'_>> = u
                    .children(a, &d)
                    .into_iter()
                    .filter(|c| c.tag == DW_TAG_SUBRANGE_TYPE)
                    .collect();
                if dims.is_empty() {
                    out.push_str("[]");
                }
                for c in dims.iter().take(32) {
                    match Self::uint(&u, c, DW_AT_COUNT).or_else(|| {
                        let upper = Self::uint(&u, c, DW_AT_UPPER_BOUND)?;
                        let lower = Self::uint(&u, c, DW_AT_LOWER_BOUND).unwrap_or(0);
                        upper.checked_sub(lower)?.checked_add(1)
                    }) {
                        Some(n) => out.push_str(&format!("[{n}]")),
                        None => out.push_str("[]"),
                    }
                }
            }
            DW_TAG_SUBROUTINE_TYPE => {
                self.write_name(target, out, depth + 1);
                out.push_str(" (");
                let mut first = true;
                for c in u.children(a, &d) {
                    let arg = match c.tag {
                        DW_TAG_FORMAL_PARAMETER => Some(self.type_of(&u, &c)),
                        DW_TAG_UNSPECIFIED_PARAMETERS => None,
                        _ => continue,
                    };
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    match arg {
                        Some(t) => self.write_name(t, out, depth + 1),
                        None => out.push_str("..."),
                    }
                    if out.len() > MAX_NAME_LEN {
                        break;
                    }
                }
                out.push(')');
            }
            _ => out.push_str(&format!("<tag {:#x}>", d.tag)),
        }
    }

    /// The enumerators of enumeration `ty` (see [`crate::DebugInfo::enumerators`]).
    pub fn enumerators(&self, ty: TypeRef) -> Option<crate::Enumerators> {
        let at = self.through(ty, None);
        let (u, a, d) = self.die(at)?;
        if d.tag != DW_TAG_ENUMERATION_TYPE {
            return None;
        }
        // Signed if its underlying type is (or, with none named, if any
        // enumerator is negative).
        let underlying = self.type_of(&u, &d);
        let signed_type = (underlying != VOID).then(|| {
            matches!(
                self.type_shape(underlying),
                crate::TypeShape::Basic {
                    kind: crate::BasicType::Int | crate::BasicType::Long | crate::BasicType::Char,
                    ..
                }
            )
        });
        let mut any_negative = false;
        let mut values = Vec::new();
        for c in u.children(a, &d) {
            if c.tag != DW_TAG_ENUMERATOR {
                continue;
            }
            let Some(v) = c.attr(DW_AT_CONST_VALUE) else {
                continue;
            };
            let bits = match v.value {
                Value::Sint(n) => {
                    any_negative |= n < 0;
                    n as u64
                }
                _ => u.uint(&v.value).unwrap_or(0),
            };
            values.push((Self::string(&u, &c, DW_AT_NAME).unwrap_or_default(), bits));
        }
        Some(crate::Enumerators {
            signed: signed_type.unwrap_or(any_negative),
            values,
        })
    }

    fn is_pointer(&self, ty: TypeRef) -> bool {
        self.die(ty).is_some_and(|(_, _, d)| {
            matches!(
                d.tag,
                DW_TAG_POINTER_TYPE
                    | DW_TAG_REFERENCE_TYPE
                    | DW_TAG_RVALUE_REFERENCE_TYPE
                    | DW_TAG_PTR_TO_MEMBER_TYPE
            )
        })
    }

    /// Where a member or base lies in its object: `DW_AT_data_member_location`
    /// as a constant, or as an expression that adds one.
    fn member_offset(u: &Unit<'_>, d: &Die<'_>) -> Option<u64> {
        let a = d.attr(DW_AT_DATA_MEMBER_LOCATION)?;
        if let Value::Block(b) = a.value {
            let mut r = hexcavator_dwarf::Reader::new(b, 1, u.sections().endian);
            return match *b.first()? {
                DW_OP_PLUS_UCONST => r.uleb().filter(|_| r.is_empty()),
                DW_OP_CONSTU => r.uleb().filter(|_| r.is_empty()),
                _ => None,
            };
        }
        u.uint(&a.value)
    }

    /// Whether a class has no data: no members, vtable pointer, or virtual
    /// bases, and only empty bases.
    fn is_empty_class(&self, ty: TypeRef) -> bool {
        self.is_empty_class_in(ty, 0, &mut HashMap::new())
    }

    /// [`Self::is_empty_class`], each class's answer kept in `known`: a
    /// hostile hierarchy whose classes share bases (each with two bases that
    /// are both the next) would otherwise take time exponential in its
    /// depth. (A class is taken as not empty while its own bases are being
    /// looked at, which ends a cycle.)
    fn is_empty_class_in(
        &self,
        ty: TypeRef,
        depth: u32,
        known: &mut HashMap<TypeRef, bool>,
    ) -> bool {
        if let Some(&e) = known.get(&ty) {
            return e;
        }
        if depth > MAX_BASE_DEPTH {
            return false;
        }
        known.insert(ty, false);
        let e = self.is_empty_class_uncached(ty, depth, known);
        known.insert(ty, e);
        e
    }

    fn is_empty_class_uncached(
        &self,
        ty: TypeRef,
        depth: u32,
        known: &mut HashMap<TypeRef, bool>,
    ) -> bool {
        let at = self.through(ty, None);
        let Some((u, a, d)) = self.die(at) else {
            return false;
        };
        if !matches!(
            d.tag,
            DW_TAG_STRUCTURE_TYPE | DW_TAG_CLASS_TYPE | DW_TAG_INTERFACE_TYPE
        ) || d.flag(DW_AT_DECLARATION)
        {
            return false;
        }
        u.children(a, &d).iter().all(|c| match c.tag {
            DW_TAG_MEMBER => c.flag(DW_AT_DECLARATION) || c.flag(DW_AT_EXTERNAL),
            DW_TAG_INHERITANCE => {
                c.attr(DW_AT_VIRTUALITY).is_none()
                    && self.is_empty_class_in(self.type_of(&u, c), depth + 1, known)
            }
            _ => true,
        })
    }

    /// The layout of type `ty` (see [`crate::DebugInfo::layout`]).
    pub fn layout(&self, ty: TypeRef) -> Option<Layout> {
        let at = self.through(ty, None);
        let (u, a, d) = self.die(at)?;
        if !matches!(
            d.tag,
            DW_TAG_STRUCTURE_TYPE | DW_TAG_CLASS_TYPE | DW_TAG_UNION_TYPE | DW_TAG_INTERFACE_TYPE
        ) || d.flag(DW_AT_DECLARATION)
        {
            return None;
        }
        let size = Self::uint(&u, &d, DW_AT_BYTE_SIZE)?;
        let union = d.tag == DW_TAG_UNION_TYPE;
        let pointer = u64::from(u.address_size);
        let mut incomplete = false;
        let mut parts = Vec::new();
        let mut vbases = Vec::new();
        let typed = |mut p: Part, ty: TypeRef| {
            p.type_name = self.type_name(ty);
            p.ty = ty;
            p
        };
        for c in u.children(a, &d) {
            match c.tag {
                DW_TAG_INHERITANCE => {
                    let base = self.through(self.type_of(&u, &c), None);
                    if c.attr(DW_AT_VIRTUALITY).is_some() {
                        vbases.push(base);
                        continue;
                    }
                    let offset = Self::member_offset(&u, &c).unwrap_or(0);
                    let size = if self.is_empty_class(base) {
                        0
                    } else {
                        self.type_size(base).filter(|&s| s > 0).unwrap_or_else(|| {
                            incomplete = true;
                            0
                        })
                    };
                    parts.push(typed(Part::new(offset, size, PartKind::Base), base));
                }
                DW_TAG_MEMBER => {
                    // (Static members aren't in the object.)
                    if c.flag(DW_AT_DECLARATION) || c.flag(DW_AT_EXTERNAL) {
                        continue;
                    }
                    let name = Self::string(&u, &c, DW_AT_NAME).unwrap_or_default();
                    let mty = self.type_of(&u, &c);
                    let offset = Self::member_offset(&u, &c);
                    if c.flag(DW_AT_ARTIFICIAL) && name.starts_with("_vptr") {
                        parts.push(Part::new(offset.unwrap_or(0), pointer, PartKind::VfPtr));
                        continue;
                    }
                    if let Some(bits) = Self::uint(&u, &c, DW_AT_BIT_SIZE) {
                        let unit = Self::uint(&u, &c, DW_AT_BYTE_SIZE)
                            .or_else(|| self.type_size(mty))
                            .filter(|&n| n > 0 && n <= 16)
                            .unwrap_or(4);
                        let (unit_at, first) = match Self::uint(&u, &c, DW_AT_DATA_BIT_OFFSET) {
                            Some(dbo) => {
                                let at = dbo / (unit * 8) * unit;
                                (at, dbo - at * 8)
                            }
                            None => {
                                let at = offset.unwrap_or(0);
                                let from_top = Self::uint(&u, &c, DW_AT_BIT_OFFSET).unwrap_or(0);
                                let first = match u.sections().endian {
                                    Endian::Little => {
                                        (unit * 8).saturating_sub(from_top).saturating_sub(bits)
                                    }
                                    Endian::Big => from_top,
                                };
                                (at, first)
                            }
                        };
                        let mut p = Part::new(unit_at, unit, PartKind::Member);
                        p.name = name;
                        p.bits = Some((
                            u8::try_from(first).unwrap_or(u8::MAX),
                            u8::try_from(bits).unwrap_or(u8::MAX),
                        ));
                        parts.push(typed(p, mty));
                        continue;
                    }
                    let size = self.type_size(mty).filter(|&s| s > 0).unwrap_or_else(|| {
                        incomplete = true;
                        0
                    });
                    let mut p = Part::new(offset.unwrap_or(0), size, PartKind::Member);
                    p.name = name;
                    parts.push(typed(p, mty));
                }
                _ => {}
            }
        }
        // Virtual bases, after the rest, in order, each at its own
        // alignment (the Itanium ABI's placement; MSVC's, which the PDB
        // backend follows, first rounds up to a pointer's).
        if !vbases.is_empty() {
            let end = parts
                .iter()
                .map(|p| p.offset.saturating_add(p.size))
                .max()
                .unwrap_or(0);
            let mut at = end;
            for &b in &vbases {
                let size = self.type_size(b).unwrap_or(0);
                let align = size
                    .clamp(1, pointer.max(1))
                    .next_power_of_two()
                    .min(pointer.max(1));
                at = at.next_multiple_of(align);
                parts.push(typed(Part::new(at, size, PartKind::VirtualBase), b));
                at = at.saturating_add(size);
            }
        }
        parts.sort_by_key(|p| (p.offset, p.bits.map_or(0, |b| b.0)));
        let name = self.qualified_name(at);
        let mut l = fill(name.clone(), size, union, parts);
        l.ty = at;
        l.key = if crate::layout::is_anonymous(&name) {
            // (Anonymous types can't be told apart by name.)
            format!("{name}@{:#x}", at.0)
        } else {
            name
        };
        l.incomplete = incomplete;
        Some(l)
    }

    /// Every defined class, structure, and union (one per key), with its
    /// layout.
    pub fn layouts(&self) -> Result<Vec<Layout>, hexcavator_core::Error> {
        let mut defs = Vec::new();
        self.walk(|w| {
            let d = w.die;
            if matches!(
                d.tag,
                DW_TAG_STRUCTURE_TYPE
                    | DW_TAG_CLASS_TYPE
                    | DW_TAG_UNION_TYPE
                    | DW_TAG_INTERFACE_TYPE
            ) && !d.flag(DW_AT_DECLARATION)
                && d.attr(DW_AT_BYTE_SIZE).is_some()
            {
                defs.push(w.at);
            }
            Walk::Into
        });
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for at in defs {
            if let Some(l) = self.layout(at)
                && seen.insert(l.key.clone())
            {
                out.push(l);
            }
        }
        Ok(out)
    }
}

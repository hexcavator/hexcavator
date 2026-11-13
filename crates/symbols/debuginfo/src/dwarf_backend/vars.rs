//! A function's parameters and locals, and where each lives: DWARF
//! location expressions (and lists of them) read as places.
//!
//! Only expressions that name a place are read: a register, memory at an
//! offset from a register or from the frame base, and pieces of those.
//! Computed values (`DW_OP_stack_value`, implicit values and pointers,
//! entry values) aren't places, and are left out.

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Abbrevs, Die, Reader, Unit, Value};

use super::{DwarfInfo, MAX_DEPTH};
use crate::{FunctionVariables, Place, TypeRef, VarRange, Variable};

/// The most variables read of one function.
const MAX_VARIABLES: usize = 1 << 16;

/// Where a function's frame base is (`DW_AT_frame_base`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameBase {
    /// The value of a register (`DW_OP_regN`).
    Register(u16),
    /// A register plus an offset (`DW_OP_bregN`).
    Relative(u16, i64),
    /// The canonical frame address.
    Cfa,
    Unknown,
}

fn frame_base(u: &Unit<'_>, v: Option<&Value<'_>>) -> FrameBase {
    let Some(Value::Block(b)) = v.copied() else {
        return FrameBase::Unknown;
    };
    match places(u, b, FrameBase::Unknown).as_deref() {
        Some([(_, Place::Register(r))]) => FrameBase::Register(*r),
        Some([(_, Place::Relative { register, offset })]) => {
            FrameBase::Relative(*register, i64::from(*offset))
        }
        _ if b == [DW_OP_CALL_FRAME_CFA] => FrameBase::Cfa,
        _ => FrameBase::Unknown,
    }
}

/// The places an expression names: one for the whole variable, or one
/// per piece (with its offset into the variable). `None` if it names no
/// place, or a place this doesn't describe.
fn places(u: &Unit<'_>, expr: &[u8], frame: FrameBase) -> Option<Vec<(u32, Place)>> {
    let mut r = Reader::new(expr, 0, u.sections().endian);
    let mut out = Vec::new();
    let mut field = 0u32;
    let mut current: Option<Place> = None;
    let reg = |n: u64| u16::try_from(n).ok();
    let off = |n: i64| i32::try_from(n).ok();
    while !r.is_empty() {
        let op = r.u8()?;
        let place = match op {
            DW_OP_REG0..=DW_OP_REG31 => Place::Register(u16::from(op - DW_OP_REG0)),
            DW_OP_REGX => Place::Register(reg(r.uleb()?)?),
            DW_OP_BREG0..=DW_OP_BREG31 => Place::Relative {
                register: u16::from(op - DW_OP_BREG0),
                offset: off(r.sleb()?)?,
            },
            DW_OP_BREGX => Place::Relative {
                register: reg(r.uleb()?)?,
                offset: off(r.sleb()?)?,
            },
            DW_OP_FBREG => {
                let o = r.sleb()?;
                match frame {
                    FrameBase::Register(register) => Place::Relative {
                        register,
                        offset: off(o)?,
                    },
                    FrameBase::Relative(register, base) => Place::Relative {
                        register,
                        offset: off(base.checked_add(o)?)?,
                    },
                    FrameBase::Cfa => Place::Cfa { offset: off(o)? },
                    FrameBase::Unknown => return None,
                }
            }
            DW_OP_PIECE => {
                let size = u32::try_from(r.uleb()?).ok()?;
                match current.take() {
                    // A register piece is a field of the variable in it.
                    Some(Place::Register(register)) => {
                        out.push((field, Place::Field { register, field }));
                    }
                    // The first piece, in memory: the variable is there.
                    Some(p) if field == 0 => out.push((0, p)),
                    // Other memory pieces, and pieces optimized out.
                    _ => {}
                }
                field = field.checked_add(size)?;
                continue;
            }
            // Anything else computes: not a place.
            _ => return None,
        };
        if current.is_some() {
            return None;
        }
        current = Some(place);
    }
    match current {
        Some(p) if out.is_empty() && field == 0 => Some(vec![(0, p)]),
        // (Ops after the last piece.)
        Some(_) => None,
        None if !out.is_empty() => Some(out),
        None => None,
    }
}

impl DwarfInfo<'_> {
    /// The variables of the function at `addr` (see [`crate::DebugInfo::variables`]).
    pub fn variables(
        &self,
        compiland: Option<u32>,
        addr: u64,
    ) -> Result<Option<FunctionVariables>, hexcavator_core::Error> {
        let Some(candidates) = self.functions().get(&addr) else {
            return Ok(None);
        };
        // The compiland's own function first.
        let in_compiland = |r: &TypeRef| {
            compiland.is_some() && self.meta_of(*r).and_then(|m| m.compiland) == compiland
        };
        let Some(&at) = candidates
            .iter()
            .find(|r| in_compiland(r))
            .or_else(|| candidates.first())
        else {
            return Ok(None);
        };
        let Some((u, a, d)) = self.die(at) else {
            return Ok(None);
        };
        let ranges = self.ranges(&u, &d);
        let end = ranges
            .iter()
            .map(|&(s, n)| s.saturating_add(n))
            .max()
            .unwrap_or(addr);
        // The frame base is the definition's (or its abstract origin's).
        let frame = frame_base(&u, d.attr(DW_AT_FRAME_BASE).map(|a| &a.value));
        let mut out = FunctionVariables {
            start: addr,
            end,
            frame: (0, 0),
            variables: Vec::new(),
        };
        self.collect(&u, a, &d, &ranges, frame, false, 0, &mut out.variables);
        Ok(Some(out))
    }

    /// The variables among `parent`'s children (and theirs: blocks, and
    /// functions inlined into it), depth first, with the walk's stack on
    /// the heap (blocks and inlined functions nest as deeply as the data
    /// says, to [`MAX_DEPTH`]).
    #[allow(clippy::too_many_arguments, reason = "a walk's state")]
    fn collect(
        &self,
        u: &Unit<'_>,
        a: &Abbrevs,
        parent: &Die<'_>,
        code: &[(u64, u64)],
        frame: FrameBase,
        inlined: bool,
        depth: i64,
        out: &mut Vec<Variable>,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        // Each level's children still to look at, and whether they are in
        // an inlined function.
        let mut stack = vec![(u.children(a, parent).into_iter(), inlined, depth)];
        while let Some((children, inlined, depth)) = stack.last_mut() {
            let (inlined, depth) = (*inlined, *depth);
            let Some(c) = children.next() else {
                stack.pop();
                continue;
            };
            if out.len() >= MAX_VARIABLES {
                return;
            }
            match c.tag {
                DW_TAG_FORMAL_PARAMETER | DW_TAG_VARIABLE => {
                    if let Some(v) = self.variable(u, &c, code, frame, inlined) {
                        out.push(v);
                    }
                }
                DW_TAG_LEXICAL_BLOCK | DW_TAG_INLINED_SUBROUTINE if depth < MAX_DEPTH => {
                    let inlined = inlined || c.tag == DW_TAG_INLINED_SUBROUTINE;
                    stack.push((u.children(a, &c).into_iter(), inlined, depth + 1));
                }
                _ => {}
            }
        }
    }

    fn variable(
        &self,
        u: &Unit<'_>,
        d: &Die<'_>,
        code: &[(u64, u64)],
        frame: FrameBase,
        inlined: bool,
    ) -> Option<Variable> {
        let loc = d.attr(DW_AT_LOCATION)?;
        let at = super::to_ref(u.source, u.section, d.offset);
        let (_, name) = self.origin(at);
        // (A fixed address is a static's: a symbol, not a local.)
        if u.location_address(&loc.value).is_some() {
            return None;
        }
        let list: Vec<(u64, u64, &[u8])> = match loc.value {
            Value::Block(b) => code
                .iter()
                .map(|&(s, n)| (s, s.saturating_add(n), b))
                .collect(),
            Value::ListIndex(i) => {
                self.image_list(u.source, u.location_list(u.loclist_offset(i)?)?)
            }
            _ => self.image_list(u.source, u.location_list(u.uint(&loc.value)?)?),
        };
        let mut ranges = Vec::new();
        for (start, end, expr) in list {
            let Some(places) = places(u, expr, frame) else {
                continue;
            };
            for (_, place) in places {
                ranges.push(VarRange {
                    start,
                    end,
                    gaps: Vec::new(),
                    place,
                });
            }
        }
        if ranges.is_empty() {
            return None;
        }
        Some(Variable {
            name: name.unwrap_or_default(),
            type_index: self.declared_type(at).0,
            param: d.tag == DW_TAG_FORMAL_PARAMETER,
            inlined,
            ranges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexcavator_core::Endian;
    use hexcavator_dwarf::{Sections, UnitSection};

    /// A unit to read expressions with (little-endian, 8-byte addresses).
    fn with_unit(f: impl FnOnce(&Unit<'_>)) {
        // A DWARF 4 unit header with one null DIE.
        let mut info = vec![8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 0];
        info[0] = 8;
        let mut s = Sections::new(Endian::Little);
        s.info = &info;
        s.abbrev = &[0];
        let u = Unit::iter(s, UnitSection::Info, 0).next().unwrap();
        f(&u);
    }

    #[test]
    fn registers_memory_and_the_frame_base() {
        with_unit(|u| {
            let p = |e: &[u8], f| places(u, e, f);
            let none = FrameBase::Unknown;
            assert_eq!(
                p(&[DW_OP_REG0 + 5], none),
                Some(vec![(0, Place::Register(5))])
            );
            assert_eq!(
                p(&[DW_OP_REGX, 0x80, 0x02], none),
                Some(vec![(0, Place::Register(256))])
            );
            // breg7 -8 (sleb 0x78).
            assert_eq!(
                p(&[DW_OP_BREG0 + 7, 0x78], none),
                Some(vec![(
                    0,
                    Place::Relative {
                        register: 7,
                        offset: -8
                    }
                )])
            );
            // fbreg -16 (0x70) over each kind of frame base.
            let fb = [DW_OP_FBREG, 0x70];
            assert_eq!(
                p(&fb, FrameBase::Register(6)),
                Some(vec![(
                    0,
                    Place::Relative {
                        register: 6,
                        offset: -16
                    }
                )])
            );
            assert_eq!(
                p(&fb, FrameBase::Relative(7, 8)),
                Some(vec![(
                    0,
                    Place::Relative {
                        register: 7,
                        offset: -8
                    }
                )])
            );
            assert_eq!(
                p(&fb, FrameBase::Cfa),
                Some(vec![(0, Place::Cfa { offset: -16 })])
            );
            assert_eq!(p(&fb, none), None);
        });
    }

    #[test]
    fn pieces_and_what_is_not_a_place() {
        with_unit(|u| {
            let p = |e: &[u8]| places(u, e, FrameBase::Unknown);
            // A 16-byte structure in rax (0) and rdx (1), 8 bytes each.
            assert_eq!(
                p(&[DW_OP_REG0, DW_OP_PIECE, 8, DW_OP_REG0 + 1, DW_OP_PIECE, 8]),
                Some(vec![
                    (
                        0,
                        Place::Field {
                            register: 0,
                            field: 0
                        }
                    ),
                    (
                        8,
                        Place::Field {
                            register: 1,
                            field: 8
                        }
                    ),
                ])
            );
            // A piece optimized out (no location) before a register's.
            assert_eq!(
                p(&[DW_OP_PIECE, 4, DW_OP_REG0 + 3, DW_OP_PIECE, 4]),
                Some(vec![(
                    4,
                    Place::Field {
                        register: 3,
                        field: 4
                    }
                )])
            );
            // Computed: a constant's value, a register plus a dereference.
            assert_eq!(p(&[DW_OP_LIT0 + 3, DW_OP_STACK_VALUE]), None);
            assert_eq!(p(&[DW_OP_BREG0, 0, DW_OP_DEREF]), None);
            // Two places with no piece between: malformed.
            assert_eq!(p(&[DW_OP_REG0, DW_OP_REG0 + 1]), None);
            // Empty (optimized out), truncated, an offset too wide.
            assert_eq!(p(&[]), None);
            assert_eq!(p(&[DW_OP_BREG0]), None);
            assert_eq!(p(&[DW_OP_BREG0, 0x80, 0x80, 0x80, 0x80, 0x40]), None);
            assert_eq!(p(&[DW_OP_REGX, 0x80, 0x80, 0x04]), None);
        });
    }

    #[test]
    fn frame_bases() {
        with_unit(|u| {
            let fb = |e: &[u8]| frame_base(u, Some(&Value::Block(e)));
            assert_eq!(fb(&[DW_OP_REG0 + 6]), FrameBase::Register(6));
            assert_eq!(fb(&[DW_OP_BREG0 + 7, 8]), FrameBase::Relative(7, 8));
            assert_eq!(fb(&[DW_OP_CALL_FRAME_CFA]), FrameBase::Cfa);
            assert_eq!(fb(&[DW_OP_LIT0]), FrameBase::Unknown);
            assert_eq!(frame_base(u, None), FrameBase::Unknown);
        });
    }
}

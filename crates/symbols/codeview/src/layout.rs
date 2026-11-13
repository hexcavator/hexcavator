//! Type layouts' parts: where each part of a class, structure, or union
//! lies, as its records say (the holes between them, and comparisons, are
//! format-independent: `hexcavator_debuginfo::layout`).
//!
//! From a type's field list: its base classes, its virtual function table
//! pointer, its members (bitfields with their bit positions), and its
//! virtual base table pointer and virtual bases. A
//! virtual base's offset isn't in the type records (it's found at run time
//! through the vbtable); MSVC places virtual bases after the rest of the
//! object, aligned, in order, so they are laid out there. An empty base takes no space (the empty base
//! optimization).

use hexcavator_core::Reader;

use crate::types::{Field, TypeFormatter, leaf};
use crate::types::{TypeIndex, TypeSource};

/// What a part of a layout is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartKind {
    Base,
    VirtualBase,
    /// The virtual function table pointer.
    VfPtr,
    /// The virtual base table pointer.
    VbPtr,
    Member,
}

impl PartKind {
    pub fn label(self) -> &'static str {
        match self {
            PartKind::Base => "base",
            PartKind::VirtualBase => "virtual base",
            PartKind::VfPtr => "vfptr",
            PartKind::VbPtr => "vbptr",
            PartKind::Member => "member",
        }
    }
}

/// One part of a layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub offset: u64,
    pub size: u64,
    /// For a bitfield (or bit padding): its first bit and how many bits.
    pub bits: Option<(u8, u8)>,
    pub kind: PartKind,
    /// The member's name (empty for others).
    pub name: String,
    /// The part's type, as C++ (empty for padding).
    pub type_name: String,
    /// The part's type (a base's, a member's, or a bitfield's storage
    /// unit's), or 0 for pointers.
    pub ty: TypeIndex,
}

/// A type's layout: its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Its record.
    pub ti: TypeIndex,
    pub name: String,
    /// What tells it from others of its name: its unique (decorated) name,
    /// if it has one (anonymous types all share the name `<unnamed-tag>`).
    pub key: String,
    /// Whether some part's size is unknown (a member of a type with no
    /// definition here): its padding is then not known either.
    pub incomplete: bool,
    pub size: u64,
    pub union: bool,
    /// By offset (and bit).
    pub parts: Vec<Part>,
}

/// How deep base classes may nest before a layout gives up (hostile input
/// can make a type its own base).
const MAX_DEPTH: u32 = 64;

/// The layout of the class, structure, or union `ti` (resolving a forward
/// reference to its definition), or `None` if it isn't one or has no
/// definition.
pub fn layout(types: &dyn TypeSource, ti: TypeIndex) -> Option<Layout> {
    build(types, ti, true, &mut Cache::default())
}

/// Types' sizes and whether they are empty, as found: a type stream's
/// layouts ask about the same types again and again, and each answer
/// looks up a definition by name.
#[derive(Default)]
struct Cache {
    sizes: std::collections::HashMap<u32, Option<u64>>,
    empty: std::collections::HashMap<u32, bool>,
}

impl Cache {
    fn size(&mut self, f: &TypeFormatter<'_>, ti: TypeIndex) -> Option<u64> {
        *self.sizes.entry(ti.0).or_insert_with(|| f.size_of(ti))
    }

    fn empty(&mut self, types: &dyn TypeSource, ti: TypeIndex) -> bool {
        is_empty(types, ti, 0, &mut self.empty)
    }
}

/// [`layout`], with the parts' type names only if `names` (formatting them
/// is most of the work, and a list of types needs none).
fn build(types: &dyn TypeSource, ti: TypeIndex, names: bool, cache: &mut Cache) -> Option<Layout> {
    let ti = types.resolve_forward(ti);
    let rec = types.record(ti)?;
    if !leaf::is_class(rec.kind) && !leaf::is_union(rec.kind) {
        return None;
    }
    let udt = rec.udt()?;
    if udt.is_forward_ref() {
        return None;
    }
    let f = TypeFormatter { types };
    let type_name = |t: TypeIndex| if names { f.name(t) } else { String::new() };
    let union = leaf::is_union(rec.kind);
    let mut incomplete = false;
    let mut parts = Vec::new();
    let mut vbases = Vec::new();
    let mut vbptr: Option<u64> = None;
    for field in fields(types, udt.field_list) {
        match field {
            Field::BaseClass { ty, offset, .. } => {
                let size = if cache.empty(types, ty) {
                    0
                } else {
                    cache.size(&f, ty).filter(|&s| s > 0).unwrap_or_else(|| {
                        incomplete = true;
                        0
                    })
                };
                parts.push(typed(
                    part(
                        offset,
                        size,
                        None,
                        PartKind::Base,
                        String::new(),
                        type_name(ty),
                    ),
                    ty,
                ));
            }
            Field::VirtualBaseClass {
                ty, vbptr_offset, ..
            } => {
                vbptr.get_or_insert(vbptr_offset);
                vbases.push(ty);
            }
            Field::VFuncTab { ty } => {
                let size = cache.size(&f, ty).filter(|&s| s > 0).unwrap_or(8);
                // A base's vfptr is the class's own: only one at offset 0.
                if !parts
                    .iter()
                    .any(|p| p.offset == 0 && p.kind == PartKind::Base && p.size > 0)
                {
                    parts.push(part(
                        0,
                        size,
                        None,
                        PartKind::VfPtr,
                        String::new(),
                        String::new(),
                    ));
                }
            }
            Field::Member {
                ty, offset, name, ..
            } => {
                let name = String::from_utf8_lossy(name).into_owned();
                match bitfield(types, ty) {
                    Some((base, len, pos)) => {
                        let size = cache.size(&f, base).unwrap_or(0);
                        parts.push(typed(
                            part(
                                offset,
                                size,
                                Some((pos, len)),
                                PartKind::Member,
                                name,
                                type_name(base),
                            ),
                            base,
                        ));
                    }
                    None => {
                        // No member is empty: one of size 0 is of a type
                        // with no definition here.
                        let size = cache.size(&f, ty).filter(|&s| s > 0).unwrap_or_else(|| {
                            incomplete = true;
                            0
                        });
                        parts.push(typed(
                            part(offset, size, None, PartKind::Member, name, type_name(ty)),
                            ty,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    let pointer = pointer_size(types, udt.field_list).unwrap_or(8);
    if let Some(at) = vbptr
        && !parts
            .iter()
            .any(|p| p.offset <= at && at < p.offset.saturating_add(p.size))
    {
        parts.push(part(
            at,
            pointer,
            None,
            PartKind::VbPtr,
            String::new(),
            String::new(),
        ));
    }
    // Virtual bases, after the rest (rounded up to the vbptr's alignment),
    // in order, each at its own alignment.
    if !vbases.is_empty() {
        // (Offsets and sizes are the type records': a hostile one can be
        // near 2^64. Then the virtual bases are left out.)
        let end = parts
            .iter()
            .map(|p| p.offset.saturating_add(p.size))
            .max()
            .unwrap_or(0);
        let mut at = end.checked_next_multiple_of(pointer).unwrap_or(u64::MAX);
        for &b in &vbases {
            let size = cache.size(&f, b).unwrap_or(0);
            let align = size.clamp(1, pointer).next_power_of_two().min(pointer);
            let Some(next) = at.checked_next_multiple_of(align) else {
                break;
            };
            at = next;
            parts.push(typed(
                part(
                    at,
                    size,
                    None,
                    PartKind::VirtualBase,
                    String::new(),
                    type_name(b),
                ),
                b,
            ));
            at = at.saturating_add(size);
        }
    }
    parts.sort_by_key(|p| (p.offset, p.bits.map_or(0, |b| b.0)));
    Some(Layout {
        ti,
        name: udt_name(udt.name),
        key: udt_name(udt.unique_name.unwrap_or(udt.name)),
        incomplete,
        size: udt.size,
        union,
        parts,
    })
}

fn udt_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn part(
    offset: u64,
    size: u64,
    bits: Option<(u8, u8)>,
    kind: PartKind,
    name: String,
    type_name: String,
) -> Part {
    Part {
        offset,
        size,
        bits,
        kind,
        name,
        type_name,
        ty: TypeIndex(0),
    }
}

fn typed(mut p: Part, ty: TypeIndex) -> Part {
    p.ty = ty;
    p
}

/// The fields of a field list and the lists it continues in.
/// The most field lists chained by `LF_INDEX` that are followed (a hostile
/// chain could otherwise loop).
const MAX_FIELD_LISTS: u32 = 1024;

fn fields<'a>(types: &'a dyn TypeSource, list: TypeIndex) -> Vec<Field<'a>> {
    let mut out = Vec::new();
    let mut next = Some(list);
    let mut seen = 0;
    while let Some(ti) = next.take() {
        seen += 1;
        if seen > MAX_FIELD_LISTS {
            break;
        }
        let Some(rec) = types.record(ti) else { break };
        for field in rec.fields() {
            match field {
                Field::Index { ty } => next = Some(ty),
                f => out.push(f),
            }
        }
    }
    out
}

/// Whether `ti` is a class with no data: no members, no vfptr, no virtual
/// bases, and only empty bases. Each class's answer is kept in `known`: a
/// hostile hierarchy whose classes share bases (each with two bases that
/// are both the next) would otherwise take time exponential in its depth.
/// (A class is taken as not empty while its own bases are being looked at,
/// which ends a cycle.)
fn is_empty(
    types: &dyn TypeSource,
    ti: TypeIndex,
    depth: u32,
    known: &mut std::collections::HashMap<u32, bool>,
) -> bool {
    if let Some(&e) = known.get(&ti.0) {
        return e;
    }
    if depth > MAX_DEPTH {
        return false;
    }
    known.insert(ti.0, false);
    let e = is_empty_uncached(types, ti, depth, known);
    known.insert(ti.0, e);
    e
}

fn is_empty_uncached(
    types: &dyn TypeSource,
    ti: TypeIndex,
    depth: u32,
    known: &mut std::collections::HashMap<u32, bool>,
) -> bool {
    let ti = types.resolve_forward(ti);
    let Some(udt) = types.record(ti).and_then(|r| r.udt()) else {
        return false;
    };
    if udt.is_forward_ref() {
        return false;
    }
    fields(types, udt.field_list).iter().all(|f| match f {
        Field::BaseClass { ty, .. } => is_empty(types, *ty, depth + 1, known),
        Field::Member { .. } | Field::VFuncTab { .. } | Field::VirtualBaseClass { .. } => false,
        _ => true,
    })
}

/// If `ti` is a bitfield: its underlying type, length, and position.
fn bitfield(types: &dyn TypeSource, ti: TypeIndex) -> Option<(TypeIndex, u8, u8)> {
    if ti.is_simple() {
        return None;
    }
    let rec = types.record(ti)?;
    if rec.kind != leaf::LF_BITFIELD {
        return None;
    }
    let mut r = Reader::new(rec.data);
    let base = TypeIndex(r.u32_le().ok()?);
    Some((base, r.u8().ok()?, r.u8().ok()?))
}

/// The size of a pointer in this type stream: from a vfptr's type in the
/// field list, if there is one.
fn pointer_size(types: &dyn TypeSource, list: TypeIndex) -> Option<u64> {
    let f = TypeFormatter { types };
    fields(types, list).iter().find_map(|field| match field {
        Field::VFuncTab { ty } => f.size_of(*ty).filter(|&s| s > 0),
        _ => None,
    })
}

/// Every defined class, structure, and union of `types` (one per unique
/// name), with its layout, without the parts' type names (see
/// [`layout`] for one with them).
pub fn all(types: &dyn TypeSource) -> Vec<Layout> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut cache = Cache::default();
    // Every record's offset, once: lookups by index then cost nothing.
    for (ti, rec) in types.records() {
        if !leaf::is_class(rec.kind) && !leaf::is_union(rec.kind) {
            continue;
        }
        let Some(udt) = rec.udt() else { continue };
        if udt.is_forward_ref() || !seen.insert(udt.unique_name.unwrap_or(udt.name).to_vec()) {
            continue;
        }
        if let Some(l) = build(types, ti, false, &mut cache) {
            out.push(l);
        }
    }
    out
}

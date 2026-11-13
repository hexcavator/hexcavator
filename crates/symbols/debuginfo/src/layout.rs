//! Type layouts, whatever the debug format: where each part of a class,
//! structure, or union lies, and the bytes (and bits) that hold nothing.
//!
//! The backends give each type's parts: its bases, virtual function and
//! base table pointers, members (bitfields with their bit positions), and
//! virtual bases, where they lie. [`fill`] finds the holes between them;
//! [`compare`] compares two builds' layouts; [`flat_fields`] flattens one
//! into the fields a disassembly can name.

use crate::{DebugInfo, TypeRef, TypeShape};

/// What a part of a layout is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PartKind {
    /// A base class.
    Base,
    /// A virtual base class.
    VirtualBase,
    /// The virtual function table pointer.
    VfPtr,
    /// The virtual base table pointer.
    VbPtr,
    /// A data member.
    Member,
    /// Bytes between parts that hold nothing.
    Padding,
    /// Bytes after the last part, up to the type's size.
    TailPadding,
    /// Bits of a bitfield's storage no bitfield uses (`bits` says which).
    BitPadding,
}

impl PartKind {
    /// Its name, as reports print it.
    pub fn label(self) -> &'static str {
        match self {
            PartKind::Base => "base",
            PartKind::VirtualBase => "virtual base",
            PartKind::VfPtr => "vfptr",
            PartKind::VbPtr => "vbptr",
            PartKind::Member => "member",
            PartKind::Padding => "padding",
            PartKind::TailPadding => "tail padding",
            PartKind::BitPadding => "bit padding",
        }
    }

    /// Whether the part holds nothing.
    pub fn is_padding(self) -> bool {
        matches!(
            self,
            PartKind::Padding | PartKind::TailPadding | PartKind::BitPadding
        )
    }
}

/// One part of a layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// From the start of the type.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// For a bitfield (or bit padding): its first bit and how many bits.
    pub bits: Option<(u8, u8)>,
    /// What it is.
    pub kind: PartKind,
    /// The member's name (empty for others).
    pub name: String,
    /// The part's type, as C++ (empty for padding).
    pub type_name: String,
    /// The part's type (a base's, a member's, or a bitfield's storage
    /// unit's), or 0 for pointers and padding.
    pub ty: TypeRef,
}

impl Part {
    /// A part of `kind` at `offset`, `size` bytes long (unnamed, untyped).
    pub fn new(offset: u64, size: u64, kind: PartKind) -> Self {
        Self {
            offset,
            size,
            bits: None,
            kind,
            name: String::new(),
            type_name: String::new(),
            ty: TypeRef(0),
        }
    }
}

/// A type's layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The type.
    pub ty: TypeRef,
    /// Its qualified name.
    pub name: String,
    /// What tells it from others of its name across builds: its unique
    /// (decorated) name if the format has one, else its qualified name.
    pub key: String,
    /// Whether some part's size is unknown (a member of a type with no
    /// definition here): its padding is then not known either.
    pub incomplete: bool,
    /// Its size in bytes.
    pub size: u64,
    /// Whether it is a union.
    pub union: bool,
    /// By offset (and bit).
    pub parts: Vec<Part>,
    /// Bytes of padding (between parts and at the end).
    pub padding: u64,
    /// Bits of bitfield storage unused.
    pub bit_padding: u64,
}

impl Layout {
    /// The bytes that hold nothing, counting unused bits in whole bytes
    /// (rounded down); none known if the layout is incomplete.
    pub fn waste(&self) -> u64 {
        if self.incomplete {
            0
        } else {
            self.padding + self.bit_padding / 8
        }
    }
}

/// Whether a type's name is one every anonymous type shares (and so can't
/// be told apart across builds): PDB's `<unnamed-tag>` (and other `<...>`
/// names), DWARF's `(anonymous struct)` and the like.
pub fn is_anonymous(name: &str) -> bool {
    name.starts_with('<') || name.starts_with("(anonymous") || name.contains("::(anonymous")
}

/// A layout of `size` bytes from its `parts` (sorted by offset and bit),
/// with the holes between them, and after them, as padding parts.
pub fn fill(name: String, size: u64, union: bool, parts: Vec<Part>) -> Layout {
    let mut out = Vec::with_capacity(parts.len() * 2);
    let (mut padding, mut bit_padding) = (0u64, 0u64);
    let layout = |parts, padding, bit_padding| Layout {
        ty: TypeRef(0),
        name,
        key: String::new(),
        incomplete: false,
        size,
        union,
        parts,
        padding,
        bit_padding,
    };
    if union {
        let used = parts.iter().map(|p| p.size).max().unwrap_or(0);
        out.extend(parts);
        if size > used {
            padding += size - used;
            out.push(Part::new(used, size - used, PartKind::TailPadding));
        }
        return layout(out, padding, bit_padding);
    }
    let mut cursor = 0u64;
    let mut i = 0;
    while i < parts.len() {
        let p = &parts[i];
        if p.offset > cursor {
            padding += p.offset - cursor;
            out.push(Part::new(cursor, p.offset - cursor, PartKind::Padding));
        }
        if p.bits.is_some() {
            // A storage unit of bitfields: those at this offset.
            let unit = p.size;
            let start = i;
            while i < parts.len() && parts[i].offset == p.offset && parts[i].bits.is_some() {
                i += 1;
            }
            let group = &parts[start..i];
            out.extend(group.iter().cloned());
            let used: u64 = group
                .iter()
                .map(|g| u64::from(g.bits.map_or(0, |b| b.1)))
                .sum();
            let total = unit.saturating_mul(8);
            if total > used {
                let first = group
                    .iter()
                    .map(|g| g.bits.map_or(0, |b| b.0.saturating_add(b.1)))
                    .max()
                    .unwrap_or(0);
                bit_padding += total - used;
                let mut b = Part::new(p.offset, unit, PartKind::BitPadding);
                b.bits = Some((first, u8::try_from(total - used).unwrap_or(u8::MAX)));
                out.push(b);
            }
            cursor = cursor.max(p.offset.saturating_add(unit));
            continue;
        }
        cursor = cursor.max(p.offset.saturating_add(p.size));
        out.push(p.clone());
        i += 1;
    }
    if size > cursor {
        padding += size - cursor;
        out.push(Part::new(cursor, size - cursor, PartKind::TailPadding));
    }
    layout(out, padding, bit_padding)
}

/// A field of a flattened structure: its name (`a.b` for a member's
/// member), its offset from the start of the whole, and its size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlatField {
    /// Its name (`a.b` for a member's member).
    pub name: String,
    /// From the start of the whole.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
}

/// How deep [`flat_fields`] goes, and how many fields it gives at most.
const FLAT_DEPTH: u32 = 3;
const FLAT_MAX: usize = 4096;

/// The fields of the structure `ty`, flattened: its members (and their
/// members, as `a.b`, three levels down), its bases' members as its own,
/// and its vfptr and vbptr; each at its offset from the start of the
/// whole. Bounded: at most 4,096 fields.
pub fn flat_fields(debug: &DebugInfo<'_>, ty: TypeRef) -> Vec<FlatField> {
    let mut out = Vec::new();
    flatten(debug, ty, "", 0, 0, &mut out);
    out
}

fn flatten(
    debug: &DebugInfo<'_>,
    ty: TypeRef,
    prefix: &str,
    at: u64,
    depth: u32,
    out: &mut Vec<FlatField>,
) {
    if depth > FLAT_DEPTH || out.len() > FLAT_MAX {
        return;
    }
    let Some(l) = debug.layout(ty) else {
        return;
    };
    for p in &l.parts {
        let offset = at.saturating_add(p.offset);
        match p.kind {
            PartKind::Base | PartKind::VirtualBase => {
                flatten(debug, p.ty, prefix, offset, depth + 1, out);
            }
            PartKind::VfPtr | PartKind::VbPtr | PartKind::Member => {
                let name = if p.kind == PartKind::Member {
                    format!("{prefix}{}", p.name)
                } else {
                    format!("{prefix}{}", p.kind.label())
                };
                out.push(FlatField {
                    name: name.clone(),
                    offset,
                    size: p.size,
                });
                if p.kind == PartKind::Member && p.bits.is_none() {
                    flatten(debug, p.ty, &format!("{name}."), offset, depth + 1, out);
                }
            }
            _ => {}
        }
    }
}

/// What the pointer (or reference: one is a pointer in memory) type `ty`
/// points to, through qualifiers. Pointers to members hold offsets, not
/// addresses: they point to nothing.
pub fn pointer_target(debug: &DebugInfo<'_>, ty: TypeRef) -> Option<TypeRef> {
    use crate::PointerKind;
    let mut at = ty;
    for _ in 0..4 {
        match debug.type_shape(at) {
            TypeShape::Modified { base, .. } => at = base,
            TypeShape::Pointer { target, kind, .. } if kind != PointerKind::Member => {
                return Some(target);
            }
            _ => return None,
        }
    }
    None
}

/// Two builds' layouts compared, by key: those whose layout changed
/// (largest change in size first), and those added and removed.
#[derive(Clone, Debug, Default)]
pub struct LayoutDiff<'a> {
    /// (old, new).
    pub changed: Vec<(&'a Layout, &'a Layout)>,
    /// Layouts only the new build has.
    pub added: Vec<&'a Layout>,
    /// Layouts only the old build has.
    pub removed: Vec<&'a Layout>,
}

/// Compares two builds' layouts. Anonymous types (see [`is_anonymous`])
/// can't be told apart across builds, and are left out. Parts are compared
/// but for their type references, which are each file's own.
pub fn compare<'a>(old: &'a [Layout], new: &'a [Layout]) -> LayoutDiff<'a> {
    use std::collections::HashMap;
    let named = |l: &&Layout| !is_anonymous(&l.name);
    let by_key = |v: &'a [Layout]| -> HashMap<&'a str, &'a Layout> {
        v.iter()
            .filter(named)
            .map(|l| (l.key.as_str(), l))
            .collect()
    };
    let (olds, news) = (by_key(old), by_key(new));
    let same_parts = |a: &[Part], b: &[Part]| {
        a.len() == b.len()
            && a.iter().zip(b).all(|(x, y)| {
                (x.offset, x.size, x.bits, x.kind, &x.name, &x.type_name)
                    == (y.offset, y.size, y.bits, y.kind, &y.name, &y.type_name)
            })
    };
    let mut changed: Vec<(&Layout, &Layout)> = new
        .iter()
        .filter(named)
        .filter_map(|n| olds.get(n.key.as_str()).map(|o| (*o, n)))
        .filter(|(o, n)| !same_parts(&o.parts, &n.parts) || o.size != n.size)
        .collect();
    changed.sort_by(|a, b| {
        let d = |(o, n): &(&Layout, &Layout)| i128::from(n.size) - i128::from(o.size);
        d(b).abs()
            .cmp(&d(a).abs())
            .then_with(|| a.1.name.cmp(&b.1.name))
    });
    let added = new
        .iter()
        .filter(named)
        .filter(|n| !olds.contains_key(n.key.as_str()))
        .collect();
    let removed = old
        .iter()
        .filter(named)
        .filter(|o| !news.contains_key(o.key.as_str()))
        .collect();
    LayoutDiff {
        changed,
        added,
        removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(offset: u64, size: u64, name: &str) -> Part {
        let mut p = Part::new(offset, size, PartKind::Member);
        p.name = name.into();
        p
    }

    fn bits(offset: u64, unit: u64, first: u8, len: u8, name: &str) -> Part {
        let mut p = member(offset, unit, name);
        p.bits = Some((first, len));
        p
    }

    #[test]
    fn holes_between_and_after() {
        // char a; int b; char c: a@0, 3 padding, b@4, c@8, 3 tail.
        let l = fill(
            "Padded".into(),
            12,
            false,
            vec![member(0, 1, "a"), member(4, 4, "b"), member(8, 1, "c")],
        );
        let kinds: Vec<(u64, u64, PartKind)> =
            l.parts.iter().map(|p| (p.offset, p.size, p.kind)).collect();
        assert_eq!(
            kinds,
            [
                (0, 1, PartKind::Member),
                (1, 3, PartKind::Padding),
                (4, 4, PartKind::Member),
                (8, 1, PartKind::Member),
                (9, 3, PartKind::TailPadding),
            ]
        );
        assert_eq!((l.padding, l.waste()), (6, 6));
    }

    #[test]
    fn bitfields_share_their_storage() {
        // unsigned a:3, b:5 (24 bits unused); int c@4.
        let l = fill(
            "Bits".into(),
            8,
            false,
            vec![
                bits(0, 4, 0, 3, "a"),
                bits(0, 4, 3, 5, "b"),
                member(4, 4, "c"),
            ],
        );
        let pad = l
            .parts
            .iter()
            .find(|p| p.kind == PartKind::BitPadding)
            .unwrap();
        assert_eq!((pad.offset, pad.size, pad.bits), (0, 4, Some((8, 24))));
        assert_eq!((l.padding, l.bit_padding, l.waste()), (0, 24, 3));
    }

    #[test]
    fn unions_and_incomplete_layouts() {
        let l = fill(
            "U".into(),
            8,
            true,
            vec![member(0, 1, "c"), member(0, 4, "i")],
        );
        assert_eq!(l.padding, 4);
        assert_eq!(l.parts.last().unwrap().kind, PartKind::TailPadding);
        let mut l = fill("I".into(), 8, false, vec![member(0, 0, "x")]);
        l.incomplete = true;
        assert_eq!(l.waste(), 0);
        // Hostile: offsets and sizes at the limits don't overflow.
        let l = fill(
            "H".into(),
            u64::MAX,
            false,
            vec![
                member(u64::MAX - 1, u64::MAX, "x"),
                bits(5, u64::MAX, 250, 250, "y"),
            ],
        );
        assert!(!l.parts.is_empty());
    }

    #[test]
    fn anonymous_names() {
        for n in [
            "<unnamed-tag>",
            "<lambda_1>",
            "(anonymous struct)",
            "ns::(anonymous union)",
        ] {
            assert!(is_anonymous(n), "{n}");
        }
        for n in ["Padded", "std::vector<int>", "ns::A"] {
            assert!(!is_anonymous(n), "{n}");
        }
    }

    #[test]
    fn layouts_compared_by_key() {
        let l = |name: &str, size| {
            let mut l = fill(name.into(), size, false, vec![member(0, size, "x")]);
            l.key = name.into();
            l
        };
        let old = [l("A", 4), l("B", 8), l("Gone", 1), l("<unnamed-tag>", 4)];
        let new = [l("A", 4), l("B", 16), l("New", 2), l("<unnamed-tag>", 8)];
        let d = compare(&old, &new);
        assert_eq!(d.changed.len(), 1);
        assert_eq!((d.changed[0].0.size, d.changed[0].1.size), (8, 16));
        assert_eq!(
            d.added.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
            ["New"]
        );
        assert_eq!(
            d.removed
                .iter()
                .map(|l| l.name.as_str())
                .collect::<Vec<_>>(),
            ["Gone"]
        );
    }
}

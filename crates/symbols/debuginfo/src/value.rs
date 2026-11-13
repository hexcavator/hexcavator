//! Values, whatever the debug format: an object's bytes read as its type,
//! as a tree: a structure's bases and members (bitfields by their bits),
//! an array's elements, a pointer's address, an enum's enumerator, a
//! number. Bounded: so many elements per array, nodes in all, and levels
//! of nesting, so that a large or hostile input gives a short answer, not
//! a long one.
//!
//! Arrays of characters (of any width) and of single-byte integers read as
//! strings. (PDB's explicit `__int8` arrays read so too: its basic types
//! don't tell them from `signed char`.) A plain `char` reads as signed, as
//! MSVC's and x86's ABIs have it.

use crate::layout::PartKind;
use crate::{BasicType, DebugInfo, PointerKind, TypeRef, TypeShape};

/// What a value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueKind {
    /// A structure or class.
    Struct,
    /// A union.
    Union,
    /// An array.
    Array,
    /// A pointer or reference.
    Pointer,
    /// An enumeration's value.
    Enum,
    /// An integer.
    Integer,
    /// A floating-point number.
    Float,
    /// A character.
    Char,
    /// A `bool`.
    Bool,
    /// A base class's part of the object.
    Base,
    /// A virtual base class's part of the object.
    VirtualBase,
    /// The virtual function table pointer.
    VfPtr,
    /// The virtual base table pointer.
    VbPtr,
    /// Bytes that hold nothing (their contents in `text`).
    Padding,
    /// A type this doesn't read (a function's, one with no definition):
    /// its bytes in `text`.
    Unknown,
}

impl ValueKind {
    /// Its name, as reports print it.
    pub fn label(self) -> &'static str {
        match self {
            ValueKind::Struct => "struct",
            ValueKind::Union => "union",
            ValueKind::Array => "array",
            ValueKind::Pointer => "pointer",
            ValueKind::Enum => "enum",
            ValueKind::Integer => "integer",
            ValueKind::Float => "float",
            ValueKind::Char => "char",
            ValueKind::Bool => "bool",
            ValueKind::Base => "base",
            ValueKind::VirtualBase => "virtual base",
            ValueKind::VfPtr => "vfptr",
            ValueKind::VbPtr => "vbptr",
            ValueKind::Padding => "padding",
            ValueKind::Unknown => "unknown",
        }
    }
}

/// A value: its place in the object, its type, and what it holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    /// A member's name, an element's index (`[3]`), a base's type; empty
    /// for the object itself.
    pub name: String,
    /// Its type's name.
    pub type_name: String,
    /// What it is.
    pub kind: ValueKind,
    /// From the start of the object.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// A bitfield's first bit and its length.
    pub bits: Option<(u8, u8)>,
    /// What it holds, as text (empty for a structure; a character array's
    /// string).
    pub text: String,
    /// A pointer's address.
    pub pointer: Option<u64>,
    /// Its parts: members, elements, and bases.
    pub children: Vec<Value>,
    /// Elements (or members) not shown, past the limits.
    pub elided: u64,
}

/// How much to read.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Elements of an array.
    pub elements: usize,
    /// Values in all.
    pub nodes: usize,
    /// Levels of nesting.
    pub depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            elements: 256,
            nodes: 20_000,
            depth: 24,
        }
    }
}

/// Reads `bytes` (an object's, from its start) as type `ty`. Numbers are
/// little-endian.
pub fn read(debug: &DebugInfo<'_>, ty: TypeRef, bytes: &[u8], limits: Limits) -> Value {
    let mut r = Values {
        debug,
        bytes,
        limits,
        nodes: 0,
    };
    r.value(ty, 0, String::new(), 0)
}

struct Values<'d, 'a, 'b> {
    debug: &'d DebugInfo<'a>,
    bytes: &'b [u8],
    limits: Limits,
    nodes: usize,
}

/// A basic type's value kind, and whether it is signed.
fn class(kind: BasicType) -> Option<(ValueKind, bool)> {
    Some(match kind {
        BasicType::Int | BasicType::Long => (ValueKind::Integer, true),
        BasicType::UInt | BasicType::ULong | BasicType::HResult => (ValueKind::Integer, false),
        BasicType::Char => (ValueKind::Char, true),
        BasicType::WideChar | BasicType::Char8 | BasicType::Char16 | BasicType::Char32 => {
            (ValueKind::Char, false)
        }
        BasicType::Bool => (ValueKind::Bool, false),
        BasicType::Float => (ValueKind::Float, true),
        _ => return None,
    })
}

/// Whether arrays of a type of this shape read as strings.
fn is_char(shape: &TypeShape) -> bool {
    match *shape {
        TypeShape::Basic { kind, size } => match kind {
            BasicType::Char | BasicType::Char8 | BasicType::WideChar => true,
            BasicType::Char16 | BasicType::Char32 => true,
            BasicType::Int | BasicType::UInt => size == 1,
            _ => false,
        },
        _ => false,
    }
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// A float: plainly, or (very large or small) with an exponent.
fn float_text(x: f64) -> String {
    let m = x.abs();
    if x == 0.0 || !x.is_finite() || (1e-6..1e16).contains(&m) {
        format!("{x}")
    } else {
        format!("{x:e}")
    }
}

/// A character, quoted, if it prints.
fn char_text(c: u32) -> String {
    match char::from_u32(c) {
        Some('\0') => "0 '\\0'".to_string(),
        Some('\n') => "10 '\\n'".to_string(),
        Some(ch) if !ch.is_control() => format!("{c} '{ch}'"),
        _ => format!("{c}"),
    }
}

impl Values<'_, '_, '_> {
    fn slice(&self, offset: u64, size: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        self.bytes.get(start..end)
    }

    /// Little-endian, up to 8 bytes.
    fn uint(&self, offset: u64, size: u64) -> Option<u64> {
        let b = self.slice(offset, size.min(8))?;
        Some(b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
    }

    fn leaf(
        name: String,
        type_name: String,
        kind: ValueKind,
        offset: u64,
        size: u64,
        text: String,
    ) -> Value {
        Value {
            name,
            type_name,
            kind,
            offset,
            size,
            bits: None,
            text,
            pointer: None,
            children: Vec::new(),
            elided: 0,
        }
    }

    fn raw(
        &self,
        name: String,
        type_name: String,
        kind: ValueKind,
        offset: u64,
        size: u64,
    ) -> Value {
        let text = match self.slice(offset, size.min(64)) {
            Some(b) => hex_bytes(b) + if size > 64 { " …" } else { "" },
            None => "(beyond the data)".into(),
        };
        Self::leaf(name, type_name, kind, offset, size, text)
    }

    /// A number of a basic kind: its text.
    fn number(&self, kind: BasicType, offset: u64, size: u64) -> Option<(ValueKind, String)> {
        let (class, signed) = class(kind)?;
        // (Half and extended precision floats: their bytes.)
        if class == ValueKind::Float && size != 4 && size != 8 {
            return None;
        }
        let v = self.uint(offset, size)?;
        if size > 8 {
            return Some((
                class,
                format!(
                    "0x{}",
                    hex_bytes(self.slice(offset, size)?).replace(' ', "")
                ),
            ));
        }
        let sext = |v: u64| {
            if size == 0 {
                return 0;
            }
            let shift = 64 - size * 8;
            ((v << shift) as i64) >> shift
        };
        let text = match class {
            ValueKind::Integer if kind == BasicType::HResult => format!("{v:#010x}"),
            ValueKind::Integer if signed => sext(v).to_string(),
            ValueKind::Integer => v.to_string(),
            ValueKind::Char if signed => {
                let n = sext(v);
                if n >= 0 {
                    char_text(u32::try_from(n).unwrap_or(u32::MAX))
                } else {
                    n.to_string()
                }
            }
            ValueKind::Char => char_text(u32::try_from(v).unwrap_or(u32::MAX)),
            ValueKind::Bool => match v {
                0 => "false".into(),
                1 => "true".into(),
                n => format!("{n} (not 0 or 1)"),
            },
            ValueKind::Float if size == 4 => {
                float_text(f64::from(f32::from_bits(u32::try_from(v).unwrap_or(0))))
            }
            ValueKind::Float if size == 8 => float_text(f64::from_bits(v)),
            // (Half and extended precision: their bytes.)
            _ => return None,
        };
        Some((class, text))
    }

    fn value(&mut self, ty: TypeRef, offset: u64, name: String, depth: u32) -> Value {
        self.nodes += 1;
        let type_name = self.debug.type_name(ty);
        let size = self.debug.type_size(ty).unwrap_or(0);
        if depth > self.limits.depth || self.nodes > self.limits.nodes {
            let mut v = self.raw(name, type_name, ValueKind::Unknown, offset, size);
            v.text = format!("(not read: too deep or too many values) {}", v.text);
            return v;
        }
        let shape = self.debug.type_shape(ty);
        // (An array reads the elements there are; anything else, whole.)
        let array = matches!(shape, TypeShape::Array { .. });
        let within = usize::try_from(offset).is_ok_and(|o| o < self.bytes.len());
        if self.slice(offset, size).is_none() && !(array && within) {
            return Self::leaf(
                name,
                type_name,
                ValueKind::Unknown,
                offset,
                size,
                "(beyond the data)".into(),
            );
        }
        match shape {
            TypeShape::Basic { kind, .. } => match self.number(kind, offset, size) {
                Some((kind, text)) => Self::leaf(name, type_name, kind, offset, size, text),
                None => self.raw(name, type_name, ValueKind::Unknown, offset, size),
            },
            TypeShape::Modified { base, .. } => {
                // (A level deeper: a modifier can name itself.)
                let mut v = self.value(base, offset, name, depth + 1);
                v.type_name = type_name;
                v
            }
            // Pointers to members are offsets (or more), not addresses.
            TypeShape::Pointer {
                kind: PointerKind::Member,
                ..
            } => self.raw(name, type_name, ValueKind::Integer, offset, size),
            TypeShape::Pointer { .. } => self.pointer(name, type_name, offset, size),
            TypeShape::Array { element, .. } => {
                self.array(element, name, type_name, offset, size, depth)
            }
            TypeShape::Enum { .. } => self.enumeration(ty, name, type_name, offset, size),
            TypeShape::Udt { .. } => self.compound(ty, name, type_name, offset, size, depth),
            _ => self.raw(name, type_name, ValueKind::Unknown, offset, size),
        }
    }

    fn pointer(&self, name: String, type_name: String, offset: u64, size: u64) -> Value {
        let Some(p) = self.uint(offset, size) else {
            return self.raw(name, type_name, ValueKind::Pointer, offset, size);
        };
        let mut v = Self::leaf(
            name,
            type_name,
            ValueKind::Pointer,
            offset,
            size,
            if p == 0 {
                "nullptr".into()
            } else {
                format!("{p:#x}")
            },
        );
        v.pointer = (p != 0).then_some(p);
        v
    }

    fn array(
        &mut self,
        elem: TypeRef,
        name: String,
        type_name: String,
        offset: u64,
        size: u64,
        depth: u32,
    ) -> Value {
        let elem_size = self.debug.type_size(elem).unwrap_or(0);
        let mut v = Self::leaf(
            name,
            type_name,
            ValueKind::Array,
            offset,
            size,
            String::new(),
        );
        if elem_size == 0 {
            v.text = self
                .raw(
                    String::new(),
                    String::new(),
                    ValueKind::Unknown,
                    offset,
                    size,
                )
                .text;
            return v;
        }
        let count = size / elem_size;
        // Those in the data (a vtable's type may count more slots than the
        // image has).
        let there = (self.bytes.len() as u64).saturating_sub(offset) / elem_size;
        if there < count {
            v.text = format!("({there} of {count} elements in the data)");
        }
        let count = count.min(there);
        // Characters: the string, up to its terminator.
        let elem_shape = self.debug.type_shape(elem);
        let chars = match elem_shape {
            TypeShape::Modified { base, .. } => is_char(&self.debug.type_shape(base)),
            ref s => is_char(s),
        };
        if chars && elem_size <= 4 {
            let mut s = String::new();
            for i in 0..count {
                let Some(c) = self.uint(offset + i * elem_size, elem_size) else {
                    break;
                };
                if c == 0 {
                    break;
                }
                match char::from_u32(u32::try_from(c).unwrap_or(u32::MAX)) {
                    Some(ch) if !ch.is_control() => s.push(ch),
                    Some('\n') => s.push_str("\\n"),
                    Some('\t') => s.push_str("\\t"),
                    _ => s.push_str(&format!("\\x{c:02x}")),
                }
                if s.len() > 512 {
                    s.push('…');
                    break;
                }
            }
            v.text = format!("\"{s}\"");
        }
        let shown = count.min(self.limits.elements as u64);
        for i in 0..shown {
            if self.nodes > self.limits.nodes {
                v.elided = count - i;
                return v;
            }
            let e = self.value(elem, offset + i * elem_size, format!("[{i}]"), depth + 1);
            v.children.push(e);
        }
        v.elided = count - shown;
        v
    }

    fn enumeration(
        &self,
        ty: TypeRef,
        name: String,
        type_name: String,
        offset: u64,
        size: u64,
    ) -> Value {
        let Some(e) = self.debug.enumerators(ty) else {
            return self.raw(name, type_name, ValueKind::Enum, offset, size);
        };
        let Some(raw) = self.uint(offset, size) else {
            return self.raw(name, type_name, ValueKind::Enum, offset, size);
        };
        let v = if e.signed && size > 0 && size < 8 {
            let shift = 64 - size * 8;
            (((raw << shift) as i64) >> shift) as u64
        } else {
            raw
        };
        // (An enumerator's value as the same width: a narrow enum's
        // negative enumerators are recorded sign-extended, or not.)
        let mask = if size == 0 || size >= 8 {
            u64::MAX
        } else {
            (1u64 << (size * 8)) - 1
        };
        let names: Vec<&str> = e
            .values
            .iter()
            .filter(|(_, x)| *x == v || (*x & mask) == (v & mask))
            .map(|(n, _)| n.as_str())
            .collect();
        let number = if e.signed {
            (v as i64).to_string()
        } else {
            v.to_string()
        };
        let text = match names.first() {
            Some(n) => format!("{n} ({number})"),
            None => number,
        };
        Self::leaf(name, type_name, ValueKind::Enum, offset, size, text)
    }

    fn compound(
        &mut self,
        ty: TypeRef,
        name: String,
        type_name: String,
        offset: u64,
        size: u64,
        depth: u32,
    ) -> Value {
        let Some(l) = self.debug.layout(ty) else {
            return self.raw(name, type_name, ValueKind::Unknown, offset, size);
        };
        let kind = if l.union {
            ValueKind::Union
        } else {
            ValueKind::Struct
        };
        let mut v = Self::leaf(name, type_name, kind, offset, size, String::new());
        for p in &l.parts {
            if self.nodes > self.limits.nodes {
                v.elided += 1;
                continue;
            }
            let at = offset.saturating_add(p.offset);
            let child = match p.kind {
                PartKind::Base | PartKind::VirtualBase => {
                    let mut c = self.value(p.ty, at, p.type_name.clone(), depth + 1);
                    c.kind = if p.kind == PartKind::Base {
                        ValueKind::Base
                    } else {
                        ValueKind::VirtualBase
                    };
                    c
                }
                PartKind::VfPtr | PartKind::VbPtr => {
                    self.nodes += 1;
                    let mut c = self.pointer(p.kind.label().into(), String::new(), at, p.size);
                    c.kind = if p.kind == PartKind::VfPtr {
                        ValueKind::VfPtr
                    } else {
                        ValueKind::VbPtr
                    };
                    c
                }
                PartKind::Member => match p.bits {
                    Some((pos, len)) => {
                        self.nodes += 1;
                        let unit = self.uint(at, p.size).unwrap_or(0);
                        let bits = if len >= 64 {
                            unit
                        } else {
                            unit.checked_shr(u32::from(pos)).unwrap_or(0) & ((1u64 << len) - 1)
                        };
                        let mut c = Self::leaf(
                            p.name.clone(),
                            p.type_name.clone(),
                            ValueKind::Integer,
                            at,
                            p.size,
                            bits.to_string(),
                        );
                        if matches!(
                            self.debug.type_shape(p.ty),
                            TypeShape::Basic {
                                kind: BasicType::Bool,
                                ..
                            }
                        ) {
                            c.kind = ValueKind::Bool;
                            c.text = if bits == 0 { "false" } else { "true" }.into();
                        }
                        c.bits = Some((pos, len));
                        c
                    }
                    None => self.value(p.ty, at, p.name.clone(), depth + 1),
                },
                PartKind::Padding | PartKind::TailPadding => {
                    self.nodes += 1;
                    self.raw(String::new(), String::new(), ValueKind::Padding, at, p.size)
                }
                _ => continue,
            };
            v.children.push(child);
        }
        v
    }
}

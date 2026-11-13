//! Types, from DWARF's type DIEs: their shapes, sizes, and the classes
//! with their bases and methods.
//!
//! Typedefs are looked through (as PDB type references have no typedefs
//! in them): a typedef's shape and size are its type's.

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Die, Unit};

use super::{DwarfInfo, MAX_CHAIN, VOID};
use crate::{BasicType, Class, Method, MethodKind, PointerKind, Qualifiers, TypeRef, TypeShape};

/// The most array dimensions read.
const MAX_DIMENSIONS: usize = 32;

impl DwarfInfo<'_> {
    /// `r`, past typedefs (and, if `qualifiers`, qualifiers, which are
    /// gathered there).
    pub(super) fn through(&self, r: TypeRef, mut qualifiers: Option<&mut Qualifiers>) -> TypeRef {
        let mut at = r;
        for _ in 0..MAX_CHAIN {
            let Some((u, _, d)) = self.die(at) else {
                return at;
            };
            let q = qualifiers.as_deref_mut();
            match (d.tag, q) {
                (DW_TAG_TYPEDEF, _) => at = self.type_of(&u, &d),
                (DW_TAG_CONST_TYPE, Some(q)) => {
                    q.is_const = true;
                    at = self.type_of(&u, &d);
                }
                (DW_TAG_VOLATILE_TYPE, Some(q)) => {
                    q.is_volatile = true;
                    at = self.type_of(&u, &d);
                }
                (DW_TAG_RESTRICT_TYPE, Some(q)) => {
                    q.is_restrict = true;
                    at = self.type_of(&u, &d);
                }
                // A declaration whose definition is a type unit's.
                (
                    DW_TAG_STRUCTURE_TYPE
                    | DW_TAG_CLASS_TYPE
                    | DW_TAG_UNION_TYPE
                    | DW_TAG_ENUMERATION_TYPE,
                    _,
                ) if d.flag(DW_AT_DECLARATION) => {
                    match d.attr(DW_AT_SIGNATURE).and_then(|a| self.reference(&u, a)) {
                        Some(def) if def != at => at = def,
                        _ => return at,
                    }
                }
                _ => return at,
            }
        }
        at
    }

    /// The structure of type `ty` (see [`crate::DebugInfo::type_shape`]).
    pub fn type_shape(&self, ty: TypeRef) -> TypeShape {
        if ty == VOID {
            return TypeShape::Basic {
                kind: BasicType::Void,
                size: 0,
            };
        }
        let mut qualifiers = Qualifiers::default();
        let at = self.through(ty, Some(&mut qualifiers));
        if qualifiers != Qualifiers::default() {
            return TypeShape::Modified {
                base: self.through(at, None),
                qualifiers,
            };
        }
        if at == VOID {
            return self.type_shape(VOID);
        }
        let Some((mut u, mut a, mut d)) = self.die(at) else {
            return TypeShape::Unknown;
        };
        // An out-of-line or concrete copy of a function: its declaration
        // (in whichever unit) has its type.
        if d.tag == DW_TAG_SUBPROGRAM && d.attr(DW_AT_TYPE).is_none() {
            let (decl, _) = self.origin(at);
            if let Some(o) = self.die(decl).filter(|_| decl != at) {
                (u, a, d) = o;
            }
        }
        let pointer = |kind| TypeShape::Pointer {
            target: self.type_of(&u, &d),
            kind,
            qualifiers: Qualifiers::default(),
            size: Self::uint(&u, &d, DW_AT_BYTE_SIZE).unwrap_or(u64::from(u.address_size)),
        };
        match d.tag {
            DW_TAG_BASE_TYPE => {
                let size = Self::uint(&u, &d, DW_AT_BYTE_SIZE).unwrap_or(0);
                let name = Self::string(&u, &d, DW_AT_NAME).unwrap_or_default();
                let encoding = Self::uint(&u, &d, DW_AT_ENCODING).unwrap_or(0);
                TypeShape::Basic {
                    kind: basic(encoding, &name, size),
                    size,
                }
            }
            DW_TAG_UNSPECIFIED_TYPE => {
                // `decltype(nullptr)`, and `void` as some producers say it.
                let name = Self::string(&u, &d, DW_AT_NAME).unwrap_or_default();
                if name == "void" {
                    self.type_shape(VOID)
                } else {
                    TypeShape::Udt { name }
                }
            }
            DW_TAG_POINTER_TYPE => pointer(PointerKind::Pointer),
            DW_TAG_REFERENCE_TYPE => pointer(PointerKind::LValueReference),
            DW_TAG_RVALUE_REFERENCE_TYPE => pointer(PointerKind::RValueReference),
            DW_TAG_PTR_TO_MEMBER_TYPE => pointer(PointerKind::Member),
            DW_TAG_STRUCTURE_TYPE
            | DW_TAG_CLASS_TYPE
            | DW_TAG_UNION_TYPE
            | DW_TAG_INTERFACE_TYPE => TypeShape::Udt {
                name: self.qualified_name(at),
            },
            DW_TAG_ENUMERATION_TYPE => TypeShape::Enum {
                name: self.qualified_name(at),
            },
            DW_TAG_ARRAY_TYPE => TypeShape::Array {
                element: self.type_of(&u, &d),
                size: self.array_size(&u, &d).unwrap_or(0),
            },
            DW_TAG_SUBROUTINE_TYPE | DW_TAG_SUBPROGRAM => {
                let mut args = Vec::new();
                let mut class = None;
                let mut this_qualifiers = None;
                for c in u.children(a, &d) {
                    match c.tag {
                        DW_TAG_FORMAL_PARAMETER if c.flag(DW_AT_ARTIFICIAL) && class.is_none() => {
                            // `this`: a pointer to the (qualified) class.
                            let mut q = Qualifiers::default();
                            let pointee = match self.type_shape(self.type_of(&u, &c)) {
                                TypeShape::Pointer { target, .. } => {
                                    self.through(target, Some(&mut q))
                                }
                                _ => TypeRef(0),
                            };
                            class = Some(pointee);
                            this_qualifiers = Some(q);
                        }
                        DW_TAG_FORMAL_PARAMETER => args.push(self.type_of(&u, &c)),
                        // `...`.
                        DW_TAG_UNSPECIFIED_PARAMETERS => args.push(TypeRef(0)),
                        _ => {}
                    }
                }
                TypeShape::Function {
                    ret: self.type_of(&u, &d),
                    args,
                    class,
                    this_qualifiers,
                }
            }
            _ => TypeShape::Unknown,
        }
    }

    /// An array's size: its byte size, or its element's times its
    /// dimensions'.
    fn array_size(&self, u: &Unit<'_>, d: &Die<'_>) -> Option<u64> {
        if let Some(n) = Self::uint(u, d, DW_AT_BYTE_SIZE) {
            return Some(n);
        }
        let element = self.type_size(self.type_of(u, d))?;
        element.checked_mul(self.array_count(u, d)?)
    }

    /// How many elements an array has: the product of its dimensions.
    fn array_count(&self, u: &Unit<'_>, d: &Die<'_>) -> Option<u64> {
        let a = self.abbrevs_of(u)?;
        let mut size = 1u64;
        for (i, c) in u.children(a, d).iter().enumerate() {
            if i >= MAX_DIMENSIONS {
                return None;
            }
            if c.tag != DW_TAG_SUBRANGE_TYPE && c.tag != DW_TAG_ENUMERATION_TYPE {
                continue;
            }
            let count = match Self::uint(u, c, DW_AT_COUNT) {
                Some(n) => n,
                None => {
                    // (A bound that isn't a constant, a VLA's, is unknown.)
                    let upper = Self::uint(u, c, DW_AT_UPPER_BOUND)?;
                    let lower = Self::uint(u, c, DW_AT_LOWER_BOUND).unwrap_or(0);
                    upper.checked_sub(lower)?.checked_add(1)?
                }
            };
            size = size.checked_mul(count)?;
        }
        Some(size)
    }

    /// The size of type `ty` in bytes, if it has one. (An array without a
    /// byte size is its element's size times its count: the element type
    /// is followed in a loop, at most `MAX_CHAIN` arrays deep, so an
    /// array of itself ends.)
    pub fn type_size(&self, ty: TypeRef) -> Option<u64> {
        let mut ty = ty;
        let mut count = 1u64;
        for _ in 0..MAX_CHAIN {
            let mut qualifiers = Qualifiers::default();
            let at = self.through(ty, Some(&mut qualifiers));
            if at == VOID {
                return None;
            }
            let (u, _, d) = self.die(at)?;
            if let Some(n) = Self::uint(&u, &d, DW_AT_BYTE_SIZE) {
                return n.checked_mul(count);
            }
            return match d.tag {
                DW_TAG_POINTER_TYPE
                | DW_TAG_REFERENCE_TYPE
                | DW_TAG_RVALUE_REFERENCE_TYPE
                | DW_TAG_PTR_TO_MEMBER_TYPE => u64::from(u.address_size).checked_mul(count),
                DW_TAG_ARRAY_TYPE => {
                    count = count.checked_mul(self.array_count(&u, &d)?)?;
                    ty = self.type_of(&u, &d);
                    continue;
                }
                _ => None,
            };
        }
        None
    }

    /// The class definitions (see [`crate::DebugInfo::classes`]).
    pub fn classes(&self) -> Result<Vec<Class>, hexcavator_core::Error> {
        let mut out = Vec::new();
        self.walk(|w| {
            let d = w.die;
            if !matches!(
                d.tag,
                DW_TAG_CLASS_TYPE | DW_TAG_STRUCTURE_TYPE | DW_TAG_INTERFACE_TYPE
            ) || d.flag(DW_AT_DECLARATION)
            {
                return super::Walk::Into;
            }
            let u = w.unit;
            let Some(a) = self.abbrevs_of(u) else {
                return super::Walk::Into;
            };
            let mut class = Class {
                name: self.qualified_name(w.at),
                ty: w.at,
                bases: Vec::new(),
                methods: Vec::new(),
            };
            for c in u.children(a, d) {
                match c.tag {
                    DW_TAG_INHERITANCE => {
                        class.bases.push(self.through(self.type_of(u, &c), None));
                    }
                    DW_TAG_SUBPROGRAM => {
                        let at = super::to_ref(u.source, u.section, c.offset);
                        let virtuality =
                            Self::uint(u, &c, DW_AT_VIRTUALITY).and_then(|v| u8::try_from(v).ok());
                        let kind = match virtuality {
                            Some(DW_VIRTUALITY_PURE_VIRTUAL) => MethodKind::PureVirtual,
                            Some(DW_VIRTUALITY_VIRTUAL) => MethodKind::Virtual,
                            _ if self.is_static(u, &c) => MethodKind::Static,
                            _ => MethodKind::Plain,
                        };
                        class.methods.push(Method {
                            name: Self::string(u, &c, DW_AT_NAME).unwrap_or_default(),
                            ty: at,
                            kind,
                        });
                    }
                    _ => {}
                }
            }
            out.push(class);
            super::Walk::Into
        });
        Ok(out)
    }

    /// Whether a member function is static: it has no `this`.
    fn is_static(&self, u: &Unit<'_>, d: &Die<'_>) -> bool {
        if d.attr(DW_AT_OBJECT_POINTER).is_some() {
            return false;
        }
        let Some(a) = self.abbrevs_of(u) else {
            return false;
        };
        !u.children(a, d)
            .iter()
            .any(|c| c.tag == DW_TAG_FORMAL_PARAMETER && c.flag(DW_AT_ARTIFICIAL))
    }
}

/// A base type's kind, by its encoding (and, for the character and wide
/// character types, its name).
fn basic(encoding: u64, name: &str, size: u64) -> BasicType {
    let encoding = u8::try_from(encoding).unwrap_or(0);
    match encoding {
        DW_ATE_BOOLEAN => BasicType::Bool,
        DW_ATE_FLOAT | DW_ATE_COMPLEX_FLOAT | DW_ATE_IMAGINARY_FLOAT | DW_ATE_DECIMAL_FLOAT => {
            BasicType::Float
        }
        _ if name == "wchar_t" => BasicType::WideChar,
        _ if name == "char" => BasicType::Char,
        DW_ATE_UTF | DW_ATE_UCS | DW_ATE_ASCII => match size {
            1 => BasicType::Char8,
            2 => BasicType::Char16,
            _ => BasicType::Char32,
        },
        DW_ATE_SIGNED | DW_ATE_SIGNED_CHAR | DW_ATE_SIGNED_FIXED => BasicType::Int,
        DW_ATE_UNSIGNED | DW_ATE_UNSIGNED_CHAR | DW_ATE_UNSIGNED_FIXED | DW_ATE_ADDRESS => {
            BasicType::UInt
        }
        _ => BasicType::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_types_by_encoding_and_name() {
        assert_eq!(basic(u64::from(DW_ATE_SIGNED), "int", 4), BasicType::Int);
        assert_eq!(
            basic(u64::from(DW_ATE_UNSIGNED), "unsigned long", 8),
            BasicType::UInt
        );
        assert_eq!(
            basic(u64::from(DW_ATE_SIGNED_CHAR), "char", 1),
            BasicType::Char
        );
        // Arm's char is unsigned; it is still char.
        assert_eq!(
            basic(u64::from(DW_ATE_UNSIGNED_CHAR), "char", 1),
            BasicType::Char
        );
        assert_eq!(
            basic(u64::from(DW_ATE_SIGNED_CHAR), "signed char", 1),
            BasicType::Int
        );
        assert_eq!(
            basic(u64::from(DW_ATE_UNSIGNED_CHAR), "unsigned char", 1),
            BasicType::UInt
        );
        assert_eq!(
            basic(u64::from(DW_ATE_SIGNED), "wchar_t", 4),
            BasicType::WideChar
        );
        assert_eq!(basic(u64::from(DW_ATE_UTF), "char8_t", 1), BasicType::Char8);
        assert_eq!(
            basic(u64::from(DW_ATE_UTF), "char16_t", 2),
            BasicType::Char16
        );
        assert_eq!(
            basic(u64::from(DW_ATE_UTF), "char32_t", 4),
            BasicType::Char32
        );
        assert_eq!(basic(u64::from(DW_ATE_BOOLEAN), "bool", 1), BasicType::Bool);
        assert_eq!(
            basic(u64::from(DW_ATE_FLOAT), "double", 8),
            BasicType::Float
        );
        assert_eq!(basic(0x99, "?", 4), BasicType::None);
        assert_eq!(basic(u64::MAX, "?", 4), BasicType::None);
    }
}

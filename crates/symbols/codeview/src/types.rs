//! CodeView type records (leaves).

use hexcavator_core::{Reader, Result};

/// A type index. Values below `0x1000` are built-in (simple) types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeIndex(pub u32);

impl TypeIndex {
    /// The first index of a type record (`CV_FIRST_NONPRIM`); those below
    /// are simple types (see [`simple`]).
    pub const FIRST_NON_SIMPLE: u32 = 0x1000;

    #[inline]
    pub fn is_simple(self) -> bool {
        self.0 < Self::FIRST_NON_SIMPLE
    }
}

/// Where type records come from: a PDB's TPI or IPI stream, or a COFF
/// object's `.debug$T` section.
pub trait TypeSource {
    /// The record with index `ti`.
    fn record(&self, ti: TypeIndex) -> Option<TypeRecord<'_>>;

    /// The definition a forward reference stands for (by unique name, or
    /// name), as debuggers resolve them; `ti` if there is none.
    fn resolve_forward(&self, ti: TypeIndex) -> TypeIndex {
        ti
    }

    /// Every record, in index order.
    fn records(&self) -> Box<dyn Iterator<Item = (TypeIndex, TypeRecord<'_>)> + '_>;
}

/// Simple (built-in) types, as cvinfo.h defines them: a type index below
/// [`TypeIndex::FIRST_NON_SIMPLE`] is a kind (`CV_TMASK | CV_SMASK`: a
/// `T_*` value) and a pointer mode (`CV_MMASK`: `CV_TM_*`).
#[allow(missing_docs)]
pub mod simple {
    pub const CV_SMASK: u32 = 0x000F;
    pub const CV_TMASK: u32 = 0x00F0;
    pub const CV_MMASK: u32 = 0x0700;
    pub const CV_MSHIFT: u32 = 8;
    /// The layout's reserved bit above the mode (`r mode type r sub`).
    pub const CV_RESERVED: u32 = 0x0800;

    /// Whether a simple type index is well formed: its reserved bit is
    /// clear.
    pub const fn is_valid(ti: u32) -> bool {
        ti & CV_RESERVED == 0
    }

    /// A simple type index's kind: its `T_*` value without a mode.
    pub const fn kind(ti: u32) -> u32 {
        ti & (CV_TMASK | CV_SMASK)
    }

    /// A simple type index's pointer mode (`CV_MODE`).
    pub const fn mode(ti: u32) -> u32 {
        (ti & CV_MMASK) >> CV_MSHIFT
    }

    // Pointer modes (`CV_prmode_e`).
    pub const CV_TM_DIRECT: u32 = 0;
    pub const CV_TM_NPTR: u32 = 1;
    pub const CV_TM_FPTR: u32 = 2;
    pub const CV_TM_HPTR: u32 = 3;
    pub const CV_TM_NPTR32: u32 = 4;
    pub const CV_TM_FPTR32: u32 = 5;
    pub const CV_TM_NPTR64: u32 = 6;
    pub const CV_TM_NPTR128: u32 = 7;

    // Kinds (`T_*`).
    pub const T_NOTYPE: u32 = 0x0000;
    pub const T_VOID: u32 = 0x0003;
    pub const T_HRESULT: u32 = 0x0008;
    pub const T_CHAR: u32 = 0x0010;
    pub const T_UCHAR: u32 = 0x0020;
    pub const T_RCHAR: u32 = 0x0070;
    pub const T_WCHAR: u32 = 0x0071;
    pub const T_CHAR16: u32 = 0x007A;
    pub const T_CHAR32: u32 = 0x007B;
    /// `char8_t` (newer than the published cvinfo.h).
    pub const T_CHAR8: u32 = 0x007C;
    pub const T_INT1: u32 = 0x0068;
    pub const T_UINT1: u32 = 0x0069;
    pub const T_SHORT: u32 = 0x0011;
    pub const T_USHORT: u32 = 0x0021;
    pub const T_INT2: u32 = 0x0072;
    pub const T_UINT2: u32 = 0x0073;
    pub const T_LONG: u32 = 0x0012;
    pub const T_ULONG: u32 = 0x0022;
    pub const T_INT4: u32 = 0x0074;
    pub const T_UINT4: u32 = 0x0075;
    pub const T_QUAD: u32 = 0x0013;
    pub const T_UQUAD: u32 = 0x0023;
    pub const T_INT8: u32 = 0x0076;
    pub const T_UINT8: u32 = 0x0077;
    pub const T_OCT: u32 = 0x0014;
    pub const T_UOCT: u32 = 0x0024;
    pub const T_INT16: u32 = 0x0078;
    pub const T_UINT16: u32 = 0x0079;
    pub const T_REAL16: u32 = 0x0046;
    pub const T_REAL32: u32 = 0x0040;
    pub const T_REAL64: u32 = 0x0041;
    pub const T_REAL80: u32 = 0x0042;
    pub const T_REAL128: u32 = 0x0043;
    pub const T_BOOL08: u32 = 0x0030;
    pub const T_BOOL16: u32 = 0x0031;
    pub const T_BOOL32: u32 = 0x0032;
    pub const T_BOOL64: u32 = 0x0033;
    pub const T_CPLX32: u32 = 0x0050;
    pub const T_CPLX64: u32 = 0x0051;
    pub const T_BIT: u32 = 0x0060;
}

/// `lfPointer`'s attributes (`lfPointerAttr`): bit fields.
#[allow(missing_docs)]
pub mod pointer {
    /// `ptrmode`: bits 5-7.
    pub const PTRMODE_SHIFT: u32 = 5;
    pub const PTRMODE_MASK: u32 = 0x7;
    /// `isvolatile`.
    pub const ISVOLATILE: u32 = 1 << 9;
    /// `isconst`.
    pub const ISCONST: u32 = 1 << 10;
    /// `isunaligned`.
    pub const ISUNALIGNED: u32 = 1 << 11;
    /// `isrestrict`.
    pub const ISRESTRICT: u32 = 1 << 12;
    /// `size`: bits 13-18, the pointer's size in bytes.
    pub const SIZE_SHIFT: u32 = 13;
    pub const SIZE_MASK: u32 = 0x3F;

    // Pointer modes (`CV_ptrmode_e`).
    pub const CV_PTR_MODE_PTR: u32 = 0x00;
    pub const CV_PTR_MODE_LVREF: u32 = 0x01;
    pub const CV_PTR_MODE_PMEM: u32 = 0x02;
    pub const CV_PTR_MODE_PMFUNC: u32 = 0x03;
    pub const CV_PTR_MODE_RVREF: u32 = 0x04;
}

/// `lfModifier`'s attributes (`CV_modifier_t`).
#[allow(missing_docs)]
pub mod modifier {
    pub const MOD_CONST: u16 = 0x0001;
    pub const MOD_VOLATILE: u16 = 0x0002;
    pub const MOD_UNALIGNED: u16 = 0x0004;
}

/// Field attributes (`CV_fldattr_t`).
#[allow(missing_docs)]
pub mod field_attr {
    /// `mprop`: bits 2-4.
    pub const MPROP_SHIFT: u16 = 2;
    pub const MPROP_MASK: u16 = 0x7;

    // Method properties (`CV_methodprop_e`).
    pub const CV_MTVANILLA: u16 = 0x00;
    pub const CV_MTVIRTUAL: u16 = 0x01;
    pub const CV_MTSTATIC: u16 = 0x02;
    pub const CV_MTFRIEND: u16 = 0x03;
    pub const CV_MTINTRO: u16 = 0x04;
    pub const CV_MTPUREVIRT: u16 = 0x05;
    pub const CV_MTPUREINTRO: u16 = 0x06;
}

/// Leaf kinds.
#[allow(missing_docs)]
pub mod leaf {
    /// The first padding byte between fields (`LF_PAD0`; up to `LF_PAD15`).
    pub const LF_PAD0: u16 = 0xF0;
    pub const LF_VTSHAPE: u16 = 0x000A;
    pub const LF_LABEL: u16 = 0x000E;
    pub const LF_ENDPRECOMP: u16 = 0x0014;
    pub const LF_MODIFIER: u16 = 0x1001;
    pub const LF_POINTER: u16 = 0x1002;
    pub const LF_PROCEDURE: u16 = 0x1008;
    pub const LF_MFUNCTION: u16 = 0x1009;
    pub const LF_ARGLIST: u16 = 0x1201;
    pub const LF_FIELDLIST: u16 = 0x1203;
    pub const LF_BITFIELD: u16 = 0x1205;
    pub const LF_METHODLIST: u16 = 0x1206;
    pub const LF_BCLASS: u16 = 0x1400;
    pub const LF_VBCLASS: u16 = 0x1401;
    pub const LF_IVBCLASS: u16 = 0x1402;
    pub const LF_INDEX: u16 = 0x1404;
    pub const LF_VFUNCTAB: u16 = 0x1409;
    pub const LF_ENUMERATE: u16 = 0x1502;
    pub const LF_ARRAY: u16 = 0x1503;
    pub const LF_CLASS: u16 = 0x1504;
    pub const LF_STRUCTURE: u16 = 0x1505;
    pub const LF_UNION: u16 = 0x1506;
    pub const LF_ENUM: u16 = 0x1507;
    pub const LF_PRECOMP: u16 = 0x1509;
    pub const LF_MEMBER: u16 = 0x150D;
    pub const LF_STMEMBER: u16 = 0x150E;
    pub const LF_METHOD: u16 = 0x150F;
    pub const LF_NESTTYPE: u16 = 0x1510;
    pub const LF_ONEMETHOD: u16 = 0x1511;
    pub const LF_TYPESERVER2: u16 = 0x1515;
    pub const LF_INTERFACE: u16 = 0x1519;
    pub const LF_BINTERFACE: u16 = 0x151A;
    /// The `...2` forms (MSVC 17.x) have a 32-bit property field.
    pub const LF_CLASS2: u16 = 0x1608;
    pub const LF_STRUCTURE2: u16 = 0x1609;
    pub const LF_UNION2: u16 = 0x160A;
    pub const LF_INTERFACE2: u16 = 0x160B;

    /// Classes, structures, and interfaces (in either form).
    pub fn is_class(kind: u16) -> bool {
        matches!(
            kind,
            LF_CLASS | LF_STRUCTURE | LF_INTERFACE | LF_CLASS2 | LF_STRUCTURE2 | LF_INTERFACE2
        )
    }

    /// Unions (in either form).
    pub fn is_union(kind: u16) -> bool {
        matches!(kind, LF_UNION | LF_UNION2)
    }

    /// Records a forward reference and its definition can both be: the
    /// same family, whichever form each uses (`LF_CLASS` and `LF_CLASS2`).
    pub fn same_udt_family(a: u16, b: u16) -> bool {
        let family = |k: u16| match k {
            LF_CLASS | LF_CLASS2 => 1,
            LF_STRUCTURE | LF_STRUCTURE2 => 2,
            LF_INTERFACE | LF_INTERFACE2 => 3,
            LF_UNION | LF_UNION2 => 4,
            LF_ENUM => 5,
            _ => 0,
        };
        family(a) != 0 && family(a) == family(b)
    }
    pub const LF_VFTABLE: u16 = 0x151D;
    pub const LF_FUNC_ID: u16 = 0x1601;
    pub const LF_MFUNC_ID: u16 = 0x1602;
    pub const LF_BUILDINFO: u16 = 0x1603;
    pub const LF_SUBSTR_LIST: u16 = 0x1604;
    pub const LF_STRING_ID: u16 = 0x1605;
    pub const LF_UDT_SRC_LINE: u16 = 0x1606;
    pub const LF_UDT_MOD_SRC_LINE: u16 = 0x1607;
    pub const LF_NUMERIC: u16 = 0x8000;
    pub const LF_CHAR: u16 = 0x8000;
    pub const LF_SHORT: u16 = 0x8001;
    pub const LF_USHORT: u16 = 0x8002;
    pub const LF_LONG: u16 = 0x8003;
    pub const LF_ULONG: u16 = 0x8004;
    pub const LF_REAL32: u16 = 0x8005;
    pub const LF_REAL64: u16 = 0x8006;
    pub const LF_REAL80: u16 = 0x8007;
    pub const LF_REAL128: u16 = 0x8008;
    pub const LF_QUADWORD: u16 = 0x8009;
    pub const LF_UQUADWORD: u16 = 0x800A;
    pub const LF_REAL48: u16 = 0x800B;
    pub const LF_VARSTRING: u16 = 0x8010;
    pub const LF_OCTWORD: u16 = 0x8017;
    pub const LF_UOCTWORD: u16 = 0x8018;
    pub const LF_UTF8STRING: u16 = 0x801B;
    pub const LF_REAL16: u16 = 0x801C;

    /// A short name for a leaf kind.
    pub fn name(kind: u16) -> &'static str {
        match kind {
            LF_VTSHAPE => "LF_VTSHAPE",
            LF_LABEL => "LF_LABEL",
            LF_MODIFIER => "LF_MODIFIER",
            LF_POINTER => "LF_POINTER",
            LF_PROCEDURE => "LF_PROCEDURE",
            LF_MFUNCTION => "LF_MFUNCTION",
            LF_ARGLIST => "LF_ARGLIST",
            LF_FIELDLIST => "LF_FIELDLIST",
            LF_BITFIELD => "LF_BITFIELD",
            LF_METHODLIST => "LF_METHODLIST",
            LF_ARRAY => "LF_ARRAY",
            LF_CLASS => "LF_CLASS",
            LF_STRUCTURE => "LF_STRUCTURE",
            LF_UNION => "LF_UNION",
            LF_ENUM => "LF_ENUM",
            LF_INTERFACE => "LF_INTERFACE",
            LF_CLASS2 => "LF_CLASS2",
            LF_STRUCTURE2 => "LF_STRUCTURE2",
            LF_UNION2 => "LF_UNION2",
            LF_INTERFACE2 => "LF_INTERFACE2",
            LF_VFTABLE => "LF_VFTABLE",
            LF_PRECOMP => "LF_PRECOMP",
            LF_ENDPRECOMP => "LF_ENDPRECOMP",
            LF_TYPESERVER2 => "LF_TYPESERVER2",
            LF_FUNC_ID => "LF_FUNC_ID",
            LF_MFUNC_ID => "LF_MFUNC_ID",
            LF_BUILDINFO => "LF_BUILDINFO",
            LF_SUBSTR_LIST => "LF_SUBSTR_LIST",
            LF_STRING_ID => "LF_STRING_ID",
            LF_UDT_SRC_LINE => "LF_UDT_SRC_LINE",
            LF_UDT_MOD_SRC_LINE => "LF_UDT_MOD_SRC_LINE",
            _ => "LF_???",
        }
    }
}

/// `CV_prop_t`: properties of a user-defined type.
pub mod prop {
    pub const PACKED: u16 = 0x0001;
    pub const CTOR: u16 = 0x0002;
    pub const OVLOPS: u16 = 0x0004;
    pub const IS_NESTED: u16 = 0x0008;
    pub const CNESTED: u16 = 0x0010;
    pub const OPASSIGN: u16 = 0x0020;
    pub const OPCAST: u16 = 0x0040;
    pub const FWDREF: u16 = 0x0080;
    pub const SCOPED: u16 = 0x0100;
    pub const HAS_UNIQUE_NAME: u16 = 0x0200;
    pub const SEALED: u16 = 0x0400;
    pub const INTRINSIC: u16 = 0x2000;
}

/// A type or id record: its kind and the bytes after the kind.
#[derive(Clone, Copy, Debug)]
pub struct TypeRecord<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}

/// A numeric leaf value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Numeric {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    /// A value kind we do not decode (shown as raw).
    Other(u16),
}

impl Numeric {
    pub fn as_u64(self) -> u64 {
        match self {
            Numeric::Signed(v) => v as u64,
            Numeric::Unsigned(v) => v,
            Numeric::Float(f) => f as u64,
            Numeric::Other(_) => 0,
        }
    }
}

impl std::fmt::Display for Numeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Numeric::Signed(v) => write!(f, "{v}"),
            Numeric::Unsigned(v) => write!(f, "{v}"),
            Numeric::Float(v) => write!(f, "{v}"),
            Numeric::Other(k) => write!(f, "<numeric {k:#x}>"),
        }
    }
}

/// The bytes of an `LF_REAL80` value (an x87 extended double).
const REAL80_SIZE: usize = 10;
/// The bytes of an `LF_REAL48` value (a Pascal real).
const REAL48_SIZE: usize = 6;

/// Reads a numeric leaf: a u16 below 0x8000 is the value itself; otherwise
/// it names the type of the value that follows.
pub fn read_numeric(r: &mut Reader<'_>) -> Result<Numeric> {
    let tag = r.u16_le()?;
    if tag < leaf::LF_NUMERIC {
        return Ok(Numeric::Unsigned(u64::from(tag)));
    }
    Ok(match tag {
        leaf::LF_CHAR => Numeric::Signed(i64::from(r.u8()? as i8)),
        leaf::LF_SHORT => Numeric::Signed(i64::from(r.u16_le()? as i16)),
        leaf::LF_USHORT => Numeric::Unsigned(u64::from(r.u16_le()?)),
        leaf::LF_LONG => Numeric::Signed(i64::from(r.u32_le()? as i32)),
        leaf::LF_ULONG => Numeric::Unsigned(u64::from(r.u32_le()?)),
        leaf::LF_QUADWORD => Numeric::Signed(r.u64_le()? as i64),
        leaf::LF_UQUADWORD => Numeric::Unsigned(r.u64_le()?),
        leaf::LF_REAL32 => Numeric::Float(f64::from(f32::from_bits(r.u32_le()?))),
        leaf::LF_REAL64 => Numeric::Float(f64::from_bits(r.u64_le()?)),
        // Values we keep as their leaf only: skip their bytes (`lfReal16`,
        // `lfReal80`, `lfReal128`/`lfOct`/`lfUOct`, `lfReal48`).
        leaf::LF_REAL16 => {
            r.skip(size_of::<u16>())?;
            Numeric::Other(tag)
        }
        leaf::LF_REAL80 => {
            r.skip(REAL80_SIZE)?;
            Numeric::Other(tag)
        }
        leaf::LF_REAL128 | leaf::LF_OCTWORD | leaf::LF_UOCTWORD => {
            r.skip(size_of::<u128>())?;
            Numeric::Other(tag)
        }
        leaf::LF_REAL48 => {
            r.skip(REAL48_SIZE)?;
            Numeric::Other(tag)
        }
        leaf::LF_VARSTRING => {
            let n = usize::from(r.u16_le()?);
            r.skip(n)?;
            Numeric::Other(tag)
        }
        _ => Numeric::Other(tag),
    })
}

/// A class, structure, interface, union, or enum.
#[derive(Clone, Copy, Debug)]
pub struct Udt<'a> {
    pub kind: u16,
    pub count: u16,
    pub properties: u16,
    pub field_list: TypeIndex,
    pub derived: TypeIndex,
    pub vshape: TypeIndex,
    /// For enums: the underlying type.
    pub underlying: TypeIndex,
    pub size: u64,
    pub name: &'a [u8],
    pub unique_name: Option<&'a [u8]>,
}

impl Udt<'_> {
    pub fn is_forward_ref(&self) -> bool {
        self.properties & prop::FWDREF != 0
    }
}

fn ti(r: &mut Reader<'_>) -> Result<TypeIndex> {
    r.u32_le().map(TypeIndex)
}

impl<'a> TypeRecord<'a> {
    /// Reads a length-prefixed record.
    pub fn read(r: &mut Reader<'a>) -> Result<Self> {
        let len = usize::from(r.u16_le()?);
        let body = r.bytes(len)?;
        let kind = u16::from_le_bytes([*body.first().unwrap_or(&0), *body.get(1).unwrap_or(&0)]);
        Ok(Self {
            kind,
            data: body.get(2..).unwrap_or(&[]),
        })
    }

    fn reader(&self) -> Reader<'a> {
        Reader::new(self.data)
    }

    pub fn udt(&self) -> Option<Udt<'a>> {
        let mut r = self.reader();
        let mut u = Udt {
            kind: self.kind,
            count: 0,
            properties: 0,
            field_list: TypeIndex(0),
            derived: TypeIndex(0),
            vshape: TypeIndex(0),
            underlying: TypeIndex(0),
            size: 0,
            name: &[],
            unique_name: None,
        };
        match self.kind {
            leaf::LF_CLASS | leaf::LF_STRUCTURE | leaf::LF_INTERFACE => {
                u.count = r.u16_le().ok()?;
                u.properties = r.u16_le().ok()?;
                u.field_list = ti(&mut r).ok()?;
                u.derived = ti(&mut r).ok()?;
                u.vshape = ti(&mut r).ok()?;
                u.size = read_numeric(&mut r).ok()?.as_u64();
            }
            leaf::LF_UNION => {
                u.count = r.u16_le().ok()?;
                u.properties = r.u16_le().ok()?;
                u.field_list = ti(&mut r).ok()?;
                u.size = read_numeric(&mut r).ok()?.as_u64();
            }
            // The 32-bit property field's flags that matter here are all
            // in its low 16 bits.
            leaf::LF_CLASS2 | leaf::LF_STRUCTURE2 | leaf::LF_INTERFACE2 => {
                u.properties = r.u32_le().ok()? as u16;
                u.field_list = ti(&mut r).ok()?;
                u.derived = ti(&mut r).ok()?;
                u.vshape = ti(&mut r).ok()?;
                u.count = r.u16_le().ok()?;
                u.size = read_numeric(&mut r).ok()?.as_u64();
            }
            leaf::LF_UNION2 => {
                u.properties = r.u32_le().ok()? as u16;
                u.field_list = ti(&mut r).ok()?;
                u.count = r.u16_le().ok()?;
                u.size = read_numeric(&mut r).ok()?.as_u64();
            }
            leaf::LF_ENUM => {
                u.count = r.u16_le().ok()?;
                u.properties = r.u16_le().ok()?;
                u.underlying = ti(&mut r).ok()?;
                u.field_list = ti(&mut r).ok()?;
            }
            _ => return None,
        }
        u.name = r.cstr().ok()?;
        if u.properties & prop::HAS_UNIQUE_NAME != 0 {
            u.unique_name = r.cstr().ok();
        }
        Some(u)
    }

    /// The name of a record that has one (UDTs, ids, labels).
    pub fn name(&self) -> Option<&'a [u8]> {
        if let Some(u) = self.udt() {
            return Some(u.name);
        }
        let mut r = self.reader();
        match self.kind {
            leaf::LF_FUNC_ID => {
                // lfFuncId: scopeId, type, name.
                let (_scope, _ty) = (r.u32_le().ok()?, r.u32_le().ok()?);
                r.cstr().ok()
            }
            leaf::LF_MFUNC_ID => {
                // lfMFuncId: parentType, type, name.
                let (_parent, _ty) = (r.u32_le().ok()?, r.u32_le().ok()?);
                r.cstr().ok()
            }
            leaf::LF_STRING_ID => {
                // lfStringId: id, name.
                let _id = r.u32_le().ok()?;
                r.cstr().ok()
            }
            _ => None,
        }
    }

    /// The entries of an `LF_METHODLIST`: each overload's attributes and
    /// function type.
    pub fn method_list(&self) -> Vec<(u16, TypeIndex)> {
        let mut out = Vec::new();
        if self.kind != leaf::LF_METHODLIST {
            return out;
        }
        let mut r = self.reader();
        while let (Ok(attributes), Ok(_pad), Ok(ty)) = (r.u16_le(), r.u16_le(), ti(&mut r)) {
            out.push((attributes, ty));
            if introduces_vtable_slot(attributes) && r.u32_le().is_err() {
                break;
            }
        }
        out
    }

    /// Iterates over the members of an `LF_FIELDLIST`.
    pub fn fields(&self) -> FieldIter<'a> {
        FieldIter {
            r: if self.kind == leaf::LF_FIELDLIST {
                self.reader()
            } else {
                Reader::new(&[])
            },
        }
    }
}

/// A member of a field list.
#[derive(Clone, Copy, Debug)]
pub enum Field<'a> {
    BaseClass {
        attributes: u16,
        ty: TypeIndex,
        offset: u64,
    },
    VirtualBaseClass {
        indirect: bool,
        attributes: u16,
        ty: TypeIndex,
        vbptr: TypeIndex,
        vbptr_offset: u64,
        vbtable_index: u64,
    },
    Member {
        attributes: u16,
        ty: TypeIndex,
        offset: u64,
        name: &'a [u8],
    },
    StaticMember {
        attributes: u16,
        ty: TypeIndex,
        name: &'a [u8],
    },
    Method {
        count: u16,
        method_list: TypeIndex,
        name: &'a [u8],
    },
    OneMethod {
        attributes: u16,
        ty: TypeIndex,
        vtable_offset: Option<u32>,
        name: &'a [u8],
    },
    NestedType {
        ty: TypeIndex,
        name: &'a [u8],
    },
    Enumerate {
        attributes: u16,
        value: Numeric,
        name: &'a [u8],
    },
    VFuncTab {
        ty: TypeIndex,
    },
    /// Continues in another field list.
    Index {
        ty: TypeIndex,
    },
    Unknown {
        kind: u16,
    },
}

pub struct FieldIter<'a> {
    r: Reader<'a>,
}

/// Whether a method's property (`mprop`) gives it a vtable offset: it
/// introduces a virtual function.
fn introduces_vtable_slot(attributes: u16) -> bool {
    use field_attr::*;
    matches!(
        (attributes >> MPROP_SHIFT) & MPROP_MASK,
        CV_MTINTRO | CV_MTPUREINTRO
    )
}

impl<'a> Iterator for FieldIter<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        // Skip padding bytes (LF_PAD0..LF_PAD15).
        while self
            .r
            .remaining()
            .first()
            .is_some_and(|&b| u16::from(b) >= leaf::LF_PAD0)
        {
            self.r.skip(1).ok()?;
        }
        let r = &mut self.r;
        let kind = r.u16_le().ok()?;
        let field = match kind {
            leaf::LF_BCLASS | leaf::LF_BINTERFACE => {
                let attributes = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                let offset = read_numeric(r).ok()?.as_u64();
                Field::BaseClass {
                    attributes,
                    ty,
                    offset,
                }
            }
            leaf::LF_VBCLASS | leaf::LF_IVBCLASS => {
                let attributes = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                let vbptr = ti(r).ok()?;
                let vbptr_offset = read_numeric(r).ok()?.as_u64();
                let vbtable_index = read_numeric(r).ok()?.as_u64();
                Field::VirtualBaseClass {
                    indirect: kind == leaf::LF_IVBCLASS,
                    attributes,
                    ty,
                    vbptr,
                    vbptr_offset,
                    vbtable_index,
                }
            }
            leaf::LF_MEMBER => {
                let attributes = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                let offset = read_numeric(r).ok()?.as_u64();
                Field::Member {
                    attributes,
                    ty,
                    offset,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_STMEMBER => {
                let attributes = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                Field::StaticMember {
                    attributes,
                    ty,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_METHOD => {
                let count = r.u16_le().ok()?;
                let method_list = ti(r).ok()?;
                Field::Method {
                    count,
                    method_list,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_ONEMETHOD => {
                let attributes = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                let vtable_offset = if introduces_vtable_slot(attributes) {
                    Some(r.u32_le().ok()?)
                } else {
                    None
                };
                Field::OneMethod {
                    attributes,
                    ty,
                    vtable_offset,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_NESTTYPE => {
                let _pad0 = r.u16_le().ok()?;
                let ty = ti(r).ok()?;
                Field::NestedType {
                    ty,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_ENUMERATE => {
                let attributes = r.u16_le().ok()?;
                let value = read_numeric(r).ok()?;
                Field::Enumerate {
                    attributes,
                    value,
                    name: r.cstr().ok()?,
                }
            }
            leaf::LF_VFUNCTAB => {
                let _pad0 = r.u16_le().ok()?;
                Field::VFuncTab { ty: ti(r).ok()? }
            }
            leaf::LF_INDEX => {
                let _pad0 = r.u16_le().ok()?;
                Field::Index { ty: ti(r).ok()? }
            }
            _ => {
                // Unknown field kinds have unknown sizes: stop.
                self.r = Reader::new(&[]);
                return Some(Field::Unknown { kind });
            }
        };
        Some(field)
    }
}

/// The name of a built-in (simple) type.
pub fn simple_type_name(ti: TypeIndex) -> String {
    use simple::*;
    if !is_valid(ti.0) {
        return "<unknown simple type>".to_string();
    }
    let base = match kind(ti.0) {
        T_NOTYPE => "<no type>",
        T_VOID => "void",
        T_HRESULT => "HRESULT",
        T_CHAR => "signed char",
        T_UCHAR => "unsigned char",
        T_INT1 => "__int8",
        T_UINT1 => "unsigned __int8",
        T_RCHAR => "char",
        T_WCHAR => "wchar_t",
        T_CHAR16 => "char16_t",
        T_CHAR32 => "char32_t",
        T_CHAR8 => "char8_t",
        T_SHORT => "short",
        T_USHORT => "unsigned short",
        T_INT2 => "__int16",
        T_UINT2 => "unsigned __int16",
        T_LONG => "long",
        T_ULONG => "unsigned long",
        T_INT4 => "int",
        T_UINT4 => "unsigned int",
        T_QUAD => "__int64",
        T_UQUAD => "unsigned __int64",
        T_INT8 => "__int64",
        T_UINT8 => "unsigned __int64",
        T_OCT => "__int128",
        T_UOCT => "unsigned __int128",
        T_INT16 => "__int128",
        T_UINT16 => "unsigned __int128",
        T_REAL16 => "_Float16",
        T_REAL32 => "float",
        T_REAL64 => "double",
        T_REAL80 => "long double",
        T_REAL128 => "__float128",
        T_BOOL08 => "bool",
        T_BOOL16 => "__bool16",
        T_BOOL32 => "__bool32",
        T_BOOL64 => "__bool64",
        T_CPLX32 => "_Complex float",
        T_CPLX64 => "_Complex double",
        // cvinfo.h names 0x60 T_BIT; this reader has always printed it so.
        T_BIT => "std::nullptr_t",
        _ => "<unknown simple type>",
    };
    if mode(ti.0) == CV_TM_DIRECT {
        base.to_string()
    } else {
        format!("{base}*")
    }
}

/// How deeply the formatter follows nested types before writing `...`.
const MAX_DEPTH: u32 = 20;

/// Formats type indexes as C++-style names, looking up records in a type
/// stream.
pub struct TypeFormatter<'t> {
    pub types: &'t dyn TypeSource,
}

impl TypeFormatter<'_> {
    pub fn name(&self, ti: TypeIndex) -> String {
        let mut out = String::new();
        self.write(ti, &mut out, 0);
        out
    }

    fn write(&self, ti: TypeIndex, out: &mut String, depth: u32) {
        // A name has a length past which it stops (a hostile procedure type
        // whose arguments name it again would otherwise take time
        // exponential in the depth: every visit writes something, so the
        // length bounds the work).
        if out.len() > MAX_NAME_LEN {
            if !out.ends_with("...") {
                out.push_str("...");
            }
            return;
        }
        if ti.is_simple() {
            out.push_str(&simple_type_name(ti));
            return;
        }
        if depth > MAX_DEPTH {
            out.push_str("...");
            return;
        }
        let Some(rec) = self.types.record(ti) else {
            out.push_str(&format!("<type {:#x}>", ti.0));
            return;
        };
        let mut r = Reader::new(rec.data);
        match rec.kind {
            k if leaf::is_class(k) || leaf::is_union(k) || k == leaf::LF_ENUM => {
                if let Some(u) = rec.udt() {
                    out.push_str(&String::from_utf8_lossy(u.name));
                }
            }
            leaf::LF_MODIFIER => {
                let (Ok(base), Ok(mods)) = (ti_read(&mut r), r.u16_le()) else {
                    return;
                };
                if mods & modifier::MOD_CONST != 0 {
                    out.push_str("const ");
                }
                if mods & modifier::MOD_VOLATILE != 0 {
                    out.push_str("volatile ");
                }
                if mods & modifier::MOD_UNALIGNED != 0 {
                    out.push_str("__unaligned ");
                }
                self.write(base, out, depth + 1);
            }
            leaf::LF_POINTER => {
                let (Ok(base), Ok(attrs)) = (ti_read(&mut r), r.u32_le()) else {
                    return;
                };
                self.write(base, out, depth + 1);
                use pointer::*;
                out.push_str(match (attrs >> PTRMODE_SHIFT) & PTRMODE_MASK {
                    CV_PTR_MODE_LVREF => " &",
                    CV_PTR_MODE_PMEM | CV_PTR_MODE_PMFUNC => " ::*",
                    CV_PTR_MODE_RVREF => " &&",
                    _ => " *",
                });
                if attrs & ISCONST != 0 {
                    out.push_str(" const");
                }
                if attrs & ISVOLATILE != 0 {
                    out.push_str(" volatile");
                }
            }
            leaf::LF_ARRAY => {
                let (Ok(elem), Ok(_index), Ok(size)) =
                    (ti_read(&mut r), ti_read(&mut r), read_numeric(&mut r))
                else {
                    return;
                };
                self.write(elem, out, depth + 1);
                let elem_size = self.size_of(elem);
                match elem_size {
                    Some(n) if n > 0 => out.push_str(&format!("[{}]", size.as_u64() / n)),
                    _ => out.push_str("[]"),
                }
            }
            leaf::LF_PROCEDURE => {
                let (Ok(ret), Ok(_cc), Ok(_attrs), Ok(_count), Ok(args)) =
                    (ti_read(&mut r), r.u8(), r.u8(), r.u16_le(), ti_read(&mut r))
                else {
                    return;
                };
                self.write(ret, out, depth + 1);
                out.push_str(" (");
                self.write_args(args, out, depth);
                out.push(')');
            }
            leaf::LF_MFUNCTION => {
                let (Ok(ret), Ok(class), Ok(_this), Ok(_cc), Ok(_attrs), Ok(_count), Ok(args)) = (
                    ti_read(&mut r),
                    ti_read(&mut r),
                    ti_read(&mut r),
                    r.u8(),
                    r.u8(),
                    r.u16_le(),
                    ti_read(&mut r),
                ) else {
                    return;
                };
                self.write(ret, out, depth + 1);
                out.push_str(" (");
                self.write(class, out, depth + 1);
                out.push_str("::*)(");
                self.write_args(args, out, depth);
                out.push(')');
            }
            leaf::LF_BITFIELD => {
                let (Ok(base), Ok(len), Ok(pos)) = (ti_read(&mut r), r.u8(), r.u8()) else {
                    return;
                };
                self.write(base, out, depth + 1);
                out.push_str(&format!(" : {len} (at bit {pos})"));
            }
            leaf::LF_ARGLIST => self.write_args(ti, out, depth),
            other => out.push_str(leaf::name(other)),
        }
    }

    fn write_args(&self, args: TypeIndex, out: &mut String, depth: u32) {
        let Some(rec) = self.types.record(args) else {
            return;
        };
        let mut r = Reader::new(rec.data);
        let Ok(count) = r.u32_le() else { return };
        for i in 0..count {
            let Ok(a) = ti_read(&mut r) else { return };
            if i > 0 {
                out.push_str(", ");
            }
            self.write(a, out, depth + 1);
        }
    }

    /// The size in bytes of a type, if known. (Modifiers and enums are
    /// followed to what they name, at most [`MAX_CHAIN`] deep: a hostile
    /// record can name itself.)
    pub fn size_of(&self, mut ti: TypeIndex) -> Option<u64> {
        for _ in 0..MAX_CHAIN {
            match self.size_step(ti)? {
                Step::Size(n) => return Some(n),
                Step::Follow(next) => ti = next,
            }
        }
        None
    }

    fn size_step(&self, ti: TypeIndex) -> Option<Step> {
        if ti.is_simple() {
            // Simple pointer types: the mode gives the pointer's size.
            use simple::*;
            if !is_valid(ti.0) {
                return None;
            }
            match mode(ti.0) {
                CV_TM_DIRECT => {}
                CV_TM_NPTR => return Some(Step::Size(2)), // 16-bit
                CV_TM_FPTR | CV_TM_HPTR => return Some(Step::Size(4)), // 16:16
                CV_TM_NPTR32 => return Some(Step::Size(4)),
                CV_TM_FPTR32 => return Some(Step::Size(6)), // 16:32
                CV_TM_NPTR64 => return Some(Step::Size(8)),
                CV_TM_NPTR128 => return Some(Step::Size(16)),
                _ => return None,
            }
            return Some(Step::Size(match kind(ti.0) {
                T_CHAR | T_UCHAR | T_INT1 | T_UINT1 | T_RCHAR | T_BOOL08 | T_CHAR8 => 1,
                T_SHORT | T_USHORT | T_INT2 | T_UINT2 | T_WCHAR | T_CHAR16 | T_REAL16
                | T_BOOL16 => 2,
                T_LONG | T_ULONG | T_INT4 | T_UINT4 | T_REAL32 | T_CHAR32 | T_BOOL32
                | T_HRESULT => 4,
                T_QUAD | T_UQUAD | T_INT8 | T_UINT8 | T_REAL64 | T_BOOL64 | T_CPLX32 => 8,
                T_REAL80 => 10,
                T_OCT | T_UOCT | T_INT16 | T_UINT16 | T_REAL128 | T_CPLX64 => 16,
                _ => return None,
            }));
        }
        let ti = self.types.resolve_forward(ti);
        let rec = self.types.record(ti)?;
        let mut r = Reader::new(rec.data);
        match rec.kind {
            k if leaf::is_class(k) || leaf::is_union(k) => rec.udt().map(|u| Step::Size(u.size)),
            leaf::LF_ENUM => Some(Step::Follow(rec.udt()?.underlying)),
            leaf::LF_MODIFIER => Some(Step::Follow(ti_read(&mut r).ok()?)),
            leaf::LF_POINTER => {
                let _ = ti_read(&mut r).ok()?;
                let attrs = r.u32_le().ok()?;
                Some(Step::Size(u64::from(
                    (attrs >> pointer::SIZE_SHIFT) & pointer::SIZE_MASK,
                )))
            }
            leaf::LF_ARRAY => {
                // lfArray: elemtype, idxtype, then the size.
                let (_elem, _index) = (ti_read(&mut r).ok()?, ti_read(&mut r).ok()?);
                Some(Step::Size(read_numeric(&mut r).ok()?.as_u64()))
            }
            _ => None,
        }
    }
}

/// The longest a type's name grows before [`TypeFormatter::name`] stops
/// it with `...`.
pub const MAX_NAME_LEN: usize = 4096;

/// How many modifiers (or enums) [`TypeFormatter::size_of`] follows.
pub const MAX_CHAIN: usize = 64;

/// One step of finding a size: the size, or a type to look at next.
enum Step {
    Size(u64),
    Follow(TypeIndex),
}

fn ti_read(r: &mut Reader<'_>) -> Result<TypeIndex> {
    r.u32_le().map(TypeIndex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No records: only simple types.
    struct Empty;

    impl TypeSource for Empty {
        fn record(&self, _: TypeIndex) -> Option<TypeRecord<'_>> {
            None
        }

        fn records(&self) -> Box<dyn Iterator<Item = (TypeIndex, TypeRecord<'_>)> + '_> {
            Box::new(std::iter::empty())
        }
    }

    #[test]
    fn simple_type_sizes() {
        let f = TypeFormatter { types: &Empty };
        let size = |ti: u32| f.size_of(TypeIndex(ti));
        // char, short, int, __int64, wchar_t, float, double, int128.
        assert_eq!(size(0x0070), Some(1));
        assert_eq!(size(0x0011), Some(2));
        assert_eq!(size(0x0074), Some(4));
        assert_eq!(size(0x0013), Some(8));
        assert_eq!(size(0x0071), Some(2));
        assert_eq!(size(0x0040), Some(4));
        assert_eq!(size(0x0041), Some(8));
        assert_eq!(size(0x0078), Some(16));
        // Pointers to int, by mode: near, far, huge, near32, far32,
        // near64, near128.
        for (mode, bytes) in [(1, 2), (2, 4), (3, 4), (4, 4), (5, 6), (6, 8), (7, 16)] {
            assert_eq!(size(0x0074 | (mode << 8)), Some(bytes), "mode {mode}");
        }
        // void* (32- and 64-bit).
        assert_eq!(size(0x0403), Some(4));
        assert_eq!(size(0x0603), Some(8));
        // void, no type, and invalid modes have no size.
        assert_eq!(size(0x0003), None);
        assert_eq!(size(0x0000), None);
        assert_eq!(size(0x0874), None);
        // A record that isn't there.
        assert_eq!(size(0x1000), None);
    }
}

#[cfg(test)]
mod udt_tests {
    use super::*;

    #[test]
    fn class2_forward_reference() {
        // An LF_STRUCTURE2 forward reference from a PDB written by MSVC 17.x.
        let mut data = vec![0x80, 0x02, 0, 0]; // property: fwdref, has unique name
        data.extend_from_slice(&[0; 12]); // field list, derived, vshape
        data.extend_from_slice(&[0, 0]); // count
        data.extend_from_slice(&[0, 0]); // size (numeric 0)
        data.extend_from_slice(b"HINSTANCE__\0.?AUHINSTANCE__@@\0");
        let rec = TypeRecord {
            kind: leaf::LF_STRUCTURE2,
            data: &data,
        };
        let u = rec.udt().unwrap();
        assert_eq!(u.name, b"HINSTANCE__");
        assert_eq!(u.unique_name, Some(&b".?AUHINSTANCE__@@"[..]));
        assert!(u.is_forward_ref());
        assert_eq!(u.size, 0);
        assert_eq!(rec.name(), Some(&b"HINSTANCE__"[..]));
    }

    #[test]
    fn class2_definition() {
        let mut data = vec![0x00, 0x02, 0, 0]; // has unique name
        data.extend_from_slice(&0x1234u32.to_le_bytes()); // field list
        data.extend_from_slice(&0u32.to_le_bytes()); // derived
        data.extend_from_slice(&0x1300u32.to_le_bytes()); // vshape
        data.extend_from_slice(&3u16.to_le_bytes()); // count
        data.extend_from_slice(&[0x02, 0x80, 0x00, 0x01]); // LF_USHORT 256
        data.extend_from_slice(b"Big\0.?AVBig@@\0");
        let rec = TypeRecord {
            kind: leaf::LF_CLASS2,
            data: &data,
        };
        let u = rec.udt().unwrap();
        assert_eq!((u.name, u.size, u.count), (&b"Big"[..], 256, 3));
        assert_eq!(u.field_list, TypeIndex(0x1234));
        assert_eq!(u.vshape, TypeIndex(0x1300));
        assert!(!u.is_forward_ref());
        // Truncated anywhere: no UDT, no panic.
        for len in 0..data.len() - 1 {
            let rec = TypeRecord {
                kind: leaf::LF_CLASS2,
                data: &data[..len],
            };
            let _ = rec.udt();
        }
    }

    #[test]
    fn udt_families() {
        assert!(leaf::same_udt_family(leaf::LF_CLASS, leaf::LF_CLASS2));
        assert!(leaf::same_udt_family(
            leaf::LF_STRUCTURE2,
            leaf::LF_STRUCTURE
        ));
        assert!(leaf::same_udt_family(leaf::LF_UNION, leaf::LF_UNION2));
        assert!(!leaf::same_udt_family(leaf::LF_CLASS, leaf::LF_STRUCTURE));
        assert!(!leaf::same_udt_family(leaf::LF_POINTER, leaf::LF_POINTER));
        assert!(leaf::is_class(leaf::LF_INTERFACE2) && !leaf::is_class(leaf::LF_UNION2));
    }
}

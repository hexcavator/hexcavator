//! CodeView symbol records.

use hexcavator_core::{Reader, Result};

use crate::types::TypeIndex;

/// `COMPILESYM3`'s flags: the language (`iLanguage`) is the low 8 bits.
pub const COMPILE3_LANGUAGE_MASK: u32 = 0xFF;

/// `DEFRANGESYMSUBFIELDREGISTER`'s `offParent`: the low
/// `CV_OFFSET_PARENT_LENGTH_LIMIT` bits of its 32-bit field.
pub const CV_OFFSET_PARENT_LENGTH_LIMIT: u32 = 12;
/// The mask of `offParent`.
pub const OFFSET_PARENT_MASK: u32 = (1 << CV_OFFSET_PARENT_LENGTH_LIMIT) - 1;
use crate::types::{Numeric, read_numeric};

/// Symbol record kinds.
#[allow(missing_docs)]
pub mod kind {
    pub const S_END: u16 = 0x0006;
    pub const S_FRAMEPROC: u16 = 0x1012;
    pub const S_ANNOTATION: u16 = 0x1019;
    pub const S_OBJNAME: u16 = 0x1101;
    pub const S_THUNK32: u16 = 0x1102;
    pub const S_BLOCK32: u16 = 0x1103;
    pub const S_LABEL32: u16 = 0x1105;
    pub const S_REGISTER: u16 = 0x1106;
    pub const S_CONSTANT: u16 = 0x1107;
    pub const S_UDT: u16 = 0x1108;
    pub const S_BPREL32: u16 = 0x110B;
    pub const S_LDATA32: u16 = 0x110C;
    pub const S_GDATA32: u16 = 0x110D;
    pub const S_PUB32: u16 = 0x110E;
    pub const S_LPROC32: u16 = 0x110F;
    pub const S_GPROC32: u16 = 0x1110;
    pub const S_REGREL32: u16 = 0x1111;
    pub const S_LTHREAD32: u16 = 0x1112;
    pub const S_GTHREAD32: u16 = 0x1113;
    pub const S_COMPILE2: u16 = 0x1116;
    pub const S_UNAMESPACE: u16 = 0x1124;
    pub const S_PROCREF: u16 = 0x1125;
    pub const S_DATAREF: u16 = 0x1126;
    pub const S_LPROCREF: u16 = 0x1127;
    pub const S_TRAMPOLINE: u16 = 0x112C;
    pub const S_SEPCODE: u16 = 0x1132;
    pub const S_SECTION: u16 = 0x1136;
    pub const S_COFFGROUP: u16 = 0x1137;
    pub const S_EXPORT: u16 = 0x1138;
    pub const S_CALLSITEINFO: u16 = 0x1139;
    pub const S_FRAMECOOKIE: u16 = 0x113A;
    pub const S_COMPILE3: u16 = 0x113C;
    pub const S_ENVBLOCK: u16 = 0x113D;
    pub const S_LOCAL: u16 = 0x113E;
    pub const S_DEFRANGE: u16 = 0x113F;
    pub const S_DEFRANGE_SUBFIELD: u16 = 0x1140;
    pub const S_DEFRANGE_REGISTER: u16 = 0x1141;
    pub const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
    pub const S_DEFRANGE_SUBFIELD_REGISTER: u16 = 0x1143;
    pub const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16 = 0x1144;
    pub const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
    pub const S_LPROC32_ID: u16 = 0x1146;
    pub const S_GPROC32_ID: u16 = 0x1147;
    pub const S_BUILDINFO: u16 = 0x114C;
    pub const S_INLINESITE: u16 = 0x114D;
    pub const S_INLINESITE_END: u16 = 0x114E;
    pub const S_PROC_ID_END: u16 = 0x114F;
    pub const S_FILESTATIC: u16 = 0x1153;
    pub const S_ARMSWITCHTABLE: u16 = 0x1159;
    pub const S_CALLEES: u16 = 0x115A;
    pub const S_CALLERS: u16 = 0x115B;
    pub const S_HEAPALLOCSITE: u16 = 0x115E;
    pub const S_INLINEES: u16 = 0x1168;
    pub const S_GMANPROC: u16 = 0x112A;
    pub const S_LMANPROC: u16 = 0x112B;
    pub const S_LPROC32_DPC: u16 = 0x1155;
    pub const S_LPROC32_DPC_ID: u16 = 0x1156;
    pub const S_POGODATA: u16 = 0x115C;
    pub const S_INLINESITE2: u16 = 0x115D;
    pub const S_FASTLINK: u16 = 0x1167;
    pub const S_REGREL32_INDIR: u16 = 0x1171;
    pub const S_DEFRANGE_REGISTER_REL_INDIR: u16 = 0x1177;

    pub fn name(kind: u16) -> &'static str {
        match kind {
            S_END => "S_END",
            S_FRAMEPROC => "S_FRAMEPROC",
            S_ANNOTATION => "S_ANNOTATION",
            S_OBJNAME => "S_OBJNAME",
            S_THUNK32 => "S_THUNK32",
            S_BLOCK32 => "S_BLOCK32",
            S_LABEL32 => "S_LABEL32",
            S_REGISTER => "S_REGISTER",
            S_CONSTANT => "S_CONSTANT",
            S_UDT => "S_UDT",
            S_BPREL32 => "S_BPREL32",
            S_LDATA32 => "S_LDATA32",
            S_GDATA32 => "S_GDATA32",
            S_PUB32 => "S_PUB32",
            S_LPROC32 => "S_LPROC32",
            S_GPROC32 => "S_GPROC32",
            S_REGREL32 => "S_REGREL32",
            S_LTHREAD32 => "S_LTHREAD32",
            S_GTHREAD32 => "S_GTHREAD32",
            S_COMPILE2 => "S_COMPILE2",
            S_UNAMESPACE => "S_UNAMESPACE",
            S_PROCREF => "S_PROCREF",
            S_DATAREF => "S_DATAREF",
            S_LPROCREF => "S_LPROCREF",
            S_TRAMPOLINE => "S_TRAMPOLINE",
            S_SEPCODE => "S_SEPCODE",
            S_SECTION => "S_SECTION",
            S_COFFGROUP => "S_COFFGROUP",
            S_EXPORT => "S_EXPORT",
            S_CALLSITEINFO => "S_CALLSITEINFO",
            S_FRAMECOOKIE => "S_FRAMECOOKIE",
            S_COMPILE3 => "S_COMPILE3",
            S_ENVBLOCK => "S_ENVBLOCK",
            S_LOCAL => "S_LOCAL",
            S_DEFRANGE => "S_DEFRANGE",
            S_DEFRANGE_SUBFIELD => "S_DEFRANGE_SUBFIELD",
            S_DEFRANGE_REGISTER => "S_DEFRANGE_REGISTER",
            S_DEFRANGE_FRAMEPOINTER_REL => "S_DEFRANGE_FRAMEPOINTER_REL",
            S_DEFRANGE_SUBFIELD_REGISTER => "S_DEFRANGE_SUBFIELD_REGISTER",
            S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE",
            S_DEFRANGE_REGISTER_REL => "S_DEFRANGE_REGISTER_REL",
            S_LPROC32_ID => "S_LPROC32_ID",
            S_GPROC32_ID => "S_GPROC32_ID",
            S_BUILDINFO => "S_BUILDINFO",
            S_INLINESITE => "S_INLINESITE",
            S_INLINESITE_END => "S_INLINESITE_END",
            S_PROC_ID_END => "S_PROC_ID_END",
            S_FILESTATIC => "S_FILESTATIC",
            S_ARMSWITCHTABLE => "S_ARMSWITCHTABLE",
            S_CALLEES => "S_CALLEES",
            S_CALLERS => "S_CALLERS",
            S_HEAPALLOCSITE => "S_HEAPALLOCSITE",
            S_INLINEES => "S_INLINEES",
            S_GMANPROC => "S_GMANPROC",
            S_LMANPROC => "S_LMANPROC",
            S_LPROC32_DPC => "S_LPROC32_DPC",
            S_LPROC32_DPC_ID => "S_LPROC32_DPC_ID",
            S_POGODATA => "S_POGODATA",
            S_INLINESITE2 => "S_INLINESITE2",
            S_FASTLINK => "S_FASTLINK",
            S_REGREL32_INDIR => "S_REGREL32_INDIR",
            S_DEFRANGE_REGISTER_REL_INDIR => "S_DEFRANGE_REGISTER_REL_INDIR",
            _ => "S_???",
        }
    }

    /// Whether a symbol opens a scope closed by S_END / S_PROC_ID_END /
    /// S_INLINESITE_END.
    pub fn opens_scope(kind: u16) -> bool {
        matches!(
            kind,
            S_GPROC32
                | S_LPROC32
                | S_GPROC32_ID
                | S_LPROC32_ID
                | S_BLOCK32
                | S_THUNK32
                | S_SEPCODE
                | S_INLINESITE
                | S_INLINESITE2
                | S_LPROC32_DPC
                | S_LPROC32_DPC_ID
                | S_GMANPROC
                | S_LMANPROC
        )
    }

    pub fn closes_scope(kind: u16) -> bool {
        matches!(kind, S_END | S_PROC_ID_END | S_INLINESITE_END)
    }
}

/// A symbol record: kind, the bytes after the kind, and its offset in its
/// stream (which other records use to refer to it).
#[derive(Clone, Copy, Debug)]
pub struct SymbolRecord<'a> {
    pub offset: u32,
    pub kind: u16,
    pub data: &'a [u8],
}

/// Iterates over a buffer of symbol records starting at `base`.
pub struct SymbolIter<'a> {
    r: Reader<'a>,
    base: u32,
}

impl<'a> SymbolIter<'a> {
    pub fn new(data: &'a [u8], base: u32) -> Self {
        Self {
            r: Reader::new(data),
            base,
        }
    }
}

impl<'a> Iterator for SymbolIter<'a> {
    type Item = SymbolRecord<'a>;

    fn next(&mut self) -> Option<SymbolRecord<'a>> {
        if self.r.remaining().len() < 4 {
            return None;
        }
        let offset = self.base + self.r.position() as u32;
        let len = usize::from(self.r.u16_le().ok()?);
        if len < 2 {
            return None;
        }
        let body = self.r.bytes(len).ok()?;
        Some(SymbolRecord {
            offset,
            kind: u16::from_le_bytes([body[0], body[1]]),
            data: &body[2..],
        })
    }
}

/// A decoded symbol. Variants hold borrowed names.
#[derive(Clone, Copy, Debug)]
pub enum Symbol<'a> {
    Public {
        flags: u32,
        offset: u32,
        segment: u16,
        name: &'a [u8],
    },
    Procedure {
        global: bool,
        id: bool,
        parent: u32,
        end: u32,
        next: u32,
        len: u32,
        debug_start: u32,
        debug_end: u32,
        ty: TypeIndex,
        offset: u32,
        segment: u16,
        flags: u8,
        name: &'a [u8],
    },
    Data {
        global: bool,
        thread: bool,
        ty: TypeIndex,
        offset: u32,
        segment: u16,
        name: &'a [u8],
    },
    Udt {
        ty: TypeIndex,
        name: &'a [u8],
    },
    Constant {
        ty: TypeIndex,
        value: Numeric,
        name: &'a [u8],
    },
    /// S_PROCREF, S_LPROCREF, S_DATAREF: a reference to a symbol in a module.
    Reference {
        kind: u16,
        sum_name: u32,
        symbol_offset: u32,
        module: u16,
        name: &'a [u8],
    },
    RegisterRelative {
        offset: i32,
        ty: TypeIndex,
        register: u16,
        name: &'a [u8],
    },
    BpRelative {
        offset: i32,
        ty: TypeIndex,
        name: &'a [u8],
    },
    Register {
        ty: TypeIndex,
        register: u16,
        name: &'a [u8],
    },
    Local {
        ty: TypeIndex,
        flags: u16,
        name: &'a [u8],
    },
    Block {
        parent: u32,
        end: u32,
        len: u32,
        offset: u32,
        segment: u16,
        name: &'a [u8],
    },
    Label {
        offset: u32,
        segment: u16,
        flags: u8,
        name: &'a [u8],
    },
    Thunk {
        parent: u32,
        end: u32,
        next: u32,
        offset: u32,
        segment: u16,
        len: u16,
        ordinal: u8,
        name: &'a [u8],
    },
    ObjName {
        signature: u32,
        name: &'a [u8],
    },
    Compile3 {
        flags: u32,
        machine: u16,
        frontend: [u16; 4],
        backend: [u16; 4],
        version: &'a [u8],
    },
    FrameProc {
        frame_size: u32,
        pad_size: u32,
        pad_offset: u32,
        callee_saved_size: u32,
        eh_offset: u32,
        eh_section: u16,
        flags: u32,
    },
    Section {
        section: u16,
        alignment: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: &'a [u8],
    },
    CoffGroup {
        size: u32,
        characteristics: u32,
        offset: u32,
        segment: u16,
        name: &'a [u8],
    },
    BuildInfo {
        id: TypeIndex,
    },
    /// S_SEPCODE: a block of a function's code separated from its body
    /// (by PGO, into a cold region, say).
    SeparatedCode {
        parent: u32,
        end: u32,
        len: u32,
        flags: u32,
        offset: u32,
        parent_offset: u32,
        segment: u16,
        parent_segment: u16,
    },
    /// S_ANNOTATION: strings the code attached to an address (the
    /// `__annotation` intrinsic).
    Annotation {
        offset: u32,
        segment: u16,
        /// The strings, as stored (up to the record's end).
        strings: &'a [u8],
        count: u16,
    },
    InlineSite {
        parent: u32,
        end: u32,
        inlinee: TypeIndex,
        annotations: &'a [u8],
    },
    /// S_DEFRANGE_*: where a preceding S_LOCAL lives over a range of code.
    DefRange {
        kind: u16,
        data: &'a [u8],
    },
    End {
        kind: u16,
    },
    Other {
        kind: u16,
        data: &'a [u8],
    },
}

impl<'a> SymbolRecord<'a> {
    /// Decodes the record into a typed view.
    pub fn parse(&self) -> Result<Symbol<'a>> {
        use kind::*;
        let mut r = Reader::new(self.data);
        let r = &mut r;
        let ty = |r: &mut Reader<'a>| r.u32_le().map(TypeIndex);
        Ok(match self.kind {
            S_PUB32 => Symbol::Public {
                flags: r.u32_le()?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                name: r.cstr()?,
            },
            S_GPROC32 | S_LPROC32 | S_GPROC32_ID | S_LPROC32_ID | S_LPROC32_DPC
            | S_LPROC32_DPC_ID => Symbol::Procedure {
                global: matches!(self.kind, S_GPROC32 | S_GPROC32_ID),
                id: matches!(self.kind, S_GPROC32_ID | S_LPROC32_ID | S_LPROC32_DPC_ID),
                parent: r.u32_le()?,
                end: r.u32_le()?,
                next: r.u32_le()?,
                len: r.u32_le()?,
                debug_start: r.u32_le()?,
                debug_end: r.u32_le()?,
                ty: ty(r)?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                flags: r.u8()?,
                name: r.cstr()?,
            },
            S_GDATA32 | S_LDATA32 | S_GTHREAD32 | S_LTHREAD32 => Symbol::Data {
                global: matches!(self.kind, S_GDATA32 | S_GTHREAD32),
                thread: matches!(self.kind, S_GTHREAD32 | S_LTHREAD32),
                ty: ty(r)?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                name: r.cstr()?,
            },
            S_UDT => Symbol::Udt {
                ty: ty(r)?,
                name: r.cstr()?,
            },
            S_CONSTANT => Symbol::Constant {
                ty: ty(r)?,
                value: read_numeric(r)?,
                name: r.cstr()?,
            },
            S_PROCREF | S_LPROCREF | S_DATAREF => Symbol::Reference {
                kind: self.kind,
                sum_name: r.u32_le()?,
                symbol_offset: r.u32_le()?,
                module: r.u16_le()?,
                name: r.cstr()?,
            },
            S_REGREL32 => Symbol::RegisterRelative {
                offset: r.u32_le()? as i32,
                ty: ty(r)?,
                register: r.u16_le()?,
                name: r.cstr()?,
            },
            S_BPREL32 => Symbol::BpRelative {
                offset: r.u32_le()? as i32,
                ty: ty(r)?,
                name: r.cstr()?,
            },
            S_REGISTER => Symbol::Register {
                ty: ty(r)?,
                register: r.u16_le()?,
                name: r.cstr()?,
            },
            S_LOCAL => Symbol::Local {
                ty: ty(r)?,
                flags: r.u16_le()?,
                name: r.cstr()?,
            },
            S_BLOCK32 => Symbol::Block {
                parent: r.u32_le()?,
                end: r.u32_le()?,
                len: r.u32_le()?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                name: r.cstr()?,
            },
            S_LABEL32 => Symbol::Label {
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                flags: r.u8()?,
                name: r.cstr()?,
            },
            S_THUNK32 => Symbol::Thunk {
                parent: r.u32_le()?,
                end: r.u32_le()?,
                next: r.u32_le()?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                len: r.u16_le()?,
                ordinal: r.u8()?,
                name: r.cstr()?,
            },
            S_OBJNAME => Symbol::ObjName {
                signature: r.u32_le()?,
                name: r.cstr()?,
            },
            S_COMPILE3 => Symbol::Compile3 {
                flags: r.u32_le()?,
                machine: r.u16_le()?,
                frontend: [r.u16_le()?, r.u16_le()?, r.u16_le()?, r.u16_le()?],
                backend: [r.u16_le()?, r.u16_le()?, r.u16_le()?, r.u16_le()?],
                version: r.cstr()?,
            },
            S_FRAMEPROC => Symbol::FrameProc {
                frame_size: r.u32_le()?,
                pad_size: r.u32_le()?,
                pad_offset: r.u32_le()?,
                callee_saved_size: r.u32_le()?,
                eh_offset: r.u32_le()?,
                eh_section: r.u16_le()?,
                flags: r.u32_le()?,
            },
            S_SECTION => Symbol::Section {
                section: r.u16_le()?,
                alignment: r.u8()?,
                rva: {
                    r.u8()?;
                    r.u32_le()?
                },
                size: r.u32_le()?,
                characteristics: r.u32_le()?,
                name: r.cstr()?,
            },
            S_COFFGROUP => Symbol::CoffGroup {
                size: r.u32_le()?,
                characteristics: r.u32_le()?,
                offset: r.u32_le()?,
                segment: r.u16_le()?,
                name: r.cstr()?,
            },
            S_BUILDINFO => Symbol::BuildInfo { id: ty(r)? },
            S_SEPCODE => Symbol::SeparatedCode {
                parent: r.u32_le()?,
                end: r.u32_le()?,
                len: r.u32_le()?,
                flags: r.u32_le()?,
                offset: r.u32_le()?,
                parent_offset: r.u32_le()?,
                segment: r.u16_le()?,
                parent_segment: r.u16_le()?,
            },
            S_ANNOTATION => {
                let offset = r.u32_le()?;
                let segment = r.u16_le()?;
                let count = r.u16_le()?;
                Symbol::Annotation {
                    offset,
                    segment,
                    strings: r.remaining(),
                    count,
                }
            }
            S_INLINESITE => Symbol::InlineSite {
                parent: r.u32_le()?,
                end: r.u32_le()?,
                inlinee: ty(r)?,
                annotations: r.remaining(),
            },
            // S_INLINESITE2 adds the number of invocations.
            S_INLINESITE2 => {
                let parent = r.u32_le()?;
                let end = r.u32_le()?;
                let inlinee = ty(r)?;
                let _invocations = r.u32_le()?;
                Symbol::InlineSite {
                    parent,
                    end,
                    inlinee,
                    annotations: r.remaining(),
                }
            }
            S_DEFRANGE..=S_DEFRANGE_REGISTER_REL => Symbol::DefRange {
                kind: self.kind,
                data: self.data,
            },
            S_END | S_PROC_ID_END | S_INLINESITE_END => Symbol::End { kind: self.kind },
            _ => Symbol::Other {
                kind: self.kind,
                data: self.data,
            },
        })
    }

    /// The symbol's name, if it has one.
    pub fn name(&self) -> Option<&'a [u8]> {
        Some(match self.parse().ok()? {
            Symbol::Public { name, .. }
            | Symbol::Procedure { name, .. }
            | Symbol::Data { name, .. }
            | Symbol::Udt { name, .. }
            | Symbol::Constant { name, .. }
            | Symbol::Reference { name, .. }
            | Symbol::RegisterRelative { name, .. }
            | Symbol::BpRelative { name, .. }
            | Symbol::Register { name, .. }
            | Symbol::Local { name, .. }
            | Symbol::Block { name, .. }
            | Symbol::Label { name, .. }
            | Symbol::Thunk { name, .. }
            | Symbol::ObjName { name, .. }
            | Symbol::Section { name, .. }
            | Symbol::CoffGroup { name, .. } => name,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record of `kind` with `body`, as it appears in a symbol stream.
    fn record(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(body.len() + 2).unwrap().to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn inline_sites_and_dpc_procedures() {
        let mut body = Vec::new();
        for v in [0x10u32, 0x60, 0x1234] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        let annotations = [0x0Bu8, 0x02, 0x00, 0x00];
        let mut one = body.clone();
        one.extend_from_slice(&annotations);
        let mut two = body.clone();
        two.extend_from_slice(&5u32.to_le_bytes()); // invocations
        two.extend_from_slice(&annotations);
        for (k, b) in [(kind::S_INLINESITE, one), (kind::S_INLINESITE2, two)] {
            let data = record(k, &b);
            let rec = SymbolIter::new(&data, 0).next().unwrap();
            assert!(kind::opens_scope(rec.kind), "{}", kind::name(rec.kind));
            match rec.parse().unwrap() {
                Symbol::InlineSite {
                    parent,
                    end,
                    inlinee,
                    annotations: a,
                } => {
                    assert_eq!((parent, end, inlinee), (0x10, 0x60, TypeIndex(0x1234)));
                    assert_eq!(a, annotations);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(kind::name(kind::S_INLINESITE2), "S_INLINESITE2");
        // A DPC procedure has a procedure's layout, and is local.
        let mut body = Vec::new();
        for v in [0u32, 0, 0, 0x20, 0, 0, 0x1001, 0x40] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(0);
        body.extend_from_slice(b"dpc");
        body.push(0);
        for k in [kind::S_LPROC32_DPC, kind::S_LPROC32_DPC_ID] {
            let data = record(k, &body);
            let rec = SymbolIter::new(&data, 0).next().unwrap();
            assert!(kind::opens_scope(rec.kind));
            match rec.parse().unwrap() {
                Symbol::Procedure {
                    global,
                    len,
                    name,
                    id,
                    ..
                } => {
                    assert!(!global);
                    assert_eq!(id, k == kind::S_LPROC32_DPC_ID);
                    assert_eq!((len, name), (0x20, &b"dpc"[..]));
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn separated_code() {
        let mut body = Vec::new();
        for v in [0x10u32, 0x60, 0x40, 0x2, 0x1234, 0x100] {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        let data = record(kind::S_SEPCODE, &body);
        let rec = SymbolIter::new(&data, 0).next().unwrap();
        assert!(kind::opens_scope(rec.kind));
        assert_eq!(kind::name(rec.kind), "S_SEPCODE");
        match rec.parse().unwrap() {
            Symbol::SeparatedCode {
                parent,
                end,
                len,
                flags,
                offset,
                parent_offset,
                segment,
                parent_segment,
            } => {
                assert_eq!((parent, end, len, flags), (0x10, 0x60, 0x40, 2));
                assert_eq!((offset, parent_offset), (0x1234, 0x100));
                assert_eq!((segment, parent_segment), (1, 2));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(rec.name(), None);
        // Truncated records are errors.
        for len in 0..body.len() {
            let data = record(kind::S_SEPCODE, &body[..len]);
            let rec = SymbolIter::new(&data, 0).next().unwrap();
            assert!(rec.parse().is_err(), "{len}");
        }
    }
}

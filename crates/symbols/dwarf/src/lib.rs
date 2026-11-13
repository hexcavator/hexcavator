//! DWARF debug information, versions 2 to 5, 32- and 64-bit, either byte
//! order: units of `.debug_info` and `.debug_types`, abbreviation tables,
//! DIEs and their attributes, string and address indirection
//! (`.debug_str`, `.debug_line_str`, `.debug_str_offsets`, `.debug_addr`),
//! range lists (`.debug_ranges`, `.debug_rnglists`), location lists
//! (`.debug_loc`), address ranges (`.debug_aranges`), and name tables
//! (`.debug_pubnames`, `.debug_pubtypes`); call frame information
//! (`.eh_frame`, `.debug_frame`: [`cfi`]); and expression evaluation
//! ([`expr`]).
//!
//! Everything works on borrowed section bytes ([`Sections`]) and reports
//! where in them each thing lies, so that size analysis can charge bytes
//! to what they describe. Malformed data ends iteration (or yields `None`);
//! nothing panics.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hexcavator_core::Endian;

pub mod cfi;
pub mod consts;
pub mod expr;
mod line;
pub mod names;
pub mod registers;
pub mod spelling;

pub use line::{FileEntry, LineProgram, Row, line_program};

use consts::*;

/// The DWARF sections of a file (empty when absent).
#[derive(Clone, Copy, Debug)]
pub struct Sections<'d> {
    pub endian: Endian,
    pub info: &'d [u8],
    pub types: &'d [u8],
    pub abbrev: &'d [u8],
    pub str: &'d [u8],
    pub line_str: &'d [u8],
    pub str_offsets: &'d [u8],
    pub addr: &'d [u8],
    pub ranges: &'d [u8],
    pub rnglists: &'d [u8],
    pub loc: &'d [u8],
    pub loclists: &'d [u8],
    pub line: &'d [u8],
    pub aranges: &'d [u8],
    pub pubnames: &'d [u8],
    pub pubtypes: &'d [u8],
    /// `.debug_names`.
    pub names: &'d [u8],
}

impl<'d> Sections<'d> {
    pub fn new(endian: Endian) -> Self {
        Self {
            endian,
            info: &[],
            types: &[],
            abbrev: &[],
            str: &[],
            line_str: &[],
            str_offsets: &[],
            addr: &[],
            ranges: &[],
            rnglists: &[],
            loc: &[],
            loclists: &[],
            line: &[],
            aranges: &[],
            pubnames: &[],
            pubtypes: &[],
            names: &[],
        }
    }

    /// Sets the section `name` names (`.debug_info`, `__debug_info`,
    /// `.zdebug_info` style prefixes stripped by the caller: `info`,
    /// `abbrev`, ...). Returns whether the name is one of ours.
    pub fn set(&mut self, name: &[u8], data: &'d [u8]) -> bool {
        let slot = match name {
            b"info" => &mut self.info,
            b"types" => &mut self.types,
            b"abbrev" => &mut self.abbrev,
            b"str" => &mut self.str,
            b"line_str" => &mut self.line_str,
            b"str_offsets" | b"str_offs" => &mut self.str_offsets,
            b"addr" => &mut self.addr,
            b"ranges" => &mut self.ranges,
            b"rnglists" => &mut self.rnglists,
            b"loc" => &mut self.loc,
            b"loclists" => &mut self.loclists,
            b"line" => &mut self.line,
            b"aranges" => &mut self.aranges,
            b"pubnames" => &mut self.pubnames,
            b"pubtypes" => &mut self.pubtypes,
            b"names" => &mut self.names,
            _ => return false,
        };
        *slot = data;
        true
    }
}

/// A reading position in a section.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'d> {
    pub data: &'d [u8],
    pub pos: usize,
    pub endian: Endian,
}

impl<'d> Reader<'d> {
    pub fn new(data: &'d [u8], pos: usize, endian: Endian) -> Self {
        Self { data, pos, endian }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn bytes(&mut self, n: u64) -> Option<&'d [u8]> {
        let n = usize::try_from(n).ok()?;
        let end = self.pos.checked_add(n)?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    /// An `n`-byte unsigned integer (1 to 8 bytes).
    pub fn uint(&mut self, n: usize) -> Option<u64> {
        let b = self.bytes(n as u64)?;
        let mut v = 0u64;
        match self.endian {
            Endian::Little => {
                for &x in b.iter().rev() {
                    v = (v << 8) | u64::from(x);
                }
            }
            Endian::Big => {
                for &x in b {
                    v = (v << 8) | u64::from(x);
                }
            }
        }
        Some(v)
    }

    pub fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    pub fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// A NUL-terminated string (without the NUL).
    pub fn cstr(&mut self) -> Option<&'d [u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        self.pos += n + 1;
        Some(&rest[..n])
    }

    /// An initial length: the unit's extent after it, and whether it is
    /// 64-bit DWARF. `None` if it runs past the data.
    pub fn initial_length(&mut self) -> Option<(usize, usize, bool)> {
        let mut len = self.uint(4)?;
        let dwarf64 = len == 0xFFFF_FFFF;
        if dwarf64 {
            len = self.uint(8)?;
        }
        let start = self.pos;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        if end > self.data.len() {
            return None;
        }
        Some((start, end, dwarf64))
    }

    pub fn offset(&mut self, dwarf64: bool) -> Option<u64> {
        self.uint(if dwarf64 { 8 } else { 4 })
    }
}

/// One attribute specification of an abbreviation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttrSpec {
    pub name: u16,
    pub form: u16,
    /// `DW_FORM_implicit_const`'s value.
    pub implicit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abbrev {
    pub code: u64,
    pub tag: u16,
    pub children: bool,
    pub attrs: Vec<AttrSpec>,
}

/// An abbreviation table, and the bytes it occupies.
#[derive(Clone, Debug, Default)]
pub struct Abbrevs {
    pub offset: u64,
    pub len: u64,
    by_code: BTreeMap<u64, usize>,
    list: Vec<Abbrev>,
}

impl Abbrevs {
    /// Reads the table at `offset` of `.debug_abbrev`.
    pub fn parse(data: &[u8], offset: u64, endian: Endian) -> Option<Self> {
        let mut r = Reader::new(data, usize::try_from(offset).ok()?, endian);
        let mut t = Self {
            offset,
            ..Self::default()
        };
        loop {
            let code = r.uleb()?;
            if code == 0 {
                break;
            }
            let tag = u16::try_from(r.uleb()?).ok()?;
            let children = match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let mut attrs = Vec::new();
            loop {
                let name = u16::try_from(r.uleb()?).ok()?;
                let form = u16::try_from(r.uleb()?).ok()?;
                if name == 0 && form == 0 {
                    break;
                }
                let implicit = if form == DW_FORM_IMPLICIT_CONST {
                    r.sleb()?
                } else {
                    0
                };
                attrs.push(AttrSpec {
                    name,
                    form,
                    implicit,
                });
            }
            if t.by_code.insert(code, t.list.len()).is_some() {
                return None;
            }
            t.list.push(Abbrev {
                code,
                tag,
                children,
                attrs,
            });
        }
        t.len = r.pos as u64 - offset;
        Some(t)
    }

    pub fn get(&self, code: u64) -> Option<&Abbrev> {
        self.by_code.get(&code).map(|&i| &self.list[i])
    }

    /// Its abbreviations, in the order the table lists them.
    pub fn iter(&self) -> impl Iterator<Item = &Abbrev> {
        self.list.iter()
    }
}

/// Which string section a string offset refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrSection {
    Str,
    LineStr,
}

/// An attribute's value, as encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'d> {
    /// Constants, offsets, references, flags.
    Uint(u64),
    Sint(i64),
    Addr(u64),
    /// An index into `.debug_addr`.
    AddrIndex(u64),
    /// `DW_FORM_dataN` bytes.
    Data(&'d [u8]),
    /// A block or expression.
    Block(&'d [u8]),
    /// An inline string.
    Str(&'d [u8]),
    /// An offset into a string section.
    StrOffset(StrSection, u64),
    /// An index into `.debug_str_offsets`.
    StrIndex(u64),
    /// A `DW_FORM_rnglistx` or `DW_FORM_loclistx` index.
    ListIndex(u64),
}

/// A resolved string, and where it lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrRef<'d> {
    pub bytes: &'d [u8],
    /// The string section and offset of an indirect string; `None` for an
    /// inline one.
    pub at: Option<(StrSection, u64)>,
}

/// Which section a unit is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnitSection {
    Info,
    Types,
}

/// A unit header and the bases its attributes are relative to.
#[derive(Clone, Copy, Debug)]
pub struct Unit<'d> {
    pub section: UnitSection,
    /// Where the unit (with its initial length) starts and ends.
    pub offset: u64,
    pub end: u64,
    pub version: u16,
    pub dwarf64: bool,
    pub address_size: u8,
    pub unit_type: u8,
    pub abbrev_offset: u64,
    /// Where the first DIE starts.
    pub dies: u64,
    pub addr_base: u64,
    pub str_offsets_base: u64,
    pub rnglists_base: u64,
    pub loclists_base: u64,
    /// The unit's `DW_AT_low_pc`: the base of its range lists.
    pub low_pc: u64,
    /// Whether this is a split unit (of a `.dwo` file or a `.dwp`
    /// package): set from the unit type in DWARF 5, by the caller for
    /// GNU's DWARF 4 extension, whose location lists then have the split
    /// form (and `loclists_base` is the unit's `.debug_loc.dwo`
    /// contribution).
    pub split: bool,
    /// The ID of a skeleton or split compile unit (DWARF 5's header field).
    pub dwo_id: Option<u64>,
    /// Which of the caller's files the unit was read from (0 unless the
    /// caller says otherwise); the reader doesn't use it.
    pub source: u32,
    data: &'d [u8],
    s: Sections<'d>,
}

impl<'d> Unit<'d> {
    /// The units of `.debug_info` (or `.debug_types`), from `start`.
    pub fn iter(
        s: Sections<'d>,
        section: UnitSection,
        start: u64,
    ) -> impl Iterator<Item = Unit<'d>> {
        let data = match section {
            UnitSection::Info => s.info,
            UnitSection::Types => s.types,
        };
        let mut pos = usize::try_from(start).unwrap_or(usize::MAX);
        core::iter::from_fn(move || {
            if pos >= data.len() {
                return None;
            }
            let u = Self::parse(s, section, data, pos)?;
            pos = usize::try_from(u.end).ok()?;
            Some(u)
        })
    }

    /// The unit at `offset` of `.debug_info`.
    pub fn at(s: Sections<'d>, offset: u64) -> Option<Self> {
        Self::parse(s, UnitSection::Info, s.info, usize::try_from(offset).ok()?)
    }

    fn parse(s: Sections<'d>, section: UnitSection, data: &'d [u8], pos: usize) -> Option<Self> {
        let mut r = Reader::new(data, pos, s.endian);
        let (start, end, dwarf64) = r.initial_length()?;
        r.data = &data[..end];
        let _ = start;
        let version = u16::try_from(r.uint(2)?).ok()?;
        if !(2..=5).contains(&version) {
            return None;
        }
        let (unit_type, address_size, abbrev_offset);
        let mut dwo_id = None;
        if version == 5 {
            unit_type = r.u8()?;
            address_size = r.u8()?;
            abbrev_offset = r.offset(dwarf64)?;
            match unit_type {
                DW_UT_SKELETON | DW_UT_SPLIT_COMPILE => {
                    dwo_id = Some(r.uint(8)?);
                }
                DW_UT_TYPE | DW_UT_SPLIT_TYPE => {
                    r.uint(8)?;
                    r.offset(dwarf64)?;
                }
                _ => {}
            }
        } else {
            abbrev_offset = r.offset(dwarf64)?;
            address_size = r.u8()?;
            unit_type = if section == UnitSection::Types {
                r.uint(8)?;
                r.offset(dwarf64)?;
                DW_UT_TYPE
            } else {
                DW_UT_COMPILE
            };
        }
        if address_size != 4 && address_size != 8 {
            return None;
        }
        Some(Self {
            section,
            offset: pos as u64,
            end: end as u64,
            version,
            dwarf64,
            address_size,
            unit_type,
            abbrev_offset,
            dies: r.pos as u64,
            addr_base: if version >= 5 { 8 } else { 0 },
            str_offsets_base: if version >= 5 { 8 } else { 0 },
            rnglists_base: 0,
            loclists_base: 0,
            low_pc: 0,
            split: unit_type == DW_UT_SPLIT_COMPILE || unit_type == DW_UT_SPLIT_TYPE,
            dwo_id,
            source: 0,
            data: &data[..end],
            s,
        })
    }

    pub fn sections(&self) -> &Sections<'d> {
        &self.s
    }

    /// A reader of the unit's DIEs.
    pub fn dies(&self) -> DieReader<'d> {
        DieReader {
            r: Reader::new(
                self.data,
                usize::try_from(self.dies).unwrap_or(usize::MAX),
                self.s.endian,
            ),
            depth: 0,
            offset: 0,
        }
    }

    /// Records the bases of the unit's top DIE attributes
    /// (`DW_AT_addr_base` and the like), which later attributes use.
    pub fn set_bases(&mut self, attrs: &[Attr<'d>]) {
        for a in attrs {
            if let Value::Uint(v) = a.value {
                match a.name {
                    DW_AT_ADDR_BASE | DW_AT_GNU_ADDR_BASE => self.addr_base = v,
                    DW_AT_STR_OFFSETS_BASE => self.str_offsets_base = v,
                    DW_AT_RNGLISTS_BASE => self.rnglists_base = v,
                    DW_AT_LOCLISTS_BASE => self.loclists_base = v,
                    _ => {}
                }
            }
        }
        // The base address, which may be indexed through the address base.
        if let Some(a) = attrs.iter().find(|a| a.name == DW_AT_LOW_PC) {
            self.low_pc = self.uint(&a.value).unwrap_or(0);
        }
    }

    pub fn max_address(&self) -> u64 {
        if self.address_size == 8 {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        }
    }

    /// Whether `addr` is a real address (not 0 or the all-ones tombstone
    /// of discarded code).
    pub fn is_valid_address(&self, addr: u64) -> bool {
        addr != 0 && addr != self.max_address()
    }

    /// The address at `index` of `.debug_addr`.
    pub fn indexed_address(&self, index: u64) -> Option<u64> {
        let n = u64::from(self.address_size);
        let at = self.addr_base.checked_add(index.checked_mul(n)?)?;
        Reader::new(self.s.addr, usize::try_from(at).ok()?, self.s.endian)
            .uint(usize::from(self.address_size))
    }

    /// A string value, resolved.
    pub fn string(&self, v: &Value<'d>) -> Option<StrRef<'d>> {
        let (sec, off) = match *v {
            Value::Str(b) => return Some(StrRef { bytes: b, at: None }),
            Value::StrOffset(sec, off) => (sec, off),
            Value::StrIndex(i) => {
                let w: u64 = if self.dwarf64 { 8 } else { 4 };
                let at = self.str_offsets_base.checked_add(i.checked_mul(w)?)?;
                let off = Reader::new(self.s.str_offsets, usize::try_from(at).ok()?, self.s.endian)
                    .uint(usize::try_from(w).ok()?)?;
                (StrSection::Str, off)
            }
            _ => return None,
        };
        let data = match sec {
            StrSection::Str => self.s.str,
            StrSection::LineStr => self.s.line_str,
        };
        let bytes = Reader::new(data, usize::try_from(off).ok()?, self.s.endian).cstr()?;
        Some(StrRef {
            bytes,
            at: Some((sec, off)),
        })
    }

    /// An unsigned value (constants, addresses, `DW_FORM_dataN` as
    /// numbers), resolved through `.debug_addr` for indexed addresses.
    pub fn uint(&self, v: &Value<'d>) -> Option<u64> {
        match *v {
            Value::Uint(x) | Value::Addr(x) => Some(x),
            Value::Sint(x) => Some(x as u64),
            Value::AddrIndex(i) => self.indexed_address(i),
            Value::Data(b) if matches!(b.len(), 1 | 2 | 4 | 8) => {
                Reader::new(b, 0, self.s.endian).uint(b.len())
            }
            _ => None,
        }
    }

    /// Reads one attribute value of `form`.
    pub fn read_value(&self, r: &mut Reader<'d>, form: u16, implicit: i64) -> Option<Value<'d>> {
        let w = if self.dwarf64 { 8 } else { 4 };
        Some(match form {
            DW_FORM_ADDR => Value::Addr(r.uint(usize::from(self.address_size))?),
            DW_FORM_BLOCK1 => {
                let n = r.uint(1)?;
                Value::Block(r.bytes(n)?)
            }
            DW_FORM_BLOCK2 => {
                let n = r.uint(2)?;
                Value::Block(r.bytes(n)?)
            }
            DW_FORM_BLOCK4 => {
                let n = r.uint(4)?;
                Value::Block(r.bytes(n)?)
            }
            DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
                let n = r.uleb()?;
                Value::Block(r.bytes(n)?)
            }
            DW_FORM_DATA1 => Value::Data(r.bytes(1)?),
            DW_FORM_DATA2 => Value::Data(r.bytes(2)?),
            DW_FORM_DATA4 => Value::Data(r.bytes(4)?),
            DW_FORM_DATA8 => Value::Data(r.bytes(8)?),
            DW_FORM_DATA16 => Value::Data(r.bytes(16)?),
            DW_FORM_STRING => Value::Str(r.cstr()?),
            DW_FORM_FLAG => Value::Uint(r.uint(1)?),
            DW_FORM_FLAG_PRESENT => Value::Uint(1),
            DW_FORM_SDATA => Value::Sint(r.sleb()?),
            DW_FORM_UDATA | DW_FORM_REF_UDATA => Value::Uint(r.uleb()?),
            DW_FORM_STRP => Value::StrOffset(StrSection::Str, r.uint(w)?),
            DW_FORM_LINE_STRP => Value::StrOffset(StrSection::LineStr, r.uint(w)?),
            DW_FORM_STRP_SUP | DW_FORM_GNU_STRP_ALT => Value::Uint(r.uint(w)?),
            DW_FORM_REF_SUP4 => Value::Uint(r.uint(4)?),
            DW_FORM_REF_SUP8 => Value::Uint(r.uint(8)?),
            DW_FORM_REF_ADDR => {
                if self.version <= 2 {
                    Value::Uint(r.uint(usize::from(self.address_size))?)
                } else {
                    Value::Uint(r.uint(w)?)
                }
            }
            DW_FORM_SEC_OFFSET | DW_FORM_GNU_REF_ALT => Value::Uint(r.uint(w)?),
            DW_FORM_REF1 => Value::Uint(r.uint(1)?),
            DW_FORM_REF2 => Value::Uint(r.uint(2)?),
            DW_FORM_REF4 => Value::Uint(r.uint(4)?),
            DW_FORM_REF8 | DW_FORM_REF_SIG8 => Value::Uint(r.uint(8)?),
            DW_FORM_STRX | DW_FORM_GNU_STR_INDEX => Value::StrIndex(r.uleb()?),
            DW_FORM_STRX1 => Value::StrIndex(r.uint(1)?),
            DW_FORM_STRX2 => Value::StrIndex(r.uint(2)?),
            DW_FORM_STRX3 => Value::StrIndex(r.uint(3)?),
            DW_FORM_STRX4 => Value::StrIndex(r.uint(4)?),
            DW_FORM_ADDRX | DW_FORM_GNU_ADDR_INDEX => Value::AddrIndex(r.uleb()?),
            DW_FORM_ADDRX1 => Value::AddrIndex(r.uint(1)?),
            DW_FORM_ADDRX2 => Value::AddrIndex(r.uint(2)?),
            DW_FORM_ADDRX3 => Value::AddrIndex(r.uint(3)?),
            DW_FORM_ADDRX4 => Value::AddrIndex(r.uint(4)?),
            DW_FORM_LOCLISTX | DW_FORM_RNGLISTX => Value::ListIndex(r.uleb()?),
            DW_FORM_IMPLICIT_CONST => Value::Sint(implicit),
            DW_FORM_INDIRECT => {
                let f = u16::try_from(r.uleb()?).ok()?;
                if f == DW_FORM_INDIRECT {
                    return None;
                }
                return self.read_value(r, f, implicit);
            }
            _ => return None,
        })
    }

    /// The address of a location that is exactly one `DW_OP_addr` (or
    /// `DW_OP_addrx`) operation: a variable at a fixed address.
    pub fn location_address(&self, v: &Value<'d>) -> Option<u64> {
        let Value::Block(b) = *v else { return None };
        let mut r = Reader::new(b, 1, self.s.endian);
        let a = match *b.first()? {
            DW_OP_ADDR => r.uint(usize::from(self.address_size))?,
            DW_OP_ADDRX | DW_OP_GNU_ADDR_INDEX => self.indexed_address(r.uleb()?)?,
            _ => return None,
        };
        r.is_empty().then_some(a)
    }

    /// The entries of a location list: `(start, end, expression)`, the
    /// addresses absolute. A default location (DWARF 5) covers every
    /// address. `offset` is of `.debug_loc` for DWARF 2-4 (where the
    /// unit's `DW_AT_low_pc` is the base), of `.debug_loclists` for DWARF 5.
    pub fn location_list(&self, offset: u64) -> Option<Vec<(u64, u64, &'d [u8])>> {
        if self.version >= 5 {
            return self.loclist(offset);
        }
        if self.split {
            return self.split_location_list(offset);
        }
        let mut r = Reader::new(self.s.loc, usize::try_from(offset).ok()?, self.s.endian);
        let n = usize::from(self.address_size);
        let mut base = self.low_pc;
        let mut out = Vec::new();
        loop {
            let (a, b) = (r.uint(n)?, r.uint(n)?);
            if a == 0 && b == 0 {
                break;
            }
            if a == self.max_address() {
                base = b;
                continue;
            }
            let len = r.uint(2)?;
            let expr = r.bytes(len)?;
            out.push((base.wrapping_add(a), base.wrapping_add(b), expr));
        }
        Some(out)
    }

    /// A location list of GNU's split DWARF 4 (`.debug_loc.dwo`, at
    /// `offset` of the unit's contribution): DWARF 5's first entry kinds,
    /// with indexed addresses, 4-byte lengths, and 2-byte expression
    /// lengths.
    fn split_location_list(&self, offset: u64) -> Option<Vec<(u64, u64, &'d [u8])>> {
        let at = self.loclists_base.checked_add(offset)?;
        let mut r = Reader::new(self.s.loc, usize::try_from(at).ok()?, self.s.endian);
        let mut base = self.low_pc;
        let mut out = Vec::new();
        let expr = |r: &mut Reader<'d>| {
            let len = r.uint(2)?;
            r.bytes(len)
        };
        loop {
            match r.u8()? {
                DW_LLE_END_OF_LIST => break,
                DW_LLE_BASE_ADDRESSX => base = self.indexed_address(r.uleb()?)?,
                DW_LLE_STARTX_ENDX => {
                    let s = self.indexed_address(r.uleb()?)?;
                    let e = self.indexed_address(r.uleb()?)?;
                    out.push((s, e, expr(&mut r)?));
                }
                DW_LLE_STARTX_LENGTH => {
                    let s = self.indexed_address(r.uleb()?)?;
                    let len = r.uint(4)?;
                    out.push((s, s.wrapping_add(len), expr(&mut r)?));
                }
                DW_LLE_OFFSET_PAIR => {
                    let s = r.uint(4)?.wrapping_add(base);
                    let e = r.uint(4)?.wrapping_add(base);
                    out.push((s, e, expr(&mut r)?));
                }
                _ => return None,
            }
        }
        Some(out)
    }

    /// The offset of the `.debug_loclists` list a `DW_FORM_loclistx`
    /// index names.
    pub fn loclist_offset(&self, index: u64) -> Option<u64> {
        let w: u64 = if self.dwarf64 { 8 } else { 4 };
        let at = self.loclists_base.checked_add(index.checked_mul(w)?)?;
        let off = Reader::new(self.s.loclists, usize::try_from(at).ok()?, self.s.endian)
            .uint(usize::try_from(w).ok()?)?;
        self.loclists_base.checked_add(off)
    }

    fn loclist(&self, offset: u64) -> Option<Vec<(u64, u64, &'d [u8])>> {
        let mut r = Reader::new(
            self.s.loclists,
            usize::try_from(offset).ok()?,
            self.s.endian,
        );
        let n = usize::from(self.address_size);
        let mut base = self.low_pc;
        let mut out = Vec::new();
        let expr = |r: &mut Reader<'d>| {
            let len = r.uleb()?;
            r.bytes(len)
        };
        loop {
            match r.u8()? {
                DW_LLE_END_OF_LIST => break,
                DW_LLE_BASE_ADDRESSX => base = self.indexed_address(r.uleb()?)?,
                DW_LLE_STARTX_ENDX => {
                    let s = self.indexed_address(r.uleb()?)?;
                    let e = self.indexed_address(r.uleb()?)?;
                    out.push((s, e, expr(&mut r)?));
                }
                DW_LLE_STARTX_LENGTH => {
                    let s = self.indexed_address(r.uleb()?)?;
                    let len = r.uleb()?;
                    out.push((s, s.wrapping_add(len), expr(&mut r)?));
                }
                DW_LLE_OFFSET_PAIR => {
                    let s = r.uleb()?.wrapping_add(base);
                    let e = r.uleb()?.wrapping_add(base);
                    out.push((s, e, expr(&mut r)?));
                }
                DW_LLE_DEFAULT_LOCATION => out.push((0, u64::MAX, expr(&mut r)?)),
                DW_LLE_BASE_ADDRESS => base = r.uint(n)?,
                DW_LLE_START_END => {
                    let s = r.uint(n)?;
                    let e = r.uint(n)?;
                    out.push((s, e, expr(&mut r)?));
                }
                DW_LLE_START_LENGTH => {
                    let s = r.uint(n)?;
                    let len = r.uleb()?;
                    out.push((s, s.wrapping_add(len), expr(&mut r)?));
                }
                // A view pair (GNU) names views, not addresses: skipped.
                DW_LLE_GNU_VIEW_PAIR => {
                    r.uleb()?;
                    r.uleb()?;
                }
                _ => return None,
            }
        }
        Some(out)
    }

    /// The bytes of the location list at `offset` of `.debug_loc` (DWARF
    /// 2-4): its extent, through the terminating entry.
    pub fn location_list_len(&self, offset: u64) -> Option<u64> {
        let start = usize::try_from(offset).ok()?;
        let mut r = Reader::new(self.s.loc, start, self.s.endian);
        let n = usize::from(self.address_size);
        loop {
            let (a, b) = (r.uint(n)?, r.uint(n)?);
            if a == 0 && b == 0 {
                break;
            }
            if a != self.max_address() {
                let len = r.uint(2)?;
                r.bytes(len)?;
            }
        }
        Some((r.pos - start) as u64)
    }

    /// The ranges of the `.debug_ranges` list at `offset` (DWARF 2-4),
    /// relative to `base` (the unit's `DW_AT_low_pc`) until a base
    /// address entry: `(start, size)` pairs, and the list's length.
    pub fn range_list(&self, offset: u64, base: u64) -> Option<(Vec<(u64, u64)>, u64)> {
        let start = usize::try_from(offset).ok()?;
        let mut r = Reader::new(self.s.ranges, start, self.s.endian);
        let n = usize::from(self.address_size);
        let mut base = base;
        let mut out = Vec::new();
        loop {
            let (a, b) = (r.uint(n)?, r.uint(n)?);
            if a == 0 && b == 0 {
                break;
            }
            if a == self.max_address() {
                base = b;
            } else if b >= a {
                out.push((base.wrapping_add(a), b - a));
            }
        }
        Some((out, (r.pos - start) as u64))
    }

    /// The offset of the `.debug_rnglists` list a `DW_FORM_rnglistx` index
    /// names.
    pub fn rnglist_offset(&self, index: u64) -> Option<u64> {
        let w: u64 = if self.dwarf64 { 8 } else { 4 };
        let at = self.rnglists_base.checked_add(index.checked_mul(w)?)?;
        let off = Reader::new(self.s.rnglists, usize::try_from(at).ok()?, self.s.endian)
            .uint(usize::try_from(w).ok()?)?;
        self.rnglists_base.checked_add(off)
    }

    /// The ranges of the `.debug_rnglists` list at `offset` (DWARF 5):
    /// `(start, size)` pairs, and the list's length.
    pub fn rnglist(&self, offset: u64) -> Option<(Vec<(u64, u64)>, u64)> {
        let start = usize::try_from(offset).ok()?;
        let mut r = Reader::new(self.s.rnglists, start, self.s.endian);
        let n = usize::from(self.address_size);
        let mut base = self.low_pc;
        let mut out = Vec::new();
        loop {
            match r.u8()? {
                DW_RLE_END_OF_LIST => break,
                DW_RLE_BASE_ADDRESSX => base = self.indexed_address(r.uleb()?)?,
                DW_RLE_STARTX_ENDX => {
                    let s = self.indexed_address(r.uleb()?)?;
                    let e = self.indexed_address(r.uleb()?)?;
                    out.push((s, e.wrapping_sub(s)));
                }
                DW_RLE_STARTX_LENGTH => {
                    let s = self.indexed_address(r.uleb()?)?;
                    out.push((s, r.uleb()?));
                }
                DW_RLE_OFFSET_PAIR => {
                    let s = r.uleb()?.wrapping_add(base);
                    let e = r.uleb()?.wrapping_add(base);
                    out.push((s, e.wrapping_sub(s)));
                }
                DW_RLE_BASE_ADDRESS => base = r.uint(n)?,
                DW_RLE_START_END => {
                    let s = r.uint(n)?;
                    let e = r.uint(n)?;
                    out.push((s, e.wrapping_sub(s)));
                }
                DW_RLE_START_LENGTH => {
                    let s = r.uint(n)?;
                    out.push((s, r.uleb()?));
                }
                _ => return None,
            }
        }
        Some((out, (r.pos - start) as u64))
    }
}

/// An attribute of a DIE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr<'d> {
    pub name: u16,
    pub form: u16,
    pub value: Value<'d>,
}

/// A DIE, read: where it is, its tag, and its attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Die<'d> {
    /// Where it starts in its unit's section.
    pub offset: u64,
    pub tag: u16,
    /// Whether children follow it.
    pub children: bool,
    pub attrs: Vec<Attr<'d>>,
    /// Where what follows it starts: its first child, if it has children.
    pub next: u64,
}

impl<'d> Die<'d> {
    /// Its attribute `name`.
    pub fn attr(&self, name: u16) -> Option<&Attr<'d>> {
        self.attrs.iter().find(|a| a.name == name)
    }

    /// Whether it has the flag `name` set.
    pub fn flag(&self, name: u16) -> bool {
        self.attr(name)
            .is_some_and(|a| matches!(a.value, Value::Uint(v) if v != 0))
    }
}

/// At most this many children are read of one DIE.
const MAX_CHILDREN: usize = 1 << 20;

impl<'d> Unit<'d> {
    /// Whether `offset` (of the unit's section) is among the unit's DIEs.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.dies && offset < self.end
    }

    fn reader_at(&self, offset: u64, depth: i64) -> Option<DieReader<'d>> {
        if !self.contains(offset) {
            return None;
        }
        Some(DieReader {
            r: Reader::new(self.data, usize::try_from(offset).ok()?, self.s.endian),
            depth,
            offset,
        })
    }

    /// The DIE at `offset` of the unit's section (which must be in the
    /// unit), read with the unit's `abbrevs`.
    pub fn entry(&self, abbrevs: &Abbrevs, offset: u64) -> Option<Die<'d>> {
        let mut r = self.reader_at(offset, 0)?;
        // (A null entry is no DIE.)
        if self.data.get(usize::try_from(offset).ok()?) == Some(&0) {
            return None;
        }
        let a = r.next(abbrevs)?;
        let mut attrs = Vec::new();
        r.attrs(self, a, &mut attrs)?;
        Some(Die {
            offset,
            tag: a.tag,
            children: a.children,
            attrs,
            next: r.position(),
        })
    }

    /// The direct children of `parent` (read with the unit's `abbrevs`),
    /// in order.
    pub fn children(&self, abbrevs: &Abbrevs, parent: &Die<'d>) -> Vec<Die<'d>> {
        let mut out = Vec::new();
        if !parent.children {
            return out;
        }
        let Some(mut r) = self.reader_at(parent.next, 1) else {
            return out;
        };
        let mut attrs = Vec::new();
        while out.len() < MAX_CHILDREN {
            r.skip_nulls();
            if r.depth < 1 || r.r.is_empty() {
                break;
            }
            let Some(a) = r.next(abbrevs) else { break };
            let offset = r.offset;
            if r.attrs(self, a, &mut attrs).is_none() {
                break;
            }
            out.push(Die {
                offset,
                tag: a.tag,
                children: a.children,
                attrs: attrs.clone(),
                next: r.position(),
            });
            if r.skip_children(self, abbrevs, a).is_none() {
                break;
            }
        }
        out
    }

    /// Where a reference attribute's DIE is, in the unit's section: the
    /// unit-relative forms are relative to the unit; `DW_FORM_ref_addr` is
    /// already section-relative. (`DW_FORM_ref_sig8` names a type unit by
    /// its signature, and references to supplementary files are in other
    /// files: neither is an offset here.)
    pub fn reference(&self, attr: &Attr<'d>) -> Option<u64> {
        let Value::Uint(v) = attr.value else {
            return None;
        };
        match attr.form {
            DW_FORM_REF1 | DW_FORM_REF2 | DW_FORM_REF4 | DW_FORM_REF8 | DW_FORM_REF_UDATA => {
                self.offset.checked_add(v)
            }
            DW_FORM_REF_ADDR => Some(v),
            _ => None,
        }
    }

    /// The type signature of a type unit (DWARF 5 `DW_UT_type`, or a
    /// DWARF 4 `.debug_types` unit), and where its type's DIE is.
    pub fn type_signature(&self) -> Option<(u64, u64)> {
        if self.unit_type != DW_UT_TYPE && self.unit_type != DW_UT_SPLIT_TYPE {
            return None;
        }
        // After the initial length, version, and (in DWARF 5) the unit
        // type and address size, or (DWARF 4) the abbreviation offset and
        // address size.
        let w: usize = if self.dwarf64 { 8 } else { 4 };
        let len = if self.dwarf64 { 12 } else { 4 };
        let at = usize::try_from(self.offset).ok()?
            + len
            + 2
            + if self.version >= 5 { 2 + w } else { w + 1 };
        let mut r = Reader::new(self.data, at, self.s.endian);
        let signature = r.uint(8)?;
        let type_offset = r.uint(w)?;
        Some((signature, self.offset.checked_add(type_offset)?))
    }
}

/// Reads a unit's DIEs in order, tracking their depth.
#[derive(Clone, Copy, Debug)]
pub struct DieReader<'d> {
    r: Reader<'d>,
    pub depth: i64,
    /// Where the DIE last returned by `next` starts.
    pub offset: u64,
}

impl<'d> DieReader<'d> {
    /// The next DIE's abbreviation, skipping null entries; `None` at the
    /// end of the unit or on an unknown code.
    pub fn next<'t>(&mut self, abbrevs: &'t Abbrevs) -> Option<&'t Abbrev> {
        self.skip_nulls();
        if self.r.is_empty() {
            return None;
        }
        self.offset = self.r.pos as u64;
        let code = self.r.uleb()?;
        let a = abbrevs.get(code)?;
        if a.children {
            self.depth += 1;
        }
        Some(a)
    }

    fn skip_nulls(&mut self) {
        while self.r.data.get(self.r.pos) == Some(&0) {
            self.r.pos += 1;
            self.depth -= 1;
        }
    }

    /// Where the reader is (the end of the DIE just read, once its
    /// attributes are).
    pub fn position(&self) -> u64 {
        self.r.pos as u64
    }

    /// Reads the DIE's attributes into `out`.
    pub fn attrs(
        &mut self,
        unit: &Unit<'d>,
        abbrev: &Abbrev,
        out: &mut Vec<Attr<'d>>,
    ) -> Option<()> {
        out.clear();
        for spec in &abbrev.attrs {
            let value = unit.read_value(&mut self.r, spec.form, spec.implicit)?;
            out.push(Attr {
                name: spec.name,
                form: spec.form,
                value,
            });
        }
        Some(())
    }

    /// Skips the children of the DIE just read (whose attributes have been
    /// read).
    pub fn skip_children(
        &mut self,
        unit: &Unit<'d>,
        abbrevs: &Abbrevs,
        abbrev: &Abbrev,
    ) -> Option<()> {
        if !abbrev.children {
            return Some(());
        }
        let target = self.depth - 1;
        let mut scratch = Vec::new();
        self.skip_nulls();
        while self.depth > target {
            let Some(a) = self.next(abbrevs) else {
                return Some(());
            };
            self.attrs(unit, a, &mut scratch)?;
            self.skip_nulls();
        }
        Some(())
    }
}

/// A DWARF 5 per-unit table (`.debug_str_offsets`, `.debug_addr`,
/// `.debug_rnglists`, `.debug_loclists`) whose entries start at `base`:
/// the extent of its contribution, header included. `header` is the
/// header's size after the initial length (4 for string offsets and
/// addresses, 8 for range and location lists).
pub fn contribution(data: &[u8], base: u64, header: u64, endian: Endian) -> Option<(u64, u64)> {
    for (len_size, dwarf64) in [(4u64, false), (12, true)] {
        let Some(start) = base.checked_sub(header + len_size) else {
            continue;
        };
        let mut r = Reader::new(data, usize::try_from(start).ok()?, endian);
        if let Some((_, end, d64)) = r.initial_length()
            && d64 == dwarf64
        {
            return Some((start, end as u64 - start));
        }
    }
    None
}

/// One `.debug_aranges` set entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArangeEntry {
    /// The unit it describes, by its `.debug_info` offset.
    pub info_offset: u64,
    pub address: u64,
    pub length: u64,
    pub address_size: u8,
    /// Where the entry lies in `.debug_aranges`.
    pub offset: u64,
    pub size: u64,
}

/// The entries of `.debug_aranges`.
pub fn aranges(data: &[u8], endian: Endian) -> Vec<ArangeEntry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let mut r = Reader::new(data, pos, endian);
        let Some((_, end, dwarf64)) = r.initial_length() else {
            break;
        };
        r.data = &data[..end];
        let (Some(_version), Some(info_offset), Some(address_size), Some(segment)) =
            (r.uint(2), r.offset(dwarf64), r.u8(), r.u8())
        else {
            break;
        };
        pos = end;
        if segment != 0 || (address_size != 4 && address_size != 8) {
            continue;
        }
        // The first entry is aligned to twice the address size.
        let align = 2 * usize::from(address_size);
        r.pos = r.pos.next_multiple_of(align);
        let n = usize::from(address_size);
        while r.pos + 2 * n <= end {
            let at = r.pos;
            let (Some(address), Some(length)) = (r.uint(n), r.uint(n)) else {
                break;
            };
            if address == 0 && length == 0 {
                break;
            }
            out.push(ArangeEntry {
                info_offset,
                address,
                length,
                address_size,
                offset: at as u64,
                size: 2 * n as u64,
            });
        }
    }
    out
}

/// A name-table (`.debug_pubnames`, `.debug_pubtypes`) set: the unit it
/// describes and the set's extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameSet {
    pub info_offset: u64,
    pub offset: u64,
    pub size: u64,
}

pub fn name_sets(data: &[u8], endian: Endian) -> Vec<NameSet> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let mut r = Reader::new(data, pos, endian);
        let Some((_, end, dwarf64)) = r.initial_length() else {
            break;
        };
        let (Some(_), Some(info_offset)) = (r.uint(2), r.offset(dwarf64)) else {
            break;
        };
        out.push(NameSet {
            info_offset,
            offset: pos as u64,
            size: (end - pos) as u64,
        });
        pos = end;
    }
    out
}

/// The extent of the line-number program at `offset` of `.debug_line`
/// (its unit, initial length included).
pub fn line_program_len(data: &[u8], offset: u64, endian: Endian) -> Option<u64> {
    let start = usize::try_from(offset).ok()?;
    let mut r = Reader::new(data, start, endian);
    let (_, end, _) = r.initial_length()?;
    Some((end - start) as u64)
}

/// `v`'s low `bytes` bytes, sign-extended.
pub(crate) fn sext(v: u64, bytes: u32) -> u64 {
    let shift = 64 - 8 * bytes.clamp(1, 8);
    (((v << shift) as i64) >> shift) as u64
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod cfi_tests;
#[cfg(test)]
mod expr_tests;
#[cfg(test)]
mod tests;

//! Function bodies: their locals, their instructions decoded, and each
//! instruction as text (the WebAssembly text format's plain form:
//! `i32.load offset=16`, `br_table 0 1 2`, `f32.const 1.5`).
//!
//! Decoding is bounded by the bytes given: malformed or truncated code
//! gives an error at the offending instruction, never a panic, and
//! nothing is allocated in proportion to a count before its items are
//! read.

use alloc::vec::Vec;
use core::fmt;

use hexcavator_core::{Error, ErrorKind, Result};

use crate::ops::{self, Kind, Op};

/// A heap type: abstract, or a type index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeapType {
    /// `func`.
    Func,
    /// `extern`.
    Extern,
    /// `any`.
    Any,
    /// `eq`.
    Eq,
    /// `i31`.
    I31,
    /// `struct`.
    Struct,
    /// `array`.
    Array,
    /// `exn`.
    Exn,
    /// `none`.
    None,
    /// `noextern`.
    NoExtern,
    /// `nofunc`.
    NoFunc,
    /// `noexn`.
    NoExn,
    /// A type in the type section, by index.
    Index(u32),
}

/// A value type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValType {
    /// `i32`.
    I32,
    /// `i64`.
    I64,
    /// `f32`.
    F32,
    /// `f64`.
    F64,
    /// `v128`.
    V128,
    /// A reference type.
    Ref {
        /// Whether it may be null.
        nullable: bool,
        /// What it refers to.
        heap: HeapType,
    },
}

/// A block's type: no values, one, or a function type's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockType {
    /// No result.
    Empty,
    /// One result.
    Value(ValType),
    /// A function type, by index.
    Index(u32),
}

/// A memory access's alignment (log2 bytes), memory, and offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemArg {
    /// The alignment, as a power of two.
    pub align: u32,
    /// The memory (0 unless multi-memory).
    pub memory: u32,
    /// The offset.
    pub offset: u64,
}

/// A `try_table` catch clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Catch {
    /// `catch`: a tag's exception, to a label.
    Catch {
        /// The tag.
        tag: u32,
        /// The label.
        label: u32,
    },
    /// `catch_ref`: likewise, with the exception's reference.
    CatchRef {
        /// The tag.
        tag: u32,
        /// The label.
        label: u32,
    },
    /// `catch_all`: any exception, to a label.
    CatchAll {
        /// The label.
        label: u32,
    },
    /// `catch_all_ref`: likewise, with its reference.
    CatchAllRef {
        /// The label.
        label: u32,
    },
}

/// An instruction's immediates.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Imm {
    /// None.
    None,
    /// A block type (`block`, `loop`, `if`).
    Block(BlockType),
    /// One index (a label, function, local, global, table, memory, tag,
    /// type, data or element segment) or lane.
    Index(u32),
    /// Two: (type, table) of `call_indirect`, (data, memory) of
    /// `memory.init`, (destination, source) of the copies, (element,
    /// table) of `table.init`, and the GC instructions' pairs.
    Two(u32, u32),
    /// The labels, the default last.
    BrTable(Vec<u32>),
    /// `select`'s types.
    SelectT(Vec<ValType>),
    /// `try_table`'s type and catches.
    TryTable(BlockType, Vec<Catch>),
    /// A memory access.
    MemArg(MemArg),
    /// A memory access and a lane.
    MemArgLane(MemArg, u8),
    /// An `i32` constant.
    I32(i32),
    /// An `i64` constant.
    I64(i64),
    /// A float's bits.
    F32(u32),
    /// An `f64` constant's bits.
    F64(u64),
    /// A `v128` constant.
    V128([u8; 16]),
    /// `i8x16.shuffle`'s lanes.
    Shuffle([u8; 16]),
    /// A heap type.
    Heap(HeapType),
    /// A reference type (`ref.test`, `ref.cast`).
    Ref(ValType),
    /// `br_on_cast` and `br_on_cast_fail`.
    BrOnCast {
        /// The label.
        label: u32,
        /// The type cast from.
        from: ValType,
        /// The type cast to.
        to: ValType,
    },
}

/// A decoded instruction: what it is, its immediates, and its length in
/// bytes.
#[derive(Clone, Debug)]
pub struct Instruction {
    /// The instruction.
    pub op: &'static Op,
    /// Its immediates.
    pub imm: Imm,
    /// Its length in bytes.
    pub len: usize,
}

/// A function body's locals: (count, type) groups, and where the code
/// after them starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locals {
    /// The locals: (count, type) groups.
    pub groups: Vec<(u32, ValType)>,
    /// Where the code starts, in the body.
    pub code_start: usize,
}

struct Reader<'d> {
    data: &'d [u8],
    pos: usize,
}

impl Reader<'_> {
    fn err(&self, kind: ErrorKind, what: &'static str) -> Error {
        Error::new(kind, self.pos as u64, what)
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.err(ErrorKind::Truncated, "instruction"))?;
        self.pos += 1;
        Ok(b)
    }

    /// An unsigned LEB128 of at most `bits` bits.
    fn uleb(&mut self, bits: u32) -> Result<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift >= bits || (bits - shift < 7 && u32::from(b & 0x7F) >> (bits - shift) != 0) {
                return Err(self.err(ErrorKind::Malformed, "LEB128 integer too large"));
            }
            v |= u64::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
    }

    fn u32(&mut self) -> Result<u32> {
        let v = self.uleb(32)?;
        u32::try_from(v).map_err(|_| self.err(ErrorKind::Malformed, "LEB128 integer too large"))
    }

    /// A signed LEB128 of at most `bits` bits.
    fn sleb(&mut self, bits: u32) -> Result<i64> {
        let mut v = 0i64;
        let mut shift = 0u32;
        loop {
            let b = self.u8()?;
            if shift >= bits {
                return Err(self.err(ErrorKind::Malformed, "LEB128 integer too large"));
            }
            if shift < 64 {
                v |= i64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Ok(v);
            }
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.checked_add(N).filter(|&e| e <= self.data.len());
        let end = end.ok_or_else(|| self.err(ErrorKind::Truncated, "immediate"))?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(out)
    }

    fn heap_type(&mut self) -> Result<HeapType> {
        let v = self.sleb(33)?;
        Ok(match v {
            -16 => HeapType::Func,
            -17 => HeapType::Extern,
            -18 => HeapType::Any,
            -19 => HeapType::Eq,
            -20 => HeapType::I31,
            -21 => HeapType::Struct,
            -22 => HeapType::Array,
            -23 => HeapType::Exn,
            -15 => HeapType::None,
            -14 => HeapType::NoExtern,
            -13 => HeapType::NoFunc,
            -12 => HeapType::NoExn,
            v if v >= 0 => HeapType::Index(
                u32::try_from(v).map_err(|_| self.err(ErrorKind::Malformed, "type index"))?,
            ),
            _ => return Err(self.err(ErrorKind::Malformed, "heap type")),
        })
    }

    /// A value type starting with byte `b` (already read).
    fn val_type_from(&mut self, b: u8) -> Result<ValType> {
        let abstract_ref = |heap| ValType::Ref {
            nullable: true,
            heap,
        };
        Ok(match b {
            0x7F => ValType::I32,
            0x7E => ValType::I64,
            0x7D => ValType::F32,
            0x7C => ValType::F64,
            0x7B => ValType::V128,
            0x70 => abstract_ref(HeapType::Func),
            0x6F => abstract_ref(HeapType::Extern),
            0x6E => abstract_ref(HeapType::Any),
            0x6D => abstract_ref(HeapType::Eq),
            0x6C => abstract_ref(HeapType::I31),
            0x6B => abstract_ref(HeapType::Struct),
            0x6A => abstract_ref(HeapType::Array),
            0x69 => abstract_ref(HeapType::Exn),
            0x71 => abstract_ref(HeapType::None),
            0x72 => abstract_ref(HeapType::NoExtern),
            0x73 => abstract_ref(HeapType::NoFunc),
            0x74 => abstract_ref(HeapType::NoExn),
            0x63 | 0x64 => ValType::Ref {
                nullable: b == 0x63,
                heap: self.heap_type()?,
            },
            _ => return Err(self.err(ErrorKind::Malformed, "value type")),
        })
    }

    fn val_type(&mut self) -> Result<ValType> {
        let b = self.u8()?;
        self.val_type_from(b)
    }

    fn block_type(&mut self) -> Result<BlockType> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.err(ErrorKind::Truncated, "block type"))?;
        if b == 0x40 {
            self.pos += 1;
            return Ok(BlockType::Empty);
        }
        // A value type's first byte, as an s33, is negative; a type index
        // isn't.
        if b & 0xC0 == 0x40 {
            self.pos += 1;
            return Ok(BlockType::Value(self.val_type_from(b)?));
        }
        let v = self.sleb(33)?;
        u32::try_from(v)
            .map(BlockType::Index)
            .map_err(|_| self.err(ErrorKind::Malformed, "block type"))
    }

    fn mem_arg(&mut self) -> Result<MemArg> {
        let flags = self.u32()?;
        // Bit 6: a memory index follows (multiple memories).
        let memory = if flags & 0x40 != 0 { self.u32()? } else { 0 };
        let align = flags & !0x40;
        if align >= 64 {
            return Err(self.err(ErrorKind::Malformed, "alignment"));
        }
        let offset = self.uleb(64)?;
        Ok(MemArg {
            align,
            memory,
            offset,
        })
    }

    /// A list of `count` items, each read by `f` (none allocated ahead of
    /// being read).
    fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let n = self.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }
}

/// The locals of a function body (a code section entry's contents, after
/// its size).
pub fn locals(body: &[u8]) -> Result<Locals> {
    let mut r = Reader { data: body, pos: 0 };
    let groups = r.list(|r| Ok((r.u32()?, r.val_type()?)))?;
    Ok(Locals {
        groups,
        code_start: r.pos,
    })
}

/// Decodes the instruction at the start of `code`.
pub fn decode(code: &[u8]) -> Result<Instruction> {
    let mut r = Reader { data: code, pos: 0 };
    let first = r.u8()?;
    let (prefix, opcode) = if ops::is_prefix(first) {
        (first, r.u32()?)
    } else {
        (0, u32::from(first))
    };
    let op = ops::lookup(prefix, opcode)
        .ok_or_else(|| Error::new(ErrorKind::Malformed, 0, "unknown opcode"))?;
    let imm = match op.kind {
        Kind::None => Imm::None,
        Kind::Block => Imm::Block(r.block_type()?),
        Kind::Label
        | Kind::Func
        | Kind::Type
        | Kind::Tag
        | Kind::Local
        | Kind::Global
        | Kind::Table
        | Kind::Memory
        | Kind::Data
        | Kind::Elem => Imm::Index(r.u32()?),
        Kind::Lane => Imm::Index(u32::from(r.u8()?)),
        Kind::CallIndirect
        | Kind::MemoryInit
        | Kind::MemoryCopy
        | Kind::TableCopy
        | Kind::TableInit
        | Kind::TypeField
        | Kind::TypeType
        | Kind::TypeData
        | Kind::TypeElem
        | Kind::TypeN => Imm::Two(r.u32()?, r.u32()?),
        Kind::BrTable => {
            let mut labels = r.list(Reader::u32)?;
            labels.push(r.u32()?);
            Imm::BrTable(labels)
        }
        Kind::SelectT => Imm::SelectT(r.list(Reader::val_type)?),
        Kind::TryTable => {
            let block = r.block_type()?;
            let catches = r.list(|r| {
                Ok(match r.u8()? {
                    0 => Catch::Catch {
                        tag: r.u32()?,
                        label: r.u32()?,
                    },
                    1 => Catch::CatchRef {
                        tag: r.u32()?,
                        label: r.u32()?,
                    },
                    2 => Catch::CatchAll { label: r.u32()? },
                    3 => Catch::CatchAllRef { label: r.u32()? },
                    _ => return Err(r.err(ErrorKind::Malformed, "catch clause")),
                })
            })?;
            Imm::TryTable(block, catches)
        }
        Kind::MemArg => Imm::MemArg(r.mem_arg()?),
        Kind::MemArgLane => {
            let m = r.mem_arg()?;
            Imm::MemArgLane(m, r.u8()?)
        }
        Kind::I32 => {
            let v = r.sleb(32)?;
            Imm::I32(i32::try_from(v).map_err(|_| r.err(ErrorKind::Malformed, "i32 constant"))?)
        }
        Kind::I64 => Imm::I64(r.sleb(64)?),
        Kind::F32 => Imm::F32(u32::from_le_bytes(r.array()?)),
        Kind::F64 => Imm::F64(u64::from_le_bytes(r.array()?)),
        Kind::V128 => Imm::V128(r.array()?),
        Kind::Shuffle => Imm::Shuffle(r.array()?),
        Kind::HeapType => {
            let heap = r.heap_type()?;
            if op.name == "ref.null" {
                Imm::Heap(heap)
            } else {
                Imm::Ref(ValType::Ref {
                    nullable: false,
                    heap,
                })
            }
        }
        Kind::NullHeapType => Imm::Ref(ValType::Ref {
            nullable: true,
            heap: r.heap_type()?,
        }),
        Kind::Fence => {
            if r.u8()? != 0 {
                return Err(r.err(ErrorKind::Malformed, "atomic.fence"));
            }
            Imm::None
        }
        Kind::BrOnCast => {
            let flags = r.u8()?;
            let label = r.u32()?;
            let from = ValType::Ref {
                nullable: flags & 1 != 0,
                heap: r.heap_type()?,
            };
            let to = ValType::Ref {
                nullable: flags & 2 != 0,
                heap: r.heap_type()?,
            };
            Imm::BrOnCast { label, from, to }
        }
    };
    Ok(Instruction {
        op,
        imm,
        len: r.pos,
    })
}

/// The instructions of `code` (from a body's `code_start`), each with its
/// offset in `code`; an error ends them.
pub fn instructions(code: &[u8]) -> impl Iterator<Item = (usize, Result<Instruction>)> + '_ {
    let mut pos = 0;
    let mut failed = false;
    core::iter::from_fn(move || {
        if failed || pos >= code.len() {
            return None;
        }
        let at = pos;
        match decode(&code[pos..]) {
            Ok(i) => {
                pos += i.len;
                Some((at, Ok(i)))
            }
            Err(e) => {
                failed = true;
                // (The error's offset is within the instruction.)
                Some((
                    at,
                    Err(Error::new(
                        e.kind,
                        (at as u64).saturating_add(e.offset),
                        e.what,
                    )),
                ))
            }
        }
    })
}

/// The natural alignment (log2 bytes) of a memory instruction's access.
pub fn natural_align(name: &str) -> u32 {
    let has = |s: &str| name.contains(s);
    // SIMD loads of half a vector, extended.
    if has("8x8") || has("16x4") || has("32x2") {
        return 3;
    }
    for (pattern, align) in [
        ("8_splat", 0),
        ("16_splat", 1),
        ("32_splat", 2),
        ("64_splat", 3),
        ("32_zero", 2),
        ("64_zero", 3),
        ("8_lane", 0),
        ("16_lane", 1),
        ("32_lane", 2),
        ("64_lane", 3),
    ] {
        if has(pattern) {
            return align;
        }
    }
    if name.starts_with("v128.") {
        return 4;
    }
    if has("_f16") {
        return 1;
    }
    if name == "memory.atomic.notify" || name == "memory.atomic.wait32" {
        return 2;
    }
    if name == "memory.atomic.wait64" {
        return 3;
    }
    // load8, store16, rmw32, ...: the access size after the operation.
    for (op, rest) in [("load", 4), ("store", 5), ("rmw", 3)] {
        if let Some(i) = name.find(op) {
            let after = &name[i + rest..];
            if after.starts_with('8') {
                return 0;
            }
            if after.starts_with("16") {
                return 1;
            }
            if after.starts_with("32") {
                return 2;
            }
        }
    }
    if name.starts_with("i64") || name.starts_with("f64") {
        3
    } else {
        2
    }
}

impl fmt::Display for HeapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HeapType::Func => "func",
            HeapType::Extern => "extern",
            HeapType::Any => "any",
            HeapType::Eq => "eq",
            HeapType::I31 => "i31",
            HeapType::Struct => "struct",
            HeapType::Array => "array",
            HeapType::Exn => "exn",
            HeapType::None => "none",
            HeapType::NoExtern => "noextern",
            HeapType::NoFunc => "nofunc",
            HeapType::NoExn => "noexn",
            HeapType::Index(i) => return write!(f, "{i}"),
        })
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValType::I32 => f.write_str("i32"),
            ValType::I64 => f.write_str("i64"),
            ValType::F32 => f.write_str("f32"),
            ValType::F64 => f.write_str("f64"),
            ValType::V128 => f.write_str("v128"),
            ValType::Ref {
                nullable: true,
                heap,
            } if !matches!(heap, HeapType::Index(_)) => {
                // The shorthands: funcref, nullexternref, ...
                let short = match heap {
                    HeapType::None => "null",
                    HeapType::NoExtern => "nullextern",
                    HeapType::NoFunc => "nullfunc",
                    HeapType::NoExn => "nullexn",
                    _ => "",
                };
                if short.is_empty() {
                    write!(f, "{heap}ref")
                } else {
                    write!(f, "{short}ref")
                }
            }
            ValType::Ref { nullable, heap } => {
                write!(f, "(ref {}{heap})", if *nullable { "null " } else { "" })
            }
        }
    }
}

impl fmt::Display for BlockType {
    /// As it follows `block` (with its leading space, or nothing).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Empty => Ok(()),
            BlockType::Value(t) => write!(f, " (result {t})"),
            BlockType::Index(i) => write!(f, " (type {i})"),
        }
    }
}

/// A float as the text format writes it: decimal, `inf`, or `nan` (with
/// its payload where it isn't the canonical one).
fn float(
    f: &mut fmt::Formatter<'_>,
    negative: bool,
    value: f64,
    nan: Option<(u64, u64)>,
) -> fmt::Result {
    let sign = if negative { "-" } else { "" };
    match nan {
        Some((payload, canonical)) if payload == canonical => write!(f, "{sign}nan"),
        Some((payload, _)) => write!(f, "{sign}nan:{payload:#x}"),
        None if value.is_infinite() => write!(f, "{sign}inf"),
        None => Ok(()),
    }
}

fn f32_text(f: &mut fmt::Formatter<'_>, bits: u32) -> fmt::Result {
    let v = f32::from_bits(bits);
    if v.is_nan() || v.is_infinite() {
        let nan = v
            .is_nan()
            .then_some((u64::from(bits & 0x7F_FFFF), 0x40_0000));
        return float(f, bits >> 31 == 1, f64::from(v), nan);
    }
    let a = v.abs();
    if a != 0.0 && !(1e-5..1e16).contains(&a) {
        write!(f, "{v:e}")
    } else {
        write!(f, "{v}")
    }
}

fn f64_text(f: &mut fmt::Formatter<'_>, bits: u64) -> fmt::Result {
    let v = f64::from_bits(bits);
    if v.is_nan() || v.is_infinite() {
        let nan = v
            .is_nan()
            .then_some((bits & 0xF_FFFF_FFFF_FFFF, 0x8_0000_0000_0000));
        return float(f, bits >> 63 == 1, v, nan);
    }
    let a = v.abs();
    if a != 0.0 && !(1e-5..1e16).contains(&a) {
        write!(f, "{v:e}")
    } else {
        write!(f, "{v}")
    }
}

fn mem_arg(f: &mut fmt::Formatter<'_>, name: &str, m: &MemArg) -> fmt::Result {
    if m.memory != 0 {
        write!(f, " {}", m.memory)?;
    }
    if m.offset != 0 {
        write!(f, " offset={}", m.offset)?;
    }
    if m.align != natural_align(name) {
        write!(f, " align={}", 1u64 << m.align)?;
    }
    Ok(())
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.op.name;
        f.write_str(name)?;
        match (&self.imm, self.op.kind) {
            (Imm::None, _) => Ok(()),
            (Imm::Block(b), _) => write!(f, "{b}"),
            // Memory 0 needn't be named.
            (Imm::Index(0), Kind::Memory) => Ok(()),
            (Imm::Index(i), _) => write!(f, " {i}"),
            (Imm::Two(t, 0), Kind::CallIndirect) => write!(f, " (type {t})"),
            (Imm::Two(t, table), Kind::CallIndirect) => write!(f, " {table} (type {t})"),
            (Imm::Two(data, 0), Kind::MemoryInit) => write!(f, " {data}"),
            (Imm::Two(data, memory), Kind::MemoryInit) => write!(f, " {memory} {data}"),
            (Imm::Two(elem, 0), Kind::TableInit) => write!(f, " {elem}"),
            (Imm::Two(elem, table), Kind::TableInit) => write!(f, " {table} {elem}"),
            (Imm::Two(0, 0), Kind::MemoryCopy | Kind::TableCopy) => Ok(()),
            (Imm::Two(a, b), _) => write!(f, " {a} {b}"),
            (Imm::BrTable(labels), _) => {
                for l in labels {
                    write!(f, " {l}")?;
                }
                Ok(())
            }
            (Imm::SelectT(types), _) => {
                f.write_str(" (result")?;
                for t in types {
                    write!(f, " {t}")?;
                }
                f.write_str(")")
            }
            (Imm::TryTable(block, catches), _) => {
                write!(f, "{block}")?;
                for c in catches {
                    match c {
                        Catch::Catch { tag, label } => write!(f, " (catch {tag} {label})")?,
                        Catch::CatchRef { tag, label } => write!(f, " (catch_ref {tag} {label})")?,
                        Catch::CatchAll { label } => write!(f, " (catch_all {label})")?,
                        Catch::CatchAllRef { label } => write!(f, " (catch_all_ref {label})")?,
                    }
                }
                Ok(())
            }
            (Imm::MemArg(m), _) => mem_arg(f, name, m),
            (Imm::MemArgLane(m, lane), _) => {
                mem_arg(f, name, m)?;
                write!(f, " {lane}")
            }
            (Imm::I32(v), _) => write!(f, " {v}"),
            (Imm::I64(v), _) => write!(f, " {v}"),
            (Imm::F32(bits), _) => {
                f.write_str(" ")?;
                f32_text(f, *bits)
            }
            (Imm::F64(bits), _) => {
                f.write_str(" ")?;
                f64_text(f, *bits)
            }
            (Imm::V128(b), _) => {
                f.write_str(" i32x4")?;
                for lane in b.as_chunks::<4>().0 {
                    let v = u32::from_le_bytes([lane[0], lane[1], lane[2], lane[3]]);
                    write!(f, " {v:#010x}")?;
                }
                Ok(())
            }
            (Imm::Shuffle(lanes), _) => {
                for l in lanes {
                    write!(f, " {l}")?;
                }
                Ok(())
            }
            (Imm::Heap(h), _) => write!(f, " {h}"),
            (Imm::Ref(t), _) => write!(f, " {t}"),
            (Imm::BrOnCast { label, from, to }, _) => write!(f, " {label} {from} {to}"),
        }
    }
}

/// How an instruction changes the nesting of blocks: +1 for one that
/// opens a block, -1 for `end`, and 0 for those (`else`, `catch`) that
/// continue one; for indenting a listing.
pub fn nesting(op: &Op) -> i32 {
    match (op.prefix, op.code) {
        (0, 0x02..=0x04 | 0x06 | 0x1F) => 1,
        (0, 0x0B) => -1,
        // `delegate` ends a `try`.
        (0, 0x18) => -1,
        _ => 0,
    }
}

/// Whether an instruction continues the block it's in at the block's own
/// indentation (`else`, `catch`, `catch_all`).
pub fn is_continuation(op: &Op) -> bool {
    matches!((op.prefix, op.code), (0, 0x05 | 0x07 | 0x19))
}

#[cfg(test)]
mod tests;

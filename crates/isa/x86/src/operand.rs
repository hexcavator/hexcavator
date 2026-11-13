//! Decoded operands.

use crate::Register;

/// The size of a memory operand, as the assembler names it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MemSize {
    /// No size is implied (`lea`, `prefetch`, `fxsave`, ...).
    None,
    /// One byte.
    Byte,
    /// Two bytes.
    Word,
    /// Four bytes.
    Dword,
    /// 8 bytes of integer or x87 data.
    Qword,
    /// 8 bytes of MMX/SSE data.
    Mmword,
    /// 16 bytes of integer data (`cmpxchg16b`).
    Oword,
    /// Sixteen bytes of vector.
    Xmmword,
    /// Thirty-two bytes of vector.
    Ymmword,
    /// Sixty-four bytes of vector.
    Zmmword,
    /// 10 bytes (x87 extended precision, far pointers with a 64-bit offset).
    Tbyte,
    /// 6 bytes (far pointers with a 32-bit offset, descriptor tables).
    Fword,
    /// 64 bytes of AMX tile configuration.
    Zword,
    /// An AMX tile (its size depends on the tile configuration).
    Tile,
}

impl MemSize {
    /// Its size in bytes.
    pub const fn bytes(self) -> u16 {
        match self {
            MemSize::None => 0,
            MemSize::Byte => 1,
            MemSize::Word => 2,
            MemSize::Dword => 4,
            MemSize::Qword | MemSize::Mmword => 8,
            MemSize::Oword | MemSize::Xmmword => 16,
            MemSize::Ymmword => 32,
            MemSize::Zmmword => 64,
            MemSize::Tbyte => 10,
            MemSize::Fword => 6,
            MemSize::Zword => 64,
            MemSize::Tile => 0,
        }
    }

    /// Its name, as Intel syntax writes it (`dword`).
    pub const fn name(self) -> &'static str {
        match self {
            MemSize::None => "",
            MemSize::Byte => "byte",
            MemSize::Word => "word",
            MemSize::Dword => "dword",
            MemSize::Qword => "qword",
            MemSize::Mmword => "mmword",
            MemSize::Oword => "oword",
            MemSize::Xmmword => "xmmword",
            MemSize::Ymmword => "ymmword",
            MemSize::Zmmword => "zmmword",
            MemSize::Tbyte => "tbyte",
            MemSize::Fword => "fword",
            MemSize::Zword => "zword",
            MemSize::Tile => "tile",
        }
    }

    /// The conventional name for a size in bytes (8 is `qword`).
    pub const fn from_bytes(bytes: u16) -> Self {
        match bytes {
            1 => MemSize::Byte,
            2 => MemSize::Word,
            4 => MemSize::Dword,
            6 => MemSize::Fword,
            8 => MemSize::Qword,
            10 => MemSize::Tbyte,
            16 => MemSize::Xmmword,
            32 => MemSize::Ymmword,
            64 => MemSize::Zmmword,
            _ => MemSize::None,
        }
    }
}

/// A memory operand: `segment:[base + index*scale + disp]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    /// An explicit segment override, if any.
    pub segment: Option<Register>,
    /// The base register; `rip`/`eip` for RIP-relative addressing.
    pub base: Option<Register>,
    /// The index register (a vector register for VSIB).
    pub index: Option<Register>,
    /// The index's scale (1, 2, 4, or 8).
    pub scale: u8,
    /// The displacement, sign-extended (and, for EVEX, already scaled). For
    /// RIP-relative operands this is relative to the next instruction.
    pub disp: i64,
    /// The encoded displacement width in bytes (0, 1, 2, 4, or 8).
    pub disp_size: u8,
    /// The size of what is accessed.
    pub size: MemSize,
    /// The address size in bytes (2, 4, or 8).
    pub address_size: u8,
    /// For an EVEX broadcast, the number of elements (otherwise 0); `size`
    /// is then the element size.
    pub broadcast: u8,
    /// Whether this is a direct `moffs` operand (A0-A3), whose address is
    /// always shown with at least 32 bits.
    pub moffs: bool,
}

impl Memory {
    /// Whether it is relative to the next instruction.
    #[inline]
    pub fn is_rip_relative(&self) -> bool {
        self.base.is_some_and(|b| b.class() == crate::RegClass::Ip)
    }
}

/// An immediate value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Immediate {
    /// The value, sign- or zero-extended to `size` bytes as the instruction
    /// defines, and zero above that.
    pub value: u64,
    /// The operand size in bytes the value applies to.
    pub size: u8,
}

/// One decoded operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Operand {
    /// None.
    #[default]
    None,
    /// A register.
    Reg(Register),
    /// Memory.
    Mem(Memory),
    /// An immediate.
    Imm(Immediate),
    /// A branch target (already resolved to an absolute address).
    Rel(u64),
    /// A far pointer immediate.
    Far {
        /// The segment.
        segment: u16,
        /// The offset.
        offset: u32,
        /// The offset's size in bytes (2 or 4).
        offset_size: u8,
    },
}

//! The opcode-table types. `build.rs` compiles `tables/*.txt` into static
//! arrays of these.

/// Where an operand comes from.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Loc {
    None,
    /// ModRM.rm: a general-purpose register or memory.
    GprRm,
    /// ModRM.rm, register form only.
    GprRmReg,
    /// ModRM.rm, memory form only.
    Mem,
    /// ModRM.reg general-purpose register.
    GprReg,
    /// VEX/EVEX.vvvv general-purpose register.
    GprVvvv,
    /// The low three bits of the opcode (plus REX.B).
    GprOpcode,
    /// An immediate, zero-extended.
    Imm,
    /// An 8-bit immediate, sign-extended to the operand size.
    ImmSx8,
    /// A 32-bit (or 16-bit) immediate, sign-extended to a 64-bit operand.
    ImmSx,
    /// A second immediate (ENTER, EXTRQ, INSERTQ).
    Imm2,
    /// A relative branch target.
    Rel,
    /// A direct memory offset (`moffs`), as wide as the address size.
    Moffs,
    /// A far pointer immediate, `ptr16:16` or `ptr16:32`.
    FarPtr,
    /// String source, `ds:[rsi]`.
    StrSrc,
    /// String destination, `es:[rdi]`.
    StrDst,
    /// `xlat`: `ds:[rbx]`.
    Xlat,
    /// A fixed register (in `fixed`).
    Fixed,
    /// A fixed general-purpose register whose size is the operand size
    /// (`fixed` is its index): `rAX`, `rDX`, ...
    FixedGpr,
    /// The constant 1 (shifts).
    One,
    /// `st(i)` from ModRM.rm.
    StRm,
    MmxReg,
    /// ModRM.rm: an MMX register or memory.
    MmxRm,
    MmxRmReg,
    VecReg,
    VecVvvv,
    /// ModRM.rm: a vector register or memory.
    VecRm,
    VecRmReg,
    /// A vector register in bits 7:4 of an 8-bit immediate.
    VecIs4,
    /// The low two bits of the imm8 that holds a `VecIs4` register.
    Is4Low,
    SegReg,
    CrReg,
    DrReg,
    /// 386/486 test registers.
    TrReg,
    KReg,
    /// ModRM.rm: a mask register or memory.
    KRm,
    KRmReg,
    KVvvv,
    TmmReg,
    TmmRmReg,
    TmmVvvv,
    BndReg,
    /// ModRM.rm: a bound register or memory.
    BndRm,
    /// A VSIB memory operand; `vsize` is the index register width.
    Vsib,
    /// A 64-bit absolute branch target (JMPABS).
    Abs64,
}

/// An operand or memory size. Fixed sizes are in bytes; the others depend on
/// the instruction's operand size or vector length.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Size {
    /// No size (`lea`, `prefetch`): memory is shown without `ptr`.
    None,
    B,
    W,
    D,
    /// 8 bytes, shown as `qword`.
    Q,
    /// 8 bytes, shown as `mmword`.
    Mm,
    /// 16 bytes, shown as `oword`.
    O,
    /// 16 bytes, shown as `xmmword`.
    X,
    /// 32 bytes, `ymmword`.
    Y,
    /// 64 bytes, `zmmword`.
    Z,
    /// 10 bytes, `tbyte`.
    T,
    /// 6 bytes, `fword`.
    F,
    /// Operand size: 2, 4, or 8.
    V,
    /// 2 or 4: the operand size, capped at 4.
    Z4,
    /// 4 or 8: 8 with REX.W, else 4.
    Yw,
    /// A far pointer: 2 + the operand size.
    P,
    /// The vector length.
    Vl,
    /// Half the vector length.
    VlHalf,
    /// A quarter of the vector length.
    VlQuarter,
    /// An eighth of the vector length.
    VlEighth,
    /// The address size (for `moffs` and the like).
    A,
    /// 64 bytes, shown as `zword` (AMX tile configuration).
    Zw,
    /// An AMX tile in memory, shown as `tile`.
    Tile,
    /// Two operand-size values (`bound`).
    Pair,
}

/// How an operand is located and sized.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpSpec {
    pub loc: Loc,
    /// The register size or width (general-purpose, vector, VSIB index), or
    /// the immediate size.
    pub size: Size,
    /// The memory size, for operands that can be memory.
    pub msize: Size,
    /// For `Loc::Fixed`: the register, as `RegClass as u16` << 8 | index.
    pub fixed: u16,
}

impl OpSpec {
    pub const NONE: Self = Self {
        loc: Loc::None,
        size: Size::None,
        msize: Size::None,
        fixed: 0,
    };
}

/// The disp8*N compression tuple type of an EVEX instruction.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tuple {
    None,
    /// Full vector: N = vector length, or element size with broadcast.
    Fv,
    /// Half vector: N = half the vector length, or element size with broadcast.
    Hv,
    /// Full vector memory: N = vector length.
    Fvm,
    /// Half/quarter/eighth vector memory.
    Hvm,
    Qvm,
    /// Quarter vector: N = a quarter of the vector length, or the element
    /// size with broadcast.
    Qv,
    Ovm,
    /// One scalar element: N = element size.
    T1s,
    /// One fixed-size element (N = `elem`), independent of EVEX.W.
    T1f,
    /// Two, four, or eight elements.
    T2,
    T4,
    T8,
    /// 16 bytes regardless of vector length.
    M128,
    /// `vmovddup`: 8, 32, or 64 bytes.
    Dup,
}

/// Instruction attributes.
pub(crate) mod attr {
    pub const LOCK: u32 = 1 << 0;
    /// F3 is shown as `rep`.
    pub const REP: u32 = 1 << 1;
    /// F3 is shown as `repe` and F2 as `repne`.
    pub const REPE: u32 = 1 << 2;
    /// Operand size defaults to 64 bits in 64-bit mode.
    pub const D64: u32 = 1 << 3;
    /// Operand size is always 64 bits in 64-bit mode.
    pub const F64: u32 = 1 << 4;
    /// EVEX: merge masking allowed.
    pub const MASK: u32 = 1 << 5;
    /// EVEX: zero masking allowed.
    pub const ZERO: u32 = 1 << 6;
    /// EVEX: a mask other than k0 is required.
    pub const MASK_REQ: u32 = 1 << 7;
    /// EVEX: memory broadcast allowed.
    pub const BCST: u32 = 1 << 8;
    /// EVEX: embedded rounding allowed (register form).
    pub const ER: u32 = 1 << 9;
    /// EVEX: suppress-all-exceptions allowed (register form).
    pub const SAE: u32 = 1 << 10;
    /// The operand size is 16 bits regardless of prefixes (in 64-bit mode
    /// with REX.W it is still 16): used by a few instructions.
    pub const OS16: u32 = 1 << 11;
    /// 66 is a mandatory prefix only in the sense of selecting this entry;
    /// it does not change the operand size.
    pub const NO66: u32 = 1 << 12;
    /// F2 is shown as `bnd` (MPX branch prefix).
    pub const BND: u32 = 1 << 13;
    /// Accepts the XACQUIRE/XRELEASE hints.
    pub const HLE: u32 = 1 << 14;
    /// VEX/EVEX.vvvv must be 1111b (unused).
    pub const NOVVVV: u32 = 1 << 15;
    /// A compare whose immediate selects a pseudo-op (`cmpltps`).
    pub const CMP_PSEUDO: u32 = 1 << 16;
    /// Element size is 8 bytes when W is 1, else 4 (EVEX).
    pub const ELEM_W: u32 = 1 << 17;
    /// 3DNow!: the opcode is the trailing immediate byte.
    pub const SUFFIX: u32 = 1 << 18;
    /// The operand size is 32 bits in 64-bit mode unless REX.W is set (the
    /// usual rule), but 66 has no effect.
    pub const NO_OS16: u32 = 1 << 19;
    /// Operand size is 64 bits in 64-bit mode regardless of REX.W, as for
    /// `mov cr`/`mov dr` (registers are full width).
    pub const MODE_SIZE: u32 = 1 << 20;
    /// EVEX: the instruction's memory operand is written, so broadcast is
    /// not allowed and zero-masking is invalid with memory.
    pub const STORE: u32 = 1 << 21;
    /// VEX/EVEX: the vector length field is ignored (scalar).
    pub const LIG: u32 = 1 << 22;
    /// 66 selects this entry and also sets a 16-bit operand size.
    pub const OS66: u32 = 1 << 23;
    /// Shown with a `vex` prefix (the instruction also has an EVEX form).
    pub const VEX_PREFIX: u32 = 1 << 24;
    /// APX: an EVEX-promoted general-purpose instruction, whose last EVEX
    /// payload byte holds ND (new data destination), NF (no flags), and
    /// the condition of CCMP/CTEST in place of masking and broadcast.
    pub const APX: u32 = 1 << 25;
    /// APX: EVEX.NF suppresses the flags (shown as `{nf}`).
    pub const NF: u32 = 1 << 26;
    /// APX: an EVEX promotion of a legacy instruction, shown as `{evex}`
    /// unless its NF or ND says why it is EVEX.
    pub const EVEX_PROMOTED: u32 = 1 << 27;
    /// APX: CCMP/CTEST: the payload's low bits are the source condition,
    /// and EVEX.vvvv the default flags value.
    pub const SCC: u32 = 1 << 28;
    /// APX PUSH2/POP2: neither register may be `rsp`.
    pub const NORSP: u32 = 1 << 29;
    /// Only with a REX2 prefix (PUSHP, POPP, JMPABS).
    pub const REX2: u32 = 1 << 30;
    /// An EVEX promotion of a VEX (or legacy 0F38) instruction, whose other
    /// encoding can't reach r16-r31: shown as `{evex}` only when no such
    /// register says why it is EVEX.
    pub const EVEX_VEX: u32 = 1 << 31;
}

/// One opcode table entry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub mnemonic: crate::Mnemonic,
    pub ops: [OpSpec; 5],
    /// 0 = any, 1 = none of 66/F2/F3, 2 = 66, 3 = F3, 4 = F2.
    pub pfx: u8,
    /// Required ModRM.reg, or 0xFF.
    pub reg: u8,
    /// Required ModRM.rm (register form), or 0xFF.
    pub rm: u8,
    /// 0 = any, 1 = memory form only, 2 = register form only.
    pub md: u8,
    /// Allowed W values, as a bit mask (bit 0 = W0, bit 1 = W1).
    pub w: u8,
    /// Allowed vector lengths, as a bit mask (bit n = L'L of n).
    pub l: u8,
    /// 0 = any, 1 = 64-bit mode only, 2 = not in 64-bit mode.
    pub mode: u8,
    /// Allowed operand sizes, as a bit mask (bit 0 = 16, bit 1 = 32, bit 2 = 64).
    pub os: u8,
    /// Allowed address sizes, likewise.
    pub asz: u8,
    pub attrs: u32,
    pub tuple: Tuple,
    /// EVEX element size in bytes (0: by `ELEM_W` or not applicable).
    pub elem: u8,
    /// APX: allowed EVEX.ND values, as a bit mask (bit 0 = 0, bit 1 = 1).
    pub nd: u8,
    /// APX: allowed EVEX.NF values, likewise.
    pub nf: u8,
    /// APX CCMP/CTEST: the source condition this entry is for.
    pub scc: u8,
}

/// Opcode maps, in table order.
pub(crate) mod map {
    pub const LEGACY: usize = 0;
    pub const M0F: usize = 1;
    pub const M0F38: usize = 2;
    pub const M0F3A: usize = 3;
    pub const AMD3DNOW: usize = 4;
    pub const VEX0F: usize = 5;
    pub const VEX0F38: usize = 6;
    pub const VEX0F3A: usize = 7;
    pub const EVEX0F: usize = 8;
    pub const EVEX0F38: usize = 9;
    pub const EVEX0F3A: usize = 10;
    pub const EVEX4: usize = 11;
    pub const EVEX5: usize = 12;
    pub const EVEX6: usize = 13;
    pub const XOP8: usize = 14;
    pub const XOP9: usize = 15;
    pub const XOPA: usize = 16;
    pub const EVEX7: usize = 17;
    pub const VEX7: usize = 18;
    pub const VEX5: usize = 19;
    pub const COUNT: usize = 20;
}

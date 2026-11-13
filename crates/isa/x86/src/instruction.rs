//! Decoded instructions.

use crate::spec::attr;
use crate::{Mnemonic, Mode, Operand};

/// How the instruction was encoded.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    /// Legacy (and REX) encoding.
    Legacy,
    /// Legacy with an APX REX2 prefix.
    Rex2,
    /// A VEX prefix (AVX).
    Vex,
    /// An EVEX prefix (AVX-512).
    Evex,
    /// An XOP prefix (AMD).
    Xop,
    /// AMD's 3DNow! (`0F 0F`, its opcode last).
    ThreeDNow,
}

/// EVEX embedded rounding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rounding {
    /// To nearest (`{rn-sae}`).
    Nearest,
    /// Down (`{rd-sae}`).
    Down,
    /// Up (`{ru-sae}`).
    Up,
    /// Toward zero (`{rz-sae}`).
    Zero,
}

/// Prefixes that affect how the instruction is shown or behaves.
pub mod prefix {
    /// `lock`.
    pub const LOCK: u16 = 1 << 0;
    /// `rep` (on a string instruction without a condition).
    pub const REP: u16 = 1 << 1;
    /// `repe`/`repz`.
    pub const REPE: u16 = 1 << 2;
    /// `repne`/`repnz`.
    pub const REPNE: u16 = 1 << 3;
    /// `bnd` (MPX).
    pub const BND: u16 = 1 << 4;
    /// `xacquire` (HLE).
    pub const XACQUIRE: u16 = 1 << 5;
    /// `xrelease` (HLE).
    pub const XRELEASE: u16 = 1 << 6;
    /// `3E` on a conditional branch.
    pub const HINT_TAKEN: u16 = 1 << 7;
    /// `2E` on a conditional branch.
    pub const HINT_NOT_TAKEN: u16 = 1 << 8;
    /// `F3` with no other meaning (`rep ret`).
    pub const REP_OTHER: u16 = 1 << 9;
    /// A VEX encoding of an instruction that also has an EVEX form.
    pub const VEX: u16 = 1 << 10;
}

/// How control leaves an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// An unconditional jump.
    Jump,
    /// A conditional jump (falls through or branches).
    ConditionalJump,
    /// A call.
    Call,
    /// A return.
    Return,
    /// Traps or stops (`int3`, `ud2`, `hlt`, ...): does not fall through.
    Stop,
    /// Software interrupts and system calls: resumes at the next instruction.
    Interrupt,
}

/// A decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub(crate) mnemonic: Mnemonic,
    pub(crate) len: u8,
    pub(crate) mode: Mode,
    pub(crate) encoding: Encoding,
    pub(crate) op_count: u8,
    pub(crate) ops: [Operand; 5],
    pub(crate) prefixes: u16,
    /// EVEX opmask register (0 = none).
    pub(crate) mask: u8,
    pub(crate) zeroing: bool,
    pub(crate) rounding: Option<Rounding>,
    pub(crate) sae: bool,
    pub(crate) attrs: u32,
    pub(crate) address: u64,
    /// The vector length in bytes, for VEX/EVEX instructions.
    pub(crate) vector_length: u8,
    /// The immediate that selected a pseudo-op mnemonic, if any.
    pub(crate) pseudo_imm: Option<u8>,
    /// APX decorations ([`apx`] bits).
    pub(crate) apx: u8,
    /// APX CCMP/CTEST: the default flags value.
    pub(crate) dfv: u8,
}

/// APX decorations.
pub(crate) mod apx {
    /// `{nf}`: the instruction doesn't update the flags.
    pub const NF: u8 = 1 << 0;
    /// `{evex}`: an EVEX encoding of a legacy instruction.
    pub const EVEX: u8 = 1 << 1;
    /// CCMP/CTEST: has a default flags value.
    pub const DFV: u8 = 1 << 2;
}

impl Instruction {
    /// What it is.
    #[inline]
    pub fn mnemonic(&self) -> Mnemonic {
        self.mnemonic
    }

    /// Its length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether it is empty (it never is).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The mode it was decoded in.
    #[inline]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// How it is encoded.
    #[inline]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// The address the instruction was decoded at.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The address of the next instruction.
    #[inline]
    pub fn next_address(&self) -> u64 {
        self.address.wrapping_add(u64::from(self.len))
    }

    /// Its operands, in Intel order.
    #[inline]
    pub fn operands(&self) -> &[Operand] {
        &self.ops[..usize::from(self.op_count)]
    }

    /// Its prefixes ([`prefix`] bits).
    #[inline]
    pub fn prefixes(&self) -> u16 {
        self.prefixes
    }

    /// The EVEX opmask register index (`k1`..`k7`), if masked.
    #[inline]
    pub fn mask(&self) -> Option<u8> {
        (self.mask != 0).then_some(self.mask)
    }

    /// EVEX zeroing-masking (`{z}`).
    #[inline]
    pub fn zeroing(&self) -> bool {
        self.zeroing
    }

    /// EVEX static rounding, if any.
    #[inline]
    pub fn rounding(&self) -> Option<Rounding> {
        self.rounding
    }

    /// EVEX suppress-all-exceptions (`{sae}`).
    #[inline]
    pub fn suppress_all_exceptions(&self) -> bool {
        self.sae
    }

    /// APX: whether EVEX.NF suppresses the instruction's flag updates
    /// (`{nf}`).
    #[inline]
    pub fn no_flags(&self) -> bool {
        self.apx & apx::NF != 0
    }

    /// APX: whether this is the EVEX encoding of an instruction that also
    /// has a legacy one, with nothing that needs EVEX (`{evex}`).
    #[inline]
    pub fn evex_promoted(&self) -> bool {
        self.apx & apx::EVEX != 0
    }

    /// APX CCMP/CTEST: the flags set when the condition is false, as bits
    /// OF (8), SF (4), ZF (2), and CF (1).
    #[inline]
    pub fn default_flags(&self) -> Option<u8> {
        (self.apx & apx::DFV != 0).then_some(self.dfv)
    }

    /// Its vector length in bytes (16, 32, or 64) for VEX and EVEX; else 0.
    #[inline]
    pub fn vector_length(&self) -> u8 {
        self.vector_length
    }

    #[inline]
    pub(crate) fn has_attr(&self, a: u32) -> bool {
        self.attrs & a != 0
    }

    /// Whether this is a string instruction that accepts `rep`.
    pub fn is_string(&self) -> bool {
        self.has_attr(attr::REP | attr::REPE)
    }

    /// How control leaves this instruction.
    pub fn flow(&self) -> Flow {
        use Mnemonic as M;
        match self.mnemonic {
            M::Jmp | M::Jmpabs => Flow::Jump,
            M::Jo
            | M::Jno
            | M::Jb
            | M::Jae
            | M::Je
            | M::Jne
            | M::Jbe
            | M::Ja
            | M::Js
            | M::Jns
            | M::Jp
            | M::Jnp
            | M::Jl
            | M::Jge
            | M::Jle
            | M::Jg
            | M::Jcxz
            | M::Jecxz
            | M::Jrcxz
            | M::Loop
            | M::Loope
            | M::Loopne
            | M::Xbegin => Flow::ConditionalJump,
            M::Call => Flow::Call,
            M::Ret
            | M::Retf
            | M::Retfq
            | M::Iret
            | M::Iretd
            | M::Iretq
            | M::Sysret
            | M::Sysretq
            | M::Sysexit => Flow::Return,
            M::Int | M::Into | M::Syscall | M::Sysenter => Flow::Interrupt,
            M::Ud2 | M::Hlt => Flow::Stop,
            _ => Flow::Next,
        }
    }

    /// The target of a direct branch or call, if any.
    pub fn branch_target(&self) -> Option<u64> {
        self.operands().iter().find_map(|op| match op {
            Operand::Rel(target) => Some(*target),
            _ => None,
        })
    }
}

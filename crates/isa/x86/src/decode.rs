// Field extraction truncates by design: values are read as u64 and narrowed
// to the width the encoding defines.
#![allow(clippy::cast_possible_truncation)]

//! The instruction decoder.
//!
//! Decoding is a single forward pass over at most 15 bytes: legacy prefixes,
//! REX/REX2/VEX/EVEX, the opcode, ModRM/SIB/displacement, then a match
//! against the opcode table's candidate forms, then immediates.

use crate::instruction::{Encoding, Instruction, Rounding, prefix};
use crate::spec::{Entry, Loc, OpSpec, Size, Tuple, attr, map};
use crate::tables::{ENTRIES, HAS_MODRM, INDEX};
use crate::{Immediate, MemSize, Memory, Mnemonic, Operand, RegClass, Register};

/// The processor mode, which sets default operand and address sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// 16-bit code (real mode, or a 16-bit segment).
    Bits16,
    /// 32-bit code.
    Bits32,
    /// 64-bit code (long mode).
    Bits64,
}

/// Why an instruction could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeError {
    /// The bytes end before the instruction does.
    Truncated,
    /// The bytes do not encode a valid instruction (or one we do not know).
    Invalid,
}

/// The maximum length of an instruction.
pub const MAX_LENGTH: usize = 15;

/// Decodes one instruction at the start of `bytes`, which is at `address`.
pub fn decode(bytes: &[u8], mode: Mode, address: u64) -> Result<Instruction, DecodeError> {
    let bytes = &bytes[..bytes.len().min(MAX_LENGTH)];
    let mut d = Decoder::new(bytes, mode, address);
    d.run()
}

#[derive(Clone, Copy, Default)]
struct ModRm {
    md: u8,
    reg: u8,
    rm: u8,
    // Memory form:
    base: Option<u8>,
    index: Option<u8>,
    scale: u8,
    disp: i64,
    disp_size: u8,
    rip: bool,
    /// The SIB index field (with extensions), even when it means "none":
    /// VSIB uses it unconditionally.
    sib_index: Option<u8>,
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    mode: Mode,
    address: u64,

    lock: bool,
    /// The last of F2/F3, if any.
    rep: u8,
    has_66: bool,
    has_67: bool,
    /// The last segment override (as a segment register index).
    segment: Option<u8>,
    /// The last of 66/F2/F3, which dumpbin treats as the mandatory prefix.
    last_simd: u8,
    seen_simd: u8,
    /// Overrides the mandatory prefix selector (0 = no override).
    mp_override: u8,

    encoding: Encoding,
    rex: bool,
    w: bool,
    /// Register extensions: bit 0 is REX's (R3, X3, B3), bit 1 APX's R4,
    /// X4, B4 (for EVEX.R, EVEX.R').
    r: u8,
    x: u8,
    b: u8,
    // VEX/EVEX:
    vvvv: u8,
    l: u8,
    pp: u8,
    evex_aaa: u8,
    evex_z: bool,
    evex_b: bool,
    /// The raw last EVEX payload byte (APX reads it as ND, NF, and SCC).
    evex_p2: u8,

    map: usize,
    opcode: u8,
    modrm: Option<ModRm>,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], mode: Mode, address: u64) -> Self {
        Self {
            bytes,
            pos: 0,
            mode,
            address,
            lock: false,
            rep: 0,
            has_66: false,
            has_67: false,
            segment: None,
            last_simd: 0,
            seen_simd: 0,
            mp_override: 0,
            encoding: Encoding::Legacy,
            rex: false,
            w: false,
            r: 0,
            x: 0,
            b: 0,
            vvvv: 0,
            l: 0,
            pp: 0,
            evex_aaa: 0,
            evex_z: false,
            evex_b: false,
            evex_p2: 0,
            map: map::LEGACY,
            opcode: 0,
            modrm: None,
        }
    }

    #[inline]
    fn is64(&self) -> bool {
        self.mode == Mode::Bits64
    }

    #[inline]
    fn peek(&self) -> Result<u8, DecodeError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::Truncated)
    }

    #[inline]
    fn next(&mut self) -> Result<u8, DecodeError> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn read_le(&mut self, size: usize) -> Result<u64, DecodeError> {
        let end = self.pos + size;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice
            .iter()
            .rev()
            .fold(0u64, |acc, &b| acc << 8 | u64::from(b)))
    }

    fn address_size(&self) -> u8 {
        match (self.mode, self.has_67) {
            (Mode::Bits64, false) => 8,
            (Mode::Bits64 | Mode::Bits16, true) | (Mode::Bits32, false) => 4,
            _ => 2,
        }
    }

    fn prefixes(&mut self) -> Result<(), DecodeError> {
        loop {
            let b = self.peek()?;
            match b {
                0xF0 => self.lock = true,
                0xF2 | 0xF3 => self.rep = b,
                0x26 => self.segment = Some(0),
                0x2E => self.segment = Some(1),
                0x36 => self.segment = Some(2),
                0x3E => self.segment = Some(3),
                0x64 => self.segment = Some(4),
                0x65 => self.segment = Some(5),
                0x66 => self.has_66 = true,
                0x67 => self.has_67 = true,
                0x40..=0x4F if self.is64() => {
                    self.pos += 1;
                    match self.peek()? {
                        // A legacy prefix after REX cancels the REX.
                        0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66
                        | 0x67 => continue,
                        0x40..=0x4F => continue,
                        _ => {
                            self.rex = true;
                            self.w = b & 8 != 0;
                            self.r = (b >> 2) & 1;
                            self.x = (b >> 1) & 1;
                            self.b = b & 1;
                            return Ok(());
                        }
                    }
                }
                _ => return Ok(()),
            }
            if matches!(b, 0x66 | 0xF2 | 0xF3) {
                let bit = match b {
                    0x66 => 1,
                    0xF2 => 2,
                    _ => 4,
                };
                self.seen_simd |= bit;
                self.last_simd = b;
            }
            self.pos += 1;
            if self.pos >= MAX_LENGTH {
                return Err(DecodeError::Invalid);
            }
        }
    }

    /// Reads the opcode (and any VEX/EVEX/REX2 prefix), setting `map` and `opcode`.
    fn opcode(&mut self) -> Result<(), DecodeError> {
        let b = self.next()?;
        let next_is_reg = |d: &Self| d.bytes.get(d.pos).is_some_and(|&n| n >= 0xC0);
        match b {
            0xD5 if self.is64() => {
                if self.rex {
                    return Err(DecodeError::Invalid);
                }
                let p = self.next()?;
                self.encoding = Encoding::Rex2;
                self.rex = true;
                self.w = p & 0x08 != 0;
                self.r = (p >> 2) & 1 | ((p >> 6) & 1) << 1;
                self.x = (p >> 1) & 1 | ((p >> 5) & 1) << 1;
                self.b = p & 1 | ((p >> 4) & 1) << 1;
                self.map = if p & 0x80 != 0 { map::M0F } else { map::LEGACY };
                self.opcode = self.next()?;
                if rex2_invalid(self.map, self.opcode) {
                    return Err(DecodeError::Invalid);
                }
                // A1 with REX2 is JMPABS, which takes no REX2.W and no
                // 66, 67, F2, or F3.
                if self.map == map::LEGACY
                    && self.opcode == 0xA1
                    && (self.w || self.has_66 || self.has_67 || self.rep != 0)
                {
                    return Err(DecodeError::Invalid);
                }
            }
            0xC5 if self.is64() || next_is_reg(self) => {
                self.vex_prefix_check()?;
                let p = self.next()?;
                self.encoding = Encoding::Vex;
                self.r = !p >> 7 & 1;
                self.vvvv = !p >> 3 & 0xF;
                self.l = p >> 2 & 1;
                self.pp = p & 3;
                self.map = map::VEX0F;
                self.opcode = self.next()?;
            }
            0xC4 if self.is64() || next_is_reg(self) => {
                self.vex_prefix_check()?;
                let p0 = self.next()?;
                let p1 = self.next()?;
                self.encoding = Encoding::Vex;
                self.r = !p0 >> 7 & 1;
                self.x = !p0 >> 6 & 1;
                self.b = !p0 >> 5 & 1;
                self.map = match p0 & 0x1F {
                    1 => map::VEX0F,
                    2 => map::VEX0F38,
                    3 => map::VEX0F3A,
                    5 => map::VEX5,
                    7 => map::VEX7,
                    _ => return Err(DecodeError::Invalid),
                };
                self.w = p1 & 0x80 != 0;
                self.vvvv = !p1 >> 3 & 0xF;
                self.l = p1 >> 2 & 1;
                self.pp = p1 & 3;
                self.opcode = self.next()?;
            }
            0x62 if self.is64() || next_is_reg(self) => {
                self.vex_prefix_check()?;
                let p0 = self.next()?;
                let p1 = self.next()?;
                let p2 = self.next()?;
                self.encoding = Encoding::Evex;
                self.r = (!p0 >> 7 & 1) | (!p0 >> 4 & 1) << 1;
                // APX: B4 is P0 bit 3 (not inverted), X4 the inverse of
                // P1 bit 2 (U, formerly fixed at 1).
                self.x = (!p0 >> 6 & 1) | (!p1 >> 2 & 1) << 1;
                self.b = (!p0 >> 5 & 1) | (p0 >> 3 & 1) << 1;
                if !self.is64() && (p0 & 0x08 != 0 || p1 & 0x04 == 0) {
                    return Err(DecodeError::Invalid);
                }
                self.map = match p0 & 0x07 {
                    1 => map::EVEX0F,
                    2 => map::EVEX0F38,
                    3 => map::EVEX0F3A,
                    4 => map::EVEX4,
                    5 => map::EVEX5,
                    6 => map::EVEX6,
                    7 => map::EVEX7,
                    _ => return Err(DecodeError::Invalid),
                };
                self.w = p1 & 0x80 != 0;
                self.vvvv = (!p1 >> 3 & 0xF) | (!p2 >> 3 & 1) << 4;
                self.pp = p1 & 3;
                self.evex_z = p2 & 0x80 != 0;
                self.l = p2 >> 5 & 3;
                self.evex_b = p2 & 0x10 != 0;
                self.evex_aaa = p2 & 7;
                self.evex_p2 = p2;
                self.opcode = self.next()?;
            }
            // XOP (AMD): 8F with a map of 8 or more in its low five bits; POP
            // r/m (8F /0) has ModRM.reg 0, so its low five bits are below 8.
            0x8F if self.bytes.get(self.pos).is_some_and(|&n| n & 0x1F >= 8) => {
                self.vex_prefix_check()?;
                let p0 = self.next()?;
                let p1 = self.next()?;
                self.encoding = Encoding::Xop;
                self.r = !p0 >> 7 & 1;
                self.x = !p0 >> 6 & 1;
                self.b = !p0 >> 5 & 1;
                self.map = match p0 & 0x1F {
                    8 => map::XOP8,
                    9 => map::XOP9,
                    0x0A => map::XOPA,
                    _ => return Err(DecodeError::Invalid),
                };
                self.w = p1 & 0x80 != 0;
                self.vvvv = !p1 >> 3 & 0xF;
                self.l = p1 >> 2 & 1;
                self.pp = p1 & 3;
                // XOP has no implied prefixes.
                if self.pp != 0 {
                    return Err(DecodeError::Invalid);
                }
                self.opcode = self.next()?;
            }
            0x0F => {
                let b2 = self.next()?;
                match b2 {
                    0x38 => {
                        self.map = map::M0F38;
                        self.opcode = self.next()?;
                    }
                    0x3A => {
                        self.map = map::M0F3A;
                        self.opcode = self.next()?;
                    }
                    0x0F => {
                        self.map = map::AMD3DNOW;
                        self.encoding = Encoding::ThreeDNow;
                    }
                    _ => {
                        self.map = map::M0F;
                        self.opcode = b2;
                    }
                }
            }
            _ => {
                self.map = map::LEGACY;
                self.opcode = b;
            }
        }
        if !self.is64()
            && matches!(
                self.encoding,
                Encoding::Vex | Encoding::Evex | Encoding::Xop
            )
        {
            // Outside 64-bit mode the inverted extension bits are ignored.
            self.r &= !1;
            self.x = 0;
            self.b = 0;
            self.vvvv &= 7;
        }
        Ok(())
    }

    /// VEX and EVEX may not follow 66, F2, F3, F0, or REX.
    fn vex_prefix_check(&self) -> Result<(), DecodeError> {
        if self.has_66 || self.rep != 0 || self.lock || self.rex {
            return Err(DecodeError::Invalid);
        }
        Ok(())
    }

    fn read_modrm(&mut self) -> Result<(), DecodeError> {
        let byte = self.next()?;
        let mut m = ModRm {
            md: byte >> 6,
            reg: byte >> 3 & 7,
            rm: byte & 7,
            scale: 1,
            ..ModRm::default()
        };
        if m.md != 3 {
            match self.address_size() {
                2 => self.modrm16(&mut m)?,
                _ => self.modrm32(&mut m)?,
            }
        }
        self.modrm = Some(m);
        Ok(())
    }

    fn modrm16(&mut self, m: &mut ModRm) -> Result<(), DecodeError> {
        const BASES: [(Option<u8>, Option<u8>); 8] = [
            (Some(3), Some(6)),
            (Some(3), Some(7)),
            (Some(5), Some(6)),
            (Some(5), Some(7)),
            (Some(6), None),
            (Some(7), None),
            (Some(5), None),
            (Some(3), None),
        ];
        let (base, index) = BASES[usize::from(m.rm)];
        m.base = base;
        m.index = index;
        match m.md {
            0 if m.rm == 6 => {
                m.base = None;
                m.disp = i64::from(self.read_le(2)? as u16 as i16);
                m.disp_size = 2;
            }
            1 => {
                m.disp = i64::from(self.next()? as i8);
                m.disp_size = 1;
            }
            2 => {
                m.disp = i64::from(self.read_le(2)? as u16 as i16);
                m.disp_size = 2;
            }
            _ => {}
        }
        Ok(())
    }

    fn modrm32(&mut self, m: &mut ModRm) -> Result<(), DecodeError> {
        let mut base = m.rm;
        if m.rm == 4 {
            let sib = self.next()?;
            m.scale = 1 << (sib >> 6);
            let index = sib >> 3 & 7 | self.x << 3;
            m.sib_index = Some(index);
            m.index = (index != 4).then_some(index);
            base = sib & 7;
            if base == 5 && m.md == 0 {
                m.base = None;
                m.disp = i64::from(self.read_le(4)? as u32 as i32);
                m.disp_size = 4;
                return Ok(());
            }
        } else if m.rm == 5 && m.md == 0 {
            m.disp = i64::from(self.read_le(4)? as u32 as i32);
            m.disp_size = 4;
            m.rip = self.is64();
            return Ok(());
        }
        m.base = Some(base | self.b << 3);
        match m.md {
            1 => {
                m.disp = i64::from(self.next()? as i8);
                m.disp_size = 1;
            }
            2 => {
                m.disp = i64::from(self.read_le(4)? as u32 as i32);
                m.disp_size = 4;
            }
            _ => {}
        }
        Ok(())
    }

    /// The mandatory prefix selector: 1 = none, 2 = 66, 3 = F3, 4 = F2.
    fn mandatory_prefix(&self) -> u8 {
        if matches!(
            self.encoding,
            Encoding::Vex | Encoding::Evex | Encoding::Xop
        ) {
            return self.pp + 1;
        }
        if self.mp_override != 0 {
            return self.mp_override;
        }
        match self.last_simd {
            0x66 => 2,
            0xF3 => 3,
            0xF2 => 4,
            _ => 1,
        }
    }

    /// Whether 66 changes the operand size for this entry.
    fn opsize_prefix(&self, e: &Entry) -> bool {
        // (In APX's EVEX forms, EVEX.pp = 66 is the operand-size prefix.)
        let has_66 = self.has_66
            || (self.encoding == Encoding::Evex && self.pp == 1 && e.attrs & attr::APX != 0);
        has_66
            && (e.pfx != 2 || e.attrs & attr::OS66 != 0)
            && e.attrs & (attr::NO66 | attr::NO_OS16) == 0
    }

    /// The operand size in bytes for this entry.
    fn operand_size(&self, e: &Entry) -> u8 {
        let os16 = self.opsize_prefix(e);
        match self.mode {
            Mode::Bits64 => {
                if e.attrs & attr::F64 != 0 || self.w {
                    8
                } else if os16 {
                    2
                } else if e.attrs & attr::D64 != 0 {
                    8
                } else {
                    4
                }
            }
            Mode::Bits32 => {
                if os16 {
                    2
                } else {
                    4
                }
            }
            Mode::Bits16 => {
                if os16 {
                    4
                } else {
                    2
                }
            }
        }
    }

    fn matches(&self, e: &Entry) -> bool {
        if e.attrs & attr::REX2 != 0 && self.encoding != Encoding::Rex2 {
            return false;
        }
        if e.attrs & attr::APX != 0 {
            if self.encoding != Encoding::Evex {
                return false;
            }
            let p2 = self.evex_p2;
            if e.nd & (1 << (p2 >> 4 & 1)) == 0 {
                return false;
            }
            if e.attrs & attr::SCC != 0 {
                if p2 & 0x0F != e.scc {
                    return false;
                }
            } else if e.nf & (1 << (p2 >> 2 & 1)) == 0 {
                return false;
            }
        }
        let pfx_ok = match e.pfx {
            0 => true,
            p => p == self.mandatory_prefix(),
        };
        if !pfx_ok {
            return false;
        }
        if let Some(m) = &self.modrm {
            if e.reg != 0xFF && m.reg != e.reg {
                return false;
            }
            if e.rm != 0xFF && m.rm != e.rm {
                return false;
            }
            match e.md {
                1 if m.md == 3 => return false,
                2 if m.md != 3 => return false,
                _ => {}
            }
        }
        if e.w & (1 << u8::from(self.w)) == 0 {
            return false;
        }
        let l = if self.evex_b
            && self.encoding == Encoding::Evex
            && self.modrm.is_some_and(|m| m.md == 3)
        {
            // With EVEX.b in the register form, L'L is the rounding mode
            // (for ER) and the vector length is 512.
            if e.attrs & (attr::ER | attr::SAE) != 0 {
                2
            } else {
                self.l
            }
        } else {
            self.l
        };
        if e.l & (1 << l) == 0 {
            return false;
        }
        match e.mode {
            1 if !self.is64() => return false,
            2 if self.is64() => return false,
            _ => {}
        }
        let os_bit = match self.operand_size(e) {
            2 => 1,
            4 => 2,
            _ => 4,
        };
        if e.os & os_bit == 0 {
            return false;
        }
        let as_bit = match self.address_size() {
            2 => 1,
            4 => 2,
            _ => 4,
        };
        e.asz & as_bit != 0
    }

    fn run(&mut self) -> Result<Instruction, DecodeError> {
        self.prefixes()?;
        self.opcode()?;
        // A 66/F2/F3 prefix on an instruction that has no form for it (MMX,
        // mostly) is not a mandatory prefix: F2/F3 are shown as
        // `rep`/`repne` and 66 is ignored. This applies only when the plain
        // form has no XMM operands; SSE instructions are invalid instead.
        if matches!(self.encoding, Encoding::Legacy | Encoding::Rex2) && self.map != map::AMD3DNOW {
            let mp = self.mandatory_prefix();
            if mp >= 2 {
                let (start, count) = INDEX[self.map][usize::from(self.opcode)];
                let entries = &ENTRIES[usize::from(start)..usize::from(start) + usize::from(count)];
                let has_form = |p: u8| entries.iter().any(|e| e.pfx == p);
                let uses_xmm = |e: &Entry| {
                    e.ops
                        .iter()
                        .any(|o| matches!(o.loc, Loc::VecReg | Loc::VecRm | Loc::VecRmReg))
                };
                let plain = || entries.iter().filter(|e| e.pfx == 1);
                let fallback = !entries.iter().any(|e| e.pfx == 0 || e.pfx == mp)
                    && plain().next().is_some()
                    && !plain().any(uses_xmm)
                    && !has_form(3)
                    && !has_form(4)
                    && self.map == map::M0F;
                if fallback {
                    self.mp_override = 1;
                }
            }
        }
        let has_modrm = self.map == map::AMD3DNOW
            || HAS_MODRM[self.map][usize::from(self.opcode)] & (1 << self.mandatory_prefix()) != 0;
        if has_modrm {
            self.read_modrm()?;
            // The XSAVE family is #UD with REX2.
            if let Some(m) = self.modrm {
                let xsave = match self.opcode {
                    0xAE => (4..=6).contains(&m.reg),
                    0xC7 => (3..=5).contains(&m.reg),
                    _ => false,
                };
                if self.encoding == Encoding::Rex2
                    && self.map == map::M0F
                    && xsave
                    && m.md != 3
                    && self.mandatory_prefix() == 1
                {
                    return Err(DecodeError::Invalid);
                }
            }
        }
        if self.map == map::AMD3DNOW {
            self.opcode = self.next()?;
        }

        // The `90` family: with REX.B it is `xchg r8, rax`.
        let mut opcode = self.opcode;
        if self.map == map::LEGACY
            && opcode == 0x90
            && self.b & 1 != 0
            && self.mandatory_prefix() != 3
        {
            opcode = 0x91;
        }

        let (start, count) = INDEX[self.map][usize::from(opcode)];
        let candidates = &ENTRIES[usize::from(start)..usize::from(start) + usize::from(count)];
        let entry = candidates
            .iter()
            .find(|e| self.matches(e))
            .ok_or(DecodeError::Invalid)?;

        // dumpbin treats conflicting mandatory prefixes on SIMD instructions
        // as invalid (it shows the earlier prefix as a lone byte).
        if entry.pfx != 0 && self.encoding == Encoding::Legacy && self.seen_simd.count_ones() > 1 {
            return Err(DecodeError::Invalid);
        }
        // EVEX.U (X4) only extends a memory operand's index: it must be
        // clear in register forms.
        if self.encoding == Encoding::Evex
            && self.x & 2 != 0
            && self.modrm.is_none_or(|m| m.md == 3)
        {
            return Err(DecodeError::Invalid);
        }
        let mut apx = Apx::default();
        if entry.attrs & attr::APX != 0 {
            apx = self.apx(entry)?;
        }
        // EVEX.L'L = 3 is reserved, except as a rounding mode.
        if self.encoding == Encoding::Evex
            && self.l == 3
            && !(self.evex_b
                && self.modrm.is_some_and(|m| m.md == 3)
                && entry.attrs & (attr::ER | attr::SAE) != 0)
            && entry.attrs & attr::LIG == 0
        {
            return Err(DecodeError::Invalid);
        }
        // VEX/EVEX.vvvv (and EVEX.V') must be 1111b when the instruction has
        // no operand there. With VSIB, EVEX.V' extends the index instead.
        // (CCMP/CTEST's vvvv is its default flags value.)
        if matches!(
            self.encoding,
            Encoding::Vex | Encoding::Evex | Encoding::Xop
        ) && entry.attrs & attr::SCC == 0
        {
            let uses = |l: Loc| entry.ops.iter().any(|o| o.loc == l);
            let unused = if uses(Loc::VecVvvv)
                || uses(Loc::GprVvvv)
                || uses(Loc::KVvvv)
                || uses(Loc::TmmVvvv)
            {
                0
            } else if uses(Loc::Vsib) {
                0x0F
            } else {
                0x1F
            };
            if self.vvvv & unused != 0 {
                return Err(DecodeError::Invalid);
            }
        }
        let mut inst = self.build(entry, self.opcode)?;
        inst.apx = apx.flags;
        inst.dfv = apx.dfv;
        // `{evex}` where another encoding would do: one without NF or ND
        // (and for VEX's twins, without r16-r31, which VEX can't reach).
        let plain = entry.attrs & attr::APX == 0 || self.evex_p2 & 0x14 == 0;
        if self.encoding == Encoding::Evex
            && plain
            && (entry.attrs & attr::EVEX_PROMOTED != 0
                || entry.attrs & attr::EVEX_VEX != 0 && !uses_egpr(&inst))
        {
            inst.apx |= crate::instruction::apx::EVEX;
        }
        if entry.attrs & attr::NORSP != 0 {
            let regs = inst.operands();
            let rsp = regs
                .iter()
                .any(|o| matches!(o, Operand::Reg(r) if r.index() == 4));
            // (POP2 into one register twice is #UD.)
            let same = regs.first() == regs.get(1)
                && entry.mnemonic != Mnemonic::Push2
                && entry.mnemonic != Mnemonic::Push2p;
            if rsp || same {
                return Err(DecodeError::Invalid);
            }
        }
        Ok(inst)
    }

    /// Checks an APX EVEX form's payload, which holds ND, NF, and SCC in
    /// place of masking, broadcast, and vector length, and takes those out
    /// of the EVEX state that the operands are built from.
    fn apx(&mut self, e: &Entry) -> Result<Apx, DecodeError> {
        let p2 = self.evex_p2;
        // z and L'L must be 0; so must the opmask bits that aren't NF.
        if p2 & 0xE0 != 0 {
            return Err(DecodeError::Invalid);
        }
        let mut apx = Apx::default();
        if e.attrs & attr::SCC != 0 {
            apx.flags |= crate::instruction::apx::DFV;
            // EVEX.vvvv, not inverted: OF, SF, ZF, CF.
            apx.dfv = !self.vvvv & 0x0F;
        } else {
            if p2 & 0x03 != 0 {
                return Err(DecodeError::Invalid);
            }
            let nf = p2 & 0x04 != 0;
            if nf && e.attrs & attr::NF != 0 {
                apx.flags |= crate::instruction::apx::NF;
            }
        }
        // ND and NF are not broadcast and masking.
        self.evex_b = false;
        self.evex_aaa = 0;
        self.evex_z = false;
        Ok(apx)
    }

    fn vector_length(&self, e: &Entry) -> u16 {
        match self.encoding {
            Encoding::Vex | Encoding::Xop => 16 << self.l,
            Encoding::Evex => {
                if self.evex_b
                    && self.modrm.is_some_and(|m| m.md == 3)
                    && e.attrs & (attr::ER | attr::SAE) != 0
                {
                    64
                } else {
                    16 << self.l.min(2)
                }
            }
            _ => 16,
        }
    }

    fn element_size(&self, e: &Entry) -> u16 {
        if e.elem != 0 {
            u16::from(e.elem)
        } else if e.attrs & attr::ELEM_W != 0 {
            if self.w { 8 } else { 4 }
        } else {
            4
        }
    }

    fn build(&mut self, e: &Entry, opcode: u8) -> Result<Instruction, DecodeError> {
        let os = self.operand_size(e);
        let asz = self.address_size();
        let vl = self.vector_length(e);
        let rex_byte_regs = self.rex
            || matches!(
                self.encoding,
                Encoding::Vex | Encoding::Evex | Encoding::Xop
            );
        let is_evex = self.encoding == Encoding::Evex;
        let elem = self.element_size(e);
        let broadcast = is_evex && self.evex_b && self.modrm.is_some_and(|m| m.md != 3);
        if broadcast && e.attrs & attr::BCST == 0 {
            return Err(DecodeError::Invalid);
        }

        let w64 = self.w && self.is64();
        let gpr_size = move |size: Size| -> u8 {
            match size {
                Size::B => 1,
                Size::W => 2,
                Size::D => 4,
                Size::Q => 8,
                Size::V => os,
                Size::Z4 => os.min(4),
                Size::Yw => {
                    if w64 {
                        8
                    } else {
                        4
                    }
                }
                Size::A => asz,
                _ => os,
            }
        };
        let vec_width = move |size: Size| -> u16 {
            match size {
                Size::X => 16,
                Size::Y => 32,
                Size::Z => 64,
                Size::Vl => vl,
                Size::VlHalf => (vl / 2).max(16),
                Size::VlQuarter => (vl / 4).max(16),
                Size::VlEighth => (vl / 8).max(16),
                _ => 16,
            }
        };
        let mem_size = move |size: Size| -> MemSize {
            match size {
                Size::None => MemSize::None,
                Size::B => MemSize::Byte,
                Size::W => MemSize::Word,
                Size::D => MemSize::Dword,
                Size::Q => MemSize::Qword,
                Size::Mm => MemSize::Mmword,
                Size::O => MemSize::Oword,
                Size::X => MemSize::Xmmword,
                Size::Y => MemSize::Ymmword,
                Size::Z => MemSize::Zmmword,
                Size::T => MemSize::Tbyte,
                Size::F => MemSize::Fword,
                Size::V | Size::Z4 | Size::Yw | Size::A => {
                    MemSize::from_bytes(u16::from(gpr_size(size)))
                }
                Size::P => match os {
                    2 => MemSize::Dword,
                    4 => MemSize::Fword,
                    _ => MemSize::Tbyte,
                },
                Size::Pair => MemSize::from_bytes(u16::from(os) * 2),
                Size::Zw => MemSize::Zword,
                Size::Tile => MemSize::Tile,
                Size::Vl => MemSize::from_bytes(vl),
                Size::VlHalf => vector_part(vl / 2),
                Size::VlQuarter => vector_part(vl / 4),
                Size::VlEighth => vector_part(vl / 8),
            }
        };

        let modrm = self.modrm.unwrap_or_default();
        let reg_index = modrm.reg | self.r << 3;
        // REX2's R4 is for general-purpose registers only (EVEX's R' does
        // extend vector registers).
        let vec_reg_index = if is_evex {
            reg_index
        } else {
            modrm.reg | (self.r & 1) << 3
        };
        let rm_index = modrm.rm | self.b << 3;
        let segment = self.segment.map(|s| Register::new(RegClass::Segment, s));

        // The memory operand, if the ModRM byte encodes one.
        let memory = |d: &Self, size: MemSize, vsib: Option<u16>| -> Memory {
            let gpr = |i: u8| Register::gpr(asz, i, true);
            let (base, index) = if modrm.rip {
                (
                    Some(Register::new(RegClass::Ip, if asz == 8 { 0 } else { 1 })),
                    None,
                )
            } else if let Some(width) = vsib {
                // A vector index: X3 and (EVEX) V' extend it; X4 doesn't.
                let index = modrm
                    .sib_index
                    .map(|i| i & 0x0F | if is_evex { (d.vvvv >> 4) << 4 } else { 0 });
                (
                    modrm.base.map(gpr),
                    index.map(|i| Register::vector(width, i)),
                )
            } else {
                (modrm.base.map(gpr), modrm.index.map(gpr))
            };
            let (base, index) = if asz == 2 {
                (
                    modrm.base.map(|i| Register::gpr(2, i, true)),
                    modrm.index.map(|i| Register::gpr(2, i, true)),
                )
            } else {
                (base, index)
            };
            Memory {
                segment,
                base,
                index,
                scale: if index.is_some() { modrm.scale } else { 1 },
                disp: modrm.disp,
                disp_size: modrm.disp_size,
                size,
                address_size: asz,
                broadcast: 0,
                moffs: false,
            }
        };

        let mut ops = [Operand::None; 5];
        let mut count = 0;
        let mut rel: Option<(usize, i64)> = None;
        let mut mem_index: Option<usize> = None;
        let mut pseudo_imm = None;
        let mut is4 = 0u8;

        for spec in e.ops.iter().take_while(|s| s.loc != Loc::None) {
            let op = match spec.loc {
                Loc::None => unreachable!(),
                Loc::GprRm | Loc::GprRmReg | Loc::Mem if modrm.md != 3 => {
                    if spec.loc == Loc::GprRmReg {
                        return Err(DecodeError::Invalid);
                    }
                    // A tile in memory needs a SIB byte (XED: RM=100b SIB).
                    if spec.msize == Size::Tile && modrm.sib_index.is_none() {
                        return Err(DecodeError::Invalid);
                    }
                    mem_index = Some(count);
                    Operand::Mem(memory(self, mem_size(spec.msize), None))
                }
                Loc::GprRm | Loc::GprRmReg => {
                    let size = gpr_size(spec.size);
                    Operand::Reg(Register::gpr(size, rm_index, rex_byte_regs))
                }
                Loc::Mem => return Err(DecodeError::Invalid),
                Loc::GprReg => {
                    Operand::Reg(Register::gpr(gpr_size(spec.size), reg_index, rex_byte_regs))
                }
                Loc::GprVvvv => {
                    // (EVEX.V' is APX's V4.)
                    let index = if is_evex { self.vvvv } else { self.vvvv & 0xF };
                    Operand::Reg(Register::gpr(gpr_size(spec.size), index, true))
                }
                Loc::GprOpcode => Operand::Reg(Register::gpr(
                    gpr_size(spec.size),
                    opcode & 7 | self.b << 3,
                    rex_byte_regs,
                )),
                Loc::Imm => {
                    let size = gpr_size(spec.size);
                    let value = self.read_le(usize::from(size))?;
                    Operand::Imm(Immediate { value, size })
                }
                Loc::ImmSx8 => {
                    let value = i64::from(self.next()? as i8) as u64;
                    Operand::Imm(Immediate {
                        value: truncate(value, os),
                        size: os,
                    })
                }
                Loc::ImmSx => {
                    let size = os.min(4);
                    let raw = self.read_le(usize::from(size))?;
                    let value = if size == 2 {
                        i64::from(raw as u16 as i16) as u64
                    } else {
                        i64::from(raw as u32 as i32) as u64
                    };
                    Operand::Imm(Immediate {
                        value: truncate(value, os),
                        size: os,
                    })
                }
                Loc::Imm2 => {
                    let value = self.next()?;
                    Operand::Imm(Immediate {
                        value: value.into(),
                        size: 1,
                    })
                }
                Loc::Abs64 => {
                    let target = self.read_le(8)?;
                    Operand::Rel(target)
                }
                Loc::Rel => {
                    let size = gpr_size(spec.size);
                    let raw = self.read_le(usize::from(size))?;
                    let disp = match size {
                        1 => i64::from(raw as u8 as i8),
                        2 => i64::from(raw as u16 as i16),
                        _ => i64::from(raw as u32 as i32),
                    };
                    rel = Some((count, disp));
                    Operand::Rel(0)
                }
                Loc::Moffs => {
                    let value = self.read_le(usize::from(asz))?;
                    Operand::Mem(Memory {
                        segment,
                        base: None,
                        index: None,
                        scale: 1,
                        disp: value as i64,
                        disp_size: asz,
                        size: mem_size(spec.msize),
                        address_size: asz,
                        broadcast: 0,
                        moffs: true,
                    })
                }
                Loc::FarPtr => {
                    let offset_size = os.min(4);
                    let offset = self.read_le(usize::from(offset_size))? as u32;
                    let segment = self.read_le(2)? as u16;
                    Operand::Far {
                        segment,
                        offset,
                        offset_size,
                    }
                }
                Loc::StrSrc | Loc::StrDst => {
                    let src = spec.loc == Loc::StrSrc;
                    Operand::Mem(Memory {
                        // Outside 64-bit mode the destination is shown as es:[edi].
                        segment: if src {
                            segment
                        } else if self.is64() {
                            None
                        } else {
                            Some(Register::new(RegClass::Segment, 0))
                        },
                        base: Some(Register::gpr(asz, if src { 6 } else { 7 }, true)),
                        index: None,
                        scale: 1,
                        disp: 0,
                        disp_size: 0,
                        size: mem_size(spec.msize),
                        address_size: asz,
                        broadcast: 0,
                        moffs: false,
                    })
                }
                Loc::Xlat => Operand::Mem(Memory {
                    segment,
                    base: Some(Register::gpr(asz, 3, true)),
                    index: None,
                    scale: 1,
                    disp: 0,
                    disp_size: 0,
                    size: MemSize::Byte,
                    address_size: asz,
                    broadcast: 0,
                    moffs: false,
                }),
                Loc::Fixed => {
                    let class = fixed_class(spec.fixed >> 8);
                    Operand::Reg(Register::new(class, (spec.fixed & 0xFF) as u8))
                }
                Loc::FixedGpr => {
                    Operand::Reg(Register::gpr(gpr_size(spec.size), spec.fixed as u8, true))
                }
                Loc::One => Operand::Imm(Immediate {
                    value: u64::from(spec.fixed.max(1)),
                    size: 1,
                }),
                Loc::StRm => Operand::Reg(Register::new(RegClass::St, modrm.rm)),
                Loc::MmxReg => Operand::Reg(Register::new(RegClass::Mmx, modrm.reg)),
                Loc::MmxRm | Loc::MmxRmReg if modrm.md == 3 => {
                    Operand::Reg(Register::new(RegClass::Mmx, modrm.rm))
                }
                Loc::MmxRm => {
                    mem_index = Some(count);
                    Operand::Mem(memory(self, mem_size(spec.msize), None))
                }
                Loc::MmxRmReg => return Err(DecodeError::Invalid),
                Loc::VecReg => Operand::Reg(Register::vector(vec_width(spec.size), vec_reg_index)),
                Loc::VecVvvv => Operand::Reg(Register::vector(vec_width(spec.size), self.vvvv)),
                Loc::VecRm | Loc::VecRmReg if modrm.md == 3 => {
                    // A vector register: B3 and (EVEX) X3 extend it; B4
                    // is for general-purpose registers only.
                    let index =
                        modrm.rm | (self.b & 1) << 3 | if is_evex { (self.x & 1) << 4 } else { 0 };
                    Operand::Reg(Register::vector(vec_width(spec.size), index))
                }
                Loc::VecRm => {
                    mem_index = Some(count);
                    let mut m = memory(self, mem_size(spec.msize), None);
                    if broadcast {
                        m.size = MemSize::from_bytes(elem);
                        m.broadcast = (vl / elem) as u8;
                    }
                    Operand::Mem(m)
                }
                Loc::VecRmReg => return Err(DecodeError::Invalid),
                Loc::Is4Low => Operand::Imm(Immediate {
                    value: u64::from(is4 & 3),
                    size: 1,
                }),
                Loc::VecIs4 => {
                    let imm = self.next()?;
                    is4 = imm;
                    let index = if self.is64() { imm >> 4 } else { imm >> 4 & 7 };
                    Operand::Reg(Register::vector(vec_width(spec.size), index))
                }
                Loc::SegReg if modrm.reg > 5 => return Err(DecodeError::Invalid),
                Loc::SegReg => Operand::Reg(Register::new(RegClass::Segment, modrm.reg)),
                // (There are no control or debug registers 16-31.)
                Loc::CrReg | Loc::DrReg if reg_index >= 16 => return Err(DecodeError::Invalid),
                Loc::CrReg => Operand::Reg(Register::new(RegClass::Control, reg_index)),
                Loc::DrReg => Operand::Reg(Register::new(RegClass::Debug, reg_index)),
                Loc::TrReg => Operand::Reg(Register::new(RegClass::Test, modrm.reg)),
                // An opmask register in ModRM.reg takes no REX/VEX/EVEX.R
                // or R' (#UD otherwise: XED's MASK_R).
                Loc::KReg if self.r != 0 => return Err(DecodeError::Invalid),
                Loc::KReg => Operand::Reg(Register::new(RegClass::Mask, modrm.reg)),
                Loc::KRm | Loc::KRmReg if modrm.md == 3 => {
                    Operand::Reg(Register::new(RegClass::Mask, modrm.rm))
                }
                Loc::KRm => {
                    mem_index = Some(count);
                    Operand::Mem(memory(self, mem_size(spec.msize), None))
                }
                Loc::KRmReg => return Err(DecodeError::Invalid),
                // Nor in vvvv, whose fourth bit must be clear (MASK_N).
                Loc::KVvvv if self.vvvv & 0x18 != 0 => return Err(DecodeError::Invalid),
                Loc::KVvvv => Operand::Reg(Register::new(RegClass::Mask, self.vvvv & 7)),
                // Likewise a tile register in an EVEX form (XED's TMM_R3).
                Loc::TmmReg if is_evex && self.r != 0 => return Err(DecodeError::Invalid),
                Loc::TmmReg => Operand::Reg(Register::new(RegClass::Tmm, modrm.reg)),
                // And in rm, EVEX.B and X must be clear (XED's TMM_B3).
                Loc::TmmRmReg if is_evex && (self.b | self.x) & 1 != 0 => {
                    return Err(DecodeError::Invalid);
                }
                Loc::TmmRmReg => Operand::Reg(Register::new(RegClass::Tmm, modrm.rm)),
                Loc::TmmVvvv => Operand::Reg(Register::new(RegClass::Tmm, self.vvvv & 7)),
                Loc::BndReg if modrm.reg > 3 => return Err(DecodeError::Invalid),
                Loc::BndReg => Operand::Reg(Register::new(RegClass::Bound, modrm.reg)),
                Loc::BndRm if modrm.md == 3 && modrm.rm > 3 => return Err(DecodeError::Invalid),
                Loc::BndRm if modrm.md == 3 => {
                    Operand::Reg(Register::new(RegClass::Bound, modrm.rm))
                }
                Loc::BndRm => {
                    mem_index = Some(count);
                    Operand::Mem(memory(self, mem_size(spec.msize), None))
                }
                Loc::Vsib => {
                    if modrm.md == 3 || modrm.sib_index.is_none() {
                        return Err(DecodeError::Invalid);
                    }
                    mem_index = Some(count);
                    let width = vec_width(spec.size);
                    let mut m = memory(self, mem_size(spec.msize), Some(width));
                    m.scale = modrm.scale;
                    Operand::Mem(m)
                }
            };
            ops[count] = op;
            count += 1;
        }

        // A compare whose immediate selects the mnemonic drops the immediate.
        if e.attrs & attr::CMP_PSEUDO != 0
            && let Some(Operand::Imm(imm)) = ops[..count].last()
        {
            let limit = if self.encoding == Encoding::Vex {
                32
            } else {
                8
            };
            if imm.value < limit {
                pseudo_imm = Some(imm.value as u8);
                count -= 1;
                ops[count] = Operand::None;
            }
        }

        let len = self.pos;
        let next = self.address.wrapping_add(len as u64);
        if let Some((i, disp)) = rel {
            let target = next.wrapping_add(disp as u64);
            // In 64-bit mode an operand-size prefix truncates the target to
            // 16 bits (as AMD processors do, and as dumpbin shows it), though
            // rel32 branches still read four bytes.
            let width = match self.mode {
                Mode::Bits64 if self.opsize_prefix(e) && !self.w => 2,
                Mode::Bits64 => 8,
                _ => os.max(2),
            };
            ops[i] = Operand::Rel(truncate(target, width));
        }

        // EVEX: compressed displacements, masking, rounding.
        let mut rounding = None;
        let mut sae = false;
        if is_evex {
            if let Some(i) = mem_index
                && let Operand::Mem(m) = &mut ops[i]
                && m.disp_size == 1
            {
                m.disp *= i64::from(self.disp8_scale(e, vl, elem, broadcast));
            }
            if self.evex_b && modrm.md == 3 {
                if e.attrs & attr::ER != 0 {
                    rounding = Some(match self.l {
                        0 => Rounding::Nearest,
                        1 => Rounding::Down,
                        2 => Rounding::Up,
                        _ => Rounding::Zero,
                    });
                } else if e.attrs & attr::SAE != 0 {
                    sae = true;
                } else {
                    return Err(DecodeError::Invalid);
                }
            }
            if self.evex_aaa != 0 && e.attrs & attr::MASK == 0 {
                return Err(DecodeError::Invalid);
            }
            if self.evex_z && (e.attrs & attr::ZERO == 0 || self.evex_aaa == 0) {
                return Err(DecodeError::Invalid);
            }
            // A store takes no zero-masking (or broadcast) into memory.
            if e.attrs & attr::STORE != 0 && mem_index.is_some() && (self.evex_z || broadcast) {
                return Err(DecodeError::Invalid);
            }
            if e.attrs & attr::MASK_REQ != 0 && self.evex_aaa == 0 {
                return Err(DecodeError::Invalid);
            }
        }
        // RIP-relative displacements are relative to the next instruction.
        let _ = next;

        // Like dumpbin, show `lock` wherever it appears; whether it is valid
        // (a lockable instruction with a memory destination) is separate.
        let mut prefixes = 0u16;
        if self.lock {
            prefixes |= prefix::LOCK;
        }
        if e.attrs & attr::VEX_PREFIX != 0 {
            prefixes |= prefix::VEX;
        }
        if self.rep != 0 && e.pfx < 3 && matches!(self.encoding, Encoding::Legacy | Encoding::Rex2)
        {
            let f3 = self.rep == 0xF3;
            prefixes |= if e.attrs & attr::REPE != 0 {
                if f3 { prefix::REPE } else { prefix::REPNE }
            } else if e.attrs & attr::REP != 0 {
                if f3 { prefix::REP } else { prefix::REPNE }
            } else if e.attrs & attr::HLE != 0 && !f3 {
                prefix::XACQUIRE
            } else if e.attrs & attr::HLE != 0 && self.lock {
                prefix::XRELEASE
            } else if e.attrs & attr::BND != 0 && !f3 {
                prefix::BND
            } else if f3 {
                prefix::REP_OTHER
            } else {
                prefix::REPNE
            };
        }
        if self.map <= map::M0F && rel.is_some() && is_jcc(e.mnemonic) {
            match self.segment {
                Some(1) => prefixes |= prefix::HINT_NOT_TAKEN,
                Some(3) => prefixes |= prefix::HINT_TAKEN,
                _ => {}
            }
        }

        Ok(Instruction {
            mnemonic: e.mnemonic,
            len: len as u8,
            mode: self.mode,
            encoding: self.encoding,
            op_count: count as u8,
            ops,
            prefixes,
            mask: if is_evex { self.evex_aaa } else { 0 },
            zeroing: is_evex && self.evex_z,
            rounding,
            sae,
            attrs: e.attrs,
            address: self.address,
            vector_length: if matches!(
                self.encoding,
                Encoding::Vex | Encoding::Evex | Encoding::Xop
            ) {
                vl as u8
            } else {
                0
            },
            pseudo_imm,
            apx: 0,
            dfv: 0,
        })
    }

    /// The EVEX disp8*N scale factor.
    fn disp8_scale(&self, e: &Entry, vl: u16, elem: u16, broadcast: bool) -> u16 {
        match e.tuple {
            Tuple::None => 1,
            Tuple::Fv => {
                if broadcast {
                    elem
                } else {
                    vl
                }
            }
            Tuple::Hv => {
                if broadcast {
                    elem
                } else {
                    vl / 2
                }
            }
            Tuple::Qv => {
                if broadcast {
                    elem
                } else {
                    vl / 4
                }
            }
            Tuple::Fvm => vl,
            Tuple::Hvm => vl / 2,
            Tuple::Qvm => vl / 4,
            Tuple::Ovm => vl / 8,
            Tuple::T1s | Tuple::T1f => elem,
            Tuple::T2 => elem * 2,
            Tuple::T4 => elem * 4,
            Tuple::T8 => elem * 8,
            Tuple::M128 => 16,
            Tuple::Dup => {
                if vl == 16 {
                    8
                } else {
                    vl
                }
            }
        }
    }
}

/// Whether an operand is (or addresses through) one of APX's r16-r31.
fn uses_egpr(inst: &Instruction) -> bool {
    let egpr = |r: &Register| {
        matches!(
            r.class(),
            RegClass::Gpr8 | RegClass::Gpr16 | RegClass::Gpr32 | RegClass::Gpr64
        ) && r.index() >= 16
    };
    inst.operands().iter().any(|o| match o {
        Operand::Reg(r) => egpr(r),
        Operand::Mem(m) => m.base.as_ref().is_some_and(egpr) || m.index.as_ref().is_some_and(egpr),
        _ => false,
    })
}

/// What an APX form adds to the instruction.
#[derive(Default)]
struct Apx {
    flags: u8,
    dfv: u8,
}

/// Opcodes that are #UD with a REX2 prefix: those whose operand forms
/// can't use it (relative branches, `moffs`, string and port I/O
/// instructions, MSR and XSAVE-family instructions) and the escapes.
fn rex2_invalid(map: usize, opcode: u8) -> bool {
    if map == map::LEGACY {
        // (A1 is JMPABS; its table entry takes only REX2.W = 0.)
        matches!(opcode >> 4, 0x4 | 0x7 | 0xE) || matches!(opcode, 0xA0 | 0xA2..=0xAF | 0x0F)
    } else {
        matches!(opcode >> 4, 0x3 | 0x8) || matches!(opcode, 0x0F)
    }
}

fn vector_part(bytes: u16) -> MemSize {
    match bytes {
        8 => MemSize::Mmword,
        b => MemSize::from_bytes(b),
    }
}

fn truncate(value: u64, size: u8) -> u64 {
    match size {
        1 => value & 0xFF,
        2 => value & 0xFFFF,
        4 => value & 0xFFFF_FFFF,
        _ => value,
    }
}

fn fixed_class(class: u16) -> RegClass {
    match class {
        0 => RegClass::Gpr8,
        1 => RegClass::Gpr8High,
        2 => RegClass::Gpr16,
        3 => RegClass::Gpr32,
        4 => RegClass::Gpr64,
        5 => RegClass::Segment,
        8 => RegClass::St,
        10 => RegClass::Xmm,
        _ => RegClass::Gpr64,
    }
}

fn is_jcc(m: Mnemonic) -> bool {
    use Mnemonic as M;
    // Branch hints (2E/3E) apply to relative jumps and loops.
    matches!(
        m,
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
            | M::Jmp
            | M::Jcxz
            | M::Jecxz
            | M::Jrcxz
            | M::Loop
            | M::Loope
            | M::Loopne
            | M::Xbegin
    )
}

#[allow(dead_code)]
fn unused(_: OpSpec) {}

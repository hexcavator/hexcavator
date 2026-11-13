//! Call frame information: `.eh_frame` (the LSB's form, with GCC's pointer
//! encodings and augmentations) and `.debug_frame` (DWARF versions 1, 3,
//! and 4), and the interpreter that turns a frame description's
//! instructions into the unwind rule table's row for an address.
//!
//! Hostile data ends iteration or gives `None`: instruction streams are
//! bounded by their entries, and the remembered-state stack is limited.

use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::{Reader, sext};

/// Which section a [`Cfi`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfiKind {
    EhFrame,
    DebugFrame,
}

/// A call frame information section.
#[derive(Clone, Copy, Debug)]
pub struct Cfi<'d> {
    pub data: &'d [u8],
    pub kind: CfiKind,
    pub endian: Endian,
    /// The section's address (for PC-relative pointers).
    pub address: u64,
    /// The target's address size (`.eh_frame` absolute pointers, and
    /// `.debug_frame` before version 4).
    pub address_size: u8,
    /// The bases of `DW_EH_PE_textrel` and `DW_EH_PE_datarel` pointers, if
    /// known.
    pub text_base: Option<u64>,
    pub data_base: Option<u64>,
}

/// A common information entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cie<'d> {
    /// Its offset in the section.
    pub offset: u64,
    pub version: u8,
    pub augmentation: &'d [u8],
    pub address_size: u8,
    pub code_alignment: u64,
    pub data_alignment: i64,
    pub return_address_register: u16,
    /// The FDEs' pointer encoding (`R`; absolute by default).
    pub fde_encoding: u8,
    /// The LSDA pointers' encoding (`L`).
    pub lsda_encoding: Option<u8>,
    /// The personality routine (`P`).
    pub personality: Option<u64>,
    /// `S`: the frames are signal handlers' (their PC is not after a call).
    pub signal_frame: bool,
    /// `B`: return addresses are signed with the B key (AArch64).
    pub b_key: bool,
    pub instructions: &'d [u8],
}

/// A frame description entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fde<'d> {
    pub offset: u64,
    pub cie: u64,
    pub pc_begin: u64,
    pub pc_range: u64,
    pub lsda: Option<u64>,
    pub instructions: &'d [u8],
}

impl Fde<'_> {
    pub fn contains(&self, pc: u64) -> bool {
        pc.wrapping_sub(self.pc_begin) < self.pc_range
    }
}

/// An entry of the section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry<'d> {
    Cie(Cie<'d>),
    Fde(Fde<'d>),
}

/// An entry's header (see `Cfi::header_at`).
struct Header<'d> {
    is_cie: bool,
    /// Where the CIE id or pointer is, and its value.
    id_at: usize,
    id: u64,
    body: Reader<'d>,
    end: usize,
}

// DW_EH_PE_*.
const PE_OMIT: u8 = 0xFF;
const PE_ABSPTR: u8 = 0x00;
const PE_ULEB128: u8 = 0x01;
const PE_UDATA2: u8 = 0x02;
const PE_UDATA4: u8 = 0x03;
const PE_UDATA8: u8 = 0x04;
const PE_SLEB128: u8 = 0x09;
const PE_SDATA2: u8 = 0x0A;
const PE_SDATA4: u8 = 0x0B;
const PE_SDATA8: u8 = 0x0C;
const PE_PCREL: u8 = 0x10;
const PE_TEXTREL: u8 = 0x20;
const PE_DATAREL: u8 = 0x30;
const PE_FUNCREL: u8 = 0x40;
const PE_ALIGNED: u8 = 0x50;
const PE_INDIRECT: u8 = 0x80;

impl<'d> Cfi<'d> {
    /// Reads a pointer with `encoding`, at `r` (an offset into the
    /// section). Indirect pointers aren't followed (the value is the
    /// pointer's address); `funcrel` gives the offset itself.
    fn pointer(&self, r: &mut Reader<'d>, encoding: u8, address_size: u8) -> Option<u64> {
        if encoding == PE_OMIT {
            return None;
        }
        let at = self.address.wrapping_add(r.pos as u64);
        if encoding & 0x70 == PE_ALIGNED {
            let a = usize::from(address_size.max(1));
            r.pos = r.pos.checked_add(a - 1)? / a * a;
        }
        let raw = match encoding & 0x0F {
            PE_ABSPTR => r.uint(usize::from(address_size.clamp(1, 8)))?,
            PE_ULEB128 => r.uleb()?,
            PE_UDATA2 => r.uint(2)?,
            PE_UDATA4 => r.uint(4)?,
            PE_UDATA8 => r.uint(8)?,
            PE_SLEB128 => r.sleb()? as u64,
            PE_SDATA2 => sext(r.uint(2)?, 2),
            PE_SDATA4 => sext(r.uint(4)?, 4),
            PE_SDATA8 => r.uint(8)?,
            _ => return None,
        };
        let base = match encoding & 0x70 {
            PE_ABSPTR | PE_ALIGNED | PE_FUNCREL => 0,
            PE_PCREL => at,
            PE_TEXTREL => self.text_base?,
            PE_DATAREL => self.data_base?,
            _ => return None,
        };
        let v = raw.wrapping_add(base);
        Some(if address_size == 4 {
            v & 0xFFFF_FFFF
        } else {
            v
        })
    }

    /// The entries, in order (stopping at an `.eh_frame` terminator or
    /// anything malformed).
    pub fn entries(&self) -> impl Iterator<Item = Entry<'d>> + '_ {
        let mut pos = 0usize;
        core::iter::from_fn(move || {
            let (entry, next) = self.entry_at(pos)?;
            pos = next;
            Some(entry)
        })
    }

    /// The entry at `offset`, and the offset after it.
    pub fn entry_at(&self, offset: usize) -> Option<(Entry<'d>, usize)> {
        let h = self.header_at(offset)?;
        let entry = if h.is_cie {
            Entry::Cie(self.cie(h.body, offset as u64)?)
        } else {
            let cie_offset = match self.kind {
                CfiKind::EhFrame => (h.id_at as u64).checked_sub(h.id)?,
                CfiKind::DebugFrame => h.id,
            };
            // (The CIE's header only: an FDE naming another FDE is
            // malformed, not followed, so a chain of them can't recurse.)
            let c = self.header_at(usize::try_from(cie_offset).ok()?)?;
            if !c.is_cie {
                return None;
            }
            let cie = self.cie(c.body, cie_offset)?;
            Entry::Fde(self.fde(h.body, offset as u64, &cie)?)
        };
        Some((entry, h.end))
    }

    /// The header of the entry at `offset`: whether it is a CIE, its id
    /// (and where), its body, and where it ends. `None` at an `.eh_frame`
    /// terminator.
    fn header_at(&self, offset: usize) -> Option<Header<'d>> {
        let mut r = Reader::new(self.data, offset, self.endian);
        let (start, end, dwarf64) = r.initial_length()?;
        if end == start && self.kind == CfiKind::EhFrame {
            return None; // terminator
        }
        let id_at = r.pos;
        let id = r.offset(dwarf64)?;
        let is_cie = match self.kind {
            CfiKind::EhFrame => id == 0,
            CfiKind::DebugFrame => id == if dwarf64 { u64::MAX } else { 0xFFFF_FFFF },
        };
        let body = Reader::new(self.data.get(..end)?, r.pos, self.endian);
        Some(Header {
            is_cie,
            id_at,
            id,
            body,
            end,
        })
    }

    fn cie(&self, mut r: Reader<'d>, offset: u64) -> Option<Cie<'d>> {
        let version = r.u8()?;
        if !matches!(version, 1 | 3 | 4) {
            return None;
        }
        let augmentation = r.cstr()?;
        let mut address_size = self.address_size;
        if version == 4 {
            address_size = r.u8()?;
            let _segment_size = r.u8()?;
        }
        // (GCC's old "eh" augmentation: a pointer to the EH data.)
        if augmentation.starts_with(b"eh") {
            r.bytes(u64::from(address_size))?;
        }
        let code_alignment = r.uleb()?;
        let data_alignment = r.sleb()?;
        let return_address_register = if version == 1 {
            u16::from(r.u8()?)
        } else {
            u16::try_from(r.uleb()?).ok()?
        };
        let mut cie = Cie {
            offset,
            version,
            augmentation,
            address_size,
            code_alignment,
            data_alignment,
            return_address_register,
            fde_encoding: PE_ABSPTR,
            lsda_encoding: None,
            personality: None,
            signal_frame: false,
            b_key: false,
            instructions: &[],
        };
        if augmentation.first() == Some(&b'z') {
            let len = r.uleb()?;
            let data_end = r.pos.checked_add(usize::try_from(len).ok()?)?;
            for &c in &augmentation[1..] {
                match c {
                    b'R' => cie.fde_encoding = r.u8()?,
                    b'L' => cie.lsda_encoding = Some(r.u8()?),
                    b'P' => {
                        let enc = r.u8()?;
                        cie.personality = self.pointer(&mut r, enc & !PE_INDIRECT, address_size);
                    }
                    b'S' => cie.signal_frame = true,
                    b'B' => cie.b_key = true,
                    // (MTE-tagged frames; nothing to read.)
                    b'G' => {}
                    _ => break,
                }
            }
            if r.pos > data_end {
                return None;
            }
            r.pos = data_end;
        } else if !augmentation.is_empty() && !augmentation.starts_with(b"eh") {
            // An augmentation we can't skip: the instructions can't be found.
            return None;
        }
        cie.instructions = r.data.get(r.pos..)?;
        Some(cie)
    }

    fn fde(&self, mut r: Reader<'d>, offset: u64, cie: &Cie<'d>) -> Option<Fde<'d>> {
        let (pc_begin, pc_range) = match self.kind {
            CfiKind::EhFrame => {
                let begin = self.pointer(&mut r, cie.fde_encoding, cie.address_size)?;
                // (The range uses the value format only.)
                let range = self.pointer(&mut r, cie.fde_encoding & 0x0F, cie.address_size)?;
                (begin, range)
            }
            CfiKind::DebugFrame => {
                let n = usize::from(cie.address_size.clamp(1, 8));
                (r.uint(n)?, r.uint(n)?)
            }
        };
        let mut lsda = None;
        if cie.augmentation.first() == Some(&b'z') {
            let len = r.uleb()?;
            let data_end = r.pos.checked_add(usize::try_from(len).ok()?)?;
            if let Some(enc) = cie.lsda_encoding
                && len > 0
            {
                lsda = self.pointer(&mut r, enc, cie.address_size);
            }
            r.pos = data_end;
        }
        Some(Fde {
            offset,
            cie: cie.offset,
            pc_begin,
            pc_range,
            lsda,
            instructions: r.data.get(r.pos..)?,
        })
    }

    /// The FDE covering `pc`, and its CIE (by a linear search).
    pub fn find(&self, pc: u64) -> Option<(Cie<'d>, Fde<'d>)> {
        self.entries().find_map(|e| match e {
            Entry::Fde(f) if f.contains(pc) => match self.entry_at(usize::try_from(f.cie).ok()?)?.0
            {
                Entry::Cie(c) => Some((c, f)),
                Entry::Fde(_) => None,
            },
            _ => None,
        })
    }
}

/// How the CFA is computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfaRule<'d> {
    /// A register plus an offset.
    RegisterOffset { register: u16, offset: i64 },
    /// A DWARF expression's value.
    Expression(&'d [u8]),
}

/// How a register of the caller is recovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterRule<'d> {
    /// It can't be (`DW_CFA_undefined`).
    Undefined,
    /// It has the same value (`DW_CFA_same_value`).
    SameValue,
    /// It is saved at CFA + offset.
    Offset(i64),
    /// It is CFA + offset.
    ValOffset(i64),
    /// It is in another register.
    Register(u16),
    /// It is saved at the address an expression (with the CFA pushed)
    /// computes.
    Expression(&'d [u8]),
    /// It is the value an expression (with the CFA pushed) computes.
    ValExpression(&'d [u8]),
}

/// A row of the unwind rule table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindRow<'d> {
    /// The first address the row applies to.
    pub address: u64,
    pub cfa: CfaRule<'d>,
    /// The registers with rules, by DWARF number (others are unspecified).
    pub registers: Vec<(u16, RegisterRule<'d>)>,
    /// AArch64: whether the return address is signed, once a
    /// `DW_CFA_AARCH64_negate_ra_state` has said (`None`: never; unsigned).
    pub return_address_signed: Option<bool>,
    /// `DW_CFA_GNU_args_size`: the bytes of outgoing arguments pushed.
    pub args_size: u64,
}

impl<'d> UnwindRow<'d> {
    pub fn rule(&self, register: u16) -> Option<RegisterRule<'d>> {
        self.registers
            .iter()
            .find(|(r, _)| *r == register)
            .map(|&(_, rule)| rule)
    }

    fn set(&mut self, register: u16, rule: RegisterRule<'d>) {
        match self.registers.binary_search_by_key(&register, |&(r, _)| r) {
            Ok(i) => self.registers[i].1 = rule,
            Err(i) => self.registers.insert(i, (register, rule)),
        }
    }

    fn unset(&mut self, register: u16) {
        if let Ok(i) = self.registers.binary_search_by_key(&register, |&(r, _)| r) {
            self.registers.remove(i);
        }
    }
}

/// The deepest `DW_CFA_remember_state` nesting allowed.
const MAX_REMEMBERED: usize = 64;

// DW_CFA_*.
const ADVANCE_LOC: u8 = 0x40;
const OFFSET: u8 = 0x80;
const RESTORE: u8 = 0xC0;
const NOP: u8 = 0x00;
const SET_LOC: u8 = 0x01;
const ADVANCE_LOC1: u8 = 0x02;
const ADVANCE_LOC2: u8 = 0x03;
const ADVANCE_LOC4: u8 = 0x04;
const OFFSET_EXTENDED: u8 = 0x05;
const RESTORE_EXTENDED: u8 = 0x06;
const UNDEFINED: u8 = 0x07;
const SAME_VALUE: u8 = 0x08;
const REGISTER: u8 = 0x09;
const REMEMBER_STATE: u8 = 0x0A;
const RESTORE_STATE: u8 = 0x0B;
const DEF_CFA: u8 = 0x0C;
const DEF_CFA_REGISTER: u8 = 0x0D;
const DEF_CFA_OFFSET: u8 = 0x0E;
const DEF_CFA_EXPRESSION: u8 = 0x0F;
const EXPRESSION: u8 = 0x10;
const OFFSET_EXTENDED_SF: u8 = 0x11;
const DEF_CFA_SF: u8 = 0x12;
const DEF_CFA_OFFSET_SF: u8 = 0x13;
const VAL_OFFSET: u8 = 0x14;
const VAL_OFFSET_SF: u8 = 0x15;
const VAL_EXPRESSION: u8 = 0x16;
const MIPS_ADVANCE_LOC8: u8 = 0x1D;
const AARCH64_NEGATE_RA_STATE_WITH_PC: u8 = 0x2C;
const GNU_WINDOW_SAVE: u8 = 0x2D;
const GNU_ARGS_SIZE: u8 = 0x2E;
const GNU_NEGATIVE_OFFSET_EXTENDED: u8 = 0x2F;

/// Interprets a CIE's and FDE's instructions: the rows, each with its
/// start address, in order (consecutive rows may be equal). `None` if the
/// instructions are malformed.
pub fn rows<'d>(cfi: &Cfi<'d>, cie: &Cie<'d>, fde: &Fde<'d>) -> Option<Vec<UnwindRow<'d>>> {
    let mut out = Vec::new();
    run(cfi, cie, fde, None, &mut |row| {
        out.push(row.clone());
        true
    })?;
    Some(out)
}

/// The row that applies at `pc` (which `fde` must contain).
pub fn row_at<'d>(cfi: &Cfi<'d>, cie: &Cie<'d>, fde: &Fde<'d>, pc: u64) -> Option<UnwindRow<'d>> {
    let mut found = None;
    run(cfi, cie, fde, Some(pc), &mut |row| {
        found = Some(row.clone());
        true
    })?;
    found
}

/// Runs the instructions, calling `emit` with each row as it is finished
/// (stopping early once a row starts after `until`).
fn run<'d>(
    cfi: &Cfi<'d>,
    cie: &Cie<'d>,
    fde: &Fde<'d>,
    until: Option<u64>,
    emit: &mut dyn FnMut(&UnwindRow<'d>) -> bool,
) -> Option<()> {
    let mut row = UnwindRow {
        address: fde.pc_begin,
        cfa: CfaRule::RegisterOffset {
            register: 0,
            offset: 0,
        },
        registers: Vec::new(),
        return_address_signed: None,
        args_size: 0,
    };
    let mut stack: Vec<UnwindRow<'d>> = Vec::new();
    // The CIE's instructions set up the initial row (which DW_CFA_restore
    // returns to).
    let mut ignore = |_: &UnwindRow<'d>| true;
    execute(
        cfi,
        cie,
        cie.instructions,
        &mut row,
        None,
        &mut stack,
        until,
        &mut ignore,
    )?;
    let initial = row.clone();
    stack.clear();
    let stop = execute(
        cfi,
        cie,
        fde.instructions,
        &mut row,
        Some(&initial),
        &mut stack,
        until,
        emit,
    )?;
    if !stop {
        emit(&row);
    }
    Some(())
}

/// Executes instructions on `row`; returns whether it stopped early (the
/// last row emitted already covers `until`).
#[allow(clippy::too_many_arguments)]
fn execute<'d>(
    cfi: &Cfi<'d>,
    cie: &Cie<'d>,
    instructions: &'d [u8],
    row: &mut UnwindRow<'d>,
    initial: Option<&UnwindRow<'d>>,
    stack: &mut Vec<UnwindRow<'d>>,
    until: Option<u64>,
    emit: &mut dyn FnMut(&UnwindRow<'d>) -> bool,
) -> Option<bool> {
    // (Read in place in the section, so that PC-relative `DW_CFA_set_loc`
    // operands are relative to where they are.)
    let start = (instructions.as_ptr() as usize).wrapping_sub(cfi.data.as_ptr() as usize);
    let mut r = match start.checked_add(instructions.len()) {
        Some(end) if end <= cfi.data.len() => Reader::new(&cfi.data[..end], start, cfi.endian),
        _ => Reader::new(instructions, 0, cfi.endian),
    };
    let caf = cie.code_alignment;
    let daf = cie.data_alignment;
    let reg = |r: &mut Reader<'d>| -> Option<u16> { u16::try_from(r.uleb()?).ok() };
    let block = |r: &mut Reader<'d>| -> Option<&'d [u8]> {
        let n = r.uleb()?;
        r.bytes(n)
    };
    // Moves to a new address: emits the finished row.
    let advance =
        |row: &mut UnwindRow<'d>, to: u64, emit: &mut dyn FnMut(&UnwindRow<'d>) -> bool| -> bool {
            if until.is_some_and(|u| to > u) {
                emit(row);
                return true;
            }
            emit(row);
            row.address = to;
            false
        };
    while !r.is_empty() {
        let op = r.u8()?;
        let (high, low) = (op & 0xC0, op & 0x3F);
        match high {
            ADVANCE_LOC => {
                let to = row.address.wrapping_add(u64::from(low).wrapping_mul(caf));
                if initial.is_some() && advance(row, to, emit) {
                    return Some(true);
                }
                continue;
            }
            OFFSET => {
                let off = (r.uleb()? as i64).wrapping_mul(daf);
                row.set(u16::from(low), RegisterRule::Offset(off));
                continue;
            }
            RESTORE => {
                restore(row, initial, u16::from(low));
                continue;
            }
            _ => {}
        }
        match op {
            NOP => {}
            SET_LOC => {
                let to = match cfi.kind {
                    CfiKind::EhFrame => cfi.pointer(&mut r, cie.fde_encoding, cie.address_size)?,
                    CfiKind::DebugFrame => r.uint(usize::from(cie.address_size.clamp(1, 8)))?,
                };
                if initial.is_some() && advance(row, to, emit) {
                    return Some(true);
                }
            }
            ADVANCE_LOC1 | ADVANCE_LOC2 | ADVANCE_LOC4 | MIPS_ADVANCE_LOC8 => {
                let n = match op {
                    ADVANCE_LOC1 => 1,
                    ADVANCE_LOC2 => 2,
                    ADVANCE_LOC4 => 4,
                    _ => 8,
                };
                let to = row.address.wrapping_add(r.uint(n)?.wrapping_mul(caf));
                if initial.is_some() && advance(row, to, emit) {
                    return Some(true);
                }
            }
            OFFSET_EXTENDED => {
                let n = reg(&mut r)?;
                row.set(
                    n,
                    RegisterRule::Offset((r.uleb()? as i64).wrapping_mul(daf)),
                );
            }
            OFFSET_EXTENDED_SF => {
                let n = reg(&mut r)?;
                row.set(n, RegisterRule::Offset(r.sleb()?.wrapping_mul(daf)));
            }
            GNU_NEGATIVE_OFFSET_EXTENDED => {
                let n = reg(&mut r)?;
                row.set(
                    n,
                    RegisterRule::Offset((r.uleb()? as i64).wrapping_neg().wrapping_mul(daf)),
                );
            }
            RESTORE_EXTENDED => {
                let n = reg(&mut r)?;
                restore(row, initial, n);
            }
            UNDEFINED => row.set(reg(&mut r)?, RegisterRule::Undefined),
            SAME_VALUE => row.set(reg(&mut r)?, RegisterRule::SameValue),
            REGISTER => {
                let n = reg(&mut r)?;
                let from = reg(&mut r)?;
                row.set(n, RegisterRule::Register(from));
            }
            REMEMBER_STATE => {
                if stack.len() >= MAX_REMEMBERED {
                    return None;
                }
                stack.push(row.clone());
            }
            RESTORE_STATE => {
                let saved = stack.pop()?;
                // (The location stays.)
                let address = row.address;
                *row = saved;
                row.address = address;
            }
            DEF_CFA => {
                let register = reg(&mut r)?;
                let offset = r.uleb()? as i64;
                row.cfa = CfaRule::RegisterOffset { register, offset };
            }
            DEF_CFA_SF => {
                let register = reg(&mut r)?;
                let offset = r.sleb()?.wrapping_mul(daf);
                row.cfa = CfaRule::RegisterOffset { register, offset };
            }
            DEF_CFA_REGISTER => {
                let register = reg(&mut r)?;
                let offset = match row.cfa {
                    CfaRule::RegisterOffset { offset, .. } => offset,
                    CfaRule::Expression(_) => 0,
                };
                row.cfa = CfaRule::RegisterOffset { register, offset };
            }
            DEF_CFA_OFFSET | DEF_CFA_OFFSET_SF => {
                let offset = if op == DEF_CFA_OFFSET {
                    r.uleb()? as i64
                } else {
                    r.sleb()?.wrapping_mul(daf)
                };
                match &mut row.cfa {
                    CfaRule::RegisterOffset { offset: o, .. } => *o = offset,
                    CfaRule::Expression(_) => return None,
                }
            }
            DEF_CFA_EXPRESSION => row.cfa = CfaRule::Expression(block(&mut r)?),
            EXPRESSION => {
                let n = reg(&mut r)?;
                row.set(n, RegisterRule::Expression(block(&mut r)?));
            }
            VAL_EXPRESSION => {
                let n = reg(&mut r)?;
                row.set(n, RegisterRule::ValExpression(block(&mut r)?));
            }
            VAL_OFFSET => {
                let n = reg(&mut r)?;
                row.set(
                    n,
                    RegisterRule::ValOffset((r.uleb()? as i64).wrapping_mul(daf)),
                );
            }
            VAL_OFFSET_SF => {
                let n = reg(&mut r)?;
                row.set(n, RegisterRule::ValOffset(r.sleb()?.wrapping_mul(daf)));
            }
            GNU_WINDOW_SAVE | AARCH64_NEGATE_RA_STATE_WITH_PC => {
                row.return_address_signed = Some(!row.return_address_signed.unwrap_or(false));
            }
            GNU_ARGS_SIZE => row.args_size = r.uleb()?,
            _ => return None,
        }
    }
    Some(false)
}

/// `DW_CFA_restore`: back to the CIE's rule (or none).
fn restore<'d>(row: &mut UnwindRow<'d>, initial: Option<&UnwindRow<'d>>, register: u16) {
    match initial.and_then(|i| i.rule(register)) {
        Some(rule) => row.set(register, rule),
        None => row.unset(register),
    }
}

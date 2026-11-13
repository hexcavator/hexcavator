//! The exception directory (`.pdata`) and unwind information (`.xdata`).
//!
//! x64 images have 12-byte `RUNTIME_FUNCTION` entries (begin, end, unwind
//! info RVA). ARM64 (and ARM32) images have 8-byte entries: a begin RVA and
//! either packed unwind data or the RVA of an `.xdata` record. ARM64EC
//! images mix the two in one table, with the code range map deciding which
//! kind each entry is.

use hexcavator_core::{Reader, Rva};

use crate::PeFile;
use crate::consts::{directory, machine};
use crate::load_config::CodeKind;

/// One `.pdata` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFunction {
    /// x64: `[begin, end)` and the RVA of its `UNWIND_INFO`.
    X64 { begin: Rva, end: Rva, unwind: Rva },
    /// ARM64/ARM32: the function start and its unwind word, which is
    /// either packed unwind data (low two bits non-zero) or the RVA of an
    /// `.xdata` record.
    Arm { begin: Rva, unwind: u32 },
}

impl RuntimeFunction {
    pub fn begin(&self) -> Rva {
        match *self {
            RuntimeFunction::X64 { begin, .. } | RuntimeFunction::Arm { begin, .. } => begin,
        }
    }

    /// For ARM entries: the packed-unwind flag (0 = `.xdata` RVA).
    pub fn arm_flag(&self) -> Option<u32> {
        match *self {
            RuntimeFunction::Arm { unwind, .. } => Some(unwind & 3),
            RuntimeFunction::X64 { .. } => None,
        }
    }
}

/// A `.pdata` entry and where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PdataEntry {
    /// The entry's offset from the start of the table (both tables, for
    /// hybrid images; see [`PeFile::runtime_functions`]).
    pub offset: u32,
    /// The entry's own RVA.
    pub rva: Rva,
    /// Whether the entry is in the exception directory (rather than a
    /// hybrid image's second table).
    pub in_exception_directory: bool,
    pub function: RuntimeFunction,
}

impl<'data> PeFile<'data> {
    /// The exception directory's raw bytes.
    pub fn pdata(&self) -> &'data [u8] {
        self.data_directory(directory::EXCEPTION)
            .and_then(|d| {
                self.bytes_at_rva(Rva(d.virtual_address.get()), d.size.get())
                    .ok()
            })
            .unwrap_or(&[])
    }

    /// The `.pdata` entries, in order. Hybrid images have a second table in
    /// their hybrid metadata. ARM64EC images (an x64 machine) list it, of
    /// ARM64 entries, first and then the exception directory; ARM64X images
    /// (an ARM64 machine) list the exception directory, of ARM64 entries,
    /// and then it, of x64 entries. Offsets run on across both.
    pub fn runtime_functions(&self) -> impl Iterator<Item = PdataEntry> + 'data {
        use crate::load_config::arm64ec;
        let hybrid = self
            .load_config()
            .and_then(|c| c.hybrid_metadata())
            .filter(|h| !h.is_x86());
        let (extra_rva, extra) = hybrid
            .as_ref()
            .and_then(|h| {
                let rva = h.field(arm64ec::EXTRA_RFE_TABLE);
                let size = h.field(arm64ec::EXTRA_RFE_TABLE_SIZE);
                (rva != 0).then(|| Some((rva, self.bytes_at_rva(Rva(rva), size).ok()?)))?
            })
            .unwrap_or((0, &[]));
        let pdata_rva = self
            .data_directory(directory::EXCEPTION)
            .map_or(0, |d| d.virtual_address.get());
        let fixed = match self.machine() {
            machine::ARM64 | machine::ARM64EC | machine::ARM64X | machine::ARMNT => Some(false),
            machine::AMD64 if hybrid.is_none() => Some(true),
            machine::AMD64 => None,
            _ => Some(true),
        };
        let is_x64 = move |begin: Rva| {
            fixed.unwrap_or_else(|| {
                hybrid
                    .as_ref()
                    .and_then(|h| h.code_kind_at(begin))
                    .is_some_and(|k| k == CodeKind::X64)
            })
        };
        let extra_len = u32::try_from(extra.len()).unwrap_or(u32::MAX);
        let arm64x = self.machine() == machine::ARM64 && hybrid.is_some();
        let pdata = self.pdata();
        let pdata_len = u32::try_from(pdata.len()).unwrap_or(u32::MAX);
        // (data, its RVA, offset of its first entry, all x64 / all ARM / by
        // code map, whether it is the exception directory)
        let (first, second) = if arm64x {
            (
                (pdata, pdata_rva, 0, Some(false), true),
                (extra, extra_rva, pdata_len, Some(true), false),
            )
        } else {
            (
                (extra, extra_rva, 0, None, false),
                (pdata, pdata_rva, extra_len, None, true),
            )
        };
        let parse = move |(data, table_rva, base, kind, directory): (
            &'data [u8],
            u32,
            u32,
            Option<bool>,
            bool,
        )| {
            let mut r = Reader::new(data);
            core::iter::from_fn(move || {
                let position = u32::try_from(r.position()).ok()?;
                let offset = base.checked_add(position)?;
                let rva = Rva(table_rva.checked_add(position)?);
                let begin = Rva(r.u32_le().ok()?);
                let function = if kind.unwrap_or_else(|| is_x64(begin)) {
                    RuntimeFunction::X64 {
                        begin,
                        end: Rva(r.u32_le().ok()?),
                        unwind: Rva(r.u32_le().ok()?),
                    }
                } else {
                    RuntimeFunction::Arm {
                        begin,
                        unwind: r.u32_le().ok()?,
                    }
                };
                Some(PdataEntry {
                    offset,
                    rva,
                    in_exception_directory: directory,
                    function,
                })
            })
        };
        parse(first).chain(parse(second))
    }

    /// The x64 unwind information at `rva`.
    pub fn x64_unwind_info(&self, rva: Rva) -> Option<X64UnwindInfo<'data>> {
        let header = self.bytes_at_rva(rva, 4).ok()?;
        let count = u32::from(header[2]);
        // Codes are padded to an even count; then comes the handler or the
        // chained entry.
        let codes_len = count.div_ceil(2) * 4;
        let codes = if count == 0 {
            &[][..]
        } else {
            self.bytes_at_rva(Rva(rva.get() + 4), count * 2).ok()?
        };
        let tail = Rva(rva.get() + 4 + codes_len);
        Some(X64UnwindInfo {
            version: header[0] & 7,
            flags: header[0] >> 3,
            prolog_size: header[1],
            frame_register: header[3] & 0xF,
            frame_offset: header[3] >> 4,
            codes,
            tail,
            file: *self,
        })
    }
}

/// `UNW_FLAG_*`.
pub mod unwind_flags {
    pub const EHANDLER: u8 = 1;
    pub const UHANDLER: u8 = 2;
    pub const CHAININFO: u8 = 4;
}

/// x64 `UNWIND_INFO`.
#[derive(Clone, Copy, Debug)]
pub struct X64UnwindInfo<'data> {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    /// 0 if the function has no frame pointer.
    pub frame_register: u8,
    /// The frame pointer's offset from RSP, divided by 16.
    pub frame_offset: u8,
    /// The raw unwind codes (two bytes each).
    pub codes: &'data [u8],
    /// The RVA after the codes: the handler, or the chained entry.
    tail: Rva,
    file: PeFile<'data>,
}

/// One decoded x64 unwind operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X64UnwindCode {
    PushNonvol {
        reg: u8,
    },
    AllocLarge {
        size: u32,
    },
    AllocSmall {
        size: u32,
    },
    SetFpreg,
    SaveNonvol {
        reg: u8,
        offset: u32,
    },
    SaveNonvolFar {
        reg: u8,
        offset: u32,
    },
    /// Version 2: the first epilog code gives the size (and, in bit 0 of
    /// `flags`, whether the epilog is at the end of the function).
    EpilogFirst {
        flags: u8,
        size: u8,
    },
    /// Version 2: another epilog, at this distance from the function end.
    Epilog {
        offset_from_end: u32,
    },
    SaveXmm128 {
        reg: u8,
        offset: u32,
    },
    SaveXmm128Far {
        reg: u8,
        offset: u32,
    },
    PushMachframe {
        error_code: bool,
    },
    /// An operation this decoder does not know.
    Unknown {
        op: u8,
        info: u8,
    },
}

impl<'data> X64UnwindInfo<'data> {
    pub fn count_of_codes(&self) -> usize {
        self.codes.len() / 2
    }

    /// The decoded codes: `(prolog offset, operation)`.
    pub fn unwind_codes(&self) -> impl Iterator<Item = (u8, X64UnwindCode)> + 'data {
        x64_unwind_codes(self.codes, self.version)
    }
}

/// Decodes raw x64 unwind codes (two bytes each, as in `UNWIND_INFO`):
/// `(prolog offset, operation)`. A code whose extra slots are missing ends
/// the sequence.
pub fn x64_unwind_codes(
    codes: &[u8],
    version: u8,
) -> impl Iterator<Item = (u8, X64UnwindCode)> + '_ {
    {
        let mut i = 0usize;
        let mut first_epilog = true;
        let slot = move |i: usize| -> Option<u32> {
            Some(u32::from(u16::from_le_bytes([
                *codes.get(i * 2)?,
                *codes.get(i * 2 + 1)?,
            ])))
        };
        core::iter::from_fn(move || {
            let offset = *codes.get(i * 2)?;
            let byte = *codes.get(i * 2 + 1)?;
            let (op, info) = (byte & 0xF, byte >> 4);
            i += 1;
            let code = match op {
                0 => X64UnwindCode::PushNonvol { reg: info },
                1 if info == 0 => {
                    let size = slot(i)? * 8;
                    i += 1;
                    X64UnwindCode::AllocLarge { size }
                }
                1 => {
                    let size = slot(i)? | slot(i + 1)? << 16;
                    i += 2;
                    X64UnwindCode::AllocLarge { size }
                }
                2 => X64UnwindCode::AllocSmall {
                    size: u32::from(info) * 8 + 8,
                },
                3 => X64UnwindCode::SetFpreg,
                4 => {
                    let offset = slot(i)? * 8;
                    i += 1;
                    X64UnwindCode::SaveNonvol { reg: info, offset }
                }
                5 => {
                    let offset = slot(i)? | slot(i + 1)? << 16;
                    i += 2;
                    X64UnwindCode::SaveNonvolFar { reg: info, offset }
                }
                6 if version >= 2 => {
                    if first_epilog {
                        first_epilog = false;
                        X64UnwindCode::EpilogFirst {
                            flags: info,
                            size: offset,
                        }
                    } else {
                        X64UnwindCode::Epilog {
                            offset_from_end: u32::from(offset) | u32::from(info) << 8,
                        }
                    }
                }
                8 => {
                    let offset = slot(i)? * 16;
                    i += 1;
                    X64UnwindCode::SaveXmm128 { reg: info, offset }
                }
                9 => {
                    let offset = slot(i)? | slot(i + 1)? << 16;
                    i += 2;
                    X64UnwindCode::SaveXmm128Far { reg: info, offset }
                }
                10 => X64UnwindCode::PushMachframe {
                    error_code: info != 0,
                },
                _ => X64UnwindCode::Unknown { op, info },
            };
            Some((offset, code))
        })
    }
}

impl X64UnwindInfo<'_> {
    /// The record's size in bytes: the header, the codes (padded to an even
    /// count), and the handler RVA or the chained entry, but not the
    /// handler's own data (whose size depends on the handler).
    pub fn size(&self) -> u32 {
        // At most 255 codes (a byte counts them).
        let codes = u32::try_from(self.codes.len() / 2)
            .unwrap_or(u32::MAX)
            .div_ceil(2)
            * 4;
        let tail = if self.flags & unwind_flags::CHAININFO != 0 {
            12
        } else if self.flags & (unwind_flags::EHANDLER | unwind_flags::UHANDLER) != 0 {
            4
        } else {
            0
        };
        4 + codes + tail
    }

    /// The exception handler's RVA, if the flags call for one.
    pub fn handler(&self) -> Option<Rva> {
        if self.flags & (unwind_flags::EHANDLER | unwind_flags::UHANDLER) == 0
            || self.flags & unwind_flags::CHAININFO != 0
        {
            return None;
        }
        let b = self.file.bytes_at_rva(self.tail, 4).ok()?;
        Some(Rva(u32::from_le_bytes(b.try_into().ok()?)))
    }

    /// The RVA of the handler's language-specific data.
    pub fn handler_data(&self) -> Option<Rva> {
        self.handler().map(|_| Rva(self.tail.get() + 4))
    }

    /// The chained (parent) entry, for `CHAININFO`.
    pub fn chained(&self) -> Option<RuntimeFunction> {
        if self.flags & unwind_flags::CHAININFO == 0 {
            return None;
        }
        let b = self.file.bytes_at_rva(self.tail, 12).ok()?;
        let word = |i: usize| Rva(u32::from_le_bytes(b[i..i + 4].try_into().expect("4 bytes")));
        Some(RuntimeFunction::X64 {
            begin: word(0),
            end: word(4),
            unwind: word(8),
        })
    }
}

/// The size of an ARM32 or ARM64 `.xdata` record at `rva` (header, epilog
/// scopes, unwind codes, and the handler RVA if it has one), and the
/// handler's RVA. The two differ only in how the first word packs the
/// epilog count and code words.
pub fn arm_xdata_extent(file: &PeFile<'_>, rva: Rva, arm32: bool) -> Option<(u32, Option<Rva>)> {
    let word = |at: u32| -> Option<u32> {
        Some(u32::from_le_bytes(
            file.bytes_at_rva(Rva(at), 4).ok()?.try_into().ok()?,
        ))
    };
    let first = word(rva.get())?;
    let x = (first >> 20) & 1 != 0;
    let e = (first >> 21) & 1 != 0;
    let (epilogs, codes) = if arm32 {
        ((first >> 23) & 0x1F, (first >> 28) & 0xF)
    } else {
        ((first >> 22) & 0x1F, (first >> 27) & 0x1F)
    };
    let (mut size, epilogs, codes) = if epilogs == 0 && codes == 0 {
        let second = word(rva.get().checked_add(4)?)?;
        (8, second & 0xFFFF, (second >> 16) & 0xFF)
    } else {
        (4, epilogs, codes)
    };
    if !e {
        size += 4 * epilogs;
    }
    size += 4 * codes;
    let handler = if x {
        let at = rva.get().checked_add(size)?;
        size += 4;
        Some(Rva(word(at)?))
    } else {
        None
    };
    Some((size, handler))
}

/// ARM64 packed unwind data (`.pdata` entries with flag 1 or 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64PackedUnwind {
    /// 1: packed; 2: packed, for a fragment without a prolog.
    pub flag: u8,
    /// In bytes.
    pub function_length: u32,
    /// The number of saved floating-point registers (d8–d15), minus one.
    pub reg_f: u8,
    /// The number of saved integer registers (x19–x28).
    pub reg_i: u8,
    /// Whether x0–x7 are homed.
    pub h: bool,
    /// 0: unchained; 1: lr saved alone (unchained); 2: chained, with a
    /// `pacibsp`; 3: chained.
    pub cr: u8,
    /// In bytes.
    pub frame_size: u32,
}

impl Arm64PackedUnwind {
    pub fn decode(word: u32) -> Option<Self> {
        let flag = (word & 3) as u8;
        if flag == 0 || flag == 3 {
            return None;
        }
        Some(Self {
            flag,
            function_length: ((word >> 2) & 0x7FF) * 4,
            reg_f: ((word >> 13) & 7) as u8,
            reg_i: ((word >> 16) & 0xF) as u8,
            h: (word >> 20) & 1 != 0,
            cr: ((word >> 21) & 3) as u8,
            frame_size: ((word >> 23) & 0x1FF) * 16,
        })
    }
}

/// An ARM64 `.xdata` record.
#[derive(Clone, Copy, Debug)]
pub struct Arm64Xdata<'data> {
    /// The header words (one, or two with the extended counts).
    pub header: &'data [u8],
    /// In bytes.
    pub function_length: u32,
    pub version: u8,
    /// Whether an exception handler follows the codes.
    pub x: bool,
    /// Whether the single epilog's codes are given by `epilog_count`
    /// (an index into the codes) rather than an epilog scope list.
    pub e: bool,
    pub epilog_count: u16,
    pub code_words: u8,
    /// The epilog scopes (one word each), unless `e`.
    pub epilog_scopes: &'data [u8],
    /// The unwind code bytes (`code_words * 4`).
    pub codes: &'data [u8],
    /// The handler RVA, if `x`.
    pub handler: Option<Rva>,
    /// The record's total size, in bytes (handler RVA included).
    pub size: u32,
}

/// One ARM64 epilog scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64EpilogScope {
    /// In bytes from the function start.
    pub start_offset: u32,
    /// The condition (always 14, "always", on ARM64).
    pub condition: u8,
    /// The index of the epilog's first unwind code byte.
    pub start_index: u16,
}

impl<'data> Arm64Xdata<'data> {
    pub fn parse(file: &PeFile<'data>, rva: Rva) -> Option<Self> {
        let first = u32::from_le_bytes(file.bytes_at_rva(rva, 4).ok()?.try_into().ok()?);
        let mut function_length = (first & 0x3_FFFF) * 4;
        let version = ((first >> 18) & 3) as u8;
        let x = (first >> 20) & 1 != 0;
        let e = (first >> 21) & 1 != 0;
        let mut epilog_count = ((first >> 22) & 0x1F) as u16;
        let mut code_words = (first >> 27) as u8;
        let mut header_len = 4u32;
        if epilog_count == 0 && code_words == 0 {
            let second = u32::from_le_bytes(
                file.bytes_at_rva(Rva(rva.get() + 4), 4)
                    .ok()?
                    .try_into()
                    .ok()?,
            );
            epilog_count = (second & 0xFFFF) as u16;
            code_words = ((second >> 16) & 0xFF) as u8;
            header_len = 8;
        }
        let _ = &mut function_length;
        let header = file.bytes_at_rva(rva, header_len).ok()?;
        let scopes_len = if e { 0 } else { u32::from(epilog_count) * 4 };
        let epilog_scopes = file
            .bytes_at_rva(Rva(rva.get() + header_len), scopes_len)
            .ok()?;
        let codes_rva = rva.get() + header_len + scopes_len;
        let codes_len = u32::from(code_words) * 4;
        let codes = file.bytes_at_rva(Rva(codes_rva), codes_len).ok()?;
        let mut size = header_len + scopes_len + codes_len;
        let handler = if x {
            let b = file.bytes_at_rva(Rva(codes_rva + codes_len), 4).ok()?;
            size += 4;
            Some(Rva(u32::from_le_bytes(b.try_into().ok()?)))
        } else {
            None
        };
        Some(Self {
            header,
            function_length,
            version,
            x,
            e,
            epilog_count,
            code_words,
            epilog_scopes,
            codes,
            handler,
            size,
        })
    }

    pub fn epilog_scopes(&self) -> impl Iterator<Item = Arm64EpilogScope> + 'data {
        self.epilog_scopes.as_chunks::<4>().0.iter().map(|c| {
            let w = u32::from_le_bytes(*c);
            Arm64EpilogScope {
                start_offset: (w & 0x3_FFFF) * 4,
                condition: ((w >> 18) & 0xF) as u8,
                start_index: (w >> 22) as u16,
            }
        })
    }

    /// The decoded unwind codes starting at byte `index`, up to and
    /// including the first `end` (or `end_c`).
    pub fn codes_from(
        &self,
        index: usize,
    ) -> impl Iterator<Item = (usize, Arm64UnwindCode)> + 'data {
        let codes = self.codes;
        let mut i = index;
        let mut done = false;
        core::iter::from_fn(move || {
            if done {
                return None;
            }
            let (code, len) = Arm64UnwindCode::decode(codes.get(i..)?)?;
            let at = i;
            i += len;
            if matches!(code, Arm64UnwindCode::End | Arm64UnwindCode::EndC) {
                done = true;
            }
            Some((at, code))
        })
    }
}

/// One ARM64 unwind code. Offsets and sizes are in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm64UnwindCode {
    /// `sub sp, sp, #size` (size < 512).
    AllocS {
        size: u32,
    },
    /// `stp x19, x20, [sp, #-offset]!`.
    SaveR19R20X {
        offset: u32,
    },
    /// `stp fp, lr, [sp, #offset]`.
    SaveFpLr {
        offset: u32,
    },
    /// `stp fp, lr, [sp, #-offset]!`.
    SaveFpLrX {
        offset: u32,
    },
    /// `sub sp, sp, #size` (size < 32 KB).
    AllocM {
        size: u32,
    },
    /// `stp x(19+reg), x(20+reg), [sp, #offset]`.
    SaveRegp {
        reg: u8,
        offset: u32,
    },
    /// `stp x(19+reg), x(20+reg), [sp, #-offset]!`.
    SaveRegpX {
        reg: u8,
        offset: u32,
    },
    /// `str x(19+reg), [sp, #offset]`.
    SaveReg {
        reg: u8,
        offset: u32,
    },
    /// `str x(19+reg), [sp, #-offset]!`.
    SaveRegX {
        reg: u8,
        offset: u32,
    },
    /// `stp x(19+2*reg), lr, [sp, #offset]`.
    SaveLrpair {
        reg: u8,
        offset: u32,
    },
    /// `stp d(8+reg), d(9+reg), [sp, #offset]`.
    SaveFregp {
        reg: u8,
        offset: u32,
    },
    SaveFregpX {
        reg: u8,
        offset: u32,
    },
    SaveFreg {
        reg: u8,
        offset: u32,
    },
    SaveFregX {
        reg: u8,
        offset: u32,
    },
    /// Allocates `count` SVE vector lengths of stack.
    AllocZ {
        count: u8,
    },
    /// `sub sp, sp, #size` (size < 256 MB).
    AllocL {
        size: u32,
    },
    /// `mov fp, sp`.
    SetFp,
    /// `add fp, sp, #offset`.
    AddFp {
        offset: u32,
    },
    Nop,
    End,
    /// End of a code fragment whose prolog/epilog continues elsewhere.
    EndC,
    SaveNext,
    /// `stp`/`str` of any register, with an explicit kind (`save_any_reg`).
    SaveAnyReg {
        raw: u16,
    },
    /// `pacibsp`/`autibsp`.
    PacSignLr,
    /// Custom stack cases: 0xE8 `MSFT_OP_TRAP_FRAME`, 0xE9
    /// `MSFT_OP_MACHINE_FRAME`, 0xEA `MSFT_OP_CONTEXT`, 0xEB
    /// `MSFT_OP_EC_CONTEXT`, 0xEC `MSFT_OP_CLEAR_UNWOUND_TO_CALL`.
    Custom {
        op: u8,
    },
    /// A reserved code.
    Reserved {
        op: u8,
    },
}

impl Arm64UnwindCode {
    /// Decodes the code at the start of `b`: the code and its length.
    pub fn decode(b: &[u8]) -> Option<(Self, usize)> {
        let b0 = *b.first()?;
        let b1 = || b.get(1).copied().map(u32::from);
        let w2 = || Some(u32::from(b0) << 8 | b1()?);
        Some(match b0 {
            0x00..=0x1F => (
                Self::AllocS {
                    size: u32::from(b0) * 16,
                },
                1,
            ),
            0x20..=0x3F => (
                Self::SaveR19R20X {
                    offset: u32::from(b0 & 0x1F) * 8,
                },
                1,
            ),
            0x40..=0x7F => (
                Self::SaveFpLr {
                    offset: u32::from(b0 & 0x3F) * 8,
                },
                1,
            ),
            0x80..=0xBF => (
                Self::SaveFpLrX {
                    offset: (u32::from(b0 & 0x3F) + 1) * 8,
                },
                1,
            ),
            0xC0..=0xC7 => (
                Self::AllocM {
                    size: (w2()? & 0x7FF) * 16,
                },
                2,
            ),
            0xC8..=0xCF => {
                let w = w2()?;
                let reg = ((w >> 6) & 0xF) as u8;
                let off = w & 0x3F;
                match b0 & 0xFC {
                    0xC8 => (
                        Self::SaveRegp {
                            reg,
                            offset: off * 8,
                        },
                        2,
                    ),
                    _ => (
                        Self::SaveRegpX {
                            reg,
                            offset: (off + 1) * 8,
                        },
                        2,
                    ),
                }
            }
            0xD0..=0xD5 => {
                let w = w2()?;
                let reg = ((w >> 6) & 0xF) as u8;
                let off = w & 0x3F;
                match b0 & 0xFC {
                    0xD0 => (
                        Self::SaveReg {
                            reg,
                            offset: off * 8,
                        },
                        2,
                    ),
                    _ => {
                        // save_reg_x: 1101010x xxxzzzzz: reg is 4 bits,
                        // offset 5 bits.
                        let reg = ((w >> 5) & 0xF) as u8;
                        let off = w & 0x1F;
                        (
                            Self::SaveRegX {
                                reg,
                                offset: (off + 1) * 8,
                            },
                            2,
                        )
                    }
                }
            }
            0xD6..=0xD7 => {
                let w = w2()?;
                (
                    Self::SaveLrpair {
                        reg: ((w >> 6) & 7) as u8,
                        offset: (w & 0x3F) * 8,
                    },
                    2,
                )
            }
            0xD8..=0xDF => {
                let w = w2()?;
                let reg = ((w >> 6) & 7) as u8;
                let off = w & 0x3F;
                match b0 & 0xFE {
                    0xD8 => (
                        Self::SaveFregp {
                            reg,
                            offset: off * 8,
                        },
                        2,
                    ),
                    0xDA => (
                        Self::SaveFregpX {
                            reg,
                            offset: (off + 1) * 8,
                        },
                        2,
                    ),
                    0xDC => (
                        Self::SaveFreg {
                            reg,
                            offset: off * 8,
                        },
                        2,
                    ),
                    _ if b0 == 0xDF => (
                        Self::AllocZ {
                            count: (w & 0xFF) as u8,
                        },
                        2,
                    ),
                    _ => {
                        // save_freg_x: 11011110 xxxzzzzz.
                        let reg = ((w >> 5) & 7) as u8;
                        let off = w & 0x1F;
                        (
                            Self::SaveFregX {
                                reg,
                                offset: (off + 1) * 8,
                            },
                            2,
                        )
                    }
                }
            }
            0xE0 => {
                let size = u32::from(*b.get(1)?) << 16
                    | u32::from(*b.get(2)?) << 8
                    | u32::from(*b.get(3)?);
                (Self::AllocL { size: size * 16 }, 4)
            }
            0xE1 => (Self::SetFp, 1),
            0xE2 => (Self::AddFp { offset: b1()? * 8 }, 2),
            0xE3 => (Self::Nop, 1),
            0xE4 => (Self::End, 1),
            0xE5 => (Self::EndC, 1),
            0xE6 => (Self::SaveNext, 1),
            0xE7 => {
                let raw = u16::from_le_bytes([*b.get(2)?, *b.get(1)?]);
                (Self::SaveAnyReg { raw }, 3)
            }
            0xE8..=0xEC => (Self::Custom { op: b0 }, 1),
            0xF8..=0xFB => (Self::Reserved { op: b0 }, usize::from(b0 - 0xF6)),
            0xFC => (Self::PacSignLr, 1),
            _ => (Self::Reserved { op: b0 }, 1),
        })
    }
}

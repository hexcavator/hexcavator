//! Text in the syntax of LLVM's disassembler (`llvm-objdump`, `llvm-mc`):
//! each encoding's template (from Arm's specification), its operands as
//! the architecture defines them (registers, expanded immediates, branch
//! targets, register lists, data types).

use alloc::string::String;
use core::fmt::Write as _;

use crate::{Instruction, Rule, rule};

/// How branch and literal targets are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Targets {
    /// As addresses: where they lead (hexadecimal).
    #[default]
    Addresses,
    /// As LLVM writes them when it has no symbols: the offset from the
    /// PC (`#-4`).
    Offsets,
}

/// `i` (at `addr`) as text: its mnemonic, then a space and its operands.
pub fn format(i: &Instruction, addr: u64, targets: Targets) -> String {
    let mut out = String::new();
    format_into(i, addr, targets, &mut out);
    out
}

/// Where a direct branch or call (B, BL, BLX, CBZ, CBNZ) at `addr` goes;
/// `None` for anything else.
pub fn branch_target(i: &Instruction, addr: u64) -> Option<u64> {
    let n = i.encoding.name;
    let branch = n.starts_with("B_")
        || n.starts_with("BL_i")
        || n.starts_with("CBZ")
        || n.starts_with("CBNZ");
    if !branch {
        return None;
    }
    let c = Ctx {
        i,
        addr,
        targets: Targets::Addresses,
        it: None,
    };
    let offset = c.label_offset()?;
    let pc = addr.wrapping_add(if i.thumb { 4 } else { 8 });
    // (BLX from T32 lands on a word.)
    let pc = if n == "BL_i_T2" { pc & !3 } else { pc };
    Some(pc.wrapping_add_signed(offset) & 0xffff_ffff)
}

/// [`format`], into `out`.
pub fn format_into(i: &Instruction, addr: u64, targets: Targets, out: &mut String) {
    format_in_it(i, addr, targets, None, out);
}

/// The condition each instruction of an IT block has (`firstcond` and
/// `mask` are the IT instruction's): the first's, then each next's from
/// its bit of the mask; as many as the block has.
pub fn it_conditions(firstcond: u32, mask: u32) -> impl Iterator<Item = u32> {
    let count = 4 - (mask & 15).trailing_zeros().min(4);
    (0..count).map(move |k| {
        if k == 0 {
            firstcond & 15
        } else {
            firstcond & 0xe | mask >> (4 - k) & 1
        }
    })
}

/// [`format_into`] for an instruction in an IT block (T32), which has the
/// condition `it` (see [`it_conditions`]); outside one (`None`), a T16
/// instruction with an S form sets the flags, as LLVM takes it.
pub fn format_in_it(
    i: &Instruction,
    addr: u64,
    targets: Targets,
    it: Option<u32>,
    out: &mut String,
) {
    let c = Ctx {
        i,
        addr,
        targets,
        it,
    };
    if c.alias(out) {
        return;
    }
    let t = i.encoding.asm.as_bytes();
    // The mnemonic: its leading letters and digits, lowercased (LLVM's,
    // where it differs).
    let end = t
        .iter()
        .position(|b| !b.is_ascii_alphanumeric())
        .unwrap_or(t.len());
    match llvm_mnemonic(i.encoding.name) {
        Some(m) => out.push_str(m),
        None => {
            for &b in &t[..end] {
                out.push(char::from(b.to_ascii_lowercase()));
            }
            // (A T16 instruction outside an IT block, as LLVM takes it,
            // sets the flags where an S form of it is its alias.)
            if i.thumb && i.size == 2 && it.is_none() && sets_flags_outside_it(i.encoding) {
                out.push('s');
            }
        }
    }
    // (LLVM's `.w` goes after the condition: the template's `{<c>}`
    // comes first.)
    let wide = i.thumb && i.size == 4 && llvm_wide(i.encoding.name);
    let mut pos = end;
    let before = out.len();
    if wide {
        // The condition (if any), `.w`, then the rest.
        let rest = &t[end..];
        let close = if rest.starts_with(b"{%{") {
            rest.iter().position(|&b| b == b'}').map(|p| p + 2)
        } else if rest.starts_with(b"%{") {
            rest.iter().position(|&b| b == b'}').map(|p| p + 1)
        } else {
            None
        };
        if let Some(n) = close {
            let mut p = 0;
            c.seq(&rest[..n], &mut p, out, 0);
            pos += n;
        }
        // (Unless the template writes it.)
        let head = &t[pos..];
        let head = &head[..head.iter().position(|&b| b == b' ').unwrap_or(head.len())];
        if !head.windows(2).any(|w| w == b".W") {
            out.push_str(".w");
        }
    }
    c.seq(t, &mut pos, out, 0);
    // (LLVM writes comparisons with zero `#0`.)
    if i.encoding.name.starts_with("VCMP") && out[before..].ends_with("#0.0") {
        out.truncate(out.len() - 2);
    }
}

/// Whether a T16 encoding has an S form, preferred outside an IT block.
fn sets_flags_outside_it(e: &crate::Encoding) -> bool {
    let base = crate::mnemonic_of(e.asm);
    e.aliases.iter().any(|a| {
        let m = crate::mnemonic_of(a);
        m.len() == base.len() + 1 && m.starts_with(base) && m.ends_with('S')
    })
}

/// The T32 encodings LLVM writes with `.w` (those with a 16-bit form of
/// the same operation).
fn llvm_wide(name: &str) -> bool {
    matches!(
        name,
        "ADCS_r_T2"
            | "ADCS_r_T2_RRX"
            | "ADC_r_T2"
            | "ADC_r_T2_RRX"
            | "ADDS_SP_i_T3"
            | "ADDS_SP_r_T3"
            | "ADDS_SP_r_T3_RRX"
            | "ADD_SP_r_T3_RRX"
            | "ADDS_i_T3"
            | "ADDS_r_T3"
            | "ADDS_r_T3_RRX"
            | "ADD_SP_i_T3"
            | "ADD_SP_r_T3"
            | "ADD_i_T3"
            | "ADD_r_T3"
            | "ADD_r_T3_RRX"
            | "ADR_T2"
            | "ADR_T3"
            | "ANDS_r_T2"
            | "ANDS_r_T2_RRX"
            | "AND_r_T2"
            | "AND_r_T2_RRX"
            | "BICS_r_T2"
            | "BICS_r_T2_RRX"
            | "BIC_r_T2"
            | "BIC_r_T2_RRX"
            | "B_T3"
            | "B_T4"
            | "CMN_i_T1"
            | "CMN_r_T2"
            | "CMN_r_T2_RRX"
            | "CMP_i_T2"
            | "CMP_r_T3"
            | "CMP_r_T3_RRX"
            | "EORS_r_T2"
            | "EORS_r_T2_RRX"
            | "EOR_r_T2"
            | "EOR_r_T2_RRX"
            | "HVC_T1"
            | "LDM_T2"
            | "LDRB_i_T2"
            | "LDRB_l_T1"
            | "LDRB_r_T2"
            | "LDRH_i_T2"
            | "LDRH_l_T1"
            | "LDRH_r_T2"
            | "LDRSB_i_T1"
            | "LDRSB_l_T1"
            | "LDRSB_r_T2"
            | "LDRSH_i_T1"
            | "LDRSH_l_T1"
            | "LDRSH_r_T2"
            | "LDR_i_T3"
            | "LDR_l_T2"
            | "LDR_r_T2"
            | "MOVS_i_T2"
            | "MOVS_r_T3"
            | "MOVS_rr_T2"
            | "MOV_i_T2"
            | "MOV_r_T3"
            | "MOV_rr_T2"
            | "MVNS_r_T2"
            | "MVNS_r_T2_RRX"
            | "MVN_r_T2"
            | "MVN_r_T2_RRX"
            | "ORRS_r_T2"
            | "ORRS_r_T2_RRX"
            | "ORR_r_T2"
            | "ORR_r_T2_RRX"
            | "REV_T2"
            | "REV16_T2"
            | "REVSH_T2"
            | "RSBS_i_T2"
            | "RSB_i_T2"
            | "SBCS_r_T2"
            | "SBCS_r_T2_RRX"
            | "SBC_r_T2"
            | "SBC_r_T2_RRX"
            | "STM_T2"
            | "STRB_i_T2"
            | "STRB_r_T2"
            | "STRH_i_T2"
            | "STRH_r_T2"
            | "STR_i_T3"
            | "STR_r_T2"
            | "SUBS_SP_i_T2"
            | "SUBS_SP_r_T1"
            | "SUBS_SP_r_T1_RRX"
            | "SUBS_i_T3"
            | "SUBS_r_T2"
            | "SUBS_r_T2_RRX"
            | "SUB_SP_i_T2"
            | "SUB_SP_r_T1"
            | "SUB_SP_r_T1_RRX"
            | "SUB_i_T3"
            | "SUB_r_T2"
            | "SUB_r_T2_RRX"
            | "SXTB_T2"
            | "SXTH_T2"
            | "UXTB_T2"
            | "UXTH_T2"
            | "TEQ_i_T1"
            | "TEQ_r_T1"
            | "TST_i_T1"
            | "TST_r_T2"
            | "TST_r_T2_RRX"
            | "UDF_T2"
            | "NOP_T2"
            | "YIELD_T2"
            | "WFE_T2"
            | "WFI_T2"
            | "SEV_T2"
            | "SEVL_T2"
    )
}

/// LLVM's mnemonic for an encoding, where it isn't the template's.
fn llvm_mnemonic(name: &str) -> Option<&'static str> {
    Some(match name {
        "MOV_i_A2" | "MOV_i_T3" => "movw",
        "VLDM_A1" | "VLDM_A2" | "VLDM_T1" | "VLDM_T2" => "vldmia",
        "VSTM_A1" | "VSTM_A2" | "VSTM_T1" | "VSTM_T2" => "vstmia",
        "ADD_i_T4" | "ADD_SP_i_T4" => "addw",
        "SUB_i_T4" | "SUB_SP_i_T3" => "subw",
        _ => return None,
    })
}

/// The rotation LLVM would encode `imm` with (`getSOImmValRotate`): the
/// smallest even right rotation that leaves it in the low 8 bits.
fn canonical_rotation(imm: u32) -> u32 {
    if imm & !255 == 0 {
        return 0;
    }
    let tz = imm.trailing_zeros() & !1;
    if imm.rotate_right(tz) & !255 == 0 {
        return (32 - tz) & 31;
    }
    // (Wrapping around: the bits at the bottom and at the top.)
    if imm & 63 != 0 {
        let tz2 = (imm & !63).trailing_zeros() & !1;
        if imm.rotate_right(tz2) & !255 == 0 {
            return (32 - tz2) & 31;
        }
    }
    (32 - tz) & 31
}

/// An A32 modified immediate, as LLVM writes it: the value (signed) if
/// `imm12`'s rotation is the one it would choose for it, else its parts
/// (`#bits, #rotation`).
fn write_mod_imm(imm12: u32, out: &mut String) {
    write_mod_imm_as(imm12, true, out);
}

/// [`write_mod_imm`], the value signed or not (MSR's).
fn write_mod_imm_as(imm12: u32, signed: bool, out: &mut String) {
    let imm = a32_expand_imm(imm12);
    let rot = (imm12 >> 8 & 15) * 2;
    if canonical_rotation(imm) == rot {
        if signed {
            let _ = write!(out, "{}", imm as i32);
        } else {
            let _ = write!(out, "{imm}");
        }
    } else {
        let _ = write!(out, "{}, #{rot}", imm12 & 0xff);
    }
}

/// The names of the condition codes.
const CONDS: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "",
];

/// The name of general-purpose register `n`.
fn reg(n: u32) -> &'static str {
    const NAMES: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
        "lr", "pc",
    ];
    NAMES[(n & 15) as usize]
}

fn bits(w: u32, hi: u8, lo: u8) -> u32 {
    let width = u32::from(hi.saturating_sub(lo)) + 1;
    let v = w >> lo;
    if width >= 32 {
        v
    } else {
        v & ((1 << width) - 1)
    }
}

fn sign_extend(v: u32, width: u32) -> i64 {
    if width == 0 || width >= 64 {
        return i64::from(v);
    }
    let shift = 64 - width;
    (i64::from(v) << shift) >> shift
}

/// A32's modified immediate: `imm8` rotated right by twice `rot`.
pub fn a32_expand_imm(imm12: u32) -> u32 {
    (imm12 & 0xff).rotate_right(2 * (imm12 >> 8 & 15))
}

/// T32's modified immediate (`i:imm3:imm8`).
pub fn t32_expand_imm(imm12: u32) -> u32 {
    let imm8 = imm12 & 0xff;
    if imm12 >> 10 == 0 {
        match imm12 >> 8 & 3 {
            0 => imm8,
            1 => imm8 << 16 | imm8,
            2 => imm8 << 24 | imm8 << 8,
            _ => imm8 << 24 | imm8 << 16 | imm8 << 8 | imm8,
        }
    } else {
        (0x80 | imm12 & 0x7f).rotate_right(imm12 >> 7 & 31)
    }
}

struct Ctx<'a> {
    i: &'a Instruction,
    addr: u64,
    targets: Targets,
    /// The condition from an IT block.
    it: Option<u32>,
}

impl Ctx<'_> {
    fn name(&self) -> &'static str {
        self.i.encoding.name
    }

    /// The condition suffix (`eq`; none for always).
    fn cond_suffix(&self, out: &mut String) {
        let c = self.value("<c>").map(|v| v.0).or(self.it);
        if let Some(c) = c
            && c < 14
        {
            out.push_str(CONDS[c as usize]);
        }
    }

    /// The instructions LLVM writes as aliases of their own: PUSH and
    /// POP for stores and loads of several registers at SP with
    /// writeback, shifts for MOV of a shifted register, SUB from the PC
    /// for A32's ADR that subtracts, and literal loads as offsets from
    /// the PC. Whether it wrote one.
    fn alias(&self, out: &mut String) -> bool {
        let n = self.name();
        let f = |x: &str| self.field(x);
        let wide = if self.i.thumb && self.i.size == 4 {
            ".w"
        } else {
            ""
        };
        match n {
            "STMDB_A1" | "STMDB_T1" | "LDM_A1" | "LDM_T2"
                if f("Rn") == Some(13) && f("W") == Some(1) =>
            {
                out.push_str(if n.starts_with("STM") { "push" } else { "pop" });
                self.cond_suffix(out);
                out.push_str(wide);
                out.push(' ');
                self.register_list(out);
                true
            }
            "MOV_r_A1" | "MOVS_r_A1" | "MOV_r_T3" | "MOVS_r_T3" => {
                let t = f("stype").unwrap_or(0);
                let amount = self.amount().unwrap_or(0);
                if t == 0 && amount == 0 {
                    return false;
                }
                let names = ["lsl", "lsr", "asr", "ror"];
                let rrx = t == 3 && amount == 0;
                out.push_str(if rrx { "rrx" } else { names[t as usize] });
                if n.starts_with("MOVS") {
                    out.push('s');
                }
                self.cond_suffix(out);
                out.push_str(wide);
                let rd = reg(f("Rd").unwrap_or(0));
                let rm = reg(f("Rm").unwrap_or(0));
                if rrx {
                    let _ = write!(out, " {rd}, {rm}");
                } else {
                    let amount = if amount == 0 { 32 } else { amount };
                    let _ = write!(out, " {rd}, {rm}, #{amount}");
                }
                true
            }
            "MOV_rr_A1" | "MOVS_rr_A1" | "MOV_rr_T2" | "MOVS_rr_T2" => {
                let names = ["lsl", "lsr", "asr", "ror"];
                out.push_str(names[f("stype").unwrap_or(0) as usize & 3]);
                if n.starts_with("MOVS") {
                    out.push('s');
                }
                self.cond_suffix(out);
                out.push_str(wide);
                let _ = write!(
                    out,
                    " {}, {}, {}",
                    reg(f("Rd").unwrap_or(0)),
                    reg(f("Rm").unwrap_or(0)),
                    reg(f("Rs").unwrap_or(0))
                );
                true
            }
            "IT_T1" => {
                let first = f("firstcond").unwrap_or(0);
                let mask = f("mask").unwrap_or(0);
                out.push_str("it");
                let n = 4 - mask.trailing_zeros().min(4);
                for k in 1..n {
                    let bit = mask >> (4 - k) & 1;
                    out.push(if bit == first & 1 { 't' } else { 'e' });
                }
                out.push(' ');
                out.push_str(if first == 14 {
                    "al"
                } else {
                    CONDS[first as usize & 15]
                });
                true
            }
            "UDF_T1" if f("imm8") == Some(0xfe) => {
                out.push_str("trap");
                true
            }
            "UDF_T1" if f("imm8") == Some(0xf9) => {
                out.push_str("__brkdiv0");
                true
            }
            "VEXT_A1_D" | "VEXT_A1_Q" | "VEXT_T1_D" | "VEXT_T1_Q" => {
                let (size, scale) = self.vext_size();
                let q = n.ends_with('Q');
                let r = |hi: &str, lo: &str| {
                    let v = f(hi).unwrap_or(0) << 4 | f(lo).unwrap_or(0);
                    if q { (b'q', v >> 1) } else { (b'd', v) }
                };
                let (k, d) = r("D", "Vd");
                let (_, nn) = r("N", "Vn");
                let (_, m) = r("M", "Vm");
                let k = char::from(k);
                let _ = write!(
                    out,
                    "vext.{size} {k}{d}, {k}{nn}, {k}{m}, #{}",
                    f("imm4").unwrap_or(0) / scale
                );
                true
            }
            "VSHLL_A2" | "VSHLL_T2" => {
                let esize = 8 << f("size").unwrap_or(0);
                let _ = write!(
                    out,
                    "vshll.i{esize} q{}, d{}, #{esize}",
                    (f("D").unwrap_or(0) << 4 | f("Vd").unwrap_or(0)) >> 1,
                    f("M").unwrap_or(0) << 4 | f("Vm").unwrap_or(0)
                );
                true
            }
            "MOV_r_A1_RRX" | "MOVS_r_A1_RRX" | "MOV_r_T3_RRX" | "MOVS_r_T3_RRX" => {
                out.push_str("rrx");
                if n.starts_with("MOVS") {
                    out.push('s');
                }
                self.cond_suffix(out);
                let _ = write!(
                    out,
                    " {}, {}",
                    reg(f("Rd").unwrap_or(0)),
                    reg(f("Rm").unwrap_or(0))
                );
                true
            }
            "MRS_A1_AS" | "MRS_T1_AS" => {
                out.push_str("mrs");
                self.cond_suffix(out);
                let _ = write!(
                    out,
                    " {}, {}",
                    reg(f("Rd").unwrap_or(0)),
                    if f("R") == Some(1) { "spsr" } else { "apsr" }
                );
                true
            }
            "MSR_i_A1_AS" | "MSR_r_A1_AS" | "MSR_r_T1_AS" => {
                out.push_str("msr");
                self.cond_suffix(out);
                out.push(' ');
                let mask = f("mask").unwrap_or(0);
                if f("R") == Some(1) {
                    out.push_str("SPSR_");
                    status_fields(mask, out);
                } else {
                    match mask {
                        8 => out.push_str("APSR_nzcvq"),
                        4 => out.push_str("APSR_g"),
                        12 => out.push_str("APSR_nzcvqg"),
                        _ => {
                            out.push_str("CPSR_");
                            status_fields(mask, out);
                        }
                    }
                }
                if n.starts_with("MSR_i") {
                    out.push_str(", #");
                    write_mod_imm_as(f("imm12").unwrap_or(0), false, out);
                } else {
                    let rn = f("Rn").or_else(|| f("Rm")).unwrap_or(0);
                    let _ = write!(out, ", {}", reg(rn));
                }
                true
            }
            "UDF_A1" if self.i.word == 0xe7ff_defe => {
                out.push_str("trap");
                true
            }
            "MOV_r_T2" => {
                let t = f("op").unwrap_or(0);
                let amount = f("imm5").unwrap_or(0);
                let rd = reg(f("Rd").unwrap_or(0));
                let rm = reg(f("Rm").unwrap_or(0));
                let s = if self.it.is_none() { "s" } else { "" };
                if t == 0 && amount == 0 {
                    let _ = write!(out, "mov{s}");
                    self.cond_suffix(out);
                    let _ = write!(out, " {rd}, {rm}");
                } else {
                    let amount = if amount == 0 { 32 } else { amount };
                    let _ = write!(out, "{}{s}", ["lsl", "lsr", "asr", "ror"][t as usize & 3]);
                    self.cond_suffix(out);
                    let _ = write!(out, " {rd}, {rm}, #{amount}");
                }
                true
            }
            "MOV_rr_T1_LSL" | "MOV_rr_T1_LSR" | "MOV_rr_T1_ASR" | "MOV_rr_T1_ROR" => {
                let op = &n[10..13];
                out.push_str(&op.to_ascii_lowercase());
                if self.it.is_none() {
                    out.push('s');
                }
                self.cond_suffix(out);
                let _ = write!(
                    out,
                    " {}, {}",
                    reg(f("Rdm").unwrap_or(0)),
                    reg(f("Rs").unwrap_or(0))
                );
                true
            }
            "VSTMDB_A1" | "VSTMDB_A2" | "VSTMDB_T1" | "VSTMDB_T2" | "VLDM_A1" | "VLDM_A2"
            | "VLDM_T1" | "VLDM_T2"
                if f("Rn") == Some(13) && f("W") == Some(1) =>
            {
                out.push_str(if n.starts_with("VSTM") {
                    "vpush"
                } else {
                    "vpop"
                });
                self.cond_suffix(out);
                out.push(' ');
                self.vfp_list(out);
                true
            }
            "STM_u_A1_AS" | "LDM_u_A1_AS" | "LDM_e_A1_AS" => {
                out.push_str(if n.starts_with("STM") { "stm" } else { "ldm" });
                out.push_str(match (f("P"), f("U")) {
                    (Some(0), Some(0)) => "da",
                    (Some(1), Some(0)) => "db",
                    (Some(1), Some(1)) => "ib",
                    _ => "",
                });
                self.cond_suffix(out);
                let _ = write!(out, " {}", reg(f("Rn").unwrap_or(0)));
                if f("W") == Some(1) {
                    out.push('!');
                }
                out.push_str(", ");
                let mut mask = f("register_list").unwrap_or(0);
                if n.starts_with("LDM_e") {
                    mask |= 1 << 15;
                }
                list_of(mask, out);
                out.push_str(" ^");
                true
            }
            // (LLVM writes A32's ADR as the ADD or SUB it is.)
            "ADR_A1" | "ADR_A2" => {
                out.push_str(if n == "ADR_A1" { "add" } else { "sub" });
                self.cond_suffix(out);
                let _ = write!(out, " {}, pc, #", reg(f("Rd").unwrap_or(0)));
                write_mod_imm(f("imm12").unwrap_or(0), out);
                true
            }
            _ if !self.i.thumb && n.contains("_l_A") && f("imm12").is_some()
                || n == "LDRD_l_A1"
                || n == "LDRH_l_A1"
                || n == "LDRSB_l_A1"
                || n == "LDRSH_l_A1" =>
            {
                self.literal_a32(out)
            }
            _ if self.i.thumb && (n.starts_with("LDR") && n.contains("_l_T")) => {
                self.literal_t32(out)
            }
            _ if n.starts_with("PLD_l")
                || n.starts_with("PLI_l")
                || n == "PLI_i_T3" && self.has_operand("<label>") =>
            {
                out.push_str(if n.starts_with("PLD") { "pld" } else { "pli" });
                let imm = f("imm12").unwrap_or(0);
                let sign = if f("U") == Some(0) { "-" } else { "" };
                let _ = write!(out, " [pc, #{sign}{imm}]");
                true
            }
            _ if n.starts_with("LDC_l") => {
                out.push_str("ldc");
                if f("D") == Some(1) {
                    out.push('l');
                }
                self.cond_suffix(out);
                let imm = f("imm8").unwrap_or(0) * 4;
                let sign = if f("U") == Some(0) { "-" } else { "" };
                if f("P") == Some(0) {
                    let _ = write!(out, " p14, c5, [pc], #{sign}{imm}");
                } else {
                    let _ = write!(out, " p14, c5, [pc, #{sign}{imm}]");
                    if f("W") == Some(1) {
                        out.push('!');
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// A T32 (or T16) literal load: `ldr r0, [pc, #imm]`.
    fn literal_t32(&self, out: &mut String) -> bool {
        let n = self.name();
        let f = |x: &str| self.field(x);
        out.push_str(&crate::mnemonic_of(self.i.encoding.asm).to_ascii_lowercase());
        if self.i.size == 4 && llvm_wide(n) {
            out.push_str(".w");
        }
        out.push(' ');
        if let Some(rt) = f("Rt") {
            out.push_str(reg(rt));
            out.push_str(", ");
        }
        if n.starts_with("LDRD") {
            out.push_str(reg(f("Rt2").unwrap_or(0)));
            out.push_str(", ");
        }
        let (imm, scale) = match (f("imm12"), f("imm8")) {
            (Some(i), _) => (i, 1),
            (None, Some(i)) => (i, 4),
            _ => (0, 1),
        };
        let sign = if f("U") == Some(0) { "-" } else { "" };
        match (f("P"), f("W")) {
            (Some(0), _) => {
                let _ = write!(out, "[pc], #{sign}{}", imm * scale);
            }
            (_, Some(1)) => {
                let _ = write!(out, "[pc, #{sign}{}]!", imm * scale);
            }
            _ => {
                let _ = write!(out, "[pc, #{sign}{}]", imm * scale);
            }
        }
        true
    }

    /// An A32 load from the PC (a literal, or another form of it with
    /// writeback or post-indexing): as LLVM writes it, `[pc, #imm]`.
    fn literal_a32(&self, out: &mut String) -> bool {
        let n = self.name();
        let f = |x: &str| self.field(x);
        let t = self.i.encoding.asm.as_bytes();
        let end = t
            .iter()
            .position(|b| !b.is_ascii_alphanumeric())
            .unwrap_or(t.len());
        for &b in &t[..end] {
            out.push(char::from(b.to_ascii_lowercase()));
        }
        if n.starts_with("PLD") || n.starts_with("PLI") {
            // (Unconditional.)
        } else {
            self.cond_suffix(out);
        }
        out.push(' ');
        if let Some(rt) = f("Rt") {
            out.push_str(reg(rt));
            out.push_str(", ");
            if n.starts_with("LDRD") {
                out.push_str(reg(rt + 1));
                out.push_str(", ");
            }
        }
        let imm = match (f("imm12"), f("imm4H"), f("imm4L")) {
            (Some(i), _, _) => i,
            (None, Some(h), Some(l)) => h << 4 | l,
            _ => 0,
        };
        let sign = if f("U") == Some(0) { "-" } else { "" };
        let p = f("P").unwrap_or(1);
        let w = f("W").unwrap_or(0);
        if p == 0 {
            let _ = write!(out, "[pc], #{sign}{imm}");
        } else {
            let _ = write!(out, "[pc, #{sign}{imm}]");
            if w == 1 {
                out.push('!');
            }
        }
        true
    }

    /// Field `name`'s value.
    fn field(&self, name: &str) -> Option<u32> {
        self.i
            .encoding
            .fields
            .iter()
            .find(|f| f.0 == name)
            .map(|f| bits(self.i.word, f.1, f.2))
    }

    /// Operand `display`'s fields, concatenated: (value, width).
    fn value(&self, display: &str) -> Option<(u32, u32)> {
        let (_, parts) = self.i.encoding.operands.iter().find(|o| o.0 == display)?;
        let mut v = 0u32;
        let mut width = 0u32;
        for &(hi, lo) in *parts {
            let w = u32::from(hi - lo) + 1;
            v = v.checked_shl(w).unwrap_or(0) | bits(self.i.word, hi, lo);
            width += w;
        }
        Some((v, width))
    }

    /// The text of the template `t` from `pos` to its end (or a closing
    /// brace), into `out`; whether something in it is not its default
    /// (an optional part is shown if so).
    fn seq(&self, t: &[u8], pos: &mut usize, out: &mut String, depth: u32) -> bool {
        let mut shown = false;
        while *pos < t.len() {
            match t[*pos] {
                b'}' => return shown,
                b'%' if t.get(*pos + 1) == Some(&b'{') => {
                    let start = *pos + 2;
                    let end = t[start..]
                        .iter()
                        .position(|&b| b == b'}')
                        .map_or(t.len(), |e| start + e);
                    let id = core::str::from_utf8(&t[start..end]).unwrap_or("");
                    *pos = (end + 1).min(t.len());
                    shown |= self.reference(id, out);
                }
                b'{' if depth < 8 && self.repeated_operand(t, *pos) => {
                    // (Skipped: T16's two-operand form.)
                    let mut level = 0;
                    while *pos < t.len() {
                        match t[*pos] {
                            b'{' => level += 1,
                            b'}' => {
                                level -= 1;
                                if level == 0 {
                                    *pos += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        *pos += 1;
                    }
                }
                b'{' if depth < 8 => {
                    *pos += 1;
                    let mut inner = String::new();
                    let has_ref = t[*pos..].starts_with(b"%{");
                    let inner_shown = self.seq(t, pos, &mut inner, depth + 1);
                    if *pos < t.len() {
                        *pos += 1;
                    }
                    // (An optional space shows unless another optional
                    // part follows it.)
                    let space = inner == " " && !matches!(t.get(*pos), Some(b'{' | b','));
                    if space || inner == "#" {
                        // (Shown, but not something shown.)
                        out.push_str(&inner);
                    } else if inner_shown || (!has_ref && self.literal_shown(&inner)) {
                        out.push_str(&inner);
                        shown = true;
                    }
                }
                b => {
                    out.push(char::from(b.to_ascii_lowercase()));
                    *pos += 1;
                }
            }
        }
        shown
    }

    /// Whether the optional part at `t[at]` (`{%{Rdn}, }`) is an operand
    /// the template repeats right after it, which LLVM leaves out of T16
    /// instructions.
    fn repeated_operand(&self, t: &[u8], at: usize) -> bool {
        let n = self.name();
        let simd_imm = n.starts_with("VORR_i") || n.starts_with("VBIC_i");
        if !(self.i.thumb && self.i.size == 2 || simd_imm) {
            return false;
        }
        let rest = &t[at + 1..];
        let Some(close) = rest.windows(3).position(|w| w == b", }") else {
            return false;
        };
        let inner = &rest[..close];
        if inner.contains(&b'{') && !inner.starts_with(b"%{") {
            return false;
        }
        rest[close + 3..].starts_with(inner)
    }

    /// Whether an optional part of literal text alone is shown.
    fn literal_shown(&self, text: &str) -> bool {
        match text {
            "-" => self.field("U") == Some(0),
            // (T16's LDM writes back unless it loads its base.)
            "!" if self.name() == "LDM_T1" => {
                let rn = self.field("Rn").unwrap_or(0);
                self.field("register_list").unwrap_or(0) >> rn & 1 == 0
            }
            "!" => self.field("W") == Some(1),
            "#" => true,
            "ia" => {
                let n = self.name();
                n.starts_with("RFE") || n.starts_with("SRS")
            }
            _ => false,
        }
    }

    /// Operand rule `id`, into `out`; whether it is other than its
    /// default.
    fn reference(&self, id: &str, out: &mut String) -> bool {
        let Some(r) = rule(id) else {
            return false;
        };
        if let Some(shown) = self.simd_choice(r.display, out) {
            return shown;
        }
        match r.display {
            "<c>" => return self.condition(out),
            "<q>" => return false,
            "<shift>" => return self.shift(r, out),
            "<amount>"
                if self.value("<shift>").is_some()
                    || self.name().contains("ASR")
                    || self.name().starts_with("PKHTB") =>
            {
                return self.shift_amount(out);
            }
            _ => {}
        }
        if r.text.is_none() {
            return self.choice(r, out);
        }
        self.operand(r, out)
    }

    fn condition(&self, out: &mut String) -> bool {
        let Some(c) = self.value("<c>").map(|v| v.0).or(self.it) else {
            return false;
        };
        if c >= 14 {
            return false;
        }
        out.push_str(CONDS[c as usize]);
        true
    }

    /// A shift's type (`stype`), and its amount (`imm5`, or T32's
    /// `imm3:imm2`) when the alternatives write it (`LSL #<n>`): as
    /// DecodeImmShift decodes them (LSR and ASR #0 are #32, ROR #0 is
    /// RRX). LSL #0 is no shift (the default).
    fn shift(&self, r: &Rule, out: &mut String) -> bool {
        let Some((t, _)) = self.value("<shift>") else {
            return false;
        };
        let with_amount = r.alts.iter().any(|a| a.1.contains("%{"));
        let names = ["lsl", "lsr", "asr", "ror"];
        if !with_amount {
            out.push_str(names[(t & 3) as usize]);
            return t != 0 || self.amount() != Some(0);
        }
        let n = self.amount().unwrap_or(0);
        match (t & 3, n) {
            (0, 0) => false,
            (3, 0) => {
                out.push_str("rrx");
                true
            }
            (1 | 2, 0) => {
                let _ = write!(out, "{} #32", names[(t & 3) as usize]);
                true
            }
            (t, n) => {
                let _ = write!(out, "{} #{n}", names[t as usize]);
                true
            }
        }
    }

    /// The shift amount's field value (`imm5`, or `imm3:imm2`).
    fn amount(&self) -> Option<u32> {
        if let Some((v, _)) = self.value("<amount>") {
            return Some(v);
        }
        if let Some(v) = self.field("imm5") {
            return Some(v);
        }
        Some(self.field("imm3")? << 2 | self.field("imm2")?)
    }

    /// A shift amount written apart from its type (`<shift> #<amount>`).
    fn shift_amount(&self, out: &mut String) -> bool {
        let t = self.value("<shift>").map_or(0, |v| v.0 & 3);
        // (A fixed ASR: SSAT's, PKHTB's.)
        let t = if self.name().contains("ASR") || self.name().starts_with("PKHTB") {
            2
        } else {
            t
        };
        let n = self.amount().unwrap_or(0);
        let n = if n == 0 && (t == 1 || t == 2) { 32 } else { n };
        let _ = write!(out, "{n}");
        n != 0
    }

    /// A choice: the alternative named for the operand's value (or the
    /// value's place among them).
    fn choice(&self, r: &Rule, out: &mut String) -> bool {
        let Some((v, width)) = self.value(r.display) else {
            return false;
        };
        let pick = r
            .alts
            .iter()
            .find(|(name, _)| alt_bits(name).is_some_and(|(m, b, w)| w == width && v & m == b))
            .or_else(|| {
                // (Named for fewer bits than the fields have, VQMOVN's
                // `op<0>:size`: the low ones.)
                r.alts.iter().find(|(name, _)| {
                    alt_bits(name).is_some_and(|(m, b, w)| w < width && v & m == b)
                })
            })
            .or_else(|| {
                // Unnamed by bits: by place.
                r.alts
                    .iter()
                    .all(|(name, _)| alt_bits(name).is_none())
                    .then(|| r.alts.get(v as usize))
                    .flatten()
            });
        let Some((_, text)) = pick else {
            return false;
        };
        // (An alternative's text can name rules of its own.)
        let mut pos = 0;
        let mut s = String::new();
        self.seq(text.as_bytes(), &mut pos, &mut s, 1);
        if r.display == "<banked_reg>" && s.starts_with("spsr") {
            s.replace_range(..4, "SPSR");
        }
        out.push_str(&s);
        !s.is_empty()
    }

    /// An operand rule with text (`R%{UInteger}`).
    fn operand(&self, r: &Rule, out: &mut String) -> bool {
        let text = r.text.unwrap_or("");
        let d = r.display;
        if let Some(shown) = self.simd_operand(d, out) {
            return shown;
        }
        match d {
            "<const>" => {
                let Some((v, _)) = self.value(d) else {
                    return false;
                };
                if self.i.thumb {
                    let _ = write!(out, "{}", t32_expand_imm(v));
                    return true;
                }
                write_mod_imm(v, out);
                return true;
            }
            "<iflags>" => {
                let start = out.len();
                for (field, c) in [("A", 'a'), ("I", 'i'), ("F", 'f')] {
                    if self.field(field) == Some(1) {
                        out.push(c);
                    }
                }
                if out.len() == start {
                    out.push_str("none");
                }
                return true;
            }
            "<option>" => {
                let Some((v, _)) = self.value(d) else {
                    return false;
                };
                let _ = write!(out, "{{{v}}}");
                return true;
            }
            "<imm>" if self.name().starts_with("PKHTB") => {
                let v = self.amount().unwrap_or(0);
                let _ = write!(out, "{}", if v == 0 { 32 } else { v });
                return true;
            }
            "<CRn>" | "<CRm>" | "<CRd>" => {
                let Some((v, _)) = self.value(d) else {
                    return false;
                };
                let _ = write!(out, "c{v}");
                return true;
            }
            "<label>" => return self.label(out),
            "<registers>" | "<registers_with_pc>" | "<registers_without_pc>" => {
                return self.register_list(out);
            }
            _ => {}
        }
        // A register: its class's letter and number.
        if let Some(class) = text.strip_suffix("%{UInteger}")
            && !class.is_empty()
            && class.bytes().all(|b| b.is_ascii_uppercase())
        {
            let n = match self.value(d) {
                // (LDRD's second register, when the specification
                // gives it the first's field: the one after it.)
                Some((v, _)) if d == "<Rt2>" && self.same_fields("<Rt2>", "<Rt>") => v + 1,
                Some((v, _)) if d == "<Rdm>" && self.name() == "ADD_SP_r_T1" => {
                    v | self.field("DM").unwrap_or(0) << 3
                }
                Some((v, _)) => v,
                None if d == "<Rt2>" => match self.value("<Rt>") {
                    Some((v, _)) => v + 1,
                    None => return false,
                },
                None => return false,
            };
            match class {
                // (MRC and VMRS to the PC: the flags.)
                "R" if n == 15 && self.name().starts_with("MRC") => out.push_str("apsr_nzcv"),
                "R" if n == 15
                    && self.name().starts_with("VMRS")
                    && self.field("reg") == Some(1) =>
                {
                    out.push_str("APSR_nzcv");
                }
                "R" => out.push_str(reg(n)),
                "Q" => {
                    let _ = write!(out, "q{}", n >> 1);
                }
                other => {
                    for b in other.bytes() {
                        out.push(char::from(b.to_ascii_lowercase()));
                    }
                    let _ = write!(out, "{n}");
                }
            }
            return true;
        }
        if text == "%{UInteger}" || text == "%{SInteger}" {
            let Some((v, _)) = self.value(d) else {
                return false;
            };
            let v = self.immediate(d, v);
            let _ = write!(out, "{v}");
            // (LLVM writes a coprocessor's opc2 even when it is 0.)
            return v != 0 || d == "<opc2>";
        }
        // Other text: as it is.
        let mut pos = 0;
        let mut s = String::new();
        self.seq(text.as_bytes(), &mut pos, &mut s, 1);
        out.push_str(&s);
        !s.is_empty()
    }

    /// A bitfield's lsb: `lsb`, or T32's `imm3:imm2`.
    fn bitfield_lsb(&self) -> u32 {
        match self.value("<lsb>") {
            Some((l, _)) => l,
            None => match (self.field("imm3"), self.field("imm2")) {
                (Some(h), Some(l)) => h << 2 | l,
                _ => self.field("lsb").unwrap_or(0),
            },
        }
    }

    /// Whether two operands are encoded in the same fields.
    fn same_fields(&self, a: &str, b: &str) -> bool {
        let find = |d: &str| {
            self.i
                .encoding
                .operands
                .iter()
                .find(|o| o.0 == d)
                .map(|o| o.1)
        };
        matches!((find(a), find(b)), (Some(x), Some(y)) if x == y)
    }

    /// A number operand, as the encoding defines it.
    fn immediate(&self, display: &str, v: u32) -> i64 {
        let n = self.name();
        let v = i64::from(v);
        // (Fields that hold one less, or the top bit.)
        if display == "<width>" {
            let bitfield_insert = n.starts_with("BFI") || n.starts_with("BFC");
            if self.field("widthm1").is_some() && !bitfield_insert {
                return v + 1;
            }
            if self.field("msb").is_some() {
                // (An lsb past the msb: LLVM takes the msb for it.)
                let lsb = i64::from(self.bitfield_lsb()).min(v);
                return v - lsb + 1;
            }
        }
        if display == "<lsb>" && (n.starts_with("BFI") || n.starts_with("BFC")) {
            let msb = i64::from(self.field("msb").unwrap_or(31));
            return v.min(msb);
        }
        if display == "<imm>" && n.starts_with("SSAT") {
            return v + 1;
        }
        if display == "<imm>" && (n.starts_with("VLDR") || n.starts_with("VSTR")) {
            return if n.ends_with("_H") { v * 2 } else { v * 4 };
        }
        if display == "<imm>" && (n.starts_with("LDC") || n.starts_with("STC")) {
            return v * 4;
        }
        if matches!(
            n,
            "LDR_i_T1"
                | "STR_i_T1"
                | "LDR_i_T2"
                | "STR_i_T2"
                | "ADD_SP_i_T1"
                | "ADD_SP_i_T2"
                | "SUB_SP_i_T1"
                | "STREX_T1"
                | "LDREX_T1"
        ) || n.starts_with("LDRD_i_T1")
            || n.starts_with("STRD_i_T1")
        {
            return v * 4;
        }
        if matches!(n, "LDRH_i_T1" | "STRH_i_T1") {
            return v * 2;
        }
        v
    }

    /// A branch's offset from the PC: its fields, as each encoding
    /// arranges them.
    fn label_offset(&self) -> Option<i64> {
        let f = |n: &str| self.field(n).unwrap_or(0);
        let s = f("S");
        let i1 = !(f("J1") ^ s) & 1;
        let i2 = !(f("J2") ^ s) & 1;
        Some(match self.name() {
            "BL_i_T1" | "B_T4" => sign_extend(
                s << 24 | i1 << 23 | i2 << 22 | f("imm10") << 12 | f("imm11") << 1,
                25,
            ),
            "BL_i_T2" => sign_extend(
                s << 24 | i1 << 23 | i2 << 22 | f("imm10H") << 12 | f("imm10L") << 2,
                25,
            ),
            "B_T3" => sign_extend(
                s << 20 | f("J2") << 19 | f("J1") << 18 | f("imm6") << 12 | f("imm11") << 1,
                21,
            ),
            "B_T1" => sign_extend(f("imm8") << 1, 9),
            "B_T2" => sign_extend(f("imm11") << 1, 12),
            "CBZ_T1" | "CBNZ_T1" => i64::from(f("i") << 6 | f("imm5") << 1),
            "B_A1" | "BL_i_A1" => sign_extend(f("imm24") << 2, 26),
            "BL_i_A2" => sign_extend(f("imm24") << 2 | f("H") << 1, 26),
            _ => {
                let (v, width) = self.value("<label>")?;
                let _ = width;
                let v = i64::from(v);
                match self.field("U") {
                    Some(0) => -v,
                    _ => v,
                }
            }
        })
    }

    /// A branch or literal target.
    fn label(&self, out: &mut String) -> bool {
        let Some(offset) = self.label_offset() else {
            return false;
        };
        // (LLVM writes ADR's offset, not where it leads.)
        if self.name().starts_with("ADR") {
            let scale = if self.name() == "ADR_T1" { 4 } else { 1 };
            // (ADR.W's T2 subtracts.)
            let sign = if self.name() == "ADR_T2" { -1 } else { 1 };
            let _ = write!(out, "#{}", offset * scale * sign);
            return true;
        }
        match self.targets {
            Targets::Offsets => {
                let _ = write!(out, "#{offset}");
            }
            Targets::Addresses => {
                let pc = self.addr.wrapping_add(if self.i.thumb { 4 } else { 8 });
                // (BLX from T32 lands on a word.)
                let pc = if self.name() == "BL_i_T2" {
                    pc & !3
                } else {
                    pc
                };
                let _ = write!(out, "{:#x}", pc.wrapping_add_signed(offset) & 0xffff_ffff);
            }
        }
        true
    }

    /// A list of general-purpose registers: `register_list`'s bits, with
    /// `M` (LR) and `P` (PC).
    fn register_list(&self, out: &mut String) -> bool {
        let mut mask = self.field("register_list").unwrap_or(0);
        // (T32's lists have LR and PC apart; A32's, all 16.)
        if self.i.thumb {
            let n = self.name();
            if self.field("M") == Some(1) && !n.starts_with("POP") {
                mask |= 1 << 14;
            }
            if self.field("P") == Some(1) && !n.starts_with("PUSH") {
                mask |= 1 << 15;
            }
        }
        list_of(mask, out);
        true
    }
}

/// The status register fields a mask names (`fsxc`: bits 3 to 0).
fn status_fields(mask: u32, out: &mut String) {
    for (bit, c) in [(8, 'f'), (4, 's'), (2, 'x'), (1, 'c')] {
        if mask & bit != 0 {
            out.push(c);
        }
    }
}

/// A list of general-purpose registers, by bit (`{r4, r5, lr}`).
fn list_of(mask: u32, out: &mut String) {
    out.push('{');
    let mut first = true;
    for n in 0..16 {
        if mask & 1 << n != 0 {
            if !first {
                out.push_str(", ");
            }
            out.push_str(reg(n));
            first = false;
        }
    }
    out.push('}');
}

impl Ctx<'_> {
    /// Whether this is an Advanced SIMD shift by an immediate (its
    /// element size in `L:imm6`).
    fn is_simd_shift(&self) -> bool {
        self.field("imm6").is_some() && self.field("imm3H").is_some()
    }

    /// An Advanced SIMD shift's element size: 64 if `L`, else by
    /// `imm6`'s top set bit (8, 16, or 32).
    fn shift_esize(&self) -> u32 {
        if self.field("L") == Some(1) {
            return 64;
        }
        let imm6 = self.field("imm6").unwrap_or(0);
        if imm6 >> 5 != 0 {
            32
        } else if imm6 >> 4 != 0 {
            16
        } else {
            8
        }
    }

    /// Whether the shift is to the right (its amount `2 * esize - imm6`)
    /// rather than to the left (`imm6 - esize`).
    fn shift_right(&self) -> bool {
        let m = crate::mnemonic_of(self.i.encoding.asm);
        matches!(m, "VSHR" | "VSRA" | "VRSHR" | "VRSRA" | "VSRI")
            || m.ends_with("SHRN")
            || m.ends_with("SHRUN")
    }

    /// Whether the shift narrows (its size the source's: twice esize).
    fn shift_narrows(&self) -> bool {
        let m = crate::mnemonic_of(self.i.encoding.asm);
        m.ends_with("SHRN") || m.ends_with("SHRUN")
    }

    /// Advanced SIMD and floating-point operands with a meaning of their
    /// own (sizes and amounts of shifts, scalars, register lists,
    /// expanded immediates): `Some(shown)`, or `None` if `d` isn't one.
    fn simd_operand(&self, d: &str, out: &mut String) -> Option<bool> {
        let n = self.name();
        let f = |x: &str| self.field(x).unwrap_or(0);
        match d {
            "<imm>" if self.is_simd_shift() => {
                let esize = self.shift_esize();
                let imm6 = f("imm6");
                let imm6 = if esize == 64 { imm6 + 64 } else { imm6 };
                let amount = if self.shift_right() {
                    2 * esize - imm6
                } else {
                    imm6 - esize
                };
                let _ = write!(out, "{amount}");
                Some(true)
            }
            "<fbits>" if self.is_simd_shift() => {
                let _ = write!(out, "{}", 64 - f("imm6"));
                Some(true)
            }
            "<fbits>" if self.field("sx").is_some() => {
                let size = if f("sx") == 1 { 32 } else { 16 };
                let _ = write!(out, "{}", size - i64::from(f("imm4") << 1 | f("i")));
                Some(true)
            }
            // A scalar written as a register and an index.
            "<Dm>" | "<Sm>" if self.has_operand("<index>") => {
                let (reg, _) = self.scalar(d)?;
                let _ = write!(out, "{}{reg}", if d == "<Sm>" { 's' } else { 'd' });
                Some(true)
            }
            "<index>" if self.has_operand("<Dm>") || self.has_operand("<Sm>") => {
                let (_, index) = self.scalar(d)?;
                let _ = write!(out, "{index}");
                Some(true)
            }
            "<Qd>" | "<Qn>" | "<Qm>" => {
                let (hi, lo) = match d {
                    "<Qd>" => ("D", "Vd"),
                    "<Qn>" => ("N", "Vn"),
                    _ => ("M", "Vm"),
                };
                let _ = write!(out, "q{}", (f(hi) << 4 | f(lo)) >> 1);
                Some(true)
            }
            "<Sm1>" => {
                let _ = write!(out, "s{}", (f("Vm") << 1 | f("M")) + 1);
                Some(true)
            }
            "<Sd1>" => {
                let _ = write!(out, "s{}", (f("Vd") << 1 | f("D")) + 1);
                Some(true)
            }
            "<dreglist>" | "<sreglist>" => {
                self.vfp_list(out);
                Some(true)
            }
            "<registers>" | "<list>" if n.starts_with("VLD") || n.starts_with("VST") => {
                self.element_list(out);
                Some(true)
            }
            "<registers>" | "<list>" if n.starts_with("VTB") => {
                let first = f("N") << 4 | f("Vn");
                let count = f("len") + 1;
                out.push('{');
                for k in 0..count {
                    if k > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "d{}", (first + k) & 31);
                }
                out.push('}');
                Some(true)
            }
            "<align>" if n.starts_with("VLD") || n.starts_with("VST") => {
                let a = self.alignment();
                if a == 0 {
                    return Some(false);
                }
                let _ = write!(out, "{a}");
                Some(true)
            }
            "<Dm[x]>" | "<Dn[x]>" | "<Dd[x]>" => {
                let (reg, index) = self.scalar(d)?;
                let _ = write!(out, "d{reg}[{index}]");
                Some(true)
            }
            "<imm>" if n.starts_with("VEXT") => {
                let (_, scale) = self.vext_size();
                let _ = write!(out, "{}", f("imm4") / scale);
                Some(true)
            }
            "<imm>" if self.field("cmode").is_some() => {
                self.simd_immediate(out);
                Some(true)
            }
            "<imm>" if n.starts_with("VMOV_i_A2") || n.starts_with("VMOV_i_T2") => {
                let imm8 = f("imm4H") << 4 | f("imm4L");
                write_vfp_imm(imm8, out);
                Some(true)
            }
            "<label>" if n.starts_with("VLDR") || n.starts_with("VSTR") => {
                let scale = if n.ends_with("_H") { 2 } else { 4 };
                let sign = if f("U") == 0 { "-" } else { "" };
                if f("imm8") == 0 && sign.is_empty() {
                    out.push_str("[pc]");
                } else {
                    let _ = write!(out, "[pc, #{sign}{}]", f("imm8") * scale);
                }
                Some(true)
            }
            _ => None,
        }
    }

    /// Advanced SIMD choices whose value the encoding gives otherwise
    /// than in their fields (sizes of shifts, VEXT, scalars).
    fn simd_choice(&self, d: &str, out: &mut String) -> Option<bool> {
        let n = self.name();
        let f = |x: &str| self.field(x).unwrap_or(0);
        match d {
            "<size>" if self.is_simd_shift() => {
                let esize = self.shift_esize();
                let size = if self.shift_narrows() {
                    esize * 2
                } else {
                    esize
                };
                let _ = write!(out, "{size}");
                Some(true)
            }
            "<size>" if n.starts_with("VEXT") => {
                let _ = write!(out, "{}", self.vext_size().0);
                Some(true)
            }
            "<size>" if n.starts_with("VDUP_s") => {
                let imm4 = f("imm4");
                let size = if imm4 & 1 != 0 {
                    8
                } else if imm4 & 2 != 0 {
                    16
                } else {
                    32
                };
                let _ = write!(out, "{size}");
                Some(true)
            }
            "<size>" if n.starts_with("VMOV_rs") => {
                let (size, _) = scalar_move(f("opc1"), f("opc2"));
                let _ = write!(out, "{size}");
                Some(true)
            }
            "<type>" if self.is_simd_shift() => {
                let m = crate::mnemonic_of(self.i.encoding.asm);
                let signed = f("U") == 0 || m == "VQSHLU" || m == "VQSHRUN" || m == "VQRSHRUN";
                out.push(if signed { 's' } else { 'u' });
                Some(true)
            }
            "<size>" if n.starts_with("VDUP_r") => {
                let size = match f("B") << 1 | f("E") {
                    0 => 32,
                    1 => 16,
                    _ => 8,
                };
                let _ = write!(out, "{size}");
                Some(true)
            }
            "<spec_reg>" if n.starts_with("VMSR") || n.starts_with("VMRS") => {
                out.push_str(match f("reg") {
                    0 => "fpsid",
                    1 => "fpscr",
                    5 => "mvfr2",
                    6 => "mvfr1",
                    7 => "mvfr0",
                    8 => "fpexc",
                    9 => "fpinst",
                    10 => "fpinst2",
                    _ => return None,
                });
                Some(true)
            }
            "<dt>" if n.starts_with("VMOV_sr") => {
                let (size, _) = scalar_move(f("opc1"), f("opc2"));
                match (size, f("U")) {
                    (32, _) => out.push_str("32"),
                    (s, 0) => {
                        let _ = write!(out, "s{s}");
                    }
                    (s, _) => {
                        let _ = write!(out, "u{s}");
                    }
                }
                Some(true)
            }
            _ => None,
        }
    }

    /// Whether the encoding has the operand `display`.
    fn has_operand(&self, display: &str) -> bool {
        self.i.encoding.operands.iter().any(|o| o.0 == display)
    }

    /// VEXT's element size (the largest that divides its byte offset, as
    /// LLVM decodes it) and the offset's scale.
    fn vext_size(&self) -> (u32, u32) {
        let imm4 = self.field("imm4").unwrap_or(0);
        let q = self.field("Q") == Some(1);
        if q && imm4.is_multiple_of(8) {
            (64, 8)
        } else if imm4.is_multiple_of(4) {
            (32, 4)
        } else if imm4.is_multiple_of(2) {
            (16, 2)
        } else {
            (8, 1)
        }
    }

    /// A scalar: its D register and index.
    fn scalar(&self, d: &str) -> Option<(u32, u32)> {
        let n = self.name();
        let f = |x: &str| self.field(x).unwrap_or(0);
        if n.starts_with("VMOV_sr") || n.starts_with("VMOV_rs") {
            let (_, index) = scalar_move(f("opc1"), f("opc2"));
            let reg = if n.starts_with("VMOV_sr") {
                f("N") << 4 | f("Vn")
            } else {
                f("D") << 4 | f("Vd")
            };
            return Some((reg, index));
        }
        if n.starts_with("VDUP_s") {
            let imm4 = f("imm4");
            let index = if imm4 & 1 != 0 {
                imm4 >> 1
            } else if imm4 & 2 != 0 {
                imm4 >> 2
            } else {
                imm4 >> 3
            };
            return Some((f("M") << 4 | f("Vm"), index));
        }
        // The by-element forms: 16-bit elements in D0-D7, the index in
        // M:Vm<3>; 32-bit ones in D0-D15, the index M. (VFMAL's: in
        // S0-S15, Vm<2:0>:M, the index Vm<3>; or for Q, as 16-bit.)
        let _ = d;
        let vm = f("Vm");
        let m = f("M");
        if n.starts_with("VFMA_bfs") {
            return Some((vm & 7, m << 1 | vm >> 3));
        }
        if n.starts_with("VFMAL") || n.starts_with("VFMSL") {
            return Some(if f("Q") == 0 {
                ((vm & 7) << 1 | m, vm >> 3)
            } else {
                (vm & 7, m << 1 | vm >> 3)
            });
        }
        if f("size") == 1 {
            Some((vm & 7, m << 1 | vm >> 3))
        } else {
            Some((vm, m))
        }
    }

    /// The floating-point register list of VLDM, VSTM, VPUSH, VPOP (and
    /// FLDMX, FSTMX): D registers (`size` 11), or S registers; as many as
    /// `imm8` says, to the last register at most.
    fn vfp_list(&self, out: &mut String) {
        let f = |x: &str| self.field(x).unwrap_or(0);
        let imm8 = f("imm8");
        out.push('{');
        if f("size") == 3 {
            let first = f("D") << 4 | f("Vd");
            let x = self.name().starts_with('F');
            let count = (imm8 / 2).max(1);
            let _ = x;
            let count = count.min(32u32.saturating_sub(first));
            for k in 0..count {
                if k > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "d{}", first + k);
            }
        } else {
            let first = f("Vd") << 1 | f("D");
            let count = imm8.max(1).min(32u32.saturating_sub(first));
            for k in 0..count {
                if k > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "s{}", first + k);
            }
        }
        out.push('}');
    }

    /// The element structure loads' and stores' list: of whole registers
    /// (`_m_`), one lane (`_1_`), or all lanes (`_a_`).
    fn element_list(&self, out: &mut String) {
        let n = self.name();
        let f = |x: &str| self.field(x).unwrap_or(0);
        let first = f("D") << 4 | f("Vd");
        let structs = n.as_bytes().get(3).map_or(1, |b| u32::from(b - b'0'));
        let (count, inc, lane): (u32, u32, Option<Option<u32>>) = if n.contains("_m_") {
            let (count, inc) = match f("itype") {
                0b0111 => (1, 1),
                0b1010 => (2, 1),
                0b0110 => (3, 1),
                0b0010 => (4, 1),
                0b1000 => (2, 1),
                0b1001 => (2, 2),
                0b0011 => (4, 1),
                0b0100 => (3, 1),
                0b0101 => (3, 2),
                0b0000 => (4, 1),
                0b0001 => (4, 2),
                _ => (1, 1),
            };
            (count, inc, None)
        } else if n.contains("_1_") {
            let size = f("size");
            let ia = f("index_align");
            let (index, inc) = match size {
                0 => (ia >> 1, 1),
                1 => (ia >> 2, if structs > 1 { (ia >> 1 & 1) + 1 } else { 1 }),
                _ => (ia >> 3, if structs > 1 { (ia >> 2 & 1) + 1 } else { 1 }),
            };
            (structs, inc, Some(Some(index)))
        } else {
            let t = f("T");
            let (count, inc) = if structs == 1 {
                (t + 1, 1)
            } else {
                (structs, t + 1)
            };
            (count, inc, Some(None))
        };
        out.push('{');
        for k in 0..count {
            if k > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "d{}", (first + k * inc) & 31);
            match lane {
                Some(Some(i)) => {
                    let _ = write!(out, "[{i}]");
                }
                Some(None) => out.push_str("[]"),
                None => {}
            }
        }
        out.push('}');
    }

    /// An element structure load's or store's alignment, in bits (0 for
    /// none).
    fn alignment(&self) -> u32 {
        let n = self.name();
        let f = |x: &str| self.field(x).unwrap_or(0);
        let structs = n.as_bytes().get(3).map_or(1, |b| u32::from(b - b'0'));
        if n.contains("_m_") {
            return match f("align") {
                0 => 0,
                a => 32 << a,
            };
        }
        if n.contains("_1_") {
            let size = f("size");
            let ia = f("index_align");
            return match (structs, size) {
                (1, 1) if ia & 1 != 0 => 16,
                (1, 2) if ia & 3 == 3 => 32,
                (2, 0) if ia & 1 != 0 => 16,
                (2, 1) if ia & 1 != 0 => 32,
                (2, 2) if ia & 1 != 0 => 64,
                (4, 0) if ia & 1 != 0 => 32,
                (4, 1) if ia & 1 != 0 => 64,
                (4, 2) if ia & 3 != 0 => 64 << (ia & 3) >> 1,
                _ => 0,
            };
        }
        // All lanes.
        if f("a") == 0 {
            return 0;
        }
        let esize = 8 << f("size");
        match structs {
            1 => esize,
            2 => 2 * esize,
            4 if f("size") == 3 => 128,
            4 => (4 * esize).min(64),
            _ => 0,
        }
    }

    /// An Advanced SIMD modified immediate (VMOV, VMVN, VORR, VBIC), as
    /// LLVM writes it: the element's value in hexadecimal, or a float.
    fn simd_immediate(&self, out: &mut String) {
        let f = |x: &str| self.field(x).unwrap_or(0);
        let imm8 = f("i") << 7 | f("imm3") << 4 | f("imm4");
        let cmode = f("cmode");
        let op = f("op");
        let imm8_64 = u64::from(imm8);
        let value: u64 = match cmode >> 1 {
            0 => imm8_64,
            1 => imm8_64 << 8,
            2 => imm8_64 << 16,
            3 => imm8_64 << 24,
            4 => imm8_64,
            5 => imm8_64 << 8,
            6 if cmode & 1 == 0 => imm8_64 << 8 | 0xff,
            6 => imm8_64 << 16 | 0xffff,
            _ => match (cmode & 1, op) {
                (0, 0) => imm8_64,
                (0, _) => {
                    let mut v = 0u64;
                    for b in 0..8 {
                        if imm8 >> b & 1 != 0 {
                            v |= 0xff << (8 * b);
                        }
                    }
                    v
                }
                _ => {
                    write_vfp_imm(imm8, out);
                    return;
                }
            },
        };
        let _ = write!(out, "{value:#x}");
    }
}

/// The size and index of VMOV between a general-purpose register and a
/// scalar, from `opc1:opc2`.
fn scalar_move(opc1: u32, opc2: u32) -> (u32, u32) {
    if opc1 & 2 != 0 {
        (8, (opc1 & 1) << 2 | opc2)
    } else if opc2 & 1 != 0 {
        (16, (opc1 & 1) << 1 | opc2 >> 1)
    } else {
        (32, opc1 & 1)
    }
}

/// A floating-point immediate (VFPExpandImm of `imm8`), as LLVM writes
/// it: `%e` (`-2.250000e+00`). Its value is `±(16 + imm8<3:0>) / 16 *
/// 2^e`, with `e` from -3 to 4: exactly a few decimal digits.
fn write_vfp_imm(imm8: u32, out: &mut String) {
    let negative = imm8 & 0x80 != 0;
    let exp = ((imm8 >> 4 & 7) ^ 4) as i32 - 3;
    // The value times 2^7, an integer: (16 + frac) * 2^(exp + 3).
    let scaled = (16 + u64::from(imm8 & 15)) << (exp + 3) as u32;
    // In decimal: scaled / 128, to 7 digits after the point.
    let micro = scaled * 10_000_000 / 128;
    // As d.dddddd e±xx.
    let mut digits = micro;
    let mut e10 = -7i32;
    while digits >= 10_000_000 {
        // (Exact: the value has at most 7 decimal digits after the point.)
        digits /= 10;
        e10 += 1;
    }
    while digits < 1_000_000 {
        digits *= 10;
        e10 -= 1;
    }
    let e10 = e10 + 6;
    if negative {
        out.push('-');
    }
    let _ = write!(
        out,
        "{}.{:06}e{}{:02}",
        digits / 1_000_000,
        digits % 1_000_000,
        if e10 < 0 { '-' } else { '+' },
        e10.unsigned_abs()
    );
}

/// The field values a choice's alternative is named for
/// (`dt_0_01_S16`: 0, 01; `dt_110x_I32`: 110 and any bit), concatenated:
/// (mask, value, width). The last part of the name is the text, not
/// bits (`rotate_00_0`).
fn alt_bits(name: &str) -> Option<(u32, u32, u32)> {
    // (Without a `__2` suffix, and the text.)
    let name = match name.rfind("__") {
        Some(i) if name[i + 2..].bytes().all(|b| b.is_ascii_digit()) => &name[..i],
        _ => name,
    };
    let (body, _) = name.rsplit_once('_')?;
    let (mut m, mut v, mut width) = (0u32, 0u32, 0u32);
    let mut any = false;
    for part in body.split('_') {
        if !part.is_empty() && part.bytes().all(|b| matches!(b, b'0' | b'1' | b'x')) {
            for b in part.bytes() {
                m <<= 1;
                v <<= 1;
                if b != b'x' {
                    m |= 1;
                    v |= u32::from(b - b'0');
                }
                width += 1;
            }
            any = true;
        }
    }
    any.then_some((m, v, width))
}

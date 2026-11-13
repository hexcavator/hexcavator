//! Text output in the MASM-style syntax of Microsoft's disassembler
//! (`dumpbin /disasm`), as a stream of classified tokens so that callers can
//! colorize it.

use alloc::{format, string::String, vec::Vec};

use core::fmt::Write as _;

use crate::instruction::prefix;
use crate::{Instruction, Memory, Mnemonic, Mode, Operand, Rounding};

/// What a piece of formatted text is, for coloring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A prefix (`lock`, `rep`, ...).
    Prefix,
    /// The mnemonic.
    Mnemonic,
    /// A register.
    Register,
    /// An immediate or displacement.
    Number,
    /// An absolute address (branch target or memory address).
    Address,
    /// `byte ptr`, `bcst`, ...
    Keyword,
    /// `{k1}`, `{z}`, `{rn-sae}`.
    Decorator,
    /// Punctuation and spacing.
    Punctuation,
}

/// Receives formatted text.
pub trait TokenSink {
    /// Takes the next piece of the text, and what it is.
    fn token(&mut self, kind: TokenKind, text: &str);
}

impl TokenSink for String {
    #[inline]
    fn token(&mut self, _: TokenKind, text: &str) {
        self.push_str(text);
    }
}

/// Names for addresses, for showing branch targets and memory operands
/// symbolically (as dumpbin does when it has a PDB).
pub trait Symbols {
    /// The name of the symbol that starts exactly at `address`.
    fn name_at(&self, address: u64) -> Option<&str>;

    /// Whether to use the style dumpbin uses when it has symbols: compact,
    /// signed displacements and compact addresses.
    fn symbolic(&self) -> bool {
        true
    }
}

/// No symbols.
pub struct NoSymbols;

impl Symbols for NoSymbols {
    #[inline]
    fn name_at(&self, _: u64) -> Option<&str> {
        None
    }

    fn symbolic(&self) -> bool {
        false
    }
}

/// The column at which operands start.
pub const MNEMONIC_WIDTH: usize = 12;

/// Formats `value` the way MASM writes numbers: decimal below 10, otherwise
/// hex with an `h` suffix and a leading `0` if it starts with a letter.
pub fn masm_hex(value: u64) -> String {
    if value < 10 {
        return format!("{value}");
    }
    let s = format!("{value:X}h");
    if s.as_bytes()[0].is_ascii_alphabetic() {
        format!("0{s}")
    } else {
        s
    }
}

/// The instruction's mnemonic as shown, including prefixes such as `lock`
/// and pseudo-op expansions such as `cmpltps`.
pub fn mnemonic_text(inst: &Instruction) -> String {
    let mut s = String::new();
    let p = inst.prefixes();
    // In dumpbin's order. A meaningless F3 is shown as `repe` alongside
    // `lock` and as `rep` otherwise.
    let rep_other = if p & prefix::LOCK != 0 { "repe" } else { "rep" };
    let words: [(u16, &str); 11] = [
        (prefix::VEX, "vex"),
        (prefix::XACQUIRE, "xacquire"),
        (prefix::XRELEASE, "xrelease"),
        (prefix::REP, "rep"),
        (prefix::REP_OTHER, rep_other),
        (prefix::REPE, "repe"),
        (prefix::REPNE, "repne"),
        (prefix::BND, "bnd"),
        (prefix::HINT_TAKEN, "ht"),
        (prefix::HINT_NOT_TAKEN, "hnt"),
        (prefix::LOCK, "lock"),
    ];
    for (bit, word) in words {
        if p & bit != 0 {
            s.push_str(word);
            s.push(' ');
        }
    }
    // APX pseudo-prefixes, as Intel's syntax writes them.
    if inst.no_flags() {
        s.push_str("{nf} ");
    }
    if inst.evex_promoted() {
        s.push_str("{evex} ");
    }
    let name = inst.mnemonic().name();
    match inst.pseudo_imm {
        Some(imm) => {
            const PREDICATES: [&str; 32] = [
                "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq_uq", "nge", "ngt",
                "false", "neq_oq", "ge", "gt", "true", "eq_os", "lt_oq", "le_oq", "unord_s",
                "neq_us", "nlt_uq", "nle_uq", "ord_s", "eq_us", "nge_uq", "ngt_uq", "false_os",
                "neq_os", "ge_oq", "gt_oq", "true_us",
            ];
            // cmpps -> cmp + lt + ps
            let (head, tail) = name.split_at(name.len() - 2);
            s.push_str(head);
            s.push_str(PREDICATES[usize::from(imm & 31)]);
            s.push_str(tail);
        }
        None => {
            s.push_str(name);
            // `aam`/`aad` with a base other than 10 are `aamb`/`aadb`.
            if matches!(inst.mnemonic(), Mnemonic::Aam | Mnemonic::Aad)
                && matches!(inst.operands().first(), Some(Operand::Imm(i)) if i.value != 10)
            {
                s.push('b');
            }
        }
    }
    s
}

/// Formats an instruction: mnemonic, padding, and operands.
pub fn format(inst: &Instruction, out: &mut dyn TokenSink) {
    format_with(inst, out, &NoSymbols);
}

/// Formats an instruction, naming addresses through `symbols`.
pub fn format_with(inst: &Instruction, out: &mut dyn TokenSink, symbols: &dyn Symbols) {
    let mnemonic = mnemonic_text(inst);
    let operands = visible_operands(inst);
    out.token(TokenKind::Mnemonic, &mnemonic);
    if operands.is_empty() {
        return;
    }
    let pad = MNEMONIC_WIDTH.saturating_sub(mnemonic.len()).max(1);
    out.token(TokenKind::Punctuation, &" ".repeat(pad));
    if let Some(dfv) = inst.default_flags() {
        out.token(TokenKind::Decorator, &default_flags(dfv));
        out.token(TokenKind::Punctuation, " ");
    }
    for (i, op) in operands.iter().enumerate() {
        if i > 0 {
            out.token(TokenKind::Punctuation, ",");
        }
        operand(inst, op, out, symbols);
        if i == 0 && inst.mask().is_some() {
            out.token(
                TokenKind::Decorator,
                &format!("{{k{}}}", inst.mask().unwrap_or(0)),
            );
            if inst.zeroing() {
                out.token(TokenKind::Decorator, "{z}");
            }
        }
    }
    if let Some(r) = inst.rounding() {
        let text = match r {
            Rounding::Nearest => " {rn-sae}",
            Rounding::Down => " {rd-sae}",
            Rounding::Up => " {ru-sae}",
            Rounding::Zero => " {rz-sae}",
        };
        out.token(TokenKind::Decorator, text);
    } else if inst.suppress_all_exceptions() {
        out.token(TokenKind::Decorator, " {sae}");
    }
}

/// Formats an instruction into a string.
pub fn to_string(inst: &Instruction) -> String {
    let mut s = String::new();
    format(inst, &mut s);
    s
}

/// APX CCMP/CTEST's default flags value: `{dfv=of,cf}`.
fn default_flags(dfv: u8) -> String {
    let names: Vec<&str> = [(8, "of"), (4, "sf"), (2, "zf"), (1, "cf")]
        .iter()
        .filter(|(bit, _)| dfv & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    format!("{{dfv={}}}", names.join(","))
}

fn visible_operands(inst: &Instruction) -> &[Operand] {
    let ops = inst.operands();
    // `aam`/`aad` with the default base of 10 omit it.
    if matches!(inst.mnemonic(), Mnemonic::Aam | Mnemonic::Aad)
        && matches!(ops.first(), Some(Operand::Imm(i)) if i.value == 10)
    {
        return &[];
    }
    ops
}

fn operand(inst: &Instruction, op: &Operand, out: &mut dyn TokenSink, symbols: &dyn Symbols) {
    match op {
        Operand::None => {}
        Operand::Reg(r) => out.token(TokenKind::Register, r.name()),
        Operand::Imm(i) => {
            // A 32-bit immediate that is a symbol's address.
            let name = (symbols.symbolic() && i.size == 4)
                .then(|| symbols.name_at(i.value))
                .flatten();
            match name {
                Some(name) => {
                    out.token(TokenKind::Keyword, "offset ");
                    out.token(TokenKind::Address, name);
                }
                None => out.token(TokenKind::Number, &masm_hex(i.value)),
            }
        }
        Operand::Rel(target) => match symbols.name_at(*target) {
            Some(name) => out.token(TokenKind::Address, name),
            None => out.token(TokenKind::Address, &address(inst.mode(), *target)),
        },
        Operand::Far {
            segment,
            offset,
            offset_size,
        } => {
            let text = if *offset_size == 2 {
                format!("{segment:04X}:{offset:04X}")
            } else {
                format!("{segment:04X}:{offset:08X}")
            };
            out.token(TokenKind::Address, &text);
        }
        Operand::Mem(m) => memory(inst, m, out, symbols),
    }
}

fn address(mode: Mode, value: u64) -> String {
    match mode {
        Mode::Bits64 => format!("{value:016X}"),
        _ => format!("{:08X}", value & 0xFFFF_FFFF),
    }
}

fn memory(inst: &Instruction, m: &Memory, out: &mut dyn TokenSink, symbols: &dyn Symbols) {
    if m.size != crate::MemSize::None {
        out.token(TokenKind::Keyword, m.size.name());
        out.token(
            TokenKind::Keyword,
            if m.broadcast != 0 { " bcst " } else { " ptr " },
        );
    }
    let absolute = m.base.is_none() && m.index.is_none();
    let mask = match m.address_size {
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    };
    // A named target replaces the address (and the implied `ds:`).
    let target = if m.is_rip_relative() {
        Some(inst.next_address().wrapping_add(m.disp as u64) & mask)
    } else if absolute && m.segment.is_none() {
        Some(m.disp as u64 & mask)
    } else {
        None
    };
    if let Some(name) = target.and_then(|t| symbols.name_at(t)) {
        out.token(TokenKind::Punctuation, "[");
        out.token(TokenKind::Address, name);
        out.token(TokenKind::Punctuation, "]");
        return;
    }
    // A table indexed by a register: `name[index*scale]`.
    if m.base.is_none()
        && m.segment.is_none()
        && m.disp_size == 4
        && let Some(index) = m.index
    {
        let disp = m.disp as u64 & mask;
        if let Some(name) = symbols.symbolic().then(|| symbols.name_at(disp)).flatten() {
            out.token(TokenKind::Address, name);
            out.token(TokenKind::Punctuation, "[");
            out.token(TokenKind::Register, index.name());
            if m.scale > 1 {
                out.token(TokenKind::Punctuation, "*");
                out.token(TokenKind::Number, &format!("{}", m.scale));
            }
            out.token(TokenKind::Punctuation, "]");
            return;
        }
    }
    if let Some(seg) = m.segment {
        out.token(TokenKind::Register, seg.name());
        out.token(TokenKind::Punctuation, ":");
    } else if absolute && inst.mode() != Mode::Bits64 {
        out.token(TokenKind::Register, "ds");
        out.token(TokenKind::Punctuation, ":");
    }
    out.token(TokenKind::Punctuation, "[");
    let width = usize::from(m.address_size) * 2;
    let symbolic = symbols.symbolic();
    if m.is_rip_relative() {
        let target = inst.next_address().wrapping_add(m.disp as u64) & mask;
        if symbolic {
            out.token(TokenKind::Address, &masm_hex(target));
        } else {
            let mut s = String::new();
            let _ = write!(s, "{target:0width$X}h");
            out.token(TokenKind::Address, &s);
        }
    } else if absolute {
        let value = m.disp as u64 & mask;
        if symbolic && !m.moffs {
            out.token(TokenKind::Address, &masm_hex(value));
        } else {
            let width = if m.moffs { width.max(8) } else { width };
            let mut s = String::new();
            let _ = write!(s, "{value:0width$X}h");
            out.token(TokenKind::Address, &s);
        }
    } else {
        if let Some(base) = m.base {
            out.token(TokenKind::Register, base.name());
        }
        if let Some(index) = m.index {
            if m.base.is_some() {
                out.token(TokenKind::Punctuation, "+");
            }
            out.token(TokenKind::Register, index.name());
            if m.scale > 1 {
                out.token(TokenKind::Punctuation, "*");
                out.token(TokenKind::Number, &format!("{}", m.scale));
            }
        }
        match m.disp_size {
            0 => {}
            1 => {
                if m.disp < 0 {
                    out.token(TokenKind::Punctuation, "-");
                    out.token(TokenKind::Number, &masm_hex(m.disp.unsigned_abs()));
                } else if m.disp > 0 || m.address_size == 2 {
                    // With 16-bit addressing a zero disp8 is still shown.
                    out.token(TokenKind::Punctuation, "+");
                    out.token(TokenKind::Number, &masm_hex(m.disp as u64));
                }
            }
            _ if symbolic => {
                // Signed and compact, like MASM; zero is left out.
                if m.disp == 0 {
                } else if m.disp < 0 {
                    out.token(TokenKind::Punctuation, "-");
                    out.token(TokenKind::Number, &masm_hex(m.disp.unsigned_abs()));
                } else {
                    out.token(TokenKind::Punctuation, "+");
                    out.token(TokenKind::Number, &masm_hex(m.disp as u64));
                }
            }
            _ => {
                out.token(TokenKind::Punctuation, "+");
                let mut s = String::new();
                let _ = write!(s, "{:0width$X}h", m.disp as u64 & mask);
                out.token(TokenKind::Number, &s);
            }
        }
    }
    out.token(TokenKind::Punctuation, "]");
}

/// Formats a line of a `dumpbin /disasm` listing: address, up to six bytes,
/// and the instruction (or nothing, for an undecodable byte), followed by
/// continuation lines for the remaining bytes. Lines end with `\n`.
pub fn listing(mode: Mode, address: u64, bytes: &[u8], inst: Option<&Instruction>) -> String {
    listing_with(mode, address, bytes, inst, &NoSymbols)
}

/// Like [`listing`], naming addresses through `symbols`.
pub fn listing_with(
    mode: Mode,
    address: u64,
    bytes: &[u8],
    inst: Option<&Instruction>,
    symbols: &dyn Symbols,
) -> String {
    let addr = match mode {
        Mode::Bits64 => format!("{address:016X}"),
        _ => format!("{:08X}", address & 0xFFFF_FFFF),
    };
    let indent = " ".repeat(addr.len() + 4);
    let mut out = String::new();
    let mut chunks = bytes.chunks(6);
    let first = chunks.next().unwrap_or(&[]);
    let hex: Vec<String> = first.iter().map(|b| format!("{b:02X}")).collect();
    let text = inst
        .map(|i| {
            let mut s = String::new();
            format_with(i, &mut s, symbols);
            s
        })
        .unwrap_or_default();
    let _ = write!(out, "  {addr}: {:<19}{text}", hex.join(" "));
    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    out.push('\n');
    for chunk in chunks {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let _ = writeln!(out, "{indent}{}", hex.join(" "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masm_numbers() {
        assert_eq!(masm_hex(0), "0");
        assert_eq!(masm_hex(9), "9");
        assert_eq!(masm_hex(10), "0Ah");
        assert_eq!(masm_hex(0x10), "10h");
        assert_eq!(masm_hex(0xFFFF_FFFF), "0FFFFFFFFh");
    }
}

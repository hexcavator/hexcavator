//! Text output in the syntax of Microsoft's ARM64 disassembler.
//!
//! An encoding's template (ARM syntax, from the ISA description) is
//! rendered symbol by symbol; optional `{...}` groups are left out when
//! they hold only default values. The result is converted to Microsoft's
//! conventions: lower case, no space after commas, `0x` hex immediates,
//! and register names such as `xip0`, `fp`, and `lr`.

use alloc::{format, string::String, string::ToString, vec::Vec};

use core::fmt::Write as _;

use crate::Instruction;
use crate::tables::{Kind, NONE, Symbol, Tok, attr, ms_mnemonic, rule, symbol, value};

/// Names for addresses, for showing branch targets symbolically.
pub trait Symbols {
    /// The name of the symbol at `address`, if there is one.
    fn name_at(&self, address: u64) -> Option<&str>;
}

struct NoSymbols;

impl Symbols for NoSymbols {
    fn name_at(&self, _: u64) -> Option<&str> {
        None
    }
}

/// The column operands start at.
const MNEMONIC_WIDTH: usize = 12;

/// A general-purpose register's name, where it is not `x<n>` or `w<n>`.
fn gpr_name(n: u64, wide: bool, sp: bool) -> Option<&'static str> {
    Some(match (n, wide) {
        (31, true) if sp => "sp",
        (31, false) if sp => "wsp",
        (31, true) => "xzr",
        (31, false) => "wzr",
        (16, true) => "xip0",
        (17, true) => "xip1",
        (18, true) => "xpr",
        (29, true) => "fp",
        (30, true) => "lr",
        (16, false) => "wip0",
        (17, false) => "wip1",
        (18, false) => "wpr",
        (29, false) => "wfp",
        (30, false) => "wlr",
        _ => return None,
    })
}

/// The symbol's raw number (before its attributes' scaling).
fn raw(sym: &Symbol, w: u32) -> u64 {
    value(sym.encoded, w)
}

fn number(sym: &Symbol, w: u32) -> i64 {
    match &sym.value {
        Some(v) => v.eval(w),
        None => raw(sym, w) as i64,
    }
}

/// Finds the table row matching the word.
/// A table row's result: its text, or a computed number.
enum TableResult {
    /// Text shown as it is, and whether it is a default.
    Shown(&'static str, bool),
    Text(&'static str),
    Number(i64),
}

fn table_lookup(sym: &Symbol, w: u32) -> Option<TableResult> {
    let t = sym.table?;
    let key = value(t.key, w);
    let &(_, _, result, expr, mul, add, shown) = t.rows.iter().find(|r| key & r.0 == r.1)?;
    Some(if let Some((text, default)) = shown {
        TableResult::Shown(text, default)
    } else if expr.is_empty() {
        TableResult::Text(result)
    } else {
        TableResult::Number(mul * value(expr, w) as i64 + add)
    })
}

/// Rewrites `#<decimal>` numbers in ARM text the Microsoft way.
fn fix_numbers(s: &str) -> String {
    let mut out = String::new();
    if !fix_numbers_into(s, &mut out) {
        out.push_str(s);
    }
    out
}

/// [`fix_numbers`] of `s` into `out`, or `false` (nothing written) where
/// it would not change `s`.
fn fix_numbers_into(s: &str, out: &mut String) -> bool {
    if !needs_fix_numbers(s) {
        return false;
    }
    let mut rest = s;
    while let Some(i) = rest.find('#') {
        out.push_str(&rest[..=i]);
        rest = &rest[i + 1..];
        let neg = rest.starts_with('-');
        let body = &rest[usize::from(neg)..];
        let n = body.bytes().take_while(u8::is_ascii_digit).count();
        let after = &body[n..];
        // Leave fractions and numbers already in hex alone.
        if n == 0 || after.starts_with('.') || after.starts_with('x') {
            continue;
        }
        let v: i64 = body[..n].parse().unwrap_or(0);
        push_imm(out, if neg { -v } else { v });
        rest = after;
    }
    out.push_str(rest);
    true
}

/// Renders a symbol into `out`: whether its value is the default an
/// optional group may leave out, or `None` (nothing written) if it does not
/// render.
fn render_symbol(
    inst: &Instruction,
    sym: &Symbol,
    symbols: &dyn Symbols,
    out: &mut String,
) -> Option<bool> {
    let w = inst.word;
    if let Some((p, v)) = sym.when
        && value(p, w) != v
    {
        return None;
    }
    if sym.table.is_some() {
        let name = sym.display.trim_start_matches('<').trim_end_matches('>');
        // (A condition with no row, AL or NV for an inverted condition, is
        // not shown.)
        let lookup = table_lookup(sym, w).or_else(|| {
            matches!(sym.display, "<cond>" | "<invcond>").then_some(TableResult::Text("AL"))
        });
        // Values a table of names doesn't name (SVE patterns, barrier
        // options, prefetch operations): the number, as LLVM prints them.
        if lookup.is_none() && sym.has(attr::ORIMM) {
            out.push('#');
            push_imm(out, raw(sym, w) as i64);
            return Some(false);
        }
        let result = match lookup? {
            TableResult::Shown(text, default) => {
                out.push_str(text);
                return Some(default);
            }
            TableResult::Text(t) => t,
            TableResult::Number(n) => {
                push_decimal(out, n);
                return Some(n == 0);
            }
        };
        if result == "RESERVED" {
            return None;
        }
        // An extended register's UXTW (32-bit) or UXTX (64-bit) is LSL
        // only where Rd or Rn is SP (LLVM's printArithExtend).
        // (The option it applies to: UXTW, 010, in the 32-bit forms; UXTX,
        // 011, in the 64-bit forms.)
        let option = (w >> 13) & 7;
        let wide = w >> 31 == 1;
        let result = if sym.has(attr::LSLSP)
            && matches!(result, "LSL" | "UXTW" | "UXTX")
            && option == if wide { 3 } else { 2 }
        {
            // (Rd 31 is SP only without S: ADDS and SUBS set XZR.)
            let sets_flags = (w >> 29) & 1 == 1;
            let sp = (w & 0x1F == 31 && !sets_flags) || (w >> 5) & 0x1F == 31;
            match (sp, wide) {
                (true, _) => "LSL",
                (false, true) => "UXTX",
                (false, false) => "UXTW",
            }
        } else {
            result
        };
        // Optional suffixes and modifiers: "UMULL{2}", "{, <mod>}".
        if result == "[absent]" {
            return Some(true);
        }
        if result == "[present]" {
            push_lower(out, name);
            return Some(false);
        }
        if matches!(sym.display, "<cond>" | "<invcond>") {
            // "CS|HS": Microsoft uses the second name; AL and NV are not
            // shown.
            let c = result.rsplit('|').next().unwrap_or(result);
            let c = if c == "AL" || c == "NV" { "" } else { c };
            push_lower(out, c);
            return Some(false);
        }
        // Prefetch operations: Microsoft knows the classic names, in upper
        // case, and shows others as numbers.
        // "#uimm4": the operation has no name; show the number.
        if result.starts_with("#u") || result.starts_with("#imm") {
            out.push('#');
            push_imm(out, raw(sym, w) as i64);
            return Some(false);
        }
        if sym.display == "<prfop>" {
            let classic = result.len() == 9
                && ["PLD", "PLI", "PST"].contains(&&result[..3])
                && ["L1", "L2", "L3"].contains(&&result[3..5])
                && ["KEEP", "STRM"].contains(&&result[5..]);
            // (Others, such as PLDSLCKEEP, as numbers.)
            if classic {
                out.push_str(result);
            } else {
                out.push('#');
                push_imm(out, raw(sym, w) as i64);
            }
            return Some(false);
        }
        // "LSL|UXTW": LSL when the stack pointer is involved.
        if let Some((lsl, other)) = result.split_once('|') {
            let rd = w & 0x1F;
            let rn = (w >> 5) & 0x1F;
            let sets_flags = w >> 29 & 1 == 1;
            let use_lsl = rn == 31 || (rd == 31 && !sets_flags);
            push_lower(out, if use_lsl { lsl } else { other });
            // "LSL #0" is left out.
            return Some(use_lsl);
        }
        // System operation names (AT, DC, IC, TLBI, ...) stay upper case.
        if sym.display.ends_with("_op>") && inst.encoding_name().contains("_SYS_") {
            out.push_str(result);
            return Some(false);
        }
        // SVE predicate patterns: upper case, and ALL is the default.
        if sym.display == "<pattern>" {
            let start = out.len();
            out.push_str(result);
            fix_numbers_from(out, start);
            return Some(result == "ALL");
        }
        let default = result.ends_with(" #0")
            || result == "#0"
            || result.is_empty()
            || (result == "LSL" && sym.display == "<extend>");
        let start = out.len();
        push_lower(out, result);
        fix_numbers_from(out, start);
        return Some(default);
    }
    if sym.has(attr::MAY_SPECIAL)
        && let Some(d) = special(inst, sym, out)
    {
        return Some(d);
    }
    // Floating-point immediates: imm8 expands to +-n/16 * 2^r.
    if is_fp_imm8(sym) {
        push_fp_imm8(out, raw_value(sym, w));
        return Some(false);
    }
    let n = number(sym, w);
    let reg = |out: &mut String, prefix: &str, n: i64| {
        out.push_str(prefix);
        push_decimal(out, n);
        Some(false)
    };
    match sym.kind {
        Kind::Pair(wide) => {
            push_gpr(out, (raw(sym, w) + 1) & 31, wide, false);
            return Some(false);
        }
        Kind::GprSp(wide) => {
            push_gpr(out, n as u64, wide, true);
            return Some(false);
        }
        Kind::Gpr(wide) => {
            // The zero register is the default for optional operands.
            push_gpr(out, n as u64, wide, false);
            // (Microsoft shows XZR for first-fault loads.) RET's register
            // "defaults to X30 if absent".
            return Some(
                (n == 31 && !inst.encoding_name().starts_with("ldff1"))
                    || (n == 30 && sym.has(attr::X30)),
            );
        }
        Kind::Reg(prefix) => return reg(out, prefix, n),
        Kind::Pn => {
            let n = if sym.has(attr::PN8) && n < 8 {
                n + 8
            } else {
                n
            };
            return reg(out, "pn", n);
        }
        Kind::Num => {
            if n == 31 && sym.has(attr::ZR31) {
                out.push_str("zr");
                return Some(false);
            }
            return reg(out, "", n);
        }
        Kind::Label => {
            let target = if sym.has(attr::PAGE) {
                (inst.address & !0xFFF).wrapping_add(n as u64)
            } else {
                inst.address.wrapping_add(n as u64)
            };
            match symbols.name_at(target) {
                Some(s) => out.push_str(s),
                None => {
                    push_hex(out, target, 16);
                }
            }
            return Some(false);
        }
        Kind::Bitmask => {
            // The fields' positions depend on the class: general forms
            // have N in bit 22, immr in 21:16, and imms in 15:10; SVE
            // forms have N:immr:imms in bits 17:5.
            let general = inst.class() == "general";
            let (n_bit, immr, imms) = if general {
                (
                    u64::from(w >> 22) & 1,
                    u64::from(w >> 16) & 0x3F,
                    u64::from(w >> 10) & 0x3F,
                )
            } else {
                (
                    u64::from(w >> 17) & 1,
                    u64::from(w >> 11) & 0x3F,
                    u64::from(w >> 5) & 0x3F,
                )
            };
            let datasize = if general && w >> 31 == 0 { 32 } else { 64 };
            let (mask, _) = crate::alias::decode_bit_masks(n_bit, imms, immr, true, datasize)?;
            // General 64-bit masks are shown signed; SVE masks at their
            // element size.
            let esize = if general {
                datasize
            } else {
                // (The arrangement is at least bytes.)
                let combined = (n_bit << 6) | (!imms & 0x3F);
                (1u32 << (63 - combined.leading_zeros())).max(8)
            };
            if esize >= 64 {
                push_imm(out, mask as i64);
            } else {
                push_imm(out, (mask & ((1u64 << esize) - 1)) as i64);
            }
            return Some(false);
        }
        Kind::SysReg => {
            let v = raw(sym, w);
            let (o0, op1, crn, crm, op2) = (
                (v >> 14) & 1,
                (v >> 11) & 7,
                (v >> 7) & 0xF,
                (v >> 3) & 0xF,
                v & 7,
            );
            // The register's name, if it has one.
            let key = u32::try_from(v & 0x7FFF).unwrap_or(0) | (1 << 15);
            if let Ok(i) = crate::tables::SYSREGS.binary_search_by_key(&key, |e| e.0) {
                out.push_str(crate::tables::SYSREGS[i].1);
            } else {
                let _ = write!(out, "S{}_{op1}_C{crn}_C{crm}_{op2}", o0 + 2);
            }
            return Some(false);
        }
        Kind::Imm => {}
    }
    // The default an optional group leaves out is what an all-zero field
    // means: #0, or MUL #1 (`add=1`).
    push_imm(out, n);
    Some(n == 0 || (sym.has(attr::ADD) && raw_value(sym, w) == 0))
}

/// Renders template tokens. Returns whether every symbol in them was a
/// default.
/// (`floor`: where the text being rendered begins, which a left-out group's
/// spaces stop at.)
fn render(
    inst: &Instruction,
    toks: &[Tok],
    symbols: &dyn Symbols,
    out: &mut String,
    floor: usize,
) -> Option<bool> {
    let mut all_default = true;
    for t in toks {
        match *t {
            Tok::Lit(text) => out.push_str(text),
            Tok::Sym(i) => {
                let sym = symbol(usize::from(i));
                let at = out.len();
                all_default &= render_symbol(inst, sym, symbols, out)?;
                // A number after a `#` (the literal's, which build.rs has
                // already put in Microsoft's form) is an immediate: hex from
                // 10 on. (Not a floating-point immediate, `#1.5` or `#31`.)
                let hash = if out[..at].ends_with('#') {
                    Some(at - 1)
                } else if out[..at].ends_with("#-") {
                    Some(at - 2)
                } else {
                    None
                };
                if let Some(h) = hash
                    && !is_fp_imm8(sym)
                {
                    fix_numbers_from(out, h);
                }
            }
            Tok::Group(inner, optional) => {
                let start = out.len();
                let defaults = render(inst, inner, symbols, out, floor)? && optional;
                if defaults {
                    out.truncate(start);
                    // The space before a left-out group goes too: "SXTH {#0}".
                    while out.len() > floor && out.ends_with(' ') {
                        out.pop();
                    }
                } else {
                    all_default = false;
                }
            }
        }
    }
    Some(all_default)
}

/// Renders the instruction into `out`: mnemonic, padding, operands. If an
/// operand is reserved, `None`, and `out` is as it was.
fn render_all(inst: &Instruction, symbols: &dyn Symbols, out: &mut String) -> Option<()> {
    let start = out.len();
    let r = render_parts(inst, symbols, out, start);
    if r.is_none() {
        out.truncate(start);
    }
    r
}

fn render_parts(
    inst: &Instruction,
    symbols: &dyn Symbols,
    out: &mut String,
    start: usize,
) -> Option<()> {
    let e = inst.encoding();
    let w = inst.word;
    match ms_mnemonic(e) {
        Some(m) => out.push_str(m),
        None => {
            render(inst, e.mnem, symbols, out, start)?;
        }
    }
    // `b.eq` is `beq`.
    if out.as_bytes()[start..].contains(&b'.') {
        let mut i = 0;
        out.retain(|c| {
            i += c.len_utf8();
            i <= start || c != '.'
        });
    }
    // Microsoft folds a trailing condition operand into the mnemonic
    // (`csel x0,x1,x2,eq` is `cseleq x0,x1,x2`), as it does `b.eq`.
    if e.cond != NONE {
        render_symbol(inst, symbol(usize::from(e.cond)), symbols, out)?;
    }
    if inst.is_unpredictable() {
        out.insert(start, '?');
    }
    // Microsoft's own mnemonics for some forms (whatever the operands).
    let set_mnemonic = |out: &mut String, m: &str| {
        out.truncate(start);
        out.push_str(m);
    };
    // ORR (immediate) from the zero register: Microsoft's MOV or MOVI.
    let orr_from_zr = e.rule == rule::ORR_IMM && (w >> 5) & 0x1F == 31;
    if e.rule == rule::MOV_ORR || orr_from_zr {
        set_mnemonic(out, ms_mov_or_movi(w));
    }
    // A zero LSR is Microsoft's "lsl #0".
    if e.rule == rule::LSR_UBFM && (w >> 16) & 0x3F == 0 {
        set_mnemonic(out, "lsl");
    }
    // Microsoft's UXTB/UXTH for 64-bit UBFM: "uxtb x0,w1".
    let imms = (w >> 10) & 0x3F;
    let uxt =
        e.rule == rule::UBFX_64 && (w >> 16) & 0x3F == 0 && (imms == 7 || imms == 15 || imms == 31);
    if uxt {
        set_mnemonic(
            out,
            match imms {
                7 => "uxtb",
                15 => "uxth",
                _ => "uxtw",
            },
        );
    }
    // The operands, after the padding (taken back if there are none).
    let pad = MNEMONIC_WIDTH.saturating_sub(out.len() - start).max(1);
    let pad_start = out.len();
    out.extend(core::iter::repeat_n(' ', pad));
    let ops = out.len();
    render(inst, e.ops, symbols, out, ops)?;
    if uxt {
        out.truncate(ops);
        push_gpr(out, u64::from(w & 0x1F), true, false);
        out.push(',');
        push_gpr(out, u64::from((w >> 5) & 0x1F), false, false);
    }
    if orr_from_zr {
        for zr in [",wzr", ",xzr"] {
            if let Some(i) = find(&out[ops..], zr) {
                out.replace_range(ops + i..ops + i + zr.len(), "");
            }
        }
    }
    // The rest of Microsoft's conventions, where text from different
    // symbols and literals meets: one look at the operands says which of
    // the rewrites can apply (most instructions need none), and each copies
    // the operands (through `scratch`) only where it changes them.
    let t = triggers(&out.as_bytes()[ops..]);
    let mut scratch = String::new();
    let mut step = |out: &mut String, trigger: u8, f: &dyn Fn(&str, &mut String) -> bool| {
        if t & trigger == 0 {
            return;
        }
        scratch.clear();
        if f(&out[ops..], &mut scratch) {
            out.truncate(ops);
            out.push_str(&scratch);
        }
    };
    step(out, trigger::REGISTER, &ms_registers);
    step(out, trigger::EXTEND, &extend_amounts);
    step(out, trigger::SPACING, &ms_spacing);
    // No `#0` offset in an addressing form (`[x0]!`).
    step(out, trigger::ZERO_OFFSET, &|s, d| {
        replace_into(s, d, ",#0]", "]")
    });
    // Microsoft leaves out a zero LSL, except in ADD/SUB (shifted
    // register) with the zero register.
    let zr = w & 0x1F == 31 || (w >> 5) & 0x1F == 31;
    if !(zr && e.rule == rule::ADD_SUB_SHIFT) {
        step(out, trigger::LSL, &drop_zero_lsl);
    }
    step(out, trigger::INDEX, &decimal_indexes);
    // Microsoft keeps a space before the register of a post-indexed
    // structure load or store: "[x2], x0".
    if e.post_index
        && let Some(i) = out[ops..].rfind("],")
        && !out[ops + i + 2..].starts_with('#')
    {
        out.insert(ops + i + 2, ' ');
    }
    if out.len() == ops {
        out.truncate(pad_start);
    }
    Some(())
}

/// What [`triggers`] finds: text a rewrite in `render_parts` may change.
mod trigger {
    /// `x16`, `w30`, ...: a register Microsoft names (`xip0`, `wlr`), put
    /// together from parts.
    pub const REGISTER: u8 = 1;
    /// `xt`: an extend (`uxtw`) that may need its amount.
    pub const EXTEND: u8 = 2;
    /// A `#` after a letter: a shift or extend and its amount.
    pub const SPACING: u8 = 4;
    /// `,#0]`.
    pub const ZERO_OFFSET: u8 = 8;
    /// `,lsl #0` or `,lsl#0` (before spacing), not `,lsl #0x10`.
    pub const LSL: u8 = 16;
    /// `[0x`.
    pub const INDEX: u8 = 32;
}

/// Which rewrites may apply to operands `s`: [`trigger`] flags, each for
/// text the rewrite changes, or that an earlier one can turn into it
/// (`,lsl#0` becomes `,lsl #0`).
fn triggers(s: &[u8]) -> u8 {
    let mut t = 0;
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'x' | b'w' => {
                let in_token = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
                let whole = (i == 0 || !in_token(s[i - 1])) && !in_token(at(i + 3));
                if whole
                    && matches!(
                        (at(i + 1), at(i + 2)),
                        (b'1', b'6'..=b'8') | (b'2', b'9') | (b'3', b'0')
                    )
                {
                    t |= trigger::REGISTER;
                }
                if c == b'x' && at(i + 1) == b't' {
                    t |= trigger::EXTEND;
                }
            }
            b'#' if i > 0 && s[i - 1].is_ascii_alphabetic() => t |= trigger::SPACING,
            b',' if at(i + 1) == b'#' && at(i + 2) == b'0' && at(i + 3) == b']' => {
                t |= trigger::ZERO_OFFSET;
            }
            b',' if s[i + 1..].starts_with(b"lsl") => {
                let amount = if at(i + 4) == b' ' { i + 5 } else { i + 4 };
                if at(amount) == b'#'
                    && at(amount + 1) == b'0'
                    && !at(amount + 2).is_ascii_alphanumeric()
                {
                    t |= trigger::LSL;
                }
            }
            b'[' if at(i + 1) == b'0' && at(i + 2) == b'x' => t |= trigger::INDEX,
            _ => {}
        }
    }
    t
}

/// Where `pat` is in `s`: for the short patterns and strings here, cheaper
/// than `str::find`'s searcher.
fn find(s: &str, pat: &str) -> Option<usize> {
    let (s, p) = (s.as_bytes(), pat.as_bytes());
    let (&first, rest) = p.split_first()?;
    (0..(s.len() + 1).saturating_sub(p.len()))
        .find(|&i| s[i] == first && s[i + 1..i + p.len()] == *rest)
}

/// Whether [`render_all`] is `Some` (what [`is_valid`] answers quickly).
pub(crate) fn renders_fully(inst: &Instruction) -> bool {
    render_all(inst, &NoSymbols, &mut String::new()).is_some()
}

/// Whether `inst` renders: [`render_all`] is `Some` exactly when this is
/// true (what can fail there is a template's symbols, groups, and
/// alternations, walked here the same way; the text is not built).
pub(crate) fn is_valid(inst: &Instruction) -> bool {
    let e = inst.encoding();
    if !e.checked {
        return true;
    }
    if e.cond != NONE && !symbol_renders(inst, symbol(usize::from(e.cond))) {
        return false;
    }
    (ms_mnemonic(e).is_some() || renders(inst, e.mnem)) && renders(inst, e.ops)
}

/// Whether [`render_symbol`] of `sym` is `Some`: it fails only where its
/// condition (`when`) doesn't hold, where its table has no row for the
/// word (or the row is RESERVED), and where a logical immediate's bits
/// are not a valid mask. Everything else renders.
fn symbol_renders(inst: &Instruction, sym: &Symbol) -> bool {
    let w = inst.word;
    if let Some((p, v)) = sym.when
        && value(p, w) != v
    {
        return false;
    }
    if sym.table.is_some() {
        return match table_lookup(sym, w) {
            Some(TableResult::Text(t)) => t != "RESERVED",
            Some(TableResult::Number(_) | TableResult::Shown(..)) => true,
            None => matches!(sym.display, "<cond>" | "<invcond>") || sym.has(attr::ORIMM),
        };
    }
    let name = sym.display.trim_start_matches('<').trim_end_matches('>');
    if !(matches!(name, "const" | "imm") && sym.has(attr::BITMASK)) {
        return true;
    }
    if special(inst, sym, &mut String::new()).is_some()
        || (sym.has(attr::FP8) && sym.value.as_ref().is_some_and(|v| v.width == 8))
    {
        return true;
    }
    let general = inst.class() == "general";
    let (n_bit, immr, imms) = if general {
        (
            u64::from(w >> 22) & 1,
            u64::from(w >> 16) & 0x3F,
            u64::from(w >> 10) & 0x3F,
        )
    } else {
        (
            u64::from(w >> 17) & 1,
            u64::from(w >> 11) & 0x3F,
            u64::from(w >> 5) & 0x3F,
        )
    };
    let datasize = if general && w >> 31 == 0 { 32 } else { 64 };
    crate::alias::decode_bit_masks(n_bit, imms, immr, true, datasize).is_some()
}

/// Whether [`render`] of `toks` is `Some`.
fn renders(inst: &Instruction, toks: &[Tok]) -> bool {
    toks.iter().all(|t| match *t {
        Tok::Lit(_) => true,
        Tok::Sym(i) => symbol_renders(inst, symbol(usize::from(i))),
        Tok::Group(inner, _) => renders(inst, inner),
    })
}

/// For tools: how an encoding renders a word, operand by operand (the
/// template, and each symbol's text, or `None` where it fails).
#[doc(hidden)]
pub fn explain_encoding(inst: &Instruction) -> alloc::string::String {
    use core::fmt::Write as _;
    /// Each symbol of `toks`, and how it renders.
    fn symbols_of(inst: &Instruction, toks: &[Tok], out: &mut String) {
        for t in toks {
            match *t {
                Tok::Lit(_) => {}
                Tok::Group(inner, _) => symbols_of(inst, inner, out),
                Tok::Sym(i) => {
                    let sym = symbol(usize::from(i));
                    let mut text = String::new();
                    let r = render_symbol(inst, sym, &NoSymbols, &mut text).map(|_| text);
                    let _ = writeln!(
                        out,
                        "    {} {:?} attrs {:?} -> {:?}",
                        sym.display, sym.encoded, sym.attrs, r
                    );
                }
            }
        }
    }
    let e = inst.encoding();
    let mut out = alloc::string::String::new();
    let _ = writeln!(
        out,
        "  {} {:08x}/{:08x} template {:?} {:?}",
        e.name, e.mask, e.value, e.mnem, e.ops
    );
    symbols_of(inst, e.mnem, &mut out);
    if e.cond != NONE {
        symbols_of(inst, &[Tok::Sym(e.cond)], &mut out);
    }
    symbols_of(inst, e.ops, &mut out);
    out
}

/// Formats an instruction: mnemonic, padding, operands.
pub fn format(inst: &Instruction) -> String {
    format_with(inst, &NoSymbols)
}

/// Formats an instruction, naming addresses through `symbols`.
pub fn format_with(inst: &Instruction, symbols: &dyn Symbols) -> String {
    let mut s = String::with_capacity(48);
    format_into(inst, symbols, &mut s);
    s
}

/// Formats an instruction into `out` (appended), naming addresses through
/// `symbols`: [`format_with`] without allocating a string.
pub fn format_into(inst: &Instruction, symbols: &dyn Symbols, out: &mut String) {
    let _ = render_all(inst, symbols, out);
}
/// Operands whose values the ISA description leaves to the reader: the
/// bitfield aliases and wide-immediate moves. Writes the operand to `out`
/// and returns whether it is a default, or returns `None` (nothing
/// written) for other operands.
fn special(inst: &Instruction, sym: &Symbol, out: &mut String) -> Option<bool> {
    let w = inst.word;
    let name = inst.encoding_name();
    let size: i64 = if w >> 31 == 1 { 64 } else { 32 };
    let immr = i64::from((w >> 16) & 0x3F);
    let imms = i64::from((w >> 10) & 0x3F);
    fn num(out: &mut String, v: i64) -> Option<bool> {
        push_imm(out, v);
        Some(v == 0)
    }
    // A register offset's amount (LLVM's printMemExtend): with S set, the
    // log2 of the access size in bytes (#0 for bytes); without, none.
    if sym.has(attr::MEMEXT)
        && sym.display == "<amount>"
        && let Some(width) = sym.attr("memext")
    {
        let width: u32 = width.parse().unwrap_or(8);
        if raw(sym, w) == 1 {
            out.push('#');
            push_imm(out, i64::from((width / 8).trailing_zeros()));
            return Some(false);
        }
        return Some(true);
    }
    // "it must be #0, encoded in "S" as 0 if omitted, or as 1 if present".
    if sym.has(attr::PRESENT01) {
        let present = raw_value(sym, w) == 1;
        if present {
            out.push_str("#0");
        }
        return Some(!present);
    }
    // SVE shifts by immediate: tsz gives the element size, and the
    // amount is tsz:imm3 minus the element size (left shifts) or twice
    // the element size minus tsz:imm3 (right shifts).
    if sym.has(attr::TSZ)
        && let Some(v) = sym.value.as_ref().filter(|v| v.width >= 4)
    {
        let raw = value(v.pieces, w) as i64;
        // The immediate below the size bits: imm3, or imm5 for the
        // multi-vector forms.
        let imm_bits = match v.pieces.last() {
            Some(crate::tables::Piece::Bits(h, l)) => i64::from(h - l + 1),
            _ => 3,
        };
        let tsz = raw >> imm_bits;
        if tsz != 0 {
            let esize = (8i64 << (63 - i64::from(tsz.leading_zeros()))) << (imm_bits - 3);
            let mnemonic = name.split('_').next().unwrap_or("");
            let left = [
                "lsl", "sli", "sqshl", "uqshl", "sqshlu", "sshllb", "sshllt", "ushllb", "ushllt",
            ]
            .contains(&mnemonic);
            let amount = if left { raw - esize } else { 2 * esize - raw };
            return num(out, amount);
        }
    }
    // ZERO { <mask> }.
    if sym.display == "<mask>" && name.starts_with("zero_za_i") {
        out.push_str(&za_mask(raw(sym, w)));
        return Some(false);
    }
    // Symbols with no encoding: "is the destination width specifier, H."
    // and "is the second slice index offset, with implicit value 1."
    if sym.encoded.is_empty() && sym.value.is_none() {
        if let Some(n) = sym.attr("implicit") {
            out.push_str(n);
            return Some(false);
        }
        if let Some(s) = sym.attr("spec") {
            push_lower(out, s);
            return Some(false);
        }
    }
    // AdvSIMD MOVI with 64-bit elements: each bit of a:b:c:d:e:f:g:h is a
    // byte of ones or zeros.
    if sym.has(attr::BYTEMASK) {
        let v = raw_value(sym, w);
        let mut mask = 0u64;
        for i in 0..8 {
            if v >> i & 1 != 0 {
                mask |= 0xFF << (8 * i);
            }
        }
        push_imm(out, mask as i64);
        return Some(false);
    }
    // SVE multipliers: "in the range 1 to 16, defaulting to 1, encoded in
    // the imm4 field" (as the value minus one).
    if sym.has(attr::MULT16) {
        let v = raw_value(sym, w) as i64 + 1;
        push_imm(out, v);
        return Some(v == 1);
    }
    // SVE DUP (indexed): the index is above the lowest set bit of tsz.
    if sym.display == "<imm>"
        && sym.has(attr::DUPINDEX)
        && (name.starts_with("dup_z_zi") || name.starts_with("mov_z_zi__dup"))
    {
        let v = raw_value(sym, w);
        let tsz = v & 0x1F;
        if tsz != 0 {
            push_decimal(out, (v >> (tsz.trailing_zeros() + 1)) as i64);
            return Some(false);
        }
    }
    let prefix = name.split('_').next().unwrap_or("");
    match (prefix, sym.display) {
        ("UBFX" | "SBFX" | "BFXIL", "<lsb>") => num(out, immr),
        ("UBFX" | "SBFX" | "BFXIL", "<width>") => num(out, imms + 1 - immr),
        ("UBFIZ" | "SBFIZ" | "BFI" | "BFC", "<lsb>") => num(out, (-immr).rem_euclid(size)),
        ("UBFIZ" | "SBFIZ" | "BFI" | "BFC", "<width>") => num(out, imms + 1),
        ("LSL", "<shift>") if name.contains("UBFM") => num(out, (-immr).rem_euclid(size)),
        ("MOV", "<imm>") if name.contains("MOVZ") || name.contains("MOVN") => {
            let imm16 = u64::from((w >> 5) & 0xFFFF);
            let hw = (w >> 21) & 3;
            let v = imm16 << (16 * hw);
            // Microsoft shows a MOVN value as the 64-bit inverse, signed
            // (even for the 32-bit form), and a MOVZ value unsigned.
            let v = if name.contains("MOVN") {
                !v as i64
            } else {
                v as i64
            };
            num(out, v)
        }
        _ => None,
    }
}

/// Writes a number as Microsoft writes immediates: decimal below 10,
/// otherwise `0x` and upper-case hex; negative values with a leading `-`.
fn push_imm(out: &mut String, v: i64) {
    let m = v.unsigned_abs();
    if v < 0 {
        out.push('-');
    }
    if m < 10 {
        out.push(char::from(b'0' + m as u8));
    } else {
        out.push_str("0x");
        push_hex(out, m, 1);
    }
}

/// Writes a number in decimal.
fn push_decimal(out: &mut String, v: i64) {
    if v < 0 {
        out.push('-');
    }
    push_unsigned(out, v.unsigned_abs());
}

/// Writes an unsigned number in decimal.
fn push_unsigned(out: &mut String, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend(digits[i..].iter().map(|&d| char::from(d)));
}

/// Writes a number in upper-case hex, with at least `min` digits.
fn push_hex(out: &mut String, v: u64, min: u32) {
    let digits = (64 - v.leading_zeros()).div_ceil(4).max(min);
    for k in (0..digits).rev() {
        let d = (v >> (4 * k)) & 0xF;
        out.push(char::from(b"0123456789ABCDEF"[d as usize]));
    }
}

/// Writes `s` in lower case.
fn push_lower(out: &mut String, s: &str) {
    out.extend(s.chars().map(|c| c.to_ascii_lowercase()));
}

/// Writes a general-purpose register's name.
fn push_gpr(out: &mut String, n: u64, wide: bool, sp: bool) {
    match gpr_name(n, wide, sp) {
        Some(name) => out.push_str(name),
        None => {
            out.push(if wide { 'x' } else { 'w' });
            push_decimal(out, n as i64);
        }
    }
}

/// Applies [`fix_numbers`] to what `out` holds from `start` on.
fn fix_numbers_from(out: &mut String, start: usize) {
    if needs_fix_numbers(&out[start..]) {
        let fixed = fix_numbers(&out[start..]);
        out.truncate(start);
        out.push_str(&fixed);
    }
}

/// Microsoft's names for x16, x17, x18, x29, and x30 (and their W forms),
/// applied to register tokens put together from parts (`<R><m>`). (Into
/// `out`, or `false` where there are none.)
fn ms_registers(s: &str, out: &mut String) -> bool {
    let name = |token: &[u8]| {
        Some(match token {
            b"x16" => "xip0",
            b"x17" => "xip1",
            b"x18" => "xpr",
            b"x29" => "fp",
            b"x30" => "lr",
            b"w16" => "wip0",
            b"w17" => "wip1",
            b"w18" => "wpr",
            b"w29" => "wfp",
            b"w30" => "wlr",
            _ => return None,
        })
    };
    let in_token = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = s.as_bytes();
    // A whole token of three characters at `i`, one renamed.
    let renamed = |i: usize| {
        if !matches!(b[i], b'x' | b'w')
            || i + 3 > b.len()
            || (i > 0 && in_token(b[i - 1]))
            || b.get(i + 3).is_some_and(|&c| in_token(c))
        {
            return None;
        }
        name(&b[i..i + 3])
    };
    let Some(first) = (0..b.len()).find(|&i| renamed(i).is_some()) else {
        return false;
    };
    out.push_str(&s[..first]);
    let mut i = first;
    while i < b.len() {
        if let Some(n) = renamed(i) {
            out.push_str(n);
            i += 3;
            continue;
        }
        // Up to the next possible register (a whole character at a time).
        let next = s[i + 1..].find(['x', 'w']).map_or(s.len(), |j| i + 1 + j);
        out.push_str(&s[i..next]);
        i = next;
    }
    true
}

/// The value of a symbol's precise encoding (its `source=`), unscaled.
fn raw_value(sym: &Symbol, w: u32) -> u64 {
    match &sym.value {
        Some(v) => value(v.pieces, w),
        None => raw(sym, w),
    }
}

/// Whether `sym` is an 8-bit floating-point immediate.
fn is_fp_imm8(sym: &Symbol) -> bool {
    sym.has(attr::FP8) && sym.value.as_ref().is_some_and(|v| v.width == 8)
}

/// `VFPExpandImm`: an 8-bit floating-point immediate, as Microsoft shows
/// it (the shortest decimal).
fn push_fp_imm8(out: &mut String, imm8: u64) {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exp = (((imm8 >> 4) & 7) ^ 4) as i32 - 3;
    let mantissa = (16 + (imm8 & 0xF)) as f64 / 16.0;
    // 2^exp, exactly (exp is -3..=4), without libm's powi.
    let scale = f64::from_bits(((1023 + exp) as u64) << 52);
    let _ = write!(out, "{}", sign * mantissa * scale);
}

/// Microsoft always shows the amount of an extend other than LSL:
/// `sxtw #0`, not `sxtw`. (Into `out`, or `false` where nothing changes.)
fn extend_amounts(s: &str, out: &mut String) -> bool {
    const EXTENDS: [&str; 8] = [
        "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
    ];
    if find(s, "xt").is_none() {
        return false;
    }
    let mut changed = false;
    let mut rest = s;
    while let Some(i) = rest.find(',') {
        out.push_str(&rest[..=i]);
        rest = &rest[i + 1..];
        // Only after a general-purpose register (SVE vector offsets keep
        // a bare "uxtw").
        let before = out[..out.len() - 1]
            .rsplit([',', '[', ' '])
            .next()
            .unwrap_or("");
        let gpr = before.starts_with(['w', 'x']) && before.len() <= 4
            || matches!(before, "fp" | "lr" | "sp" | "wsp");
        if !gpr {
            continue;
        }
        for ext in EXTENDS {
            if let Some(tail) = rest.strip_prefix(ext) {
                if tail.is_empty() || tail.starts_with([',', ']']) {
                    out.push_str(ext);
                    out.push_str(" #0");
                    rest = tail;
                    changed = true;
                }
                break;
            }
        }
    }
    out.push_str(rest);
    changed
}

/// Microsoft's spacing: a space between a shift or extend and its amount
/// (`sxtw #1`). (Into `out`, or `false` where nothing changes.)
fn ms_spacing(s: &str, out: &mut String) -> bool {
    const KEYWORDS: [&str; 13] = [
        "lsl", "lsr", "asr", "ror", "msl", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw",
        "sxtx",
    ];
    let spaced = |i: usize| KEYWORDS.iter().any(|k| s[..i].ends_with(k));
    let Some(first) = s.match_indices('#').map(|(i, _)| i).find(|&i| spaced(i)) else {
        return false;
    };
    let mut from = 0;
    for (i, _) in s[first..].match_indices('#') {
        let i = first + i;
        out.push_str(&s[from..i]);
        if spaced(i) {
            out.push(' ');
        }
        from = i;
    }
    out.push_str(&s[from..]);
    true
}

/// `s` with `from` replaced by `to` into `out`, or `false` (nothing
/// written) where it has no `from`.
fn replace_into(s: &str, out: &mut String, from: &str, to: &str) -> bool {
    let Some(first) = find(s, from) else {
        return false;
    };
    out.push_str(&s[..first]);
    out.push_str(to);
    let mut rest = &s[first + from.len()..];
    while let Some(i) = find(rest, from) {
        out.push_str(&rest[..i]);
        out.push_str(to);
        rest = &rest[i + from.len()..];
    }
    out.push_str(rest);
    true
}

/// Whether [`fix_numbers`] would change `s`: a `#` number of two digits or
/// more (or a negative zero).
fn needs_fix_numbers(s: &str) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        if c != b'#' {
            return false;
        }
        let neg = b.get(i + 1) == Some(&b'-');
        let j = i + 1 + usize::from(neg);
        let digit = |k: usize| b.get(k).is_some_and(u8::is_ascii_digit);
        digit(j) && (digit(j + 1) || (neg && b[j] == b'0'))
    })
}

/// Removes `,lsl #0` (but not `,lsl #0x20`). (Into `out`, or `false` where
/// there is none.)
fn drop_zero_lsl(s: &str, out: &mut String) -> bool {
    if find(s, ",lsl #0").is_none() {
        return false;
    }
    let mut rest = s;
    while let Some(i) = find(rest, ",lsl #0") {
        let after = &rest[i + 7..];
        out.push_str(&rest[..i]);
        if after.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            out.push_str(",lsl #0");
        }
        rest = after;
    }
    out.push_str(rest);
    true
}

/// How Microsoft shows ORR (immediate) from the zero register: MOVI when
/// MOVZ or MOVN could make the value (it fits one aligned halfword, or
/// its inverse does), when a 64-bit form repeats a smaller element, or
/// when the rotation is not reduced (immr at least the element size);
/// MOV otherwise. (Worked out from dumpbin's output over every encoding.)
fn ms_mov_or_movi(w: u32) -> &'static str {
    let sf = w >> 31;
    let n_bit = u64::from(w >> 22) & 1;
    let immr = u64::from(w >> 16) & 0x3F;
    let imms = u64::from(w >> 10) & 0x3F;
    let datasize = if sf == 1 { 64 } else { 32 };
    let Some((v, _)) = crate::alias::decode_bit_masks(n_bit, imms, immr, true, datasize) else {
        return "mov";
    };
    let combined = (n_bit << 6) | (!imms & 0x3F);
    let esize = 1u64 << (63 - combined.leading_zeros());
    let mask = if sf == 1 { u64::MAX } else { 0xFFFF_FFFF };
    let fits = |x: u64| (0..datasize / 16).any(|k| x & !(0xFFFFu64 << (16 * k)) & mask == 0);
    if fits(v) || fits(!v & mask) || (sf == 1 && esize < 64) || immr >= esize {
        "movi"
    } else {
        "mov"
    }
}

/// Indexes alone in brackets are decimal: `zt0[56]`, not `zt0[0x38]`.
/// (Into `out`, or `false` where there is none.)
fn decimal_indexes(s: &str, out: &mut String) -> bool {
    if find(s, "[0x").is_none() {
        return false;
    }
    let mut rest = s;
    while let Some(i) = find(rest, "[0x") {
        out.push_str(&rest[..=i]);
        rest = &rest[i + 1..];
        let n = rest[2..].bytes().take_while(u8::is_ascii_hexdigit).count();
        if rest[2 + n..].starts_with(']')
            && let Ok(v) = u64::from_str_radix(&rest[2..2 + n], 16)
        {
            push_unsigned(out, v);
            rest = &rest[2 + n..];
        }
    }
    out.push_str(rest);
    true
}

/// `ZERO { <mask> }`: the ZA tiles of an 8-bit mask, in Microsoft's form
/// (the whole array, or 64-bit tiles).
pub(crate) fn za_mask(mask: u64) -> String {
    if mask == 0xFF {
        return "za".to_string();
    }
    let tiles: Vec<String> = (0..8)
        .filter(|i| mask >> i & 1 != 0)
        .map(|i| format!("za{i}.d"))
        .collect();
    tiles.join(",")
}

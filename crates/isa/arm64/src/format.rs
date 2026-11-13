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
use crate::tables::{Symbol, symbol, value};

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

/// A number as Microsoft writes immediates: decimal below 10, otherwise
/// `0x` and upper-case hex; negative values with a leading `-`.
pub(crate) fn imm(v: i64) -> String {
    let (sign, m) = if v < 0 {
        ("-", v.unsigned_abs())
    } else {
        ("", v as u64)
    };
    if m < 10 {
        format!("{sign}{m}")
    } else {
        format!("{sign}0x{m:X}")
    }
}

fn gpr(n: u64, wide: bool, sp: bool) -> String {
    let name = match (n, wide) {
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
        _ => return format!("{}{n}", if wide { 'x' } else { 'w' }),
    };
    name.to_string()
}

/// One rendered symbol.
struct Rendered {
    text: String,
    /// Whether the value is the default an optional group may leave out.
    default: bool,
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
    Text(&'static str),
    Number(i64),
}

fn table_lookup(sym: &Symbol, w: u32) -> Option<TableResult> {
    let t = sym.table?;
    // The columns' values and widths (tables have a few columns; more are
    // read as they are needed).
    const COLS: usize = 8;
    let mut vals = [(0u64, 0u32); COLS];
    for (slot, c) in vals.iter_mut().zip(t.cols) {
        *slot = (value(c, w), crate::tables::width(c));
    }
    let col = |i: usize| -> Option<(u64, u32)> {
        let c = t.cols.get(i)?;
        Some(if i < COLS {
            vals[i]
        } else {
            (value(c, w), crate::tables::width(c))
        })
    };
    'rows: for &(pats, result, expr, mul, add) in t.rows {
        for (i, pat) in pats.iter().enumerate() {
            let Some((v, width)) = col(i) else {
                continue 'rows;
            };
            // The pattern's bits, spaces left out ("1x 0" is "1x0").
            let bits = pat.bytes().filter(|&c| c != b' ');
            let mut n = 0u32;
            for c in bits.clone() {
                if !matches!(c, b'0' | b'1' | b'x') {
                    // Not a bit pattern (for example "!= 000"): skip the row.
                    continue 'rows;
                }
                n += 1;
            }
            if n == 0 {
                continue;
            }
            if n != width {
                continue 'rows;
            }
            for (j, c) in bits.enumerate() {
                let bit = (v >> (n - 1 - j as u32)) & 1;
                match c {
                    b'0' if bit != 0 => continue 'rows,
                    b'1' if bit != 1 => continue 'rows,
                    _ => {}
                }
            }
        }
        if !expr.is_empty() {
            return Some(TableResult::Number(mul * value(expr, w) as i64 + add));
        }
        return Some(TableResult::Text(result));
    }
    None
}

/// Rewrites `#<decimal>` numbers in ARM text the Microsoft way.
fn fix_numbers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('#') {
        out.push_str(&rest[..=i]);
        rest = &rest[i + 1..];
        let neg = rest.starts_with('-');
        let digits: String = rest[usize::from(neg)..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let after = &rest[usize::from(neg) + digits.len()..];
        // Leave fractions, numbers already in hex, and verbatim text alone.
        if digits.is_empty()
            || after.starts_with('.')
            || after.starts_with('x')
            || after.starts_with(VERBATIM)
        {
            continue;
        }
        let v: i64 = digits.parse().unwrap_or(0);
        out.push_str(&imm(if neg { -v } else { v }));
        rest = after;
    }
    out.push_str(rest);
    out
}

fn render_symbol(inst: &Instruction, sym: &Symbol, symbols: &dyn Symbols) -> Option<Rendered> {
    let w = inst.word;
    if let Some((p, v)) = sym.when
        && value(p, w) != v
    {
        return None;
    }
    let name = sym.display.trim_start_matches('<').trim_end_matches('>');
    if sym.table.is_some() {
        // (A condition with no row, AL or NV for an inverted condition, is
        // not shown.)
        let lookup = table_lookup(sym, w).or_else(|| {
            matches!(sym.display, "<cond>" | "<invcond>").then_some(TableResult::Text("AL"))
        });
        // Values a table of names doesn't name (SVE patterns, barrier
        // options, prefetch operations): the number, as LLVM prints them.
        if lookup.is_none() && sym.has("orimm") {
            let v = raw(sym, w) as i64;
            return Some(Rendered {
                text: format!("#{}", imm(v)),
                default: false,
            });
        }
        let result = match lookup? {
            TableResult::Text(t) => t,
            TableResult::Number(n) => {
                return Some(Rendered {
                    text: format!("{n}"),
                    default: n == 0,
                });
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
        let result = if sym.has("lslsp")
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
            return Some(Rendered {
                text: String::new(),
                default: true,
            });
        }
        if result == "[present]" {
            return Some(Rendered {
                text: name.to_ascii_lowercase(),
                default: false,
            });
        }
        if matches!(sym.display, "<cond>" | "<invcond>") {
            // "CS|HS": Microsoft uses the second name; AL and NV are not
            // shown.
            let c = result.rsplit('|').next().unwrap_or(result);
            let c = if c == "AL" || c == "NV" { "" } else { c };
            return Some(Rendered {
                text: c.to_ascii_lowercase(),
                default: false,
            });
        }
        // Prefetch operations: Microsoft knows the classic names, in upper
        // case, and shows others as numbers.
        // "#uimm4": the operation has no name; show the number.
        if result.starts_with("#u") || result.starts_with("#imm") {
            return Some(Rendered {
                text: format!("#{}", imm(raw(sym, w) as i64)),
                default: false,
            });
        }
        if sym.display == "<prfop>" {
            let classic = result.len() == 9
                && ["PLD", "PLI", "PST"].contains(&&result[..3])
                && ["L1", "L2", "L3"].contains(&&result[3..5])
                && ["KEEP", "STRM"].contains(&&result[5..]);
            // (Others, such as PLDSLCKEEP, as numbers.)
            return Some(Rendered {
                text: if classic {
                    result.to_string()
                } else {
                    format!("#{}", imm(raw(sym, w) as i64))
                },
                default: false,
            });
        }
        // "LSL|UXTW": LSL when the stack pointer is involved.
        if let Some((lsl, other)) = result.split_once('|') {
            let rd = w & 0x1F;
            let rn = (w >> 5) & 0x1F;
            let sets_flags = w >> 29 & 1 == 1;
            let use_lsl = rn == 31 || (rd == 31 && !sets_flags);
            let pick = if use_lsl { lsl } else { other };
            return Some(Rendered {
                text: pick.to_ascii_lowercase(),
                // "LSL #0" is left out.
                default: use_lsl,
            });
        }
        // System operation names (AT, DC, IC, TLBI, ...) stay upper case.
        if inst.encoding_name().contains("_SYS_") && sym.display.ends_with("_op>") {
            return Some(Rendered {
                text: result.to_string(),
                default: false,
            });
        }
        // SVE predicate patterns: upper case, and ALL is the default.
        if sym.display == "<pattern>" {
            return Some(Rendered {
                text: fix_numbers(result),
                default: result == "ALL",
            });
        }
        let default = result.ends_with(" #0")
            || result == "#0"
            || result.is_empty()
            || (result == "LSL" && sym.display == "<extend>");
        return Some(Rendered {
            text: fix_numbers(&result.to_ascii_lowercase()),
            default,
        });
    }
    if let Some(r) = special(inst, sym) {
        return Some(r);
    }
    // Floating-point immediates: imm8 expands to +-n/16 * 2^r.
    if sym.has("fp8") && sym.value.as_ref().is_some_and(|v| v.width == 8) {
        let v = raw_value(sym, w);
        return Some(Rendered {
            text: fp_imm8(v),
            default: false,
        });
    }
    let n = number(sym, w);
    let reg = |t: String| {
        Some(Rendered {
            text: t,
            default: false,
        })
    };
    let first = name.chars().next().unwrap_or(' ');
    let rest: &str = name.get(1..).unwrap_or("");
    // "d", "n2", "n+1" (the next register of a list).
    let is_reg_suffix = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+')
    };
    // The second register of a pair: "<W(s+1)>", "<X(t+1)>".
    if let Some(inner) = name
        .strip_prefix("W(")
        .or_else(|| name.strip_prefix("X("))
        .and_then(|s| s.strip_suffix("+1)"))
    {
        let _ = inner;
        return Some(Rendered {
            text: gpr((raw(sym, w) + 1) & 31, first == 'X', false),
            default: false,
        });
    }
    // General-purpose registers.
    if let Some(base) = name.strip_suffix("|WSP").or(name.strip_suffix("|SP")) {
        let wide = base.starts_with('X');
        return reg(gpr(n as u64, wide, true));
    }
    if (first == 'W' || first == 'X') && is_reg_suffix(rest) {
        // The zero register is the default for optional operands.
        return Some(Rendered {
            text: gpr(n as u64, first == 'X', false),
            // (Microsoft shows XZR for first-fault loads.) RET's register
            // "defaults to X30 if absent".
            default: (n == 31 && !inst.encoding_name().starts_with("ldff1"))
                || (n == 30 && sym.has("x30")),
        });
    }
    // SIMD&FP and SVE registers.
    if matches!(first, 'B' | 'H' | 'S' | 'D' | 'Q' | 'V') && is_reg_suffix(rest) {
        return reg(format!("{}{n}", first.to_ascii_lowercase()));
    }
    if let Some(r) = name.strip_prefix("ZA")
        && (is_reg_suffix(r) || r.is_empty())
    {
        return reg(format!("za{n}"));
    }
    if first == 'Z' && is_reg_suffix(rest) {
        return reg(format!("z{n}"));
    }
    if let Some(r) = name.strip_prefix("PN")
        && is_reg_suffix(r)
    {
        let n = if sym.has("pn8") && n < 8 { n + 8 } else { n };
        return reg(format!("pn{n}"));
    }
    if first == 'P' && is_reg_suffix(rest) {
        return reg(format!("p{n}"));
    }
    // Register numbers following a <R> or <V> prefix symbol.
    if matches!(name, "d" | "n" | "m" | "t" | "dn" | "a" | "s" | "t2" | "t1") {
        if n == 31 && sym.has("zr31") {
            return reg("zr".into());
        }
        return reg(format!("{n}"));
    }
    match name {
        // Lane indexes are decimal.
        "index" => return reg(format!("{n}")),
        "label" => {
            let target = if sym.has("page") {
                (inst.address & !0xFFF).wrapping_add(n as u64)
            } else {
                inst.address.wrapping_add(n as u64)
            };
            let text = match symbols.name_at(target) {
                Some(s) => s.to_string(),
                None => format!("{target:016X}"),
            };
            return reg(text);
        }
        "const" | "imm" if sym.has("bitmask") => {
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
            let text = if esize >= 64 {
                imm(mask as i64)
            } else {
                imm((mask & ((1u64 << esize) - 1)) as i64)
            };
            return Some(Rendered {
                text,
                default: false,
            });
        }
        "systemreg" => {
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
                return reg(crate::tables::SYSREGS[i].1.to_string());
            }
            return reg(format!("S{}_{op1}_C{crn}_C{crm}_{op2}", o0 + 2));
        }
        "Cn" | "Cm" => return reg(format!("C{n}")),
        _ => {}
    }
    // The default an optional group leaves out is what an all-zero field
    // means: #0, or MUL #1 (`add=1`).
    Some(Rendered {
        text: imm(n),
        default: n == 0 || (sym.attr("add").is_some() && raw_value(sym, w) == 0),
    })
}

/// Renders the operand part of a template (after the mnemonic). Returns
/// the text and whether every symbol in it was a default.
fn render(inst: &Instruction, t: &str, symbols: &dyn Symbols, out: &mut String) -> Option<bool> {
    let mut all_default = true;
    let mut rest = t;
    while !rest.is_empty() {
        if let Some(after) = rest
            .strip_prefix('(')
            .filter(|a| alternation_end(a).is_some())
        {
            // Alternatives, "(<prfop>|#<imm5>)": the first that renders.
            let end = alternation_end(after)?;
            let inner = &after[..end];
            let mut done = false;
            for alt in split_top(inner, '|') {
                let mut s = String::new();
                if let Some(d) = render(inst, alt, symbols, &mut s) {
                    out.push_str(&s);
                    all_default &= d;
                    done = true;
                    break;
                }
            }
            if !done {
                return None;
            }
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix('{') {
            // An optional group: find its matching brace.
            let mut depth = 1;
            let mut end = None;
            for (i, c) in after.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            // (An unclosed group: a bad template, shown as nothing.)
            let end = end?;
            let inner = &after[..end];
            let mut s = String::new();
            // Groups of plain text ("{, VGx2}") are always shown, except a
            // zero offset ("{, #0}").
            let defaults = render(inst, inner, symbols, &mut s)?
                && (inner.contains('%') || inner.trim() == ", #0");
            if defaults {
                // The space before a left-out group goes too: "SXTH {#0}".
                while out.ends_with(' ') {
                    out.pop();
                }
            } else {
                out.push_str(&s);
                all_default = false;
            }
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix('%') {
            let end = after.find('%')?;
            let index: usize = after[..end].parse().ok()?;
            let r = render_symbol(inst, symbol(index), symbols)?;
            all_default &= r.default;
            out.push_str(&r.text);
            rest = &after[end + 1..];
        } else {
            // Literal text, up to the next group, symbol, or alternation (a
            // lone parenthesis is literal).
            let end = rest[1..]
                .find(['{', '%', '('])
                .map_or(rest.len(), |i| i + 1);
            // build.rs marks register-list braces as \u{1} and \u{2}.
            let literal = rest[..end].replace('\u{1}', "{").replace('\u{2}', "}");
            // Lower case, except for MUL VL and MUL #.
            let mut lower = literal
                .to_ascii_lowercase()
                .replace("mul vl", "MUL VL")
                .replace("mul #", "MUL #")
                .replace("rctx", "RCTX");
            // A system register by number: S<op0>_<op1>_C<n>_C<m>_<op2>.
            let next = &rest[end..];
            let sysreg = next.starts_with('%')
                && next[1..]
                    .find('%')
                    .is_some_and(|i| next[i + 2..].starts_with('_'));
            if literal.ends_with('S') && sysreg {
                lower.pop();
                lower.push('S');
            }
            out.push_str(&fix_numbers(&lower));
            rest = &rest[end..];
        }
    }
    Some(all_default)
}

/// The mnemonic and operands, or `None` if an operand is reserved.
fn render_all(inst: &Instruction, symbols: &dyn Symbols) -> Option<(String, String)> {
    let t = inst.template();
    let (mnemonic, operands) = t.split_once(' ').unwrap_or((t, ""));
    // Microsoft folds a trailing condition operand into the mnemonic
    // (`csel x0,x1,x2,eq` is `cseleq x0,x1,x2`), as it does `b.eq`.
    let mut operands = operands;
    let mut cond = String::new();
    if let Some(i) = operands.rfind(", %") {
        let tail = &operands[i + 3..];
        if let Some(index) = tail.strip_suffix('%').and_then(|s| s.parse::<usize>().ok())
            && matches!(symbol(index).display, "<cond>" | "<invcond>")
        {
            cond = render_symbol(inst, symbol(index), symbols)?.text;
            operands = &operands[..i];
        }
    }
    let mut m = String::new();
    match ms_mnemonic(inst.encoding_name()) {
        Some(name) => m.push_str(name),
        None => {
            render(inst, mnemonic, symbols, &mut m)?;
        }
    }
    // `b.eq` is `beq`.
    let mut m = m.replace('.', "");
    m.push_str(&cond);
    if inst.is_unpredictable() {
        m.insert(0, '?');
    }
    let mut ops = String::new();
    render(inst, operands, symbols, &mut ops)?;
    let name = inst.encoding_name();
    // ORR (immediate) from the zero register: Microsoft's MOV or MOVI.
    if name.starts_with("MOV_ORR_") && name.ends_with("_log_imm") {
        m = ms_mov_or_movi(inst.word).to_string();
    }
    // A zero LSR is Microsoft's "lsl #0".
    if name.starts_with("LSR_UBFM") && (inst.word >> 16) & 0x3F == 0 {
        m = "lsl".to_string();
    }
    // Microsoft's UXTB/UXTH for 64-bit UBFM: "uxtb x0,w1".
    if name == "UBFX_UBFM_64M_bitfield" && (inst.word >> 16) & 0x3F == 0 {
        let imms = (inst.word >> 10) & 0x3F;
        if imms == 7 || imms == 15 || imms == 31 {
            m = match imms {
                7 => "uxtb",
                15 => "uxth",
                _ => "uxtw",
            }
            .to_string();
            let rd = gpr(u64::from(inst.word & 0x1F), true, false);
            let rn = gpr(u64::from((inst.word >> 5) & 0x1F), false, false);
            ops = format!("{rd}, {rn}");
        }
    }
    if (name == "ORR_32_log_imm" || name == "ORR_64_log_imm") && (inst.word >> 5) & 0x1F == 31 {
        m = ms_mov_or_movi(inst.word).to_string();
        ops = ops.replacen(", wzr", "", 1).replacen(", xzr", "", 1);
    }
    let ops = ms_registers(&fix_numbers(&ops.replace(", ", ",")));
    let ops = ms_spacing(&extend_amounts(&ops)).replace(VERBATIM, "");
    // Microsoft leaves out a zero LSL, except in ADD/SUB (shifted
    // register) with the zero register.
    let zr = inst.word & 0x1F == 31 || (inst.word >> 5) & 0x1F == 31;
    let base_add_sub = ["ADD_", "ADDS_", "SUB_", "SUBS_"]
        .iter()
        .any(|p| name.starts_with(p));
    let ops = if zr && base_add_sub && name.ends_with("_addsub_shift") {
        ops
    } else {
        drop_zero_lsl(&ops)
    };
    // Comparisons with zero are "#0", not "#0.0".
    let ops = ops.replace("#0.0", "#0");
    let ops = decimal_indexes(&ops);
    // Microsoft keeps a space before the register of a post-indexed
    // structure load or store: "[x2], x0".
    let ops = if inst.encoding_name().contains("_asisdlsop_")
        || inst.encoding_name().contains("_asisdlsep_")
    {
        match ops.rfind("],") {
            Some(i) if !ops[i + 2..].starts_with('#') => {
                format!("{}], {}", &ops[..i], &ops[i + 2..])
            }
            _ => ops,
        }
    } else {
        ops
    };
    Some((m, ops))
}

/// Whether [`render_all`] is `Some` (what [`is_valid`] answers quickly).
pub(crate) fn renders_fully(inst: &Instruction) -> bool {
    render_all(inst, &NoSymbols).is_some()
}

/// Whether `inst` renders: [`render_all`] is `Some` exactly when this is
/// true (what can fail there is a template's symbols, groups, and
/// alternations, walked here the same way; the text is not built).
pub(crate) fn is_valid(inst: &Instruction) -> bool {
    let t = inst.template();
    let (mnemonic, operands) = t.split_once(' ').unwrap_or((t, ""));
    let mut operands = operands;
    if let Some(i) = operands.rfind(", %") {
        let tail = &operands[i + 3..];
        if let Some(index) = tail.strip_suffix('%').and_then(|s| s.parse::<usize>().ok())
            && matches!(symbol(index).display, "<cond>" | "<invcond>")
        {
            if !symbol_renders(inst, symbol(index)) {
                return false;
            }
            operands = &operands[..i];
        }
    }
    (ms_mnemonic(inst.encoding_name()).is_some() || renders(inst, mnemonic))
        && renders(inst, operands)
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
            Some(TableResult::Number(_)) => true,
            None => matches!(sym.display, "<cond>" | "<invcond>") || sym.has("orimm"),
        };
    }
    let name = sym.display.trim_start_matches('<').trim_end_matches('>');
    if !(matches!(name, "const" | "imm") && sym.has("bitmask")) {
        return true;
    }
    if special(inst, sym).is_some()
        || (sym.has("fp8") && sym.value.as_ref().is_some_and(|v| v.width == 8))
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

/// Whether [`render`] of `t` is `Some`.
fn renders(inst: &Instruction, t: &str) -> bool {
    let mut rest = t;
    while !rest.is_empty() {
        if let Some(after) = rest
            .strip_prefix('(')
            .filter(|a| alternation_end(a).is_some())
        {
            let Some(end) = alternation_end(after) else {
                return false;
            };
            if !split_top(&after[..end], '|')
                .into_iter()
                .any(|alt| renders(inst, alt))
            {
                return false;
            }
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix('{') {
            let mut depth = 1;
            let mut end = None;
            for (i, c) in after.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                return false;
            };
            if !renders(inst, &after[..end]) {
                return false;
            }
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix('%') {
            let Some(end) = after.find('%') else {
                return false;
            };
            let Ok(index) = after[..end].parse::<usize>() else {
                return false;
            };
            if !symbol_renders(inst, symbol(index)) {
                return false;
            }
            rest = &after[end + 1..];
        } else {
            let end = rest[1..]
                .find(['{', '%', '('])
                .map_or(rest.len(), |i| i + 1);
            rest = &rest[end..];
        }
    }
    true
}

/// For tools: how an encoding renders a word, operand by operand (the
/// template, and each symbol's text, or `None` where it fails).
#[doc(hidden)]
pub fn explain_encoding(inst: &Instruction) -> alloc::string::String {
    use core::fmt::Write as _;
    let e = inst.encoding();
    let mut out = alloc::string::String::new();
    let _ = writeln!(
        out,
        "  {} {:08x}/{:08x} asm {:?}",
        e.name, e.mask, e.value, e.asm
    );
    let mut rest = e.asm;
    while let Some(i) = rest.find('%') {
        let after = &rest[i + 1..];
        let Some(end) = after.find('%') else { break };
        if let Ok(index) = after[..end].parse::<usize>() {
            let sym = symbol(index);
            let r = render_symbol(inst, sym, &NoSymbols);
            let _ = writeln!(
                out,
                "    {} {:?} attrs {:?} -> {:?}",
                sym.display,
                sym.encoded,
                sym.attrs,
                r.map(|r| r.text)
            );
        }
        rest = &after[end + 1..];
    }
    out
}

/// Formats an instruction: mnemonic, padding, operands.
pub fn format(inst: &Instruction) -> String {
    format_with(inst, &NoSymbols)
}

/// Formats an instruction, naming addresses through `symbols`.
pub fn format_with(inst: &Instruction, symbols: &dyn Symbols) -> String {
    let Some((mnemonic, ops)) = render_all(inst, symbols) else {
        return String::new();
    };
    let mut s = mnemonic;
    if !ops.is_empty() {
        let pad = MNEMONIC_WIDTH.saturating_sub(s.len()).max(1);
        let _ = write!(s, "{:pad$}{ops}", "");
    }
    s
}

/// Operands whose values the ISA description leaves to the reader: the
/// bitfield aliases and wide-immediate moves.
fn special(inst: &Instruction, sym: &Symbol) -> Option<Rendered> {
    let w = inst.word;
    let name = inst.encoding_name();
    let size: i64 = if w >> 31 == 1 { 64 } else { 32 };
    let immr = i64::from((w >> 16) & 0x3F);
    let imms = i64::from((w >> 10) & 0x3F);
    let num = |v: i64| {
        Some(Rendered {
            text: imm(v),
            default: v == 0,
        })
    };
    // A register offset's amount (LLVM's printMemExtend): with S set, the
    // log2 of the access size in bytes (#0 for bytes); without, none.
    if let Some(width) = sym.attr("memext")
        && sym.display == "<amount>"
    {
        let width: u32 = width.parse().unwrap_or(8);
        if raw(sym, w) == 1 {
            return Some(Rendered {
                text: format!("#{}", imm(i64::from((width / 8).trailing_zeros()))),
                default: false,
            });
        }
        return Some(Rendered {
            text: String::new(),
            default: true,
        });
    }
    // "it must be #0, encoded in "S" as 0 if omitted, or as 1 if present".
    if sym.has("present01") {
        let present = raw_value(sym, w) == 1;
        return Some(Rendered {
            text: if present { "#0".into() } else { String::new() },
            default: !present,
        });
    }
    // SVE shifts by immediate: tsz gives the element size, and the
    // amount is tsz:imm3 minus the element size (left shifts) or twice
    // the element size minus tsz:imm3 (right shifts).
    if sym.has("tsz")
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
            return num(amount);
        }
    }
    // ZERO { <mask> }.
    if sym.display == "<mask>" && inst.encoding_name().starts_with("zero_za_i") {
        return Some(Rendered {
            text: za_mask(raw(sym, w)),
            default: false,
        });
    }
    // Symbols with no encoding: "is the destination width specifier, H."
    // and "is the second slice index offset, with implicit value 1."
    if sym.encoded.is_empty() && sym.value.is_none() {
        if let Some(n) = sym.attr("implicit") {
            return Some(Rendered {
                text: n.to_string(),
                default: false,
            });
        }
        if let Some(s) = sym.attr("spec") {
            return Some(Rendered {
                text: s.to_ascii_lowercase(),
                default: false,
            });
        }
    }
    // AdvSIMD MOVI with 64-bit elements: each bit of a:b:c:d:e:f:g:h is a
    // byte of ones or zeros.
    if sym.has("bytemask") {
        let v = raw_value(sym, w);
        let mut out = 0u64;
        for i in 0..8 {
            if v >> i & 1 != 0 {
                out |= 0xFF << (8 * i);
            }
        }
        return Some(Rendered {
            text: imm(out as i64),
            default: false,
        });
    }
    // SVE multipliers: "in the range 1 to 16, defaulting to 1, encoded in
    // the imm4 field" (as the value minus one).
    if sym.has("mult16") {
        let v = raw_value(sym, w) as i64 + 1;
        return Some(Rendered {
            text: imm(v),
            default: v == 1,
        });
    }
    // SVE DUP (indexed): the index is above the lowest set bit of tsz.
    if sym.display == "<imm>"
        && sym.has("dupindex")
        && (name.starts_with("dup_z_zi") || name.starts_with("mov_z_zi__dup"))
    {
        {
            let v = raw_value(sym, w);
            let tsz = v & 0x1F;
            if tsz != 0 {
                return Some(Rendered {
                    text: format!("{}", v >> (tsz.trailing_zeros() + 1)),
                    default: false,
                });
            }
        }
    }
    let prefix = name.split('_').next().unwrap_or("");
    match (prefix, sym.display) {
        ("UBFX" | "SBFX" | "BFXIL", "<lsb>") => num(immr),
        ("UBFX" | "SBFX" | "BFXIL", "<width>") => num(imms + 1 - immr),
        ("UBFIZ" | "SBFIZ" | "BFI" | "BFC", "<lsb>") => num((-immr).rem_euclid(size)),
        ("UBFIZ" | "SBFIZ" | "BFI" | "BFC", "<width>") => num(imms + 1),
        ("LSL", "<shift>") if name.contains("UBFM") => num((-immr).rem_euclid(size)),
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
            num(v)
        }
        _ => None,
    }
}

/// Microsoft's names for x16, x17, x18, x29, and x30 (and their W forms),
/// applied to register tokens put together from parts (`<R><m>`).
fn ms_registers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        let name = match token.as_str() {
            "x16" => "xip0",
            "x17" => "xip1",
            "x18" => "xpr",
            "x29" => "fp",
            "x30" => "lr",
            "w16" => "wip0",
            "w17" => "wip1",
            "w18" => "wpr",
            "w29" => "wfp",
            "w30" => "wlr",
            other => other,
        };
        out.push_str(name);
        token.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// If `s` (just after a `(`) holds a top-level `|` before its closing
/// parenthesis, the index of that parenthesis.
fn alternation_end(s: &str) -> Option<usize> {
    let mut depth = 0;
    let mut bar = false;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '{' | '[' => depth += 1,
            ']' | '}' => depth -= 1,
            ')' if depth == 0 => return bar.then_some(i),
            ')' => depth -= 1,
            '|' if depth == 0 => bar = true,
            _ => {}
        }
    }
    None
}

/// Splits `s` at top-level occurrences of `sep`.
fn split_top(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            _ if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Microsoft's own mnemonics for some encodings.
fn ms_mnemonic(encoding: &str) -> Option<&'static str> {
    Some(match encoding {
        "EXT_asimdext_only" => "ext8",
        "movprfx_z_p_z_" => "moveprfx",
        "movprfx_z_z_" => "moveprfx",
        _ => return None,
    })
}

/// The value of a symbol's precise encoding (its `source=`), unscaled.
fn raw_value(sym: &Symbol, w: u32) -> u64 {
    match &sym.value {
        Some(v) => value(v.pieces, w),
        None => raw(sym, w),
    }
}

/// `VFPExpandImm`: an 8-bit floating-point immediate, as Microsoft shows
/// it (the shortest decimal).
fn fp_imm8(imm8: u64) -> String {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exp = (((imm8 >> 4) & 7) ^ 4) as i32 - 3;
    let mantissa = (16 + (imm8 & 0xF)) as f64 / 16.0;
    // 2^exp, exactly (exp is -3..=4), without libm's powi.
    let scale = f64::from_bits(((1023 + exp) as u64) << 52);
    format!("{}{VERBATIM}", sign * mantissa * scale)
}

/// Microsoft always shows the amount of an extend other than LSL:
/// `sxtw #0`, not `sxtw`.
fn extend_amounts(s: &str) -> String {
    const EXTENDS: [&str; 8] = [
        "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
    ];
    let mut out = String::with_capacity(s.len() + 4);
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
                }
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Marks text that `fix_numbers` must leave alone (floating-point values
/// that happen to be integers, such as `#27`).
const VERBATIM: char = '\u{3}';

/// Microsoft's spacing: a space between a shift or extend and its amount
/// (`sxtw #1`), and no `#0` offset in an addressing form (`[x0]!`).
fn ms_spacing(s: &str) -> String {
    let mut out = s.to_string();
    for kw in [
        "lsl", "lsr", "asr", "ror", "msl", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw",
        "sxtx",
    ] {
        out = out.replace(&format!("{kw}#"), &format!("{kw} #"));
    }
    out.replace(",#0]", "]")
}

/// Removes `,lsl #0` (but not `,lsl #0x20`).
fn drop_zero_lsl(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(",lsl #0") {
        let after = &rest[i + 7..];
        out.push_str(&rest[..i]);
        if after.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            out.push_str(",lsl #0");
        }
        rest = after;
    }
    out.push_str(rest);
    out
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
fn decimal_indexes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("[0x") {
        out.push_str(&rest[..=i]);
        rest = &rest[i + 1..];
        let hex: String = rest[2..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        if rest[2 + hex.len()..].starts_with(']')
            && let Ok(v) = u64::from_str_radix(&hex, 16)
        {
            out.push_str(&v.to_string());
            rest = &rest[2 + hex.len()..];
        }
    }
    out.push_str(rest);
    out
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

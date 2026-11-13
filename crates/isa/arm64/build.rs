//! Compiles `tables/a64.txt` (generated from AARCHMRS and LLVM by `tools/arm64/extract.py`) into decode
//! tables: encodings with their masks, constraints, UNDEFINED conditions,
//! alias preferences, assembler templates, and operand symbols.

#![allow(
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    reason = "a code generator and tools over small table values"
)]

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

#[derive(Default, Clone)]
struct Enc {
    name: String,
    class: String,
    mask: u32,
    value: u32,
    /// Should-be bits (Arm's `(0)`/`(1)`): not matched; when they differ,
    /// the encoding is CONSTRAINED UNPREDICTABLE.
    should_mask: u32,
    should_value: u32,
    fields: Vec<(String, u32, u32)>,
    not_equal: Vec<String>,
    asm: String,
    undef: Vec<String>,
    unpred: Vec<String>,
    feature: String,
    alias: Option<(String, String)>,
    file: usize,
}

#[derive(Default, Clone)]
struct Sym {
    link: String,
    display: String,
    encoded_in: String,
    table: Option<(Vec<String>, Vec<(Vec<String>, String)>)>,
    attrs: Vec<String>,
}

impl Sym {
    fn has(&self, a: &str) -> bool {
        self.attrs.iter().any(|x| x == a)
    }

    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find_map(|x| x.strip_prefix(key)?.strip_prefix('='))
    }
}

#[derive(Default)]
struct File {
    syms: Vec<Sym>,
}

fn parse(src: &str) -> (Vec<Enc>, Vec<File>) {
    let mut encs = Vec::new();
    let mut files: Vec<File> = Vec::new();
    for line in src.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("file ") {
            let _ = rest;
            files.push(File::default());
        } else if let Some(rest) = line.strip_prefix("enc ") {
            let mut parts = rest.split_whitespace();
            encs.push(Enc {
                name: parts.next().unwrap().to_string(),
                class: parts.next().unwrap_or("").to_string(),
                file: files.len() - 1,
                ..Enc::default()
            });
        } else if let Some(rest) = line.strip_prefix("  bits ") {
            let e = encs.last_mut().unwrap();
            for (i, c) in rest.trim().chars().enumerate() {
                let bit = 31 - i as u32;
                match c {
                    '0' => e.mask |= 1 << bit,
                    '1' => {
                        e.mask |= 1 << bit;
                        e.value |= 1 << bit;
                    }
                    'Z' => e.should_mask |= 1 << bit,
                    'O' => {
                        e.should_mask |= 1 << bit;
                        e.should_value |= 1 << bit;
                    }
                    _ => {}
                }
            }
        } else if let Some(rest) = line.strip_prefix("  fields ") {
            let e = encs.last_mut().unwrap();
            for f in rest.split_whitespace() {
                let (name, range) = f.split_once('=').unwrap();
                let (hi, lo) = match range.split_once(':') {
                    Some((h, l)) => (h.parse().unwrap(), l.parse().unwrap()),
                    None => {
                        let b: u32 = range.parse().unwrap();
                        (b, b)
                    }
                };
                e.fields.push((name.to_string(), hi, lo));
            }
        } else if let Some(rest) = line.strip_prefix("  ne ") {
            encs.last_mut().unwrap().not_equal.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("  asm ") {
            encs.last_mut().unwrap().asm = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("  undef ") {
            encs.last_mut().unwrap().undef.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("  unpred ") {
            encs.last_mut().unwrap().unpred.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("  feat ") {
            encs.last_mut().unwrap().feature = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("  alias ") {
            let (target, cond) = rest.split_once(" when ").unwrap_or((rest, ""));
            encs.last_mut().unwrap().alias = Some((target.to_string(), cond.to_string()));
        } else if let Some(rest) = line.strip_prefix("sym ") {
            let mut s = Sym::default();
            let (head, table) = match rest.split_once(" = ") {
                Some((h, t)) => (h, Some(t)),
                None => (rest, None),
            };
            let mut parts = head.splitn(3, ' ');
            s.link = parts.next().unwrap().to_string();
            s.display = parts.next().unwrap_or("").to_string();
            s.encoded_in = parts.next().unwrap_or("").to_string();
            if let Some(t) = table {
                let mut cells = t.split(" | ");
                let head: Vec<String> = cells
                    .next()
                    .unwrap()
                    .split(',')
                    .map(|c| c.trim().to_string())
                    .collect();
                let rows = cells
                    .filter_map(|r| {
                        let (vals, result) = r.split_once(':')?;
                        Some((
                            vals.split(',').map(|v| v.trim().to_string()).collect(),
                            result.trim().to_string(),
                        ))
                    })
                    .collect();
                s.table = Some((head, rows));
            }
            files.last_mut().unwrap().syms.push(s);
        } else if let Some(rest) = line.strip_prefix("  attr ")
            && let Some(s) = files.last_mut().and_then(|f| f.syms.last_mut())
        {
            // (`src=` says where the attributes came from.)
            s.attrs.extend(
                rest.split_whitespace()
                    .filter(|a| !a.starts_with("src="))
                    .map(str::to_string),
            );
        }
    }
    (encs, files)
}

// ---------------------------------------------------------------------------
// Bit sources: fields, slices, literals, concatenations.

/// A piece of a value: bits `hi..=lo` of the word, or literal bits.
#[derive(Clone, Debug, PartialEq)]
enum Piece {
    Bits(u32, u32),
    Lit(u64, u32),
}

/// Parses `a`, `a<1:0>`, `a[3]`, `'10'`, and `::`/`:` concatenations into
/// pieces, most significant first.
fn pieces(expr: &str, fields: &[(String, u32, u32)]) -> Option<Vec<Piece>> {
    let expr = expr.trim().trim_start_matches('(').trim_end_matches(')');
    let mut out = Vec::new();
    // Split at top-level `::` or `:` (not the `:` of a `[4:1]` slice).
    let parts: Vec<&str> = if expr.contains("::") {
        expr.split("::").collect()
    } else {
        let mut parts = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (i, c) in expr.char_indices() {
            match c {
                '[' | '<' => depth += 1,
                ']' | '>' => depth -= 1,
                ':' if depth == 0 => {
                    parts.push(&expr[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        parts.push(&expr[start..]);
        parts
    };
    for part in parts {
        let part = part.trim();
        if let Some(lit) = part.strip_prefix('\'').and_then(|p| p.strip_suffix('\'')) {
            let v = u64::from_str_radix(lit, 2).ok()?;
            out.push(Piece::Lit(v, lit.len() as u32));
            continue;
        }
        let (name, sel) = match part.find(['<', '[']) {
            Some(i) => (&part[..i], Some(&part[i + 1..part.len() - 1])),
            None => (part, None),
        };
        let &(_, hi, lo) = fields.iter().find(|(n, _, _)| n == name)?;
        match sel {
            None => out.push(Piece::Bits(hi, lo)),
            Some(sel) => {
                let (h, l) = match sel.split_once(':') {
                    Some((h, l)) => (h.parse::<u32>().ok()?, l.parse::<u32>().ok()?),
                    None => {
                        let b = sel.parse::<u32>().ok()?;
                        (b, b)
                    }
                };
                out.push(Piece::Bits(lo + h, lo + l));
            }
        }
    }
    Some(out)
}

fn pieces_code(p: &[Piece]) -> String {
    let mut s = String::from("&[");
    for piece in p {
        match piece {
            Piece::Bits(h, l) => {
                let _ = write!(s, "Piece::Bits({h},{l}),");
            }
            Piece::Lit(v, n) => {
                let _ = write!(s, "Piece::Lit({v},{n}),");
            }
        }
    }
    s.push(']');
    s
}

fn width(p: &[Piece]) -> u32 {
    p.iter()
        .map(|x| match x {
            Piece::Bits(h, l) => h - l + 1,
            Piece::Lit(_, n) => *n,
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Conditions: the ASL subset used in UNDEFINED checks and alias
// preferences, compiled to Rust.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Bits(String),
    Num(i64),
    Op(String),
}

pub fn lex(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' {
            let end = s[i + 1..].find('\'')? + i + 1;
            out.push(Tok::Bits(s[i + 1..end].replace(' ', "")));
            i = end + 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i] as char).is_ascii_digit() {
                i += 1;
            }
            out.push(Tok::Num(s[start..i].parse().ok()?));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() && ((b[i] as char).is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Ident(s[start..i].to_string()));
        } else {
            let two = s.get(i..i + 2).unwrap_or("");
            if ["==", "!=", "&&", "||", "<=", ">=", "::"].contains(&two) {
                out.push(Tok::Op(two.to_string()));
                i += 2;
            } else {
                out.push(Tok::Op(c.to_string()));
                i += 1;
            }
        }
    }
    Some(out)
}

/// A compiled expression: either a boolean, an integer, or a bit value of
/// known width.
enum Val {
    Bool(String),
    Int(String),
    Bits(String, u32),
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    fields: &'a [(String, u32, u32)],
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn eat(&mut self, op: &str) -> bool {
        if self.peek() == Some(&Tok::Op(op.to_string())) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, op: &str) -> Option<()> {
        self.eat(op).then_some(())
    }

    fn bool_of(v: Val) -> Option<String> {
        match v {
            Val::Bool(s) => Some(s),
            _ => None,
        }
    }

    fn or(&mut self) -> Option<Val> {
        let first = self.and()?;
        if !matches!(self.peek(), Some(Tok::Op(o)) if o == "||") {
            return Some(first);
        }
        let mut l = Self::bool_of(first)?;
        while self.eat("||") {
            let r = Self::bool_of(self.and()?)?;
            l = or_of(&l, &r);
        }
        Some(Val::Bool(l))
    }

    fn and(&mut self) -> Option<Val> {
        let first = self.cmp()?;
        if !matches!(self.peek(), Some(Tok::Op(o)) if o == "&&") {
            return Some(first);
        }
        let mut l = Self::bool_of(first)?;
        while self.eat("&&") {
            let r = Self::bool_of(self.cmp()?)?;
            l = and_of(&l, &r);
        }
        Some(Val::Bool(l))
    }

    fn cmp(&mut self) -> Option<Val> {
        let l = self.sum()?;
        let op = match self.peek() {
            Some(Tok::Op(o)) if ["==", "!=", "<", ">", "<=", ">="].contains(&o.as_str()) => {
                o.clone()
            }
            Some(Tok::Ident(i)) if i == "IN" => "IN".to_string(),
            _ => return Some(l),
        };
        self.pos += 1;
        if op == "IN" {
            self.expect("{")?;
            let mut alts = Vec::new();
            loop {
                match self.peek()?.clone() {
                    Tok::Bits(b) => {
                        self.pos += 1;
                        alts.push(b);
                    }
                    _ => return None,
                }
                if self.eat("}") {
                    break;
                }
                self.expect(",")?;
            }
            let Val::Bits(code, _) = l else { return None };
            let tests: Vec<String> = alts.iter().map(|b| bits_match(&code, b)).collect();
            return Some(Val::Bool(format!("({})", tests.join(" || "))));
        }
        // A bit pattern on the right of == or != may contain x.
        if let Some(Tok::Bits(b)) = self.peek().cloned() {
            self.pos += 1;
            let Val::Bits(code, _) = l else { return None };
            let m = bits_match(&code, &b);
            return Some(Val::Bool(match op.as_str() {
                "==" => m,
                "!=" => format!("!{m}"),
                _ => return None,
            }));
        }
        let r = self.sum()?;
        let as_int = |v: Val| match v {
            Val::Int(s) | Val::Bits(s, _) => Some(s),
            Val::Bool(_) => None,
        };
        let (l, r) = (as_int(l)?, as_int(r)?);
        Some(Val::Bool(format!("((({l}) as i64) {op} (({r}) as i64))")))
    }

    fn sum(&mut self) -> Option<Val> {
        let mut l = self.unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op(o)) if o == "+" || o == "-" => o.clone(),
                _ => return Some(l),
            };
            self.pos += 1;
            let r = self.unary()?;
            let li = match l {
                Val::Int(s) | Val::Bits(s, _) => s,
                Val::Bool(_) => return None,
            };
            let ri = match r {
                Val::Int(s) | Val::Bits(s, _) => s,
                Val::Bool(_) => return None,
            };
            l = Val::Int(format!("((({li}) as i64) {op} (({ri}) as i64))"));
        }
    }

    fn unary(&mut self) -> Option<Val> {
        if self.eat("!") {
            let v = Self::bool_of(self.unary()?)?;
            return Some(Val::Bool(not_of(&v)));
        }
        let mut v = self.primary()?;
        // Concatenation.
        while self.eat("::") {
            let r = self.primary()?;
            let (Val::Bits(a, wa), Val::Bits(b, wb)) = (v, r) else {
                return None;
            };
            v = Val::Bits(format!("((({a}) << {wb}) | ({b}))"), wa + wb);
        }
        Some(v)
    }

    fn primary(&mut self) -> Option<Val> {
        match self.peek()?.clone() {
            Tok::Op(o) if o == "(" => {
                self.pos += 1;
                let v = self.or()?;
                self.expect(")")?;
                Some(v)
            }
            Tok::Num(n) => {
                self.pos += 1;
                Some(Val::Int(format!("{n}i64")))
            }
            Tok::Bits(b) => {
                self.pos += 1;
                let v = u64::from_str_radix(&b.replace('x', "0"), 2).ok()?;
                Some(Val::Bits(format!("{v}u64"), b.len() as u32))
            }
            Tok::Ident(id) => {
                self.pos += 1;
                match id.as_str() {
                    "TRUE" => return Some(Val::Bool("true".into())),
                    "FALSE" => return Some(Val::Bool("false".into())),
                    _ => {}
                }
                if self.eat("(") {
                    return self.call(&id);
                }
                let &(_, hi, lo) = self.fields.iter().find(|(n, _, _)| *n == id)?;
                let (mut hi, mut lo) = (hi, lo);
                if self.eat("[") {
                    let Tok::Num(a) = self.peek()?.clone() else {
                        return None;
                    };
                    self.pos += 1;
                    let (h, l) = if self.eat(":") {
                        let Tok::Num(b) = self.peek()?.clone() else {
                            return None;
                        };
                        self.pos += 1;
                        (a as u32, b as u32)
                    } else {
                        (a as u32, a as u32)
                    };
                    self.expect("]")?;
                    hi = lo + h;
                    lo += l;
                }
                let n = hi - lo + 1;
                Some(Val::Bits(
                    format!("((w as u64 >> {lo}) & {:#x})", (1u64 << n) - 1),
                    n,
                ))
            }
            _ => None,
        }
    }

    /// A function call; the opening parenthesis has been consumed.
    fn call(&mut self, name: &str) -> Option<Val> {
        // Arguments, as compiled values (feature names are skipped).
        let mut args = Vec::new();
        if !self.eat(")") {
            loop {
                if let Some(Tok::Ident(id)) = self.peek().cloned()
                    && (id.starts_with("FEAT_") || name.starts_with("IsFeature"))
                {
                    self.pos += 1;
                    if self.eat(")") {
                        break;
                    }
                    self.expect(",")?;
                    continue;
                }
                args.push(self.or()?);
                if self.eat(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        let int = |v: &Val| match v {
            Val::Int(s) | Val::Bits(s, _) => Some(s.clone()),
            Val::Bool(_) => None,
        };
        let width = |v: &Val| match v {
            Val::Bits(_, w) => Some(*w),
            _ => None,
        };
        Some(match name {
            // We decode as if every feature is implemented, with the
            // largest vector lengths, and in Debug state (so that
            // Debug-only instructions such as DCPS3 decode).
            "IsFeatureImplemented"
            | "HaveEL"
            | "HaveSVE2FP8FMA"
            | "HaveSVE2FP8DOT4"
            | "HaveSVE2FP8DOT2" => Val::Bool("true".into()),
            "Halted" => Val::Bool("true".into()),
            "MaxImplementedVL" | "MaxImplementedSVL" | "MaxImplementedAnyVL" => {
                Val::Int("2048i64".into())
            }
            "UInt" => Val::Int(int(args.first()?)?),
            "IsZero" => Val::Bool(format!("({} == 0)", int(args.first()?)?)),
            "IsOnes" => {
                let w = width(args.first()?)?;
                Val::Bool(format!(
                    "({} == {:#x})",
                    int(args.first()?)?,
                    (1u64 << w) - 1
                ))
            }
            "BitCount" => Val::Int(format!(
                "(({}) as u64).count_ones() as i64",
                int(args.first()?)?
            )),
            "BFXPreferred" => Val::Bool(format!(
                "crate::alias::bfx_preferred({}, {}, {}, {})",
                int(&args[0])?,
                int(&args[1])?,
                int(&args[2])?,
                int(&args[3])?
            )),
            "MoveWidePreferred" => Val::Bool(format!(
                "crate::alias::move_wide_preferred({}, {}, {}, {})",
                int(&args[0])?,
                int(&args[1])?,
                int(&args[2])?,
                int(&args[3])?
            )),
            "SVEMoveMaskPreferred" => Val::Bool(format!(
                "crate::alias::sve_move_mask_preferred({})",
                int(&args[0])?
            )),
            "SysOp" => Val::Int(format!(
                "crate::alias::sys_op({}, {}, {}, {})",
                int(&args[0])?,
                int(&args[1])?,
                int(&args[2])?,
                int(&args[3])?
            )),
            _ => return None,
        })
    }
}

/// A condition's constant value, if it is `true` or `false` (in
/// parentheses or not). Conditions fold as they are built: features are
/// all implemented (see `call`), so many are constant, and the decoder
/// shouldn't test what can't vary.
fn literal(s: &str) -> Option<bool> {
    let mut t = s.trim();
    while t.starts_with('(') && t.ends_with(')') && balanced(&t[1..t.len() - 1]) {
        t = t[1..t.len() - 1].trim();
    }
    match t {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Whether `s`'s parentheses balance (so that one around it encloses it).
fn balanced(s: &str) -> bool {
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn or_of(l: &str, r: &str) -> String {
    match (literal(l), literal(r)) {
        (Some(true), _) | (_, Some(true)) => "true".into(),
        (Some(false), _) => r.into(),
        (_, Some(false)) => l.into(),
        _ => format!("({l} || {r})"),
    }
}

fn and_of(l: &str, r: &str) -> String {
    match (literal(l), literal(r)) {
        (Some(false), _) | (_, Some(false)) => "false".into(),
        (Some(true), _) => r.into(),
        (_, Some(true)) => l.into(),
        _ => format!("({l} && {r})"),
    }
}

fn not_of(v: &str) -> String {
    match literal(v) {
        Some(b) => (!b).to_string(),
        None => format!("!{v}"),
    }
}

/// Conditions, any of which holds: none if each is `false`; `true` if one
/// is.
fn any_of(conds: Vec<String>) -> Option<String> {
    let live: Vec<String> = conds
        .into_iter()
        .filter(|c| literal(c) != Some(false))
        .collect();
    if live.is_empty() {
        None
    } else if live.iter().any(|c| literal(c) == Some(true)) {
        Some("true".into())
    } else {
        Some(live.join(" || "))
    }
}

/// Rust code testing that `code` matches the bit pattern `b` (with x).
fn bits_match(code: &str, b: &str) -> String {
    let n = b.len();
    let mut mask = 0u64;
    let mut val = 0u64;
    for (i, c) in b.chars().enumerate() {
        let bit = n - 1 - i;
        match c {
            '0' => mask |= 1 << bit,
            '1' => {
                mask |= 1 << bit;
                val |= 1 << bit;
            }
            _ => {}
        }
    }
    format!("((({code}) & {mask:#x}) == {val:#x})")
}

/// Compiles a condition; `None` if it uses something unsupported.
pub fn condition(src: &str, fields: &[(String, u32, u32)]) -> Option<String> {
    match src.trim() {
        "Never" => return Some("false".into()),
        "Unconditionally" | "" => return Some("true".into()),
        _ => {}
    }
    // `SysOp(...) == Sys_AT` and friends compare against named constants.
    let src = src
        .replace("Sys_AT", "1")
        .replace("Sys_DC", "2")
        .replace("Sys_IC", "3")
        .replace("Sys_TLBI", "4")
        .replace("Sys_SYS", "0");
    let toks = lex(&src)?;
    let mut p = Parser {
        toks,
        pos: 0,
        fields,
    };
    let v = p.or()?;
    if p.pos != p.toks.len() {
        return None;
    }
    Parser::bool_of(v)
}

// ---------------------------------------------------------------------------
// Operand values, from the symbols' attributes (which come from LLVM's
// operand types; see tools/arm64/extract.py).

#[derive(Default)]
struct Value {
    pieces: Vec<Piece>,
    mul: i64,
    add: i64,
    modulo: i64,
    /// `N minus field`: the value is `N - field`.
    sub_from: Option<i64>,
    signed: bool,
}

fn attr_value(sym: &Sym, fields: &[(String, u32, u32)]) -> Option<Value> {
    let num = |k: &str| sym.attr(k).and_then(|v| v.parse::<i64>().ok());
    let mut v = Value {
        // (`source=` overrides the encoded-in bits: a strided list's first
        // register, `T:'0':Zt`.)
        pieces: pieces(sym.attr("source").unwrap_or(&sym.encoded_in), fields)?,
        mul: num("mul").or_else(|| num("regmul")).unwrap_or(1),
        add: num("add").unwrap_or(0),
        modulo: num("mod").unwrap_or(0),
        sub_from: num("subfrom"),
        signed: sym.has("signed"),
    };
    // The later registers of a list (`<Zn2>`, `<Vn+1>`) are encoded by the
    // first's field: the next ones, wrapping (or, for an aligned list, the
    // next ones of an aligned group).
    let name = sym.display.trim_matches(['<', '>']);
    let offset = if let Some((_, k)) = name.split_once('+') {
        k.parse::<i64>().ok()
    } else {
        name.chars()
            .last()
            .and_then(|c| c.to_digit(10))
            .filter(|&d| (2..=4).contains(&d))
            .map(|d| i64::from(d) - 1)
    };
    if let Some(k) = offset
        && name.starts_with(['Z', 'V', 'P'])
        && sym.attr("add").is_none()
    {
        if let Some(step) = num("regstep") {
            // Strided: {z0, z8}, {z0, z4, z8, z12}.
            v.add = k * step;
        } else {
            v.add = k;
            if num("regmul").is_none() {
                v.modulo = if name.starts_with('P') { 16 } else { 32 };
            }
        }
    }
    Some(v)
}

/// Entries per chunk of a large table (see [`chunked`]).
const CHUNK: usize = 256;

/// Writes `items` (one per line, `n` of them) as the table `name`: in
/// statics of `CHUNK` entries, and `name` the list of them, indexed by
/// `src/tables.rs` (`name[i / CHUNK][i % CHUNK]`). One static of tens of
/// thousands of entries takes rustc minutes to type-check (its time grows
/// faster than the entries); small ones take seconds in all.
fn chunked(code: &mut String, name: &str, ty: &str, items: &str, n: usize) {
    let lines: Vec<&str> = items.lines().collect();
    assert_eq!(lines.len(), n, "{name}: one entry per line");
    let chunks: Vec<&[&str]> = lines.chunks(CHUNK).collect();
    for (k, c) in chunks.iter().enumerate() {
        let _ = writeln!(
            code,
            "static {name}_{k}: [{ty}; {}] = [\n{}\n];",
            c.len(),
            c.join("\n")
        );
    }
    let list: Vec<String> = (0..chunks.len()).map(|k| format!("&{name}_{k}")).collect();
    let _ = writeln!(
        code,
        "pub(crate) static {name}: [&[{ty}]; {}] = [{}];",
        chunks.len(),
        list.join(", ")
    );
    let _ = writeln!(code, "pub(crate) const {name}_CHUNK: usize = {CHUNK};");
    let _ = writeln!(code, "pub(crate) const {name}_LEN: usize = {n};");
}

fn main() {
    let path = Path::new("tables/a64.txt");
    println!("cargo:rerun-if-changed={}", path.display());
    let src = std::fs::read_to_string(path).unwrap();
    let (encs, files) = parse(&src);

    let mut code = String::new();
    let mut warnings = Vec::new();

    // Symbols, numbered globally.
    let mut sym_out = String::new();
    let mut n_syms = 0usize;
    // Symbols are compiled per encoding (their fields differ by class), so
    // index them by (file, link) and compile with the first encoding's
    // fields that uses them.
    // A symbol is compiled once per field layout that uses it: the
    // encodings of a file can place the same field at different bits.
    let fields_key = |f: &[(String, u32, u32)]| format!("{f:?}");
    let mut uses: BTreeMap<(usize, String, String), Vec<(String, u32, u32)>> = BTreeMap::new();
    for e in &encs {
        let mut rest = e.asm.as_str();
        while let Some(i) = rest.find("%{") {
            let end = rest[i..].find('}').unwrap() + i;
            uses.entry((e.file, rest[i + 2..end].to_string(), fields_key(&e.fields)))
                .or_insert_with(|| e.fields.clone());
            rest = &rest[end + 1..];
        }
    }
    let mut sym_by_use: HashMap<(usize, String, String), usize> = HashMap::new();
    for ((fi, link, key), fields) in &uses {
        let Some(s) = files[*fi].syms.iter().find(|s| &s.link == link) else {
            continue;
        };
        let fields = fields.as_slice();
        {
            sym_by_use.insert((*fi, link.clone(), key.clone()), n_syms);
            n_syms += 1;
            // The source bits.
            let value = if s.table.is_none() {
                attr_value(s, fields)
            } else {
                None
            };
            let encoded = pieces(&s.encoded_in, fields).unwrap_or_default();
            let table = match &s.table {
                Some((head, rows)) => {
                    let cols: Vec<String> = head
                        .iter()
                        .map(|c| {
                            pieces(c, fields).map_or_else(
                                || {
                                    warnings.push(format!("table column {c} in {}", s.link));
                                    "&[]".to_string()
                                },
                                |p| pieces_code(&p),
                            )
                        })
                        .collect();
                    let rows: Vec<String> = rows
                        .iter()
                        .map(|(vals, r)| {
                            let vals: Vec<String> = vals.iter().map(|v| format!("{v:?}")).collect();
                            // Results such as "UInt(H :: L :: M)" are computed.
                            let (expr, mul, add) = table_expr(r, fields).unwrap_or_default();
                            format!(
                                "(&[{}], {r:?}, {}, {mul}, {add})",
                                vals.join(","),
                                pieces_code(&expr)
                            )
                        })
                        .collect();
                    format!(
                        "Some(&Table {{ cols: &[{}], rows: &[{}] }})",
                        cols.join(","),
                        rows.join(",")
                    )
                }
                None => "None".into(),
            };
            let value = match value {
                Some(v) => format!(
                    "Some(Value {{ pieces: {}, width: {}, mul: {}, add: {}, modulo: {}, sub_from: {}, signed: {} }})",
                    pieces_code(&v.pieces),
                    width(&v.pieces),
                    v.mul,
                    v.add,
                    v.modulo,
                    v.sub_from.unwrap_or(0),
                    v.signed
                ),
                None => "None".into(),
            };
            // `when=option<0>=0`: the symbol applies only when those bits
            // have that value (another alternative applies otherwise).
            let when = s
                .attr("when")
                .and_then(|t| t.rsplit_once('='))
                .and_then(|(f, v)| {
                    let p = pieces(f, fields)?;
                    let value = u64::from_str_radix(v, 2).ok()?;
                    Some(format!("Some(({}, {value}))", pieces_code(&p)))
                })
                .unwrap_or_else(|| "None".to_string());
            let _ = writeln!(
                sym_out,
                "    Symbol {{ display: {:?}, encoded: {}, table: {table}, value: {value}, when: {when}, attrs: {:?} }},",
                s.display,
                pieces_code(&encoded),
                s.attrs.join(" ")
            );
        }
    }

    // Encodings.
    let by_name: HashMap<&str, usize> = encs
        .iter()
        .enumerate()
        .map(|(i, e)| (e.name.as_str(), i))
        .collect();
    let mut fns = String::new();
    let mut enc_out = String::new();
    let mut n_fns = 0;
    for e in &encs {
        // Constraints.
        let mut ne = Vec::new();
        for c in &e.not_equal {
            let (lhs, bits) = c.split_once("!=").unwrap();
            let p = match lhs.split_once(':') {
                Some((h, l)) => vec![Piece::Bits(h.parse().unwrap(), l.parse().unwrap())],
                None => pieces(lhs, &e.fields).unwrap_or_default(),
            };
            if let [Piece::Bits(h, l)] = p[..] {
                let mut mask = 0u32;
                let mut val = 0u32;
                for (i, ch) in bits.chars().enumerate() {
                    let bit = h - i as u32;
                    if bit < l {
                        break;
                    }
                    match ch {
                        '0' => mask |= 1 << bit,
                        '1' => {
                            mask |= 1 << bit;
                            val |= 1 << bit;
                        }
                        _ => {}
                    }
                }
                ne.push(format!("({mask:#x},{val:#x})"));
            }
        }
        // UNDEFINED conditions.
        let mut undef_fn = "None".to_string();
        let mut conds = Vec::new();
        for u in &e.undef {
            match condition(u, &e.fields) {
                Some(c) => conds.push(c),
                None => warnings.push(format!("undef in {}: {u}", e.name)),
            }
        }
        if let Some(c) = any_of(conds) {
            let _ = writeln!(
                fns,
                "#[allow(unused_parens, unused_variables, clippy::all, clippy::pedantic)]\nfn cond_{n_fns}(w: u32) -> bool {{ {c} }}"
            );
            undef_fn = format!("Some(cond_{n_fns})");
            n_fns += 1;
        }
        // CONSTRAINED UNPREDICTABLE conditions.
        let mut unpred_fn = "None".to_string();
        let conds: Vec<String> = e
            .unpred
            .iter()
            .filter_map(|u| condition(u, &e.fields))
            .collect();
        if let Some(c) = any_of(conds) {
            let _ = writeln!(
                fns,
                "#[allow(unused_parens, unused_variables, clippy::all, clippy::pedantic)]
fn cond_{n_fns}(w: u32) -> bool {{ {c} }}"
            );
            unpred_fn = format!("Some(cond_{n_fns})");
            n_fns += 1;
        }
        // Alias.
        let (alias_of, prefer) = match &e.alias {
            Some((target, cond)) => {
                let target = by_name.get(target.as_str()).copied();
                let pref = match condition(cond, &e.fields) {
                    Some(c) => {
                        let _ = writeln!(
                            fns,
                            "#[allow(unused_parens, unused_variables, clippy::all, clippy::pedantic)]\nfn cond_{n_fns}(w: u32) -> bool {{ {c} }}"
                        );
                        n_fns += 1;
                        format!("Some(cond_{})", n_fns - 1)
                    }
                    None => {
                        warnings.push(format!("alias in {}: {cond}", e.name));
                        "None".into()
                    }
                };
                (target.map_or("NONE".to_string(), |t| t.to_string()), pref)
            }
            None => ("NONE".to_string(), "None".into()),
        };
        // The template, with symbols as indexes into SYMBOLS.
        let listed = comma_lists(&e.asm, &files[e.file].syms, &e.name);
        let mut asm = String::new();
        let mut rest = listed.as_str();
        while let Some(i) = rest.find("%{") {
            asm.push_str(&rest[..i]);
            let end = rest[i..].find('}').unwrap() + i;
            let link = &rest[i + 2..end];
            match sym_by_use.get(&(e.file, link.to_string(), fields_key(&e.fields))) {
                Some(n) => {
                    let _ = write!(asm, "%{n}%");
                }
                None => {
                    warnings.push(format!("symbol {link} in {}", e.name));
                    asm.push('?');
                }
            }
            rest = &rest[end + 1..];
        }
        asm.push_str(rest);
        // Register-list braces have spaces inside ("{ <Zt1>.B-<Zt2>.B }");
        // optional groups do not. Mark the list braces so the formatter
        // prints them literally.
        let asm = mark_list_braces(&asm);
        let _ = writeln!(
            enc_out,
            "    Encoding {{ name: {:?}, class: {:?}, feature: {:?}, mask: {:#010x}, value: {:#010x}, should: ({:#010x}, {:#010x}), ne: &[{}], undef: {undef_fn}, unpred: {unpred_fn}, alias_of: {alias_of}, prefer: {prefer}, asm: {asm:?} }},",
            e.name,
            e.class,
            e.feature,
            e.mask,
            e.value,
            e.should_mask,
            e.should_value,
            ne.join(",")
        );
    }

    // A first-level index on bits 31:21 (and 13:10 within groups too large
    // to scan): each bucket lists the encodings that can match.
    let mut buckets: Vec<Vec<u16>> = vec![Vec::new(); 2048];
    for (i, e) in encs.iter().enumerate() {
        let m = e.mask >> 21;
        let v = e.value >> 21;
        for b in 0..2048u32 {
            if b & m == v {
                buckets[b as usize].push(i as u16);
            }
        }
    }
    let mut bucket_out = String::new();
    for b in &buckets {
        let ids: Vec<String> = b.iter().map(u16::to_string).collect();
        let _ = writeln!(bucket_out, "    &[{}],", ids.join(","));
    }

    let _ = writeln!(code, "pub(crate) const NONE: u16 = u16::MAX;");
    chunked(&mut code, "ENCODINGS", "Encoding", &enc_out, encs.len());
    chunked(&mut code, "SYMBOLS", "Symbol", &sym_out, n_syms);
    let _ = writeln!(
        code,
        "pub(crate) static BUCKETS: [&[u16]; 2048] = [\n{bucket_out}];"
    );
    code.push_str(&fns);

    // System register names, by op0:op1:CRn:CRm:op2.
    let sysregs_path = Path::new("tables/sysregs.txt");
    println!("cargo:rerun-if-changed={}", sysregs_path.display());
    let mut sysregs: Vec<(u32, String)> = std::fs::read_to_string(sysregs_path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            let n = |i: usize| p.get(i)?.parse::<u32>().ok();
            let key = n(0)? << 14 | n(1)? << 11 | n(2)? << 7 | n(3)? << 3 | n(4)?;
            Some((key, p.get(5)?.to_string()))
        })
        .collect();
    sysregs.sort();
    sysregs.dedup_by_key(|e| e.0);
    let _ = writeln!(
        code,
        "pub(crate) static SYSREGS: [(u32, &str); {}] = [",
        sysregs.len()
    );
    for (k, n) in &sysregs {
        let _ = writeln!(code, "    ({k:#x}, {n:?}),");
    }
    let _ = writeln!(code, "];");

    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("tables.rs");
    std::fs::write(out, code).unwrap();
    let report = Path::new(&std::env::var("OUT_DIR").unwrap()).join("warnings.txt");
    std::fs::write(report, warnings.join("\n")).unwrap();
}

/// A table result that is a computed value: `UInt(<pieces>)`, optionally
/// plus or minus a constant.
fn table_expr(r: &str, fields: &[(String, u32, u32)]) -> Option<(Vec<Piece>, i64, i64)> {
    let r = r.trim();
    // "64 - UInt(immh:immb)".
    if let Some((n, rest)) = r.split_once(" - UInt(") {
        let n: i64 = n.trim().parse().ok()?;
        let inner = rest.strip_suffix(')')?;
        return Some((pieces(inner, fields)?, -1, n));
    }
    let start = r.find("UInt(")?;
    let end = start + r[start..].find(')')?;
    let inner = &r[start + 5..end];
    let p = pieces(inner, fields)?;
    let rest = r[end + 1..].trim();
    let add = if let Some(n) = rest.strip_prefix('+') {
        n.trim().parse().ok()?
    } else if let Some(n) = rest.strip_prefix('-') {
        -n.trim().parse::<i64>().ok()?
    } else if rest.is_empty() {
        0
    } else {
        return None;
    };
    if start != 0 {
        return None;
    }
    Some((p, 1, add))
}

/// Marks register-list braces ("{ <Zt1>.B-<Zt2>.B }") as \u{1} and \u{2},
/// leaving optional groups ("{, <shift>}", "{ <amount>}") alone: a list's
/// closing brace has a space before it.
fn mark_list_braces(asm: &str) -> String {
    let chars: Vec<char> = asm.chars().collect();
    let mut out = chars.clone();
    for (i, &c) in chars.iter().enumerate() {
        if c != '{' || chars.get(i + 1) != Some(&' ') {
            continue;
        }
        let mut depth = 0;
        for j in i..chars.len() {
            match chars[j] {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if chars[j - 1] == ' ' {
                            out[i] = '\u{1}';
                            out[j] = '\u{2}';
                            // Drop the spaces inside the braces.
                            out[i + 1] = '\u{0}';
                            out[j - 1] = '\u{0}';
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out.into_iter().filter(|&c| c != '\u{0}').collect()
}

/// Microsoft writes a register list as a range ("{z0.d-z1.d}") when its
/// first register is aligned to the list's length (encoded "times 2"), and
/// as a list ("{z2.s,z3.s}") when any register can start it.
fn comma_lists(asm: &str, syms: &[Sym], name: &str) -> String {
    // (Except for the multiply-long-long forms, which Microsoft writes as
    // ranges.)
    if name.contains("mlall") || name.contains("mlsll") {
        return asm.to_string();
    }
    let mut out = String::new();
    let mut rest = asm;
    while let Some(i) = rest.find("{ %{") {
        out.push_str(&rest[..i]);
        let Some(close) = rest[i..].find(" }") else {
            // Not a register list (`{ %{amount}}`): the rest as it is.
            rest = &rest[i..];
            break;
        };
        let list = &rest[i..i + close];
        let first = list[4..].split('}').next().unwrap_or("");
        let aligned = syms
            .iter()
            .find(|s| s.link == first)
            .is_some_and(|s| s.has("aligned") || s.table.is_some());
        // Only two-register lists ("<Zn1>-<Zn2>", not "<Zn1>-<Zn4>") are
        // written with a comma.
        let last = list
            .split("-%{")
            .nth(1)
            .and_then(|s| s.split('}').next())
            .unwrap_or("");
        let two = syms
            .iter()
            .find(|s| s.link == last)
            .is_some_and(|s| s.display.trim_end_matches('>').ends_with('2'));
        if aligned || !two || !list.contains("-%{") {
            out.push_str(list);
        } else {
            out.push_str(&list.replace("-%{", ", %{"));
        }
        rest = &rest[i + close..];
    }
    out.push_str(rest);
    out
}

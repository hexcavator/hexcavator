//! WPA's filter queries (a preset's `InitialFilterQuery`, WPA's "filter
//! to selection" box): conditions on a table's columns, joined.
//!
//! - A condition: `[Column]` (a name in brackets), an operator, a value
//!   (`"quoted"`, with `""` for a quote, or a bare word): `:=` equal,
//!   `:<>` not equal, `:~=` contains, `:~<` starts with, `:~>` ends with,
//!   `:&=` (a number) has any of these bits, `:<`, `:<=`, `:>`, `:>=`.
//!   Text compares without case; a number compares as a number when both
//!   sides read as one (decimal, or hexadecimal with `0x`).
//! - Conditions side by side (or with `AND`) must all hold; `OR` between
//!   them, either; `NOT` before one, it mustn't; parentheses group.

use std::cmp::Ordering;

/// A query: conditions, joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// All of these.
    All(Vec<Query>),
    /// Any of these.
    Any(Vec<Query>),
    /// Not this.
    Not(Box<Query>),
    /// A condition on a column.
    Is {
        /// The column's name.
        column: String,
        /// How it's compared.
        op: Op,
        /// What with.
        value: String,
    },
}

/// A comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `:=`
    Equal,
    /// `:<>`
    NotEqual,
    /// `:~=`
    Contains,
    /// `:~<`
    StartsWith,
    /// `:~>`
    EndsWith,
    /// `:&=`
    AnyBits,
    /// `:<`
    Less,
    /// `:<=`
    LessOrEqual,
    /// `:>`
    Greater,
    /// `:>=`
    GreaterOrEqual,
}

/// A column's value in a row.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    /// Text.
    Text(String),
    /// A number.
    Number(f64),
}

impl Query {
    /// Reads a query.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut p = Parser {
            s: text.as_bytes(),
            pos: 0,
            depth: 0,
        };
        let q = p.any()?;
        p.space();
        if p.pos < p.s.len() {
            return Err(format!("unexpected '{}' at {}", p.rest(), p.pos));
        }
        Ok(q)
    }

    /// The columns it names, each once, in order.
    pub fn columns(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.each_column(&mut out);
        out
    }

    fn each_column<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Self::All(qs) | Self::Any(qs) => qs.iter().for_each(|q| q.each_column(out)),
            Self::Not(q) => q.each_column(out),
            Self::Is { column, .. } => {
                if !out.contains(&column.as_str()) {
                    out.push(column);
                }
            }
        }
    }

    /// Whether a row holds it: `cell` gives a column's value (none: the
    /// row has nothing there, which only `:<>` holds for).
    pub fn holds(&self, cell: &dyn Fn(&str) -> Option<Cell>) -> bool {
        match self {
            Self::All(qs) => qs.iter().all(|q| q.holds(cell)),
            Self::Any(qs) => qs.iter().any(|q| q.holds(cell)),
            Self::Not(q) => !q.holds(cell),
            Self::Is { column, op, value } => match cell(column) {
                None => *op == Op::NotEqual,
                Some(c) => compare(&c, *op, value),
            },
        }
    }
}

/// A number's value: decimal (with a fraction, a sign), or `0x` hex.
fn number(s: &str) -> Option<f64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok().map(|v| v as f64);
    }
    t.replace(',', "").parse().ok()
}

/// A whole number's bits: decimal or `0x` hex.
fn bits(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => t.replace(',', "").parse().ok(),
    }
}

fn compare(cell: &Cell, op: Op, value: &str) -> bool {
    let text = match cell {
        Cell::Text(t) => t.clone(),
        Cell::Number(n) => n.to_string(),
    };
    let order = || -> Option<Ordering> {
        match (cell, number(value)) {
            (Cell::Number(n), Some(v)) => n.partial_cmp(&v),
            (Cell::Text(t), Some(v)) if number(t).is_some() => number(t)?.partial_cmp(&v),
            _ => Some(text.to_lowercase().cmp(&value.to_lowercase())),
        }
    };
    let (t, v) = (text.to_lowercase(), value.to_lowercase());
    match op {
        Op::Equal => order() == Some(Ordering::Equal),
        Op::NotEqual => order() != Some(Ordering::Equal),
        Op::Contains => t.contains(&v),
        Op::StartsWith => t.starts_with(&v),
        Op::EndsWith => t.ends_with(&v),
        Op::AnyBits => match (bits(&text), bits(value)) {
            (Some(a), Some(b)) => a & b != 0,
            _ => false,
        },
        Op::Less => order() == Some(Ordering::Less),
        Op::LessOrEqual => matches!(order(), Some(Ordering::Less | Ordering::Equal)),
        Op::Greater => order() == Some(Ordering::Greater),
        Op::GreaterOrEqual => matches!(order(), Some(Ordering::Greater | Ordering::Equal)),
    }
}

/// How deeply parentheses may nest.
const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn rest(&self) -> String {
        String::from_utf8_lossy(&self.s[self.pos..(self.pos + 12).min(self.s.len())]).into_owned()
    }

    fn space(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// The keyword `word` (any case, then a non-word character), taken.
    fn keyword(&mut self, word: &str) -> bool {
        self.space();
        let end = self.pos + word.len();
        let ok = self
            .s
            .get(self.pos..end)
            .is_some_and(|w| w.eq_ignore_ascii_case(word.as_bytes()))
            && self
                .s
                .get(end)
                .is_none_or(|c| !c.is_ascii_alphanumeric() && *c != b'_');
        if ok {
            self.pos = end;
        }
        ok
    }

    fn any(&mut self) -> Result<Query, String> {
        let mut terms = vec![self.all()?];
        while self.keyword("OR") || self.symbol("||") {
            terms.push(self.all()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Query::Any(terms)
        })
    }

    fn symbol(&mut self, sym: &str) -> bool {
        self.space();
        let ok = self.s[self.pos..].starts_with(sym.as_bytes());
        if ok {
            self.pos += sym.len();
        }
        ok
    }

    fn all(&mut self) -> Result<Query, String> {
        let mut factors = vec![self.factor()?];
        loop {
            if self.keyword("AND") || self.symbol("&&") {
                factors.push(self.factor()?);
                continue;
            }
            self.space();
            // (Side by side: another condition, a group, or NOT.)
            let save = self.pos;
            if matches!(self.s.get(self.pos), Some(b'[' | b'(')) || self.keyword("NOT") {
                self.pos = save;
                factors.push(self.factor()?);
                continue;
            }
            break;
        }
        Ok(if factors.len() == 1 {
            factors.remove(0)
        } else {
            Query::All(factors)
        })
    }

    fn factor(&mut self) -> Result<Query, String> {
        if self.keyword("NOT") || self.symbol("!") {
            return Ok(Query::Not(Box::new(self.factor()?)));
        }
        self.space();
        match self.s.get(self.pos) {
            Some(b'(') => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err("parentheses nest too deeply".into());
                }
                self.pos += 1;
                let q = self.any()?;
                if !self.symbol(")") {
                    return Err(format!("expected ')' at {}", self.pos));
                }
                self.depth -= 1;
                Ok(q)
            }
            Some(b'[') => self.condition(),
            None => Err("expected a condition at the end".into()),
            Some(_) => Err(format!(
                "expected a condition at {}: '{}'",
                self.pos,
                self.rest()
            )),
        }
    }

    fn condition(&mut self) -> Result<Query, String> {
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.s.len() && self.s[self.pos] != b']' {
            self.pos += 1;
        }
        if self.pos >= self.s.len() {
            return Err("a column's name has no ']'".into());
        }
        let column = String::from_utf8_lossy(&self.s[start..self.pos])
            .trim()
            .to_string();
        self.pos += 1;
        self.space();
        const OPS: [(&str, Op); 10] = [
            (":<>", Op::NotEqual),
            (":<=", Op::LessOrEqual),
            (":>=", Op::GreaterOrEqual),
            (":~=", Op::Contains),
            (":~<", Op::StartsWith),
            (":~>", Op::EndsWith),
            (":&=", Op::AnyBits),
            (":=", Op::Equal),
            (":<", Op::Less),
            (":>", Op::Greater),
        ];
        let op = OPS
            .iter()
            .find(|(t, _)| self.s[self.pos..].starts_with(t.as_bytes()))
            .ok_or_else(|| format!("[{column}]: expected an operator at {}", self.pos))?;
        self.pos += op.0.len();
        let value = self.value()?;
        Ok(Query::Is {
            column,
            op: op.1,
            value,
        })
    }

    fn value(&mut self) -> Result<String, String> {
        self.space();
        if self.s.get(self.pos) == Some(&b'"') {
            self.pos += 1;
            let mut out = Vec::new();
            loop {
                match self.s.get(self.pos) {
                    None => return Err("a quoted value has no end".into()),
                    Some(b'"') if self.s.get(self.pos + 1) == Some(&b'"') => {
                        out.push(b'"');
                        self.pos += 2;
                    }
                    Some(b'"') => {
                        self.pos += 1;
                        break;
                    }
                    Some(&c) => {
                        out.push(c);
                        self.pos += 1;
                    }
                }
            }
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        let start = self.pos;
        while self.pos < self.s.len()
            && !self.s[self.pos].is_ascii_whitespace()
            && !matches!(self.s[self.pos], b')' | b'(' | b'[')
        {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(format!("expected a value at {}", self.pos));
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }
}

//! The query language's parser (see the crate's documentation).

use crate::{Column, Error, Expr, Kind, Literal, Op, Query, SortKey};

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    /// A word: a keyword, a column, or a bare value.
    Word(String),
    /// A quoted string.
    Quoted(String),
    Op(Op),
    Open,
    Close,
    Comma,
}

fn lex(text: &str) -> Result<Vec<(usize, Tok)>, Error> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let start = i;
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'(' => {
                out.push((i, Tok::Open));
                i += 1;
            }
            b')' => {
                out.push((i, Tok::Close));
                i += 1;
            }
            b',' => {
                out.push((i, Tok::Comma));
                i += 1;
            }
            b'\'' | b'"' => {
                let Some(len) = text[i + 1..].find(c as char) else {
                    return Err(Error {
                        at: i,
                        message: "a string with no closing quote".into(),
                    });
                };
                out.push((i, Tok::Quoted(text[i + 1..i + 1 + len].to_string())));
                i += len + 2;
            }
            b'=' | b'!' | b'<' | b'>' | b'~' => {
                let two = b.get(i + 1).copied();
                let (op, len) = match (c, two) {
                    (b'!', Some(b'=')) => (Op::Ne, 2),
                    (b'!', Some(b'~')) => (Op::NotMatch, 2),
                    (b'<', Some(b'=')) => (Op::Le, 2),
                    (b'>', Some(b'=')) => (Op::Ge, 2),
                    (b'=', Some(b'=')) => (Op::Eq, 2),
                    (b'=', _) => (Op::Eq, 1),
                    (b'<', _) => (Op::Lt, 1),
                    (b'>', _) => (Op::Gt, 1),
                    (b'~', _) => (Op::Match, 1),
                    _ => {
                        return Err(Error {
                            at: i,
                            message: "'!' needs '=' or '~' after it".into(),
                        });
                    }
                };
                out.push((start, Tok::Op(op)));
                i += len;
            }
            _ => {
                while i < b.len() && !b" \t\r\n(),'\"=!<>~".contains(&b[i]) {
                    i += 1;
                }
                out.push((start, Tok::Word(text[start..i].to_string())));
            }
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<(usize, Tok)>,
    pos: usize,
    end: usize,
    columns: &'a [Column],
    /// How deeply parentheses and `not`s nest here, and how many
    /// comparisons there have been: both bounded, so that parsing, and
    /// evaluating and dropping the expression, recurse a bounded depth.
    nesting: u32,
    terms: u32,
}

/// The most parentheses and `not`s an expression may nest.
const MAX_NESTING: u32 = 16;
/// The most comparisons a filter may have.
const MAX_TERMS: u32 = 1024;

const CLAUSES: [&str; 4] = ["group", "sort", "limit", "select"];

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.1)
    }

    fn at(&self) -> usize {
        self.toks.get(self.pos).map_or(self.end, |t| t.0)
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T, Error> {
        Err(Error {
            at: self.at(),
            message: message.into(),
        })
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x.eq_ignore_ascii_case(w))
    }

    fn eat_word(&mut self, w: &str) -> bool {
        let yes = self.is_word(w);
        if yes {
            self.pos += 1;
        }
        yes
    }

    fn at_clause(&self) -> bool {
        CLAUSES.iter().any(|c| self.is_word(c))
    }

    fn column(&mut self) -> Result<usize, Error> {
        let Some(Tok::Word(w)) = self.peek().cloned() else {
            return self.err("a column name");
        };
        match self
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(&w))
        {
            Some(i) => {
                self.pos += 1;
                Ok(i)
            }
            None => self.err(format!(
                "no column '{w}' (the columns are {})",
                self.columns
                    .iter()
                    .map(|c| c.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    fn or(&mut self) -> Result<Expr, Error> {
        let mut any = vec![self.and()?];
        while self.eat_word("or") {
            any.push(self.and()?);
        }
        Ok(if any.len() == 1 {
            any.remove(0)
        } else {
            Expr::Or(any)
        })
    }

    fn and(&mut self) -> Result<Expr, Error> {
        let mut all = vec![self.unary()?];
        loop {
            if self.eat_word("and") {
                all.push(self.unary()?);
                continue;
            }
            // Juxtaposition is `and`, up to `or`, `)`, a clause, or the end.
            match self.peek() {
                None | Some(Tok::Close) => break,
                _ if self.is_word("or") || self.at_clause() => break,
                _ => all.push(self.unary()?),
            }
        }
        Ok(if all.len() == 1 {
            all.remove(0)
        } else {
            Expr::And(all)
        })
    }

    fn unary(&mut self) -> Result<Expr, Error> {
        let nested = self.is_word("not") || self.peek() == Some(&Tok::Open);
        if nested {
            if self.nesting >= MAX_NESTING {
                return self.err(format!(
                    "at most {MAX_NESTING} nested parentheses and 'not's"
                ));
            }
            self.nesting += 1;
            let e = self.nested();
            self.nesting -= 1;
            return e;
        }
        self.terms += 1;
        if self.terms > MAX_TERMS {
            return self.err(format!("at most {MAX_TERMS} comparisons"));
        }
        self.comparison()
    }

    /// `not` and its operand, or a parenthesized expression.
    fn nested(&mut self) -> Result<Expr, Error> {
        if self.eat_word("not") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.pos += 1;
        let e = self.or()?;
        if self.peek() != Some(&Tok::Close) {
            return self.err("a ')'");
        }
        self.pos += 1;
        Ok(e)
    }

    /// `column op value`, or a true-or-false column.
    fn comparison(&mut self) -> Result<Expr, Error> {
        let at = self.at();
        let column = self.column()?;
        let col = self.columns[column];
        let Some(Tok::Op(op)) = self.peek().cloned() else {
            if col.kind == Kind::Bool {
                return Ok(Expr::Is(column));
            }
            return self.err(format!(
                "an operator after '{}' (=, !=, <, <=, >, >=, ~, !~)",
                col.name
            ));
        };
        self.pos += 1;
        let vat = self.at();
        let text = match self.peek().cloned() {
            Some(Tok::Word(w)) => w,
            Some(Tok::Quoted(q)) => q,
            _ => return self.err(format!("a value to compare '{}' with", col.name)),
        };
        self.pos += 1;
        let bad = |message: String| Err(Error { at: vat, message });
        let value = match (op, col.kind) {
            (Op::Match | Op::NotMatch, Kind::Str) => match regex::Regex::new(&text) {
                Ok(re) => Literal::Regex(re),
                Err(e) => return bad(format!("not a regular expression: {e}")),
            },
            (Op::Match | Op::NotMatch, _) => {
                return Err(Error {
                    at,
                    message: format!("'{}' is not text: ~ and !~ match text", col.name),
                });
            }
            (_, Kind::Int) => match number(&text) {
                Some(n) => Literal::Int(n),
                None => return bad(format!("'{}' is a number: '{text}' is not one", col.name)),
            },
            (_, Kind::Bool) => match text.to_ascii_lowercase().as_str() {
                "true" => Literal::Bool(true),
                "false" => Literal::Bool(false),
                _ => {
                    return bad(format!(
                        "'{}' is true or false: '{text}' is neither",
                        col.name
                    ));
                }
            },
            (_, Kind::Str) => Literal::Str(text),
        };
        Ok(Expr::Cmp { column, op, value })
    }

    fn list<T>(
        &mut self,
        mut one: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let mut out = vec![one(self)?];
        while self.peek() == Some(&Tok::Comma) {
            self.pos += 1;
            out.push(one(self)?);
        }
        Ok(out)
    }
}

/// A number: decimal or `0x` hexadecimal, with `k`, `M`, or `G` for 1024s.
fn number(text: &str) -> Option<u64> {
    let (digits, scale) = match text.as_bytes().last()? {
        b'k' | b'K' => (&text[..text.len() - 1], 1u64 << 10),
        b'm' | b'M' => (&text[..text.len() - 1], 1 << 20),
        b'g' | b'G' => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    let n = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => digits.parse().ok()?,
    };
    n.checked_mul(scale)
}

/// Parses `text` as a query over `columns`.
pub fn parse(text: &str, columns: &[Column]) -> Result<Query, Error> {
    let mut p = Parser {
        toks: lex(text)?,
        pos: 0,
        end: text.len(),
        columns,
        nesting: 0,
        terms: 0,
    };
    let mut q = Query::default();
    if p.peek().is_some() && !p.at_clause() {
        q.filter = Some(p.or()?);
    }
    while p.peek().is_some() {
        if p.eat_word("group") {
            if !p.eat_word("by") {
                return p.err("'by' after 'group'");
            }
            q.group = p.list(Parser::column)?;
        } else if p.eat_word("sort") {
            if !p.eat_word("by") {
                return p.err("'by' after 'sort'");
            }
            q.sort = p.list(|p| {
                let Some(Tok::Word(w)) = p.peek().cloned() else {
                    return p.err("a column to sort by");
                };
                p.pos += 1;
                let descending = if p.eat_word("desc") {
                    true
                } else {
                    p.eat_word("asc");
                    false
                };
                Ok(SortKey {
                    column: w,
                    descending,
                })
            })?;
        } else if p.eat_word("select") {
            q.select = p.list(Parser::column)?;
        } else if p.eat_word("limit") {
            let Some(Tok::Word(w)) = p.peek().cloned() else {
                return p.err("a number after 'limit'");
            };
            let Some(n) = number(&w).and_then(|n| usize::try_from(n).ok()) else {
                return p.err(format!("'{w}' is not a number"));
            };
            p.pos += 1;
            q.limit = Some(n);
        } else if p.peek() == Some(&Tok::Close) {
            return p.err("a ')' with no '('");
        } else {
            return p.err(
                "'group by', 'sort by', 'select', or 'limit' (or 'and' or 'or' to join filters)",
            );
        }
    }
    if !q.group.is_empty() && !q.select.is_empty() {
        return Err(Error {
            at: 0,
            message: "'select' and 'group by' don't go together: grouping shows its keys, count, and sums".into(),
        });
    }
    Ok(q)
}

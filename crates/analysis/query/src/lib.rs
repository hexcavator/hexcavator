//! A small query language over tables of facts about an image (its
//! symbols, say), shared by the command line, the MCP server, and editors.
//!
//! ```text
//! kind=function file>1k name~'^std::' group by library sort by file desc limit 10
//! ```
//!
//! A query is a filter, then clauses in any order:
//!
//! - The filter: comparisons `column op value`, joined by `and` (or just a
//!   space), `or`, and `not`, grouped with parentheses. The operators are
//!   `=`, `!=`, `<`, `<=`, `>`, `>=`, and `~` / `!~` (a regular
//!   expression, matched anywhere: `name~'^std::'`). A boolean column
//!   alone is a test (`folded`, `not folded`). Values are numbers (with
//!   `k`, `M`, or `G` for 1024s: `4k`), strings in quotes (`'a b'` or
//!   `"a b"`), or bare words (`function`), and `true` or `false`.
//! - `group by a, b`: one row per distinct `a, b`, with `count` and the
//!   sum of each summable column (sizes).
//! - `sort by a [asc|desc], ...`: by the output's columns (`count`, and
//!   the sums, when grouping).
//! - `select a, b`: the columns to show (without grouping).
//! - `limit n`: at most `n` rows.
//!
//! Column names are a table's ([`Table::columns`]); keywords and names are
//! case-insensitive, string comparisons case-sensitive (regular
//! expressions take `(?i)`).

#![warn(missing_docs)]

use std::borrow::Cow;
use std::cmp::Ordering;

mod parse;

pub use parse::parse;

/// What a column holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Unsigned integers (sizes, addresses, counts).
    Int,
    /// Text.
    Str,
    /// True or false.
    Bool,
}

/// A column of a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    /// Its name, as queries spell it.
    pub name: &'static str,
    /// What it holds.
    pub kind: Kind,
    /// Whether grouping sums it (a size).
    pub summable: bool,
    /// What it is, for help.
    pub doc: &'static str,
}

/// A value of a cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// An integer.
    Int(u64),
    /// Text.
    Str(Cow<'a, str>),
    /// True or false.
    Bool(bool),
    /// Unknown (a compiland a symbol has none of, say).
    Null,
}

impl Value<'_> {
    /// The value, owning its string.
    pub fn into_owned(self) -> Value<'static> {
        match self {
            Value::Int(n) => Value::Int(n),
            Value::Str(s) => Value::Str(Cow::Owned(s.into_owned())),
            Value::Bool(b) => Value::Bool(b),
            Value::Null => Value::Null,
        }
    }

    /// The value as text, as a table shows it (`-` for unknown).
    pub fn text(&self) -> Cow<'_, str> {
        match self {
            Value::Int(n) => Cow::Owned(n.to_string()),
            Value::Str(s) => Cow::Borrowed(s),
            Value::Bool(b) => Cow::Borrowed(if *b { "true" } else { "false" }),
            Value::Null => Cow::Borrowed("-"),
        }
    }

    /// An order: unknown first, then by value (strings bytewise).
    fn order(&self, other: &Value<'_>) -> Ordering {
        let rank = |v: &Value<'_>| match v {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Int(_) => 2,
            Value::Str(_) => 3,
        };
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a.cmp(b),
            (Value::Str(a), Value::Str(b)) => a.cmp(b),
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            _ => rank(self).cmp(&rank(other)),
        }
    }
}

/// A table to query: rows of cells, by column index.
pub trait Table {
    /// Its columns.
    fn columns(&self) -> &[Column];
    /// How many rows it has.
    fn rows(&self) -> usize;
    /// The cell at `row` of `column` (both indexes).
    fn cell(&self, row: usize, column: usize) -> Value<'_>;
}

/// A comparison's operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `=`.
    Eq,
    /// `!=`.
    Ne,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `~`: matches a regular expression.
    Match,
    /// `!~`: doesn't.
    NotMatch,
}

/// A filter.
#[derive(Clone, Debug)]
pub enum Expr {
    /// All of them (two or more: a list, so that a long chain is shallow).
    And(Vec<Expr>),
    /// Any of them.
    Or(Vec<Expr>),
    /// Not this.
    Not(Box<Expr>),
    /// A column compared with a value.
    Cmp {
        /// The column's index.
        column: usize,
        /// How it is compared.
        op: Op,
        /// With what.
        value: Literal,
    },
    /// A boolean column, true.
    Is(usize),
}

/// A value in a query.
#[derive(Clone, Debug)]
pub enum Literal {
    /// An integer.
    Int(u64),
    /// Text.
    Str(String),
    /// True or false.
    Bool(bool),
    /// A regular expression (for `~` and `!~`).
    Regex(regex::Regex),
}

/// A sort key: an output column, and whether descending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SortKey {
    /// The output column's name.
    pub column: String,
    /// Largest first.
    pub descending: bool,
}

/// A parsed query.
#[derive(Clone, Debug, Default)]
pub struct Query {
    /// Which rows to keep (all, if none).
    pub filter: Option<Expr>,
    /// Columns to group by (indexes into the table's columns).
    pub group: Vec<usize>,
    /// How to order the output.
    pub sort: Vec<SortKey>,
    /// Columns to show, when not grouping (all, if empty).
    pub select: Vec<usize>,
    /// Rows to show at most.
    pub limit: Option<usize>,
}

/// A query's result: its columns' names, and rows of values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The columns' names.
    pub columns: Vec<String>,
    /// The rows.
    pub rows: Vec<Vec<Value<'static>>>,
    /// The rows the filter kept (before grouping and the limit).
    pub matched: usize,
}

/// An error in a query: what, and where (a byte offset into it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Where in the query (a byte offset).
    pub at: usize,
    /// What's wrong.
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (at offset {})", self.message, self.at)
    }
}

impl std::error::Error for Error {}

fn eval(expr: &Expr, table: &dyn Table, row: usize) -> bool {
    match expr {
        Expr::And(all) => all.iter().all(|e| eval(e, table, row)),
        Expr::Or(any) => any.iter().any(|e| eval(e, table, row)),
        Expr::Not(a) => !eval(a, table, row),
        Expr::Is(c) => table.cell(row, *c) == Value::Bool(true),
        Expr::Cmp { column, op, value } => {
            let cell = table.cell(row, *column);
            match (value, &cell) {
                (Literal::Regex(re), Value::Str(s)) => re.is_match(s) == (*op == Op::Match),
                (Literal::Regex(_), _) => *op == Op::NotMatch,
                (_, Value::Null) => *op == Op::Ne,
                (Literal::Int(n), Value::Int(v)) => compare(v.cmp(n), *op),
                (Literal::Str(s), Value::Str(v)) => compare(v.as_ref().cmp(s.as_str()), *op),
                (Literal::Bool(b), Value::Bool(v)) => compare(v.cmp(b), *op),
                _ => *op == Op::Ne,
            }
        }
    }
}

fn compare(o: Ordering, op: Op) -> bool {
    match op {
        Op::Eq => o == Ordering::Equal,
        Op::Ne => o != Ordering::Equal,
        Op::Lt => o == Ordering::Less,
        Op::Le => o != Ordering::Greater,
        Op::Gt => o == Ordering::Greater,
        Op::Ge => o != Ordering::Less,
        Op::Match | Op::NotMatch => false,
    }
}

/// Runs `query` over `table`.
pub fn run(query: &Query, table: &dyn Table) -> Result<Output, Error> {
    let cols = table.columns();
    let kept: Vec<usize> = (0..table.rows())
        .filter(|&r| query.filter.as_ref().is_none_or(|f| eval(f, table, r)))
        .collect();
    let matched = kept.len();
    let (columns, mut rows): (Vec<String>, Vec<Vec<Value<'static>>>) = if query.group.is_empty() {
        let shown: Vec<usize> = if query.select.is_empty() {
            (0..cols.len()).collect()
        } else {
            query.select.clone()
        };
        (
            shown.iter().map(|&c| cols[c].name.to_string()).collect(),
            kept.iter()
                .map(|&r| {
                    shown
                        .iter()
                        .map(|&c| table.cell(r, c).into_owned())
                        .collect()
                })
                .collect(),
        )
    } else {
        let sums: Vec<usize> = (0..cols.len())
            .filter(|&c| cols[c].summable && cols[c].kind == Kind::Int)
            .collect();
        // Group by the keys' values: sort the rows by them, then fold runs.
        let key = |r: usize| -> Vec<Value<'_>> {
            query.group.iter().map(|&c| table.cell(r, c)).collect()
        };
        let mut order = kept.clone();
        order.sort_by(|&a, &b| {
            key(a)
                .iter()
                .zip(key(b).iter())
                .map(|(x, y)| x.order(y))
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        });
        let mut rows: Vec<Vec<Value<'static>>> = Vec::new();
        let mut last: Option<Vec<Value<'_>>> = None;
        for r in order {
            let k = key(r);
            if last.as_ref() != Some(&k) {
                let mut row: Vec<Value<'static>> =
                    k.iter().cloned().map(Value::into_owned).collect();
                row.push(Value::Int(0));
                row.extend(sums.iter().map(|_| Value::Int(0)));
                rows.push(row);
                last = Some(k);
            }
            let row = rows.last_mut().expect("a row per group");
            let g = query.group.len();
            if let Value::Int(n) = &mut row[g] {
                *n += 1;
            }
            for (i, &c) in sums.iter().enumerate() {
                if let (Value::Int(total), Value::Int(v)) = (&mut row[g + 1 + i], table.cell(r, c))
                {
                    *total += v;
                }
            }
        }
        let mut names: Vec<String> = query
            .group
            .iter()
            .map(|&c| cols[c].name.to_string())
            .collect();
        names.push("count".to_string());
        names.extend(sums.iter().map(|&c| cols[c].name.to_string()));
        (names, rows)
    };
    // Sorting: by the keys given, or, when grouping, the first sum (else
    // the count), largest first.
    let mut keys: Vec<(usize, bool)> = Vec::new();
    for k in &query.sort {
        let i = columns
            .iter()
            .position(|c| c.eq_ignore_ascii_case(&k.column))
            .ok_or_else(|| Error {
                at: 0,
                message: format!(
                    "can't sort by '{}': the output's columns are {}",
                    k.column,
                    columns.join(", ")
                ),
            })?;
        keys.push((i, k.descending));
    }
    if keys.is_empty() && !query.group.is_empty() {
        let g = query.group.len();
        keys.push((if columns.len() > g + 1 { g + 1 } else { g }, true));
    }
    if !keys.is_empty() {
        rows.sort_by(|a, b| {
            keys.iter()
                .map(|&(i, desc)| {
                    let o = a[i].order(&b[i]);
                    if desc { o.reverse() } else { o }
                })
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        });
    }
    if let Some(n) = query.limit {
        rows.truncate(n);
    }
    Ok(Output {
        columns,
        rows,
        matched,
    })
}

#[cfg(test)]
mod tests;

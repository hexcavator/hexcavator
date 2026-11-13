//! Types for the generated decode tables (see `build.rs`).

#![allow(clippy::unreadable_literal)]

/// Bits of the instruction word, or literal bits.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Piece {
    Bits(u32, u32),
    Lit(u64, u32),
}

/// The value of concatenated pieces, most significant first.
pub(crate) fn value(pieces: &[Piece], w: u32) -> u64 {
    let mut v = 0u64;
    for p in pieces {
        match *p {
            Piece::Bits(hi, lo) => {
                let n = hi - lo + 1;
                v = (v << n) | ((u64::from(w) >> lo) & ((1u64 << n) - 1));
            }
            Piece::Lit(bits, n) => v = (v << n) | bits,
        }
    }
    v
}

pub(crate) fn width(pieces: &[Piece]) -> u32 {
    pieces
        .iter()
        .map(|p| match *p {
            Piece::Bits(hi, lo) => hi - lo + 1,
            Piece::Lit(_, n) => n,
        })
        .sum()
}

pub(crate) struct Encoding {
    pub name: &'static str,
    pub class: &'static str,
    /// The architecture feature the encoding needs, such as `FEAT_SVE2`.
    pub feature: &'static str,
    pub mask: u32,
    pub value: u32,
    /// Should-be bits (Arm's `(0)` and `(1)`): `(mask, value)`. Not
    /// matched: when they differ, the instruction is CONSTRAINED
    /// UNPREDICTABLE, not UNDEFINED.
    pub should: (u32, u32),
    /// `(mask, value)` pairs the word must not match.
    pub ne: &'static [(u32, u32)],
    pub undef: Option<fn(u32) -> bool>,
    /// When the encoding is CONSTRAINED UNPREDICTABLE.
    pub unpred: Option<fn(u32) -> bool>,
    /// For aliases: the index of the encoding this stands for.
    pub alias_of: u16,
    /// For aliases: when to prefer the alias.
    pub prefer: Option<fn(u32) -> bool>,
    pub asm: &'static str,
}

/// A table row: a pattern per column, the result text, and for computed
/// results ("UInt(H:L:M)"), the bits and `mul * bits + add`.
pub(crate) type Row = (
    &'static [&'static str],
    &'static str,
    &'static [Piece],
    i64,
    i64,
);

/// A table mapping field values to text.
pub(crate) struct Table {
    pub cols: &'static [&'static [Piece]],
    pub rows: &'static [Row],
}

/// How a symbol's number is computed from its field(s).
pub(crate) struct Value {
    pub pieces: &'static [Piece],
    pub width: u32,
    pub mul: i64,
    pub add: i64,
    pub modulo: i64,
    /// If non-zero, the value is `sub_from - field`.
    pub sub_from: i64,
    pub signed: bool,
}

impl Value {
    pub fn eval(&self, w: u32) -> i64 {
        let raw = value(self.pieces, w);
        let mut v = if self.signed && self.width > 0 && self.width < 64 {
            let shift = 64 - self.width;
            ((raw << shift) as i64) >> shift
        } else {
            raw as i64
        };
        if self.sub_from != 0 {
            v = self.sub_from - v;
        }
        v = v * self.mul + self.add;
        if self.modulo != 0 {
            v = v.rem_euclid(self.modulo);
        }
        v
    }
}

pub(crate) struct Symbol {
    /// `<Wd|WSP>`, `<T>`, `<imm>`, ...
    pub display: &'static str,
    /// The bits the symbol is encoded in.
    pub encoded: &'static [Piece],
    pub table: Option<&'static Table>,
    pub value: Option<Value>,
    /// The symbol applies only when these bits have this value.
    pub when: Option<(&'static [Piece], u64)>,
    /// What the operand is, beyond its display name and value: `fp8`,
    /// `bitmask`, `page`, `implicit=1`, ... (space-separated; see
    /// tools/arm64/extract.py, which takes them from LLVM's operand types).
    pub attrs: &'static str,
}

impl Symbol {
    /// Whether the symbol has attribute `a`.
    pub fn has(&self, a: &str) -> bool {
        self.attrs.split(' ').any(|x| x == a)
    }

    /// The value of attribute `key=value`.
    pub fn attr(&self, key: &str) -> Option<&'static str> {
        self.attrs
            .split(' ')
            .find_map(|x| x.strip_prefix(key)?.strip_prefix('='))
    }
}

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

// (The large tables are in chunks, which rustc type-checks in seconds
// where one array takes minutes: see build.rs's `chunked`.)

/// The encoding at `i`.
#[inline]
pub(crate) fn encoding(i: usize) -> &'static Encoding {
    &ENCODINGS[i / ENCODINGS_CHUNK][i % ENCODINGS_CHUNK]
}

/// The symbol at `i`.
#[inline]
pub(crate) fn symbol(i: usize) -> &'static Symbol {
    &SYMBOLS[i / SYMBOLS_CHUNK][i % SYMBOLS_CHUNK]
}

/// Every encoding, in order.
pub(crate) fn encodings() -> impl Iterator<Item = &'static Encoding> {
    ENCODINGS.iter().flat_map(|c| c.iter())
}

/// How many encodings there are.
#[allow(dead_code, reason = "for tests and tools")]
pub(crate) const fn encoding_count() -> usize {
    ENCODINGS_LEN
}

/// How many symbols there are.
#[allow(dead_code, reason = "for tests and tools")]
pub(crate) const fn symbol_count() -> usize {
    SYMBOLS_LEN
}

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

pub(crate) struct Encoding {
    pub name: &'static str,
    /// The instruction class (an index into `CLASSES`).
    pub class: u8,
    /// The architecture feature the encoding needs, such as `FEAT_SVE2` (an
    /// index into `FEATURES`).
    pub feature: u8,
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
    /// The template compiled (see build.rs's `tokens`): the mnemonic, the
    /// operands, and the condition operand folded into the mnemonic (a
    /// symbol, or `NONE`).
    pub mnem: &'static [Tok],
    pub ops: &'static [Tok],
    pub cond: u16,
    /// Whether a word can fail to render (some symbol of the template has
    /// a table, a condition, or a logical immediate): if not, every word
    /// that matches renders.
    pub checked: bool,
    /// The first encoding with this one's name (an encoding can be in
    /// parts, one per operand layout).
    pub group: u16,
    /// For aliases: where Microsoft's preference differs from ARM's (an
    /// [`ms`] constant).
    pub ms: u8,
    /// Whether Microsoft keeps a space before the register of a
    /// post-indexed structure load or store ("[x2], x0").
    pub post_index: bool,
    /// Which of Microsoft's formatting rules applies (a [`rule`] constant).
    pub rule: u8,
}

/// Microsoft's formatting rules for particular encodings (build.rs's
/// `ms_rule`; see format.rs's `render_parts`).
pub(crate) mod rule {
    /// None.
    pub const NONE: u8 = 0;
    /// MOV (bitmask immediate): MOV or MOVI.
    pub const MOV_ORR: u8 = 1;
    /// ORR (immediate): MOV or MOVI from the zero register.
    pub const ORR_IMM: u8 = 2;
    /// LSR (immediate): `lsl #0` when the shift is zero.
    pub const LSR_UBFM: u8 = 3;
    /// UBFX (64-bit): UXTB, UXTH, UXTW.
    pub const UBFX_64: u8 = 4;
    /// ADD/SUB (shifted register): a zero LSL kept with the zero register.
    pub const ADD_SUB_SHIFT: u8 = 5;
    /// EXT: Microsoft's `ext8`.
    pub const EXT8: u8 = 6;
    /// MOVPRFX: Microsoft's `moveprfx`.
    pub const MOVEPRFX: u8 = 7;
}

/// Microsoft's own mnemonic for an encoding, where it has one.
pub(crate) fn ms_mnemonic(e: &Encoding) -> Option<&'static str> {
    match e.rule {
        rule::EXT8 => Some("ext8"),
        rule::MOVEPRFX => Some("moveprfx"),
        _ => None,
    }
}

/// Where Microsoft's disassembler prefers an alias differently from ARM
/// (build.rs's `ms_preference`).
pub(crate) mod ms {
    /// As ARM's description says.
    pub const ARM: u8 = 0;
    /// Never (ARM prefers it; Microsoft does not use it).
    pub const NOT_PREFERRED: u8 = 1;
    /// CINC and CINV: where Rn is Rm, and not the zero register.
    pub const CINC: u8 = 2;
    /// CNEG: where Rn is Rm.
    pub const CNEG: u8 = 3;
    /// CSET and CSETM: where Rn and Rm are the zero register.
    pub const CSET: u8 = 4;
}

/// A piece of a compiled template.
#[derive(Debug)]
pub(crate) enum Tok {
    /// Text, as shown.
    Lit(&'static str),
    /// A symbol, by index.
    Sym(u16),
    /// `{...}`: left out when every symbol in it is a default (and it has
    /// symbols, or is `, #0`: `optional`).
    Group(&'static [Tok], bool),
}

/// A table row: the mask and value it matches over the table's key, the
/// result text, for computed results ("UInt(H:L:M)") the bits and
/// `mul * bits + add`, and for results shown as they are, the text shown
/// and whether it is a default (see build.rs's `shown_as_is`).
pub(crate) type Row = (
    u64,
    u64,
    &'static str,
    &'static [Piece],
    i64,
    i64,
    Option<(&'static str, bool)>,
);

/// A table mapping field values to text: the first row matching the key
/// (the table's columns side by side).
pub(crate) struct Table {
    pub key: &'static [Piece],
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
    /// The attributes in [`attr`], as flags.
    pub flags: u32,
    /// How it shows, where it has no table and is not special.
    pub kind: Kind,
}

/// How a symbol without a table shows (worked out from its display name by
/// build.rs's `symbol_kind`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    /// The second register of a pair, `<X(t+1)>` (64-bit if true).
    Pair(bool),
    /// A general-purpose register where 31 is the stack pointer.
    GprSp(bool),
    /// A general-purpose register where 31 is the zero register.
    Gpr(bool),
    /// A register or number shown as this prefix and the decimal number
    /// (`v`, `z`, `p`, `za`, `C`; nothing for lane indexes).
    Reg(&'static str),
    /// A predicate-as-counter register (`pn8` for 0 with `pn8`).
    Pn,
    /// A register number after a `<R>` or `<V>` prefix symbol.
    Num,
    /// A branch target.
    Label,
    /// A logical immediate.
    Bitmask,
    /// A system register.
    #[expect(
        dead_code,
        reason = "no symbol is shown as <systemreg>: system registers show by number (S3_0_C4_C2_2), never by name"
    )]
    SysReg,
    /// Any other number: an immediate.
    Imm,
}

impl Symbol {
    /// Whether the symbol has attribute `a` (an [`attr`] flag).
    #[inline]
    pub fn has(&self, a: u32) -> bool {
        self.flags & a != 0
    }

    /// The value of attribute `key=value`.
    pub fn attr(&self, key: &str) -> Option<&'static str> {
        self.attrs
            .split(' ')
            .find_map(|x| x.strip_prefix(key)?.strip_prefix('='))
    }
}

/// The attributes the formatter tests, as flags (build.rs's `ATTR_FLAGS`,
/// in the same order): an attribute `a` or `a=value`.
pub(crate) mod attr {
    pub const ORIMM: u32 = 1 << 0;
    pub const LSLSP: u32 = 1 << 1;
    pub const FP8: u32 = 1 << 2;
    pub const X30: u32 = 1 << 3;
    pub const ZR31: u32 = 1 << 4;
    pub const PN8: u32 = 1 << 5;
    pub const PAGE: u32 = 1 << 6;
    pub const BITMASK: u32 = 1 << 7;
    pub const MEMEXT: u32 = 1 << 8;
    pub const PRESENT01: u32 = 1 << 9;
    pub const TSZ: u32 = 1 << 10;
    pub const BYTEMASK: u32 = 1 << 11;
    pub const MULT16: u32 = 1 << 12;
    pub const DUPINDEX: u32 = 1 << 13;
    pub const ADD: u32 = 1 << 14;
    /// Not an attribute: build.rs sets it where format.rs's `special` may
    /// apply.
    pub const MAY_SPECIAL: u32 = 1 << 15;
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

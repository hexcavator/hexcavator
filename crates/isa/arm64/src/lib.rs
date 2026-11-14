//! AArch64 (ARM64) instruction decoder and formatter.
//!
//! The decode tables are generated from Arm's Machine Readable
//! Specification (AARCHMRS) and LLVM's AArch64 target (see
//! `tables/a64.txt` and `tools/arm64/extract.py`): every encoding with its
//! fixed bits, constraints, UNDEFINED conditions, alias preferences, and
//! assembler template. Output follows the Microsoft
//! disassembler's syntax (`dumpbin /disasm`).

#![no_std]
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#![warn(missing_docs)]

extern crate alloc;

mod alias;
mod format;
mod tables;

pub use format::{Symbols, format, format_into, format_with};

use tables::{BUCKETS, Encoding, NONE, encoding, ms};

/// A decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    word: u32,
    address: u64,
    encoding: u16,
}

impl Instruction {
    /// The instruction's word.
    #[inline]
    pub fn word(&self) -> u32 {
        self.word
    }

    /// Its address.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The encoding's name in ARM's ISA description, such as
    /// `ADD_64_addsub_imm`.
    #[inline]
    pub fn encoding_name(&self) -> &'static str {
        self.encoding().name
    }

    /// The instruction class: `general`, `float`, `advsimd`, `sve`, ...
    #[inline]
    pub fn class(&self) -> &'static str {
        self.encoding().class
    }

    /// The architecture feature the instruction needs, such as `FEAT_SVE2`
    /// (empty for the base instruction set).
    #[inline]
    pub fn feature(&self) -> &'static str {
        self.encoding().feature
    }

    /// Whether the encoding is CONSTRAINED UNPREDICTABLE (such as a
    /// load pair with writeback into one of its registers). Microsoft
    /// marks these with a `?` before the mnemonic.
    /// So are words whose should-be bits (Arm's `(0)` and `(1)`) differ.
    pub fn is_unpredictable(&self) -> bool {
        let e = self.encoding();
        let unpredictable =
            |e: &Encoding| e.unpred.is_some_and(|f| f(self.word)) || !should_hold(e, self.word);
        unpredictable(e) || (e.alias_of != NONE && unpredictable(encoding(usize::from(e.alias_of))))
    }

    /// Whether the word's should-be bits (Arm's `(0)` and `(1)`) are as
    /// the encoding has them. When they aren't, the instruction is
    /// CONSTRAINED UNPREDICTABLE: decoded (and marked), not rejected.
    pub fn should_bits_hold(&self) -> bool {
        let e = self.encoding();
        should_hold(e, self.word)
            && (e.alias_of == NONE || should_hold(encoding(usize::from(e.alias_of)), self.word))
    }

    fn encoding(&self) -> &'static Encoding {
        encoding(usize::from(self.encoding))
    }
}

/// Whether a word's should-be bits are as the encoding would have them.
fn should_hold(e: &Encoding, w: u32) -> bool {
    w & e.should.0 == e.should.1
}

fn matches(e: &Encoding, w: u32) -> bool {
    w & e.mask == e.value && e.ne.iter().all(|&(m, v)| w & m != v) && !e.undef.is_some_and(|f| f(w))
}

/// Decodes the instruction `word` at `address`, or `None` if it is not a
/// valid (allocated, defined) encoding.
pub fn decode(word: u32, address: u64) -> Option<Instruction> {
    let candidates = BUCKETS[(word >> 21) as usize];
    // The base encoding: the most specific match that is not an alias,
    // among those whose should-be bits hold, else (CONSTRAINED
    // UNPREDICTABLE) among those whose don't.
    let best = |exact: bool| {
        let mut base: Option<u16> = None;
        for &i in candidates {
            let e = encoding(usize::from(i));
            if e.alias_of != NONE || !matches(e, word) || should_hold(e, word) != exact {
                continue;
            }
            let better = base.is_none_or(|b| {
                let b = encoding(usize::from(b));
                e.mask.count_ones() + e.should.0.count_ones()
                    > b.mask.count_ones() + b.should.0.count_ones()
            });
            if better {
                base = Some(i);
            }
        }
        base
    };
    let base = best(true).or_else(|| best(false))?;
    // A preferred alias of it, if any.
    let mut chosen = base;
    for &i in candidates {
        let e = encoding(usize::from(i));
        // (An encoding can be in parts, one per operand layout, all with its
        // name: an alias is of any of them.)
        let of_base = e.alias_of != NONE
            && (e.alias_of == base
                || encoding(usize::from(e.alias_of)).group == encoding(usize::from(base)).group);
        if !of_base || e.ms == ms::NOT_PREFERRED {
            continue;
        }
        // Where Microsoft has its own preference, the alias's "not equal"
        // constraints (such as "cond != 111x") do not apply either.
        let (rn, rm) = ((word >> 5) & 0x1F, (word >> 16) & 0x1F);
        let ms_prefers = match e.ms {
            ms::CINC => Some(rn == rm && rn != 31),
            ms::CNEG => Some(rn == rm),
            ms::CSET => Some(rn == 31 && rm == 31),
            _ => None,
        };
        let preferred = match ms_prefers {
            Some(p) => p && word & e.mask == e.value,
            None => w_matches_alias(e, word) && e.prefer.is_some_and(|f| f(word)),
        };
        if preferred {
            chosen = i;
            break;
        }
    }
    let inst = Instruction {
        word,
        address,
        encoding: chosen,
    };
    if format::is_valid(&inst) {
        return Some(inst);
    }
    // An alias whose operands do not render (such as a TLBI operation
    // with no name) falls back to the instruction it stands for.
    let inst = Instruction {
        encoding: base,
        ..inst
    };
    // Reserved operand values (such as an arrangement marked RESERVED)
    // make the encoding invalid.
    format::is_valid(&inst).then_some(inst)
}

fn w_matches_alias(e: &Encoding, w: u32) -> bool {
    w & e.mask == e.value && e.ne.iter().all(|&(m, v)| w & m != v)
}

/// For tools: every encoding whose fixed bits match `word`, whether its
/// constraints hold, and how it renders the word.
#[doc(hidden)]
pub fn explain(word: u32) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for &i in BUCKETS[(word >> 21) as usize] {
        let e = encoding(usize::from(i));
        if word & e.mask != e.value {
            continue;
        }
        out.push_str(if matches(e, word) {
            "match"
        } else {
            "rejected (ne/undef)"
        });
        out.push_str(if e.alias_of == NONE { "" } else { " alias" });
        out.push('\n');
        let inst = Instruction {
            word,
            address: 0,
            encoding: i,
        };
        out.push_str(&format::explain_encoding(&inst));
    }
    out
}

/// For tests: the first encoding matching `word` whose quick validity
/// check (what [`decode`] uses) disagrees with rendering it in full, if
/// any.
#[doc(hidden)]
pub fn validity_disagrees(word: u32) -> Option<&'static str> {
    for &i in BUCKETS[(word >> 21) as usize] {
        let e = encoding(usize::from(i));
        if word & e.mask != e.value {
            continue;
        }
        let inst = Instruction {
            word,
            address: 0,
            encoding: i,
        };
        if format::is_valid(&inst) != format::renders_fully(&inst) {
            return Some(e.name);
        }
    }
    None
}

/// Every encoding in the tables: its name and fixed bits (`word & mask ==
/// value`). For generating test cases.
pub fn encodings() -> impl Iterator<Item = (&'static str, u32, u32)> {
    tables::encodings().map(|e| (e.name, e.mask, e.value))
}

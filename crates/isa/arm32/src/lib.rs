//! AArch32 instruction decoding: A32 (ARM) and T32 (Thumb, 16- and 32-bit)
//! encodings, from Arm's Machine Readable Specification (AARCHMRS; see
//! `tables/aarch32.txt` and `tools/arm32/extract.py`).
//!
//! Decoding identifies each word's encoding (its name in Arm's
//! specification, its features, its assembler template, its operands'
//! fields) and whether it decodes at all; [`format`] writes it as text, in
//! the syntax of LLVM's disassembler. Neither panics.

#![no_std]

extern crate alloc;

/// An encoding of the instruction set.
#[derive(Debug)]
pub struct Encoding {
    /// Its name in Arm's specification, such as `ADD_i_T3`.
    pub name: &'static str,
    mask: u32,
    value: u32,
    sb_mask: u32,
    sb_value: u32,
    cond: Option<fn(u32) -> bool>,
    /// The architecture features it needs (`FEAT_FP16`), if any.
    pub feature: &'static str,
    /// Its assembler template (Arm's syntax, operands as `%{rule}`).
    pub asm: &'static str,
    /// Its aliases' templates.
    pub aliases: &'static [&'static str],
    /// Its operands (by their display, `<Rd>`), and the bits (hi, lo) of
    /// the fields each is encoded in, most significant first.
    pub operands: &'static [(&'static str, &'static [(u8, u8)])],
    /// Its fields: name, hi, lo.
    pub fields: &'static [(&'static str, u8, u8)],
}

/// An operand rule a template names (`%{Rd__4}`): its display (`<Rd>`),
/// and its text (`R%{UInteger}`) or, for a choice, its alternatives,
/// each named for the field values it is for (`size_01_16`).
#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub display: &'static str,
    pub text: Option<&'static str>,
    pub alts: &'static [(&'static str, &'static str)],
}

/// The rule `id`.
pub fn rule(id: &str) -> Option<&'static Rule> {
    tables::RULES
        .binary_search_by(|r| r.id.cmp(id))
        .ok()
        .map(|i| &tables::RULES[i])
}

impl Encoding {
    fn matches(&self, w: u32) -> bool {
        w & self.mask == self.value && self.cond.is_none_or(|c| c(w))
    }

    /// The mnemonic, lowercased, without its optional parts (`add` for
    /// `ADD{<c>}{<q>}`).
    pub fn mnemonic(&self) -> &'static str {
        mnemonic_of(self.asm)
    }
}

/// A template's mnemonic: its leading letters and digits.
pub fn mnemonic_of(template: &'static str) -> &'static str {
    let end = template
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(template.len());
    &template[..end]
}

pub mod format;

mod tables {
    // (Generated: conditions as the table writes them.)
    #![allow(unused_parens, clippy::all)]
    use super::{Encoding, Rule};
    include!(concat!(env!("OUT_DIR"), "/tables.rs"));
}

/// A decoded instruction.
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    /// The word, or for a 16-bit Thumb instruction, its halfword (and for
    /// a 32-bit one, the first halfword in the top half).
    pub word: u32,
    /// 2 or 4.
    pub size: u8,
    /// T32 (Thumb), not A32.
    pub thumb: bool,
    pub encoding: &'static Encoding,
}

impl Instruction {
    /// Whether its "should be" bits are other than they should be
    /// (CONSTRAINED UNPREDICTABLE).
    pub fn breaks_should_be(&self) -> bool {
        self.word & self.encoding.sb_mask != self.encoding.sb_value
    }
}

fn find(
    table: &'static [Encoding],
    buckets: &'static [&'static [u16]],
    key: (u32, u32),
    w: u32,
) -> Option<&'static Encoding> {
    let bucket = buckets.get(((w >> key.0) & key.1) as usize)?;
    bucket
        .iter()
        .map(|&i| &table[usize::from(i)])
        .find(|e| e.matches(w))
}

/// Decodes an A32 (ARM) word.
pub fn decode_a32(word: u32) -> Option<Instruction> {
    let encoding = find(&tables::A32, &tables::A32_BUCKETS, tables::A32_KEY, word)?;
    Some(Instruction {
        word,
        size: 4,
        thumb: false,
        encoding,
    })
}

/// Whether a T32 instruction starting with this halfword is 32 bits long.
pub fn is_t32_wide(first: u16) -> bool {
    first >> 11 >= 0b11101
}

/// Decodes a T32 (Thumb) instruction from its first halfword and, for a
/// 32-bit one, its second (`None` if it is missing).
pub fn decode_t32(first: u16, second: Option<u16>) -> Option<Instruction> {
    if is_t32_wide(first) {
        let word = u32::from(first) << 16 | u32::from(second?);
        let encoding = find(&tables::T32, &tables::T32_BUCKETS, tables::T32_KEY, word)?;
        Some(Instruction {
            word,
            size: 4,
            thumb: true,
            encoding,
        })
    } else {
        let word = u32::from(first);
        let encoding = find(&tables::T16, &tables::T16_BUCKETS, tables::T16_KEY, word)?;
        Some(Instruction {
            word,
            size: 2,
            thumb: true,
            encoding,
        })
    }
}

/// The number of encodings in each table (A32, T16, T32).
pub fn counts() -> (usize, usize, usize) {
    (tables::A32.len(), tables::T16.len(), tables::T32.len())
}

#[cfg(test)]
mod tests;

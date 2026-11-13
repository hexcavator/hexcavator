//! For tools/arm32/oracle.py: reads lines of `A32 <word> <address>`,
//! `T16 <half> <address>`, or `T32 <first><second> <address>`
//! (hexadecimal) and writes, for each, the line, its encoding's name, and
//! its text, separated by tabs; `-` for words that don't decode.

#![allow(clippy::cast_possible_truncation)]

use std::io::{BufRead, Write};

use hexcavator_arm32::format::{Targets, format};
use hexcavator_arm32::{decode_a32, decode_t32};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let mut it = line.split_whitespace();
        let (Some(iset), Some(hex), Some(at)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Ok(w), Ok(at)) = (u32::from_str_radix(hex, 16), u64::from_str_radix(at, 16)) else {
            continue;
        };
        let i = match iset {
            "A32" => decode_a32(w),
            "T16" => decode_t32(w as u16, None),
            _ => decode_t32((w >> 16) as u16, Some(w as u16)),
        };
        match i {
            Some(i) => writeln!(
                out,
                "{line}\t{}\t{}",
                i.encoding.name,
                format(&i, at, Targets::Addresses)
            ),
            None => writeln!(out, "{line}\t-\t-"),
        }
        .unwrap();
    }
}

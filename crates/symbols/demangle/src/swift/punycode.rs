// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Follows the Swift project's demangler (see LICENSE-SWIFT at the crate root).

//! Swift's Punycode (RFC 3492 with `_` as the delimiter, `A`-`J` as digits
//! 26-35, and U+D800-D87F standing for non-symbol ASCII characters):
//! decoding only, as `Punycode::decodePunycodeUTF8` does it.

use alloc::string::String;
use alloc::vec::Vec;

const BASE: i32 = 36;
const TMIN: i32 = 1;
const TMAX: i32 = 26;
const SKEW: i32 = 38;
const DAMP: i32 = 700;
const INITIAL_BIAS: i32 = 72;
const INITIAL_N: u32 = 128;

/// The longest input decoded (decoding inserts into the middle of the
/// output, so it is quadratic): longer identifiers are refused.
const MAX_INPUT: usize = 1 << 16;

fn digit_index(c: u8) -> i32 {
    match c {
        b'a'..=b'z' => i32::from(c - b'a'),
        b'A'..=b'J' => i32::from(c - b'A') + 26,
        _ => -1,
    }
}

fn is_valid_unicode_scalar(s: u32) -> bool {
    s < 0xD880 || (0xE000..=0x10FFFF).contains(&s)
}

fn adapt(mut delta: i32, numpoints: i32, first: bool) -> i32 {
    delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

fn decode(input: &[u8]) -> Option<Vec<u32>> {
    if input.len() > MAX_INPUT {
        return None;
    }
    let mut out: Vec<u32> = Vec::with_capacity(input.len());
    let mut n = INITIAL_N;
    let mut i: i32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut rest = input;
    if let Some(last) = input.iter().rposition(|&c| c == b'_') {
        for &c in &input[..last] {
            if c > 0x7F {
                return None;
            }
            out.push(u32::from(c));
        }
        rest = &input[last + 1..];
    }
    while !rest.is_empty() {
        let oldi = i;
        let mut w: i32 = 1;
        let mut k = BASE;
        loop {
            let (&c, tail) = rest.split_first()?;
            rest = tail;
            let digit = digit_index(c);
            if digit < 0 {
                return None;
            }
            if digit > (i32::MAX - i) / w {
                return None;
            }
            i += digit * w;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            if w > i32::MAX / (BASE - t) {
                return None;
            }
            w *= BASE - t;
            k += BASE;
        }
        let len1 = out.len() + 1;
        bias = adapt(i - oldi, len1 as i32, oldi == 0);
        // (Swift's check, in its types: `INT_MAX - n` is unsigned.)
        if (i as usize) / len1 > (0x7FFF_FFFFu32.wrapping_sub(n)) as usize {
            return None;
        }
        n = n.wrapping_add(((i as usize) / len1) as u32);
        i = ((i as usize) % len1) as i32;
        if n < 0x80 {
            return None;
        }
        out.insert(i as usize, n);
        i += 1;
    }
    Some(out)
}

/// Decodes Swift Punycode to UTF-8; `None` if it is malformed.
pub fn decode_utf8(input: &[u8]) -> Option<String> {
    let points = decode(input)?;
    let mut out = String::with_capacity(points.len());
    for mut s in points {
        if !is_valid_unicode_scalar(s) {
            return None;
        }
        if (0xD800..0xD880).contains(&s) {
            s -= 0xD800;
        }
        // (Valid scalars, and the ASCII ones from the D800 range.)
        out.push(char::from_u32(s)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        // From Swift's test/Demangle/Inputs/manglings.txt.
        assert_eq!(
            decode_utf8(b"egbpdajGbuEbxfgehfvwxn").as_deref(),
            Some("ليهمابتكلموشعربي؟")
        );
        assert_eq!(
            decode_utf8(b"ihqwcrbEcvIaIdqgAFGpqjye").as_deref(),
            Some("他们为什么不说中文")
        );
        assert_eq!(
            decode_utf8(b"Proprostnemluvesky_uybCEdmaEBa").as_deref(),
            Some("Pročprostěnemluvíčesky")
        );
        // Only basic code points.
        assert_eq!(decode_utf8(b"abc_").as_deref(), Some("abc"));
        assert_eq!(decode_utf8(b"").as_deref(), Some(""));
    }

    #[test]
    fn rejects_malformed() {
        // A digit sequence that runs out, an invalid digit, an overflowing
        // delta, and too much input.
        assert_eq!(decode_utf8(b"x"), None);
        assert_eq!(decode_utf8(b"abc_!"), None);
        assert_eq!(decode_utf8(&[b'J'; 64]), None);
        assert_eq!(decode_utf8(&[b'a'; MAX_INPUT + 1]), None);
    }
}

//! "Plain LZ77" decompression, as specified in [MS-XCA] section 2.4.
//!
//! ETW compresses each buffer's events (everything after the buffer header)
//! with this algorithm when a trace is written with compression.
//!
//! [MS-XCA]: https://learn.microsoft.com/openspecs/windows_protocols/ms-xca

use hexcavator_core::{Error, ErrorKind, Result};

/// Decompresses `input`, appending to `out`, which must end up exactly
/// `expected` bytes longer. Back references may reach only into what this
/// call writes.
pub fn decompress(input: &[u8], expected: usize, out: &mut Vec<u8>) -> Result<()> {
    let err = |kind, pos: usize, what| Error::new(kind, pos as u64, what);
    let start = out.len();
    let limit =
        start
            .checked_add(expected)
            .ok_or(err(ErrorKind::Overflow, 0, "decompressed size"))?;
    // Reserve what the input could plausibly expand to, not what it claims:
    // a hostile size costs nothing until matches actually fill it.
    out.reserve(expected.min(input.len().saturating_mul(8)));
    let mut pos = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    // Where the half byte shared by two consecutive long matches is, once
    // the first of them has used its low half.
    let mut half_byte: Option<usize> = None;
    let byte = |pos: &mut usize, what| -> Result<u8> {
        let b = *input
            .get(*pos)
            .ok_or(err(ErrorKind::Truncated, *pos, what))?;
        *pos += 1;
        Ok(b)
    };
    let u16_le = |pos: &mut usize, what| -> Result<u16> {
        let b = input
            .get(*pos..*pos + 2)
            .ok_or(err(ErrorKind::Truncated, *pos, what))?;
        *pos += 2;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    };
    loop {
        if flag_count == 0 {
            if pos == input.len() {
                break;
            }
            let b = input
                .get(pos..pos + 4)
                .ok_or(err(ErrorKind::Truncated, pos, "LZ77 flags"))?;
            flags = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            pos += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        if flags & (1 << flag_count) == 0 {
            if pos == input.len() {
                break;
            }
            if out.len() == limit {
                return Err(err(ErrorKind::Malformed, pos, "LZ77 output size"));
            }
            out.push(input[pos]);
            pos += 1;
            continue;
        }
        if pos == input.len() {
            break;
        }
        let match_bytes = u16_le(&mut pos, "LZ77 match")?;
        let offset = usize::from(match_bytes / 8) + 1;
        let mut length = usize::from(match_bytes % 8);
        if length == 7 {
            length = match half_byte.take() {
                None => {
                    let at = pos;
                    let b = byte(&mut pos, "LZ77 length")?;
                    half_byte = Some(at);
                    usize::from(b % 16)
                }
                Some(at) => usize::from(input[at] / 16),
            };
            if length == 15 {
                length = usize::from(byte(&mut pos, "LZ77 length")?);
                if length == 255 {
                    length = usize::from(u16_le(&mut pos, "LZ77 length")?);
                    if length == 0 {
                        let b = input.get(pos..pos + 4).ok_or(err(
                            ErrorKind::Truncated,
                            pos,
                            "LZ77 length",
                        ))?;
                        length = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                        pos += 4;
                    }
                    length = length.checked_sub(15 + 7).ok_or(err(
                        ErrorKind::Malformed,
                        pos,
                        "LZ77 length",
                    ))?;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        let written = out.len() - start;
        if offset > written {
            return Err(err(ErrorKind::Malformed, pos, "LZ77 match offset"));
        }
        if length > limit - out.len() {
            return Err(err(ErrorKind::Malformed, pos, "LZ77 output size"));
        }
        let from = out.len() - offset;
        if offset >= length {
            out.extend_from_within(from..from + length);
        } else {
            // An overlapping copy repeats the last `offset` bytes.
            for i in 0..length {
                let b = out[from + i];
                out.push(b);
            }
        }
    }
    if out.len() != limit {
        return Err(err(ErrorKind::Malformed, pos, "LZ77 output size"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8], expected: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decompress(input, expected, &mut out).map(|()| out)
    }

    // The examples from [MS-XCA] 3.1 ("abcdefghijklmnopqrstuvwxyz" and
    // "abc" repeated 100 times).
    #[test]
    fn spec_examples() {
        let alphabet = [
            0x3f, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            0x79, 0x7a,
        ];
        assert_eq!(run(&alphabet, 26).unwrap(), b"abcdefghijklmnopqrstuvwxyz");

        let abc = [
            0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
        ];
        assert_eq!(run(&abc, 300).unwrap(), b"abc".repeat(100));
    }

    #[test]
    fn shared_half_byte() {
        // Two long matches share one length byte: 0x21 gives the first
        // 3 + 7 + 1 = 11 and the second 3 + 7 + 2 = 12.
        let input = [0x00, 0x00, 0x00, 0x60, b'x', 0x07, 0x00, 0x21, 0x07, 0x00];
        assert_eq!(run(&input, 24).unwrap(), vec![b'x'; 24]);
    }

    #[test]
    fn rejects_malformed() {
        // A match before any output.
        assert!(run(&[0x00, 0x00, 0x00, 0x80, 0x00, 0x00], 3).is_err());
        // More output than expected.
        assert!(run(&[0x00, 0x00, 0x00, 0x00, b'a', b'b'], 1).is_err());
        // Less output than expected.
        assert!(run(&[0x00, 0x00, 0x00, 0x00, b'a'], 2).is_err());
        // Truncated flags, match and lengths.
        assert!(run(&[0x00, 0x00], 0).is_err());
        assert!(run(&[0x00, 0x00, 0x00, 0x40, b'a', 0x07], 4).is_err());
        assert!(run(&[0x00, 0x00, 0x00, 0x40, b'a', 0x07, 0x00], 11).is_err());
        assert!(run(&[0x00, 0x00, 0x00, 0x40, b'a', 0x07, 0x00, 0x0f], 26).is_err());
        // A 32-bit length below the bias.
        let input = [
            0x00, 0x00, 0x00, 0x40, b'a', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00,
        ];
        assert!(run(&input, 10).is_err());
        // A huge length is refused before anything is written for it.
        let input = [
            0x00, 0x00, 0x00, 0x40, b'a', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff,
        ];
        assert!(run(&input, 10).is_err());
    }

    #[test]
    fn empty() {
        assert_eq!(run(&[], 0).unwrap(), b"");
        assert_eq!(run(&[0, 0, 0, 0], 0).unwrap(), b"");
    }
}

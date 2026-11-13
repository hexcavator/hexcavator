//! A reader of ASN.1's DER (and the BER that signatures sometimes use:
//! indefinite lengths, constructed strings), borrowing its input.
//!
//! Signatures are what an attacker writes, so every length is checked
//! against what holds it, nesting is bounded, and nothing is copied.

use std::fmt;

/// Tags (class, constructed, and number, as one byte: low tag numbers only).
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const ENUMERATED: u8 = 0x0A;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const T61_STRING: u8 = 0x14;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const VISIBLE_STRING: u8 = 0x1A;
    pub const UNIVERSAL_STRING: u8 = 0x1C;
    pub const BMP_STRING: u8 = 0x1E;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    /// `[n]`, constructed (EXPLICIT, or IMPLICIT of a constructed type).
    pub const fn context(n: u8) -> u8 {
        0xA0 | n
    }

    /// `[n]`, primitive (IMPLICIT of a primitive type).
    pub const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

/// The deepest nesting read.
const MAX_DEPTH: usize = 64;

/// What went wrong reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// What was being read.
    pub what: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed {}", self.what)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn err<T>(what: &'static str) -> Result<T> {
    Err(Error { what })
}

/// One element: its tag, its contents, and all of its bytes (tag and
/// length too).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The contents (for an indefinite length, without the end-of-contents
    /// marker).
    pub body: &'a [u8],
    /// The whole element.
    pub raw: &'a [u8],
    /// Whether its length was indefinite (BER).
    pub indefinite: bool,
}

impl fmt::Debug for Tlv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tlv({:#04x}, {} bytes)", self.tag, self.body.len())
    }
}

impl<'a> Tlv<'a> {
    /// Whether it is constructed (holds elements).
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// A reader of the elements it holds.
    pub fn reader(&self) -> Reader<'a> {
        Reader::nested(self.body, 1)
    }

    /// It as an element of `tag`.
    pub fn expect(self, tag: u8, what: &'static str) -> Result<Self> {
        if self.tag == tag { Ok(self) } else { err(what) }
    }

    /// An OBJECT IDENTIFIER's contents.
    pub fn oid(&self) -> Result<Oid<'a>> {
        if self.tag != tag::OID || self.body.is_empty() {
            return err("object identifier");
        }
        Ok(Oid(self.body))
    }

    /// An INTEGER's bytes (big-endian, two's complement), as written.
    pub fn integer(&self) -> Result<&'a [u8]> {
        if self.tag != tag::INTEGER || self.body.is_empty() {
            return err("integer");
        }
        Ok(self.body)
    }

    /// A small INTEGER's value.
    pub fn small(&self) -> Result<i64> {
        let b = self.integer()?;
        if b.len() > 8 {
            return err("integer");
        }
        let mut v: i64 = if b[0] & 0x80 != 0 { -1 } else { 0 };
        for &x in b {
            v = (v << 8) | i64::from(x);
        }
        Ok(v)
    }

    /// A BIT STRING's bits (whole bytes: the unused-bit count must be 0).
    pub fn bits(&self) -> Result<&'a [u8]> {
        match self.body.split_first() {
            Some((0, rest)) if self.tag == tag::BIT_STRING => Ok(rest),
            _ => err("bit string"),
        }
    }

    /// A BIT STRING's bits and unused-bit count (for flags).
    pub fn flags(&self) -> Result<(&'a [u8], u8)> {
        match self.body.split_first() {
            Some((&unused, rest)) if self.tag == tag::BIT_STRING && unused < 8 => {
                Ok((rest, unused))
            }
            _ => err("bit string"),
        }
    }

    /// A BOOLEAN's value.
    pub fn boolean(&self) -> Result<bool> {
        match self.body {
            [b] if self.tag == tag::BOOLEAN => Ok(*b != 0),
            _ => err("boolean"),
        }
    }

    /// A string's text, by its kind (UTF-8, printable, IA5, BMP, ...).
    pub fn text(&self) -> Result<String> {
        let b = self.body;
        match self.tag & 0x1F {
            // (T61 is Latin-1 in practice.)
            0x14 => Ok(b.iter().map(|&c| char::from(c)).collect()),
            0x1E => {
                let units: Vec<u16> = b
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Ok(String::from_utf16_lossy(&units))
            }
            0x1C => Ok(b
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| {
                    char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        .unwrap_or('\u{FFFD}')
                })
                .collect()),
            0x0C | 0x12 | 0x13 | 0x16 | 0x1A | 0x15 | 0x19 | 0x1B => {
                Ok(String::from_utf8_lossy(b).into_owned())
            }
            _ => err("string"),
        }
    }

    /// An OCTET STRING's bytes (a constructed one's pieces joined).
    pub fn octets(&self) -> Result<std::borrow::Cow<'a, [u8]>> {
        match self.tag {
            tag::OCTET_STRING => Ok(std::borrow::Cow::Borrowed(self.body)),
            0x24 => {
                let mut out = Vec::new();
                let mut r = self.reader();
                while let Some(piece) = r.next()? {
                    out.extend_from_slice(piece.expect(tag::OCTET_STRING, "octet string")?.body);
                }
                Ok(std::borrow::Cow::Owned(out))
            }
            _ => err("octet string"),
        }
    }

    /// A time (UTCTime or GeneralizedTime).
    pub fn time(&self) -> Result<Time> {
        Time::parse(self.tag, self.body)
    }
}

/// A reader of a run of elements.
#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    depth: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, depth: 0 }
    }

    fn nested(data: &'a [u8], depth: usize) -> Self {
        Reader { data, depth }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// What's left.
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The next element (`None` at the end).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Tlv<'a>>> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let (tlv, used) = read_one(self.data, self.depth)?;
        self.data = &self.data[used..];
        Ok(Some(tlv))
    }

    /// The next element, which must be there.
    pub fn take(&mut self, what: &'static str) -> Result<Tlv<'a>> {
        match self.next()? {
            Some(t) => Ok(t),
            None => err(what),
        }
    }

    /// The next element, which must be of `tag`.
    pub fn expect(&mut self, tag: u8, what: &'static str) -> Result<Tlv<'a>> {
        self.take(what)?.expect(tag, what)
    }

    /// The next element if it has `tag`.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.data.first() == Some(&tag) {
            self.next()
        } else {
            Ok(None)
        }
    }

    /// The tag of the next element.
    pub fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

/// One element at the start of `data`, and how many bytes it takes.
fn read_one(data: &[u8], depth: usize) -> Result<(Tlv<'_>, usize)> {
    if depth > MAX_DEPTH {
        return err("nesting (too deep)");
    }
    let &tag = data.first().ok_or(Error { what: "tag" })?;
    if tag & 0x1F == 0x1F {
        // (High tag numbers: none of the structures here use them.)
        return err("tag (high tag number)");
    }
    let &first = data.get(1).ok_or(Error { what: "length" })?;
    let (len, header) = match first {
        0x80 => {
            // Indefinite: constructed only, up to an end-of-contents marker.
            if tag & 0x20 == 0 {
                return err("length (indefinite, of a primitive)");
            }
            let mut at = 2;
            loop {
                match data.get(at..at + 2) {
                    Some([0, 0]) => break,
                    Some(_) => {
                        let (_, used) = read_one(&data[at..], depth + 1)?;
                        at += used;
                    }
                    None => return err("end of contents"),
                }
            }
            let body = &data[2..at];
            return Ok((
                Tlv {
                    tag,
                    body,
                    raw: &data[..at + 2],
                    indefinite: true,
                },
                at + 2,
            ));
        }
        n if n & 0x80 == 0 => (usize::from(n), 2),
        n => {
            let count = usize::from(n & 0x7F);
            if count > 4 {
                return err("length");
            }
            let bytes = data.get(2..2 + count).ok_or(Error { what: "length" })?;
            let len = bytes.iter().fold(0usize, |v, &b| (v << 8) | usize::from(b));
            (len, 2 + count)
        }
    };
    let end = header.checked_add(len).ok_or(Error { what: "length" })?;
    let body = data.get(header..end).ok_or(Error {
        what: "length (past its container)",
    })?;
    Ok((
        Tlv {
            tag,
            body,
            raw: &data[..end],
            indefinite: false,
        },
        end,
    ))
}

/// The one element that is all of `data`.
pub fn parse(data: &[u8]) -> Result<Tlv<'_>> {
    let (tlv, used) = read_one(data, 0)?;
    if used != data.len() {
        // (Trailing zeros pad some signatures to an alignment.)
        if data[used..].iter().any(|&b| b != 0) {
            return err("trailing data");
        }
    }
    Ok(tlv)
}

/// The DER of a definite-length element: `tag`, its length, then `body`.
pub fn encode(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    match u8::try_from(body.len()) {
        Ok(n) if n < 0x80 => out.push(n),
        _ => {
            let bytes = body.len().to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            // (At most 8 length bytes.)
            out.push(0x80 | (bytes.len() - skip).to_le_bytes()[0]);
            out.extend_from_slice(&bytes[skip..]);
        }
    }
    out.extend_from_slice(body);
    out
}

/// An object identifier's contents.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oid<'a>(pub &'a [u8]);

impl Oid<'_> {
    /// Whether it is `dotted` ("1.2.840.113549.1.1.11").
    pub fn is(&self, dotted: &str) -> bool {
        self.to_string() == dotted
    }
}

impl fmt::Display for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut v: u128 = 0;
        for &b in self.0 {
            v = (v << 7) | u128::from(b & 0x7F);
            if v > u128::from(u64::MAX) {
                return f.write_str("?");
            }
            if b & 0x80 == 0 {
                if first {
                    let (a, b) = if v < 40 {
                        (0, v)
                    } else if v < 80 {
                        (1, v - 40)
                    } else {
                        (2, v - 80)
                    };
                    write!(f, "{a}.{b}")?;
                    first = false;
                } else {
                    write!(f, ".{v}")?;
                }
                v = 0;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Oid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

/// A time, in UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    /// Seconds since 1970-01-01 (negative before).
    pub unix: i64,
}

impl Time {
    fn parse(tag: u8, b: &[u8]) -> Result<Self> {
        let s = std::str::from_utf8(b).map_err(|_| Error { what: "time" })?;
        let s = s.strip_suffix('Z').ok_or(Error {
            what: "time (not UTC)",
        })?;
        let digits = |r: std::ops::Range<usize>| -> Result<i64> {
            let t = s.get(r).ok_or(Error { what: "time" })?;
            if !t.bytes().all(|c| c.is_ascii_digit()) {
                return err("time");
            }
            t.parse().map_err(|_| Error { what: "time" })
        };
        let (year, rest) = match tag {
            tag::UTC_TIME => {
                let y = digits(0..2)?;
                // (RFC 5280: 50-99 are 19xx.)
                (if y >= 50 { 1900 + y } else { 2000 + y }, 2)
            }
            tag::GENERALIZED_TIME => (digits(0..4)?, 4),
            _ => return err("time"),
        };
        let month = digits(rest..rest + 2)?;
        let day = digits(rest + 2..rest + 4)?;
        let hour = digits(rest + 4..rest + 6)?;
        let minute = digits(rest + 6..rest + 8)?;
        // (Seconds may be left out in UTCTime; fractions follow in
        // GeneralizedTime.)
        let second = if s.len() >= rest + 10 {
            digits(rest + 8..rest + 10)?
        } else {
            0
        };
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 60
        {
            return err("time");
        }
        Ok(Time {
            unix: days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second,
        })
    }

    /// The time `unix` seconds after 1970.
    pub fn from_unix(unix: i64) -> Self {
        Time { unix }
    }

    /// Now.
    pub fn now() -> Self {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        Time { unix }
    }
}

impl fmt::Display for Time {
    /// ISO 8601: `2026-11-12T10:30:00Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.unix.div_euclid(86_400);
        let secs = self.unix.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

/// Days since 1970-01-01 of a date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_short_long_and_indefinite() {
        let t = parse(&[0x30, 0x03, 0x02, 0x01, 0x05]).unwrap();
        assert_eq!(t.reader().take("x").unwrap().small().unwrap(), 5);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        assert_eq!(parse(&long).unwrap().body.len(), 0x80);
        // BER: a constructed element of indefinite length.
        let t = parse(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]).unwrap();
        assert!(t.indefinite);
        assert_eq!(t.body, &[0x02, 0x01, 0x01]);
        // Past the end; indefinite primitive; too deep.
        assert!(parse(&[0x30, 0x05, 0x02]).is_err());
        assert!(parse(&[0x04, 0x80, 0x00, 0x00]).is_err());
        let mut deep = [0x30, 0x80].repeat(100);
        deep.extend([0u8; 200]);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn oids_and_times() {
        let oid = Oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]);
        assert_eq!(oid.to_string(), "1.2.840.113549.1.1.11");
        let t = Time::parse(tag::UTC_TIME, b"260102030405Z").unwrap();
        assert_eq!(t.to_string(), "2026-01-02T03:04:05Z");
        let t = Time::parse(tag::GENERALIZED_TIME, b"19991231235959.123Z").unwrap();
        assert_eq!(t.to_string(), "1999-12-31T23:59:59Z");
        assert_eq!(
            Time::parse(tag::UTC_TIME, b"700101000000Z").unwrap().unix,
            0
        );
        assert!(Time::parse(tag::UTC_TIME, b"261302030405Z").is_err());
    }

    #[test]
    fn encode_lengths() {
        assert_eq!(encode(0x31, &[1, 2]), vec![0x31, 2, 1, 2]);
        let e = encode(0x31, &[0; 300]);
        assert_eq!(&e[..4], &[0x31, 0x82, 0x01, 0x2C]);
    }
}

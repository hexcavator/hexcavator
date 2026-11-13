//! The on-disk index: an image's symbols, saved so that the next report on
//! the same image and debug information needn't read them again (most of a
//! report's time on a large PDB: 3 s of 4.5 on clang's 1.45 GB one).
//!
//! The file is a header (magic, format version, the key), the symbols, and
//! a checksum. The key says what the symbols were built from (the image's
//! and debug file's sizes and times, and the tool's own identity, so that a
//! rebuilt Hexcavator doesn't trust an old index); an index whose key, version, or
//! checksum differs is ignored, as is any that doesn't decode exactly. It
//! is read as untrusted input: every length is checked, names must be
//! UTF-8, and nothing it says is believed beyond its own bytes.
//!
//! The symbols are deflated (their size given first, and held to), with
//! each name stored as what it shares with the one before and the rest:
//! names are nearly all of an index, and neighbors share much (clang's:
//! 151 MB plain, about 16 MB so).

use std::hash::Hasher;

use crate::Size;
use crate::symbols::{Symbol, SymbolKind};

pub const MAGIC: &[u8; 8] = b"HEXCIDX\0";
/// Bumped when the layout changes.
pub const VERSION: u32 = 2;

/// Deflate's level for indexes: the fastest, which keeps nearly all of
/// the saving.
const LEVEL: u8 = 1;

/// What an index was built from: opaque bytes, compared whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Key(pub Vec<u8>);

impl Key {
    /// Appends a file's identity: its size and modification time.
    pub fn file(&mut self, meta: &std::fs::Metadata) {
        self.number(meta.len());
        let time = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        self.0.extend_from_slice(&time.to_le_bytes());
    }

    pub fn number(&mut self, n: u64) {
        self.0.extend_from_slice(&n.to_le_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.number(b.len() as u64);
        self.0.extend_from_slice(b);
    }
}

fn uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn checksum(data: &[u8]) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    h.write(data);
    h.write_usize(data.len());
    h.finish()
}

const FOLDED: u8 = 1;
const FILE_STATIC: u8 = 2;
const COMPILAND: u8 = 4;

/// The length of what `a` and `b` begin with, on a character boundary.
fn shared_prefix(a: &str, b: &str) -> usize {
    let mut n = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
    while !b.is_char_boundary(n) {
        n -= 1;
    }
    n
}

/// Encodes an index of `symbols`, built from what `key` describes.
pub fn encode(key: &Key, symbols: &[Symbol]) -> Vec<u8> {
    let payload = symbols_payload(symbols);
    let packed = miniz_oxide::deflate::compress_to_vec(&payload, LEVEL);
    let mut out = Vec::with_capacity(packed.len() + key.0.len() + 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    uleb(&mut out, key.0.len() as u64);
    out.extend_from_slice(&key.0);
    uleb(&mut out, payload.len() as u64);
    out.extend_from_slice(&packed);
    let sum = checksum(&out);
    out.extend_from_slice(&sum.to_le_bytes());
    out
}

/// The symbols, before deflating: a count, then each symbol.
fn symbols_payload(symbols: &[Symbol]) -> Vec<u8> {
    let mut out = Vec::with_capacity(symbols.len() * 48 + 16);
    uleb(&mut out, symbols.len() as u64);
    let mut prev = 0u64;
    let mut prev_name = "";
    for s in symbols {
        // Addresses mostly ascend: store the difference (zigzag).
        let delta = s.addr.wrapping_sub(prev) as i64;
        uleb(&mut out, ((delta << 1) ^ (delta >> 63)) as u64);
        prev = s.addr;
        uleb(&mut out, s.size.file);
        uleb(&mut out, s.size.vm);
        out.push(s.kind as u8);
        let mut flags = 0;
        if s.folded {
            flags |= FOLDED;
        }
        if s.file_static {
            flags |= FILE_STATIC;
        }
        if s.compiland.is_some() {
            flags |= COMPILAND;
        }
        out.push(flags);
        if let Some(c) = s.compiland {
            uleb(&mut out, u64::from(c));
        }
        // The name: what it shares with the previous one, then the rest.
        let shared = shared_prefix(prev_name, &s.name);
        uleb(&mut out, shared as u64);
        uleb(&mut out, (s.name.len() - shared) as u64);
        out.extend_from_slice(&s.name.as_bytes()[shared..]);
        prev_name = &s.name;
    }
    out
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            v |= u64::from(b & 0x7F).checked_shl(shift)?;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
}

/// The symbols of an index built from what `key` describes, or `None` if
/// `data` isn't one (wrong key, version, or checksum, or malformed).
pub fn decode(data: &[u8], key: &Key) -> Option<Vec<Symbol>> {
    let (body, sum) = data.split_at_checked(data.len().checked_sub(8)?)?;
    if checksum(body) != u64::from_le_bytes(sum.try_into().ok()?) {
        return None;
    }
    let mut r = Reader { data: body, pos: 0 };
    if r.take(8)? != MAGIC || r.take(4)? != VERSION.to_le_bytes() {
        return None;
    }
    let key_len = usize::try_from(r.uleb()?).ok()?;
    if r.take(key_len)? != key.0 {
        return None;
    }
    // The symbols' size, which inflating must give exactly. (Deflate
    // expands at most about 1032 times: a bound on what to allocate.)
    let size = usize::try_from(r.uleb()?).ok()?;
    let packed = &body[r.pos..];
    if size > packed.len().saturating_mul(1032).saturating_add(64) {
        return None;
    }
    decode_symbols(&inflate_exactly(packed, size)?)
}

/// `packed` inflated, if it is one whole deflate stream of exactly `size`
/// bytes, with nothing after it.
fn inflate_exactly(packed: &[u8], size: usize) -> Option<Vec<u8>> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    let mut out = vec![0u8; size];
    let mut state = DecompressorOxide::new();
    let (status, read, written) = decompress(
        &mut state,
        packed,
        &mut out,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    (status == TINFLStatus::Done && read == packed.len() && written == size).then_some(out)
}

/// The symbols of an index's (inflated) payload.
fn decode_symbols(payload: &[u8]) -> Option<Vec<Symbol>> {
    let mut r = Reader {
        data: payload,
        pos: 0,
    };
    let body = payload;
    let count = usize::try_from(r.uleb()?).ok()?;
    // Each symbol takes at least 7 bytes: a bound on what to allocate.
    let mut out: Vec<Symbol> = Vec::with_capacity(count.min(body.len() / 7));
    let mut addr = 0u64;
    for _ in 0..count {
        let z = r.uleb()?;
        let delta = ((z >> 1) as i64) ^ -((z & 1) as i64);
        addr = addr.wrapping_add(delta as u64);
        let file = r.uleb()?;
        let vm = r.uleb()?;
        let kind = *SymbolKind::ALL.get(usize::from(r.byte()?))?;
        let flags = r.byte()?;
        if flags & !(FOLDED | FILE_STATIC | COMPILAND) != 0 {
            return None;
        }
        let compiland = if flags & COMPILAND != 0 {
            Some(u32::try_from(r.uleb()?).ok()?)
        } else {
            None
        };
        let shared = usize::try_from(r.uleb()?).ok()?;
        let len = usize::try_from(r.uleb()?).ok()?;
        let prev = out.last().map_or("", |s| s.name.as_str());
        let mut name = String::with_capacity(shared.saturating_add(len).min(body.len()));
        name.push_str(prev.get(..shared)?);
        name.push_str(std::str::from_utf8(r.take(len)?).ok()?);
        out.push(Symbol {
            addr,
            size: Size::new(file, vm),
            kind,
            folded: flags & FOLDED != 0,
            name,
            compiland,
            file_static: flags & FILE_STATIC != 0,
        });
    }
    (r.pos == body.len()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Symbol> {
        SymbolKind::ALL
            .iter()
            .enumerate()
            .map(|(i, &kind)| Symbol {
                // Not ascending everywhere, and some huge.
                addr: if i % 5 == 0 {
                    u64::MAX - i as u64
                } else {
                    0x1000 * i as u64
                },
                size: Size::new(i as u64 * 300, i as u64 * 7000),
                kind,
                folded: i % 2 == 0,
                name: format!("name {i} \u{e9}\u{1F600}"),
                compiland: (i % 3 != 0).then_some(i as u32 * 1000),
                file_static: i % 4 == 0,
            })
            .collect()
    }

    #[test]
    fn kinds_round_trip() {
        for (i, k) in SymbolKind::ALL.iter().enumerate() {
            assert_eq!(*k as usize, i);
        }
    }

    #[test]
    fn round_trips() {
        let syms = sample();
        let mut key = Key::default();
        key.number(42);
        key.bytes(b"tool");
        let data = encode(&key, &syms);
        assert_eq!(decode(&data, &key), Some(syms.clone()));
        assert_eq!(decode(&encode(&key, &[]), &key), Some(vec![]));
        // Another key, version, or a changed byte: not this index.
        let mut other = key.clone();
        other.number(1);
        assert_eq!(decode(&data, &other), None);
        for i in (0..data.len()).step_by(7) {
            let mut d = data.clone();
            d[i] ^= 0x10;
            assert_eq!(decode(&d, &key), None, "{i}");
        }
        for n in 0..data.len() {
            assert_eq!(decode(&data[..n], &key), None);
        }
    }

    /// Hostile indexes with good checksums (anyone can compute one) still
    /// decode to nothing, or to what they say, without panicking or
    /// allocating more than their size allows.
    #[test]
    fn hostile_indexes() {
        let key = Key(b"k".to_vec());
        let seal = |mut body: Vec<u8>| {
            let s = checksum(&body);
            body.extend_from_slice(&s.to_le_bytes());
            body
        };
        let mut head = MAGIC.to_vec();
        head.extend_from_slice(&VERSION.to_le_bytes());
        head.extend_from_slice(&[1, b'k']);
        // An index holding `payload` (deflated), saying it is `size` bytes.
        let index = |payload: &[u8], size: u64| {
            let mut b = head.clone();
            uleb(&mut b, size);
            b.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(payload, LEVEL));
            seal(b)
        };
        // A huge count with no records.
        let p = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        assert_eq!(decode(&index(&p, p.len() as u64), &key), None);
        // A bad kind, bad flags, a name past the end, non-UTF-8, a shared
        // prefix longer than the previous name, a shared prefix ending
        // inside a character.
        for rec in [
            &[1u8, 0, 0, 0, 200, 0, 0, 0][..],
            &[1, 0, 0, 0, 0, 0x80, 0, 0],
            &[1, 0, 0, 0, 0, 0, 0, 50, b'x'],
            &[1, 0, 0, 0, 0, 0, 0, 1, 0xFF],
            &[1, 0, 0, 0, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0],
            &[1, 0, 0, 0, 0, 0, 3, 0],
            &[2, 0, 0, 0, 0, 0, 0, 2, 0xC3, 0xA9, 0, 0, 0, 0, 0, 1, 0],
        ] {
            assert_eq!(decode(&index(rec, rec.len() as u64), &key), None, "{rec:?}");
        }
        // A good record, then sizes that don't match what inflates.
        let good = [1u8, 0, 0, 0, 0, 0, 0, 1, b'x'];
        assert!(decode(&index(&good, good.len() as u64), &key).is_some());
        assert_eq!(decode(&index(&good, good.len() as u64 + 1), &key), None);
        assert_eq!(decode(&index(&good, good.len() as u64 - 1), &key), None);
        // A size far past what deflate could expand to.
        assert_eq!(decode(&index(&good, 1 << 40), &key), None);
        // Trailing bytes in the payload, and after it.
        let mut p = good.to_vec();
        p.push(0);
        assert_eq!(decode(&index(&p, p.len() as u64), &key), None);
        let mut b = encode(&key, &sample());
        b.truncate(b.len() - 8);
        b.push(0);
        assert_eq!(decode(&seal(b), &key), None);
    }

    /// Names share what they can with the one before, never splitting a
    /// character.
    #[test]
    fn names_are_front_coded() {
        let names = [
            "std::vector<int>::push_back",
            "std::vector<int>::size",
            "",
            "\u{e9}a",
            "\u{e8}b",
            "x",
        ];
        let syms: Vec<Symbol> = names
            .iter()
            .map(|n| Symbol {
                addr: 0,
                size: Size::new(0, 0),
                kind: SymbolKind::ALL[0],
                folded: false,
                name: (*n).to_string(),
                compiland: None,
                file_static: false,
            })
            .collect();
        let key = Key::default();
        assert_eq!(decode(&encode(&key, &syms), &key), Some(syms));
        assert_eq!(shared_prefix("\u{e9}", "\u{e8}"), 0);
        assert_eq!(shared_prefix("abc", "abd"), 2);
        let payload = symbols_payload(&[]);
        assert_eq!(payload, [0]);
    }
}

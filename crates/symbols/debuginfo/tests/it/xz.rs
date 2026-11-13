//! The xz decoder (MiniDebugInfo's container) against streams Python's
//! lzma module (liblzma) wrote: testdata/xz, from tools/elf/minidebuginfo.py.

use hexcavator_debuginfo::decompress::xz;

fn testdata(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/xz")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_check_and_two_streams() {
    let text = testdata("text.txt");
    for name in ["none", "crc32", "crc64", "sha256", "two-streams"] {
        let data = testdata(&format!("text-{name}.xz"));
        assert_eq!(xz(&data, 1 << 20).as_deref(), Some(&text[..]), "{name}");
    }
}

#[test]
fn limits_and_refusals() {
    let text = testdata("text.txt");
    let data = testdata("text-crc64.xz");
    // Exactly the limit, and one byte under it.
    assert_eq!(xz(&data, text.len() as u64).as_deref(), Some(&text[..]));
    assert_eq!(xz(&data, text.len() as u64 - 1), None);
    // A filter chain other than LZMA2 alone.
    assert_eq!(xz(&testdata("text-bcj.xz"), 1 << 20), None);
    assert_eq!(xz(b"", 10), None);
    assert_eq!(xz(b"not xz at all", 10), None);
}

#[test]
fn damage_is_caught() {
    let text = testdata("text.txt");
    for name in ["crc32", "crc64"] {
        let data = testdata(&format!("text-{name}.xz"));
        // Every truncation fails (none succeeds with less, or panics).
        for n in 0..data.len() {
            assert_eq!(xz(&data[..n], 1 << 20), None, "{name} cut at {n}");
        }
        // A flipped byte anywhere is caught (by a header's CRC, the
        // decoder, the check, or the index), or decodes the same.
        for at in (0..data.len()).step_by(7) {
            let mut bad = data.clone();
            bad[at] ^= 0x55;
            let got = xz(&bad, 1 << 20);
            assert!(
                got.is_none() || got.as_deref() == Some(&text[..]),
                "{name} flipped at {at}"
            );
        }
    }
}

#[test]
fn a_dictionary_too_large_is_refused_before_it_is_allocated() {
    // A stream header (no check), and a block header asking for LZMA2 with
    // a 3 GiB dictionary (property 39): refused, not allocated.
    let crc = |d: &[u8]| {
        let mut c = !0u32;
        for &b in d {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    };
    let mut s = b"\xFD7zXZ\0\0\0".to_vec();
    let h = crc(&s[6..8]);
    s.extend(h.to_le_bytes());
    let block = [0x02u8, 0x00, 0x21, 0x01, 39, 0, 0, 0];
    s.extend(block);
    s.extend(crc(&block).to_le_bytes());
    s.extend([0u8; 64]);
    assert_eq!(xz(&s, 1 << 20), None);
}

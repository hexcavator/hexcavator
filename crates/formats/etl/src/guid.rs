use core::fmt;

/// A GUID, as Windows stores one: a little-endian `u32`, two little-endian
/// `u16`s, then eight bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Guid {
    /// The first field.
    pub data1: u32,
    /// The second field.
    pub data2: u16,
    /// The third field.
    pub data3: u16,
    /// The last eight bytes.
    pub data4: [u8; 8],
}

impl Guid {
    /// The all-zero GUID.
    pub const ZERO: Guid = Guid::new(0, 0, 0, [0; 8]);

    /// A GUID from its fields.
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Reads a GUID from its 16-byte on-disk form.
    pub const fn from_bytes(b: &[u8; 16]) -> Self {
        Self {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }

    /// The 16-byte on-disk form.
    pub const fn to_bytes(&self) -> [u8; 16] {
        let a = self.data1.to_le_bytes();
        let b = self.data2.to_le_bytes();
        let c = self.data3.to_le_bytes();
        let d = self.data4;
        [
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ]
    }

    /// Parses the registry form, with or without braces:
    /// `68fdd900-4a3e-11d1-84f4-0000f80464e3`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(s);
        let b = s.as_bytes();
        if b.len() != 36 || b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return None;
        }
        let hex = |r: core::ops::Range<usize>| -> Option<u64> {
            let t = s.get(r)?;
            if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(t, 16).ok()
        };
        let mut data4 = [0u8; 8];
        data4[..2].copy_from_slice(&hex(19..23)?.to_be_bytes()[6..]);
        data4[2..].copy_from_slice(&hex(24..36)?.to_be_bytes()[2..]);
        Some(Self {
            data1: u32::try_from(hex(0..8)?).ok()?,
            data2: u16::try_from(hex(9..13)?).ok()?,
            data3: u16::try_from(hex(14..18)?).ok()?,
            data4,
        })
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{self}}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let text = "68fdd900-4a3e-11d1-84f4-0000f80464e3";
        let g = Guid::parse(text).unwrap();
        assert_eq!(g.to_string(), text);
        assert_eq!(Guid::from_bytes(&g.to_bytes()), g);
        assert_eq!(
            Guid::parse("{68FDD900-4A3E-11D1-84F4-0000F80464E3}"),
            Some(g)
        );
        assert_eq!(g.data1, 0x68fdd900);
        assert_eq!(g.data4, [0x84, 0xf4, 0, 0, 0xf8, 0x04, 0x64, 0xe3]);
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "68fdd900-4a3e-11d1-84f4-0000f80464e",
            "68fdd900-4a3e-11d1-84f4-0000f80464e33",
            "68fdd900x4a3e-11d1-84f4-0000f80464e3",
            "68fdd90g-4a3e-11d1-84f4-0000f80464e3",
            "+8fdd900-4a3e-11d1-84f4-0000f80464e3",
            "{68fdd900-4a3e-11d1-84f4-0000f80464e3",
        ] {
            assert_eq!(Guid::parse(s), None, "{s:?}");
        }
    }
}

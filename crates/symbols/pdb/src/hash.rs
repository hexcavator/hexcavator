//! The hash functions PDB tables are keyed by (from Microsoft's `misc.h`,
//! `hashStringV1`/`V2`, and the CRC used for type records).

/// `hashStringV1`'s case folding: it ORs every byte with 0x20 (`toLowerMask`).
const TO_LOWER_MASK: u32 = 0x2020_2020;
/// `hashStringV2`'s initial value.
const V2_SEED: u32 = 0xB170_A1BF;
/// `hashStringV2`'s final step: a linear congruential generator's
/// multiplier and increment (Numerical Recipes').
const V2_LCG_MULTIPLIER: u32 = 1_664_525;
const V2_LCG_INCREMENT: u32 = 1_013_904_223;
/// The CRC-32 polynomial, reflected (IEEE 802.3).
const CRC32_POLYNOMIAL: u32 = 0xEDB8_8320;

/// `LHashPbCb` / `hashStringV1`: used by the GSI, TPI name hashes, the named
/// stream map, and version-1 string tables.
pub fn hash_v1(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    let (words, mut rest) = bytes.as_chunks::<4>();
    for w in words {
        result ^= u32::from_le_bytes(*w);
    }
    if rest.len() >= 2 {
        result ^= u32::from(u16::from_le_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
    }
    if let [b] = rest {
        result ^= u32::from(*b);
    }
    result |= TO_LOWER_MASK;
    result ^= result >> 11;
    result ^ (result >> 16)
}

/// `hashStringV2`: used by version-2 string tables (`/names`).
pub fn hash_v2(bytes: &[u8]) -> u32 {
    let mut hash = V2_SEED;
    let (words, rest) = bytes.as_chunks::<4>();
    for w in words {
        hash = hash.wrapping_add(u32::from_le_bytes(*w));
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    for &b in rest {
        hash = hash.wrapping_add(u32::from(b));
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash.wrapping_mul(V2_LCG_MULTIPLIER)
        .wrapping_add(V2_LCG_INCREMENT)
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                CRC32_POLYNOMIAL ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// The CRC-32 (zero initial value, no final inversion) that hashes type
/// records which are not keyed by name.
pub fn hash_record(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |crc, &b| {
        CRC_TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_reference() {
        // Standard CRC-32 of "123456789" is CBF43926 (init and final xor
        // FFFFFFFF). With zero init and no final xor it is the CRC of the
        // same bytes run through the same table from 0.
        let standard = !b"123456789".iter().fold(!0u32, |c, &b| {
            CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8)
        });
        assert_eq!(standard, 0xCBF4_3926);
        assert_eq!(hash_record(b""), 0);
    }

    #[test]
    fn case_insensitive_v1() {
        // hash_v1 folds ASCII case for the trailing bytes (|0x20202020).
        assert_eq!(hash_v1(b"main") % 4096, hash_v1(b"MAIN") % 4096);
    }
}

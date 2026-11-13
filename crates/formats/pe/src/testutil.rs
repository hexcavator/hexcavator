//! Synthetic images for unit tests.

extern crate std;
use std::vec::Vec;

use crate::consts::{machine, magic};

/// A PE32+ DLL with one section `name` at `va` holding `contents`, file
/// alignment 0x200 and section alignment 0x1000, image base 0x1_8000_0000,
/// and the given data directories (index, RVA, size).
pub(crate) fn image64_with(
    name: &[u8],
    va: u32,
    contents: &[u8],
    directories: &[(usize, u32, u32)],
) -> Vec<u8> {
    fn put(b: &mut Vec<u8>, at: usize, bytes: &[u8]) {
        if b.len() < at + bytes.len() {
            b.resize(at + bytes.len(), 0);
        }
        b[at..at + bytes.len()].copy_from_slice(bytes);
    }
    let len = u32::try_from(contents.len()).unwrap();
    let raw = len.div_ceil(0x200).max(1) * 0x200;
    let vsize = len.max(1);
    let mut b = Vec::new();
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3C, &0x80u32.to_le_bytes());
    put(&mut b, 0x80, b"PE\0\0");
    put(&mut b, 0x84, &machine::AMD64.to_le_bytes());
    put(&mut b, 0x86, &1u16.to_le_bytes());
    put(&mut b, 0x94, &0xF0u16.to_le_bytes());
    put(&mut b, 0x96, &0x2022u16.to_le_bytes());
    let o = 0x98;
    put(&mut b, o, &magic::PE32_PLUS.to_le_bytes());
    put(&mut b, o + 24, &0x1_8000_0000u64.to_le_bytes());
    put(&mut b, o + 32, &0x1000u32.to_le_bytes());
    put(&mut b, o + 36, &0x200u32.to_le_bytes());
    let image_size = (va + vsize).div_ceil(0x1000) * 0x1000;
    put(&mut b, o + 56, &image_size.to_le_bytes());
    put(&mut b, o + 60, &0x200u32.to_le_bytes());
    put(&mut b, o + 68, &3u16.to_le_bytes());
    put(&mut b, o + 108, &16u32.to_le_bytes());
    for &(index, rva, size) in directories {
        put(&mut b, o + 112 + index * 8, &rva.to_le_bytes());
        put(&mut b, o + 112 + index * 8 + 4, &size.to_le_bytes());
    }
    let s = o + 0xF0;
    put(&mut b, s, name);
    put(&mut b, s + 8, &vsize.to_le_bytes());
    put(&mut b, s + 12, &va.to_le_bytes());
    put(&mut b, s + 16, &raw.to_le_bytes());
    put(&mut b, s + 20, &0x200u32.to_le_bytes());
    put(&mut b, s + 36, &0x4000_0040u32.to_le_bytes());
    put(&mut b, 0x200, contents);
    b.resize(0x200 + raw as usize, 0);
    b
}

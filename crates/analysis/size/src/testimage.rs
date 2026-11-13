//! Synthetic images for unit tests.

/// A little-endian buffer that grows as it is written.
#[derive(Default)]
pub(crate) struct Buf(pub Vec<u8>);

impl Buf {
    pub fn bytes(&mut self, at: usize, bytes: &[u8]) -> &mut Self {
        if self.0.len() < at + bytes.len() {
            self.0.resize(at + bytes.len(), 0);
        }
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
        self
    }
    pub fn u16(&mut self, at: usize, v: u16) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
    pub fn u32(&mut self, at: usize, v: u32) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
    pub fn u64(&mut self, at: usize, v: u64) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
}

/// The RVA of the one section of [`image`].
pub(crate) const SECTION_RVA: u32 = 0x1000;
/// The image base of [`image`].
pub(crate) const IMAGE_BASE: u64 = 0x40_0000;

/// A DLL (PE32+ if `is64`, else PE32) with one section at [`SECTION_RVA`]
/// holding `contents` (file alignment 0x200, section alignment 0x1000),
/// and the given data directories (index, RVA, size).
pub(crate) fn image(is64: bool, contents: &[u8], directories: &[(usize, u32, u32)]) -> Vec<u8> {
    let raw = u32::try_from(contents.len())
        .unwrap()
        .div_ceil(0x200)
        .max(1)
        * 0x200;
    let mut b = Buf::default();
    b.bytes(0, b"MZ").u32(0x3C, 0x80).bytes(0x80, b"PE\0\0");
    let optional_size: u16 = if is64 { 0xF0 } else { 0xE0 };
    b.u16(0x84, if is64 { 0x8664 } else { 0x14C })
        .u16(0x86, 1)
        .u16(0x94, optional_size)
        .u16(0x96, 0x2102);
    let o = 0x98;
    // Fields after the image base move by 4 in PE32 (no base of data,
    // 8-byte stack and heap sizes in PE32+).
    if is64 {
        b.u16(o, 0x20B).u64(o + 24, IMAGE_BASE);
    } else {
        b.u16(o, 0x10B).u32(o + 28, IMAGE_BASE as u32);
    }
    let size_of_image = (SECTION_RVA + raw).div_ceil(0x1000) * 0x1000;
    b.u32(o + 32, 0x1000)
        .u32(o + 36, 0x200)
        .u32(o + 56, size_of_image)
        .u32(o + 60, 0x200)
        .u16(o + 68, 3);
    let dirs = if is64 { o + 112 } else { o + 96 };
    b.u32(dirs - 4, 16);
    for &(index, rva, size) in directories {
        b.u32(dirs + index * 8, rva).u32(dirs + index * 8 + 4, size);
    }
    let s = o + usize::from(optional_size);
    b.bytes(s, b".data")
        .u32(s + 8, raw)
        .u32(s + 12, SECTION_RVA)
        .u32(s + 16, raw)
        .u32(s + 20, 0x200)
        .u32(s + 36, 0xC000_0040);
    b.bytes(0x200, contents);
    b.0.resize(0x200 + raw as usize, 0);
    b.0
}

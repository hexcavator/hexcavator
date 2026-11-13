//! Sections, in a form common to every file format.

/// What a section holds and how it is mapped, independent of format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SectionFlags(pub u32);

impl SectionFlags {
    /// Mapped readable.
    pub const READ: u32 = 1 << 0;
    /// Mapped writable.
    pub const WRITE: u32 = 1 << 1;
    /// Mapped executable.
    pub const EXECUTE: u32 = 1 << 2;
    /// Holds code.
    pub const CODE: u32 = 1 << 3;
    /// Holds initialized data.
    pub const DATA: u32 = 1 << 4;
    /// Holds zero-initialized data, which occupies memory but not the file.
    pub const ZERO_FILL: u32 = 1 << 5;
    /// Not loaded at run time (debug info, linker directives, ...).
    pub const NOT_LOADED: u32 = 1 << 6;
    /// A COMDAT section (objects only): one of possibly many duplicates the
    /// linker chooses between.
    pub const COMDAT: u32 = 1 << 7;
    /// Information for the linker only (objects only).
    pub const LINKER_INFO: u32 = 1 << 8;

    /// Whether every flag in `flags` is set.
    #[inline]
    pub const fn contains(self, flags: u32) -> bool {
        self.0 & flags == flags
    }
}

/// A section of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'data> {
    /// The section's index in the file's section table (0-based).
    pub index: usize,
    /// Its name (in a format's own encoding; for a Mach-O section, without
    /// its segment's).
    pub name: &'data [u8],
    /// The section's address (see the crate documentation); 0 in objects.
    pub addr: u64,
    /// The section's size in memory; for objects, its size.
    pub vm_size: u64,
    /// Where the section's data starts in the file.
    pub file_offset: u64,
    /// How many bytes of the section's data are in the file. This can be
    /// less than `vm_size` (the rest is zero-filled) or more (the data is
    /// padded to the file alignment).
    pub file_size: u64,
    /// What it holds and how it is mapped, whatever the format.
    pub flags: SectionFlags,
    /// The format's own flags (PE: `Characteristics`).
    pub raw_flags: u32,
}

impl Section<'_> {
    /// Whether `addr` is within the section's memory extent.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr - self.addr < self.vm_size
    }

    /// The end of the section's memory extent, or `None` on overflow.
    pub fn end(&self) -> Option<u64> {
        self.addr.checked_add(self.vm_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(addr: u64, vm_size: u64) -> Section<'static> {
        Section {
            index: 0,
            name: b".text",
            addr,
            vm_size,
            file_offset: 0,
            file_size: 0,
            flags: SectionFlags::default(),
            raw_flags: 0,
        }
    }

    #[test]
    fn contains() {
        let s = section(0x1000, 0x10);
        assert!(!s.contains(0xFFF));
        assert!(s.contains(0x1000));
        assert!(s.contains(0x100F));
        assert!(!s.contains(0x1010));
        assert!(!section(0x1000, 0).contains(0x1000));
    }

    #[test]
    fn end_and_overflow() {
        assert_eq!(section(0x1000, 0x10).end(), Some(0x1010));
        assert_eq!(section(u64::MAX, 1).end(), None);
        assert!(section(u64::MAX, 1).contains(u64::MAX));
    }

    #[test]
    fn flags() {
        let f = SectionFlags(SectionFlags::READ | SectionFlags::CODE);
        assert!(f.contains(SectionFlags::READ));
        assert!(f.contains(SectionFlags::READ | SectionFlags::CODE));
        assert!(!f.contains(SectionFlags::READ | SectionFlags::WRITE));
        assert!(f.contains(0));
    }
}

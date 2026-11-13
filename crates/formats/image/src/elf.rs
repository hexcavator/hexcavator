//! The ELF backend.

use alloc::vec::Vec;

use hexcavator_elf::consts::*;
use hexcavator_elf::{AddressRelocation, Class, ElfFile};

use crate::{DebugId, Kind, Section, SectionFlags};

pub(crate) fn kind(elf: &ElfFile<'_>) -> Kind {
    match elf.header().kind {
        ET_REL => Kind::Object,
        ET_CORE => Kind::Dump,
        _ => Kind::Linked,
    }
}

/// Translates a section's type and flags to [`SectionFlags`].
pub(crate) fn flags(kind: u32, flags: u64, comdat: bool) -> SectionFlags {
    let alloc = flags & SHF_ALLOC != 0;
    let exec = flags & SHF_EXECINSTR != 0;
    let mut f = 0;
    if alloc {
        f |= SectionFlags::READ;
    } else {
        f |= SectionFlags::NOT_LOADED;
    }
    if flags & SHF_WRITE != 0 {
        f |= SectionFlags::WRITE;
    }
    if exec {
        f |= SectionFlags::EXECUTE | SectionFlags::CODE;
    }
    if kind == SHT_NOBITS {
        f |= SectionFlags::ZERO_FILL;
    } else if alloc && !exec {
        f |= SectionFlags::DATA;
    }
    if comdat {
        f |= SectionFlags::COMDAT;
    }
    if flags & SHF_EXCLUDE != 0 {
        f |= SectionFlags::LINKER_INFO | SectionFlags::NOT_LOADED;
    }
    SectionFlags(f)
}

pub(crate) fn sections<'data>(elf: &ElfFile<'data>) -> Vec<Section<'data>> {
    let object = elf.is_object();
    // The members of COMDAT groups.
    let mut comdat: Vec<u32> = elf
        .groups()
        .into_iter()
        .filter(|g| g.flags & GRP_COMDAT != 0)
        .flat_map(|g| g.members)
        .collect();
    comdat.sort_unstable();
    elf.sections()
        .filter(|s| s.kind != SHT_NULL)
        .map(|s| {
            let in_comdat = u32::try_from(s.index).is_ok_and(|i| comdat.binary_search(&i).is_ok());
            // Sections that aren't loaded have no extent in memory (their
            // address is 0); objects' sections have their size.
            let vm_size = if object || s.is_alloc() { s.size } else { 0 };
            Section {
                index: s.index,
                name: s.name,
                addr: if object { 0 } else { s.addr },
                vm_size,
                file_offset: s.offset,
                file_size: s.file_size(),
                flags: flags(s.kind, s.flags, in_comdat),
                // (ELF's flags are 64 bits wide; every one defined is in the
                // low 32.)
                raw_flags: u32::try_from(s.flags & 0xFFFF_FFFF).unwrap_or_default(),
            }
        })
        .collect()
}

pub(crate) fn debug_ids<'data>(elf: &ElfFile<'data>) -> Vec<DebugId<'data>> {
    let mut out = Vec::new();
    if let Some(id) = elf.build_id() {
        out.push(DebugId::BuildId(id));
    }
    if let Some(l) = elf.debug_link() {
        out.push(DebugId::DebugLink {
            path: l.path,
            crc: Some(l.crc),
        });
    }
    if let Some(l) = elf.alt_link() {
        out.push(DebugId::AltLink {
            path: l.path,
            build_id: l.build_id,
        });
    }
    out
}

pub(crate) fn pointer_slots(elf: &ElfFile<'_>) -> Vec<crate::PointerSlot> {
    let mut out = Vec::new();
    if elf.is_object() {
        return out;
    }
    let width: u8 = match elf.class() {
        Class::Elf32 => 4,
        Class::Elf64 => 8,
    };
    let machine = elf.header().machine;
    let sections: Vec<_> = elf.sections().collect();
    // The word the file holds at `addr` (a REL relocation's addend).
    let word = |addr: u64| {
        let b = bytes_at(elf, addr, u64::from(width))?;
        Some(match elf.endian() {
            hexcavator_core::Endian::Little => {
                b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x))
            }
            hexcavator_core::Endian::Big => b.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)),
        })
    };
    for s in &sections {
        // (Relocations the loader applies are in loaded sections.)
        if !s.is_alloc() {
            continue;
        }
        if s.kind == SHT_RELR || s.kind == SHT_ANDROID_RELR {
            for addr in elf.relr(s) {
                out.push(crate::PointerSlot {
                    addr,
                    width,
                    target: word(addr),
                });
            }
            continue;
        }
        if !matches!(
            s.kind,
            SHT_REL | SHT_RELA | SHT_ANDROID_REL | SHT_ANDROID_RELA
        ) {
            continue;
        }
        let symbols = sections
            .get(s.link as usize)
            .map(|t| elf.symbols(t))
            .unwrap_or_default();
        for r in elf.relocations(s) {
            let Some(how) = hexcavator_elf::address_relocation(machine, r.kind) else {
                continue;
            };
            let addend = r.addend.map(|a| a as u64).or_else(|| word(r.offset));
            let target = match how {
                AddressRelocation::Relative | AddressRelocation::IndirectFunction => addend,
                AddressRelocation::Symbol => symbols
                    .get(r.symbol as usize)
                    .filter(|sym| sym.shndx != u32::from(SHN_UNDEF))
                    .map(|sym| sym.value.wrapping_add(r.addend.map_or(0, |a| a as u64))),
            };
            out.push(crate::PointerSlot {
                addr: r.offset,
                width,
                target,
            });
        }
    }
    out
}

pub(crate) fn bytes_at<'data>(elf: &ElfFile<'data>, addr: u64, len: u64) -> Option<&'data [u8]> {
    if elf.is_object() {
        return None;
    }
    let s = elf.sections().find(|s| {
        s.is_alloc()
            && s.has_file_data()
            && addr >= s.addr
            && addr - s.addr < s.size
            && len <= s.size - (addr - s.addr)
    })?;
    let data = elf.section_data(&s);
    let at = usize::try_from(addr - s.addr).ok()?;
    data.get(at..at.checked_add(usize::try_from(len).ok()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_flags() {
        let f = flags(SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, false);
        assert!(f.contains(SectionFlags::CODE | SectionFlags::EXECUTE | SectionFlags::READ));
        assert!(!f.contains(SectionFlags::WRITE));
        assert!(!f.contains(SectionFlags::DATA));
        assert!(!f.contains(SectionFlags::NOT_LOADED));
    }

    #[test]
    fn data_and_bss_flags() {
        let data = flags(SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, false);
        assert!(data.contains(SectionFlags::DATA | SectionFlags::WRITE | SectionFlags::READ));
        let bss = flags(SHT_NOBITS, SHF_ALLOC | SHF_WRITE, false);
        assert!(bss.contains(SectionFlags::ZERO_FILL | SectionFlags::WRITE));
        assert!(!bss.contains(SectionFlags::DATA));
    }

    #[test]
    fn unloaded_comdat_and_excluded() {
        assert!(flags(SHT_PROGBITS, 0, false).contains(SectionFlags::NOT_LOADED));
        assert!(!flags(SHT_PROGBITS, 0, false).contains(SectionFlags::READ));
        assert!(flags(SHT_PROGBITS, SHF_ALLOC, true).contains(SectionFlags::COMDAT));
        let ex = flags(SHT_PROGBITS, SHF_EXCLUDE, false);
        assert!(ex.contains(SectionFlags::LINKER_INFO | SectionFlags::NOT_LOADED));
    }
}

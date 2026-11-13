//! Symbol versions (GNU: `.gnu.version`, `.gnu.version_d`,
//! `.gnu.version_r`) and the dynamic symbol hash tables (SysV `.hash`,
//! GNU `.gnu.hash`), by which the loader finds a symbol by name.
//!
//! Bounded: lists to 2^16 entries, chains to the table's length. Damage
//! ends a list (or a lookup).

use alloc::vec::Vec;

use crate::consts::*;
use crate::{Class, ElfFile, Section, Symbol, read_u16, read_u32};

/// The most entries of a version list read.
const MAX: usize = 1 << 16;

/// A version a file defines (`Elf*_Verdef`): its index (what symbols'
/// versions name), flags (`VER_FLG_*`), hash, name, and the versions it
/// succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionDefinition<'d> {
    pub index: u16,
    pub flags: u16,
    pub hash: u32,
    pub name: &'d [u8],
    pub predecessors: Vec<&'d [u8]>,
}

/// A version a file needs of another (`Elf*_Vernaux`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionNeeded<'d> {
    pub index: u16,
    pub flags: u16,
    pub hash: u32,
    pub name: &'d [u8],
}

/// A file a file needs versions of (`Elf*_Verneed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionNeed<'d> {
    pub file: &'d [u8],
    pub versions: Vec<VersionNeeded<'d>>,
}

/// A dynamic symbol's version: its name, whether it is hidden (not the
/// default: `@` rather than `@@`), and, for one needed of another file,
/// that file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolVersion<'d> {
    pub index: u16,
    pub name: &'d [u8],
    pub hidden: bool,
    pub file: Option<&'d [u8]>,
}

pub const VER_FLG_BASE: u16 = 0x1;
pub const VER_FLG_WEAK: u16 = 0x2;
pub const VER_NDX_LOCAL: u16 = 0;
pub const VER_NDX_GLOBAL: u16 = 1;

/// The SysV hash of a symbol name (`.hash`'s).
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    for &c in name {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// The GNU hash of a symbol name (`.gnu.hash`'s: DJB's).
pub fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |h, &c| {
        h.wrapping_mul(33).wrapping_add(u32::from(c))
    })
}

impl<'data> ElfFile<'data> {
    fn find_kind(&self, kind: u32) -> Option<Section<'data>> {
        self.sections()
            .find(|s| s.kind == kind && s.has_file_data())
    }

    /// A string of the string table `link` names.
    fn linked_string(&self, link: u32, offset: u32) -> &'data [u8] {
        let Some(strtab) = self.section(link as usize) else {
            return &[];
        };
        let data = self.section_data(&strtab);
        data.get(offset as usize..)
            .and_then(|r| r.split(|&b| b == 0).next())
            .unwrap_or(&[])
    }

    /// The versions the file defines.
    pub fn version_definitions(&self) -> Vec<VersionDefinition<'data>> {
        let mut out = Vec::new();
        let Some(s) = self.find_kind(SHT_GNU_VERDEF) else {
            return out;
        };
        let data = self.section_data(&s);
        let e = self.endian();
        let mut at = 0u64;
        while out.len() < MAX {
            let (
                Some(_version),
                Some(flags),
                Some(index),
                Some(count),
                Some(hash),
                Some(aux),
                Some(next),
            ) = (
                read_u16(data, at, e),
                read_u16(data, at + 2, e),
                read_u16(data, at + 4, e),
                read_u16(data, at + 6, e),
                read_u32(data, at + 8, e),
                read_u32(data, at + 12, e),
                read_u32(data, at + 16, e),
            )
            else {
                break;
            };
            let mut names = Vec::new();
            let mut a = at + u64::from(aux);
            for _ in 0..count.min(256) {
                let (Some(name), Some(anext)) = (read_u32(data, a, e), read_u32(data, a + 4, e))
                else {
                    break;
                };
                names.push(self.linked_string(s.link, name));
                if anext == 0 {
                    break;
                }
                a += u64::from(anext);
            }
            let mut names = names.into_iter();
            out.push(VersionDefinition {
                index,
                flags,
                hash,
                name: names.next().unwrap_or(&[]),
                predecessors: names.collect(),
            });
            if next == 0 {
                break;
            }
            at += u64::from(next);
        }
        out
    }

    /// The versions the file needs of others.
    pub fn version_needs(&self) -> Vec<VersionNeed<'data>> {
        let mut out = Vec::new();
        let Some(s) = self.find_kind(SHT_GNU_VERNEED) else {
            return out;
        };
        let data = self.section_data(&s);
        let e = self.endian();
        let mut at = 0u64;
        while out.len() < MAX {
            let (Some(_version), Some(count), Some(file), Some(aux), Some(next)) = (
                read_u16(data, at, e),
                read_u16(data, at + 2, e),
                read_u32(data, at + 4, e),
                read_u32(data, at + 8, e),
                read_u32(data, at + 12, e),
            ) else {
                break;
            };
            let mut versions = Vec::new();
            let mut a = at + u64::from(aux);
            for _ in 0..count.min(256) {
                let (Some(hash), Some(flags), Some(other), Some(name), Some(anext)) = (
                    read_u32(data, a, e),
                    read_u16(data, a + 4, e),
                    read_u16(data, a + 6, e),
                    read_u32(data, a + 8, e),
                    read_u32(data, a + 12, e),
                ) else {
                    break;
                };
                versions.push(VersionNeeded {
                    index: other,
                    flags,
                    hash,
                    name: self.linked_string(s.link, name),
                });
                if anext == 0 {
                    break;
                }
                a += u64::from(anext);
            }
            out.push(VersionNeed {
                file: self.linked_string(s.link, file),
                versions,
            });
            if next == 0 {
                break;
            }
            at += u64::from(next);
        }
        out
    }

    /// Each dynamic symbol's version (by its index in `.dynsym`): none
    /// for local and global (unversioned) symbols.
    pub fn symbol_versions(&self) -> Vec<Option<SymbolVersion<'data>>> {
        let Some(s) = self.find_kind(SHT_GNU_VERSYM) else {
            return Vec::new();
        };
        let defs = self.version_definitions();
        let needs = self.version_needs();
        let data = self.section_data(&s);
        let e = self.endian();
        (0..data.len() as u64 / 2)
            .map(|i| {
                let v = read_u16(data, i * 2, e)?;
                let (index, hidden) = (v & 0x7FFF, v & 0x8000 != 0);
                if index == VER_NDX_LOCAL || index == VER_NDX_GLOBAL {
                    return None;
                }
                if let Some(d) = defs.iter().find(|d| d.index == index) {
                    return Some(SymbolVersion {
                        index,
                        name: d.name,
                        hidden,
                        file: None,
                    });
                }
                needs.iter().find_map(|n| {
                    let v = n.versions.iter().find(|v| v.index == index)?;
                    Some(SymbolVersion {
                        index,
                        name: v.name,
                        hidden,
                        file: Some(n.file),
                    })
                })
            })
            .collect()
    }

    /// The `.dynsym` index of the symbol named `name`, found as the loader
    /// finds it: through `.gnu.hash` if there is one, else `.hash`.
    pub fn lookup(&self, name: &[u8]) -> Option<usize> {
        if self.find_kind(SHT_GNU_HASH).is_some() {
            self.gnu_lookup(name)
        } else {
            self.sysv_lookup(name)
        }
    }

    /// `name`'s `.dynsym` index, through `.gnu.hash`.
    pub fn gnu_lookup(&self, name: &[u8]) -> Option<usize> {
        let dynsym = self.find_kind(SHT_DYNSYM)?;
        let symbols = self.symbols(&dynsym);
        let named = |i: usize| symbols.get(i).is_some_and(|s: &Symbol<'_>| s.name == name);
        let e = self.endian();
        {
            let s = self.find_kind(SHT_GNU_HASH)?;
            let d = self.section_data(&s);
            let (nbuckets, symoffset, bloom_size, shift) = (
                read_u32(d, 0, e)?,
                read_u32(d, 4, e)?,
                read_u32(d, 8, e)?,
                read_u32(d, 12, e)?,
            );
            let (w, bits) = match self.class() {
                Class::Elf32 => (4u64, 32u32),
                Class::Elf64 => (8, 64),
            };
            if nbuckets == 0 || bloom_size == 0 {
                return None;
            }
            let h = gnu_hash(name);
            // The Bloom filter: both bits, or it isn't there.
            let word_at = 16 + u64::from((h / bits) % bloom_size) * w;
            let word = match self.class() {
                Class::Elf32 => u64::from(read_u32(d, word_at, e)?),
                Class::Elf64 => crate::read_u64(d, word_at, e)?,
            };
            let mask = (1u64 << (h % bits)) | (1u64 << ((h >> (shift & 31)) % bits));
            if word & mask != mask {
                return None;
            }
            let buckets = 16 + u64::from(bloom_size) * w;
            let first = read_u32(d, buckets + u64::from(h % nbuckets) * 4, e)?;
            if first < symoffset {
                return None;
            }
            let chains = buckets + u64::from(nbuckets) * 4;
            // (A chain is the symbols from the bucket's first, to the one
            // whose hash has its low bit set; at most every symbol.)
            for i in (first..u32::MAX).take(symbols.len()) {
                let h2 = read_u32(d, chains + u64::from(i - symoffset) * 4, e)?;
                if h | 1 == h2 | 1 && named(i as usize) {
                    return Some(i as usize);
                }
                if h2 & 1 != 0 {
                    return None;
                }
            }
            None
        }
    }

    /// `name`'s `.dynsym` index, through `.hash`.
    pub fn sysv_lookup(&self, name: &[u8]) -> Option<usize> {
        let dynsym = self.find_kind(SHT_DYNSYM)?;
        let symbols = self.symbols(&dynsym);
        let named = |i: usize| symbols.get(i).is_some_and(|s: &Symbol<'_>| s.name == name);
        let e = self.endian();
        let s = self.find_kind(SHT_HASH)?;
        let d = self.section_data(&s);
        let (nbucket, nchain) = (read_u32(d, 0, e)?, read_u32(d, 4, e)?);
        if nbucket == 0 {
            return None;
        }
        let mut i = read_u32(d, 8 + u64::from(sysv_hash(name) % nbucket) * 4, e)?;
        let chains = 8 + u64::from(nbucket) * 4;
        for _ in 0..nchain {
            if i == 0 || i >= nchain {
                return None;
            }
            if named(i as usize) {
                return Some(i as usize);
            }
            i = read_u32(d, chains + u64::from(i) * 4, e)?;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        // The gABI's and glibc's.
        assert_eq!(sysv_hash(b""), 0);
        assert_eq!(sysv_hash(b"printf"), 0x077905A6);
        assert_eq!(gnu_hash(b""), 5381);
        assert_eq!(gnu_hash(b"printf"), 0x156B2BB8);
    }
}

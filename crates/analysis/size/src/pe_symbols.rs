//! Symbols for the structures a PE image describes itself, apart from
//! exception data ([`crate::eh`]) and resources ([`crate::rsrc`]): imports,
//! delay-load imports, PE directories, debug directory data, and the load
//! configuration's guard tables, named as SizeBench names them.
//!
//! Where SizeBench goes wrong, these don't follow it:
//!
//! - Import name tables end at a zero entry, not at an entry whose low 16
//!   bits are zero (a name at an RVA that is a multiple of 0x10000).
//! - Delay-load descriptors are 32 bytes (`IMAGE_DELAYLOAD_DESCRIPTOR`),
//!   not 20 (`IMAGE_IMPORT_DESCRIPTOR`); Visual C++ 6 descriptors, which
//!   hold addresses rather than RVAs, are read as such.
//! - An import descriptor with a name but no import name table is a
//!   descriptor, not the terminator.
//! - Guard tables are found whenever the load configuration's own size
//!   holds their fields, not by the data directory's size.

use std::collections::HashSet;

use hexcavator_core::{Rva, Va, cstr_at};
use hexcavator_pe::PeFile;
use hexcavator_pe::consts::directory;
use hexcavator_pe::load_config::field;

use crate::Size;
use crate::symbols::{Symbol, SymbolKind};

/// At most this many entries are read from any one table.
const MAX_ENTRIES: u32 = 0x10_0000;

struct Builder<'a, 'data> {
    pe: &'a PeFile<'data>,
    /// Symbol addresses so far: the first symbol at an address wins.
    seen: HashSet<u64>,
    out: Vec<Symbol>,
    /// Pointer size.
    word: u32,
}

impl Builder<'_, '_> {
    fn add(&mut self, kind: SymbolKind, rva: u32, size: u64, name: String) {
        if !self.seen.insert(u64::from(rva)) {
            return;
        }
        self.out.push(Symbol {
            addr: u64::from(rva),
            size: Size::new(size, size),
            kind,
            folded: false,
            name,
            compiland: None,
            file_static: false,
        });
    }

    fn u32(&self, rva: u32) -> Option<u32> {
        let b = self.pe.bytes_at_rva(Rva(rva), 4).ok()?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    fn u16(&self, rva: u32) -> Option<u16> {
        let b = self.pe.bytes_at_rva(Rva(rva), 2).ok()?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    }

    /// A pointer-sized value.
    fn word(&self, rva: u32) -> Option<u64> {
        self.pe.thunk(Rva(rva))
    }

    /// The NUL-terminated string at `rva`.
    fn cstr(&self, rva: u32) -> Option<String> {
        let offset = self.pe.rva_to_offset(Rva(rva))?;
        let bytes = cstr_at(self.pe.data(), offset).ok()?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    fn ordinal_flag(&self) -> u64 {
        if self.word == 8 { 1 << 63 } else { 1 << 31 }
    }

    /// A DLL's name, and its string symbol.
    fn dll_name(&mut self, rva: u32) -> Option<String> {
        let name = self.cstr(rva)?;
        self.add(
            SymbolKind::ImportString,
            rva,
            name.len() as u64 + 1,
            format!("`string': \"{name}\""),
        );
        Some(name)
    }

    /// One import name table entry (and, for a delay-load DLL, the import
    /// address table entry beside it); `bias` converts an entry's address
    /// of its name to an RVA. Returns `false` at the terminator.
    fn thunk(
        &mut self,
        dll: &str,
        name_entry: u32,
        address_entry: Option<u32>,
        bias: u64,
    ) -> Option<bool> {
        let value = self.word(name_entry)?;
        let word = u64::from(self.word);
        if value == 0 {
            if let Some(iat) = address_entry {
                self.add(
                    SymbolKind::ImportThunk,
                    name_entry,
                    word,
                    format!("[import thunk] {dll} INT null terminator, ordinal 0"),
                );
                self.add(
                    SymbolKind::ImportThunk,
                    iat,
                    word,
                    format!("[import thunk] {dll} IAT null terminator, ordinal 0"),
                );
            } else {
                self.add(
                    SymbolKind::ImportThunk,
                    name_entry,
                    word,
                    format!("[import thunk] {dll} null terminator, ordinal 0"),
                );
            }
            return Some(false);
        }
        let name = if value & self.ordinal_flag() != 0 {
            format!("[import thunk] {dll} Ordinal {}", value & 0xFFFF)
        } else {
            let rva = u32::try_from(value.checked_sub(bias)?).ok()?;
            let hint = self.u16(rva)?;
            let function = self.cstr(rva.checked_add(2)?)?;
            self.add(
                SymbolKind::ImportByName,
                rva,
                function.len() as u64 + 3,
                format!("`string': \"{function}\""),
            );
            format!("[import thunk] {dll} {function}, ordinal {hint}")
        };
        if let Some(iat) = address_entry {
            self.add(SymbolKind::ImportThunk, name_entry, word, name.clone());
            self.add(SymbolKind::ImportThunk, iat, word, name);
        } else {
            self.add(SymbolKind::ImportThunk, name_entry, word, name);
        }
        Some(true)
    }

    fn imports(&mut self) {
        let Some(d) = self.pe.data_directory(directory::IMPORT) else {
            return;
        };
        let (start, size) = (d.virtual_address.get(), d.size.get());
        if size == 0 {
            return;
        }
        let end = start.saturating_add(size);
        let mut at = start;
        while at < end {
            let field = |i: u32| self.u32(at.checked_add(4 * i)?);
            let (Some(names), Some(name)) = (field(0), field(3)) else {
                break;
            };
            if name == 0 {
                self.add(
                    SymbolKind::ImportDescriptor,
                    at,
                    20,
                    "[import descriptor] null terminator".into(),
                );
                break;
            }
            let dll = self.dll_name(name).unwrap_or_default();
            self.add(
                SymbolKind::ImportDescriptor,
                at,
                20,
                format!("[import descriptor] {dll}"),
            );
            if names != 0 {
                for i in 0..MAX_ENTRIES {
                    let Some(entry) = names.checked_add(i * self.word) else {
                        break;
                    };
                    if self.thunk(&dll, entry, None, 0) != Some(true) {
                        break;
                    }
                }
            }
            let Some(next) = at.checked_add(20) else {
                break;
            };
            at = next;
        }
    }

    fn delay_imports(&mut self) {
        let Some(d) = self.pe.data_directory(directory::DELAY_IMPORT) else {
            return;
        };
        let (start, size) = (d.virtual_address.get(), d.size.get());
        if size == 0 {
            return;
        }
        let base = self
            .pe
            .optional_header()
            .map_or(0, |h| h.image_base().get());
        let end = start.saturating_add(size);
        let mut at = start;
        while at < end {
            let Some(attributes) = self.u32(at) else {
                break;
            };
            let rva_based = attributes & 1 != 0;
            let bias = if rva_based { 0 } else { base };
            let to_rva = |v: u32| -> Option<u32> {
                if v == 0 {
                    None
                } else if rva_based {
                    Some(v)
                } else {
                    self.pe
                        .va_to_rva(Va(u64::from(v)))
                        .map(hexcavator_core::Rva::get)
                }
            };
            let field = |i: u32| self.u32(at.checked_add(4 * i)?).and_then(to_rva);
            let (name, iat, int) = (field(1), field(3), field(4));
            let (Some(name), Some(iat), Some(int)) = (name, iat, int) else {
                self.add(
                    SymbolKind::ImportDescriptor,
                    at,
                    32,
                    "[import descriptor] null terminator".into(),
                );
                break;
            };
            let dll = self.dll_name(name).unwrap_or_default();
            self.add(
                SymbolKind::ImportDescriptor,
                at,
                32,
                format!("[import descriptor] {dll}"),
            );
            for i in 0..MAX_ENTRIES {
                let offset = i * self.word;
                let (Some(n), Some(a)) = (int.checked_add(offset), iat.checked_add(offset)) else {
                    break;
                };
                if self.thunk(&dll, n, Some(a), bias) != Some(true) {
                    break;
                }
            }
            let Some(next) = at.checked_add(32) else {
                break;
            };
            at = next;
        }
    }

    /// `[PE Directory] <name>` for directory `index`, if it has an RVA.
    fn directory(&mut self, index: usize, name: &str) {
        if let Some(d) = self.pe.data_directory(index)
            && d.virtual_address.get() != 0
        {
            self.add(
                SymbolKind::PeDirectory,
                d.virtual_address.get(),
                u64::from(d.size.get()),
                format!("[PE Directory] {name}"),
            );
        }
    }

    fn debug(&mut self) {
        self.directory(directory::DEBUG, "Debug");
        let entries = self.pe.debug_directories().unwrap_or(&[]);
        for (i, e) in entries.iter().enumerate() {
            let (rva, size) = (e.address_of_raw_data.get(), e.size_of_data.get());
            // (SizeBench shows the first entry even if it is empty.)
            if rva == 0 || (size == 0 && i > 0) {
                continue;
            }
            self.add(
                SymbolKind::PeDirectory,
                rva,
                u64::from(size),
                format!(
                    "[PE Directory] [Debug Directory] {}",
                    debug_type_name(e.kind.get())
                ),
            );
        }
    }

    fn load_config(&mut self) {
        let Some(d) = self.pe.data_directory(directory::LOAD_CONFIG) else {
            return;
        };
        if d.virtual_address.get() == 0 || d.size.get() == 0 {
            return;
        }
        self.directory(directory::LOAD_CONFIG, "Load Config");
        let Some(lc) = self.pe.load_config() else {
            return;
        };
        let stride = 4 + lc.guard_table_stride() as u64;
        for (table, count, name) in [
            (
                field::GUARD_CF_FUNCTION_TABLE,
                field::GUARD_CF_FUNCTION_COUNT,
                "FID Table",
            ),
            (
                field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_TABLE,
                field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_COUNT,
                "IAT Address-Taken Table",
            ),
        ] {
            let (Some(va), Some(count)) = (lc.get(table), lc.get(count)) else {
                continue;
            };
            if va == 0 || count == 0 {
                continue;
            }
            let Some(rva) = self.pe.va_to_rva(Va(va)) else {
                continue;
            };
            let Some(size) = count
                .checked_mul(stride)
                .filter(|&s| s <= u64::from(u32::MAX))
            else {
                continue;
            };
            self.add(SymbolKind::LoadConfigTable, rva.get(), size, name.into());
        }
    }
}

/// The name SizeBench gives a debug directory entry type.
pub fn debug_type_name(kind: u32) -> String {
    let name = match kind {
        0 => "Unknown",
        1 => "COFF",
        2 => "CodeView",
        3 => "FPO",
        4 => "Misc",
        5 => "Exception",
        6 => "Fixup",
        7 => "OmapToSrc",
        8 => "OmapFromSrc",
        9 => "Borland",
        10 => "Reserved10",
        11 => "Clsid",
        12 => "VCFeature",
        13 => "POGO",
        14 => "ILTCG",
        15 => "MPX",
        16 => "Repro",
        17 => "EmbeddedPortablePDB",
        18 => "SPGO",
        19 => "PDBChecksum",
        20 => "ExtendedDllCharacteristics",
        _ => return kind.to_string(),
    };
    name.to_string()
}

/// The symbols for `pe`'s imports, directories, debug data, and guard
/// tables, sorted by address.
pub fn symbols(pe: &PeFile<'_>) -> Vec<Symbol> {
    let word = match pe.optional_header() {
        Some(h) if h.is_64() => 8,
        _ => 4,
    };
    let mut b = Builder {
        pe,
        seen: HashSet::new(),
        out: Vec::new(),
        word,
    };
    // In SizeBench's order, which decides which of two symbols at one
    // address is kept.
    if pe
        .data_directory(directory::EXPORT)
        .is_some_and(|d| d.size.get() != 0)
    {
        b.directory(directory::EXPORT, "Exports");
    }
    b.imports();
    b.directory(directory::BASERELOC, "Base Relocation Table");
    b.debug();
    b.load_config();
    b.delay_imports();
    let mut out = b.out;
    out.sort_by_key(|s| s.addr);
    out
}

#[cfg(test)]
#[path = "pe_symbols_tests.rs"]
mod tests;

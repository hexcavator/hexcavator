//! A datum of a program: its bytes (as loaded), its section, its value read
//! as its type (from the debug information), and the slots its image's
//! base relocations say hold addresses, each named by what it points into.
//!
//! (Pointer slots are the image's: PE's base relocations, ELF's dynamic
//! and packed relocations; Mach-O's, not yet.)

use hexcavator_debuginfo::TypeRef;
use hexcavator_debuginfo::value::{self, Limits, Value};
use hexcavator_size::symbols::{Symbol, SymbolKind};

use crate::Program;

/// Names addresses: the symbol each is in, and how far into it
/// (`name+0x10`).
#[derive(Clone, Debug, Default)]
pub struct AddressNames {
    /// The image's base: the names are of virtual addresses.
    base: u64,
    /// (rva, size, name), by address.
    symbols: Vec<(u64, u64, String)>,
}

impl AddressNames {
    /// Names by `symbols` (relative to `base`).
    pub fn new(base: u64, symbols: &[Symbol]) -> Self {
        let mut list: Vec<(u64, u64, String)> = symbols
            .iter()
            .filter(|s| !s.folded)
            .map(|s| (s.addr, s.size.vm.max(s.size.file), s.name.clone()))
            .collect();
        list.sort_by_key(|s| s.0);
        Self {
            base,
            symbols: list,
        }
    }

    /// The symbol virtual address `va` is in, and the offset into it.
    pub fn name(&self, va: u64) -> Option<String> {
        let rva = va.checked_sub(self.base)?;
        let i = self
            .symbols
            .partition_point(|s| s.0 <= rva)
            .checked_sub(1)?;
        let (at, size, name) = &self.symbols[i];
        let off = rva - at;
        if off == 0 {
            Some(name.clone())
        } else if off < (*size).max(1) {
            Some(format!("{name}+{off:#x}"))
        } else {
            None
        }
    }
}

/// A slot holding an address (by the base relocations).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pointer {
    /// From the start of the datum.
    pub offset: u64,
    /// Its width in bytes.
    pub size: u64,
    /// The address it holds.
    pub target: u64,
    /// What that address is in.
    pub name: Option<String>,
}

/// A datum, read.
#[derive(Clone, Debug)]
pub struct Datum {
    /// Its symbol's name.
    pub name: String,
    /// Its symbol's kind.
    pub kind: SymbolKind,
    /// Its address, in the image's convention (an RVA for PE).
    pub rva: u64,
    /// Its virtual address (at the image's preferred base).
    pub address: u64,
    /// The section it is in.
    pub section: String,
    /// Its size (in memory, or in the file if more).
    pub size: u64,
    /// Its bytes in the file (the rest are zeros when loaded).
    pub file_size: u64,
    /// The bytes read (up to the maximum asked for).
    pub bytes: Vec<u8>,
    /// Its value as its type, if the debug information gives one.
    pub value: Option<Value>,
    /// The slots in it the loader writes addresses into.
    pub pointers: Vec<Pointer>,
}

/// Whether a symbol of this kind is code.
pub fn is_code(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Function
            | SymbolKind::PrimaryBlock
            | SymbolKind::SeparatedBlock
            | SymbolKind::Thunk
    )
}

impl Program<'_> {
    /// Names for this program's addresses.
    ///
    /// # Errors
    ///
    /// If the debug information is damaged.
    pub fn address_names(&self) -> Result<AddressNames, crate::Error> {
        Ok(AddressNames::new(self.image.image_base(), self.symbols()?))
    }

    /// The datum named `name` (else the one whose name is it with
    /// parameters or more), its first `max` bytes read.
    ///
    /// # Errors
    ///
    /// If there is no such datum (or the name is code's), or the debug
    /// information is damaged.
    pub fn datum(&self, name: &str, max: u64) -> Result<Datum, crate::Error> {
        let syms = self.symbols()?;
        let candidates: Vec<&Symbol> = syms
            .iter()
            .filter(|s| !is_code(s.kind) && !s.folded && s.size.vm.max(s.size.file) > 0)
            .collect();
        let target = match candidates.iter().find(|s| s.name == name) {
            Some(s) => *s,
            None => {
                if syms.iter().any(|s| s.name == name && is_code(s.kind)) {
                    return Err(crate::Error::IsCode {
                        path: self.path.to_path_buf(),
                        name: name.to_string(),
                    });
                }
                let mut alone = hexcavator_size::disasm::ByNameAlone::new(name);
                for s in &candidates {
                    alone.offer(s.addr, &s.name, || *s);
                }
                alone.take().ok_or_else(|| crate::Error::NoDatum {
                    path: self.path.to_path_buf(),
                    name: name.to_string(),
                })?
            }
        };
        let rva = target.addr;
        let size = target.size.vm.max(target.size.file);
        let read = size.min(max);
        // Its bytes: those in the file, then zeros (as loaded).
        let in_file = target.size.file.min(read);
        let mut bytes = if in_file > 0 {
            self.image
                .bytes_at(rva, in_file)
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // (`max` bounds it: the caller's choice of how much to hold.)
        bytes.resize(usize::try_from(read).unwrap_or(usize::MAX), 0);
        let base = self.image.image_base();
        let section = self
            .model()?
            .sections
            .iter()
            .find(|s| rva >= s.addr && rva - s.addr < s.size.vm.max(s.size.file))
            .map(|s| s.name.clone())
            .unwrap_or_default();
        // Its type: the debug information's variable at its address.
        let debug_syms = self
            .debug
            .symbols()
            .map_err(crate::Error::format(self.debug_path))?;
        let ti = debug_syms
            .iter()
            .filter(|d| d.addr == rva && d.type_index != 0)
            .min_by_key(|d| {
                (
                    d.name != target.name,
                    d.kind != hexcavator_debuginfo::SymbolKind::Data,
                )
            })
            .map(|d| TypeRef(d.type_index));
        let value = ti.map(|ty| value::read(&self.debug, ty, &bytes, Limits::default()));
        // The slots the loader writes addresses into.
        let names = AddressNames::new(base, syms);
        let mut pointers = Vec::new();
        let slots = self.image.pointer_slots();
        let first = slots.partition_point(|p| p.addr < rva);
        for slot in &slots[first..] {
            let (at, w) = (slot.addr, u64::from(slot.width));
            if at.saturating_add(w) > rva + read {
                break;
            }
            let off = at - rva;
            // The address it holds: the image's say (a relocation's
            // addend), else its bytes. (Within `bytes`, whose length is a
            // usize: these fit.)
            let (from, to) = (
                usize::try_from(off).unwrap_or(0),
                usize::try_from(off + w).unwrap_or(0),
            );
            let held = bytes[from..to]
                .iter()
                .rev()
                .fold(0u64, |v, &x| (v << 8) | u64::from(x));
            let v = slot.target.map_or(held, |t| base.wrapping_add(t));
            pointers.push(Pointer {
                offset: off,
                size: w,
                target: v,
                name: slot.target.and_then(|_| names.name(v)),
            });
        }
        pointers.sort_by_key(|p| p.offset);
        Ok(Datum {
            name: target.name.clone(),
            kind: target.kind,
            rva,
            address: base + rva,
            section,
            size,
            file_size: target.size.file,
            bytes,
            value,
            pointers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexcavator_size::Size;

    fn sym(addr: u64, size: u64, name: &str, folded: bool) -> Symbol {
        Symbol {
            addr,
            size: Size {
                file: size,
                vm: size,
            },
            kind: SymbolKind::Data,
            folded,
            name: name.into(),
            compiland: None,
            file_static: false,
        }
    }

    #[test]
    fn addresses_by_the_symbol_they_are_in() {
        let names = AddressNames::new(
            0x1_4000_0000,
            &[
                sym(0x2000, 0x10, "table", false),
                sym(0x1000, 8, "first", false),
                sym(0x1000, 8, "folded", true),
                sym(0x3000, 0, "empty", false),
            ],
        );
        assert_eq!(names.name(0x1_4000_1000).as_deref(), Some("first"));
        assert_eq!(names.name(0x1_4000_2008).as_deref(), Some("table+0x8"));
        // Past a symbol's end, before the next: nothing.
        assert_eq!(names.name(0x1_4000_2010), None);
        // A symbol of no size still names its own address.
        assert_eq!(names.name(0x1_4000_3000).as_deref(), Some("empty"));
        // Before the image, or before its first symbol.
        assert_eq!(names.name(0x1000), None);
        assert_eq!(names.name(0x1_4000_0010), None);
    }
}

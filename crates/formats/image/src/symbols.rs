//! An image's own symbols: what it names without debug information (PE
//! exports and COFF symbols, ELF symbol tables, Mach-O's, WebAssembly's
//! `name` section), and the extent of the image in memory.

use alloc::vec::Vec;

use crate::Image;

/// What an [`ImageSymbol`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SymbolKind {
    /// Code.
    Function,
    /// Data.
    Data,
    /// Something else, or not said (a Mach-O symbol, a PE export).
    Other,
}

/// Where an [`ImageSymbol`] is from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SymbolSource {
    /// The full symbol table (ELF `.symtab`, Mach-O's, COFF's).
    SymbolTable,
    /// What the dynamic linker sees (ELF `.dynsym`, PE exports).
    Exported,
    /// WebAssembly's `name` section.
    Names,
}

/// A symbol the image names itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSymbol<'data> {
    /// Its address (see the crate's addresses).
    pub addr: u64,
    /// Its size, if the format records it (ELF, WebAssembly).
    pub size: Option<u64>,
    /// Its name, as linked (decorated, mangled).
    pub name: &'data [u8],
    /// What it names.
    pub kind: SymbolKind,
    /// Where it is from.
    pub source: SymbolSource,
    /// Whether it is global (seen from other modules).
    pub global: bool,
}

impl<'data> Image<'data> {
    /// The image's own symbols with addresses, sorted by address; at an
    /// address named in more than one table, the full table's first. Files
    /// and sections' names, and undefined and absolute symbols, are left
    /// out.
    pub fn symbols(&self) -> Vec<ImageSymbol<'data>> {
        let mut out = match self {
            Image::Pe(pe) => pe_symbols(pe),
            Image::Elf(elf) => elf_symbols(elf),
            Image::MachO(m) => macho_symbols(m),
            Image::Wasm(m) => wasm_symbols(m),
        };
        out.sort_by(|a, b| {
            (a.addr, a.source, b.size.is_some())
                .cmp(&(b.addr, b.source, a.size.is_some()))
                .then_with(|| a.name.cmp(b.name))
        });
        out.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
        out
    }

    /// The image's extent in memory, as `[start, end)` in the format's
    /// tools' addresses (PE images with their preferred base added): where
    /// its first loaded byte goes, and past its last. The start is what a
    /// `module+offset` address counts from. `None` for objects, and for
    /// images that load nothing.
    pub fn extent(&self) -> Option<(u64, u64)> {
        match self {
            Image::Pe(pe) => {
                let h = pe.optional_header()?;
                let base = h.image_base().get();
                Some((base, base.checked_add(u64::from(h.size_of_image()))?))
            }
            Image::Elf(elf) => {
                use hexcavator_elf::consts::PT_LOAD;
                let mut range: Option<(u64, u64)> = None;
                for s in elf.segments().filter(|s| s.kind == PT_LOAD && s.memsz > 0) {
                    // (The first page holds the headers: a load segment
                    // starts at its alignment.)
                    let align = if s.align.is_power_of_two() {
                        s.align
                    } else {
                        1
                    };
                    let start = s.vaddr & !(align - 1);
                    let end = s.vaddr.checked_add(s.memsz)?;
                    range = Some(match range {
                        Some((a, b)) => (a.min(start), b.max(end)),
                        None => (start, end),
                    });
                }
                range
            }
            Image::MachO(m) => {
                let mut range: Option<(u64, u64)> = None;
                for s in m.segments() {
                    // (`__PAGEZERO` maps no file and guards address 0.)
                    if s.vmsize == 0 || (s.filesize == 0 && s.initprot == 0) {
                        continue;
                    }
                    let end = s.vmaddr.checked_add(s.vmsize)?;
                    range = Some(match range {
                        Some((a, b)) => (a.min(s.vmaddr), b.max(end)),
                        None => (s.vmaddr, end),
                    });
                }
                range
            }
            Image::Wasm(_) => {
                let code = self.sections().into_iter().find(|s| s.vm_size > 0)?;
                Some((0, code.vm_size))
            }
        }
    }
}

fn pe_symbols<'data>(pe: &hexcavator_pe::PeFile<'data>) -> Vec<ImageSymbol<'data>> {
    use hexcavator_pe::exports::ExportTarget;
    let mut out = Vec::new();
    if let Some(exports) = pe.exports() {
        for e in exports.iter() {
            if let (Some(name), ExportTarget::Rva(rva)) = (e.name, e.target) {
                out.push(ImageSymbol {
                    addr: u64::from(rva.0),
                    size: None,
                    name,
                    kind: SymbolKind::Other,
                    source: SymbolSource::Exported,
                    global: true,
                });
            }
        }
    }
    // A COFF symbol table (MinGW's images keep one).
    if let Ok(Some(table)) = pe.symbols() {
        let sections = pe.sections();
        let mut i = 0;
        while let Some(s) = table.get(i) {
            i += 1 + s.aux_count();
            let Some(header) = usize::try_from(s.section - 1)
                .ok()
                .and_then(|n| sections.get(n))
            else {
                continue;
            };
            // External, static, and label symbols; not files, sections,
            // or functions' begin and end markers.
            const EXTERNAL: u8 = 2;
            const STATIC: u8 = 3;
            if !matches!(s.storage_class, EXTERNAL | STATIC)
                || (s.storage_class == STATIC && s.value == 0 && s.aux_count() > 0)
            {
                continue;
            }
            let Some(name) = table.name(&s).filter(|n| !n.is_empty()) else {
                continue;
            };
            let code = s.kind >> 4 == 2;
            out.push(ImageSymbol {
                addr: u64::from(header.virtual_address.get()) + u64::from(s.value),
                size: None,
                name,
                kind: if code {
                    SymbolKind::Function
                } else {
                    SymbolKind::Other
                },
                source: SymbolSource::SymbolTable,
                global: s.storage_class == EXTERNAL,
            });
        }
    }
    out
}

fn elf_symbols<'data>(elf: &hexcavator_elf::ElfFile<'data>) -> Vec<ImageSymbol<'data>> {
    use hexcavator_elf::consts::{SHT_DYNSYM, SHT_SYMTAB, STB_LOCAL, STT_FUNC, STT_OBJECT};
    /// `STT_GNU_IFUNC`: an indirect function (a resolver's).
    const STT_GNU_IFUNC: u8 = 10;
    /// `STT_TLS`: thread-local data, at an offset, not an address.
    const STT_TLS: u8 = 6;
    let mut out = Vec::new();
    for table in elf
        .sections()
        .filter(|s| s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM)
    {
        let source = if table.kind == SHT_SYMTAB {
            SymbolSource::SymbolTable
        } else {
            SymbolSource::Exported
        };
        for s in elf.symbols(&table) {
            // Defined in a section (not undefined, absolute, or common).
            if s.shndx == 0 || s.shndx >= 0xFF00 || s.name.is_empty() || s.kind == STT_TLS {
                continue;
            }
            // (ARM's mapping symbols mark code and data, naming nothing.)
            if s.name.starts_with(b"$") {
                continue;
            }
            let kind = match s.kind {
                STT_FUNC | STT_GNU_IFUNC => SymbolKind::Function,
                STT_OBJECT => SymbolKind::Data,
                0 if s.bind != STB_LOCAL => SymbolKind::Other,
                _ => continue,
            };
            out.push(ImageSymbol {
                // (Thumb functions' addresses have their low bit set.)
                addr: if kind == SymbolKind::Function
                    && elf.header().machine == hexcavator_elf::consts::EM_ARM
                {
                    s.value & !1
                } else {
                    s.value
                },
                size: (s.size > 0).then_some(s.size),
                name: s.name,
                kind,
                source,
                global: s.bind != STB_LOCAL,
            });
        }
    }
    out
}

fn macho_symbols<'data>(m: &hexcavator_macho::MachO<'data>) -> Vec<ImageSymbol<'data>> {
    use hexcavator_macho::consts::N_EXT;
    let mut out = Vec::new();
    for s in m.symbols() {
        if !s.is_section_defined() || s.name.is_empty() {
            continue;
        }
        out.push(ImageSymbol {
            addr: s.n_value,
            size: None,
            name: s.name,
            kind: SymbolKind::Other,
            source: SymbolSource::SymbolTable,
            global: s.n_type & N_EXT != 0,
        });
    }
    out
}

fn wasm_symbols<'data>(m: &hexcavator_wasm::Module<'data>) -> Vec<ImageSymbol<'data>> {
    let mut out = Vec::new();
    let Some(code) = m
        .sections()
        .iter()
        .find(|s| s.id == hexcavator_wasm::SECTION_CODE)
    else {
        return out;
    };
    let functions = m.functions();
    let first = functions.first().map_or(0, |f| f.index);
    for n in m.names(hexcavator_wasm::NAME_FUNCTION) {
        let Some(f) = n
            .index
            .checked_sub(first)
            .and_then(|i| functions.get(usize::try_from(i).ok()?))
        else {
            continue;
        };
        out.push(ImageSymbol {
            addr: f.offset.saturating_sub(code.contents_offset),
            size: Some(f.size),
            name: n.name,
            kind: SymbolKind::Function,
            source: SymbolSource::Names,
            global: false,
        });
    }
    out
}

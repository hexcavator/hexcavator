//! Base relocations (`.reloc`) and dynamic value relocations (DVRT).
//!
//! Both use the same block layout: a page RVA, a block size, and then
//! entries for locations within that page.

use hexcavator_core::{Reader, Rva, U16Le, Va};

use crate::PeFile;
use crate::consts::directory;
use crate::load_config::{LoadConfig, field};

/// A block of relocations for one 4 KB page.
#[derive(Clone, Copy, Debug)]
pub struct RelocBlock<'data> {
    pub page: Rva,
    /// The block's size, header included.
    pub size: u32,
    /// The entries (the block after its 8-byte header).
    pub entries: &'data [u8],
}

impl<'data> RelocBlock<'data> {
    /// The entries as 16-bit values (base relocations and most DVRT kinds).
    pub fn entries_u16(&self) -> &'data [U16Le] {
        hexcavator_core::slice_from_bytes(self.entries, self.entries.len() / 2).unwrap_or(&[])
    }

    /// The entries as 32-bit values (import control transfer DVRT kinds).
    pub fn entries_u32(&self) -> impl Iterator<Item = u32> + 'data {
        self.entries
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
    }
}

/// Iterates over relocation blocks in `data`.
pub fn reloc_blocks(data: &[u8]) -> impl Iterator<Item = RelocBlock<'_>> + '_ {
    let mut r = Reader::new(data);
    core::iter::from_fn(move || {
        let page = r.u32_le().ok()?;
        let size = r.u32_le().ok()?;
        if size < 8 {
            return None;
        }
        let entries = r.bytes(size as usize - 8).ok()?;
        Some(RelocBlock {
            page: Rva(page),
            size,
            entries,
        })
    })
}

/// `IMAGE_REL_BASED_*` base relocation types.
pub mod base_reloc {
    pub const ABSOLUTE: u8 = 0;
    pub const HIGH: u8 = 1;
    pub const LOW: u8 = 2;
    pub const HIGHLOW: u8 = 3;
    pub const HIGHADJ: u8 = 4;
    /// MIPS JMPADDR, ARM MOV32, RISC-V HIGH20.
    pub const MACHINE_SPECIFIC_5: u8 = 5;
    pub const RESERVED: u8 = 6;
    /// Thumb MOV32, RISC-V LOW12I.
    pub const MACHINE_SPECIFIC_7: u8 = 7;
    /// RISC-V LOW12S, LoongArch MARK_LA.
    pub const MACHINE_SPECIFIC_8: u8 = 8;
    /// MIPS JMPADDR16, IA64 IMM64.
    pub const MACHINE_SPECIFIC_9: u8 = 9;
    pub const DIR64: u8 = 10;
}

/// One base relocation: a type and the RVA it applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseReloc {
    pub rva: Rva,
    pub kind: u8,
    /// The raw entry (type in the top 4 bits, page offset in the rest).
    pub raw: u16,
}

impl<'data> PeFile<'data> {
    /// The base relocation blocks.
    pub fn base_reloc_blocks(&self) -> impl Iterator<Item = RelocBlock<'data>> + 'data {
        let data = self
            .data_directory(directory::BASERELOC)
            .and_then(|d| {
                self.bytes_at_rva(Rva(d.virtual_address.get()), d.size.get())
                    .ok()
            })
            .unwrap_or(&[]);
        reloc_blocks(data)
    }

    /// All base relocations, in order.
    pub fn base_relocs(&self) -> impl Iterator<Item = BaseReloc> + 'data {
        self.base_reloc_blocks().flat_map(|b| {
            b.entries_u16().iter().map(move |e| {
                let e = e.get();
                BaseReloc {
                    rva: Rva(b.page.get().wrapping_add(u32::from(e & 0xFFF))),
                    kind: (e >> 12) as u8,
                    raw: e,
                }
            })
        })
    }
}

/// `IMAGE_DYNAMIC_RELOCATION_*` symbols: what a DVRT entry's fixups are for.
pub mod dynamic_symbol {
    pub const GUARD_RF_PROLOGUE: u64 = 1;
    pub const GUARD_RF_EPILOGUE: u64 = 2;
    pub const GUARD_IMPORT_CONTROL_TRANSFER: u64 = 3;
    pub const GUARD_INDIR_CONTROL_TRANSFER: u64 = 4;
    pub const GUARD_SWITCHTABLE_BRANCH: u64 = 5;
    pub const ARM64X: u64 = 6;
    pub const FUNCTION_OVERRIDE: u64 = 7;
    pub const ARM64_KERNEL_IMPORT_CALL_TRANSFER: u64 = 8;

    pub const fn name(symbol: u64) -> Option<&'static str> {
        Some(match symbol {
            GUARD_RF_PROLOGUE => "IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE",
            GUARD_RF_EPILOGUE => "IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE",
            GUARD_IMPORT_CONTROL_TRANSFER => {
                "IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER"
            }
            GUARD_INDIR_CONTROL_TRANSFER => "IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER",
            GUARD_SWITCHTABLE_BRANCH => "IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH",
            ARM64X => "IMAGE_DYNAMIC_RELOCATION_ARM64X",
            FUNCTION_OVERRIDE => "IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE",
            ARM64_KERNEL_IMPORT_CALL_TRANSFER => {
                "IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER"
            }
            _ => return None,
        })
    }
}

/// The dynamic value relocation table.
#[derive(Clone, Copy, Debug)]
pub struct DynamicRelocationTable<'data> {
    pub version: u32,
    /// The entries (the table after its 8-byte header).
    data: &'data [u8],
    is_64: bool,
}

/// One DVRT entry: a symbol and its fixups.
#[derive(Clone, Copy, Debug)]
pub struct DynamicRelocation<'data> {
    pub symbol: u64,
    /// Version 2 only.
    pub symbol_group: u32,
    /// Version 2 only.
    pub flags: u32,
    /// Version 2 only: the header after the fixed fields (prologue/epilogue
    /// bytes for the RF kinds).
    pub header: &'data [u8],
    /// The fixups: relocation blocks, except for `FUNCTION_OVERRIDE`.
    pub fixups: &'data [u8],
}

impl<'data> DynamicRelocation<'data> {
    pub fn blocks(&self) -> impl Iterator<Item = RelocBlock<'data>> + 'data {
        reloc_blocks(self.fixups)
    }

    /// The function overrides, for `FUNCTION_OVERRIDE` entries.
    pub fn function_overrides(&self) -> Option<FunctionOverrides<'data>> {
        if self.symbol != dynamic_symbol::FUNCTION_OVERRIDE {
            return None;
        }
        let mut r = Reader::new(self.fixups);
        let size = r.u32_le().ok()? as usize;
        let overrides = r.bytes(size).ok()?;
        Some(FunctionOverrides {
            overrides,
            bdd: r.remaining(),
        })
    }
}

impl<'data> DynamicRelocationTable<'data> {
    pub fn iter(&self) -> impl Iterator<Item = DynamicRelocation<'data>> + 'data {
        let mut r = Reader::new(self.data);
        let (version, is_64) = (self.version, self.is_64);
        core::iter::from_fn(move || {
            if version >= 2 {
                let start = r.position();
                let header_size = r.u32_le().ok()? as usize;
                let fixup_size = r.u32_le().ok()? as usize;
                let symbol = if is_64 {
                    r.u64_le().ok()?
                } else {
                    u64::from(r.u32_le().ok()?)
                };
                let symbol_group = r.u32_le().ok()?;
                let flags = r.u32_le().ok()?;
                let used = r.position() - start;
                let header = r.bytes(header_size.checked_sub(used)?).ok()?;
                let fixups = r.bytes(fixup_size).ok()?;
                Some(DynamicRelocation {
                    symbol,
                    symbol_group,
                    flags,
                    header,
                    fixups,
                })
            } else {
                let symbol = if is_64 {
                    r.u64_le().ok()?
                } else {
                    u64::from(r.u32_le().ok()?)
                };
                let size = r.u32_le().ok()? as usize;
                Some(DynamicRelocation {
                    symbol,
                    symbol_group: 0,
                    flags: 0,
                    header: &[],
                    fixups: r.bytes(size).ok()?,
                })
            }
        })
    }
}

/// The function overrides of a `FUNCTION_OVERRIDE` DVRT entry, and the
/// branch descriptor data (BDD) they refer to.
#[derive(Clone, Copy, Debug)]
pub struct FunctionOverrides<'data> {
    overrides: &'data [u8],
    bdd: &'data [u8],
}

/// `IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION` and its trailing data.
#[derive(Clone, Copy, Debug)]
pub struct FunctionOverride<'data> {
    pub original_rva: Rva,
    pub bdd_offset: u32,
    /// RVAs of the replacement functions.
    pub rvas: &'data [u8],
    /// Relocation blocks: the call sites to patch.
    pub fixups: &'data [u8],
}

/// One branch descriptor (`IMAGE_BDD_DYNAMIC_RELOCATION`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchDescriptor {
    pub left: u16,
    pub right: u16,
    pub value: u32,
}

impl<'data> FunctionOverride<'data> {
    pub fn rvas(&self) -> impl Iterator<Item = Rva> + 'data {
        self.rvas
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| Rva(u32::from_le_bytes(*c)))
    }

    pub fn blocks(&self) -> impl Iterator<Item = RelocBlock<'data>> + 'data {
        reloc_blocks(self.fixups)
    }
}

impl<'data> FunctionOverrides<'data> {
    /// The size of the override list, in bytes.
    pub fn overrides_size(&self) -> usize {
        self.overrides.len()
    }

    /// The size of the BDD data, in bytes.
    pub fn bdd_size(&self) -> usize {
        self.bdd.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = FunctionOverride<'data>> + 'data {
        let mut r = Reader::new(self.overrides);
        core::iter::from_fn(move || {
            let original_rva = Rva(r.u32_le().ok()?);
            let bdd_offset = r.u32_le().ok()?;
            let rva_size = r.u32_le().ok()? as usize;
            let reloc_size = r.u32_le().ok()? as usize;
            Some(FunctionOverride {
                original_rva,
                bdd_offset,
                rvas: r.bytes(rva_size).ok()?,
                fixups: r.bytes(reloc_size).ok()?,
            })
        })
    }

    /// The BDD block at `offset`: its version and descriptors.
    pub fn bdd_at(&self, offset: u32) -> Option<(u32, &'data [u8])> {
        let mut r = Reader::new(self.bdd.get(offset as usize..)?);
        let version = r.u32_le().ok()?;
        let size = r.u32_le().ok()? as usize;
        Some((version, r.bytes(size).ok()?))
    }

    /// Decodes a BDD block's descriptors.
    pub fn descriptors(block: &'data [u8]) -> impl Iterator<Item = BranchDescriptor> + 'data {
        block.as_chunks::<8>().0.iter().map(|c| BranchDescriptor {
            left: u16::from_le_bytes([c[0], c[1]]),
            right: u16::from_le_bytes([c[2], c[3]]),
            value: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
    }
}

impl<'data> LoadConfig<'data> {
    /// The dynamic value relocation table.
    pub fn dynamic_relocations(&self) -> Option<DynamicRelocationTable<'data>> {
        let file = self.file();
        let rva = match self
            .get(field::DYNAMIC_VALUE_RELOC_TABLE)
            .filter(|&v| v != 0)
        {
            Some(va) => file.va_to_rva(Va(va))?,
            None => {
                let section = self.get(field::DYNAMIC_VALUE_RELOC_TABLE_SECTION)?;
                let offset = self.get(field::DYNAMIC_VALUE_RELOC_TABLE_OFFSET)?;
                let index = usize::try_from(section).ok()?.checked_sub(1)?;
                let section = file.sections().get(index)?;
                Rva(section
                    .virtual_address
                    .get()
                    .checked_add(u32::try_from(offset).ok()?)?)
            }
        };
        let header = file.bytes_at_rva(rva, 8).ok()?;
        let version = u32::from_le_bytes(header[..4].try_into().ok()?);
        let size = u32::from_le_bytes(header[4..].try_into().ok()?);
        let data = file.bytes_at_rva(Rva(rva.get() + 8), size).ok()?;
        Some(DynamicRelocationTable {
            version,
            data,
            is_64: self.is_64(),
        })
    }
}

/// `IMAGE_REL_*` COFF relocation type names, by machine, as dumpbin shows
/// them.
pub fn coff_reloc_name(machine: u16, kind: u16) -> Option<&'static str> {
    use crate::consts::machine as m;
    let names: &[&str] = match machine {
        m::AMD64 => &[
            "ABSOLUTE", "ADDR64", "ADDR32", "ADDR32NB", "REL32", "REL32_1", "REL32_2", "REL32_3",
            "REL32_4", "REL32_5", "SECTION", "SECREL", "SECREL7", "TOKEN", "SREL32", "PAIR",
            "SSPAN32",
        ],
        m::I386 => &[
            "ABSOLUTE", "DIR16", "REL16", "", "", "", "DIR32", "DIR32NB", "", "SEG12", "SECTION",
            "SECREL", "TOKEN", "SECREL7", "", "", "", "", "", "", "REL32",
        ],
        m::ARM64 | m::ARM64EC | m::ARM64X => &[
            "ABSOLUTE",
            "ADDR32",
            "ADDR32NB",
            "BRANCH26",
            "PAGEBASE_REL21",
            "REL21",
            "PAGEOFFSET_12A",
            "PAGEOFFSET_12L",
            "SECREL",
            "SECREL_LOW12A",
            "SECREL_HIGH12A",
            "SECREL_LOW12L",
            "TOKEN",
            "SECTION",
            "ADDR64",
            "BRANCH19",
            "BRANCH14",
            "REL32",
        ],
        m::ARM | m::ARMNT | m::THUMB => &[
            "ABSOLUTE",
            "ADDR32",
            "ADDR32NB",
            "BRANCH24",
            "BRANCH11",
            "TOKEN",
            "GPREL12",
            "GPREL7",
            "BLX24",
            "BLX11",
            "REL32",
            "",
            "",
            "",
            "SECTION",
            "SECREL",
            "MOV32A",
            "MOV32T",
            "BRANCH20T",
            "",
            "BRANCH24T",
            "BLX23T",
            "PAIR",
        ],
        _ => return None,
    };
    names
        .get(usize::from(kind))
        .copied()
        .filter(|n| !n.is_empty())
}

/// The number of bytes a COFF relocation of `kind` patches (for showing the
/// value it is applied to), by machine.
pub fn coff_reloc_size(machine: u16, kind: u16) -> usize {
    use crate::consts::machine as m;
    match (machine, kind) {
        (m::AMD64, 0x01) => 8,
        (m::AMD64 | m::I386, 0x0A) => 2,
        (m::ARM64 | m::ARM64EC | m::ARM64X, 0x0D) => 2,
        (m::ARM64 | m::ARM64EC | m::ARM64X, 0x0E) => 8,
        (m::ARM | m::ARMNT | m::THUMB, 0x0E) => 2,
        (m::ARM | m::ARMNT | m::THUMB, 0x10..=0x11) => 8,
        (m::I386, 0x01 | 0x02) => 2,
        (_, 0) => 0,
        _ => 4,
    }
}

impl<'data> PeFile<'data> {
    /// The COFF relocations of an object's section.
    pub fn section_relocations(
        &self,
        section: &crate::raw::SectionHeader,
    ) -> &'data [crate::raw::Relocation] {
        use crate::consts::section_characteristics as scn;
        let offset = u64::from(section.pointer_to_relocations.get());
        let mut count = u64::from(section.number_of_relocations.get());
        if offset == 0 {
            return &[];
        }
        let mut start = offset;
        // With more than 0xFFFF relocations, the first one holds the count
        // (itself included).
        if section.characteristics.get() & scn::LNK_NRELOC_OVFL != 0
            && count == 0xFFFF
            && let Ok(first) =
                hexcavator_core::read_at::<crate::raw::Relocation>(self.data(), offset)
        {
            count = u64::from(first.virtual_address.get()).saturating_sub(1);
            start += size_of::<crate::raw::Relocation>() as u64;
        }
        hexcavator_core::read_slice_at(self.data(), start, count).unwrap_or(&[])
    }
}

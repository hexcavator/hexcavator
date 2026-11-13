//! The load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY32/64`)
//! and the tables it points to: Control Flow Guard tables, SafeSEH
//! handlers, volatile metadata, and ARM64EC/CHPE hybrid metadata.
//!
//! The structure has grown over the years; its first field gives the size
//! the linker wrote, and fields beyond it are absent. Each accessor returns
//! `None` for a field the image's structure does not cover.

use hexcavator_core::{Reader, Rva, U32Le, Va};

use crate::PeFile;
use crate::consts::{directory, machine};

/// A load config field's position: (offset in PE32, offset in PE32+, width).
/// A width of 0 means pointer-sized (4 or 8 bytes).
pub type Field = (u16, u16, u8);

macro_rules! fields {
    ($($(#[$meta:meta])* $name:ident: $o32:literal, $o64:literal, $w:literal;)*) => {
        /// Field positions, for code that iterates over them.
        pub mod field {
            $(
                $(#[$meta])*
                pub const $name: super::Field = ($o32, $o64, $w);
            )*
        }
    };
}

fields! {
    SIZE: 0x00, 0x00, 4;
    TIME_DATE_STAMP: 0x04, 0x04, 4;
    MAJOR_VERSION: 0x08, 0x08, 2;
    MINOR_VERSION: 0x0A, 0x0A, 2;
    GLOBAL_FLAGS_CLEAR: 0x0C, 0x0C, 4;
    GLOBAL_FLAGS_SET: 0x10, 0x10, 4;
    CRITICAL_SECTION_DEFAULT_TIMEOUT: 0x14, 0x14, 4;
    DE_COMMIT_FREE_BLOCK_THRESHOLD: 0x18, 0x18, 0;
    DE_COMMIT_TOTAL_FREE_THRESHOLD: 0x1C, 0x20, 0;
    LOCK_PREFIX_TABLE: 0x20, 0x28, 0;
    MAXIMUM_ALLOCATION_SIZE: 0x24, 0x30, 0;
    VIRTUAL_MEMORY_THRESHOLD: 0x28, 0x38, 0;
    /// PE32 has the heap flags before the affinity mask; PE32+ after.
    PROCESS_HEAP_FLAGS: 0x2C, 0x48, 4;
    PROCESS_AFFINITY_MASK: 0x30, 0x40, 0;
    CSD_VERSION: 0x34, 0x4C, 2;
    DEPENDENT_LOAD_FLAGS: 0x36, 0x4E, 2;
    EDIT_LIST: 0x38, 0x50, 0;
    SECURITY_COOKIE: 0x3C, 0x58, 0;
    SE_HANDLER_TABLE: 0x40, 0x60, 0;
    SE_HANDLER_COUNT: 0x44, 0x68, 0;
    GUARD_CF_CHECK_FUNCTION_POINTER: 0x48, 0x70, 0;
    GUARD_CF_DISPATCH_FUNCTION_POINTER: 0x4C, 0x78, 0;
    GUARD_CF_FUNCTION_TABLE: 0x50, 0x80, 0;
    GUARD_CF_FUNCTION_COUNT: 0x54, 0x88, 0;
    GUARD_FLAGS: 0x58, 0x90, 4;
    CODE_INTEGRITY_FLAGS: 0x5C, 0x94, 2;
    CODE_INTEGRITY_CATALOG: 0x5E, 0x96, 2;
    CODE_INTEGRITY_CATALOG_OFFSET: 0x60, 0x98, 4;
    CODE_INTEGRITY_RESERVED: 0x64, 0x9C, 4;
    GUARD_ADDRESS_TAKEN_IAT_ENTRY_TABLE: 0x68, 0xA0, 0;
    GUARD_ADDRESS_TAKEN_IAT_ENTRY_COUNT: 0x6C, 0xA8, 0;
    GUARD_LONG_JUMP_TARGET_TABLE: 0x70, 0xB0, 0;
    GUARD_LONG_JUMP_TARGET_COUNT: 0x74, 0xB8, 0;
    DYNAMIC_VALUE_RELOC_TABLE: 0x78, 0xC0, 0;
    CHPE_METADATA_POINTER: 0x7C, 0xC8, 0;
    GUARD_RF_FAILURE_ROUTINE: 0x80, 0xD0, 0;
    GUARD_RF_FAILURE_ROUTINE_FUNCTION_POINTER: 0x84, 0xD8, 0;
    DYNAMIC_VALUE_RELOC_TABLE_OFFSET: 0x88, 0xE0, 4;
    DYNAMIC_VALUE_RELOC_TABLE_SECTION: 0x8C, 0xE4, 2;
    RESERVED2: 0x8E, 0xE6, 2;
    GUARD_RF_VERIFY_STACK_POINTER_FUNCTION_POINTER: 0x90, 0xE8, 0;
    HOT_PATCH_TABLE_OFFSET: 0x94, 0xF0, 4;
    RESERVED3: 0x98, 0xF4, 4;
    ENCLAVE_CONFIGURATION_POINTER: 0x9C, 0xF8, 0;
    VOLATILE_METADATA_POINTER: 0xA0, 0x100, 0;
    GUARD_EH_CONTINUATION_TABLE: 0xA4, 0x108, 0;
    GUARD_EH_CONTINUATION_COUNT: 0xA8, 0x110, 0;
    GUARD_XFG_CHECK_FUNCTION_POINTER: 0xAC, 0x118, 0;
    GUARD_XFG_DISPATCH_FUNCTION_POINTER: 0xB0, 0x120, 0;
    GUARD_XFG_TABLE_DISPATCH_FUNCTION_POINTER: 0xB4, 0x128, 0;
    CAST_GUARD_OS_DETERMINED_FAILURE_MODE: 0xB8, 0x130, 0;
    GUARD_MEMCPY_FUNCTION_POINTER: 0xBC, 0x138, 0;
    UMA_FUNCTION_POINTERS: 0xC0, 0x140, 0;
}

/// `IMAGE_GUARD_*` flags in `GuardFlags`.
pub mod guard_flags {
    pub const CF_INSTRUMENTED: u32 = 0x0000_0100;
    pub const CFW_INSTRUMENTED: u32 = 0x0000_0200;
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
    pub const RF_INSTRUMENTED: u32 = 0x0002_0000;
    pub const RF_ENABLE: u32 = 0x0004_0000;
    pub const RF_STRICT: u32 = 0x0008_0000;
    pub const RETPOLINE_PRESENT: u32 = 0x0010_0000;
    pub const EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
    pub const XFG_ENABLED: u32 = 0x0080_0000;
    pub const CASTGUARD_PRESENT: u32 = 0x0100_0000;
    pub const MEMCPY_PRESENT: u32 = 0x0200_0000;
    /// The number of metadata bytes after each RVA in the guard tables.
    pub const FUNCTION_TABLE_SIZE_MASK: u32 = 0xF000_0000;
    pub const FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
}

/// `IMAGE_GUARD_FLAG_*` bits in a guard table entry's metadata byte.
pub mod guard_entry {
    pub const FID_SUPPRESSED: u8 = 0x01;
    pub const EXPORT_SUPPRESSED: u8 = 0x02;
    pub const FID_LANGEXCPTHANDLER: u8 = 0x04;
    pub const FID_XFG: u8 = 0x08;
}

/// The load configuration directory.
#[derive(Clone, Copy, Debug)]
pub struct LoadConfig<'data> {
    file: PeFile<'data>,
    /// The structure, cut to the size it declares.
    data: &'data [u8],
    is_64: bool,
}

impl<'data> LoadConfig<'data> {
    pub(crate) fn parse(file: &PeFile<'data>) -> Option<Self> {
        let dir = file.data_directory(directory::LOAD_CONFIG)?;
        let rva = Rva(dir.virtual_address.get());
        let is_64 = file.optional_header()?.is_64();
        // The structure's own size field wins over the directory's size
        // (which old linkers set to 0x40 for x86 regardless).
        let size = u32::from_le_bytes(file.bytes_at_rva(rva, 4).ok()?.try_into().ok()?);
        let data = file.bytes_at_rva(rva, size.max(4)).ok()?;
        Some(Self {
            file: *file,
            data,
            is_64,
        })
    }

    /// The image this load config belongs to.
    #[inline]
    pub fn file(&self) -> PeFile<'data> {
        self.file
    }

    /// The raw structure.
    #[inline]
    pub fn bytes(&self) -> &'data [u8] {
        self.data
    }

    #[inline]
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// The declared size of the structure.
    #[inline]
    pub fn size(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap_or(u32::MAX)
    }

    /// A field's value, if the structure is large enough to hold it.
    pub fn get(&self, field: Field) -> Option<u64> {
        let (o32, o64, width) = field;
        let offset = usize::from(if self.is_64 { o64 } else { o32 });
        let width = match width {
            0 if self.is_64 => 8,
            0 => 4,
            w => usize::from(w),
        };
        let bytes = self.data.get(offset..offset + width)?;
        let mut value = [0u8; 8];
        value[..width].copy_from_slice(bytes);
        Some(u64::from_le_bytes(value))
    }

    /// Whether the structure is large enough to hold `field`.
    pub fn has(&self, field: Field) -> bool {
        self.get(field).is_some()
    }

    pub fn guard_flags(&self) -> u32 {
        self.get(field::GUARD_FLAGS)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0)
    }

    /// Bytes of metadata after each RVA in the guard tables.
    pub fn guard_table_stride(&self) -> usize {
        ((self.guard_flags() & guard_flags::FUNCTION_TABLE_SIZE_MASK)
            >> guard_flags::FUNCTION_TABLE_SIZE_SHIFT) as usize
    }

    fn guard_table(&self, table: Field, count: Field) -> GuardTable<'data> {
        let stride = 4 + self.guard_table_stride();
        let entries = (|| {
            let va = self.get(table).filter(|&v| v != 0)?;
            let count = self.get(count)?;
            let len = u32::try_from(count.checked_mul(stride as u64)?).ok()?;
            self.file.bytes_at_va(Va(va), len).ok()
        })();
        GuardTable {
            data: entries.unwrap_or(&[]),
            stride,
        }
    }

    /// The Control Flow Guard function table (valid indirect-call targets).
    pub fn guard_cf_functions(&self) -> GuardTable<'data> {
        self.guard_table(
            field::GUARD_CF_FUNCTION_TABLE,
            field::GUARD_CF_FUNCTION_COUNT,
        )
    }

    /// The IAT entries whose addresses are taken.
    pub fn guard_address_taken_iat_entries(&self) -> GuardTable<'data> {
        self.guard_table(
            field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_TABLE,
            field::GUARD_ADDRESS_TAKEN_IAT_ENTRY_COUNT,
        )
    }

    /// The valid `longjmp` targets.
    pub fn guard_long_jump_targets(&self) -> GuardTable<'data> {
        self.guard_table(
            field::GUARD_LONG_JUMP_TARGET_TABLE,
            field::GUARD_LONG_JUMP_TARGET_COUNT,
        )
    }

    /// The valid exception-handling continuation targets.
    pub fn guard_eh_continuations(&self) -> GuardTable<'data> {
        self.guard_table(
            field::GUARD_EH_CONTINUATION_TABLE,
            field::GUARD_EH_CONTINUATION_COUNT,
        )
    }

    /// The SafeSEH handler table (PE32 only): handler RVAs.
    pub fn safe_seh_handlers(&self) -> &'data [U32Le] {
        (|| {
            if self.is_64 {
                return None;
            }
            let va = self.get(field::SE_HANDLER_TABLE).filter(|&v| v != 0)?;
            let count = self.get(field::SE_HANDLER_COUNT)?;
            let bytes = self
                .file
                .bytes_at_va(Va(va), u32::try_from(count.checked_mul(4)?).ok()?)
                .ok()?;
            hexcavator_core::slice_from_bytes(bytes, usize::try_from(count).ok()?)
        })()
        .unwrap_or(&[])
    }

    /// The hybrid (ARM64EC/ARM64X, or CHPE x86) metadata.
    pub fn hybrid_metadata(&self) -> Option<HybridMetadata<'data>> {
        HybridMetadata::parse(self)
    }

    /// The volatile metadata (for x86/x64 emulation on ARM64).
    pub fn volatile_metadata(&self) -> Option<VolatileMetadata<'data>> {
        let va = self
            .get(field::VOLATILE_METADATA_POINTER)
            .filter(|&v| v != 0)?;
        let rva = self.file.va_to_rva(Va(va))?;
        let size = u32::from_le_bytes(self.file.bytes_at_rva(rva, 4).ok()?.try_into().ok()?);
        let data = self.file.bytes_at_rva(rva, size.max(4)).ok()?;
        Some(VolatileMetadata {
            file: self.file,
            data,
        })
    }
}

/// A guard table: RVAs, each followed by a few bytes of flags.
#[derive(Clone, Copy, Debug)]
pub struct GuardTable<'data> {
    data: &'data [u8],
    stride: usize,
}

/// One guard table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardEntry {
    pub rva: Rva,
    /// `IMAGE_GUARD_FLAG_*` bits (0 if the table has no metadata).
    pub flags: u8,
}

impl GuardTable<'_> {
    pub fn len(&self) -> usize {
        self.data.len() / self.stride
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<GuardEntry> {
        let e = self
            .data
            .get(index * self.stride..(index + 1) * self.stride)?;
        Some(GuardEntry {
            rva: Rva(u32::from_le_bytes(e[..4].try_into().ok()?)),
            flags: e.get(4).copied().unwrap_or(0),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = GuardEntry> + '_ {
        (0..self.len()).filter_map(|i| self.get(i))
    }
}

/// `IMAGE_VOLATILE_METADATA`.
#[derive(Clone, Copy, Debug)]
pub struct VolatileMetadata<'data> {
    file: PeFile<'data>,
    data: &'data [u8],
}

impl<'data> VolatileMetadata<'data> {
    fn u32_at(&self, offset: usize) -> u32 {
        self.data
            .get(offset..offset + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    pub fn size(&self) -> u32 {
        self.u32_at(0)
    }

    /// The version: the minimum in the low half, the maximum in the high.
    pub fn version(&self) -> u32 {
        self.u32_at(4)
    }

    pub fn access_table_rva(&self) -> Rva {
        Rva(self.u32_at(8))
    }

    pub fn access_table_size(&self) -> u32 {
        self.u32_at(12)
    }

    pub fn info_range_table_rva(&self) -> Rva {
        Rva(self.u32_at(16))
    }

    pub fn info_range_table_size(&self) -> u32 {
        self.u32_at(20)
    }

    fn table(&self, rva: Rva, size: u32) -> &'data [U32Le] {
        if rva.get() == 0 {
            return &[];
        }
        self.file
            .bytes_at_rva(rva, size / 4 * 4)
            .ok()
            .and_then(|b| hexcavator_core::slice_from_bytes(b, b.len() / 4))
            .unwrap_or(&[])
    }

    /// RVAs of instructions that access volatile memory.
    pub fn access_rvas(&self) -> &'data [U32Le] {
        self.table(self.access_table_rva(), self.access_table_size())
    }

    /// `(rva, size)` ranges of code that may access volatile memory.
    pub fn info_ranges(&self) -> impl Iterator<Item = (Rva, u32)> + 'data {
        self.table(self.info_range_table_rva(), self.info_range_table_size())
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[start, size]| (Rva(start.get()), size.get()))
    }
}

/// What kind of code a hybrid code range holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodeKind {
    Arm64,
    Arm64ec,
    X64,
    X86,
}

/// One entry of the hybrid code range map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeRange {
    pub rva: Rva,
    pub size: u32,
    pub kind: CodeKind,
}

impl<'data> PeFile<'data> {
    /// The load configuration directory.
    pub fn load_config(&self) -> Option<LoadConfig<'data>> {
        LoadConfig::parse(self)
    }

    /// Whether the image is an ARM64EC or ARM64X hybrid: an x64 or ARM64
    /// image with ARM64EC metadata.
    pub fn is_arm64ec(&self) -> bool {
        matches!(self.machine(), machine::AMD64 | machine::ARM64)
            && self
                .load_config()
                .is_some_and(|c| c.get(field::CHPE_METADATA_POINTER).is_some_and(|p| p != 0))
    }
}

/// Field indexes (in 32-bit words) of `IMAGE_ARM64EC_METADATA`.
pub mod arm64ec {
    pub const VERSION: usize = 0;
    pub const CODE_MAP: usize = 1;
    pub const CODE_MAP_COUNT: usize = 2;
    pub const CODE_RANGES_TO_ENTRY_POINTS: usize = 3;
    pub const REDIRECTION_METADATA: usize = 4;
    pub const DISPATCH_CALL_NO_REDIRECT: usize = 5;
    pub const DISPATCH_RET: usize = 6;
    pub const DISPATCH_CALL: usize = 7;
    pub const DISPATCH_ICALL: usize = 8;
    pub const DISPATCH_ICALL_CFG: usize = 9;
    pub const ALTERNATE_ENTRY_POINT: usize = 10;
    pub const AUXILIARY_IAT: usize = 11;
    pub const CODE_RANGES_TO_ENTRY_POINTS_COUNT: usize = 12;
    pub const REDIRECTION_METADATA_COUNT: usize = 13;
    pub const GET_X64_INFORMATION_FUNCTION_POINTER: usize = 14;
    pub const SET_X64_INFORMATION_FUNCTION_POINTER: usize = 15;
    pub const EXTRA_RFE_TABLE: usize = 16;
    pub const EXTRA_RFE_TABLE_SIZE: usize = 17;
    pub const DISPATCH_FPTR: usize = 18;
    pub const AUXILIARY_IAT_COPY: usize = 19;
    /// Version 2 and later.
    pub const AUXILIARY_DELAYLOAD_IAT: usize = 20;
    pub const AUXILIARY_DELAYLOAD_IAT_COPY: usize = 21;
    pub const HYBRID_IMAGE_INFO_BITFIELD: usize = 22;

    /// The number of fields in a structure of `version`.
    pub const fn field_count(version: u32) -> usize {
        if version >= 2 { 23 } else { 20 }
    }
}

/// Field indexes (in 32-bit words) of `IMAGE_CHPE_METADATA_X86`.
pub mod chpe_x86 {
    pub const VERSION: usize = 0;
    pub const CODE_MAP: usize = 1;
    pub const CODE_MAP_COUNT: usize = 2;
    /// Pointers (VAs) to the WoW64 emulator's helper routines.
    pub const WOWA64_EXCEPTION_HANDLER_FUNCTION_POINTER: usize = 3;
    pub const WOWA64_DISPATCH_CALL_FUNCTION_POINTER: usize = 4;
    pub const WOWA64_DISPATCH_INDIRECT_CALL_FUNCTION_POINTER: usize = 5;
    pub const WOWA64_DISPATCH_INDIRECT_CALL_CFG_FUNCTION_POINTER: usize = 6;
    pub const WOWA64_DISPATCH_RET_FUNCTION_POINTER: usize = 7;
    pub const WOWA64_DISPATCH_RET_LEAF_FUNCTION_POINTER: usize = 8;
    pub const WOWA64_DISPATCH_JUMP_FUNCTION_POINTER: usize = 9;
    /// Version 2 and later.
    pub const COMPILER_IAT_POINTER: usize = 10;
    /// Version 3 and later.
    pub const WOWA64_RDTSC_FUNCTION_POINTER: usize = 11;

    pub const fn field_count(version: u32) -> usize {
        match version {
            0 | 1 => 10,
            2 => 11,
            _ => 12,
        }
    }
}

/// ARM64EC (`IMAGE_ARM64EC_METADATA`, see [`arm64ec`]) or CHPE x86
/// (`IMAGE_CHPE_METADATA_X86`, see [`chpe_x86`]) metadata: 32-bit fields
/// whose number depends on the version.
#[derive(Clone, Copy, Debug)]
pub struct HybridMetadata<'data> {
    file: PeFile<'data>,
    data: &'data [u8],
    x86: bool,
}

impl<'data> HybridMetadata<'data> {
    fn parse(config: &LoadConfig<'data>) -> Option<Self> {
        let file = config.file;
        let va = config
            .get(field::CHPE_METADATA_POINTER)
            .filter(|&v| v != 0)?;
        let rva = file.va_to_rva(Va(va))?;
        let version = u32::from_le_bytes(file.bytes_at_rva(rva, 4).ok()?.try_into().ok()?);
        let x86 = matches!(file.machine(), machine::I386 | machine::CHPE_X86);
        let count = if x86 {
            chpe_x86::field_count(version)
        } else {
            arm64ec::field_count(version)
        };
        let data = file
            .bytes_at_rva(rva, u32::try_from(count * 4).ok()?)
            .ok()?;
        Some(Self { file, data, x86 })
    }

    pub fn version(&self) -> u32 {
        self.field(0)
    }

    /// Whether this is x86 CHPE metadata rather than ARM64EC.
    pub fn is_x86(&self) -> bool {
        self.x86
    }

    /// The number of fields.
    pub fn len(&self) -> usize {
        self.data.len() / 4
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Field `index` (see [`arm64ec`] and [`chpe_x86`]), or 0 if this
    /// version does not have it.
    pub fn field(&self, index: usize) -> u32 {
        self.data
            .get(index * 4..index * 4 + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    pub fn code_map_rva(&self) -> Rva {
        Rva(self.field(arm64ec::CODE_MAP))
    }

    pub fn code_map_count(&self) -> u32 {
        self.field(arm64ec::CODE_MAP_COUNT)
    }

    /// The code range map: which ranges of the image hold which kind of
    /// code. The kind is in the low two bits of each start RVA.
    pub fn code_ranges(&self) -> impl Iterator<Item = CodeRange> + 'data {
        let x86 = self.x86;
        let entries: &[U32Le] = (|| {
            let len = self.code_map_count().checked_mul(8)?;
            let b = self.file.bytes_at_rva(self.code_map_rva(), len).ok()?;
            hexcavator_core::slice_from_bytes(b, b.len() / 4)
        })()
        .unwrap_or(&[]);
        entries.as_chunks::<2>().0.iter().map(move |e| {
            let start = e[0].get();
            let kind = match (x86, start & 3) {
                (true, 0) => CodeKind::X86,
                (true, _) => CodeKind::Arm64,
                (false, 0) => CodeKind::Arm64,
                (false, 1) => CodeKind::Arm64ec,
                (false, _) => CodeKind::X64,
            };
            CodeRange {
                rva: Rva(start & !3),
                size: e[1].get(),
                kind,
            }
        })
    }

    /// The kind of code at `rva`, if the code map covers it.
    pub fn code_kind_at(&self, rva: Rva) -> Option<CodeKind> {
        self.code_ranges()
            .find(|r| rva >= r.rva && rva.get() - r.rva.get() < r.size)
            .map(|r| r.kind)
    }

    /// The x64-code-ranges-to-entry-points table (ARM64EC): `(start, end,
    /// entry point)` for each range of x64 code that ARM64EC code can call
    /// into.
    pub fn x64_entry_points(&self) -> impl Iterator<Item = (Rva, Rva, Rva)> + 'data {
        let rva = self.field(arm64ec::CODE_RANGES_TO_ENTRY_POINTS);
        let count = self.field(arm64ec::CODE_RANGES_TO_ENTRY_POINTS_COUNT);
        let data = if self.x86 || rva == 0 {
            &[][..]
        } else {
            count
                .checked_mul(12)
                .and_then(|len| self.file.bytes_at_rva(Rva(rva), len).ok())
                .unwrap_or(&[])
        };
        let mut r = Reader::new(data);
        core::iter::from_fn(move || {
            Some((
                Rva(r.u32_le().ok()?),
                Rva(r.u32_le().ok()?),
                Rva(r.u32_le().ok()?),
            ))
        })
    }
}

/// `IMAGE_ENCLAVE_CONFIG32/64`: the configuration of a VBS enclave image.
#[derive(Clone, Copy, Debug)]
pub struct EnclaveConfig<'data> {
    file: PeFile<'data>,
    data: &'data [u8],
    is_64: bool,
}

/// `IMAGE_ENCLAVE_IMPORT`: an image the enclave may load.
#[derive(Clone, Copy, Debug)]
pub struct EnclaveImport<'data> {
    /// `IMAGE_ENCLAVE_IMPORT_MATCH_*`: none, unique ID, author ID, family
    /// ID, image ID.
    pub match_type: u32,
    pub minimum_security_version: u32,
    pub unique_or_author_id: &'data [u8; 32],
    pub family_id: &'data [u8; 16],
    pub image_id: &'data [u8; 16],
    pub name: Option<&'data [u8]>,
    pub reserved: u32,
}

impl<'data> EnclaveConfig<'data> {
    fn u32_at(&self, offset: usize) -> u32 {
        self.data
            .get(offset..offset + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    pub fn size(&self) -> u32 {
        self.u32_at(0)
    }
    pub fn minimum_required_config_size(&self) -> u32 {
        self.u32_at(4)
    }
    pub fn policy_flags(&self) -> u32 {
        self.u32_at(8)
    }
    pub fn number_of_imports(&self) -> u32 {
        self.u32_at(12)
    }
    pub fn import_list(&self) -> Rva {
        Rva(self.u32_at(16))
    }
    pub fn import_entry_size(&self) -> u32 {
        self.u32_at(20)
    }
    pub fn family_id(&self) -> &'data [u8] {
        self.data.get(24..40).unwrap_or(&[])
    }
    pub fn image_id(&self) -> &'data [u8] {
        self.data.get(40..56).unwrap_or(&[])
    }
    pub fn image_version(&self) -> u32 {
        self.u32_at(56)
    }
    pub fn security_version(&self) -> u32 {
        self.u32_at(60)
    }
    pub fn enclave_size(&self) -> u64 {
        if self.is_64 {
            u64::from(self.u32_at(64)) | u64::from(self.u32_at(68)) << 32
        } else {
            u64::from(self.u32_at(64))
        }
    }
    fn tail(&self) -> usize {
        if self.is_64 { 72 } else { 68 }
    }
    pub fn number_of_threads(&self) -> u32 {
        self.u32_at(self.tail())
    }
    pub fn enclave_flags(&self) -> u32 {
        self.u32_at(self.tail() + 4)
    }

    pub fn imports(&self) -> impl Iterator<Item = EnclaveImport<'data>> + 'data {
        let file = self.file;
        let (list, count, size) = (
            self.import_list(),
            self.number_of_imports(),
            self.import_entry_size().max(80),
        );
        (0..count).map_while(move |i| {
            let rva = Rva(list.get().checked_add(i.checked_mul(size)?)?);
            let e = file.bytes_at_rva(rva, 80).ok()?;
            let u32_at = |o: usize| u32::from_le_bytes(e[o..o + 4].try_into().expect("4 bytes"));
            let name_rva = u32_at(72);
            let name = (name_rva != 0)
                .then(|| {
                    let offset = file.rva_to_offset(Rva(name_rva))?;
                    hexcavator_core::cstr_at(file.data(), offset).ok()
                })
                .flatten();
            Some(EnclaveImport {
                match_type: u32_at(0),
                minimum_security_version: u32_at(4),
                unique_or_author_id: e[8..40].try_into().ok()?,
                family_id: e[40..56].try_into().ok()?,
                image_id: e[56..72].try_into().ok()?,
                name,
                reserved: u32_at(76),
            })
        })
    }
}

impl<'data> LoadConfig<'data> {
    /// The enclave configuration, for VBS enclave images.
    pub fn enclave_config(&self) -> Option<EnclaveConfig<'data>> {
        let va = self
            .get(field::ENCLAVE_CONFIGURATION_POINTER)
            .filter(|&v| v != 0)?;
        let rva = self.file.va_to_rva(Va(va))?;
        let size = u32::from_le_bytes(self.file.bytes_at_rva(rva, 4).ok()?.try_into().ok()?);
        let data = self.file.bytes_at_rva(rva, size.max(4)).ok()?;
        Some(EnclaveConfig {
            file: self.file,
            data,
            is_64: self.is_64,
        })
    }
}

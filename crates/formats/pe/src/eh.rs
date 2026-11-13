//! Language-specific exception handler data: what follows an x64 or ARM64
//! unwind record's handler RVA.
//!
//! Each handler defines its own data. The common ones:
//!
//! - `__C_specific_handler` (SEH, `__try`/`__except`): a [`ScopeTable`].
//! - `__CxxFrameHandler3` (C++ EH): the RVA of a [`FuncInfo`].
//! - `__GSHandlerCheck`: a GS cookie offset (and, for `__GSHandlerCheck_EH`
//!   and `_SEH`, the C++ or SEH data before it).
//!
//! (`__CxxFrameHandler4` data is compressed; it is not decoded here yet.)
//! All offsets are RVAs; this is the 64-bit (x64 and ARM64) layout.

use hexcavator_core::{I32Le, Rva, U32Le, pod};

use crate::PeFile;

/// `__CxxFrameHandler3` magic numbers (in the low 29 bits of the first
/// field; the top three are "BBT" flags).
pub mod magic {
    pub const VC6: u32 = 0x1993_0520;
    /// Adds the exception specification type list.
    pub const VC7: u32 = 0x1993_0521;
    /// Adds the EH flags.
    pub const VC8: u32 = 0x1993_0522;
}

pod! {
    /// `FuncInfo` (`_s_FuncInfo`): a function's C++ EH tables.
    #[derive(Debug)]
    pub struct FuncInfo {
        pub magic_and_bbt_flags: U32Le,
        pub max_state: I32Le,
        pub unwind_map: U32Le,
        pub try_blocks: U32Le,
        pub try_block_map: U32Le,
        pub ip_map_entries: U32Le,
        pub ip_to_state_map: U32Le,
        /// The frame offset of the "unwind help" slot.
        pub unwind_help: I32Le,
        /// The exception specification type list (VC7 and later).
        pub es_type_list: U32Le,
        /// `FI_EHS_FLAG` (1), `FI_DYNSTKALIGN_FLAG` (2), `FI_EHNOEXCEPT_FLAG`
        /// (4); VC8 and later.
        pub eh_flags: I32Le,
    }

    /// `UnwindMapEntry`: the state to go to, and the cleanup that gets there.
    #[derive(Debug)]
    pub struct UnwindMapEntry {
        pub to_state: I32Le,
        pub action: U32Le,
    }

    /// `TryBlockMapEntry`.
    #[derive(Debug)]
    pub struct TryBlockMapEntry {
        pub try_low: I32Le,
        pub try_high: I32Le,
        pub catch_high: I32Le,
        pub catches: I32Le,
        pub handler_array: U32Le,
    }

    /// `HandlerType`: one `catch` clause.
    #[derive(Debug)]
    pub struct HandlerType {
        pub adjectives: U32Le,
        pub type_descriptor: U32Le,
        pub catch_object: I32Le,
        pub handler: U32Le,
        /// The handler's frame offset from its parent's.
        pub frame: U32Le,
    }

    /// `IptoStateMapEntry`.
    #[derive(Debug)]
    pub struct IpToStateMapEntry {
        pub ip: U32Le,
        pub state: I32Le,
    }

    /// One `__C_specific_handler` scope (`C_SCOPE_TABLE` entry).
    #[derive(Debug)]
    pub struct ScopeRecord {
        pub begin: U32Le,
        pub end: U32Le,
        /// The filter (or 1, `EXCEPTION_EXECUTE_HANDLER`), or 0 for a
        /// `__finally` block.
        pub handler: U32Le,
        /// The `__except` block, or 0 for a `__finally` block.
        pub jump_target: U32Le,
    }
}

impl FuncInfo {
    pub fn magic(&self) -> u32 {
        self.magic_and_bbt_flags.get() & 0x1FFF_FFFF
    }

    pub fn is_valid(&self) -> bool {
        (magic::VC6..=magic::VC8).contains(&self.magic())
    }
}

impl<'data> PeFile<'data> {
    fn table<T: hexcavator_core::Pod>(&self, rva: u32, count: u32) -> &'data [T] {
        let Ok(size) = u32::try_from(size_of::<T>()) else {
            return &[];
        };
        count
            .checked_mul(size)
            .and_then(|len| self.bytes_at_rva(Rva(rva), len).ok())
            .and_then(|b| hexcavator_core::slice_from_bytes(b, count as usize))
            .unwrap_or(&[])
    }

    /// The `FuncInfo` at `rva`, if it has a known magic number.
    pub fn func_info(&self, rva: Rva) -> Option<&'data FuncInfo> {
        let size = u32::try_from(size_of::<FuncInfo>()).ok()?;
        let b = self.bytes_at_rva(rva, size).ok()?;
        let info: &FuncInfo = hexcavator_core::from_bytes(b)?;
        info.is_valid().then_some(info)
    }

    pub fn unwind_map(&self, info: &FuncInfo) -> &'data [UnwindMapEntry] {
        let n = u32::try_from(info.max_state.get()).unwrap_or(0);
        self.table(info.unwind_map.get(), n)
    }

    pub fn try_block_map(&self, info: &FuncInfo) -> &'data [TryBlockMapEntry] {
        self.table(info.try_block_map.get(), info.try_blocks.get())
    }

    pub fn ip_to_state_map(&self, info: &FuncInfo) -> &'data [IpToStateMapEntry] {
        self.table(info.ip_to_state_map.get(), info.ip_map_entries.get())
    }

    pub fn catch_handlers(&self, entry: &TryBlockMapEntry) -> &'data [HandlerType] {
        let n = u32::try_from(entry.catches.get()).unwrap_or(0);
        self.table(entry.handler_array.get(), n)
    }

    /// A `__C_specific_handler` scope table: a count, then the records.
    pub fn scope_table(&self, rva: Rva) -> &'data [ScopeRecord] {
        let Some(count) = self
            .bytes_at_rva(rva, 4)
            .ok()
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
        else {
            return &[];
        };
        self.table(rva.get().wrapping_add(4), count)
    }
}

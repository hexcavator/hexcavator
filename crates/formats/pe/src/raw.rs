//! On-disk PE/COFF structures, as laid out in the file.

use hexcavator_core::{I16Le, U16Le, U32Le, U64Le, pod};

pod! {
    /// `IMAGE_FILE_HEADER`: the COFF header shared by images and objects.
    #[derive(Debug)]
    pub struct FileHeader {
        pub machine: U16Le,
        pub number_of_sections: U16Le,
        pub time_date_stamp: U32Le,
        pub pointer_to_symbol_table: U32Le,
        pub number_of_symbols: U32Le,
        pub size_of_optional_header: U16Le,
        pub characteristics: U16Le,
    }

    /// `IMAGE_OPTIONAL_HEADER32`, without the trailing data directories.
    #[derive(Debug)]
    pub struct OptionalHeader32 {
        pub magic: U16Le,
        pub major_linker_version: u8,
        pub minor_linker_version: u8,
        pub size_of_code: U32Le,
        pub size_of_initialized_data: U32Le,
        pub size_of_uninitialized_data: U32Le,
        pub address_of_entry_point: U32Le,
        pub base_of_code: U32Le,
        pub base_of_data: U32Le,
        pub image_base: U32Le,
        pub section_alignment: U32Le,
        pub file_alignment: U32Le,
        pub major_operating_system_version: U16Le,
        pub minor_operating_system_version: U16Le,
        pub major_image_version: U16Le,
        pub minor_image_version: U16Le,
        pub major_subsystem_version: U16Le,
        pub minor_subsystem_version: U16Le,
        pub win32_version_value: U32Le,
        pub size_of_image: U32Le,
        pub size_of_headers: U32Le,
        pub check_sum: U32Le,
        pub subsystem: U16Le,
        pub dll_characteristics: U16Le,
        pub size_of_stack_reserve: U32Le,
        pub size_of_stack_commit: U32Le,
        pub size_of_heap_reserve: U32Le,
        pub size_of_heap_commit: U32Le,
        pub loader_flags: U32Le,
        pub number_of_rva_and_sizes: U32Le,
    }

    /// `IMAGE_OPTIONAL_HEADER64`, without the trailing data directories.
    #[derive(Debug)]
    pub struct OptionalHeader64 {
        pub magic: U16Le,
        pub major_linker_version: u8,
        pub minor_linker_version: u8,
        pub size_of_code: U32Le,
        pub size_of_initialized_data: U32Le,
        pub size_of_uninitialized_data: U32Le,
        pub address_of_entry_point: U32Le,
        pub base_of_code: U32Le,
        pub image_base: U64Le,
        pub section_alignment: U32Le,
        pub file_alignment: U32Le,
        pub major_operating_system_version: U16Le,
        pub minor_operating_system_version: U16Le,
        pub major_image_version: U16Le,
        pub minor_image_version: U16Le,
        pub major_subsystem_version: U16Le,
        pub minor_subsystem_version: U16Le,
        pub win32_version_value: U32Le,
        pub size_of_image: U32Le,
        pub size_of_headers: U32Le,
        pub check_sum: U32Le,
        pub subsystem: U16Le,
        pub dll_characteristics: U16Le,
        pub size_of_stack_reserve: U64Le,
        pub size_of_stack_commit: U64Le,
        pub size_of_heap_reserve: U64Le,
        pub size_of_heap_commit: U64Le,
        pub loader_flags: U32Le,
        pub number_of_rva_and_sizes: U32Le,
    }

    /// `IMAGE_DATA_DIRECTORY`.
    #[derive(Debug)]
    pub struct DataDirectory {
        pub virtual_address: U32Le,
        pub size: U32Le,
    }

    /// `IMAGE_SECTION_HEADER`.
    #[derive(Debug)]
    pub struct SectionHeader {
        pub name: [u8; 8],
        /// `VirtualSize` in images; `PhysicalAddress` (normally 0) in objects.
        pub virtual_size: U32Le,
        pub virtual_address: U32Le,
        pub size_of_raw_data: U32Le,
        pub pointer_to_raw_data: U32Le,
        pub pointer_to_relocations: U32Le,
        pub pointer_to_linenumbers: U32Le,
        pub number_of_relocations: U16Le,
        pub number_of_linenumbers: U16Le,
        pub characteristics: U32Le,
    }

    /// `IMAGE_DEBUG_DIRECTORY`.
    #[derive(Debug)]
    pub struct DebugDirectory {
        pub characteristics: U32Le,
        pub time_date_stamp: U32Le,
        pub major_version: U16Le,
        pub minor_version: U16Le,
        pub kind: U32Le,
        pub size_of_data: U32Le,
        pub address_of_raw_data: U32Le,
        pub pointer_to_raw_data: U32Le,
    }

    /// `IMAGE_SYMBOL`: one COFF symbol table record (or auxiliary record).
    #[derive(Debug)]
    pub struct Symbol {
        /// Either the name itself (padded with NULs), or four zero bytes
        /// followed by an offset into the string table.
        pub name: [u8; 8],
        pub value: U32Le,
        /// 1-based section index, or 0 (undefined), -1 (absolute), -2 (debug).
        pub section_number: I16Le,
        pub kind: U16Le,
        pub storage_class: u8,
        pub number_of_aux_symbols: u8,
    }
}

impl SectionHeader {
    /// The name field, up to the first NUL. For long names this is a
    /// `/offset` reference; use [`PeFile::section_name`](crate::PeFile::section_name)
    /// to resolve it.
    pub fn raw_name(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        &self.name[..len]
    }
}

pod! {
    /// `IMAGE_RELOCATION`: one COFF object relocation.
    #[derive(Debug)]
    pub struct Relocation {
        /// The offset of the location within the section.
        pub virtual_address: U32Le,
        pub symbol_table_index: U32Le,
        /// `IMAGE_REL_<machine>_*`.
        pub kind: U16Le,
    }
}

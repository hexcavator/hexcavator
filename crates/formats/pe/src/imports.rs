//! Imports (`IMAGE_IMPORT_DESCRIPTOR`) and delay-load imports
//! (`IMAGE_DELAYLOAD_DESCRIPTOR`).

use hexcavator_core::{Rva, U32Le, cstr_at, pod, read_at};

use crate::PeFile;
use crate::consts::directory;

pod! {
    /// `IMAGE_IMPORT_DESCRIPTOR`.
    #[derive(Debug)]
    pub struct ImportDescriptor {
        /// RVA of the import name table (`OriginalFirstThunk`).
        pub import_name_table: U32Le,
        /// 0 if not bound; -1 if bound with new-style binding; otherwise the
        /// bound DLL's time stamp.
        pub time_date_stamp: U32Le,
        pub forwarder_chain: U32Le,
        pub name: U32Le,
        /// RVA of the import address table (`FirstThunk`).
        pub import_address_table: U32Le,
    }

    /// `IMAGE_DELAYLOAD_DESCRIPTOR`.
    #[derive(Debug)]
    pub struct DelayLoadDescriptor {
        /// Bit 0 set: the other fields are RVAs; clear: VAs (Visual C++ 6).
        pub attributes: U32Le,
        pub dll_name: U32Le,
        pub module_handle: U32Le,
        pub import_address_table: U32Le,
        pub import_name_table: U32Le,
        pub bound_import_address_table: U32Le,
        pub unload_information_table: U32Le,
        pub time_date_stamp: U32Le,
    }
}

/// One imported function: by name (with a hint) or by ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportName<'data> {
    Name { hint: u16, name: &'data [u8] },
    Ordinal(u16),
}

/// One imported function and the thunks that refer to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportThunk<'data> {
    pub import: ImportName<'data>,
    /// The import name table entry.
    pub name_thunk: u64,
    /// The import address table entry, as stored in the file.
    pub address_thunk: u64,
    /// The RVA of the IAT slot.
    pub iat_rva: Rva,
}

/// One imported DLL.
#[derive(Clone, Copy, Debug)]
pub struct ImportedDll<'data> {
    file: PeFile<'data>,
    pub descriptor: &'data ImportDescriptor,
    pub name: &'data [u8],
}

/// One delay-loaded DLL.
#[derive(Clone, Copy, Debug)]
pub struct DelayImportedDll<'data> {
    file: PeFile<'data>,
    pub descriptor: &'data DelayLoadDescriptor,
    pub name: &'data [u8],
}

impl<'data> PeFile<'data> {
    fn thunk_size(&self) -> u32 {
        match self.optional_header() {
            Some(h) if h.is_64() => 8,
            _ => 4,
        }
    }

    /// The pointer-sized value (an import thunk) at `rva`.
    pub fn thunk(&self, rva: Rva) -> Option<u64> {
        let b = self.bytes_at_rva(rva, self.thunk_size()).ok()?;
        Some(match b.len() {
            8 => u64::from_le_bytes(b.try_into().ok()?),
            _ => u64::from(u32::from_le_bytes(b.try_into().ok()?)),
        })
    }

    fn cstr_at_rva(&self, rva: Rva) -> Option<&'data [u8]> {
        cstr_at(self.data(), self.rva_to_offset(rva)?).ok()
    }

    /// Decodes an import name table entry.
    fn import_name(&self, thunk: u64, bias: u64) -> Option<ImportName<'data>> {
        let ordinal_flag = if self.thunk_size() == 8 {
            1u64 << 63
        } else {
            1u64 << 31
        };
        if thunk & ordinal_flag != 0 {
            let [lo, hi, ..] = thunk.to_le_bytes();
            return Some(ImportName::Ordinal(u16::from_le_bytes([lo, hi])));
        }
        let rva = Rva(u32::try_from(thunk.checked_sub(bias)?).ok()?);
        let hint = u16::from_le_bytes(self.bytes_at_rva(rva, 2).ok()?.try_into().ok()?);
        let name = self.cstr_at_rva(Rva(rva.get() + 2))?;
        Some(ImportName::Name { hint, name })
    }

    /// Walks parallel name and address tables until a zero name entry.
    fn thunks(
        &self,
        names: Rva,
        addresses: Rva,
        bias: u64,
    ) -> impl Iterator<Item = ImportThunk<'data>> + use<'data> {
        let file = *self;
        let size = self.thunk_size();
        // Some linkers omit the name table; the IAT then holds the names.
        let names = if names.get() == 0 { addresses } else { names };
        (0u32..).map_while(move |i| {
            let offset = i.checked_mul(size)?;
            let name_thunk = file.thunk(Rva(names.get().checked_add(offset)?))?;
            if name_thunk == 0 {
                return None;
            }
            let iat_rva = Rva(addresses.get().checked_add(offset)?);
            let address_thunk = file.thunk(iat_rva).unwrap_or(0);
            Some(ImportThunk {
                import: file.import_name(name_thunk, bias)?,
                name_thunk,
                address_thunk,
                iat_rva,
            })
        })
    }

    /// The imported DLLs.
    pub fn imports(&self) -> impl Iterator<Item = ImportedDll<'data>> + 'data {
        let file = *self;
        let start = self
            .data_directory(directory::IMPORT)
            .and_then(|d| self.rva_to_offset(Rva(d.virtual_address.get())));
        (0u64..).map_while(move |i| {
            let offset = start? + i * size_of::<ImportDescriptor>() as u64;
            let descriptor: &ImportDescriptor = read_at(file.data(), offset).ok()?;
            if descriptor.name.get() == 0 && descriptor.import_address_table.get() == 0 {
                return None;
            }
            Some(ImportedDll {
                file,
                descriptor,
                name: file.cstr_at_rva(Rva(descriptor.name.get())).unwrap_or(b""),
            })
        })
    }

    /// The delay-loaded DLLs.
    pub fn delay_imports(&self) -> impl Iterator<Item = DelayImportedDll<'data>> + 'data {
        let file = *self;
        let start = self
            .data_directory(directory::DELAY_IMPORT)
            .and_then(|d| self.rva_to_offset(Rva(d.virtual_address.get())));
        (0u64..).map_while(move |i| {
            let offset = start? + i * size_of::<DelayLoadDescriptor>() as u64;
            let descriptor: &DelayLoadDescriptor = read_at(file.data(), offset).ok()?;
            if descriptor.dll_name.get() == 0 {
                return None;
            }
            let dll = DelayImportedDll {
                file,
                descriptor,
                name: &[],
            };
            Some(DelayImportedDll {
                name: dll
                    .rva(descriptor.dll_name.get())
                    .and_then(|r| file.cstr_at_rva(r))
                    .unwrap_or(b""),
                ..dll
            })
        })
    }
}

impl<'data> ImportedDll<'data> {
    /// The imported functions.
    pub fn thunks(&self) -> impl Iterator<Item = ImportThunk<'data>> + 'data {
        self.file.thunks(
            Rva(self.descriptor.import_name_table.get()),
            Rva(self.descriptor.import_address_table.get()),
            0,
        )
    }
}

impl<'data> DelayImportedDll<'data> {
    /// Whether the descriptor's addresses are RVAs (otherwise VAs).
    pub fn is_rva_based(&self) -> bool {
        self.descriptor.attributes.get() & 1 != 0
    }

    /// Converts one of the descriptor's address fields to an RVA.
    pub fn rva(&self, value: u32) -> Option<Rva> {
        if value == 0 {
            return None;
        }
        if self.is_rva_based() {
            Some(Rva(value))
        } else {
            self.file.va_to_rva(hexcavator_core::Va(u64::from(value)))
        }
    }

    /// The imported functions.
    pub fn thunks(&self) -> impl Iterator<Item = ImportThunk<'data>> + 'data {
        let names = self.rva(self.descriptor.import_name_table.get());
        let addresses = self.rva(self.descriptor.import_address_table.get());
        let bias = if self.is_rva_based() {
            0
        } else {
            file_base(&self.file)
        };
        let file = self.file;
        let iter = match (names, addresses) {
            (Some(n), Some(a)) => Some(file.thunks(n, a, bias)),
            _ => None,
        };
        iter.into_iter().flatten()
    }
}

fn file_base(file: &PeFile<'_>) -> u64 {
    file.optional_header().map_or(0, |h| h.image_base().get())
}

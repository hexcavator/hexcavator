//! Exports (`IMAGE_EXPORT_DIRECTORY`).

#![allow(
    clippy::cast_possible_truncation,
    reason = "table indexes are bounded by the directory's 32-bit counts"
)]

use alloc::vec::Vec;

use hexcavator_core::{Rva, U16Le, U32Le, cstr_at, pod, read_at, read_slice_at};

use crate::PeFile;
use crate::consts::directory;

pod! {
    /// `IMAGE_EXPORT_DIRECTORY`.
    #[derive(Debug)]
    pub struct ExportDirectory {
        pub characteristics: U32Le,
        pub time_date_stamp: U32Le,
        pub major_version: U16Le,
        pub minor_version: U16Le,
        pub name: U32Le,
        pub base: U32Le,
        pub number_of_functions: U32Le,
        pub number_of_names: U32Le,
        pub address_of_functions: U32Le,
        pub address_of_names: U32Le,
        pub address_of_name_ordinals: U32Le,
    }
}

/// What an export refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportTarget<'data> {
    /// Code or data in this image.
    Rva(Rva),
    /// Another DLL's export: `"DLL.Name"` or `"DLL.#ordinal"`.
    Forwarder(&'data [u8]),
}

/// One exported function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Export<'data> {
    pub ordinal: u32,
    /// The index into the name table, for named exports.
    pub hint: Option<u32>,
    pub name: Option<&'data [u8]>,
    pub target: ExportTarget<'data>,
}

/// The export directory and its tables.
#[derive(Clone, Copy, Debug)]
pub struct Exports<'data> {
    file: PeFile<'data>,
    pub directory: &'data ExportDirectory,
    /// The directory's RVA range: function RVAs inside it are forwarders.
    range: (u32, u32),
    functions: &'data [U32Le],
    names: &'data [U32Le],
    ordinals: &'data [U16Le],
}

impl<'data> Exports<'data> {
    fn parse(file: &PeFile<'data>) -> Option<Self> {
        let dir = file.data_directory(directory::EXPORT)?;
        let start = dir.virtual_address.get();
        let directory: &ExportDirectory =
            read_at(file.data(), file.rva_to_offset(Rva(start))?).ok()?;
        let table = |rva: u32, count: u32| -> Option<u64> {
            (count == 0 || rva != 0)
                .then(|| file.rva_to_offset(Rva(rva)))
                .flatten()
        };
        let functions = table(
            directory.address_of_functions.get(),
            directory.number_of_functions.get(),
        )
        .and_then(|o| {
            read_slice_at(
                file.data(),
                o,
                u64::from(directory.number_of_functions.get()),
            )
            .ok()
        })
        .unwrap_or(&[]);
        let n = u64::from(directory.number_of_names.get());
        let names = table(
            directory.address_of_names.get(),
            directory.number_of_names.get(),
        )
        .and_then(|o| read_slice_at(file.data(), o, n).ok())
        .unwrap_or(&[]);
        let ordinals = table(
            directory.address_of_name_ordinals.get(),
            directory.number_of_names.get(),
        )
        .and_then(|o| read_slice_at(file.data(), o, n).ok())
        .unwrap_or(&[]);
        Some(Self {
            file: *file,
            directory,
            range: (start, start.saturating_add(dir.size.get())),
            functions,
            names,
            ordinals,
        })
    }

    fn cstr(&self, rva: u32) -> Option<&'data [u8]> {
        cstr_at(self.file.data(), self.file.rva_to_offset(Rva(rva))?).ok()
    }

    /// The DLL's own name, as recorded at link time.
    pub fn dll_name(&self) -> Option<&'data [u8]> {
        self.cstr(self.directory.name.get())
    }

    pub fn ordinal_base(&self) -> u32 {
        self.directory.base.get()
    }

    /// The number of entries in the export address table.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// The `(hint, name)` pairs, in name table (sorted) order, with each
    /// name's index into the export address table.
    pub fn names(&self) -> impl Iterator<Item = (u32, &'data [u8], u16)> + '_ {
        self.names
            .iter()
            .zip(self.ordinals)
            .enumerate()
            .filter_map(|(i, (n, o))| Some((i as u32, self.cstr(n.get())?, o.get())))
    }

    fn target(&self, rva: u32) -> ExportTarget<'data> {
        if rva >= self.range.0
            && rva < self.range.1
            && let Some(s) = self.cstr(rva)
        {
            return ExportTarget::Forwarder(s);
        }
        ExportTarget::Rva(Rva(rva))
    }

    /// All exports in ordinal order. Unused slots (RVA 0) are skipped; an
    /// entry with several names appears once per name.
    pub fn iter(&self) -> alloc::vec::IntoIter<Export<'data>> {
        // The name table is sorted by name; index it by function.
        let mut by_index: Vec<(u16, u32)> = self
            .ordinals
            .iter()
            .enumerate()
            .map(|(hint, o)| (o.get(), hint as u32))
            .collect();
        by_index.sort_unstable();
        let mut out = Vec::with_capacity(self.functions.len().max(by_index.len()));
        let mut names = by_index.iter().peekable();
        for (i, f) in self.functions.iter().enumerate() {
            let ordinal = self.ordinal_base().wrapping_add(i as u32);
            let target = self.target(f.get());
            let mut named = false;
            while let Some(&&(index, hint)) = names.peek() {
                if usize::from(index) > i {
                    break;
                }
                names.next();
                if usize::from(index) == i && f.get() != 0 {
                    named = true;
                    out.push(Export {
                        ordinal,
                        hint: Some(hint),
                        name: self
                            .names
                            .get(hint as usize)
                            .and_then(|n| self.cstr(n.get())),
                        target,
                    });
                }
            }
            if !named && f.get() != 0 {
                out.push(Export {
                    ordinal,
                    hint: None,
                    name: None,
                    target,
                });
            }
        }
        out.into_iter()
    }

    /// Finds an export by name, using the sorted name table.
    pub fn find(&self, name: &[u8]) -> Option<Export<'data>> {
        let i = self
            .names
            .binary_search_by(|n| self.cstr(n.get()).unwrap_or(b"").cmp(name))
            .ok()?;
        let index = self.ordinals.get(i)?.get();
        let rva = self.functions.get(usize::from(index))?.get();
        Some(Export {
            ordinal: self.ordinal_base().wrapping_add(u32::from(index)),
            hint: Some(i as u32),
            name: Some(self.cstr(self.names[i].get())?),
            target: self.target(rva),
        })
    }

    /// Finds an export by ordinal.
    pub fn by_ordinal(&self, ordinal: u32) -> Option<ExportTarget<'data>> {
        let index = ordinal.checked_sub(self.ordinal_base())?;
        let rva = self.functions.get(index as usize)?.get();
        (rva != 0).then(|| self.target(rva))
    }
}

impl<'data> PeFile<'data> {
    /// The export directory.
    pub fn exports(&self) -> Option<Exports<'data>> {
        Exports::parse(self)
    }
}

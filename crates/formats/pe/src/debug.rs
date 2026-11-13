//! The debug directory (`IMAGE_DEBUG_DIRECTORY` entries) and the payloads
//! of its common entry types.

use hexcavator_core::{Reader, Rva, U32Le, bytes_at};

use crate::PeFile;
use crate::consts::debug_type;
use crate::raw::DebugDirectory;

/// A debug directory entry and its data.
#[derive(Clone, Copy, Debug)]
pub struct DebugEntry<'data> {
    pub header: &'data DebugDirectory,
    /// The entry's data, if it lies within the file.
    pub data: Option<&'data [u8]>,
}

impl<'data> DebugEntry<'data> {
    pub(crate) fn new(file: &PeFile<'data>, header: &'data DebugDirectory) -> Self {
        let size = u64::from(header.size_of_data.get());
        let ptr = header.pointer_to_raw_data.get();
        let data = if ptr != 0 {
            bytes_at(file.data(), u64::from(ptr), size).ok()
        } else {
            file.bytes_at_rva(
                Rva(header.address_of_raw_data.get()),
                header.size_of_data.get(),
            )
            .ok()
        };
        Self { header, data }
    }

    #[inline]
    pub fn kind(&self) -> u32 {
        self.header.kind.get()
    }

    /// The CodeView record, for `IMAGE_DEBUG_TYPE_CODEVIEW` entries.
    pub fn codeview(&self) -> Option<CodeView<'data>> {
        (self.kind() == debug_type::CODEVIEW)
            .then(|| CodeView::parse(self.data?))
            .flatten()
    }

    /// The POGO/COFF-group header, for `IMAGE_DEBUG_TYPE_POGO` entries.
    pub fn pogo(&self) -> Option<Pogo<'data>> {
        if self.kind() != debug_type::POGO {
            return None;
        }
        let data = self.data?;
        let signature = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
        Some(Pogo {
            signature,
            entries: &data[4..],
        })
    }

    /// The `IMAGE_DEBUG_TYPE_VC_FEATURE` counts: pre-VC++ 11, C/C++, /GS,
    /// /sdl, and guardN, as many as the entry holds.
    pub fn vc_feature(&self) -> Option<&'data [U32Le]> {
        if self.kind() != debug_type::VC_FEATURE {
            return None;
        }
        let data = self.data?;
        let n = data.len() / 4;
        hexcavator_core::slice_from_bytes(&data[..n * 4], n)
    }

    /// The extended DLL characteristics (`IMAGE_DLLCHARACTERISTICS_EX_*`).
    pub fn ex_dll_characteristics(&self) -> Option<u32> {
        if self.kind() != debug_type::EX_DLLCHARACTERISTICS {
            return None;
        }
        Some(u32::from_le_bytes(self.data?.get(..4)?.try_into().ok()?))
    }

    /// The hash recorded by `/Brepro`, for `IMAGE_DEBUG_TYPE_REPRO` entries:
    /// the bytes after the length prefix.
    pub fn repro_hash(&self) -> Option<&'data [u8]> {
        if self.kind() != debug_type::REPRO {
            return None;
        }
        let data = self.data?;
        let len = u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize;
        data.get(4..4 + len)
    }
}

/// A CodeView debug record, naming the PDB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeView<'data> {
    /// PDB 7.0 (`RSDS`): a GUID and age.
    Rsds {
        guid: [u8; 16],
        age: u32,
        path: &'data [u8],
    },
    /// PDB 2.0 (`NB10`): a time stamp and age.
    Nb10 {
        offset: u32,
        signature: u32,
        age: u32,
        path: &'data [u8],
    },
    /// Some other format, such as `NB09` (embedded CodeView 4).
    Other { signature: [u8; 4] },
}

impl<'data> CodeView<'data> {
    pub fn parse(data: &'data [u8]) -> Option<Self> {
        let mut r = Reader::new(data);
        let signature: [u8; 4] = r.bytes(4).ok()?.try_into().ok()?;
        let path = |r: &mut Reader<'data>| {
            let rest = r.remaining();
            &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())]
        };
        Some(match &signature {
            b"RSDS" => {
                let guid = r.bytes(16).ok()?.try_into().ok()?;
                let age = r.u32_le().ok()?;
                CodeView::Rsds {
                    guid,
                    age,
                    path: path(&mut r),
                }
            }
            b"NB10" => {
                let offset = r.u32_le().ok()?;
                let signature = r.u32_le().ok()?;
                let age = r.u32_le().ok()?;
                CodeView::Nb10 {
                    offset,
                    signature,
                    age,
                    path: path(&mut r),
                }
            }
            _ => CodeView::Other { signature },
        })
    }

    /// The path of the PDB, if the record names one.
    pub fn path(&self) -> Option<&'data [u8]> {
        match self {
            CodeView::Rsds { path, .. } | CodeView::Nb10 { path, .. } => Some(path),
            CodeView::Other { .. } => None,
        }
    }
}

/// A POGO debug entry: a signature (`PGU`, `LTCG`, ...) and the image's COFF
/// groups (`.text$mn`, `.rdata$zz`, ...).
#[derive(Clone, Copy, Debug)]
pub struct Pogo<'data> {
    pub signature: u32,
    entries: &'data [u8],
}

/// One COFF group: a contiguous run of the image with one group name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoffGroup<'data> {
    pub rva: Rva,
    pub size: u32,
    pub name: &'data [u8],
}

impl<'data> Pogo<'data> {
    /// The signature as text (`"PGU"`, `"LTCG"`, ...): its bytes from most
    /// to least significant, up to the first NUL.
    pub fn signature_name(&self) -> [u8; 4] {
        self.signature.to_be_bytes()
    }

    /// The COFF groups. Each name is NUL-terminated and padded to 4 bytes.
    pub fn groups(&self) -> impl Iterator<Item = CoffGroup<'data>> + 'data {
        let mut r = Reader::new(self.entries);
        core::iter::from_fn(move || {
            let rva = r.u32_le().ok()?;
            let size = r.u32_le().ok()?;
            let name = r.cstr().ok()?;
            // The name and its terminator are padded to a multiple of 4.
            let used = name.len() + 1;
            let _ = r.skip((4 - used % 4) % 4);
            Some(CoffGroup {
                rva: Rva(rva),
                size,
                name,
            })
        })
    }
}

impl<'data> PeFile<'data> {
    /// The debug directory entries with their data.
    pub fn debug_entries(&self) -> impl Iterator<Item = DebugEntry<'data>> + '_ {
        let file = *self;
        self.debug_directories()
            .unwrap_or(&[])
            .iter()
            .map(move |d| DebugEntry::new(&file, d))
    }

    /// The image's PDB reference, from its first CodeView debug entry.
    pub fn codeview(&self) -> Option<CodeView<'data>> {
        self.debug_entries().find_map(|e| e.codeview())
    }
}

//! Win32 resources (`.rsrc`): a tree of `IMAGE_RESOURCE_DIRECTORY` tables
//! whose leaves are `IMAGE_RESOURCE_DATA_ENTRY` records.
//!
//! By convention the tree has three levels: type, name, and language.
//! Offsets within the tree are relative to the resource directory's start;
//! data entries hold RVAs.

use hexcavator_core::{Rva, U16Le, U32Le, pod, read_at, read_slice_at};

use crate::PeFile;
use crate::consts::directory;

pod! {
    /// `IMAGE_RESOURCE_DIRECTORY`.
    #[derive(Debug)]
    pub struct ResourceDirectoryHeader {
        pub characteristics: U32Le,
        pub time_date_stamp: U32Le,
        pub major_version: U16Le,
        pub minor_version: U16Le,
        pub number_of_named_entries: U16Le,
        pub number_of_id_entries: U16Le,
    }

    /// `IMAGE_RESOURCE_DIRECTORY_ENTRY`.
    #[derive(Debug)]
    pub struct ResourceDirectoryEntry {
        /// High bit set: the low 31 bits are the offset of the name (an
        /// `IMAGE_RESOURCE_DIR_STRING_U`); clear: the low 16 bits are the ID.
        pub name: U32Le,
        /// High bit set: the low 31 bits are the offset of a subdirectory;
        /// clear: the offset of a data entry.
        pub offset: U32Le,
    }

    /// `IMAGE_RESOURCE_DATA_ENTRY`.
    #[derive(Debug)]
    pub struct ResourceDataEntry {
        /// The RVA of the resource's data.
        pub data: U32Le,
        pub size: U32Le,
        pub code_page: U32Le,
        pub reserved: U32Le,
    }
}

/// The size of a directory's header.
pub const DIRECTORY_HEADER_SIZE: u32 = 16;
/// The size of a directory entry.
pub const DIRECTORY_ENTRY_SIZE: u32 = 8;
/// The size of a data entry.
pub const DATA_ENTRY_SIZE: u32 = 16;

/// The predefined resource types (`RT_*`).
pub mod resource_type {
    pub const CURSOR: u16 = 1;
    pub const BITMAP: u16 = 2;
    pub const ICON: u16 = 3;
    pub const MENU: u16 = 4;
    pub const DIALOG: u16 = 5;
    pub const STRING: u16 = 6;
    pub const FONTDIR: u16 = 7;
    pub const FONT: u16 = 8;
    pub const ACCELERATOR: u16 = 9;
    pub const RCDATA: u16 = 10;
    pub const MESSAGETABLE: u16 = 11;
    pub const GROUP_CURSOR: u16 = 12;
    pub const GROUP_ICON: u16 = 14;
    pub const VERSION: u16 = 16;
    pub const DLGINCLUDE: u16 = 17;
    pub const PLUGPLAY: u16 = 19;
    pub const VXD: u16 = 20;
    pub const ANICURSOR: u16 = 21;
    pub const ANIICON: u16 = 22;
    pub const HTML: u16 = 23;
    pub const MANIFEST: u16 = 24;
}

/// A resource directory entry's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceName<'data> {
    Id(u16),
    /// A counted UTF-16 string, at `rva`.
    Name {
        rva: Rva,
        units: &'data [U16Le],
    },
}

impl ResourceName<'_> {
    /// The name's text (`#<id>` for IDs, as resource compilers write them).
    pub fn text(&self) -> alloc::string::String {
        match self {
            ResourceName::Id(id) => alloc::format!("#{id}"),
            ResourceName::Name { units, .. } => alloc::string::String::from_utf16_lossy(
                &units
                    .iter()
                    .map(|u| u.get())
                    .collect::<alloc::vec::Vec<_>>(),
            ),
        }
    }
}

/// What a directory entry leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceTarget {
    /// A subdirectory, at this RVA.
    Directory(Rva),
    /// A data entry, at this RVA.
    Data(Rva),
}

/// One entry of a [`ResourceDirectory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceEntry<'data> {
    /// The entry's RVA.
    pub rva: Rva,
    /// The name, or `None` if a named entry's string can't be read.
    pub name: Option<ResourceName<'data>>,
    /// The raw name field (an ID's low 16 bits are the ID).
    pub raw_name: u32,
    pub target: ResourceTarget,
}

/// One table of the resource tree.
#[derive(Clone, Copy, Debug)]
pub struct ResourceDirectory<'data> {
    file: PeFile<'data>,
    /// The resource tree's base (the resource directory's RVA).
    base: Rva,
    /// This table's RVA.
    pub rva: Rva,
    pub header: &'data ResourceDirectoryHeader,
    /// The entries that lie within the file.
    pub entries: &'data [ResourceDirectoryEntry],
    /// How many entries the header claims.
    pub claimed_entries: u32,
}

impl<'data> ResourceDirectory<'data> {
    /// The table's size, header and entries (as claimed) included.
    pub fn size(&self) -> u32 {
        DIRECTORY_HEADER_SIZE + DIRECTORY_ENTRY_SIZE * self.claimed_entries
    }

    /// The tree's base RVA.
    pub fn base(&self) -> Rva {
        self.base
    }

    /// The table's entries.
    pub fn iter(&self) -> impl Iterator<Item = ResourceEntry<'data>> + 'data {
        let file = self.file;
        let base = self.base.get();
        let rva = self.rva.get();
        self.entries.iter().zip(0u32..).map(move |(e, i)| {
            let raw_name = e.name.get();
            let name = if raw_name & 0x8000_0000 != 0 {
                let at = base.wrapping_add(raw_name & 0x7FFF_FFFF);
                file.resource_string(Rva(at))
                    .map(|units| ResourceName::Name {
                        rva: Rva(at),
                        units,
                    })
            } else {
                Some(ResourceName::Id((raw_name & 0xFFFF) as u16))
            };
            let offset = e.offset.get();
            let at = Rva(base.wrapping_add(offset & 0x7FFF_FFFF));
            let target = if offset & 0x8000_0000 != 0 {
                ResourceTarget::Directory(at)
            } else {
                ResourceTarget::Data(at)
            };
            // (At most 0x1FFFF entries, so the offset fits.)
            let entry_rva = rva.wrapping_add(DIRECTORY_HEADER_SIZE + DIRECTORY_ENTRY_SIZE * i);
            ResourceEntry {
                rva: Rva(entry_rva),
                name,
                raw_name,
                target,
            }
        })
    }
}

impl<'data> PeFile<'data> {
    /// The root of the resource tree, if there is one.
    pub fn resource_root(&self) -> Option<ResourceDirectory<'data>> {
        let d = self.data_directory(directory::RESOURCE)?;
        let base = Rva(d.virtual_address.get());
        if base.get() == 0 {
            return None;
        }
        self.resource_directory(base, base)
    }

    /// The resource table at `rva`, in the tree based at `base`.
    pub fn resource_directory(&self, base: Rva, rva: Rva) -> Option<ResourceDirectory<'data>> {
        let offset = self.rva_to_offset(rva)?;
        let header: &ResourceDirectoryHeader = read_at(self.data(), offset).ok()?;
        let claimed_entries = u32::from(header.number_of_named_entries.get())
            + u32::from(header.number_of_id_entries.get());
        // The entries the file holds (a truncated table keeps those that fit).
        let available = (self.data().len() as u64)
            .saturating_sub(offset + u64::from(DIRECTORY_HEADER_SIZE))
            / u64::from(DIRECTORY_ENTRY_SIZE);
        let count = u64::from(claimed_entries).min(available);
        let entries = read_slice_at(
            self.data(),
            offset + u64::from(DIRECTORY_HEADER_SIZE),
            count,
        )
        .ok()?;
        Some(ResourceDirectory {
            file: *self,
            base,
            rva,
            header,
            entries,
            claimed_entries,
        })
    }

    /// The data entry at `rva`.
    pub fn resource_data_entry(&self, rva: Rva) -> Option<&'data ResourceDataEntry> {
        read_at(self.data(), self.rva_to_offset(rva)?).ok()
    }

    /// The counted UTF-16 string (`IMAGE_RESOURCE_DIR_STRING_U`) at `rva`.
    pub fn resource_string(&self, rva: Rva) -> Option<&'data [U16Le]> {
        let offset = self.rva_to_offset(rva)?;
        let len: &U16Le = read_at(self.data(), offset).ok()?;
        read_slice_at(self.data(), offset + 2, u64::from(len.get())).ok()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::testutil::image64_with;

    /// A tree: root -> type 24 (MANIFEST) and type "NAMED" -> ID 1 ->
    /// language 0x409 -> data.
    fn tree() -> Vec<u8> {
        let mut r = Vec::new();
        let put32 = |r: &mut Vec<u8>, at: usize, v: u32| {
            if r.len() < at + 4 {
                r.resize(at + 4, 0);
            }
            r[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        let base = 0x2000u32;
        // Root at 0: one named entry, one ID entry.
        put32(&mut r, 12, 1 | (1 << 16));
        put32(&mut r, 16, 0x8000_0000 | 0x80); // named, string at 0x80
        put32(&mut r, 20, 0x8000_0000 | 0x28); // dir at 0x28
        put32(&mut r, 24, 24);
        put32(&mut r, 28, 0x8000_0000 | 0x28);
        // Name table at 0x28: ID 1 -> 0x40.
        put32(&mut r, 0x28 + 12, 1 << 16);
        put32(&mut r, 0x28 + 16, 1);
        put32(&mut r, 0x28 + 20, 0x8000_0000 | 0x40);
        // Language table at 0x40: 0x409 -> data entry at 0x60.
        put32(&mut r, 0x40 + 12, 1 << 16);
        put32(&mut r, 0x40 + 16, 0x409);
        put32(&mut r, 0x40 + 20, 0x60);
        // Data entry: RVA base + 0x90, 4 bytes.
        put32(&mut r, 0x60, base + 0x90);
        put32(&mut r, 0x64, 4);
        // "NAMED".
        r.resize(0x90, 0);
        r[0x80..0x82].copy_from_slice(&5u16.to_le_bytes());
        for (i, c) in "NAMED".encode_utf16().enumerate() {
            r[0x82 + 2 * i..0x84 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
        r.extend_from_slice(b"data");
        r
    }

    #[test]
    fn walks_the_tree() {
        let data = image64_with(
            b".rsrc",
            0x2000,
            &tree(),
            &[(directory::RESOURCE, 0x2000, 0x94)],
        );
        let pe = PeFile::parse(&data).unwrap();
        let root = pe.resource_root().unwrap();
        assert_eq!(root.rva, Rva(0x2000));
        assert_eq!(root.size(), 32);
        let entries: Vec<_> = root.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rva, Rva(0x2010));
        assert_eq!(entries[0].name.unwrap().text(), "NAMED");
        assert!(matches!(
            entries[0].name,
            Some(ResourceName::Name {
                rva: Rva(0x2080),
                ..
            })
        ));
        assert_eq!(entries[1].name, Some(ResourceName::Id(24)));
        let ResourceTarget::Directory(names) = entries[1].target else {
            panic!("a directory");
        };
        let names = pe.resource_directory(root.base(), names).unwrap();
        let first = names.iter().next().unwrap();
        assert_eq!(first.name.unwrap().text(), "#1");
        let ResourceTarget::Directory(langs) = first.target else {
            panic!("a directory");
        };
        let lang = pe
            .resource_directory(root.base(), langs)
            .unwrap()
            .iter()
            .next()
            .unwrap();
        assert_eq!(lang.name, Some(ResourceName::Id(0x409)));
        let ResourceTarget::Data(entry) = lang.target else {
            panic!("data");
        };
        assert_eq!(entry, Rva(0x2060));
        let entry = pe.resource_data_entry(entry).unwrap();
        assert_eq!(entry.data.get(), 0x2090);
        assert_eq!(
            pe.bytes_at_rva(Rva(entry.data.get()), entry.size.get())
                .unwrap(),
            b"data"
        );
    }

    #[test]
    fn no_resources() {
        let data = image64_with(b".rsrc", 0x2000, &tree(), &[]);
        assert!(PeFile::parse(&data).unwrap().resource_root().is_none());
    }

    #[test]
    fn truncated_tables_keep_what_fits() {
        let mut t = tree();
        // Claim 0xFFFF + 0xFFFF entries in the root.
        t[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let data = image64_with(b".rsrc", 0x2000, &t, &[(directory::RESOURCE, 0x2000, 0x94)]);
        let pe = PeFile::parse(&data).unwrap();
        let root = pe.resource_root().unwrap();
        assert_eq!(root.claimed_entries, 0x1FFFE);
        assert!(root.entries.len() < 0x1FFFE);
        // Garbage entries don't panic.
        for e in root.iter() {
            if let ResourceTarget::Directory(d) = e.target {
                let _ = pe.resource_directory(root.base(), d);
            }
        }
        // A name past the end of the file.
        let mut t = tree();
        t[16..20].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let data = image64_with(b".rsrc", 0x2000, &t, &[(directory::RESOURCE, 0x2000, 0x94)]);
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(
            pe.resource_root().unwrap().iter().next().unwrap().name,
            None
        );
    }
}

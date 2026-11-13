//! Short import objects (`IMPORT_OBJECT_HEADER`), the members of import
//! libraries: each describes one function or variable a DLL exports,
//! from which the linker synthesizes the import thunk and descriptors.

use hexcavator_core::{Error, ErrorKind, Result};

/// The size of the header.
pub const HEADER_SIZE: usize = 20;

/// What an import is (`IMPORT_OBJECT_TYPE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportType {
    Code,
    Data,
    Const,
    Unknown(u8),
}

/// How the import's name is found (`IMPORT_OBJECT_NAME_TYPE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportNameType {
    /// By ordinal (`ordinal_or_hint` is the ordinal).
    Ordinal,
    /// The symbol's name as is.
    Name,
    /// The symbol's name without a leading `?`, `@`, or `_`.
    NoPrefix,
    /// As `NoPrefix`, and cut at the first `@`.
    Undecorate,
    /// The name given after the DLL's name.
    ExportAs,
    Unknown(u8),
}

/// A short import object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportObject<'data> {
    pub version: u16,
    pub machine: u16,
    pub time_date_stamp: u32,
    /// The size of the data after the header (the names).
    pub size_of_data: u32,
    pub ordinal_or_hint: u16,
    pub kind: ImportType,
    pub name_type: ImportNameType,
    /// The public symbol the import defines (`__imp_` is added for the
    /// import address table entry).
    pub symbol: &'data [u8],
    pub dll: &'data [u8],
    /// For [`ImportNameType::ExportAs`]: the name to import.
    pub export_name: Option<&'data [u8]>,
}

impl<'data> ImportObject<'data> {
    /// Whether `data` starts with an import object's signature (an
    /// anonymous object header of version 0).
    pub fn is_import_object(data: &[u8]) -> bool {
        data.len() >= 6 && data[0..4] == [0, 0, 0xFF, 0xFF] && data[4..6] == [0, 0]
    }

    pub fn parse(data: &'data [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE || !Self::is_import_object(data) {
            return Err(Error::new(ErrorKind::BadMagic, 0, "import object header"));
        }
        let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
        let u32_at =
            |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let size_of_data = u32_at(12);
        let bits = u16_at(18);
        let kind = match (bits & 3) as u8 {
            0 => ImportType::Code,
            1 => ImportType::Data,
            2 => ImportType::Const,
            k => ImportType::Unknown(k),
        };
        let name_type = match ((bits >> 2) & 7) as u8 {
            0 => ImportNameType::Ordinal,
            1 => ImportNameType::Name,
            2 => ImportNameType::NoPrefix,
            3 => ImportNameType::Undecorate,
            4 => ImportNameType::ExportAs,
            k => ImportNameType::Unknown(k),
        };
        let end = HEADER_SIZE
            .saturating_add(usize::try_from(size_of_data).unwrap_or(usize::MAX))
            .min(data.len());
        let mut names = data[HEADER_SIZE..end].split(|&b| b == 0);
        let symbol = names.next().unwrap_or(&[]);
        let dll = names.next().ok_or(Error::new(
            ErrorKind::Truncated,
            HEADER_SIZE as u64,
            "import object names",
        ))?;
        let export_name = if name_type == ImportNameType::ExportAs {
            names.next()
        } else {
            None
        };
        Ok(Self {
            version: u16_at(4),
            machine: u16_at(6),
            time_date_stamp: u32_at(8),
            size_of_data,
            ordinal_or_hint: u16_at(16),
            kind,
            name_type,
            symbol,
            dll,
            export_name,
        })
    }

    /// The name the DLL exports, as the loader looks it up; `None` for
    /// imports by ordinal.
    pub fn import_name(&self) -> Option<&'data [u8]> {
        let strip = |n: &'data [u8]| match n.first() {
            Some(b'?' | b'@' | b'_') => &n[1..],
            _ => n,
        };
        Some(match self.name_type {
            ImportNameType::Ordinal => return None,
            ImportNameType::Name | ImportNameType::Unknown(_) => self.symbol,
            ImportNameType::NoPrefix => strip(self.symbol),
            ImportNameType::Undecorate => {
                let n = strip(self.symbol);
                n.split(|&b| b == b'@').next().unwrap_or(n)
            }
            ImportNameType::ExportAs => self.export_name.unwrap_or(self.symbol),
        })
    }

    /// The object's size: the header and its names.
    pub fn size(&self) -> u64 {
        HEADER_SIZE as u64 + u64::from(self.size_of_data)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    use super::*;

    fn object(kind: u16, name_type: u16, hint: u16, names: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0, 0, 0xFF, 0xFF, 0, 0]);
        v.extend_from_slice(&0x8664u16.to_le_bytes());
        v.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        v.extend_from_slice(&u32::try_from(names.len()).unwrap().to_le_bytes());
        v.extend_from_slice(&hint.to_le_bytes());
        v.extend_from_slice(&(kind | (name_type << 2)).to_le_bytes());
        v.extend_from_slice(names);
        v
    }

    #[test]
    fn names_by_type() {
        let o = object(0, 1, 7, b"CreateFileW\0KERNEL32.dll\0");
        let i = ImportObject::parse(&o).unwrap();
        assert_eq!(i.machine, 0x8664);
        assert_eq!(i.time_date_stamp, 0x1234_5678);
        assert_eq!(i.ordinal_or_hint, 7);
        assert_eq!(i.kind, ImportType::Code);
        assert_eq!(i.name_type, ImportNameType::Name);
        assert_eq!(
            (i.symbol, i.dll),
            (&b"CreateFileW"[..], &b"KERNEL32.dll"[..])
        );
        assert_eq!(i.import_name(), Some(&b"CreateFileW"[..]));
        assert_eq!(i.size(), 20 + 25);
        let o = object(1, 2, 0, b"_errno\0msvcrt.dll\0");
        let i = ImportObject::parse(&o).unwrap();
        assert_eq!(i.kind, ImportType::Data);
        assert_eq!(i.import_name(), Some(&b"errno"[..]));
        let o = object(0, 3, 0, b"_Sleep@4\0KERNEL32.dll\0");
        assert_eq!(
            ImportObject::parse(&o).unwrap().import_name(),
            Some(&b"Sleep"[..])
        );
        let o = object(0, 0, 42, b"Ord\0X.dll\0");
        let i = ImportObject::parse(&o).unwrap();
        assert_eq!(
            (i.name_type, i.import_name()),
            (ImportNameType::Ordinal, None)
        );
        let o = object(2, 4, 0, b"#f\0X.dll\0f_EC\0");
        let i = ImportObject::parse(&o).unwrap();
        assert_eq!(i.kind, ImportType::Const);
        assert_eq!(i.import_name(), Some(&b"f_EC"[..]));
        let o = object(3, 7, 0, b"a\0b\0");
        let i = ImportObject::parse(&o).unwrap();
        assert_eq!(
            (i.kind, i.name_type),
            (ImportType::Unknown(3), ImportNameType::Unknown(7))
        );
    }

    #[test]
    fn damaged() {
        assert!(ImportObject::parse(b"").is_err());
        assert!(!ImportObject::is_import_object(b"\0\0\xFF\xFF\x02\0"));
        // No DLL name.
        assert!(ImportObject::parse(&object(0, 1, 0, b"onlyname")).is_err());
        // A size of data past the end: the names that are there.
        let mut o = object(0, 1, 0, b"f\0d.dll\0");
        o[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(ImportObject::parse(&o).unwrap().dll, b"d.dll");
        for len in 0..o.len() {
            let _ = ImportObject::parse(&o[..len]);
        }
    }
}

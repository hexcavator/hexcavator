//! The parts of an image the loader mostly doesn't read: the Rich header
//! (the linker's record of the tools that built the image), the attribute
//! certificates (Authenticode), the bound imports, the CLR header and
//! metadata root of a managed image, and the overlay (bytes past the last
//! section).
//!
//! Damaged data gives fewer entries, never a panic.

use alloc::vec::Vec;

use hexcavator_core::{Rva, bytes_at};

use crate::PeFile;
use crate::consts::directory;

/// The most entries any of these lists has.
const MAX_ENTRIES: usize = 1 << 16;

fn u16_at(data: &[u8], at: u64) -> Option<u16> {
    let b = bytes_at(data, at, 2).ok()?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: u64) -> Option<u32> {
    let b = bytes_at(data, at, 4).ok()?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One tool's record in the Rich header: its product (`@comp.id`'s high
/// half), its build, and how many objects it made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RichEntry {
    pub product: u16,
    pub build: u16,
    pub count: u32,
}

/// The Rich header: the tools that built the image, the key (the XOR
/// mask, also the checksum), and whether the checksum holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rich {
    /// Where it starts (its `DanS`) and ends (past its key).
    pub offset: u64,
    pub end: u64,
    pub key: u32,
    pub entries: Vec<RichEntry>,
    /// Whether the key is the checksum of the DOS header, stub, and
    /// entries (link.exe's).
    pub valid: bool,
}

/// An attribute certificate (`WIN_CERTIFICATE`): its revision, type
/// (`WIN_CERT_TYPE_*`), and data (a PKCS#7 SignedData, for Authenticode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate<'data> {
    /// Its file offset.
    pub offset: u64,
    pub revision: u16,
    pub kind: u16,
    pub data: &'data [u8],
}

pub const WIN_CERT_REVISION_1_0: u16 = 0x0100;
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
pub const WIN_CERT_TYPE_X509: u16 = 0x0001;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 0x0004;

/// A bound import (`IMAGE_BOUND_IMPORT_DESCRIPTOR`): the DLL, the time
/// stamp of the build it was bound to, and the DLLs it forwards to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundImport<'data> {
    pub name: &'data [u8],
    pub time_date_stamp: u32,
    pub forwarders: Vec<(&'data [u8], u32)>,
}

/// The CLR header (`IMAGE_COR20_HEADER`) and its metadata root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clr<'data> {
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    /// The metadata's (rva, size).
    pub metadata: (u32, u32),
    /// `COMIMAGE_FLAGS_*`.
    pub flags: u32,
    /// The entry point's token (or, with `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`,
    /// its RVA).
    pub entry_point: u32,
    pub resources: (u32, u32),
    pub strong_name_signature: (u32, u32),
    pub code_manager_table: (u32, u32),
    pub vtable_fixups: (u32, u32),
    pub export_address_table_jumps: (u32, u32),
    pub managed_native_header: (u32, u32),
    /// The metadata root's version string (`v4.0.30319`), if the root is
    /// there.
    pub version: Option<&'data [u8]>,
    /// Its streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`): name, and
    /// (offset from the root, size).
    pub streams: Vec<(&'data [u8], u32, u32)>,
}

pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
pub const COMIMAGE_FLAGS_IL_LIBRARY: u32 = 0x0000_0004;
pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;
pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: u32 = 0x0001_0000;
pub const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;

const RICH: u32 = 0x6863_6952; // "Rich"
const DANS: u32 = 0x536E_6144; // "DanS"

impl<'data> PeFile<'data> {
    /// The Rich header, if the DOS stub has one.
    pub fn rich(&self) -> Option<Rich> {
        let data = self.data();
        // Between the DOS header and the PE header.
        let end = self
            .file_header_offset()
            .min(data.len() as u64)
            .saturating_sub(4);
        let mut at = 0x40u64;
        let mut marker = None;
        while at + 8 <= end + 4 {
            if u32_at(data, at) == Some(RICH) {
                marker = Some(at);
            }
            at += 4;
        }
        let marker = marker?;
        let key = u32_at(data, marker + 4)?;
        // Back from the marker to `DanS`, masked.
        let mut start = marker;
        loop {
            start = start.checked_sub(4)?;
            if start < 0x40 {
                return None;
            }
            if u32_at(data, start)? ^ key == DANS {
                break;
            }
        }
        let mut entries = Vec::new();
        let mut at = start + 16;
        while at + 8 <= marker && entries.len() < MAX_ENTRIES {
            let id = u32_at(data, at)? ^ key;
            let count = u32_at(data, at + 4)? ^ key;
            entries.push(RichEntry {
                product: (id >> 16) as u16,
                build: (id & 0xFFFF) as u16,
                count,
            });
            at += 8;
        }
        // The checksum: the offset, the DOS header and stub's bytes (but
        // e_lfanew's) each rotated by its offset, and each entry's id
        // rotated by its count.
        let mut sum = u32::try_from(start).unwrap_or(0);
        for (i, &b) in data.get(..usize::try_from(start).ok()?)?.iter().enumerate() {
            if (0x3C..0x40).contains(&i) {
                continue;
            }
            sum = sum.wrapping_add(u32::from(b).rotate_left(u32::try_from(i & 31).unwrap_or(0)));
        }
        for e in &entries {
            let id = u32::from(e.product) << 16 | u32::from(e.build);
            sum = sum.wrapping_add(id.rotate_left(e.count & 31));
        }
        Some(Rich {
            offset: start,
            end: marker + 8,
            key,
            entries,
            valid: sum == key,
        })
    }

    /// The attribute certificates (the security directory, whose address
    /// is a file offset).
    pub fn certificates(&self) -> Vec<Certificate<'data>> {
        let mut out = Vec::new();
        let Some(d) = self.data_directory(directory::SECURITY) else {
            return out;
        };
        let data = self.data();
        let (start, size) = (u64::from(d.virtual_address.get()), u64::from(d.size.get()));
        let end = start.saturating_add(size).min(data.len() as u64);
        let mut at = start;
        while at + 8 <= end && out.len() < MAX_ENTRIES {
            let (Some(len), Some(revision), Some(kind)) =
                (u32_at(data, at), u16_at(data, at + 4), u16_at(data, at + 6))
            else {
                break;
            };
            let len = u64::from(len);
            if len < 8 || at + len > end {
                break;
            }
            let Ok(body) = bytes_at(data, at + 8, len - 8) else {
                break;
            };
            out.push(Certificate {
                offset: at,
                revision,
                kind,
                data: body,
            });
            // (Each is 8-byte aligned.)
            at += len.next_multiple_of(8);
        }
        out
    }

    /// The bound imports (from the image's headers).
    pub fn bound_imports(&self) -> Vec<BoundImport<'data>> {
        let mut out = Vec::new();
        let Some(d) = self.data_directory(directory::BOUND_IMPORT) else {
            return out;
        };
        let (rva, size) = (d.virtual_address.get(), d.size.get());
        // (The table lies in the headers, which map at their file offsets.)
        let Ok(table) = self
            .bytes_at_rva(Rva(rva), size)
            .or_else(|_| bytes_at(self.data(), u64::from(rva), u64::from(size)))
        else {
            return out;
        };
        let name = |offset: u16| -> &'data [u8] {
            table
                .get(usize::from(offset)..)
                .and_then(|r| r.split(|&b| b == 0).next())
                .unwrap_or(&[])
        };
        let mut at = 0u64;
        while at + 8 <= table.len() as u64 && out.len() < MAX_ENTRIES {
            let (Some(stamp), Some(name_off), Some(forwarders)) = (
                u32_at(table, at),
                u16_at(table, at + 4),
                u16_at(table, at + 6),
            ) else {
                break;
            };
            if stamp == 0 && name_off == 0 {
                break;
            }
            at += 8;
            let mut f = Vec::new();
            for _ in 0..forwarders {
                let (Some(s), Some(n)) = (u32_at(table, at), u16_at(table, at + 4)) else {
                    break;
                };
                f.push((name(n), s));
                at += 8;
            }
            out.push(BoundImport {
                name: name(name_off),
                time_date_stamp: stamp,
                forwarders: f,
            });
        }
        out
    }

    /// The CLR header and metadata root, if this is a managed image.
    pub fn clr(&self) -> Option<Clr<'data>> {
        let d = self.data_directory(directory::COM_DESCRIPTOR)?;
        let h = self
            .bytes_at_rva(Rva(d.virtual_address.get()), d.size.get().min(72))
            .ok()?;
        let pair = |at: u64| Some((u32_at(h, at)?, u32_at(h, at + 4)?));
        let mut clr = Clr {
            major_runtime_version: u16_at(h, 4)?,
            minor_runtime_version: u16_at(h, 6)?,
            metadata: pair(8)?,
            flags: u32_at(h, 16)?,
            entry_point: u32_at(h, 20)?,
            resources: pair(24)?,
            strong_name_signature: pair(32)?,
            code_manager_table: pair(40)?,
            vtable_fixups: pair(48)?,
            export_address_table_jumps: pair(56)?,
            managed_native_header: pair(64)?,
            version: None,
            streams: Vec::new(),
        };
        // The metadata root: "BSJB", versions, the version string, then
        // the stream headers.
        let Ok(root) = self.bytes_at_rva(Rva(clr.metadata.0), clr.metadata.1) else {
            return Some(clr);
        };
        if u32_at(root, 0) != Some(0x424A_5342) {
            return Some(clr);
        }
        let Some(len) = u32_at(root, 12) else {
            return Some(clr);
        };
        let len = u64::from(len);
        let Ok(version) = bytes_at(root, 16, len) else {
            return Some(clr);
        };
        clr.version = Some(version.split(|&b| b == 0).next().unwrap_or(version));
        let mut at = 16 + len.next_multiple_of(4);
        let Some(count) = u16_at(root, at + 2) else {
            return Some(clr);
        };
        at += 4;
        for _ in 0..count {
            let (Some(offset), Some(size)) = (u32_at(root, at), u32_at(root, at + 4)) else {
                break;
            };
            let Some(rest) = root.get(usize::try_from(at + 8).ok()?..) else {
                break;
            };
            let Some(n) = rest.iter().take(32).position(|&b| b == 0) else {
                break;
            };
            clr.streams.push((&rest[..n], offset, size));
            at += 8 + (n as u64 + 1).next_multiple_of(4);
        }
        Some(clr)
    }

    /// The overlay: the file's bytes past the end of its last section's
    /// data (an installer's payload, the attribute certificates), as (file
    /// offset, size), if there are any.
    pub fn overlay(&self) -> Option<(u64, u64)> {
        let end = self
            .sections()
            .iter()
            .filter(|s| s.size_of_raw_data.get() > 0)
            .map(|s| u64::from(s.pointer_to_raw_data.get()) + u64::from(s.size_of_raw_data.get()))
            .max()?;
        let len = self.data().len() as u64;
        (len > end).then(|| (end, len - end))
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, reason = "small test data")]
mod tests {
    use super::*;

    #[test]
    fn rich_checksums() {
        // A synthetic image (PE header at 0x80), its stub holding DanS,
        // padding, two entries, Rich, and the key, at 0x40: the key as
        // link.exe computes it.
        let mut data = crate::testutil::image64_with(b".text", 0x1000, &[0xC3], &[]);
        let entries = [(0x0104_7809u32, 3u32), (0x0103_7809, 12)];
        let start = 0x40u32;
        let mut sum = start;
        for (i, &b) in data[..start as usize].iter().enumerate() {
            if !(0x3C..0x40).contains(&i) {
                sum = sum.wrapping_add(u32::from(b).rotate_left(i as u32 & 31));
            }
        }
        for &(id, count) in &entries {
            sum = sum.wrapping_add(id.rotate_left(count & 31));
        }
        let key = sum;
        let mut rich = Vec::new();
        for w in [DANS ^ key, key, key, key] {
            rich.extend_from_slice(&w.to_le_bytes());
        }
        for &(id, count) in &entries {
            rich.extend_from_slice(&(id ^ key).to_le_bytes());
            rich.extend_from_slice(&(count ^ key).to_le_bytes());
        }
        rich.extend_from_slice(&RICH.to_le_bytes());
        rich.extend_from_slice(&key.to_le_bytes());
        data[0x40..0x40 + rich.len()].copy_from_slice(&rich);
        let r = PeFile::parse_image(&data).unwrap().rich().unwrap();
        assert_eq!((r.offset, r.end), (0x40, 0x68));
        assert_eq!(r.key, key);
        assert!(r.valid);
        assert_eq!(
            r.entries,
            [
                RichEntry {
                    product: 0x0104,
                    build: 0x7809,
                    count: 3
                },
                RichEntry {
                    product: 0x0103,
                    build: 0x7809,
                    count: 12
                },
            ]
        );
        // A changed count: the checksum fails.
        let mut bad = data.clone();
        bad[0x40 + 20] ^= 1;
        assert!(!PeFile::parse_image(&bad).unwrap().rich().unwrap().valid);
        // No marker: none.
        let plain = crate::testutil::image64_with(b".text", 0x1000, &[0xC3], &[]);
        assert!(PeFile::parse_image(&plain).unwrap().rich().is_none());
    }

    #[test]
    fn certificates_and_overlay() {
        let mut data = crate::testutil::image64_with(b".text", 0x1000, &[0xC3], &[]);
        let end = data.len() as u64;
        // Two certificates (the first's length not a multiple of 8).
        let mut table = Vec::new();
        for (kind, body) in [
            (WIN_CERT_TYPE_PKCS_SIGNED_DATA, &b"signed"[..]),
            (WIN_CERT_TYPE_X509, b"x509 data"),
        ] {
            let len = 8 + body.len() as u32;
            table.extend_from_slice(&len.to_le_bytes());
            table.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
            table.extend_from_slice(&kind.to_le_bytes());
            table.extend_from_slice(body);
            table.resize(table.len().next_multiple_of(8), 0);
        }
        data.extend_from_slice(&table);
        // The security directory (index 4) at 0x98 + 112 + 32.
        let at = 0x98 + 112 + directory::SECURITY * 8;
        data[at..at + 4].copy_from_slice(&(end as u32).to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
        let pe = PeFile::parse_image(&data).unwrap();
        let certs = pe.certificates();
        assert_eq!(certs.len(), 2);
        assert_eq!(
            (certs[0].kind, certs[0].data),
            (WIN_CERT_TYPE_PKCS_SIGNED_DATA, &b"signed"[..])
        );
        assert_eq!(
            (certs[1].offset, certs[1].data),
            (end + 16, &b"x509 data"[..])
        );
        assert_eq!(pe.overlay(), Some((end, table.len() as u64)));
        // Damaged: a length past the table, a length too short.
        for bad in [0xFFFF_FFFFu32, 4] {
            let mut d = data.clone();
            d[end as usize..end as usize + 4].copy_from_slice(&bad.to_le_bytes());
            assert!(PeFile::parse_image(&d).unwrap().certificates().is_empty());
        }
    }
}

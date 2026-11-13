//! The version resource (`VS_VERSIONINFO`): the fixed file information
//! (`VS_FIXEDFILEINFO`: file and product versions, flags, OS, type) and the
//! strings of each language (`StringFileInfo`: CompanyName, FileDescription,
//! ProductName, FileVersion, LegalCopyright, ...), as Explorer's Details tab
//! and `sigcheck` show them.

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::Rva;

use crate::PeFile;
use crate::resources::{ResourceName, ResourceTarget, resource_type};

/// `VS_FIXEDFILEINFO`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FixedFileInfo {
    /// The file's version: major, minor, build, revision.
    pub file_version: [u16; 4],
    pub product_version: [u16; 4],
    /// `VS_FF_*`, masked by the flags mask.
    pub flags: u32,
    /// `VOS_*`.
    pub os: u32,
    /// `VFT_*` (1: an application, 2: a DLL, 3: a driver, ...).
    pub file_type: u32,
    pub file_subtype: u32,
}

impl FixedFileInfo {
    /// The flags, by name.
    pub fn flag_names(&self) -> Vec<&'static str> {
        [
            (0x1, "debug"),
            (0x2, "prerelease"),
            (0x4, "patched"),
            (0x8, "private build"),
            (0x10, "info inferred"),
            (0x20, "special build"),
        ]
        .iter()
        .filter(|(b, _)| self.flags & b != 0)
        .map(|(_, n)| *n)
        .collect()
    }

    /// The file type's name.
    pub fn type_name(&self) -> &'static str {
        match self.file_type {
            1 => "application",
            2 => "DLL",
            3 => "driver",
            4 => "font",
            5 => "virtual device",
            7 => "static library",
            _ => "unknown",
        }
    }
}

/// A version as `a.b.c.d`.
pub fn dotted(v: [u16; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

/// One language's strings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StringTable {
    /// Its language and code page, as its key gives them (`040904B0`).
    pub key: String,
    /// The strings, in order: (name, value).
    pub strings: Vec<(String, String)>,
}

/// A version resource.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub fixed: Option<FixedFileInfo>,
    pub tables: Vec<StringTable>,
    /// The languages and code pages it declares (`VarFileInfo\Translation`).
    pub translations: Vec<(u16, u16)>,
}

impl VersionInfo {
    /// The value of string `name` (`CompanyName`): of the first table that
    /// has it (U.S. English first, as Explorer prefers).
    pub fn get(&self, name: &str) -> Option<&str> {
        let english = self
            .tables
            .iter()
            .filter(|t| t.key.to_ascii_uppercase().starts_with("0409"));
        let others = self
            .tables
            .iter()
            .filter(|t| !t.key.to_ascii_uppercase().starts_with("0409"));
        english
            .chain(others)
            .find_map(|t| {
                t.strings
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            })
            .filter(|v| !v.is_empty())
    }

    /// Parses the `VS_VERSIONINFO` block `data`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let root = Node::read(data, 0)?;
        if root.key != "VS_VERSION_INFO" {
            return None;
        }
        let mut out = VersionInfo::default();
        let v = root.value;
        if v.len() >= 52 && u32_at(v, 0) == Some(0xFEEF_04BD) {
            let w = |at: usize| u32_at(v, at).unwrap_or(0);
            // (Each u32 holds two of the four parts, high then low.)
            let halves = |x: u32| x.to_be_bytes();
            let pair = |hi: u32, lo: u32| {
                let (h, l) = (halves(hi), halves(lo));
                [
                    u16::from_be_bytes([h[0], h[1]]),
                    u16::from_be_bytes([h[2], h[3]]),
                    u16::from_be_bytes([l[0], l[1]]),
                    u16::from_be_bytes([l[2], l[3]]),
                ]
            };
            out.fixed = Some(FixedFileInfo {
                file_version: pair(w(8), w(12)),
                product_version: pair(w(16), w(20)),
                flags: w(28) & w(24),
                os: w(32),
                file_type: w(36),
                file_subtype: w(40),
            });
        }
        for child in root.children(data).take(16) {
            match child.key.as_str() {
                "StringFileInfo" => {
                    for table in child.children(data).take(64) {
                        let mut t = StringTable {
                            key: table.key.clone(),
                            strings: Vec::new(),
                        };
                        for s in table.children(data).take(256) {
                            t.strings.push((s.key.clone(), s.text()));
                        }
                        out.tables.push(t);
                    }
                }
                "VarFileInfo" => {
                    for var in child.children(data).take(16) {
                        if var.key == "Translation" {
                            out.translations.extend(
                                var.value.as_chunks::<4>().0.iter().take(64).map(
                                    |&[a, b, c, d]| {
                                        (u16::from_le_bytes([a, b]), u16::from_le_bytes([c, d]))
                                    },
                                ),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        Some(out)
    }
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// A block of the version resource: `wLength`, `wValueLength`, `wType`,
/// its key (UTF-16, NUL-terminated), its value, and its children, each
/// aligned to 4 bytes.
struct Node<'a> {
    key: String,
    /// The value's bytes.
    value: &'a [u8],
    /// Whether the value is text (`wType` 1).
    is_text: bool,
    /// Where its children lie: [start, end) of the block's data.
    children: (usize, usize),
}

impl<'a> Node<'a> {
    fn read(data: &'a [u8], at: usize) -> Option<Self> {
        let len = usize::from(u16_at(data, at)?);
        let value_len = usize::from(u16_at(data, at + 2)?);
        let kind = u16_at(data, at + 4)?;
        let end = at.checked_add(len)?.min(data.len());
        if len < 6 {
            return None;
        }
        // The key.
        let mut p = at + 6;
        let mut units = Vec::new();
        loop {
            let u = u16_at(data, p)?;
            p += 2;
            if u == 0 || p > end {
                break;
            }
            if units.len() < 256 {
                units.push(u);
            }
        }
        let key = String::from_utf16_lossy(&units);
        let p = (p + 3) & !3;
        // (A text value's length counts UTF-16 units, some writers' bytes:
        // the block's end bounds it either way.)
        let is_text = kind == 1;
        let bytes = if is_text { value_len * 2 } else { value_len };
        let v_end = p.saturating_add(bytes).min(end);
        let value = data.get(p.min(v_end)..v_end).unwrap_or(&[]);
        let children = ((v_end + 3) & !3, end);
        Some(Node {
            key,
            value,
            is_text,
            children,
        })
    }

    fn children(&self, data: &'a [u8]) -> impl Iterator<Item = Node<'a>> + use<'a> {
        let (mut at, end) = self.children;
        core::iter::from_fn(move || {
            if at + 6 > end {
                return None;
            }
            let node = Node::read(data, at)?;
            let len = usize::from(u16_at(data, at)?);
            if len == 0 {
                return None;
            }
            at = (at + len + 3) & !3;
            Some(node)
        })
    }

    /// A text value (without its NUL).
    fn text(&self) -> String {
        let units: Vec<u16> = self
            .value
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        if !self.is_text && units.is_empty() {
            return String::new();
        }
        String::from_utf16_lossy(&units)
    }
}

impl PeFile<'_> {
    /// The image's version resource (the first of type `RT_VERSION`).
    pub fn version_info(&self) -> Option<VersionInfo> {
        let root = self.resource_root()?;
        let by_type = root
            .iter()
            .find(|e| e.name == Some(ResourceName::Id(resource_type::VERSION)))?;
        // Type, then name (the first), then language: U.S. English, else
        // neutral, else the first (as Windows falls back, for an English
        // user; a resource DLL may hold many languages').
        let ResourceTarget::Directory(rva) = by_type.target else {
            return None;
        };
        let ResourceTarget::Directory(rva) = self
            .resource_directory(root.base(), rva)?
            .iter()
            .next()?
            .target
        else {
            return None;
        };
        let languages = self.resource_directory(root.base(), rva)?;
        let id = |e: &crate::resources::ResourceEntry<'_>| match e.name {
            Some(ResourceName::Id(id)) => Some(id),
            _ => None,
        };
        let target = languages
            .iter()
            .find(|e| id(e) == Some(0x409))
            .or_else(|| languages.iter().find(|e| id(e) == Some(0)))
            .or_else(|| languages.iter().next())?
            .target;
        let ResourceTarget::Data(rva) = target else {
            return None;
        };
        let entry = self.resource_data_entry(rva)?;
        let data = self
            .bytes_at_rva(Rva(entry.data.get()), entry.size.get())
            .ok()?;
        VersionInfo::parse(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block: its key, value (binary or text), and children.
    fn block(key: &str, value: &[u8], text: bool, children: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend([0u8; 6]);
        for u in key.encode_utf16().chain([0]) {
            b.extend(u.to_le_bytes());
        }
        while b.len() % 4 != 0 {
            b.push(0);
        }
        b.extend(value);
        let value_len = if text { value.len() / 2 } else { value.len() };
        for c in children {
            while b.len() % 4 != 0 {
                b.push(0);
            }
            b.extend(c);
        }
        let n = u16::try_from(b.len()).unwrap();
        b[0..2].copy_from_slice(&n.to_le_bytes());
        b[2..4].copy_from_slice(&u16::try_from(value_len).unwrap().to_le_bytes());
        b[4..6].copy_from_slice(&u16::from(text).to_le_bytes());
        b
    }

    fn text(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn fixed_info_and_strings() {
        let mut fixed = Vec::new();
        for w in [
            0xFEEF_04BDu32,
            0x1_0000,
            0x0001_0002,
            0x0003_0004,
            0x0005_0006,
            0x0007_0008,
            0x3F,
            0x2,
            0x4_0004,
            2,
            0,
            0,
            0,
        ] {
            fixed.extend(w.to_le_bytes());
        }
        let strings = block(
            "StringFileInfo",
            &[],
            true,
            &[block(
                "040904B0",
                &[],
                true,
                &[
                    block("CompanyName", &text("Contoso"), true, &[]),
                    block("FileVersion", &text("1.2.3.4"), true, &[]),
                ],
            )],
        );
        let vars = block(
            "VarFileInfo",
            &[],
            true,
            &[block("Translation", &[0x09, 0x04, 0xB0, 0x04], false, &[])],
        );
        let data = block("VS_VERSION_INFO", &fixed, false, &[strings, vars]);
        let v = VersionInfo::parse(&data).unwrap();
        let f = v.fixed.unwrap();
        assert_eq!(dotted(f.file_version), "1.2.3.4");
        assert_eq!(dotted(f.product_version), "5.6.7.8");
        assert_eq!(f.flag_names(), ["prerelease"]);
        assert_eq!(f.type_name(), "DLL");
        assert_eq!(v.get("CompanyName"), Some("Contoso"));
        assert_eq!(v.get("companyname"), Some("Contoso"));
        assert_eq!(v.get("ProductName"), None);
        assert_eq!(v.translations, [(0x409, 0x4B0)]);
        // Truncated anywhere: no panic.
        for n in 0..data.len() {
            let _ = VersionInfo::parse(&data[..n]);
        }
    }
}

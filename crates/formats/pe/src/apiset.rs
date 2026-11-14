//! API set schemas: what Windows' virtual DLL names (`api-ms-win-*`,
//! `ext-ms-*`) stand for. The loader reads `apisetschema.dll`'s `.apiset`
//! section, a namespace of API sets, each with the DLLs that host it (a
//! default, and others for particular importers).
//!
//! Three versions are read: 2 (Windows 7), 4 (Windows 8.1), and 6
//! (Windows 10 and later). Names are UTF-16. In version 6 a set matches a
//! name by its name up to its last hyphen (its hashed length: any minor
//! version of the set); in the others, by its whole name, which omits the
//! `api-` prefix.

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::Reader;

/// The most sets and hosts read (Windows 11 has about 2,000 sets).
const MAX_SETS: u32 = 1 << 16;
const MAX_HOSTS: u32 = 64;

/// An API set: its name, and its hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiSet {
    /// Its name, lower case, without `.dll` (`api-ms-win-core-file-l1-2-0`;
    /// in versions 2 and 4, without `api-` too).
    pub name: String,
    /// How much of `name` a name must match (version 6: up to its last
    /// hyphen; else all of it).
    pub hashed: usize,
    /// Its hosts: (importer, host), the importer empty for the default.
    pub hosts: Vec<(String, String)>,
}

/// An API set schema.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiSetSchema {
    /// Its version (2, 4, or 6).
    pub version: u32,
    /// Its sets, sorted by name.
    pub sets: Vec<ApiSet>,
}

/// Whether `dll` is an API set's name (`api-*` or `ext-*`, case aside).
pub fn is_api_set_name(dll: &str) -> bool {
    let lower = dll.to_ascii_lowercase();
    lower.starts_with("api-") || lower.starts_with("ext-")
}

impl ApiSetSchema {
    /// Reads the schema in an `.apiset` section's contents.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let version = Reader::new(data).u32_le().ok()?;
        let sets = match version {
            6 => v6(data)?,
            4 => v4(data)?,
            2 => v2(data)?,
            _ => return None,
        };
        let mut sets = sets;
        sets.sort_by(|a, b| a.name.cmp(&b.name));
        Some(Self { version, sets })
    }

    /// The set `dll` names (`.dll` optional, case aside), if it is one.
    pub fn find(&self, dll: &str) -> Option<&ApiSet> {
        let mut name = dll.to_ascii_lowercase();
        if let Some(stem) = name.strip_suffix(".dll") {
            name.truncate(stem.len());
        }
        if self.version != 6 {
            let short = name.strip_prefix("api-").unwrap_or(&name);
            return self
                .sets
                .binary_search_by(|s| s.name.as_str().cmp(short))
                .ok()
                .map(|i| &self.sets[i]);
        }
        // Version 6: the name up to its last hyphen against each set's
        // hashed prefix.
        let key = &name[..name.rfind('-').unwrap_or(name.len())];
        let i = self
            .sets
            .partition_point(|s| s.name[..s.hashed.min(s.name.len())] < *key);
        self.sets
            .get(i)
            .filter(|s| s.name.get(..s.hashed) == Some(key))
    }

    /// The DLL `dll` (an API set's name) stands for when `importer` (a
    /// file name, case aside) imports it: its host for that importer, else
    /// its default. `None` if it is no set; `Some(None)` if the set has no
    /// host (one not on this system).
    pub fn resolve(&self, dll: &str, importer: &str) -> Option<Option<&str>> {
        let set = self.find(dll)?;
        let importer = importer.to_ascii_lowercase();
        let host = set
            .hosts
            .iter()
            .find(|(by, _)| !by.is_empty() && by.eq_ignore_ascii_case(&importer))
            .or_else(|| set.hosts.iter().find(|(by, _)| by.is_empty()))
            .or_else(|| set.hosts.first())
            .map(|(_, h)| h.as_str())
            .filter(|h| !h.is_empty());
        Some(host)
    }
}

/// UTF-16 text of `bytes` bytes at `offset` (from the schema's start).
fn text(data: &[u8], offset: u32, bytes: u32) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(bytes).ok()?)?;
    let raw = data.get(start..end)?;
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units).to_ascii_lowercase())
}

fn words<const N: usize>(data: &[u8], at: u32) -> Option<[u32; N]> {
    let mut r = Reader::new(data.get(usize::try_from(at).ok()?..)?);
    let mut out = [0u32; N];
    for w in &mut out {
        *w = r.u32_le().ok()?;
    }
    Some(out)
}

/// Version 6: `API_SET_NAMESPACE` (version, size, flags, count, entry
/// offset, hash offset, hash factor); entries (flags, name offset, name
/// length, hashed length, value offset, value count); values (flags, name
/// offset, name length, value offset, value length).
fn v6(data: &[u8]) -> Option<Vec<ApiSet>> {
    let [_, _, _, count, entries, ..] = words::<7>(data, 0)?;
    let mut out = Vec::new();
    for i in 0..count.min(MAX_SETS) {
        let at = entries.checked_add(i.checked_mul(24)?)?;
        let Some([_, name_off, name_len, hashed, value_off, value_count]) = words::<6>(data, at)
        else {
            break;
        };
        let Some(name) = text(data, name_off, name_len) else {
            continue;
        };
        let mut hosts = Vec::new();
        for j in 0..value_count.min(MAX_HOSTS) {
            let Some(at) = j.checked_mul(20).and_then(|o| value_off.checked_add(o)) else {
                break;
            };
            let Some([_, by_off, by_len, host_off, host_len]) = words::<5>(data, at) else {
                break;
            };
            let by = text(data, by_off, by_len).unwrap_or_default();
            let host = text(data, host_off, host_len).unwrap_or_default();
            hosts.push((by, host));
        }
        let hashed = usize::try_from(hashed / 2)
            .unwrap_or(usize::MAX)
            .min(name.len());
        out.push(ApiSet {
            name,
            hashed,
            hosts,
        });
    }
    Some(out)
}

/// Version 4: `API_SET_NAMESPACE_ARRAY` (version, size, flags, count),
/// entries (flags, name offset, name length, alias offset, alias length,
/// data offset); at a data offset, `API_SET_VALUE_ARRAY` (flags, count)
/// and values (flags, name offset, name length, value offset, value
/// length).
fn v4(data: &[u8]) -> Option<Vec<ApiSet>> {
    let [_, _, _, count] = words::<4>(data, 0)?;
    let mut out = Vec::new();
    for i in 0..count.min(MAX_SETS) {
        let at = 16u32.checked_add(i.checked_mul(24)?)?;
        let Some([_, name_off, name_len, _, _, values]) = words::<6>(data, at) else {
            break;
        };
        let Some(name) = text(data, name_off, name_len) else {
            continue;
        };
        let hosts = value_array(data, values, 8, 20, 1);
        let hashed = name.len();
        out.push(ApiSet {
            name,
            hashed,
            hosts,
        });
    }
    Some(out)
}

/// Version 2: `API_SET_NAMESPACE_ARRAY` (version, count), entries (name
/// offset, name length, data offset); at a data offset, a count and
/// values (name offset, name length, value offset, value length).
fn v2(data: &[u8]) -> Option<Vec<ApiSet>> {
    let [_, count] = words::<2>(data, 0)?;
    let mut out = Vec::new();
    for i in 0..count.min(MAX_SETS) {
        let at = 8u32.checked_add(i.checked_mul(12)?)?;
        let Some([name_off, name_len, values]) = words::<3>(data, at) else {
            break;
        };
        let Some(name) = text(data, name_off, name_len) else {
            continue;
        };
        let hosts = value_array(data, values, 4, 16, 0);
        let hashed = name.len();
        out.push(ApiSet {
            name,
            hashed,
            hosts,
        });
    }
    Some(out)
}

/// Versions 2 and 4's value arrays: a header of `header` bytes (its count
/// last), then values of `size` bytes whose fields start `skip` words in.
fn value_array(data: &[u8], at: u32, header: u32, size: u32, skip: usize) -> Vec<(String, String)> {
    let mut hosts = Vec::new();
    let Some(count) = header
        .checked_sub(4)
        .and_then(|o| at.checked_add(o))
        .and_then(|o| words::<1>(data, o))
    else {
        return hosts;
    };
    for j in 0..count[0].min(MAX_HOSTS) {
        let Some(v) = j
            .checked_mul(size)
            .and_then(|o| o.checked_add(header))
            .and_then(|o| at.checked_add(o))
            .and_then(|o| words::<5>(data, o))
        else {
            break;
        };
        let f = &v[skip..];
        let by = text(data, f[0], f[1]).unwrap_or_default();
        let host = text(data, f[2], f[3]).unwrap_or_default();
        hosts.push((by, host));
    }
    hosts
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, reason = "small test data")]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    /// An API set: its name, hashed length, and hosts (importer, host).
    type Set<'a> = (&'a str, usize, &'a [(&'a str, &'a str)]);

    /// A version 6 schema of `sets`.
    fn v6_schema(sets: &[Set<'_>]) -> Vec<u8> {
        let mut strings: Vec<u8> = Vec::new();
        let put = |s: &str, strings: &mut Vec<u8>| -> (u32, u32) {
            let at = strings.len();
            for u in s.encode_utf16() {
                strings.extend_from_slice(&u.to_le_bytes());
            }
            (at as u32, (strings.len() - at) as u32)
        };
        let entries = 28u32;
        let values = entries + 24 * sets.len() as u32;
        let hosts: usize = sets.iter().map(|s| s.2.len()).sum();
        let base = values + 20 * hosts as u32;
        let mut e = Vec::new();
        let mut v = Vec::new();
        let mut value_at = values;
        for (name, hashed, hs) in sets {
            let (no, nl) = put(name, &mut strings);
            for w in [
                0,
                base + no,
                nl,
                2 * *hashed as u32,
                value_at,
                hs.len() as u32,
            ] {
                e.extend_from_slice(&w.to_le_bytes());
            }
            for (by, host) in *hs {
                let (bo, bl) = put(by, &mut strings);
                let (ho, hl) = put(host, &mut strings);
                for w in [0, base + bo, bl, base + ho, hl] {
                    v.extend_from_slice(&w.to_le_bytes());
                }
                value_at += 20;
            }
        }
        let mut out = Vec::new();
        for w in [6u32, 0, 0, sets.len() as u32, entries, 0, 0] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend(e);
        out.extend(v);
        out.extend(strings);
        out
    }

    #[test]
    fn version_6() {
        let data = v6_schema(&[
            ("api-ms-win-core-file-l1-2-0", 25, &[("", "kernelbase.dll")]),
            (
                "api-ms-win-core-heap-l1-1-0",
                25,
                &[("", "kernelbase.dll"), ("kernelbase.dll", "ntdll.dll")],
            ),
            ("ext-ms-win-gaming-xinput-l1-1-0", 29, &[]),
        ]);
        let s = ApiSetSchema::parse(&data).unwrap();
        assert_eq!(s.version, 6);
        assert_eq!(s.sets.len(), 3);
        // Any minor version, any case, .dll or not.
        for name in [
            "api-ms-win-core-file-l1-2-0.dll",
            "API-MS-WIN-CORE-FILE-L1-2-3",
            "api-ms-win-core-file-l1-2-1.dll",
        ] {
            assert_eq!(
                s.resolve(name, "app.exe"),
                Some(Some("kernelbase.dll")),
                "{name}"
            );
        }
        assert_eq!(
            s.resolve("api-ms-win-core-file-l1-3-0.dll", "app.exe"),
            None
        );
        // An importer's own host.
        assert_eq!(
            s.resolve("api-ms-win-core-heap-l1-1-0.dll", "KernelBase.dll"),
            Some(Some("ntdll.dll"))
        );
        assert_eq!(
            s.resolve("api-ms-win-core-heap-l1-1-0.dll", "app.exe"),
            Some(Some("kernelbase.dll"))
        );
        // A set with no host here.
        assert_eq!(
            s.resolve("ext-ms-win-gaming-xinput-l1-1-0.dll", "app.exe"),
            Some(None)
        );
        assert_eq!(s.resolve("kernel32.dll", "app.exe"), None);
        assert!(
            is_api_set_name("API-ms-x.dll")
                && is_api_set_name("ext-ms-y")
                && !is_api_set_name("apix.dll")
        );
    }

    #[test]
    fn versions_2_and_4() {
        // Version 4: one set, its value array (flags, count) then a value.
        let name: Vec<u8> = "ms-win-core-file-l1-1-0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let host: Vec<u8> = "kernel32.dll"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut d = Vec::new();
        let names = 16 + 24;
        let values = names + name.len() as u32;
        let hosts = values + 8 + 20;
        for w in [4u32, 0, 0, 1, 0, names, name.len() as u32, 0, 0, values] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&name);
        for w in [0u32, 1, 0, 0, 0, hosts, host.len() as u32] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&host);
        let s = ApiSetSchema::parse(&d).unwrap();
        assert_eq!(
            s.resolve("api-ms-win-core-file-l1-1-0.dll", "x.exe"),
            Some(Some("kernel32.dll"))
        );
        assert_eq!(s.resolve("api-ms-win-core-file-l1-1-1.dll", "x.exe"), None);
        // Version 2: the same, laid out so.
        let mut d = Vec::new();
        let names = 8 + 12;
        let values = names + name.len() as u32;
        let hosts = values + 4 + 16;
        for w in [2u32, 1, names, name.len() as u32, values] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&name);
        for w in [1u32, 0, 0, hosts, host.len() as u32] {
            d.extend_from_slice(&w.to_le_bytes());
        }
        d.extend_from_slice(&host);
        let s = ApiSetSchema::parse(&d).unwrap();
        assert_eq!(s.version, 2);
        assert_eq!(
            s.resolve("API-MS-WIN-CORE-FILE-L1-1-0.DLL", "x.exe"),
            Some(Some("kernel32.dll"))
        );
    }

    /// Hostile schemas: truncated, with counts and offsets past the end.
    #[test]
    fn hostile() {
        assert!(ApiSetSchema::parse(&[]).is_none());
        assert!(ApiSetSchema::parse(&[7, 0, 0, 0]).is_none());
        let data = v6_schema(&[("api-ms-win-core-file-l1-2-0", 25, &[("", "kernelbase.dll")])]);
        for n in 0..data.len() {
            if let Some(s) = ApiSetSchema::parse(&data[..n]) {
                let _ = s.resolve("api-ms-win-core-file-l1-2-0", "x");
            }
        }
        let mut huge = data.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let s = ApiSetSchema::parse(&huge).unwrap();
        assert!(s.sets.is_empty());
        let mut d = vec![4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        d.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(ApiSetSchema::parse(&d).unwrap().sets.len(), 0);
        // A hashed length past the name: clamped.
        let data = v6_schema(&[("api-x-1", 99, &[("", "h.dll")])]);
        let s = ApiSetSchema::parse(&data).unwrap();
        assert_eq!(s.sets[0].hashed, 7);
    }
}

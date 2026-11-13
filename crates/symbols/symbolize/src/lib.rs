//! Finding an image's symbols, and the function at an address.
//!
//! [`SymbolPath`] finds the PDB that matches an image's debug identity
//! (GUID and age), looking only on this machine: at the path the image
//! recorded, and in directories laid out like a symbol store or a flat
//! folder. It never downloads anything; a symbol server's local cache works
//! if `_NT_SYMBOL_PATH` names it. A found PDB is checked against the
//! identity before it is used.
//!
//! [`FunctionTable`] is a PDB's public symbols sorted by address, with
//! undecorated names, for finding the function an address is in.

use std::path::{Path, PathBuf};

use hexcavator_codeview::Symbol;
use hexcavator_core::Result;
use hexcavator_pdb::{Pdb, gsi};

/// Where to look for symbol files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymbolPath {
    /// Directories to search, in order.
    pub dirs: Vec<PathBuf>,
}

impl SymbolPath {
    /// The local directories of `_NT_SYMBOL_PATH`, if set.
    pub fn from_env() -> Self {
        std::env::var("_NT_SYMBOL_PATH").map_or_else(|_| Self::default(), |v| Self::parse(&v))
    }

    /// The local directories of a symbol path: plain directories, and the
    /// caches of `srv*` and `cache*` entries (URLs are skipped).
    pub fn parse(path: &str) -> Self {
        Self {
            dirs: hexcavator_debuginfo::nt_symbol_dirs(path),
        }
    }

    /// The PDB with `guid` and `age`, recorded at `pdb_path` when the image
    /// was built: there, or in a directory of the symbol path (as
    /// `name.pdb/GUIDAGE/name.pdb` or `name.pdb`).
    pub fn find_pdb(&self, pdb_path: &str, guid: &[u8; 16], age: u32) -> Option<PathBuf> {
        let name = pdb_path
            .rsplit(['\\', '/'])
            .next()
            .filter(|n| !n.is_empty())?;
        let key = symbol_store_key(guid, age);
        let mut candidates = vec![PathBuf::from(pdb_path)];
        for dir in &self.dirs {
            candidates.push(dir.join(name).join(&key).join(name));
            candidates.push(dir.join(name));
        }
        candidates.into_iter().find(|p| matches(p, guid, age))
    }
}

pub use hexcavator_debuginfo::symbol_store_key;

/// Whether the PDB at `path` has `guid` and `age`. (The first candidate
/// is the path the trace records: a hostile trace could name a network
/// share, a device, or a FIFO, so only a local regular file is opened.)
fn matches(path: &Path, guid: &[u8; 16], age: u32) -> bool {
    let Ok(map) = hexcavator_mmap::Mmap::open_named(path) else {
        return false;
    };
    let Ok(pdb) = Pdb::parse(&map) else {
        return false;
    };
    let info = pdb.info();
    // The image records the PDB's age when it was linked; a PDB can be
    // newer (updated later), never older.
    info.guid() == *guid && info.age() >= age
}

/// A PDB's functions, by address: its procedures (with their code
/// ranges), and public symbols for code no procedure covers (each running
/// to the next function).
#[derive(Clone, Debug, Default)]
pub struct FunctionTable {
    /// (start RVA, end RVA, name), sorted by start, not overlapping.
    entries: Vec<(u32, u32, String)>,
    /// Inlined code: (start RVA, end RVA, depth, site), sorted by start.
    /// Nested sites' ranges lie within their callers'.
    inlines: Vec<(u32, u32, u32, u32)>,
    /// Each inline site's inlined function's name.
    site_names: Vec<String>,
    /// Source lines: (start RVA, end RVA, file, line), sorted by start.
    lines: Vec<(u32, u32, u32, u32)>,
    /// The source files.
    files: Vec<String>,
}

impl FunctionTable {
    /// Reads the functions of the PDB in `data`.
    pub fn from_pdb(data: &[u8]) -> Result<Self> {
        let pdb = Pdb::parse(data)?;
        let sections = pdb.sections()?;
        let mut demangler = hexcavator_demangle::msvc::Demangler::new();

        // Procedures, from every module's symbols.
        let mut procs: Vec<(u32, u32, String)> = Vec::new();
        let dbi = pdb.dbi()?;
        for module in dbi.modules() {
            let Ok(Some(stream)) = pdb.module_stream(module) else {
                continue;
            };
            for record in stream.symbols() {
                let Ok(Symbol::Procedure {
                    segment,
                    offset,
                    len,
                    name,
                    ..
                }) = record.parse()
                else {
                    continue;
                };
                let Some(rva) = pdb.rva(&sections, segment, offset) else {
                    continue;
                };
                let raw = String::from_utf8_lossy(name);
                procs.push((
                    rva,
                    rva.saturating_add(len.max(1)),
                    undecorate(&mut demangler, &raw),
                ));
            }
        }
        procs.sort_by_key(|e| (e.0, std::cmp::Reverse(e.1)));
        procs.dedup_by_key(|e| e.0);

        // Publics, for what no procedure covers.
        let mut publics: Vec<(u32, String)> = Vec::new();
        if let Ok(stream) = pdb.publics() {
            let records = pdb.symbol_records();
            for off in stream.address_map() {
                let Some(record) = gsi::symbol_at(records, off.get()) else {
                    continue;
                };
                let Ok(Symbol::Public {
                    segment,
                    offset,
                    name,
                    ..
                }) = record.parse()
                else {
                    continue;
                };
                let Some(rva) = pdb.rva(&sections, segment, offset) else {
                    continue;
                };
                let i = procs.partition_point(|p| p.0 <= rva);
                if i > 0 && rva < procs[i - 1].1 {
                    continue;
                }
                let raw = String::from_utf8_lossy(name);
                publics.push((rva, undecorate(&mut demangler, &raw)));
            }
        }
        publics.sort_by_key(|e| e.0);
        publics.dedup_by_key(|e| e.0);

        // A public runs to the next function of either kind.
        let mut starts: Vec<u32> = procs
            .iter()
            .map(|e| e.0)
            .chain(publics.iter().map(|p| p.0))
            .collect();
        starts.sort_unstable();
        let mut entries = procs;
        for (rva, name) in publics {
            let next = starts[starts.partition_point(|&s| s <= rva)..]
                .first()
                .copied()
                .unwrap_or(u32::MAX);
            entries.push((rva, next, name));
        }
        entries.sort_by_key(|e| e.0);
        // Nested or overlapping ranges (rare) end where the next begins.
        for i in 1..entries.len() {
            let next = entries[i].0;
            if entries[i - 1].1 > next {
                entries[i - 1].1 = next;
            }
        }
        let mut table = Self {
            entries,
            ..Self::default()
        };
        // Inline sites and lines, from the format-independent reader. A PDB
        // without them still has its functions.
        if let Ok(info) = hexcavator_debuginfo::DebugInfo::parse(data) {
            if let Ok(sites) = info.inline_sites() {
                for (i, site) in sites.sites.iter().enumerate() {
                    let Ok(index) = u32::try_from(i) else { break };
                    let name = sites
                        .inlinees
                        .get(site.inlinee as usize)
                        .cloned()
                        .unwrap_or_default();
                    table.site_names.push(name);
                    for &(addr, size) in &site.ranges {
                        let (Ok(start), Ok(end)) = (
                            u32::try_from(addr),
                            u32::try_from(addr.saturating_add(size)),
                        ) else {
                            continue;
                        };
                        table.inlines.push((start, end, site.depth, index));
                    }
                }
                table.inlines.sort_unstable();
            }
            if let Ok(lines) = info.source_lines() {
                table.files = lines.files;
                for span in &lines.spans {
                    let (Ok(start), Ok(end)) = (
                        u32::try_from(span.addr),
                        u32::try_from(span.addr.saturating_add(span.size)),
                    ) else {
                        continue;
                    };
                    table.lines.push((start, end, span.file, span.line));
                }
                table.lines.sort_unstable();
            }
        }
        Ok(table)
    }

    /// The inlined calls at `rva`, outermost first: each one's site and
    /// inlined function's name.
    pub fn inlines(&self, rva: u32) -> Vec<(u32, &str)> {
        // Sites lie within their function, so only ranges starting in the
        // function (at or before `rva`) can cover it.
        let Some((start, _)) = self.function(rva) else {
            return Vec::new();
        };
        let lo = self.inlines.partition_point(|r| r.0 < start);
        let hi = self.inlines.partition_point(|r| r.0 <= rva);
        let mut found: Vec<(u32, u32)> = self.inlines[lo..hi]
            .iter()
            .filter(|r| rva < r.1)
            .map(|r| (r.2, r.3))
            .collect();
        found.sort_unstable();
        found.dedup_by_key(|f| f.0);
        found
            .into_iter()
            .map(|(_, site)| (site, self.site_names[site as usize].as_str()))
            .collect()
    }

    /// The name of an inline site's inlined function.
    pub fn site_name(&self, site: u32) -> Option<&str> {
        self.site_names.get(site as usize).map(String::as_str)
    }

    /// The source file and line of `rva`.
    pub fn line(&self, rva: u32) -> Option<(&str, u32)> {
        let i = self.lines.partition_point(|l| l.0 <= rva);
        let &(_, end, file, line) = self.lines.get(i.checked_sub(1)?)?;
        (rva < end).then(|| {
            (
                self.files.get(file as usize).map_or("", String::as_str),
                line,
            )
        })
    }

    /// The number of functions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The functions: start, end and name, by address.
    pub fn iter(&self) -> impl Iterator<Item = (u32, u32, &str)> {
        self.entries.iter().map(|(s, e, n)| (*s, *e, n.as_str()))
    }

    /// The function containing `rva`: its start and name.
    pub fn function(&self, rva: u32) -> Option<(u32, &str)> {
        let i = self.entries.partition_point(|e| e.0 <= rva);
        let (start, end, name) = self.entries.get(i.checked_sub(1)?)?;
        (rva < *end).then_some((*start, name.as_str()))
    }
}

/// A public symbol's name as a tree shows it: MSVC names undecorated to
/// the qualified name only, Rust names demangled, others as they are.
fn undecorate(demangler: &mut hexcavator_demangle::msvc::Demangler, raw: &str) -> String {
    let mut out = String::new();
    if raw.starts_with('?') {
        if demangler.demangle_into(raw, hexcavator_demangle::msvc::flags::NAME_ONLY, &mut out) {
            return out;
        }
    } else if (raw.starts_with("_ZN") || raw.starts_with("_R"))
        && hexcavator_demangle::rust::demangle_into(raw, &mut out)
    {
        // Rust's legacy names end in a hash; trees read better without it.
        if let Some(i) = out.rfind("::h")
            && out[i + 3..].len() == 16
            && out[i + 3..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.truncate(i);
        }
        return out;
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PDB path a trace records is the trace's to choose: one naming a
    /// share, a device, or a namespace isn't opened (on Windows, opening a
    /// share would connect to it, offering the user's credentials).
    #[test]
    fn recorded_paths_naming_shares_are_not_opened() {
        let path = SymbolPath::default();
        for pdb in [
            r"\\attacker.invalid\share\app.pdb",
            "//attacker.invalid/share/app.pdb",
            r"\\.\pipe\app.pdb",
            r"\\?\UNC\attacker.invalid\share\app.pdb",
        ] {
            assert_eq!(path.find_pdb(pdb, &[0; 16], 1), None, "{pdb}");
        }
    }

    #[test]
    fn parses_symbol_paths() {
        let p = SymbolPath::parse(
            r"srv*C:\symbols*https://msdl.microsoft.com/download/symbols; C:\mine ;cache*D:\cache;;",
        );
        assert_eq!(
            p.dirs,
            [
                PathBuf::from(r"C:\symbols"),
                PathBuf::from(r"C:\mine"),
                PathBuf::from(r"D:\cache")
            ]
        );
        assert_eq!(SymbolPath::parse(""), SymbolPath::default());
    }

    #[test]
    fn symbol_store_keys() {
        // {3844DBB9-2017-4967-BE79-96A1D5D8A60D}, age 1.
        let guid = [
            0xb9, 0xdb, 0x44, 0x38, 0x17, 0x20, 0x67, 0x49, 0xbe, 0x79, 0x96, 0xa1, 0xd5, 0xd8,
            0xa6, 0x0d,
        ];
        assert_eq!(
            symbol_store_key(&guid, 1),
            "3844DBB920174967BE7996A1D5D8A60D1"
        );
        assert_eq!(
            symbol_store_key(&guid, 0x1a),
            "3844DBB920174967BE7996A1D5D8A60D1A"
        );
    }

    #[test]
    fn finds_nothing_that_is_not_there() {
        let p = SymbolPath::parse(r"C:\no\such\dir");
        assert_eq!(p.find_pdb(r"C:\no\such\file.pdb", &[0; 16], 1), None);
        assert_eq!(p.find_pdb("", &[0; 16], 1), None);
    }

    #[test]
    fn function_lookup() {
        let t = FunctionTable {
            entries: vec![(0x1000, 0x1080, "a".into()), (0x1100, 0x1200, "b".into())],
            ..FunctionTable::default()
        };
        assert_eq!(t.function(0xfff), None);
        assert_eq!(t.function(0x1000), Some((0x1000, "a")));
        assert_eq!(t.function(0x107f), Some((0x1000, "a")));
        // Between functions: in none.
        assert_eq!(t.function(0x1080), None);
        assert_eq!(t.function(0x11ff), Some((0x1100, "b")));
        assert_eq!(t.function(0x1200), None);
    }

    #[test]
    fn inlines_and_lines() {
        // a (0x1000..0x1080) inlines x at 0x1010..0x1040, which inlines y
        // at 0x1020..0x1030.
        let t = FunctionTable {
            entries: vec![(0x1000, 0x1080, "a".into())],
            inlines: vec![(0x1010, 0x1040, 0, 0), (0x1020, 0x1030, 1, 1)],
            site_names: vec!["x".into(), "y".into()],
            lines: vec![(0x1000, 0x1020, 0, 10), (0x1020, 0x1080, 0, 11)],
            files: vec!["a.cpp".into()],
        };
        assert!(t.inlines(0x1008).is_empty());
        assert_eq!(t.inlines(0x1010), [(0, "x")]);
        assert_eq!(t.inlines(0x1025), [(0, "x"), (1, "y")]);
        assert_eq!(t.inlines(0x1030), [(0, "x")]);
        assert!(t.inlines(0x1040).is_empty());
        assert!(t.inlines(0x2000).is_empty());
        assert_eq!(t.site_name(1), Some("y"));
        assert_eq!(t.site_name(2), None);
        assert_eq!(t.line(0x101f), Some(("a.cpp", 10)));
        assert_eq!(t.line(0x1020), Some(("a.cpp", 11)));
        assert_eq!(t.line(0x1080), None);
    }

    #[test]
    fn undecorates() {
        let mut d = hexcavator_demangle::msvc::Demangler::new();
        assert_eq!(undecorate(&mut d, "?f@C@@QEAAXH@Z"), "C::f");
        assert_eq!(
            undecorate(&mut d, "_ZN4core3ptr13drop_in_place17h0123456789abcdefE"),
            "core::ptr::drop_in_place"
        );
        assert_eq!(undecorate(&mut d, "memcpy"), "memcpy");
    }
}

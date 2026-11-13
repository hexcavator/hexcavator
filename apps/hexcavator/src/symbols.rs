//! Names for addresses in an image, from its PDB.
//!
//! The PDB is found the way dumpbin finds it: at the path in the image's
//! CodeView record, or next to the image, and only if its GUID matches.

use std::path::Path;

use hexcavator_codeview::symbols::Symbol;
use hexcavator_mmap::Mmap;
use hexcavator_pdb::Pdb;
use hexcavator_pe::{CodeView, PeFile};

/// Symbols by address (VA).
#[derive(Default)]
pub struct SymbolMap {
    /// Sorted by address; one name per address, and whether it is public.
    entries: Vec<(u64, String, bool)>,
    /// The `[start, end)` VA ranges that object files contributed, sorted.
    contributions: Vec<(u64, u64)>,
}

impl SymbolMap {
    /// Loads the symbols for `file` (read from `path`) from its PDB, if it
    /// can be found.
    pub fn for_image(file: &PeFile<'_>, path: &Path) -> Option<Self> {
        let CodeView::Rsds {
            guid,
            age,
            path: pdb_path,
        } = file.codeview()?
        else {
            return None;
        };
        // The recorded path may use either separator, whatever the host's.
        let id = hexcavator_image::DebugId::Pdb {
            guid,
            age,
            path: pdb_path,
        };
        let dirs = hexcavator_debuginfo::symbol_dirs();
        for candidate in hexcavator_debuginfo::candidate_paths_in(path, &id, &dirs) {
            let Ok(map) = Mmap::open_named(&candidate) else {
                continue;
            };
            let Ok(pdb) = Pdb::parse(&map) else {
                continue;
            };
            if pdb.info().guid() != guid {
                continue;
            }
            return Some(Self::from_pdb(&pdb, file));
        }
        None
    }

    fn from_pdb(pdb: &Pdb<'_>, file: &PeFile<'_>) -> Self {
        let base = file.optional_header().map_or(0, |h| h.image_base().get());
        let Ok(sections) = pdb.sections() else {
            return Self::default();
        };
        let va = |segment: u16, offset: u32| {
            pdb.rva(&sections, segment, offset)
                .map(|r| base.wrapping_add(u64::from(r)))
        };
        let mut entries: Vec<(u64, String)> = Vec::new();
        // Publics first: where a public and a procedure share an address,
        // the (decorated) public name wins.
        let records = pdb.symbol_records();
        if let Ok(publics) = pdb.publics() {
            for off in publics.address_map() {
                if let Some(Ok(Symbol::Public {
                    offset,
                    segment,
                    name,
                    ..
                })) = hexcavator_pdb::gsi::symbol_at(records, off.get()).map(|r| r.parse())
                    && let Some(a) = va(segment, offset)
                {
                    entries.push((a, String::from_utf8_lossy(name).into_owned()));
                }
            }
        }
        let publics = entries.len();
        let mut contributions = Vec::new();
        if let Ok(dbi) = pdb.dbi() {
            for c in dbi
                .section_contribs()
                .iter()
                .flat_map(hexcavator_pdb::dbi::SectionContribs::iter)
            {
                let size = u64::try_from(c.size.get()).unwrap_or(0);
                let offset = u32::try_from(c.offset.get()).unwrap_or(0);
                if let Some(a) = va(c.section.get(), offset) {
                    contributions.push((a, a + size));
                }
            }
            contributions.sort_unstable();
            for m in dbi.modules() {
                let Ok(Some(stream)) = pdb.module_stream(m) else {
                    continue;
                };
                for rec in stream.symbols() {
                    if let Ok(Symbol::Procedure {
                        offset,
                        segment,
                        name,
                        ..
                    }) = rec.parse()
                        && let Some(a) = va(segment, offset)
                    {
                        entries.push((a, String::from_utf8_lossy(name).into_owned()));
                    }
                }
            }
        }
        // Keep the first name for each address, preferring publics.
        let mut keyed: Vec<(u64, usize, String)> = entries
            .into_iter()
            .enumerate()
            .map(|(i, (a, n))| (a, usize::from(i >= publics), n))
            .collect();
        keyed.sort_by_key(|e| (e.0, e.1));
        keyed.dedup_by_key(|e| e.0);
        Self {
            entries: keyed
                .into_iter()
                .map(|(a, kind, n)| (a, n, kind == 0))
                .collect(),
            contributions,
        }
    }

    /// If `address` is outside every contribution (such as linker padding
    /// between functions), where the next contribution starts.
    pub fn gap_end(&self, address: u64) -> Option<u64> {
        if self.contributions.is_empty() {
            return None;
        }
        let i = self.contributions.partition_point(|c| c.0 <= address);
        if i > 0 && address < self.contributions[i - 1].1 {
            return None;
        }
        Some(self.contributions.get(i).map_or(u64::MAX, |c| c.0))
    }

    /// The name of the symbol at exactly `address`: a public, or a
    /// procedure (such as a static function) that has none.
    pub fn at(&self, address: u64) -> Option<&str> {
        let i = self.entries.binary_search_by_key(&address, |e| e.0).ok()?;
        Some(&self.entries[i].1)
    }

    /// The public symbol at exactly `address`. dumpbin names operands only
    /// with publics.
    pub fn public_at(&self, address: u64) -> Option<&str> {
        let i = self.entries.binary_search_by_key(&address, |e| e.0).ok()?;
        let e = &self.entries[i];
        e.2.then_some(e.1.as_str())
    }
}

impl hexcavator_x86::format::Symbols for SymbolMap {
    fn name_at(&self, address: u64) -> Option<&str> {
        self.public_at(address)
    }
}

//! A [`Symbolizer`] from PDBs found on this machine.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use rustc_hash::FxHashMap;

use hexcavator_symbolize::{FunctionTable, SymbolPath};
use hexcavator_trace::{ImageIx, Trace};

use crate::keys::Symbolizer;

/// A PDB's identity: GUID and age.
type DebugKey = ([u8; 16], u32);

/// Finds functions in the PDBs of a trace's images, loading each PDB the
/// first time one of its addresses is asked about. Images without a debug
/// identity, or whose PDB isn't found, have no functions. Threads may share
/// it.
pub struct PdbSymbolizer {
    path: SymbolPath,
    /// By (GUID, age): the same DLL is loaded in many processes. Each is
    /// loaded once: a thread that wants one being loaded waits for it.
    tables: Mutex<FxHashMap<DebugKey, Slot>>,
}

/// A PDB's slot in a [`PdbSymbolizer`].
type Slot = Arc<OnceLock<Option<Arc<FunctionTable>>>>;

impl PdbSymbolizer {
    /// A symbolizer that searches `path` (and each image's recorded PDB
    /// path).
    pub fn new(path: SymbolPath) -> Self {
        Self {
            path,
            tables: Mutex::new(FxHashMap::default()),
        }
    }

    /// The function table of `image`'s PDB, if found.
    pub fn table(&self, trace: &Trace, image: ImageIx) -> Option<Arc<FunctionTable>> {
        let id = trace.images[image.index()].debug_id.as_ref()?;
        self.load(&id.pdb_path, &id.guid, id.age)
    }

    /// The function table of the PDB recorded at `pdb_path` with `guid`
    /// and `age`, if found: loaded the first time it is asked for (by one
    /// thread; others asking meanwhile wait for it, and others' other
    /// PDBs load at once).
    pub fn load(&self, pdb_path: &str, guid: &[u8; 16], age: u32) -> Option<Arc<FunctionTable>> {
        let slot: Slot = Arc::clone(self.tables().entry((*guid, age)).or_default());
        slot.get_or_init(|| {
            self.path
                .find_pdb(pdb_path, guid, age)
                // (Perhaps the path the trace records: see `open_named`.)
                .and_then(|p| hexcavator_mmap::Mmap::open_named(p).ok())
                .and_then(|map| FunctionTable::from_pdb(&map).ok())
                .map(Arc::new)
        })
        .clone()
    }

    fn tables(&self) -> std::sync::MutexGuard<'_, FxHashMap<DebugKey, Slot>> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets the PDBs that weren't found, so that they are looked for
    /// again (after a download).
    pub fn forget_missing(&self) {
        self.tables()
            .retain(|_, t| t.get().is_none_or(Option::is_some));
    }

    /// How many PDBs were looked for, and how many found.
    pub fn loaded(&self) -> (usize, usize) {
        let t = self.tables();
        (
            t.len(),
            t.values()
                .filter(|v| v.get().is_some_and(Option::is_some))
                .count(),
        )
    }
}

impl Symbolizer for PdbSymbolizer {
    fn function(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(u64, String)> {
        let table = self.table(trace, image)?;
        let (start, name) = table.function(u32::try_from(offset).ok()?)?;
        Some((u64::from(start), name.to_string()))
    }

    fn inlines(&self, trace: &Trace, image: ImageIx, offset: u64) -> Vec<(u32, String)> {
        let (Some(table), Ok(rva)) = (self.table(trace, image), u32::try_from(offset)) else {
            return Vec::new();
        };
        table
            .inlines(rva)
            .into_iter()
            .map(|(site, name)| (site, name.to_string()))
            .collect()
    }

    fn inline_name(&self, trace: &Trace, image: ImageIx, site: u32) -> Option<String> {
        self.table(trace, image)?
            .site_name(site)
            .map(str::to_string)
    }

    fn line(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(String, u32)> {
        let table = self.table(trace, image)?;
        let (file, line) = table.line(u32::try_from(offset).ok()?)?;
        Some((file.to_string(), line))
    }
}

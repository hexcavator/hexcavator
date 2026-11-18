//! A [`Symbolizer`] from PDBs found on this machine.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

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
    tables: RwLock<FxHashMap<DebugKey, Slot>>,
    /// Whether lookups wait for a PDB to load (else they use only those
    /// loaded already: see [`PdbSymbolizer::set_waiting`]).
    waiting: AtomicBool,
    /// By image: what lookups found, so that later lookups take no lock
    /// (a tree's threads look up millions of frames at once).
    by_image: OnceLock<Vec<ImageCache>>,
    /// Bumped whenever a PDB is loaded, seeded or forgotten: an image
    /// found missing at an older generation is looked for again.
    generation: AtomicU64,
}

/// What lookups found for an image.
#[derive(Default)]
struct ImageCache {
    /// Its table, once found, with its PDB's identity (checked on each
    /// use). A table found stays found.
    found: OnceLock<(DebugKey, Arc<FunctionTable>)>,
    /// The generation (plus one) at which it was found missing; 0 if not.
    missing_at: AtomicU64,
}

/// A PDB's slot in a [`PdbSymbolizer`].
type Slot = Arc<OnceLock<Option<Arc<FunctionTable>>>>;

impl PdbSymbolizer {
    /// A symbolizer that searches `path` (and each image's recorded PDB
    /// path).
    pub fn new(path: SymbolPath) -> Self {
        Self {
            path,
            tables: RwLock::new(FxHashMap::default()),
            waiting: AtomicBool::new(true),
            by_image: OnceLock::new(),
            generation: AtomicU64::new(0),
        }
    }

    /// The function table of `image`'s PDB, if found.
    pub fn table(&self, trace: &Trace, image: ImageIx) -> Option<Arc<FunctionTable>> {
        let id = trace.images[image.index()].debug_id.as_ref()?;
        if self.waiting.load(Ordering::Relaxed) {
            return self.load(&id.pdb_path, &id.guid, id.age);
        }
        self.tables().get(&(id.guid, id.age))?.get()?.clone()
    }

    /// `f` of the function table of `image`'s PDB, if found: as
    /// [`Self::table`], but a PDB loaded already is only borrowed (lookups
    /// on many threads at once share nothing they write).
    fn with_table<R>(
        &self,
        trace: &Trace,
        image: ImageIx,
        f: impl FnOnce(&FunctionTable) -> R,
    ) -> Option<R> {
        let id = trace.images[image.index()].debug_id.as_ref()?;
        let key = (id.guid, id.age);
        let cache = self.by_image.get_or_init(|| {
            (0..trace.images.len())
                .map(|_| ImageCache::default())
                .collect()
        });
        let cached = cache.get(image.index());
        if let Some((k, table)) = cached.and_then(|c| c.found.get())
            && *k == key
        {
            return Some(f(table));
        }
        // Missing, and nothing loaded since: still missing.
        let generation = self.generation.load(Ordering::Acquire);
        if cached.is_some_and(|c| c.missing_at.load(Ordering::Relaxed) == generation + 1) {
            return None;
        }
        let missing = || {
            if let Some(c) = cached {
                c.missing_at.store(generation + 1, Ordering::Relaxed);
            }
            None
        };
        let found = {
            let tables = self.tables();
            match tables.get(&key).and_then(|slot| slot.get()) {
                // (Looked for already: found, or not.)
                Some(Some(t)) => Some(Arc::clone(t)),
                Some(None) => return missing(),
                // Not yet: without waiting, perhaps later (after a
                // download).
                None if !self.waiting.load(Ordering::Relaxed) => return missing(),
                None => None,
            }
        };
        let table = match found {
            Some(t) => t,
            None => match self.load(&id.pdb_path, &id.guid, id.age) {
                Some(t) => t,
                None => return missing(),
            },
        };
        if let Some(c) = cached {
            let _ = c.found.set((key, Arc::clone(&table)));
        }
        Some(f(&table))
    }

    /// Whether lookups wait for a PDB to load (they do, at first). Without
    /// waiting, a lookup uses only the PDBs loaded already ([`Self::load`]
    /// loads them, as a background preload does), so that a query answers
    /// at once and a later one has the names.
    pub fn set_waiting(&self, waiting: bool) {
        self.waiting.store(waiting, Ordering::Relaxed);
        // (What wasn't loaded yet is worth waiting for now.)
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// How many PDBs are loaded and found.
    pub fn loaded_count(&self) -> usize {
        self.tables()
            .values()
            .filter(|v| v.get().is_some_and(Option::is_some))
            .count()
    }

    /// The function table of the PDB recorded at `pdb_path` with `guid`
    /// and `age`, if found: loaded the first time it is asked for (by one
    /// thread; others asking meanwhile wait for it, and others' other
    /// PDBs load at once).
    pub fn load(&self, pdb_path: &str, guid: &[u8; 16], age: u32) -> Option<Arc<FunctionTable>> {
        let slot: Slot = Arc::clone(self.tables_mut().entry((*guid, age)).or_default());
        slot.get_or_init(|| {
            let t = self
                .path
                .find_pdb(pdb_path, guid, age)
                // (Perhaps the path the trace records: see `open_named`.)
                .and_then(|p| hexcavator_mmap::Mmap::open_named(p).ok())
                .and_then(|map| FunctionTable::from_pdb(&map).ok())
                .map(Arc::new);
            if t.is_some() {
                self.generation.fetch_add(1, Ordering::Release);
            }
            t
        })
        .clone()
    }

    /// Gives the PDB with `guid` and `age` the table `table` (one saved
    /// for this trace: see [`FunctionTable::subset`]) instead of loading
    /// it. A PDB loaded or seeded already keeps what it has.
    pub fn seed(&self, guid: &[u8; 16], age: u32, table: Arc<FunctionTable>) {
        let slot: Slot = Arc::clone(self.tables_mut().entry((*guid, age)).or_default());
        if slot.set(Some(table)).is_ok() {
            self.generation.fetch_add(1, Ordering::Release);
        }
    }

    /// The PDBs loaded (or seeded) and found: each one's GUID, age and
    /// table, in GUID order.
    pub fn found(&self) -> Vec<([u8; 16], u32, Arc<FunctionTable>)> {
        let mut out: Vec<_> = self
            .tables()
            .iter()
            .filter_map(|(&(guid, age), slot)| Some((guid, age, Arc::clone(slot.get()?.as_ref()?))))
            .collect();
        out.sort_by_key(|a| (a.0, a.1));
        out
    }

    /// The PDBs, to read: a lookup's (many threads at once).
    fn tables(&self) -> std::sync::RwLockReadGuard<'_, FxHashMap<DebugKey, Slot>> {
        self.tables.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The PDBs, to add or remove one.
    fn tables_mut(&self) -> std::sync::RwLockWriteGuard<'_, FxHashMap<DebugKey, Slot>> {
        self.tables.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets the PDBs that weren't found, so that they are looked for
    /// again (after a download).
    pub fn forget_missing(&self) {
        self.tables_mut()
            .retain(|_, t| t.get().is_none_or(Option::is_some));
        self.generation.fetch_add(1, Ordering::Release);
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
        let rva = u32::try_from(offset).ok()?;
        self.with_table(trace, image, |t| {
            t.function(rva)
                .map(|(start, name)| (u64::from(start), name.to_string()))
        })?
    }

    fn function_start(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<u64> {
        let rva = u32::try_from(offset).ok()?;
        self.with_table(trace, image, |t| {
            t.function(rva).map(|(start, _)| u64::from(start))
        })?
    }

    fn inline_sites(&self, trace: &Trace, image: ImageIx, offset: u64) -> Vec<u32> {
        let Ok(rva) = u32::try_from(offset) else {
            return Vec::new();
        };
        self.with_table(trace, image, |t| {
            t.inlines(rva).into_iter().map(|(site, _)| site).collect()
        })
        .unwrap_or_default()
    }

    fn inlines(&self, trace: &Trace, image: ImageIx, offset: u64) -> Vec<(u32, String)> {
        let Ok(rva) = u32::try_from(offset) else {
            return Vec::new();
        };
        self.with_table(trace, image, |t| {
            t.inlines(rva)
                .into_iter()
                .map(|(site, name)| (site, name.to_string()))
                .collect()
        })
        .unwrap_or_default()
    }

    fn inline_name(&self, trace: &Trace, image: ImageIx, site: u32) -> Option<String> {
        self.with_table(trace, image, |t| t.site_name(site).map(str::to_string))?
    }

    fn line(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(String, u32)> {
        let rva = u32::try_from(offset).ok()?;
        self.with_table(trace, image, |t| {
            t.line(rva).map(|(file, line)| (file.to_string(), line))
        })?
    }
}

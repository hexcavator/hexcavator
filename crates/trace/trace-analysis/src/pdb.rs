//! A [`Symbolizer`] from PDBs found on this machine.

use std::cell::RefCell;
use std::rc::Rc;

use rustc_hash::FxHashMap;

use hexcavator_symbolize::{FunctionTable, SymbolPath};
use hexcavator_trace::{ImageIx, Trace};

use crate::keys::Symbolizer;

/// A PDB's identity: GUID and age.
type DebugKey = ([u8; 16], u32);

/// Finds functions in the PDBs of a trace's images, loading each PDB the
/// first time one of its addresses is asked about. Images without a debug
/// identity, or whose PDB isn't found, have no functions.
pub struct PdbSymbolizer {
    path: SymbolPath,
    /// By (GUID, age): the same DLL is loaded in many processes.
    tables: RefCell<FxHashMap<DebugKey, Option<Rc<FunctionTable>>>>,
}

impl PdbSymbolizer {
    /// A symbolizer that searches `path` (and each image's recorded PDB
    /// path).
    pub fn new(path: SymbolPath) -> Self {
        Self {
            path,
            tables: RefCell::new(FxHashMap::default()),
        }
    }

    /// The function table of `image`'s PDB, if found.
    pub fn table(&self, trace: &Trace, image: ImageIx) -> Option<Rc<FunctionTable>> {
        let id = trace.images[image.index()].debug_id.as_ref()?;
        let key = (id.guid, id.age);
        if let Some(t) = self.tables.borrow().get(&key) {
            return t.clone();
        }
        let table = self
            .path
            .find_pdb(&id.pdb_path, &id.guid, id.age)
            // (Perhaps the path the trace records: see `open_named`.)
            .and_then(|p| hexcavator_mmap::Mmap::open_named(p).ok())
            .and_then(|map| FunctionTable::from_pdb(&map).ok())
            .map(Rc::new);
        self.tables.borrow_mut().insert(key, table.clone());
        table
    }

    /// How many PDBs were looked for, and how many found.
    pub fn loaded(&self) -> (usize, usize) {
        let t = self.tables.borrow();
        (t.len(), t.values().filter(|v| v.is_some()).count())
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

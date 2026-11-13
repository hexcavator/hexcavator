//! A program, loaded once for every analysis and every front end (the
//! command line, the MCP server, the editor): its image (PE, ELF, Mach-O,
//! or WebAssembly), the debug information that matches it (a PDB found as
//! the linker recorded it or beside it; DWARF in the image itself, or in a
//! separate file its build ID, debug link, or UUID names), and, built when
//! first asked for and kept, its model of sections, groups, and
//! compilands, and its symbols (and kept, see [`cache`]).
//!
//! ```no_run
//! # fn f(path: &std::path::Path) -> Result<(), hexcavator_program::Error> {
//! let opened = hexcavator_program::Opened::open(path, None)?;
//! let program = opened.program()?;
//! let symbols = program.symbols()?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Opened`] owns the files (memory-mapped); a [`Program`] borrows them.

#![warn(missing_docs)]

pub mod cache;
pub mod data;
mod error;
pub mod server;
pub mod variables;

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use error::Error;
use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_mmap::Mmap;
use hexcavator_size::symbols::{self, Symbol};
use hexcavator_size::{Model, model};

/// The debug information for the image at `image_path`: `given`, if one
/// is; else the image itself, if it has DWARF of its own; else the first
/// file of those the image's debug identities name, beside it or in the
/// symbol directories (see `hexcavator_debuginfo::candidate_paths_in` and
/// `symbol_dirs`), that matches it; and its path.
pub fn find_debug(
    image_path: &Path,
    image: &Image<'_>,
    given: Option<&Path>,
) -> Result<(PathBuf, Mmap), Error> {
    if let Some(p) = given {
        let map = Mmap::open(p).map_err(Error::io(p))?;
        return Ok((p.to_path_buf(), map));
    }
    if image.pe().is_none() && DebugInfo::parse(image.data()).is_ok() {
        let map = Mmap::open(image_path).map_err(Error::io(image_path))?;
        return Ok((image_path.to_path_buf(), map));
    }
    let ids = image.debug_ids();
    let servers = server::servers();
    let mut dirs = hexcavator_debuginfo::symbol_dirs();
    // (What was fetched before is in the symbol cache.)
    if let Some(c) = &servers.cache
        && !dirs.contains(c)
    {
        dirs.push(c.clone());
    }
    let mut tried = Vec::new();
    for id in &ids {
        for candidate in hexcavator_debuginfo::candidate_paths_in(image_path, id, &dirs) {
            let Ok(map) = Mmap::open_named(&candidate) else {
                tried.push(format!("{} (not found)", candidate.display()));
                continue;
            };
            match DebugInfo::parse(&map) {
                Ok(d) if d.matches(id) => return Ok((candidate, map)),
                Ok(_) => tried.push(format!("{} (does not match)", candidate.display())),
                Err(e) => tried.push(format!("{} ({e})", candidate.display())),
            }
        }
    }
    // Then the symbol servers, if any are given.
    for id in &ids {
        for (url, cached) in server::locations(&servers, id) {
            let Some(map) = server::fetch(&url, cached.as_deref()) else {
                tried.push(format!("{url} (not there)"));
                continue;
            };
            let found = cached.unwrap_or_else(|| PathBuf::from(&url));
            match DebugInfo::parse(&map) {
                Ok(d) if d.matches(id) => return Ok((found, map)),
                Ok(_) => tried.push(format!("{url} (does not match)")),
                Err(e) => tried.push(format!("{url} ({e})")),
            }
        }
    }
    // (PE images name PDBs; the others' debug information is DWARF.)
    let what = if image.pe().is_some() {
        "PDB"
    } else {
        "debug information"
    };
    // (An image that names nothing has nothing tried.)
    if ids.is_empty() {
        tried.clear();
    }
    // Places with nothing there, past the first few, are counted.
    const SHOWN: usize = 6;
    let missing = tried.iter().filter(|t| t.ends_with("(not found)")).count();
    if missing > SHOWN {
        let mut kept = 0;
        tried.retain(|t| {
            if !t.ends_with("(not found)") {
                return true;
            }
            kept += 1;
            kept <= SHOWN
        });
        tried.push(format!("{} more places (not found)", missing - SHOWN));
    }
    Err(Error::NoDebug {
        path: image_path.to_path_buf(),
        what,
        tried,
    })
}

/// The split DWARF files the debug information at `debug_path` (of the
/// image at `image_path`) names, opened: its `.dwp` package if there is
/// one, else each `.dwo` file found (see
/// [`hexcavator_debuginfo::dwarf_backend::split_paths`]). Those not found are left
/// out: their compilands are then their skeletons alone.
pub fn open_splits(
    image_path: &Path,
    debug_path: &Path,
    debug: &DebugInfo<'_>,
) -> Vec<(PathBuf, Mmap)> {
    use hexcavator_debuginfo::dwarf_backend as dwarf;
    let Some(d) = debug.dwarf() else {
        return Vec::new();
    };
    let files = d.split_files();
    if files.is_empty() {
        return Vec::new();
    }
    for p in dwarf::package_paths(image_path, debug_path) {
        if let Ok(map) = Mmap::open_named(&p) {
            return vec![(p, map)];
        }
    }
    let mut out: Vec<(PathBuf, Mmap)> = Vec::new();
    for f in &files {
        for p in dwarf::split_paths(image_path, debug_path, f) {
            if out.iter().any(|(q, _)| *q == p) {
                break;
            }
            if let Ok(map) = Mmap::open_named(&p) {
                out.push((p, map));
                break;
            }
        }
    }
    out
}

/// Adds split DWARF files (from [`open_splits`]) to `debug`. Files that
/// aren't split DWARF are left out.
pub fn add_splits<'d>(debug: &mut DebugInfo<'d>, splits: &'d [(PathBuf, Mmap)]) {
    if let Some(d) = debug.dwarf_mut() {
        for (_, map) in splits {
            let _ = d.add_split(map);
        }
    }
}

/// An object file of a Mach-O image's debug map, opened.
struct MapObject {
    /// The file (the archive, for a member of one).
    path: PathBuf,
    map: Mmap,
    /// The member's place in the archive (start, end), the archive's
    /// path, and the member's name, for a member of one.
    member: Option<(usize, usize, String, String)>,
    /// Its entry of the debug map.
    entry: usize,
}

impl MapObject {
    fn data(&self) -> &[u8] {
        match &self.member {
            Some((start, end, ..)) => self.map.get(*start..*end).unwrap_or_default(),
            None => &self.map,
        }
    }
}

/// Where the debug map's object path `oso` may be, in order: a relative
/// path from the image's directory (the linker's, often), then as written
/// (from the current directory), then by its name beside the image. A
/// member of an archive (`lib.a(member.o)`) is the archive's path and the
/// member's name.
pub fn debug_map_paths(image_path: &Path, oso: &[u8]) -> (Vec<PathBuf>, Option<String>) {
    // (As bytes: a path needn't be UTF-8, and on Unix is opened as it is.)
    let (file, member) = match oso.strip_suffix(b")").and_then(|t| {
        let i = t.iter().position(|&b| b == b'(')?;
        Some((&t[..i], &t[i + 1..]))
    }) {
        Some((archive, member)) if !archive.is_empty() => {
            (archive, Some(String::from_utf8_lossy(member).into_owned()))
        }
        _ => (oso, None),
    };
    let dir = image_path.parent().unwrap_or(Path::new(""));
    let written = path_of_bytes(file);
    let mut out = Vec::new();
    if written.is_relative() {
        out.push(dir.join(&written));
    }
    out.push(written);
    if let Some(name) = file
        .rsplit(|&b| b == b'\\' || b == b'/')
        .next()
        .filter(|n| !n.is_empty())
    {
        out.push(dir.join(path_of_bytes(name)));
    }
    out.dedup();
    (out, member)
}

/// A path a file records, from its bytes: on Unix as they are; elsewhere
/// (Windows' paths are UTF-16) read as UTF-8.
fn path_of_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Opens the object files `image`'s debug map names (those found).
fn open_debug_map(image_path: &Path, image: &Image<'_>) -> Vec<MapObject> {
    let Some(macho) = image.macho() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (entry, o) in macho.debug_map().iter().enumerate() {
        if o.symbols.is_empty() {
            continue;
        }
        let (paths, member) = debug_map_paths(image_path, o.path);
        for p in paths {
            let Ok(map) = Mmap::open_named(&p) else {
                continue;
            };
            let place = match &member {
                None => None,
                Some(name) => {
                    let Some(place) = member_place(&map, name) else {
                        continue;
                    };
                    Some((place.0, place.1, p.display().to_string(), name.clone()))
                }
            };
            out.push(MapObject {
                path: p,
                map,
                member: place,
                entry,
            });
            break;
        }
    }
    out
}

/// Where the archive `data`'s member `name` is in it (start, end).
fn member_place(data: &[u8], name: &str) -> Option<(usize, usize)> {
    let archive = hexcavator_archive::Archive::parse(data).ok()?;
    let m = archive.files().find(|m| &*m.name == name.as_bytes())?;
    let start = usize::try_from(m.data_offset).ok()?;
    Some((start, start.checked_add(m.data.len())?))
}

/// An image and its debug information, opened (memory-mapped).
pub struct Opened {
    path: PathBuf,
    data: Mmap,
    debug_path: PathBuf,
    debug: Mmap,
    /// Split DWARF files.
    splits: Vec<(PathBuf, Mmap)>,
    /// The object files of a Mach-O image's debug map, when its DWARF is
    /// read from them (no dSYM found).
    objects: Vec<MapObject>,
}

impl Opened {
    /// Opens the image at `path` and finds its debug information (`debug`,
    /// if given).
    ///
    /// # Errors
    ///
    /// If a file can't be read, the image isn't one, or no debug
    /// information for it is found.
    pub fn open(path: &Path, debug: Option<&Path>) -> Result<Self, Error> {
        let data = Mmap::open(path).map_err(Error::io(path))?;
        let image = Image::parse(&data).map_err(Error::format(path))?;
        let given = debug.is_some();
        let (debug_path, debug) = match find_debug(path, &image, debug) {
            Ok(found) => found,
            // A Mach-O image without a dSYM: the DWARF of the objects its
            // debug map names, if any are found.
            Err(e @ Error::NoDebug { .. }) if !given => {
                let objects = open_debug_map(path, &image);
                if objects.is_empty() {
                    return Err(e);
                }
                let again = Mmap::open(path).map_err(Error::io(path))?;
                return Ok(Self {
                    path: path.to_path_buf(),
                    data,
                    debug_path: path.to_path_buf(),
                    debug: again,
                    splits: Vec::new(),
                    objects,
                });
            }
            Err(e) => return Err(e),
        };
        let splits = DebugInfo::parse(&debug)
            .map(|d| open_splits(path, &debug_path, &d))
            .unwrap_or_default();
        Ok(Self {
            path: path.to_path_buf(),
            data,
            debug_path,
            debug,
            splits,
            objects: Vec::new(),
        })
    }

    /// The debug information read from the objects of the image's debug
    /// map (see [`Opened::open`]).
    fn debug_map_info(&self, image: &Image<'_>) -> Result<DebugInfo<'_>, Error> {
        use hexcavator_debuginfo::dwarf_backend::DwarfInfo;
        let image_data = match hexcavator_macho::preferred_slice(&self.debug) {
            Some((_, slice)) => slice,
            None => &self.debug[..],
        };
        let mut d = DwarfInfo::from_debug_map(image_data).map_err(Error::format(&self.path))?;
        let map = image
            .macho()
            .map(hexcavator_macho::MachO::debug_map)
            .unwrap_or_default();
        for o in &self.objects {
            let Some(entry) = map.get(o.entry) else {
                continue;
            };
            let library = o.member.as_ref().map_or("", |m| m.2.as_str());
            // (An object without DWARF, or not one: left out.)
            let _ = d.add_object(o.data(), &entry.symbols, library);
        }
        Ok(DebugInfo::Dwarf(Box::new(d)))
    }

    /// The program: the image and its debug information parsed, checked to
    /// go together.
    ///
    /// # Errors
    ///
    /// If the debug information can't be read, or doesn't go with the
    /// image (or the image can't be analyzed).
    pub fn program(&self) -> Result<Program<'_>, Error> {
        let image = Image::parse(&self.data).map_err(Error::format(&self.path))?;
        let debug = self.debug_info_of(&image)?;
        model::check(&image, &debug).map_err(|why| Error::Unsupported {
            path: self.path.clone(),
            why,
        })?;
        Ok(Program {
            path: &self.path,
            debug_path: &self.debug_path,
            split_paths: self.split_paths().collect(),
            image,
            debug,
            model: OnceCell::new(),
            symbols: OnceCell::new(),
        })
    }

    /// The debug information, parsed (with its split DWARF files, or the
    /// objects of its debug map), not checked against the image.
    ///
    /// # Errors
    ///
    /// If the image or the debug information can't be read.
    pub fn debug_info(&self) -> Result<DebugInfo<'_>, Error> {
        let image = Image::parse(&self.data).map_err(Error::format(&self.path))?;
        self.debug_info_of(&image)
    }

    fn debug_info_of(&self, image: &Image<'_>) -> Result<DebugInfo<'_>, Error> {
        let mut debug = if self.objects.is_empty() {
            DebugInfo::parse(&self.debug).map_err(Error::format(&self.debug_path))?
        } else {
            self.debug_map_info(image)?
        };
        add_splits(&mut debug, &self.splits);
        Ok(debug)
    }

    /// Whether the debug information is read from the objects of a Mach-O
    /// image's debug map (it has no dSYM).
    pub fn is_debug_map(&self) -> bool {
        !self.objects.is_empty()
    }

    /// The bytes of each object file of the debug map (see
    /// [`Opened::is_debug_map`]).
    pub fn debug_map_objects(&self) -> impl Iterator<Item = &[u8]> {
        self.objects.iter().map(MapObject::data)
    }

    /// Each object file of the debug map: its name (`lib.a(member.o)` for
    /// an archive's member) and its bytes.
    pub fn debug_map_files(&self) -> impl Iterator<Item = (String, &[u8])> {
        self.objects.iter().map(|o| {
            let name = match &o.member {
                Some((_, _, archive, member)) => format!("{archive}({member})"),
                None => o.path.display().to_string(),
            };
            (name, o.data())
        })
    }

    /// The image's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The debug information's path (the image's, if it holds its own).
    pub fn debug_path(&self) -> &Path {
        &self.debug_path
    }

    /// The split DWARF files found (a `.dwp`, or `.dwo` files), or the
    /// object files (and archives) of a Mach-O image's debug map.
    pub fn split_paths(&self) -> impl Iterator<Item = &Path> {
        let mut objects: Vec<&Path> = Vec::new();
        for o in &self.objects {
            if !objects.contains(&o.path.as_path()) {
                objects.push(&o.path);
            }
        }
        self.splits.iter().map(|(p, _)| p.as_path()).chain(objects)
    }

    /// The image's bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A loaded program: its image and debug information, and what is built
/// from them on first use.
pub struct Program<'a> {
    /// The image's path.
    pub path: &'a Path,
    /// The debug information's path.
    pub debug_path: &'a Path,
    /// The split DWARF files read with it.
    pub split_paths: Vec<&'a Path>,
    /// The image, parsed.
    pub image: Image<'a>,
    /// Its debug information, parsed.
    pub debug: DebugInfo<'a>,
    model: OnceCell<Arc<Model>>,
    symbols: OnceCell<Arc<Vec<Symbol>>>,
}

impl Program<'_> {
    /// Its debug files' paths.
    fn debug_files(&self) -> Vec<&Path> {
        let mut debug = vec![self.debug_path];
        debug.extend(&self.split_paths);
        debug
    }

    /// The paths of the files it is read from: its image, then its debug
    /// files (as [`cache::remember`] takes them).
    pub fn files(&self) -> Vec<&Path> {
        let mut all = vec![self.path];
        all.extend(self.debug_files());
        all
    }

    /// Its model: sections, groups, compilands, libraries, contributions.
    ///
    /// # Errors
    ///
    /// If the debug information is damaged.
    pub fn model(&self) -> Result<&Model, Error> {
        if let Some(m) = self.model.get() {
            return Ok(m);
        }
        let build =
            || model::model(&self.image, &self.debug).map_err(Error::format(self.debug_path));
        let m = cache::remember(&self.files(), "model", build)?;
        Ok(self.model.get_or_init(|| m))
    }

    /// Its symbols: kept (see [`cache`]), or built.
    ///
    /// # Errors
    ///
    /// If the debug information is damaged.
    pub fn symbols(&self) -> Result<&[Symbol], Error> {
        if let Some(s) = self.symbols.get() {
            return Ok(s);
        }
        let model = self.model()?;
        let build = || {
            cache::indexed(self.path, &self.debug_files(), || {
                symbols::build(&self.image, &self.debug, model)
                    .map_err(Error::format(self.debug_path))
            })
        };
        // (The model is built first: building symbols must not wait for it
        // while holding their place.)
        let s = cache::remember(&self.files(), "symbols", build)?;
        Ok(self.symbols.get_or_init(|| s))
    }

    /// Its model and symbols, built if they aren't, shared (for callers
    /// that keep them past the program).
    ///
    /// # Errors
    ///
    /// If the debug information is damaged.
    pub fn into_built(self) -> Result<(Arc<Model>, Arc<Vec<Symbol>>), Error> {
        self.symbols()?;
        // (Both are built now.)
        let model = self.model.into_inner().unwrap_or_default();
        let symbols = self.symbols.into_inner().unwrap_or_default();
        Ok((model, symbols))
    }
}

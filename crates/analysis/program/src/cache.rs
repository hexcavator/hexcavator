//! What is built from a program's files (its model, its symbols, a size
//! report's maps), kept so that it needn't be built again. Neither keeping
//! is on unless asked for:
//!
//! - In memory ([`keep_in_memory`], [`remember`]), for a process that
//!   answers many requests (`hexc serve`): what is built from the same
//!   files again is what was built the first time, until they change.
//! - In an index file ([`set_file`], `hexc --cache <path>`): the symbols,
//!   in `path` if it is a file, or in `path/{name}.{hash}.hexc-index` if it
//!   is a directory (`hash` of the image's full path, so that images of the
//!   same name don't share one).
//!
//! Either is used only while what it was built from is unchanged: the same
//! Hexcavator, and the files of the same sizes and modification times.

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use hexcavator_size::index::{Key, decode, encode};
use hexcavator_size::symbols::Symbol;

/// Where index files go, if anywhere.
static FILE: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Whether what is built is kept in memory.
static MEMORY: AtomicBool = AtomicBool::new(false);

/// How many things are kept in memory (a program's model, its symbols,
/// each set of maps): the least recently used goes first.
const KEPT_MAX: usize = 32;

/// What is kept in memory, the most recently used last.
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

/// A thing kept in memory.
struct Kept {
    /// What it is, and of which files (their full paths).
    what: Vec<u8>,
    /// The files' identities, and Hexcavator's, when it was built.
    key: Key,
    /// It, once built. (Locked while it is built: another request for it
    /// waits for that build.)
    value: Arc<Mutex<Option<Arc<dyn Any + Send + Sync>>>>,
}

/// Saves symbols in index files at `path` (see the module), or (`None`)
/// nowhere. For this process.
pub fn set_file(path: Option<PathBuf>) {
    *FILE.write().unwrap_or_else(PoisonError::into_inner) = path;
}

/// Keeps what is built in memory (see the module), or not. For this
/// process. Turning it off forgets what was kept.
pub fn keep_in_memory(on: bool) {
    MEMORY.store(on, Ordering::Relaxed);
    if !on {
        lock(&KEPT).clear();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A build that panicked leaves nothing half-kept: only its result is.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What is built from `files` (an image first, then its debug files) by
/// this Hexcavator depends on: their sizes and modification times.
fn key(files: &[&Path]) -> Option<Key> {
    let mut key = Key::default();
    key.bytes(env!("CARGO_PKG_VERSION").as_bytes());
    // (A universal file's image is the architecture chosen.)
    key.bytes(&hexcavator_macho::preferred_arch_key().to_le_bytes());
    // The executable itself: a rebuilt Hexcavator may build differently.
    key.file(&std::fs::metadata(std::env::current_exe().ok()?).ok()?);
    for f in files {
        key.file(&std::fs::metadata(f).ok()?);
    }
    Some(key)
}

/// `what` (a name for the thing, and anything else it is built from) of
/// `files`, by their full paths.
fn identity(files: &[&Path], what: &str) -> Option<Vec<u8>> {
    let mut id = Key::default();
    id.bytes(what.as_bytes());
    id.bytes(&hexcavator_macho::preferred_arch_key().to_le_bytes());
    for f in files {
        let full = std::fs::canonicalize(f).ok()?;
        id.bytes(full.as_os_str().as_encoded_bytes());
    }
    Some(id.0)
}

/// `what` built from `files` (an image first, then its debug files): the
/// one kept in memory, if what is built is kept (see [`keep_in_memory`])
/// and the files are unchanged; else `build`'s (then kept, if things are).
/// Two requests for the same thing at once wait for one build.
///
/// `what` names the thing, with anything else it depends on (a size
/// report's sources, say); `T` is part of it, too.
///
/// # Errors
///
/// `build`'s.
pub fn remember<T: Send + Sync + 'static, E>(
    files: &[&Path],
    what: &str,
    build: impl FnOnce() -> Result<T, E>,
) -> Result<Arc<T>, E> {
    if !MEMORY.load(Ordering::Relaxed) {
        return build().map(Arc::new);
    }
    let what = format!("{what}\0{}", std::any::type_name::<T>());
    let (Some(id), Some(key)) = (identity(files, &what), key(files)) else {
        return build().map(Arc::new);
    };
    let slot = {
        let mut all = lock(&KEPT);
        let found = all.iter().position(|k| k.what == id);
        let mut kept = match found {
            Some(i) => all.remove(i),
            None => Kept {
                what: id,
                key: key.clone(),
                value: Arc::default(),
            },
        };
        if kept.key != key {
            // Built from other files: built again.
            kept.key = key;
            kept.value = Arc::default();
        }
        let slot = Arc::clone(&kept.value);
        all.push(kept);
        if all.len() > KEPT_MAX {
            all.remove(0);
        }
        slot
    };
    let mut value = lock(&slot);
    if let Some(v) = value.as_ref()
        && let Ok(t) = Arc::clone(v).downcast::<T>()
    {
        return Ok(t);
    }
    let t = Arc::new(build()?);
    *value = Some(Arc::clone(&t) as Arc<dyn Any + Send + Sync>);
    Ok(t)
}

/// The index file for `image`, if index files are on (see the module).
pub fn index_path(image: &Path) -> Option<PathBuf> {
    let at = FILE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()?;
    if !at.is_dir() {
        return Some(at);
    }
    let full = std::fs::canonicalize(image).unwrap_or_else(|_| image.to_path_buf());
    let mut h = rustc_hash::FxHasher::default();
    std::hash::Hasher::write(&mut h, full.as_os_str().as_encoded_bytes());
    let name = image
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    Some(at.join(format!(
        "{name}.{:016x}.hexc-index",
        std::hash::Hasher::finish(&h)
    )))
}

/// The symbols of `image` (with debug files `debug`): from its index file
/// if index files are on and it is current, else from `build` (then saved,
/// if index files are on).
///
/// # Errors
///
/// `build`'s.
pub fn indexed<E>(
    image: &Path,
    debug: &[&Path],
    build: impl FnOnce() -> Result<Vec<Symbol>, E>,
) -> Result<Vec<Symbol>, E> {
    let Some(path) = index_path(image) else {
        return build();
    };
    let mut files = vec![image];
    files.extend(debug);
    let Some(key) = key(&files) else {
        return build();
    };
    if let Ok(data) = std::fs::read(&path)
        && let Some(syms) = decode(&data, &key)
    {
        return Ok(syms);
    }
    let syms = build()?;
    // An index that can't be saved costs only time next run.
    let _ = write_atomically(&path, &encode(&key, &syms));
    Ok(syms)
}

/// Writes `data` to a temporary file beside `path`, then renames it into
/// place, so that a reader never sees half an index.
fn write_atomically(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // (Unique to the writer: one process may write it from two threads.)
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = WRITES.fetch_add(1, Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.{n}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

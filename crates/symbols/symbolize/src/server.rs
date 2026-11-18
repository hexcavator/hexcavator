//! Downloading PDBs from symbol servers into a symbol cache, many at once.
//!
//! The cache has the layout WinDbg's (and `symstore`'s) has,
//! `name.pdb/<GUID><age>/name.pdb`, so WinDbg and Stackrabbit can share
//! one, and [`crate::SymbolPath`] finds what is downloaded there (when the
//! cache is one of its directories). Servers are asked by the same key
//! (Microsoft's layout, which `msdl.microsoft.com`, `symstore` shares over
//! HTTP and .NET's symbol servers serve).
//!
//! Files are fetched with the system's `curl` (on Windows 10 and later,
//! macOS and Linux), limited in size and time, written beside their place
//! and renamed into it when complete, and kept only if they are the PDB
//! asked for: what a server sends is hostile like any input. Many fetches
//! run at once ([`SymbolServers::fetch_all`]), so that a fast connection
//! is kept busy.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{matches, symbol_store_key};

/// The largest file fetched.
const MAX_FILE: u64 = 4 << 30;
/// The longest a fetch may take, in seconds.
const MAX_SECONDS: u32 = 900;
/// Microsoft's public symbol server.
pub const MICROSOFT: &str = "https://msdl.microsoft.com/download/symbols";

/// A PDB to find: its file name and identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PdbId {
    /// Its file name (`app.pdb`), or the path the image records.
    pub name: String,
    /// Its GUID.
    pub guid: [u8; 16],
    /// Its age.
    pub age: u32,
}

/// What became of a fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// It was in the cache already.
    Cached(PathBuf),
    /// It was downloaded into the cache.
    Downloaded(PathBuf),
    /// No server has it (or what came wasn't it).
    Missing,
    /// Its name can't be used in a path or URL.
    BadName,
}

impl Fetched {
    /// The PDB's path, if it is in the cache now.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Cached(p) | Self::Downloaded(p) => Some(p),
            Self::Missing | Self::BadName => None,
        }
    }
}

/// Symbol servers and the cache they download into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolServers {
    /// The cache.
    pub cache: PathBuf,
    /// The servers, asked in order.
    pub urls: Vec<String>,
}

impl SymbolServers {
    /// The servers and cache of a symbol path's `srv*cache*url...`
    /// entries (the first entry's cache; every entry's URLs); `None` if it
    /// has none with both.
    pub fn from_nt_symbol_path(path: &str) -> Option<Self> {
        let mut cache = None;
        let mut urls = Vec::new();
        for entry in path.split(';') {
            let parts: Vec<&str> = entry.split('*').map(str::trim).collect();
            if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("srv") {
                continue;
            }
            for p in &parts[1..] {
                if p.starts_with("https://") || p.starts_with("http://") {
                    urls.push(p.trim_end_matches('/').to_string());
                } else if cache.is_none() && !p.is_empty() {
                    cache = Some(PathBuf::from(p));
                }
            }
        }
        Some(Self {
            cache: cache?,
            urls: (!urls.is_empty()).then_some(urls)?,
        })
    }

    /// Where the cache keeps `id`, if its name is usable.
    pub fn cached_path(&self, id: &PdbId) -> Option<PathBuf> {
        let name = file_name(&id.name)?;
        Some(
            self.cache
                .join(&name)
                .join(symbol_store_key(&id.guid, id.age))
                .join(&name),
        )
    }

    /// `id` in the cache: there already, or downloaded from the first
    /// server that has it.
    pub fn fetch(&self, id: &PdbId) -> Fetched {
        let Some(name) = file_name(&id.name) else {
            return Fetched::BadName;
        };
        let Some(path) = self.cached_path(id) else {
            return Fetched::BadName;
        };
        if matches(&path, &id.guid, id.age) {
            return Fetched::Cached(path);
        }
        let key = format!("{name}/{}/{name}", symbol_store_key(&id.guid, id.age));
        for url in &self.urls {
            if download(&format!("{url}/{key}"), &path) {
                if matches(&path, &id.guid, id.age) {
                    return Fetched::Downloaded(path);
                }
                // Not what was asked for: not kept.
                let _ = std::fs::remove_file(&path);
            }
        }
        Fetched::Missing
    }

    /// Fetches each of `ids` (see [`SymbolServers::fetch`]), `concurrency`
    /// at a time, in order of `ids` (so the most wanted come first);
    /// `progress` hears of each as it finishes. Returns what became of
    /// each.
    pub fn fetch_all(
        &self,
        ids: &[PdbId],
        concurrency: usize,
        progress: impl Fn(usize, &PdbId, &Fetched) + Sync,
    ) -> Vec<Fetched> {
        let next = AtomicUsize::new(0);
        let results: Vec<Mutex<Option<Fetched>>> = ids.iter().map(|_| Mutex::new(None)).collect();
        std::thread::scope(|scope| {
            for _ in 0..concurrency.clamp(1, ids.len().max(1)) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(id) = ids.get(i) else { return };
                        let r = self.fetch(id);
                        progress(i, id, &r);
                        *results[i]
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r);
                    }
                });
            }
        });
        results
            .into_iter()
            .map(|m| {
                m.into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .unwrap_or(Fetched::Missing)
            })
            .collect()
    }
}

/// A PDB's file name from the path an image records, lower case, if it is
/// usable in a path and a URL: letters, digits and `._-+` only (no
/// separators, no `..`).
fn file_name(path: &str) -> Option<String> {
    let name = path.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b));
    ok.then_some(name)
}

/// Downloads `url` to `path` with `curl`: written beside it, then renamed
/// (a half-fetched file is never found). Whether it worked.
fn download(url: &str, path: &Path) -> bool {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return false;
    }
    let Some(dir) = path.parent() else {
        return false;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    // (Named for this process and this download: two at once never share
    // one.)
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}.{}.part",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp);
    let ok = std::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--location",
            "--compressed",
            "--proto",
            "=https,http",
            "--proto-redir",
            "=https,http",
            "--max-redirs",
            "5",
            "--max-time",
            &MAX_SECONDS.to_string(),
            "--max-filesize",
            &MAX_FILE.to_string(),
            "--user-agent",
            concat!("stackrabbit/", env!("CARGO_PKG_VERSION")),
            "--output",
        ])
        .arg(&tmp)
        .arg("--")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok || std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

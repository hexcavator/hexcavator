//! Debug information from symbol servers, when asked for: Microsoft's
//! (and anything that serves its layout, SSQP: `msdl.microsoft.com`,
//! `symstore` shares over HTTP, .NET's symbol servers) and debuginfod.
//!
//! Nothing is asked of a server unless servers are given
//! ([`set_servers`]: hexc's `--symbol-server` and `--debuginfod`, or
//! `HEXC_SYMBOL_SERVER` and `HEXC_DEBUGINFOD`). debuginfod's own
//! `DEBUGINFOD_URLS` is not followed: distributions set it for every
//! user, and asking a server tells it which builds are being looked at.
//!
//! Files are fetched with the system's `curl` (on Windows 10 and later,
//! macOS, and Linux), limited in size and time, and kept in memory, or
//! in the symbol cache if one is given (in the servers' layout, where the
//! lookup finds them next time: see `hexcavator_debuginfo::candidate_paths_in`).
//! What a server sends is hostile like any input, and is used only if it
//! matches the image (`DebugInfo::matches`).

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use hexcavator_image::DebugId;
use hexcavator_mmap::Mmap;

/// Where to ask for debug information, and where to keep what is found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Servers {
    /// Servers with Microsoft's layout (SSQP), by base URL.
    pub symbol_servers: Vec<String>,
    /// debuginfod servers, by base URL.
    pub debuginfod: Vec<String>,
    /// Where to keep what is fetched (else it is kept in memory only).
    pub cache: Option<PathBuf>,
}

impl Servers {
    /// Whether there is anything to ask.
    pub fn is_empty(&self) -> bool {
        self.symbol_servers.is_empty() && self.debuginfod.is_empty()
    }

    /// The servers the environment names: `HEXC_SYMBOL_SERVER`
    /// (separated by `;`), `HEXC_DEBUGINFOD` (by spaces, as
    /// `DEBUGINFOD_URLS`), and `HEXC_SYMBOL_CACHE`.
    pub fn from_env() -> Self {
        let var = |n: &str| std::env::var(n).ok().filter(|v| !v.trim().is_empty());
        Servers {
            symbol_servers: var("HEXC_SYMBOL_SERVER")
                .map(|v| {
                    v.split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            debuginfod: var("HEXC_DEBUGINFOD")
                .map(|v| v.split_whitespace().map(String::from).collect())
                .unwrap_or_default(),
            cache: var("HEXC_SYMBOL_CACHE").map(PathBuf::from),
        }
    }
}

static SERVERS: RwLock<Option<Servers>> = RwLock::new(None);

/// The servers to ask (none: nothing is asked).
pub fn set_servers(servers: Servers) {
    *SERVERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(servers);
}

/// The servers set (else the environment's).
pub fn servers() -> Servers {
    SERVERS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(Servers::from_env)
}

/// The largest file fetched (a debug file can be large; a server that
/// sends more is refused).
pub const MAX_FILE: u64 = 4 << 30;

/// The longest a fetch may take, in seconds.
const MAX_SECONDS: u32 = 600;

/// The key a server with Microsoft's layout keeps `id`'s file under, if
/// it has one: `app.pdb/<GUID><age>/app.pdb`,
/// `_.debug/elf-buildid-sym-<id>/_.debug`,
/// `_.dwarf/mach-uuid-sym-<uuid>/_.dwarf`.
pub fn ssqp_key(id: &DebugId<'_>) -> Option<String> {
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    match *id {
        DebugId::Pdb { guid, age, path } => {
            let path = String::from_utf8_lossy(path);
            let name = path.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
            if !safe_name(&name) {
                return None;
            }
            let key = hexcavator_debuginfo::symbol_store_key(&guid, age);
            Some(format!("{name}/{key}/{name}"))
        }
        DebugId::BuildId(b) | DebugId::AltLink { build_id: b, .. } if b.len() >= 2 => {
            Some(format!("_.debug/elf-buildid-sym-{}/_.debug", hex(b)))
        }
        DebugId::Uuid(u) => Some(format!("_.dwarf/mach-uuid-sym-{}/_.dwarf", hex(&u))),
        _ => None,
    }
}

/// The path a debuginfod server serves `id`'s debug file at, if it can.
pub fn debuginfod_path(id: &DebugId<'_>) -> Option<String> {
    match *id {
        DebugId::BuildId(b) | DebugId::AltLink { build_id: b, .. } if b.len() >= 2 => {
            let hex: String = b.iter().map(|b| format!("{b:02x}")).collect();
            Some(format!("buildid/{hex}/debuginfo"))
        }
        _ => None,
    }
}

/// A name from an image that goes into a URL and a path: letters,
/// digits, and `._-+` only (no separators, no `..`).
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
}

/// Where the servers have `id`'s file: (URL, where the cache keeps it).
pub fn locations(servers: &Servers, id: &DebugId<'_>) -> Vec<(String, Option<PathBuf>)> {
    let mut out = Vec::new();
    if let Some(key) = ssqp_key(id) {
        for s in &servers.symbol_servers {
            let cached = servers
                .cache
                .as_ref()
                .map(|c| key.split('/').fold(c.clone(), |p, part| p.join(part)));
            out.push((format!("{}/{key}", s.trim_end_matches('/')), cached));
        }
    }
    if let Some(path) = debuginfod_path(id) {
        for s in &servers.debuginfod {
            // (debuginfod's own cache layout: <id>/debuginfo.)
            let cached = servers.cache.as_ref().map(|c| {
                path.trim_start_matches("buildid/")
                    .split('/')
                    .fold(c.clone(), |p, part| p.join(part))
            });
            out.push((format!("{}/{path}", s.trim_end_matches('/')), cached));
        }
    }
    out
}

/// Fetches `url` (with `curl`): into `cached` if given (and returns it
/// mapped), else into memory. `None` if it isn't there, or anything
/// fails.
pub fn fetch(url: &str, cached: Option<&Path>) -> Option<Mmap> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return None;
    }
    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "--fail",
        "--silent",
        "--location",
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
        concat!("hexc/", env!("CARGO_PKG_VERSION")),
    ]);
    match cached {
        Some(path) => {
            let dir = path.parent()?;
            std::fs::create_dir_all(dir).ok()?;
            // (Written beside it, then renamed: a half-fetched file is never
            // found.)
            let mut tmp = path.as_os_str().to_owned();
            tmp.push(format!(".{}.part", std::process::id()));
            let tmp = PathBuf::from(tmp);
            let ok = cmd
                .arg("--output")
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
                return None;
            }
            Mmap::open_named(path).ok()
        }
        None => {
            let out = cmd
                .arg("--output")
                .arg("-")
                .arg("--")
                .arg(url)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            (out.status.success() && !out.stdout.is_empty()).then(|| Mmap::from(out.stdout))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let guid = [
            0xFD, 0x0D, 0xB9, 0x1C, 0xB9, 0x4C, 0xA8, 0x4B, 0xBA, 0x9C, 0xAE, 0x62, 0x63, 0x7E,
            0x69, 0x30,
        ];
        let pdb = DebugId::Pdb {
            guid,
            age: 1,
            path: br"D:\a\CoreCLR.pdb",
        };
        assert_eq!(
            ssqp_key(&pdb).as_deref(),
            Some("coreclr.pdb/1CB90DFD4CB94BA8BA9CAE62637E69301/coreclr.pdb")
        );
        let id = DebugId::BuildId(&[0x2e, 0x52, 0x99]);
        assert_eq!(
            ssqp_key(&id).as_deref(),
            Some("_.debug/elf-buildid-sym-2e5299/_.debug")
        );
        assert_eq!(
            debuginfod_path(&id).as_deref(),
            Some("buildid/2e5299/debuginfo")
        );
        let mach = DebugId::Uuid([0xca; 16]);
        assert_eq!(
            ssqp_key(&mach).as_deref(),
            Some("_.dwarf/mach-uuid-sym-cacacacacacacacacacacacacacacaca/_.dwarf")
        );
        assert_eq!(debuginfod_path(&mach), None);
        // Names that would leave the key's directory, or the URL's path.
        for bad in [&b"../x.pdb"[..], b"a?b.pdb", b"a b.pdb", b"..", b""] {
            let id = DebugId::Pdb {
                guid,
                age: 1,
                path: bad,
            };
            let key = ssqp_key(&id);
            assert!(
                key.as_deref().is_none_or(|k| k.split('/').all(safe_name)),
                "{bad:?}: {key:?}"
            );
        }
        assert_eq!(
            ssqp_key(&DebugId::Pdb {
                guid,
                age: 1,
                path: b"x/.."
            }),
            None
        );
    }

    #[test]
    fn locations_and_cache_paths() {
        let servers = Servers {
            symbol_servers: vec!["https://msdl.microsoft.com/download/symbols/".into()],
            debuginfod: vec!["https://debuginfod.example".into()],
            cache: Some(PathBuf::from("/c")),
        };
        let id = DebugId::BuildId(&[0xab, 0xcd]);
        let l = locations(&servers, &id);
        assert_eq!(
            l[0].0,
            "https://msdl.microsoft.com/download/symbols/_.debug/elf-buildid-sym-abcd/_.debug"
        );
        assert_eq!(
            l[0].1,
            Some(
                Path::new("/c")
                    .join("_.debug")
                    .join("elf-buildid-sym-abcd")
                    .join("_.debug")
            )
        );
        assert_eq!(l[1].0, "https://debuginfod.example/buildid/abcd/debuginfo");
        assert_eq!(l[1].1, Some(Path::new("/c").join("abcd").join("debuginfo")));
        assert!(locations(&Servers::default(), &id).is_empty());
        // Only HTTP(S) is fetched.
        assert!(fetch("file:///etc/passwd", None).is_none());
        assert!(fetch("-o/tmp/x", None).is_none());
    }
}

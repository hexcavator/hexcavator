//! Read-only memory mapping of files.
//!
//! On Windows and Unix the file is mapped (with the `memmap2` crate);
//! elsewhere, such as WebAssembly, it is read into memory. Either way the
//! result is a `&[u8]` that the parsers borrow.
//!
//! # Caveat
//!
//! The bytes of a mapping can change if another process modifies the file
//! while it is mapped. On Windows we hold the file open without write sharing,
//! which prevents that; on Unix there is no way to prevent it. Parsers must
//! therefore never assume that two reads of the same location agree (they
//! should read each location once and work with the value). And on Unix,
//! if another process truncates the file while it is mapped, reading a page
//! past its new end raises SIGBUS, which ends the process. Doing that takes
//! a local process able to write the file, which could do worse; so we
//! accept it.

// The one `unsafe` call is `memmap2::MmapOptions::map`, unsafe only because
// of the caveat above.
#![allow(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::fs::File;
use std::io;
use std::ops::Deref;
use std::path::Path;

/// A read-only view of a file's contents.
pub struct Mmap {
    inner: Inner,
}

enum Inner {
    Owned(Box<[u8]>),
    #[cfg(any(windows, unix))]
    Mapped {
        map: memmap2::Mmap,
        // Held so that, on Windows, other processes cannot open the file for
        // writing while it is mapped.
        _file: File,
    },
}

impl Mmap {
    /// Maps the file at `path`.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = open_read_only(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::of_file(file, len)
    }

    /// Maps the open `file`, `len` bytes long.
    fn of_file(file: File, len: u64) -> io::Result<Self> {
        let len = usize::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "file is too large to map on this host",
            )
        })?;
        if len == 0 {
            // Zero-length mappings are an error on some systems.
            return Ok(Self::from(Vec::new()));
        }
        Self::map(file, len)
    }

    /// Maps the file at `path` when the path came from a file's contents
    /// (a PDB path an image records, a split DWARF file a unit names, a
    /// source map URL), not from the user: a hostile file could name a
    /// network share (which Windows would connect to, offering the user's
    /// credentials), a device, or a FIFO (whose opening blocks). Only a
    /// local regular file is opened (see [`is_local_path`]).
    pub fn open_named(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !is_local_path(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a local file's path",
            ));
        }
        // A regular file before it's opened (a FIFO's open blocks; a
        // device's can do anything)...
        if !std::fs::metadata(path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        // ...and what was opened, checked by its handle, not its path again
        // (which another process could have pointed elsewhere since): what
        // is mapped is what was checked. (On Unix, opened without blocking:
        // a FIFO swapped in since opens at once, and is refused here.)
        let file = open_named_read_only(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Self::of_file(file, meta.len())
    }

    #[cfg(any(windows, unix))]
    fn map(file: File, len: usize) -> io::Result<Self> {
        // SAFETY: the mapping is read-only, so we never write through it. The
        // file changing underneath us (see the crate caveat) can change what
        // we read, but parsers treat the bytes as untrusted input anyway.
        let map = unsafe { memmap2::MmapOptions::new().len(len).map(&file)? };
        Ok(Self {
            inner: Inner::Mapped { map, _file: file },
        })
    }

    #[cfg(not(any(windows, unix)))]
    fn map(mut file: File, len: usize) -> io::Result<Self> {
        use std::io::Read;
        let mut data = Vec::with_capacity(len);
        file.read_to_end(&mut data)?;
        Ok(Self::from(data))
    }

    /// The file's bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.inner {
            Inner::Owned(data) => data,
            #[cfg(any(windows, unix))]
            Inner::Mapped { map, .. } => map,
        }
    }

    /// Whether the data is mapped from a file (as opposed to held in memory).
    #[inline]
    pub fn is_mapped(&self) -> bool {
        !matches!(self.inner, Inner::Owned(_))
    }
}
impl From<Vec<u8>> for Mmap {
    fn from(data: Vec<u8>) -> Self {
        Self {
            inner: Inner::Owned(data.into_boxed_slice()),
        }
    }
}

impl Deref for Mmap {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Mmap {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for Mmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mmap")
            .field("len", &self.len())
            .field("mapped", &self.is_mapped())
            .finish()
    }
}

/// Whether `path` (one a file names) is a plain local path: not a network
/// share or a device or kernel namespace (`\\server\share`, `//server`,
/// `\\?\`, `\\.\`, `\??\`), which merely asking about would reach
/// (Windows connects to a share to see whether a file is there). Checking
/// the text, before any file system call, on every host.
pub fn is_local_path(path: &Path) -> bool {
    let s = path.as_os_str().as_encoded_bytes();
    let sep = |b: u8| b == b'\\' || b == b'/';
    let doubled = s.len() >= 2 && sep(s[0]) && sep(s[1]);
    let nt = s.len() >= 4 && sep(s[0]) && s[1] == b'?' && s[2] == b'?' && sep(s[3]);
    !s.is_empty() && !doubled && !nt && !s.contains(&0)
}

#[cfg(windows)]
fn open_read_only(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(windows))]
fn open_read_only(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Opens a path a file names (see [`Mmap::open_named`]): on Unix, without
/// blocking (`O_NONBLOCK`: a FIFO's open would wait for a writer; a regular
/// file's reads are unaffected).
#[cfg(unix)]
fn open_named_read_only(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_named_read_only(path: &Path) -> io::Result<File> {
    open_read_only(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("hexcavator-mmap-{}-{}", std::process::id(), name));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn maps_file_contents() {
        let contents: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
        let path = temp_file("contents", &contents);
        {
            let map = Mmap::open(&path).unwrap();
            assert_eq!(&*map, &contents[..]);
            assert_eq!(map.is_mapped(), cfg!(any(windows, unix)));
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn empty_file() {
        let path = temp_file("empty", b"");
        {
            let map = Mmap::open(&path).unwrap();
            assert!(map.is_empty());
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_file() {
        let err = Mmap::open("this/file/does/not/exist").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Paths a hostile file names: shares, devices, and namespaces are
    /// refused without any file system call; so are directories (and, on
    /// Unix, FIFOs and devices) by what they are.
    #[test]
    fn named_paths() {
        for bad in [
            r"\\server\share\app.pdb",
            "//server/share/app.pdb",
            r"\\?\C:\app.pdb",
            r"\\?\UNC\server\share\app.pdb",
            r"\\.\pipe\x",
            r"\??\C:\app.pdb",
            "",
        ] {
            assert!(!is_local_path(Path::new(bad)), "{bad}");
            assert!(Mmap::open_named(bad).is_err(), "{bad}");
        }
        for good in [
            r"C:\build\app.pdb",
            "/home/me/app.debug",
            "app.pdb",
            r"sub\app.dwo",
        ] {
            assert!(is_local_path(Path::new(good)), "{good}");
        }
        assert!(Mmap::open_named(std::env::temp_dir()).is_err());
        let path = temp_file("named", b"abc");
        assert_eq!(&*Mmap::open_named(&path).unwrap(), b"abc");
        std::fs::remove_file(&path).unwrap();
    }

    /// A FIFO a file names is refused, and opening it doesn't wait for a
    /// writer (as it would without `O_NONBLOCK`): one swapped in after the
    /// path was checked can't hang the reader.
    #[cfg(unix)]
    #[test]
    fn named_fifos_are_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;
        let path =
            std::env::temp_dir().join(format!("hexcavator-mmap-{}-fifo", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // (Without a writer, a blocking open would never return.)
        let file = open_named_read_only(&path).unwrap();
        assert!(file.metadata().unwrap().file_type().is_fifo());
        assert!(Mmap::open_named(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}

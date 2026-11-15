//! Files: what one is (format, architecture), finding a name in a
//! directory (case aside, for Windows names on any host), and opening a
//! candidate only if the root could load it.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

use hexcavator_mmap::Mmap;

use crate::{Format, Loaded};

/// An image's architecture: its name, and what must match to load it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Arch {
    pub name: String,
    key: Key,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    /// A PE machine; hybrid (ARM64EC, ARM64X: loadable by x64 and ARM64
    /// processes both).
    Pe {
        machine: u16,
        hybrid: bool,
    },
    Elf {
        wide: bool,
        machine: u16,
        big: bool,
    },
    MachO {
        cputype: u32,
    },
}

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

impl Arch {
    /// Whether an image of `self` can be loaded by a process of `root`.
    fn loads_in(&self, root: &Arch) -> bool {
        match (self.key, root.key) {
            (Key::Pe { machine: a, hybrid }, Key::Pe { machine: b, .. }) => {
                a == b
                    || (hybrid
                        && matches!(b, IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64)
                        && matches!(
                            a,
                            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 | 0xA641 | 0xA64E
                        ))
            }
            (a, b) => a == b,
        }
    }

    /// Whether this is a 32-bit image (PE: x86, ARM32).
    pub fn pe_32_bit(&self) -> Option<u16> {
        match self.key {
            Key::Pe { machine, .. } if matches!(machine, 0x14C | 0x1C0 | 0x1C2 | 0x1C4) => {
                Some(machine)
            }
            _ => None,
        }
    }

    /// Whether this is a 64-bit ELF image.
    pub fn elf_wide(&self) -> Option<bool> {
        match self.key {
            Key::Elf { wide, .. } => Some(wide),
            _ => None,
        }
    }

    /// The Mach-O CPU type.
    pub fn cputype(&self) -> Option<u32> {
        match self.key {
            Key::MachO { cputype } => Some(cputype),
            _ => None,
        }
    }
}

/// The format of the image in `data`, and where it is (a universal Mach-O
/// file's slice: for `cputype`, or the preferred one).
pub(crate) fn identify(data: &[u8], cputype: Option<u32>) -> Option<(Format, Range<usize>)> {
    if hexcavator_pe::PeFile::parse_image(data).is_ok() {
        return Some((Format::Pe, 0..data.len()));
    }
    if hexcavator_elf::ElfFile::parse(data).is_ok() {
        return Some((Format::Elf, 0..data.len()));
    }
    if let Some(archs) = hexcavator_macho::fat_archs(data) {
        let pick = match cputype {
            Some(c) => archs.into_iter().find(|a| a.cputype == c)?,
            None => hexcavator_macho::preferred_slice(data)?.0,
        };
        let start = usize::try_from(pick.offset).ok()?;
        let end = start.checked_add(usize::try_from(pick.size).ok()?)?;
        data.get(start..end)?;
        return Some((Format::MachO, start..end));
    }
    if hexcavator_macho::MachO::parse(data).is_ok() {
        return Some((Format::MachO, 0..data.len()));
    }
    None
}

/// The architecture of the `format` image in `data`.
pub(crate) fn arch_of(format: Format, data: &[u8]) -> Option<Arch> {
    let image = hexcavator_image::Image::parse(data).ok();
    match format {
        Format::Pe => {
            let pe = hexcavator_pe::PeFile::parse_image(data).ok()?;
            let machine = pe.machine();
            let hybrid = image
                .as_ref()
                .and_then(hexcavator_image::Image::hybrid)
                .is_some();
            Some(Arch {
                name: hexcavator_image::coff_machine_name(machine).to_string(),
                key: Key::Pe { machine, hybrid },
            })
        }
        Format::Elf => {
            let elf = hexcavator_elf::ElfFile::parse(data).ok()?;
            let h = elf.header();
            Some(Arch {
                name: image.map_or_else(
                    || format!("machine {}", h.machine),
                    |i| i.arch().name().to_string(),
                ),
                key: Key::Elf {
                    wide: h.class == hexcavator_elf::Class::Elf64,
                    machine: h.machine,
                    big: h.endian == hexcavator_core::Endian::Big,
                },
            })
        }
        Format::MachO => {
            let m = hexcavator_macho::MachO::parse(data).ok()?;
            let h = m.header();
            Some(Arch {
                name: hexcavator_macho::arch_name(h.cputype, h.cpusubtype),
                key: Key::MachO { cputype: h.cputype },
            })
        }
    }
}

/// This host's system root for `format`'s images: the Windows directory on
/// Windows (for PE), `/` on Linux (ELF) and macOS (Mach-O).
pub(crate) fn host_sysroot(format: Format) -> Option<PathBuf> {
    let root = match format {
        Format::Pe if cfg!(windows) => std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from),
        Format::Elf if cfg!(any(target_os = "linux", target_os = "android")) => PathBuf::from("/"),
        Format::MachO if cfg!(target_os = "macos") => PathBuf::from("/"),
        _ => return None,
    };
    root.is_dir().then_some(root)
}

/// Why a candidate wasn't taken.
pub(crate) enum Reject {
    /// No such file.
    Absent,
    /// For another architecture.
    WrongArch(String),
    /// Not one (or unreadable).
    Unreadable(String),
}

/// Finding and opening files.
pub(crate) struct Search {
    format: Format,
    /// The root's architecture.
    pub arch: Option<Arch>,
    /// Directories listed (for names whose case differs), by path: their
    /// entries by lower-case name.
    listings: HashMap<PathBuf, HashMap<String, String>>,
}

/// The most entries of a directory listed.
const MAX_LISTED: usize = 1 << 16;

impl Search {
    pub fn new(format: Format, arch: Option<Arch>) -> Self {
        Self {
            format,
            arch,
            listings: HashMap::new(),
        }
    }

    /// The path of `name` in `dir`: as named, or (for PE, whose names are
    /// any case) the entry whose name it is, case aside.
    pub fn in_dir(&mut self, dir: &Path, name: &str) -> PathBuf {
        let exact = dir.join(name);
        if self.format != Format::Pe || cfg!(windows) || exact.exists() {
            return exact;
        }
        let listing = self.listings.entry(dir.to_path_buf()).or_insert_with(|| {
            let mut out = HashMap::new();
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten().take(MAX_LISTED) {
                    let n = e.file_name().to_string_lossy().into_owned();
                    out.insert(n.to_lowercase(), n);
                }
            }
            out
        });
        match listing.get(&name.to_lowercase()) {
            Some(real) => dir.join(real),
            None => exact,
        }
    }

    /// The image at `path`, if the root could load it.
    pub fn open(&self, path: &Path) -> Result<Loaded, Reject> {
        let path = &normalize(path);
        if !hexcavator_mmap::is_local_path(path) || !path.is_file() {
            return Err(Reject::Absent);
        }
        let map = Mmap::open_named(path).map_err(|e| Reject::Unreadable(e.to_string()))?;
        let cputype = self.arch.as_ref().and_then(Arch::cputype);
        let Some((format, range)) = identify(&map, cputype) else {
            // (A universal file without the root's slice: another
            // architecture's.)
            if hexcavator_macho::fat_archs(&map).is_some() {
                return Err(Reject::WrongArch("other architectures".into()));
            }
            return Err(Reject::Unreadable(format!(
                "not a {} image",
                self.format.name()
            )));
        };
        if format != self.format {
            return Err(Reject::Unreadable(format!(
                "a {} image, not {}",
                format.name(),
                self.format.name()
            )));
        }
        let loaded = Loaded { map, range };
        let arch = arch_of(format, loaded.data());
        match (&arch, &self.arch) {
            (Some(a), Some(root)) if !a.loads_in(root) => Err(Reject::WrongArch(a.name.clone())),
            _ => Ok(loaded),
        }
    }
}

/// `path` with `.` and `dir/..` taken out (lexically: as a loader joins
/// names, not following links).
pub(crate) fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // (The root's parent is the root.)
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => out.push(".."),
            },
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Whether `name` is a plain file name (no directories, drive, or stream:
/// what a PE import names).
pub(crate) fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':', '\0'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized() {
        let n = |p: &str| normalize(Path::new(p)).to_string_lossy().replace('\\', "/");
        assert_eq!(n("a/lib/../libb/x.so"), "a/libb/x.so");
        assert_eq!(n("./a/./b"), "a/b");
        assert_eq!(n("../x"), "../x");
        assert_eq!(n("a/../../x"), "../x");
        assert_eq!(n("/usr/lib/../lib64/y"), "/usr/lib64/y");
        assert_eq!(n("/.."), "/");
        assert_eq!(n("."), ".");
        assert_eq!(n(""), ".");
    }

    #[test]
    fn plain_names() {
        for good in ["kernel32.dll", "a b.dll", "x"] {
            assert!(is_plain_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b.dll",
            "..\\x.dll",
            "\\\\server\\x.dll",
            "C:x.dll",
            "a\0b",
            "x.dll:stream",
        ] {
            assert!(!is_plain_name(bad), "{bad:?}");
        }
    }
}

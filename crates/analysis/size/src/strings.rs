//! Strings an image holds that a build could make smaller: the absolute
//! paths of the build's source files (`__FILE__` in `assert`s and logging,
//! Rust's panic locations), which mapping the build's directory away
//! shortens ([`build_paths`]); and string literals with copies of
//! themselves the linker didn't merge ([`duplicate_strings`]).
//!
//! Both read the image's read-only data: sections mapped, not written,
//! and not code (`.rodata`, `.rdata`, `__TEXT,__cstring`, `__const`).

use rustc_hash::FxHashMap;

/// The data sections of an image that hold its string literals: (address,
/// bytes). By name, as the loader's own tables (`.dynstr`, `.eh_frame`)
/// are read-only data too: ELF's `.rodata` (and `.rodata.*`), PE's
/// `.rdata`, and its `.data` (where MSVC puts them unless it pools them,
/// `/GF`), Mach-O's `__cstring` and `__const`.
fn read_only<'d>(image: &hexcavator_image::Image<'d>) -> Vec<(u64, &'d [u8])> {
    use hexcavator_image::SectionFlags;
    let pe = image.pe().is_some();
    image
        .sections()
        .into_iter()
        .filter(|s| {
            let n = s.name;
            let constants = n == b".rodata"
                || n.starts_with(b".rodata.")
                || n == b".rdata"
                || n == b"__cstring"
                || n == b"__const";
            (constants && !s.flags.contains(SectionFlags::WRITE) || pe && n == b".data")
                && !s.flags.contains(SectionFlags::CODE)
                && s.file_size > 0
                && s.vm_size > 0
        })
        .filter_map(|s| {
            let len = s.file_size.min(s.vm_size);
            Some((s.addr, image.bytes_at(s.addr, len)?))
        })
        .collect()
}

/// A directory the build's source paths start with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRoot {
    /// The directory (without a separator at its end).
    pub root: String,
    /// The paths under it, as they are in the image (each once), and how
    /// many times each is there.
    pub paths: Vec<(String, u64)>,
    /// The bytes mapping it to `.` would save: its length less one, for
    /// each path.
    pub saving: u64,
    /// Whether they're Rust's (`.rs`): `--remap-path-prefix` maps them.
    pub rust: bool,
}

/// The source files' extensions a path in an image ends with.
/// (Longest first: an alternative is taken in order.)
const SOURCE: &str =
    r"(?:c\+\+|cpp|cxx|cc|cp|c|h\+\+|hpp|hxx|hh|h|inc|inl|ipp|tcc|mm|m|rs|swift|go|zig|cu|d)";

/// The absolute paths of source files in `bytes`: POSIX (`/a/b/c.cpp`), or
/// Windows (`C:\a\b.c`, `C:/a/b.c`), of at least two directories, ending in
/// a source file's extension (greedily, the last such in a run of path
/// characters: Rust's strings aren't terminated), and neither part of a
/// longer name (`.c` of `.cache`) nor the tail of a relative path.
pub fn source_paths(bytes: &[u8]) -> Vec<&[u8]> {
    static RE: std::sync::OnceLock<Option<regex::bytes::Regex>> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::bytes::Regex::new(&format!(
            r"(?:[A-Za-z]:[\\/]|/)(?:[A-Za-z0-9_.+@~\-]+[\\/]){{2,}}[A-Za-z0-9_.+@~\-]+\.{SOURCE}"
        ))
        .ok()
    });
    let Some(re) = re else {
        return Vec::new();
    };
    re.find_iter(bytes)
        .filter(|m| {
            // (Rust's run into what follows; others' don't.)
            let more = bytes
                .get(m.end())
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
            if more && !m.as_bytes().ends_with(b".rs") {
                return false;
            }
            !(m.start() > 0
                && m.as_bytes()[0] == b'/'
                && (bytes[m.start() - 1].is_ascii_alphanumeric() || bytes[m.start() - 1] == b'.'))
        })
        .map(|m| m.as_bytes())
        .collect()
}

/// The absolute paths of source files in the image's read-only data,
/// grouped by the directories they start with (the deepest each group
/// shares, at least two levels down, such as `/home/me/project`), largest
/// saving first.
pub fn build_paths(image: &hexcavator_image::Image<'_>) -> Vec<PathRoot> {
    let mut found: FxHashMap<String, u64> = FxHashMap::default();
    for (_, bytes) in read_only(image) {
        for p in source_paths(bytes) {
            *found
                .entry(String::from_utf8_lossy(p).into_owned())
                .or_default() += 1;
        }
    }
    // By their first two directories, then what those share.
    let parts = |p: &str| -> Vec<String> { p.split(['/', '\\']).map(str::to_string).collect() };
    let mut groups: FxHashMap<String, Vec<(String, u64)>> = FxHashMap::default();
    for (p, n) in found {
        let ps = parts(&p);
        let key = ps.iter().take(3).cloned().collect::<Vec<_>>().join("/");
        groups.entry(key).or_default().push((p, n));
    }
    let mut out: Vec<PathRoot> = groups
        .into_values()
        .filter_map(|mut paths| {
            paths.sort();
            // The directories all share (not the file's own name).
            let first = parts(&paths[0].0);
            let mut shared = first.len() - 1;
            for (p, _) in &paths[1..] {
                let ps = parts(p);
                shared = shared.min(ps.len() - 1);
                shared = (0..shared).find(|&i| ps[i] != first[i]).unwrap_or(shared);
            }
            // (`/` and `/home`: too little to be a build's directory.)
            if shared < 3 {
                return None;
            }
            let sep = if paths[0].0.contains('\\') { "\\" } else { "/" };
            let root = first[..shared].join(sep);
            let cut = root.len() as u64 - 1;
            let saving = paths.iter().map(|(_, n)| cut * n).sum();
            let rust = paths.iter().filter(|(p, _)| p.ends_with(".rs")).count() * 2 > paths.len();
            Some(PathRoot {
                root,
                paths,
                saving,
                rust,
            })
        })
        .collect();
    out.sort_by(|a, b| b.saving.cmp(&a.saving).then_with(|| a.root.cmp(&b.root)));
    out
}

/// A string literal with copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateString {
    pub text: String,
    /// Where each copy is.
    pub copies: Vec<u64>,
    /// Its bytes (its terminator among them).
    pub size: u64,
}

/// The NUL-terminated strings (of at least 4 printable characters) in the
/// image's read-only data that are there more than once, where `named`
/// says none of a string's copies is in named data (an array, which can't
/// be merged: its address is its own), largest waste first.
pub fn duplicate_strings(
    image: &hexcavator_image::Image<'_>,
    named: &dyn Fn(u64) -> bool,
) -> Vec<DuplicateString> {
    let mut seen: FxHashMap<&[u8], Vec<u64>> = FxHashMap::default();
    for (addr, bytes) in read_only(image) {
        let mut start = 0usize;
        while start < bytes.len() {
            let end = bytes[start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(bytes.len(), |e| start + e);
            let s = &bytes[start..end];
            if end < bytes.len()
                && s.len() >= 4
                && s.iter()
                    .all(|&c| c == b'\t' || c == b'\n' || (0x20..0x7F).contains(&c))
            {
                seen.entry(s).or_default().push(addr + start as u64);
            }
            start = end + 1;
        }
    }
    let mut out: Vec<DuplicateString> = seen
        .into_iter()
        .filter(|(_, at)| at.len() > 1 && !at.iter().any(|&a| named(a)))
        .map(|(s, copies)| DuplicateString {
            text: String::from_utf8_lossy(s).into_owned(),
            size: s.len() as u64 + 1,
            copies,
        })
        .collect();
    out.sort_by(|a, b| {
        (b.size * (b.copies.len() as u64 - 1))
            .cmp(&(a.size * (a.copies.len() as u64 - 1)))
            .then_with(|| a.text.cmp(&b.text))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(b: &[u8]) -> Vec<String> {
        source_paths(b)
            .into_iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect()
    }

    #[test]
    fn paths() {
        // C's, terminated; C++'s (not taken for `.c`); a header's.
        assert_eq!(
            found(b"x\0/home/me/proj/src/a.c\0/home/me/proj/src/b.cpp\0/usr/include/c++/13/vector.h\0"),
            [
                "/home/me/proj/src/a.c",
                "/home/me/proj/src/b.cpp",
                "/usr/include/c++/13/vector.h"
            ]
        );
        // Rust's, run together with what follows.
        assert_eq!(
            found(
                b"on a None value\0/home/me/.cargo/registry/src/serde-1.0/src/de.rsinvalid length"
            ),
            ["/home/me/.cargo/registry/src/serde-1.0/src/de.rs"]
        );
        // Windows'.
        assert_eq!(
            found(br"C:\build\proj\src\main.cpp"),
            [r"C:\build\proj\src\main.cpp"]
        );
        assert_eq!(found(b"D:/w/x/y.h\0"), ["D:/w/x/y.h"]);
        // Not: relative ones, of one directory, other extensions, longer
        // names.
        assert!(
            found(b"src/lib/a.c\0../x/y/z.c\0/tmp/a.c\0/a/b/c.cache\0/a/b/c.o\0").is_empty(),
            "{:?}",
            found(b"src/lib/a.c\0../x/y/z.c\0/tmp/a.c\0/a/b/c.cache\0/a/b/c.o\0")
        );
    }
}

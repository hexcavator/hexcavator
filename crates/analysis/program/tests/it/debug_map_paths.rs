//! Where a Mach-O debug map's object paths may be: an archive's member
//! split from its archive; a path as written, from the image's directory,
//! and by its name beside the image; its bytes kept as they are where a
//! path is bytes (Unix).

use std::path::{Path, PathBuf};

use hexcavator_program::debug_map_paths;

#[test]
fn an_archives_member_and_a_relative_object() {
    let image = Path::new("/build/out/app");
    let dir = image.parent().unwrap();

    let (paths, member) = debug_map_paths(image, b"/deps/libfoo.a(foo.o)");
    assert_eq!(member.as_deref(), Some("foo.o"));
    assert!(
        paths.contains(&PathBuf::from("/deps/libfoo.a")),
        "{paths:?}"
    );
    assert_eq!(paths.last(), Some(&dir.join("libfoo.a")), "{paths:?}");

    let (paths, member) = debug_map_paths(image, b"obj/bar.o");
    assert_eq!(member, None);
    assert_eq!(
        paths,
        [
            dir.join("obj/bar.o"),
            PathBuf::from("obj/bar.o"),
            dir.join("bar.o")
        ]
    );

    // Not an archive: no member.
    let (_, member) = debug_map_paths(image, b"(odd).o");
    assert_eq!(member, None);
}

/// A path that isn't UTF-8 is opened as its bytes, not as text with
/// replacement characters (which names no file).
#[cfg(unix)]
#[test]
fn bytes_that_arent_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let (paths, _) = debug_map_paths(Path::new("/b/app"), b"/o/caf\xe9.o");
    assert!(
        paths
            .iter()
            .any(|p| p.as_os_str().as_bytes() == b"/o/caf\xe9.o"),
        "{paths:?}"
    );
}

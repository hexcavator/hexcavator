//! The libraries an image links, its run paths, and its install name, of
//! the dependency test's images (tools/deps/build-unix.cmd).

use hexcavator_macho::MachO;
use hexcavator_macho::consts::{LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/deps/macho/app")
            .join(name),
    )
    .unwrap()
}

#[test]
fn dylibs_rpaths_and_install_names() {
    let data = read("main");
    let m = MachO::parse(&data).unwrap();
    let libs: Vec<(u32, &[u8])> = m.dylibs().iter().map(|d| (d.cmd, d.name)).collect();
    assert_eq!(
        libs,
        [
            (LC_LOAD_DYLIB, &b"@rpath/liba.dylib"[..]),
            (LC_LOAD_WEAK_DYLIB, b"@rpath/libweak.dylib"),
            (LC_LOAD_DYLIB, b"/usr/lib/libSystem.B.dylib"),
        ]
    );
    assert_eq!(m.rpaths(), [&b"@executable_path/lib"[..]]);
    assert_eq!(m.install_name(), None);
    let data = read("lib/liba.dylib");
    let a = MachO::parse(&data).unwrap();
    assert_eq!(a.install_name(), Some(&b"@rpath/liba.dylib"[..]));
    assert_eq!(a.rpaths(), [&b"@loader_path"[..]]);
    let re = a
        .dylibs()
        .into_iter()
        .find(|d| d.cmd == LC_REEXPORT_DYLIB)
        .unwrap();
    assert_eq!(re.name, b"@loader_path/libre.dylib");
    // Damage: cut short anywhere, they give what's there, never panic.
    for n in (0..data.len().min(4096)).step_by(7) {
        if let Ok(m) = MachO::parse(&data[..n]) {
            let _ = (m.dylibs(), m.rpaths(), m.install_name());
        }
    }
}

//! `LC_BUILD_VERSION`: the platform, its versions, and the tools that
//! built an image (MachO::build_versions, MachO::linker).

use hexcavator_macho::consts::{TOOL_LD, TOOL_LLD};
use hexcavator_macho::{BuildTool, MachO, version_string};

fn read(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/macho")
            .join(name),
    )
    .unwrap()
}

#[test]
fn linked_by_lld() {
    // (tools/macho/build.cmd: ld64.lld, -platform_version macos 13.0 13.0.)
    for name in ["program-arm64", "program-x86_64", "libsecond-arm64.dylib"] {
        let data = read(name);
        let m = MachO::parse(&data).unwrap();
        let b = m.build_versions();
        assert_eq!(b.len(), 1, "{name}");
        assert_eq!(b[0].platform, 1, "{name}");
        assert_eq!(version_string(b[0].minos), "13.0");
        assert_eq!(version_string(b[0].sdk), "13.0");
        assert_eq!(b[0].tools.len(), 1, "{name}");
        let lld = m.linker().unwrap();
        assert_eq!(lld.tool, TOOL_LLD);
        assert_eq!(lld.name(), Some("lld"));
        assert!(version_string(lld.version).starts_with("24."), "{name}");
    }
}

/// A 64-bit Mach-O header and one LC_BUILD_VERSION of `cmdsize`, with
/// `ntools` claimed and `tools` given, in either byte order.
fn image(big: bool, cmdsize: u32, ntools: u32, tools: &[(u32, u32)]) -> Vec<u8> {
    let w = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let mut d = Vec::new();
    for v in [0xFEED_FACF, 0x0100_000C, 0, 2, 1, cmdsize, 0, 0] {
        d.extend(w(v));
    }
    for v in [0x32, cmdsize, 2, 0x000E_0000, 0x000E_0200, ntools] {
        d.extend(w(v));
    }
    for &(t, v) in tools {
        d.extend(w(t));
        d.extend(w(v));
    }
    d
}

#[test]
fn ld64_in_either_byte_order() {
    for big in [false, true] {
        let data = image(big, 40, 2, &[(1, 0x000F_0000), (TOOL_LD, 0x041D_0C00)]);
        let m = MachO::parse(&data).unwrap();
        let b = m.build_versions();
        assert_eq!(b.len(), 1, "big: {big}");
        assert_eq!(
            (b[0].platform, version_string(b[0].minos)),
            (2, "14.0".into())
        );
        assert_eq!(version_string(b[0].sdk), "14.2");
        assert_eq!(b[0].tools[0].name(), Some("clang"));
        assert_eq!(
            m.linker(),
            Some(BuildTool {
                tool: TOOL_LD,
                version: 0x041D_0C00
            })
        );
        assert_eq!(version_string(m.linker().unwrap().version), "1053.12");
    }
}

#[test]
fn more_tools_claimed_than_there_is_room_for() {
    // (ntools past the command: only those within it.)
    let data = image(false, 32, 1_000_000, &[(TOOL_LD, 0x0300_0000)]);
    let m = MachO::parse(&data).unwrap();
    assert_eq!(m.build_versions()[0].tools.len(), 1);
    // A command too short for its fields: none.
    let mut data = image(false, 16, 0, &[]);
    data.truncate(48);
    let m = MachO::parse(&data).unwrap();
    assert!(m.build_versions().is_empty());
    assert_eq!(m.linker(), None);
    assert_eq!(
        BuildTool {
            tool: 99,
            version: 0
        }
        .name(),
        None
    );
}

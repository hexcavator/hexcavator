//! The Rich header, the CLR header and metadata root, and the overlay of
//! testdata's images (SizeBench's test binaries, MSVC- and lld-linked, and
//! a managed DLL; the CLR header's values are dumpbin /clrheader's).

use hexcavator_pe::PeFile;

fn images() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/sizebench/bin");
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("dll" | "exe")))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn rich_headers_check_out() {
    let mut with = 0;
    for (name, data) in images() {
        let pe = PeFile::parse_image(&data).unwrap();
        let Some(r) = pe.rich() else { continue };
        with += 1;
        // link.exe's checksum holds, and the tools made objects.
        assert!(r.valid, "{name}");
        assert!(!r.entries.is_empty(), "{name}");
        assert!(r.entries.iter().all(|e| e.count > 0), "{name}");
        assert!(r.end <= pe.file_header_offset(), "{name}");
    }
    // (Most are link.exe's; lld-link writes none.)
    assert!(with >= 10, "{with}");
    let clang = images()
        .into_iter()
        .find(|(n, _)| n.contains("ClangClx64"))
        .unwrap();
    assert!(PeFile::parse_image(&clang.1).unwrap().rich().is_none());
}

#[test]
fn a_managed_images_clr_header() {
    let (_, data) = images()
        .into_iter()
        .find(|(n, _)| n.contains("Dllx64Managed"))
        .unwrap();
    let pe = PeFile::parse_image(&data).unwrap();
    let clr = pe.clr().unwrap();
    assert_eq!(
        (clr.major_runtime_version, clr.minor_runtime_version),
        (2, 5)
    );
    assert_eq!(clr.metadata, (0x2050, 0x5D8));
    assert_eq!(clr.flags, hexcavator_pe::extras::COMIMAGE_FLAGS_ILONLY);
    assert_eq!(clr.entry_point, 0);
    assert_eq!(clr.resources, (0, 0));
    let version = String::from_utf8_lossy(clr.version.unwrap()).into_owned();
    assert!(version.starts_with('v'), "{version}");
    let streams: Vec<String> = clr
        .streams
        .iter()
        .map(|s| String::from_utf8_lossy(s.0).into_owned())
        .collect();
    assert!(streams.contains(&"#Strings".to_string()), "{streams:?}");
    assert!(
        streams.iter().any(|s| s == "#~" || s == "#-"),
        "{streams:?}"
    );
    // Each stream within the metadata.
    assert!(
        clr.streams
            .iter()
            .all(|s| u64::from(s.1) + u64::from(s.2) <= u64::from(clr.metadata.1))
    );
    // Native images have none.
    for (name, data) in images() {
        if !name.contains("Managed") {
            assert!(
                PeFile::parse_image(&data).unwrap().clr().is_none(),
                "{name}"
            );
        }
    }
}

#[test]
fn overlays_and_bound_imports() {
    for (name, data) in images() {
        let pe = PeFile::parse_image(&data).unwrap();
        // An overlay, if any, is past every section's data.
        if let Some((at, size)) = pe.overlay() {
            assert_eq!(at + size, data.len() as u64, "{name}");
        }
        // (No bound imports: modern linkers don't bind.)
        assert!(pe.bound_imports().is_empty(), "{name}");
        assert!(pe.certificates().is_empty(), "{name}");
    }
}

#[test]
fn damaged_headers_do_not_panic() {
    for (_, data) in images().into_iter().take(4) {
        let mut d = data.clone();
        for at in 0..0x400.min(d.len()) {
            let was = d[at];
            for v in [0x00, 0xFF, was ^ 0x5A] {
                d[at] = v;
                if let Ok(pe) = PeFile::parse_image(&d) {
                    let _ = (
                        pe.rich(),
                        pe.certificates(),
                        pe.bound_imports(),
                        pe.clr(),
                        pe.overlay(),
                    );
                }
            }
            d[at] = was;
        }
    }
}

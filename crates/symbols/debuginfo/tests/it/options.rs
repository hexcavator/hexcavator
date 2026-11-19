//! How each compiland was compiled (`DebugInfo::compile_options`): from
//! DWARF's DW_AT_producer, a `.GCC.command.line` section, and a PDB's
//! S_COMPILE3 and LF_BUILDINFO.

use hexcavator_debuginfo::DebugInfo;

fn testdata(path: &str) -> Vec<u8> {
    let p = format!("{}/../../../testdata/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// Each compiland's (name, options).
fn options(data: &[u8]) -> Vec<(String, hexcavator_debuginfo::CompileOptions)> {
    let d = DebugInfo::parse(data).unwrap();
    let names = d.compilands().unwrap();
    let opts = d.compile_options().unwrap();
    assert_eq!(names.len(), opts.len());
    names.into_iter().map(|c| c.name).zip(opts).collect()
}

#[test]
fn dwarf_producer() {
    let o = options(&testdata("linkopts/funcs-rec"));
    assert_eq!(o.len(), 1);
    let (name, o) = &o[0];
    assert_eq!(name, "funcs.c");
    // (Built with -fno-ident: no version, only the command line.)
    assert_eq!(o.compiler, "", "{o:?}");
    assert_eq!(
        o.args.as_deref().unwrap(),
        [
            "-O2",
            "-g",
            "-ffunction-sections",
            "-fdata-sections",
            "-c",
            "funcs.c"
        ]
    );
    // Not recorded (and -fno-ident: an empty producer).
    let o = options(&testdata("linkopts/funcs-plain"));
    assert_eq!(o[0].1, hexcavator_debuginfo::CompileOptions::default());
    // (Producers with versions: options.rs's unit tests; the fixtures here
    // are all built with -fno-ident.)
}

#[test]
fn gcc_command_line_section() {
    // (-frecord-command-line: the unit's own producer records none; the
    // command line naming its source does.)
    let o = options(&testdata("linkopts/funcs-rec-nosections-gc-icf"));
    let (_, o) = &o[0];
    assert_eq!(o.args.as_deref().unwrap(), ["-O2", "-g", "-c", "funcs.c"]);
    assert!(!o.has("-ffunction-sections"));
}

#[test]
fn pdb_build_info() {
    // main.cpp compiled with /Gy, dead.cpp with /Gy- (tools/xref/build.cmd).
    let o = options(&testdata("xref/xref-x64.pdb"));
    let of = |file: &str| {
        &o.iter()
            .find(|(n, _)| n.to_ascii_lowercase().ends_with(file))
            .unwrap_or_else(|| panic!("{file}: {o:?}"))
            .1
    };
    let main = of("main.obj");
    assert!(main.compiler.contains("Microsoft"), "{main:?}");
    assert_eq!(main.last_of(&["-Gy", "-Gy-"]), Some("-Gy"), "{main:?}");
    assert_eq!(main.last_of(&["-O1", "-O2"]), Some("-O1"), "{main:?}");
    // (cl records a switch that's on: /Gy- isn't recorded, being off by
    // default.)
    let dead = of("dead.obj");
    assert!(dead.args.is_some(), "{dead:?}");
    assert_eq!(dead.last_of(&["-Gy", "-Gy-"]), None, "{dead:?}");
    // What the linker made has no command line.
    let linker = o.iter().find(|(n, _)| n == "* Linker *").unwrap();
    assert_eq!(linker.1.args, None);
}

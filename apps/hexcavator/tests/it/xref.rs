//! `hexc xref` end to end, over the cross-reference test program
//! (tools/xref: virtual functions reached through their classes'
//! constructors, a static initializer, a table of function pointers, an
//! export, and code the linker kept that nothing reaches), built for x64
//! and ARM64.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(arch: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/xref")
        .join(format!("xref-{arch}.exe"))
}

fn hexc(args: &[&str], image: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("xref")
        .args(args)
        .arg(image)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn ok(args: &[&str], image: &Path) -> String {
    let (ok, stdout, stderr) = hexc(args, image);
    assert!(ok, "{args:?}: {stderr}");
    stdout
}

/// What nothing reaches: dead.cpp's dead_entry (kept because its section
/// is), everything only it reaches (Ghost's constructor, and so its
/// vtable, virtual functions, and RTTI), and the CRT's three variables
/// nothing refers to.
#[test]
fn unreachable() {
    let ghost = [
        "dead_entry(int)",
        "dead_helper(int)",
        "Ghost::Ghost()",
        "Ghost::`vftable'",
        "Ghost::area() const",
        "Ghost::name() const",
        "const Ghost::`RTTI Complete Object Locator'",
        "Ghost::`RTTI Base Class Descriptor at (0,-1,0,64)'",
        "Ghost::`RTTI Base Class Array'",
        "Ghost::`RTTI Class Hierarchy Descriptor'",
        "struct Ghost `RTTI Type Descriptor'",
        "`string': \"ghost\"",
        "__scrt_native_dllmain_reason",
        "_fltused",
    ];
    for (arch, extra) in [
        (
            "x64",
            &[
                "[pdata] dead_entry(int)",
                "[unwind] dead_entry(int)",
                // Ghost::area's 0.5.
                "__real@3fe0000000000000",
                "__scrt_debugger_hook_flag",
            ][..],
        ),
        ("arm64", &["[packedUnwindData-pdata] dead_entry(int)"][..]),
    ] {
        let out = ok(&["-unreachable", "-n", "0"], &fixture(arch));
        let mut names: Vec<&str> = out
            .lines()
            .skip(1)
            .map(|l| l.trim_start().split_once("  ").unwrap().1)
            .map(|l| l.rsplit_once("  [").unwrap().0)
            .collect();
        names.sort_unstable();
        let mut expected: Vec<&str> = ghost.iter().chain(extra).copied().collect();
        expected.sort_unstable();
        assert_eq!(names, expected, "{arch}");
        // Largest first.
        let sizes: Vec<u64> = out
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().next().unwrap().parse().unwrap())
            .collect();
        assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{arch}: {sizes:?}");
    }
}

/// Why the linker kept each: dead.obj (no /Gy) and three CRT objects have
/// sections that are not COMDATs; the rest are COMDATs (or the linker's
/// own data) that those refer to.
#[test]
fn kept() {
    let out = ok(&["-n", "0"], &fixture("x64"));
    assert_eq!(
        out.lines().skip(1).collect::<Vec<_>>(),
        [
            "18 unreachable (320 of 10846 bytes)",
            "         106 bytes code in sections that are not COMDATs (compile with /Gy)",
            "          24 bytes data in sections that are not COMDATs (compile with /Gw)",
            "         190 bytes that those refer to",
            "",
            "Unreachable, largest first (and why the linker kept it):",
            "          66  dead_entry(int)  [not a COMDAT, dead.obj]",
            "          36  const Ghost::`RTTI Complete Object Locator'  [from Ghost::Ghost(), dead.obj]",
            "          36  Ghost::`RTTI Base Class Descriptor at (0,-1,0,64)'  [from Ghost::Ghost(), dead.obj]",
            "          28  struct Ghost `RTTI Type Descriptor'  [from Ghost::Ghost(), dead.obj]",
            "          24  Ghost::`vftable'  [from Ghost::Ghost(), dead.obj]",
            "          20  Ghost::`RTTI Class Hierarchy Descriptor'  [from Ghost::Ghost(), dead.obj]",
            "          20  Ghost::`RTTI Base Class Array'  [from Ghost::Ghost(), dead.obj]",
            "          14  Ghost::Ghost()  [not a COMDAT, dead.obj]",
            "          12  [unwind] dead_entry(int)  [not a COMDAT, dead.obj]",
            "          12  [pdata] dead_entry(int)  [from dead_entry(int)]",
            "           9  Ghost::area() const  [not a COMDAT, dead.obj]",
            "           9  dead_helper(int)  [not a COMDAT, dead.obj]",
            "           8  Ghost::name() const  [not a COMDAT, dead.obj]",
            "           8  __real@3fe0000000000000  [from Ghost::area() const, dead.obj]",
            "           6  `string': \"ghost\"  [from Ghost::name() const, dead.obj]",
            "           4  __scrt_native_dllmain_reason  [not a COMDAT, utility.obj]",
            "           4  _fltused  [not a COMDAT, fltused.obj]",
            "           4  __scrt_debugger_hook_flag  [not a COMDAT, utility_desktop.obj]",
        ]
    );
    let out = ok(&["-why", "dead_helper"], &fixture("arm64"));
    assert!(
        out.contains("  the linker kept it with its section of dead.obj, which is not a COMDAT and has something used in it (compile with /Gy to let /OPT:REF drop it alone)\n"),
        "{out}"
    );
    let out = ok(&["-why", "Ghost::`vftable'"], &fixture("arm64"));
    assert!(
        out.contains("  the linker kept it because Ghost::Ghost() refers to it"),
        "{out}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&ok(&["-json", "-n", "1"], &fixture("x64"))).unwrap();
    assert_eq!(v["kept"]["codeNotComdat"], 106);
    assert_eq!(v["kept"]["referencedByThose"], 190);
    assert_eq!(
        v["unreachable"][0]["object"]
            .as_str()
            .unwrap()
            .rsplit('\\')
            .next(),
        Some("dead.obj")
    );
    assert_eq!(v["unreachable"][0]["comdat"], false);
}

/// The chain to each kind of reference, on both architectures.
#[test]
fn why() {
    for arch in ["x64", "arm64"] {
        let image = fixture(arch);
        let why = |name: &str| ok(&["-why", name], &image);
        // A virtual function: through the constructor and the vtable.
        let out = why("Square::area() const");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Square::area() const:", "{arch}: {out}");
        assert_eq!(
            lines[1], "  mainCRTStartup(void*)  (the entry point)",
            "{arch}: {out}"
        );
        assert_eq!(
            lines[lines.len() - 4..],
            [
                "    calls make_shape(int)",
                // x64 tail-calls the constructor; ARM64 calls it.
                if arch == "x64" {
                    "    jumps to Square::Square(double)"
                } else {
                    "    calls Square::Square(double)"
                },
                "    refers to Square::`vftable'",
                "    points to Square::area() const",
            ],
            "{arch}: {out}"
        );
        // By its name without the parameters, the same.
        assert_eq!(why("Square::area"), out);
        // A static initializer's work.
        let out = why("Circle::Circle(double)");
        assert_eq!(
            out,
            "Circle::Circle(double):\n  [.CRT$XCU]  (the initializers in .CRT$XCU)\n    points to `dynamic initializer for 'unit_circle''()\n    calls Circle::Circle(double)\n",
            "{arch}"
        );
        // Through a table of pointers.
        assert!(
            why("op_sub").ends_with("    refers to ops\n    points to op_sub(int)\n"),
            "{arch}"
        );
        // An export.
        assert_eq!(
            why("exported_twice"),
            "exported_twice(int):\n  exported_twice(int)  (exported as exported_twice)\n"
        );
        // An SEH filter: through its function's exception data.
        let out = why("`__scrt_common_main_seh'::`1'::filt$0()");
        assert!(out.contains("    owns [unwind] __scrt_common_main_seh()\n    points to `__scrt_common_main_seh'::`1'::filt$0()\n"), "{arch}: {out}");
        // Unreached, with what refers to it.
        assert_eq!(
            why("Ghost::area() const"),
            "Ghost::area() const: no root reaches it\n  the linker kept it with its section of dead.obj, which is not a COMDAT and has something used in it (compile with /Gy to let /OPT:REF drop it alone)\n  what refers to it (none reached):\n    dead_entry(int) calls it\n    Ghost::`vftable' points to it\n",
            "{arch}"
        );
        assert_eq!(
            why("dead_entry"),
            "dead_entry(int): no root reaches it\n  the linker kept it with its section of dead.obj, which is not a COMDAT and has something used in it (compile with /Gy to let /OPT:REF drop it alone)\n  and nothing refers to it\n"
        );
    }
}

#[test]
fn refs() {
    let out = ok(&["-refs", "Ghost::`vftable'"], &fixture("x64"));
    assert_eq!(
        out,
        "Ghost::`vftable' (24 bytes, unreachable)\n\
         \x20 referred to by:\n\
         \x20   Ghost::Ghost() refers to it\n\
         \x20 refers to:\n\
         \x20   points to Ghost::`scalar deleting destructor'(unsigned int)\n\
         \x20   points to Ghost::area() const\n\
         \x20   points to Ghost::name() const\n\
         \x20   owns const Ghost::`RTTI Complete Object Locator'\n"
    );
}

#[test]
fn json() {
    let image = fixture("arm64");
    let v: serde_json::Value = serde_json::from_str(&ok(&["-json", "-n", "3"], &image)).unwrap();
    assert_eq!(v["unreachableCount"], 15);
    assert_eq!(v["unreachable"].as_array().unwrap().len(), 3);
    assert_eq!(v["unreachable"][0]["name"], "dead_entry(int)");
    assert_eq!(v["unreachable"][0]["code"], true);
    let v: serde_json::Value =
        serde_json::from_str(&ok(&["-json", "-why", "op_add"], &image)).unwrap();
    assert_eq!(v["reached"], true);
    assert_eq!(v["root"]["reason"], "the entry point");
    let chain = v["chain"].as_array().unwrap();
    assert_eq!(chain.last().unwrap()["edge"], "points to");
    assert_eq!(chain.last().unwrap()["name"], "op_add(int)");
    let v: serde_json::Value =
        serde_json::from_str(&ok(&["-json", "-why", "dead_helper"], &image)).unwrap();
    assert_eq!(v["reached"], false);
    let v: serde_json::Value =
        serde_json::from_str(&ok(&["-json", "-refs", "inner"], &image)).unwrap();
    assert_eq!(v["referrers"][0]["name"], "outer(int)");
    assert_eq!(v["referrers"][0]["edge"], "calls");
}

#[test]
fn summary_and_errors() {
    let image = fixture("x64");
    let out = ok(&["-n", "2"], &image);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].ends_with(" roots"), "{out}");
    assert!(lines[1].starts_with("18 unreachable ("), "{out}");
    assert_eq!(
        lines[6],
        "Unreachable, largest first (and why the linker kept it):"
    );
    assert!(lines[9].starts_with("  (16 more"), "{out}");

    let (good, _, stderr) = hexc(&["-why", "nope"], &image);
    assert!(!good && stderr.contains("nothing named 'nope'"), "{stderr}");
    let (good, _, stderr) = hexc(&["-bogus"], &image);
    assert!(
        !good && stderr.contains("unknown option 'bogus'"),
        "{stderr}"
    );
    let (good, _, stderr) = hexc(&["-n", "x"], &image);
    assert!(!good && stderr.contains("-n needs a number"), "{stderr}");
    // -why takes the image as its name, leaving none.
    let (good, _, stderr) = hexc(&["-why"], &image);
    assert!(!good && stderr.contains("no image given"), "{stderr}");
    let (good, _, stderr) = hexc(&["a.exe"], &image);
    assert!(!good && stderr.contains("unexpected argument"), "{stderr}");
}

/// The SizeBench test DLLs: each export and DllMain reached, and most of
/// the image.
#[test]
fn sizebench_dlls() {
    let dll = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sizebench/bin/CppTestCases_BasicDiffObjectsAfter.dll");
    let out = ok(&["-why", "DllMain"], &dll);
    assert!(out.contains("(the entry point)"), "{out}");
    let v: serde_json::Value = serde_json::from_str(&ok(&["-json", "-n", "0"], &dll)).unwrap();
    assert!(v["nodes"].as_u64().unwrap() > 100);
}

/// The vtables no code refers to: Tag's, whose only object is initialized
/// at compile time.
#[test]
fn vtables() {
    for arch in ["x64", "arm64"] {
        let image = fixture(arch);
        assert_eq!(
            ok(&["-vtables"], &image),
            "9 vtables; 1 that no code refers to (8 bytes), largest first:\n\
             \x20        8  Tag::`vftable'\n\
             \x20             tag points to it\n",
            "{arch}"
        );
        assert!(
            ok(&["-why", "Tag::label"], &image).ends_with(
                "    refers to named\n    points to tag\n    points to Tag::`vftable'\n    points to Tag::label() const\n"
            ),
            "{arch}"
        );
        let v: serde_json::Value =
            serde_json::from_str(&ok(&["-vtables", "-json"], &image)).unwrap();
        assert_eq!(v["vtables"], 9);
        assert_eq!(v["list"][0]["referrers"][0]["name"], "tag");
        assert_eq!(v["list"][0]["reached"], true);
    }
}

/// Functions the linker could have folded: none in the test program, which
/// is linked with /OPT:ICF.
#[test]
fn identical() {
    for arch in ["x64", "arm64"] {
        let out = ok(&["-identical"], &fixture(arch));
        assert!(
            out.starts_with("0 groups of identical functions"),
            "{arch}: {out}"
        );
        let v: serde_json::Value =
            serde_json::from_str(&ok(&["-identical", "-json"], &fixture(arch))).unwrap();
        assert_eq!(v["groups"], 0);
    }
}

/// Two builds compared: the same program with `inner` renamed is the same
/// functions, one renamed; `outer`, which calls it, is unchanged (it calls
/// the same function, by another name).
#[test]
fn compare_builds() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/xref");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "xref".as_ref(),
            dir.join("xref-x64-renamed.exe").as_os_str(),
            "--".as_ref(),
        ])
        .arg(dir.join("xref-x64.exe"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = text.lines().next().unwrap();
    assert!(
        first.ends_with(" unchanged, 0 changed, 1 renamed, 0 added, 0 removed"),
        "{text}"
    );
    assert!(
        text.contains("Renamed (the same code, another name), largest first:\n        10  inner_renamed(int)\n            was inner(int)\n"),
        "{text}"
    );
    // A build against itself: all unchanged.
    let image = fixture("arm64");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "xref".as_ref(),
            "-json".as_ref(),
            image.as_os_str(),
            "--".as_ref(),
            image.as_os_str(),
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["unchanged"].as_u64().unwrap() > 50, "{v}");
    for k in ["changedCount", "renamedCount", "addedCount", "removedCount"] {
        assert_eq!(v[k], 0, "{k}");
    }
    // SizeBench's pair: FunctionInStaticLib2 became FunctionInStaticLib3
    // with the same code (renamed), DllMain grew, and the C++ stream code
    // came in.
    let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/sizebench/bin");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["xref", "-n", "0"])
        .arg(bin.join("CppTestCases_BasicDiffObjectsAfter.dll"))
        .arg("--")
        .arg(bin.join("CppTestCases_BasicDiffObjectsBefore.dll"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains(" 1 renamed, 8 added, 0 removed"), "{text}");
    assert!(
        text.contains("       +41  DllMain(HINSTANCE__*, unsigned long, void*)\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "        50  FunctionInStaticLib3(int)\n            was FunctionInStaticLib2(int)\n"
        ),
        "{text}"
    );
    assert!(!text.contains("Removed,"), "{text}");
    // Options go before the base image.
    let (good, _, stderr) = hexc(&["--", "a.exe", "-n"], &image);
    assert!(!good && stderr.contains("unexpected argument"), "{stderr}");
}

/// Rust trait objects' vtables have no symbols: the unlabeled data they
/// are in is split where code takes their addresses, so a closure called
/// through one is reached through that one alone.
#[test]
fn unlabeled_vtables() {
    let dll = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sizebench/bin/sizebenchv2_analysisengine_tests_rust.dll");
    let out = ok(&["-why", "rustc_demangle::demangle()"], &dll);
    assert!(
        out.contains("(exported as exported_function_to_root_code)"),
        "{out}"
    );
    assert!(
        out.contains(
            "    calls std::sys_common::backtrace::_print_fmt::closure$1()\n\
             \x20   refers to [unnamed data in .rdata at 0x1c6f0]\n\
             \x20   points to std::sys_common::backtrace::_print_fmt::closure$1::closure$0()\n"
        ),
        "{out}"
    );
    let out = ok(&["-unreachable", "-n", "0"], &dll);
    assert_eq!(
        out,
        "Unreachable, largest first (and why the linker kept it):\n           4  _fltused  [not a COMDAT, fltused.obj]\n           4  __scrt_native_dllmain_reason  [not a COMDAT, utility.obj]\n"
    );
}

/// Recommendations for the test program: dead.obj (compiled without /Gy)
/// keeps 308 bytes nothing reaches; the link already uses /OPT:REF and
/// /OPT:ICF, and the CRT's objects can't be rebuilt.
#[test]
fn recommend() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("recommend")
        .arg(fixture("x64"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "The link: /OPT:REF on, /OPT:ICF on.", "{text}");
    assert_eq!(
        lines[1], "1 recommendation, saving 308 bytes in all:",
        "{text}"
    );
    assert!(lines[3].ends_with("308  compile dead.obj with /Gy: its functions nothing reaches are kept with the sections they share with ones that are used"), "{text}");
    assert!(lines[4].ends_with("66    dead_entry(int)"), "{text}");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-json"])
        .arg(fixture("arm64"))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["link"]["optRef"], true);
    let recs = v["recommendations"].as_array().unwrap();
    assert_eq!(recs.len(), 1, "{v}");
    assert!(
        recs[0]["advice"]
            .as_str()
            .unwrap()
            .starts_with("compile dead.obj with /Gy")
    );
    assert_eq!(recs[0]["saving"], v["saving"]);
}

fn elf(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/elf")
        .join(name)
}

/// ELF: a static executable (every address resolved in place: data's
/// words taken as pointers) whose second compile unit nothing calls, and
/// a shared object whose exports are its roots.
#[test]
fn elf_images() {
    let (ok, out, err) = hexc(&["-json"], &elf("dwarf5-x86_64-linux-gnu"));
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let unreached: Vec<&str> = v["unreachable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        unreached,
        ["second_table", "second_sum(int)", "second_len()"]
    );
    // Each in its compile unit, in ELF's terms.
    let (ok, out, _) = hexc(&[], &elf("dwarf5-x86_64-linux-gnu"));
    assert!(ok);
    assert!(out.contains("[maybe its own section, second.c]"), "{out}");
    assert!(!out.contains("COMDAT"), "{out}");
    let (ok, out, _) = hexc(&["-why", "second_sum"], &elf("dwarf5-x86_64-linux-gnu"));
    assert!(ok);
    assert!(out.contains("--gc-sections"), "{out}");
    // A shared object: every function is exported, so reached.
    let (ok, out, err) = hexc(&[], &elf("program.so"));
    assert!(ok, "{err}");
    assert!(out.contains("0 unreachable"), "{out}");
    let (ok, out, _) = hexc(&["-why", "compute"], &elf("program.so"));
    assert!(ok);
    assert!(out.contains("exported as compute"), "{out}");
}

/// Mach-O: an executable (its DWARF given) whose entry point and exports
/// (an executable's external symbols) are its roots.
#[test]
fn macho_images() {
    let macho = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/macho");
    let dwarf = macho.join("program-arm64.dwarf");
    let image = macho.join("program-arm64");
    let (ok, out, err) = hexc(&["-pdb", dwarf.to_str().unwrap()], &image);
    assert!(ok, "{err}");
    assert!(out.contains("0 unreachable"), "{out}");
    let (ok, out, _) = hexc(&["-pdb", dwarf.to_str().unwrap(), "-why", "start"], &image);
    assert!(ok);
    assert!(out.contains("the entry point"), "{out}");
    let (ok, out, _) = hexc(
        &["-pdb", dwarf.to_str().unwrap(), "-why", "compute"],
        &image,
    );
    assert!(ok);
    assert!(out.contains("exported as _compute"), "{out}");
}

/// ELF images get advice in GCC's and Clang's terms, judged from the image
/// (nothing records the link's options): `second.c`'s functions and data
/// nothing reaches were kept, so nothing collected them.
#[test]
fn recommend_elf() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("recommend")
        .arg(elf("dwarf5-x86_64-linux-gnu"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "The link's options aren't recorded: what it dropped and folded is judged from the image.",
        "{text}"
    );
    assert_eq!(
        lines[1], "1 recommendation, saving 209 bytes in all:",
        "{text}"
    );
    assert!(lines[3].ends_with("209  link with -Wl,--gc-sections (compiling with -ffunction-sections -fdata-sections): functions and data nothing reaches are kept"), "{text}");
    assert!(!text.contains("/OPT") && !text.contains("PDB"), "{text}");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-json"])
        .arg(elf("dwarf5-x86_64-linux-gnu"))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["toolchain"], "gnu");
    assert!(v["link"].is_null());
    assert_eq!(v["saving"], 209);
}

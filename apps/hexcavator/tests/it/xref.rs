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

/// Mach-O: an executable (its DWARF given) whose entry point is its root,
/// and not its exports (an executable's external symbols), which
/// -dead_strip drops unless they're reached (or it's linked with
/// -export_dynamic). (A dylib's exports are roots.)
#[test]
fn macho_images() {
    let macho = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/macho");
    let dwarf = macho.join("program-arm64.dwarf");
    let image = macho.join("program-arm64");
    let (ok, out, err) = hexc(&["-pdb", dwarf.to_str().unwrap()], &image);
    assert!(ok, "{err}");
    // second_sum, exported but uncalled; and the program's stand-in for
    // dyld's __tlv_bootstrap, which its thread-local variable's descriptor
    // names in a way not seen here (a real program imports it).
    assert!(out.contains("2 unreachable"), "{out}");
    assert!(out.contains("second_sum(int)"), "{out}");
    let (ok, out, _) = hexc(&["-pdb", dwarf.to_str().unwrap(), "-why", "start"], &image);
    assert!(ok);
    assert!(out.contains("the entry point"), "{out}");
    let (ok, out, _) = hexc(
        &["-pdb", dwarf.to_str().unwrap(), "-why", "compute"],
        &image,
    );
    assert!(ok);
    assert!(out.contains("start()  (the entry point)"), "{out}");
}

/// ELF images get advice in GCC's and Clang's terms, judged from the image
/// (nothing records the link's options): `second.c`'s functions and data
/// nothing reaches were kept, so nothing collected them.
#[test]
fn recommend_without_debug_information() {
    // Nothing to find for it: what the image's structure shows.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("recommend")
        .arg(elf("relr-rela.so"))
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
        "No debug information: only what the image's structure shows (give it with -debug for the rest).",
        "{text}"
    );
    assert_eq!(
        lines[1], "1 recommendation, saving 192 bytes in all:",
        "{text}"
    );
    assert!(lines[3].contains("pack-relative-relocs"), "{text}");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-json"])
        .arg(elf("relr-rela.so"))
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["debug"], false);
    assert!(v["judged"].is_null() && v["link"].is_null(), "{v}");
    assert_eq!(v["recommendations"][0]["kind"], "relr", "{v}");
    // Already packed: nothing.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("recommend")
        .arg(elf("relr.so"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("No recommendations")
    );
    // Debug information given, but not found: still an error.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-debug", "no-such-file"])
        .arg(elf("relr-rela.so"))
        .output()
        .unwrap();
    assert!(!out.status.success());
}

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
        "The link's options aren't recorded: as the image shows it, the link didn't collect unreferenced functions (--gc-sections) and didn't fold identical ones (ICF).",
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

/// What a link without recorded options did, judged from what it left
/// (tools/linkopts: one program linked with and without --gc-sections and
/// --icf=all), and the recommendations that follow: none for what it did.
#[test]
fn recommend_judges_the_link() {
    let linkopts = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/linkopts")
            .join(name)
    };
    let recommend = |name: &str| -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .args(["recommend", "-json"])
            .arg(linkopts(name))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let kinds = |v: &serde_json::Value| -> Vec<String> {
        let mut k: Vec<String> = v["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["kind"].as_str().unwrap().to_string())
            .collect();
        k.sort();
        k
    };
    // (name, collected, folded, what's recommended)
    let cases: [(&str, bool, bool, &[&str]); 7] = [
        ("funcs-plain", false, false, &["gc", "icf"]),
        ("funcs-gc", true, false, &["icf"]),
        ("funcs-icf", false, true, &["gc"]),
        ("funcs-gc-icf", true, true, &[]),
        // (Nothing unreferenced to collect. Folded across compile units:
        // the DWARF of both at one address; and work<N>, with an LSDA,
        // which lld's ICF never folds.)
        // (work<1> and work<2>, which ICF doesn't fold, differ only in a
        // constant: near-identical.)
        ("eh-icf", false, true, &["near-identical"]),
        // (Without ICF, only plain<N>: work<N> has an LSDA, and use<N>
        // calls different work<N>.)
        ("eh", false, false, &["icf", "near-identical"]),
        // (Only data folded: nothing says the link folded functions,
        // and there are none to fold.)
        ("dup-icf", false, false, &[]),
    ];
    for (name, collected, folded, want) in cases {
        let v = recommend(name);
        assert!(v["link"].is_null(), "{name}");
        assert_eq!(v["judged"]["optRef"], collected, "{name}: {v}");
        assert_eq!(v["judged"]["optIcf"], folded, "{name}: {v}");
        assert_eq!(kinds(&v), want, "{name}: {v}");
    }
    let v = recommend("funcs-plain");
    let icf = &v["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "icf")
        .unwrap()["examples"];
    assert_eq!(icf[0]["name"], "add_a(int, int) (3 copies)", "{v}");
    let v = recommend("eh");
    let icf = v["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "icf")
        .unwrap();
    assert_eq!(icf["examples"].as_array().unwrap().len(), 1, "{v}");
    assert!(
        icf["examples"][0]["name"]
            .as_str()
            .unwrap()
            .starts_with("plain<"),
        "{v}"
    );
    // Duplicated variables: constants copied from one definition (the
    // header's lut, dup.c's tag, three times each), not variables, nor
    // other.c's tag, alike but defined apart.
    let v = recommend("dup");
    assert_eq!(kinds(&v), ["duplicates"], "{v}");
    let examples: Vec<&str> = v["recommendations"][0]["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(examples, ["lut (3 copies)", "tag (3 copies)"], "{v}");
    // (Compiled without -ffunction-sections, the link's --gc-sections and
    // --icf=all have nothing to drop or fold, and leave no evidence: the
    // advice says to compile so.)
    let v = recommend("funcs-nosections-gc-icf");
    for r in v["recommendations"].as_array().unwrap() {
        assert!(
            r["advice"]
                .as_str()
                .unwrap()
                .contains("compiling with -ffunction-sections"),
            "{v}"
        );
    }
    // Its options recorded (in DW_AT_producer), with -ffunction-sections
    // and -fdata-sections: the advice needn't say to compile so.
    let v = recommend("funcs-rec");
    assert_eq!(kinds(&v), ["gc", "icf"], "{v}");
    let advice: Vec<&str> = v["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["advice"].as_str().unwrap())
        .collect();
    assert!(advice.iter().all(|a| !a.contains("compiling with")), "{v}");
    // Recorded (in .GCC.command.line) without them: the link can't be
    // judged, nothing is foldable, and what nothing reaches is kept with
    // funcs.c's sections, its functions' and its data's.
    let v = recommend("funcs-rec-nosections-gc-icf");
    assert!(v["judged"].is_null() && v["debug"] == true, "{v}");
    assert_eq!(kinds(&v), ["data-sections", "function-sections"], "{v}");
    for r in v["recommendations"].as_array().unwrap() {
        let a = r["advice"].as_str().unwrap();
        assert!(
            a.starts_with("compile funcs.c with -f")
                && a.contains("(and link with -Wl,--gc-sections)"),
            "{v}"
        );
    }
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("recommend")
        .arg(linkopts("funcs-rec-nosections-gc-icf"))
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("The link's options aren't recorded, and its objects were compiled without -ffunction-sections"),
        "{text}"
    );
}

/// What a Mach-O link did, judged from the image (testdata/linkopts's
/// macho-*: ld64.lld's links of one object, and two marked as Apple's
/// ld's), and the advice in Apple's terms.
#[test]
fn recommend_judges_a_macho_link() {
    let run = |args: &[&str], name: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("recommend")
            .args(args)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../testdata/linkopts")
                    .join(name),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let recommend =
        |name: &str| -> serde_json::Value { serde_json::from_str(&run(&["-json"], name)).unwrap() };
    let advice = |v: &serde_json::Value, kind: &str| -> Option<String> {
        v["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind)
            .map(|r| r["advice"].as_str().unwrap().to_string())
    };
    // (name, collected, folded, gc recommended, ICF recommended)
    let cases = [
        ("macho-plain", false, false, true, true),
        // (ld64.lld's ICF keeps the folded functions' symbols, at the
        // kept one's address.)
        ("macho-icf", false, true, true, false),
        // (-dead_strip drops even an executable's exports: their DWARF is
        // in the debug map's object, their symbols aren't in the image.)
        ("macho-dead", true, false, false, true),
        ("macho-dead-icf", true, true, false, false),
        // Apple's ld folds unless given -no_deduplicate, which clang
        // gives it at -O0 and -O1: -O2 recorded, it's taken to have.
        ("macho-ld", false, true, true, false),
        ("macho-ld-O1", false, false, true, true),
    ];
    for (name, collected, folded, gc, icf) in cases {
        let v = recommend(name);
        assert_eq!(v["toolchain"], "apple", "{name}");
        assert_eq!(v["judged"]["optRef"], collected, "{name}: {v}");
        assert_eq!(v["judged"]["optIcf"], folded, "{name}: {v}");
        assert_eq!(advice(&v, "gc").is_some(), gc, "{name}: {v}");
        assert_eq!(advice(&v, "icf").is_some(), icf, "{name}: {v}");
    }
    let v = recommend("macho-plain");
    assert!(
        advice(&v, "gc")
            .unwrap()
            .starts_with("link with -Wl,-dead_strip"),
        "{v}"
    );
    assert!(
        advice(&v, "icf").unwrap().starts_with(
            "link with -Wl,--icf=all (ld64.lld; Apple's ld folds them unless given -no_deduplicate)"
        ),
        "{v}"
    );
    let v = recommend("macho-ld-O1");
    assert!(
        advice(&v, "icf")
            .unwrap()
            .starts_with("link without -no_deduplicate"),
        "{v}"
    );
    let text = run(&[], "macho-ld");
    assert!(
        text.lines()
            .nth(1)
            .unwrap()
            .starts_with("(Apple's ld linked it:"),
        "{text}"
    );
    assert!(!run(&[], "macho-plain").contains("Apple's ld linked it"));
}

/// What an ELF shared object's exports cost, and what hiding them would
/// save (testdata/linkopts's libexp*.so, without debug information, and
/// exp-main, which imports exp_used).
#[test]
fn recommend_exports() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkopts");
    let recommend = |args: &[&str], name: &str| -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("recommend")
            .arg("-json")
            .args(args)
            .arg(dir.join(name))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let rec = |v: &serde_json::Value, kind: &str| -> Option<serde_json::Value> {
        v["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind)
            .cloned()
    };
    let names = |r: &serde_json::Value| -> Vec<String> {
        let mut v: Vec<String> = r["examples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };
    // Template instantiations (Box<T>::get, ::twice), exported, and called
    // through the PLT; and its calls to its own exports.
    let v = recommend(&[], "libexp.so");
    assert_eq!(v["debug"], false);
    assert!(v["importers"].is_null());
    let vague = rec(&v, "vague-linkage").unwrap();
    assert!(
        vague["advice"]
            .as_str()
            .unwrap()
            .contains("it exports 8 template instantiations and inline functions"),
        "{v}"
    );
    assert!(
        names(&vague).iter().all(|n| n.starts_with("Box<")),
        "{vague}"
    );
    let calls = rec(&v, "bsymbolic").unwrap();
    assert_eq!(
        names(&calls),
        ["exp_helper(int)", "exp_internal_a(int)", "exp_used(int)"],
        "{calls}"
    );
    // (Without importers, which exports are its API isn't known.)
    assert!(rec(&v, "visibility").is_none(), "{v}");
    // Its importer imports exp_used: the rest of its own exports aren't.
    for importers in [&["-importers", "exp-main"][..], &["-importers", "."]] {
        let args: Vec<String> = importers
            .iter()
            .map(|a| {
                if *a == "-importers" {
                    a.to_string()
                } else {
                    dir.join(a).to_string_lossy().into_owned()
                }
            })
            .collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let v = recommend(&args, "libexp.so");
        // (Of the directory's files, only exp-main loads it.)
        assert_eq!(v["importers"], 1, "{v}");
        let hide = rec(&v, "visibility").unwrap();
        assert_eq!(
            names(&hide),
            [
                "exp_helper(int)",
                "exp_internal_a(int)",
                "exp_internal_b(int)",
                "exp_unused(int)"
            ],
            "{hide}"
        );
        assert!(
            hide["advice"]
                .as_str()
                .unwrap()
                .ends_with("4 exported symbols aren't imported by the importer given"),
            "{hide}"
        );
    }
    // An importer that doesn't load it: none of its exports are imported.
    let funcs = dir.join("funcs-plain").to_string_lossy().into_owned();
    let v = recommend(&["-importers", &funcs], "libexp.so");
    assert_eq!(v["importers"], 0, "{v}");
    assert!(
        rec(&v, "visibility").unwrap()["advice"]
            .as_str()
            .unwrap()
            .contains("5 exported symbols aren't imported by any importer"),
        "{v}"
    );
    // -Bsymbolic-functions: no calls through the PLT; its template
    // instantiations cost only their entries.
    let v = recommend(&[], "libexp-bsymbolic.so");
    assert!(rec(&v, "bsymbolic").is_none(), "{v}");
    assert!(
        rec(&v, "vague-linkage").unwrap()["saving"].as_u64()
            < rec(&recommend(&[], "libexp.so"), "vague-linkage").unwrap()["saving"].as_u64(),
        "{v}"
    );
    // -fvisibility=hidden: only its API is exported, two of which call
    // each other through the PLT.
    let v = recommend(&[], "libexp-hidden.so");
    assert!(rec(&v, "vague-linkage").is_none(), "{v}");
    assert_eq!(
        names(&rec(&v, "bsymbolic").unwrap()),
        ["exp_helper(int)", "exp_used(int)"],
        "{v}"
    );
}

/// Near-identical functions: templates' instantiations alike but for the
/// sizes of what they work on, or what they call (testdata/linkopts/near:
/// total<T>, apply<F>), and not those that differ (pick<T>).
#[test]
fn recommend_near_identical() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-json"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkopts/near"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let near = v["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "near-identical")
        .unwrap_or_else(|| panic!("{v}"));
    let examples: Vec<&str> = near["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(examples.iter().any(|e| e.starts_with("total<>")), "{v}");
    assert!(examples.contains(&"apply<> (2 versions)"), "{v}");
    assert!(!examples.iter().any(|e| e.starts_with("pick<>")), "{v}");
    // At most all but the largest version of each.
    let saving = near["saving"].as_u64().unwrap();
    let sum: u64 = near["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["size"].as_u64().unwrap())
        .sum();
    assert_eq!(saving, sum, "{v}");
}

/// Inlining weighed: testdata/linkopts/inline's mix, inlined into 12
/// functions, would cost less called (each call estimated by its two
/// parameters); nothing else is worth it.
#[test]
fn recommend_inlining() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["recommend", "-json"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkopts/inline"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = v["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "inlining")
        .unwrap_or_else(|| panic!("{v}"));
    assert!(
        r["advice"]
            .as_str()
            .unwrap()
            .starts_with("mark a function __attribute__((noinline))"),
        "{r}"
    );
    let e = &r["examples"][0];
    let name = e["name"].as_str().unwrap();
    assert!(name.starts_with("mix (12 copies, "), "{r}");
    // As calls: 12 × (5 + 2 × 5 + 8), and a copy of the largest with a
    // return.
    let inlined: u64 = name
        .trim_start_matches("mix (12 copies, ")
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let as_calls: u64 = name
        .split("; ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(as_calls > 12 * 23, "{r}");
    assert_eq!(e["size"].as_u64().unwrap(), inlined - as_calls, "{r}");
    assert_eq!(r["examples"].as_array().unwrap().len(), 1, "{r}");
}

/// What an image's strings recommend: the build's paths (testdata/
/// linkopts/strings: four __FILE__s under /home/user/project, as #line
/// sets them), and string literals with copies (msvc-strs-nogf.exe, /GF-:
/// two, in each of two objects; msvc-strs-gf.exe, /GF: pooled, none), but
/// not named arrays alike (strings' banner_a and banner_b).
#[test]
fn recommend_strings() {
    let recommend = |name: &str| -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .args(["recommend", "-json"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../testdata/linkopts")
                    .join(name),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let rec = |v: &serde_json::Value, kind: &str| {
        v["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind)
            .cloned()
    };
    let v = recommend("strings");
    let paths = rec(&v, "build-paths").unwrap_or_else(|| panic!("{v}"));
    assert!(
        paths["advice"]
            .as_str()
            .unwrap()
            .starts_with("compile with -fmacro-prefix-map=/home/user/project=. "),
        "{paths}"
    );
    // ("/home/user/project" less the "." it becomes: 17 bytes a path.)
    assert_eq!(paths["saving"], 4 * 17, "{paths}");
    assert_eq!(paths["examples"][0]["name"], "/home/user/project (4 paths)");
    assert!(rec(&v, "duplicate-strings").is_none(), "{v}");
    let v = recommend("msvc-strs-nogf.exe");
    let dups = rec(&v, "duplicate-strings").unwrap_or_else(|| panic!("{v}"));
    assert!(
        dups["advice"]
            .as_str()
            .unwrap()
            .starts_with("compile with /GF"),
        "{dups}"
    );
    assert_eq!(dups["saving"], 47 + 46, "{dups}");
    assert_eq!(
        dups["examples"][0]["name"],
        "\"the same literal in two objects, pooled or not\" (2 copies)"
    );
    let v = recommend("msvc-strs-gf.exe");
    assert!(rec(&v, "duplicate-strings").is_none(), "{v}");
}

/// What exception handling costs each function, and the cleanups nothing a
/// function calls can throw through (testdata/linkopts/noexc: needless()
/// calls only helper(), which can't throw; needed() calls thrower(),
/// which throws); none in a C++ image built without them (eh's work<N>
/// call what isn't resolved: it may throw).
#[test]
fn recommend_exceptions() {
    let recommend = |name: &str| -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .args(["recommend", "-json"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../testdata/linkopts")
                    .join(name),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let v = recommend("noexc");
    let e = &v["exceptions"];
    let f = |name: &str| {
        e["functions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name}: {e}"))
    };
    // Each with an FDE; the two with cleanups with an LSDA each.
    for name in [
        "needless(int)",
        "needed(int)",
        "thrower(int)",
        "helper(int)",
    ] {
        assert!(f(name)["unwind"].as_u64().unwrap() > 0, "{name}: {e}");
    }
    assert!(f("needless(int)")["handlers"].as_u64().unwrap() > 0, "{e}");
    assert_eq!(f("needless(int)")["needless"], true, "{e}");
    assert_eq!(f("needed(int)")["needless"], false, "{e}");
    assert_eq!(f("helper(int)")["handlers"], 0, "{e}");
    let total: u64 = e["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["handlers"].as_u64().unwrap())
        .sum();
    assert_eq!(e["handlers"].as_u64().unwrap(), total, "{e}");
    let v = recommend("eh");
    assert!(
        v["exceptions"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["needless"] == false),
        "{v}"
    );
}

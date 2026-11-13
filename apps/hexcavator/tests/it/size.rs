//! `hexc size` end to end, over SizeBench's test binaries.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sizebench/bin")
        .join(name)
}

fn hexc(args: &[&std::ffi::OsStr]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("size")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn sizebench_mode_matches_the_oracle() {
    let image = bin("SizeBenchV2.AnalysisEngine.Tests.CppDll.dll");
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-sizebench".as_ref()]);
    assert!(ok, "{stderr}");
    let oracle = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/sizebench/oracle/SizeBenchV2.AnalysisEngine.Tests.CppDll.txt"),
    )
    .unwrap();
    let expected: Vec<&str> = oracle
        .lines()
        .filter(|l| !l.starts_with("SYMBOL "))
        .collect();
    let actual: Vec<&str> = stdout.lines().collect();
    assert_eq!(actual, expected);
}

#[test]
fn table_mode() {
    let image = bin("PEParser.Tests.Dllx64.dll");
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-top".as_ref(), "3".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("(x64)"));
    assert!(stdout.contains("PEParser.Tests.Dllx64.pdb"));
    // Every section, with its groups indented below it.
    for name in [
        ".text", ".rdata", ".data", ".pdata", ".gfids", ".rsrc", ".reloc",
    ] {
        assert!(
            stdout.lines().any(|l| l.starts_with(&format!("{name} "))),
            "{name}"
        );
    }
    assert!(stdout.contains("\n  .text$mn "));
    assert!(stdout.contains("\n  [base relocations] "));
    // Totals and the top 3 libraries and compilands.
    assert!(stdout.contains("Total                                   950,272        949,902"));
    assert!(stdout.contains("Libraries: 9 (by file size, top 3)"));
    assert!(stdout.contains("Compilands: 38 (by file size, top 3)"));
    let libraries = stdout
        .split("Libraries:")
        .nth(1)
        .unwrap()
        .split("Compilands:")
        .next()
        .unwrap();
    assert_eq!(libraries.lines().filter(|l| l.contains(":\\")).count(), 3);
    assert!(stdout.contains("Attributed to compilands: "));
}

#[test]
fn explicit_pdb() {
    let image = bin("PEParser.Tests.Dllx64.dll");
    let pdb = bin("PEParser.Tests.Dllx64.pdb");
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-pdb".as_ref(), pdb.as_os_str()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("PEParser.Tests.Dllx64.pdb"));
}

#[test]
fn errors() {
    // Another binary's PDB.
    let image = bin("PEParser.Tests.Dllx64.dll");
    let other = bin("PEParser.Tests.Dllx86.pdb");
    let (ok, _, stderr) = hexc(&[image.as_os_str(), "-pdb".as_ref(), other.as_os_str()]);
    assert!(!ok);
    assert!(stderr.contains("does not match"), "{stderr}");

    // Managed code, and a /DEBUG:FASTLINK PDB.
    let (ok, _, stderr) =
        hexc(&[bin("SizeBenchV2.AnalysisEngine.Tests.Dllx64Managed.dll").as_os_str()]);
    assert!(!ok);
    assert!(stderr.contains("managed code"), "{stderr}");
    let (ok, _, stderr) =
        hexc(&[bin("SizeBenchV2.AnalysisEngine.Tests.Dllx64MinimalPDB.dll").as_os_str()]);
    assert!(!ok);
    assert!(stderr.contains("FASTLINK"), "{stderr}");

    // No PDB beside the image.
    let dir = std::env::temp_dir().join(format!("hexcavator-size-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lonely = dir.join("PEParser.Tests.Dllx64.dll");
    std::fs::copy(&image, &lonely).unwrap();
    let (ok, _, stderr) = hexc(&[lonely.as_os_str()]);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!ok);
    assert!(stderr.contains("no matching PDB found"), "{stderr}");

    // Not an image; no such file; bad usage.
    let pdb = bin("PEParser.Tests.Dllx64.pdb");
    let (ok, _, stderr) = hexc(&[pdb.as_os_str()]);
    assert!(!ok && !stderr.is_empty());
    let (ok, _, _) = hexc(&["no-such-file.dll".as_ref()]);
    assert!(!ok);
    let (ok, _, stderr) = hexc(&[]);
    assert!(!ok && stderr.contains("usage"));
}

/// Sums the `filesize` column (the last) of CSV output.
fn csv_file_total(csv: &str) -> i64 {
    csv.lines()
        .skip(1)
        .map(|l| l.rsplit(',').next().unwrap().parse::<i64>().unwrap())
        .sum()
}

#[test]
fn bloaty_mode_labels_every_byte() {
    let image = bin("PEParser.Tests.Dllx64.dll");
    let len = std::fs::metadata(&image).unwrap().len() as i64;
    for sources in [
        "sections",
        "sections,symbols",
        "compileunits",
        "libraries,groups",
    ] {
        let (ok, stdout, stderr) = hexc(&[
            image.as_os_str(),
            "-d".as_ref(),
            sources.as_ref(),
            "-n".as_ref(),
            "0".as_ref(),
            "-csv".as_ref(),
        ]);
        assert!(ok, "{sources}: {stderr}");
        let header = stdout.lines().next().unwrap();
        assert_eq!(header, format!("{sources},vmsize,filesize"));
        assert_eq!(csv_file_total(&stdout), len, "{sources}");
    }
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-d".as_ref(), "sections".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("    FILE SIZE        VM SIZE    \n"));
    assert!(stdout.contains("    .rsrc\n"));
    assert!(stdout.contains("    [PE Headers]\n"));
    assert!(stdout.trim_end().ends_with("TOTAL"));
    // JSON.
    let (ok, stdout, _) = hexc(&[
        image.as_os_str(),
        "-d".as_ref(),
        "sections".as_ref(),
        "-json".as_ref(),
    ]);
    assert!(ok);
    assert!(
        stdout.starts_with(
            "{\"sources\":[\"sections\"],\"diff\":false,\"total\":{\"name\":\"TOTAL\""
        )
    );
    assert!(stdout.contains(&format!("\"file\":{len}")));
}

#[test]
fn bloaty_diffs() {
    let a = bin("PEParser.Tests.Dllx64.dll");
    let b = bin("PEParser.Tests.Dllx86.dll");
    // An image against itself: nothing but the total.
    let (ok, stdout, stderr) = hexc(&[a.as_os_str(), "--".as_ref(), a.as_os_str()]);
    assert!(ok, "{stderr}");
    let rows: Vec<&str> = stdout.lines().skip(2).collect();
    assert_eq!(rows.len(), 1, "{stdout}");
    assert!(rows[0].ends_with("TOTAL"));
    // Against another: the sizes are the differences.
    let (ok, stdout, stderr) =
        hexc(&[a.as_os_str(), "-csv".as_ref(), "--".as_ref(), b.as_os_str()]);
    assert!(ok, "{stderr}");
    let la = std::fs::metadata(&a).unwrap().len() as i64;
    let lb = std::fs::metadata(&b).unwrap().len() as i64;
    let total: i64 = stdout
        .lines()
        .skip(1)
        .map(|l| l.split(',').nth(2).unwrap().parse::<i64>().unwrap())
        .sum();
    assert_eq!(total, la - lb);
}

#[test]
fn bloaty_mode_errors() {
    let image = bin("PEParser.Tests.Dllx64.dll");
    let (ok, _, stderr) = hexc(&[image.as_os_str(), "-d".as_ref(), "nope".as_ref()]);
    assert!(!ok);
    assert!(stderr.contains("unknown data source 'nope'"), "{stderr}");
    let (ok, stdout, _) = hexc(&["-list-sources".as_ref()]);
    assert!(ok);
    assert!(stdout.contains("compileunits"));
}

fn coff(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/coff")
        .join(name)
}

#[test]
fn objects_and_libraries() {
    for name in [
        "objects.obj",
        "objects-big.obj",
        "objects.lib",
        "imports.lib",
    ] {
        let path = coff(name);
        let len = std::fs::metadata(&path).unwrap().len() as i64;
        // The default report is by sections.
        let (ok, stdout, stderr) = hexc(&[path.as_os_str()]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.trim_end().ends_with("TOTAL"), "{name}: {stdout}");
        for sources in [
            "sections",
            "symbols",
            "groups,symbols",
            "armembers",
            "libraries,inputfiles",
        ] {
            let (ok, stdout, stderr) = hexc(&[
                path.as_os_str(),
                "-d".as_ref(),
                sources.as_ref(),
                "-n".as_ref(),
                "0".as_ref(),
                "-csv".as_ref(),
            ]);
            assert!(ok, "{name} {sources}: {stderr}");
            assert_eq!(csv_file_total(&stdout), len, "{name} {sources}");
        }
    }
    let (_, stdout, _) = hexc(&[
        coff("objects.obj").as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
    ]);
    assert!(stdout.contains("use_statics(int)"), "{stdout}");
    assert!(
        stdout.contains("    .text$mn")
            || stdout.contains("[section .text$mn]")
            || stdout.contains("exported"),
        "{stdout}"
    );
    let (_, stdout, _) = hexc(&[
        coff("objects.lib").as_os_str(),
        "-d".as_ref(),
        "armembers".as_ref(),
    ]);
    assert!(
        stdout.contains("objects.obj") && stdout.contains("objects-big.obj"),
        "{stdout}"
    );
    assert!(stdout.contains("[AR Symbol Table]"), "{stdout}");
    let (_, stdout, _) = hexc(&[
        coff("imports.lib").as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
    ]);
    assert!(stdout.contains("[import] ByName (example.dll)"), "{stdout}");
    // A library diffed against itself is empty.
    let lib = coff("objects.lib");
    let (ok, stdout, stderr) = hexc(&[lib.as_os_str(), "--".as_ref(), lib.as_os_str()]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.lines().count(), 3, "{stdout}");
}

fn elf(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/elf")
        .join(name)
}

/// bloaty's several input files (summed, `inputfiles` telling them apart),
/// and its remaining options: `-C`, `-w`, `--version`, `--name=value`,
/// `--debug-vmaddr`, `--debug-fileoff`, `--raw-map`.
#[test]
fn bloaty_options() {
    let (a, b) = (
        elf("program-x86_64-linux-gnu.o"),
        elf("program-aarch64-linux-gnu.o"),
    );
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "inputfiles".as_ref(),
        "-csv".as_ref(),
        a.as_os_str(),
        b.as_os_str(),
    ]);
    assert!(ok, "{err}");
    let rows: Vec<&str> = out.lines().skip(1).collect();
    assert_eq!(rows.len(), 2, "{out}");
    let total: i64 = rows
        .iter()
        .map(|r| r.rsplit(',').next().unwrap().parse::<i64>().unwrap())
        .sum();
    let size = |p: &Path| std::fs::metadata(p).unwrap().len() as i64;
    assert_eq!(total, size(&a) + size(&b));
    // Several against several.
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "inputfiles".as_ref(),
        a.as_os_str(),
        b.as_os_str(),
        "--".as_ref(),
        b.as_os_str(),
        a.as_os_str(),
    ]);
    assert!(ok, "{err}");
    assert!(out.contains("TOTAL"), "{out}");
    // Demangling: none gives the mangled names, full the parameters.
    let names = elf("names.o");
    let (_, raw, _) = hexc(&[
        "-d".as_ref(),
        "symbols".as_ref(),
        "-C".as_ref(),
        "none".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        names.as_os_str(),
    ]);
    assert!(raw.contains("_Z"), "{raw}");
    let (_, full, _) = hexc(&[
        "-d".as_ref(),
        "symbols".as_ref(),
        "--demangle=full".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        names.as_os_str(),
    ]);
    assert!(full.contains("use_points(int)"), "{full}");
    let (ok, _, err) = hexc(&["-C".as_ref(), "sideways".as_ref(), names.as_os_str()]);
    assert!(!ok && err.contains("none, short, or full"), "{err}");
    // -w changes nothing (labels are never cut).
    let (_, wide, _) = hexc(&["-w".as_ref(), a.as_os_str()]);
    let (_, plain, _) = hexc(&[a.as_os_str()]);
    assert_eq!(wide, plain);
    let (ok, out, _) = hexc(&["--version".as_ref()]);
    assert!(ok && out.starts_with("hexc "), "{out}");
    // What each source says about an address, and the maps.
    let exe = elf("program-x86_64-linux-gnu");
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "sections".as_ref(),
        "--debug-fileoff=0".as_ref(),
        exe.as_os_str(),
    ]);
    assert!(ok, "{err}");
    assert!(out.starts_with("file offset 0x0:\n  [base]  "), "{out}");
    assert!(out.contains("\n  sections       [0x0, "), "{out}");
    let (ok, out, _) = hexc(&["--raw-map".as_ref(), exe.as_os_str()]);
    assert!(ok && out.starts_with("[base] VM map:\n"), "{out}");
    assert!(out.contains("sections file map:\n"), "{out}");
    let (ok, _, err) = hexc(&["--debug-vmaddr=zz".as_ref(), exe.as_os_str()]);
    assert!(!ok && err.contains("not an address: zz"), "{err}");
}

#[test]
fn elf_files() {
    for name in [
        "program-x86_64-linux-gnu",
        "program-x86_64-linux-gnu.o",
        "program-aarch64_be-linux-gnu",
        "program.so",
        "program.a",
    ] {
        let path = elf(name);
        let len = std::fs::metadata(&path).unwrap().len() as i64;
        // The default report is by sections, as for objects.
        let (ok, stdout, stderr) = hexc(&[path.as_os_str()]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.contains("    .text\n"), "{name}: {stdout}");
        for sources in [
            "sections",
            "segments",
            "symbols",
            "armembers,sections",
            "inputfiles",
        ] {
            let (ok, stdout, stderr) = hexc(&[
                path.as_os_str(),
                "-d".as_ref(),
                sources.as_ref(),
                "-n".as_ref(),
                "0".as_ref(),
                "-csv".as_ref(),
            ]);
            assert!(ok, "{name} {sources}: {stderr}");
            assert_eq!(csv_file_total(&stdout), len, "{name} {sources}");
        }
    }
    let (_, stdout, _) = hexc(&[
        elf("program-x86_64-linux-gnu").as_os_str(),
        "-d".as_ref(),
        "segments".as_ref(),
    ]);
    assert!(stdout.contains("    LOAD #2 [RX]\n"), "{stdout}");
    let (_, stdout, _) = hexc(&[
        elf("program-x86_64-linux-gnu.o").as_os_str(),
        "-d".as_ref(),
        "segments".as_ref(),
    ]);
    assert!(stdout.contains("    Section [AX]\n"), "{stdout}");
    let (_, stdout, _) = hexc(&[
        elf("program.a").as_os_str(),
        "-d".as_ref(),
        "armembers".as_ref(),
    ]);
    assert!(
        stdout.contains("    program-aarch64-linux-gnu.o\n"),
        "{stdout}"
    );
    assert!(stdout.contains("    [AR Symbol Table]\n"), "{stdout}");
    let (_, stdout, _) = hexc(&[
        elf("unwind-x86_64-linux-gnu").as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
    ]);
    assert!(
        stdout.contains("    compute\n") && stdout.contains("    [ELF Header]\n"),
        "{stdout}"
    );
    // Diffs: one target against another.
    let (ok, stdout, stderr) = hexc(&[
        elf("program-x86_64-linux-gnu").as_os_str(),
        "-csv".as_ref(),
        "--".as_ref(),
        elf("unwind-x86_64-linux-gnu").as_os_str(),
    ]);
    assert!(ok, "{stderr}");
    let total: i64 = stdout
        .lines()
        .skip(1)
        .map(|l| l.split(',').nth(2).unwrap().parse::<i64>().unwrap())
        .sum();
    let la = std::fs::metadata(elf("program-x86_64-linux-gnu"))
        .unwrap()
        .len() as i64;
    let lb = std::fs::metadata(elf("unwind-x86_64-linux-gnu"))
        .unwrap()
        .len() as i64;
    assert_eq!(total, la - lb);
}

fn macho(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/macho")
        .join(name)
}

#[test]
fn macho_files() {
    for name in [
        "program-arm64",
        "program-x86_64.o",
        "libsecond-arm64.dylib",
        "program-universal",
        "libprogram-arm64.a",
        "libprogram-universal.a",
    ] {
        let path = macho(name);
        let len = std::fs::metadata(&path).unwrap().len() as i64;
        let (ok, stdout, stderr) = hexc(&[path.as_os_str()]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.contains("__TEXT,__text"), "{name}: {stdout}");
        for sources in [
            "sections",
            "segments",
            "symbols",
            "archs,segments",
            "fullsymbols",
            "armembers,sections",
        ] {
            let (ok, stdout, stderr) = hexc(&[
                path.as_os_str(),
                "-d".as_ref(),
                sources.as_ref(),
                "-n".as_ref(),
                "0".as_ref(),
                "-csv".as_ref(),
            ]);
            assert!(ok, "{name} {sources}: {stderr}");
            assert_eq!(csv_file_total(&stdout), len, "{name} {sources}");
        }
    }
    // A static library's members.
    let (_, stdout, _) = hexc(&[
        macho("libprogram-arm64.a").as_os_str(),
        "-d".as_ref(),
        "armembers".as_ref(),
    ]);
    for row in [
        "program-arm64.o",
        "second-arm64.o",
        "[AR Headers]",
        "[AR Symbol Table]",
    ] {
        assert!(
            stdout.contains(&format!(
                "    {row}
"
            )),
            "{row}: {stdout}"
        );
    }
    let (_, stdout, _) = hexc(&[
        macho("program-universal").as_os_str(),
        "-d".as_ref(),
        "archs".as_ref(),
    ]);
    assert!(
        stdout.contains("    arm64\n") && stdout.contains("    x86_64\n"),
        "{stdout}"
    );
    let (_, stdout, _) = hexc(&[
        macho("program-arm64").as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
    ]);
    assert!(
        stdout.contains("    _compute\n") && stdout.contains("    [Mach-O Headers]\n"),
        "{stdout}"
    );
}

#[test]
fn findings() {
    let image = bin("CppTestCases_BasicDiffObjectsAfter.dll");
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-findings".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.starts_with("Duplicate data: 2 variables"),
        "{stdout}"
    );
    assert!(stdout.contains("duplicatedPointArray"), "{stdout}");
    assert!(stdout.contains("Wasteful virtuals: 6 classes"), "{stdout}");
    assert!(
        stdout.contains("std::exception: what() const (never overridden)"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-findings".as_ref(), "-json".as_ref()]);
    assert!(ok, "{stderr}");
    let v = serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
    let dups = v.get("duplicate_data").unwrap();
    assert_eq!(dups.get("count").unwrap().as_i64(), Some(2));
    assert_eq!(dups.get("wasted_file").unwrap().as_i64(), Some(96));
    let first = &dups.get("items").unwrap().as_array().unwrap()[0];
    assert_eq!(
        first.get("name").unwrap().as_str(),
        Some("duplicatedPointArray")
    );
    assert_eq!(
        first.get("compilands").unwrap().as_array().unwrap().len(),
        4
    );
    let virtuals = v.get("wasteful_virtuals").unwrap();
    assert_eq!(virtuals.get("count").unwrap().as_i64(), Some(6));
    assert_eq!(virtuals.get("wasted").unwrap().as_i64(), Some(744));
}

#[test]
fn linker_logs() {
    let log = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkerlog/verbose.txt");
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
            .arg("linkerlog")
            .arg(&log)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let summary = run(&[]);
    assert!(summary.contains("inputs linked."), "{summary}");
    assert!(summary.contains("libucrt.lib"), "{summary}");
    assert!(summary.contains("OLDNAMES.lib"), "{summary}");
    let why = run(&["-why", "xthrow.obj"]);
    assert!(why.starts_with("libcpmt.lib(xthrow.obj) was loaded for void __cdecl std::_Xlength_error(char const *), referenced in main.obj"), "{why}");
    let json = run(&["-why", "LIBCMT.lib(gshandler.obj)", "-json"]);
    let v = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert_eq!(v.get("why").unwrap().as_array().unwrap().len(), 1);
    let summary = serde_json::from_str::<serde_json::Value>(&run(&["-json"])).unwrap();
    assert!(summary.get("linked").unwrap().as_i64().unwrap() > 300);
}

#[test]
fn maps_instead_of_pdbs() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/linkerlog");
    let image = dir.join("main.exe");
    let map = dir.join("main.map");
    let len = std::fs::metadata(&image).unwrap().len() as i64;
    let (ok, stdout, stderr) = hexc(&[
        image.as_os_str(),
        "-map".as_ref(),
        map.as_os_str(),
        "-top".as_ref(),
        "3".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("Map: "), "{stdout}");
    assert!(stdout.contains("libucrt.lib"), "{stdout}");
    let (ok, stdout, stderr) = hexc(&[
        image.as_os_str(),
        "-map".as_ref(),
        map.as_os_str(),
        "-d".as_ref(),
        "libraries,compileunits,symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        "-csv".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    assert_eq!(csv_file_total(&stdout), len);
    assert!(stdout.contains("libucrt.lib,"), "{stdout}");
    let (ok, _, stderr) = hexc(&[
        image.as_os_str(),
        "-map".as_ref(),
        map.as_os_str(),
        "-findings".as_ref(),
    ]);
    assert!(!ok && stderr.contains("needs the image's PDB"), "{stderr}");
    let (ok, _, stderr) = hexc(&[image.as_os_str(), "-map".as_ref(), image.as_os_str()]);
    assert!(!ok && stderr.contains("not a linker map"), "{stderr}");
}

#[test]
fn debug_files() {
    // A dSYM bundle next to the image is found.
    let dir = std::env::temp_dir().join(format!("hexc-dsym-{}", std::process::id()));
    let dwarf_dir = dir.join("program-arm64.dSYM/Contents/Resources/DWARF");
    std::fs::create_dir_all(&dwarf_dir).unwrap();
    let image = dir.join("program-arm64");
    std::fs::copy(macho("program-arm64"), &image).unwrap();
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-d".as_ref(), "compileunits".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(!stdout.contains("program.c"), "{stdout}");
    std::fs::copy(
        macho("program-arm64.dwarf"),
        dwarf_dir.join("program-arm64"),
    )
    .unwrap();
    let (ok, stdout, stderr) = hexc(&[image.as_os_str(), "-d".as_ref(), "compileunits".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("    program.c\n"), "{stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
    // Or given.
    let (ok, stdout, _) = hexc(&[
        macho("program-x86_64").as_os_str(),
        "-d".as_ref(),
        "compileunits".as_ref(),
        "-debug-file".as_ref(),
        macho("program-x86_64.dwarf").as_os_str(),
    ]);
    assert!(ok && stdout.contains("    program.c\n"), "{stdout}");
    // ELF: a stripped image and its debug file.
    let (ok, stdout, stderr) = hexc(&[
        elf("program-split").as_os_str(),
        "-d".as_ref(),
        "compileunits".as_ref(),
        "-debug-file".as_ref(),
        elf("program-split.debug").as_os_str(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("    program.c\n"), "{stdout}");
    // One for another build is refused.
    let (ok, _, stderr) = hexc(&[
        elf("program-split").as_os_str(),
        "-d".as_ref(),
        "compileunits".as_ref(),
        "-debug-file".as_ref(),
        elf("program-aarch64-linux-gnu").as_os_str(),
    ]);
    assert!(!ok && stderr.contains("another build"), "{stderr}");
}

#[test]
fn wasm_modules() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wasm/module.wasm");
    let len = std::fs::metadata(&path).unwrap().len() as i64;
    for sources in ["sections", "symbols", "archs", "fullsymbols,sections"] {
        let (ok, stdout, stderr) = hexc(&[
            path.as_os_str(),
            "-d".as_ref(),
            sources.as_ref(),
            "-n".as_ref(),
            "0".as_ref(),
            "-csv".as_ref(),
        ]);
        assert!(ok, "{sources}: {stderr}");
        assert_eq!(csv_file_total(&stdout), len, "{sources}");
    }
    let (ok, stdout, _) = hexc(&[
        path.as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
    ]);
    assert!(
        ok && stdout.contains("    main\n") && stdout.contains("    func[3]\n"),
        "{stdout}"
    );
    for sources in ["compileunits", "inlines", "compileunits,symbols"] {
        let (ok, stdout, stderr) = hexc(&[
            path.as_os_str(),
            "-d".as_ref(),
            sources.as_ref(),
            "-n".as_ref(),
            "0".as_ref(),
            "-csv".as_ref(),
        ]);
        assert!(ok, "{sources}: {stderr}");
        assert_eq!(csv_file_total(&stdout), len, "{sources}");
    }
}

/// A module's source map: found beside it by its sourceMappingURL, or
/// given with -source-map (by URL or path) or -debug-file.
#[test]
fn wasm_source_maps() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wasm");
    let module = dir.join("module.wasm");
    let run = |extra: &[&std::ffi::OsStr]| {
        let mut args = vec![module.as_os_str(), "-d".as_ref(), "compileunits".as_ref()];
        args.extend_from_slice(extra);
        hexc(&args)
    };
    let (ok, stdout, stderr) = run(&[]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("    src/math.c\n") && stdout.contains("    src/main.c\n"),
        "{stdout}"
    );

    // A copy elsewhere, with another file name, so only the options find it.
    let tmp = std::env::temp_dir().join(format!("hexc-sourcemap-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let copy = tmp.join("module.wasm");
    std::fs::copy(&module, &copy).unwrap();
    let other = tmp.join("other.map");
    let text = std::fs::read_to_string(dir.join("module.wasm.map")).unwrap();
    std::fs::write(&other, text.replace("math.c", "other.c")).unwrap();
    let by = |args: &[&std::ffi::OsStr]| {
        let mut all = vec![copy.as_os_str(), "-d".as_ref(), "compileunits".as_ref()];
        all.extend_from_slice(args);
        hexc(&all)
    };
    let (ok, stdout, _) = by(&[]);
    assert!(ok && !stdout.contains(".c\n"), "{stdout}");
    let by_url = format!("module.wasm.map={}", other.display());
    let by_path = format!("{}={}", copy.display(), other.display());
    for args in [
        vec!["-source-map".as_ref(), by_url.as_ref()],
        vec!["-source-map".as_ref(), by_path.as_ref()],
        vec!["-debug-file".as_ref(), other.as_os_str()],
    ] {
        let (ok, stdout, stderr) = by(&args);
        assert!(ok, "{args:?}: {stderr}");
        assert!(stdout.contains("    src/other.c\n"), "{args:?}: {stdout}");
    }
    // A map for something else is not used.
    let (ok, stdout, _) = by(&["-source-map".as_ref(), "nope.map=x".as_ref()]);
    assert!(ok && !stdout.contains(".c\n"), "{stdout}");
    let (ok, _, stderr) = by(&["-source-map".as_ref(), "no-equals".as_ref()]);
    assert!(!ok && stderr.contains("<id>=<path>"), "{stderr}");
    std::fs::write(&other, "{not json").unwrap();
    let (ok, _, stderr) = by(&["-debug-file".as_ref(), other.as_os_str()]);
    assert!(!ok && stderr.contains("source map"), "{stderr}");

    // A module's URL that climbs out of its directory (or is absolute)
    // isn't followed: a module names only files beside or below it.
    let sub = tmp.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    let mut bytes = std::fs::read(&module).unwrap();
    let at = bytes
        .windows(15)
        .position(|w| w == b"module.wasm.map")
        .unwrap();
    bytes[at..at + 15].copy_from_slice(b"../aaaaaaaa.map");
    let climbing = sub.join("module.wasm");
    std::fs::write(&climbing, &bytes).unwrap();
    std::fs::write(tmp.join("aaaaaaaa.map"), text).unwrap();
    let (ok, stdout, stderr) =
        hexc(&[climbing.as_os_str(), "-d".as_ref(), "compileunits".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(
        !stdout.contains(
            ".c
"
        ),
        "followed ../: {stdout}"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn source_filters_and_custom_sources() {
    let path = elf("dwarf5-x86_64-linux-gnu");
    let (ok, stdout, stderr) = hexc(&[
        path.as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-source-filter".as_ref(),
        "^(compute|second_)".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    let rows: Vec<&str> = stdout.lines().skip(2).collect();
    assert!(
        rows.iter()
            .filter(|r| !r.ends_with("TOTAL") && !r.starts_with("Filtering"))
            .all(|r| r.ends_with("compute") || r.contains("second_")),
        "{stdout}"
    );
    assert!(
        stdout.contains("Filtering enabled (source_filter); omitted file ="),
        "{stdout}"
    );
    let (ok, _, stderr) = hexc(&[
        path.as_os_str(),
        "-d".as_ref(),
        "symbols".as_ref(),
        "-source-filter".as_ref(),
        "(".as_ref(),
    ]);
    assert!(!ok && stderr.contains("-source-filter"), "{stderr}");
    // A custom source from a config file.
    let dir = std::env::temp_dir().join(format!("hexc-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("x.bloaty");
    std::fs::write(
        &config,
        "custom_data_source: {\n  name: \"kind\"\n  base_data_source: \"sections\"\n  rewrite: { pattern: \"^\\\\.debug_\" replacement: \"debug info\" }\n}\ndata_source: \"kind\"\n",
    )
    .unwrap();
    let len = std::fs::metadata(&path).unwrap().len() as i64;
    let (ok, stdout, stderr) = hexc(&[
        "-c".as_ref(),
        config.as_os_str(),
        path.as_os_str(),
        "-n".as_ref(),
        "0".as_ref(),
        "-csv".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("kind,vmsize,filesize\n"), "{stdout}");
    assert!(
        stdout.contains("\ndebug info,") && !stdout.contains(".debug_"),
        "{stdout}"
    );
    assert_eq!(csv_file_total(&stdout), len);
    let (ok, _, stderr) = hexc(&[
        "-c".as_ref(),
        config.as_os_str(),
        path.as_os_str(),
        "-d".as_ref(),
        "nope".as_ref(),
    ]);
    assert!(
        !ok && stderr.contains("unknown data source 'nope'"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// -disassemble: one function's code, its branches labeled and its calls
/// named, from ELF and Mach-O files; errors name what is wrong.
#[test]
fn disassemble() {
    for (file, name, header) in [
        (elf("refs-x86_64-linux-gnu"), "jumps", "jumps:"),
        (elf("refs-aarch64-linux-gnu"), "jumps", "jumps:"),
        (macho("refs-arm64"), "jumps", "_jumps:"),
        (macho("refs-x86_64"), "_jumps", "_jumps:"),
        (elf("program-i386-linux-gnu"), "compute", "compute:"),
    ] {
        let (ok, stdout, stderr) =
            hexc(&[file.as_os_str(), "-disassemble".as_ref(), name.as_ref()]);
        assert!(ok, "{name}: {stderr}");
        assert!(stdout.starts_with(&format!("{header}\n")), "{stdout}");
        assert!(stdout.contains(">0"), "{stdout}");
        if name.ends_with("jumps") {
            assert!(stdout.contains("shared_first"), "{stdout}");
        }
    }
    // A C++ function by its name without its parameters, though a lambda
    // inside it begins the same way.
    let (ok, stdout, stderr) = hexc(&[
        elf("names.o").as_os_str(),
        "-disassemble".as_ref(),
        "use_points".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("use_points():\n"), "{stdout}");
    let (ok, _, stderr) = hexc(&[
        elf("refs-x86_64-linux-gnu").as_os_str(),
        "-disassemble".as_ref(),
        "nope".as_ref(),
    ]);
    assert!(
        !ok && stderr.contains("no function named 'nope'"),
        "{stderr}"
    );
    let (ok, _, stderr) = hexc(&[
        elf("program-armeb-linux-gnueabi").as_os_str(),
        "-disassemble".as_ref(),
        "compute".as_ref(),
    ]);
    assert!(!ok && stderr.contains("no disassembler"), "{stderr}");
    // 32-bit ARM, A32 and Thumb: as llvm-objdump writes each line (but a
    // branch's or call's target, which reads as a label or a name).
    for mode in ["arm", "thumb"] {
        let file = elf(&format!("program-{mode}-linux-gnueabihf"));
        let objdump = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../testdata/elf/program-{mode}-linux-gnueabihf.objdump.txt"
        )))
        .unwrap();
        let mut theirs = std::collections::HashMap::new();
        for line in objdump.lines() {
            let Some((at, text)) = line.trim_start().split_once(':') else {
                continue;
            };
            let Ok(at) = u64::from_str_radix(at, 16) else {
                continue;
            };
            let text = text.split(" @ ").next().unwrap().trim();
            theirs.insert(at, text.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        for name in ["compute", "_start"] {
            let (ok, stdout, stderr) =
                hexc(&[file.as_os_str(), "-disassemble".as_ref(), name.as_ref()]);
            assert!(ok, "{mode} {name}: {stderr}");
            let mut lines = 0;
            for line in stdout.lines().skip(1) {
                let mut it = line.split_whitespace();
                let Some(at) = it.next().and_then(|a| u64::from_str_radix(a, 16).ok()) else {
                    continue;
                };
                let rest: Vec<&str> = it.filter(|w| !w.ends_with(':')).collect();
                if rest.first() == Some(&"(not") {
                    continue;
                }
                let ours = rest.join(" ");
                let want = &theirs[&at];
                let branch =
                    ["b", "bl", "bne", "blt", "bge", "beq", "cbz", "cbnz"].contains(&rest[0]);
                if branch {
                    assert_eq!(rest[0], want.split(' ').next().unwrap(), "{mode} {at:x}");
                } else {
                    assert_eq!(&ours, want, "{mode} {at:x}");
                }
                lines += 1;
            }
            assert!(
                lines > 10,
                "{mode} {name}:
{stdout}"
            );
        }
    }
    // A module without -d: its sections.
    let wasm = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wasm/module.wasm");
    let (ok, stdout, stderr) = hexc(&[wasm.as_os_str()]);
    assert!(ok && stdout.contains("    Code\n"), "{stdout}{stderr}");
    // A module's function: offsets in the file (as llvm-objdump's), calls
    // named; one without a name is func[i], with its locals.
    let (ok, stdout, stderr) = hexc(&[wasm.as_os_str(), "-disassemble".as_ref(), "main".as_ref()]);
    assert!(ok, "{stderr}");
    assert_eq!(
        stdout,
        "main:\n\
         \x20              86  i32.const 2\n\
         \x20              88  i32.const 3\n\
         \x20              8a  call 1 <add>\n\
         \x20              8c  call 2 <square>\n\
         \x20              8e  call 0 <log>\n\
         \x20              90  end\n"
    );
    let (ok, stdout, stderr) = hexc(&[
        wasm.as_os_str(),
        "-disassemble".as_ref(),
        "func[3]".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.starts_with("func[3]:\n               92  (local i32 i32)\n"),
        "{stdout}"
    );
    // A PE image's function, from its PDB: by its name without its
    // parameters too; calls named.
    let dll = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/sizebench/bin/CppTestCases_BasicDiffObjectsAfter.dll");
    let (ok, stdout, stderr) =
        hexc(&[dll.as_os_str(), "-disassemble".as_ref(), "DllMain".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("DllMain("), "{stdout}");
    assert!(stdout.lines().count() > 3, "{stdout}");
    assert!(stdout.contains("ret"), "{stdout}");
    let (ok, _, stderr) = hexc(&[dll.as_os_str(), "-disassemble".as_ref(), "nope".as_ref()]);
    assert!(
        !ok && stderr.contains("no function named 'nope'"),
        "{stderr}"
    );
    let (ok, _, stderr) = hexc(&[wasm.as_os_str(), "-disassemble".as_ref(), "nope".as_ref()]);
    assert!(
        !ok && stderr.contains("no function named 'nope'"),
        "{stderr}"
    );
}

/// -disassemble -blocks: by basic block, labeled L1, L2, ...; and -json:
/// the lines, blocks and their edges, and (from the PDB) source lines.
#[test]
fn disassemble_blocks_and_json() {
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/xref/xref-x64.exe");
    let name = "__scrt_common_main_seh()";
    let run = |extra: &str| {
        let (ok, stdout, stderr) = hexc(&[
            exe.as_os_str(),
            "-disassemble".as_ref(),
            name.as_ref(),
            extra.as_ref(),
        ]);
        assert!(ok, "{stderr}");
        stdout
    };
    let blocks = run("-blocks");
    assert!(blocks.starts_with(&format!("{name}:\n\n")), "{blocks}");
    // Each label on its own line, after a blank one; branches to labels.
    assert!(blocks.contains("\n\nL1:\n "), "{blocks}");
    assert!(!blocks.contains(">0") && !blocks.contains("<0"), "{blocks}");
    let jumps = blocks
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .last()
                .is_some_and(|w| w.starts_with('L') && w[1..].parse::<u32>().is_ok())
        })
        .count();
    assert!(jumps > 5, "{blocks}");
    let json: serde_json::Value = serde_json::from_str(&run("-json")).unwrap();
    assert_eq!(json["name"], name);
    assert_eq!(json["isa"], "x86-64");
    let lines = json["lines"].as_array().unwrap();
    let blocks_ = json["blocks"].as_array().unwrap();
    // The blocks cover the lines, in order.
    let mut next = 0;
    for b in blocks_ {
        assert_eq!(b["first"].as_u64().unwrap(), next);
        next += b["count"].as_u64().unwrap();
        for s in b["successors"].as_array().unwrap() {
            assert!(s["block"].as_u64().unwrap() < blocks_.len() as u64);
            assert!(["next", "taken", "not-taken", "jump"].contains(&s["edge"].as_str().unwrap()));
        }
        // A block's first line has its label (all but the entry's).
        assert_eq!(
            b["label"],
            lines[usize::try_from(b["first"].as_u64().unwrap()).unwrap()]
                .get("label")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        );
    }
    assert_eq!(next, lines.len() as u64);
    // A conditional branch: taken, and not.
    let branch = blocks_
        .iter()
        .find(|b| b["successors"].as_array().unwrap().len() == 2)
        .unwrap();
    let edges: Vec<&str> = branch["successors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["edge"].as_str().unwrap())
        .collect();
    assert_eq!(edges, ["taken", "not-taken"]);
    // A return ends a block with nowhere to go.
    let ret = lines.iter().position(|l| l["flow"] == "return").unwrap();
    let last = blocks_
        .iter()
        .find(|b| {
            (b["first"].as_u64().unwrap()
                ..b["first"].as_u64().unwrap() + b["count"].as_u64().unwrap())
                .contains(&(ret as u64))
        })
        .unwrap();
    assert!(last["successors"].as_array().unwrap().is_empty());
    // The CRT's source, from the PDB's line tables.
    let files = json["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .any(|f| f.as_str().unwrap().ends_with("exe_common.inl")),
        "{files:?}"
    );
    assert!(
        lines
            .iter()
            .all(|l| l["source"][1].as_u64().is_some_and(|n| n > 0))
    );
    assert!(
        lines
            .iter()
            .all(|l| l["bytes"].as_str().unwrap().len() >= 2)
    );
}

/// -disassemble -json's variables (from the PDB): each parameter, where it
/// lives over which code, and its pointee's fields (through its bases).
#[test]
fn disassemble_variables() {
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/types/types.exe");
    let (ok, stdout, stderr) = hexc(&[
        exe.as_os_str(),
        "-disassemble".as_ref(),
        "use(Padded*, Bits*, Derived*, WithEmpty*, Diamond*, Either*, Grows*)".as_ref(),
        "-json".as_ref(),
    ]);
    assert!(ok, "{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let vars = json["variables"].as_array().unwrap();
    let names: Vec<&str> = vars.iter().map(|v| v["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["p", "b", "d", "w", "m", "e", "g"]);
    let p = &vars[0];
    assert_eq!(p["type"], "Padded *");
    assert_eq!(p["param"], true);
    // In rcx at the entry (the first parameter, on x64), at the function's start.
    let first = &p["ranges"][0];
    assert_eq!(first["register"], "rcx");
    assert_eq!(first["start"], json["address"]);
    // Its home slot too (an S_REGREL32: [rsp+...]), merged into it.
    assert!(
        p["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["base"] == "rsp"),
        "{p}"
    );
    let field = |v: &serde_json::Value, name: &str| {
        v["pointee"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .cloned()
    };
    assert_eq!(field(p, "b").unwrap()["offset"], 4);
    // Derived's x is its base's.
    assert_eq!(field(&vars[2], "x").unwrap()["offset"], 8);
    assert_eq!(field(&vars[2], "vfptr").unwrap()["offset"], 0);
    // No variables for code without debug information about them.
    let wasm = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wasm/module.wasm");
    let (ok, stdout, _) = hexc(&[
        wasm.as_os_str(),
        "-disassemble".as_ref(),
        "main".as_ref(),
        "-json".as_ref(),
    ]);
    assert!(ok);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("variables").is_none());
}

/// The symbol index: none unless asked for. `--cache <dir>` writes one in
/// the directory on the first symbols report and reads it (giving the same
/// report) on the next; a damaged one is rebuilt; `--cache <file>` is that
/// file.
#[test]
fn symbol_index() {
    let dir = std::env::temp_dir().join(format!("hexc-index-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("CppTestCases_BasicDiffObjectsAfter.dll");
    std::fs::copy(bin("CppTestCases_BasicDiffObjectsAfter.dll"), &image).unwrap();
    std::fs::copy(
        bin("CppTestCases_BasicDiffObjectsAfter.pdb"),
        dir.join("CppTestCases_BasicDiffObjectsAfter.pdb"),
    )
    .unwrap();
    let indexes = || -> Vec<std::path::PathBuf> {
        let mut all: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().ends_with(".hexc-index"))
            .collect();
        all.sort();
        all
    };
    let run = |cache: Option<&std::path::Path>| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_hexc"));
        if let Some(p) = cache {
            c.arg("--cache").arg(p);
        }
        let out = c
            .args(["size".as_ref(), image.as_os_str()])
            .args(["-d", "symbols", "-n", "0", "-csv"])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    // None by default.
    let first = run(None);
    assert!(indexes().is_empty());
    // In a directory: `--cache .`.
    assert_eq!(run(Some(".".as_ref())), first);
    let found = indexes();
    assert_eq!(found.len(), 1, "{found:?}");
    let index = &found[0];
    let name = index.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("CppTestCases_BasicDiffObjectsAfter.dll."),
        "{name}"
    );
    let written = std::fs::metadata(index).unwrap().modified().unwrap();
    assert_eq!(run(Some(".".as_ref())), first);
    // Read, not rewritten.
    assert_eq!(
        std::fs::metadata(index).unwrap().modified().unwrap(),
        written
    );
    // Damaged: rebuilt, and the report the same.
    let mut data = std::fs::read(index).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    std::fs::write(index, &data).unwrap();
    assert_eq!(run(Some(".".as_ref())), first);
    assert_ne!(std::fs::read(index).unwrap(), data);
    std::fs::remove_file(index).unwrap();
    // A file.
    let file = dir.join("mine.idx");
    assert_eq!(run(Some(&file)), first);
    assert!(file.exists());
    assert_eq!(run(Some(&file)), first);
    assert!(indexes().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// --cache without a path is an error, as a usage.
#[test]
fn cache_option_needs_a_path() {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["version", "--cache"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--cache"));
}

/// -budget: limits on sizes and on growth from a base; exits 1, listing
/// what exceeds them, when anything does.
#[test]
fn size_budgets() {
    let dir = std::env::temp_dir().join(format!("hexc-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let image = elf("program-x86_64-linux-gnu");
    let base = elf("program-i386-linux-gnu");
    let len = std::fs::metadata(&image).unwrap().len();
    let check = |rules: &str, extra: &[&std::ffi::OsStr]| {
        let path = dir.join("budget.json");
        std::fs::write(&path, rules).unwrap();
        let mut args = vec![image.as_os_str(), "-budget".as_ref(), path.as_os_str()];
        args.extend_from_slice(extra);
        hexc(&args)
    };
    let (ok, stdout, stderr) = check(&format!(r#"{{"rules": [{{"max_file": {len}}}]}}"#), &[]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "Budget met: 1 rules\n");
    let (ok, stdout, stderr) = check(
        &format!(
            r#"{{"rules": [
                {{"name": "image", "max_file": {}}},
                {{"source": "sections", "match": "^\\.text$", "max_vm": 100}},
                {{"source": "sections", "max_vm": "1 MiB"}}
            ]}}"#,
            len - 1
        ),
        &[],
    );
    assert!(
        !ok && stderr.contains("size budget exceeded (2 limits)"),
        "{stderr}"
    );
    assert!(stdout.contains("FAIL  image: file"), "{stdout}");
    assert!(stdout.contains(": .text: vm 178 > 100"), "{stdout}");
    assert!(
        stdout.ends_with("Budget exceeded: 2 of 3 rules, 2 limits\n"),
        "{stdout}"
    );
    // Growth from a base, and JSON.
    let rules = r#"{"rules": [{"source": "symbols", "match": "^compute$", "max_growth_file": 0}]}"#;
    let (_, _, stderr) = check(rules, &[]);
    assert!(stderr.contains("need a base image"), "{stderr}");
    // Against itself, nothing grows; a limit below zero (it must shrink)
    // then fails.
    let (ok, stdout, stderr) = check(rules, &["-json".as_ref(), "--".as_ref(), image.as_os_str()]);
    assert!(ok, "{stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        (json["met"].clone(), json["rules"].clone()),
        (true.into(), 1.into())
    );
    let shrink =
        r#"{"rules": [{"source": "symbols", "match": "^compute$", "max_growth_file": -1}]}"#;
    let (ok, stdout, _) = check(
        shrink,
        &["-json".as_ref(), "--".as_ref(), image.as_os_str()],
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(!ok);
    assert_eq!(json["violations"][0]["label"], "compute");
    assert_eq!(json["violations"][0]["measure"], "file growth");
    assert_eq!(json["violations"][0]["actual"], 0);
    // Against another build, `compute` is whatever it grew by.
    let (_, stdout, _) = check(rules, &["-json".as_ref(), "--".as_ref(), base.as_os_str()]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["met"].is_boolean());
    // Errors.
    let (ok, _, stderr) = check(r#"{"rules": [{"source": "nope", "max_file": 1}]}"#, &[]);
    assert!(
        !ok && stderr.contains("unknown data source 'nope'"),
        "{stderr}"
    );
    let (ok, _, stderr) = check(r#"{"rules": [{"max_flie": 1}]}"#, &[]);
    assert!(!ok && stderr.contains("unknown field"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn testdata(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(path)
}

/// -sizebench and -findings read DWARF as well as PDBs (they used to be
/// ignored for ELF and Mach-O, which went to the bloaty-style report).
#[test]
fn sizebench_and_findings_on_every_format() {
    let elf = testdata("elf/dwarf5-x86_64-linux-gnu");
    let (ok, stdout, stderr) = hexc(&[elf.as_os_str(), "-sizebench".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("COMPILAND ...no name found... | program.c size=165"),
        "{stdout}"
    );
    assert!(!stdout.contains("FILE SIZE"), "{stdout}");
    let macho = testdata("macho/program-arm64");
    let dwarf = testdata("macho/program-arm64.dwarf");
    let (ok, stdout, stderr) = hexc(&[
        macho.as_os_str(),
        "-findings".as_ref(),
        "-debug-file".as_ref(),
        dwarf.as_os_str(),
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.starts_with("Duplicate data:"), "{stdout}");
    // Without them, ELF's default report is still bloaty's.
    let (ok, stdout, _) = hexc(&[elf.as_os_str()]);
    assert!(ok && stdout.contains("FILE SIZE"), "{stdout}");
    // Objects have no debug information to read that way.
    let obj = coff("objects-big.obj");
    let (ok, _, stderr) = hexc(&[obj.as_os_str(), "-sizebench".as_ref()]);
    assert!(!ok);
    assert!(
        stderr.contains("read linked images, not objects or libraries"),
        "{stderr}"
    );
}

/// size -table: summed by any source, the rollup hexc would give.
#[test]
fn a_table_sums_to_every_rollup() {
    let image = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/xref/xref-x64.exe");
    let (ok, out, err) = hexc(&[image.as_os_str(), "-table".as_ref()]);
    assert!(ok, "{err}");
    let t: serde_json::Value = serde_json::from_str(&out).unwrap();
    let columns: Vec<&str> = t["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let strings: Vec<&str> = t["strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    for source in ["sections", "groups", "compileunits", "libraries"] {
        let (ok, out, err) = hexc(&[
            image.as_os_str(),
            "-d".as_ref(),
            format!("{source},symbols").as_ref(),
            "-n".as_ref(),
            "0".as_ref(),
            "-json".as_ref(),
        ]);
        assert!(ok, "{err}");
        let r: serde_json::Value = serde_json::from_str(&out).unwrap();
        let k = columns.iter().position(|c| *c == source).unwrap();
        let mut sums: std::collections::BTreeMap<&str, (i64, i64)> = Default::default();
        for row in t["rows"].as_array().unwrap() {
            let row = row.as_array().unwrap();
            let e = sums
                .entry(strings[usize::try_from(row[k].as_u64().unwrap()).unwrap()])
                .or_default();
            e.0 += row[row.len() - 2].as_i64().unwrap();
            e.1 += row[row.len() - 1].as_i64().unwrap();
        }
        sums.retain(|_, v| *v != (0, 0));
        let want: std::collections::BTreeMap<&str, (i64, i64)> = r["total"]["children"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap(),
                    (c["file"].as_i64().unwrap(), c["vm"].as_i64().unwrap()),
                )
            })
            .collect();
        assert_eq!(sums, want, "{source}");
    }
}

#[test]
fn source_files_and_definitions() {
    // sourcefiles: code by the file its line tables name, as `hexc
    // sourcefiles` counts it.
    let image = testdata("xref/xref-x64.exe").into_os_string();
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "sourcefiles".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        "-csv".as_ref(),
        &image,
    ]);
    assert!(ok, "{err}");
    let main = out
        .lines()
        .find(|l| l.contains("main.cpp"))
        .unwrap_or_else(|| panic!("{out}"));
    let files = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "sourcefiles".as_ref(),
            "-json".as_ref(),
            "-n".as_ref(),
            "0".as_ref(),
            image.as_os_str(),
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&files.stdout).unwrap();
    let want = v["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["file"].as_str().unwrap().ends_with("main.cpp"))
        .unwrap()["bytes"]
        .as_u64()
        .unwrap();
    assert!(main.contains(&format!(",{want},")), "{main} vs {want}");
    // As a table, with symbols: what the Symbols page groups by Source.
    let (ok, out, err) = hexc(&[
        "-table".as_ref(),
        "-d".as_ref(),
        "sourcefiles,symbols".as_ref(),
        &image,
    ]);
    assert!(ok, "{err}");
    let t: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(t["columns"], serde_json::json!(["sourcefiles", "symbols"]));
    // A function's definition: PDB (its signature's line), DWARF (its
    // declaration), and Mach-O through a debug map.
    for (image, name, want) in [
        ("xref/xref-x64.exe", "main", "main.cpp:53"),
        ("xref/xref-x64.exe", "Circle::area", "main.cpp:17"),
        ("xref/xref-x64.exe", "dead_entry(int)", "dead.cpp:13"),
        ("types/types-x86_64-linux-gnu", "main", "types.cpp:106"),
        ("macho/oso/oso-arm64", "_compute", "program.c:17"),
    ] {
        let (ok, out, err) = hexc(&[
            "-definition".as_ref(),
            name.as_ref(),
            testdata(image).as_os_str(),
        ]);
        assert!(
            ok && out.trim_end().ends_with(want),
            "{image} {name}: {out}{err}"
        );
    }
    let (ok, _, err) = hexc(&["-definition".as_ref(), "no_such_function".as_ref(), &image]);
    assert!(!ok && err.contains("no function"), "{err}");
}

#[test]
fn diff_of_two_builds() {
    // testdata/diff (tools/diff): a function and a datum added, removed,
    // and changed between v1 and v2; the rest the same.
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        "-csv".as_ref(),
        testdata("diff/diff-v2.exe").as_os_str(),
        "--".as_ref(),
        testdata("diff/diff-v1.exe").as_os_str(),
    ]);
    assert!(ok, "{err}");
    let row = |name: &str| {
        out.lines()
            .find(|l| l.starts_with(&format!("{name},")) || l.starts_with(&format!("\"{name}\",")))
            .unwrap_or_else(|| panic!("{name}: {out}"))
            .to_string()
    };
    // (CSV: name, the memory and file changes, then the old and new sizes.)
    let delta = |name: &str| -> i64 { row(name).split(',').nth(2).unwrap().parse().unwrap() };
    assert_eq!(delta("g_added_table"), 512);
    assert_eq!(delta("g_removed_table"), -256);
    assert_eq!(delta("g_lookup"), 256);
    assert!(delta("added_fn(int)") > 0);
    assert!(delta("removed_fn(int)") < 0);
    assert!(delta("transform(int)") > 0);
    assert!(
        !out.lines()
            .any(|l| l.starts_with("kept_same(int),") || l.starts_with("g_same,")),
        "unchanged: {out}"
    );
    // By fingerprint: one changed (and main, which calls another), one
    // added, one removed.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "xref".as_ref(),
            testdata("diff/diff-v2.exe").as_os_str(),
            "--".as_ref(),
            testdata("diff/diff-v1.exe").as_os_str(),
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("2 changed, 0 renamed, 1 added, 1 removed"),
        "{text}"
    );
}

#[test]
fn a_diffs_table_sums_to_its_report() {
    // hexc size -table new -- old: each row's change and base sizes, every
    // set of labels either build has; summed by symbol, the diff report's.
    let (ok, out, err) = hexc(&[
        "-table".as_ref(),
        testdata("diff/diff-v2.exe").as_os_str(),
        "--".as_ref(),
        testdata("diff/diff-v1.exe").as_os_str(),
    ]);
    assert!(ok, "{err}");
    let t: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(t["diff"], true);
    let strings = t["strings"].as_array().unwrap();
    let col = t["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c == "symbols")
        .unwrap();
    let mut by: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
    for r in t["rows"].as_array().unwrap() {
        let r = r.as_array().unwrap();
        let n = r.len();
        let e = by
            .entry(
                strings[usize::try_from(r[col].as_u64().unwrap()).unwrap()]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
            .or_default();
        e.0 += r[n - 4].as_i64().unwrap();
        e.1 += r[n - 2].as_i64().unwrap();
    }
    let (ok, out, err) = hexc(&[
        "-d".as_ref(),
        "symbols".as_ref(),
        "-n".as_ref(),
        "0".as_ref(),
        "-json".as_ref(),
        testdata("diff/diff-v2.exe").as_os_str(),
        "--".as_ref(),
        testdata("diff/diff-v1.exe").as_os_str(),
    ]);
    assert!(ok, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    for c in report["total"]["children"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let (change, base) = by[name];
        assert_eq!(change, c["file"].as_i64().unwrap(), "{name}");
        assert_eq!(base, c["old_file"].as_i64().unwrap(), "{name}");
    }
    // Unchanged symbols are rows too (their groups' base sizes need them).
    assert_eq!(by["kept_same(int)"].0, 0);
    assert!(by["kept_same(int)"].1 > 0);
    assert_eq!(t["file"], report["total"]["file"]);
    assert_eq!(t["old_file"], report["total"]["old_file"]);
}

#[test]
fn findings_of_elf_and_mach_o() {
    // (Their headers once read as COFF objects', which findings refused.)
    for image in ["types/types-x86_64-linux-gnu", "macho/oso/oso-arm64"] {
        let (ok, out, err) = hexc(&[
            "-findings".as_ref(),
            "-json".as_ref(),
            testdata(image).as_os_str(),
        ]);
        assert!(ok, "{image}: {err}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["duplicate_data"].is_object(), "{image}: {v}");
    }
}

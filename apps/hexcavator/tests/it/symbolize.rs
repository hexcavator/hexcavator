//! `hexc symbolize` end to end. Every byte of the source lines test
//! program's code (tools/lines: inline sites, one nested in another, and a
//! header's code), as the reference symbolizers see it
//! (tools/lines/symbolize-oracle.py): DIA for the PE image (its PDB), and
//! llvm-symbolizer for the ELF images (DWARF 5, plain and split). Then
//! addresses as offsets, as loaded, and by image name; return addresses;
//! text read, with addresses of several images in it; an image's own
//! symbols without debug information; and arguments that aren't.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn hexc(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("symbolize")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn ok(args: &[&str]) -> String {
    let (code, out, err) = hexc(args);
    assert_eq!(code, 0, "{args:?}: {err}");
    out
}

/// A frame: function, file, line, inlined.
type Frame = (String, String, u64, bool);

/// llvm-symbolizer's name without what hexc leaves out: its parameters
/// (`square(int)`), and a function template's return type
/// (`int twice<int>(int)`).
fn base_name(name: &str) -> String {
    let mut depth = 0i32;
    let mut end = name.len();
    for (i, c) in name.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            '(' if depth == 0 && i > 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let name = &name[..end];
    match (name.find(' '), name.find('<')) {
        (Some(space), Some(angle)) if space < angle => name[space + 1..].to_string(),
        _ => name.to_string(),
    }
}

/// A golden file's answers (see symbolize-oracle.py), by address.
fn golden(rel: &str, elf: bool) -> Vec<(u64, Vec<Frame>)> {
    let text = std::fs::read_to_string(testdata(rel)).unwrap();
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let (range, frames) = line.split_once('\t').unwrap();
        let (a, b) = range.split_once("..").unwrap();
        let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        let frames: Vec<Value> = serde_json::from_str(frames).unwrap();
        let frames: Vec<Frame> = frames
            .iter()
            .map(|f| {
                let name = f[0].as_str().unwrap();
                (
                    if elf {
                        base_name(name)
                    } else {
                        name.to_string()
                    },
                    f[1].as_str().unwrap().to_string(),
                    f[2].as_u64().unwrap(),
                    f[3].as_bool().unwrap(),
                )
            })
            .collect();
        for addr in hex(a)..=hex(b) {
            out.push((addr, frames.clone()));
        }
    }
    out
}

/// hexc's answers for `addrs` in `image` (with -json).
fn answers(image: &Path, addrs: &[u64]) -> Vec<Vec<Frame>> {
    let image = image.to_str().unwrap();
    let mut out = Vec::new();
    // (A few hundred at a time: a command line has a limit.)
    for chunk in addrs.chunks(500) {
        let hexs: Vec<String> = chunk.iter().map(|a| format!("{a:#x}")).collect();
        let mut args = vec!["-json", image];
        args.extend(hexs.iter().map(String::as_str));
        let json: Vec<Value> = serde_json::from_str(&ok(&args)).unwrap();
        for a in json {
            out.push(
                a["frames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        (
                            f["function"].as_str().unwrap().to_string(),
                            f["file"].as_str().unwrap_or("").to_string(),
                            f["line"].as_u64().unwrap_or(0),
                            f["inlined"].as_bool().unwrap(),
                        )
                    })
                    .collect(),
            );
        }
    }
    out
}

/// hexc gives what the golden file does at each of its addresses.
fn matches_golden(image: &str, elf: bool) {
    let want = golden(&format!("lines/{image}.symbolize.txt"), elf);
    let addrs: Vec<u64> = want.iter().map(|w| w.0).collect();
    let got = answers(&testdata(&format!("lines/{image}")), &addrs);
    assert_eq!(got.len(), want.len());
    let mut wrong = Vec::new();
    let mut named = 0;
    for ((addr, want), got) in want.iter().zip(&got) {
        // A divergence on purpose: code no procedure covers (import
        // thunks, assembly), which DIA's function lookup has nothing for,
        // named by its public symbol (as WinDbg names it), without a line.
        if want.is_empty() && got.len() == 1 && got[0].1.is_empty() && got[0].2 == 0 && !elf {
            named += 1;
            continue;
        }
        if want != got {
            wrong.push(format!("{addr:#x}\n  want {want:?}\n  got  {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} addresses differ:\n{}",
        wrong.len(),
        want.len(),
        wrong[..wrong.len().min(10)].join("\n")
    );
    // (lines.exe's import thunks, 6 bytes each, and a few of the CRT's
    // stubs: not much more.)
    assert!(
        named <= 256,
        "{named} addresses named by public symbols only"
    );
}

/// The PE image's every byte of code, as DIA has it (the CRT's too):
/// names, files, lines, and inline frames.
#[test]
fn pe_matches_dia() {
    matches_golden("lines.exe", false);
}

/// The ELF image's, as llvm-symbolizer has it.
#[test]
fn dwarf_matches_llvm_symbolizer() {
    matches_golden("lines-x86_64-linux-gnu", true);
}

/// Split DWARF: the frames from the `.dwo`, the lines (and the files of
/// the calls inlined, which the `.dwo` has no table of) from the skeleton.
#[test]
fn split_dwarf_matches_llvm_symbolizer() {
    matches_golden("lines-split-x86_64-linux-gnu", true);
}

/// The text form: frames innermost first, aligned, inlined ones marked;
/// the outermost with its offset into its function.
#[test]
fn text() {
    let exe = testdata("lines/lines.exe");
    let exe = exe.to_str().unwrap();
    assert_eq!(
        ok(&[exe, "0x140001043", "0x140001062"]),
        "0x140001043  square          R:\\tools\\lines\\lines.h:5  (inlined)\n\
         \x20            sum_of_squares  R:\\tools\\lines\\lines.h:8  (inlined)\n\
         \x20            third+0x3       R:\\tools\\lines\\lines.cpp:11\n\
         0x140001062  main+0x2  R:\\tools\\lines\\lines.cpp:13\n"
    );
    // Nothing there: said so (and not an error).
    assert_eq!(ok(&[exe, "0x1"]), "0x1  ?? (nothing in lines.exe there)\n");
}

/// An address as an offset, as loaded at a base, and by the image's name
/// (with its extension or without): the same frames.
#[test]
fn offsets_bases_and_names() {
    let exe = testdata("lines/lines.exe");
    let exe = exe.to_str().unwrap();
    let frames = |out: &str| -> Vec<String> {
        out.lines()
            .map(|l| {
                l.split_whitespace()
                    .skip(usize::from(!l.starts_with(' ')))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    };
    let want = frames(&ok(&[exe, "0x140001043"]));
    assert_eq!(frames(&ok(&["-offset", exe, "0x1043"])), want);
    assert_eq!(frames(&ok(&[exe, "lines+0x1043"])), want);
    assert_eq!(frames(&ok(&[exe, "LINES.EXE+1043"])), want);
    let loaded = format!("{exe}@0x7ff600000000");
    assert_eq!(frames(&ok(&[&loaded, "0x7ff600001043"])), want);
    // WinDbg's 64-bit form.
    assert_eq!(frames(&ok(&[&loaded, "00007ff6`00001043"])), want);
    // A return address: the call before it (shown with its own offset).
    let ret = ok(&["-return", exe, "0x140001044"]);
    assert!(ret.contains("third+0x4"), "{ret}");
    assert_eq!(frames(&ret)[..2], want[..2]);
}

/// Text read: each address in it followed by where it is, for several
/// images, in the forms logs and stack traces write them; other numbers
/// and text as they were.
#[test]
fn text_read() {
    let dir = std::env::temp_dir().join(format!("hexc-symbolize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("crash.txt");
    std::fs::write(
        &log,
        "at 0x140001043 and lines.exe+0x1062\n\
         and 0xdeadbeef 1234\n\
         \x20 #00 pc 00000000000011c0  /system/lib/lines-x86_64-linux-gnu\n\
         ./lines-x86_64-linux-gnu(+0x11d2) [0x7f0000]\n",
    )
    .unwrap();
    let exe = testdata("lines/lines.exe");
    let elf = testdata("lines/lines-x86_64-linux-gnu");
    let out = ok(&[
        exe.to_str().unwrap(),
        elf.to_str().unwrap(),
        "-input",
        log.to_str().unwrap(),
    ]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        out,
        "at 0x140001043 [square (R:\\tools\\lines\\lines.h:5), inlined in sum_of_squares (R:\\tools\\lines\\lines.h:8), inlined in lines.exe!third+0x3 (R:\\tools\\lines\\lines.cpp:11)] and lines.exe+0x1062 [lines.exe!main+0x2 (R:\\tools\\lines\\lines.cpp:13)]\n\
         and 0xdeadbeef 1234\n\
         \x20 #00 pc 00000000000011c0 [square (./lines.h:5), inlined in lines-x86_64-linux-gnu!first (./lines-elf.cpp:6)]  /system/lib/lines-x86_64-linux-gnu\n\
         ./lines-x86_64-linux-gnu(+0x11d2) [square (./lines.h:5), inlined in lines-x86_64-linux-gnu!second+0x2 (./lines-elf.cpp:8)] [0x7f0000]\n"
    );
}

/// Text read on standard input (a pipe).
#[test]
fn standard_input() {
    use std::io::Write;
    let exe = testdata("lines/lines.exe");
    let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["symbolize", exe.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"0x140001062\nno address\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "0x140001062 [main+0x2 (R:\\tools\\lines\\lines.cpp:13)]\nno address\n"
    );
}

/// Without debug information: the image's own symbols (ELF's symbol
/// table, sized; Mach-O's, a C name without its `_`).
#[test]
fn image_symbols() {
    let elf = testdata("elf/hardened-x86_64-linux-gnu");
    assert_eq!(
        ok(&[elf.to_str().unwrap(), "0x1371", "0x1300"]),
        "0x1371  compute+0x1\n0x1300  ?? (nothing in hardened-x86_64-linux-gnu there)\n"
    );
    let macho = testdata("macho/libsecond-arm64.dylib");
    assert_eq!(
        ok(&[macho.to_str().unwrap(), "0x31c"]),
        "0x31c  second_len+0x4\n"
    );
}

/// JSON: each address with its image and frames (offsets for functions,
/// not inlined copies).
#[test]
fn json() {
    let exe = testdata("lines/lines.exe");
    let out: Value =
        serde_json::from_str(&ok(&["-json", exe.to_str().unwrap(), "0x140001043"])).unwrap();
    assert_eq!(out[0]["address"], "0x140001043");
    assert_eq!(out[0]["module"], "lines.exe");
    let frames = out[0]["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["function"], "square");
    assert_eq!(frames[0]["inlined"], true);
    assert!(frames[0]["offset"].is_null());
    assert_eq!(frames[2]["function"], "third");
    assert_eq!(frames[2]["offset"], 3);
    assert_eq!(frames[2]["line"], 11);
}

/// Arguments that aren't: usage errors (exit 2), and failures (exit 1)
/// that still answer the rest.
#[test]
fn bad_arguments() {
    let exe = testdata("lines/lines.exe");
    let exe = exe.to_str().unwrap();
    for args in [
        &[][..],
        &["-nonesuch", exe],
        &["-json", exe],
        &["-input"],
        &[exe, "0x1", "-input", "x.txt"],
        &["lines.exe@nothex"],
    ] {
        let (code, out, err) = hexc(args);
        assert_eq!(code, 2, "{args:?}: {out}{err}");
        assert!(err.contains("usage: hexc symbolize"), "{args:?}: {err}");
    }
    // An image that isn't there, or isn't one.
    let (code, _, err) = hexc(&["no-such-file.exe", "0x1"]);
    assert_eq!(code, 1, "{err}");
    let notes = testdata("lines/lines.exe.symbolize.txt");
    let (code, _, err) = hexc(&[notes.to_str().unwrap(), "0x1"]);
    assert_eq!(code, 1, "{err}");
    // An image name not given: said, and the rest answered.
    let (code, out, err) = hexc(&[exe, "other.dll+0x10", "0x140001062"]);
    assert_eq!(code, 1);
    assert!(err.contains("no image named 'other.dll'"), "{err}");
    assert!(out.starts_with("0x140001062  main+0x2"), "{out}");
    // Addresses past anything (and past 64 bits): nothing there.
    let (code, out, _) = hexc(&[exe, "0xffffffffffffffff", "-offset"]);
    assert_eq!(code, 0);
    assert!(out.contains("??"), "{out}");
}

/// Served (`hexc serve`): addresses are answered; text is read from a
/// file only (standard input is the server's requests).
#[test]
fn served() {
    use std::io::Write;
    let exe = testdata("lines/lines.exe");
    let exe = serde_json::to_string(exe.to_str().unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = format!(
        "{{\"id\": 1, \"args\": [\"symbolize\", {exe}, \"0x140001062\"]}}\n\
         {{\"id\": 2, \"args\": [\"symbolize\", {exe}]}}\n"
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let mut answers: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    answers.sort_by_key(|a| a["id"].as_i64());
    assert_eq!(answers[0]["code"], 0);
    assert!(answers[0]["stdout"].as_str().unwrap().contains("main+0x2"));
    assert_eq!(answers[1]["code"], 2);
    assert!(
        answers[1]["stderr"]
            .as_str()
            .unwrap()
            .contains("no addresses or -input")
    );
}

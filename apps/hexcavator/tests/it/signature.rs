//! `hexc signature`: Authenticode (RSA with a nested signature, ECDSA),
//! verified against a test root given with -root; untrusted without it;
//! a changed file fails; an unsigned one says so; and a Mach-O image the
//! linker signed ad hoc has its pages checked.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(args: &[&str]) -> (serde_json::Value, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .arg("signature")
        .args(args)
        .output()
        .unwrap();
    let v = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    (v, out.status.success())
}

fn file(p: &str) -> String {
    root().join(p).display().to_string()
}

fn check<'a>(checks: &'a serde_json::Value, name: &str) -> &'a str {
    checks
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("{name}: {checks}"))["status"]
        .as_str()
        .unwrap()
}

#[test]
fn authenticode_with_a_nested_signature() {
    let test_root = file("testdata/signature/test-root.cer");
    let (v, ok) = run(&[
        "-json",
        "-root",
        &test_root,
        &file("testdata/signature/signed.exe"),
    ]);
    assert!(ok, "{v}");
    let sigs = v["authenticode"].as_array().unwrap();
    assert_eq!(sigs.len(), 2, "{v}");
    // The primary: SHA-1 (a warning), the nested: SHA-256.
    assert_eq!(sigs[0]["kind"], "Authenticode");
    assert_eq!(sigs[0]["status"], "warn");
    assert_eq!(sigs[0]["fileDigest"]["algorithm"], "SHA-1");
    assert_eq!(sigs[1]["kind"], "Authenticode (nested)");
    assert_eq!(sigs[1]["status"], "pass", "{}", sigs[1]);
    assert_eq!(sigs[1]["fileDigest"]["algorithm"], "SHA-256");
    let signer = &sigs[1]["signer"];
    assert_eq!(signer["name"], "Hexcavator Test Signer");
    for name in [
        "Message digest",
        "Signature",
        "Chain",
        "Validity",
        "Usage",
        "Trust",
    ] {
        assert_eq!(check(&signer["checks"], name), "pass", "{name}");
    }
    assert_eq!(check(&sigs[1]["checks"], "File hash"), "pass");
    let links = signer["chain"]["links"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    assert_eq!(links[1]["certificate"]["name"], "Hexcavator Test Root");
    assert_eq!(links[1]["fromRoots"], true);
    // Without the test root: it checks, but nothing trusted vouches for it.
    let (v, _) = run(&["-json", &file("testdata/signature/signed.exe")]);
    let signer = &v["authenticode"][1]["signer"];
    assert_eq!(check(&signer["checks"], "Signature"), "pass");
    assert_eq!(check(&signer["checks"], "Trust"), "warn");
    assert_ne!(v["authenticode"][1]["status"], "pass");
}

#[test]
fn authenticode_by_ecdsa() {
    let test_root = file("testdata/signature/test-root.cer");
    let (v, ok) = run(&[
        "-json",
        "-root",
        &test_root,
        &file("testdata/signature/signed-ecdsa.exe"),
    ]);
    assert!(ok, "{v}");
    let s = &v["authenticode"][0];
    assert_eq!(s["status"], "pass", "{s}");
    assert_eq!(
        s["signer"]["chain"]["links"][0]["certificate"]["key"],
        "ECDSA P-256"
    );
}

#[test]
fn a_changed_file_fails() {
    let mut data = std::fs::read(root().join("testdata/signature/signed-ecdsa.exe")).unwrap();
    // A byte of code (well before the certificates).
    data[0x500] ^= 0xFF;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join("signature-changed.exe");
    std::fs::write(&path, &data).unwrap();
    let test_root = file("testdata/signature/test-root.cer");
    let (v, ok) = run(&["-json", "-root", &test_root, &path.display().to_string()]);
    assert!(!ok);
    let s = &v["authenticode"][0];
    assert_eq!(s["status"], "fail");
    assert_eq!(check(&s["checks"], "File hash"), "fail");
    assert_ne!(s["fileDigest"]["signed"], s["fileDigest"]["file"]);
    // (The signer's own signature still checks: it's the file that changed.)
    assert_eq!(check(&s["signer"]["checks"], "Signature"), "pass");
}

#[test]
fn unsigned() {
    let (v, ok) = run(&["-json", &file("testdata/types/types.exe")]);
    assert!(!ok);
    assert_eq!(v["status"], "unsigned");
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args(["signature", &file("testdata/types/types.exe")])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("Unsigned"));
}

#[test]
fn macho_signed_ad_hoc_by_the_linker() {
    let (v, ok) = run(&["-json", &file("testdata/macho/oso/oso-arm64")]);
    assert!(ok, "{v}");
    let a = &v["apple"][0];
    assert_eq!(a["arch"], "arm64");
    assert_eq!(a["identifier"], "oso-arm64");
    assert_eq!(a["adhoc"], true);
    assert_eq!(a["linkerSigned"], true);
    assert_eq!(a["status"], "warn");
    assert_eq!(check(&a["checks"], "Code pages"), "pass");
    assert_eq!(a["directories"][0]["hash"], "SHA-256");
    assert_eq!(a["directories"][0]["cdhash"].as_str().unwrap().len(), 40);
    // A page changed: it fails.
    let mut data = std::fs::read(root().join("testdata/macho/oso/oso-arm64")).unwrap();
    data[0x4100] ^= 0xFF;
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("signature-changed-arm64");
    std::fs::write(&path, &data).unwrap();
    let (v, ok) = run(&["-json", &path.display().to_string()]);
    assert!(!ok);
    assert_eq!(check(&v["apple"][0]["checks"], "Code pages"), "fail");
}

#[test]
fn version_details() {
    // (A SizeBench test DLL with Visual Studio's template version resource:
    // the values Windows' FileVersionInfo gives.)
    let (v, _) = run(&[
        "-json",
        &file("testdata/sizebench/bin/SizeBenchV2.AnalysisEngine.Tests.CodePageWin32Rsrc.dll"),
    ]);
    let info: Vec<(String, String)> = v["info"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["name"].as_str().unwrap().to_string(),
                x["value"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let get = |k: &str| info.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("Company"), Some("TODO: <Company name>"));
    assert_eq!(get("Description"), Some("TODO: <File description>"));
    assert_eq!(get("Product"), Some("TODO: <Product name>"));
    assert_eq!(get("Product version"), Some("1.0.0.1"));
    assert_eq!(get("File version"), Some("1.0.0.1"));
    assert_eq!(get("File version (binary)"), Some("1.0.0.1"));
    assert_eq!(get("Copyright"), Some("Copyright (C) 2024"));
    assert_eq!(
        get("Original file name"),
        Some("SizeBenchV2.AnalysisEngine.Tests.CodePageWin32Rsr")
    );
    assert_eq!(get("Language"), Some("0x0409, code page 1200"));
    // And in the text, before the signature.
    let out = Command::new(env!("CARGO_BIN_EXE_hexc"))
        .args([
            "signature",
            &file("testdata/sizebench/bin/SizeBenchV2.AnalysisEngine.Tests.CodePageWin32Rsrc.dll"),
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.find("Company").unwrap() < text.find("Unsigned").unwrap(),
        "{text}"
    );
}

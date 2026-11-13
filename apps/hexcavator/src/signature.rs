//! `hexc signature`: a binary's code signatures (Authenticode, Apple code
//! signing), read and verified here, whatever the platform: who signed it,
//! when, with what, and whether it's unchanged and trusted.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use hexcavator_mmap::Mmap;
use hexcavator_signature::{
    CertInfo, Check, CodeSignature, Report, Signature, Signer, Status, Timestamp,
};
use serde_json::{Value as Json, json};

const USAGE: &str = "\
usage: hexc signature [-json] [-root <cert>]... <image>...

Reads and verifies a PE image's Authenticode signatures (and those nested in
them) or a Mach-O image's code signature (each architecture's), on any
platform: the file's hash, the signer's signature, the certificate chain,
the timestamps, and (for Mach-O) each page of code, the entitlements, and
the requirements.

Trust is hexc's own list of roots (Microsoft's, Apple's, and the public code
signing authorities), not the machine's; -root adds one (DER or PEM).
Revocation isn't checked, nor signatures kept outside the file (a Windows
catalog's, a notarization ticket).

Exit status: 0 if every file is signed and verifies, 1 if not.";

pub fn run(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut files = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.strip_prefix('-') {
            Some("json") => json = true,
            Some("root") => match it.next() {
                Some(p) => match std::fs::read(p)
                    .map_err(|e| e.to_string())
                    .and_then(|d| hexcavator_signature::roots::add(&d))
                {
                    Ok(_) => {}
                    Err(e) => {
                        ereport!("hexc signature: -root {p}: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => {
                    ereport!("hexc signature: -root: expected a certificate's path");
                    return ExitCode::from(2);
                }
            },
            Some(x) if !x.is_empty() && !Path::new(a).exists() => {
                ereport!("hexc signature: unknown option '{a}'\n\n{USAGE}");
                return ExitCode::from(2);
            }
            _ => files.push(a.clone()),
        }
    }
    if files.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut status = ExitCode::SUCCESS;
    let mut all = Vec::new();
    let mut text = String::new();
    for f in &files {
        let report = Mmap::open(f)
            .map_err(|e| format!("{f}: {e}"))
            .and_then(|m| hexcavator_signature::of_file(&m).map_err(|e| format!("{f}: {e}")));
        match report {
            Ok(r) => {
                if !verified(&r) {
                    status = ExitCode::FAILURE;
                }
                if json {
                    all.push(to_json(f, &r));
                } else {
                    write_text(f, &r, &mut text);
                }
            }
            Err(e) => {
                ereport!("hexc signature: {e}");
                status = ExitCode::FAILURE;
            }
        }
    }
    let text = if json {
        let v = if all.len() == 1 {
            all.remove(0)
        } else {
            Json::Array(all)
        };
        format!("{v}\n")
    } else {
        text
    };
    if !crate::out::printed(text.as_bytes()) {
        return ExitCode::FAILURE;
    }
    status
}

/// Whether every signature of the file verifies (a warning, such as an
/// unknown root or ad hoc signing, doesn't).
fn verified(r: &Report) -> bool {
    r.signed()
        && r.authenticode.iter().all(|s| s.status != Status::Fail)
        && r.apple.iter().all(|s| s.status != Status::Fail)
}

/// The JSON of a file's signatures (what the Build Information page shows).
pub fn to_json(path: &str, r: &Report) -> Json {
    let status = if r.signed() {
        let worst = r
            .authenticode
            .iter()
            .map(|s| s.status)
            .chain(r.apple.iter().map(|s| s.status))
            .max_by_key(|s| rank(*s))
            .unwrap_or(Status::Pass);
        worst.key()
    } else {
        "unsigned"
    };
    json!({
        "path": path,
        "format": r.format,
        "status": status,
        "info": r.info.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect::<Vec<_>>(),
        "authenticode": r.authenticode.iter().map(signature_json).collect::<Vec<_>>(),
        "apple": r.apple.iter().map(apple_json).collect::<Vec<_>>(),
        "roots": hexcavator_signature::roots::bundled_names().count(),
    })
}

fn rank(s: Status) -> u8 {
    match s {
        Status::Pass => 0,
        Status::Warn => 1,
        Status::Unknown => 2,
        Status::Fail => 3,
    }
}

fn check_json(c: &Check) -> Json {
    json!({ "name": c.name, "status": c.status.key(), "detail": c.detail })
}

fn cert_json(c: &CertInfo) -> Json {
    json!({
        "name": c.name,
        "subject": c.subject,
        "issuer": c.issuer,
        "serial": c.serial,
        "notBefore": c.not_before.to_string(),
        "notAfter": c.not_after.to_string(),
        "key": c.key,
        "signatureAlgorithm": c.signature_algorithm,
        "sha1": c.sha1,
        "sha256": c.sha256,
        "usages": c.usages,
        "keyUsage": c.key_usage,
        "ca": c.ca,
        "selfSigned": c.self_signed,
        "version": c.version,
    })
}

fn signer_json(s: &Signer) -> Json {
    json!({
        "name": s.name,
        "digestAlgorithm": s.digest_algorithm,
        "signatureAlgorithm": s.signature_algorithm,
        "signingTime": s.signing_time.map(|t| t.to_string()),
        "checks": s.checks.iter().map(check_json).collect::<Vec<_>>(),
        "chain": s.chain.as_ref().map(|c| json!({
            "trusted": c.trusted,
            "links": c.links.iter().map(|l| json!({
                "certificate": cert_json(&l.certificate),
                "fromRoots": l.from_roots,
                "signed": match &l.signed {
                    None => Json::Null,
                    Some(Ok(())) => json!("pass"),
                    Some(Err(e)) => json!(e.to_string()),
                },
            })).collect::<Vec<_>>(),
        })),
    })
}

fn stamp_json(t: &Timestamp) -> Json {
    json!({ "kind": t.kind, "time": t.time.map(|t| t.to_string()), "signer": signer_json(&t.signer) })
}

fn signature_json(s: &Signature) -> Json {
    json!({
        "kind": s.kind,
        "status": s.status.key(),
        "summary": s.summary,
        "program": s.program,
        "url": s.url,
        "fileDigest": s.file_digest.as_ref().map(|(a, signed, file)| json!({ "algorithm": a, "signed": signed, "file": file })),
        "checks": s.checks.iter().map(check_json).collect::<Vec<_>>(),
        "signer": s.signer.as_ref().map(signer_json),
        "timestamps": s.timestamps.iter().map(stamp_json).collect::<Vec<_>>(),
        "certificates": s.certificates.iter().map(cert_json).collect::<Vec<_>>(),
    })
}

fn apple_json(c: &CodeSignature) -> Json {
    json!({
        "arch": c.arch,
        "status": c.status.key(),
        "summary": c.summary,
        "identifier": c.identifier,
        "team": c.team,
        "flags": format!("{:#x}", c.flags),
        "flagNames": c.flag_names,
        "version": format!("{:#x}", c.version),
        "platform": c.platform,
        "runtime": c.runtime,
        "execSegment": c.exec_segment,
        "adhoc": c.adhoc,
        "linkerSigned": c.linker_signed,
        "directories": c.directories.iter().map(|d| json!({
            "hash": d.hash,
            "pageSize": d.page_size,
            "codeSlots": d.code_slots,
            "specialSlots": d.special_slots,
            "codeLimit": d.code_limit,
            "cdhash": d.cdhash,
        })).collect::<Vec<_>>(),
        "requirements": c.requirements,
        "entitlements": c.entitlements,
        "checks": c.checks.iter().map(check_json).collect::<Vec<_>>(),
        "signature": c.signature.as_ref().map(signature_json),
    })
}

// ------------------------------------------------------------------- text

fn mark(s: Status) -> &'static str {
    match s {
        Status::Pass => "ok  ",
        Status::Fail => "FAIL",
        Status::Warn => "warn",
        Status::Unknown => "?   ",
    }
}

fn verdict(s: Status) -> &'static str {
    match s {
        Status::Pass => "Verified",
        Status::Fail => "NOT VERIFIED",
        Status::Warn => "Verified, with warnings",
        Status::Unknown => "Couldn't verify",
    }
}

fn write_text(path: &str, r: &Report, out: &mut String) {
    let _ = writeln!(out, "{path}:");
    // What it says it is (as sigcheck shows it, before its signature).
    for (k, v) in &r.info {
        let _ = writeln!(out, "  {k:<26}{v}");
    }
    if !r.info.is_empty() {
        out.push('\n');
    }
    if !r.signed() {
        let _ = writeln!(
            out,
            "  Unsigned{}\n",
            if r.format == "pe" {
                " (no embedded signature; a Windows file may be signed in a catalog)"
            } else {
                ""
            }
        );
        return;
    }
    for s in &r.authenticode {
        signature_text(s, "  ", out);
    }
    for c in &r.apple {
        let _ = writeln!(out, "  {} ({}): {}", verdict(c.status), c.arch, c.summary);
        let field = |out: &mut String, k: &str, v: &str| {
            if !v.is_empty() {
                let _ = writeln!(out, "    {k:<16}{v}");
            }
        };
        field(out, "Identifier", &c.identifier);
        field(out, "Team ID", c.team.as_deref().unwrap_or(""));
        field(
            out,
            "Flags",
            &format!("{:#x} ({})", c.flags, c.flag_names.join(", ")),
        );
        field(out, "Runtime", c.runtime.as_deref().unwrap_or(""));
        field(out, "Exec segment", &c.exec_segment.join(", "));
        for d in &c.directories {
            field(
                out,
                "Code directory",
                &format!(
                    "{}, {} pages of {} bytes, {} special slots; CDHash {}",
                    d.hash, d.code_slots, d.page_size, d.special_slots, d.cdhash
                ),
            );
        }
        for q in &c.requirements {
            field(out, "Requirement", q);
        }
        if let Some(e) = &c.entitlements {
            field(out, "Entitlements", &format!("{} bytes", e.len()));
        }
        for k in &c.checks {
            let _ = writeln!(out, "    [{}] {}: {}", mark(k.status), k.name, k.detail);
        }
        if let Some(s) = &c.signature {
            signature_text(s, "    ", out);
        }
        out.push('\n');
    }
}

fn signature_text(s: &Signature, pad: &str, out: &mut String) {
    let _ = writeln!(
        out,
        "{pad}{} ({}): {}",
        verdict(s.status),
        s.kind,
        s.summary
    );
    let field = |out: &mut String, k: &str, v: &str| {
        if !v.is_empty() {
            let _ = writeln!(out, "{pad}  {k:<16}{v}");
        }
    };
    if let Some(sig) = &s.signer {
        field(out, "Signer", &sig.name);
        if let Some(t) = sig.signing_time {
            field(out, "Signing time", &t.to_string());
        }
        field(
            out,
            "Algorithms",
            &format!("{}, {}", sig.digest_algorithm, sig.signature_algorithm),
        );
    }
    field(out, "Program", s.program.as_deref().unwrap_or(""));
    field(out, "URL", s.url.as_deref().unwrap_or(""));
    if let Some((alg, signed, file)) = &s.file_digest {
        field(out, "Signed hash", &format!("{alg} {signed}"));
        if file.as_deref() != Some(signed) {
            field(out, "File's hash", file.as_deref().unwrap_or("?"));
        }
    }
    for k in s
        .checks
        .iter()
        .chain(s.signer.iter().flat_map(|x| x.checks.iter()))
    {
        let _ = writeln!(out, "{pad}  [{}] {}: {}", mark(k.status), k.name, k.detail);
    }
    if let Some(chain) = s.signer.as_ref().and_then(|x| x.chain.as_ref()) {
        let _ = writeln!(out, "{pad}  Chain:");
        for (i, l) in chain.links.iter().enumerate() {
            let c = &l.certificate;
            let _ = writeln!(
                out,
                "{pad}    {}{}{}  ({}, {} to {}, SHA-1 {})",
                "  ".repeat(i),
                c.name,
                if l.from_roots { " [trusted root]" } else { "" },
                c.key,
                &c.not_before.to_string()[..10],
                &c.not_after.to_string()[..10],
                c.sha1
            );
        }
    }
    for t in &s.timestamps {
        let _ = writeln!(
            out,
            "{pad}  Timestamp ({}): {} by {}",
            t.kind,
            t.time.map_or_else(|| "?".to_string(), |t| t.to_string()),
            t.signer.name
        );
        for k in &t.signer.checks {
            let _ = writeln!(
                out,
                "{pad}    [{}] {}: {}",
                mark(k.status),
                k.name,
                k.detail
            );
        }
    }
}

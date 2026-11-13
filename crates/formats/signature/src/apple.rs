//! Apple code signing: a Mach-O image's embedded signature (its
//! LC_CODE_SIGNATURE superblob): its code directories (what's signed, by
//! hash: each page of code, and the other blobs), checked against the
//! file; its requirements and entitlements; and its CMS signature (a
//! Developer ID's, or Apple's), checked as Authenticode's are.

use hexcavator_macho::MachO;

use crate::authenticode::{Signature, summarize, unreadable};
use crate::cms::SignedData;
use crate::crypto::Hash;
use crate::oid;
use crate::verify::{self, CertInfo, Check, Status};
use crate::x509::hex;

const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
const CSMAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;
const CSMAGIC_DER_ENTITLEMENTS: u32 = 0xFADE_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
const CSSLOT_ALTERNATE: u32 = 0x1000;
const CSSLOT_SIGNATURE: u32 = 0x10000;

/// One image's code signature (one architecture's, in a universal file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeSignature {
    pub arch: String,
    pub identifier: String,
    pub team: Option<String>,
    /// The flags (`CS_*`), and their names.
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub version: u32,
    pub platform: u8,
    /// The hardened runtime's version (if it's on).
    pub runtime: Option<String>,
    /// The executable segment's flags, by name.
    pub exec_segment: Vec<&'static str>,
    /// Each code directory: its hash, page size, slots, and cdhash.
    pub directories: Vec<Directory>,
    /// Signed ad hoc (no signer: only its hashes).
    pub adhoc: bool,
    /// Signed by the linker (ad hoc, and only the code).
    pub linker_signed: bool,
    /// Its requirements, as `codesign -d -r-` shows them.
    pub requirements: Vec<String>,
    /// Its entitlements (a property list's XML).
    pub entitlements: Option<String>,
    /// Checks of the hashes: the code pages and the other blobs.
    pub checks: Vec<Check>,
    /// Its CMS signature (none if ad hoc).
    pub signature: Option<Signature>,
    pub status: Status,
    pub summary: String,
}

/// A code directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    pub hash: String,
    pub page_size: u64,
    pub code_slots: u32,
    pub special_slots: u32,
    pub code_limit: u64,
    /// The CDHash (its hash, truncated to 20 bytes), hex.
    pub cdhash: String,
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn be64(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        d.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn cd_hash(kind: u8) -> Option<(Hash, &'static str)> {
    Some(match kind {
        1 => (Hash::Sha1, "SHA-1"),
        2 => (Hash::Sha256, "SHA-256"),
        3 => (Hash::Sha256, "SHA-256 (truncated)"),
        4 => (Hash::Sha384, "SHA-384"),
        _ => return None,
    })
}

const FLAGS: &[(u32, &str)] = &[
    (0x1, "valid"),
    (0x2, "adhoc"),
    (0x4, "get-task-allow"),
    (0x8, "installer"),
    (0x10, "forced-lv"),
    (0x20, "invalid-allowed"),
    (0x100, "hard"),
    (0x200, "kill"),
    (0x400, "check-expiration"),
    (0x800, "restrict"),
    (0x1000, "enforcement"),
    (0x2000, "library-validation"),
    (0x10000, "runtime"),
    (0x20000, "linker-signed"),
];

const EXEC_FLAGS: &[(u64, &str)] = &[
    (0x1, "main binary"),
    (0x10, "allow unsigned"),
    (0x20, "debugger"),
    (0x40, "jit"),
    (0x80, "skip library validation"),
    (0x100, "can load cdhash"),
    (0x200, "can exec cdhash"),
];

/// The code signature of the Mach-O image `m`, if it has one.
pub fn macho(m: &MachO<'_>, arch: String) -> Option<CodeSignature> {
    let lc = m
        .load_commands()
        .into_iter()
        .find(|c| c.cmd == hexcavator_macho::consts::LC_CODE_SIGNATURE)?;
    let (off, size) = m.linkedit_data(&lc)?;
    let image = m.data();
    let Some(sig) = image.get(off as usize..(off as usize).checked_add(size as usize)?) else {
        return Some(broken(arch, "the signature lies past the end of the file"));
    };
    if be32(sig, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        return Some(broken(arch, "not an embedded signature (its magic)"));
    }
    // The blobs, by slot.
    let count = be32(sig, 8).unwrap_or(0) as usize;
    let mut blobs: Vec<(u32, &[u8])> = Vec::new();
    for i in 0..count.min(64) {
        let (Some(slot), Some(at)) = (be32(sig, 12 + i * 8), be32(sig, 16 + i * 8)) else {
            break;
        };
        let at = at as usize;
        let Some(len) = be32(sig, at + 4) else {
            continue;
        };
        if let Some(b) = sig.get(at..at.saturating_add(len as usize))
            && b.len() >= 8
        {
            blobs.push((slot, b));
        }
    }
    let blob = |slot: u32| blobs.iter().find(|(s, _)| *s == slot).map(|(_, b)| *b);
    let directories: Vec<&[u8]> = blobs
        .iter()
        .filter(|(s, b)| {
            (*s == 0 || (CSSLOT_ALTERNATE..CSSLOT_ALTERNATE + 5).contains(s))
                && be32(b, 0) == Some(CSMAGIC_CODEDIRECTORY)
        })
        .map(|(_, b)| *b)
        .collect();
    let Some(&primary) = directories.first() else {
        return Some(broken(arch, "no code directory"));
    };
    let mut out = CodeSignature {
        arch,
        identifier: String::new(),
        team: None,
        flags: 0,
        flag_names: Vec::new(),
        version: 0,
        platform: 0,
        runtime: None,
        exec_segment: Vec::new(),
        directories: Vec::new(),
        adhoc: false,
        linker_signed: false,
        requirements: Vec::new(),
        entitlements: None,
        checks: Vec::new(),
        signature: None,
        status: Status::Unknown,
        summary: String::new(),
    };
    let string = |cd: &[u8], at: u32| -> Option<String> {
        let s = cd.get(at as usize..)?;
        let s = &s[..s.iter().position(|&c| c == 0)?];
        Some(String::from_utf8_lossy(s).into_owned())
    };
    // The primary directory: who and how.
    let cd = primary;
    out.version = be32(cd, 8).unwrap_or(0);
    out.flags = be32(cd, 12).unwrap_or(0);
    out.flag_names = FLAGS
        .iter()
        .filter(|(b, _)| out.flags & b != 0)
        .map(|(_, n)| *n)
        .collect();
    out.identifier = be32(cd, 20).and_then(|o| string(cd, o)).unwrap_or_default();
    out.platform = cd.get(38).copied().unwrap_or(0);
    if out.version >= 0x20200 {
        out.team = be32(cd, 48).filter(|&o| o != 0).and_then(|o| string(cd, o));
    }
    if out.version >= 0x20400
        && let Some(f) = be64(cd, 80)
    {
        out.exec_segment = EXEC_FLAGS
            .iter()
            .filter(|(b, _)| f & b != 0)
            .map(|(_, n)| *n)
            .collect();
    }
    if out.version >= 0x20500
        && out.flags & 0x10000 != 0
        && let Some(r) = be32(cd, 88)
    {
        out.runtime = Some(format!("{}.{}.{}", r >> 16, (r >> 8) & 0xFF, r & 0xFF));
    }
    out.adhoc = out.flags & 0x2 != 0;
    out.linker_signed = out.flags & 0x20000 != 0;
    // Each directory: its pages and special slots, checked.
    for &cd in &directories {
        let Some(d) = directory(cd, image, &blobs, &mut out.checks) else {
            continue;
        };
        out.directories.push(d);
    }
    // Requirements, entitlements.
    if let Some(r) = blob(2).filter(|b| be32(b, 0) == Some(CSMAGIC_REQUIREMENTS)) {
        out.requirements = crate::requirement::decode_set(r);
    }
    if let Some(e) = blob(5).filter(|b| be32(b, 0) == Some(CSMAGIC_ENTITLEMENTS)) {
        out.entitlements = Some(String::from_utf8_lossy(&e[8..]).into_owned());
    } else if blob(7).is_some_and(|b| be32(b, 0) == Some(CSMAGIC_DER_ENTITLEMENTS)) {
        out.entitlements = Some("(DER entitlements only)".into());
    }
    // The CMS signature: of the primary directory.
    let cms =
        blob(CSSLOT_SIGNATURE).filter(|b| be32(b, 0) == Some(CSMAGIC_BLOBWRAPPER) && b.len() > 8);
    match cms {
        Some(b) => out.signature = Some(cms_signature(&b[8..], primary, &out.directories)),
        None => {
            if !out.adhoc {
                out.checks.push(Check {
                    name: "Signature",
                    status: Status::Fail,
                    detail: "not ad hoc, but no CMS signature".into(),
                });
            }
        }
    }
    let (status, summary) = verdict(&out);
    out.status = status;
    out.summary = summary;
    Some(out)
}

fn broken(arch: String, why: &str) -> CodeSignature {
    CodeSignature {
        arch,
        identifier: String::new(),
        team: None,
        flags: 0,
        flag_names: Vec::new(),
        version: 0,
        platform: 0,
        runtime: None,
        exec_segment: Vec::new(),
        directories: Vec::new(),
        adhoc: false,
        linker_signed: false,
        requirements: Vec::new(),
        entitlements: None,
        checks: vec![Check {
            name: "Format",
            status: Status::Fail,
            detail: why.into(),
        }],
        signature: None,
        status: Status::Fail,
        summary: format!("unreadable: {why}"),
    }
}

/// A code directory, its hashes checked against the image and the blobs.
fn directory(
    cd: &[u8],
    image: &[u8],
    blobs: &[(u32, &[u8])],
    checks: &mut Vec<Check>,
) -> Option<Directory> {
    let version = be32(cd, 8)?;
    let hash_offset = be32(cd, 16)? as usize;
    let special_slots = be32(cd, 24)?;
    let code_slots = be32(cd, 28)?;
    let mut code_limit = u64::from(be32(cd, 32)?);
    let hash_size = usize::from(*cd.get(36)?);
    let (hash, name) = cd_hash(*cd.get(37)?)?;
    let page_log = *cd.get(39)?;
    if version >= 0x20300
        && let Some(l) = be64(cd, 56).filter(|&l| l != 0)
    {
        code_limit = l;
    }
    let page_size = if page_log == 0 || page_log >= 32 {
        0
    } else {
        1u64 << page_log
    };
    let cdhash = hash.digest(cd);
    let d = Directory {
        hash: name.into(),
        page_size,
        code_slots,
        special_slots,
        code_limit,
        cdhash: hex(&cdhash[..20.min(cdhash.len())]),
    };
    // A code slot's hash (page `n`'s), or (`special`) special slot `n`'s,
    // which lie before the code slots.
    let slot_hash = |special: bool, n: usize| -> Option<&[u8]> {
        let step = n.checked_mul(hash_size)?;
        let at = if special {
            hash_offset.checked_sub(step)?
        } else {
            hash_offset.checked_add(step)?
        };
        cd.get(at..at.checked_add(hash_size)?)
    };
    // The pages of code.
    let wanted = usize::try_from(code_limit).unwrap_or(usize::MAX);
    let limit = wanted.min(image.len());
    let page = usize::try_from(page_size).unwrap_or(usize::MAX);
    let mut bad = Vec::new();
    let pages = if page == 0 { 1 } else { limit.div_ceil(page) };
    if u32::try_from(pages).ok() != Some(code_slots) || limit < wanted {
        checks.push(Check {
            name: "Code pages",
            status: Status::Fail,
            detail: format!("{name}: {code_slots} pages signed, but the file holds {pages}"),
        });
    } else {
        for j in 0..pages.min(1 << 24) {
            let start = j.saturating_mul(page).min(limit);
            let end = if page == 0 {
                limit
            } else {
                start.saturating_add(page).min(limit)
            };
            let h = hash.digest(&image[start..end]);
            if slot_hash(false, j).is_none_or(|s| s != &h[..hash_size.min(h.len())]) {
                bad.push(j);
            }
        }
        checks.push(if bad.is_empty() {
            Check {
                name: "Code pages",
                status: Status::Pass,
                detail: format!("{name}: all {pages} pages match (the first {code_limit} bytes)"),
            }
        } else {
            Check {
                name: "Code pages",
                status: Status::Fail,
                detail: format!(
                    "{name}: {} of {pages} pages changed (the first at {:#x})",
                    bad.len(),
                    bad[0].saturating_mul(page.max(1))
                ),
            }
        });
    }
    // The special slots: the blobs that are here (requirements,
    // entitlements, DER entitlements), each hashed.
    for (slot, what) in [
        (2u32, "requirements"),
        (5, "entitlements"),
        (7, "DER entitlements"),
    ] {
        if slot > special_slots {
            continue;
        }
        let Some(expected) = slot_hash(true, slot as usize) else {
            continue;
        };
        let present = blobs.iter().find(|(s, _)| *s == slot).map(|(_, b)| *b);
        let zero = expected.iter().all(|&b| b == 0);
        match (present, zero) {
            (Some(b), _) => {
                let h = hash.digest(b);
                checks.push(if h[..hash_size.min(h.len())] == *expected {
                    Check {
                        name: "Special slots",
                        status: Status::Pass,
                        detail: format!("{name}: the {what} match"),
                    }
                } else {
                    Check {
                        name: "Special slots",
                        status: Status::Fail,
                        detail: format!("{name}: the {what} changed after signing"),
                    }
                });
            }
            (None, false) => checks.push(Check {
                name: "Special slots",
                status: Status::Fail,
                detail: format!("{name}: the {what} were signed but are missing"),
            }),
            (None, true) => {}
        }
    }
    Some(d)
}

/// The CMS signature of a code signature: it signs the primary code
/// directory (and names every directory's cdhash).
fn cms_signature(der: &[u8], primary: &[u8], directories: &[Directory]) -> Signature {
    let sd = match SignedData::from_der(der) {
        Ok(sd) => sd,
        Err(e) => return unreadable("Apple", e.to_string()),
    };
    let mut checks = Vec::new();
    let Some(s) = sd.signers.first() else {
        // (Ad hoc signatures carry an empty CMS.)
        return Signature {
            kind: "Apple",
            status: Status::Warn,
            summary: "no signer (ad hoc)".into(),
            program: None,
            url: None,
            file_digest: None,
            checks,
            signer: None,
            timestamps: Vec::new(),
            certificates: Vec::new(),
        };
    };
    let mut signer = verify::signer(&sd, s, Some(primary));
    let timestamps = verify::timestamps(&sd, s);
    let (at, at_what) = verify::judged_at(&timestamps);
    verify::finish(&mut signer, at, at_what, oid::EKU_CODE_SIGNING);
    // The cdhashes it names (a property list of them): each directory's.
    if let Some(list) = s.signed_attribute(oid::APPLE_CDHASHES) {
        let text = list
            .octets()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let named: Vec<String> = text
            .split("<data>")
            .skip(1)
            .filter_map(|p| p.split("</data>").next())
            .filter_map(crate::roots::decode_base64)
            .map(|b| hex(&b[..20.min(b.len())]))
            .collect();
        let missing: Vec<&str> = directories
            .iter()
            .filter(|d| !named.contains(&d.cdhash))
            .map(|d| d.hash.as_str())
            .collect();
        checks.push(if missing.is_empty() {
            Check {
                name: "CDHashes",
                status: Status::Pass,
                detail: format!(
                    "it names every code directory's cdhash ({})",
                    directories.len()
                ),
            }
        } else {
            Check {
                name: "CDHashes",
                status: Status::Fail,
                detail: format!(
                    "it doesn't name the {} directory's cdhash",
                    missing.join(", ")
                ),
            }
        });
    }
    let (status, summary) = summarize(&checks, Some(&signer), &timestamps);
    Signature {
        kind: "Apple",
        status,
        summary,
        program: None,
        url: None,
        file_digest: None,
        checks,
        signer: Some(signer),
        timestamps,
        certificates: sd.certificates.iter().map(CertInfo::of).collect(),
    }
}

/// A code signature's verdict: its hashes, then its CMS signature's.
fn verdict(c: &CodeSignature) -> (Status, String) {
    if let Some(f) = c.checks.iter().find(|x| x.status == Status::Fail) {
        return (Status::Fail, format!("{}: {}", f.name, f.detail));
    }
    match &c.signature {
        Some(s) if s.signer.is_some() => (s.status, s.summary.clone()),
        _ if c.adhoc => (
            Status::Warn,
            if c.linker_signed {
                "signed ad hoc by the linker: its code is unchanged, but no one vouches for it"
                    .into()
            } else {
                "signed ad hoc: unchanged, but no one vouches for it".into()
            },
        ),
        Some(s) => (s.status, s.summary.clone()),
        None => (Status::Fail, "no signature".into()),
    }
}

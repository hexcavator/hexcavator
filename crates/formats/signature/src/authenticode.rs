//! Authenticode: a PE image's signatures (its attribute certificates, and
//! the signatures nested in them), each checked: the image's hash, the
//! signer's signature, its chain, and its timestamps.

use std::collections::HashMap;

use hexcavator_pe::PeFile;

use crate::cms::{IndirectData, MAX_NESTING, OpusInfo, SignedData};
use crate::crypto::Hash;
use crate::oid;
use crate::verify::{self, CertInfo, Check, Signer, Status, Timestamp};
use crate::x509::hex;

/// A signature, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// "Authenticode", "Authenticode (nested)", or "Apple".
    pub kind: &'static str,
    /// How it came out, all told, and why.
    pub status: Status,
    pub summary: String,
    /// The program's name and link (Authenticode's SpcSpOpusInfo).
    pub program: Option<String>,
    pub url: Option<String>,
    /// The hash it signed, of the file (Authenticode's): its algorithm,
    /// the signed value, and the file's.
    pub file_digest: Option<(String, String, Option<String>)>,
    /// Checks of the file (its hash).
    pub checks: Vec<Check>,
    pub signer: Option<Signer>,
    pub timestamps: Vec<Timestamp>,
    /// Every certificate it carries.
    pub certificates: Vec<CertInfo>,
}

/// The most signatures of a file checked.
pub const MAX_SIGNATURES: usize = 32;

/// A signature that couldn't be read.
pub(crate) fn unreadable(kind: &'static str, why: String) -> Signature {
    Signature {
        kind,
        status: Status::Fail,
        summary: format!("unreadable: {why}"),
        program: None,
        url: None,
        file_digest: None,
        checks: vec![Check {
            name: "Format",
            status: Status::Fail,
            detail: why,
        }],
        signer: None,
        timestamps: Vec::new(),
        certificates: Vec::new(),
    }
}

/// A PE image's Authenticode hash with `h`: all of it but its checksum, its
/// certificate table's directory entry, and the certificates.
pub fn image_hash(pe: &PeFile<'_>, h: Hash) -> Option<Vec<u8>> {
    let data = pe.data();
    let len = data.len() as u64;
    let (checksum, entry) =
        pe.checksum_and_directory_offsets(hexcavator_pe::consts::directory::SECURITY)?;
    let (start, size) = pe
        .data_directory(hexcavator_pe::consts::directory::SECURITY)
        .map_or((len, 0), |d| {
            (u64::from(d.virtual_address.get()), u64::from(d.size.get()))
        });
    let mut holes = vec![(checksum, 4)];
    if let Some(e) = entry {
        holes.push((e, 8));
    }
    if size > 0 {
        holes.push((start, size));
    }
    holes.sort_unstable();
    let mut hasher = h.hasher();
    let mut at = 0usize;
    for (from, n) in holes {
        let from = usize::try_from(from).ok()?;
        if from < at || from > data.len() {
            return None;
        }
        hasher.update(&data[at..from]);
        at = from.checked_add(usize::try_from(n).ok()?)?.min(data.len());
    }
    hasher.update(&data[at..]);
    Some(hasher.finish())
}

/// Every Authenticode signature of a PE image, checked.
pub fn pe(pe: &PeFile<'_>) -> Vec<Signature> {
    let mut out = Vec::new();
    let mut hashes: HashMap<Hash, Option<Vec<u8>>> = HashMap::new();
    for cert in pe.certificates() {
        if out.len() >= MAX_SIGNATURES {
            break;
        }
        if cert.kind != hexcavator_pe::extras::WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            out.push(unreadable(
                "Authenticode",
                format!("a certificate of type {:#x}, not PKCS #7", cert.kind),
            ));
            continue;
        }
        match SignedData::from_der(cert.data) {
            Ok(sd) => one(pe, &sd, "Authenticode", 0, &mut hashes, &mut out),
            Err(e) => out.push(unreadable("Authenticode", e.to_string())),
        }
    }
    out
}

fn one(
    pe: &PeFile<'_>,
    sd: &SignedData<'_>,
    kind: &'static str,
    depth: usize,
    hashes: &mut HashMap<Hash, Option<Vec<u8>>>,
    out: &mut Vec<Signature>,
) {
    // (A hostile file could nest a great many: each costs checks.)
    if out.len() >= MAX_SIGNATURES {
        return;
    }
    let mut checks = Vec::new();
    let content = sd.content.as_ref().map(super::cms::Content::digested);
    // What it signed: the image's hash.
    let indirect = sd
        .content
        .as_ref()
        .filter(|_| sd.content_type == oid::SPC_INDIRECT_DATA)
        .and_then(|c| IndirectData::parse(c.tlv).ok());
    let mut file_digest = None;
    match &indirect {
        Some(ind) => {
            let alg = ind.digest_algorithm.name();
            match Hash::of(&ind.digest_algorithm.oid) {
                Some(h) => {
                    let computed = hashes.entry(h).or_insert_with(|| image_hash(pe, h)).clone();
                    checks.push(match &computed {
                        Some(c) if c == ind.digest => Check {
                            name: "File hash",
                            status: Status::Pass,
                            detail: format!("the file's {alg} matches the signed hash: it hasn't changed since it was signed"),
                        },
                        Some(_) => Check {
                            name: "File hash",
                            status: Status::Fail,
                            detail: format!("the file's {alg} isn't the signed hash: it was changed after it was signed"),
                        },
                        None => Check {
                            name: "File hash",
                            status: Status::Unknown,
                            detail: "the image's headers don't let it be hashed".into(),
                        },
                    });
                    file_digest = Some((alg, hex(ind.digest), computed.map(|c| hex(&c))));
                }
                None => checks.push(Check {
                    name: "File hash",
                    status: Status::Unknown,
                    detail: format!("can't compute {alg}"),
                }),
            }
            if ind.data_type != oid::SPC_PE_IMAGE_DATA {
                checks.push(Check {
                    name: "Content",
                    status: Status::Warn,
                    detail: format!("signs {}, not a PE image", oid::display(&ind.data_type)),
                });
            }
        }
        None => checks.push(Check {
            name: "File hash",
            status: Status::Fail,
            detail: format!(
                "it signs {}, not an image's hash",
                oid::display(&sd.content_type)
            ),
        }),
    }
    let s = sd.signers.first();
    if sd.signers.len() != 1 {
        checks.push(Check {
            name: "Signers",
            status: Status::Warn,
            detail: format!("{} signers (Authenticode has one)", sd.signers.len()),
        });
    }
    let mut signer = None;
    let mut timestamps = Vec::new();
    let mut program = None;
    let mut url = None;
    if let Some(s) = s {
        let mut sig = verify::signer(sd, s, content.as_deref());
        timestamps = verify::timestamps(sd, s);
        let (at, at_what) = verify::judged_at(&timestamps);
        verify::finish(&mut sig, at, at_what, oid::EKU_CODE_SIGNING);
        if let Some(info) = s
            .signed_attribute(oid::SPC_SP_OPUS_INFO)
            .and_then(|t| OpusInfo::parse(t).ok())
        {
            program = info.program.filter(|p| !p.is_empty());
            url = info.url.filter(|u| !u.is_empty());
        }
        signer = Some(sig);
    }
    let (status, summary) = summarize(&checks, signer.as_ref(), &timestamps);
    out.push(Signature {
        kind,
        status,
        summary,
        program,
        url,
        file_digest,
        checks,
        signer,
        timestamps,
        certificates: sd.certificates.iter().map(CertInfo::of).collect(),
    });
    // Its nested signatures (another hash, another signer).
    if depth < MAX_NESTING {
        for s in &sd.signers {
            for v in s.unsigned_attributes(oid::SPC_NESTED_SIGNATURE) {
                match SignedData::from_content_info(v) {
                    Ok(nested) => one(pe, &nested, "Authenticode (nested)", depth + 1, hashes, out),
                    Err(e) => out.push(unreadable("Authenticode (nested)", e.to_string())),
                }
            }
        }
    }
}

/// A signature's verdict, from its checks: it fails if any check of the
/// file, the signer, or its chain fails; a timestamp's failure, a weak
/// hash, or an untrusted root is a warning.
pub(crate) fn summarize(
    checks: &[Check],
    signer: Option<&Signer>,
    stamps: &[Timestamp],
) -> (Status, String) {
    let signer_checks = signer.map_or(&[][..], |s| &s.checks[..]);
    let all = checks.iter().chain(signer_checks);
    let failed: Vec<&Check> = all.clone().filter(|c| c.status == Status::Fail).collect();
    if let Some(f) = failed.first() {
        return (Status::Fail, format!("{}: {}", f.name, f.detail));
    }
    if signer.is_none() {
        return (Status::Fail, "no signer".into());
    }
    let unknown: Vec<&Check> = all
        .clone()
        .filter(|c| c.status == Status::Unknown)
        .collect();
    if let Some(u) = unknown.first() {
        return (Status::Unknown, format!("{}: {}", u.name, u.detail));
    }
    let who = signer.map_or(String::new(), |s| s.name.clone());
    let stamp_failed = stamps
        .iter()
        .any(|t| t.signer.checks.iter().any(|c| c.status == Status::Fail));
    let warned: Vec<&Check> = all.filter(|c| c.status == Status::Warn).collect();
    if stamp_failed {
        return (
            Status::Warn,
            format!("signed by {who}; a timestamp doesn't check"),
        );
    }
    if let Some(w) = warned.first() {
        return (Status::Warn, format!("signed by {who}; {}", w.detail));
    }
    (
        Status::Pass,
        format!("signed by {who}, trusted, and unchanged"),
    )
}

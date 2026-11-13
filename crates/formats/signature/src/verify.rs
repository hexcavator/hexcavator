//! Checking a CMS signature: its signer's signature, the chain of
//! certificates up to a root, its timestamps, and what they're allowed to
//! do. The answers are owned (no borrowing of the file), to show.

use crate::cms::{SignedData, SignerInfo, TstInfo, countersigner};
use crate::crypto::{self, Failure, Hash};
use crate::der::Time;
use crate::oid;
use crate::roots;
use crate::x509::{Certificate, hex};

/// How a check came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// It holds.
    Pass,
    /// It doesn't.
    Fail,
    /// It holds, with a caveat (a weak hash, an unknown root).
    Warn,
    /// It couldn't be checked.
    Unknown,
}

impl Status {
    pub fn key(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Warn => "warn",
            Status::Unknown => "unknown",
        }
    }
}

/// One check: what, how it came out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

/// A certificate, as shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    /// Its common name (or organization).
    pub name: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: Time,
    pub not_after: Time,
    pub key: String,
    pub signature_algorithm: String,
    pub sha1: String,
    pub sha256: String,
    /// Its extended key usages, by name (`None`: any).
    pub usages: Option<Vec<String>>,
    pub key_usage: Option<Vec<&'static str>>,
    pub ca: bool,
    pub self_signed: bool,
    pub version: i64,
}

impl CertInfo {
    pub fn of(c: &Certificate<'_>) -> Self {
        CertInfo {
            subject: c.subject.to_string(),
            name: c.subject.short(),
            issuer: c.issuer.to_string(),
            serial: c.serial_hex(),
            not_before: c.not_before,
            not_after: c.not_after,
            key: c.public_key.describe(),
            signature_algorithm: c.signature_algorithm.name(),
            sha1: hex(&Hash::Sha1.digest(c.raw)),
            sha256: hex(&Hash::Sha256.digest(c.raw)),
            usages: c
                .extended_key_usage()
                .map(|l| l.iter().map(|o| oid::display(o)).collect()),
            key_usage: c.key_usage(),
            ca: c.is_ca(),
            self_signed: c.is_self_issued(),
            version: c.version,
        }
    }
}

/// A link of a chain: a certificate, and whether its issuer's signature
/// on it checks (the last: a root's own, or `None` if it has no issuer
/// here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub certificate: CertInfo,
    /// Where it came from: the signature, or the trusted roots.
    pub from_roots: bool,
    pub signed: Option<Result<(), Failure>>,
}

/// A chain, from the signer's certificate to a root, and whether that
/// root is trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub links: Vec<Link>,
    /// The trusted root it ends at (its name), if it does.
    pub trusted: Option<String>,
}

/// A signer: who, when, and the checks of its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    pub name: String,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    /// When it says it signed (an attribute, not proof).
    pub signing_time: Option<Time>,
    pub chain: Option<Chain>,
    pub checks: Vec<Check>,
}

/// A timestamp: who stamped it, when, and the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// "RFC 3161" or "PKCS #9 countersignature".
    pub kind: &'static str,
    pub time: Option<Time>,
    pub signer: Signer,
}

/// The longest chain built.
const MAX_CHAIN: usize = 12;

/// The most timestamps of a signer checked.
const MAX_STAMPS: usize = 4;

/// The most issuers tried for one certificate.
const MAX_CANDIDATES: usize = 8;

/// The chain from `leaf` up through `pool` (the signature's certificates)
/// and the trusted roots.
pub fn chain<'a>(leaf: &Certificate<'a>, pool: &[Certificate<'a>]) -> Chain {
    let roots = roots::all();
    let mut links: Vec<Link> = Vec::new();
    let mut current: Certificate<'_> = leaf.clone();
    let mut from_roots = false;
    let mut trusted = None;
    for _ in 0..MAX_CHAIN {
        let info = CertInfo::of(&current);
        if from_roots || roots::is_trusted(&info.sha256) {
            trusted = roots::name(&info.sha256)
                .map(str::to_string)
                .or(Some(info.name.clone()));
        }
        if current.is_self_issued() {
            let signed = crypto::verify(
                &current.public_key,
                &current.signature_algorithm,
                None,
                current.tbs,
                current.signature,
            );
            links.push(Link {
                certificate: info,
                from_roots,
                signed: Some(signed),
            });
            break;
        }
        // Its issuer: a certificate whose subject is its issuer (and whose
        // key identifier matches, where both say), that signed it.
        let wanted = current.authority_key_id();
        // (The trusted roots first: a signature may carry a cross
        // certificate for a root, another issuer's, with the same key.)
        let candidates = roots
            .iter()
            .map(|c| (c, true))
            .chain(pool.iter().map(|c| (c, false)))
            .filter(|(c, _)| c.subject.raw == current.issuer.raw && c.raw != current.raw)
            .filter(|(c, _)| match (wanted, c.subject_key_id()) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            });
        let mut found: Option<(Certificate<'_>, bool, Result<(), Failure>)> = None;
        // (A hostile signature could name many: each costs a check.)
        for (c, root) in candidates.take(MAX_CANDIDATES) {
            let r = crypto::verify(
                &c.public_key,
                &current.signature_algorithm,
                None,
                current.tbs,
                current.signature,
            );
            let ok = r.is_ok();
            if found.is_none() || ok {
                found = Some((c.clone(), root, r));
            }
            if ok {
                break;
            }
        }
        match found {
            Some((issuer, root, signed)) => {
                links.push(Link {
                    certificate: info,
                    from_roots,
                    signed: Some(signed),
                });
                current = issuer;
                from_roots = root;
            }
            None => {
                links.push(Link {
                    certificate: info,
                    from_roots,
                    signed: None,
                });
                break;
            }
        }
    }
    Chain { links, trusted }
}

/// The checks of a chain: each certificate signed by the next, each valid
/// at `at`, the leaf allowed to `usage`, and the root trusted.
fn chain_checks(chain: &Chain, at: Time, at_what: &str, usage: &str, out: &mut Vec<Check>) {
    // (A trusted root is trusted for its thumbprint, not its signature on
    // itself: some old ones sign with MD2.)
    let n = chain.links.len();
    let root_trusted = chain.trusted.is_some()
        && chain
            .links
            .last()
            .is_some_and(|l| l.certificate.self_signed);
    let broken: Vec<String> = chain
        .links
        .iter()
        .take(if root_trusted { n - 1 } else { n })
        .filter_map(|l| match &l.signed {
            Some(Err(Failure::Invalid)) => Some(format!(
                "{}: its issuer's signature doesn't match",
                l.certificate.name
            )),
            Some(Err(Failure::Unsupported(s))) => Some(format!("{}: {s}", l.certificate.name)),
            _ => None,
        })
        .collect();
    let complete = chain.links.last().is_some_and(|l| l.signed.is_some());
    out.push(if !broken.is_empty() {
        let invalid = chain
            .links
            .iter()
            .any(|l| matches!(l.signed, Some(Err(Failure::Invalid))));
        check(
            "Chain",
            if invalid {
                Status::Fail
            } else {
                Status::Unknown
            },
            broken.join("; "),
        )
    } else if !complete {
        let last = chain
            .links
            .last()
            .map_or(String::new(), |l| l.certificate.issuer.clone());
        check(
            "Chain",
            Status::Unknown,
            format!("incomplete: no certificate here for its issuer, {last}"),
        )
    } else {
        check(
            "Chain",
            Status::Pass,
            format!(
                "{} certificates, each signed by the next",
                chain.links.len()
            ),
        )
    });
    let expired: Vec<String> = chain
        .links
        .iter()
        .filter(|l| !(l.certificate.not_before <= at && at <= l.certificate.not_after))
        .map(|l| {
            format!(
                "{} ({} to {})",
                l.certificate.name, l.certificate.not_before, l.certificate.not_after
            )
        })
        .collect();
    out.push(if expired.is_empty() {
        check(
            "Validity",
            Status::Pass,
            format!("every certificate valid {at_what} ({at})"),
        )
    } else {
        check(
            "Validity",
            Status::Fail,
            format!("not valid {at_what} ({at}): {}", expired.join(", ")),
        )
    });
    if let Some(leaf) = chain.links.first() {
        let allowed = leaf.certificate.usages.as_ref().is_none_or(|u| {
            u.iter()
                .any(|n| n == &oid::display(usage) || n == "Any Purpose")
        });
        out.push(if allowed {
            check(
                "Usage",
                Status::Pass,
                format!("the certificate allows {}", oid::display(usage)),
            )
        } else {
            check(
                "Usage",
                Status::Fail,
                format!(
                    "the certificate doesn't allow {} (only {})",
                    oid::display(usage),
                    leaf.certificate
                        .usages
                        .clone()
                        .unwrap_or_default()
                        .join(", ")
                ),
            )
        });
    }
    out.push(match &chain.trusted {
        Some(root) => check(
            "Trust",
            Status::Pass,
            format!("ends at a trusted root: {root}"),
        ),
        None => {
            let last = chain
                .links
                .last()
                .map_or("?".to_string(), |l| l.certificate.name.clone());
            check(
                "Trust",
                Status::Warn,
                format!("ends at {last}, not a root hexc trusts"),
            )
        }
    });
}

/// Checks signer `s` of `sd`: the message digest (of `content`: the
/// signature's own, or what the caller says is signed) and its signature;
/// and builds its chain (`finish` checks it).
pub fn signer(sd: &SignedData<'_>, s: &SignerInfo<'_>, content: Option<&[u8]>) -> Signer {
    let mut checks = Vec::new();
    let cert = sd.certificate(&s.id);
    // The message digest: the content's hash, as the signer signed it.
    let hash = Hash::of(&s.digest_algorithm.oid);
    match (s.message_digest(), content, hash) {
        (Some(signed), Some(content), Some(h)) => {
            let computed = h.digest(content);
            checks.push(if computed == signed {
                check(
                    "Message digest",
                    Status::Pass,
                    format!("{} of what's signed matches", h.name()),
                )
            } else {
                check(
                    "Message digest",
                    Status::Fail,
                    format!(
                        "{} of what's signed is {}, not {}",
                        h.name(),
                        hex(&computed),
                        hex(signed)
                    ),
                )
            });
        }
        (None, _, _) if s.signed.is_none() => {}
        (_, _, None) => checks.push(check(
            "Message digest",
            Status::Unknown,
            format!("can't compute {}", s.digest_algorithm.name()),
        )),
        _ => checks.push(check(
            "Message digest",
            Status::Unknown,
            "nothing to compare",
        )),
    }
    // The signature, by the signer's key.
    match (cert, s.signed_bytes(content)) {
        (Some(c), Some(bytes)) => {
            let r = crypto::verify(
                &c.public_key,
                &s.signature_algorithm,
                Some(&s.digest_algorithm),
                &bytes,
                s.signature,
            );
            checks.push(match r {
                Ok(()) => check(
                    "Signature",
                    Status::Pass,
                    format!(
                        "signed by {} ({})",
                        c.subject.short(),
                        c.public_key.describe()
                    ),
                ),
                Err(Failure::Invalid) => check(
                    "Signature",
                    Status::Fail,
                    "the signature doesn't match its certificate's key",
                ),
                Err(Failure::Unsupported(why)) => {
                    check("Signature", Status::Unknown, format!("can't check: {why}"))
                }
            });
        }
        (None, _) => checks.push(check(
            "Signature",
            Status::Fail,
            "the signer's certificate isn't in the signature",
        )),
        (Some(_), None) => checks.push(check(
            "Signature",
            Status::Unknown,
            "nothing to check it against",
        )),
    }
    let hash_note = hash.filter(|h| matches!(h, Hash::Md5 | Hash::Sha1));
    if let Some(h) = hash_note {
        checks.push(check(
            "Digest algorithm",
            Status::Warn,
            format!("{} is weak (collisions can be made)", h.name()),
        ));
    }
    let chain = cert.map(|c| chain(c, &sd.certificates));
    Signer {
        name: cert.map_or_else(|| "(unknown)".to_string(), |c| c.subject.short()),
        digest_algorithm: s.digest_algorithm.name(),
        signature_algorithm: s.signature_algorithm.name(),
        signing_time: s.signing_time(),
        chain,
        checks,
    }
}

/// The checks of a signer's chain, at `at`.
pub fn finish(signer: &mut Signer, at: Time, at_what: &str, usage: &str) {
    if let Some(chain) = signer.chain.clone() {
        chain_checks(&chain, at, at_what, usage, &mut signer.checks);
    }
}

/// A signer's timestamps (RFC 3161 tokens, and PKCS #9 countersignatures),
/// each checked: it stamped this signer's signature.
pub fn timestamps(sd: &SignedData<'_>, s: &SignerInfo<'_>) -> Vec<Timestamp> {
    let mut out = Vec::new();
    for v in s
        .unsigned_attributes(oid::MS_RFC3161_TIMESTAMP)
        .chain(s.unsigned_attributes("1.2.840.113549.1.9.16.2.14"))
        .take(MAX_STAMPS)
    {
        let Ok(token) = SignedData::from_content_info(v) else {
            continue;
        };
        let tst = token.content.as_ref().map(super::cms::Content::digested);
        let info = tst.as_deref().and_then(|b| TstInfo::parse(b).ok());
        for ts in token.signers.iter().take(MAX_STAMPS) {
            let mut sig = signer(&token, ts, tst.as_deref());
            match &info {
                Some(info) => {
                    let h = Hash::of(&info.imprint_algorithm.oid);
                    sig.checks.insert(
                        0,
                        match h {
                            Some(h) if h.digest(s.signature) == info.imprint => {
                                check("Imprint", Status::Pass, "it stamps this signature")
                            }
                            Some(_) => check(
                                "Imprint",
                                Status::Fail,
                                "it stamps something else (its hash isn't this signature's)",
                            ),
                            None => check(
                                "Imprint",
                                Status::Unknown,
                                format!("can't compute {}", info.imprint_algorithm.name()),
                            ),
                        },
                    );
                    finish(&mut sig, info.time, "when stamped", oid::EKU_TIME_STAMPING);
                }
                None => sig
                    .checks
                    .push(check("Imprint", Status::Fail, "no TSTInfo")),
            }
            out.push(Timestamp {
                kind: "RFC 3161",
                time: info.as_ref().map(|i| i.time),
                signer: sig,
            });
        }
    }
    for v in s
        .unsigned_attributes(oid::COUNTER_SIGNATURE)
        .take(MAX_STAMPS)
    {
        let Ok(cs) = countersigner(v) else {
            continue;
        };
        // A countersignature: its message digest is the hash of the
        // signature it stamps; its certificates are the outer signature's.
        let mut sig = signer(sd, &cs, Some(s.signature));
        let time = cs.signing_time();
        if let Some(c) = sig.checks.iter_mut().find(|c| c.name == "Message digest") {
            c.name = "Imprint";
            if c.status == Status::Pass {
                c.detail = "it stamps this signature".into();
            }
        }
        finish(
            &mut sig,
            time.unwrap_or_else(Time::now),
            if time.is_some() {
                "when stamped"
            } else {
                "now"
            },
            oid::EKU_TIME_STAMPING,
        );
        out.push(Timestamp {
            kind: "PKCS #9 countersignature",
            time,
            signer: sig,
        });
    }
    out
}

/// When the signature is to be judged: a valid timestamp's time (the
/// certificates had to be valid then), else now.
pub fn judged_at(stamps: &[Timestamp]) -> (Time, &'static str) {
    stamps
        .iter()
        .filter(|t| t.signer.checks.iter().all(|c| c.status != Status::Fail))
        .find_map(|t| t.time)
        .map_or((Time::now(), "now"), |t| (t, "when timestamped"))
}

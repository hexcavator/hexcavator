//! Code signatures, read and verified the same on every platform: a PE
//! image's Authenticode signatures, and a Mach-O image's Apple code
//! signature (each architecture's, in a universal file).
//!
//! The parsing (DER, X.509, CMS, Authenticode's and Apple's structures)
//! is ours; the cryptography (hashes, RSA, ECDSA) is RustCrypto's. Trust
//! is a bundled set of roots (Microsoft's, Apple's, and the public code
//! signing authorities), plus any the caller adds: not the machine's, so
//! the answer is the same wherever it's asked. Revocation isn't checked
//! (it needs the network), nor are signatures kept outside the file (a
//! Windows catalog's, an app bundle's notarization ticket).

pub mod apple;
pub mod authenticode;
pub mod cms;
pub mod crypto;
pub mod der;
pub mod info;
pub mod oid;
pub mod requirement;
pub mod roots;
pub mod verify;
pub mod x509;

pub use apple::CodeSignature;
pub use authenticode::Signature;
pub use verify::{CertInfo, Chain, Check, Link, Signer, Status, Timestamp};

/// A file's signatures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// "pe" or "macho".
    pub format: &'static str,
    /// A PE image's Authenticode signatures (the primary first, then those
    /// nested in it).
    pub authenticode: Vec<Signature>,
    /// A Mach-O image's code signatures, one per architecture.
    pub apple: Vec<CodeSignature>,
    /// What it says it is: its company, product, versions, ... (a PE
    /// image's version resource; a Mach-O image's versions and Info.plist).
    pub info: info::Details,
}

impl Report {
    /// Whether it has any signature.
    pub fn signed(&self) -> bool {
        !self.authenticode.is_empty() || !self.apple.is_empty()
    }
}

/// The signatures of the file `data` (a PE or Mach-O image, or a
/// universal file).
pub fn of_file(data: &[u8]) -> Result<Report, String> {
    if data.starts_with(b"MZ") {
        let pe = hexcavator_pe::PeFile::parse_image(data).map_err(|e| e.to_string())?;
        return Ok(Report {
            format: "pe",
            authenticode: authenticode::pe(&pe),
            apple: Vec::new(),
            info: info::pe(&pe),
        });
    }
    if let Some(archs) = hexcavator_macho::fat_archs(data) {
        let mut apple = Vec::new();
        let mut details = None;
        for a in archs.iter().take(32) {
            let Some(slice) = usize::try_from(a.offset)
                .ok()
                .zip(usize::try_from(a.size).ok())
                .and_then(|(o, n)| data.get(o..o.checked_add(n)?))
            else {
                continue;
            };
            let name = hexcavator_macho::arch_name(a.cputype, a.cpusubtype);
            if let Ok(m) = hexcavator_macho::MachO::parse(slice) {
                // (The first architecture's details: they're the same.)
                details.get_or_insert_with(|| info::macho(&m));
                if let Some(s) = apple::macho(&m, name) {
                    apple.push(s);
                }
            }
        }
        return Ok(Report {
            format: "macho",
            authenticode: Vec::new(),
            apple,
            info: details.unwrap_or_default(),
        });
    }
    if let Ok(m) = hexcavator_macho::MachO::parse(data) {
        let h = m.header();
        let name = hexcavator_macho::arch_name(h.cputype, h.cpusubtype);
        return Ok(Report {
            format: "macho",
            authenticode: Vec::new(),
            apple: apple::macho(&m, name).into_iter().collect(),
            info: info::macho(&m),
        });
    }
    Err("signatures are read from PE and Mach-O images".into())
}

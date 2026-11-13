//! The roots hexc trusts: Microsoft's and Apple's, and the public code
//! signing and timestamping authorities (see tools/signature/roots.py),
//! and any the caller adds (`hexc signature -root <file>`).
//!
//! Trust is ours to say, the same on every platform: not the machine's
//! store, and without checking revocation (that needs the network).

use std::sync::{Mutex, OnceLock};

use crate::x509::{Certificate, hex};

#[path = "roots_list.rs"]
mod list;

static BUNDLED: OnceLock<Vec<Certificate<'static>>> = OnceLock::new();
static ADDED: Mutex<Vec<(&'static str, String, Certificate<'static>)>> = Mutex::new(Vec::new());

fn bundled() -> &'static [Certificate<'static>] {
    BUNDLED.get_or_init(|| {
        list::ROOTS
            .iter()
            .filter_map(|(_, _, der)| Certificate::from_der(der).ok())
            .collect()
    })
}

/// Every trusted root.
pub fn all() -> Vec<Certificate<'static>> {
    let mut out = bundled().to_vec();
    if let Ok(added) = ADDED.lock() {
        out.extend(added.iter().map(|(_, _, c)| c.clone()));
    }
    out
}

/// Whether the certificate with SHA-256 thumbprint `sha256` (lowercase
/// hex) is a trusted root.
pub fn is_trusted(sha256: &str) -> bool {
    name(sha256).is_some()
}

/// A trusted root's name, by its SHA-256 thumbprint.
pub fn name(sha256: &str) -> Option<&'static str> {
    if let Some((n, _, _)) = list::ROOTS.iter().find(|(_, t, _)| *t == sha256) {
        return Some(n);
    }
    let added = ADDED.lock().ok()?;
    added
        .iter()
        .find(|(_, t, _)| t == sha256)
        .map(|(n, _, _)| *n)
}

/// Trusts the certificate `der` (DER, or PEM) as a root too; its name.
pub fn add(data: &[u8]) -> Result<String, String> {
    let der = pem(data).unwrap_or_else(|| data.to_vec());
    let der: &'static [u8] = Box::leak(der.into_boxed_slice());
    let cert = Certificate::from_der(der).map_err(|e| e.to_string())?;
    // (Added roots live as long as the process: their names too.)
    let name: &'static str = Box::leak(cert.subject.short().into_boxed_str());
    let sha256 = hex(&crate::crypto::Hash::Sha256.digest(der));
    let mut added = ADDED
        .lock()
        .map_err(|_| "the roots are poisoned".to_string())?;
    added.push((name, sha256, cert));
    Ok(name.to_string())
}

/// The bundled roots: (name, SHA-256 thumbprint).
pub fn bundled_names() -> impl Iterator<Item = (&'static str, &'static str)> {
    list::ROOTS.iter().map(|(n, t, _)| (*n, *t))
}

/// The first certificate of a PEM file, decoded.
fn pem(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")? + "-----BEGIN CERTIFICATE-----".len();
    let end = start + text[start..].find("-----END CERTIFICATE-----")?;
    decode_base64(&text[start..end])
}

pub(crate) fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_root_parses_and_signs_itself() {
        for (name, sha256, der) in list::ROOTS {
            let c = Certificate::from_der(der).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                hex(&crate::crypto::Hash::Sha256.digest(der)),
                *sha256,
                "{name}"
            );
            assert!(c.is_self_issued(), "{name}");
            // (One old VeriSign root signs itself with MD2, which we don't
            // compute: it's trusted for its thumbprint.)
            match crate::crypto::verify(
                &c.public_key,
                &c.signature_algorithm,
                None,
                c.tbs,
                c.signature,
            ) {
                Ok(()) => {}
                Err(crate::crypto::Failure::Unsupported(_))
                    if c.signature_algorithm.oid == "1.2.840.113549.1.1.2" => {}
                Err(e) => panic!("{name}: {e}"),
            }
        }
        assert_eq!(bundled().len(), list::ROOTS.len());
    }

    #[test]
    fn pem_decodes() {
        assert_eq!(decode_base64("aGV4Yw==").unwrap(), b"hexc");
    }
}

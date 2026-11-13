//! X.509 certificates (RFC 5280): who they name, who issued them, when
//! they're valid, their key, and what they may be used for.

use crate::der::{self, Time, Tlv, tag};
use crate::oid;

/// A distinguished name: its attributes, in order, and its encoding (two
/// names are the same when their encodings are).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name<'a> {
    pub raw: &'a [u8],
    pub attributes: Vec<(String, String)>,
}

impl<'a> Name<'a> {
    fn parse(t: Tlv<'a>) -> der::Result<Self> {
        let t = t.expect(tag::SEQUENCE, "name")?;
        let mut attributes = Vec::new();
        let mut rdns = t.reader();
        while let Some(rdn) = rdns.next()? {
            let mut set = rdn.expect(tag::SET, "relative name")?.reader();
            while let Some(atv) = set.next()? {
                let mut r = atv.expect(tag::SEQUENCE, "attribute")?.reader();
                let o = r.expect(tag::OID, "attribute type")?.oid()?.to_string();
                let v = r.take("attribute value")?;
                let text = v.text().unwrap_or_else(|_| hex(v.body));
                if attributes.len() < 64 {
                    attributes.push((o, text));
                }
            }
        }
        Ok(Name {
            raw: t.raw,
            attributes,
        })
    }

    /// The first value of attribute `oid` (dotted).
    pub fn get(&self, oid: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == oid)
            .map(|(_, v)| v.as_str())
    }

    /// Its common name (else its organization, else all of it).
    pub fn short(&self) -> String {
        self.get("2.5.4.3")
            .or_else(|| self.get("2.5.4.10"))
            .map_or_else(|| self.to_string(), str::to_string)
    }
}

impl std::fmt::Display for Name<'_> {
    /// `CN=..., O=..., C=...` (most specific first, as Windows shows it).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (k, v)) in self.attributes.iter().rev().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}={}", oid::display(k), v)?;
        }
        Ok(())
    }
}

/// The name `t`.
pub(crate) fn parse_name(t: Tlv<'_>) -> der::Result<Name<'_>> {
    Name::parse(t)
}

/// An algorithm and its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Algorithm<'a> {
    pub oid: String,
    pub params: Option<Tlv<'a>>,
}

impl<'a> Algorithm<'a> {
    pub(crate) fn parse(t: Tlv<'a>) -> der::Result<Self> {
        let mut r = t.expect(tag::SEQUENCE, "algorithm")?.reader();
        let oid = r.expect(tag::OID, "algorithm")?.oid()?.to_string();
        let params = r.next()?.filter(|p| p.tag != tag::NULL);
        Ok(Algorithm { oid, params })
    }

    pub fn name(&self) -> String {
        oid::display(&self.oid)
    }
}

/// A public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<'a> {
    pub algorithm: Algorithm<'a>,
    /// The key (an RSAPublicKey's DER, or an EC point).
    pub key: &'a [u8],
    /// The whole SubjectPublicKeyInfo.
    pub raw: &'a [u8],
}

impl PublicKey<'_> {
    /// Its kind and size: "RSA 2048", "ECDSA P-256".
    pub fn describe(&self) -> String {
        match self.algorithm.oid.as_str() {
            oid::RSA_ENCRYPTION | oid::RSA_PSS => match self.rsa() {
                Some((n, _)) => format!("RSA {}", bits(n)),
                None => "RSA".into(),
            },
            oid::EC_PUBLIC_KEY => format!(
                "ECDSA {}",
                self.curve()
                    .map_or_else(|| "?".to_string(), |c| oid::display(&c))
            ),
            o => oid::display(o),
        }
    }

    /// An RSA key's modulus and exponent.
    pub fn rsa(&self) -> Option<(&[u8], &[u8])> {
        let mut r = der::parse(self.key)
            .ok()?
            .expect(tag::SEQUENCE, "rsa key")
            .ok()?
            .reader();
        let n = r.expect(tag::INTEGER, "modulus").ok()?.body;
        let e = r.expect(tag::INTEGER, "exponent").ok()?.body;
        Some((n, e))
    }

    /// An EC key's curve.
    pub fn curve(&self) -> Option<String> {
        let p = self.algorithm.params?;
        p.oid().ok().map(|o| o.to_string())
    }
}

/// The bits of a big-endian unsigned integer.
fn bits(n: &[u8]) -> usize {
    let n = &n[n.iter().take_while(|&&b| b == 0).count()..];
    match n.first() {
        Some(&b) => n.len() * 8 - b.leading_zeros() as usize,
        None => 0,
    }
}

/// An extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    pub oid: String,
    pub critical: bool,
    pub value: &'a [u8],
}

/// A certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// All of it.
    pub raw: &'a [u8],
    /// What its issuer signed.
    pub tbs: &'a [u8],
    pub version: i64,
    pub serial: &'a [u8],
    pub issuer: Name<'a>,
    pub subject: Name<'a>,
    pub not_before: Time,
    pub not_after: Time,
    pub public_key: PublicKey<'a>,
    pub extensions: Vec<Extension<'a>>,
    pub signature_algorithm: Algorithm<'a>,
    pub signature: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// The certificate `t`.
    pub fn parse(t: Tlv<'a>) -> der::Result<Self> {
        let mut outer = t.expect(tag::SEQUENCE, "certificate")?.reader();
        let tbs = outer.expect(tag::SEQUENCE, "certificate")?;
        let signature_algorithm = Algorithm::parse(outer.take("signature algorithm")?)?;
        let signature = outer.expect(tag::BIT_STRING, "signature")?.bits()?;
        let mut r = tbs.reader();
        let version = match r.optional(tag::context(0))? {
            Some(v) => v.reader().take("version")?.small()?,
            None => 0,
        };
        let serial = r.take("serial number")?.integer()?;
        let _alg = r.take("signature algorithm")?;
        let issuer = Name::parse(r.take("issuer")?)?;
        let mut validity = r.expect(tag::SEQUENCE, "validity")?.reader();
        let not_before = validity.take("not before")?.time()?;
        let not_after = validity.take("not after")?.time()?;
        let subject = Name::parse(r.take("subject")?)?;
        let spki = r.expect(tag::SEQUENCE, "public key")?;
        let mut k = spki.reader();
        let algorithm = Algorithm::parse(k.take("public key algorithm")?)?;
        let key = k.expect(tag::BIT_STRING, "public key")?.bits()?;
        let mut extensions = Vec::new();
        while let Some(t) = r.next()? {
            if t.tag != tag::context(3) {
                // (Unique IDs: [1], [2].)
                continue;
            }
            let mut list = t.reader().expect(tag::SEQUENCE, "extensions")?.reader();
            while let Some(e) = list.next()? {
                let mut x = e.expect(tag::SEQUENCE, "extension")?.reader();
                let oid = x.expect(tag::OID, "extension")?.oid()?.to_string();
                let critical = match x.optional(tag::BOOLEAN)? {
                    Some(b) => b.boolean()?,
                    None => false,
                };
                let value = x.expect(tag::OCTET_STRING, "extension value")?.body;
                if extensions.len() < 64 {
                    extensions.push(Extension {
                        oid,
                        critical,
                        value,
                    });
                }
            }
        }
        Ok(Certificate {
            raw: t.raw,
            tbs: tbs.raw,
            version: version + 1,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            public_key: PublicKey {
                algorithm,
                key,
                raw: spki.raw,
            },
            extensions,
            signature_algorithm,
            signature,
        })
    }

    /// The certificate that is all of `data`.
    pub fn from_der(data: &'a [u8]) -> der::Result<Self> {
        Self::parse(der::parse(data)?)
    }

    fn extension(&self, oid: &str) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|e| e.oid == oid)
            .map(|e| e.value)
    }

    /// Its extended key usages (dotted); `None` if it doesn't limit them.
    pub fn extended_key_usage(&self) -> Option<Vec<String>> {
        let v = self.extension(oid::EXTENDED_KEY_USAGE)?;
        let mut out = Vec::new();
        let mut r = der::parse(v).ok()?.reader();
        while let Ok(Some(t)) = r.next() {
            if let Ok(o) = t.oid() {
                out.push(o.to_string());
            }
        }
        Some(out)
    }

    /// Whether it may be used for `eku` (it names it, or any purpose, or
    /// doesn't limit its use).
    pub fn allows(&self, eku: &str) -> bool {
        self.extended_key_usage()
            .is_none_or(|list| list.iter().any(|o| o == eku || o == oid::EKU_ANY))
    }

    /// Its key usages, by name.
    pub fn key_usage(&self) -> Option<Vec<&'static str>> {
        let v = self.extension(oid::KEY_USAGE)?;
        let (bits, _) = der::parse(v).ok()?.flags().ok()?;
        const NAMES: [&str; 9] = [
            "Digital Signature",
            "Non-Repudiation",
            "Key Encipherment",
            "Data Encipherment",
            "Key Agreement",
            "Certificate Signing",
            "CRL Signing",
            "Encipher Only",
            "Decipher Only",
        ];
        Some(
            NAMES
                .iter()
                .enumerate()
                .filter(|&(i, _)| bits.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
                .map(|(_, n)| *n)
                .collect(),
        )
    }

    /// Whether it is a certificate authority's (basicConstraints cA).
    pub fn is_ca(&self) -> bool {
        let Some(v) = self.extension(oid::BASIC_CONSTRAINTS) else {
            // (Version 1 roots have no extensions.)
            return self.version < 3 && self.is_self_issued();
        };
        der::parse(v)
            .ok()
            .and_then(|t| t.reader().optional(tag::BOOLEAN).ok().flatten())
            .is_some_and(|b| b.boolean().unwrap_or(false))
    }

    /// Its subject key identifier.
    pub fn subject_key_id(&self) -> Option<&'a [u8]> {
        let v = self.extension(oid::SUBJECT_KEY_ID)?;
        der::parse(v)
            .ok()?
            .expect(tag::OCTET_STRING, "key id")
            .ok()
            .map(|t| t.body)
    }

    /// Its authority (issuer's) key identifier.
    pub fn authority_key_id(&self) -> Option<&'a [u8]> {
        let v = self.extension(oid::AUTHORITY_KEY_ID)?;
        let mut r = der::parse(v).ok()?.reader();
        r.optional(tag::context_primitive(0))
            .ok()
            .flatten()
            .map(|t| t.body)
    }

    /// Whether it names itself as its issuer.
    pub fn is_self_issued(&self) -> bool {
        self.issuer.raw == self.subject.raw
    }

    /// Whether it was valid at `t`.
    pub fn valid_at(&self, t: Time) -> bool {
        self.not_before <= t && t <= self.not_after
    }

    /// Its serial number, in hex.
    pub fn serial_hex(&self) -> String {
        let s = self.serial;
        // (A leading zero only keeps it positive.)
        let s = if s.len() > 1 && s[0] == 0 { &s[1..] } else { s };
        hex(s)
    }
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

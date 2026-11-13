//! CMS (PKCS #7) SignedData (RFC 5652), as Authenticode and Apple code
//! signing use it; Authenticode's own structures; and timestamps (RFC 3161
//! TSTInfo, and PKCS #9 countersignatures).

use crate::der::{self, Time, Tlv, err, tag};
use crate::oid;
use crate::x509::{Algorithm, Certificate, Name};

/// The deepest nesting of signatures (nested in unsigned attributes) read.
pub const MAX_NESTING: usize = 8;

/// A SignedData.
#[derive(Clone, Debug)]
pub struct SignedData<'a> {
    pub version: i64,
    pub digest_algorithms: Vec<Algorithm<'a>>,
    /// What's signed: its type, and its contents (absent for a detached
    /// signature, as Apple's are).
    pub content_type: String,
    pub content: Option<Content<'a>>,
    pub certificates: Vec<Certificate<'a>>,
    pub signers: Vec<SignerInfo<'a>>,
}

/// Signed contents: the element, as written.
#[derive(Clone, Copy, Debug)]
pub struct Content<'a> {
    pub tlv: Tlv<'a>,
}

impl<'a> Content<'a> {
    /// The bytes the signer's message digest covers: an OCTET STRING's
    /// contents; for anything else (Authenticode's SpcIndirectDataContent),
    /// its contents without its tag and length.
    pub fn digested(&self) -> std::borrow::Cow<'a, [u8]> {
        match self.tlv.octets() {
            Ok(b) => b,
            Err(_) => std::borrow::Cow::Borrowed(self.tlv.body),
        }
    }
}

/// Who signed: a certificate's issuer and serial number, or its subject key
/// identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerId<'a> {
    IssuerSerial { issuer: Name<'a>, serial: &'a [u8] },
    KeyId(&'a [u8]),
}

impl SignerId<'_> {
    /// Whether `c` is the certificate it names.
    pub fn names(&self, c: &Certificate<'_>) -> bool {
        match self {
            SignerId::IssuerSerial { issuer, serial } => {
                c.issuer.raw == issuer.raw && strip(c.serial) == strip(serial)
            }
            SignerId::KeyId(id) => c.subject_key_id() == Some(id),
        }
    }
}

/// An INTEGER's bytes without the zeros that only keep it positive.
fn strip(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .take_while(|&&x| x == 0)
        .count()
        .min(b.len().saturating_sub(1));
    &b[n..]
}

/// An attribute: its type, and its values.
#[derive(Clone, Debug)]
pub struct Attribute<'a> {
    pub oid: String,
    pub values: Vec<Tlv<'a>>,
}

/// One signer.
#[derive(Clone, Debug)]
pub struct SignerInfo<'a> {
    pub version: i64,
    pub id: SignerId<'a>,
    pub digest_algorithm: Algorithm<'a>,
    /// The signed attributes, and their element (`[0]`; what is signed is
    /// it as a SET).
    pub signed: Option<(Tlv<'a>, Vec<Attribute<'a>>)>,
    pub signature_algorithm: Algorithm<'a>,
    pub signature: &'a [u8],
    pub unsigned: Vec<Attribute<'a>>,
}

impl<'a> SignerInfo<'a> {
    fn parse(t: Tlv<'a>) -> der::Result<Self> {
        let mut r = t.expect(tag::SEQUENCE, "signer info")?.reader();
        let version = r.expect(tag::INTEGER, "version")?.small()?;
        let sid = r.take("signer")?;
        let id = match sid.tag {
            tag::SEQUENCE => {
                let mut s = sid.reader();
                let issuer = crate::x509::parse_name(s.take("issuer")?)?;
                let serial = s.take("serial")?.integer()?;
                SignerId::IssuerSerial { issuer, serial }
            }
            t if t == tag::context_primitive(0) => SignerId::KeyId(sid.body),
            _ => return err("signer identifier"),
        };
        let digest_algorithm = Algorithm::parse(r.take("digest algorithm")?)?;
        let signed = match r.optional(tag::context(0))? {
            Some(t) => Some((t, attributes(t)?)),
            None => None,
        };
        let signature_algorithm = Algorithm::parse(r.take("signature algorithm")?)?;
        let signature = r.expect(tag::OCTET_STRING, "signature")?.body;
        let unsigned = match r.optional(tag::context(1))? {
            Some(t) => attributes(t)?,
            None => Vec::new(),
        };
        Ok(SignerInfo {
            version,
            id,
            digest_algorithm,
            signed,
            signature_algorithm,
            signature,
            unsigned,
        })
    }

    /// The signed attribute `oid`'s first value.
    pub fn signed_attribute(&self, oid: &str) -> Option<Tlv<'a>> {
        self.signed
            .as_ref()?
            .1
            .iter()
            .find(|a| a.oid == oid)?
            .values
            .first()
            .copied()
    }

    /// The values of unsigned attribute `oid`.
    pub fn unsigned_attributes(&self, oid: &str) -> impl Iterator<Item = Tlv<'a>> + '_ {
        let oid = oid.to_string();
        self.unsigned
            .iter()
            .filter(move |a| a.oid == oid)
            .flat_map(|a| a.values.iter().copied())
    }

    /// The message digest it signed (its messageDigest attribute).
    pub fn message_digest(&self) -> Option<&'a [u8]> {
        self.signed_attribute(oid::MESSAGE_DIGEST)?
            .expect(tag::OCTET_STRING, "digest")
            .ok()
            .map(|t| t.body)
    }

    /// When it says it signed (its signingTime attribute).
    pub fn signing_time(&self) -> Option<Time> {
        self.signed_attribute(oid::SIGNING_TIME)?.time().ok()
    }

    /// The bytes its signature covers: the signed attributes (as a SET,
    /// DER), or else the content.
    pub fn signed_bytes(&self, content: Option<&[u8]>) -> Option<Vec<u8>> {
        match &self.signed {
            Some((t, _)) => Some(der::encode(tag::SET, t.body)),
            None => content.map(<[u8]>::to_vec),
        }
    }
}

fn attributes<'a>(t: Tlv<'a>) -> der::Result<Vec<Attribute<'a>>> {
    let mut out = Vec::new();
    let mut r = t.reader();
    while let Some(a) = r.next()? {
        let mut x = a.expect(tag::SEQUENCE, "attribute")?.reader();
        let oid = x.expect(tag::OID, "attribute")?.oid()?.to_string();
        let mut values = Vec::new();
        let mut set = x.expect(tag::SET, "attribute values")?.reader();
        while let Some(v) = set.next()? {
            if values.len() < 64 {
                values.push(v);
            }
        }
        if out.len() < 64 {
            out.push(Attribute { oid, values });
        }
    }
    Ok(out)
}

impl<'a> SignedData<'a> {
    /// The ContentInfo (of a SignedData) that is all of `data`.
    pub fn from_der(data: &'a [u8]) -> der::Result<Self> {
        Self::from_content_info(der::parse(data)?)
    }

    /// The SignedData of ContentInfo `t`.
    pub fn from_content_info(t: Tlv<'a>) -> der::Result<Self> {
        let mut r = t.expect(tag::SEQUENCE, "content info")?.reader();
        let kind = r.expect(tag::OID, "content type")?.oid()?.to_string();
        if kind != oid::SIGNED_DATA {
            return err("content info (not signed data)");
        }
        let sd = r
            .expect(tag::context(0), "signed data")?
            .reader()
            .expect(tag::SEQUENCE, "signed data")?;
        let mut r = sd.reader();
        let version = r.expect(tag::INTEGER, "version")?.small()?;
        let mut digest_algorithms = Vec::new();
        let mut algs = r.expect(tag::SET, "digest algorithms")?.reader();
        while let Some(a) = algs.next()? {
            if digest_algorithms.len() < 16 {
                digest_algorithms.push(Algorithm::parse(a)?);
            }
        }
        let mut encap = r.expect(tag::SEQUENCE, "content")?.reader();
        let content_type = encap.expect(tag::OID, "content type")?.oid()?.to_string();
        let content = match encap.optional(tag::context(0))? {
            Some(c) => c.reader().next()?.map(|tlv| Content { tlv }),
            None => None,
        };
        let mut certificates = Vec::new();
        if let Some(set) = r.optional(tag::context(0))? {
            let mut cr = set.reader();
            while let Some(c) = cr.next()? {
                // (Other choices, attribute certificates, are skipped.)
                if c.tag == tag::SEQUENCE
                    && certificates.len() < 256
                    && let Ok(cert) = Certificate::parse(c)
                {
                    certificates.push(cert);
                }
            }
        }
        // (CRLs: skipped.)
        let _ = r.optional(tag::context(1))?;
        let mut signers = Vec::new();
        let mut set = r.expect(tag::SET, "signer infos")?.reader();
        while let Some(s) = set.next()? {
            if signers.len() < 16 {
                signers.push(SignerInfo::parse(s)?);
            }
        }
        Ok(SignedData {
            version,
            digest_algorithms,
            content_type,
            content,
            certificates,
            signers,
        })
    }

    /// The certificate `id` names.
    pub fn certificate(&self, id: &SignerId<'_>) -> Option<&Certificate<'a>> {
        self.certificates.iter().find(|c| id.names(c))
    }
}

/// Authenticode's SpcIndirectDataContent: what kind of thing was signed,
/// and its hash.
#[derive(Clone, Debug)]
pub struct IndirectData<'a> {
    pub data_type: String,
    pub digest_algorithm: Algorithm<'a>,
    pub digest: &'a [u8],
}

impl<'a> IndirectData<'a> {
    pub fn parse(t: Tlv<'a>) -> der::Result<Self> {
        let mut r = t.expect(tag::SEQUENCE, "indirect data")?.reader();
        let mut data = r.expect(tag::SEQUENCE, "indirect data")?.reader();
        let data_type = data.expect(tag::OID, "data type")?.oid()?.to_string();
        let mut info = r.expect(tag::SEQUENCE, "digest info")?.reader();
        let digest_algorithm = Algorithm::parse(info.take("digest algorithm")?)?;
        let digest = info.expect(tag::OCTET_STRING, "digest")?.body;
        Ok(IndirectData {
            data_type,
            digest_algorithm,
            digest,
        })
    }
}

/// Authenticode's SpcSpOpusInfo: the program's name and a link to more.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpusInfo {
    pub program: Option<String>,
    pub url: Option<String>,
}

impl OpusInfo {
    pub fn parse(t: Tlv<'_>) -> der::Result<Self> {
        let mut out = OpusInfo::default();
        let mut r = t.expect(tag::SEQUENCE, "opus info")?.reader();
        while let Some(f) = r.next()? {
            match f.tag {
                // programName [0] EXPLICIT SpcString: [0] unicode, [1] ascii.
                0xA0 => out.program = spc_string(f.reader().take("program name")?),
                // moreInfo [1] EXPLICIT SpcLink: [0] url, [1] moniker, [2] file.
                0xA1 => {
                    let link = f.reader().take("link")?;
                    out.url = match link.tag {
                        0x80 => Some(String::from_utf8_lossy(link.body).into_owned()),
                        0xA2 => spc_string(link.reader().take("file")?),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

fn spc_string(t: Tlv<'_>) -> Option<String> {
    match t.tag {
        0x80 | 0xA0 => {
            let units: Vec<u16> = t
                .body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Some(
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_string(),
            )
        }
        0x81 | 0xA1 => Some(
            String::from_utf8_lossy(t.body)
                .trim_end_matches('\0')
                .to_string(),
        ),
        _ => None,
    }
}

/// An RFC 3161 timestamp's TSTInfo: what was timestamped (a hash), and when.
#[derive(Clone, Debug)]
pub struct TstInfo<'a> {
    pub policy: String,
    pub imprint_algorithm: Algorithm<'a>,
    pub imprint: &'a [u8],
    pub serial: &'a [u8],
    pub time: Time,
    /// The TSA's name, if it gives it.
    pub tsa: Option<String>,
}

impl<'a> TstInfo<'a> {
    pub fn parse(data: &'a [u8]) -> der::Result<Self> {
        let t = der::parse(data)?;
        let mut r = t.expect(tag::SEQUENCE, "TSTInfo")?.reader();
        let _version = r.expect(tag::INTEGER, "version")?;
        let policy = r.expect(tag::OID, "policy")?.oid()?.to_string();
        let mut imprint = r.expect(tag::SEQUENCE, "message imprint")?.reader();
        let imprint_algorithm = Algorithm::parse(imprint.take("imprint algorithm")?)?;
        let imprint = imprint.expect(tag::OCTET_STRING, "imprint")?.body;
        let serial = r.take("serial")?.integer()?;
        let time = r.expect(tag::GENERALIZED_TIME, "time")?.time()?;
        let mut tsa = None;
        while let Some(f) = r.next()? {
            if f.tag == tag::context(0) {
                // GeneralName: [4] directoryName.
                if let Some(n) = f.reader().next()?
                    && n.tag == tag::context(4)
                    && let Some(name) = n.reader().next()?
                {
                    tsa = crate::x509::parse_name(name).ok().map(|n| n.to_string());
                }
            }
        }
        Ok(TstInfo {
            policy,
            imprint_algorithm,
            imprint,
            serial,
            time,
            tsa,
        })
    }
}

/// The SignerInfo in a countersignature attribute value.
pub fn countersigner(t: Tlv<'_>) -> der::Result<SignerInfo<'_>> {
    SignerInfo::parse(t)
}

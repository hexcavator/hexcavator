//! The cryptography: hashes, and checking signatures with public keys. All
//! of it is RustCrypto's (`sha1`, `sha2`, `md-5`, `rsa`, `p256`, `p384`);
//! here we only choose which function an algorithm's identifier names, and
//! pass it the bytes.

use crate::der::{self, tag};
use crate::oid;
use crate::x509::{Algorithm, PublicKey};

/// A hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// The hash a digest algorithm's identifier names (or a signature
    /// algorithm's: sha256WithRSAEncryption is SHA-256).
    pub fn of(oid: &str) -> Option<Self> {
        Some(match oid {
            oid::MD5 | oid::MD5_WITH_RSA => Hash::Md5,
            oid::SHA1 | oid::SHA1_WITH_RSA | oid::SHA1_WITH_RSA_OIW | oid::ECDSA_WITH_SHA1 => {
                Hash::Sha1
            }
            oid::SHA256 | oid::SHA256_WITH_RSA | oid::ECDSA_WITH_SHA256 => Hash::Sha256,
            oid::SHA384 | oid::SHA384_WITH_RSA | oid::ECDSA_WITH_SHA384 => Hash::Sha384,
            oid::SHA512 | oid::SHA512_WITH_RSA | oid::ECDSA_WITH_SHA512 => Hash::Sha512,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Hash::Md5 => "MD5",
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    /// A running hash.
    pub fn hasher(self) -> Hasher {
        use sha2::Digest;
        match self {
            Hash::Md5 => Hasher::Md5(md5::Md5::new()),
            Hash::Sha1 => Hasher::Sha1(sha1::Sha1::new()),
            Hash::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Hash::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Hash::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
        }
    }

    /// The hash of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.hasher();
        h.update(data);
        h.finish()
    }
}

/// A hash being computed.
pub enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Why a signature didn't check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// It doesn't match: the key didn't sign these bytes.
    Invalid,
    /// An algorithm (or key) we can't check.
    Unsupported(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Invalid => f.write_str("the signature doesn't match"),
            Failure::Unsupported(s) => write!(f, "can't check: {s}"),
        }
    }
}

/// Checks `signature` over `message` by `key`, with `algorithm` (a
/// signature algorithm; or, as CMS signers write it, rsaEncryption with
/// `digest` naming the hash).
pub fn verify(
    key: &PublicKey<'_>,
    algorithm: &Algorithm<'_>,
    digest: Option<&Algorithm<'_>>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Failure> {
    let hash = Hash::of(&algorithm.oid)
        .or_else(|| digest.and_then(|d| Hash::of(&d.oid)))
        .ok_or_else(|| Failure::Unsupported(format!("the hash of {}", algorithm.name())))?;
    let hashed = hash.digest(message);
    match key.algorithm.oid.as_str() {
        oid::RSA_ENCRYPTION => {
            if algorithm.oid == oid::RSA_PSS {
                return Err(Failure::Unsupported("RSASSA-PSS".into()));
            }
            verify_rsa(key, hash, &hashed, signature)
        }
        oid::EC_PUBLIC_KEY => verify_ecdsa(key, &hashed, signature),
        o => Err(Failure::Unsupported(format!("{} keys", oid::display(o)))),
    }
}

fn verify_rsa(
    key: &PublicKey<'_>,
    hash: Hash,
    hashed: &[u8],
    signature: &[u8],
) -> Result<(), Failure> {
    use rsa::traits::PublicKeyParts;
    use rsa::{BoxedUint, Pkcs1v15Sign};
    let (n, e) = key
        .rsa()
        .ok_or_else(|| Failure::Unsupported("a malformed RSA key".into()))?;
    let n = BoxedUint::from_be_slice_vartime(n);
    let e = BoxedUint::from_be_slice_vartime(e);
    // (Old signatures have small keys, 512 bits and up: we check them,
    // and say how big they are elsewhere.)
    let key = rsa::PublicKey::new_with_size_limits(n, e, 512..=16384)
        .map_err(|e| Failure::Unsupported(format!("the RSA key ({e})")))?;
    let scheme = match hash {
        Hash::Md5 => Pkcs1v15Sign::new::<md5::Md5>(),
        Hash::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        Hash::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        Hash::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        Hash::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
    };
    // (Old signers dropped the signature's leading zero bytes: as Windows
    // does, we put them back.)
    let size = key.size();
    let padded;
    let signature = if signature.len() < size {
        padded = [vec![0; size - signature.len()], signature.to_vec()].concat();
        &padded[..]
    } else {
        signature
    };
    if key.verify(scheme.clone(), hashed, signature).is_ok() {
        return Ok(());
    }
    // Old signers wrote what Windows accepts too, the same check with
    // another prefix: the DigestInfo's algorithm without its NULL
    // parameters; or (VeriSign's timestamps) no DigestInfo, the bare hash.
    if let Some(prefix) = without_null(&scheme.prefix) {
        let alt = Pkcs1v15Sign {
            hash_len: scheme.hash_len,
            prefix: prefix.into_boxed_slice(),
        };
        if key.verify(alt, hashed, signature).is_ok() {
            return Ok(());
        }
    }
    let bare = Pkcs1v15Sign {
        hash_len: scheme.hash_len,
        prefix: Box::new([]),
    };
    key.verify(bare, hashed, signature)
        .map_err(|_| Failure::Invalid)
}

/// A DigestInfo prefix (`30 L 30 L' 06 n <oid> 05 00 04 h`) without the
/// algorithm's NULL parameters (`30 L-2 30 L'-2 06 n <oid> 04 h`).
fn without_null(prefix: &[u8]) -> Option<Vec<u8>> {
    let n = usize::from(*prefix.get(5)?);
    if prefix.first() != Some(&0x30)
        || prefix.get(2) != Some(&0x30)
        || prefix.get(4) != Some(&0x06)
        || prefix.get(6 + n..8 + n) != Some(&[0x05, 0x00])
    {
        return None;
    }
    let mut out = prefix.to_vec();
    out.drain(6 + n..8 + n);
    out[1] = out[1].checked_sub(2)?;
    out[3] = out[3].checked_sub(2)?;
    Some(out)
}

fn verify_ecdsa(key: &PublicKey<'_>, hashed: &[u8], signature: &[u8]) -> Result<(), Failure> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    // The signature: a SEQUENCE of r and s (parsing, ours), as the fixed
    // r || s the curve's crate takes.
    let rs = |size: usize| -> Result<Vec<u8>, Failure> {
        let t = der::parse(signature).map_err(|_| Failure::Invalid)?;
        let mut r = t
            .expect(tag::SEQUENCE, "ecdsa signature")
            .map_err(|_| Failure::Invalid)?
            .reader();
        let mut out = Vec::with_capacity(size * 2);
        for _ in 0..2 {
            let v = r
                .take("ecdsa signature")
                .and_then(|t| t.integer())
                .map_err(|_| Failure::Invalid)?;
            let v = &v[v.iter().take_while(|&&b| b == 0).count()..];
            if v.len() > size {
                return Err(Failure::Invalid);
            }
            out.resize(out.len() + size - v.len(), 0);
            out.extend_from_slice(v);
        }
        Ok(out)
    };
    match key.curve().as_deref() {
        Some(oid::P256) => {
            let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.key)
                .map_err(|_| Failure::Unsupported("a malformed P-256 key".into()))?;
            let s = p256::ecdsa::Signature::from_slice(&rs(32)?).map_err(|_| Failure::Invalid)?;
            k.verify_prehash(hashed, &s).map_err(|_| Failure::Invalid)
        }
        Some(oid::P384) => {
            let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(key.key)
                .map_err(|_| Failure::Unsupported("a malformed P-384 key".into()))?;
            let s = p384::ecdsa::Signature::from_slice(&rs(48)?).map_err(|_| Failure::Invalid)?;
            k.verify_prehash(hashed, &s).map_err(|_| Failure::Invalid)
        }
        Some(c) => Err(Failure::Unsupported(format!(
            "the curve {}",
            oid::display(c)
        ))),
        None => Err(Failure::Unsupported(
            "an EC key without a named curve".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_info_without_null() {
        let p = rsa::Pkcs1v15Sign::new::<sha1::Sha1>().prefix;
        assert_eq!(
            &*p,
            &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14
            ]
        );
        assert_eq!(
            without_null(&p).unwrap(),
            vec![
                0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14
            ]
        );
    }

    #[test]
    fn hashes_of_abc() {
        let hex = crate::x509::hex;
        assert_eq!(
            hex(&Hash::Md5.digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&Hash::Sha1.digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&Hash::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut h = Hash::Sha256.hasher();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finish(), Hash::Sha256.digest(b"abc"));
    }
}

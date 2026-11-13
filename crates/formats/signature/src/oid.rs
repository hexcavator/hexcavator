//! The object identifiers signatures use, and their names.

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const RSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const MD5_WITH_RSA: &str = "1.2.840.113549.1.1.4";
pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const SHA1_WITH_RSA_OIW: &str = "1.3.14.3.2.29";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_WITH_SHA1: &str = "1.2.840.10045.4.1";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
pub const P256: &str = "1.2.840.10045.3.1.7";
pub const P384: &str = "1.3.132.0.34";
pub const P521: &str = "1.3.132.0.35";

pub const MD5: &str = "1.2.840.113549.2.5";
pub const SHA1: &str = "1.3.14.3.2.26";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";

pub const DATA: &str = "1.2.840.113549.1.7.1";
pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const COUNTER_SIGNATURE: &str = "1.2.840.113549.1.9.6";
pub const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

pub const SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
pub const SPC_STATEMENT_TYPE: &str = "1.3.6.1.4.1.311.2.1.11";
pub const SPC_SP_OPUS_INFO: &str = "1.3.6.1.4.1.311.2.1.12";
pub const SPC_PE_IMAGE_DATA: &str = "1.3.6.1.4.1.311.2.1.15";
pub const SPC_NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
pub const MS_RFC3161_TIMESTAMP: &str = "1.3.6.1.4.1.311.3.3.1";

pub const APPLE_CDHASHES: &str = "1.2.840.113635.100.9.1";
pub const APPLE_CDHASHES2: &str = "1.2.840.113635.100.9.2";

pub const KEY_USAGE: &str = "2.5.29.15";
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
pub const SUBJECT_KEY_ID: &str = "2.5.29.14";
pub const AUTHORITY_KEY_ID: &str = "2.5.29.35";

pub const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const EKU_ANY: &str = "2.5.29.37.0";

/// A name for `oid` (dotted), if it's one we know.
pub fn name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        RSA_ENCRYPTION => "rsaEncryption",
        RSA_PSS => "RSASSA-PSS",
        MD5_WITH_RSA => "md5WithRSAEncryption",
        SHA1_WITH_RSA | SHA1_WITH_RSA_OIW => "sha1WithRSAEncryption",
        SHA256_WITH_RSA => "sha256WithRSAEncryption",
        SHA384_WITH_RSA => "sha384WithRSAEncryption",
        SHA512_WITH_RSA => "sha512WithRSAEncryption",
        EC_PUBLIC_KEY => "ecPublicKey",
        ECDSA_WITH_SHA1 => "ecdsa-with-SHA1",
        ECDSA_WITH_SHA256 => "ecdsa-with-SHA256",
        ECDSA_WITH_SHA384 => "ecdsa-with-SHA384",
        ECDSA_WITH_SHA512 => "ecdsa-with-SHA512",
        P256 => "P-256",
        P384 => "P-384",
        P521 => "P-521",
        MD5 => "MD5",
        SHA1 => "SHA-1",
        SHA256 => "SHA-256",
        SHA384 => "SHA-384",
        SHA512 => "SHA-512",
        DATA => "data",
        SIGNED_DATA => "signedData",
        CONTENT_TYPE => "contentType",
        MESSAGE_DIGEST => "messageDigest",
        SIGNING_TIME => "signingTime",
        COUNTER_SIGNATURE => "counterSignature",
        TST_INFO => "TSTInfo",
        SPC_INDIRECT_DATA => "SpcIndirectDataContent",
        SPC_STATEMENT_TYPE => "SpcStatementType",
        SPC_SP_OPUS_INFO => "SpcSpOpusInfo",
        SPC_PE_IMAGE_DATA => "SpcPeImageData",
        SPC_NESTED_SIGNATURE => "nested signature",
        MS_RFC3161_TIMESTAMP => "RFC 3161 timestamp",
        "1.3.6.1.4.1.311.2.1.21" => "individual code signing",
        "1.3.6.1.4.1.311.2.1.22" => "commercial code signing",
        APPLE_CDHASHES => "Apple cdhashes",
        APPLE_CDHASHES2 => "Apple cdhashes (by type)",
        KEY_USAGE => "keyUsage",
        BASIC_CONSTRAINTS => "basicConstraints",
        EXTENDED_KEY_USAGE => "extKeyUsage",
        SUBJECT_KEY_ID => "subjectKeyIdentifier",
        AUTHORITY_KEY_ID => "authorityKeyIdentifier",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        EKU_CODE_SIGNING => "Code Signing",
        EKU_TIME_STAMPING => "Time Stamping",
        EKU_ANY => "Any Purpose",
        "1.3.6.1.5.5.7.3.1" => "Server Authentication",
        "1.3.6.1.5.5.7.3.2" => "Client Authentication",
        "1.3.6.1.5.5.7.3.4" => "Email Protection",
        "1.3.6.1.4.1.311.10.3.6" => "Windows System Component Verification",
        "1.3.6.1.4.1.311.10.3.5" => "Windows Hardware Driver Verification",
        "1.3.6.1.4.1.311.10.3.39" => "Windows Hardware Driver Extended Verification",
        "1.3.6.1.4.1.311.61.1.1" => "Kernel Mode Code Signing",
        "1.3.6.1.4.1.311.76.3.1" => "Windows Store",
        "1.3.6.1.4.1.311.10.3.13" => "Lifetime Signing",
        "1.3.6.1.4.1.311.97.1.0" => "Microsoft Publisher",
        "1.2.840.113635.100.4.13" => "Apple Package Signing",
        "1.2.840.113635.100.6.1.13" => "Apple Developer ID Application",
        "1.2.840.113635.100.6.1.14" => "Apple Developer ID Installer",
        "1.2.840.113635.100.6.1.2" => "Apple iPhone Developer",
        "1.2.840.113635.100.6.1.12" => "Apple Mac Developer",
        "1.2.840.113635.100.6.1.7" => "Apple Mac App Store Application",
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "PostalCode",
        "2.5.4.42" => "G",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "E",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionS",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return None,
    })
}

/// `oid`'s name, or the dotted form.
pub fn display(oid: &str) -> String {
    name(oid).map_or_else(|| oid.to_string(), str::to_string)
}

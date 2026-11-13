// Written by tools/signature/roots.py: the roots hexc trusts for code
// signatures (name, SHA-256 thumbprint, certificate).

pub(crate) static ROOTS: &[(&str, &str, &[u8])] = &[
    (
        "Microsoft Root Certificate Authority 2010",
        "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e",
        include_bytes!("../roots/3b1efd3a66ea28b16697394703a72ca340a05bd5.cer"),
    ),
    (
        "Microsoft Root Certificate Authority 2011",
        "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61",
        include_bytes!("../roots/8f43288ad272f3103b6fb1428485ea3014c0bcfe.cer"),
    ),
    (
        "Microsoft Root Authority",
        "f38406e540d7a9d90cb4a9479299640ffb6df9e224ecc7a01c0d9558d8dad77d",
        include_bytes!("../roots/a43489159a520f0d93d032ccaf37e7fe20a8b419.cer"),
    ),
    (
        "Microsoft Root Certificate Authority",
        "885de64c340e3ea70658f01e1145f957fcda27aabeea1ab9faa9fdb0102d4077",
        include_bytes!("../roots/cdd4eeae6000ac7f40c3802c171e30148030c072.cer"),
    ),
    (
        "Microsoft Identity Verification Root Certificate Authority 2020",
        "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270",
        include_bytes!("../roots/f40042e2e5f7e8ef8189fed15519aece42c3bfa2.cer"),
    ),
    (
        "Microsoft ECC Root Certificate Authority 2017",
        "358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02",
        include_bytes!("../roots/999a64c37ff47d9fab95f14769891460eec4c3c5.cer"),
    ),
    (
        "Microsoft RSA Root Certificate Authority 2017",
        "c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0",
        include_bytes!("../roots/73a5e64a3bff8316ff0edccc618a906e4eae4d74.cer"),
    ),
    (
        "Microsoft ECC Product Root Certificate Authority 2018",
        "caca93b9d23d2b6fa76e8b8471931e0df3ec6f63af3cdbb936c41954a1872326",
        include_bytes!("../roots/06f1aa330b927b753a40e68cdf22e34bcbef3352.cer"),
    ),
    (
        "Microsoft Time Stamp Root Certificate Authority 2014",
        "65af95f4be86847344634282f941b2e605063ef0c8542f014ca088d182109e4f",
        include_bytes!("../roots/0119e81be9a14cd8e22f40ac118c687ecba3f4d8.cer"),
    ),
    (
        "Microsoft ECC TS Root Certificate Authority 2018",
        "3fd4be8baad2f26e1bde06c7584bb720dd1a972d111f5a4999bc44b08fb4960d",
        include_bytes!("../roots/31f9fc8ba3805986b721ea7295c65b3a44534274.cer"),
    ),
    (
        "DigiCert Assured ID Root CA",
        "3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c",
        include_bytes!("../roots/0563b8630d62d75abbc8ab1e4bdfb5a899b24d43.cer"),
    ),
    (
        "DigiCert Trusted Root G4",
        "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        include_bytes!("../roots/ddfb16cd4931c973a2037d3fc83a4d7d775d05e4.cer"),
    ),
    (
        "DigiCert High Assurance EV Root CA",
        "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf",
        include_bytes!("../roots/5fb7ee0633e259dbad0c4c9ae6d38f1a61c7dc25.cer"),
    ),
    (
        "DigiCert Global Root CA",
        "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161",
        include_bytes!("../roots/a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436.cer"),
    ),
    (
        "DigiCert Global Root G2",
        "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f",
        include_bytes!("../roots/df3c24f9bfd666761b268073fe06d1cc8d4f82a4.cer"),
    ),
    (
        "USERTrust RSA Certification Authority",
        "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2",
        include_bytes!("../roots/2b8f1b57330dbba2d07a6c51f70ee90ddab9ad8e.cer"),
    ),
    (
        "AAA Certificate Services",
        "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
        include_bytes!("../roots/d1eb23a46d17d68fd92564c2f1f1601764d8e349.cer"),
    ),
    (
        "GlobalSign Root CA",
        "ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99",
        include_bytes!("../roots/b1bc968bd4f49d622aa89a81f2150152a41d829c.cer"),
    ),
    (
        "GlobalSign Root CA - R3",
        "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b",
        include_bytes!("../roots/d69b561148f01c77c54578c10926df5b856976ad.cer"),
    ),
    (
        "VeriSign Class 3 Public Primary Certification Authority - G5",
        "9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df",
        include_bytes!("../roots/4eb6d578499b1ccf5f581ead56be3d9b6744a5e5.cer"),
    ),
    (
        "VeriSign Class 3 Public Primary Certification Authority",
        "e7685634efacf69ace939a6b255b7b4fabef42935b50a265acb5cb6027e44e70",
        include_bytes!("../roots/742c3192e607e424eb4549542be1bbc53e6174e2.cer"),
    ),
    (
        "Thawte Timestamping CA",
        "6b6c1e01f590f5afc5fcf85cd0b9396884048659fc2c6d1170d68b045216c3fd",
        include_bytes!("../roots/be36a4562fb2ee05dbb3d32323adf445084ed656.cer"),
    ),
    (
        "Entrust Root Certification Authority - G2",
        "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339",
        include_bytes!("../roots/8cf427fd790c3ad166068de81e57efbb932272d4.cer"),
    ),
    (
        "Entrust Root Certification Authority",
        "73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c",
        include_bytes!("../roots/b31eb1b740e36c8402dadc37d44df5d4674952f9.cer"),
    ),
    (
        "Certum Trusted Network CA",
        "5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e",
        include_bytes!("../roots/07e032e020b72c3f192f0628a2593a19a70f069e.cer"),
    ),
    (
        "Go Daddy Class 2 Certification Authority",
        "c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4",
        include_bytes!("../roots/2796bae63f1801e277261ba0d77770028f20eee4.cer"),
    ),
    (
        "Starfield Class 2 Certification Authority",
        "1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658",
        include_bytes!("../roots/ad7e1c28b064ef8f6003402014c3d0e3370eb58a.cer"),
    ),
    (
        "Apple Root CA",
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
        include_bytes!("../roots/611e5b662c593a08ff58d14ae22452d198df6c60.cer"),
    ),
    (
        "Apple Root CA - G3",
        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
        include_bytes!("../roots/b52cb02fd567e0359fe8fa4d4c41037970fe01b0.cer"),
    ),
];

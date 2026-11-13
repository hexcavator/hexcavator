"""Fetches the root certificates hexc trusts for code signatures, and
writes them (crates/formats/signature/roots/*.cer) with the Rust list of
them (crates/formats/signature/src/roots_list.rs).

The roots: Microsoft's own and the main public code-signing and
timestamping authorities (from Microsoft's root program, whose roots
Windows downloads from ctldl.windowsupdate.com by thumbprint), and
Apple's (from apple.com). Each download is checked against its SHA-1
thumbprint before it's kept.

    python tools/signature/roots.py
"""

import hashlib
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.join(HERE, "..", "..", "crates", "formats", "signature")
CTL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{}.crt"

# (SHA-1 thumbprint, name, where from: None for Microsoft's root program).
ROOTS = [
    ("3B1EFD3A66EA28B16697394703A72CA340A05BD5", "Microsoft Root Certificate Authority 2010", None),
    ("8F43288AD272F3103B6FB1428485EA3014C0BCFE", "Microsoft Root Certificate Authority 2011", None),
    ("A43489159A520F0D93D032CCAF37E7FE20A8B419", "Microsoft Root Authority", None),
    ("CDD4EEAE6000AC7F40C3802C171E30148030C072", "Microsoft Root Certificate Authority", None),
    ("F40042E2E5F7E8EF8189FED15519AECE42C3BFA2", "Microsoft Identity Verification Root Certificate Authority 2020", None),
    ("999A64C37FF47D9FAB95F14769891460EEC4C3C5", "Microsoft ECC Root Certificate Authority 2017", None),
    ("73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74", "Microsoft RSA Root Certificate Authority 2017", None),
    ("06F1AA330B927B753A40E68CDF22E34BCBEF3352", "Microsoft ECC Product Root Certificate Authority 2018", None),
    ("0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8", "Microsoft Time Stamp Root Certificate Authority 2014", None),
    ("31F9FC8BA3805986B721EA7295C65B3A44534274", "Microsoft ECC TS Root Certificate Authority 2018", None),
    ("0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43", "DigiCert Assured ID Root CA", None),
    ("DDFB16CD4931C973A2037D3FC83A4D7D775D05E4", "DigiCert Trusted Root G4", None),
    ("5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25", "DigiCert High Assurance EV Root CA", None),
    ("A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436", "DigiCert Global Root CA", None),
    ("DF3C24F9BFD666761B268073FE06D1CC8D4F82A4", "DigiCert Global Root G2", None),
    ("2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E", "USERTrust RSA Certification Authority", None),
    ("D1EB23A46D17D68FD92564C2F1F1601764D8E349", "AAA Certificate Services", None),
    ("B1BC968BD4F49D622AA89A81F2150152A41D829C", "GlobalSign Root CA", None),
    ("D69B561148F01C77C54578C10926DF5B856976AD", "GlobalSign Root CA - R3", None),
    ("4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5", "VeriSign Class 3 Public Primary Certification Authority - G5", None),
    ("742C3192E607E424EB4549542BE1BBC53E6174E2", "VeriSign Class 3 Public Primary Certification Authority", None),
    ("BE36A4562FB2EE05DBB3D32323ADF445084ED656", "Thawte Timestamping CA", None),
    ("8CF427FD790C3AD166068DE81E57EFBB932272D4", "Entrust Root Certification Authority - G2", None),
    ("B31EB1B740E36C8402DADC37D44DF5D4674952F9", "Entrust Root Certification Authority", None),
    ("07E032E020B72C3F192F0628A2593A19A70F069E", "Certum Trusted Network CA", None),
    ("2796BAE63F1801E277261BA0D77770028F20EEE4", "Go Daddy Class 2 Certification Authority", None),
    ("AD7E1C28B064EF8F6003402014C3D0E3370EB58A", "Starfield Class 2 Certification Authority", None),
    ("611E5B662C593A08FF58D14AE22452D198DF6C60", "Apple Root CA", "https://www.apple.com/appleca/AppleIncRootCertificate.cer"),
    ("B52CB02FD567E0359FE8FA4D4C41037970FE01B0", "Apple Root CA - G3", "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer"),
]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "hexcavator-roots"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def main():
    out = os.path.join(CRATE, "roots")
    os.makedirs(out, exist_ok=True)
    lines = []
    failed = []
    for thumb, name, url in ROOTS:
        file = thumb.lower() + ".cer"
        path = os.path.join(out, file)
        if not os.path.exists(path):
            try:
                data = fetch(url or CTL.format(thumb))
            except Exception as e:  # noqa: BLE001
                failed.append(f"{name}: {e}")
                continue
            if hashlib.sha1(data).hexdigest().upper() != thumb:
                failed.append(f"{name}: the thumbprint doesn't match")
                continue
            with open(path, "wb") as f:
                f.write(data)
        with open(path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        lines.append(f'    ("{name}", "{sha256}", include_bytes!("../roots/{file}")),')
    with open(os.path.join(CRATE, "src", "roots_list.rs"), "w", encoding="utf-8", newline="\n") as f:
        f.write("// Written by tools/signature/roots.py: the roots hexc trusts for code\n")
        f.write("// signatures (name, SHA-256 thumbprint, certificate).\n\n")
        f.write("pub(crate) static ROOTS: &[(&str, &str, &[u8])] = &[\n")
        f.write("\n".join(lines) + "\n];\n")
    print(f"{len(lines)} roots")
    for x in failed:
        print("failed:", x, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

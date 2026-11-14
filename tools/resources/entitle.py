"""Adds entitlements to a thin 64-bit Mach-O image's code signature (the
ad-hoc one ld64.lld writes): `entitle.py <image> <entitlements.plist>`.

The signature's superblob gets an entitlements blob (slot 5) after its
others; LC_CODE_SIGNATURE and __LINKEDIT grow to hold it. (Its hashes are
not redone: the signature no longer verifies. It's a test of reading the
entitlements, not of signing.)"""

import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D


def main():
    path = Path(sys.argv[1])
    xml = Path(sys.argv[2]).read_bytes()
    data = bytearray(path.read_bytes())
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    assert magic == 0xFEEDFACF, "not a thin 64-bit Mach-O image"
    at = 32
    sig = linkedit = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == LC_CODE_SIGNATURE:
            sig = at
        elif cmd == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = at
        at += size
    assert sig is not None and linkedit is not None, "no code signature"
    off, size = struct.unpack_from("<II", data, sig + 8)
    blob = bytes(data[off:off + size])
    smagic, _, count = struct.unpack_from(">III", blob, 0)
    assert smagic == 0xFADE0CC0
    index = [struct.unpack_from(">II", blob, 12 + 8 * i) for i in range(count)]
    contents = [blob[o:o + struct.unpack_from(">I", blob, o + 4)[0]] for _, o in index]
    entitlements = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    slots = [t for t, _ in index] + [5]
    contents.append(entitlements)
    head = 12 + 8 * len(slots)
    body = b""
    table = b""
    for t, c in zip(slots, contents):
        table += struct.pack(">II", t, head + len(body))
        body += c
    superblob = struct.pack(">III", 0xFADE0CC0, head + len(body), len(slots)) + table + body
    # (Padded to 16 bytes, as signatures are.)
    superblob += b"\0" * (-len(superblob) % 16)
    del data[off:]
    data += superblob
    struct.pack_into("<II", data, sig + 8, off, len(superblob))
    fileoff, = struct.unpack_from("<Q", data, linkedit + 40)
    filesize = len(data) - fileoff
    vmsize = (filesize + 0x3FFF) & ~0x3FFF
    struct.pack_into("<Q", data, linkedit + 32, vmsize)
    struct.pack_into("<Q", data, linkedit + 48, filesize)
    path.write_bytes(bytes(data))


main()

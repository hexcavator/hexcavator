"""Writes compressed-debug-section variants of an ELF64 little-endian file,
as `ld --compress-debug-sections` would (this LLVM build has neither zlib
nor zstd, so the linker can't):

  <out>.zlib   SHF_COMPRESSED sections, ELFCOMPRESS_ZLIB (gABI)
  <out>.zstd   SHF_COMPRESSED sections, ELFCOMPRESS_ZSTD (gABI)
  <out>.zdebug .zdebug_* sections, "ZLIB" + big-endian size (GNU)

Each .debug_* section's contents are compressed and appended to the file;
its header then points there (the old bytes stay, unmapped). For .zdebug,
the section names change too, so a new section-name table is appended.

Usage: python compress.py <input ELF> <output prefix>
"""

import struct
import sys
import zlib
from compression import zstd

SHF_COMPRESSED = 0x800
ELFCOMPRESS_ZLIB, ELFCOMPRESS_ZSTD = 1, 2


def sections(data):
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    out = []
    for i in range(shnum):
        at = shoff + i * shentsize
        name, kind, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, at)
        out.append(dict(at=at, name=name, kind=kind, flags=flags, off=off, size=size, align=align))
    strtab = out[shstrndx]
    names = data[strtab["off"]:strtab["off"] + strtab["size"]]
    for s in out:
        end = names.index(b"\0", s["name"])
        s["sname"] = names[s["name"]:end]
    return out, shstrndx


def variant(data, mode):
    buf = bytearray(data)
    secs, shstrndx = sections(data)
    new_names = bytearray(data[secs[shstrndx]["off"]:secs[shstrndx]["off"] + secs[shstrndx]["size"]])
    for s in secs:
        if not s["sname"].startswith(b".debug_"):
            continue
        contents = data[s["off"]:s["off"] + s["size"]]
        if mode == "zdebug":
            payload = b"ZLIB" + struct.pack(">Q", len(contents)) + zlib.compress(contents)
            # The section's new name, appended to the name table.
            s["name"] = len(new_names)
            new_names += b".z" + s["sname"][1:] + b"\0"
        else:
            kind = ELFCOMPRESS_ZLIB if mode == "zlib" else ELFCOMPRESS_ZSTD
            packed = zlib.compress(contents) if mode == "zlib" else zstd.compress(contents)
            payload = struct.pack("<IIQQ", kind, 0, len(contents), max(s["align"], 1)) + packed
            s["flags"] |= SHF_COMPRESSED
        while len(buf) % 8:
            buf.append(0)
        s["off"] = len(buf)
        s["size"] = len(payload)
        buf += payload
        struct.pack_into("<I", buf, s["at"], s["name"])
        struct.pack_into("<Q", buf, s["at"] + 0x08, s["flags"])
        struct.pack_into("<QQ", buf, s["at"] + 0x18, s["off"], s["size"])
    if mode == "zdebug":
        st = secs[shstrndx]
        st["off"] = len(buf)
        st["size"] = len(new_names)
        buf += new_names
        struct.pack_into("<QQ", buf, st["at"] + 0x18, st["off"], st["size"])
    return bytes(buf)


def main():
    data = open(sys.argv[1], "rb").read()
    assert data[:6] == b"\x7fELF\x02\x01", "ELF64 little-endian only"
    for mode in ["zlib", "zstd", "zdebug"]:
        with open(f"{sys.argv[2]}.{mode}", "wb") as f:
            f.write(variant(data, mode))


main()

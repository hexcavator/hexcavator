# SPDX-License-Identifier: Apache-2.0
"""Downloads the PDBs of the modules named in x86 stack snapshots.

  python symbols.py OUT [SNAPSHOT...]

OUT is where they go (the extended tests read $HEXC_CORPUS/symbols/x86);
the snapshots default to
testdata/x86fpo/*.sync. Each module's CodeView record (RSDS: PDB name,
GUID, age) gives its symbol server path; PDBs are stored flat, by name,
where dbghelp and the x86 walk test look for them.
"""

import glob
import os
import struct
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = "https://msdl.microsoft.com/download/symbols"
SYSTEM32 = r"c:\windows\system32" + "\\"
SYSWOW64 = r"C:\Windows\SysWOW64" + "\\"


def modules(snapshot):
    data = open(snapshot, "rb").read()
    at = 0
    out = set()
    while at + 4 <= len(data):
        assert data[at:at + 4] == b"X86S"
        at += 4
        (n,) = struct.unpack_from("<I", data, at)
        at += 4 + n + 40
        (_, length) = struct.unpack_from("<II", data, at)
        at += 8 + length
        (count,) = struct.unpack_from("<I", data, at)
        at += 4
        for _ in range(count):
            _, _, chars = struct.unpack_from("<III", data, at)
            at += 12
            out.add(data[at:at + 2 * chars].decode("utf-16-le"))
            at += 2 * chars
        (truths,) = struct.unpack_from("<I", data, at)
        at += 4 + 12 * truths
    return out


def codeview(path):
    """(pdb name, GUID+age key) from a PE file's RSDS record."""
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, = struct.unpack_from("<H", d, pe + 6)
    opt_size, = struct.unpack_from("<H", d, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", d, opt)
    dirs = opt + (96 if magic == 0x10B else 112)
    rva, size = struct.unpack_from("<II", d, dirs + 8 * 6)
    secs = [struct.unpack_from("<IIII", d, opt + opt_size + 40 * i + 8) for i in range(nsec)]

    def off(r):
        for vs, va, rs, rp in secs:
            if va <= r < va + max(vs, rs):
                return rp + r - va
        return None

    o = off(rva)
    for i in range(size // 28):
        typ, = struct.unpack_from("<I", d, o + 28 * i + 12)
        if typ != 2:
            continue
        ptr, = struct.unpack_from("<I", d, o + 28 * i + 24)
        if d[ptr:ptr + 4] != b"RSDS":
            continue
        g = d[ptr + 4:ptr + 20]
        age, = struct.unpack_from("<I", d, ptr + 20)
        name = d[ptr + 24:d.index(b"\0", ptr + 24)].decode()
        name = name.replace("/", "\\").split("\\")[-1]
        a, b, c = struct.unpack_from("<IHH", g)
        key = f"{a:08X}{b:04X}{c:04X}{g[8:].hex().upper()}{age:X}"
        return name, key
    return None


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: symbols.py OUT [snapshots...]")
    out = sys.argv[1]
    snaps = sys.argv[2:] or glob.glob(os.path.join(HERE, "..", "..", "testdata", "x86fpo", "*.sync"))
    os.makedirs(out, exist_ok=True)
    paths = set()
    for s in snaps:
        paths |= modules(s)
    for p in sorted(paths):
        # (The snapshots are of a 32-bit process: its System32 is SysWOW64.)
        if p.lower().startswith(SYSTEM32):
            p = SYSWOW64 + p[len(SYSTEM32):]
        if not os.path.exists(p):
            continue
        cv = codeview(p)
        if not cv:
            continue
        name, key = cv
        dest = os.path.join(out, name)
        stamp = dest + ".key"
        if os.path.exists(dest) and os.path.exists(stamp) and open(stamp).read() == key:
            continue
        url = f"{SERVER}/{name}/{key}/{name}"
        try:
            data = urllib.request.urlopen(url, timeout=300).read()
        except Exception:
            # (Some are only stored compressed, as a cabinet: `.pd_`.)
            try:
                cab = urllib.request.urlopen(url[:-1] + "_", timeout=300).read()
            except Exception as e:
                print(f"{name}: {e}")
                continue
            with tempfile.TemporaryDirectory() as t:
                c = os.path.join(t, name[:-1] + "_")
                open(c, "wb").write(cab)
                subprocess.run(["expand", c, os.path.join(t, name)], check=True, capture_output=True)
                data = open(os.path.join(t, name), "rb").read()
        open(dest, "wb").write(data)
        open(stamp, "w").write(key)
        print(f"{name}: {len(data) >> 10} KB")


if __name__ == "__main__":
    main()

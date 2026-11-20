# SPDX-License-Identifier: Apache-2.0
"""Marks a Mach-O image ld64.lld linked as Apple's ld's: the linker its
LC_BUILD_VERSION names, TOOL_LLD (4), becomes TOOL_LD (3), in place. (What
Apple's ld does differently, folding identical functions unless given
-no_deduplicate, is judged from that name; this machine has no Apple ld.)

    python as-apple-ld.py <image>
"""

import struct
import sys

LC_BUILD_VERSION = 0x32
TOOL_LD, TOOL_LLD = 3, 4


def main(path):
    data = bytearray(open(path, "rb").read())
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        sys.exit(f"{path}: not a little-endian thin Mach-O image")
    header = 32 if magic == 0xFEEDFACF else 28
    ncmds = struct.unpack_from("<I", data, 16)[0]
    at, changed = header, 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == LC_BUILD_VERSION:
            ntools = struct.unpack_from("<I", data, at + 20)[0]
            for i in range(ntools):
                t = at + 24 + 8 * i
                if struct.unpack_from("<I", data, t)[0] == TOOL_LLD:
                    struct.pack_into("<I", data, t, TOOL_LD)
                    changed += 1
        at += size
    if not changed:
        sys.exit(f"{path}: no LC_BUILD_VERSION naming lld")
    open(path, "wb").write(data)


if __name__ == "__main__":
    main(sys.argv[1])

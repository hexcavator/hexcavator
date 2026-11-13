"""MiniDebugInfo test inputs (as Fedora builds them): an image's symbol
table, alone, xz-compressed into the .gnu_debugdata section of its
stripped copy; and xz streams of each check type, for the decoder.

    python -I minidebuginfo.py <llvm bin> <image> <out dir>

Writes <out dir>/program-minidebug (the image stripped, with
.gnu_debugdata), and <out dir>/../xz/*.xz with text.txt, the text they
hold.
"""

import lzma
import os
import subprocess
import sys


def main():
    llvm, image, out = sys.argv[1:4]
    objcopy = os.path.join(llvm, "llvm-objcopy.exe" if os.name == "nt" else "llvm-objcopy")
    mini = os.path.join(out, "minidebug.tmp")
    xz = mini + ".xz"
    # The symbol table and section headers alone: no code, no DWARF.
    subprocess.run([objcopy, "--only-keep-debug", "--strip-debug", image, mini], check=True)
    with open(mini, "rb") as f:
        data = f.read()
    with open(xz, "wb") as f:
        f.write(lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6))
    stripped = os.path.join(out, "program-minidebug")
    subprocess.run([objcopy, "--strip-all", image, stripped], check=True)
    subprocess.run([objcopy, "--add-section", ".gnu_debugdata=" + xz, stripped], check=True)
    os.remove(mini)
    os.remove(xz)

    # The decoder's inputs: text (compressible, but not trivially), in each
    # check, in blocks, and as two streams.
    xzdir = os.path.join(out, "..", "xz")
    os.makedirs(xzdir, exist_ok=True)
    text = "".join("%d: %s\n" % (i, "abcdefghij"[i % 10] * (i % 37)) for i in range(4000)).encode()
    with open(os.path.join(xzdir, "text.txt"), "wb") as f:
        f.write(text)
    for name, check in [
        ("none", lzma.CHECK_NONE),
        ("crc32", lzma.CHECK_CRC32),
        ("crc64", lzma.CHECK_CRC64),
        ("sha256", lzma.CHECK_SHA256),
    ]:
        with open(os.path.join(xzdir, "text-%s.xz" % name), "wb") as f:
            f.write(lzma.compress(text, format=lzma.FORMAT_XZ, check=check))
    # Two streams, with stream padding between them.
    half = len(text) // 2
    two = lzma.compress(text[:half], format=lzma.FORMAT_XZ) + b"\0" * 8 + lzma.compress(text[half:], format=lzma.FORMAT_XZ)
    with open(os.path.join(xzdir, "text-two-streams.xz"), "wb") as f:
        f.write(two)
    # A filter other than LZMA2 alone (x86 BCJ first): refused.
    with open(os.path.join(xzdir, "text-bcj.xz"), "wb") as f:
        f.write(lzma.compress(text, format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}]))


if __name__ == "__main__":
    main()

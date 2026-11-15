"""What a reference symbolizer says is at each byte of an image's code, as
golden data for `hexc symbolize`'s test (apps/hexcavator/tests/it/symbolize.rs).

usage: symbolize-oracle.py <llvm-symbolizer or diasymbolize> <image>

For an ELF image, llvm-symbolizer's answers for each byte of its .text; for a
PE image, diasymbolize's (the DIA SDK's, tools/diasymbolize) for each byte of
its first code section, from the PDB beside it. One line per run of
addresses with the same answer: the first and last, a tab, and the frames,
innermost first, as a JSON array of [function, file, line, inlined] (an ELF
image's paths with /):

    0x2011c0..0x2011c2<TAB>[["square(int)","./lines.h",5,true],["first(int)","./lines-elf.cpp",6,false]]
"""

import json
import os
import struct
import subprocess
import sys


def elf_text(data):
    """(address, size) of an ELF64 file's .text."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    def header(i):
        return struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
    names = header(shstrndx)[4]
    for i in range(shnum):
        h = header(i)
        name = data[names + h[0]:data.index(b"\0", names + h[0])]
        if name == b".text":
            return h[3], h[5]
    raise SystemExit("no .text")


def pe_code(data):
    """(RVA, size) of a PE image's first code section, and its image base."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count, opt = struct.unpack_from("<H12xH", data, pe + 6)
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    base = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, pe + 24 + (24 if magic == 0x20B else 28))[0]
    sections = pe + 24 + opt
    for i in range(count):
        # (VirtualSize, VirtualAddress at 8; Characteristics at 36.)
        size, rva = struct.unpack_from("<II", data, sections + i * 40 + 8)
        flags, = struct.unpack_from("<I", data, sections + i * 40 + 36)
        if flags & 0x20:
            return rva, size, base
    raise SystemExit("no code section")


def main():
    tool, image = sys.argv[1:3]
    data = open(image, "rb").read()
    lines = []
    if data[:4] == b"\x7fELF":
        start, size = elf_text(data)
        addrs = list(range(start, start + size))
        out = subprocess.run([tool, "--obj=" + image, "--inlines", "--output-style=JSON"],
                             input="".join("0x%x\n" % a for a in addrs), capture_output=True,
                             text=True, encoding="utf-8", check=True).stdout
        for a, line in zip(addrs, out.splitlines()):
            frames = []
            for f in json.loads(line)["Symbol"]:
                if f["FunctionName"]:
                    frames.append((f["FunctionName"], f["FileName"].replace("\\", "/"), f["Line"], True))
            if frames:
                frames[-1] = frames[-1][:3] + (False,)
            lines.append((a, frames))
    else:
        rva, size, base = pe_code(data)
        pdb = os.path.splitext(image)[0] + ".pdb"
        rvas = list(range(rva, rva + size))
        out = subprocess.run([tool, pdb], input="".join("%x\n" % r for r in rvas),
                             capture_output=True, text=True, encoding="utf-8", check=True).stdout
        for r, line in zip(rvas, out.splitlines()):
            frames = [(f["name"], f["file"], f["line"], f["inlined"]) for f in json.loads(line)["frames"]]
            lines.append((base + r, frames))
    print(f"# {os.path.basename(tool)}: {os.path.basename(image)}")
    # Runs of addresses with the same frames, as one line each.
    i = 0
    while i < len(lines):
        a, frames = lines[i]
        j = i
        while j + 1 < len(lines) and lines[j + 1][1] == frames and lines[j + 1][0] == lines[j][0] + 1:
            j += 1
        text = json.dumps([list(f) for f in frames], ensure_ascii=False, separators=(",", ":"))
        print(f"0x{a:x}..0x{lines[j][0]:x}\t{text}")
        i = j + 1


main()

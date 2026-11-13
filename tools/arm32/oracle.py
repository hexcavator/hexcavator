# SPDX-License-Identifier: Apache-2.0
"""Compares hexcavator-arm32's text with LLVM's for random words.

Usage: python oracle.py <llvm bin dir> [A32|T16|T32|NEON-A32|NEON-T32 ...]
                        [-n N] [-seed S] [-show ENCODING] [-golden FILE]

-golden writes, for the crate's hermetic test, up to 4 words of each
encoding that LLVM writes as we do (`ISET word address<TAB>text`).

The words are assembled with `.inst` into an object (llvm-mc) and
disassembled (llvm-objdump, immediates in decimal); each word's text is
the line at its address. Ours comes from the crate's `oracle` example
(cargo build --release -p hexcavator-arm32 --example oracle), with the
same addresses. Prints, per encoding, how many words differ and the first
differences, the encodings with the most differences first.
"""

import collections
import os
import random
import re
import subprocess
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
FEATURES = ("+v8.6a,+fp-armv8,+neon,+crypto,+crc,+dotprod,+fullfp16,+fp16fml,+bf16,+i8mm,"
            "+ras,+sb,+mp,+virtualization,+trustzone,+hwdiv-arm,+hwdiv")


def words(iset, n, rng):
    """Random words of `iset`. NEON-A32 and NEON-T32: of the Advanced SIMD
    and floating-point encoding spaces, which random words seldom reach."""
    out = []
    while len(out) < n:
        if iset == "A32":
            out.append(rng.getrandbits(32))
        elif iset == "T16":
            h = rng.getrandbits(16)
            # (Not IT: LLVM would apply it to the words after it.)
            if h >> 11 < 0b11101 and not (h >> 8 == 0xbf and h & 15):
                out.append(h)
        elif iset == "T32":
            first = rng.randrange(0b11101 << 11, 1 << 16)
            out.append(first << 16 | rng.getrandbits(16))
        elif iset == "NEON-A32":
            top = rng.choice([0xf2, 0xf3, 0xf4, 0xfc, 0xfd, 0xfe, 0xee, 0xec, 0xed, 0xe2])
            if top == 0xe2:
                top = 0xee
            w = top << 24 | rng.getrandbits(24)
            # (Floating point: coprocessors 10 and 11.)
            if top in (0xee, 0xec, 0xed):
                w = w & ~0xe00 | 0xa00 | rng.getrandbits(1) << 8
            out.append(w)
        else:
            top = rng.choice([0xef, 0xff, 0xf9, 0xfc, 0xfd, 0xfe, 0xee, 0xec, 0xed])
            w = top << 24 | rng.getrandbits(24)
            if top in (0xee, 0xec, 0xed):
                w = w & ~0xe00 | 0xa00 | rng.getrandbits(1) << 8
            out.append(w)
    return out


def base(iset):
    return iset.split("-")[-1] if iset.startswith("NEON") else iset


def layout(iset, ws):
    """Each word's address in the object assembled from them (T32 words
    have two NOPs after them, so that llvm-objdump, which steps two bytes
    past a word it can't decode, comes back into step)."""
    at, out = 0, []
    for _ in ws:
        out.append(at)
        at += {"A32": 4, "T16": 2}.get(base(iset), 8)
    return out


def llvm(bin_dir, iset, ws):
    """LLVM's text for each word, by the word."""
    b = base(iset)
    triple = "armv8.6a-linux-gnueabihf" if b == "A32" else "thumbv8.6a-linux-gnueabihf"
    lines = [".syntax unified", ".arm" if b == "A32" else ".thumb"]
    for w in ws:
        if b == "A32":
            lines.append(f".inst 0x{w:08x}")
        elif b == "T16":
            lines.append(f".inst.n 0x{w:04x}")
        else:
            lines += [f".inst.w 0x{w:08x}", ".inst.n 0xbf00", ".inst.n 0xbf00"]
    with tempfile.TemporaryDirectory() as d:
        src, obj = os.path.join(d, "w.s"), os.path.join(d, "w.o")
        with open(src, "w") as f:
            f.write("\n".join(lines) + "\n")
        subprocess.run([os.path.join(bin_dir, "llvm-mc"), "-triple=" + triple, "-mattr=" + FEATURES,
                        "-filetype=obj", src, "-o", obj], check=True)
        p = subprocess.run([os.path.join(bin_dir, "llvm-objdump"), "-d", "--no-print-imm-hex",
                            "--no-show-raw-insn", "--triple=" + triple, "--mattr=" + FEATURES, obj],
                           capture_output=True, text=True)
    by_addr = {}
    for line in p.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(.*)$", line)
        if m:
            by_addr[int(m.group(1), 16)] = m.group(2)
    got = {}
    for w, at in zip(ws, layout(iset, ws)):
        t = by_addr.get(at)
        if t is None or "<unknown>" in t:
            continue
        # (Without the comment, and a target's symbol.)
        t = re.sub(r"\s*@.*$", "", t)
        t = re.sub(r"\s*<[^>]*>", "", t)
        got[w] = norm(t)
    return got


def norm(s):
    return re.sub(r"\s+", " ", s.strip())


def ours(iset, ws):
    exe = os.path.join(ROOT, "target", "release", "examples", "oracle.exe" if os.name == "nt" else "oracle")
    text = "\n".join(f"{base(iset)} {w:08x} {at:x}" for w, at in zip(ws, layout(iset, ws))) + "\n"
    p = subprocess.run([exe], input=text, capture_output=True, text=True)
    out = {}
    for line in p.stdout.splitlines():
        head, name, txt = line.split("\t")
        out[int(head.split()[1], 16)] = (name, norm(txt))
    return out


def main():
    args = sys.argv[1:]
    bin_dir = args.pop(0)
    n, seed, show, golden = 20000, 1, None, None
    isets = []
    while args:
        a = args.pop(0)
        if a == "-n":
            n = int(args.pop(0))
        elif a == "-seed":
            seed = int(args.pop(0))
        elif a == "-show":
            show = args.pop(0)
        elif a == "-golden":
            golden = args.pop(0)
        else:
            isets.append(a)
    rng = random.Random(seed)
    kept = collections.defaultdict(list)
    for iset in isets or ["A32", "T16", "T32", "NEON-A32", "NEON-T32"]:
        ws = words(iset, n, rng)
        theirs = llvm(bin_dir, iset, ws)
        mine = ours(iset, ws)
        by = collections.defaultdict(lambda: [0, 0, []])
        only_llvm = collections.Counter()
        only_ours = collections.Counter()
        total = same = 0
        addresses = dict(zip(ws, layout(iset, ws)))
        for w in ws:
            name, text = mine.get(w, ("-", "-"))
            t = theirs.get(w)
            if t is None and name == "-":
                continue
            if t is None:
                only_ours[name] += 1
                continue
            if name == "-":
                only_llvm[t.split()[0]] += 1
                continue
            total += 1
            e = by[name]
            e[0] += 1
            if text == t:
                same += 1
                e[1] += 1
                if len(kept[name]) < 4:
                    kept[name].append(f"{base(iset)} {w:08x} {addresses[w]:x}\t{t}")
            elif len(e[2]) < 4:
                e[2].append((w, text, t))
        print(f"== {iset}: {same} of {total} the same ({100 * same / max(total, 1):.1f}%); "
              f"{sum(only_llvm.values())} LLVM only, {sum(only_ours.values())} ours only")
        rows = sorted(by.items(), key=lambda kv: -(kv[1][0] - kv[1][1]))
        for name, (count, ok, samples) in rows:
            if count == ok:
                continue
            if show and show != name:
                continue
            print(f"  {name}: {count - ok} of {count} differ")
            for w, a, b in samples[: (4 if show else 2)]:
                print(f"    {w:08x}  ours: {a}\n              llvm: {b}")
        if not show:
            print("  LLVM only:", only_llvm.most_common(8))
            print("  ours only:", only_ours.most_common(8))


    if golden:
        with open(golden, "w", encoding="utf-8", newline="\n") as f:
            f.write("# Generated by tools/arm32/oracle.py -golden: LLVM's text (llvm-objdump)\n")
            f.write("# for words of each encoding, at their addresses.\n")
            for name in sorted(kept):
                for line in kept[name]:
                    f.write(line + "\n")


if __name__ == "__main__":
    main()

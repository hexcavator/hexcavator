"""Compares hexc size with bloaty, report by report, on the ELF, Mach-O, and
WebAssembly fixtures in testdata.

Usage: python compare.py <bloaty> <hexc> [--show]  (see README.md)

For each fixture and data source, both write CSV (every row, -n 0); rows
are compared as sets. Prints, per (fixture, sources), "same", "differs"
(with the rows only one side has, with --show), or why one side failed.
Where we differ on purpose, the size modules' docs say why (bloaty's bugs
are not copied: see baseline-divergence in the notes).
"""

import pathlib
import subprocess
import sys

bloaty, hexc = sys.argv[1], sys.argv[2]
show = "--show" in sys.argv
root = pathlib.Path(__file__).resolve().parents[2] / "testdata"

FILES = sorted(
    [p for p in (root / "elf").iterdir() if p.suffix in ("", ".o", ".a", ".so", ".debug", ".zlib", ".zstd", ".zdebug")]
    + [p for p in (root / "macho").iterdir() if p.suffix in ("", ".o", ".a", ".dylib", ".dwarf")]
    + [root / "wasm" / "module.wasm"]
)
SOURCES = [
    "segments", "sections", "symbols", "rawsymbols", "fullsymbols", "compileunits", "inlines",
    "armembers", "inputfiles", "sections,symbols", "segments,sections",
]


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        return None, (p.stderr.strip().splitlines() or ["?"])[-1]
    rows = [line for line in p.stdout.splitlines()[1:] if line]
    return set(rows), None


counts = {"same": 0, "differs": 0, "bloaty refuses": 0, "hexc fails": 0, "both fail": 0}
for f in FILES:
    for s in SOURCES:
        b, be = run([bloaty, str(f), "-d", s, "-n", "0", "--csv"])
        r, re_ = run([hexc, "size", str(f), "-d", s, "-n", "0", "-csv"])
        name = f"{f.parent.name}/{f.name} {s}"
        if be and re_:
            counts["both fail"] += 1
            continue
        if be:
            counts["bloaty refuses"] += 1
            continue
        if re_:
            counts["hexc fails"] += 1
            print(f"{name}: hexc fails ({re_})")
            continue
        if b == r:
            counts["same"] += 1
            continue
        counts["differs"] += 1
        print(f"{name}: differs ({len(b - r)} rows only bloaty's, {len(r - b)} only ours)")
        if show:
            for row in sorted(b - r):
                print(f"    bloaty: {row}")
            for row in sorted(r - b):
                print(f"    hexc:   {row}")
print(counts)

"""Writes "mangled<TAB>demangled" lines for the v0 Rust names in a list of
symbol names, demangled by llvm-cxxfilt, sorted and without duplicates.

Usage: python pairs.py <llvm-cxxfilt> <names.txt> <out.txt>
"""

import subprocess
import sys

cxxfilt, names_path, out_path = sys.argv[1:4]
names = set()
for line in open(names_path, encoding="utf-8"):
    name = line.strip()
    # COFF objects may add a leading underscore or not; keep v0 names.
    if name.startswith("_R"):
        names.add(name)
names = sorted(names)
result = subprocess.run(
    [cxxfilt], input="\n".join(names) + "\n", capture_output=True, text=True, encoding="utf-8", check=True
)
demangled = result.stdout.splitlines()
assert len(demangled) == len(names), (len(demangled), len(names))
with open(out_path, "w", encoding="utf-8", newline="\n") as f:
    for m, d in zip(names, demangled):
        assert m != d, f"llvm-cxxfilt did not demangle {m}"
        f.write(f"{m}\t{d}\n")
print(f"wrote {len(names)} names")

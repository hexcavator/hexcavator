"""Keeps every line of a /VERBOSE linker log but all except the first 300
"Discarded" lines (they are most of the log, and alike)."""
import sys

kept = 0
out = []
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("    Discarded "):
            kept += 1
            if kept > 300:
                continue
        out.append(line.rstrip("\r\n"))
with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out) + "\n")

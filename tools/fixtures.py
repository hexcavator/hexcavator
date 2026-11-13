# SPDX-License-Identifier: Apache-2.0
"""Regenerates the test data the tools here build, all at once.

    python tools/fixtures.py              every step
    python tools/fixtures.py coff lines   just those
    python tools/fixtures.py --list

The repository is mapped to R: (subst) once, and each step's script runs
from there (see neutral.cmd), side by side: what the builds record is the
same on every machine. Logs: target/fixtures/logs. At the end, the test
data that changed is listed (`git status`). Rebuilt with the same tools,
the images, objects, and text come out the same, byte for byte; link.exe's
PDBs do not (it lays their pages out differently each time, around the
same contents), so restore those (git checkout) unless what built them
changed.

LLVM_BIN and LLVM_SRC come from the environment, or else from
hexcavator-private's .cargo/config.toml (which its setup.py writes), if
that is beside this repository. Visual Studio is found by vswhere.

Not here: tools/x86fpo (its snapshots are recorded from the running
program, by hand) and tools/llvm (a build of LLVM, an hour or more).
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DRIVE = "R:"

# name: (command, from R:; what it needs)
STEPS = {
    "coff": (["cmd", "/c", r"R:\tools\coff\build.cmd"], ["msvc"]),
    "lines": (["cmd", "/c", r"R:\tools\lines\build.cmd"], ["msvc"]),
    "xref": (["cmd", "/c", r"R:\tools\xref\build.cmd"], ["msvc"]),
    "types": (["cmd", "/c", r"R:\tools\types\build.cmd"], ["msvc"]),
    "linkerlog": (["cmd", "/c", r"R:\tools\linkerlog\build.cmd"], ["msvc"]),
    "snapshots": (["cmd", "/c", r"R:\tools\fixtures\snapshots.cmd"], ["msvc"]),
    "types-dwarf": (["cmd", "/c", r"R:\tools\types\build-dwarf.cmd"], ["LLVM_BIN"]),
    "elf": (["cmd", "/c", r"R:\tools\elf\build.cmd"], ["LLVM_BIN"]),
    "macho": (["cmd", "/c", r"R:\tools\macho\build.cmd"], ["LLVM_BIN"]),
    "linkmap": (["cmd", "/c", r"R:\tools\linkmap\build.cmd"], ["LLVM_BIN"]),
    "cfi": ([sys.executable, "-I", r"R:\tools\cfi\build.py", "fixtures"], ["LLVM_BIN"]),
    "wasm": (["cmd", "/c", r"R:\tools\wasm\build.cmd"], ["LLVM_BIN", "LLVM_SRC"]),
    "rust": (["cmd", "/c", r"R:\tools\rust\build.cmd"], ["LLVM_BIN"]),
}


def private_env():
    """hexcavator-private's [env], if it is beside this repository."""
    path = os.path.join(os.path.dirname(ROOT), "hexcavator-private", ".cargo", "config.toml")
    env = {}
    if not os.path.exists(path):
        return env
    section = None
    for line in open(path, encoding="utf-8"):
        if line.startswith("["):
            section = line.strip()
            continue
        k, eq, v = line.partition(" = ")
        if section == "[env]" and eq:
            env[k.strip()] = v.strip().strip('"').replace("/", "\\")
    return env


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("steps", nargs="*")
    p.add_argument("--list", action="store_true")
    a = p.parse_args()
    if a.list:
        for n, (cmd, needs) in STEPS.items():
            print(f"{n:12} {' '.join(cmd[2:] if cmd[0] == 'cmd' else cmd[2:])}  (needs {', '.join(needs)})")
        return 0
    names = a.steps or list(STEPS)
    unknown = [n for n in names if n not in STEPS]
    if unknown:
        sys.exit(f"no such step: {', '.join(unknown)} (see --list)")
    env = dict(os.environ)
    for k, v in private_env().items():
        env.setdefault(k, v)
    # (LLVM_SRC here is the llvm directory of the checkout, as wasm's script
    # wants; the private config names the checkout.)
    if "LLVM_SRC" in env and os.path.isdir(os.path.join(env["LLVM_SRC"], "llvm")):
        env["LLVM_SRC"] = os.path.join(env["LLVM_SRC"], "llvm")
    missing = {n: [r for r in STEPS[n][1] if r != "msvc" and r not in env] for n in names}
    missing = {n: m for n, m in missing.items() if m}
    for n, m in missing.items():
        print(f"[{n}] skipped: set {', '.join(m)}")
    names = [n for n in names if n not in missing]

    logs = os.path.join(ROOT, "target", "fixtures", "logs")
    os.makedirs(logs, exist_ok=True)
    mapped = subprocess.run(["subst"], capture_output=True, text=True).stdout
    ours = f"{DRIVE}\\: => {ROOT}".lower()
    if any(l.strip().lower() == ours for l in mapped.splitlines()):
        mapped_here = False
    elif os.path.exists(DRIVE + "\\"):
        sys.exit(f"{DRIVE} is in use: free it (subst {DRIVE} /d)")
    else:
        subprocess.run(["subst", DRIVE, ROOT], check=True)
        mapped_here = True
    try:
        def run(n):
            t = time.time()
            with open(os.path.join(logs, n + ".log"), "w", encoding="utf-8", errors="replace") as f:
                r = subprocess.run(STEPS[n][0], cwd=DRIVE + "\\", env=env, stdout=f, stderr=subprocess.STDOUT)
            return n, r.returncode, time.time() - t
        failed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(names) or 1) as pool:
            for n, code, dt in pool.map(run, names):
                print(f"[{n}] {'ok' if code == 0 else f'FAILED ({code})'} in {dt:.0f} s")
                if code:
                    failed.append(n)
    finally:
        if mapped_here:
            subprocess.run(["subst", DRIVE, "/d"])
    changed = subprocess.run(["git", "status", "--short", "--", "testdata", "crates", "apps"],
                             cwd=ROOT, capture_output=True, text=True).stdout
    print("changed:" if changed.strip() else "no test data changed")
    print(changed.rstrip())
    if failed:
        print(f"failed: {', '.join(failed)} (logs: {logs})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

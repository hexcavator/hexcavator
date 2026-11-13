# SPDX-License-Identifier: Apache-2.0
"""Builds call frame information test inputs with clang and ld.lld.

  python build.py fixtures   -> testdata/cfi: small executables (C with
                                alloca, many saved registers, cleanups;
                                hand-written CFI covering every
                                DW_CFA_* rule) for x86-64, i386, AArch64
                                (little and big endian), and ARM, with
                                `.eh_frame` and/or `.debug_frame`, and
                                llvm-dwarfdump's view of each.
                                Also Mach-O executables (arm64,
                                x86_64) with __unwind_info, and
                                llvm-objdump --unwind-info's view.
  python build.py corpus DIR -> DIR: compiler-rt's builtins (about 180 C
                                files) linked into one executable per
                                target and flavor (and ARM EHABI), for
                                the ignored oracle tests (not committed).

LLVM_BIN names the LLVM tools' directory; LLVM_SRC the llvm-project
checkout (for corpus).
"""

import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LLVM_BIN = os.environ.get("LLVM_BIN") or sys.exit("set LLVM_BIN to LLVM's bin directory")
LLVM_SRC = os.environ.get("LLVM_SRC", "")

TARGETS = {
    "x86_64": ["--target=x86_64-linux-gnu"],
    "i386": ["--target=i386-linux-gnu"],
    "aarch64": ["--target=aarch64-linux-gnu", "-mbranch-protection=standard"],
    "aarch64_be": ["--target=aarch64_be-linux-gnu"],
    "arm": ["--target=armv7a-linux-gnueabihf", "-mthumb"],
}

# eh: .eh_frame (asynchronous unwind tables); debug: .debug_frame only.
FLAVORS = {
    "eh": ["-fasynchronous-unwind-tables", "-fexceptions"],
    "debug": ["-g", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables"],
}

# (Built in the output directory, with relative paths, so that what the
# files and the dumps record is the same on every machine.)
COMMON = ["-O2", "-ffreestanding", "-fno-stack-protector", "-fno-ident", "-w", "-fdebug-compilation-dir=."]


def tool(name):
    return os.path.join(LLVM_BIN, name + ".exe" if os.name == "nt" else name)


def run(args, **kw):
    subprocess.run(args, check=True, **kw)


def link(objects, out):
    run([tool("ld.lld"), "-static", "-e", "_start", "--unresolved-symbols=ignore-all", "--no-gc-sections", *objects, "-o", out])


def source(name):
    """`name` in this directory, relative to the current one."""
    return os.path.relpath(os.path.join(HERE, name))


def dump(exe):
    with open(exe + ".frames.txt", "w", newline="\n") as f:
        run([tool("llvm-dwarfdump"), "--eh-frame", "--debug-frame", exe], stdout=f)


def fixtures():
    os.makedirs(os.path.join(HERE, "..", "..", "testdata", "cfi"), exist_ok=True)
    os.chdir(os.path.join(HERE, "..", "..", "testdata", "cfi"))
    out = "."
    for t, targs in TARGETS.items():
        for flavor, fargs in FLAVORS.items():
            if t == "arm" and flavor == "eh":
                # (ARM's own unwind tables, not .eh_frame.)
                continue
            objs = []
            for src in ["frames.c"]:
                o = f"{t}-{flavor}-{src}.o"
                run([tool("clang"), *targs, *COMMON, *fargs, "-c", source(src), "-o", o])
                objs.append(o)
            asm = f"rules-{t.split('_')[0]}.s"
            if flavor == "eh" and os.path.exists(os.path.join(HERE, asm)):
                o = f"{t}-rules.o"
                run([tool("clang"), *targs, "-fdebug-compilation-dir=.", "-c", source(asm), "-o", o])
                objs.append(o)
            exe = f"{t}-{flavor}"
            link(objs, exe)
            for o in objs:
                os.remove(o)
            dump(exe)
    macho_fixtures(out)
    ehabi_fixtures(out)


MACHO = {"arm64": "arm64-apple-macos13", "x86_64": "x86_64-apple-macos13"}


def link_macho(arch, objects, out):
    run([tool("lld"), "-flavor", "darwin", "-arch", arch, "-platform_version", "macos", "13.0", "13.0",
         "-e", "__start", "-undefined", "dynamic_lookup", *objects, "-o", out])


def macho_fixtures(out):
    for arch, triple in MACHO.items():
        o = f"macho-{arch}.o"
        run([tool("clang"), f"--target={triple}", "-O2", "-fno-stack-protector", "-fno-ident", "-w",
             "-fasynchronous-unwind-tables", "-fexceptions", "-fdebug-compilation-dir=.", "-c", source("frames.c"), "-o", o])
        exe = f"macho-{arch}"
        link_macho(arch, [o], exe)
        os.remove(o)
        with open(exe + ".unwind.txt", "w", newline="\n") as f:
            run([tool("llvm-objdump"), "--unwind-info", exe], stdout=f)


def ehabi_fixtures(out):
    """ARM EHABI (.ARM.exidx/.ARM.extab), ARM and Thumb, with
    llvm-readobj --unwind's view."""
    for mode in ["arm", "thumb"]:
        o = f"ehabi-{mode}.o"
        run([tool("clang"), "--target=armv7a-linux-gnueabihf", f"-m{mode}", *COMMON, "-funwind-tables", "-fexceptions",
             "-c", source("frames.c"), "-o", o])
        exe = f"ehabi-{mode}"
        link([o], exe)
        os.remove(o)
        with open(exe + ".unwind.txt", "w", newline="\n") as f:
            run([tool("llvm-readobj"), "--unwind", exe], stdout=f)


def corpus(out):
    os.makedirs(out, exist_ok=True)
    if not LLVM_SRC:
        sys.exit("set LLVM_SRC to an llvm-project checkout")
    builtins = os.path.join(LLVM_SRC, "compiler-rt", "lib", "builtins")
    sources = sorted(glob.glob(os.path.join(builtins, "*.c")))
    flavors = dict(FLAVORS, ehabi=["-funwind-tables"])
    for t, targs in TARGETS.items():
        for flavor, fargs in flavors.items():
            # (ARM: .debug_frame, or its own unwind tables; not .eh_frame.)
            if (t == "arm" and flavor == "eh") or (flavor == "ehabi" and t != "arm"):
                continue
            objs = []
            for src in sources:
                o = os.path.join(out, f"{t}-{flavor}-" + os.path.basename(src) + ".o")
                r = subprocess.run([tool("clang"), *targs, *COMMON, *fargs, "-I", builtins, "-c", src, "-o", o],
                                   stderr=subprocess.DEVNULL)
                if r.returncode == 0:
                    objs.append(o)
            start = os.path.join(out, "start.c")
            with open(start, "w") as f:
                f.write("void _start(void) {}\n")
            o = os.path.join(out, f"{t}-{flavor}-start.o")
            run([tool("clang"), *targs, *COMMON, "-c", start, "-o", o])
            objs.append(o)
            exe = os.path.join(out, f"builtins-{t}-{flavor}")
            link(objs, exe)
            for o in objs:
                os.remove(o)
            print(f"{exe}: {len(objs) - 1} objects")


if __name__ == "__main__":
    if sys.argv[1:2] == ["fixtures"]:
        fixtures()
    elif sys.argv[1:2] == ["corpus"] and len(sys.argv) == 3:
        corpus(sys.argv[2])
    else:
        sys.exit(__doc__)

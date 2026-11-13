"""Writes testdata/wasm/ops.wasm: a module with one function per WebAssembly
instruction LLVM knows (from `llvm-tblgen --dump-json` of LLVM's
WebAssembly target), each with sample immediates, for checking hexc's
disassembler against `llvm-objdump -d` (see testdata/wasm/README.md).

Usage: python all_ops.py <llvm webassembly.json> <out.wasm>

The module is for disassembly only: it doesn't validate (the operands
aren't on the stack, and indexes point at nothing).
"""

import json
import re
import struct
import sys


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not b & 0x40) or (n == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def opcodes(path):
    """{opcode: (name, operand types)} for LLVM's stack-form instructions."""
    d = json.load(open(path, encoding="utf-8"))
    out = {}
    for n in d["!instanceof"]["Instruction"]:
        r = d[n]
        if not (r.get("StackBased") or n.endswith("_S")):
            continue
        bits = r.get("Inst")
        if not isinstance(bits, list):
            continue
        v = sum(b << i for i, b in enumerate(bits) if b in (0, 1))
        name = (r.get("AsmString") or "").split("\t")[0].split(" ")[0].strip()
        if not name or v == 0xFFFFFFFF:
            continue
        types = re.findall(r"(\w+):\$", (r.get("InOperandList") or {}).get("printable", ""))
        # (The 64-bit memory forms are the same encodings.)
        if v not in out or "offset32_op" in types:
            out[v] = (name, types)
    return out


def encode(v):
    """An opcode's bytes: one, or a prefix and a LEB128 sub-opcode."""
    if v > 0xFFFF:
        return bytes([v >> 16]) + uleb(v & 0xFFFF)
    if v > 0xFF:
        return bytes([v >> 8]) + uleb(v & 0xFF)
    return bytes([v])


def immediates(name, types):
    """Sample immediates for an instruction's operand types."""
    out = bytearray()
    if name == "v128.const":
        return bytes(range(16))
    if name == "i8x16.shuffle":
        return bytes([0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31])
    for t in types:
        if t == "Signature":
            out += b"\x40"
        elif t == "bb_op":
            out += uleb(1)
        elif t == "brlist":
            out += uleb(2) + uleb(0) + uleb(1) + uleb(2)
        elif t in ("function32_op", "TypeIndex", "tag_op", "global_op32"):
            out += uleb(1)
        elif t in ("table32_op",):
            out += uleb(0)
        elif t == "local_op":
            out += uleb(3)
        elif t == "i32imm":
            out += b"\x00"
        elif t == "P2Align":
            out += uleb(2)
        elif t == "offset32_op":
            out += uleb(16)
        elif t == "vec_i8imm_op":
            out += b"\x01"
        elif t == "i32imm_op":
            out += sleb(-5) if name == "i32.const" else uleb(0)
        elif t == "i64imm_op":
            out += sleb(300)
        elif t == "f32imm_op":
            out += struct.pack("<f", 1.5)
        elif t == "f64imm_op":
            out += struct.pack("<d", -2.25)
        elif t == "typelist":
            out += uleb(1) + b"\x7f"
        elif t == "catch_list":
            out += uleb(1) + b"\x00" + uleb(0) + uleb(0)
        elif t == "MemOrder":
            # (atomic.fence's reserved byte; the memory accesses' orders
            # are in their alignment's flags.)
            if name == "atomic.fence":
                out += b"\x00"
        elif t == "I64":
            pass
        else:
            raise SystemExit(f"{name}: no sample for operand type {t}")
    return bytes(out)


def section(id_, body):
    return bytes([id_]) + uleb(len(body)) + body


def main():
    ops = opcodes(sys.argv[1])
    bodies = []
    for v in sorted(ops):
        name, types = ops[v]
        code = b"\x00" + encode(v) + immediates(name, types) + b"\x0b"
        bodies.append(uleb(len(code)) + code)
    n = len(bodies)
    types = section(1, uleb(1) + b"\x60\x00\x00")
    funcs = section(3, uleb(n) + uleb(0) * n)
    code = section(10, uleb(n) + b"".join(bodies))
    with open(sys.argv[2], "wb") as f:
        f.write(b"\0asm\x01\x00\x00\x00" + types + funcs + code)
    print(f"{n} functions", file=sys.stderr)


main()

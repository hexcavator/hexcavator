"""Writes Hexcavator's WebAssembly test module, testdata/wasm/module.wasm.

No WebAssembly compiler is at hand, so the module is assembled here: every
standard section (type, import, function, table, memory, global, export,
start, element, data count, code, data) and custom sections (name, with
module, function, local, and data segment names; producers; and a
sourceMappingURL), with functions and data that mean something:

    (import "env" "log" (func $log (param i32)))
    (import "env" "mem0" (memory 0))       -- not a function: index space
    (func $add (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
    (func $square (param i32) (result i32) local.get 0 local.get 0 i32.mul)
    (func $main (call $log (call $square (call $add (i32.const 2) (i32.const 3)))))
    (func (unnamed) ...)
    data "hello" at 16 (named .rodata), passive data (named .data), active
    data with no name.

Usage: python make.py <output directory>
"""

import sys
from pathlib import Path


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


def name(s):
    b = s.encode()
    return uleb(len(b)) + b


def vec(items):
    return uleb(len(items)) + b"".join(items)


def section(id, body):
    return bytes([id]) + uleb(len(body)) + body


def custom(n, body):
    return section(0, name(n) + body)


I32 = 0x7F
types = vec([
    bytes([0x60]) + vec([bytes([I32])]) + vec([]),                    # 0: (i32) -> ()
    bytes([0x60]) + vec([bytes([I32]), bytes([I32])]) + vec([bytes([I32])]),  # 1: (i32 i32) -> i32
    bytes([0x60]) + vec([bytes([I32])]) + vec([bytes([I32])]),         # 2: (i32) -> i32
    bytes([0x60]) + vec([]) + vec([]),                                 # 3: () -> ()
])
imports = vec([
    name("env") + name("log") + bytes([0x00]) + uleb(0),
    name("env") + name("mem0") + bytes([0x02, 0x00]) + uleb(0),
])
functions = vec([uleb(1), uleb(2), uleb(3), uleb(3)])
table = vec([bytes([0x70, 0x00]) + uleb(2)])
globals = vec([bytes([I32, 0x01, 0x41]) + sleb(1024) + bytes([0x0B])])
exports = vec([
    name("add") + bytes([0x00]) + uleb(1),
    name("main") + bytes([0x00]) + uleb(3),
    name("sp") + bytes([0x03]) + uleb(0),
])
start = uleb(3)
elements = vec([uleb(0) + bytes([0x41]) + sleb(0) + bytes([0x0B]) + vec([uleb(1), uleb(2)])])


def body(locals, code):
    b = vec(locals) + code + bytes([0x0B])
    return uleb(len(b)) + b


code = vec([
    body([], bytes([0x20, 0, 0x20, 1, 0x6A])),                                   # add
    body([], bytes([0x20, 0, 0x20, 0, 0x6C])),                                   # square
    body([], bytes([0x41]) + sleb(2) + bytes([0x41]) + sleb(3)
         + bytes([0x10]) + uleb(1) + bytes([0x10]) + uleb(2) + bytes([0x10]) + uleb(0)),  # main
    body([uleb(2) + bytes([I32])], bytes([0x41]) + sleb(7) + bytes([0x21, 0, 0x01])),     # unnamed
])
data = vec([
    uleb(0) + bytes([0x41]) + sleb(16) + bytes([0x0B]) + vec([bytes([c]) for c in b"hello"]),
    uleb(1) + vec([bytes([c]) for c in b"passive data"]),
    uleb(0) + bytes([0x41]) + sleb(64) + bytes([0x0B]) + vec([bytes([c]) for c in b"\x01\x02\x03\x04"]),
])


def subsection(id, body):
    return bytes([id]) + uleb(len(body)) + body


names = (
    subsection(0, name("module"))
    + subsection(1, vec([uleb(0) + name("log"), uleb(1) + name("add"), uleb(2) + name("square"), uleb(3) + name("main")]))
    + subsection(2, vec([uleb(1) + vec([uleb(0) + name("a"), uleb(1) + name("b")])]))
    + subsection(9, vec([uleb(0) + name(".rodata"), uleb(1) + name(".data")]))
)
producers = vec([name("processed-by") + vec([name("rbat tools/wasm/make.py") + name("1")])])

module = (
    b"\0asm" + (1).to_bytes(4, "little")
    + section(1, types)
    + section(2, imports)
    + section(3, functions)
    + section(4, table)
    + section(6, globals)
    + section(7, exports)
    + section(8, start)
    + section(9, elements)
    + section(12, uleb(3))
    + section(10, code)
    + section(11, data)
    + custom("name", names)
    + custom("producers", producers)
    + custom("sourceMappingURL", name("module.wasm.map"))
)



def vlq(n):
    """A Base64 VLQ, as source maps encode numbers."""
    digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    v = (-n << 1) | 1 if n < 0 else n << 1
    out = ""
    while True:
        d = v & 31
        v >>= 5
        out += digits[d | (32 if v else 0)]
        if not v:
            return out


def bodies():
    """Each function body's (start, code start, end) file offsets."""
    at = module.index(section(10, code)) + 1 + len(uleb(len(code)))
    at += len(uleb(4))
    out = []
    for i in range(4):
        size, n = 0, 0
        while True:
            b = module[at + n]
            size |= (b & 0x7F) << (7 * n)
            n += 1
            if b < 0x80:
                break
        start, end = at, at + n + size
        # Skip the locals: a count, then (count, type) pairs.
        p = at + n
        count = module[p]
        p += 1 + 2 * count
        out.append((start, p, end))
        at = end
    return out


# A source map (version 3) for the code: generated "columns" are file
# offsets. Segments are (offset, source, line, column), zero-based, or just
# (offset,) for bytes with no source. It has what bloaty's reader gets
# wrong: a sourceRoot, an escaped file name, and a last segment (which
# bloaty drops).
(add, square, main, unnamed) = bodies()
segments = [
    (add[1], 0, 1, 2),
    (add[1] + 4, 0, 2, 9),          # i32.add
    (square[1], 0, 5, 2),
    (main[1], 1, 2, 2),
    (main[1] + 4, 1, 3, 2),         # the calls
    (unnamed[0],),                  # its size and locals: no source
    (unnamed[1], 0, 9, 0),          # the last segment
]
mappings, prev = [], [0, 0, 0, 0]
for seg in segments:
    deltas = [v - p for v, p in zip(seg, prev)]
    mappings.append("".join(vlq(d) for d in deltas))
    prev[:len(seg)] = seg
source_map = (
    '{"version":3,"file":"module.wasm","sourceRoot":"src/",'
    '"sources":["math.c","m\\u0061in.c"],"names":[],'
    f'"mappings":"{",".join(mappings)}"}}\n'
)

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
(out / "module.wasm").write_bytes(module)
(out / "module.wasm.map").write_text(source_map, newline="\n")
print(f"wrote {len(module)} bytes")

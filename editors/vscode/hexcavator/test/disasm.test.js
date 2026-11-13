// Tests for disasm.js: `node test/disasm.test.js` (any Node, or VS Code's
// own with ELECTRON_RUN_AS_NODE=1).
"use strict";

const assert = require("assert");
const path = require("path");
const d = require(path.join(__dirname, "..", "media", "disasm.js"));

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test("a URI round-trips its file and function", () => {
  const file = "C:\\builds\\app & co\\app.wasm";
  const name = "std::vector<int>::push_back(int const&)";
  const u = d.disasmUri(file, name);
  assert.strictEqual(u.scheme, "hexc-disasm");
  assert.deepStrictEqual(d.parseDisasmQuery(u.query), { file, name, style: "raw" });
  const b = d.disasmUri(file, name, "blocks");
  assert.deepStrictEqual(d.parseDisasmQuery(b.query), { file, name, style: "blocks" });
  assert.ok(b.path.endsWith(".blocks.disasm"));
});

test("the path is a short, separator-free title", () => {
  assert.strictEqual(d.disasmUri("a.o", "a/b:c d").path, "/a_b_c_d.disasm");
  assert.strictEqual(d.disasmUri("a.o", "x".repeat(100)).path, "/" + "x".repeat(60) + ".disasm");
  assert.strictEqual(d.disasmUri("a.o", "///").path, "/_.disasm");
});

test("a query without both parts names nothing", () => {
  assert.strictEqual(d.parseDisasmQuery(""), null);
  assert.strictEqual(d.parseDisasmQuery("file=a.o"), null);
  assert.strictEqual(d.parseDisasmQuery(undefined), null);
});

test("symbol levels and names", () => {
  const sources = ["sections", "compileunits", "symbols"];
  assert.strictEqual(d.isSymbolLevel(sources, 2), true);
  assert.strictEqual(d.isSymbolLevel(sources, 0), false);
  assert.strictEqual(d.isSymbolLevel(sources, 3), false);
  assert.strictEqual(d.isSymbolLevel(["fullsymbols"], 0), true);
  assert.strictEqual(d.isSymbolLevel(undefined, 0), false);
  assert.strictEqual(d.isSymbolName("main"), true);
  assert.strictEqual(d.isSymbolName("[section .text]"), false);
  assert.strictEqual(d.isSymbolName("[12 Others]"), false);
  assert.strictEqual(d.isSymbolName(""), false);
});

test("registers by family", () => {
  const f = d.registerFamily;
  for (const r of ["rax", "eax", "ax", "al", "ah", "RAX"]) {
    assert.strictEqual(f(r), "rax", r);
  }
  assert.strictEqual(f("ecx"), "rcx");
  assert.strictEqual(f("sil"), "rsi");
  assert.strictEqual(f("esp"), "rsp");
  assert.strictEqual(f("r8d"), "r8");
  assert.strictEqual(f("r15b"), "r15");
  assert.strictEqual(f("ymm3"), "xmm3");
  assert.strictEqual(f("w5"), "x5");
  assert.strictEqual(f("x5"), "x5");
  assert.strictEqual(f("q2"), "v2");
  assert.strictEqual(f("s2"), "v2");
  assert.strictEqual(f("wzr"), "zr");
  assert.strictEqual(f("lr"), "lr");
  assert.notStrictEqual(f("r8"), f("rax"));
});

test("variables named in instructions, as windbg does", () => {
  const range = (start, end, place) => Object.assign({ start, end, gaps: [] }, place);
  const vars = [
    { name: "p", size: 8, param: true, fields: [], pointee: [{ name: "a", offset: 0, size: 1 }, { name: "b", offset: 4, size: 4 }], ranges: [range("0x1000", "0x1010", { register: "rcx" }), range("0x1010", "0x1100", { register: "rbp" })] },
    { name: "buf", size: 16, param: false, fields: [{ name: "len", offset: 0, size: 4 }, { name: "data", offset: 8, size: 8 }, { name: "data.x", offset: 8, size: 4 }], pointee: [], ranges: [range("0x1000", "0x1100", { base: "rsp", offset: 0x40 })] },
    { name: "s", size: 8, param: false, fields: [{ name: "count", offset: 4, size: 4 }], pointee: [], ranges: [range("0x1020", "0x1030", { register: "edx", field: 4 })] },
    { name: "gone", size: 4, fields: [], pointee: [], ranges: [Object.assign(range("0x1000", "0x1100", { register: "r8" }), { gaps: [["0x1004", 8]] })] },
  ];
  const a = (text, at) => d.annotate(text, BigInt(at), vars);
  // A register holding a variable, by any of its family's names.
  assert.deepStrictEqual(a("mov         eax,ecx", 0x1004), ["ecx = p"]);
  assert.deepStrictEqual(a("mov         rax,rcx", 0x1010), [], "p has moved to rbp");
  // Through a pointer: p->b.
  assert.deepStrictEqual(a("mov         eax,dword ptr [rbp+4]", 0x1020), ["[rbp+4] = p->b", "rbp = p"]);
  // In memory: buf's fields (the innermost), and an offset with none.
  assert.deepStrictEqual(a("mov         eax,dword ptr [rsp+48h]", 0x1050), ["[rsp+48h] = buf.data.x"]);
  assert.deepStrictEqual(a("mov         eax,dword ptr [rsp+40h]", 0x1050), ["[rsp+40h] = buf.len"]);
  assert.deepStrictEqual(a("mov         eax,dword ptr [rsp+44h]", 0x1050), ["[rsp+44h] = buf+4h"]);
  assert.deepStrictEqual(a("mov         eax,dword ptr [rsp+60h]", 0x1050), [], "past buf");
  // A field in a register.
  assert.deepStrictEqual(a("add         eax,edx", 0x1024), ["edx = s.count"]);
  // ARM64's [base,#disp]; and gaps.
  const arm = [{ name: "q", size: 16, fields: [{ name: "n", offset: 8, size: 4 }], pointee: [], ranges: [range("0x2000", "0x2100", { base: "sp", offset: 0x10 })] }];
  assert.deepStrictEqual(d.annotate("ldr         w0,[sp,#0x18]", 0x2004n, arm), ["[sp,#0x18] = q.n"]);
  assert.deepStrictEqual(a("mov         eax,r8d", 0x1006), [], "in a gap");
  assert.deepStrictEqual(a("mov         eax,r8d", 0x100c), ["r8d = gone"]);
  assert.strictEqual(d.displacement("-", "10h"), -16);
  assert.strictEqual(d.displacement("+", "#-0x10"), -16);
  assert.strictEqual(d.displacement("+", "zz"), null);
});

test("which binaries can be disassembled", () => {
  for (const f of ["a.o", "lib.so", "C:\\x\\mod.wasm", "/usr/bin/tool", "App.app/App", "x.dylib", "v1.2/prog",
                   "app.exe", "C:\\x.y\\Lib.DLL", "drv.sys"]) {
    assert.strictEqual(d.canDisassembleFile(f), true, f);
  }
  for (const f of ["a.obj", "b.LIB", "C:\\s\\app.pdb"]) {
    assert.strictEqual(d.canDisassembleFile(f), false, f);
  }
});

test("a diff's listings: without addresses, each side named by its binary", () => {
  const text = "transform(int):\n        140001040      mov         eax,ecx\n        14000108a  0:  lea         ecx,[r10+r9]\n";
  assert.strictEqual(d.withoutAddresses(text), "transform(int):\n              mov         eax,ecx\n          0:  lea         ecx,[r10+r9]\n");
  const a = d.disasmUri("C:\\b\\diff-v1.exe", "transform(int)", "diff");
  const b = d.disasmUri("C:\\b\\diff-v2.exe", "transform(int)", "diff");
  assert.notStrictEqual(a.path, b.path, "two documents");
  assert.ok(a.path.includes("diff-v1.exe"));
  assert.deepStrictEqual(d.parseDisasmQuery(a.query), { file: "C:\\b\\diff-v1.exe", name: "transform(int)", style: "diff" });
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    fn();
    console.log("ok  ", name);
  } catch (e) {
    failed++;
    console.log("FAIL", name, "\n", e.message);
  }
}
console.log(failed ? `${failed} failed` : "all passed");
process.exitCode = failed ? 1 : 0;

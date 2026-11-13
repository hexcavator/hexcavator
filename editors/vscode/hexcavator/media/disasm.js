// Disassembly documents: what a `hexc-disasm:` URI names (a binary and a
// function in it), and which report levels list functions. Plain
// functions with no `vscode` dependency, so they are tested under Node.
"use strict";

const SCHEME = "hexc-disasm";

/** Data sources whose rows are symbols (functions among them). */
const SYMBOL_SOURCES = ["symbols", "fullsymbols", "rawsymbols"];

/**
 * The URI parts for function `name` of the binary at `file`: a readable
 * path (the function's name, for the tab) and a query holding both.
 */
function disasmUri(file, name, style) {
  // (Tab titles come from the path; keep it short and free of separators.)
  const title = name.replace(/[\\/:*?"<>|\s]+/g, "_").slice(0, 60) || "function";
  const params = { file, name };
  if (style === "blocks" || style === "diff") {
    params.style = style;
  }
  const query = new URLSearchParams(params).toString();
  // (A diff's two sides: told apart by their binaries' names.)
  const binary = String(file).replace(/^.*[\\/]/, "").replace(/[\\/:*?"<>|\s]+/g, "_");
  const suffix = style === "blocks" ? ".blocks" : style === "diff" ? `.${binary}` : "";
  return { scheme: SCHEME, path: `/${title}${suffix}.disasm`, query };
}

/**
 * A listing for comparing builds: without its addresses (which move
 * between builds; branches are labeled, calls and data named), so that
 * only what changed differs.
 */
function withoutAddresses(text) {
  return String(text || "").replace(/^(\s*)[0-9a-fA-F]{4,16}(?= )/gm, "$1");
}

/** The binary and function a `hexc-disasm:` URI's query names (and its style), or null. */
function parseDisasmQuery(query) {
  const q = new URLSearchParams(query || "");
  const file = q.get("file");
  const name = q.get("name");
  const style = q.get("style");
  return file && name ? { file, name, style: style === "blocks" || style === "diff" ? style : "raw" } : null;
}

/**
 * Whether the rows at `depth` of a report (0: the top level's children)
 * are symbols, and so may be disassembled.
 */
function isSymbolLevel(sources, depth) {
  return Array.isArray(sources) && SYMBOL_SOURCES.includes(sources[depth]);
}

/** Whether a row's name is a real symbol, not a bloaty fallback label. */
function isSymbolName(name) {
  return typeof name === "string" && name.length > 0 && !/^\[.*\]$/.test(name);
}

/**
 * Whether hexc can disassemble functions of the binary at `file`: PE
 * images (with their PDBs), ELF, Mach-O, and WebAssembly (not yet COFF
 * objects or libraries).
 */
function canDisassembleFile(file) {
  const m = /\.([A-Za-z0-9]+)$/.exec(String(file || "").replace(/^.*[\\/]/, ""));
  return !m || !["obj", "lib", "pdb"].includes(m[1].toLowerCase());
}

if (typeof module !== "undefined") {
  module.exports = { SCHEME, SYMBOL_SOURCES, disasmUri, parseDisasmQuery, withoutAddresses, isSymbolLevel, isSymbolName, canDisassembleFile };
}

/**
 * A register's family: the register it is part of, so that eax, ax, and
 * al are rax; w0 is x0; ymm1 and zmm1 are xmm1; s2, d2, and q2 are v2.
 */
function registerFamily(name) {
  const r = String(name).toLowerCase();
  let m;
  if ((m = /^[re]?([abcd])[xlh]$/.exec(r)) || (m = /^([abcd])x$/.exec(r))) {
    return "r" + m[1] + "x";
  }
  if ((m = /^[re]?(si|di|sp|bp|ip)l?$/.exec(r))) {
    return "r" + m[1];
  }
  if ((m = /^r(\d+)[dwb]?$/.exec(r))) {
    return "r" + m[1];
  }
  if ((m = /^[xyz]mm(\d+)$/.exec(r))) {
    return "xmm" + m[1];
  }
  if ((m = /^[xw](\d+)$/.exec(r))) {
    return "x" + m[1];
  }
  if ((m = /^[qdshbv](\d+)$/.exec(r))) {
    return "v" + m[1];
  }
  if (r === "wsp") {
    return "sp";
  }
  if (r === "wzr" || r === "xzr") {
    return "zr";
  }
  return r;
}

/** A displacement as written: 40h, 0x40, #-0x10, 16. */
function displacement(sign, text) {
  let t = String(text).replace(/^#/, "");
  let neg = sign === "-";
  if (t.startsWith("-")) {
    neg = !neg;
    t = t.slice(1);
  }
  const n = /h$/i.test(t) ? parseInt(t.slice(0, -1), 16) : /^0x/i.test(t) ? parseInt(t, 16) : parseInt(t, 10);
  return Number.isNaN(n) ? null : neg ? -n : n;
}

/** Whether a variable's range covers `address` (a BigInt), but for its gaps. */
function covers(range, address) {
  if (address < BigInt(range.start) || address >= BigInt(range.end)) {
    return false;
  }
  return !(range.gaps || []).some(([at, n]) => address >= BigInt(at) && address < BigInt(at) + BigInt(n));
}

/** The field at `offset` of `fields` ({ name, offset, size }): the innermost. */
function fieldAt(fields, offset) {
  let best = null;
  for (const f of fields || []) {
    if (offset >= f.offset && offset < f.offset + Math.max(f.size, 1) && (!best || f.size <= best.size)) {
      best = f;
    }
  }
  return best;
}

/**
 * What an instruction's registers and memory operands hold, at `address`
 * (a BigInt), by `variables` (hexc size -disassemble -json's): "rcx = p",
 * "ecx = s.count" (a field in a register), "[rsp+40h] = buf.len" (a
 * variable in memory), "[rbp+4] = p->b" (through a pointer variable).
 */
function annotate(text, address, variables) {
  const notes = [];
  const add = (n) => !notes.includes(n) && notes.push(n);
  const live = (v) => (v.ranges || []).filter((r) => covers(r, address));
  const ops = String(text).replace(/^\S+\s*/, "");
  // Memory operands: [base], [base+disp], [base,#disp].
  const mem = /\[\s*([a-z][a-z0-9]*)\s*(?:([+-])\s*([0-9][0-9a-f]*h|0x[0-9a-f]+|\d+)\s*|,\s*(#-?(?:0x[0-9a-f]+|\d+))\s*)?\]/gi;
  let m;
  while ((m = mem.exec(ops))) {
    const base = registerFamily(m[1]);
    const disp = m[3] !== undefined ? displacement(m[2], m[3]) : m[4] !== undefined ? displacement("+", m[4]) : 0;
    if (disp === null) {
      continue;
    }
    const operand = m[0].replace(/\s+/g, "");
    for (const v of variables) {
      for (const r of live(v)) {
        if (r.base !== undefined && registerFamily(r.base) === base && disp >= r.offset && disp < r.offset + Math.max(v.size || 0, 1)) {
          const k = disp - r.offset;
          const f = fieldAt(v.fields, k);
          add(`${operand} = ${v.name}${f ? "." + f.name : k ? "+" + k.toString(16) + "h" : ""}`);
        } else if (r.register !== undefined && r.field === undefined && registerFamily(r.register) === base && (v.pointee || []).length) {
          const f = fieldAt(v.pointee, disp);
          add(`${operand} = ${f ? `${v.name}->${f.name}` : `*${v.name}${disp ? "+" + disp.toString(16) + "h" : ""}`}`);
        }
      }
    }
  }
  // Registers (outside memory operands' brackets, and those inside too).
  const seen = new Set();
  for (const t of ops.split(/[^A-Za-z0-9]+/)) {
    if (!t || seen.has(t.toLowerCase())) {
      continue;
    }
    seen.add(t.toLowerCase());
    const fam = registerFamily(t);
    for (const v of variables) {
      for (const r of live(v)) {
        if (r.register === undefined || registerFamily(r.register) !== fam) {
          continue;
        }
        if (r.field !== undefined) {
          const f = fieldAt(v.fields, r.field);
          add(`${t} = ${v.name}${f ? "." + f.name : "+" + r.field}`);
        } else {
          add(`${t} = ${v.name}`);
        }
      }
    }
  }
  return notes;
}

if (typeof module !== "undefined") {
  module.exports.registerFamily = registerFamily;
  module.exports.annotate = annotate;
  module.exports.displacement = displacement;
}

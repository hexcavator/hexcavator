# SPDX-License-Identifier: Apache-2.0 AND Apache-2.0 WITH LLVM-exception
# (Its decoding rules follow LLVM's AArch64 target; see crates/isa/arm64/LICENSE-LLVM.)

"""Generates crates/isa/arm64/tables/a64.txt from openly licensed sources only:

- Arm's Machine Readable Specification (AARCHMRS, BSD-3-Clause):
  Instructions.json gives every A64 encoding (its fixed bits and fields),
  its feature conditions and field constraints, its assembler syntax (as
  a grammar of rules), and its aliases with when each is preferred.
- LLVM's AArch64 target (Apache-2.0 WITH LLVM-exception), dumped by
  `llvm-tblgen --dump-json`: the meaning of operands that the syntax alone
  doesn't give (scaling, signedness, register classes).

Nothing comes from Arm's proprietary A64 ISA XML. Each `sym` line's
attributes say where they came from: `src=mrs` (the grammar) or
`src=llvm:<operand class>`.

Usage: python extract.py <mrs.tar.gz or Instructions.json> <llvm aarch64.json> > a64.txt
"""

import contextlib
import io
import json
import os
import re
import sys

def load_mrs(path):
    """AARCHMRS's Instructions.json: the file, or read from Arm's archive
    (mrs.tar.gz) without extracting it."""
    if path.endswith((".tar.gz", ".tgz")):
        import tarfile
        with tarfile.open(path, "r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith("Instructions.json"))
            return json.load(tar.extractfile(member))
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# The LLVM source tree (for the few tables its C++ holds).
LLVM_SRC = os.environ.get("LLVM_SRC", "")

# --------------------------------------------------------------------------
# AARCHMRS: encodings.

# A value-named rule: `extend_010_UXTW`, `T_00_1_16B` (its value's bits, in
# the order the operand's encoded-in fields give them).
TABLE_RULE = re.compile(r"^(?P<prefix>[^_]*(?:_[^_01x][^_]*)*?)(?P<bits>(?:_[01x]+)+)_(?P<text>[^_].*)$")


def bits_of(value):
    """A Values.Value's bit pattern ('0101x'), or None."""
    if not isinstance(value, dict):
        return None
    v = value.get("value")
    if isinstance(v, str) and v.startswith("'") and v.endswith("'"):
        return v[1:-1].replace(" ", "")
    return None


def merge(pattern, fields, encodeset):
    """Applies an encodeset to a 32-character pattern (bit 31 first) and a
    field map (name -> (hi, lo)); later (inner) encodesets win."""
    pattern = list(pattern)
    for v in (encodeset or {}).get("values", []):
        r = v["range"]
        hi, lo = r["start"] + r["width"] - 1, r["start"]
        b = bits_of(v.get("value"))
        if b is not None and len(b) == r["width"]:
            for i, c in enumerate(b):
                if c in "01":
                    pattern[31 - (hi - i)] = c
        if v["_type"].endswith("Field") and v.get("name"):
            fields[v["name"]] = (hi, lo)
    return "".join(pattern), fields


# --------------------------------------------------------------------------
# AST: conditions as ASL-like text, for build.rs's condition compiler.

def ast(node):
    """Renders an AST node as the ASL subset build.rs compiles; None if it
    has something that subset can't say."""
    t = node.get("_type", "")
    if t == "AST.Bool":
        return "TRUE" if node["value"] else "FALSE"
    if t == "AST.Identifier":
        return node["value"]
    if t == "Values.Value":
        b = bits_of(node)
        if b is not None:
            return f"'{b}'"
        return str(node.get("value"))
    if t == "AST.Integer":
        return str(node["value"])
    if t == "AST.BinaryOp":
        l, r = ast(node["left"]), ast(node["right"])
        if l is None or r is None:
            return None
        op = node["op"]
        if op == "IN":
            return f"({l} IN {r})"
        return f"({l} {op} {r})"
    if t == "AST.UnaryOp":
        e = ast(node["expr"])
        return None if e is None else f"{node['op']}({e})"
    if t == "AST.Function":
        args = [ast(a) for a in node.get("arguments", [])]
        if any(a is None for a in args):
            return None
        return f"{node['name']}({', '.join(args)})"
    if t == "AST.Set":
        vals = [ast(v) for v in node.get("values", [])]
        return None if any(v is None for v in vals) else "{" + ", ".join(vals) + "}"
    if t == "AST.Slice" or t == "AST.SquareOp":
        var = ast(node.get("var") or node.get("left"))
        args = node.get("arguments") or []
        if var is None or not args:
            return None
        a = args[0]
        if a.get("_type") == "AST.Slice":
            return f"{var}[{ast(a['left'])}:{ast(a['right'])}]"
        return f"{var}[{ast(a)}]"
    if t == "AST.Concat":
        parts = [ast(v) for v in node.get("values", [])]
        return None if any(p is None for p in parts) else "(" + " :: ".join(parts) + ")"
    return None


def conjuncts(node):
    """The terms of a chain of &&."""
    if node.get("_type") == "AST.BinaryOp" and node.get("op") == "&&":
        return conjuncts(node["left"]) + conjuncts(node["right"])
    return [node]


def is_feature(node):
    """Whether a condition term is about features only."""
    s = json.dumps(node)
    return "FEAT_" in s and not any(
        k in s for k in ('"AST.Identifier", "value": "R', '"op": "=="', '"op": "!="')
    ) or (node.get("_type") == "AST.Function" and node.get("name") == "IsFeatureImplemented")


def features(node):
    return sorted(set(re.findall(r"FEAT_[A-Za-z0-9_]+", json.dumps(node))))


def feature_expr(node, top=True):
    """A feature condition as an expression: `(FEAT_SVE2||FEAT_SME2)&&FEAT_LUT`
    (or None where it isn't only features, ANDs, and ORs)."""
    t = node.get("_type")
    if t == "AST.Function" and node.get("name") == "IsFeatureImplemented":
        names = features(node)
        return names[0] if len(names) == 1 else None
    if t == "AST.Identifier" and str(node.get("value", "")).startswith("FEAT_"):
        return node["value"]
    if t == "AST.BinaryOp" and node.get("op") in ("&&", "||"):
        left = feature_expr(node["left"], False)
        right = feature_expr(node["right"], False)
        if left is None or right is None:
            return None
        s = f"{left}{node['op']}{right}"
        return s if top else f"({s})"
    return None


# --------------------------------------------------------------------------
# Assembly syntax.

class Syntax:
    def __init__(self, rules):
        self.rules = rules
        # Operands whose every alternative begins with `#` (`<const>`: #90
        # or #270).
        self.hash_choices = set()

    def render(self, symbols, operands):
        """A template ("ADD %{Xd}, #%{imm}{, %{shift}}") from assembly
        symbols, collecting operand rule ids into `operands`."""
        out = ""
        for s in symbols:
            t = s.get("_type", "")
            if t.endswith("Literal"):
                out += s["value"]
            elif t.endswith("RuleReference"):
                out += self.reference(s["rule_id"], operands)
        # (A `#` before an operand whose own rule has one.)
        return out.replace("##%{", "#%{")

    def reference(self, rid, operands, depth=[0]):
        # Each rule renders the same everywhere: remember it (choices are
        # rendered several times to pick one).
        cache = self.__dict__.setdefault("_cache", {})
        if rid in cache:
            text, ops = cache[rid]
            operands.extend(ops)
            return text
        # (A rule can refer to itself, through a list; stop deep ones.)
        if depth[0] > 40:
            return ""
        depth[0] += 1
        try:
            ops = []
            text = self.reference1(rid, ops)
        finally:
            depth[0] -= 1
        cache[rid] = (text, ops)
        operands.extend(ops)
        return text

    def reference1(self, rid, operands):
        r = self.rules.get(rid)
        if r is None:
            return f"?{rid}?"
        t = r.get("_type", "")
        display = r.get("display")
        if t.endswith("Token"):
            return {"SPACE": " ", "COMMA": ", ", "DOT": ".", "BANG": "!"}.get(rid, r.get("default") or "")
        if display and display.startswith("<"):
            operands.append(rid)
            # A `#` the rule itself begins with (`<amount>`: #0), but not
            # a label's (dumpbin shows none).
            own = ((r.get("symbols") or {}).get("symbols")) or []
            if own and own[0].get("rule_id") == "hash" and display not in ("<label>", "<amount>"):
                return "#%{" + rid + "}"
            # A choice of immediates, each with its `#` (`<const>`: #90 or
            # #270).
            def hashed(symbols, depth=0):
                first = (symbols or [{}])[0].get("rule_id")
                if first == "hash":
                    return True
                sub = self.rules.get(first or "") or {}
                return depth < 4 and hashed(((sub.get("symbols") or {}).get("symbols")) or [], depth + 1)
            choices = [c for c in (r.get("choices") or []) if c]
            if choices and all(hashed(c.get("symbols")) for c in choices):
                # (Shown with a `#` if its value is computed, not a table's
                # text: see enc_part.)
                self.hash_choices.add(rid)
            return "%{" + rid + "}"
        if t.endswith("Choice") and not display:
            alts = []
            for c in r["choices"]:
                syms = (c or {}).get("symbols") or []
                sub = self.rules.get(syms[0].get("rule_id", "")) if len(syms) == 1 else None
                if not sub or not (sub.get("display") or "").startswith("<"):
                    alts = []
                    break
                alts.append(syms[0]["rule_id"])
            if len(alts) >= 2:
                operands.extend(alts)
                return "%{alt:" + "|".join(alts) + "}"
        if t.endswith("Choice") and rid not in ("hash", "OPT_SPACE") and self.table(rid):
            # Chosen by a field (`ADDHN{2}`, by Q): an operand too.
            operands.append(rid)
            return "%{" + rid + "}"
        if t.endswith("Choice"):
            alternatives = [self.render((c or {}).get("symbols") or [], []) if c else "" for c in r["choices"]]
            nonempty = [a for a in alternatives if a]
            if rid == "hash" or display == "#":
                return "#"
            if display == " " or rid == "OPT_SPACE":
                return " "
            # The alternative with the most to say (the others are its
            # omitted or shorter forms).
            best = max(
                (c for c in r["choices"] if c),
                key=lambda c: len(self.render(c.get("symbols") or [], [])),
            )
            inner_ops = []
            inner = self.render(best.get("symbols") or [], inner_ops)
            operands.extend(inner_ops)
            if len(nonempty) < len(alternatives):
                # Optional: an empty alternative.
                return "{" + inner + "}"
            return inner
        # A rule without a display: inline.
        return self.render(((r.get("symbols") or {}).get("symbols")) or [], operands)

    def table(self, rid):
        """For an operand that chooses among value-named rules
        (`extend_010_UXTW`), its rows: (bits, text)."""
        r = self.rules.get(rid)
        if not r or not r.get("_type", "").endswith("Choice"):
            return None
        rows = []
        for c in r["choices"]:
            syms = (c or {}).get("symbols") or []
            if len(syms) != 1 or not syms[0].get("rule_id"):
                continue
            sub = syms[0]["rule_id"]
            m = TABLE_RULE.match(sub)
            if not m:
                # An alternative chosen otherwise (`<extend>`'s LSL, when a
                # register is SP): not a row.
                continue
            text = self.render(((self.rules[sub].get("symbols") or {}).get("symbols")) or [], [])
            rows.append((m.group("bits").replace("_", ""), text.strip()))
        return rows or None

    def alternatives(self, rid):
        """An operand's alternatives, as text (`B`, `H`, ...), if each is
        a fixed rendering."""
        r = self.rules.get(rid)
        if not r or not r.get("_type", "").endswith("Choice"):
            return None
        out = []
        for c in r["choices"]:
            if not c:
                return None
            ops = []
            text = self.render(c.get("symbols") or [], ops)
            if ops:
                return None
            out.append(text.strip())
        return out


def encoded(meta, display):
    """The bits an operand is encoded in, as "Q:S:size<1>"."""
    parts = (meta or {}).get("encoded_in", {}).get(display)
    if not parts:
        return ""
    out = []
    for p in parts:
        s = ast(p)
        if s is None:
            return ""
        out.append(s.strip("()").replace(" :: ", ":"))
    return ":".join(out)


# --------------------------------------------------------------------------
# LLVM: what operands mean.

class Llvm:
    """LLVM's AArch64 instruction records (from llvm-tblgen --dump-json),
    indexed by their fixed bits, with each record's operand variables by
    bit and their operand types."""

    def __init__(self, path):
        d = json.load(open(path, encoding="utf-8"))
        self.d = d
        self.records = []
        self.index_of = {}
        for name in d["!instanceof"]["Instruction"]:
            r = d[name]
            if r.get("isPseudo") or r.get("isCodeGenOnly") or r.get("Size") != 4 or r.get("isAsmParserOnly"):
                continue
            bits = r.get("Inst")
            if not isinstance(bits, list) or len(bits) != 32:
                continue
            mask = value = 0
            var_at = {}
            var_index = {}
            for i, b in enumerate(bits):
                if b in (0, 1):
                    mask |= 1 << i
                    value |= b << i
                elif isinstance(b, dict) and b.get("kind") == "varbit":
                    var_at[i] = b["var"]
                    var_index[i] = b.get("index", 0)
                elif isinstance(b, dict) and b.get("kind") == "var":
                    var_at[i] = b["var"]
                    var_index[i] = 0
            self.index_of[name] = var_index
            types = {}
            for dag in ("OutOperandList", "InOperandList"):
                for a in (r.get(dag) or {}).get("args", []):
                    if isinstance(a[0], dict) and a[0].get("def") and a[1]:
                        types[a[1]] = a[0]["def"]
                    elif isinstance(a[0], dict) and a[0].get("kind") == "dag":
                        # A complex operand with named parts
                        # (`(arith_extended_reg32to64_i64 ?:$Rm, ?:$extend)`):
                        # each part's type is in the operand's MIOperandInfo.
                        op = (a[0].get("operator") or {}).get("def")
                        info = ((d.get(op) or {}).get("MIOperandInfo") or {}).get("args", [])
                        for (sub, part) in zip(a[0].get("args", []), info):
                            if sub[1] and isinstance(part[0], dict) and part[0].get("def"):
                                types[sub[1]] = part[0]["def"]
                        if a[1] and op:
                            types[a[1]] = op
            # (Some strings have variants: `dup{\t$Rd.16b, $Rn$idx|...}`.)
            mnemonic = re.match(r"[A-Za-z0-9.]*", r.get("AsmString") or "").group(0).lower()
            self.records.append((name, mask, value, var_at, types, mnemonic))

    def matches(self, mask, value, mnemonic):
        """The records that decode some word of the encoding (mask, value),
        best first: same mnemonic, then the one most like it."""
        out = []
        for rec in self.records:
            name, m, v, _, _, mn = rec
            if (v ^ value) & m & mask:
                continue
            common = bin(m & mask).count("1")
            extra = bin(m & ~mask).count("1") + bin(mask & ~m).count("1")
            out.append(((mn != mnemonic), extra, -common, name, rec))
        out.sort(key=lambda x: x[:4])
        return [x[4] for x in out]

    def is_register(self, t):
        sup = (self.d.get(t) or {}).get("!superclasses") or []
        return "RegisterClass" in sup or "RegisterOperand" in sup

    def operand(self, rec, bits, register=None):
        """The operand type that `bits` (bit positions) belong to in `rec`,
        and its variable, or None. Where several variables share the bits
        (a register and an index bit, `M:Rm`), `register` says which kind
        the operand is."""
        _, _, _, var_at, types, _ = rec
        vars_ = {var_at.get(b) for b in bits} - {None}
        if len(vars_) > 1 and register is not None:
            def kind(v):
                t = types.get(re.sub(r"\{.*", "", v))
                return t is not None and self.is_register(t)
            vars_ = {v for v in vars_ if kind(v) == register}
        if len(vars_) != 1:
            return None
        var = vars_.pop()
        base = re.sub(r"\{.*", "", var)
        t = types.get(base)
        if t is None:
            # A sub-operand of a complex operand (`imm` of an addsub
            # immediate) or a tied one: the type whose name the variable
            # starts with.
            for k, v in types.items():
                if base.startswith(k) or k.startswith(base):
                    t = v
                    break
        return (t, base) if t else None

    def attrs(self, type_name):
        """Attributes of a symbol whose operand has LLVM type `type_name`:
        what its print and decode methods do to the field's value."""
        r = self.d.get(type_name) or {}
        printm = r.get("PrintMethod") or ""
        decode = r.get("DecoderMethod") or ""
        # (A RegisterOperand's decoder may be its register class's.)
        cls = (r.get("RegClass") or {}).get("def") if isinstance(r.get("RegClass"), dict) else None
        if not decode and cls:
            decode = (self.d.get(cls) or {}).get("DecoderMethod") or ""
            type_name = f"{type_name} {cls}"
        out = []
        m = re.match(r"(?:s|u)imm(\d+)s(\d+)$", type_name)
        if type_name.startswith("simm") or decode.startswith("DecodeSImm"):
            out.append("signed")
        scale = re.search(r"printImmScale<(\d+)>|printUImm12Offset<(\d+)>|printImmRangeScale<(\d+),|printMatrixIndex<(\d+)>", printm)
        if scale:
            out.append(f"mul={next(g for g in scale.groups() if g)}")
        elif m and m.group(2) != "1":
            out.append(f"mul={m.group(2)}")
        if decode == "DecodeSVEIncDecImm":
            out.append("add=1")
        # (The narrow forms' top bit is fixed, and the decoder ORs it back
        # in: `DecodeVecShiftRImm(Inst, Imm | 0x20, 64)`.)
        shift = re.match(r"DecodeVecShiftR(\d+)Imm(Narrow)?", decode)
        if shift:
            n = int(shift.group(1))
            out.append(f"subfrom={n // 2 if shift.group(2) else n}")
        if "printLogicalImm" in printm:
            out.append("bitmask")
        if "printFPImmOperand" in printm:
            out.append("fp8")
        if "printSIMDType10Operand" in printm:
            out.append("bytemask")
        if printm == "printAlignedLabel":
            out += ["signed", "mul=4", "label"]
        if printm == "printAdrAdrpLabel":
            out += ["signed", "label"] + (["page"] if "adrp" in type_name else [])
        if decode == "DecodeZeroImm":
            out.append("implicit=0")
        # (In the 32-bit form, scale{5} is fixed at 1 and ORed back in:
        # 64 - (32 + scale{4:0}).)
        fixed = re.match(r"DecodeFixedPointScaleImm(32|64)", decode)
        if fixed:
            out.append("subfrom=32" if fixed.group(1) == "32" else "subfrom=64")
        if printm == "printAdrAdrpLabel" and "adrp" in type_name:
            out.append("mul=4096")
        # W8-W11 and W12-W15 (`MatrixIndexGPR32Op8_11`): numbered from 8 or 12.
        base = re.search(r"GPR32(?:Op)?_?(\d+)_\d+", f"{type_name} {decode}")
        if base and base.group(1) != "0":
            out.append(f"add={base.group(1)}")
        if "printArithExtend" in printm:
            out.append("lslsp")
        # Signed immediates printed with an optional LSL (SVE CPY, DUP).
        if re.match(r"printImm8OptLsl<int", printm):
            out.append("signed")
        # Predicate-as-counter registers numbered from 8 (PN8-PN15).
        if "p8to15" in type_name or "p8to15" in decode:
            out.append("add=8")
        # Register-offset memory operands: the amount S shows, log2 of the
        # access size in bytes (printMemExtend<'x', 64>).
        memext = re.match(r"printMemExtend<'\w', ?(\d+)>", printm)
        if memext:
            out.append(f"memext={memext.group(1)}")
        rot = re.match(r"printComplexRotationOp<(\d+), ?(\d+)>", printm)
        if rot:
            out += [f"mul={rot.group(1)}", f"add={rot.group(2)}"]
        # Ranges (`8:9`): the first scaled, the last this far after it.
        rng = re.match(r"printImmRangeScale<(\d+), ?(\d+)>", printm)
        if rng:
            out.append(f"range={rng.group(2)}")
        # Strided register lists: {z0, z8}, {z1, z9}, ... (and in fours).
        # (`DecodeZPR2StridedRegisterClass`, or the simple decoder of
        # `ZPR2StridedRegClassID`.)
        strided = re.search(r"ZPR(\d)Strided", decode)
        if strided:
            out.append(f"regstep={16 // int(strided.group(1))}")
        # Aligned lists of vectors or predicates: {z0, z1}, {p2, p3}.
        mul2 = re.match(r"Decode[ZP]PR(\d)Mul(\d)RegisterClass", decode)
        if mul2:
            out += [f"regmul={mul2.group(2)}", "aligned"]
        # General registers where 31 is the zero register (not SP).
        if re.search(r"(?:^| )GPR(?:32|64)(?:z|common|arg)?(?: |$)", type_name):
            out.append("zr31")
        return out


# --------------------------------------------------------------------------

ELEMENT = re.compile(r"printSVERegOp<'(\w)'>|printTypedVectorList<\d+, ?'(\w)'>|printMatrixTileVector<\w*>|printVRegOperand")


def element_letter(rec):
    """The element size letter (b, h, s, d, q) of a record's vector
    operands, from LLVM's operand types and their print methods."""
    _, _, _, _, types, _ = rec
    letters = set()
    for t in types.values():
        r = llvm.d.get(t) or {}
        m = ELEMENT.search(r.get("PrintMethod") or "")
        if m and (m.group(1) or m.group(2)):
            letters.add((m.group(1) or m.group(2)).lower())
            continue
        m = re.match(r"^(?:ZPR|PPR|PNR|Z|ZZ|ZZZ|ZZZZ)(8|16|32|64|128)(?:_p8to15)?$|^(?:ZPR|PPR|ZZ|ZZZ|ZZZZ|Z)_?([bhsdq])(?:_|$)", t)
        if m:
            letters.add({"8": "b", "16": "h", "32": "s", "64": "d", "128": "q"}.get(m.group(1), m.group(2)))
    return letters.pop() if len(letters) == 1 else None


LETTER_OF_TYPE = [
    (re.compile(r"^(?:ZPR|PPR)(8|16|32|64|128)$"), None),
    (re.compile(r"^GPR32"), "w"),
    (re.compile(r"^GPR64"), "x"),
    (re.compile(r"^FPR(8|16|32|64|128)"), None),
]
SIZE_LETTER = {"8": "b", "16": "h", "32": "s", "64": "d", "128": "q"}


def type_letter(t):
    """The letter an LLVM register operand type implies: GPR32 w, GPR64 x,
    FPR16 h, ZPR32 s, ... (or its print method's)."""
    r = llvm.d.get(t) or {}
    m = ELEMENT.search(r.get("PrintMethod") or "")
    if m and (m.group(1) or m.group(2)):
        return (m.group(1) or m.group(2)).lower()
    for pattern, letter in LETTER_OF_TYPE:
        mm = pattern.match(t)
        if mm:
            return letter or SIZE_LETTER.get(mm.group(1))
    return None


def specifier_table(alternatives, positions, qualified, mask, value, candidates, mnemonic):
    """A table for a specifier (`<T>`, `<R>`) that qualifies a register
    operand: for each value of the specifier's bits, the most specific LLVM
    record of the encoding that has it, and the letter its type for the
    qualified register implies."""
    if not alternatives or not positions or not qualified or len(positions) > 5:
        return None
    by_letter = {a.lower(): a for a in alternatives if len(a) == 1}
    if not by_letter:
        return None
    rows = []
    for v in range(1 << len(positions)):
        bits = format(v, f"0{len(positions)}b")
        m, val = mask, value
        for b, c in zip(positions, bits):
            m |= 1 << b
            val = (val & ~(1 << b)) | (int(c) << b)
        best = None
        for rec in candidates:
            _, rm, rv, _, _, mn = rec
            if mn != mnemonic or (rv ^ val) & rm & m:
                continue
            # More of its bits fixed: more specific.
            score = bin(rm).count("1")
            if best is None or score > best[0]:
                best = (score, rec)
        if not best:
            continue
        found = llvm.operand(best[1], qualified)
        letter = type_letter(found[0]) if found else None
        if letter in by_letter:
            rows.append((bits, by_letter[letter]))
    return rows or None


def per_value_table(alternatives, positions, mask, value, candidates, mnemonic, classify):
    """A table for an operand whose alternatives the grammar doesn't tie to
    values: for each value of its bits, the most specific LLVM record of
    the encoding with it, and the alternative `classify` reads from it."""
    if not alternatives or not positions or len(positions) > 5:
        return None
    rows = []
    for v in range(1 << len(positions)):
        bits = format(v, f"0{len(positions)}b")
        m, val = mask, value
        for b, c in zip(positions, bits):
            m |= 1 << b
            val = (val & ~(1 << b)) | (int(c) << b)
        best = None
        for rec in candidates:
            _, rm, rv, _, _, mn = rec
            if mn != mnemonic or (rv ^ val) & rm & m:
                continue
            score = bin(rm).count("1")
            if best is None or score > best[0]:
                best = (score, rec)
        if best:
            text = classify(best[1])
            if text in alternatives:
                rows.append((bits, text))
    return rows or None


def classify_za(rec):
    """`ZA.S`: the size of the record's ZA array operand."""
    for t in rec[4].values():
        m = re.match(r"^MatrixOp(\d+)$", t)
        if m:
            return {"8": "B", "16": "H", "32": "S", "64": "D", "128": "Q"}.get(m.group(1))
    return None


def classify_hv(rec):
    """`ZA0H`/`ZA0V`: the direction of the record's tile vector operand."""
    for t in rec[4].values():
        m = re.match(r"^TileVectorOp([HV])", t)
        if m:
            return m.group(1)
    return None


def classify_extend(rec):
    """SVE gathers' `<mod>`: how LLVM prints the vector offset's extend."""
    for t in rec[4].values():
        p = (llvm.d.get(t) or {}).get("PrintMethod") or ""
        m = re.match(r"printRegWithShiftExtend<(true|false), ?\d+, ?'(\w)'", p)
        if m:
            return ("SXT" if m.group(1) == "true" else "UXT") + m.group(2).upper()
    return None


def llvm_table(alternatives, positions, candidates, mnemonic):
    """A value table for an operand whose alternatives are element sizes
    (`B`, `H`, `S`, `D`) the grammar doesn't tie to values: each LLVM record
    of the encoding fixes the operand's bits and types its registers."""
    if not alternatives or not positions:
        return None
    by_letter = {a.lower(): a for a in alternatives if len(a) == 1}
    if not by_letter:
        return None
    rows = {}
    for rec in candidates:
        _, mask, value, _, _, mn = rec
        if mn != mnemonic:
            continue
        if not all(mask >> b & 1 for b in positions):
            continue
        letter = element_letter(rec)
        if letter not in by_letter:
            continue
        # The operand's bits, most significant (as encoded) first.
        bits = "".join(str(value >> b & 1) for b in positions)
        rows.setdefault(bits, by_letter[letter])
    return sorted(rows.items()) or None


def part_source(src, fields, mask, rec, register=None, claimed=(), named=False):
    """An operand's bits in a part: those of `src` the part leaves free, in
    the order of the LLVM variable they hold (idx{3..0}), as field slices.
    (Variables in `claimed` are other operands'; `named`: the operand's
    values have names, so its variable is the one LLVM prints by name.)"""
    positions = bit_positions(src, fields)
    free = [b for b in positions if not mask >> b & 1]
    if not free:
        return src
    var_at = rec[3]
    vars_ = {var_at.get(b) for b in free}
    if len(vars_) > 1 and named:
        printed = {v for v in vars_ if v and NAMED.get((llvm.d.get(rec[4].get(v, "")) or {}).get("PrintMethod") or "")}
        if len(printed) == 1:
            vars_ = printed
            free = [b for b in free if var_at.get(b) in printed]
    if len(vars_) > 1:
        # (`imm5:imm4` of INS's <index2>: idx is <index1>'s; bits LLVM
        # ignores hold no variable.)
        rest = {v for v in vars_ if v and re.sub(r"\{.*", "", v) not in claimed}
        if len(rest) == 1:
            vars_ = rest
            free = [b for b in free if var_at.get(b) in rest]
    if len(vars_) > 1 and register is not None:
        # A register and an index bit share the field (`M:Rm`): the bits
        # of the variable of the operand's kind.
        types = rec[4]
        keep = {v for v in vars_ if v and (types.get(re.sub(r"\{.*", "", v)) is not None) and llvm.is_register(types[re.sub(r"\{.*", "", v)]) == register}
        if len(keep) == 1:
            vars_ = keep
            free = [b for b in free if var_at.get(b) in keep]
    if len(vars_) != 1 or None in vars_:
        return src
    index = llvm.index_of[rec[0]]
    ordered = sorted(free, key=lambda b: -index.get(b, 0))
    if ordered == positions:
        return src
    return bits_source(ordered, src, fields)


def bits_source(ordered, src, fields):
    """Bit positions as slices of `src`'s fields ("imm5[4:1]", runs
    merged)."""
    # (The operand's own fields first: group fields overlap them.)
    own = [re.sub(r"[<\[].*", "", p) for p in concat_parts(src)]
    pool = sorted(fields.items(), key=lambda kv: (kv[0] not in own, kv[1][0] - kv[1][1]))
    out = []
    for b in ordered:
        name, (hi, lo) = next((n, f) for n, f in pool if f[1] <= b <= f[0])
        k = b - lo
        if out and out[-1][0] == name and out[-1][2] == k + 1:
            out[-1] = (name, out[-1][1], k)
        else:
            out.append((name, k, k))
    return ":".join(f"{n}[{h}:{l}]" if h != l else f"{n}[{h}]" for n, h, l in out)


def is_register_display(display):
    """Whether an operand's display names a register (`<Vm>`, `<Zn2>`,
    `<Xt|SP>`) rather than a value (`<index>`, `<imm>`)."""
    d = (display or "").strip("<>")
    # (`V<m>`, `D<d>`: a register's number alone.)
    if re.fullmatch(r"[dnmta]", d):
        return True
    return bool(re.match(r"^[WXVZPBHSDQR][a-z]{1,2}\d?$|^[WXVZPBHSDQ](?:d|n|m|t|a|s)\b|.*\|", d)) or d.startswith(("PN", "ZA"))


def qualified_bits(template, rid, meta, fields):
    """The bits of the register a specifier qualifies: the one before it
    (`%{Zd}.%{T}`) or after it (`%{R}%{m}`)."""
    m = re.search(r"%\{(\w+)\}\.%\{" + re.escape(rid) + r"\}", template) or re.search(
        r"%\{" + re.escape(rid) + r"\}%\{(\w+)\}", template
    )
    if not m:
        return None
    other = syntax.rules.get(m.group(1)) or {}
    return bit_positions(encoded(meta, other.get("display")), fields) or None


def shift_table(alternatives, positions, candidates):
    """`LSL #0` / `LSL #8` alternatives of a shift bit: the amount LLVM's
    printer gives (printImm8OptLsl: 8; printAddSubImm: 12)."""
    if not alternatives or len(positions) != 1:
        return None
    amounts = {}
    for a in alternatives:
        m = re.match(r"^LSL #(\d+)$", a)
        if not m:
            return None
        amounts[int(m.group(1))] = a
    for rec in candidates:
        found = llvm.operand(rec, positions)
        if not found:
            continue
        printm = (llvm.d.get(found[0]) or {}).get("PrintMethod") or ""
        step = 8 if "Imm8OptLsl" in printm else 12 if "AddSubImm" in printm else None
        if step and 0 in amounts and step in amounts:
            return [("0", amounts[0]), ("1", amounts[step])]
    return None


def asm_table(alts, positions, mask, value, rec, template, rid, meta, fields):
    """A specifier the part fixes (`<Tb>` of FCVTXN2: 4S; `<ZM>` of
    BRKA_PPzP: Z): the alternative LLVM's assembly string gives after the
    register it qualifies (`$Rd.4s`, `$Pg/z`)."""
    if not alts or not positions or not rec or not any(mask >> b & 1 for b in positions):
        return None
    m = re.search(r"%\{(\w+)\}([./])%\{" + re.escape(rid) + r"\}", template)
    if not m:
        return None
    other = syntax.rules.get(m.group(1)) or {}
    found = llvm.operand(rec, bit_positions(encoded(meta, other.get("display")), fields), True)
    if not found:
        return None
    asm = (llvm.d.get(rec[0]) or {}).get("AsmString") or ""
    # (The first of variants: `mla{\t$Rd.8h, ...|.8h\t$Rd, ...}`.)
    asm = re.sub(r"\{([^|}]*)\|[^}]*\}", r"\1", asm)
    hits = [a for a in alts if re.search(r"\$" + re.escape(found[1]) + re.escape(m.group(2)) + re.escape(a.lower()) + r"(?![\w])", asm)]
    if len(hits) != 1:
        return None
    # (Bits the part leaves open don't matter: `01xx`.)
    return [("".join(str(value >> b & 1) if mask >> b & 1 else "x" for b in positions), hits[0])]


def decoder_conditions(rec, mask, value, fields):
    """What LLVM's C++ decoders (AArch64Disassembler.cpp) check beyond the
    encoding, in ARM's fields: ("undef", cond) where the word doesn't
    decode, ("unpred", cond) where it decodes with SoftFail (CONSTRAINED
    UNPREDICTABLE)."""
    if not rec:
        return []
    name = rec[0]
    method = (llvm.d.get(name) or {}).get("DecoderMethod") or ""
    bit = lambda b: (value >> b & 1) if mask >> b & 1 else None
    has = lambda *f: all(x in fields for x in f)
    out = []
    # DecodeThreeAddrSRegInstruction: "if sf == '0' and imm6<5> == '1' then
    # ReservedValue()".
    if method == "DecodeThreeAddrSRegInstruction" and name.endswith("Wrs") and has("imm6"):
        out.append(("undef", "imm6 IN {'1xxxxx'}"))
    # DecodeAddSubERegInstruction: a shift above 4.
    if method == "DecodeAddSubERegInstruction" and has("imm3"):
        out.append(("undef", "imm3 IN {'101', '11x'}"))
    # DecodeSignedLdStInstruction: an indexed load (not FP) writing back to
    # its transfer register.
    # (LLVM's test, bits 11:10 != 0, takes in LDTR, 10, which has no
    # writeback: only post- and pre-indexing, x1, write back.)
    # (LLVM takes a load to be opc<0> == 1, which leaves out the
    # sign-extending loads to X registers, opc 10: LDRSB/LDRSH/LDRSW.)
    if method == "DecodeSignedLdStInstruction" and has("Rt", "Rn"):
        if (bit(22) == 1 or bit(23) == 1) and bit(26) == 0 and bit(10) == 1:
            out.append(("unpred", "(Rt == Rn) && (Rn != '11111')"))
    # The rest of these are checks of LLVM's assembler
    # (AArch64AsmParser::validateInstruction): stores writing back to the
    # register they store, and store-exclusives whose status register is
    # also a source.
    if re.fullmatch(r"STR(?:BB|HH|W|X)(?:pre|post)", name) and has("Rt", "Rn"):
        out.append(("unpred", "(Rt == Rn) && (Rn != '11111')"))
    if re.fullmatch(r"STL?XR[BHWX]", name) and has("Rs", "Rt", "Rn"):
        out.append(("unpred", "(Rs == Rt) || ((Rs == Rn) && (Rn != '11111'))"))
    if re.fullmatch(r"STL?XP[WX]", name) and has("Rs", "Rt", "Rt2", "Rn"):
        out.append(("unpred", "(Rs == Rt) || (Rs == Rt2) || ((Rs == Rn) && (Rn != '11111'))"))
    # DecodePairLdStInstruction: a load of one register twice, or (general
    # registers) writeback to a transfer register.
    if method == "DecodePairLdStInstruction" and has("Rt", "Rt2", "Rn"):
        if bit(22) == 1:
            out.append(("unpred", "Rt == Rt2"))
        if re.search(r"(?:X|W|GP|TP)(?:pre|post)$", name):
            out.append(("unpred", "(Rn != '11111') && ((Rt == Rn) || (Rt2 == Rn))"))
    # DecodeExclusiveLdStInstruction: a load pair of one register twice.
    if method == "DecodeExclusiveLdStInstruction" and name in ("LDAXPW", "LDXPW", "LDAXPX", "LDXPX") and has("Rt", "Rt2"):
        out.append(("unpred", "Rt == Rt2"))
    # DecodeAuthLoadInstruction: writeback to the transfer register.
    if method == "DecodeAuthLoadInstruction" and bit(11) == 1 and has("Rt", "Rn"):
        out.append(("unpred", "(Rt == Rn) && (Rn != '11111')"))
    # FEAT_MOPS (the ARM ARM's Unpredictable_MOPSOVERLAP31, which LLVM's
    # assembler rejects too): a copy's three registers must differ and none
    # be 31; a set's destination and size likewise, and differ from its
    # value register (which may be XZR); a tag-setting set (SETGO*) has no
    # value register.
    if re.fullmatch(r"CPYF?[PME]\w*", name) and has("Rd", "Rs", "Rn"):
        out.append(("unpred", "(Rd == Rs) || (Rd == Rn) || (Rs == Rn) || (Rd == '11111') || (Rs == '11111') || (Rn == '11111')"))
    elif re.fullmatch(r"SETGO[PME]\w*", name) and has("Rd", "Rn"):
        out.append(("unpred", "(Rd == Rn) || (Rd == '11111') || (Rn == '11111')"))
    elif re.fullmatch(r"SETG?[PME]\w*", name) and has("Rd", "Rs", "Rn"):
        out.append(("unpred", "(Rd == Rn) || (Rd == Rs) || (Rn == Rs) || (Rd == '11111') || (Rn == '11111')"))
    # DecodeImm8OptLsl<8>: bytes can't be shifted.
    for t in rec[4].values():
        if (llvm.d.get(t) or {}).get("DecoderMethod") == "DecodeImm8OptLsl<8>" and has("sh"):
            out.append(("undef", "sh IN {'1'}"))
    # Register classes whose decoders reject some numbers: pairs (CASP's
    # DecodeGPRSeqPairsClassRegisterClass: even) and eight registers
    # (LD64B's DecodeGPR64x8ClassRegisterClass: even, at most 22).
    for var, t in rec[4].items():
        r = llvm.d.get(t) or {}
        cls = (r.get("RegClass") or {}).get("def") if isinstance(r.get("RegClass"), dict) else None
        decoder = r.get("DecoderMethod") or (llvm.d.get(cls) or {}).get("DecoderMethod") or ""
        # (Classes whose decoders TableGen names after them.)
        if not decoder and re.fullmatch(r"[WX]SeqPairsClass|GPR64x8Class", cls or t):
            decoder = f"Decode{cls or t}RegisterClass"
        bits = sorted(b for b, v in rec[3].items() if v == var)
        field = next((n for n, (hi, lo) in fields.items() if bits and (hi, lo) == (bits[-1], bits[0])), None)
        if not field or len(bits) != 5:
            continue
        if "SeqPairsClass" in decoder:
            out.append(("undef", f"{field} IN {{'xxxx1'}}"))
        elif "GPR64x8Class" in decoder:
            out.append(("undef", f"{field} IN {{'xxxx1', '10111', '11xxx'}}"))
    return out


def cond_names():
    """Condition codes by value, from LLVM's AArch64BaseInfo.h
    (`getCondCodeName`, and the CondCode enumeration's order)."""
    if not LLVM_SRC:
        sys.exit("set LLVM_SRC to the llvm directory of an llvm-project checkout")
    path = LLVM_SRC + "/lib/Target/AArch64/Utils/AArch64BaseInfo.h"
    src = open(path, encoding="utf-8").read()
    enum = re.search(r"enum CondCode \{(.*?)\};", src, re.S).group(1)
    codes = re.findall(r"^\s*(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)", enum, re.M)
    names = dict(re.findall(r'case (\w+):\s*return "(\w+)";', src))
    return {int(v, 0): names[k] for k, v in codes if k in names}


# LLVM operand print methods whose values are named by system-operand
# records (each with a Name and an Encoding), or by the condition codes.
NAMED = {
    "printCondCode": "cond",
    "printInverseCondCode": "invcond",
    "printBarrierOption": "DB",
    "printBarriernXSOption": "DBnXS",
    "printPrefetchOp<false>": "PRFM",
    "printPrefetchOp": "PRFM",
    "printPrefetchOp<true>": "SVEPRFM",
    "printSVEPattern": "SVEPREDPAT",
    "printSVEVecLenSpecifier": "SVEVECLENSPECIFIER",
    "printSystemPStateField": "PStateImm0_15",
}


def named_table(rec, positions, display=None):
    """A table of value names for an operand LLVM prints by name."""
    found = llvm.operand(rec, positions)
    if not found:
        return None
    printm = (llvm.d.get(found[0]) or {}).get("PrintMethod") or ""
    kind = NAMED.get(printm)
    if not kind:
        return None
    # (An alias's inverted condition: CINC's, of CSINC's field.)
    if kind == "cond" and display == "<invcond>":
        kind = "invcond"
    n = len(positions)
    if kind in ("cond", "invcond"):
        names = cond_names()
        rows = []
        for v, name in sorted(names.items()):
            shown = v ^ 1 if kind == "invcond" else v
            if v < (1 << n):
                rows.append((format(v, f"0{n}b"), names.get(shown, name).upper()))
        return rows
    rows = []
    for r in llvm.d["!instanceof"].get(kind, []):
        rec_ = llvm.d[r]
        enc = rec_.get("Encoding")
        name = rec_.get("Name")
        if not isinstance(enc, list) or not name:
            continue
        v = sum(b << i for i, b in enumerate(enc) if b in (0, 1))
        if v < (1 << n):
            rows.append((format(v, f"0{n}b"), name.upper()))
    return sorted(set(rows)) or None


def concat_parts(src):
    """`immh[0]:immb[2:0]` as its parts (not split inside a slice)."""
    parts, depth, cur = [], 0, ""
    for c in src:
        if c in "[<":
            depth += 1
        elif c in "]>":
            depth -= 1
        if c == ":" and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    parts.append(cur)
    return parts


def bit_positions(src, fields):
    """The word's bit positions an encoded-in expression ("Q:S:size<1>")
    reads."""
    out = []
    for part in concat_parts(src):
        part = part.strip()
        if not part or part.startswith("'"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:[<\[](\d+)(?::(\d+))?[>\]])?$", part)
        if not m or m.group(1) not in fields:
            return []
        hi, lo = fields[m.group(1)]
        if m.group(2) is not None:
            h = int(m.group(2))
            l = int(m.group(3)) if m.group(3) is not None else h
            hi, lo = lo + h, lo + l
        out.extend(range(hi, lo - 1, -1))
    return out


def main():
    global llvm, syntax
    mrs = load_mrs(sys.argv[1])
    llvm = Llvm(sys.argv[2])
    syntax = Syntax(mrs["assembly_rules"])
    a64 = next(g for g in mrs["instructions"] if g["name"] == "A64")
    print("# SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0 WITH LLVM-exception")
    print("# A64 encodings, generated by tools/arm64/extract.py from Arm's AARCHMRS")
    print("# (BSD-3-Clause; see LICENSE-ARM) and LLVM's AArch64 target")
    print("# (Apache-2.0 WITH LLVM-exception; see LICENSE-LLVM).")
    print()
    classes = {"sve": "sve", "sme": "mortlach", "simd_dp": "advsimd"}

    def emit(node, pattern, fields, conds, top):
        pattern, fields = merge(pattern, dict(fields), node.get("encoding"))
        conds = conds + [c for c in conjuncts(node.get("condition") or {"_type": "AST.Bool", "value": True}) if c.get("_type") != "AST.Bool"]
        if node["_type"] == "Instruction.Instruction":
            instruction(node, pattern, fields, conds, classes.get(top, "general"))
        for k in node.get("children") or []:
            if k["_type"] != "Instruction.InstructionAlias":
                emit(k, pattern, fields, conds, top or k["name"])

    def instruction(node, pattern, fields, conds, cls):
        print(f"file {node['name']} instruction {node['name']}")
        enc(node["name"], node, pattern, fields, conds, cls, None)
        # Aliases with conditions on the encoding (LSL: imms + 1 == immr)
        # first: they are the special cases of those without (UBFIZ), and
        # the first preferred alias is used.
        aliases = [a for a in node.get("children") or [] if a["_type"] == "Instruction.InstructionAlias"]
        unconditional = lambda a: (a.get("condition") or {}).get("_type") == "AST.Bool"
        for a in sorted(aliases, key=unconditional):
            alias(a, node, pattern, fields, conds, cls)
        print()

    def enc(name, node, pattern, fields, conds, cls, alias_of):
        """An encoding: as one, or (where LLVM's records for it fix bits
        the encoding leaves open: per element size, say) as one part per
        LLVM record, each with its operands' bits as that record has them.
        What no record covers is left out: LLVM doesn't decode it."""
        mask = value = 0
        for i, c in enumerate(pattern):
            if c in "01":
                mask |= 1 << (31 - i)
                value |= int(c) << (31 - i)
        ops = []
        rendered = syntax.render(node["assembly"]["symbols"], ops)
        mnemonic = re.match(r"[A-Za-z0-9.]*", rendered).group(0).lower()
        # (`SMLAL{2}`: LLVM has smlal and smlal2.)
        names = {mnemonic, mnemonic + "2"} if rendered[len(mnemonic):].startswith("%{s_2") else {mnemonic}
        if alias_of:
            # An alias's operands are its instruction's: LLVM's records are
            # by the instruction's mnemonic.
            prendered = syntax.render(alias_of[2]["assembly"]["symbols"], [])
            pm = re.match(r"[A-Za-z0-9.]*", prendered).group(0).lower()
            names = {pm, pm + "2"} if prendered[len(pm):].startswith("%{s_2") else {pm}
        parts = [(mask, value, None)]
        # (Not the `_idx0` records: `umov w0, v0.s[0]` again, with the
        # index fixed.)
        same = [r for r in llvm.records if r[5] in names and not (r[2] ^ value) & r[1] & mask and not r[0].endswith("_idx0")]
        # (Records for broader encodings, such as MSR (register) for MSR
        # (immediate), aren't this one's.)
        covering = [r for r in same if r[1] & mask == mask]
        if covering:
            same = covering
        if not same:
            # LLVM names it otherwise (`DUP (element, scalar)` is LLVM's
            # `mov`): the records that decode only words of the encoding.
            same = [r for r in llvm.records if not (r[2] ^ value) & r[1] & mask and r[1] & mask == mask]
        if same:
            if all(r[1] & ~mask & 0xFFFFFFFF for r in same):
                seen = {}
                for r in same:
                    m = mask | r[1]
                    v = (value & mask) | (r[2] & r[1])
                    seen.setdefault((m, v), r)
                parts = sorted(((m, v, r) for (m, v), r in seen.items()), key=lambda p: -bin(p[0]).count("1"))
            elif len(same) == 1:
                # One record, fixing no more than the encoding: its operands'
                # bits are still as it has them (`SSHR D`: imm{5:0}, not
                # immh:immb with immh<3> fixed).
                parts = [(mask, value, same[0])]
            elif (general := [r for r in same if not r[1] & ~mask & 0xFFFFFFFF]) and len({r[1] for r in general}) == 1:
                # Several records for the same words, told apart by LLVM's
                # C++ (MSRpstateImm4 and MSRpstateImm1; MSRpstatesvcrImm1
                # is SMSTART's): the general one, whose named operand takes
                # the fewest bits.
                def named_bits(r):
                    return min((sum(1 for v in r[3].values() if v == var) for var, t in r[4].items()
                                if NAMED.get((llvm.d.get(t) or {}).get("PrintMethod") or "")), default=99)
                parts = [(mask, value, min(general, key=named_bits))]
        for i, (m, v, rec) in enumerate(parts):
            # (Symbols are scoped by file: an alias's first part gets its own,
            # apart from its instruction's last part's.)
            if i > 0 or alias_of:
                print(f"file {name} part {i}")
            bits = "".join(("1" if v >> b & 1 else "0") if m >> b & 1 else "x" for b in range(31, -1, -1))
            enc_part(name, node, bits, fields, conds, cls, alias_of, rec, names)

    def enc_part(*args):
        """enc_part1, then a `#` before each operand whose alternatives
        each have one where its value is computed (no table of texts, and
        no memext, which prints its own)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            enc_part1(*args)
        lines = buf.getvalue().split("\n")
        for rid in syntax.hash_choices:
            head = f"sym {rid} "
            for i, line in enumerate(lines):
                if not line.startswith(head):
                    continue
                attr = lines[i + 1] if i + 1 < len(lines) and lines[i + 1].startswith("  attr") else ""
                if " = " in line or "memext" in attr or "spec=" in attr:
                    break
                lines = [re.sub(r"(?<!#)%\{" + re.escape(rid) + r"\}", "#%{" + rid + "}", l) if l.startswith("  asm ") else l for l in lines]
                break
        sys.stdout.write("\n".join(lines))

    def enc_part1(name, node, pattern, fields, conds, cls, alias_of, part_rec, llvm_names):
        # The feature condition: each feature term ANDed, as AARCHMRS
        # writes them (or, where a term isn't plain, any of its features).
        terms = []
        for c in conds:
            if is_feature(c):
                e = feature_expr(c)
                e = e if e is not None else "||".join(features(c))
                if e not in terms:
                    terms.append(e)
        if len(terms) > 1:
            terms = [f"({t})" if ("||" in t or "&&" in t) else t for t in terms]
        feats = "&&".join(terms)
        print(f"enc {name} {cls}")
        print(f"  bits {pattern}")
        order = sorted(fields.items(), key=lambda kv: -kv[1][0])
        print("  fields " + " ".join(f"{n}={h}" if h == l else f"{n}={h}:{l}" for n, (h, l) in order))
        for c in conds:
            if is_feature(c):
                continue
            s = ast(c)
            if s is None:
                print(f"  # unsupported condition: {json.dumps(c)[:200]}")
                continue
            # The encoding exists only where the condition holds.
            print(f"  undef !{s}")
        if feats:
            print(f"  feat {feats}")
        if alias_of:
            target, when, _ = alias_of
            print(f"  alias {target} when {when}")
        operands = []
        template = syntax.render(node["assembly"]["symbols"], operands)
        # Choices between register operands: the one whose kind the part's
        # LLVM record gives that register (GPR32: <Wm>; GPR64: <Xm>).
        def pick(m):
            alts = m.group(1).split("|")
            if part_rec:
                for a in alts:
                    letter = (syntax.rules[a].get("display") or "<").strip("<")[:1].lower()
                    src_a = encoded(node.get("_meta"), syntax.rules[a].get("display"))
                    found = llvm.operand(part_rec, bit_positions(src_a, fields), True)
                    if found and type_letter(found[0]) == letter:
                        return "%{" + a + "}"
            return "%{" + alts[-1] + "}"
        template = re.sub(r"%\{alt:([\w|]+)\}", pick, template)
        # An optional first operand (`RET{ <Xn>}`): the space after the
        # mnemonic outside the group, where the mnemonic ends.
        template = re.sub(r"^([A-Z0-9.]+)\{ ", r"\1 {", template)
        # A shift or extend the part fixes (ADR's `{, LSL #<amount>}` and
        # `SXTW{ #<amount>}`, by msz): literal text, from the type of the
        # register it applies to (printRegWithShiftExtend<..., 64, ...>:
        # LSL #3); amount 0 isn't shown.
        if part_rec:
            for t in part_rec[4].values():
                pm = re.match(r"printRegWithShiftExtend<\w+, ?(\d+),", (llvm.d.get(t) or {}).get("PrintMethod") or "")
                kind = re.search(r"Ext(LSL|SXTW|UXTW)", t)
                if not pm or not kind:
                    continue
                n = {8: 0, 16: 1, 32: 2, 64: 3, 128: 4}.get(int(pm.group(1)))
                shown = f" #{n}" if n else ""
                for a in [o for o in operands if syntax.rules[o].get("display") == "<amount>"]:
                    for mod in [o for o in operands if syntax.rules[o].get("display") == "<mod>"]:
                        # (The `#` may be added later: see enc_part.)
                        group = re.escape("{, %{" + mod + "} ") + "#?" + re.escape("%{" + a + "}}")
                        template = re.sub(group, f", {kind.group(1)}{shown}" if n else "", template)
                    template = re.sub(re.escape(kind.group(1)) + "#?" + re.escape(f"%{{{a}}}"), f"{kind.group(1)}{shown}", template)
        operands = [o for o in operands if "%{" + o + "}" in template]
        print(f"  asm {template}")
        mask = 0
        value = 0
        for i, c in enumerate(pattern):
            if c in "01":
                mask |= 1 << (31 - i)
                value |= int(c) << (31 - i)
        # The mnemonic of LLVM's records (an alias's are its instruction's).
        mnemonic = part_rec[5] if part_rec else min(llvm_names, key=len)
        llvm_names = set(llvm_names) | {mnemonic}
        candidates = llvm.matches(mask, value, mnemonic)[:24]
        ranges = {}
        claimed = set()
        if part_rec:
            candidates = [part_rec] + [c for c in candidates if c is not part_rec]
        if not alias_of:
            own = part_rec or next((c for c in candidates if c[5] in llvm_names and not (c[2] ^ value) & c[1] & mask and c[1] & mask == mask), None)
            for kind, cond in decoder_conditions(own, mask, value, fields):
                print(f"  {kind} {cond}")
        for rid in dict.fromkeys(operands):
            rule = syntax.rules[rid]
            display = rule.get("display")
            src = encoded(node.get("_meta"), display)
            # (DecodeTestAndBranch puts b5 back itself.)
            whole = (llvm.d.get(part_rec[0]) or {}).get("DecoderMethod") == "DecodeTestAndBranch" if part_rec else False
            alts0 = syntax.alternatives(rid)
            names_only = alts0 is not None and not all(re.fullmatch(r"[0-9]*[A-Z]{1,2}", a) for a in alts0)
            if part_rec and not whole and not syntax.table(rid) and (alts0 is None or names_only):
                # (A specifier keeps its whole field: its table is keyed so.)
                src = part_source(src, fields, mask, part_rec, is_register_display(display), claimed, names_only)
            line = f"sym {rid} {display} {src}".rstrip()
            rows = syntax.table(rid)
            positions = bit_positions(src, fields)
            alts = syntax.alternatives(rid)
            qualified = qualified_bits(template, rid, node.get("_meta"), fields)
            complete = rows and len({b for b, _ in rows if "x" not in b}) == (1 << len(positions)) if positions else bool(rows)
            if alts and qualified and not complete and not any("x" in b for b, _ in (rows or [])) or (alts and qualified and rows and any("x" in b for b, _ in rows)):
                better = specifier_table(alts, positions, qualified, mask, value, candidates, mnemonic)
                if better:
                    rows = better
            if not rows and alts:
                for classify in (classify_za, classify_hv, classify_extend):
                    rows = per_value_table(alts, positions, mask, value, candidates, mnemonic, classify)
                    if rows:
                        break
            if not rows:
                rows = llvm_table(alts, positions, candidates, mnemonic)
            if not rows:
                rows = shift_table(alts, positions, candidates)
            if not rows:
                rows = asm_table(alts, positions, mask, value, part_rec, template, rid, node.get("_meta"), fields)
            named = False
            if not rows and positions:
                for rec in candidates:
                    if rec[5] not in llvm_names:
                        continue
                    rows = named_table(rec, positions, display)
                    if rows:
                        named = True
                        break
            own_syms = ((rule.get("symbols") or {}).get("symbols")) or []
            if not rows and len(positions) == 1 and len(own_syms) == 1 and own_syms[0].get("_type", "").endswith("Literal") and re.fullmatch(r"[A-Z]+", own_syms[0].get("value") or ""):
                # A word present or not (TENTER's `NB`), by one bit.
                rows = [("0", "[absent]"), ("1", "[present]")]
            widths = {len(b) for b, _ in rows or []}
            if rows and positions and len(widths) == 1 and widths.pop() < len(positions):
                # A table keyed by fewer bits than the field AARCHMRS gives
                # (MOVI's <amount>, "cmode", by cmode<1>): the bits the
                # encoding leaves free.
                free = [b for b in positions if not mask >> b & 1]
                if len(free) == len(rows[0][0]):
                    src = bits_source(free, src, fields)
                    line = f"sym {rid} {display} {src}"
                    positions = free
            if not rows and alts and display == "<T>" and src == "imm13":
                # The element size of an SVE logical immediate: the size of
                # its repeating element (LLVM's decodeLogicalImmediate: N,
                # then the highest clear bit of imms), at least a byte.
                src = "imm13[12]:imm13[5:0]"
                line = f"sym {rid} {display} {src}"
                rows = [("1xxxxxx", "D"), ("00xxxxx", "S"), ("010xxxx", "H"), ("0110xxx", "B"), ("01110xx", "B"), ("011110x", "B")]
                rows = [(b, t) for b, t in rows if t in alts]
            first = re.search(r"%\{(\w+)\}:%\{" + re.escape(rid) + r"\}", template)
            if first and first.group(1) in ranges:
                # The last of a range (`<offsl>` of `<offsf>:<offsl>`): the
                # first's bits, scaled the same, plus the range's length.
                fsrc, fattrs = ranges[first.group(1)]
                length = next(a for a in fattrs if a.startswith("range=")).split("=")[1]
                mul = next((a for a in fattrs if a.startswith("mul=")), "mul=1")
                print(f"sym {rid} {display} {fsrc}")
                print(f"  attr src=llvm:range {mul} add={length}")
                continue
            if alts is not None and len(alts) == 1 and re.fullmatch(r"[A-Z0-9]{1,3}", alts[0]) and not rows:
                # One alternative: a fixed specifier (`ZA.S`).
                print(f"sym {rid} {display}")
                print(f"  attr src=mrs spec={alts[0]}")
                continue
            if not src and alts is None:
                # No encoding and one fixed rendering: a specifier (`<V>`
                # of FMAXV, always H).
                fixed = syntax.render(((rule.get("symbols") or {}).get("symbols")) or [], [])
                if fixed and re.fullmatch(r"[A-Z0-9]{1,3}", fixed.strip()):
                    print(line)
                    print(f"  attr src=mrs spec={fixed.strip()}")
                    continue
            if rows:
                head = src or "?"
                line += f" = {head} | " + " | ".join(f"{b}:{t}" for b, t in rows)
            print(line)
            positions = bit_positions(src, fields)
            if positions:
                for rec in candidates:
                    found = llvm.operand(rec, positions, is_register_display(display))
                    if found:
                        t, var = found
                        # (Unnamed values are numbers, except PSTATE fields:
                        # LLVM's decoder rejects those it has no name for.)
                        pstate = (llvm.d.get(t) or {}).get("PrintMethod") == "printSystemPStateField"
                        attrs = llvm.attrs(t) + (["orimm"] if named and not pstate else [])
                        # A variable whose low bits aren't encoded
                        # (`shift{5:4}` of MOVK): a multiple of 2^lowest.
                        index = llvm.index_of[rec[0]]
                        held = [index.get(b, 0) for b in positions if rec[3].get(b) and re.sub(r"\{.*", "", rec[3][b]) == var]
                        lower = [index.get(b, 0) for b, v in rec[3].items() if re.sub(r"\{.*", "", v) == var and b not in positions]
                        if held and len(held) == len(positions) and min(held) > 0 and not any(i < min(held) for i in lower) and not llvm.is_register(t) and not any(a.startswith("mul=") for a in attrs):
                            attrs.append(f"mul={1 << min(held)}")
                        step = next((a for a in attrs if a.startswith("regstep=")), None)
                        if step and src.count(":") == 1:
                            # The first register: T, zeros, then Zt (the
                            # register number's low bits).
                            hi_part, lo_part = src.split(":")
                            low = len(bit_positions(lo_part, fields))
                            zeros = 4 - low
                            if zeros > 0 and not line.startswith("sym " + rid + " " + display + " " + hi_part + ":'"):
                                print(f"  attr src=llvm:{rec[0]}.{var}:{t} source={hi_part}:'{'0' * zeros}':{lo_part}")
                        if any(a.startswith("range=") for a in attrs):
                            ranges[rid] = (src, attrs)
                        print(f"  attr src=llvm:{rec[0]}.{var}:{t} " + " ".join(attrs))
                        if rec is part_rec:
                            claimed.add(var)
                        break

    def alias(a, parent, pattern, fields, conds, cls):
        # Equalities on fields become fixed bits; the rest, and when the
        # alias is preferred, decide whether it is shown.
        pattern = list(pattern)
        rest = []
        for c in conjuncts(a.get("condition") or {"_type": "AST.Bool", "value": True}):
            if c.get("_type") == "AST.Bool":
                continue
            # (One pattern, `CRm IN {'100x'}`, is an equality too.)
            if (c.get("_type") == "AST.BinaryOp" and c["op"] == "IN"
                    and (c.get("right") or {}).get("_type") == "AST.Set"
                    and len(c["right"].get("values") or []) == 1):
                c = dict(c, op="==", right=c["right"]["values"][0])
            if (c.get("_type") == "AST.BinaryOp" and c["op"] == "=="
                    and c["left"].get("_type") == "AST.Identifier"
                    and c["left"]["value"] in fields and bits_of(c["right"]) is not None):
                hi, lo = fields[c["left"]["value"]]
                b = bits_of(c["right"])
                if len(b) == hi - lo + 1:
                    for i, ch in enumerate(b):
                        if ch in "01":
                            pattern[31 - (hi - i)] = ch
                    continue
            rest.append(c)
        # (Feature checks aren't preferences: the encoding's `feat` has them.)
        terms = [ast(c) for c in rest if not is_feature(c)]
        pref = a.get("preferred")
        if pref:
            terms += [ast(c) for c in conjuncts(pref) if not is_feature(c) and c.get("_type") != "AST.Bool"]
            if any(c.get("_type") == "AST.Bool" and not c.get("value") for c in conjuncts(pref)):
                terms.append("FALSE")
        when = " && ".join(t for t in terms if t) or "Unconditionally"
        name = f"{a['name']}_{parent['name']}"
        enc(name, a, "".join(pattern), fields, conds, cls, (parent["name"], when, parent))

    for g in a64.get("children") or []:
        emit(g, "x" * 32, {}, [], g["name"])


def should_bits(a64):
    """Each instruction's should-be bits (Arm's `(0)` and `(1)`: bits an
    encoding fixes, but that make the instruction CONSTRAINED
    UNPREDICTABLE, not UNDEFINED, when they differ): instruction name ->
    {bit: '0' or '1'}, from the encodesets' should_be_masks down its
    ancestors."""
    out = {}

    def walk(node, inherited):
        sb = dict(inherited)
        for v in (node.get("encoding") or {}).get("values", []):
            r = v.get("range") or {}
            width, start = r.get("width"), r.get("start")
            mask, value = bits_of(v.get("should_be_mask")), bits_of(v.get("value"))
            if width is None or mask is None or value is None or len(mask) != width or len(value) != width:
                continue
            for i, (m, c) in enumerate(zip(mask, value)):
                if m == "1" and c in "01":
                    sb[start + width - 1 - i] = c
        if node.get("_type") == "Instruction.Instruction":
            out[node["name"]] = sb
        for k in node.get("children") or []:
            walk(k, sb)

    for g in a64.get("children") or []:
        walk(g, {})
    return out


def mark_should_bits(text, should):
    """Rewrites each `bits` line of an instruction's block (its own and its
    aliases') with `O` and `Z` for its should-be-one and should-be-zero
    bits, where the line fixes them as the should-be value."""
    out = []
    current = {}
    for line in text.split("\n"):
        m = re.match(r"file (\S+) instruction ", line)
        if m:
            current = should.get(m.group(1), {})
        if line.startswith("  bits ") and current:
            bits = list(line[len("  bits "):])
            for bit, c in current.items():
                i = 31 - bit
                if 0 <= i < len(bits) and bits[i] == c:
                    bits[i] = "O" if c == "1" else "Z"
            line = "  bits " + "".join(bits)
        out.append(line)
    return "\n".join(out)


if __name__ == "__main__":
    _buf = io.StringIO()
    with contextlib.redirect_stdout(_buf):
        main()
    _mrs = load_mrs(sys.argv[1])
    _a64 = next(g for g in _mrs["instructions"] if g["name"] == "A64")
    sys.stdout.write(mark_should_bits(_buf.getvalue(), should_bits(_a64)))

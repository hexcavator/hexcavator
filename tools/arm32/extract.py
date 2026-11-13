# SPDX-License-Identifier: Apache-2.0
"""Generates crates/isa/arm32/tables/aarch32.txt from Arm's Machine Readable
Specification (AARCHMRS, BSD-3-Clause): every A32 and T32 (16- and 32-bit)
encoding with its fixed bits, its fields, its encoding conditions, its
feature conditions, its "should be" bits, its assembler template, and its
aliases with when each is preferred.

Nothing comes from Arm's proprietary ISA XML.

Usage: python extract.py <mrs.tar.gz or Instructions.json> > aarch32.txt

The table's lines:

    enc NAME ISET WIDTH        an encoding (ISET A32 or T32; WIDTH 16, 32)
      bits PATTERN             its bits, most significant first: 0, 1, or x
      sb PATTERN               "should be" bits (0/1) where not x
      fields NAME=HI:LO ...    its fields
      cond EXPR                when it applies (ASL subset), if not always
      feat EXPR                the features it needs (&&, ||), if any
      asm TEMPLATE             its assembler syntax, operands as %{rule}
      in <OPERAND> FIELD...    the fields an operand is encoded in, most
                               significant first (concatenated)
    alias NAME OF              an alias of encoding OF ...
      when EXPR                ... preferred when (ASL subset), if not always
      asm TEMPLATE
      in <OPERAND> FIELD...
    rule ID <OPERAND> TEXT     an operand rule the templates name: its text,
                               numbers as %{UInteger} (and other rules)
    choice ID <OPERAND>        an operand that is one of several texts ...
      alt ID TEXT              ... each named for the field values it is
                               for (`size_01_16`: size 01 is 16), or else
                               in the order of the values

T32 32-bit encodings number their bits from the first halfword's top
(bit 31) to the second's bottom (bit 0).
"""

import json
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



def bits_of(value):
    """A Values.Value's bit pattern ('0101x'), or None."""
    if not isinstance(value, dict):
        return None
    v = value.get("value")
    if isinstance(v, str) and v.startswith("'") and v.endswith("'"):
        return v[1:-1].replace(" ", "")
    return None


def merge(pattern, sb, fields, encodeset, width):
    """Applies an encodeset to a pattern and a should-be pattern (most
    significant bit first) and a field map (name -> (hi, lo)); later
    (inner) encodesets win."""
    pattern, sb = list(pattern), list(sb)
    for v in (encodeset or {}).get("values", []):
        r = v["range"]
        hi, lo = r["start"] + r["width"] - 1, r["start"]
        if hi >= width:
            continue
        b = bits_of(v.get("value"))
        # (Should-be bits, where the mask is 1, are not fixed: other values
        # are CONSTRAINED UNPREDICTABLE, not another encoding.)
        s = bits_of(v.get("should_be_mask"))
        should = s if s is not None and b is not None and len(s) == len(b) else "0" * r["width"]
        if b is not None and len(b) == r["width"]:
            for i, (c, m) in enumerate(zip(b, should)):
                if m == "1":
                    sb[width - 1 - (hi - i)] = c
                elif c in "01":
                    pattern[width - 1 - (hi - i)] = c
        if v["_type"].endswith("Field") and v.get("name"):
            fields[v["name"]] = (hi, lo)
    return "".join(pattern), "".join(sb), fields


# The fields in scope where a condition is: its identifiers that name them
# are rendered as bit slices of the instruction (`[19:16]`), since an inner
# encodeset can reuse a name for other bits.
SCOPE = {}


def ast(node):
    """Renders an AST node as the ASL subset build.rs compiles; None if it
    has something that subset can't say."""
    t = node.get("_type", "")
    if t == "AST.Identifier" and node["value"] in SCOPE:
        hi, lo = SCOPE[node["value"]]
        return f"[{hi}:{lo}]"
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
        return f"({l} {node['op']} {r})"
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
    if t in ("AST.Slice", "AST.SquareOp"):
        target = node.get("var") or node.get("left") or {}
        args = node.get("arguments") or []
        # A slice of a field: the instruction's bits it is.
        if target.get("_type") == "AST.Identifier" and target["value"] in SCOPE and args:
            hi, lo = SCOPE[target["value"]]
            a = args[0]
            bounds = (a.get("left"), a.get("right")) if a.get("_type") == "AST.Slice" else (a, a)
            if all((b or {}).get("_type") == "AST.Integer" for b in bounds):
                h, l = bounds[0]["value"], bounds[1]["value"]
                return f"[{lo + h}:{lo + l}]"
        var = ast(target)
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
    if node.get("_type") == "AST.BinaryOp" and node.get("op") == "&&":
        return conjuncts(node["left"]) + conjuncts(node["right"])
    return [node]


def is_feature(node):
    s = json.dumps(node)
    return ("FEAT_" in s or "IsFeatureImplemented" in s) and '"op": "=="' not in s and '"op": "!="' not in s


def feature_expr(node):
    t = node.get("_type")
    if t == "AST.Function" and node.get("name") == "IsFeatureImplemented":
        names = re.findall(r"FEAT_[A-Za-z0-9_]+", json.dumps(node))
        return names[0] if len(names) == 1 else None
    if t == "AST.Identifier" and str(node.get("value", "")).startswith("FEAT_"):
        return node["value"]
    if t == "AST.BinaryOp" and node.get("op") in ("&&", "||"):
        l, r = feature_expr(node["left"]), feature_expr(node["right"])
        if l is None or r is None:
            return None
        return f"({l}{node['op']}{r})"
    return None


def encoded_in(node):
    """An encoding's (or alias's) operands' fields: (display, [field])."""
    meta = (node.get("_meta") or {}).get("encoded_in") or {}
    out = []
    for display, parts in meta.items():
        names = [p.get("value") for p in parts if p.get("_type") == "AST.Identifier"]
        if names and len(names) == len(parts):
            out.append((display, names))
    return out


class Rules:
    """The operand rules the templates name, and those they name."""

    def __init__(self, rules):
        self.rules = rules
        self.seen = []

    def text(self, symbols):
        out = ""
        for sym in symbols:
            t = sym.get("_type", "")
            if t.endswith("Literal"):
                out += sym["value"]
            elif t.endswith("RuleReference"):
                rid = sym["rule_id"]
                r = self.rules.get(rid) or {}
                punct = {"SPACE": " ", "COMMA": ", ", "DOT": ".", "BANG": "!"}
                if rid in punct:
                    out += punct[rid]
                elif rid == "hash":
                    out += "#"
                else:
                    self.want(rid)
                    out += "%{" + rid + "}"
        return out

    def want(self, rid):
        if rid not in self.seen:
            self.seen.append(rid)

    def emit(self):
        i = 0
        while i < len(self.seen):
            rid = self.seen[i]
            i += 1
            r = self.rules.get(rid)
            if r is None:
                continue
            display = r.get("display") or "-"
            if r.get("_type", "").endswith("Choice"):
                print(f"choice {rid} {display}")
                for c in r["choices"]:
                    syms = (c or {}).get("symbols") or []
                    # An alternative that is one rule: named by it.
                    if len(syms) == 1 and syms[0].get("_type", "").endswith("RuleReference"):
                        sub = self.rules.get(syms[0]["rule_id"]) or {}
                        if sub.get("_type", "").endswith("Rule"):
                            text = self.text(((sub.get("symbols") or {}).get("symbols")) or [])
                            print(f"  alt {syms[0]['rule_id']} {text}".rstrip())
                            continue
                    print(f"  alt - {self.text(syms)}".rstrip())
            elif r.get("_type", "").endswith("Rule"):
                text = self.text(((r.get("symbols") or {}).get("symbols")) or [])
                print(f"rule {rid} {display} {text}".rstrip())


class Syntax:
    """Renders assembly symbols as a template: literals as text, operand
    rules (those with a `<...>` display) as %{rule}, optional parts in
    braces, and tokens as their text."""

    def __init__(self, rules):
        self.rules = rules
        self.cache = {}

    def render(self, symbols, depth=0):
        out = ""
        for s in symbols:
            t = s.get("_type", "")
            if t.endswith("Literal"):
                out += s["value"]
            elif t.endswith("RuleReference"):
                out += self.reference(s["rule_id"], depth)
        return out

    def reference(self, rid, depth):
        if rid in self.cache:
            return self.cache[rid]
        if depth > 40:
            return ""
        r = self.rules.get(rid)
        if r is None:
            return f"?{rid}?"
        t = r.get("_type", "")
        display = r.get("display")
        if t.endswith("Token"):
            text = {"SPACE": " ", "COMMA": ", ", "DOT": ".", "BANG": "!"}.get(rid, r.get("default") or "")
        elif display and display.startswith("<"):
            text = "%{" + rid + "}"
        elif t.endswith("Choice"):
            alternatives = [self.render((c or {}).get("symbols") or [], depth + 1) if c else "" for c in r["choices"]]
            nonempty = [a for a in alternatives if a]
            if rid == "hash" or display == "#":
                text = "#"
            elif not nonempty:
                text = ""
            else:
                best = max(nonempty, key=len)
                text = "{" + best + "}" if len(nonempty) < len(alternatives) else best
        else:
            text = self.render(((r.get("symbols") or {}).get("symbols")) or [], depth + 1)
        self.cache[rid] = text
        return text


def main():
    mrs = load_mrs(sys.argv[1])
    syntax = Syntax(mrs["assembly_rules"])
    print("# SPDX-License-Identifier: BSD-3-Clause")
    print("# A32 and T32 encodings, generated by tools/arm32/extract.py from Arm's")
    print("# AARCHMRS (BSD-3-Clause; see LICENSE-ARM).")
    print()

    def emit(node, iset, width, pattern, sb, fields, conds):
        enc = node.get("encoding") or {}
        if enc.get("width") and enc["width"] != width:
            width = enc["width"]
            pattern, sb = "x" * width, "x" * width
        pattern, sb, fields = merge(pattern, sb, dict(fields), enc, width)
        cond = node.get("condition") or {"_type": "AST.Bool", "value": True}
        # (Rendered now, with this level's fields.)
        SCOPE.clear()
        SCOPE.update(fields)
        new = []
        for c in conjuncts(cond):
            if c.get("_type") == "AST.Bool":
                continue
            if is_feature(c):
                new.append(("feat", feature_expr(c) or "||".join(sorted(set(re.findall(r"FEAT_[A-Za-z0-9_]+", json.dumps(c)))))))
            else:
                new.append(("cond", ast(c) or "UNKNOWN"))
        conds = conds + [c for c in new if c not in conds]
        if node["_type"] == "Instruction.Instruction":
            instruction(node, iset, width, pattern, sb, fields, conds)
        for k in node.get("children") or []:
            if k["_type"] != "Instruction.InstructionAlias":
                emit(k, iset, width, pattern, sb, fields, conds)

    def instruction(node, iset, width, pattern, sb, fields, conds):
        name = node["name"]
        feats = [v for k, v in conds if k == "feat" and v]
        others = [v for k, v in conds if k == "cond"]
        print(f"enc {name} {iset} {width}")
        print(f"  bits {pattern}")
        if any(c in "01" for c in sb):
            print(f"  sb {sb}")
        order = sorted(fields.items(), key=lambda kv: -kv[1][0])
        print("  fields " + " ".join(f"{n}={h}" if h == l else f"{n}={h}:{l}" for n, (h, l) in order))
        if others:
            print("  cond " + " && ".join(others))
        if feats:
            print("  feat " + "&&".join(feats))
        print("  asm " + syntax.render(node["assembly"]["symbols"]))
        for display, names in encoded_in(node):
            print(f"  in {display} {' '.join(names)}")
        aliases = [a for a in node.get("children") or [] if a["_type"] == "Instruction.InstructionAlias"]
        SCOPE.clear()
        SCOPE.update(fields)
        for a in aliases:
            print(f"alias {a['name']} {name}")
            when = [ast(c) for c in conjuncts(a.get("condition") or {"_type": "AST.Bool", "value": True}) if c.get("_type") != "AST.Bool"]
            pref = a.get("preferred")
            if pref and pref.get("_type") != "AST.Bool":
                when += [ast(c) for c in conjuncts(pref)]
            if when:
                print("  when " + " && ".join(w if w is not None else "UNKNOWN" for w in when))
            print("  asm " + syntax.render(a["assembly"]["symbols"]))
            for display, names in encoded_in(a):
                print(f"  in {display} {' '.join(names)}")
        print()

    for iset_node in mrs["instructions"]:
        iset = iset_node["name"]
        if iset not in ("A32", "T32"):
            continue
        emit(iset_node, iset, 32, "x" * 32, "x" * 32, {}, [])
    # The operand rules the templates name.
    rules = Rules(mrs["assembly_rules"])
    for rid in syntax.cache:
        r = mrs["assembly_rules"].get(rid) or {}
        display = r.get("display")
        if display and display.startswith("<"):
            rules.want(rid)
    rules.emit()


if __name__ == "__main__":
    main()

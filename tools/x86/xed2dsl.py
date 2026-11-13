"""Generates hexcavator-x86 opcode table lines from Intel XED's EVEX data.

    python -I tools/x86/xed2dsl.py <xed>/datafiles/avx512-fp16/avx512-fp16-isa.xed.txt ... > table.txt

XED (https://github.com/intelxed/xed) is Apache-2.0; its data files are
read, not copied: each table line is built from a group of XED records
(one per vector length, register or memory form, and W), and says which
group it came from. Lines already in the existing tables (same map,
opcode, prefix, W, and ModRM.reg) are left out.

What it understands is the vocabulary of XED's AVX-512-style records:
XMM/YMM/ZMM_{R3,N3,B3}, MASK_R/B, MASK1 (masking; ZEROSTR: zeroing too),
GPR32/64_{R,B,N}, MEM0, IMM0; VL128/256/512 and FIX_ROUND_LEN128 (LIG);
NELEM_* and ESIZE_* (the disp8 tuple); AVX512_ROUND() and SAE(); and
BROADCAST_ENABLED. Anything else is reported on stderr and its group
skipped.
"""

import re
import sys
from collections import OrderedDict

MAPS = {'V0F': 'EVEX.0F', 'V0F38': 'EVEX.0F38', 'V0F3A': 'EVEX.0F3A', 'MAP5': 'EVEX.M5', 'MAP6': 'EVEX.M6',
        'XMAP8': 'XOP.8', 'XMAP9': 'XOP.9', 'XMAPA': 'XOP.A'}
PP = {'VNP': 'NP', 'V66': '66', 'VF3': 'F3', 'VF2': 'F2'}
VL = {'VL128': 16, 'VL256': 32, 'VL512': 64}
REGW = {'XMM': 16, 'YMM': 32, 'ZMM': 64}
ESIZE = {'ESIZE_8_BITS()': 1, 'ESIZE_16_BITS()': 2, 'ESIZE_32_BITS()': 4, 'ESIZE_64_BITS()': 8}
# A scalar memory operand's size, as our tables name it inside an xmm.
SCALAR = {1: 'b', 2: 'w', 4: 'd', 8: 'mm'}


def records(path):
    """XED's instruction records, one per PATTERN (older files give a record
    several PATTERN/OPERANDS pairs)."""
    cur = None
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if line == '{':
            cur = {'pairs': []}
        elif line == '}':
            for pattern, operands in (cur or {}).get('pairs', []):
                tokens = pattern.split()
                # (Outside 64-bit mode W is ignored; the 64-bit records say all.)
                if tokens and tokens[0] in ('EVV', 'XOPV') and 'not64' not in tokens:
                    r = {k: v for k, v in cur.items() if k != 'pairs'}
                    r['PATTERN'] = pattern
                    r['OPERANDS'] = operands
                    yield r
            cur = None
        elif cur is not None and ':' in line and not line.startswith('#'):
            k, v = line.split(':', 1)
            k, v = k.strip(), v.strip()
            if k == 'PATTERN':
                cur['pairs'].append([v, ''])
            elif k == 'OPERANDS' and cur['pairs']:
                cur['pairs'][-1][1] = v
            else:
                cur[k] = v


def ratio_code(width, vl):
    """Our size code for a register `width` bytes wide at vector length `vl`."""
    return {1: 'x', 2: 'h', 4: 'q4', 8: 'e8'}.get(vl // width) if width <= vl else None


class Skip(Exception):
    pass


def group_key(r):
    p = r['PATTERN'].split()
    opcode = next(t for t in p if t.startswith('0x'))
    mp = next(t for t in p if t in MAPS)
    pp = next(t for t in p if t in PP)
    reg = next((t for t in p if t.startswith('REG[0b')), '')
    w = 'W1' if 'W1' in p else 'W0' if 'W0' in p else ''
    return (r['ICLASS'], mp, opcode, pp, reg, w)


def operand_list(r):
    out = []
    for o in r.get('OPERANDS', '').split():
        if 'SUPP' in o:
            continue
        out.append(o)
    return out


MEMSIZE = {'b': 'b', 'wrd': 'w', 'd': 'd', 'q': 'q', 'dq': 'dq', 'qq': 'qq', 'zd': 'zz', 'zv': 'zz'}
NELEM_CODE = {'NELEM_FULL()': 'x', 'NELEM_FULLMEM()': 'x', 'NELEM_HALF()': 'h', 'NELEM_HALFMEM()': 'h',
              'NELEM_QUARTER()': 'q4', 'NELEM_QUARTERMEM()': 'q4', 'NELEM_EIGHTHMEM()': 'e8'}
TUPLES = {
    'NELEM_FULL()': ('fv', 'fvm'),
    'NELEM_HALF()': ('hv', 'hvm'),
    'NELEM_QUARTER()': ('qv', 'qvm'),
    'NELEM_EIGHTHMEM()': ('ovm', 'ovm'),
    'NELEM_HALFMEM()': ('hvm', 'hvm'),
    'NELEM_QUARTERMEM()': ('qvm', 'qvm'),
    'NELEM_FULLMEM()': ('fvm', 'fvm'),
    'NELEM_ONE()': ('t1s', 't1s'),
    'NELEM_SCALAR()': ('t1s', 't1s'),
    'NELEM_MEM128()': ('m128', 'm128'),
}


def width_of(p):
    return max([VL[t] for t in p if t in VL] or [16])


def ops_of(rec, gpry, lig, l0):
    """The operands of one record, with placeholders ('@B', code, kind) for
    a ModRM.rm register and ('@M', size) for memory; and its masking."""
    vl = width_of(rec['PATTERN'].split())
    mask = None
    ops = []
    for o in operand_list(rec):
        name = o.split('=')[1].split(':')[0].replace('()', '') if '=' in o else o.split(':')[0]
        if name == 'MASK1':
            mask = 'kz' if 'ZEROSTR' in o else 'k'
            continue
        if o.startswith('IMM0'):
            ops.append('Id' if o.split(':')[2] == 'd' else 'Ib')
            continue
        if o.startswith('MEM0'):
            ops.append(('@M', o.split(':')[2]))
            continue
        m = re.match(r'(XMM|YMM|ZMM)_(R3|N3|B3|R|N|B|SE)$', name)
        if m:
            width = REGW[m.group(1)]
            code = 'dq' if lig or (l0 and width == 16) else ratio_code(width, vl)
            if code is None:
                raise Skip('register width %s at VL %d' % (name, vl))
            role = m.group(2).rstrip('3')
            if role == 'B':
                ops.append(('@B', code, 'vec'))
            else:
                ops.append({'R': 'V', 'N': 'H', 'SE': 'L'}[role] + code)
            continue
        m = re.match(r'V?GPR(32|64|y)_(R|B|N)$', name)
        if m:
            size = 'y' if gpry or m.group(1) == 'y' else {'32': 'd', '64': 'q'}[m.group(1)]
            if m.group(2) == 'B':
                ops.append(('@B', size, 'gpr'))
            else:
                ops.append({'R': 'G', 'N': 'B'}[m.group(2)] + size)
            continue
        if name == 'MASK_R':
            ops.append('KG')
            continue
        if name == 'MASK_B':
            ops.append(('@B', '', 'mask'))
            continue
        raise Skip('operand ' + name)
    return ops, mask


def finish(ops, scalar, nelem):
    """Placeholders to table operands."""
    out = []
    for o in ops:
        if isinstance(o, str):
            out.append(o)
        elif o[0] == 'merged':
            _, code, kind, msize = o
            if kind == 'gpr':
                out.append('E' + code + (':' + msize if msize and msize != code else ''))
            elif kind == 'mask':
                out.append('KW' + (':' + msize if msize else ''))
            elif scalar:
                out.append('W%s:%s' % (code, scalar))
            elif nelem in NELEM_CODE and NELEM_CODE[nelem] != code:
                out.append('W%s:%s' % (code, NELEM_CODE[nelem]))
            else:
                out.append('W' + code)
        elif o[0] == '@B':
            out.append({'vec': 'U', 'gpr': 'R', 'mask': 'KE'}[o[2]] + o[1])
        elif o[0] == '@M':
            if nelem in NELEM_CODE and (o[1] == 'vv' or o[1].startswith('z')):
                out.append('M' + NELEM_CODE[nelem])
            elif o[1] in MEMSIZE:
                out.append('M' + MEMSIZE[o[1]])
            else:
                raise Skip('memory size ' + o[1])
    return out


def convert(key, recs):
    """Table lines for a group: one, or a register and a memory line."""
    iclass, mp, opcode, pp, reg, w = key
    pats = [r['PATTERN'].split() for r in recs]
    attrs = set()
    for r in recs:
        attrs.update(r.get('ATTRIBUTES', '').split())
    lig = any('FIX_ROUND_LEN128()' in p for p in pats) and not any(v in p for p in pats for v in VL)
    vls = sorted({VL[t] for p in pats for t in p if t in VL})
    l0 = vls == [16]
    er = any('AVX512_ROUND()' in p for p in pats)
    sae = any('SAE()' in p for p in pats)
    reg_recs = [r for r, p in zip(recs, pats) if 'MOD=3' in p and 'BCRC=1' not in p]
    mem_recs = [r for r, p in zip(recs, pats) if 'MOD!=3' in p]

    def widest(rs):
        return max(rs, key=lambda r: width_of(r['PATTERN'].split())) if rs else None

    rreg, rmem = widest(reg_recs), widest(mem_recs)
    mpat = rmem['PATTERN'].split() if rmem else []
    nelem = next((t for t in mpat if t.startswith('NELEM')), None)
    esize = next((ESIZE[t] for t in mpat if t in ESIZE), 0)
    scalar = SCALAR.get(esize) if lig or nelem in ('NELEM_ONE()', 'NELEM_SCALAR()') else None
    gpry = w == '' and any('GPR64' in r.get('OPERANDS', '') for r in recs)
    reg_ops, rmask = ops_of(rreg, gpry, lig, l0) if rreg else (None, None)
    mem_ops, mmask = ops_of(rmem, gpry, lig, l0) if rmem else (None, None)
    # Merge the forms when only rm differs (a register, or memory).
    xop_scalar = [None]
    merged = None
    if reg_ops is not None and mem_ops is not None and len(reg_ops) == len(mem_ops):
        merged = []
        for a, b in zip(reg_ops, mem_ops):
            if a == b:
                merged.append(a)
            elif isinstance(a, tuple) and a[0] == '@B' and isinstance(b, tuple) and b[0] == '@M':
                msize = MEMSIZE.get(b[1], '') if a[2] == 'mask' or a[2] == 'gpr' and not gpry else ''
                # (A scalar in an xmm register: its memory size, as ours name it.)
                if a[2] == 'vec' and b[1] in ('d', 'q') and not scalar:
                    merged.append(('merged', a[1], a[2], ''))
                    xop_scalar[0] = SCALAR[{'d': 4, 'q': 8}[b[1]]]
                    continue
                merged.append(('merged', a[1], a[2], msize))
            else:
                merged = None
                break
    scalar = scalar or xop_scalar[0]
    tuple_ = None
    if rmem and 'EVV' in mpat:
        if nelem not in TUPLES:
            raise Skip('tuple ' + str(nelem))
        tuple_ = TUPLES[nelem][0 if 'BROADCAST_ENABLED' in attrs else 1]
    forms = []
    if merged is not None:
        forms.append(('/r', finish(merged, scalar, nelem)))
    else:
        if reg_ops is not None:
            forms.append(('reg', finish(reg_ops, scalar, nelem)))
        if mem_ops is not None:
            forms.append(('mem', finish(mem_ops, scalar, nelem)))
    lines = []
    for form, ops in forms:
        memory = form != 'reg'
        head = [MAPS[mp], opcode[2:].upper(), PP[pp]]
        if reg:
            head.append('/' + str(int(reg[6:-1], 2)))
        if form != '/r' or not reg:
            head.append(form)
        if lig:
            pass
        elif vls == [16]:
            head.append('L0')
        elif vls == [64]:
            head.append('L2')
        elif vls not in ([16, 32, 64], []):
            head.extend('L%d' % {16: 0, 32: 1, 64: 2}[v] for v in vls)
        if w:
            head.append(w)
        tail = []
        mask = {'reg': rmask, 'mem': mmask}.get(form) or rmask or mmask
        if mask:
            tail.append(mask)
        # Zeroing in the register form only: a store.
        if form == '/r' and rmask == 'kz' and mmask == 'k':
            tail.append('store')
        if 'BROADCAST_ENABLED' in attrs and memory:
            tail.append('bcst')
        if er and form != 'mem':
            tail.append('er')
        elif sae and form != 'mem':
            tail.append('sae')
        if tuple_ and memory:
            t = tuple_
            gpr_mem = any(o.startswith('E') for o in ops)
            if t == 't1s' and w == '' and not gpr_mem and any(o.startswith('G') for o in ops):
                t = 't1f'  # to a GPR whose width W sets; the element is fixed
            tail.append('t:' + t)
            if t == 't1s' and gpr_mem and gpry:
                tail.append('ew')
            elif esize and t in ('fv', 'hv', 'qv', 't1s', 't1f'):
                tail.append('e%d' % esize)
        if lig:
            tail.append('LIG')
        name = {'bextr_xop': 'bextr'}.get(iclass.lower(), iclass.lower())
        line = '%s : %s %s' % (' '.join(head), name, ','.join(ops))
        if tail:
            line += ' ; ' + ' '.join(tail)
        lines.append(line)
    return lines


def existing(tables):
    have = set()
    for path in tables:
        for line in open(path, encoding='utf-8'):
            line = line.split('#')[0].strip()
            if not line.startswith('EVEX.') or ':' not in line:
                continue
            enc = line.split(':')[0].split()
            reg = next((t for t in enc if re.fullmatch(r'/[0-7]', t)), '')
            w = next((t for t in enc if t in ('W0', 'W1')), '')
            pp = next((t for t in enc if t in ('NP', '66', 'F3', 'F2')), '')
            have.add((enc[0], enc[1], pp, reg, w))
    return have


def main():
    args = sys.argv[1:]
    tables = []
    while args and args[0] == '--skip':
        tables.append(args[1])
        args = args[2:]
    have = existing(tables)
    printed = set()
    groups = OrderedDict()
    for path in args:
        for r in records(path):
            try:
                groups.setdefault(group_key(r), []).append(r)
            except StopIteration:
                print('# skipped (no map/opcode): %s' % r['ICLASS'], file=sys.stderr)
    # Merge W0/W1 groups that differ only in a GPR's width (Gy/Ey).
    for key, recs in groups.items():
        iclass, mp, opcode, pp, reg, w = key
        regcode = '/' + str(int(reg[6:-1], 2)) if reg else ''
        if (MAPS[mp], opcode[2:].upper(), PP[pp], regcode, w) in have or \
                (MAPS[mp], opcode[2:].upper(), PP[pp], regcode, '') in have:
            continue
        gpr = any(re.search(r'GPR(32|64)_', r.get('OPERANDS', '')) for r in recs)
        other = (iclass, mp, opcode, pp, reg, 'W1' if w == 'W0' else 'W0')
        if gpr and w == 'W1' and other in groups:
            continue  # emitted with its W0 twin, as Gy/Ey
        if gpr and w == 'W0' and other in groups:
            key = (iclass, mp, opcode, pp, reg, '')
            recs = recs + groups[other]
        try:
            for line in convert(key, recs):
                if line not in printed:
                    printed.add(line)
                    print(line)
        except Skip as e:
            print('# skipped %s %s %s %s: %s' % (iclass, mp, opcode, pp, e), file=sys.stderr)


if __name__ == '__main__':
    main()

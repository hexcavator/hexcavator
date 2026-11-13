#![allow(clippy::cast_possible_truncation)]

//! Compiles the opcode tables in `tables/*.txt` into Rust.
//!
//! # Table syntax
//!
//! One instruction form per line; `#` starts a comment.
//!
//! ```text
//! <encoding> : <mnemonic> [<operand>,<operand>,...] [; <attribute>...]
//! ```
//!
//! The encoding is a map (omitted for the one-byte map; `0F`, `0F38`,
//! `0F3A`, `3DNOW`, `VEX.0F`, ..., `EVEX.M6`, `XOP.8`, ...), an opcode byte
//! (`B8+r` for eight consecutive opcodes with a register in the low bits),
//! and constraints:
//!
//! | token | meaning |
//! |---|---|
//! | `NP` `66` `F3` `F2` | mandatory prefix (VEX/EVEX: `pp`) |
//! | `/r` | has a ModRM byte |
//! | `/0`..`/7` | ModRM.reg must be this value |
//! | `!XX` | the ModRM byte must be exactly XX |
//! | `mem` `reg` | memory or register form only |
//! | `W0` `W1` | REX.W / VEX.W / EVEX.W |
//! | `L0` `L1` `L2` `LIG` | vector length (several may be given) |
//! | `o64` `i64` | only in, or invalid in, 64-bit mode |
//! | `os16` `os32` `os64` | operand size |
//! | `as16` `as32` `as64` | address size |
//!
//! Operands follow the notation of the Intel SDM, Volume 2, Appendix A,
//! extended so that sizes are explicit; see `operand()` below.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

const MAPS: &[(&str, usize)] = &[
    ("0F", 1),
    ("0F38", 2),
    ("0F3A", 3),
    ("3DNOW", 4),
    ("VEX.0F", 5),
    ("VEX.0F38", 6),
    ("VEX.0F3A", 7),
    ("EVEX.0F", 8),
    ("EVEX.0F38", 9),
    ("EVEX.0F3A", 10),
    ("EVEX.M4", 11),
    ("EVEX.M5", 12),
    ("EVEX.M6", 13),
    ("XOP.8", 14),
    ("XOP.9", 15),
    ("XOP.A", 16),
    ("EVEX.M7", 17),
    ("VEX.M7", 18),
    ("VEX.M5", 19),
];
const MAP_COUNT: usize = 20;
const EVEX_M4: usize = 11;
const EVEX_M7: usize = 17;

#[derive(Clone)]
struct Form {
    map: usize,
    opcode: u8,
    plus_r: bool,
    modrm: bool,
    pfx: u8,
    reg: u8,
    rm: u8,
    md: u8,
    w: u8,
    l: u8,
    mode: u8,
    os: u8,
    asz: u8,
    mnemonic: String,
    ops: Vec<String>,
    /// The operands as written.
    raw_ops: Vec<String>,
    attrs: Vec<&'static str>,
    tuple: &'static str,
    elem: u8,
    /// APX: allowed ND and NF values (bit masks), and the CCMP/CTEST
    /// condition (0xFF: none).
    nd: u8,
    nf: u8,
    scc: u8,
    origin: String,
}

impl Form {
    /// More specific forms are tried first.
    fn specificity(&self) -> u32 {
        let mut s = 0;
        if self.rm != 0xFF {
            s += 100;
        }
        if self.reg != 0xFF {
            s += 50;
        }
        if self.md != 0 {
            s += 20;
        }
        if self.pfx != 0 {
            s += 10;
        }
        for mask in [
            self.w != 3,
            self.l != 15,
            self.os != 7,
            self.asz != 7,
            self.mode != 0,
        ] {
            if mask {
                s += 5;
            }
        }
        s
    }
}

fn size_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "n" => "None",
        "b" => "B",
        "w" => "W",
        "d" => "D",
        "q" => "Q",
        "mm" => "Mm",
        "o" => "O",
        "dq" => "X",
        "qq" => "Y",
        "zz" => "Z",
        "t" => "T",
        "f" => "F",
        "v" => "V",
        "z" => "Z4",
        "y" => "Yw",
        "p" => "P",
        "x" => "Vl",
        "h" => "VlHalf",
        "q4" => "VlQuarter",
        "e8" => "VlEighth",
        "a" => "A",
        "pr" => "Pair",
        "zw" => "Zw",
        "tile" => "Tile",
        _ => return None,
    })
}

fn spec(loc: &str, size: &str, msize: &str, fixed: u16) -> String {
    format!(
        "OpSpec {{ loc: Loc::{loc}, size: Size::{size}, msize: Size::{msize}, fixed: {fixed} }}"
    )
}

/// Register classes, matching `RegClass` in src/register.rs.
fn fixed_register(name: &str) -> Option<u16> {
    const GPR8: [&str; 8] = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"];
    const HIGH8: [&str; 4] = ["ah", "ch", "dh", "bh"];
    const GPR16: [&str; 8] = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"];
    const GPR32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    const GPR64: [&str; 8] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
    const SEG: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];
    let lists: [(&[&str], u16); 6] = [
        (&GPR8, 0),
        (&HIGH8, 1),
        (&GPR16, 2),
        (&GPR32, 3),
        (&GPR64, 4),
        (&SEG, 5),
    ];
    for (list, class) in lists {
        if let Some(i) = list.iter().position(|&n| n == name) {
            return Some(class << 8 | i as u16);
        }
    }
    match name {
        "st" => Some(8 << 8 | 8),
        "xmm0" => Some(10 << 8),
        _ => None,
    }
}

/// Parses an operand token into an `OpSpec` expression.
fn operand(tok: &str) -> Result<String, String> {
    if let Some(fixed) = fixed_register(tok) {
        return Ok(spec("Fixed", "None", "None", fixed));
    }
    const ACC: [&str; 8] = ["rAX", "rCX", "rDX", "rBX", "rSP", "rBP", "rSI", "rDI"];
    if let Some(i) = ACC.iter().position(|&n| n == tok) {
        return Ok(spec("FixedGpr", "V", "None", i as u16));
    }
    let simple = match tok {
        "eAX" => Some(spec("FixedGpr", "Z4", "None", 0)),
        "aAX" => Some(spec("FixedGpr", "A", "None", 0)),
        "aCX" => Some(spec("FixedGpr", "A", "None", 1)),
        "aDX" => Some(spec("FixedGpr", "A", "None", 2)),
        "aBX" => Some(spec("FixedGpr", "A", "None", 3)),
        "XLATb" => Some(spec("Xlat", "A", "B", 0)),
        "STi" => Some(spec("StRm", "None", "None", 0)),
        "Ap" => Some(spec("FarPtr", "P", "None", 0)),
        "Im2z" => Some(spec("Is4Low", "B", "None", 0)),
        "P" => Some(spec("MmxReg", "None", "None", 0)),
        "N" => Some(spec("MmxRmReg", "None", "None", 0)),
        "Sw" => Some(spec("SegReg", "W", "None", 0)),
        "Cd" => Some(spec("CrReg", "None", "None", 0)),
        "Dd" => Some(spec("DrReg", "None", "None", 0)),
        "Td" => Some(spec("TrReg", "None", "None", 0)),
        "KG" => Some(spec("KReg", "None", "None", 0)),
        "KE" => Some(spec("KRmReg", "None", "None", 0)),
        "KH" => Some(spec("KVvvv", "None", "None", 0)),
        "TG" => Some(spec("TmmReg", "None", "None", 0)),
        "TE" => Some(spec("TmmRmReg", "None", "None", 0)),
        "TH" => Some(spec("TmmVvvv", "None", "None", 0)),
        "BNDG" => Some(spec("BndReg", "None", "None", 0)),
        "M" => Some(spec("Mem", "None", "None", 0)),
        "Jabs" => Some(spec("Abs64", "Q", "None", 0)),
        _ => None,
    };
    if let Some(s) = simple {
        return Ok(s);
    }
    // A small constant operand (`1` for shifts, `3` for `int 3`).
    if let Ok(value) = tok.parse::<u16>() {
        return Ok(spec("One", "B", "None", value));
    }
    let err = || format!("unknown operand '{tok}'");
    // Tokens with an explicit memory size: X<size>:<msize>.
    let (head, msize) = match tok.split_once(':') {
        Some((h, m)) => (h, Some(size_code(m).ok_or_else(err)?)),
        None => (tok, None),
    };
    for (prefix, loc) in [("BNDE", "BndRm"), ("KW", "KRm"), ("VS", "Vsib")] {
        if let Some(code) = head.strip_prefix(prefix) {
            let size = if code.is_empty() {
                "None"
            } else {
                size_code(code).ok_or_else(err)?
            };
            return Ok(spec(loc, size, msize.unwrap_or(size), 0));
        }
    }
    if head == "Q" {
        return Ok(spec("MmxRm", "None", msize.unwrap_or("Mm"), 0));
    }
    let (first, code) = head.split_at(1);
    // Special immediates.
    match head {
        "Ibs" => return Ok(spec("ImmSx8", "B", "None", 0)),
        "Izs" => return Ok(spec("ImmSx", "Z4", "None", 0)),
        _ => {}
    }
    let size = size_code(code).ok_or_else(err)?;
    let m = msize.unwrap_or(size);
    Ok(match first {
        "E" => spec("GprRm", size, m, 0),
        "R" => spec("GprRmReg", size, "None", 0),
        "M" => spec("Mem", "None", size, 0),
        "G" => spec("GprReg", size, "None", 0),
        "B" => spec("GprVvvv", size, "None", 0),
        "Z" => spec("GprOpcode", size, "None", 0),
        "I" => spec("Imm", size, "None", 0),
        "J" => spec("Rel", size, "None", 0),
        "O" => spec("Moffs", "A", size, 0),
        "X" => spec("StrSrc", "A", size, 0),
        "Y" => spec("StrDst", "A", size, 0),
        "V" => spec("VecReg", size, "None", 0),
        "H" => spec("VecVvvv", size, "None", 0),
        "U" => spec("VecRmReg", size, "None", 0),
        "W" => spec("VecRm", size, m, 0),
        "L" => spec("VecIs4", size, "None", 0),
        _ => return Err(err()),
    })
}

fn parse_line(line: &str, origin: String) -> Result<Vec<Form>, String> {
    let (encoding, rest) = line.split_once(':').ok_or("missing ':'")?;
    let (inst, attrs) = match rest.split_once(';') {
        Some((i, a)) => (i, a),
        None => (rest, ""),
    };
    let mut form = Form {
        map: 0,
        opcode: 0,
        plus_r: false,
        modrm: false,
        pfx: 0,
        reg: 0xFF,
        rm: 0xFF,
        md: 0,
        w: 3,
        l: 0,
        mode: 0,
        os: 0,
        asz: 0,
        mnemonic: String::new(),
        ops: Vec::new(),
        raw_ops: Vec::new(),
        attrs: Vec::new(),
        tuple: "None",
        elem: 0,
        nd: 0,
        nf: 0,
        scc: 0xFF,
        origin,
    };
    // Expansions: `NP66` (both, 66 setting a 16-bit operand size), `SCC`
    // (each of the 16 conditions), `ndd` (with and without a new data
    // destination).
    let mut np66 = false;
    let mut scc = false;

    let mut tokens = encoding.split_whitespace().peekable();
    if let Some(&first) = tokens.peek()
        && let Some(&(_, m)) = MAPS.iter().find(|(name, _)| *name == first)
    {
        form.map = m;
        tokens.next();
    }
    let opcode = tokens.next().ok_or("missing opcode")?;
    let (hex, plus_r) = match opcode.strip_suffix("+r") {
        Some(h) => (h, true),
        None => (opcode, false),
    };
    form.opcode = u8::from_str_radix(hex, 16).map_err(|_| format!("bad opcode '{opcode}'"))?;
    form.plus_r = plus_r;
    for tok in tokens {
        match tok {
            "NP" => form.pfx = 1,
            "66" => form.pfx = 2,
            "F3" => form.pfx = 3,
            "F2" => form.pfx = 4,
            "/r" => form.modrm = true,
            "mem" => {
                form.modrm = true;
                form.md = 1;
            }
            "reg" => {
                form.modrm = true;
                form.md = 2;
            }
            "NP66" => np66 = true,
            "SCC" => scc = true,
            "ND0" => form.nd |= 1,
            "ND1" => form.nd |= 2,
            "NF0" => form.nf |= 1,
            "NF1" => form.nf |= 2,
            "rex2" => form.attrs.push("REX2"),
            "W0" => form.w = 1,
            "W1" => form.w = 2,
            "WIG" => form.w = 3,
            "L0" => form.l |= 1,
            "L1" => form.l |= 2,
            "L2" => form.l |= 4,
            "LIG" => {
                form.l = 15;
                form.attrs.push("LIG");
            }
            "o64" => form.mode = 1,
            "i64" => form.mode = 2,
            "os16" => form.os |= 1,
            "os32" => form.os |= 2,
            "os64" => form.os |= 4,
            "as16" => form.asz |= 1,
            "as32" => form.asz |= 2,
            "as64" => form.asz |= 4,
            _ if tok.len() == 2 && tok.starts_with('/') => {
                form.modrm = true;
                form.reg = tok[1..].parse().map_err(|_| format!("bad token '{tok}'"))?;
            }
            _ if tok.starts_with('!') => {
                let byte =
                    u8::from_str_radix(&tok[1..], 16).map_err(|_| format!("bad token '{tok}'"))?;
                form.modrm = true;
                form.md = 2;
                form.reg = (byte >> 3) & 7;
                form.rm = byte & 7;
                if byte < 0xC0 {
                    return Err(format!("'{tok}' is not a register-form ModRM"));
                }
            }
            _ => return Err(format!("unknown encoding token '{tok}'")),
        }
    }
    if form.l == 0 {
        form.l = 15;
    }
    if form.os == 0 {
        form.os = 7;
    }
    if form.asz == 0 {
        form.asz = 7;
    }
    // 3DNow! instructions all have a ModRM byte; the opcode is a suffix.
    if form.map == 4 {
        form.modrm = true;
        form.attrs.push("SUFFIX");
    }

    let mut parts = inst.split_whitespace();
    form.mnemonic = parts.next().ok_or("missing mnemonic")?.to_string();
    if let Some(ops) = parts.next() {
        form.ops = ops.split(',').map(operand).collect::<Result<_, _>>()?;
        form.raw_ops = ops.split(',').map(str::to_string).collect();
    }
    if parts.next().is_some() {
        return Err("operands must not contain spaces".to_string());
    }
    if form.ops.len() > 5 {
        return Err("too many operands".to_string());
    }

    for attr in attrs.split_whitespace() {
        let name = match attr {
            "lock" => "LOCK",
            "rep" => "REP",
            "repe" => "REPE",
            "d64" => "D64",
            "f64" => "F64",
            "k" => "MASK",
            "kz" => {
                form.attrs.push("MASK");
                "ZERO"
            }
            "kr" => {
                form.attrs.push("MASK");
                "MASK_REQ"
            }
            "bcst" => "BCST",
            "er" => {
                form.attrs.push("SAE");
                "ER"
            }
            "sae" => "SAE",
            "os16" => "OS16",
            "no66" => "NO66",
            "noos16" => "NO_OS16",
            "os66" => "OS66",
            "vexpfx" => "VEX_PREFIX",
            "LIG" => {
                form.l = 15;
                "LIG"
            }
            "bnd" => "BND",
            "apx" => "APX",
            "nf" => "NF",
            "evex" => "EVEX_PROMOTED",
            "evexv" => "EVEX_VEX",
            "norsp" => "NORSP",
            "ndd" => "NDD",
            "hle" => "HLE",
            "novvvv" => "NOVVVV",
            "cmp" => "CMP_PSEUDO",
            "ew" => "ELEM_W",
            "store" => "STORE",
            "e1" | "e2" | "e4" | "e8" => {
                form.elem = attr[1..].parse().unwrap();
                continue;
            }
            _ if attr.starts_with("t:") => {
                form.tuple = match &attr[2..] {
                    "fv" => "Fv",
                    "hv" => "Hv",
                    "fvm" => "Fvm",
                    "hvm" => "Hvm",
                    "qvm" => "Qvm",
                    "qv" => "Qv",
                    "ovm" => "Ovm",
                    "t1s" => "T1s",
                    "t1f" => "T1f",
                    "t2" => "T2",
                    "t4" => "T4",
                    "t8" => "T8",
                    "m128" => "M128",
                    "dup" => "Dup",
                    other => return Err(format!("unknown tuple type '{other}'")),
                };
                continue;
            }
            _ => return Err(format!("unknown attribute '{attr}'")),
        };
        form.attrs.push(name);
    }

    let apx = form.map == EVEX_M4 || form.map == EVEX_M7 || form.attrs.contains(&"APX");
    if apx {
        if !form.attrs.contains(&"APX") {
            form.attrs.push("APX");
        }
        // APX promotions are all L'L = 0.
        form.l = 1;
        if form.nd == 0 {
            form.nd = 1;
        }
        if form.nf == 0 {
            form.nf = if form.attrs.contains(&"NF") { 3 } else { 1 };
        }
    } else if form.nd != 0 || form.nf != 0 || scc || form.attrs.contains(&"NDD") {
        return Err("ND/NF/SCC/ndd are for APX forms".to_string());
    }
    let mut stage = vec![form];
    if np66 {
        stage = stage
            .into_iter()
            .flat_map(|f| {
                let mut f66 = f.clone();
                f66.pfx = 2;
                f66.attrs.push("OS66");
                let mut np = f;
                np.pfx = 1;
                [np, f66]
            })
            .collect();
    }
    if stage[0].attrs.contains(&"NDD") {
        stage = stage
            .into_iter()
            .flat_map(|mut f| {
                f.attrs.retain(|a| *a != "NDD");
                let mut nd = f.clone();
                nd.nd = 2;
                nd.attrs
                    .retain(|a| *a != "EVEX_PROMOTED" && *a != "EVEX_VEX");
                // The destination is EVEX.vvvv, as wide as the first operand.
                let first = nd.raw_ops.first().cloned().unwrap_or_default();
                let size = first.get(1..).unwrap_or("").split(':').next().unwrap_or("");
                let dest = format!("B{size}");
                nd.ops.insert(0, operand(&dest).unwrap_or_default());
                nd.raw_ops.insert(0, dest);
                f.nd = 1;
                [f, nd]
            })
            .collect();
    }
    if scc {
        const CC: [&str; 16] = [
            "o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "t", "f", "l", "ge", "le", "g",
        ];
        stage = stage
            .into_iter()
            .flat_map(|f| {
                (0..16u8).map(move |c| {
                    let mut g = f.clone();
                    g.scc = c;
                    g.mnemonic = g.mnemonic.replace("$cc", CC[usize::from(c)]);
                    if !g.attrs.contains(&"SCC") {
                        g.attrs.push("SCC");
                    }
                    g
                })
            })
            .collect();
    }
    let mut forms = Vec::new();
    for form in stage {
        if form.plus_r {
            for i in 0..8u8 {
                let mut f = form.clone();
                f.opcode = form.opcode.checked_add(i).ok_or("+r opcode overflows")?;
                forms.push(f);
            }
        } else {
            forms.push(form);
        }
    }
    Ok(forms)
}

fn variant(mnemonic: &str) -> String {
    let mut s = String::new();
    for (i, c) in mnemonic.chars().enumerate() {
        if i == 0 {
            s.extend(c.to_uppercase());
        } else if c.is_ascii_alphanumeric() {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    s
}

fn main() {
    let dir = Path::new("tables");
    println!("cargo:rerun-if-changed=tables");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("tables directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();

    let mut forms = Vec::new();
    let mut errors = Vec::new();
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
        let text = std::fs::read_to_string(file).unwrap();
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let origin = format!("{name}:{}", n + 1);
            match parse_line(line, origin.clone()) {
                Ok(f) => forms.extend(f),
                Err(e) => errors.push(format!("{origin}: {e}: {line}")),
            }
        }
    }

    // Group by (map, opcode) and check ModRM consistency.
    let mut groups: Vec<Vec<usize>> = vec![Vec::new(); MAP_COUNT * 256];
    for (i, f) in forms.iter().enumerate() {
        groups[f.map * 256 + usize::from(f.opcode)].push(i);
    }
    // Whether a ModRM byte follows, per mandatory prefix (bit n set for
    // prefix selector n: 1 = none, 2 = 66, 3 = F3, 4 = F2).
    let mut has_modrm = vec![[0u8; 256]; MAP_COUNT];
    for (key, members) in groups.iter_mut().enumerate() {
        if members.is_empty() {
            continue;
        }
        for pfx in 1..=4u8 {
            let applicable: Vec<usize> = members
                .iter()
                .copied()
                .filter(|&i| forms[i].pfx == 0 || forms[i].pfx == pfx)
                .collect();
            let with = applicable.iter().filter(|&&i| forms[i].modrm).count();
            if with != 0 && with != applicable.len() {
                let origins: Vec<_> = applicable
                    .iter()
                    .map(|&i| forms[i].origin.as_str())
                    .collect();
                errors.push(format!(
                    "map {} opcode {:02X}: mixed ModRM usage at {origins:?}",
                    key / 256,
                    key % 256
                ));
            }
            if with != 0 {
                has_modrm[key / 256][key % 256] |= 1 << pfx;
            }
        }
        members.sort_by_key(|&i| std::cmp::Reverse(forms[i].specificity()));
    }
    if !errors.is_empty() {
        for e in &errors {
            println!("cargo:warning={e}");
        }
        panic!("{} error(s) in opcode tables", errors.len());
    }

    let mnemonics: BTreeSet<&str> = forms.iter().map(|f| f.mnemonic.as_str()).collect();
    let mut out = String::new();
    out.push_str("// Generated by build.rs from tables/*.txt. Do not edit.\n\n");
    out.push_str("/// An instruction mnemonic.\n");
    out.push_str("#[allow(missing_docs)]\n#[repr(u16)]\n");
    out.push_str("#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]\n");
    out.push_str("pub enum Mnemonic {\n    Invalid,\n");
    for m in &mnemonics {
        writeln!(out, "    {},", variant(m)).unwrap();
    }
    out.push_str("}\n\n");
    writeln!(
        out,
        "static MNEMONIC_NAMES: [&str; {}] = [\n    \"(bad)\",",
        mnemonics.len() + 1
    )
    .unwrap();
    for m in &mnemonics {
        writeln!(out, "    {m:?},").unwrap();
    }
    out.push_str("];\n\n");

    let ordered: Vec<usize> = groups.iter().flatten().copied().collect();
    writeln!(
        out,
        "pub(crate) static ENTRIES: [Entry; {}] = [",
        ordered.len()
    )
    .unwrap();
    for &i in &ordered {
        let f = &forms[i];
        let mut ops: Vec<String> = f.ops.clone();
        while ops.len() < 5 {
            ops.push("OpSpec::NONE".to_string());
        }
        let attrs = if f.attrs.is_empty() {
            "0".to_string()
        } else {
            f.attrs
                .iter()
                .map(|a| format!("attr::{a}"))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        writeln!(
            out,
            "    // {}\n    Entry {{ mnemonic: Mnemonic::{}, ops: [{}], pfx: {}, reg: {}, rm: {}, md: {}, w: {}, l: {}, mode: {}, os: {}, asz: {}, attrs: {attrs}, tuple: Tuple::{}, elem: {}, nd: {}, nf: {}, scc: {} }},",
            f.origin,
            variant(&f.mnemonic),
            ops.join(", "),
            f.pfx,
            f.reg,
            f.rm,
            f.md,
            f.w,
            f.l,
            f.mode,
            f.os,
            f.asz,
            f.tuple,
            f.elem,
            f.nd,
            f.nf,
            f.scc
        )
        .unwrap();
    }
    out.push_str("];\n\n");

    writeln!(
        out,
        "pub(crate) static INDEX: [[(u16, u8); 256]; {MAP_COUNT}] = ["
    )
    .unwrap();
    let mut start = 0usize;
    for map in 0..MAP_COUNT {
        out.push_str("    [");
        for op in 0..256 {
            let n = groups[map * 256 + op].len();
            write!(out, "({start}, {n}),").unwrap();
            start += n;
        }
        out.push_str("],\n");
    }
    out.push_str("];\n\n");
    writeln!(
        out,
        "pub(crate) static HAS_MODRM: [[u8; 256]; {MAP_COUNT}] = {has_modrm:?};"
    )
    .unwrap();

    let out_path = Path::new(&std::env::var("OUT_DIR").unwrap()).join("tables.rs");
    std::fs::write(out_path, out).unwrap();
}

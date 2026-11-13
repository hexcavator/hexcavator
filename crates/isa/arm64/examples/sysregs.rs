//! Extracts AArch64 system register names and encodings from ARM's
//! machine-readable specification (AARCHMRS `Registers.json`, BSD
//! licensed) into `tables/sysregs.txt`:
//!
//!     cargo run --release -p hexcavator-arm64 --example sysregs -- Registers.json > crates/isa/arm64/tables/sysregs.txt
//!
//! Each line is `op0 op1 CRn CRm op2 NAME` (decimal). Register arrays such
//! as `PMEVCNTR<n>_EL0` are expanded.

use std::collections::BTreeMap;

/// A minimal JSON value.
enum Json {
    Null,
    Bool,
    Num(u32),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn string(&mut self) -> String {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        while self.s[self.i] != b'"' {
            if self.s[self.i] == b'\\' {
                self.i += 1;
                match self.s[self.i] {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        // Not needed for names; keep a placeholder.
                        out.push(b'?');
                        self.i += 4;
                    }
                    c => out.push(c),
                }
            } else {
                out.push(self.s[self.i]);
            }
            self.i += 1;
        }
        self.i += 1;
        String::from_utf8_lossy(&out).into_owned()
    }

    fn value(&mut self) -> Json {
        self.ws();
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut fields = Vec::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b'}' {
                        self.i += 1;
                        break;
                    }
                    let key = self.string();
                    self.ws();
                    self.i += 1; // colon
                    let v = self.value();
                    fields.push((key, v));
                    self.ws();
                    if self.s[self.i] == b',' {
                        self.i += 1;
                    }
                }
                Json::Obj(fields)
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b']' {
                        self.i += 1;
                        break;
                    }
                    items.push(self.value());
                    self.ws();
                    if self.s[self.i] == b',' {
                        self.i += 1;
                    }
                }
                Json::Arr(items)
            }
            b'"' => Json::Str(self.string()),
            b't' | b'f' => {
                self.i += if self.s[self.i] == b't' { 4 } else { 5 };
                Json::Bool
            }
            b'n' => {
                self.i += 4;
                Json::Null
            }
            _ => {
                let start = self.i;
                while self.i < self.s.len() && !matches!(self.s[self.i], b',' | b'}' | b']') {
                    self.i += 1;
                }
                let text = String::from_utf8_lossy(&self.s[start..self.i]);
                Json::Num(text.trim().parse().unwrap_or(0))
            }
        }
    }
}

fn get<'a>(fields: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn str_of(j: Option<&Json>) -> Option<&str> {
    match j {
        Some(Json::Str(s)) => Some(s),
        _ => None,
    }
}

/// A field's value: literal bits and parameter slices, most significant
/// first ("'0':m[1:0]").
fn pieces(v: &str) -> Vec<(Option<String>, String)> {
    v.split(':')
        .scan(String::new(), |pending, p| {
            // Rejoin "m[1:0]" split at its colon.
            if !pending.is_empty() {
                let s = format!("{pending}:{p}");
                pending.clear();
                return Some(Some(s));
            }
            if p.contains('[') && !p.contains(']') {
                *pending = p.to_string();
                return Some(None);
            }
            Some(Some(p.to_string()))
        })
        .flatten()
        .map(|p| {
            if let Some(bits) = p.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
                (None, bits.to_string())
            } else {
                // "m[1:0]" or "n[3]" or "m".
                let (name, sel) = p.split_once('[').unwrap_or((&p, ""));
                (
                    Some(name.to_string()),
                    sel.trim_end_matches(']').to_string(),
                )
            }
        })
        .collect()
}

fn walk(j: &Json, limit: u32, out: &mut BTreeMap<[u32; 5], (bool, String)>) {
    match j {
        Json::Obj(fields) => {
            // An accessor array gives its index range.
            let mut limit = limit;
            if let Some(Json::Arr(ix)) = get(fields, "indexes")
                && let Some(Json::Obj(r)) = ix.first()
                && let (Some(Json::Num(s)), Some(Json::Num(w))) = (get(r, "start"), get(r, "width"))
            {
                limit = s + w;
            }
            if str_of(get(fields, "_type")) == Some("Encoding") {
                record(fields, limit, out);
            }
            for (_, v) in fields {
                walk(v, limit, out);
            }
        }
        Json::Arr(items) => items.iter().for_each(|v| walk(v, limit, out)),
        _ => {}
    }
}

fn record(fields: &[(String, Json)], limit: u32, out: &mut BTreeMap<[u32; 5], (bool, String)>) {
    let Some(name) = str_of(get(fields, "asmvalue")) else {
        return;
    };
    let Some(Json::Obj(enc)) = get(fields, "encodings") else {
        return;
    };
    let keys = ["op0", "op1", "CRn", "CRm", "op2"];
    let mut values = Vec::new();
    for k in keys {
        let Some(Json::Obj(v)) = get(enc, k) else {
            return;
        };
        let Some(text) = str_of(get(v, "value")) else {
            return;
        };
        // "EquationValue": the variable and its slice ("m" with bits 2:0).
        if str_of(get(v, "_type")) == Some("Values.EquationValue") {
            let Some(Json::Arr(slices)) = get(v, "slice") else {
                return;
            };
            let Some(Json::Obj(r)) = slices.first() else {
                return;
            };
            let num = |k| match get(r, k) {
                Some(Json::Num(n)) => *n,
                _ => 0,
            };
            let (start, width) = (num("start"), num("width"));
            values.push(vec![(
                Some(text.to_string()),
                format!("{}:{start}", start + width - 1),
            )]);
            continue;
        }
        values.push(pieces(text));
    }
    // The parameters and their widths (from the slices that use them).
    let mut params: BTreeMap<String, u32> = BTreeMap::new();
    for field in &values {
        for (p, sel) in field {
            if let Some(p) = p {
                let hi: u32 = sel
                    .split(':')
                    .next()
                    .and_then(|h| h.parse().ok())
                    .unwrap_or(0);
                let e = params.entry(p.clone()).or_default();
                *e = (*e).max(hi + 1);
            }
        }
    }
    let total: u32 = params.values().sum();
    if total > 8 {
        return;
    }
    for combo in 0u32..(1 << total) {
        let mut assign: BTreeMap<&str, u32> = BTreeMap::new();
        let mut shift = 0;
        for (p, &w) in &params {
            assign.insert(p, (combo >> shift) & ((1 << w) - 1));
            shift += w;
        }
        let mut nums = [0u32; 5];
        let mut wildcard = false;
        for (i, field) in values.iter().enumerate() {
            let mut v = 0u32;
            for (p, sel) in field {
                match p {
                    None => {
                        for c in sel.chars() {
                            if c == 'x' {
                                wildcard = true;
                            }
                            v = v << 1 | u32::from(c == '1');
                        }
                    }
                    Some(p) => {
                        let value = assign[p.as_str()];
                        let (hi, lo) = match sel.split_once(':') {
                            Some((h, l)) => (h.parse().unwrap_or(0), l.parse().unwrap_or(0)),
                            None => {
                                let b: u32 = sel.parse().unwrap_or(0);
                                (b, b)
                            }
                        };
                        let n = hi - lo + 1;
                        v = v << n | ((value >> lo) & ((1 << n) - 1));
                    }
                }
            }
            nums[i] = v;
        }
        if wildcard || assign.values().any(|&v| v >= limit) {
            continue;
        }
        let mut full = name.to_string();
        for (p, v) in &assign {
            full = full.replace(&format!("<{p}>"), &v.to_string());
        }
        // Plain registers win over array elements at the same encoding.
        let plain = params.is_empty();
        match out.get(&nums) {
            Some((true, _)) => {}
            Some((false, _)) if !plain => {}
            _ => {
                out.insert(nums, (plain, full));
            }
        }
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: sysregs <Registers.json>");
    let data = std::fs::read(path).unwrap();
    let mut p = Parser { s: &data, i: 0 };
    let root = p.value();
    let mut out = BTreeMap::new();
    walk(&root, u32::MAX, &mut out);
    println!("# AArch64 system registers: op0 op1 CRn CRm op2 name.");
    println!("# From ARM's AARCHMRS Registers.json (BSD licensed) by examples/sysregs.");
    for (k, (_, name)) in out {
        println!("{} {} {} {} {} {name}", k[0], k[1], k[2], k[3], k[4]);
    }
}

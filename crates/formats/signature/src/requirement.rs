//! Code requirements (Apple's compiled requirement language), decoded to
//! the text `codesign -d -r-` shows:
//! `designated => identifier "com.example" and anchor apple generic and
//! certificate leaf[subject.OU] = "TEAMID"`.

use std::fmt::Write;

/// The requirements of a requirements set blob (`0xfade0c01`), each as
/// `kind => expression`.
pub fn decode_set(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let count = be32(blob, 8).unwrap_or(0) as usize;
    for i in 0..count.min(16) {
        let (Some(kind), Some(at)) = (be32(blob, 12 + i * 8), be32(blob, 16 + i * 8)) else {
            break;
        };
        let at = at as usize;
        let Some(len) = be32(blob, at + 4) else {
            continue;
        };
        let Some(req) = blob.get(at..at.saturating_add(len as usize)) else {
            continue;
        };
        let name = match kind {
            1 => "host",
            2 => "guest",
            3 => "designated",
            4 => "library",
            5 => "plugin",
            _ => "requirement",
        };
        let text = decode(req).unwrap_or_else(|| "/* unreadable */".into());
        out.push(format!("{name} => {text}"));
    }
    out
}

/// One requirement blob (`0xfade0c00`): its expression.
pub fn decode(req: &[u8]) -> Option<String> {
    if be32(req, 0)? != 0xFADE_0C00 || be32(req, 8)? != 1 {
        return None;
    }
    let mut r = Reader {
        data: req,
        at: 12,
        budget: 4096,
    };
    let mut out = String::new();
    r.expr(&mut out, 0, 0)?;
    Some(out)
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    /// Operations left (a hostile requirement can't run long).
    budget: usize,
}

/// Precedences: or binds loosest, then and, then not.
const OR: u8 = 1;
const AND: u8 = 2;

impl Reader<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = be32(self.data, self.at)?;
        self.at += 4;
        Some(v)
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }

    fn data(&mut self) -> Option<&[u8]> {
        let n = self.u32()? as usize;
        let d = self.data.get(self.at..self.at.checked_add(n)?)?;
        self.at += n.next_multiple_of(4);
        Some(d)
    }

    fn string(&mut self) -> Option<String> {
        self.data().map(quote)
    }

    fn slot(&mut self) -> Option<String> {
        Some(match self.i32()? {
            0 => "leaf".into(),
            -1 => "root".into(),
            n => n.to_string(),
        })
    }

    /// An expression, parenthesized if it binds looser than `context`.
    fn expr(&mut self, out: &mut String, context: u8, depth: usize) -> Option<()> {
        if depth > 64 || self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        // (The high byte holds flags.)
        let op = self.u32()? & 0x00FF_FFFF;
        match op {
            0 => out.push_str("never"),
            1 => out.push_str("always"),
            2 => {
                let s = self.string()?;
                let _ = write!(out, "identifier {s}");
            }
            3 => out.push_str("anchor apple"),
            4 => {
                let slot = self.slot()?;
                let h = self.data()?;
                let _ = write!(out, "certificate {slot} = H\"{}\"", crate::x509::hex(h));
            }
            5 => {
                let k = self.string()?;
                let v = self.string()?;
                let _ = write!(out, "info[{}] = {v}", k.trim_matches('"'));
            }
            6 | 7 => {
                let prec = if op == 6 { AND } else { OR };
                let open = prec < context;
                if open {
                    out.push('(');
                }
                self.expr(out, prec, depth + 1)?;
                out.push_str(if op == 6 { " and " } else { " or " });
                self.expr(out, prec, depth + 1)?;
                if open {
                    out.push(')');
                }
            }
            8 => {
                let h = self.data()?;
                let _ = write!(out, "cdhash H\"{}\"", crate::x509::hex(h));
            }
            9 => {
                out.push_str("! ");
                self.expr(out, 3, depth + 1)?;
            }
            10 => {
                let k = self.data()?.to_vec();
                let _ = write!(out, "info[{}]", String::from_utf8_lossy(&k));
                self.matcher(out)?;
            }
            11 => {
                let slot = self.slot()?;
                let k = self.data()?.to_vec();
                let _ = write!(out, "certificate {slot}[{}]", String::from_utf8_lossy(&k));
                self.matcher(out)?;
            }
            12 => {
                let slot = self.slot()?;
                let _ = write!(out, "certificate {slot} trusted");
            }
            13 => out.push_str("anchor trusted"),
            14 | 17 | 22 => {
                let slot = self.slot()?;
                let o = self.data()?.to_vec();
                let field = match op {
                    14 => "field",
                    17 => "policy",
                    _ => "timestamp",
                };
                let _ = write!(out, "certificate {slot}[{field}.{}]", crate::der::Oid(&o));
                self.matcher(out)?;
            }
            15 => out.push_str("anchor apple generic"),
            16 => {
                let k = self.data()?.to_vec();
                let _ = write!(out, "entitlement[{}]", quote(&k));
                self.matcher(out)?;
            }
            18 => {
                let n = self.data()?.to_vec();
                let _ = write!(out, "anchor apple {}", String::from_utf8_lossy(&n));
            }
            19 => {
                let n = self.data()?.to_vec();
                let _ = write!(out, "({})", String::from_utf8_lossy(&n));
            }
            20 => {
                let p = self.u32()?;
                let _ = write!(out, "platform = {p}");
            }
            21 => out.push_str("notarized"),
            23 => out.push_str("legacy"),
            _ => return None,
        }
        Some(())
    }

    /// A match: what the value is compared with.
    fn matcher(&mut self, out: &mut String) -> Option<()> {
        let m = self.u32()?;
        let (op, takes) = match m {
            0 => (" /* exists */", false),
            1 => (" =", true),
            2 => (" ~", true),
            3 => (" = *", true),
            4 => (" = *", true),
            5 => (" <", true),
            6 => (" >", true),
            7 => (" <=", true),
            8 => (" >=", true),
            9..=13 => (" date", true),
            14 => (" /* absent */", false),
            _ => return None,
        };
        out.push_str(op);
        if takes {
            let v = self.data()?;
            let v = if m == 3 {
                format!("{}*", quote(v).trim_matches('"'))
            } else if m == 4 {
                quote(v).trim_matches('"').to_string()
            } else if (9..=13).contains(&m) {
                String::new()
            } else {
                quote(v)
            };
            let _ = write!(out, " {v}");
        }
        Some(())
    }
}

/// A string as the language writes it (as codesign does): bare if it's
/// a word (letters, digits, underscores; not starting with a digit), else
/// quoted.
fn quote(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if !s.is_empty()
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
    {
        s.into_owned()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(out: &mut Vec<u8>, s: &[u8]) {
        out.extend(u32::try_from(s.len()).unwrap().to_be_bytes());
        out.extend(s);
        out.resize(out.len().next_multiple_of(4), 0);
    }

    #[test]
    fn identifier_and_anchor() {
        // identifier "com.example.x" and anchor apple generic and
        // certificate leaf[subject.OU] = TEAM1
        let mut e = Vec::new();
        e.extend(6u32.to_be_bytes());
        e.extend(6u32.to_be_bytes());
        e.extend(2u32.to_be_bytes());
        data(&mut e, b"com.example.x");
        e.extend(15u32.to_be_bytes());
        e.extend(11u32.to_be_bytes());
        e.extend(0u32.to_be_bytes());
        data(&mut e, b"subject.OU");
        e.extend(1u32.to_be_bytes());
        data(&mut e, b"TEAM1");
        let mut req = Vec::new();
        req.extend(0xFADE_0C00u32.to_be_bytes());
        req.extend(u32::try_from(12 + e.len()).unwrap().to_be_bytes());
        req.extend(1u32.to_be_bytes());
        req.extend(&e);
        assert_eq!(
            decode(&req).unwrap(),
            "identifier \"com.example.x\" and anchor apple generic and certificate leaf[subject.OU] = TEAM1"
        );
        // Truncated: none.
        assert!(decode(&req[..req.len() - 4]).is_none());
    }
}

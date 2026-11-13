//! A small XML reader: elements, attributes and nesting, which is what
//! configuration files such as WPA's stack tags use. Text content,
//! comments, processing instructions and DOCTYPEs are skipped. Entities
//! are the five predefined ones and numeric character references.

/// An element and its children.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Element {
    /// Its name.
    pub name: String,
    /// Its attributes, in order.
    pub attributes: Vec<(String, String)>,
    /// Its child elements.
    pub children: Vec<Element>,
}

impl Element {
    /// The value of the attribute named `name` (case-sensitive).
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// How deeply elements may nest, so that hostile input can't exhaust the
/// stack.
const MAX_DEPTH: usize = 256;

/// Parses a document and returns its root element.
pub fn parse(text: &str) -> Result<Element, String> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.skip_misc()?;
    let root = p.element(0)?;
    p.skip_misc()?;
    if p.pos != p.s.len() {
        return Err(format!("content after the root element at {}", p.pos));
    }
    Ok(root)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.pos))
    }

    fn starts(&self, t: &str) -> bool {
        self.s[self.pos..].starts_with(t.as_bytes())
    }

    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn skip_until(&mut self, end: &str) -> Result<(), String> {
        match find(&self.s[self.pos..], end.as_bytes()) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => self.err(&format!("missing {end}")),
        }
    }

    /// Whitespace, comments, processing instructions, DOCTYPE, and a BOM.
    fn skip_misc(&mut self) -> Result<(), String> {
        if self.starts("\u{feff}") {
            self.pos += 3;
        }
        loop {
            self.skip_ws();
            if self.starts("<!--") {
                self.skip_until("-->")?;
            } else if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<!DOCTYPE") {
                self.skip_until(">")?;
            } else {
                return Ok(());
            }
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.s.len() {
            let c = self.s[self.pos];
            if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':') || c >= 0x80 {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return self.err("expected a name");
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }

    fn element(&mut self, depth: usize) -> Result<Element, String> {
        if depth > MAX_DEPTH {
            return self.err("elements nested too deeply");
        }
        if !self.starts("<") {
            return self.err("expected an element");
        }
        self.pos += 1;
        let mut e = Element {
            name: self.name()?,
            ..Element::default()
        };
        loop {
            self.skip_ws();
            if self.starts("/>") {
                self.pos += 2;
                return Ok(e);
            }
            if self.starts(">") {
                self.pos += 1;
                break;
            }
            let name = self.name()?;
            self.skip_ws();
            if !self.starts("=") {
                return self.err("expected =");
            }
            self.pos += 1;
            self.skip_ws();
            let Some(&quote) = self.s.get(self.pos).filter(|&&q| q == b'"' || q == b'\'') else {
                return self.err("expected a quoted value");
            };
            self.pos += 1;
            let Some(len) = self.s[self.pos..].iter().position(|&c| c == quote) else {
                return self.err("unterminated value");
            };
            let raw = String::from_utf8_lossy(&self.s[self.pos..self.pos + len]).into_owned();
            self.pos += len + 1;
            e.attributes.push((name, unescape(&raw)?));
        }
        // Content: children, text, comments, CDATA, until our end tag.
        loop {
            if self.pos >= self.s.len() {
                return self.err(&format!("missing </{}>", e.name));
            }
            if self.starts("</") {
                self.pos += 2;
                let name = self.name()?;
                if name != e.name {
                    return self.err(&format!("</{name}> closes <{}>", e.name));
                }
                self.skip_ws();
                if !self.starts(">") {
                    return self.err("expected >");
                }
                self.pos += 1;
                return Ok(e);
            }
            if self.starts("<!--") {
                self.skip_until("-->")?;
            } else if self.starts("<![CDATA[") {
                self.skip_until("]]>")?;
            } else if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<") {
                e.children.push(self.element(depth + 1)?);
            } else {
                self.pos += 1;
            }
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn unescape(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let end = rest.find(';').ok_or("unterminated entity")?;
        let entity = &rest[..end];
        rest = &rest[end + 1..];
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(h) = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = entity.strip_prefix('#') {
                    d.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .ok_or_else(|| format!("unknown entity &{entity};"))?
            }
        };
        out.push(c);
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_elements() {
        let doc = r#"<?xml version="1.0" encoding="utf-8"?>
            <!-- a comment -->
            <Tag Name="">
              <Tag Name='A &amp; B'>
                <Entrypoint Module="x.dll" Method="f*"/>
                text <![CDATA[ <ignored/> ]]>
              </Tag>
              <Tag Name="&#65;&#x42;"></Tag>
            </Tag>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "Tag");
        assert_eq!(root.attribute("Name"), Some(""));
        assert_eq!(root.children.len(), 2);
        let a = &root.children[0];
        assert_eq!(a.attribute("Name"), Some("A & B"));
        assert_eq!(a.children[0].attribute("Method"), Some("f*"));
        assert_eq!(root.children[1].attribute("Name"), Some("AB"));
    }

    #[test]
    fn rejects_malformed() {
        for doc in [
            "",
            "<a>",
            "<a></b>",
            "<a x=1/>",
            "<a x=\"1/>",
            "<a/><b/>",
            "<a x=\"&bogus;\"/>",
            "<a x=\"&#xffffffff;\"/>",
            "<!-- unterminated",
        ] {
            assert!(parse(doc).is_err(), "{doc:?}");
        }
        let deep = "<a>".repeat(1000) + &"</a>".repeat(1000);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn never_panics_on_garbage() {
        let doc = r#"<Tag Name="x"><Entrypoint Module="m" Method="f"/></Tag>"#;
        for i in 0..doc.len() {
            if doc.is_char_boundary(i) {
                let _ = parse(&doc[..i]);
            }
        }
    }
}

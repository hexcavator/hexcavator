//! bloaty's custom data sources and configuration files: a source defined
//! by rewriting another's labels with regular expressions, as a bloaty
//! config file (`.bloaty`, protobuf text format) declares it:
//!
//! ```text
//! custom_data_source: {
//!   name: "bloaty_package"
//!   base_data_source: "compileunits"
//!   rewrite: {
//!     pattern: "^(\\.\\./)?src"
//!     replacement: "src"
//!   }
//! }
//! ```
//!
//! A label is rewritten by the first rule whose pattern matches it
//! anywhere: it becomes the replacement, with `\0`-`\9` replaced by the
//! match's groups (RE2's `Extract`). A label no rule matches is kept.

use regex::Regex;

use crate::rangemap::Label;
use crate::sources::{Maps, Source};

/// A custom data source.
#[derive(Clone, Debug)]
pub struct CustomSource {
    pub name: String,
    pub base: Source,
    pub rewrites: Vec<(Regex, String)>,
}

/// RE2's `Extract`: if `re` matches `text`, `rewrite` with `\N` replaced
/// by group N (empty if it took no part) and `\\` by a backslash.
pub fn extract(re: &Regex, text: &str, rewrite: &str) -> Option<String> {
    let caps = re.captures(text)?;
    let mut out = String::new();
    let mut chars = rewrite.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            d if d.is_ascii_digit() => {
                let g = d as usize - '0' as usize;
                if g >= caps.len() {
                    return None;
                }
                if let Some(m) = caps.get(g) {
                    out.push_str(m.as_str());
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Whether `rewrite` is valid for `re` (RE2's `CheckRewriteString`): its
/// escapes are `\\` or name groups `re` has.
fn check_rewrite(re: &Regex, rewrite: &str) -> bool {
    let mut chars = rewrite.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => {}
                Some(d)
                    if d.is_ascii_digit() && (d as usize - '0' as usize) < re.captures_len() => {}
                _ => return false,
            }
        }
    }
    true
}

impl CustomSource {
    pub fn new(name: &str, base: &str, rules: &[(String, String)]) -> Result<Self, String> {
        if Source::parse(name).is_some() {
            return Err(format!(
                "custom data source '{name}' has the name of a built-in source"
            ));
        }
        let base = Source::parse(base).ok_or_else(|| {
            format!("custom data source '{name}': no such base source '{base}' (see -list-sources)")
        })?;
        let mut rewrites = Vec::new();
        for (pattern, replacement) in rules {
            let re = Regex::new(pattern).map_err(|e| {
                format!("custom data source '{name}': bad pattern '{pattern}': {e}")
            })?;
            if !check_rewrite(&re, replacement) {
                return Err(format!(
                    "custom data source '{name}': bad replacement '{replacement}' for '{pattern}'"
                ));
            }
            rewrites.push((re, replacement.clone()));
        }
        Ok(Self {
            name: name.to_string(),
            base,
            rewrites,
        })
    }

    /// A label rewritten by the first rule that matches it.
    pub fn munge(&self, name: &str) -> String {
        for (re, rw) in &self.rewrites {
            if let Some(out) = extract(re, name, rw) {
                return out;
            }
        }
        name.to_string()
    }

    /// Rewrites the labels of source `index` of `maps` (built for this
    /// source's base).
    pub fn apply(&self, maps: &mut Maps, index: usize) {
        let mut cache: rustc_hash::FxHashMap<Label, Label> = Default::default();
        let labels = &mut maps.labels;
        let mut f = |l: Label| {
            *cache.entry(l).or_insert_with(|| {
                let new = self.munge(labels.name(l));
                labels.intern(&new)
            })
        };
        let map = &mut maps.sources[index].1;
        map.vm.relabel(&mut f);
        map.file.relabel(&mut f);
        map.vm.compress();
        map.file.compress();
    }
}

/// What a bloaty config file gives.
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub custom_sources: Vec<CustomSource>,
    /// `data_source` entries: the sources to report by.
    pub data_sources: Vec<String>,
    pub source_filter: Option<String>,
    /// `filename` entries: the input files.
    pub filenames: Vec<String>,
    /// `base_filename` entries.
    pub base_filenames: Vec<String>,
}

/// A protobuf text format value: a string, a number or identifier, or a
/// message.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Scalar(String),
    Message(Vec<(String, Value)>),
}

struct Lexer<'t> {
    t: &'t [u8],
    pos: usize,
    /// How deeply messages nest here (at most [`MAX_NESTING`]).
    depth: u32,
}

/// The most messages may nest in a configuration.
const MAX_NESTING: u32 = 16;

impl Lexer<'_> {
    fn skip(&mut self) {
        while self.pos < self.t.len() {
            match self.t[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'#' => {
                    while self.pos < self.t.len() && self.t[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn line(&self) -> usize {
        1 + self.t[..self.pos.min(self.t.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
    }

    fn fail<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("line {}: {what}", self.line()))
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip();
        self.t.get(self.pos).copied()
    }

    fn ident(&mut self) -> Result<String, String> {
        self.skip();
        let s = self.pos;
        while self.pos < self.t.len()
            && (self.t[self.pos].is_ascii_alphanumeric()
                || matches!(self.t[self.pos], b'_' | b'.' | b'-' | b'+'))
        {
            self.pos += 1;
        }
        if s == self.pos {
            return self.fail("expected a field name or value");
        }
        Ok(String::from_utf8_lossy(&self.t[s..self.pos]).into_owned())
    }

    /// A string literal (adjacent ones joined), with C escapes.
    fn string(&mut self) -> Result<String, String> {
        let mut out = Vec::new();
        while let Some(q @ (b'"' | b'\'')) = self.peek() {
            self.pos += 1;
            loop {
                let Some(&c) = self.t.get(self.pos) else {
                    return self.fail("unterminated string");
                };
                self.pos += 1;
                if c == q {
                    break;
                }
                if c == b'\n' {
                    return self.fail("newline in string");
                }
                if c != b'\\' {
                    out.push(c);
                    continue;
                }
                let Some(&e) = self.t.get(self.pos) else {
                    return self.fail("unterminated string");
                };
                self.pos += 1;
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'a' => out.push(0x07),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'v' => out.push(0x0B),
                    b'x' => {
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 2 && self.t.get(self.pos).is_some_and(u8::is_ascii_hexdigit) {
                            v = v * 16 + (self.t[self.pos] as char).to_digit(16).unwrap_or(0);
                            self.pos += 1;
                            n += 1;
                        }
                        if n == 0 {
                            return self.fail("bad \\x escape");
                        }
                        out.push(v as u8);
                    }
                    b'0'..=b'7' => {
                        let mut v = u32::from(e - b'0');
                        for _ in 0..2 {
                            match self.t.get(self.pos) {
                                Some(&d @ b'0'..=b'7') => {
                                    v = v * 8 + u32::from(d - b'0');
                                    self.pos += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(v as u8);
                    }
                    other => out.push(other),
                }
            }
        }
        String::from_utf8(out).or_else(|_| self.fail("string is not UTF-8"))
    }

    /// The fields of a message, up to `}` (or the end, at the top level).
    fn fields(&mut self, top: bool) -> Result<Vec<(String, Value)>, String> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None if top => return Ok(out),
                None => return self.fail("missing }"),
                Some(b'}') if !top => {
                    self.pos += 1;
                    return Ok(out);
                }
                _ => {}
            }
            let name = self.ident()?;
            let colon = self.peek() == Some(b':');
            if colon {
                self.pos += 1;
            }
            let value = match self.peek() {
                Some(b'{' | b'<') => {
                    self.pos += 1;
                    if self.depth >= MAX_NESTING {
                        return self.fail("messages nested too deeply");
                    }
                    self.depth += 1;
                    let fields = self.fields(false)?;
                    self.depth -= 1;
                    Value::Message(fields)
                }
                Some(b'"' | b'\'') if colon => Value::Scalar(self.string()?),
                Some(_) if colon => Value::Scalar(self.ident()?),
                _ => return self.fail("expected ':' or '{'"),
            };
            out.push((name, value));
            if matches!(self.peek(), Some(b';' | b',')) {
                self.pos += 1;
            }
        }
    }
}

fn scalar(v: &Value, field: &str) -> Result<String, String> {
    match v {
        Value::Scalar(s) => Ok(s.clone()),
        Value::Message(_) => Err(format!("'{field}' should be a value, not a message")),
    }
}

/// Parses a bloaty config file.
pub fn parse_config(text: &str) -> Result<Config, String> {
    let fields = Lexer {
        t: text.as_bytes(),
        pos: 0,
        depth: 0,
    }
    .fields(true)?;
    let mut c = Config::default();
    for (name, value) in &fields {
        match name.as_str() {
            "custom_data_source" => {
                let Value::Message(m) = value else {
                    return Err("'custom_data_source' should be a message".into());
                };
                let (mut sname, mut base, mut rules) = (None, None, Vec::new());
                for (f, v) in m {
                    match f.as_str() {
                        "name" => sname = Some(scalar(v, f)?),
                        "base_data_source" => base = Some(scalar(v, f)?),
                        "rewrite" => {
                            let Value::Message(r) = v else {
                                return Err("'rewrite' should be a message".into());
                            };
                            let (mut pattern, mut replacement) = (None, String::new());
                            for (rf, rv) in r {
                                match rf.as_str() {
                                    "pattern" => pattern = Some(scalar(rv, rf)?),
                                    "replacement" => replacement = scalar(rv, rf)?,
                                    other => {
                                        return Err(format!("unknown rewrite field '{other}'"));
                                    }
                                }
                            }
                            rules.push((pattern.ok_or("a rewrite needs a pattern")?, replacement));
                        }
                        other => return Err(format!("unknown custom_data_source field '{other}'")),
                    }
                }
                let sname = sname.ok_or("a custom_data_source needs a name")?;
                let base = base.ok_or_else(|| {
                    format!("custom data source '{sname}' needs a base_data_source")
                })?;
                if c.custom_sources.iter().any(|s| s.name == sname) {
                    return Err(format!("custom data source '{sname}' is defined twice"));
                }
                c.custom_sources
                    .push(CustomSource::new(&sname, &base, &rules)?);
            }
            "data_source" => c.data_sources.push(scalar(value, name)?),
            "source_filter" => c.source_filter = Some(scalar(value, name)?),
            "filename" => c.filenames.push(scalar(value, name)?),
            "base_filename" => c.base_filenames.push(scalar(value, name)?),
            other => return Err(format!("unsupported config field '{other}'")),
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_like_re2() {
        let re = Regex::new(r"^(.*)/([^/]*)\.(o|obj)$").unwrap();
        assert_eq!(
            extract(&re, "a/b/c.o", r"\2 in \1").as_deref(),
            Some("c in a/b")
        );
        assert_eq!(
            extract(&re, "a/b/c.o", r"[\0]").as_deref(),
            Some("[a/b/c.o]")
        );
        assert_eq!(extract(&re, "a/b/c.o", r"\\\3").as_deref(), Some("\\o"));
        assert_eq!(extract(&re, "c.cpp", r"\1"), None);
        let re = Regex::new(r"(a)|(b)").unwrap();
        assert_eq!(extract(&re, "b", r"<\1|\2>").as_deref(), Some("<|b>"));
        assert_eq!(extract(&re, "a", r"\5"), None);
        assert!(check_rewrite(&re, r"\0\1\2\\"));
        assert!(!check_rewrite(&re, r"\3"));
        assert!(!check_rewrite(&re, "\\"));
    }

    #[test]
    fn config_files() {
        let text = r#"
            # A comment.
            custom_data_source: {
              name: "package"
              base_data_source: "compileunits"
              rewrite: { pattern: "^(\\.\\./)?src/(\\w+)/" replacement: "src/\\2" }
              rewrite { pattern: "^third_party/" replacement: "third_party" }
            }
            data_source: "package"
            data_source: sections
            source_filter: 'lib' "foo"
            filename: "a.out"
        "#;
        let c = parse_config(text).unwrap();
        assert_eq!(c.custom_sources.len(), 1);
        let s = &c.custom_sources[0];
        assert_eq!(s.base, Source::CompileUnits);
        assert_eq!(s.munge("../src/core/x.c"), "src/core");
        assert_eq!(s.munge("third_party/zlib/inflate.c"), "third_party");
        assert_eq!(s.munge("main.c"), "main.c");
        assert_eq!(c.data_sources, ["package", "sections"]);
        assert_eq!(c.source_filter.as_deref(), Some("libfoo"));
        assert_eq!(c.filenames, ["a.out"]);
        for (bad, why) in [
            (
                "custom_data_source { name: \"x\" base_data_source: \"nope\" }",
                "no such base source",
            ),
            (
                "custom_data_source { name: \"sections\" base_data_source: \"symbols\" }",
                "built-in",
            ),
            (
                "custom_data_source { name: \"x\" base_data_source: \"symbols\" rewrite { pattern: \"(\" } }",
                "bad pattern",
            ),
            (
                "custom_data_source { name: \"x\" base_data_source: \"symbols\" rewrite { pattern: \"a\" replacement: \"\\\\1\" } }",
                "bad replacement",
            ),
            ("custom_data_source { name: \"x\" ", "missing }"),
            ("frobnicate: 1", "unsupported config field"),
            ("data_source: \"x", "unterminated string"),
            (
                "custom_data_source { name: \"x\" base_data_source: \"symbols\" } custom_data_source { name: \"x\" base_data_source: \"symbols\" }",
                "defined twice",
            ),
        ] {
            let e = parse_config(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    /// Deeply nested messages fail, rather than recursing without bound.
    #[test]
    fn deep_nesting_fails() {
        std::thread::Builder::new()
            .stack_size(128 << 10)
            .spawn(|| {
                let text = format!("{}{}", "a {".repeat(100_000), "}".repeat(100_000));
                assert!(
                    parse_config(&text)
                        .unwrap_err()
                        .contains("nested too deeply")
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

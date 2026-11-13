//! Stack tags and folding rules: ways to name and simplify stacks.
//!
//! **Stack tags** use WPA's XML format. `<Tag Name="...">` elements nest to
//! form a hierarchy, and each has `<Entrypoint Module="..." Method="..."/>`
//! patterns (`*` and `?` wildcards, case-insensitive). A stack's tag is the
//! one whose entrypoint matches its deepest frame (nearest the leaf); a
//! stack with no match is tagged "Other". Tags are a grouping column.
//!
//! **Folding rules** collapse runs of matching frames into one node. Each
//! line of a rules file is
//!
//! ```text
//! fold [name] module=<pattern> [method=<pattern>]
//! ```
//!
//! with `#` starting a comment. The node is labeled with the name, or the
//! module pattern if there is none.

use crate::xml;

/// A `*`/`?` pattern, matched case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob(Vec<u8>);

impl Glob {
    /// A pattern.
    pub fn new(pattern: &str) -> Self {
        Self(pattern.to_ascii_lowercase().into_bytes())
    }

    /// Whether `text` matches.
    pub fn matches(&self, text: &str) -> bool {
        let t = text.to_ascii_lowercase();
        glob_match(&self.0, t.as_bytes())
    }
}

/// Wildcard matching with backtracking over the last `*` (linear in
/// practice, and never exponential).
fn glob_match(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// One pattern pair: a module and, optionally, a method.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entrypoint {
    module: Glob,
    method: Option<Glob>,
}

impl Entrypoint {
    /// Whether a frame in `module`, in `method` if known, matches.
    fn matches(&self, module: &str, method: Option<&str>) -> bool {
        if !self.module.matches(module) {
            return false;
        }
        match (&self.method, method) {
            (None, _) => true,
            (Some(g), Some(m)) => g.matches(m),
            // A method pattern needs a method name, except one that
            // matches anything.
            (Some(g), None) => g.0 == b"*",
        }
    }
}

/// A set of stack tags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackTags {
    /// Each tag's full name: its ancestors' names and its own, joined by
    /// `\`.
    names: Vec<String>,
    /// Entrypoints in document order, with their tags.
    entrypoints: Vec<(Entrypoint, u32)>,
}

impl StackTags {
    /// Reads WPA's stack tag XML.
    pub fn from_xml(text: &str) -> Result<Self, String> {
        let root = xml::parse(text)?;
        let mut tags = Self::default();
        tags.walk(&root, "")?;
        Ok(tags)
    }

    fn walk(&mut self, e: &xml::Element, parent: &str) -> Result<(), String> {
        let path = match e.name.as_str() {
            "Tag" => {
                let name = e.attribute("Name").unwrap_or("");
                match (parent.is_empty(), name.is_empty()) {
                    (_, true) => parent.to_string(),
                    (true, false) => name.to_string(),
                    (false, false) => format!("{parent}\\{name}"),
                }
            }
            "Entrypoint" => {
                if parent.is_empty() {
                    return Err("an Entrypoint outside any named Tag".into());
                }
                let module = e
                    .attribute("Module")
                    .ok_or("an Entrypoint without a Module")?;
                let tag = self.tag(parent);
                self.entrypoints.push((
                    Entrypoint {
                        module: Glob::new(module),
                        method: e.attribute("Method").map(Glob::new),
                    },
                    tag,
                ));
                return Ok(());
            }
            // Other elements (such as a wrapping document element) just
            // contain tags.
            _ => parent.to_string(),
        };
        for c in &e.children {
            self.walk(c, &path)?;
        }
        Ok(())
    }

    fn tag(&mut self, name: &str) -> u32 {
        if let Some(i) = self.names.iter().position(|n| n == name) {
            return u32::try_from(i).expect("few tags");
        }
        self.names.push(name.to_string());
        u32::try_from(self.names.len() - 1).expect("few tags")
    }

    /// The number of tags.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// A tag's full name.
    pub fn name(&self, tag: u32) -> &str {
        &self.names[tag as usize]
    }

    /// The tag of a frame in `module` (a file name), in `method` if known:
    /// the first entrypoint in the file that matches.
    pub fn frame_tag(&self, module: &str, method: Option<&str>) -> Option<u32> {
        self.entrypoints
            .iter()
            .find(|(e, _)| e.matches(module, method))
            .map(|&(_, t)| t)
    }
}

/// Folding rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Folds {
    rules: Vec<(String, Entrypoint)>,
}

impl Folds {
    /// Reads rules (see the module's docs).
    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut folds = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let err = |what: &str| format!("line {}: {what}", n + 1);
            let words = split_words(line).map_err(|e| err(&e))?;
            if words.first().map(String::as_str) != Some("fold") {
                return Err(err("expected `fold`"));
            }
            let mut name = None;
            let mut module = None;
            let mut method = None;
            for w in &words[1..] {
                if let Some(v) = w.strip_prefix("module=") {
                    module = Some(v.to_string());
                } else if let Some(v) = w.strip_prefix("method=") {
                    method = Some(v.to_string());
                } else if name.is_none() && module.is_none() {
                    name = Some(w.clone());
                } else {
                    return Err(err(&format!("unexpected `{w}`")));
                }
            }
            let module = module.ok_or_else(|| err("missing module="))?;
            folds.rules.push((
                name.unwrap_or_else(|| module.clone()),
                Entrypoint {
                    module: Glob::new(&module),
                    method: method.as_deref().map(Glob::new),
                },
            ));
        }
        Ok(folds)
    }

    /// Whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// A rule's name.
    pub fn name(&self, rule: u32) -> &str {
        &self.rules[rule as usize].0
    }

    /// The first rule a frame matches.
    pub fn frame_rule(&self, module: &str, method: Option<&str>) -> Option<u32> {
        self.rules
            .iter()
            .position(|(_, e)| e.matches(module, method))
            .map(|i| u32::try_from(i).expect("few rules"))
    }
}

/// Splits on whitespace, keeping "quoted strings" together.
fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    words.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if quoted {
        return Err("unterminated quote".into());
    }
    if any {
        words.push(cur);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        let g = Glob::new("Rtl*Heap?");
        assert!(g.matches("RtlAllocateHeapX"));
        assert!(g.matches("rtlfreeheap1"));
        assert!(!g.matches("RtlAllocateHeap"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("a*b*c").matches("aXbYbZc"));
        assert!(!Glob::new("a*b*c").matches("aXbYbZ"));
        // Many stars against a long text stay fast.
        assert!(!Glob::new(&"*a".repeat(50)).matches(&"a".repeat(49)));
    }

    #[test]
    fn stack_tags() {
        let tags = StackTags::from_xml(
            r#"<Tag Name="">
                 <Tag Name="Windows">
                   <Tag Name="Page Fault">
                     <Entrypoint Module="ntoskrnl.exe" Method="MmAccessFault"/>
                   </Tag>
                   <Entrypoint Module="ntoskrnl.exe" Method="Ki*"/>
                 </Tag>
                 <Tag Name="Heap">
                   <Entrypoint Module="ntdll.dll" Method="Rtl*Heap*"/>
                 </Tag>
                 <Tag Name="Graphics"><Entrypoint Module="d3d1?.dll"/></Tag>
               </Tag>"#,
        )
        .unwrap();
        assert_eq!(tags.len(), 4);
        let name = |m, f| tags.frame_tag(m, f).map(|t| tags.name(t).to_string());
        assert_eq!(
            name("ntoskrnl.exe", Some("MmAccessFault")).as_deref(),
            Some("Windows\\Page Fault")
        );
        assert_eq!(
            name("NTOSKRNL.EXE", Some("KiPageFault")).as_deref(),
            Some("Windows")
        );
        assert_eq!(
            name("ntdll.dll", Some("RtlAllocateHeap")).as_deref(),
            Some("Heap")
        );
        assert_eq!(name("d3d11.dll", None).as_deref(), Some("Graphics"));
        assert_eq!(name("ntdll.dll", None), None);
        assert_eq!(name("app.exe", Some("main")), None);
        assert!(StackTags::from_xml("<Entrypoint Module='x'/>").is_err());
        assert!(StackTags::from_xml("<Tag Name='a'><Entrypoint/></Tag>").is_err());
    }

    #[test]
    fn folds() {
        let f = Folds::from_text(
            "# comment\n\nfold \"C runtime\" module=ucrtbase.dll\nfold module=ntdll.dll method=Rtl* # trailing\n",
        )
        .unwrap();
        assert_eq!(f.frame_rule("ucrtbase.dll", Some("memcpy")), Some(0));
        assert_eq!(f.name(0), "C runtime");
        assert_eq!(
            f.frame_rule("ntdll.dll", Some("RtlUserThreadStart")),
            Some(1)
        );
        assert_eq!(f.name(1), "ntdll.dll");
        assert_eq!(
            f.frame_rule("ntdll.dll", Some("NtWaitForSingleObject")),
            None
        );
        for bad in [
            "fold",
            "unfold module=x",
            "fold \"x module=y",
            "fold a b module=x",
            "fold name",
        ] {
            assert!(Folds::from_text(bad).is_err(), "{bad:?}");
        }
    }
}

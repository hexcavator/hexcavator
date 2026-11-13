//! Findings: patterns in a binary that waste space, with what they cost.
//!
//! - **Duplicate data**: a file-scope `static` (or non-`extern` `const`)
//!   variable defined in a header gets one copy per compiland that
//!   includes it. Copies with the same name, size, and bytes at different
//!   addresses are duplicates; all but one are wasted (SizeBench's
//!   "Duplicate Data", and its numbers).
//! - **Template families**: instantiations of one template (functions and
//!   data whose names differ only in template arguments), with their
//!   count, total size, and how alike their code is: where template bloat
//!   is.
//! - **Wasteful virtuals**: virtual functions no derived class overrides,
//!   and pure ones exactly one implements (SizeBench's "Wasteful
//!   Virtuals", and its numbers): each costs a vtable slot in its class
//!   and every class derived from it.

use std::collections::{BTreeMap, HashMap};

use hexcavator_image::Image;

use crate::Size;
use crate::symbols::{Symbol, SymbolKind};

/// One duplicated variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateData {
    pub name: String,
    /// One copy's size.
    pub size: Size,
    /// Each copy: its address and compiland.
    pub copies: Vec<(u64, u32)>,
}

impl DuplicateData {
    /// The bytes all copies but one take.
    pub fn wasted(&self) -> Size {
        let extra = self.copies.len().saturating_sub(1) as u64;
        Size::new(self.size.file * extra, self.size.vm * extra)
    }
}

/// The duplicated variables of an image, most wasteful first.
pub fn duplicate_data(image: &Image<'_>, symbols: &[Symbol]) -> Vec<DuplicateData> {
    // Candidates by (name, size).
    let mut groups: BTreeMap<(&str, u64, u64), Vec<&Symbol>> = BTreeMap::new();
    for s in symbols {
        if s.kind == SymbolKind::Data
            && s.file_static
            && !s.folded
            && s.compiland.is_some()
            && (s.size.file > 0 || s.size.vm > 0)
        {
            groups
                .entry((s.name.as_str(), s.size.file, s.size.vm))
                .or_default()
                .push(s);
        }
    }
    let bytes = |s: &Symbol| image.bytes_at(s.addr, s.size.file);
    let mut out = Vec::new();
    for ((name, file, vm), members) in groups {
        if members.len() < 2 {
            continue;
        }
        // Copies agree byte for byte (some same-named variables, such as
        // MIDL's `__midl_frag<n>`, differ).
        let mut clusters: Vec<(Option<&[u8]>, DuplicateData)> = Vec::new();
        for s in members {
            let b = bytes(s);
            let compiland = s.compiland.expect("filtered");
            match clusters
                .iter_mut()
                .find(|(cb, d)| *cb == b && d.copies.iter().all(|c| c.0 != s.addr))
            {
                Some((_, d)) => {
                    if d.copies.iter().all(|c| c.1 != compiland) {
                        d.copies.push((s.addr, compiland));
                    }
                }
                None => clusters.push((
                    b,
                    DuplicateData {
                        name: name.to_string(),
                        size: Size::new(file, vm),
                        copies: vec![(s.addr, compiland)],
                    },
                )),
            }
        }
        out.extend(
            clusters
                .into_iter()
                .map(|(_, d)| d)
                .filter(|d| d.copies.len() > 1),
        );
    }
    out.sort_by(|a, b| {
        let (wa, wb) = (a.wasted(), b.wasted());
        wb.file
            .max(wb.vm)
            .cmp(&wa.file.max(wa.vm))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// A class whose virtual functions cost vtable slots for nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WastefulVirtual {
    pub class: String,
    /// What one wasted slot costs: a pointer in the class's vtable and in
    /// each of its derived classes' (SizeBench's measure).
    pub per_slot: u64,
    /// Pure virtual functions exactly one derived class implements: the
    /// function could be that class's.
    pub pure_with_one_override: Vec<String>,
    /// Virtual functions no derived class overrides: they needn't be
    /// virtual.
    pub unoverridden: Vec<String>,
}

impl WastefulVirtual {
    pub fn wasted(&self) -> u64 {
        (self.pure_with_one_override.len() + self.unoverridden.len()) as u64 * self.per_slot
    }
}

/// Classes with wasteful virtual functions, most wasteful first, as
/// SizeBench finds them: a virtual function (not a destructor) is the
/// class's that introduces it, and is wasted if it is pure and exactly
/// one derived class (at any depth) overrides it, or not pure and none
/// does.
/// Functions are matched by name, arguments, and qualifiers. `word` is
/// the size of a pointer.
pub fn wasteful_virtuals(
    classes: &[hexcavator_debuginfo::Class],
    namer: &mut crate::names::Namer<'_, '_>,
    word: u64,
) -> Vec<WastefulVirtual> {
    use hexcavator_debuginfo::MethodKind;
    let index: HashMap<hexcavator_debuginfo::TypeRef, usize> =
        classes.iter().enumerate().map(|(i, c)| (c.ty, i)).collect();
    // Every class's descendants (direct or not), each once. (Base lists
    // are untrusted: a walk visits each class once, so cycles end.)
    let mut derived: Vec<Vec<usize>> = vec![Vec::new(); classes.len()];
    let mut seen = vec![usize::MAX; classes.len()];
    for (i, c) in classes.iter().enumerate() {
        let mut stack: Vec<hexcavator_debuginfo::TypeRef> = c.bases.clone();
        while let Some(b) = stack.pop() {
            let Some(&j) = index.get(&b) else { continue };
            if j == i || seen[j] == i {
                continue;
            }
            seen[j] = i;
            derived[j].push(i);
            stack.extend(classes[j].bases.iter().copied());
        }
    }
    // Each class's methods: (signature, virtual, pure).
    let methods: Vec<Vec<(String, bool, bool)>> = classes
        .iter()
        .map(|c| {
            c.methods
                .iter()
                .map(|m| {
                    let is_static = m.kind == MethodKind::Static;
                    let signature = format!(
                        "{}{}{}",
                        if is_static { "static " } else { "" },
                        m.name,
                        namer.signature_suffix(m.ty)
                    );
                    (
                        signature,
                        m.kind.is_virtual() && !is_static,
                        m.kind.is_pure(),
                    )
                })
                .collect()
        })
        .collect();
    // Whether a base of class `i` (at any depth) declares virtual
    // `signature`; each class is visited once.
    let in_base = |i: usize, signature: &str| -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut stack: Vec<hexcavator_debuginfo::TypeRef> = classes[i].bases.clone();
        while let Some(b) = stack.pop() {
            let Some(&j) = index.get(&b) else { continue };
            if !visited.insert(j) {
                continue;
            }
            if methods[j].iter().any(|(s, v, _)| *v && s == signature) {
                return true;
            }
            stack.extend(classes[j].bases.iter().copied());
        }
        false
    };
    let mut out = Vec::new();
    for (i, c) in classes.iter().enumerate() {
        if derived[i].is_empty() {
            continue;
        }
        let mut item = WastefulVirtual {
            class: c.name.clone(),
            per_slot: (derived[i].len() as u64 + 1) * word,
            pure_with_one_override: Vec::new(),
            unoverridden: Vec::new(),
        };
        for (signature, is_virtual, is_pure) in &methods[i] {
            if !is_virtual || signature.contains('~') {
                continue;
            }
            if in_base(i, signature) {
                continue;
            }
            let overrides = derived[i]
                .iter()
                .filter(|&&d| {
                    methods[d]
                        .iter()
                        .any(|(s, v, p)| s == signature && !(*p && *v))
                })
                .take(2)
                .count();
            if *is_pure && overrides == 1 {
                item.pure_with_one_override.push(signature.clone());
            } else if !is_pure && overrides == 0 {
                item.unoverridden.push(signature.clone());
            }
        }
        if item.wasted() > 0 {
            item.pure_with_one_override.sort();
            item.unoverridden.sort();
            out.push(item);
        }
    }
    out.sort_by(|a, b| {
        b.wasted()
            .cmp(&a.wasted())
            .then_with(|| a.class.cmp(&b.class))
    });
    out
}

/// A template's instantiations.
#[derive(Clone, Debug, PartialEq)]
pub struct TemplateFamily {
    /// The name with template arguments elided: `std::vector<>::push_back`.
    pub family: String,
    pub instances: usize,
    pub size: Size,
    /// The largest instance: its name and size.
    pub largest: (String, Size),
    /// How alike the instances' code is, 0 to 1: the share of equal bytes
    /// at equal offsets, averaged over pairs of instances (as SizeBench's
    /// template foldability measures it). Nearly identical instances are
    /// candidates for a type-independent base or helper. `None` without
    /// two functions in one piece to compare.
    pub similarity: Option<f32>,
}

/// The share of bytes of `a` and `b` that are equal at equal offsets, of
/// the longer one's length.
fn similarity(a: &[u8], b: &[u8]) -> f32 {
    let longer = a.len().max(b.len());
    if longer == 0 {
        return 1.0;
    }
    let same = a.iter().zip(b).filter(|(x, y)| x == y).count();
    same as f32 / longer as f32
}

/// At most this many pairs are compared per family.
const MAX_PAIRS: usize = 64;

/// `name` with every template argument list emptied (`f<int>` becomes
/// `f<>`) and its parameter list removed, if it has template arguments.
pub fn template_family(name: &str) -> Option<String> {
    let name = strip_parameters(name);
    if !name.contains('<') {
        return None;
    }
    let mut out = String::with_capacity(name.len());
    let mut depth = 0usize;
    let mut chars = name.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let operator_before = name[..i].ends_with("operator");
        match c {
            '<' if operator_before => {
                // `operator<`, `operator<<`, `operator<=`, `operator<=>`.
                out.push('<');
                while let Some(&(_, n)) = chars.peek() {
                    if matches!(n, '<' | '=' | '>') {
                        out.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            '>' if operator_before => out.push('>'),
            '-' if depth == 0 && name[i..].starts_with("->") && operator_before => {
                out.push_str("->");
                chars.next();
            }
            '<' => {
                if depth == 0 {
                    out.push('<');
                }
                depth += 1;
            }
            '>' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    out.push('>');
                }
            }
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    (out.len() < name.len()).then_some(out)
}

/// A function name without its parameter list (and the qualifiers after
/// it): `C::f(int) const` becomes `C::f`.
pub fn strip_parameters(name: &str) -> &str {
    let trimmed = name.trim_end();
    let mut end = trimmed.len();
    // Qualifiers after the parameters.
    for q in [" const", " volatile", " &&", " &", " override", " final"] {
        if let Some(t) = trimmed[..end].strip_suffix(q) {
            end = t.len();
        }
    }
    let body = &trimmed[..end];
    if !body.ends_with(')') {
        return name;
    }
    let mut depth = 0i32;
    for (i, c) in body.char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    // `operator()` keeps its name's parentheses.
                    let head = &body[..i];
                    return if head.is_empty() || head.ends_with("operator") {
                        name
                    } else {
                        head
                    };
                }
            }
            _ => {}
        }
    }
    name
}

/// Template families with at least two instances, largest first.
pub fn template_families(image: Option<&Image<'_>>, symbols: &[Symbol]) -> Vec<TemplateFamily> {
    let mut families: HashMap<String, TemplateFamily> = HashMap::new();
    // Each family's functions in one piece: (address, size).
    let mut code: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
    for s in symbols.iter().filter(|s| {
        !s.folded
            && matches!(
                s.kind,
                SymbolKind::Function
                    | SymbolKind::PrimaryBlock
                    | SymbolKind::SeparatedBlock
                    | SymbolKind::Data
            )
    }) {
        let name = s.name.strip_prefix("Block of code in ").unwrap_or(&s.name);
        let Some(family) = template_family(name) else {
            continue;
        };
        if s.kind == SymbolKind::Function && s.size.file > 0 {
            code.entry(family.clone())
                .or_default()
                .push((s.addr, s.size.file));
        }
        let f = families
            .entry(family.clone())
            .or_insert_with(|| TemplateFamily {
                family,
                instances: 0,
                size: Size::default(),
                largest: (String::new(), Size::default()),
                similarity: None,
            });
        // Blocks of one function are one instance.
        if s.kind != SymbolKind::SeparatedBlock {
            f.instances += 1;
        }
        f.size += s.size;
        if s.size.file.max(s.size.vm) > f.largest.1.file.max(f.largest.1.vm) {
            f.largest = (s.name.clone(), s.size);
        }
    }
    let mut out: Vec<TemplateFamily> = families.into_values().filter(|f| f.instances > 1).collect();
    if let Some(image) = image {
        for f in &mut out {
            let Some(list) = code.get(&f.family) else {
                continue;
            };
            let pairs: Vec<f32> = list
                .windows(2)
                .take(MAX_PAIRS)
                .filter_map(|w| {
                    let a = image.bytes_at(w[0].0, w[0].1)?;
                    let b = image.bytes_at(w[1].0, w[1].1)?;
                    Some(similarity(a, b))
                })
                .collect();
            if !pairs.is_empty() {
                f.similarity = Some(pairs.iter().sum::<f32>() / pairs.len() as f32);
            }
        }
    }
    out.sort_by(|a, b| {
        b.size
            .file
            .max(b.size.vm)
            .cmp(&a.size.file.max(a.size.vm))
            .then_with(|| a.family.cmp(&b.family))
    });
    out
}

/// Every finding of an image.
pub struct Findings {
    pub duplicates: Vec<DuplicateData>,
    pub families: Vec<TemplateFamily>,
    pub virtuals: Vec<WastefulVirtual>,
}

/// The findings of `image`, with its debug information and symbols.
pub fn find(
    image: &Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    symbols: &[Symbol],
) -> Findings {
    let word = u64::from(image.arch().pointer_size().unwrap_or(8));
    let virtuals = match debug.classes() {
        Ok(classes) => {
            let mut namer = crate::names::Namer::new(debug);
            wasteful_virtuals(&classes, &mut namer, word)
        }
        Err(_) => Vec::new(),
    };
    Findings {
        duplicates: duplicate_data(image, symbols),
        families: template_families(Some(image), symbols),
        virtuals,
    }
}

/// One item of a finding in two builds: its name, and its bytes (wasted, or
/// for template families, taken) and count (copies, instances) in each,
/// absent where it isn't.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub base: Option<(u64, usize)>,
    pub new: Option<(u64, usize)>,
}

impl Change {
    /// The change in bytes.
    pub fn delta(&self) -> i128 {
        i128::from(self.new.map_or(0, |n| n.0)) - i128::from(self.base.map_or(0, |b| b.0))
    }
}

/// The items of one finding that changed, by name: largest change first.
fn changes(base: Vec<(String, u64, usize)>, new: Vec<(String, u64, usize)>) -> Vec<Change> {
    let mut map: std::collections::BTreeMap<String, Change> = std::collections::BTreeMap::new();
    for (name, bytes, count) in base {
        map.entry(name.clone())
            .or_insert(Change {
                name,
                base: None,
                new: None,
            })
            .base = Some((bytes, count));
    }
    for (name, bytes, count) in new {
        map.entry(name.clone())
            .or_insert(Change {
                name,
                base: None,
                new: None,
            })
            .new = Some((bytes, count));
    }
    let mut out: Vec<Change> = map.into_values().filter(|c| c.base != c.new).collect();
    out.sort_by(|a, b| {
        b.delta()
            .abs()
            .cmp(&a.delta().abs())
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// The findings of an image compared with a base build's: for each
/// finding, its total in each, and the items that changed (wasted bytes of
/// duplicated variables and of virtual function slots; template families'
/// bytes), largest change first, at most `limit` (0: all) each. As text
/// and as JSON.
pub fn compare(new: &Findings, base: &Findings, limit: usize) -> (String, String) {
    use std::fmt::Write as _;
    let limit = if limit == 0 { usize::MAX } else { limit };
    let dups = |f: &Findings| -> Vec<(String, u64, usize)> {
        f.duplicates
            .iter()
            .map(|d| (d.name.clone(), d.wasted().file, d.copies.len()))
            .collect()
    };
    let families = |f: &Findings| -> Vec<(String, u64, usize)> {
        f.families
            .iter()
            .map(|t| (t.family.clone(), t.size.file, t.instances))
            .collect()
    };
    let virtuals = |f: &Findings| -> Vec<(String, u64, usize)> {
        f.virtuals
            .iter()
            .map(|v| {
                (
                    v.class.clone(),
                    v.wasted(),
                    v.pure_with_one_override.len() + v.unoverridden.len(),
                )
            })
            .collect()
    };
    let sections: [(&str, &str, &str, Vec<Change>); 3] = [
        (
            "duplicate_data",
            "Duplicate data (wasted file bytes)",
            "copies",
            changes(dups(base), dups(new)),
        ),
        (
            "template_families",
            "Template families (bytes)",
            "instances",
            changes(families(base), families(new)),
        ),
        (
            "wasteful_virtuals",
            "Wasteful virtuals (wasted bytes)",
            "functions",
            changes(virtuals(base), virtuals(new)),
        ),
    ];
    let totals = |f: &Findings| -> [u64; 3] {
        [
            f.duplicates.iter().map(|d| d.wasted().file).sum(),
            f.families.iter().map(|t| t.size.file).sum(),
            f.virtuals.iter().map(WastefulVirtual::wasted).sum(),
        ]
    };
    let (tb, tn) = (totals(base), totals(new));
    let mut text = String::new();
    let mut json = serde_json::Map::new();
    for (i, (key, title, unit, list)) in sections.iter().enumerate() {
        let delta = i128::from(tn[i]) - i128::from(tb[i]);
        let _ = writeln!(
            text,
            "{title}: {} -> {} ({delta:+}), {} changed",
            tb[i],
            tn[i],
            list.len()
        );
        for c in list.iter().take(limit) {
            let count =
                |v: Option<(u64, usize)>| v.map_or_else(|| "none".to_string(), |v| v.1.to_string());
            let _ = writeln!(
                text,
                "  {:>+10}  {} ({} -> {} {unit})",
                c.delta(),
                c.name,
                count(c.base),
                count(c.new)
            );
        }
        if list.len() > limit {
            let _ = writeln!(text, "  ({} more)", list.len() - limit);
        }
        json.insert(
            (*key).to_string(),
            serde_json::json!({
                "base": tb[i],
                "new": tn[i],
                "changes": list.iter().take(limit).map(|c| serde_json::json!({
                    "name": c.name,
                    "base": c.base.map(|b| b.0),
                    "new": c.new.map(|n| n.0),
                    "baseCount": c.base.map(|b| b.1),
                    "newCount": c.new.map(|n| n.1),
                })).collect::<Vec<_>>(),
            }),
        );
    }
    let mut j = serde_json::to_string_pretty(&serde_json::Value::Object(json)).unwrap_or_default();
    j.push('\n');
    (text, j)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ellipses() {
        assert_eq!(ellipsize("short", 10), "short");
        assert_eq!(ellipsize("abcdefghij", 4), "abcd...");
        assert_eq!(ellipsize("ééééé", 2), "éé...");
    }

    #[test]
    fn parameters() {
        assert_eq!(strip_parameters("C::f(int, char*) const"), "C::f");
        assert_eq!(strip_parameters("f(void (*)(int))"), "f");
        assert_eq!(strip_parameters("C::operator()(int)"), "C::operator()");
        assert_eq!(strip_parameters("operator()"), "operator()");
        assert_eq!(strip_parameters("f<void(int)>(int)"), "f<void(int)>");
        assert_eq!(strip_parameters("data"), "data");
        assert_eq!(strip_parameters("x (in f())"), "x ");
        assert_eq!(strip_parameters("f() &&"), "f");
    }

    #[test]
    fn families() {
        assert_eq!(
            template_family("std::vector<int,std::allocator<int> >::push_back(const int&)")
                .as_deref(),
            Some("std::vector<>::push_back")
        );
        assert_eq!(
            template_family("twice<__int64>(__int64)").as_deref(),
            Some("twice<>")
        );
        assert_eq!(template_family("f(int)"), None);
        assert_eq!(
            template_family("C<int>::operator<(const C<int>&) const").as_deref(),
            Some("C<>::operator<")
        );
        assert_eq!(
            template_family("std::basic_ostream<char>::operator<<(int)").as_deref(),
            Some("std::basic_ostream<>::operator<<")
        );
        assert_eq!(
            template_family("S<int>::operator->()").as_deref(),
            Some("S<>::operator->")
        );
        assert_eq!(
            template_family("A<B<C<D> > >::x").as_deref(),
            Some("A<>::x")
        );
        // Unbalanced names don't panic.
        assert_eq!(template_family("a<b").as_deref(), Some("a<"));
        let _ = template_family("a>b<");
    }

    fn sym(
        name: &str,
        kind: SymbolKind,
        size: u64,
        addr: u64,
        compiland: u32,
        file_static: bool,
    ) -> Symbol {
        Symbol {
            addr,
            size: Size::new(size, size),
            kind,
            folded: false,
            name: name.into(),
            compiland: Some(compiland),
            file_static,
        }
    }

    #[test]
    fn template_family_totals() {
        let symbols = [
            sym("v<int>::f()", SymbolKind::Function, 10, 0x1000, 0, false),
            sym("v<char>::f()", SymbolKind::Function, 30, 0x1010, 0, false),
            sym(
                "Block of code in v<long>::f()",
                SymbolKind::PrimaryBlock,
                5,
                0x1040,
                0,
                false,
            ),
            sym(
                "Block of code in v<long>::f()",
                SymbolKind::SeparatedBlock,
                5,
                0x9000,
                0,
                false,
            ),
            sym("w<int>::g()", SymbolKind::Function, 100, 0x2000, 0, false),
            sym("plain()", SymbolKind::Function, 1000, 0x3000, 0, false),
        ];
        let f = template_families(None, &symbols);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].family, "v<>::f");
        assert_eq!(f[0].instances, 3);
        assert_eq!(f[0].size, Size::new(50, 50));
        assert_eq!(f[0].largest.0, "v<char>::f()");
        assert_eq!(f[0].similarity, None);
    }

    #[test]
    fn cyclic_class_hierarchies_end() {
        use hexcavator_debuginfo::{Class, TypeRef};
        // A and B each derive from both: a cycle with branching.
        let class = |n: &str, ty: u32, bases: &[u32]| Class {
            name: n.into(),
            ty: TypeRef(u64::from(ty)),
            bases: bases.iter().map(|b| TypeRef(u64::from(*b))).collect(),
            methods: vec![hexcavator_debuginfo::Method {
                name: "f".into(),
                ty: TypeRef(0),
                kind: hexcavator_debuginfo::MethodKind::IntroVirtual,
            }],
        };
        let classes: Vec<Class> = (0..40)
            .map(|i| {
                class(
                    &format!("C{i}"),
                    0x1000 + i,
                    &[0x1000 + (i + 1) % 40, 0x1000 + (i + 2) % 40],
                )
            })
            .collect();
        let pdb = std::fs::read(format!(
            "{}/../../../testdata/sizebench/bin/PEParser.Tests.Dllx64.pdb",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let debug = hexcavator_debuginfo::DebugInfo::parse(&pdb).unwrap();
        let mut namer = crate::names::Namer::new(&debug);
        // Every class declares f, which a base (by the cycle) declares
        // too, so nothing is reported; the walks must end.
        assert!(wasteful_virtuals(&classes, &mut namer, 8).is_empty());
    }

    #[test]
    fn byte_similarity() {
        assert_eq!(similarity(b"abcd", b"abcd"), 1.0);
        assert_eq!(similarity(b"abcd", b"abxd"), 0.75);
        assert_eq!(similarity(b"ab", b"abcd"), 0.5);
        assert_eq!(similarity(b"", b""), 1.0);
        assert_eq!(similarity(b"", b"a"), 0.0);
    }
}

/// What [`report`] lists, and how much of it.
#[derive(Clone, Copy, Debug)]
pub struct ReportOptions {
    /// Items per finding (0: all).
    pub limit: usize,
}

/// The findings as JSON: each kind's count, totals, and first items.
#[derive(serde::Serialize)]
struct Json<'a> {
    duplicate_data: Section<DupTotals, DupJson<'a>>,
    template_families: Section<SizeTotal, FamilyJson<'a>>,
    wasteful_virtuals: Section<WastedTotal, VirtualJson<'a>>,
}

#[derive(serde::Serialize)]
struct Section<T, I> {
    count: usize,
    #[serde(flatten)]
    totals: T,
    items: Vec<I>,
}

#[derive(serde::Serialize)]
struct DupTotals {
    wasted_file: u64,
    wasted_vm: u64,
}

#[derive(serde::Serialize)]
struct SizeTotal {
    size: u64,
}

#[derive(serde::Serialize)]
struct WastedTotal {
    wasted: u64,
}

#[derive(serde::Serialize)]
struct DupJson<'a> {
    name: &'a str,
    file_size: u64,
    vm_size: u64,
    copies: usize,
    wasted_file: u64,
    wasted_vm: u64,
    compilands: Vec<CopyJson>,
}

#[derive(serde::Serialize)]
struct CopyJson {
    rva: String,
    compiland: String,
}

#[derive(serde::Serialize)]
struct FamilyJson<'a> {
    family: &'a str,
    instances: usize,
    file_size: u64,
    vm_size: u64,
    largest: &'a str,
    largest_size: u64,
    similarity: Option<f64>,
}

#[derive(serde::Serialize)]
struct VirtualJson<'a> {
    class: &'a str,
    wasted: u64,
    per_slot: u64,
    pure_with_one_override: &'a [String],
    never_overridden: &'a [String],
}
/// Every finding of an image, as text and as JSON (`{"duplicate_data":
/// {...}, "template_families": {...}}`). `compiland_name` names a symbol's
/// compiland.
pub fn report(
    image: &Image<'_>,
    debug: &hexcavator_debuginfo::DebugInfo<'_>,
    symbols: &[Symbol],
    compiland_name: &dyn Fn(u32) -> String,
    options: ReportOptions,
) -> (String, String) {
    use std::fmt::Write as _;
    let limit = if options.limit == 0 {
        usize::MAX
    } else {
        options.limit
    };
    let dups = duplicate_data(image, symbols);
    let families = template_families(Some(image), symbols);
    let word = u64::from(image.arch().pointer_size().unwrap_or(8));
    let virtuals = match debug.classes() {
        Ok(classes) => {
            let mut namer = crate::names::Namer::new(debug);
            wasteful_virtuals(&classes, &mut namer, word)
        }
        Err(_) => Vec::new(),
    };
    let wasted_slots: u64 = virtuals.iter().map(WastefulVirtual::wasted).sum();
    let wasted = dups.iter().fold(Size::default(), |a, d| a + d.wasted());
    let mut text = String::new();
    let _ = writeln!(
        text,
        "Duplicate data: {} variables defined in several compilands; {} file bytes wasted ({} in memory).",
        dups.len(),
        wasted.file,
        wasted.vm
    );
    if !dups.is_empty() {
        let _ = writeln!(
            text,
            "A file-scope `static` or non-`extern` `const` in a header gets a copy in every compiland that includes it; make it `inline constexpr` (C++17) or `extern` with one definition."
        );
        let _ = writeln!(
            text,
            "{:>10} {:>10} {:>7}  Variable",
            "Wasted", "Size", "Copies"
        );
        for d in dups.iter().take(limit) {
            let w = d.wasted();
            let _ = writeln!(
                text,
                "{:>10} {:>10} {:>7}  {}",
                w.file.max(w.vm),
                d.size.file.max(d.size.vm),
                d.copies.len(),
                d.name
            );
        }
    }
    let _ = writeln!(text);
    let in_templates = families.iter().fold(Size::default(), |a, f| a + f.size);
    let _ = writeln!(
        text,
        "Template families: {} templates with several instantiations, {} bytes in all.",
        families.len(),
        in_templates.file.max(in_templates.vm)
    );
    if !families.is_empty() {
        let _ = writeln!(
            text,
            "Instances whose code is nearly identical (similarity near 100%) can share a type-independent base or helper; many instances of a small template often come from a parameter that needn't be one."
        );
        let _ = writeln!(
            text,
            "{:>10} {:>9} {:>7}  Template (largest instance)",
            "Size", "Instances", "Similar"
        );
        for f in families.iter().take(limit) {
            let similar = f
                .similarity
                .map_or_else(|| "-".to_string(), |s| format!("{:.0}%", s * 100.0));
            let _ = writeln!(
                text,
                "{:>10} {:>9} {:>7}  {}  ({}: {})",
                f.size.file.max(f.size.vm),
                f.instances,
                similar,
                f.family,
                ellipsize(&f.largest.0, 120),
                f.largest.1.file.max(f.largest.1.vm)
            );
        }
    }
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "Wasteful virtuals: {} classes with virtual functions that needn't be; {} bytes of vtable slots.",
        virtuals.len(),
        wasted_slots
    );
    if !virtuals.is_empty() {
        let _ = writeln!(
            text,
            "A virtual function no derived class overrides needn't be virtual; a pure one exactly one derived class implements could be that class's. Each costs a vtable slot in the class and in every class derived from it (and an indirect call)."
        );
        let _ = writeln!(text, "{:>10} {:>8}  Class: functions", "Wasted", "Per slot");
        for v in virtuals.iter().take(limit) {
            let functions: Vec<String> = v
                .pure_with_one_override
                .iter()
                .map(|f| format!("{f} (pure, one override)"))
                .chain(
                    v.unoverridden
                        .iter()
                        .map(|f| format!("{f} (never overridden)")),
                )
                .collect();
            let _ = writeln!(
                text,
                "{:>10} {:>8}  {}: {}",
                v.wasted(),
                v.per_slot,
                v.class,
                ellipsize(&functions.join("; "), 240)
            );
        }
    }
    let json = Json {
        duplicate_data: Section {
            count: dups.len(),
            totals: DupTotals {
                wasted_file: wasted.file,
                wasted_vm: wasted.vm,
            },
            items: dups
                .iter()
                .take(limit)
                .map(|d| {
                    let w = d.wasted();
                    DupJson {
                        name: &d.name,
                        file_size: d.size.file,
                        vm_size: d.size.vm,
                        copies: d.copies.len(),
                        wasted_file: w.file,
                        wasted_vm: w.vm,
                        compilands: d
                            .copies
                            .iter()
                            .map(|(addr, c)| CopyJson {
                                rva: format!("0x{addr:x}"),
                                compiland: compiland_name(*c),
                            })
                            .collect(),
                    }
                })
                .collect(),
        },
        template_families: Section {
            count: families.len(),
            totals: SizeTotal {
                size: in_templates.file.max(in_templates.vm),
            },
            items: families
                .iter()
                .take(limit)
                .map(|f| FamilyJson {
                    family: &f.family,
                    instances: f.instances,
                    file_size: f.size.file,
                    vm_size: f.size.vm,
                    largest: &f.largest.0,
                    largest_size: f.largest.1.file.max(f.largest.1.vm),
                    // Three decimals are all that mean anything.
                    similarity: f
                        .similarity
                        .map(|s| (f64::from(s) * 1000.0).round() / 1000.0),
                })
                .collect(),
        },
        wasteful_virtuals: Section {
            count: virtuals.len(),
            totals: WastedTotal {
                wasted: wasted_slots,
            },
            items: virtuals
                .iter()
                .take(limit)
                .map(|v| VirtualJson {
                    class: &v.class,
                    wasted: v.wasted(),
                    per_slot: v.per_slot,
                    pure_with_one_override: &v.pure_with_one_override,
                    never_overridden: &v.unoverridden,
                })
                .collect(),
        },
    };
    let mut json = serde_json::to_string(&json).unwrap_or_default();
    json.push('\n');
    (text, json)
}

/// `s`, cut to about `max` characters (on a character boundary) with an
/// ellipsis if longer.
fn ellipsize(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    match s.char_indices().nth(max) {
        Some((i, _)) => std::borrow::Cow::Owned(format!("{}...", &s[..i])),
        None => std::borrow::Cow::Borrowed(s),
    }
}

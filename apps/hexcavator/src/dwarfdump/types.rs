//! Type names as llvm-dwarfdump prints them for `DW_AT_type` (`int (**)()`,
//! `const char[16]`, `Outer::Inner *const`): a port of LLVM's
//! `DWARFTypePrinter` (llvm/DebugInfo/DWARF/DWARFTypePrinter.h, Apache
//! License 2.0 with LLVM Exceptions), without template parameters that the
//! name doesn't already have.
//!
//! Bounded: at most [`super::MAX_TYPE_DEPTH`] references deep, and at most
//! [`MAX_TEXT`] bytes of name.

use std::fmt::Write as _;

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Die, Value};

/// The longest name built.
const MAX_TEXT: usize = 4096;

/// The most types visited naming one type (a type graph shared many ways
/// is not walked exponentially).
const MAX_STEPS: usize = 4096;

/// The units' DIEs, for naming types: read on demand from the index,
/// across units (`DW_FORM_ref_addr`).
pub struct Types<'i, 'd> {
    pub(super) index: &'i super::Index<'d>,
    /// Names already made, by DIE (a type is named wherever it is used;
    /// naming walks its children for template parameters).
    names: std::cell::RefCell<std::collections::HashMap<(usize, u64), std::rc::Rc<str>>>,
}

/// A DIE and the unit it is in.
#[derive(Clone)]
pub struct Node<'d> {
    pub unit: usize,
    pub die: Die<'d>,
}

impl<'i, 'd> Types<'i, 'd> {
    pub fn new(index: &'i super::Index<'d>) -> Self {
        Self {
            index,
            names: std::cell::RefCell::default(),
        }
    }

    /// The qualified name of the type at `offset` (in unit `unit`'s
    /// section).
    pub fn name(&self, unit: usize, offset: u64) -> std::rc::Rc<str> {
        if let Some(n) = self.names.borrow().get(&(unit, offset)) {
            return std::rc::Rc::clone(n);
        }
        let mut p = Printer {
            t: self,
            out: String::new(),
            word: true,
            ended_with_template: false,
            depth: 0,
            steps: 0,
        };
        let d = self.index.node(unit, offset);
        p.qualified_name(d.as_ref());
        let name: std::rc::Rc<str> = p.out.into();
        self.names
            .borrow_mut()
            .insert((unit, offset), std::rc::Rc::clone(&name));
        name
    }

    fn referenced(&self, d: &Node<'d>, attr: u16) -> Option<Node<'d>> {
        let a = d.die.attr(attr)?;
        let (u, off) = self.index.resolve(d.unit, a)?;
        self.index.node(u, off)
    }

    fn string(&self, d: &Node<'d>, attr: u16) -> Option<String> {
        let a = d.die.attr(attr)?;
        self.index.units[d.unit]
            .unit
            .string(&a.value)
            .map(|s| String::from_utf8_lossy(s.bytes).into_owned())
    }

    fn constant(&self, d: &Node<'d>, attr: u16) -> Option<u64> {
        let a = d.die.attr(attr)?;
        // (Constant forms only, as LLVM's getAsUnsignedConstant: a count
        // that is a reference or an expression, a variable length array's,
        // is no constant.)
        if !matches!(
            a.form,
            DW_FORM_DATA1
                | DW_FORM_DATA2
                | DW_FORM_DATA4
                | DW_FORM_DATA8
                | DW_FORM_UDATA
                | DW_FORM_SDATA
                | DW_FORM_IMPLICIT_CONST
        ) {
            return None;
        }
        match a.value {
            Value::Sint(v) => u64::try_from(v).ok(),
            _ => self.index.units[d.unit].unit.uint(&a.value),
        }
    }

    fn parent(&self, d: &Node<'d>) -> Option<Node<'d>> {
        let p = self.index.parent(d.unit, d.die.offset)?;
        self.index.node(d.unit, p)
    }

    fn children(&self, d: &Node<'d>) -> Vec<Node<'d>> {
        let u = &self.index.units[d.unit];
        u.unit
            .children(&u.abbrevs, &d.die)
            .into_iter()
            .map(|die| Node { unit: d.unit, die })
            .collect()
    }

    /// The language's default lower bound for arrays, as LLVM knows it.
    fn default_lower_bound(&self, d: &Node<'d>) -> Option<u64> {
        hexcavator_dwarf::spelling::language_lower_bound(self.index.units[d.unit].language?)
    }
}

struct Printer<'t, 'i, 'd> {
    t: &'t Types<'i, 'd>,
    out: String,
    word: bool,
    ended_with_template: bool,
    /// How deep the naming is (types within types), and how many steps
    /// it has taken in all.
    depth: usize,
    steps: usize,
}

fn tag_of(d: Option<&Node<'_>>) -> Option<u16> {
    d.map(|d| d.die.tag)
}

impl<'d> Printer<'_, '_, 'd> {
    /// Enters a type within the type being named, if the bounds allow:
    /// [`super::MAX_TYPE_DEPTH`] deep, [`MAX_STEPS`] in all, [`MAX_TEXT`]
    /// bytes of name. [`Self::leave`] undoes it.
    fn enter(&mut self) -> bool {
        if self.depth >= super::MAX_TYPE_DEPTH
            || self.steps >= MAX_STEPS
            || self.out.len() > MAX_TEXT
        {
            return false;
        }
        self.depth += 1;
        self.steps += 1;
        true
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn inner(&self, d: &Node<'d>) -> Option<Node<'d>> {
        self.t.referenced(d, DW_AT_TYPE)
    }

    fn skip_qualifiers(&self, mut d: Option<Node<'d>>) -> Option<Node<'d>> {
        let mut n = 0;
        while let Some(x) = &d {
            if !matches!(x.die.tag, DW_TAG_CONST_TYPE | DW_TAG_VOLATILE_TYPE)
                || n > super::MAX_TYPE_DEPTH
            {
                break;
            }
            d = self.inner(x);
            n += 1;
        }
        d
    }

    fn needs_parens(&self, d: Option<&Node<'d>>) -> bool {
        let d = self.skip_qualifiers(d.cloned());
        matches!(
            tag_of(d.as_ref()),
            Some(DW_TAG_SUBROUTINE_TYPE | DW_TAG_ARRAY_TYPE)
        )
    }

    fn scoped(tag: u16) -> bool {
        matches!(
            tag,
            DW_TAG_STRUCTURE_TYPE
                | DW_TAG_CLASS_TYPE
                | DW_TAG_UNION_TYPE
                | DW_TAG_NAMESPACE
                | DW_TAG_ENUMERATION_TYPE
                | DW_TAG_TYPEDEF
        )
    }

    fn qualified_name(&mut self, d: Option<&Node<'d>>) {
        if let Some(x) = d
            && Self::scoped(x.die.tag)
            && let Some(p) = self.t.parent(x)
        {
            self.scopes(&p);
        }
        self.unqualified_name(d);
    }

    fn qualified_name_before(&mut self, d: Option<&Node<'d>>) -> Option<Node<'d>> {
        if let Some(x) = d
            && Self::scoped(x.die.tag)
            && let Some(p) = self.t.parent(x)
        {
            self.scopes(&p);
        }
        self.unqualified_name_before(d)
    }

    fn unqualified_name(&mut self, d: Option<&Node<'d>>) {
        let inner = self.unqualified_name_before(d);
        self.unqualified_name_after(d, inner.as_ref(), false);
    }

    fn pointer_like_before(&mut self, inner: Option<&Node<'d>>, ptr: &str) {
        self.qualified_name_before(inner);
        if self.word {
            self.out.push(' ');
        }
        if self.needs_parens(inner) {
            self.out.push('(');
        }
        self.out.push_str(ptr);
        self.word = false;
        self.ended_with_template = false;
    }

    fn unqualified_name_before(&mut self, d: Option<&Node<'d>>) -> Option<Node<'d>> {
        self.word = true;
        let Some(d) = d else {
            self.out.push_str("void");
            return None;
        };
        if !self.enter() {
            return None;
        }
        let inner = self.before(d);
        self.leave();
        inner
    }

    fn before(&mut self, d: &Node<'d>) -> Option<Node<'d>> {
        let inner = self.inner(d);
        match d.die.tag {
            DW_TAG_POINTER_TYPE => self.pointer_like_before(inner.as_ref(), "*"),
            DW_TAG_REFERENCE_TYPE => self.pointer_like_before(inner.as_ref(), "&"),
            DW_TAG_RVALUE_REFERENCE_TYPE => self.pointer_like_before(inner.as_ref(), "&&"),
            DW_TAG_SUBROUTINE_TYPE => {
                self.qualified_name_before(inner.as_ref());
                if self.word {
                    self.out.push(' ');
                }
                self.word = false;
            }
            DW_TAG_ARRAY_TYPE => {
                self.qualified_name_before(inner.as_ref());
            }
            DW_TAG_PTR_TO_MEMBER_TYPE => {
                self.qualified_name_before(inner.as_ref());
                if self.needs_parens(inner.as_ref()) {
                    self.out.push('(');
                } else if self.word {
                    self.out.push(' ');
                }
                if let Some(c) = self.t.referenced(d, DW_AT_CONTAINING_TYPE) {
                    self.qualified_name(Some(&c));
                    self.ended_with_template = false;
                    self.out.push_str("::");
                }
                self.out.push('*');
                self.word = false;
            }
            DW_TAG_CONST_TYPE | DW_TAG_VOLATILE_TYPE => self.const_volatile_before(d),
            DW_TAG_NAMESPACE => match self.t.string(d, DW_AT_NAME) {
                Some(n) => self.out.push_str(&n),
                None => self.out.push_str("(anonymous namespace)"),
            },
            DW_TAG_UNSPECIFIED_TYPE => {
                let n = self.t.string(d, DW_AT_NAME).unwrap_or_default();
                self.word = true;
                self.out.push_str(if n == "decltype(nullptr)" {
                    "std::nullptr_t"
                } else {
                    &n
                });
                self.ended_with_template = false;
            }
            _ => {
                let Some(name) = self.t.string(d, DW_AT_NAME) else {
                    // The tag's name: `struct `, `union `.
                    if let Some(t) = hexcavator_dwarf::spelling::tag(u64::from(d.die.tag))
                        && let Some(k) = t
                            .strip_prefix("DW_TAG_")
                            .and_then(|r| r.strip_suffix("_type"))
                    {
                        let _ = write!(self.out, "{k} ");
                    }
                    return None;
                };
                self.word = true;
                self.ended_with_template = name.ends_with('>');
                self.out.push_str(&name);
                // Template parameters the name doesn't have (Rust's enum
                // variants, `None<u32 *>`).
                if !name.ends_with('>') && self.template_parameters(d, &mut true) {
                    if self.ended_with_template {
                        self.out.push(' ');
                    }
                    self.out.push('>');
                    self.ended_with_template = true;
                    self.word = true;
                }
            }
        }
        inner
    }

    fn unqualified_name_after(
        &mut self,
        d: Option<&Node<'d>>,
        inner: Option<&Node<'d>>,
        skip_artificial: bool,
    ) {
        let Some(d) = d else { return };
        if !self.enter() {
            return;
        }
        self.after(d, inner, skip_artificial);
        self.leave();
    }

    fn after(&mut self, d: &Node<'d>, inner: Option<&Node<'d>>, skip_artificial: bool) {
        match d.die.tag {
            DW_TAG_SUBROUTINE_TYPE => {
                self.subroutine_after(d, inner, skip_artificial, false, false);
            }
            DW_TAG_ARRAY_TYPE => self.array(d),
            DW_TAG_CONST_TYPE | DW_TAG_VOLATILE_TYPE => self.const_volatile_after(d),
            DW_TAG_PTR_TO_MEMBER_TYPE
            | DW_TAG_REFERENCE_TYPE
            | DW_TAG_RVALUE_REFERENCE_TYPE
            | DW_TAG_POINTER_TYPE => {
                if self.needs_parens(inner) {
                    self.out.push(')');
                }
                let next = inner.and_then(|i| self.inner(i));
                self.unqualified_name_after(
                    inner,
                    next.as_ref(),
                    d.die.tag == DW_TAG_PTR_TO_MEMBER_TYPE,
                );
            }
            _ => {}
        }
    }

    fn array(&mut self, d: &Node<'d>) {
        let default = self.t.default_lower_bound(d);
        for c in self.t.children(d) {
            if c.die.tag != DW_TAG_SUBRANGE_TYPE {
                continue;
            }
            let mut lb = self.t.constant(&c, DW_AT_LOWER_BOUND);
            let count = self.t.constant(&c, DW_AT_COUNT);
            let ub = self.t.constant(&c, DW_AT_UPPER_BOUND);
            if let (Some(l), Some(dl)) = (lb, default)
                && l == dl
            {
                lb = None;
            }
            if lb.is_none() && count.is_none() && ub.is_none() {
                self.out.push_str("[]");
            } else if let (None, true, Some(dl)) = (lb, count.is_some() || ub.is_some(), default) {
                let n = count.unwrap_or_else(|| ub.unwrap_or(0).wrapping_sub(dl).wrapping_add(1));
                let _ = write!(self.out, "[{n}]");
            } else {
                self.out.push_str("[[");
                match lb {
                    Some(l) => {
                        let _ = write!(self.out, "{l}");
                    }
                    None => self.out.push('?'),
                }
                self.out.push_str(", ");
                match (count, ub) {
                    (Some(c), _) => match lb {
                        Some(l) => {
                            let _ = write!(self.out, "{}", l.wrapping_add(c));
                        }
                        None => {
                            let _ = write!(self.out, "? + {c}");
                        }
                    },
                    (None, Some(u)) => {
                        let _ = write!(self.out, "{}", u.wrapping_add(1));
                    }
                    (None, None) => self.out.push('?'),
                }
                self.out.push_str(")]");
            }
        }
        self.ended_with_template = false;
    }

    /// (node, the type under its qualifiers, const, volatile)
    fn decompose(&self, n: &Node<'d>) -> (Option<Node<'d>>, bool, bool) {
        let (mut c, mut v) = (
            n.die.tag == DW_TAG_CONST_TYPE,
            n.die.tag == DW_TAG_VOLATILE_TYPE,
        );
        let mut t = self.inner(n);
        if let Some(x) = &t {
            if x.die.tag == DW_TAG_CONST_TYPE {
                c = true;
                t = self.inner(x);
            } else if x.die.tag == DW_TAG_VOLATILE_TYPE {
                v = true;
                t = self.inner(x);
            }
        }
        (t, c, v)
    }

    fn const_volatile_after(&mut self, n: &Node<'d>) {
        let (t, c, v) = self.decompose(n);
        if let Some(x) = &t
            && x.die.tag == DW_TAG_SUBROUTINE_TYPE
        {
            let inner = self.inner(x);
            self.subroutine_after(x, inner.as_ref(), false, c, v);
            return;
        }
        let inner = t.as_ref().and_then(|x| self.inner(x));
        self.unqualified_name_after(t.as_ref(), inner.as_ref(), false);
    }

    fn const_volatile_before(&mut self, n: &Node<'d>) {
        let (t, c, v) = self.decompose(n);
        let subroutine = tag_of(t.as_ref()) == Some(DW_TAG_SUBROUTINE_TYPE);
        let mut a = t.clone();
        let mut guard = 0;
        while tag_of(a.as_ref()) == Some(DW_TAG_ARRAY_TYPE) && guard < super::MAX_TYPE_DEPTH {
            a = a.as_ref().and_then(|x| self.inner(x));
            guard += 1;
        }
        let leading = !matches!(
            tag_of(a.as_ref()),
            Some(DW_TAG_POINTER_TYPE | DW_TAG_PTR_TO_MEMBER_TYPE)
        ) && !subroutine;
        if leading {
            if c {
                self.out.push_str("const ");
            }
            if v {
                self.out.push_str("volatile ");
            }
        }
        self.qualified_name_before(t.as_ref());
        if !leading && !subroutine {
            self.word = true;
            if c {
                self.out.push_str("const");
            }
            if v {
                if c {
                    self.out.push(' ');
                }
                self.out.push_str("volatile");
            }
        }
    }

    fn subroutine_after(
        &mut self,
        d: &Node<'d>,
        inner: Option<&Node<'d>>,
        skip_artificial: bool,
        mut is_const: bool,
        mut is_volatile: bool,
    ) {
        self.out.push('(');
        self.ended_with_template = false;
        let mut first = true;
        let mut real_first = true;
        let mut artificial: Option<Node<'d>> = None;
        for p in self.t.children(d) {
            if p.die.tag != DW_TAG_FORMAL_PARAMETER && p.die.tag != DW_TAG_UNSPECIFIED_PARAMETERS {
                return;
            }
            let t = self.inner(&p);
            if skip_artificial && real_first && p.die.attr(DW_AT_ARTIFICIAL).is_some() {
                artificial = t;
                real_first = false;
                continue;
            }
            if !first {
                self.out.push_str(", ");
            }
            first = false;
            if p.die.tag == DW_TAG_UNSPECIFIED_PARAMETERS {
                self.out.push_str("...");
            } else {
                self.qualified_name(t.as_ref());
            }
        }
        self.ended_with_template = false;
        self.out.push(')');
        if let Some(p) = artificial.filter(|p| p.die.tag == DW_TAG_POINTER_TYPE) {
            let step = |cv: &Node<'d>, c: &mut bool, v: &mut bool| {
                let u = self.inner(cv)?;
                *c |= u.die.tag == DW_TAG_CONST_TYPE;
                *v |= u.die.tag == DW_TAG_VOLATILE_TYPE;
                Some(u)
            };
            if let Some(cv) = step(&p, &mut is_const, &mut is_volatile) {
                step(&cv, &mut is_const, &mut is_volatile);
            }
        }
        if let Some(cc) = self.t.constant(d, DW_AT_CALLING_CONVENTION) {
            let attr = match cc {
                0x41 => Some("stdcall"),
                0x42 => Some("pascal"),
                0x43 => Some("fastcall"),
                0x44 => Some("thiscall"),
                _ => None,
            };
            if let Some(a) = attr {
                let _ = write!(self.out, " __attribute__(({a}))");
            }
        }
        if is_const {
            self.out.push_str(" const");
        }
        if is_volatile {
            self.out.push_str(" volatile");
        }
        if d.die.attr(DW_AT_REFERENCE).is_some() {
            self.out.push_str(" &");
        }
        if d.die.attr(DW_AT_RVALUE_REFERENCE).is_some() {
            self.out.push_str(" &&");
        }
        let next = inner.and_then(|i| self.inner(i));
        self.unqualified_name_after(inner, next.as_ref(), false);
    }

    /// A DIE's template parameters, `<int, 5>`, as LLVM's
    /// `appendTemplateParameters` writes them (without the closing `>`):
    /// whether it has any. `first`: whether none has been written yet
    /// (packs continue their parent's list).
    fn template_parameters(&mut self, d: &Node<'d>, first: &mut bool) -> bool {
        let mut is_template = false;
        let top = *first;
        if !self.enter() {
            return false;
        }
        for c in self.t.children(d) {
            let sep = |p: &mut Self, first: &mut bool| {
                p.out.push_str(if *first { "<" } else { ", " });
                p.ended_with_template = false;
                *first = false;
            };
            match c.die.tag {
                DW_TAG_GNU_TEMPLATE_PARAMETER_PACK => {
                    is_template = true;
                    self.template_parameters(&c, first);
                }
                DW_TAG_TEMPLATE_VALUE_PARAMETER => {
                    is_template = true;
                    let t = self.inner(&c);
                    sep(self, first);
                    self.template_value(&c, t.as_ref());
                }
                DW_TAG_GNU_TEMPLATE_TEMPLATE_PARAM => {
                    if let Some(n) = self.t.string(&c, DW_AT_GNU_TEMPLATE_NAME) {
                        is_template = true;
                        sep(self, first);
                        self.out.push_str(&n);
                    }
                }
                DW_TAG_TEMPLATE_TYPE_PARAMETER => {
                    is_template = true;
                    sep(self, first);
                    // (Typedefs unwrapped, as LLVM's
                    // unwrapReferencedTypedefType.)
                    let mut t = self.inner(&c);
                    let mut n = 0;
                    while let Some(x) = &t {
                        if x.die.tag != DW_TAG_TYPEDEF || n > super::MAX_TYPE_DEPTH {
                            break;
                        }
                        t = self.inner(x);
                        n += 1;
                    }
                    self.qualified_name(t.as_ref());
                }
                _ => {}
            }
        }
        self.leave();
        if is_template && *first && top {
            self.out.push('<');
            self.ended_with_template = false;
        }
        is_template
    }

    /// A template value parameter's value, as LLVM writes the kinds it
    /// knows (`true`, `5`, `5U`, `'a'`, `(short)5`).
    fn template_value(&mut self, c: &Node<'d>, t: Option<&Node<'d>>) {
        let Some(t) = t else { return };
        let a = c.die.attr(DW_AT_CONST_VALUE);
        let unit = &self.t.index.units[c.unit].unit;
        let signed = a.and_then(|a| match a.value {
            Value::Sint(v) => Some(v),
            _ => unit.uint(&a.value).map(|v| v as i64),
        });
        let unsigned = signed.map(|v| v as u64);
        if t.die.tag == DW_TAG_ENUMERATION_TYPE {
            if let Some(v) = signed {
                self.out.push('(');
                self.qualified_name(Some(t));
                let _ = write!(self.out, "){v}");
            }
            return;
        }
        if matches!(
            t.die.tag,
            DW_TAG_POINTER_TYPE | DW_TAG_REFERENCE_TYPE | DW_TAG_PTR_TO_MEMBER_TYPE
        ) {
            return;
        }
        let Some(name) = self.t.string(t, DW_AT_NAME) else {
            return;
        };
        let (Some(s), Some(u)) = (signed, unsigned) else {
            return;
        };
        match name.as_str() {
            "bool" => self.out.push_str(if u != 0 { "true" } else { "false" }),
            "short" | "unsigned short" => {
                let _ = write!(self.out, "({name}){s}");
            }
            "int" => {
                let _ = write!(self.out, "{s}");
            }
            "long" => {
                let _ = write!(self.out, "{s}L");
            }
            "long long" => {
                let _ = write!(self.out, "{s}LL");
            }
            "unsigned int" => {
                let _ = write!(self.out, "{u}U");
            }
            "unsigned long" => {
                let _ = write!(self.out, "{u}UL");
            }
            "unsigned long long" => {
                let _ = write!(self.out, "{u}ULL");
            }
            "char" | "unsigned char" | "signed char" => {
                if name != "char" {
                    let _ = write!(self.out, "({name})");
                }
                let mut v = s;
                let text = match v {
                    0x5C => "'\\\\'".to_string(),
                    0x27 => "'\\''".to_string(),
                    7 => "'\\a'".to_string(),
                    8 => "'\\b'".to_string(),
                    12 => "'\\f'".to_string(),
                    10 => "'\\n'".to_string(),
                    13 => "'\\r'".to_string(),
                    9 => "'\\t'".to_string(),
                    11 => "'\\v'".to_string(),
                    _ => {
                        if (v & !0xFF) == !0xFF {
                            v &= 0xFF;
                        }
                        if let Some(c) = u8::try_from(v).ok().filter(|c| (32..127).contains(c)) {
                            format!("'{}'", char::from(c))
                        } else if v < 256 {
                            format!("'\\x{v:02x}'")
                        } else if v <= 0xFFFF {
                            format!("'\\u{v:04x}'")
                        } else {
                            format!("'\\U{v:08x}'")
                        }
                    }
                };
                self.out.push_str(&text);
            }
            _ if name.starts_with("_BitInt") || name.starts_with("unsigned _BitInt") => {
                self.out.push('(');
                self.qualified_name(Some(t));
                if name.starts_with("unsigned") {
                    let _ = write!(self.out, "){u}");
                } else {
                    let _ = write!(self.out, "){s}");
                }
            }
            _ => {}
        }
    }

    fn scopes(&mut self, d: &Node<'d>) {
        if matches!(
            d.die.tag,
            DW_TAG_COMPILE_UNIT
                | DW_TAG_TYPE_UNIT
                | DW_TAG_SKELETON_UNIT
                | DW_TAG_SUBPROGRAM
                | DW_TAG_LEXICAL_BLOCK
        ) {
            return;
        }
        if !self.enter() {
            return;
        }
        if let Some(p) = self.t.parent(d) {
            self.scopes(&p);
        }
        self.unqualified_name(Some(d));
        self.out.push_str("::");
        self.leave();
    }
}

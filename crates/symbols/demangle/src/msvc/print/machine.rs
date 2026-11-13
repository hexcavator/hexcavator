//! The printer's machine: everything `native.rs` writes, with its
//! recursion on a stack of its own.
//!
//! Types read as C declarations do: a type is written around a declarator
//! (`int` around `* __ptr64 x` is `int * __ptr64 x`), and pointers to
//! functions and arrays parenthesize theirs. The declarator is built as a
//! chain of [`Decl`] pieces, then written once, in order, into the output:
//! printing makes no intermediate strings.
//!
//! Names come from untrusted files, and the tree nests as deeply as the
//! parser allows, so printing doesn't recurse on the thread's stack: a type
//! wrapping another is unwrapped in a loop, and what must be written after
//! something nested (a parameter list after its function's name, `>` after
//! template arguments) is a [`Task`] on a stack of the printer's own.

use alloc::string::String;

use hexcavator_core::stack::SmallStack;

use crate::msvc::flags;

use super::*;

/// A declarator's index in [`Run::decls`]; [`EMPTY`] is the empty one.
pub(super) type D = usize;

/// The empty declarator.
pub(super) const EMPTY: D = 0;

/// A declarator: what goes after (and, for pointers to functions and
/// arrays, around) a type's own text. Each piece's `D` is the rest.
#[derive(Clone, Copy, Default)]
pub(super) enum Decl<'r> {
    #[default]
    Empty,
    /// Words, then (with a space) the rest, if any: `const x`.
    Words(&'static str, D),
    /// Words, a space, then the rest even if it is empty: `const ` (how
    /// undname writes `$$C` qualifiers).
    Spaced(&'static str, D),
    /// Text directly followed by the rest: `__cdecl*`.
    Glued(&'static str, D),
    /// `* __ptr64 const`, then (with a space) the rest.
    Pointer(Indirection, Cv, PointerModifiers, D),
    /// A function pointer's own part: `*`, `*const`, `* __ptr64`; the rest
    /// follows with a space, or directly after a bare `*` (`**`, `*&`,
    /// and, for a returned pointer, the function: `*__cdecl f(void)`).
    FunctionPointer(Indirection, Cv, PointerModifiers, bool, D),
    /// `Class::` then the rest.
    Member(&'r QualifiedName<'r>, D),
    Parens(D),
    /// The rest, then `[n]...`.
    Dims(D, &'r [u64]),
    /// The rest, then `(params)` and the `this` qualifiers.
    Call(D, &'r FunctionType<'r>),
    /// A symbol's name (with a conversion operator's type), then a suffix.
    Name(
        &'r QualifiedName<'r>,
        Option<&'r Type<'r>>,
        Option<&'r Adjustment>,
    ),
}

/// Something still to write, in order: a stack of these replaces
/// recursion.
#[derive(Clone, Copy, Default)]
pub(super) enum Task<'r> {
    #[default]
    Nothing,
    Text(&'static str),
    Char(char),
    /// A type around a declarator (`returned`: see [`Run::ty`]).
    Type(&'r Type<'r>, D, bool),
    Decl(D),
    Symbol(&'r Symbol<'r>),
    /// A qualified name (with a conversion operator's type), from its
    /// `n`th component.
    Qualified(&'r QualifiedName<'r>, Option<&'r Type<'r>>, usize),
    /// Template arguments, from the `n`th.
    TemplateArgs(&'r [TemplateArg<'r>], usize),
    /// A function's parameter list, from the `n`th parameter.
    Params(&'r FunctionType<'r>, usize),
    /// `>` after template arguments, then a conversion template's type.
    CloseTemplate(Option<&'r Type<'r>>),
    /// A C++/CLI array's rank, after its element type.
    Rank(u8),
    Dims(&'r [u64]),
    Adjustment(&'r Adjustment),
    /// A tuple's values, after its symbol (if it has one).
    TupleValues(&'r [i64], bool),
    /// `vcall` thunk's offset, after its name.
    Vcall(u64),
    /// A guard's number, after its name.
    Guard(u64),
}

/// Whether [`Run::name`] writes `n` without deferring anything.
fn immediate(n: &Name<'_>, prev: Option<&Name<'_>>, conversion: Option<&Type<'_>>) -> bool {
    match n {
        Name::Identifier(_)
        | Name::Operator(_)
        | Name::Special(_)
        | Name::BaseClassDescriptor(..)
        | Name::Literal(_)
        | Name::AnonymousNamespace(_)
        | Name::Frame(_) => true,
        Name::Constructor | Name::Destructor => prev.is_none_or(|p| {
            !matches!(p, Name::Constructor | Name::Destructor) && immediate(p, None, None)
        }),
        Name::Conversion => conversion.is_none(),
        _ => false,
    }
}

impl Printer {
    pub(super) fn machine_symbol(&self, out: &mut String, s: &Symbol<'_>) {
        Run::new(self, out).finish(Task::Symbol(s));
    }

    pub(super) fn machine_qualified(
        &self,
        out: &mut String,
        q: &QualifiedName<'_>,
        conversion: Option<&Type<'_>>,
    ) {
        Run::new(self, out).finish(Task::Qualified(q, conversion, 0));
    }
}

/// One printing: the output, and the declarators and tasks.
pub(super) struct Run<'p, 'o, 'r> {
    p: &'p Printer,
    out: &'o mut String,
    decls: SmallStack<Decl<'r>, 8>,
    tasks: SmallStack<Task<'r>, 8>,
}

impl<'p, 'o, 'r> Run<'p, 'o, 'r> {
    pub(super) fn new(p: &'p Printer, out: &'o mut String) -> Self {
        let mut decls = SmallStack::new();
        decls.push(Decl::Empty);
        Self {
            p,
            out,
            decls,
            tasks: SmallStack::new(),
        }
    }

    /// Writes `task` and everything it leads to.
    pub(super) fn finish(mut self, task: Task<'r>) {
        self.tasks.push(task);
        while let Some(t) = self.tasks.pop() {
            self.task(t);
        }
    }

    /// Adds a declarator.
    pub(super) fn decl(&mut self, d: Decl<'r>) -> D {
        // (Declarators are bounded by the tree, which is by the name.)
        self.decls.push(d)
    }

    fn get(&self, d: D) -> Decl<'r> {
        self.decls.get(d).unwrap_or_default()
    }

    /// Defers `t` until what is pushed after it is written.
    fn then(&mut self, t: Task<'r>) {
        self.tasks.push(t);
    }

    fn task(&mut self, t: Task<'r>) {
        match t {
            Task::Nothing => {}
            Task::Text(s) => self.out.push_str(s),
            Task::Char(c) => self.out.push(c),
            Task::Type(t, d, returned) => self.ty(t, d, returned),
            Task::Decl(d) => self.write_decl(d),
            Task::Symbol(s) => self.symbol(s),
            Task::Qualified(q, conversion, from) => self.qualified(q, conversion, from),
            Task::TemplateArgs(args, from) => self.template_args(args, from),
            Task::Params(sig, from) => self.params(sig, from),
            Task::CloseTemplate(conversion) => {
                if self.out.ends_with('>') {
                    self.out.push(' ');
                }
                self.out.push('>');
                if let Some(t) = conversion {
                    self.out.push(' ');
                    self.then(Task::Type(t, EMPTY, false));
                }
            }
            Task::Rank(rank) => {
                if rank > 1 {
                    let _ = write!(self.out, ",{rank}");
                }
                self.out.push_str(" >");
            }
            Task::Dims(dims) => {
                for n in dims {
                    let _ = write!(self.out, "[{n}]");
                }
            }
            Task::Adjustment(a) => {
                let _ = match *a {
                    Adjustment::Adjustor(a) => write!(self.out, "`adjustor{{{a}}}' "),
                    Adjustment::Vtordisp(a, b) => write!(self.out, "`vtordisp{{{a},{b}}}' "),
                    Adjustment::VtordispEx(a, b, c, d) => {
                        write!(self.out, "`vtordispex{{{a},{b},{c},{d}}}' ")
                    }
                };
            }
            Task::TupleValues(values, after_symbol) => {
                for (i, v) in values.iter().enumerate() {
                    if i > 0 || after_symbol {
                        self.out.push(',');
                    }
                    let _ = write!(self.out, "{v}");
                }
                self.out.push('}');
            }
            Task::Vcall(offset) => {
                let _ = write!(self.out, "{{{offset},{{flat}}}}' }}'");
            }
            Task::Guard(n) => {
                let _ = write!(self.out, "{{{n}}}'");
            }
        }
    }

    fn symbol(&mut self, s: &'r Symbol<'r>) {
        let p = self.p;
        if p.name_only() {
            match &s.kind {
                SymbolKind::Hashed(text) => self.out.push_str(text),
                SymbolKind::TypeDescriptor(ty) => {
                    self.then(Task::Qualified(&s.name, None, 0));
                    self.then(Task::Char(' '));
                    self.then(Task::Type(ty, EMPTY, false));
                }
                SymbolKind::Function(f) => {
                    self.then(Task::Qualified(&s.name, f.signature.returns.as_ref(), 0));
                }
                SymbolKind::VcallThunk { offset, .. } => {
                    self.then(Task::Guard(*offset));
                    self.then(Task::Qualified(&s.name, None, 0));
                }
                _ => self.then(Task::Qualified(&s.name, None, 0)),
            }
            return;
        }
        let name = self.decl(Decl::Name(&s.name, None, None));
        match &s.kind {
            SymbolKind::Hashed(text) => self.out.push_str(text),
            SymbolKind::NameOnly => self.then(Task::Qualified(&s.name, None, 0)),
            SymbolKind::LocalStaticGuard(n) => {
                self.then(Task::Guard(*n));
                self.then(Task::Qualified(&s.name, None, 0));
            }
            SymbolKind::Function(f) => self.function(&s.name, f),
            SymbolKind::Variable {
                access,
                ty,
                cv,
                modifiers,
            } => {
                if access.is_some() {
                    self.out.push_str(p.access(*access));
                    if p.flags & flags::NO_MEMBER_TYPE == 0 {
                        self.out.push_str("static ");
                    }
                }
                let storage = self.decl(Decl::Words(p.storage(*cv, *modifiers), name));
                // A pointer variable's qualifiers are encoded twice, in the
                // pointer and in the storage class; undname shows the
                // storage class's.
                match ty {
                    Type::Pointer {
                        kind,
                        modifiers,
                        pointee,
                        ..
                    } => self.pointer(*kind, Cv::default(), *modifiers, pointee, storage, false),
                    _ => self.ty(ty, storage, false),
                }
            }
            SymbolKind::Table {
                cv,
                modifiers,
                targets,
            } => {
                if !targets.is_empty() {
                    self.then(Task::Char('}'));
                    for (i, t) in targets.iter().enumerate().rev() {
                        self.then(Task::Char('\''));
                        self.then(Task::Qualified(t, None, 0));
                        self.then(Task::Char('`'));
                        if i > 0 {
                            self.then(Task::Text("s "));
                        }
                    }
                    self.then(Task::Text("{for "));
                }
                let d = self.decl(Decl::Words(p.storage(*cv, *modifiers), name));
                self.write_decl(d);
            }
            SymbolKind::TypeDescriptor(ty) => {
                self.then(Task::Qualified(&s.name, None, 0));
                self.then(Task::Char(' '));
                self.ty(ty, EMPTY, false);
            }
            SymbolKind::VcallThunk {
                offset,
                calling_convention,
            } => {
                let cc = if p.keywords() && p.flags & flags::NO_ALLOCATION_LANGUAGE == 0 {
                    p.kw(calling_convention)
                } else {
                    ""
                };
                if cc.is_empty() {
                    self.out.push_str("[thunk]:");
                } else {
                    let _ = write!(self.out, "[thunk]: {cc} ");
                }
                self.then(Task::Vcall(*offset));
                self.then(Task::Qualified(&s.name, None, 0));
            }
        }
    }

    fn function(&mut self, name: &'r QualifiedName<'r>, f: &'r Function<'r>) {
        let p = self.p;
        let sig = &f.signature;
        if f.extern_c {
            self.out.push_str("extern \"C\" ");
        }
        if f.adjustment.is_some() {
            self.out.push_str("[thunk]:");
        }
        self.out.push_str(p.access(f.access));
        if p.flags & flags::NO_MEMBER_TYPE == 0 {
            match f.class {
                FunctionClass::Static => self.out.push_str("static "),
                FunctionClass::Virtual => self.out.push_str("virtual "),
                _ => {}
            }
        }
        let conversion = match name.last() {
            Some(Name::Conversion) => true,
            Some(Name::Template { name, .. }) => **name == Name::Conversion,
            _ => false,
        };
        let shown = self.decl(Decl::Name(
            name,
            sig.returns.as_ref().filter(|_| conversion),
            f.adjustment.as_ref(),
        ));
        let named = self.decl(Decl::Words(p.decl_cc(sig), shown));
        let decl = self.decl(Decl::Call(named, sig));
        let returns = p.flags & flags::NO_FUNCTION_RETURNS == 0;
        match sig.returns.as_ref().filter(|_| !conversion && returns) {
            // A returned pointer's own qualifiers are not shown.
            Some(Type::Pointer {
                kind,
                modifiers,
                pointee,
                ..
            }) => self.pointer(*kind, Cv::default(), *modifiers, pointee, decl, true),
            Some(r) => self.ty(r, decl, true),
            None => self.write_decl(decl),
        }
    }

    // ---- Declarators ---------------------------------------------------

    fn is_empty(&self, mut d: D) -> bool {
        loop {
            match self.get(d) {
                Decl::Empty => return true,
                Decl::Words(w, rest) | Decl::Glued(w, rest) if w.is_empty() => d = rest,
                _ => return false,
            }
        }
    }

    /// Whether the declarator starts with `*` or `&`.
    fn starts_with_pointer(&self, mut d: D) -> bool {
        loop {
            match self.get(d) {
                Decl::Pointer(..) | Decl::FunctionPointer(..) => return true,
                Decl::Words(w, rest) | Decl::Glued(w, rest) => {
                    if !w.is_empty() {
                        return w.starts_with(['*', '&']);
                    }
                    d = rest;
                }
                Decl::Dims(rest, _) | Decl::Call(rest, _) => d = rest,
                _ => return false,
            }
        }
    }

    /// Writes a declarator: its pieces in order, deferring what follows a
    /// nested piece (the parameters after a function's name, the `)` after
    /// parentheses) to tasks.
    fn write_decl(&mut self, mut d: D) {
        let p = self.p;
        loop {
            match self.get(d) {
                Decl::Empty => return,
                Decl::Words(w, rest) => {
                    self.out.push_str(w);
                    if !w.is_empty() && !self.is_empty(rest) {
                        self.out.push(' ');
                    }
                    d = rest;
                }
                Decl::Spaced(w, rest) => {
                    self.out.push_str(w);
                    self.out.push(' ');
                    d = rest;
                }
                Decl::Glued(t, rest) => {
                    self.out.push_str(t);
                    d = rest;
                }
                Decl::Pointer(kind, cv, m, rest) => {
                    self.out.push_str(indirection(kind));
                    if m.ptr64 && p.ptr64() {
                        self.out.push(' ');
                        self.out.push_str(p.kw("__ptr64"));
                    }
                    if m.restrict && p.keywords() {
                        self.out.push(' ');
                        self.out.push_str(p.kw("__restrict"));
                    }
                    let cv = cv_text(cv);
                    if !cv.is_empty() {
                        self.out.push(' ');
                        self.out.push_str(cv);
                    }
                    if !self.is_empty(rest) {
                        self.out.push(' ');
                    }
                    d = rest;
                }
                Decl::FunctionPointer(kind, cv, m, returned, rest) => {
                    self.out.push_str(indirection(kind));
                    let mut bare = true;
                    if m.ptr64 && p.ptr64() {
                        self.out.push(' ');
                        self.out.push_str(p.kw("__ptr64"));
                        bare = false;
                    }
                    let cv = cv_text(cv);
                    if !cv.is_empty() {
                        if !bare {
                            self.out.push(' ');
                        }
                        self.out.push_str(cv);
                        bare = false;
                    }
                    let tight = bare && (returned || self.starts_with_pointer(rest));
                    if !self.is_empty(rest) && !tight {
                        self.out.push(' ');
                    }
                    d = rest;
                }
                Decl::Member(class, rest) => {
                    self.then(Task::Decl(rest));
                    self.then(Task::Text("::"));
                    self.qualified(class, None, 0);
                    return;
                }
                Decl::Parens(rest) => {
                    self.out.push('(');
                    self.then(Task::Char(')'));
                    d = rest;
                }
                Decl::Dims(rest, dims) => {
                    self.then(Task::Dims(dims));
                    d = rest;
                }
                Decl::Call(rest, sig) => {
                    // `(params)` after the rest.
                    self.then(Task::Params(sig, 0));
                    d = rest;
                }
                Decl::Name(q, conversion, adjustment) => {
                    if let Some(a) = adjustment {
                        self.then(Task::Adjustment(a));
                    }
                    self.qualified(q, conversion, 0);
                    return;
                }
            }
        }
    }

    /// A function's parameter list, from parameter `from` (`(` too, from
    /// the first). Builtin types are written here; others are deferred.
    fn params(&mut self, sig: &'r FunctionType<'r>, from: usize) {
        if from == 0 {
            self.out
                .push_str(if sig.params.is_empty() && !sig.variadic {
                    "(void"
                } else {
                    "("
                });
        }
        for (i, t) in sig.params.iter().enumerate().skip(from) {
            if i > 0 {
                self.out.push(',');
            }
            if let Type::Builtin(b) = t {
                self.out.push_str(builtin(*b));
                continue;
            }
            self.then(Task::Params(sig, i + 1));
            self.ty(t, EMPTY, false);
            return;
        }
        self.after_params(sig);
    }

    /// After a function's parameter types: `...`, `)`, `noexcept`, and
    /// the `this` qualifiers.
    fn after_params(&mut self, sig: &FunctionType<'_>) {
        let p = self.p;
        if sig.variadic {
            if !sig.params.is_empty() {
                self.out.push(',');
            }
            self.out.push_str("...");
        }
        self.out.push(')');
        // `NO_THISTYPE` (both of its bits: either alone does nothing)
        // leaves out `this`'s qualifiers, which come before `noexcept`.
        let this = sig
            .this
            .as_ref()
            .filter(|_| p.flags & flags::NO_THISTYPE != flags::NO_THISTYPE);
        if let Some(this) = this {
            let cv = cv_text(this.cv);
            if !cv.is_empty() {
                self.out.push_str(cv);
                self.out.push(' ');
            }
            if this.modifiers.ptr64 && p.ptr64() {
                if cv.is_empty() {
                    self.out.push(' ');
                }
                self.out.push_str(p.kw("__ptr64"));
            }
            if let Some(r) = this.reference {
                self.out.push_str(indirection(r));
                self.out.push(' ');
            }
        }
        if sig.noexcept {
            self.out.push_str(" noexcept");
        }
    }

    // ---- Types ---------------------------------------------------------

    /// Writes `text` and then the declarator, with a space between them.
    fn simple(&mut self, text: &str, d: D) {
        self.out.push_str(text);
        if !text.is_empty() && !self.is_empty(d) {
            self.out.push(' ');
        }
        self.write_decl(d);
    }

    /// Writes a named type's keyword and name, then the declarator.
    fn named(&mut self, keyword: &str, name: &'r QualifiedName<'r>, d: D) {
        self.out.push_str(keyword);
        self.then(Task::Decl(d));
        if !self.is_empty(d) {
            self.then(Task::Char(' '));
        }
        self.qualified(name, None, 0);
    }

    /// Writes `t` around `d`. `returned`: `d` is a function's name and
    /// parameters (to which a returned function pointer binds tightly).
    /// A type that wraps another (a pointer, a qualifier, an array) wraps
    /// the declarator instead, and the loop goes on with the other.
    fn ty(&mut self, mut t: &'r Type<'r>, mut d: D, mut returned: bool) {
        let p = self.p;
        loop {
            match t {
                Type::Builtin(b) => return self.simple(builtin(*b), d),
                Type::Tag(kind, name) => {
                    let keyword = if p.ecsu() {
                        match kind {
                            TagKind::Class => "class ",
                            TagKind::Struct => "struct ",
                            TagKind::Union => "union ",
                            TagKind::Cointerface => "cointerface ",
                        }
                    } else {
                        ""
                    };
                    return self.named(keyword, name, d);
                }
                Type::Alias(name) => return self.named("", name, d),
                Type::Enum { underlying, name } => {
                    // (`NAME_ONLY` keeps `enum`, though not class-keys.)
                    if p.flags & flags::NO_ECSU == 0 {
                        self.out.push_str("enum ");
                        if !underlying.is_empty() {
                            self.out.push_str(underlying);
                            self.out.push(' ');
                        }
                    }
                    return self.named("", name, d);
                }
                Type::CliArray { rank, element } => {
                    self.out.push_str("cli::array<");
                    self.then(Task::Decl(d));
                    self.then(Task::Rank(*rank));
                    self.then(Task::Type(element, EMPTY, false));
                    return;
                }
                Type::Qualified(cv, inner) if cv.is_empty() => t = inner,
                Type::Qualified(cv, inner) => {
                    d = self.decl(Decl::Words(cv_text(*cv), d));
                    t = inner;
                    returned = false;
                }
                Type::ExplicitlyQualified(cv, inner) => {
                    d = self.decl(Decl::Spaced(cv_text(*cv), d));
                    t = inner;
                    returned = false;
                }
                // An element pointer's own qualifiers are not shown
                // (`char const * (&)[9]` for an array of `char const * const`).
                Type::Array { dims, element } => {
                    d = self.decl(Decl::Dims(d, dims));
                    returned = false;
                    match element {
                        Type::Pointer {
                            kind,
                            modifiers,
                            pointee,
                            ..
                        } => match self.pointer_step(
                            *kind,
                            Cv::default(),
                            *modifiers,
                            pointee,
                            d,
                            false,
                        ) {
                            Some((nt, nd)) => (t, d) = (nt, nd),
                            None => return,
                        },
                        _ => t = element,
                    }
                }
                Type::Function(f) => {
                    let named = self.decl(Decl::Words(p.cc(f), d));
                    match self.function_type_step(f, named) {
                        Some((nt, nd)) => (t, d) = (nt, nd),
                        None => return,
                    }
                    returned = false;
                }
                Type::Pointer {
                    kind,
                    cv,
                    modifiers,
                    pointee,
                } => {
                    match self.pointer_step(*kind, *cv, *modifiers, pointee, d, returned) {
                        Some((nt, nd)) => (t, d) = (nt, nd),
                        None => return,
                    }
                    returned = false;
                }
                Type::MemberPointer {
                    class,
                    cv,
                    modifiers,
                    pointee,
                } => {
                    match pointee {
                        Type::Function(f) => {
                            // `(__cdecl Class::* __ptr64)(params)`, and a
                            // reference to one glued on: `Class::*&&`. (The
                            // space stays when the calling convention is
                            // left out: `( Class::*)`.)
                            let fp = self.decl(Decl::FunctionPointer(
                                Indirection::Pointer,
                                *cv,
                                *modifiers,
                                false,
                                d,
                            ));
                            let member = self.decl(Decl::Member(class, fp));
                            let inner = self.decl(Decl::Spaced(p.cc(f), member));
                            let parens = self.decl(Decl::Parens(inner));
                            match self.function_type_step(f, parens) {
                                Some((nt, nd)) => (t, d) = (nt, nd),
                                None => return,
                            }
                        }
                        _ => {
                            let ptr =
                                self.decl(Decl::Pointer(Indirection::Pointer, *cv, *modifiers, d));
                            d = self.decl(Decl::Member(class, ptr));
                            t = pointee;
                        }
                    }
                    returned = false;
                }
            }
        }
    }

    /// Writes a pointer to `pointee` around `d`.
    fn pointer(
        &mut self,
        kind: Indirection,
        cv: Cv,
        m: PointerModifiers,
        pointee: &'r Type<'r>,
        d: D,
        returned: bool,
    ) {
        if let Some((t, d)) = self.pointer_step(kind, cv, m, pointee, d, returned) {
            self.ty(t, d, false);
        }
    }

    /// A pointer to `pointee` around `d`: the type and declarator to write
    /// next (or `None` once written).
    fn pointer_step(
        &mut self,
        kind: Indirection,
        cv: Cv,
        m: PointerModifiers,
        pointee: &'r Type<'r>,
        d: D,
        returned: bool,
    ) -> Option<(&'r Type<'r>, D)> {
        match pointee {
            Type::Function(f) => {
                // `(__cdecl*const & __ptr64)(params)`.
                let fp = self.decl(Decl::FunctionPointer(kind, cv, m, returned, d));
                let inner = self.decl(Decl::Glued(self.p.cc(f), fp));
                let parens = self.decl(Decl::Parens(inner));
                self.function_type_step(f, parens)
            }
            Type::Array { .. } => {
                let ptr = self.decl(Decl::Pointer(kind, cv, m, d));
                Some((pointee, self.decl(Decl::Parens(ptr))))
            }
            _ => Some((pointee, self.decl(Decl::Pointer(kind, cv, m, d)))),
        }
    }

    /// A function type around `d` (which holds its calling convention):
    /// its return type and declarator to write next (or `None` once
    /// written).
    fn function_type_step(&mut self, f: &'r FunctionType<'r>, d: D) -> Option<(&'r Type<'r>, D)> {
        let call = self.decl(Decl::Call(d, f));
        match &f.returns {
            Some(r) => Some((r, call)),
            None => {
                self.write_decl(call);
                None
            }
        }
    }

    // ---- Names -----------------------------------------------------------

    /// A qualified name, from component `from`: components written here
    /// until one defers something, after which the rest are deferred too.
    fn qualified(
        &mut self,
        q: &'r QualifiedName<'r>,
        conversion: Option<&'r Type<'r>>,
        from: usize,
    ) {
        for (i, n) in q.0.iter().enumerate().skip(from) {
            if i > 0 {
                self.out.push_str("::");
            }
            let prev = i.checked_sub(1).map(|j| &q.0[j]);
            if i + 1 < q.0.len() && !immediate(n, prev, conversion) {
                self.then(Task::Qualified(q, conversion, i + 1));
                self.name(n, prev, conversion);
                return;
            }
            self.name(n, prev, conversion);
        }
    }

    /// Template arguments from `from`: simple ones written here, the rest
    /// deferred.
    fn template_args(&mut self, args: &'r [TemplateArg<'r>], from: usize) {
        for (i, a) in args.iter().enumerate().skip(from) {
            if i > 0 {
                self.out.push(',');
            }
            match a {
                TemplateArg::Type(Type::Builtin(b)) => self.out.push_str(builtin(*b)),
                TemplateArg::Integer(n) => {
                    let _ = write!(self.out, "{n}");
                }
                _ => {
                    self.then(Task::TemplateArgs(args, i + 1));
                    self.template_arg(a);
                    return;
                }
            }
        }
    }

    /// One component; `prev` is the enclosing one (a constructor's class).
    fn name(
        &mut self,
        mut n: &'r Name<'r>,
        mut prev: Option<&'r Name<'r>>,
        mut conversion: Option<&'r Type<'r>>,
    ) {
        loop {
            match n {
                Name::Identifier(s) => self.out.push_str(s),
                Name::Template { name, args } => {
                    // A conversion operator template: `operator<args> type`.
                    let conversion_template = **name == Name::Conversion;
                    self.then(Task::CloseTemplate(
                        conversion.filter(|_| conversion_template),
                    ));
                    self.then(Task::TemplateArgs(args, 0));
                    if conversion_template {
                        self.out.push_str("operator<");
                    } else if immediate(name, prev, conversion) {
                        self.name(name, prev, conversion);
                        self.out.push('<');
                    } else {
                        self.then(Task::Char('<'));
                        n = name;
                        continue;
                    }
                }
                Name::Operator(s) | Name::Special(s) => self.out.push_str(s),
                Name::Constructor | Name::Destructor => {
                    if matches!(n, Name::Destructor) {
                        self.out.push('~');
                    }
                    if let Some(p) = prev {
                        (n, prev, conversion) = (p, None, None);
                        continue;
                    }
                }
                Name::Conversion => {
                    self.out.push_str("operator");
                    if let Some(t) = conversion {
                        self.out.push(' ');
                        self.then(Task::Type(t, EMPTY, false));
                    }
                }
                Name::BaseClassDescriptor([a, b, c], d) => {
                    let _ = write!(
                        self.out,
                        "`RTTI Base Class Descriptor at ({a},{b},{c},{d})'"
                    );
                }
                Name::DynamicInitializer { atexit, target } => {
                    self.out.push_str(if *atexit {
                        "`dynamic atexit destructor for '"
                    } else {
                        "`dynamic initializer for '"
                    });
                    self.then(Task::Text("''"));
                    match target {
                        Initialized::Name(q) => self.then(Task::Qualified(q, None, 0)),
                        Initialized::Symbol(s) => self.then(Task::Symbol(s)),
                    }
                }
                Name::Literal(s) => {
                    self.out.push_str("operator \"\" ");
                    self.out.push_str(s);
                }
                Name::AnonymousNamespace(_) => self.out.push_str("`anonymous namespace'"),
                Name::Frame(n) => {
                    let _ = write!(self.out, "`{n}'");
                }
                Name::Enclosing(s) => {
                    self.out.push('`');
                    self.then(Task::Char('\''));
                    self.then(Task::Symbol(s));
                }
                Name::Bracketed(q) => {
                    self.out.push('[');
                    self.then(Task::Char(']'));
                    self.then(Task::Qualified(q, None, 0));
                }
            }
            return;
        }
    }

    fn template_arg(&mut self, a: &'r TemplateArg<'r>) {
        match a {
            TemplateArg::Type(t) => self.ty(t, EMPTY, false),
            TemplateArg::Integer(n) => {
                let _ = write!(self.out, "{n}");
            }
            TemplateArg::Address(None) => self.out.push_str("NULL"),
            TemplateArg::Address(Some(s)) => {
                self.out.push('&');
                self.then(Task::Symbol(s));
            }
            TemplateArg::Symbol(s) => self.then(Task::Symbol(s)),
            TemplateArg::Float(m, e) => {
                let _ = write!(self.out, "{m}e{e}");
            }
            TemplateArg::TemplateParameter(n) => {
                let _ = write!(self.out, "`template-parameter{n}'");
            }
            TemplateArg::NonTypeParameter(n) => {
                let _ = write!(self.out, "`non-type-template-parameter{n}'");
            }
            TemplateArg::Tuple(sym, values) => {
                self.out.push('{');
                self.then(Task::TupleValues(values, sym.is_some()));
                if let Some(sym) = sym {
                    self.then(Task::Symbol(sym));
                }
            }
        }
    }
}

//! The parser's machine: the whole grammar, with its recursion on a stack
//! of its own (frames on the heap, at most `MAX_FRAMES`) rather than the
//! thread's. Recursive descent (`descent.rs`) parses the first
//! `NATIVE_DEPTH` levels of nesting and hands deeper ones here (`run`);
//! `parse_slowly` parses everything here, for testing that the two build
//! the same trees.

use super::*;

impl<'a> Parser<'a> {
    /// Parses `goal` (and everything it needs) to its value.
    pub(super) fn run(&mut self, goal: Goal) -> R<Value<'a>> {
        let base = self.frames.len();
        let mut step = self.start(goal);
        loop {
            match step {
                Ok(Step::Call(g, f)) => match self.leaf(g) {
                    // (Most goals are leaves: `int`, an identifier.)
                    Some(Ok(v)) => step = self.resume(f, v),
                    Some(Err(e)) => step = Err(e),
                    None if self.frames.len() >= MAX_FRAMES => step = Err(Error),
                    None => {
                        self.frames.push(f);
                        step = self.start(g);
                    }
                },
                Ok(Step::Tail(g)) => match self.leaf(g) {
                    Some(v) => step = v.map(Step::Done),
                    None => step = self.start(g),
                },
                Ok(Step::Done(v)) => {
                    if self.frames.len() == base {
                        return Ok(v);
                    }
                    match self.frames.pop() {
                        Some(f) => step = self.resume(f, v),
                        None => return Err(Error),
                    }
                }
                Err(e) => {
                    self.frames.truncate(base);
                    return Err(e);
                }
            }
        }
    }

    /// A symbol as a value.
    fn symbol_value(&mut self, name: QualifiedName<'a>, kind: SymbolKind<'a>) -> R<Step<'a>> {
        self.symbol = Some(Symbol { name, kind });
        Ok(Step::Done(Value::Symbol))
    }

    /// A symbol's kind as a value.
    fn kind_value(&mut self, kind: SymbolKind<'a>) -> R<Step<'a>> {
        self.kind = Some(kind);
        Ok(Step::Done(Value::Kind))
    }

    /// The symbol `v` is.
    pub(super) fn take_symbol(&mut self, v: Value<'a>) -> R<Symbol<'a>> {
        match v {
            Value::Symbol => self.symbol.take().ok_or(Error),
            _ => Err(Error),
        }
    }

    /// The symbol `v` is, kept in the tree.
    fn symbol_ref(&mut self, v: Value<'a>) -> R<&'a Symbol<'a>> {
        let s = self.take_symbol(v)?;
        Ok(self.alloc(s))
    }

    /// The symbol kind `v` is.
    fn take_kind(&mut self, v: Value<'a>) -> R<SymbolKind<'a>> {
        match v {
            Value::Kind => self.kind.take().ok_or(Error),
            _ => Err(Error),
        }
    }

    /// `goal`'s value, if it is a leaf: one that needs no other goal (a
    /// builtin type, an identifier, a back-reference). `None` (having read
    /// nothing) if it isn't.
    fn leaf(&mut self, goal: Goal) -> Option<R<Value<'a>>> {
        match goal {
            Goal::DataType => {
                let c = self.peek()?;
                let b = match c {
                    b'_' => extended(self.peek_at(1)?)?,
                    c => basic(c)?,
                };
                // (Counted, as a type is.)
                if let Err(e) = self.charge(1) {
                    return Some(Err(e));
                }
                self.pos += if c == b'_' { 2 } else { 1 };
                Some(Ok(Value::Type(Type::Builtin(b))))
            }
            Goal::ReturnType if self.peek() != Some(b'?') => self.leaf(Goal::DataType),
            Goal::Parameters if self.peek() == Some(b'X') => {
                self.pos += 1;
                Some(Ok(Value::Params(&[], false)))
            }
            Goal::ThrowSpec if self.peek() == Some(b'Z') => {
                self.pos += 1;
                Some(Ok(Value::Bool(false)))
            }
            Goal::Fragment | Goal::ScopeFragment => {
                let c = self.peek()?;
                if c.is_ascii_digit() {
                    self.pos += 1;
                    return Some(self.name_ref(c - b'0').map(Value::Name));
                }
                if c == b'?' {
                    return None;
                }
                let start = self.nodes;
                let name = self
                    .charge(1)
                    .and_then(|()| self.identifier())
                    .map(Name::Identifier);
                if let Ok(name) = &name {
                    self.remember_name(name, start);
                }
                Some(name.map(Value::Name))
            }
            _ => None,
        }
    }

    /// Fresh back-reference tables, until `frames` pops the
    /// [`Frame::Restore`].
    fn isolate(&mut self) {
        self.hide();
        self.frames.push(Frame::Restore);
    }

    /// Pushes `frame` for a production that goes on, here, with the one it
    /// waits for. (Only along edges of the grammar that aren't on a cycle,
    /// so the thread's stack doesn't grow with the nesting.)
    fn push(&mut self, frame: Frame<'a>) -> R<()> {
        if self.frames.len() >= MAX_FRAMES {
            return Err(Error);
        }
        self.frames.push(frame);
        Ok(())
    }

    /// Starts parsing `goal`.
    fn start(&mut self, goal: Goal) -> R<Step<'a>> {
        match goal {
            Goal::Symbol => self.symbol_start(),
            Goal::SymbolName => self.symbol_name(),
            Goal::QualifiedName => match self.leaf(Goal::Fragment) {
                Some(first) => {
                    let base = self.scratch.names.len();
                    self.scratch.names.push(first?.name()?);
                    self.qualified_rest_next(base)
                }
                None => Ok(Step::Call(Goal::Fragment, Frame::QualifiedName)),
            },
            Goal::Fragment => self.fragment(),
            Goal::ScopeFragment => self.scope_fragment(),
            Goal::TemplateName => {
                self.expect(b'$')?;
                // (`Frame::TemplateArgsOf` ends the template's tables.)
                self.hide();
                self.template_body()
            }
            Goal::TemplateArg => self.template_arg(),
            Goal::TemplateValue(kind) => self.template_value(kind),
            Goal::Operator => self.operator(),
            Goal::Table => {
                let (modifiers, cv) = self.storage()?;
                let base = self.scratch.qualified.len();
                self.table_next(base, modifiers, cv)
            }
            Goal::Signature(this) => {
                let cc = self.calling_convention()?;
                if self.eat(b'@') {
                    Ok(Step::Call(
                        Goal::Parameters,
                        Frame::Parameters {
                            cc,
                            this,
                            returns: None,
                        },
                    ))
                } else {
                    Ok(Step::Call(Goal::ReturnType, Frame::Returns { cc, this }))
                }
            }
            Goal::ReturnType => {
                if self.eat(b'?') {
                    let cv = cv(self.next()?)?;
                    return Ok(Step::Call(Goal::DataType, Frame::Qualify(cv)));
                }
                Ok(Step::Tail(Goal::DataType))
            }
            Goal::Parameters => {
                if self.eat(b'X') {
                    return Ok(Step::Done(Value::Params(&[], false)));
                }
                let base = self.scratch.types.len();
                self.parameters_next(base)
            }
            Goal::ThrowSpec => {
                if self.eat(b'Z') {
                    return Ok(Step::Done(Value::Bool(false)));
                }
                if self.eat_str("_E") {
                    return Ok(Step::Done(Value::Bool(true)));
                }
                self.throw_spec_next()
            }
            Goal::DataType => {
                self.charge(1)?;
                self.data_type()
            }
            Goal::Array => {
                let dims = self.dims()?;
                Ok(Step::Call(Goal::DataType, Frame::ArrayElement(dims)))
            }
        }
    }

    /// Continues the production that `frame` was waiting in with `v`, the
    /// value of what it waited for.
    fn resume(&mut self, frame: Frame<'a>, v: Value<'a>) -> R<Step<'a>> {
        match frame {
            Frame::Restore => {
                self.unhide()?;
                Ok(Step::Done(v))
            }
            Frame::DoubledSymbol => {
                self.pos = self.s.len();
                Ok(Step::Done(v))
            }
            Frame::SymbolName {
                start,
                refs,
                outer,
                retry,
            } => {
                let (first, special) = v.name_special()?;
                if retry {
                    self.variable_template = false;
                }
                let first = self.alloc(first);
                let next = Frame::SymbolRest {
                    first,
                    special,
                    start,
                    refs,
                    outer,
                    retry,
                };
                match special {
                    Special::TypeDescriptor | Special::Literal => {
                        let q = QualifiedName(core::slice::from_ref(first));
                        self.resume(next, Value::Qualified(q))
                    }
                    _ => {
                        let base = self.scratch.names.len();
                        self.scratch.names.push(*first);
                        self.push(next)?;
                        self.qualified_rest_next(base)
                    }
                }
            }
            Frame::SymbolRest {
                first,
                special,
                start,
                refs,
                outer,
                retry,
            } => {
                let name = v.qualified()?;
                // A variable template's name is itself a back-reference:
                // read the name again knowing that.
                if !retry
                    && matches!(*first, Name::Template { .. })
                    && matches!(self.peek(), Some(b'0'..=b'4'))
                    && special == Special::None
                {
                    self.pos = start;
                    self.names.items.truncate(refs.0);
                    self.types.items.truncate(refs.1);
                    self.variable_template = true;
                    return Ok(Step::Call(
                        Goal::SymbolName,
                        Frame::SymbolName {
                            start,
                            refs,
                            outer,
                            retry: true,
                        },
                    ));
                }
                self.variable_template = outer;
                match special {
                    Special::TypeDescriptor => {
                        // `??_R0?AVFoo@@@8`: the type, then `@8`.
                        Ok(Step::Call(Goal::ReturnType, Frame::TypeDescriptor(first)))
                    }
                    Special::Literal => self.symbol_value(
                        QualifiedName(self.alloc_slice(&[*first])),
                        SymbolKind::NameOnly,
                    ),
                    Special::Table => {
                        let c = self.next()?;
                        if c != b'6' && c != b'7' {
                            return Err(Error);
                        }
                        Ok(Step::Call(Goal::Table, Frame::SymbolKind(name)))
                    }
                    Special::None => {
                        self.push(Frame::SymbolKind(name))?;
                        self.encoding()
                    }
                }
            }
            Frame::TypeDescriptor(first) => {
                let ty = v.ty()?;
                self.expect(b'@')?;
                self.expect(b'8')?;
                self.symbol_value(
                    QualifiedName(self.alloc_slice(&[*first])),
                    SymbolKind::TypeDescriptor(ty),
                )
            }
            Frame::SymbolKind(name) => {
                let kind = self.take_kind(v)?;
                self.symbol_value(name, kind)
            }
            Frame::TemplateSymbolName { start } => {
                let name = v.name()?;
                if self.variable_template {
                    self.remember_name(&name, start);
                }
                Ok(Step::Done(Value::NameSpecial(name, Special::None)))
            }
            Frame::NoSpecial => Ok(Step::Done(Value::NameSpecial(v.name()?, Special::None))),
            Frame::QualifiedName => {
                let base = self.scratch.names.len();
                self.scratch.names.push(v.name()?);
                self.qualified_rest_next(base)
            }
            Frame::QualifiedRest(base) => {
                let part = v.name()?;
                self.scratch.names.push(part);
                self.qualified_rest_next(base)
            }
            Frame::Fragment { start } => {
                let name = v.name()?;
                self.remember_name(&name, start);
                Ok(Step::Done(Value::Name(name)))
            }
            Frame::TemplateOperator => {
                let (name, _) = v.name_special()?;
                self.push(Frame::TemplateArgsOf(self.alloc(name)))?;
                let base = self.scratch.args.len();
                self.template_args_next(base)
            }
            Frame::TemplateArgsOf(name) => {
                self.unhide()?;
                Ok(Step::Done(Value::Name(Name::Template {
                    name,
                    args: v.args()?,
                })))
            }
            Frame::TemplateArgs(base) => {
                if let Some(arg) = v.arg()? {
                    self.scratch.args.push(arg);
                }
                self.template_args_next(base)
            }
            Frame::AutoTemplateArg => {
                let value = self.next()?;
                Ok(Step::Tail(Goal::TemplateValue(value)))
            }
            Frame::AddressArg => {
                let s = self.symbol_ref(v)?;
                Ok(Step::Done(Value::Arg(Some(TemplateArg::Address(Some(s))))))
            }
            Frame::SymbolArg => {
                let s = self.symbol_ref(v)?;
                Ok(Step::Done(Value::Arg(Some(TemplateArg::Symbol(s)))))
            }
            Frame::TupleArg(kind) => {
                let s = self.symbol_ref(v)?;
                let n = usize::from(kind - b'G');
                let ints = self.ints(n)?;
                Ok(Step::Done(Value::Arg(Some(TemplateArg::Tuple(
                    Some(s),
                    ints,
                )))))
            }
            Frame::Enclosing => {
                let s = self.symbol_ref(v)?;
                Ok(Step::Done(Value::Name(Name::Enclosing(s))))
            }
            Frame::Bracketed => Ok(Step::Done(Value::Name(Name::Bracketed(v.qualified()?)))),
            Frame::InitializedSymbol { atexit } => {
                let s = self.take_symbol(v)?;
                // The nested name ends with its own `@`.
                self.eat(b'@');
                self.dynamic_initializer(atexit, Initialized::Symbol(s))
            }
            Frame::InitializedName { atexit } => {
                // Just the variable's name; the scopes that follow are the
                // initializer's.
                let name = v.name()?;
                let q = QualifiedName(self.alloc_slice(&[name]));
                self.dynamic_initializer(atexit, Initialized::Name(q))
            }
            Frame::EncodingFlags { arm64ec, extern_c } => {
                let mut kind = self.take_kind(v)?;
                if let SymbolKind::Function(f) = &mut kind {
                    f.arm64ec = arm64ec;
                    f.extern_c = extern_c;
                }
                self.kind_value(kind)
            }
            Frame::Variable(access) => {
                let ty = v.ty()?;
                let (modifiers, cv) = self.storage()?;
                self.kind_value(SymbolKind::Variable {
                    access,
                    ty,
                    cv,
                    modifiers,
                })
            }
            Frame::Function {
                access,
                class,
                adjustment,
            } => self.kind_value(SymbolKind::Function(Function {
                arm64ec: false,
                extern_c: false,
                access,
                class,
                adjustment,
                signature: *v.signature()?,
            })),
            Frame::Table {
                base,
                modifiers,
                cv,
            } => {
                let q = v.qualified()?;
                self.scratch.qualified.push(q);
                self.table_next(base, modifiers, cv)
            }
            Frame::Returns { cc, this } => {
                let returns = self.alloc(v.ty()?);
                Ok(Step::Call(
                    Goal::Parameters,
                    Frame::Parameters {
                        cc,
                        this,
                        returns: Some(returns),
                    },
                ))
            }
            Frame::Parameters { cc, this, returns } => {
                let (params, variadic) = v.params()?;
                let f = self.arena.alloc(FunctionType {
                    calling_convention: cc,
                    returns: returns.copied(),
                    params,
                    variadic,
                    noexcept: false,
                    this,
                });
                Ok(Step::Call(Goal::ThrowSpec, Frame::ThrowSpec(f)))
            }
            Frame::ThrowSpec(f) => {
                f.noexcept = v.bool()?;
                Ok(Step::Done(Value::Signature(f)))
            }
            Frame::ThrownType => self.throw_spec_next(),
            Frame::Parameter {
                base,
                start,
                start_nodes,
            } => {
                let ty = v.ty()?;
                self.remember_type(start, start_nodes, &ty);
                self.scratch.types.push(ty);
                self.parameters_next(base)
            }
            Frame::Qualify(cv) => {
                let ty = v.ty()?;
                Ok(Step::Done(Value::Type(self.qualified(cv, ty))))
            }
            Frame::ExplicitlyQualify(cv) => {
                let ty = v.ty()?;
                Ok(Step::Done(Value::Type(Type::ExplicitlyQualified(
                    cv,
                    self.alloc(ty),
                ))))
            }
            Frame::FunctionType => Ok(Step::Done(Value::Type(Type::Function(v.signature()?)))),
            Frame::Alias => Ok(Step::Done(Value::Type(Type::Alias(v.qualified()?)))),
            Frame::Tag(kind) => Ok(Step::Done(Value::Type(Type::Tag(kind, v.qualified()?)))),
            Frame::Enum(underlying) => Ok(Step::Done(Value::Type(Type::Enum {
                underlying,
                name: v.qualified()?,
            }))),
            Frame::CliArray {
                rank,
                modifiers,
                cv,
                own,
            } => {
                let element = v.ty()?;
                let array = Type::CliArray {
                    rank,
                    element: self.alloc(element),
                };
                Ok(Step::Done(Value::Type(Type::Pointer {
                    kind: Indirection::Handle,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(self.qualified(cv, array)),
                })))
            }
            Frame::PointerToFunction {
                kind,
                own,
                modifiers,
            } => {
                let pointee = Type::Function(v.signature()?);
                Ok(Step::Done(Value::Type(Type::Pointer {
                    kind,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(pointee),
                })))
            }
            Frame::MemberFunctionClass { own, modifiers } => {
                let class = v.qualified()?;
                let this = self.this_qualifiers()?;
                Ok(Step::Call(
                    Goal::Signature(Some(this)),
                    Frame::MemberFunction {
                        class,
                        own,
                        modifiers,
                    },
                ))
            }
            Frame::MemberFunction {
                class,
                own,
                modifiers,
            } => {
                let f = v.signature()?;
                Ok(Step::Done(Value::Type(Type::MemberPointer {
                    class,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(Type::Function(f)),
                })))
            }
            Frame::PointerToArray {
                kind,
                own,
                modifiers,
                cv,
            } => {
                let Type::Array { dims, element } = v.ty()? else {
                    return Err(Error);
                };
                let pointee = Type::Array {
                    dims,
                    element: self.alloc(self.qualified(cv, *element)),
                };
                Ok(Step::Done(Value::Type(Type::Pointer {
                    kind,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(pointee),
                })))
            }
            Frame::Pointee {
                kind,
                own,
                modifiers,
                cv,
            } => {
                let ty = v.ty()?;
                // A pointer's qualifiers are encoded twice: in this letter
                // and in the pointer's own.
                let pointee = if matches!(ty, Type::Pointer { .. } | Type::MemberPointer { .. }) {
                    ty
                } else {
                    self.qualified(cv, ty)
                };
                Ok(Step::Done(Value::Type(Type::Pointer {
                    kind,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(pointee),
                })))
            }
            Frame::MemberDataClass { own, modifiers, cv } => Ok(Step::Call(
                Goal::DataType,
                Frame::MemberData {
                    class: v.qualified()?,
                    own,
                    modifiers,
                    cv,
                },
            )),
            Frame::MemberData {
                class,
                own,
                modifiers,
                cv,
            } => {
                let ty = v.ty()?;
                Ok(Step::Done(Value::Type(Type::MemberPointer {
                    class,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(self.qualified(cv, ty)),
                })))
            }
            Frame::ArrayElement(dims) => {
                let element = v.ty()?;
                Ok(Step::Done(Value::Type(Type::Array {
                    dims,
                    element: self.alloc(element),
                })))
            }
        }
    }

    // ---- Symbols ---------------------------------------------------------

    /// A symbol (from [`Self::start`]).
    fn symbol_start(&mut self) -> R<Step<'a>> {
        self.expect(b'?')?;
        if self.eat_str("?@") {
            return self.symbol_value(QualifiedName::default(), SymbolKind::Hashed(self.text));
        }
        // `???...`: C++/CLI decorated a decorated name again; the inner one
        // is the name (the rest is ignored).
        if self.peek() == Some(b'?') && self.peek_at(1) == Some(b'?') {
            return Ok(Step::Call(Goal::Symbol, Frame::DoubledSymbol));
        }
        // (The tables as they were, should the name have to be read again:
        // see `Frame::SymbolRest`.)
        let refs = (self.names.items.len(), self.types.items.len());
        let outer = self.variable_template;
        self.variable_template = false;
        self.push(Frame::SymbolName {
            start: self.pos,
            refs,
            outer,
            retry: false,
        })?;
        self.symbol_name()
    }

    /// A symbol's own (unqualified) name.
    fn symbol_name(&mut self) -> R<Step<'a>> {
        if self.peek() == Some(b'?') {
            if self.peek_at(1) == Some(b'$') {
                self.pos += 1;
                let start = self.nodes;
                return Ok(Step::Call(
                    Goal::TemplateName,
                    Frame::TemplateSymbolName { start },
                ));
            }
            self.pos += 1;
            return self.operator();
        }
        Ok(Step::Call(Goal::Fragment, Frame::NoSpecial))
    }

    /// The scopes after the first component, up to `@` (pushed on
    /// `scratch.names` from `base`); the result is outermost first.
    fn qualified_rest_next(&mut self, base: usize) -> R<Step<'a>> {
        while !self.eat(b'@') {
            // (Most components are leaves: taken here, not by `run`.)
            match self.leaf(Goal::ScopeFragment) {
                Some(part) => self.scratch.names.push(part?.name()?),
                None => return Ok(Step::Call(Goal::ScopeFragment, Frame::QualifiedRest(base))),
            }
        }
        self.scratch.names[base..].reverse();
        let parts = self.alloc_slice(&self.scratch.names[base..]);
        self.scratch.names.truncate(base);
        Ok(Step::Done(Value::Qualified(QualifiedName(parts))))
    }

    /// One name component: an identifier, a back-reference, or a template.
    fn fragment(&mut self) -> R<Step<'a>> {
        let c = self.peek().ok_or(Error)?;
        if c.is_ascii_digit() {
            self.pos += 1;
            return Ok(Step::Done(Value::Name(self.name_ref(c - b'0')?)));
        }
        let start = self.nodes;
        self.charge(1)?;
        if c == b'?' && self.peek_at(1) == Some(b'$') {
            self.pos += 1;
            return Ok(Step::Call(Goal::TemplateName, Frame::Fragment { start }));
        }
        let name = Name::Identifier(self.identifier()?);
        self.remember_name(&name, start);
        Ok(Step::Done(Value::Name(name)))
    }

    /// `name@args@` of a template name (after its `?$`), with its own
    /// back-reference tables.
    fn template_body(&mut self) -> R<Step<'a>> {
        if self.peek() == Some(b'?') {
            self.pos += 1;
            return Ok(Step::Call(Goal::Operator, Frame::TemplateOperator));
        }
        let start = self.nodes;
        let name = Name::Identifier(self.identifier()?);
        self.remember_name(&name, start);
        self.push(Frame::TemplateArgsOf(self.alloc(name)))?;
        let base = self.scratch.args.len();
        self.template_args_next(base)
    }

    /// The template arguments up to `@` (pushed on `scratch.args` from
    /// `base`).
    fn template_args_next(&mut self, base: usize) -> R<Step<'a>> {
        while !self.eat(b'@') {
            // (Template arguments are not remembered as types. Leaves are
            // taken here, not by `run`.)
            let kind = self.peek_at(1);
            let leaf = if self.peek() == Some(b'$')
                && matches!(kind, Some(b'0' | b'2' | b'D' | b'F' | b'G' | b'Q' | b'S'))
            {
                self.pos += 2;
                match self.template_value(kind.ok_or(Error)?)? {
                    Step::Done(v) => v.arg()?,
                    _ => return Err(Error),
                }
            } else if self.peek() != Some(b'$')
                && let Some(ty) = self.leaf(Goal::DataType)
            {
                Some(TemplateArg::Type(ty?.ty()?))
            } else if self.peek() != Some(b'$') {
                // (The list takes the type as the argument: see `Value::arg`.)
                return Ok(Step::Call(Goal::DataType, Frame::TemplateArgs(base)));
            } else {
                return Ok(Step::Call(Goal::TemplateArg, Frame::TemplateArgs(base)));
            };
            if let Some(arg) = leaf {
                self.scratch.args.push(arg);
            }
        }
        let args = self.alloc_slice(&self.scratch.args[base..]);
        self.scratch.args.truncate(base);
        Ok(Step::Done(Value::Args(args)))
    }

    /// One template argument (`None` for an empty pack).
    fn template_arg(&mut self) -> R<Step<'a>> {
        if self.peek() == Some(b'$') {
            let kind = self.peek_at(1).ok_or(Error)?;
            match kind {
                b'0' | b'1' | b'2' | b'D' | b'E' | b'F' | b'G' | b'H' | b'I' | b'J' | b'Q'
                | b'S' => {
                    self.pos += 2;
                    return self.template_value(kind);
                }
                // `$M<type><value>`: a non-type parameter declared `auto`
                // (C++17): the type it deduced, then the value (a `$` code
                // without its `$`). undname shows only the value.
                b'M' => {
                    self.pos += 2;
                    return Ok(Step::Call(Goal::DataType, Frame::AutoTemplateArg));
                }
                b'$' if matches!(self.peek_at(2), Some(b'V' | b'Z')) => {
                    self.pos += 3;
                    return Ok(Step::Done(Value::Arg(None)));
                }
                _ => {}
            }
        }
        // (The list takes the type as the argument: see `Value::arg`.)
        Ok(Step::Tail(Goal::DataType))
    }

    /// A non-type template argument after its `$<kind>` code (`None` for
    /// an empty pack).
    fn template_value(&mut self, kind: u8) -> R<Step<'a>> {
        let arg = match kind {
            b'0' => TemplateArg::Integer(self.signed()?),
            b'1' => {
                if self.eat(b'@') {
                    TemplateArg::Address(None)
                } else {
                    // (The symbol shares the argument list's tables.)
                    return Ok(Step::Call(Goal::Symbol, Frame::AddressArg));
                }
            }
            b'E' => {
                self.frames.push(Frame::SymbolArg);
                self.isolate();
                return Ok(Step::Tail(Goal::Symbol));
            }
            b'2' => {
                let m = self.signed()?;
                let e = self.signed()?;
                TemplateArg::Float(m, e)
            }
            b'D' => TemplateArg::TemplateParameter(self.signed()?),
            b'Q' => TemplateArg::NonTypeParameter(self.signed()?),
            b'F' | b'G' => {
                let n = if kind == b'F' { 2 } else { 3 };
                TemplateArg::Tuple(None, self.ints(n)?)
            }
            // (Like `$1`'s, the symbol shares the argument list's tables:
            // `?f@12@...` refers to names before it.)
            b'H' | b'I' | b'J' => return Ok(Step::Call(Goal::Symbol, Frame::TupleArg(kind))),
            // An empty non-type pack.
            b'S' => return Ok(Step::Done(Value::Arg(None))),
            _ => return Err(Error),
        };
        Ok(Step::Done(Value::Arg(Some(arg))))
    }

    fn scope_fragment(&mut self) -> R<Step<'a>> {
        if self.peek() != Some(b'?') {
            return self.fragment();
        }
        match self.peek_at(1).ok_or(Error)? {
            b'$' => self.fragment(),
            b'A' => {
                self.pos += 2;
                let start = self.nodes;
                self.charge(1)?;
                let tag = self.identifier()?;
                let name = Name::AnonymousNamespace(tag);
                self.remember_name(&name, start);
                Ok(Step::Done(Value::Name(name)))
            }
            b'?' => {
                self.pos += 1;
                // The enclosing function's name continues this name's
                // back-reference tables.
                Ok(Step::Call(Goal::Symbol, Frame::Enclosing))
            }
            b'I' | b'Q' => {
                // `[Interface]`: the interface a member implements (C++/CX).
                self.pos += 2;
                Ok(Step::Call(Goal::QualifiedName, Frame::Bracketed))
            }
            _ => {
                self.pos += 1;
                Ok(Step::Done(Value::Name(Name::Frame(self.unsigned()?))))
            }
        }
    }

    fn dynamic_initializer(&mut self, atexit: bool, target: Initialized<'a>) -> R<Step<'a>> {
        Ok(Step::Done(Value::NameSpecial(
            Name::DynamicInitializer {
                atexit,
                target: self.alloc(target),
            },
            Special::None,
        )))
    }

    /// An operator or special name (after its `?`).
    fn operator(&mut self) -> R<Step<'a>> {
        let (name, special) = match self.next()? {
            b'0' => (Name::Constructor, Special::None),
            b'1' => (Name::Destructor, Special::None),
            b'B' => (Name::Conversion, Special::None),
            b'_' => return self.operator_underscore(),
            c => (
                Name::Operator(operator_name(c).ok_or(Error)?),
                Special::None,
            ),
        };
        Ok(Step::Done(Value::NameSpecial(name, special)))
    }

    fn operator_underscore(&mut self) -> R<Step<'a>> {
        let op = |s: &'static str| (Name::Operator(s), Special::None);
        let special = |s: &'static str| (Name::Special(s), Special::None);
        let table = |s: &'static str| (Name::Special(s), Special::Table);
        let (name, special) = match self.next()? {
            b'0' => op("operator/="),
            b'1' => op("operator%="),
            b'2' => op("operator>>="),
            b'3' => op("operator<<="),
            b'4' => op("operator&="),
            b'5' => op("operator|="),
            b'6' => op("operator^="),
            b'7' => table("`vftable'"),
            b'8' => table("`vbtable'"),
            b'9' => special("`vcall'"),
            b'A' => special("`typeof'"),
            b'B' => special("`local static guard'"),
            b'C' => {
                // A string literal: the rest is its encoding.
                self.pos = self.s.len();
                (Name::Special("`string'"), Special::Literal)
            }
            b'D' => special("`vbase destructor'"),
            b'E' => special("`vector deleting destructor'"),
            b'F' => special("`default constructor closure'"),
            b'G' => special("`scalar deleting destructor'"),
            b'H' => special("`vector constructor iterator'"),
            b'I' => special("`vector destructor iterator'"),
            b'J' => special("`vector vbase constructor iterator'"),
            b'K' => special("`virtual displacement map'"),
            b'L' => special("`eh vector constructor iterator'"),
            b'M' => special("`eh vector destructor iterator'"),
            b'N' => special("`eh vector vbase constructor iterator'"),
            b'O' => special("`copy constructor closure'"),
            b'R' => self.rtti()?,
            b'S' => table("`local vftable'"),
            b'T' => special("`local vftable constructor closure'"),
            b'U' => op("operator new[]"),
            b'V' => op("operator delete[]"),
            b'X' => special("`placement delete closure'"),
            b'Y' => special("`placement delete[] closure'"),
            b'_' => return self.operator_double_underscore(),
            _ => return Err(Error),
        };
        Ok(Step::Done(Value::NameSpecial(name, special)))
    }

    fn operator_double_underscore(&mut self) -> R<Step<'a>> {
        let special = |s: &'static str| (Name::Special(s), Special::None);
        let c = self.next()?;
        let (name, special) = match c {
            b'A' => special("`managed vector constructor iterator'"),
            b'B' => special("`managed vector destructor iterator'"),
            b'C' => special("`eh vector copy constructor iterator'"),
            b'D' => special("`eh vector vbase copy constructor iterator'"),
            b'E' | b'F' => {
                let atexit = c == b'F';
                if self.peek() == Some(b'?') {
                    self.frames.push(Frame::InitializedSymbol { atexit });
                    self.isolate();
                    return Ok(Step::Tail(Goal::Symbol));
                }
                return Ok(Step::Call(
                    Goal::Fragment,
                    Frame::InitializedName { atexit },
                ));
            }
            b'G' => special("`vector copy constructor iterator'"),
            b'H' => special("`vector vbase copy constructor iterator'"),
            b'I' => special("`managed vector copy constructor iterator'"),
            b'J' => special("`local static thread guard'"),
            b'K' => (Name::Literal(self.identifier()?), Special::None),
            b'L' => (Name::Operator("operator co_await"), Special::None),
            b'M' => (Name::Operator("operator<=>"), Special::None),
            _ => return Err(Error),
        };
        Ok(Step::Done(Value::NameSpecial(name, special)))
    }

    fn encoding(&mut self) -> R<Step<'a>> {
        let mut arm64ec = false;
        let mut extern_c = false;
        loop {
            if self.eat_str("$$h") {
                arm64ec = true;
            } else if self.eat_str("$$J") {
                // `$$J<digit>`: extern "C".
                self.next()?;
                extern_c = true;
            } else if self.eat_str("$$F") || self.eat_str("$$H") || self.eat_str("$$Q") {
                // Managed (C++/CLI) functions.
            } else {
                break;
            }
        }
        if arm64ec || extern_c {
            self.frames.push(Frame::EncodingFlags { arm64ec, extern_c });
        }
        let c = self.next()?;
        match c {
            b'0'..=b'4' => {
                let access = match c {
                    b'0' => Some(Access::Private),
                    b'1' => Some(Access::Protected),
                    b'2' => Some(Access::Public),
                    _ => None,
                };
                Ok(Step::Call(Goal::DataType, Frame::Variable(access)))
            }
            b'5' => {
                let n = self.unsigned()?;
                self.kind_value(SymbolKind::LocalStaticGuard(n))
            }
            b'6' | b'7' => Ok(Step::Tail(Goal::Table)),
            b'8' | b'9' => self.kind_value(SymbolKind::NameOnly),
            b'A'..=b'Z' => self.function(c),
            b'$' => self.special_function(),
            _ => Err(Error),
        }
    }

    /// `B@` or `B<bases>@` after a table's `6` (bases pushed on
    /// `scratch.qualified` from `base`).
    fn table_next(&mut self, base: usize, modifiers: PointerModifiers, cv: Cv) -> R<Step<'a>> {
        if !self.eat(b'@') {
            return Ok(Step::Call(
                Goal::QualifiedName,
                Frame::Table {
                    base,
                    modifiers,
                    cv,
                },
            ));
        }
        let targets = self.alloc_slice(&self.scratch.qualified[base..]);
        self.scratch.qualified.truncate(base);
        self.kind_value(SymbolKind::Table {
            cv,
            modifiers,
            targets,
        })
    }

    fn function(&mut self, code: u8) -> R<Step<'a>> {
        let index = code - b'A';
        let (access, class, thunk) = if index >= 24 {
            (None, FunctionClass::Global, false)
        } else {
            let access =
                [Access::Private, Access::Protected, Access::Public][usize::from(index / 8)];
            let (class, thunk) = match (index % 8) / 2 {
                0 => (FunctionClass::Member, false),
                1 => (FunctionClass::Static, false),
                2 => (FunctionClass::Virtual, false),
                _ => (FunctionClass::Virtual, true),
            };
            (Some(access), class, thunk)
        };
        let adjustment = if thunk {
            Some(Adjustment::Adjustor(self.signed()?))
        } else {
            None
        };
        let this = match class {
            FunctionClass::Member | FunctionClass::Virtual => Some(self.this_qualifiers()?),
            _ => None,
        };
        Ok(Step::Call(
            Goal::Signature(this),
            Frame::Function {
                access,
                class,
                adjustment,
            },
        ))
    }

    fn special_function(&mut self) -> R<Step<'a>> {
        let c = self.next()?;
        let access =
            |n: u8| [Access::Private, Access::Protected, Access::Public][usize::from(n / 2)];
        let adjustment = match c {
            b'0'..=b'5' => {
                let a = self.signed()?;
                let b = self.signed()?;
                (access(c - b'0'), Adjustment::Vtordisp(a, b))
            }
            b'R' => {
                let n = self.next()?.wrapping_sub(b'0');
                if n > 5 {
                    return Err(Error);
                }
                let a = self.signed()?;
                let b = self.signed()?;
                let c = self.signed()?;
                let d = self.signed()?;
                (access(n), Adjustment::VtordispEx(a, b, c, d))
            }
            b'B' => {
                let offset = self.unsigned()?;
                self.expect(b'A')?;
                let calling_convention = self.calling_convention()?;
                return self.kind_value(SymbolKind::VcallThunk {
                    offset,
                    calling_convention,
                });
            }
            _ => return Err(Error),
        };
        let this = self.this_qualifiers()?;
        Ok(Step::Call(
            Goal::Signature(Some(this)),
            Frame::Function {
                access: Some(adjustment.0),
                class: FunctionClass::Virtual,
                adjustment: Some(adjustment.1),
            },
        ))
    }

    /// The rest of a throw specification after `Z` and `_E`: types up to
    /// `@` (none of them `noexcept`).
    fn throw_spec_next(&mut self) -> R<Step<'a>> {
        if self.eat(b'@') {
            return Ok(Step::Done(Value::Bool(false)));
        }
        Ok(Step::Call(Goal::DataType, Frame::ThrownType))
    }

    /// The parameters (pushed on `scratch.types` from `base`), up to `@`,
    /// or `Z` for `...`.
    fn parameters_next(&mut self, base: usize) -> R<Step<'a>> {
        loop {
            match self.peek().ok_or(Error)? {
                c @ (b'@' | b'Z') => {
                    self.pos += 1;
                    let params = self.alloc_slice(&self.scratch.types[base..]);
                    self.scratch.types.truncate(base);
                    return Ok(Step::Done(Value::Params(params, c == b'Z')));
                }
                c if c.is_ascii_digit() => {
                    self.pos += 1;
                    let ty = self.type_ref(c - b'0')?;
                    self.scratch.types.push(ty);
                }
                _ => {
                    let (start, start_nodes) = (self.pos, self.nodes);
                    // (Leaves are taken here, not by `run`.)
                    if let Some(ty) = self.leaf(Goal::DataType) {
                        let ty = ty?.ty()?;
                        self.remember_type(start, start_nodes, &ty);
                        self.scratch.types.push(ty);
                        continue;
                    }
                    let frame = Frame::Parameter {
                        base,
                        start,
                        start_nodes,
                    };
                    return Ok(Step::Call(Goal::DataType, frame));
                }
            }
        }
    }

    // ---- Types ---------------------------------------------------------------

    /// A type (from [`Self::start`]).
    fn data_type(&mut self) -> R<Step<'a>> {
        let c = self.next()?;
        if let Some(b) = basic(c) {
            return Ok(Step::Done(Value::Type(Type::Builtin(b))));
        }
        match c {
            b'_' => {
                let c = self.next()?;
                Ok(Step::Done(Value::Type(Type::Builtin(
                    extended(c).ok_or(Error)?,
                ))))
            }
            b'T' | b'U' | b'V' | b'Y' => {
                let kind = match c {
                    b'T' => TagKind::Union,
                    b'U' => TagKind::Struct,
                    b'V' => TagKind::Class,
                    _ => TagKind::Cointerface,
                };
                Ok(Step::Call(Goal::QualifiedName, Frame::Tag(kind)))
            }
            b'W' => {
                let underlying = match self.next()? {
                    b'0' => "char",
                    b'1' => "unsigned char",
                    b'2' => "short",
                    b'3' => "unsigned short",
                    b'4' => "",
                    b'5' => "unsigned int",
                    b'6' => "long",
                    b'7' => "unsigned long",
                    _ => return Err(Error),
                };
                Ok(Step::Call(Goal::QualifiedName, Frame::Enum(underlying)))
            }
            b'P' | b'Q' | b'R' | b'S' => {
                let own = cv(c - b'P' + b'A')?;
                self.pointer(Indirection::Pointer, own)
            }
            b'A' => self.pointer(Indirection::Reference, CV_NONE),
            b'B' => self.pointer(Indirection::Reference, CV_VOLATILE),
            b'?' => {
                let cv = cv(self.next()?)?;
                Ok(Step::Call(Goal::DataType, Frame::Qualify(cv)))
            }
            b'$' => self.dollar_type(),
            _ => Err(Error),
        }
    }

    fn dollar_type(&mut self) -> R<Step<'a>> {
        self.expect(b'$')?;
        match self.next()? {
            b'Q' => self.pointer(Indirection::RvalueReference, CV_NONE),
            b'R' => self.pointer(Indirection::RvalueReference, CV_VOLATILE),
            b'C' => {
                let cv = cv(self.next()?)?;
                Ok(Step::Call(Goal::DataType, Frame::ExplicitlyQualify(cv)))
            }
            b'A' => match self.next()? {
                b'6' => Ok(Step::Call(Goal::Signature(None), Frame::FunctionType)),
                // `$$A8@@<this><signature>`: a member function's type, of
                // no class (`R __cdecl(params) const`, as an argument to
                // `std::function`-like templates).
                b'8' => {
                    self.expect(b'@')?;
                    self.expect(b'@')?;
                    let this = self.this_qualifiers()?;
                    Ok(Step::Call(Goal::Signature(Some(this)), Frame::FunctionType))
                }
                _ => Err(Error),
            },
            b'B' => {
                self.expect(b'Y')?;
                Ok(Step::Tail(Goal::Array))
            }
            b'T' => Ok(Step::Done(Value::Type(Type::Builtin(Builtin::Nullptr)))),
            b'Y' => Ok(Step::Call(Goal::QualifiedName, Frame::Alias)),
            _ => Err(Error),
        }
    }

    /// After the pointer's own letter: modifiers, then the pointee.
    fn pointer(&mut self, kind: Indirection, own: Cv) -> R<Step<'a>> {
        // `$0<rank>`: a handle to a C++/CLI array.
        if self.eat_str("$0") {
            let rank = self.next()?;
            let rank = match rank {
                b'1'..=b'9' => rank - b'0',
                b'A'..=b'F' => rank - b'A' + 10,
                _ => return Err(Error),
            };
            let modifiers = self.modifiers();
            let cv = cv(self.next()?)?;
            return Ok(Step::Call(
                Goal::DataType,
                Frame::CliArray {
                    rank,
                    modifiers,
                    cv,
                    own,
                },
            ));
        }
        let mut kind = kind;
        let modifiers = self.modifiers();
        // C++/CLI handles (`$A`) and tracking references (`$C`).
        if self.eat_str("$A") {
            kind = Indirection::Handle;
        } else if self.eat_str("$C") {
            kind = Indirection::TrackingReference;
        }
        let modifiers = if modifiers == PointerModifiers::default() {
            self.modifiers()
        } else {
            modifiers
        };
        let c = self.next()?;
        // A boxed value type.
        self.eat_str("__Z");
        match c {
            b'6' => Ok(Step::Call(
                Goal::Signature(None),
                Frame::PointerToFunction {
                    kind,
                    own,
                    modifiers,
                },
            )),
            b'8' => Ok(Step::Call(
                Goal::QualifiedName,
                Frame::MemberFunctionClass { own, modifiers },
            )),
            b'A'..=b'D' => {
                let cv = cv(c)?;
                let goal = if self.eat(b'Y') {
                    (
                        Goal::Array,
                        Frame::PointerToArray {
                            kind,
                            own,
                            modifiers,
                            cv,
                        },
                    )
                } else {
                    (
                        Goal::DataType,
                        Frame::Pointee {
                            kind,
                            own,
                            modifiers,
                            cv,
                        },
                    )
                };
                Ok(Step::Call(goal.0, goal.1))
            }
            b'Q'..=b'T' => {
                let cv = cv(c - b'Q' + b'A')?;
                Ok(Step::Call(
                    Goal::QualifiedName,
                    Frame::MemberDataClass { own, modifiers, cv },
                ))
            }
            _ => Err(Error),
        }
    }

    /// After `Y`: the dimension count and dimensions.
    fn dims(&mut self) -> R<&'a [u64]> {
        let count = self.unsigned()?;
        if count > 64 {
            return Err(Error);
        }
        let base = self.scratch.dims.len();
        let mut result = Ok(());
        for _ in 0..count {
            match self.unsigned() {
                Ok(v) => self.scratch.dims.push(v),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let dims = self.alloc_slice(&self.scratch.dims[base..]);
        self.scratch.dims.truncate(base);
        result.map(|()| dims)
    }
}

/// A production the parser can be asked for.
#[derive(Clone, Copy)]
pub(super) enum Goal {
    Symbol,
    SymbolName,
    QualifiedName,
    Fragment,
    ScopeFragment,
    TemplateName,
    TemplateArg,
    TemplateValue(u8),
    Operator,
    Table,
    Signature(Option<ThisQualifiers>),
    ReturnType,
    Parameters,
    ThrowSpec,
    DataType,
    Array,
}

/// What a production gives.
#[derive(Clone, Copy)]
pub(super) enum Value<'a> {
    Type(Type<'a>),
    Name(Name<'a>),
    NameSpecial(Name<'a>, Special),
    Qualified(QualifiedName<'a>),
    /// A symbol, in [`Parser::symbol`] (taken by the frame it returns
    /// to, before anything else is parsed).
    Symbol,
    Args(&'a [TemplateArg<'a>]),
    Arg(Option<TemplateArg<'a>>),
    /// A symbol kind, in [`Parser::kind`].
    Kind,
    Signature(&'a FunctionType<'a>),
    Params(&'a [Type<'a>], bool),
    Bool(bool),
}

impl<'a> Value<'a> {
    pub(super) fn ty(self) -> R<Type<'a>> {
        match self {
            Value::Type(t) => Ok(t),
            _ => Err(Error),
        }
    }

    pub(super) fn name(self) -> R<Name<'a>> {
        match self {
            Value::Name(n) => Ok(n),
            _ => Err(Error),
        }
    }

    fn name_special(self) -> R<(Name<'a>, Special)> {
        match self {
            Value::NameSpecial(n, s) => Ok((n, s)),
            _ => Err(Error),
        }
    }

    fn qualified(self) -> R<QualifiedName<'a>> {
        match self {
            Value::Qualified(q) => Ok(q),
            _ => Err(Error),
        }
    }

    fn args(self) -> R<&'a [TemplateArg<'a>]> {
        match self {
            Value::Args(a) => Ok(a),
            _ => Err(Error),
        }
    }

    fn arg(self) -> R<Option<TemplateArg<'a>>> {
        match self {
            Value::Arg(a) => Ok(a),
            Value::Type(t) => Ok(Some(TemplateArg::Type(t))),
            _ => Err(Error),
        }
    }

    fn signature(self) -> R<&'a FunctionType<'a>> {
        match self {
            Value::Signature(f) => Ok(f),
            _ => Err(Error),
        }
    }

    fn params(self) -> R<(&'a [Type<'a>], bool)> {
        match self {
            Value::Params(p, v) => Ok((p, v)),
            _ => Err(Error),
        }
    }

    fn bool(self) -> R<bool> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(Error),
        }
    }
}

/// What to do next.
pub(super) enum Step<'a> {
    /// Parse the goal, then resume the frame with its value.
    Call(Goal, Frame<'a>),
    /// Parse the goal, whose value is this production's.
    Tail(Goal),
    /// This production's value.
    Done(Value<'a>),
}

/// A production waiting for another's value, with what it has so far.
pub(super) enum Frame<'a> {
    /// Restore the back-reference tables (see [`Parser::isolate`]).
    Restore,
    /// `???`: the rest of the name is ignored.
    DoubledSymbol,
    /// A symbol's own name read from `start` (again, if `retry`), when the
    /// back-reference tables held `refs` entries.
    SymbolName {
        start: usize,
        refs: (usize, usize),
        outer: bool,
        retry: bool,
    },
    /// The symbol's qualified name read.
    SymbolRest {
        first: &'a Name<'a>,
        special: Special,
        start: usize,
        refs: (usize, usize),
        outer: bool,
        retry: bool,
    },
    TypeDescriptor(&'a Name<'a>),
    SymbolKind(QualifiedName<'a>),
    TemplateSymbolName {
        start: usize,
    },
    NoSpecial,
    QualifiedName,
    QualifiedRest(usize),
    Fragment {
        start: usize,
    },
    TemplateOperator,
    TemplateArgsOf(&'a Name<'a>),
    TemplateArgs(usize),
    AutoTemplateArg,
    AddressArg,
    SymbolArg,
    TupleArg(u8),
    Enclosing,
    Bracketed,
    InitializedSymbol {
        atexit: bool,
    },
    InitializedName {
        atexit: bool,
    },
    EncodingFlags {
        arm64ec: bool,
        extern_c: bool,
    },
    Variable(Option<Access>),
    Function {
        access: Option<Access>,
        class: FunctionClass,
        adjustment: Option<Adjustment>,
    },
    Table {
        base: usize,
        modifiers: PointerModifiers,
        cv: Cv,
    },
    Returns {
        cc: &'static str,
        this: Option<ThisQualifiers>,
    },
    Parameters {
        cc: &'static str,
        this: Option<ThisQualifiers>,
        returns: Option<&'a Type<'a>>,
    },
    ThrowSpec(&'a mut FunctionType<'a>),
    ThrownType,
    Parameter {
        base: usize,
        start: usize,
        start_nodes: usize,
    },
    Qualify(Cv),
    ExplicitlyQualify(Cv),
    FunctionType,
    Alias,
    Tag(TagKind),
    Enum(&'static str),
    CliArray {
        rank: u8,
        modifiers: PointerModifiers,
        cv: Cv,
        own: Cv,
    },
    PointerToFunction {
        kind: Indirection,
        own: Cv,
        modifiers: PointerModifiers,
    },
    MemberFunctionClass {
        own: Cv,
        modifiers: PointerModifiers,
    },
    MemberFunction {
        class: QualifiedName<'a>,
        own: Cv,
        modifiers: PointerModifiers,
    },
    PointerToArray {
        kind: Indirection,
        own: Cv,
        modifiers: PointerModifiers,
        cv: Cv,
    },
    Pointee {
        kind: Indirection,
        own: Cv,
        modifiers: PointerModifiers,
        cv: Cv,
    },
    MemberDataClass {
        own: Cv,
        modifiers: PointerModifiers,
        cv: Cv,
    },
    MemberData {
        class: QualifiedName<'a>,
        own: Cv,
        modifiers: PointerModifiers,
        cv: Cv,
    },
    ArrayElement(&'a [u64]),
}

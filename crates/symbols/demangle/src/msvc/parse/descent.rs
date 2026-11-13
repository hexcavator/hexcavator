// The recursive half of the MSVC parser: the grammar by recursive
// descent, as fast as a parser gets, for the first `NATIVE_DEPTH` levels
// of nesting. Past that, each production hands the rest of its nesting to
// the machine (`machine.rs`), whose recursion is on a stack of its own:
// the thread's stack holds at most `NATIVE_DEPTH` levels, whatever the
// name. The two build the same trees (a test compares them).

use crate::msvc::ast::*;

use super::{CV_NONE, Error, Goal, Parser, R, Special, basic, cv, extended};

impl<'a> Parser<'a> {
    // ---- Symbols ---------------------------------------------------------

    /// A symbol (by the machine, from `NATIVE_DEPTH` levels down).
    pub(super) fn r_symbol(&mut self) -> R<Symbol<'a>> {
        if self.depth >= self.native_depth {
            let v = self.run(Goal::Symbol)?;
            return self.take_symbol(v);
        }
        self.depth += 1;
        let r = self.r_symbol_inner();
        self.depth -= 1;
        r
    }

    /// Runs `f` with fresh back-reference tables.
    fn isolated<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<T> {
        self.hide();
        let r = f(self)?;
        self.unhide()?;
        Ok(r)
    }

    fn r_symbol_inner(&mut self) -> R<Symbol<'a>> {
        self.expect(b'?')?;
        if self.eat_str("?@") {
            return Ok(Symbol {
                name: QualifiedName::default(),
                kind: SymbolKind::Hashed(self.text),
            });
        }
        // `???...`: C++/CLI decorated a decorated name again; the inner one
        // is the name (the rest is ignored).
        if self.peek() == Some(b'?') && self.peek_at(1) == Some(b'?') {
            let s = self.r_symbol()?;
            self.pos = self.s.len();
            return Ok(s);
        }
        // (The tables as they were, should the name have to be read again.)
        let (start, outer) = (self.pos, self.variable_template);
        let refs = (self.names.items.len(), self.types.items.len());
        self.variable_template = false;
        let (mut first, mut special) = self.r_symbol_name()?;
        let mut name = self.r_qualified_name_rest_for(first, special)?;
        // A variable template's name is itself a back-reference: read the
        // name again knowing that.
        if matches!(first, Name::Template { .. })
            && matches!(self.peek(), Some(b'0'..=b'4'))
            && special == Special::None
        {
            self.pos = start;
            self.names.items.truncate(refs.0);
            self.types.items.truncate(refs.1);
            self.variable_template = true;
            (first, special) = self.r_symbol_name()?;
            self.variable_template = false;
            name = self.r_qualified_name_rest_for(first, special)?;
        }
        self.variable_template = outer;
        if special == Special::TypeDescriptor {
            // `??_R0?AVFoo@@@8`: the type, then `@8`.
            let ty = self.r_return_type()?;
            self.expect(b'@')?;
            self.expect(b'8')?;
            return Ok(Symbol {
                name: QualifiedName(self.alloc_slice(&[first])),
                kind: SymbolKind::TypeDescriptor(ty),
            });
        }
        if special == Special::Literal {
            return Ok(Symbol {
                name: QualifiedName(self.alloc_slice(&[first])),
                kind: SymbolKind::NameOnly,
            });
        }
        let kind = match special {
            Special::Literal => unreachable!(),
            Special::TypeDescriptor => unreachable!(),
            Special::Table => {
                let c = self.next()?;
                if c != b'6' && c != b'7' {
                    return Err(Error);
                }
                self.r_table()?
            }
            Special::None => self.r_encoding()?,
        };
        Ok(Symbol { name, kind })
    }

    /// The rest of a symbol's qualified name, for names that have one.
    fn r_qualified_name_rest_for(
        &mut self,
        first: Name<'a>,
        special: Special,
    ) -> R<QualifiedName<'a>> {
        match special {
            Special::TypeDescriptor | Special::Literal => {
                Ok(QualifiedName(self.alloc_slice(&[first])))
            }
            _ => self.r_qualified_rest(first),
        }
    }

    /// A symbol's own (unqualified) name.
    pub(super) fn r_symbol_name(&mut self) -> R<(Name<'a>, Special)> {
        if self.peek() == Some(b'?') {
            if self.peek_at(1) == Some(b'$') {
                self.pos += 1;
                let start = self.nodes;
                let name = self.r_template_name()?;
                if self.variable_template {
                    self.remember_name(&name, start);
                }
                return Ok((name, Special::None));
            }
            self.pos += 1;
            return self.r_operator();
        }
        Ok((self.r_fragment()?, Special::None))
    }

    /// The scopes after the first component, up to `@`; the result is
    /// outermost first.
    pub(super) fn r_qualified_rest(&mut self, first: Name<'a>) -> R<QualifiedName<'a>> {
        let base = self.scratch.names.len();
        self.scratch.names.push(first);
        let result = (|| {
            while !self.eat(b'@') {
                let part = self.r_scope_fragment()?;
                self.scratch.names.push(part);
            }
            Ok(())
        })();
        self.scratch.names[base..].reverse();
        let parts = self.alloc_slice(&self.scratch.names[base..]);
        self.scratch.names.truncate(base);
        result.map(|()| QualifiedName(parts))
    }

    fn r_qualified_name(&mut self) -> R<QualifiedName<'a>> {
        let first = self.r_fragment()?;
        self.r_qualified_rest(first)
    }

    /// One name component: an identifier, a back-reference, or a template.
    fn r_fragment(&mut self) -> R<Name<'a>> {
        let c = self.peek().ok_or(Error)?;
        if c.is_ascii_digit() {
            self.pos += 1;
            return self.name_ref(c - b'0');
        }
        let start = self.nodes;
        self.charge(1)?;
        let name = if c == b'?' && self.peek_at(1) == Some(b'$') {
            self.pos += 1;
            self.r_template_name()?
        } else {
            Name::Identifier(self.identifier()?)
        };
        self.remember_name(&name, start);
        Ok(name)
    }

    /// `$name@args@` (after its `?`), with its own back-reference tables.
    fn r_template_name(&mut self) -> R<Name<'a>> {
        if self.depth >= self.native_depth {
            return self.run(Goal::TemplateName)?.name();
        }
        self.expect(b'$')?;
        self.depth += 1;
        let r = self.isolated(Self::r_template_body);
        self.depth -= 1;
        r
    }

    fn r_template_body(&mut self) -> R<Name<'a>> {
        let name = if self.peek() == Some(b'?') {
            self.pos += 1;
            self.r_operator()?.0
        } else {
            let start = self.nodes;
            let n = Name::Identifier(self.identifier()?);
            self.remember_name(&n, start);
            n
        };
        let args = self.r_template_args()?;
        Ok(Name::Template {
            name: self.alloc(name),
            args,
        })
    }

    fn r_template_args(&mut self) -> R<&'a [TemplateArg<'a>]> {
        let base = self.scratch.args.len();
        let result = self.r_template_args_onto();
        let args = self.alloc_slice(&self.scratch.args[base..]);
        self.scratch.args.truncate(base);
        result.map(|()| args)
    }

    fn r_template_args_onto(&mut self) -> R<()> {
        while !self.eat(b'@') {
            // (Template arguments are not remembered as types.)
            if let Some(arg) = self.r_template_arg()? {
                self.scratch.args.push(arg);
            }
        }
        Ok(())
    }

    /// A non-type template argument after its `$<kind>` code (`None` for
    /// an empty pack).
    fn r_template_value(&mut self, kind: u8) -> R<Option<TemplateArg<'a>>> {
        Ok(Some(match kind {
            b'0' => TemplateArg::Integer(self.signed()?),
            b'1' => {
                if self.eat(b'@') {
                    return Ok(Some(TemplateArg::Address(None)));
                }
                // (The symbol shares the argument list's tables.)
                let s = self.r_symbol()?;
                TemplateArg::Address(Some(self.alloc(s)))
            }
            b'E' => {
                let s = self.isolated(Self::r_symbol)?;
                TemplateArg::Symbol(self.alloc(s))
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
            b'H' | b'I' | b'J' => {
                // (Like `$1`'s, the symbol shares the argument list's
                // tables: `?f@12@...` refers to names before it.)
                let s = self.r_symbol()?;
                let n = usize::from(kind - b'G');
                let v = self.ints(n)?;
                TemplateArg::Tuple(Some(self.alloc(s)), v)
            }
            // An empty non-type pack.
            b'S' => return Ok(None),
            _ => return Err(Error),
        }))
    }

    /// One template argument (`None` for an empty pack).
    fn r_template_arg(&mut self) -> R<Option<TemplateArg<'a>>> {
        if self.peek() == Some(b'$') {
            let kind = self.peek_at(1).ok_or(Error)?;
            match kind {
                b'0' | b'1' | b'2' | b'D' | b'E' | b'F' | b'G' | b'H' | b'I' | b'J' | b'Q'
                | b'S' => {
                    self.pos += 2;
                    return self.r_template_value(kind);
                }
                // `$M<type><value>`: a non-type parameter declared `auto`
                // (C++17): the type it deduced, then the value (a `$` code
                // without its `$`). undname shows only the value.
                b'M' => {
                    self.pos += 2;
                    self.r_data_type()?;
                    let value = self.next()?;
                    return self.r_template_value(value);
                }
                b'$' if matches!(self.peek_at(2), Some(b'V' | b'Z')) => {
                    self.pos += 3;
                    return Ok(None);
                }
                _ => {}
            }
        }
        Ok(Some(TemplateArg::Type(self.r_data_type()?)))
    }

    fn r_scope_fragment(&mut self) -> R<Name<'a>> {
        if self.peek() != Some(b'?') {
            return self.r_fragment();
        }
        match self.peek_at(1).ok_or(Error)? {
            b'$' => self.r_fragment(),
            b'A' => {
                self.pos += 2;
                let start = self.nodes;
                self.charge(1)?;
                let tag = self.identifier()?;
                let name = Name::AnonymousNamespace(tag);
                self.remember_name(&name, start);
                Ok(name)
            }
            b'?' => {
                self.pos += 1;
                // The enclosing function's name continues this name's
                // back-reference tables.
                let s = self.r_symbol()?;
                Ok(Name::Enclosing(self.alloc(s)))
            }
            b'I' | b'Q' => {
                // `[Interface]`: the interface a member implements (C++/CX).
                self.pos += 2;
                Ok(Name::Bracketed(self.r_qualified_name()?))
            }
            _ => {
                self.pos += 1;
                Ok(Name::Frame(self.unsigned()?))
            }
        }
    }

    /// An operator or special name (after its `?`).
    fn r_operator(&mut self) -> R<(Name<'a>, Special)> {
        let op = |s: &'static str| Ok((Name::Operator(s), Special::None));
        match self.next()? {
            b'0' => Ok((Name::Constructor, Special::None)),
            b'1' => Ok((Name::Destructor, Special::None)),
            b'2' => op("operator new"),
            b'3' => op("operator delete"),
            b'4' => op("operator="),
            b'5' => op("operator>>"),
            b'6' => op("operator<<"),
            b'7' => op("operator!"),
            b'8' => op("operator=="),
            b'9' => op("operator!="),
            b'A' => op("operator[]"),
            b'B' => Ok((Name::Conversion, Special::None)),
            b'C' => op("operator->"),
            b'D' => op("operator*"),
            b'E' => op("operator++"),
            b'F' => op("operator--"),
            b'G' => op("operator-"),
            b'H' => op("operator+"),
            b'I' => op("operator&"),
            b'J' => op("operator->*"),
            b'K' => op("operator/"),
            b'L' => op("operator%"),
            b'M' => op("operator<"),
            b'N' => op("operator<="),
            b'O' => op("operator>"),
            b'P' => op("operator>="),
            b'Q' => op("operator,"),
            b'R' => op("operator()"),
            b'S' => op("operator~"),
            b'T' => op("operator^"),
            b'U' => op("operator|"),
            b'V' => op("operator&&"),
            b'W' => op("operator||"),
            b'X' => op("operator*="),
            b'Y' => op("operator+="),
            b'Z' => op("operator-="),
            b'_' => self.r_operator_underscore(),
            _ => Err(Error),
        }
    }

    fn r_operator_underscore(&mut self) -> R<(Name<'a>, Special)> {
        let op = |s: &'static str| Ok((Name::Operator(s), Special::None));
        let special = |s: &'static str| Ok((Name::Special(s), Special::None));
        let table = |s: &'static str| Ok((Name::Special(s), Special::Table));
        match self.next()? {
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
                Ok((Name::Special("`string'"), Special::Literal))
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
            b'R' => self.rtti(),
            b'S' => table("`local vftable'"),
            b'T' => special("`local vftable constructor closure'"),
            b'U' => op("operator new[]"),
            b'V' => op("operator delete[]"),
            b'X' => special("`placement delete closure'"),
            b'Y' => special("`placement delete[] closure'"),
            b'_' => self.r_operator_double_underscore(),
            _ => Err(Error),
        }
    }

    fn r_operator_double_underscore(&mut self) -> R<(Name<'a>, Special)> {
        let special = |s: &'static str| Ok((Name::Special(s), Special::None));
        let c = self.next()?;
        match c {
            b'A' => special("`managed vector constructor iterator'"),
            b'B' => special("`managed vector destructor iterator'"),
            b'C' => special("`eh vector copy constructor iterator'"),
            b'D' => special("`eh vector vbase copy constructor iterator'"),
            b'E' | b'F' => {
                let target = if self.peek() == Some(b'?') {
                    let s = self.isolated(Self::r_symbol)?;
                    // The nested name ends with its own `@`.
                    self.eat(b'@');
                    Initialized::Symbol(s)
                } else {
                    // Just the variable's name; the scopes that follow are
                    // the initializer's.
                    let name = self.r_fragment()?;
                    Initialized::Name(QualifiedName(self.alloc_slice(&[name])))
                };
                Ok((
                    Name::DynamicInitializer {
                        atexit: c == b'F',
                        target: self.alloc(target),
                    },
                    Special::None,
                ))
            }
            b'G' => special("`vector copy constructor iterator'"),
            b'H' => special("`vector vbase copy constructor iterator'"),
            b'I' => special("`managed vector copy constructor iterator'"),
            b'J' => special("`local static thread guard'"),
            b'K' => Ok((Name::Literal(self.identifier()?), Special::None)),
            b'L' => Ok((Name::Operator("operator co_await"), Special::None)),
            b'M' => Ok((Name::Operator("operator<=>"), Special::None)),
            _ => Err(Error),
        }
    }

    // ---- Encodings -----------------------------------------------------

    fn r_encoding(&mut self) -> R<SymbolKind<'a>> {
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
        let mut kind = self.r_encoding_inner()?;
        if let SymbolKind::Function(f) = &mut kind {
            f.arm64ec = arm64ec;
            f.extern_c = extern_c;
        }
        Ok(kind)
    }

    fn r_encoding_inner(&mut self) -> R<SymbolKind<'a>> {
        let c = self.next()?;
        match c {
            b'0'..=b'4' => {
                let access = match c {
                    b'0' => Some(Access::Private),
                    b'1' => Some(Access::Protected),
                    b'2' => Some(Access::Public),
                    _ => None,
                };
                let ty = self.r_data_type()?;
                let (modifiers, cv) = self.storage()?;
                Ok(SymbolKind::Variable {
                    access,
                    ty,
                    cv,
                    modifiers,
                })
            }
            b'5' => Ok(SymbolKind::LocalStaticGuard(self.unsigned()?)),
            b'6' | b'7' => self.r_table(),
            b'8' | b'9' => Ok(SymbolKind::NameOnly),
            b'A'..=b'Z' => self.r_function(c),
            b'$' => self.r_special_function(),
            _ => Err(Error),
        }
    }

    /// `B@` or `B<bases>@` after a table's `6`.
    fn r_table(&mut self) -> R<SymbolKind<'a>> {
        let (modifiers, cv) = self.storage()?;
        let base = self.scratch.qualified.len();
        let result = (|| {
            while !self.eat(b'@') {
                let q = self.r_qualified_name()?;
                self.scratch.qualified.push(q);
            }
            Ok(())
        })();
        let targets = self.alloc_slice(&self.scratch.qualified[base..]);
        self.scratch.qualified.truncate(base);
        result?;
        Ok(SymbolKind::Table {
            cv,
            modifiers,
            targets,
        })
    }

    fn r_function(&mut self, code: u8) -> R<SymbolKind<'a>> {
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
        let signature = self.r_signature(this)?;
        Ok(SymbolKind::Function(Function {
            arm64ec: false,
            extern_c: false,
            access,
            class,
            adjustment,
            signature,
        }))
    }

    fn r_special_function(&mut self) -> R<SymbolKind<'a>> {
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
                return Ok(SymbolKind::VcallThunk {
                    offset,
                    calling_convention,
                });
            }
            _ => return Err(Error),
        };
        let this = self.this_qualifiers()?;
        let signature = self.r_signature(Some(this))?;
        Ok(SymbolKind::Function(Function {
            arm64ec: false,
            extern_c: false,
            access: Some(adjustment.0),
            class: FunctionClass::Virtual,
            adjustment: Some(adjustment.1),
            signature,
        }))
    }

    /// Calling convention, return type, parameters, exception spec.
    fn r_signature(&mut self, this: Option<ThisQualifiers>) -> R<FunctionType<'a>> {
        let calling_convention = self.calling_convention()?;
        let returns = if self.eat(b'@') {
            None
        } else {
            Some(self.r_return_type()?)
        };
        let (params, variadic) = self.r_parameters()?;
        let noexcept = self.r_throw_spec()?;
        Ok(FunctionType {
            calling_convention,
            returns,
            params,
            variadic,
            noexcept,
            this,
        })
    }

    /// `Z` (none), `_E` (`noexcept`), or a list of types. Returns whether
    /// it is `noexcept`.
    fn r_throw_spec(&mut self) -> R<bool> {
        if self.eat(b'Z') {
            return Ok(false);
        }
        if self.eat_str("_E") {
            return Ok(true);
        }
        while !self.eat(b'@') {
            self.r_data_type()?;
        }
        Ok(false)
    }

    fn r_parameters(&mut self) -> R<(&'a [Type<'a>], bool)> {
        if self.eat(b'X') {
            return Ok((&[], false));
        }
        let base = self.scratch.types.len();
        let result = self.r_parameters_onto();
        let params = self.alloc_slice(&self.scratch.types[base..]);
        self.scratch.types.truncate(base);
        result.map(|variadic| (params, variadic))
    }

    /// Pushes the parameters; returns whether they end in `...`.
    fn r_parameters_onto(&mut self) -> R<bool> {
        loop {
            match self.peek().ok_or(Error)? {
                b'@' => {
                    self.pos += 1;
                    return Ok(false);
                }
                b'Z' => {
                    self.pos += 1;
                    return Ok(true);
                }
                c if c.is_ascii_digit() => {
                    self.pos += 1;
                    let ty = self.type_ref(c - b'0')?;
                    self.scratch.types.push(ty);
                }
                _ => {
                    let start = self.pos;
                    let start_nodes = self.nodes;
                    let ty = self.r_data_type()?;
                    self.remember_type(start, start_nodes, &ty);
                    self.scratch.types.push(ty);
                }
            }
        }
    }

    /// A return type; `?A`-`?D` give a by-value class type's cv.
    fn r_return_type(&mut self) -> R<Type<'a>> {
        if self.eat(b'?') {
            let cv = cv(self.next()?)?;
            let ty = self.r_data_type()?;
            return Ok(self.qualified(cv, ty));
        }
        self.r_data_type()
    }

    // ---- Types ---------------------------------------------------------------

    fn r_data_type(&mut self) -> R<Type<'a>> {
        if self.depth >= self.native_depth {
            return self.run(Goal::DataType)?.ty();
        }
        self.charge(1)?;
        self.depth += 1;
        let r = self.r_data_type_inner();
        self.depth -= 1;
        r
    }

    fn r_data_type_inner(&mut self) -> R<Type<'a>> {
        let c = self.next()?;
        if let Some(b) = basic(c) {
            return Ok(Type::Builtin(b));
        }
        match c {
            b'_' => {
                let c = self.next()?;
                Ok(Type::Builtin(extended(c).ok_or(Error)?))
            }
            b'T' | b'U' | b'V' | b'Y' => {
                let kind = match c {
                    b'T' => TagKind::Union,
                    b'U' => TagKind::Struct,
                    b'V' => TagKind::Class,
                    _ => TagKind::Cointerface,
                };
                Ok(Type::Tag(kind, self.r_qualified_name()?))
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
                Ok(Type::Enum {
                    underlying,
                    name: self.r_qualified_name()?,
                })
            }
            b'P' | b'Q' | b'R' | b'S' => {
                let own = cv(c - b'P' + b'A')?;
                self.r_pointer(Indirection::Pointer, own)
            }
            b'A' => self.r_pointer(Indirection::Reference, CV_NONE),
            b'B' => self.r_pointer(
                Indirection::Reference,
                Cv {
                    is_const: false,
                    is_volatile: true,
                },
            ),
            b'?' => {
                let cv = cv(self.next()?)?;
                let ty = self.r_data_type()?;
                Ok(self.qualified(cv, ty))
            }
            b'$' => self.r_dollar_type(),
            _ => Err(Error),
        }
    }

    fn r_dollar_type(&mut self) -> R<Type<'a>> {
        self.expect(b'$')?;
        match self.next()? {
            b'Q' => self.r_pointer(Indirection::RvalueReference, CV_NONE),
            b'R' => self.r_pointer(
                Indirection::RvalueReference,
                Cv {
                    is_const: false,
                    is_volatile: true,
                },
            ),
            b'C' => {
                let cv = cv(self.next()?)?;
                let ty = self.r_data_type()?;
                Ok(Type::ExplicitlyQualified(cv, self.alloc(ty)))
            }
            b'A' => match self.next()? {
                b'6' => {
                    let f = self.r_signature(None)?;
                    Ok(Type::Function(self.alloc(f)))
                }
                // `$$A8@@<this><signature>`: a member function's type, of
                // no class (`R __cdecl(params) const`, as an argument to
                // `std::function`-like templates).
                b'8' => {
                    self.expect(b'@')?;
                    self.expect(b'@')?;
                    let this = self.this_qualifiers()?;
                    let f = self.r_signature(Some(this))?;
                    Ok(Type::Function(self.alloc(f)))
                }
                _ => Err(Error),
            },
            b'B' => {
                self.expect(b'Y')?;
                self.r_array()
            }
            b'T' => Ok(Type::Builtin(Builtin::Nullptr)),
            b'Y' => Ok(Type::Alias(self.r_qualified_name()?)),
            _ => Err(Error),
        }
    }

    /// After the pointer's own letter: modifiers, then the pointee.
    fn r_pointer(&mut self, kind: Indirection, own: Cv) -> R<Type<'a>> {
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
            let element = self.r_data_type()?;
            let array = Type::CliArray {
                rank,
                element: self.alloc(element),
            };
            return Ok(Type::Pointer {
                kind: Indirection::Handle,
                cv: own,
                modifiers,
                pointee: self.alloc(self.qualified(cv, array)),
            });
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
        let pointee = match c {
            b'6' => {
                let f = self.r_signature(None)?;
                Type::Function(self.alloc(f))
            }
            b'8' => {
                let class = self.r_qualified_name()?;
                let this = self.this_qualifiers()?;
                let f = self.r_signature(Some(this))?;
                return Ok(Type::MemberPointer {
                    class,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(Type::Function(self.alloc(f))),
                });
            }
            b'A'..=b'D' => {
                let cv = cv(c)?;
                if self.eat(b'Y') {
                    match self.r_array()? {
                        Type::Array { dims, element } => Type::Array {
                            dims,
                            element: self.alloc(self.qualified(cv, *element)),
                        },
                        _ => return Err(Error),
                    }
                } else {
                    let ty = self.r_data_type()?;
                    // A pointer's qualifiers are encoded twice: in this
                    // letter and in the pointer's own.
                    if matches!(ty, Type::Pointer { .. } | Type::MemberPointer { .. }) {
                        ty
                    } else {
                        self.qualified(cv, ty)
                    }
                }
            }
            b'Q'..=b'T' => {
                let cv = cv(c - b'Q' + b'A')?;
                let class = self.r_qualified_name()?;
                let ty = self.r_data_type()?;
                return Ok(Type::MemberPointer {
                    class,
                    cv: own,
                    modifiers,
                    pointee: self.alloc(self.qualified(cv, ty)),
                });
            }
            _ => return Err(Error),
        };
        Ok(Type::Pointer {
            kind,
            cv: own,
            modifiers,
            pointee: self.alloc(pointee),
        })
    }

    /// After `Y`: the dimension count, dimensions, and element type.
    fn r_array(&mut self) -> R<Type<'a>> {
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
        result?;
        let element = self.r_data_type()?;
        Ok(Type::Array {
            dims,
            element: self.alloc(element),
        })
    }
}

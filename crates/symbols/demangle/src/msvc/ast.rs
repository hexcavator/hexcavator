//! The syntax tree of an undecorated name.

/// A decorated symbol: its name and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: QualifiedName<'a>,
    pub kind: SymbolKind<'a>,
}

/// A qualified name, outermost component first (`std`, `vector<int>`,
/// `push_back`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QualifiedName<'a>(pub &'a [Name<'a>]);

impl<'a> QualifiedName<'a> {
    /// The innermost (unqualified) component.
    pub fn last(&self) -> Option<&Name<'a>> {
        self.0.last()
    }

    /// The enclosing scopes.
    pub fn scope(&self) -> &[Name<'a>] {
        &self.0[..self.0.len().saturating_sub(1)]
    }
}

/// One component of a qualified name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    Identifier(&'a str),
    /// A template specialization: `name<args>`.
    Template {
        name: &'a Name<'a>,
        args: &'a [TemplateArg<'a>],
    },
    /// An operator (`operator+`, `operator new[]`, ...), as written.
    Operator(&'static str),
    /// A constructor (named after its class).
    Constructor,
    /// A destructor.
    Destructor,
    /// A conversion operator (`operator int`); the type is the function's
    /// return type.
    Conversion,
    /// A compiler-generated name: `` `vftable' ``, `` `string' ``, ...
    Special(&'static str),
    /// `` `RTTI Base Class Descriptor at (a,b,c,d)' ``.
    BaseClassDescriptor([i64; 3], u64),
    /// `` `dynamic initializer for 'x'' `` (`atexit`: the destructor).
    DynamicInitializer {
        atexit: bool,
        target: &'a Initialized<'a>,
    },
    /// A literal operator: `operator "" _suffix`.
    Literal(&'a str),
    /// `` `anonymous namespace' `` (with the compiler's tag).
    AnonymousNamespace(&'a str),
    /// A lexical scope within a function: `` `2' ``.
    Frame(u64),
    /// The function (or other symbol) a local name belongs to.
    Enclosing(&'a Symbol<'a>),
    /// `[name]`: an interface or COM+ scope.
    Bracketed(QualifiedName<'a>),
}

/// What a dynamic initializer initializes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initialized<'a> {
    Name(QualifiedName<'a>),
    Symbol(Symbol<'a>),
}

/// A template argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateArg<'a> {
    Type(Type<'a>),
    Integer(i64),
    /// `&symbol`, or `NULL`.
    Address(Option<&'a Symbol<'a>>),
    /// A symbol used directly (`$E`).
    Symbol(&'a Symbol<'a>),
    /// `$2`: a floating-point value as mantissa and exponent.
    Float(i64, i64),
    /// `` `template-parameter<n>' ``.
    TemplateParameter(i64),
    /// `` `non-type-template-parameter<n>' ``.
    NonTypeParameter(i64),
    /// A member pointer or class constant: `{symbol,offsets...}` or
    /// `{offsets...}`.
    Tuple(Option<&'a Symbol<'a>>, &'a [i64]),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cv {
    pub is_const: bool,
    pub is_volatile: bool,
}

impl Cv {
    pub fn is_empty(self) -> bool {
        !self.is_const && !self.is_volatile
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    Void,
    SignedChar,
    Char,
    UnsignedChar,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    Float,
    Double,
    LongDouble,
    Int8,
    UnsignedInt8,
    Int16,
    UnsignedInt16,
    Int32,
    UnsignedInt32,
    Int64,
    UnsignedInt64,
    Int128,
    UnsignedInt128,
    Bool,
    Char8,
    Char16,
    Char32,
    WChar,
    Nullptr,
    /// A deduced return type: `auto`.
    Auto,
    /// `decltype(auto)`.
    DecltypeAuto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagKind {
    Class,
    Struct,
    Union,
    Cointerface,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indirection {
    Pointer,
    Reference,
    RvalueReference,
    /// A C++/CLI handle: `^`.
    Handle,
    /// A C++/CLI tracking reference: `%`.
    TrackingReference,
}

/// `__ptr64`, `__unaligned`, `__restrict` on a pointer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointerModifiers {
    pub ptr64: bool,
    pub unaligned: bool,
    pub restrict: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type<'a> {
    Builtin(Builtin),
    Tag(TagKind, QualifiedName<'a>),
    /// A type named by a qualified name with no class-key (`$$Y`): a
    /// member type alias such as `traits<T>::type`.
    Alias(QualifiedName<'a>),
    /// An enum; `underlying` is its spelling's suffix (`""` for int,
    /// `"char"`, `"unsigned short"`, ...).
    Enum {
        underlying: &'static str,
        name: QualifiedName<'a>,
    },
    Pointer {
        kind: Indirection,
        /// The pointer's own qualifiers (`* const`).
        cv: Cv,
        modifiers: PointerModifiers,
        pointee: &'a Type<'a>,
    },
    MemberPointer {
        class: QualifiedName<'a>,
        cv: Cv,
        modifiers: PointerModifiers,
        pointee: &'a Type<'a>,
    },
    Function(&'a FunctionType<'a>),
    Array {
        dims: &'a [u64],
        element: &'a Type<'a>,
    },
    Qualified(Cv, &'a Type<'a>),
    /// A C++/CLI managed array: `cli::array<T,rank>`.
    CliArray {
        rank: u8,
        element: &'a Type<'a>,
    },
    /// A cv-qualified type spelled out as such (`$$C`, in template
    /// arguments and array elements), which undname writes with a space
    /// after the qualifiers.
    ExplicitlyQualified(Cv, &'a Type<'a>),
}

/// A function's calling convention, return type, and parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionType<'a> {
    pub calling_convention: &'static str,
    /// `None` for constructors and destructors.
    pub returns: Option<Type<'a>>,
    pub params: &'a [Type<'a>],
    /// Ends in `...`.
    pub variadic: bool,
    pub noexcept: bool,
    /// For member functions: the `this` qualifiers.
    pub this: Option<ThisQualifiers>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThisQualifiers {
    pub cv: Cv,
    pub modifiers: PointerModifiers,
    /// `&` or `&&` ref-qualifier.
    pub reference: Option<Indirection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Private,
    Protected,
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionClass {
    Global,
    Member,
    Static,
    Virtual,
}

/// A thunk's adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adjustment {
    Adjustor(i64),
    Vtordisp(i64, i64),
    VtordispEx(i64, i64, i64, i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function<'a> {
    /// `$$h`: an ARM64EC function.
    pub arm64ec: bool,
    /// `$$J`: declared `extern "C"`.
    pub extern_c: bool,
    pub access: Option<Access>,
    pub class: FunctionClass,
    /// For thunks.
    pub adjustment: Option<Adjustment>,
    pub signature: FunctionType<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind<'a> {
    Function(Function<'a>),
    Variable {
        /// For static data members.
        access: Option<Access>,
        ty: Type<'a>,
        /// The variable's own qualifiers.
        cv: Cv,
        modifiers: PointerModifiers,
    },
    /// A virtual table (`` `vftable' ``), with the bases it is for.
    Table {
        cv: Cv,
        modifiers: PointerModifiers,
        targets: &'a [QualifiedName<'a>],
    },
    /// `` `RTTI Type Descriptor' `` for a type.
    TypeDescriptor(Type<'a>),
    /// A `vcall` thunk.
    VcallThunk {
        offset: u64,
        calling_convention: &'static str,
    },
    /// A name with nothing more to it (string literals, RTTI tables).
    NameOnly,
    /// A numbered `` `local static guard' ``.
    LocalStaticGuard(u64),
    /// An MD5-hashed name (`??@...@`), kept as decorated.
    Hashed(&'a str),
}

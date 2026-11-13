// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Follows the LLVM Project's demangler (see LICENSE-LLVM at the crate root).

//! The syntax tree of an Itanium-mangled name.
//!
//! Nodes live in one vector ([`Ast::nodes`]) and refer to each other by
//! index ([`NodeId`]); lists of nodes are ranges of [`Ast::lists`]. The
//! node kinds are those of LLVM's `ItaniumDemangle.h`, whose printing rules
//! [`super::print`] follows, so that the output matches `llvm-cxxfilt` and
//! `__cxa_demangle`.

use alloc::vec::Vec;

/// A node, by its index in [`Ast::nodes`].
pub type NodeId = u32;

/// A list of nodes: `len` entries of [`Ast::lists`] from `start`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct List {
    pub start: u32,
    pub len: u32,
}

impl List {
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Operator precedence, strongest first (for parenthesizing expressions).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Prec {
    Primary,
    Postfix,
    Unary,
    Cast,
    PtrMem,
    Multiplicative,
    Additive,
    Shift,
    Spaceship,
    Relational,
    Equality,
    And,
    Xor,
    Ior,
    AndIf,
    OrIf,
    Conditional,
    Assign,
    Comma,
    Default,
}

/// A cached property of a node: known yes, known no, or depending on which
/// element of a parameter pack is being printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    Yes,
    No,
    Unknown,
}

/// `const`, `volatile`, `restrict` bits.
pub const QUAL_CONST: u8 = 1;
pub const QUAL_VOLATILE: u8 = 2;
pub const QUAL_RESTRICT: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefQual {
    None,
    LValue,
    RValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    Type,
    NonType,
    Template,
}

/// `Sa`, `Sb`, `Ss`, `Si`, `So`, `Sd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpecialSub {
    Allocator,
    BasicString,
    String,
    Istream,
    Ostream,
    Iostream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatKind {
    Float,
    Double,
    LongDouble,
}

/// A node of the tree. Strings are bytes of the mangled name, or fixed
/// spellings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node<'a> {
    NodeArray(List),
    /// `name (.suffix)`: a clone suffix such as `.cold` or `.constprop.0`.
    DotSuffix {
        prefix: NodeId,
        suffix: &'a [u8],
    },
    VendorExtQualType {
        ty: NodeId,
        ext: &'a [u8],
        args: Option<NodeId>,
    },
    QualType {
        child: NodeId,
        quals: u8,
    },
    ConversionOperatorType(NodeId),
    PostfixQualifiedType {
        ty: NodeId,
        postfix: &'a [u8],
    },
    ElaboratedTypeSpefType {
        kind: &'a [u8],
        child: NodeId,
    },
    TransformedType {
        transform: &'a [u8],
        base: NodeId,
    },
    NameType(&'a [u8]),
    AbiTagAttr {
        base: NodeId,
        tag: &'a [u8],
    },
    EnableIfAttr(List),
    ObjCProtoName {
        ty: NodeId,
        protocol: &'a [u8],
    },
    PointerType(NodeId),
    ReferenceType {
        pointee: NodeId,
        rvalue: bool,
    },
    PointerToMemberType {
        class: NodeId,
        member: NodeId,
    },
    ArrayType {
        base: NodeId,
        dimension: Option<NodeId>,
    },
    FunctionType {
        ret: NodeId,
        params: List,
        cv: u8,
        ref_qual: RefQual,
        exception: Option<NodeId>,
    },
    NoexceptSpec(NodeId),
    DynamicExceptionSpec(List),
    ExplicitObjectParameter(NodeId),
    FunctionEncoding {
        ret: Option<NodeId>,
        name: NodeId,
        params: List,
        attrs: Option<NodeId>,
        requires: Option<NodeId>,
        cv: u8,
        ref_qual: RefQual,
    },
    LiteralOperator(NodeId),
    SpecialName {
        special: &'a [u8],
        child: NodeId,
    },
    CtorVtableSpecialName {
        first: NodeId,
        second: NodeId,
    },
    QualifiedName {
        qualifier: NodeId,
        name: NodeId,
    },
    NestedName {
        qual: NodeId,
        name: NodeId,
    },
    MemberLikeFriendName {
        qual: NodeId,
        name: NodeId,
    },
    LocalName {
        encoding: NodeId,
        entity: NodeId,
    },
    ModuleName {
        parent: Option<NodeId>,
        name: NodeId,
        partition: bool,
    },
    ModuleEntity {
        module: NodeId,
        name: NodeId,
    },
    VectorType {
        base: NodeId,
        dimension: Option<NodeId>,
    },
    PixelVectorType(NodeId),
    BinaryFPType(NodeId),
    BitIntType {
        size: NodeId,
        signed: bool,
    },
    SyntheticTemplateParamName {
        kind: ParamKind,
        index: u32,
    },
    TemplateParamQualifiedArg {
        param: NodeId,
        arg: NodeId,
    },
    TypeTemplateParamDecl(NodeId),
    ConstrainedTypeTemplateParamDecl {
        constraint: NodeId,
        name: NodeId,
    },
    NonTypeTemplateParamDecl {
        name: NodeId,
        ty: NodeId,
    },
    TemplateTemplateParamDecl {
        name: NodeId,
        params: List,
        requires: Option<NodeId>,
    },
    TemplateParamPackDecl(NodeId),
    /// An unexpanded pack: the elements of a `J...E` template argument as
    /// a template parameter refers to them.
    ParameterPack(List),
    TemplateArgumentPack(List),
    ParameterPackExpansion(NodeId),
    PackIndexing {
        pattern: NodeId,
        index: NodeId,
    },
    TemplateArgs {
        params: List,
        requires: Option<NodeId>,
    },
    /// A template parameter of a conversion operator's type, resolved once
    /// the template arguments after it are parsed: [`Ast::forward`] holds
    /// the target.
    ForwardTemplateReference {
        index: u32,
        slot: u32,
    },
    NameWithTemplateArgs {
        name: NodeId,
        args: NodeId,
    },
    GlobalQualifiedName(NodeId),
    ExpandedSpecialSubstitution(SpecialSub),
    SpecialSubstitution(SpecialSub),
    CtorDtorName {
        base: NodeId,
        dtor: bool,
        variant: u8,
    },
    DtorName(NodeId),
    UnnamedTypeName(&'a [u8]),
    ClosureTypeName {
        template_params: List,
        requires1: Option<NodeId>,
        params: List,
        requires2: Option<NodeId>,
        count: &'a [u8],
    },
    StructuredBindingName(List),
    BinaryExpr {
        lhs: NodeId,
        op: &'a [u8],
        rhs: NodeId,
    },
    ArraySubscriptExpr {
        op1: NodeId,
        op2: NodeId,
    },
    PostfixExpr {
        child: NodeId,
        op: &'a [u8],
    },
    ConditionalExpr {
        cond: NodeId,
        then: NodeId,
        otherwise: NodeId,
    },
    MemberExpr {
        lhs: NodeId,
        kind: &'a [u8],
        rhs: NodeId,
    },
    SubobjectExpr {
        ty: NodeId,
        sub: NodeId,
        offset: &'a [u8],
        selectors: List,
        one_past_end: bool,
    },
    EnclosingExpr {
        prefix: &'a [u8],
        infix: NodeId,
    },
    CastExpr {
        kind: &'a [u8],
        to: NodeId,
        from: NodeId,
    },
    SizeofParamPackExpr(NodeId),
    CallExpr {
        callee: NodeId,
        args: List,
        paren: bool,
    },
    NewExpr {
        exprs: List,
        ty: NodeId,
        inits: List,
        global: bool,
        array: bool,
    },
    DeleteExpr {
        op: NodeId,
        global: bool,
        array: bool,
    },
    PrefixExpr {
        prefix: &'a [u8],
        child: NodeId,
    },
    FunctionParam(&'a [u8]),
    ConversionExpr {
        ty: NodeId,
        exprs: List,
    },
    PointerToMemberConversionExpr {
        ty: NodeId,
        sub: NodeId,
    },
    InitListExpr {
        ty: Option<NodeId>,
        inits: List,
    },
    FoldExpr {
        left: bool,
        op: &'a [u8],
        pack: NodeId,
        init: Option<NodeId>,
    },
    ThrowExpr(NodeId),
    BoolExpr(bool),
    StringLiteral(NodeId),
    LambdaExpr(NodeId),
    EnumLiteral {
        ty: NodeId,
        integer: &'a [u8],
    },
    IntegerLiteral {
        ty: &'a [u8],
        value: &'a [u8],
    },
    FloatLiteral {
        kind: FloatKind,
        contents: &'a [u8],
    },
    BracedExpr {
        elem: NodeId,
        init: NodeId,
        array: bool,
    },
    BracedRangeExpr {
        first: NodeId,
        last: NodeId,
        init: NodeId,
    },
    RequiresExpr {
        params: List,
        requirements: List,
    },
    ExprRequirement {
        expr: NodeId,
        noexcept: bool,
        constraint: Option<NodeId>,
    },
    TypeRequirement(NodeId),
    NestedRequirement(NodeId),
}

/// What printing needs to know of a node without looking inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    pub prec: Prec,
    pub rhs: Cache,
    pub array: Cache,
    pub function: Cache,
}

/// A parsed name.
#[derive(Clone, Debug, Default)]
pub struct Ast<'a> {
    pub nodes: Vec<Node<'a>>,
    pub meta: Vec<Meta>,
    pub lists: Vec<NodeId>,
    /// The targets of forward template references, by slot.
    pub forward: Vec<Option<NodeId>>,
    pub root: Option<NodeId>,
}

impl<'a> Ast<'a> {
    pub fn node(&self, id: NodeId) -> &Node<'a> {
        &self.nodes[id as usize]
    }

    pub fn list(&self, l: List) -> &[NodeId] {
        &self.lists[l.start as usize..(l.start + l.len) as usize]
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.meta.clear();
        self.lists.clear();
        self.forward.clear();
        self.root = None;
    }

    /// The node's unqualified name, as constructor and destructor names
    /// spell their class (`getBaseName`).
    pub fn base_name(&self, id: NodeId) -> &'a [u8] {
        match *self.node(id) {
            Node::NameType(n) => n,
            Node::AbiTagAttr { base, .. } => self.base_name(base),
            Node::NestedName { name, .. }
            | Node::MemberLikeFriendName { name, .. }
            | Node::ModuleEntity { name, .. }
            | Node::QualifiedName { name, .. }
            | Node::NameWithTemplateArgs { name, .. } => self.base_name(name),
            Node::GlobalQualifiedName(child) => self.base_name(child),
            Node::ExpandedSpecialSubstitution(k) => match k {
                SpecialSub::Allocator => b"allocator",
                SpecialSub::BasicString | SpecialSub::String => b"basic_string",
                SpecialSub::Istream => b"basic_istream",
                SpecialSub::Ostream => b"basic_ostream",
                SpecialSub::Iostream => b"basic_iostream",
            },
            Node::SpecialSubstitution(k) => match k {
                SpecialSub::Allocator => b"allocator",
                SpecialSub::BasicString => b"basic_string",
                SpecialSub::String => b"string",
                SpecialSub::Istream => b"istream",
                SpecialSub::Ostream => b"ostream",
                SpecialSub::Iostream => b"iostream",
            },
            _ => b"",
        }
    }
}

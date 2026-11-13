// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Follows the LLVM Project's demangler (see LICENSE-LLVM at the crate root).

//! The parser: the Itanium C++ ABI's mangling grammar, with the GNU, Clang,
//! and Apple extensions LLVM's demangler accepts, producing an [`Ast`].
//!
//! The structure follows LLVM's `ItaniumDemangle.h` (Apache-2.0 WITH
//! LLVM-exception), production for production, so that names parse — and
//! fail to parse — as they do there. Unlike it, node counts are bounded,
//! and so is the thread's stack: see [`Parser::drive`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::{self, ManuallyDrop};

use super::ast::*;

/// Nesting deeper than this fails the parse.
const MAX_DEPTH: u32 = 256;
/// How many levels of nesting the parser recurses through on the thread's
/// stack (a constant bound on what that takes; real names rarely nest past
/// 20). Deeper levels: see [`Parser::drive`].
pub const NATIVE_DEPTH: u32 = if cfg!(debug_assertions) { 24 } else { 128 };
/// The most work (state copied, input rescanned) parsing a name nested
/// past [`NATIVE_DEPTH`] may take, beyond the parse itself: this much per
/// byte of the name (and a little more), which keeps parsing linear in the
/// name's length.
const DEEP_WORK_PER_BYTE: usize = 64;
/// More nodes than this fails the parse.
const MAX_NODES: usize = 1 << 20;
/// Longer names than this are not parsed (which keeps every count and
/// index well within a `u32`).
const MAX_INPUT: usize = 1 << 24;

/// What a template parameter scope refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tp {
    /// The outermost template arguments.
    Outer,
    /// A lambda's or template template parameter's own parameters.
    Scoped(usize),
    /// A generic lambda's parameters, with no explicit list.
    Null,
}

/// What [`Parser::parse_name`] learns of a name that heads an encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NameState {
    ctor_dtor_conversion: bool,
    ends_with_template_args: bool,
    cv: u8,
    ref_qual: RefQual,
    forward_refs_begin: usize,
    explicit_object_param: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpKind {
    Prefix,
    Postfix,
    Binary,
    Array,
    Member,
    New,
    Del,
    Call,
    CCast,
    Conditional,
    NameOnly,
    NamedCast,
    OfIdOp,
}

struct Op {
    enc: &'static [u8; 2],
    kind: OpKind,
    flag: bool,
    prec: Prec,
    name: &'static [u8],
}

impl Op {
    /// The operator as an expression spells it (`+`, `sizeof `).
    fn symbol(&self) -> &'static [u8] {
        if matches!(self.kind, OpKind::NamedCast | OpKind::OfIdOp) {
            return self.name;
        }
        let s = &self.name[b"operator".len()..];
        s.strip_prefix(b" ").unwrap_or(s)
    }
}

macro_rules! ops {
    ($($enc:literal $kind:ident $flag:literal $prec:ident $name:literal;)*) => {
        &[$(Op { enc: $enc, kind: OpKind::$kind, flag: $flag, prec: Prec::$prec, name: $name }),*]
    };
}

/// Operator encodings, ordered by encoding.
static OPS: &[Op] = ops! {
    b"aN" Binary false Assign b"operator&=";
    b"aS" Binary false Assign b"operator=";
    b"aa" Binary false AndIf b"operator&&";
    b"ad" Prefix false Unary b"operator&";
    b"an" Binary false And b"operator&";
    b"at" OfIdOp true Unary b"alignof ";
    b"aw" NameOnly false Primary b"operator co_await";
    b"az" OfIdOp false Unary b"alignof ";
    b"cc" NamedCast false Postfix b"const_cast";
    b"cl" Call false Postfix b"operator()";
    b"cm" Binary false Comma b"operator,";
    b"co" Prefix false Unary b"operator~";
    b"cp" Call true Postfix b"operator()";
    b"cv" CCast false Cast b"operator";
    b"dV" Binary false Assign b"operator/=";
    b"da" Del true Unary b"operator delete[]";
    b"dc" NamedCast false Postfix b"dynamic_cast";
    b"de" Prefix false Unary b"operator*";
    b"dl" Del false Unary b"operator delete";
    b"ds" Member false PtrMem b"operator.*";
    b"dt" Member false Postfix b"operator.";
    b"dv" Binary false Assign b"operator/";
    b"eO" Binary false Assign b"operator^=";
    b"eo" Binary false Xor b"operator^";
    b"eq" Binary false Equality b"operator==";
    b"ge" Binary false Relational b"operator>=";
    b"gt" Binary false Relational b"operator>";
    b"ix" Array false Postfix b"operator[]";
    b"lS" Binary false Assign b"operator<<=";
    b"le" Binary false Relational b"operator<=";
    b"ls" Binary false Shift b"operator<<";
    b"lt" Binary false Relational b"operator<";
    b"mI" Binary false Assign b"operator-=";
    b"mL" Binary false Assign b"operator*=";
    b"mi" Binary false Additive b"operator-";
    b"ml" Binary false Multiplicative b"operator*";
    b"mm" Postfix false Postfix b"operator--";
    b"na" New true Unary b"operator new[]";
    b"ne" Binary false Equality b"operator!=";
    b"ng" Prefix false Unary b"operator-";
    b"nt" Prefix false Unary b"operator!";
    b"nw" New false Unary b"operator new";
    b"oR" Binary false Assign b"operator|=";
    b"oo" Binary false OrIf b"operator||";
    b"or" Binary false Ior b"operator|";
    b"pL" Binary false Assign b"operator+=";
    b"pl" Binary false Additive b"operator+";
    b"pm" Member true PtrMem b"operator->*";
    b"pp" Postfix false Postfix b"operator++";
    b"ps" Prefix false Unary b"operator+";
    b"pt" Member true Postfix b"operator->";
    b"qu" Conditional false Conditional b"operator?";
    b"rM" Binary false Assign b"operator%=";
    b"rS" Binary false Assign b"operator>>=";
    b"rc" NamedCast false Postfix b"reinterpret_cast";
    b"rm" Binary false Multiplicative b"operator%";
    b"rs" Binary false Shift b"operator>>";
    b"sc" NamedCast false Postfix b"static_cast";
    b"ss" Binary false Spaceship b"operator<=>";
    b"st" OfIdOp true Unary b"sizeof ";
    b"sz" OfIdOp false Unary b"sizeof ";
    b"te" OfIdOp false Postfix b"typeid ";
    b"ti" OfIdOp true Postfix b"typeid ";
};

/// A production called one level deeper (see [`Parser::deeper`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Goal {
    /// The whole name.
    Whole,
    Name,
    QualifiedType,
    Type,
    BracedExpr,
    Expr,
    Encoding(bool),
    TemplateParamDecl(Option<usize>),
    TemplateArg,
}

/// Everything parsing depends on and changes, but the tree's contents: the
/// parser at a call into a production, or at its return.
#[derive(Clone, Debug, Default)]
struct State {
    pos: usize,
    end: usize,
    /// The tree's lengths.
    nodes: usize,
    lists: usize,
    forward: usize,
    names: Vec<NodeId>,
    subs: Vec<NodeId>,
    outer: Vec<NodeId>,
    scoped: Vec<Vec<NodeId>>,
    tparams: Vec<Tp>,
    forward_refs: Vec<(u32, u32)>,
    try_template_args: bool,
    permit_forward: bool,
    incomplete_tracking: bool,
    lambda_level: usize,
    synthetic: [u32; 3],
    /// The call's name state (`parse_name`'s), going in or coming out.
    name_state: Option<NameState>,
}

impl State {
    /// What copying it costs.
    fn weight(&self) -> usize {
        1 + self.names.len()
            + self.subs.len()
            + self.outer.len()
            + self.scoped.iter().map(Vec::len).sum::<usize>()
            + self.tparams.len()
            + self.forward_refs.len()
    }
}

/// A vector's change across a call: cut back to `keep` entries, then
/// `tail` added.
#[derive(Debug, Default)]
struct Change<T> {
    keep: usize,
    tail: Vec<T>,
}

impl<T: Copy + PartialEq> Change<T> {
    fn of(before: &[T], after: &[T]) -> Self {
        let keep = before.iter().zip(after).take_while(|(a, b)| a == b).count();
        Self {
            keep,
            tail: after[keep..].to_vec(),
        }
    }

    fn apply(&self, v: &mut Vec<T>) {
        v.truncate(self.keep);
        v.extend_from_slice(&self.tail);
    }
}

/// The parser after a call, as changed from before it (what replaying the
/// call takes is what the call changed, not the whole state).
struct Exit {
    pos: usize,
    end: usize,
    nodes: usize,
    names: Change<NodeId>,
    subs: Change<NodeId>,
    outer: Change<NodeId>,
    scoped: Vec<Vec<NodeId>>,
    tparams: Change<Tp>,
    forward_refs: Change<(u32, u32)>,
    try_template_args: bool,
    permit_forward: bool,
    incomplete_tracking: bool,
    lambda_level: usize,
    synthetic: [u32; 3],
    name_state: Option<NameState>,
}

impl Exit {
    fn weight(&self) -> usize {
        1 + self.names.tail.len()
            + self.subs.tail.len()
            + self.outer.tail.len()
            + self.scoped.iter().map(Vec::len).sum::<usize>()
            + self.tparams.tail.len()
            + self.forward_refs.tail.len()
    }
}

/// A production called past a run's levels, for [`Parser::drive`] to run.
struct Call {
    goal: Goal,
    entry: State,
    /// The depth it is called from.
    base: u32,
}

/// A call [`Parser::drive`] has run: what it returned, the parser after
/// it, and the part of the tree it built.
struct Done<'a> {
    goal: Goal,
    result: Option<NodeId>,
    exit: Exit,
    nodes: Vec<Node<'a>>,
    meta: Vec<Meta>,
    lists: Vec<NodeId>,
    forward: Vec<Option<NodeId>>,
}

impl Done<'_> {
    fn weight(&self) -> usize {
        self.exit.weight() + self.nodes.len() + self.lists.len() + self.forward.len()
    }
}

/// A call [`Parser::drive`] is running, with the results of the calls
/// past its levels it has made so far.
struct Task<'a> {
    goal: Goal,
    entry: State,
    base: u32,
    depth: u32,
    done: Vec<Done<'a>>,
}

/// The parser's state while [`Parser::drive`] parses a deep name.
#[derive(Default)]
struct Deep<'a> {
    /// The depth of this run's level 0.
    base: u32,
    /// The results of this run's calls past its levels, in call order, and
    /// how many it has made.
    done: Vec<Done<'a>>,
    done_at: usize,
    /// A call past this run's levels with no result yet: the run is
    /// unwinding.
    pending: Option<Call>,
    /// Work so far (see [`DEEP_WORK_PER_BYTE`]).
    spent: usize,
}

pub struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    end: usize,
    pub ast: Ast<'a>,
    names: Vec<NodeId>,
    subs: Vec<NodeId>,
    outer: Vec<NodeId>,
    scoped: Vec<Vec<NodeId>>,
    tparams: Vec<Tp>,
    /// Unresolved forward references: (slot, template parameter index).
    forward_refs: Vec<(u32, u32)>,
    try_template_args: bool,
    permit_forward: bool,
    incomplete_tracking: bool,
    lambda_level: usize,
    synthetic: [u32; 3],
    /// Levels of nesting of this run (on the thread's stack).
    depth: u32,
    /// How many there may be before a call goes to [`Parser::boundary`]:
    /// `native_depth`, fewer near [`MAX_DEPTH`], or 0 once a run is
    /// unwinding.
    limit: u32,
    /// [`NATIVE_DEPTH`], or fewer for testing.
    native_depth: u32,
    /// Only while parsing a deep name, which takes it back before
    /// returning. (Not dropped with the parser: a field to drop makes
    /// every parse measurably slower.)
    deep: ManuallyDrop<Option<Box<Deep<'a>>>>,
}

/// Scratch buffers kept between parses, so that parsing a name allocates
/// nothing once they have grown.
#[derive(Default)]
pub struct Buffers {
    node_capacity: usize,
    meta: Vec<Meta>,
    lists: Vec<NodeId>,
    forward: Vec<Option<NodeId>>,
    names: Vec<NodeId>,
    subs: Vec<NodeId>,
    outer: Vec<NodeId>,
    tparams: Vec<Tp>,
    forward_refs: Vec<(u32, u32)>,
}

fn cleared<T>(mut v: Vec<T>) -> Vec<T> {
    v.clear();
    v
}

impl<'a> Parser<'a> {
    pub fn new(s: &'a [u8], buffers: Buffers) -> Self {
        Self {
            s,
            pos: 0,
            end: s.len(),
            ast: Ast {
                nodes: Vec::with_capacity(buffers.node_capacity),
                meta: cleared(buffers.meta),
                lists: cleared(buffers.lists),
                forward: cleared(buffers.forward),
                root: None,
            },
            names: cleared(buffers.names),
            subs: cleared(buffers.subs),
            outer: cleared(buffers.outer),
            scoped: Vec::new(),
            tparams: cleared(buffers.tparams),
            forward_refs: cleared(buffers.forward_refs),
            try_template_args: true,
            permit_forward: false,
            incomplete_tracking: false,
            lambda_level: usize::MAX,
            synthetic: [0; 3],
            depth: 0,
            limit: NATIVE_DEPTH,
            native_depth: NATIVE_DEPTH,
            deep: ManuallyDrop::new(None),
        }
    }

    /// Recurses at most `n` (at least 1) levels on the thread's stack, for
    /// testing.
    pub fn set_native_depth(&mut self, n: u32) {
        self.native_depth = n.clamp(1, MAX_DEPTH);
        self.limit = self.native_depth;
    }

    /// The scratch buffers of a finished tree, for the next parse.
    pub fn buffers_of(ast: Ast<'_>, rest: Buffers) -> Buffers {
        Buffers {
            node_capacity: ast.nodes.capacity(),
            meta: cleared(ast.meta),
            lists: cleared(ast.lists),
            forward: cleared(ast.forward),
            ..rest
        }
    }

    /// Splits off the tree, returning the other buffers.
    pub fn finish(self) -> (Ast<'a>, Buffers) {
        let rest = Buffers {
            node_capacity: 0,
            meta: Vec::new(),
            lists: Vec::new(),
            forward: Vec::new(),
            names: cleared(self.names),
            subs: cleared(self.subs),
            outer: cleared(self.outer),
            tparams: cleared(self.tparams),
            forward_refs: cleared(self.forward_refs),
        };
        (self.ast, rest)
    }
    // -- Input --

    fn look(&self, ahead: usize) -> u8 {
        let i = self.pos + ahead;
        if i < self.end { self.s[i] } else { 0 }
    }

    fn num_left(&self) -> usize {
        self.end - self.pos
    }

    fn consume_if(&mut self, s: &[u8]) -> bool {
        if self.s[self.pos..self.end].starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    fn consume_char(&mut self, c: u8) -> bool {
        if self.pos < self.end && self.s[self.pos] == c {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume(&mut self) -> u8 {
        if self.pos < self.end {
            self.pos += 1;
            self.s[self.pos - 1]
        } else {
            0
        }
    }

    // -- Tree building --

    fn make(&mut self, node: Node<'a>) -> Option<NodeId> {
        self.make_prec(node, Prec::Primary)
    }

    fn make_prec(&mut self, node: Node<'a>, prec: Prec) -> Option<NodeId> {
        if self.ast.nodes.len() >= MAX_NODES {
            return None;
        }
        let meta = self.meta_of(&node, prec);
        let id = NodeId::try_from(self.ast.nodes.len()).ok()?;
        self.ast.nodes.push(node);
        self.ast.meta.push(meta);
        Some(id)
    }

    fn meta_of(&self, node: &Node<'a>, prec: Prec) -> Meta {
        let m = |id: NodeId| self.ast.meta[id as usize];
        let no = Meta {
            prec,
            rhs: Cache::No,
            array: Cache::No,
            function: Cache::No,
        };
        match *node {
            Node::QualType { child: c, .. } | Node::AbiTagAttr { base: c, .. } => {
                Meta { prec, ..m(c) }
            }
            Node::PointerType(p)
            | Node::ReferenceType { pointee: p, .. }
            | Node::PointerToMemberType { member: p, .. } => Meta {
                rhs: m(p).rhs,
                ..no
            },
            Node::ArrayType { .. } => Meta {
                rhs: Cache::Yes,
                array: Cache::Yes,
                ..no
            },
            Node::FunctionType { .. } | Node::FunctionEncoding { .. } => Meta {
                rhs: Cache::Yes,
                function: Cache::Yes,
                ..no
            },
            Node::TypeTemplateParamDecl(_)
            | Node::ConstrainedTypeTemplateParamDecl { .. }
            | Node::NonTypeTemplateParamDecl { .. }
            | Node::TemplateTemplateParamDecl { .. }
            | Node::TemplateParamPackDecl(_) => Meta {
                rhs: Cache::Yes,
                ..no
            },
            Node::ParameterPack(l) => {
                let all_no = |f: fn(&Meta) -> Cache| {
                    if self.ast.list(l).iter().all(|&e| f(&m(e)) == Cache::No) {
                        Cache::No
                    } else {
                        Cache::Unknown
                    }
                };
                Meta {
                    prec,
                    rhs: all_no(|m| m.rhs),
                    array: all_no(|m| m.array),
                    function: all_no(|m| m.function),
                }
            }
            Node::ForwardTemplateReference { .. } => Meta {
                prec,
                rhs: Cache::Unknown,
                array: Cache::Unknown,
                function: Cache::Unknown,
            },
            _ => no,
        }
    }

    fn name(&mut self, s: &'a [u8]) -> Option<NodeId> {
        self.make(Node::NameType(s))
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "lists are bounded by MAX_INPUT"
    )]
    fn pop_trailing(&mut self, from: usize) -> List {
        let start = self.ast.lists.len() as u32;
        self.ast.lists.extend_from_slice(&self.names[from..]);
        self.names.truncate(from);
        List {
            start,
            len: self.ast.lists.len() as u32 - start,
        }
    }

    fn kind(&self, id: NodeId) -> &Node<'a> {
        self.ast.node(id)
    }

    /// Calls `f` (which parses `goal`) one level deeper: on the thread's
    /// stack for the first [`NATIVE_DEPTH`] levels; past that, see
    /// [`Parser::boundary`].
    fn deeper(
        &mut self,
        goal: Goal,
        state: Option<&mut NameState>,
        f: impl FnOnce(&mut Self, Option<&mut NameState>) -> Option<NodeId>,
    ) -> Option<NodeId> {
        if self.depth >= self.limit {
            return self.boundary(goal, state);
        }
        self.depth += 1;
        let r = f(self, state);
        self.depth -= 1;
        r
    }

    /// `goal`, for [`Parser::drive`] (as [`Parser::deeper`] calls it).
    fn call(&mut self, goal: Goal, state: Option<&mut NameState>) -> Option<NodeId> {
        match goal {
            Goal::Whole => self.parse_whole(),
            Goal::Name => self.parse_name_inner(state),
            Goal::QualifiedType => self.parse_qualified_type_inner(),
            Goal::Type => self.parse_type_inner(),
            Goal::BracedExpr => self.parse_braced_expr_inner(),
            Goal::Expr => self.parse_expr_inner(),
            Goal::Encoding(params) => {
                self.with_saved_template_params(|p| p.parse_encoding_inner(params))
            }
            Goal::TemplateParamDecl(list) => self.parse_template_param_decl_inner(list),
            Goal::TemplateArg => self.parse_template_arg_inner(),
        }
    }

    /// A call past this run's levels: failing past [`MAX_DEPTH`]; the
    /// result [`Parser::drive`] has for it, if it has run it; else the
    /// call is left for it to run, and this run unwinds (every call
    /// failing from here on).
    #[cold]
    #[inline(never)]
    fn boundary(&mut self, goal: Goal, state: Option<&mut NameState>) -> Option<NodeId> {
        let depth = self.depth;
        let deep = match self.deep.as_deref_mut() {
            Some(deep) if deep.pending.is_some() || deep.base + depth >= MAX_DEPTH => {
                return None;
            }
            Some(deep) => deep,
            None if depth >= MAX_DEPTH => return None,
            None => {
                let deep = Box::default();
                self.deep = ManuallyDrop::new(Some(deep));
                self.deep.as_deref_mut()?
            }
        };
        if deep.done_at < deep.done.len() {
            let done = mem::take(&mut deep.done);
            let i = deep.done_at;
            deep.done_at += 1;
            let d = &done[i];
            deep.spent += d.weight();
            debug_assert_eq!(d.goal, goal);
            debug_assert_eq!(self.ast.nodes.len() + d.nodes.len(), d.exit.nodes);
            self.ast.nodes.extend_from_slice(&d.nodes);
            self.ast.meta.extend_from_slice(&d.meta);
            self.ast.lists.extend_from_slice(&d.lists);
            self.ast.forward.extend_from_slice(&d.forward);
            let e = &d.exit;
            self.pos = e.pos;
            self.end = e.end;
            e.names.apply(&mut self.names);
            e.subs.apply(&mut self.subs);
            e.outer.apply(&mut self.outer);
            self.scoped.clone_from(&e.scoped);
            e.tparams.apply(&mut self.tparams);
            e.forward_refs.apply(&mut self.forward_refs);
            self.try_template_args = e.try_template_args;
            self.permit_forward = e.permit_forward;
            self.incomplete_tracking = e.incomplete_tracking;
            self.lambda_level = e.lambda_level;
            self.synthetic = e.synthetic;
            if let (Some(st), Some(out)) = (state, d.exit.name_state) {
                *st = out;
            }
            let r = d.result;
            if let Some(deep) = self.deep.as_deref_mut() {
                deep.done = done;
            }
            return r;
        }
        let base = deep.base + depth;
        let entry = self.snapshot(state.map(|s| *s));
        if let Some(deep) = self.deep.as_deref_mut() {
            deep.pending = Some(Call { goal, entry, base });
        }
        self.limit = 0;
        None
    }

    fn snapshot(&self, name_state: Option<NameState>) -> State {
        State {
            pos: self.pos,
            end: self.end,
            nodes: self.ast.nodes.len(),
            lists: self.ast.lists.len(),
            forward: self.ast.forward.len(),
            names: self.names.clone(),
            subs: self.subs.clone(),
            outer: self.outer.clone(),
            scoped: self.scoped.clone(),
            tparams: self.tparams.clone(),
            forward_refs: self.forward_refs.clone(),
            try_template_args: self.try_template_args,
            permit_forward: self.permit_forward,
            incomplete_tracking: self.incomplete_tracking,
            lambda_level: self.lambda_level,
            synthetic: self.synthetic,
            name_state,
        }
    }

    /// Back to `st`, the tree cut back to its lengths.
    fn restore(&mut self, st: &State) {
        self.pos = st.pos;
        self.end = st.end;
        self.ast.nodes.truncate(st.nodes);
        self.ast.meta.truncate(st.nodes);
        self.ast.lists.truncate(st.lists);
        self.ast.forward.truncate(st.forward);
        self.names.clone_from(&st.names);
        self.subs.clone_from(&st.subs);
        self.outer.clone_from(&st.outer);
        self.scoped.clone_from(&st.scoped);
        self.tparams.clone_from(&st.tparams);
        self.forward_refs.clone_from(&st.forward_refs);
        self.try_template_args = st.try_template_args;
        self.permit_forward = st.permit_forward;
        self.incomplete_tracking = st.incomplete_tracking;
        self.lambda_level = st.lambda_level;
        self.synthetic = st.synthetic;
    }

    /// Parses a name nested past [`NATIVE_DEPTH`], once a run has left a
    /// call for it ([`Parser::boundary`]). The thread's stack holds at
    /// most `NATIVE_DEPTH` levels at a time: a call that would go deeper
    /// is instead run here, by itself, from the parser as it was at the
    /// call, and the run that made it is run again from its start. The
    /// parse is deterministic, so that run makes the same calls in the
    /// same order, with the same tree so far; each time it reaches a call
    /// run here, it takes that call's result (and the parser after it, and
    /// the tree it built) and goes on, until it reaches a call not yet run
    /// (which runs next) or its end. The tree built is the one parsing on
    /// the thread's stack alone would build.
    ///
    /// A run is run again once per call it makes past its levels (twice,
    /// on a name that is deep but not wide), so the work is bounded
    /// ([`DEEP_WORK_PER_BYTE`]): a name built to make it large fails.
    #[cold]
    #[inline(never)]
    fn drive(&mut self) -> Option<NodeId> {
        let mut tasks: Vec<Task<'a>> = Vec::new();
        tasks.push(Task {
            goal: Goal::Whole,
            entry: State {
                end: self.s.len(),
                try_template_args: true,
                lambda_level: usize::MAX,
                ..State::default()
            },
            base: 0,
            depth: 0,
            done: Vec::new(),
        });
        let mut result = None;
        let mut name_state = None;
        loop {
            let deep = self.deep.as_deref_mut()?;
            if let Some(call) = deep.pending.take() {
                let top = tasks.last_mut()?;
                top.done = mem::take(&mut deep.done);
                deep.spent += call.entry.weight();
                tasks.push(Task {
                    goal: call.goal,
                    entry: call.entry,
                    base: call.base,
                    depth: 1,
                    done: Vec::new(),
                });
            } else {
                let task = tasks.pop()?;
                if tasks.is_empty() {
                    return result;
                }
                let e = &task.entry;
                let d = Done {
                    goal: task.goal,
                    result,
                    nodes: self.ast.nodes[e.nodes..].to_vec(),
                    meta: self.ast.meta[e.nodes..].to_vec(),
                    lists: self.ast.lists[e.lists..].to_vec(),
                    forward: self.ast.forward[e.forward..].to_vec(),
                    exit: Exit {
                        pos: self.pos,
                        end: self.end,
                        nodes: self.ast.nodes.len(),
                        names: Change::of(&e.names, &self.names),
                        subs: Change::of(&e.subs, &self.subs),
                        outer: Change::of(&e.outer, &self.outer),
                        scoped: self.scoped.clone(),
                        tparams: Change::of(&e.tparams, &self.tparams),
                        forward_refs: Change::of(&e.forward_refs, &self.forward_refs),
                        try_template_args: self.try_template_args,
                        permit_forward: self.permit_forward,
                        incomplete_tracking: self.incomplete_tracking,
                        lambda_level: self.lambda_level,
                        synthetic: self.synthetic,
                        name_state,
                    },
                };
                let deep = self.deep.as_deref_mut()?;
                deep.spent += d.weight();
                tasks.last_mut()?.done.push(d);
            }
            let top = tasks.last_mut()?;
            self.restore(&top.entry);
            let deep = self.deep.as_deref_mut()?;
            deep.spent += top.entry.weight();
            if deep.spent > self.s.len() * DEEP_WORK_PER_BYTE + (1 << 16) {
                return None;
            }
            deep.base = top.base;
            deep.done = mem::take(&mut top.done);
            deep.done_at = 0;
            self.depth = top.depth;
            self.limit = self.native_depth.min(MAX_DEPTH - top.base);
            name_state = top.entry.name_state;
            let goal = top.goal;
            result = self.call(goal, name_state.as_mut());
            // The run's work: the input it read, the nodes it built.
            let e = &tasks.last()?.entry;
            let work =
                self.pos.saturating_sub(e.pos) + self.ast.nodes.len().saturating_sub(e.nodes);
            self.deep.as_deref_mut()?.spent += work;
        }
    }

    /// `SaveTemplateParams`: `f` sees no enclosing template parameters.
    fn with_saved_template_params<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let tparams = mem::take(&mut self.tparams);
        let outer = mem::take(&mut self.outer);
        let r = f(self);
        self.tparams = tparams;
        self.outer = outer;
        r
    }

    /// `ScopedTemplateParamList`: `f` gets a fresh parameter list (by its
    /// index in `scoped`), pushed as the innermost scope.
    fn with_scoped_list<T>(&mut self, f: impl FnOnce(&mut Self, usize) -> T) -> T {
        let old = self.tparams.len();
        let idx = self.scoped.len();
        self.scoped.push(Vec::new());
        self.tparams.push(Tp::Scoped(idx));
        let r = f(self, idx);
        self.tparams.truncate(old);
        self.scoped.truncate(idx);
        r
    }

    fn tparam_list(&self, tp: Tp) -> Option<&[NodeId]> {
        match tp {
            Tp::Outer => Some(&self.outer),
            Tp::Scoped(i) => self.scoped.get(i).map(Vec::as_slice),
            Tp::Null => None,
        }
    }

    // -- Entry point --

    /// `<mangled-name>`, the whole input.
    pub fn parse(&mut self) -> Option<NodeId> {
        if self.s.len() > MAX_INPUT {
            return None;
        }
        let r = self.parse_whole();
        if self.deep.is_none() {
            return r;
        }
        let r = self.drive();
        // (Dropped here, not with the parser.)
        *self.deep = None;
        r
    }

    fn parse_whole(&mut self) -> Option<NodeId> {
        let alloc_token = self.consume_if(b"__alloc_token_");
        if alloc_token {
            let saved = self.pos;
            if self.parse_number(false).is_empty() || !self.consume_char(b'_') {
                self.pos = saved;
            }
        }
        if self.consume_if(b"_Z") || self.consume_if(b"__Z") {
            let mut enc = self.parse_encoding(true)?;
            if self.look(0) == b'.' {
                let suffix = &self.s[self.pos..self.end];
                enc = self.make(Node::DotSuffix {
                    prefix: enc,
                    suffix,
                })?;
                self.pos = self.end;
            }
            if alloc_token {
                enc = self.make(Node::DotSuffix {
                    prefix: enc,
                    suffix: b".alloc_token",
                })?;
            }
            if self.num_left() != 0 {
                return None;
            }
            return Some(enc);
        }
        if self.consume_if(b"___Z") || self.consume_if(b"____Z") {
            let enc = self.parse_encoding(true)?;
            if !self.consume_if(b"_block_invoke") {
                return None;
            }
            let require_number = self.consume_char(b'_');
            if self.parse_number(false).is_empty() && require_number {
                return None;
            }
            if self.look(0) == b'.' {
                self.pos = self.end;
            }
            if self.num_left() != 0 {
                return None;
            }
            return self.make(Node::SpecialName {
                special: b"invocation function for block in ",
                child: enc,
            });
        }
        let ty = self.parse_type()?;
        if self.num_left() != 0 {
            return None;
        }
        Some(ty)
    }

    // -- Names --

    fn parse_name(&mut self, state: Option<&mut NameState>) -> Option<NodeId> {
        self.deeper(Goal::Name, state, Parser::parse_name_inner)
    }

    fn parse_name_inner(&mut self, mut state: Option<&mut NameState>) -> Option<NodeId> {
        if self.look(0) == b'N' {
            return self.parse_nested_name(state);
        }
        if self.look(0) == b'Z' {
            return self.parse_local_name(state);
        }
        let mut is_subst = false;
        let mut result = self.parse_unscoped_name(state.as_deref_mut(), Some(&mut is_subst))?;
        if self.look(0) == b'I' {
            if !is_subst {
                self.subs.push(result);
            }
            let args = self.parse_template_args(state.is_some())?;
            if let Some(st) = state {
                st.ends_with_template_args = true;
            }
            result = self.make(Node::NameWithTemplateArgs { name: result, args })?;
        } else if is_subst {
            return None;
        }
        Some(result)
    }

    fn parse_local_name(&mut self, state: Option<&mut NameState>) -> Option<NodeId> {
        if !self.consume_char(b'Z') {
            return None;
        }
        let encoding = self.parse_encoding(true)?;
        if !self.consume_char(b'E') {
            return None;
        }
        if self.consume_char(b's') {
            self.pos = parse_discriminator(self.s, self.pos, self.end);
            let entity = self.name(b"string literal")?;
            return self.make(Node::LocalName { encoding, entity });
        }
        self.with_saved_template_params(|p| {
            if p.consume_char(b'd') {
                p.parse_number(true);
                if !p.consume_char(b'_') {
                    return None;
                }
                let entity = p.parse_name(state)?;
                return p.make(Node::LocalName { encoding, entity });
            }
            let entity = p.parse_name(state)?;
            p.pos = parse_discriminator(p.s, p.pos, p.end);
            p.make(Node::LocalName { encoding, entity })
        })
    }

    fn parse_unscoped_name(
        &mut self,
        state: Option<&mut NameState>,
        is_subst: Option<&mut bool>,
    ) -> Option<NodeId> {
        let mut std = None;
        if self.consume_if(b"St") {
            std = Some(self.name(b"std")?);
        }
        let mut res = None;
        let mut module = None;
        if self.look(0) == b'S' {
            let s = self.parse_substitution()?;
            if matches!(self.kind(s), Node::ModuleName { .. }) {
                module = Some(s);
            } else if let (Some(flag), None) = (is_subst, std) {
                res = Some(s);
                *flag = true;
            } else {
                return None;
            }
        }
        if res.is_none() || std.is_some() {
            res = Some(self.parse_unqualified_name(state, std, module)?);
        }
        res
    }

    fn parse_unqualified_name(
        &mut self,
        mut state: Option<&mut NameState>,
        scope: Option<NodeId>,
        mut module: Option<NodeId>,
    ) -> Option<NodeId> {
        if !self.parse_module_name_opt(&mut module) {
            return None;
        }
        let member_like_friend = scope.is_some() && self.consume_char(b'F');
        self.consume_char(b'L');
        let c = self.look(0);
        let mut result = if c.is_ascii_digit() && c != b'0' {
            self.parse_source_name()?
        } else if c == b'U' {
            self.parse_unnamed_type_name(state.is_some())?
        } else if self.consume_if(b"DC") {
            let begin = self.names.len();
            loop {
                let b = self.parse_source_name()?;
                self.names.push(b);
                if self.consume_char(b'E') {
                    break;
                }
            }
            let l = self.pop_trailing(begin);
            self.make(Node::StructuredBindingName(l))?
        } else if c == b'C' || c == b'D' {
            let (Some(sc), None) = (scope, module) else {
                return None;
            };
            let mut sc = sc;
            let r = self.parse_ctor_dtor_name(&mut sc, state.as_deref_mut())?;
            // The expanded special substitution becomes the scope.
            return self.finish_unqualified(r, Some(sc), None, member_like_friend);
        } else {
            self.parse_operator_name(state)?
        };
        if let Some(m) = module {
            result = self.make(Node::ModuleEntity {
                module: m,
                name: result,
            })?;
        }
        self.finish_unqualified(result, scope, None, member_like_friend)
    }

    fn finish_unqualified(
        &mut self,
        result: NodeId,
        scope: Option<NodeId>,
        module: Option<NodeId>,
        member_like_friend: bool,
    ) -> Option<NodeId> {
        let mut result = result;
        if let Some(m) = module {
            result = self.make(Node::ModuleEntity {
                module: m,
                name: result,
            })?;
        }
        result = self.parse_abi_tags(result)?;
        match scope {
            Some(qual) if member_like_friend => {
                self.make(Node::MemberLikeFriendName { qual, name: result })
            }
            Some(qual) => self.make(Node::NestedName { qual, name: result }),
            None => Some(result),
        }
    }

    /// Returns `false` on a malformed module name.
    fn parse_module_name_opt(&mut self, module: &mut Option<NodeId>) -> bool {
        while self.consume_char(b'W') {
            let partition = self.consume_char(b'P');
            let Some(name) = self.parse_source_name() else {
                return false;
            };
            let Some(m) = self.make(Node::ModuleName {
                parent: *module,
                name,
                partition,
            }) else {
                return false;
            };
            *module = Some(m);
            self.subs.push(m);
        }
        true
    }

    fn parse_unnamed_type_name(&mut self, has_state: bool) -> Option<NodeId> {
        if has_state {
            self.tparams.clear();
        }
        if self.consume_if(b"Ut") {
            let count = self.parse_number(false);
            if !self.consume_char(b'_') {
                return None;
            }
            return self.make(Node::UnnamedTypeName(count));
        }
        if self.consume_if(b"Ul") {
            let saved_level = self.lambda_level;
            self.lambda_level = self.tparams.len();
            let r = self.with_scoped_list(Parser::parse_lambda);
            self.lambda_level = saved_level;
            return r;
        }
        if self.consume_if(b"Ub") {
            self.parse_number(false);
            if !self.consume_char(b'_') {
                return None;
            }
            return self.name(b"'block-literal'");
        }
        None
    }

    fn parse_lambda(&mut self, list: usize) -> Option<NodeId> {
        let begin = self.names.len();
        while self.is_template_param_decl() {
            let t = self.parse_template_param_decl(Some(list))?;
            self.names.push(t);
        }
        let template_params = self.pop_trailing(begin);
        if template_params.is_empty() {
            self.tparams.pop();
        }
        let mut requires1 = None;
        if self.consume_char(b'Q') {
            requires1 = Some(self.parse_constraint_expr()?);
        }
        if !self.consume_char(b'v') {
            loop {
                let p = self.parse_type()?;
                self.names.push(p);
                if self.look(0) == b'E' || self.look(0) == b'Q' {
                    break;
                }
            }
        }
        let params = self.pop_trailing(begin);
        let mut requires2 = None;
        if self.consume_char(b'Q') {
            requires2 = Some(self.parse_constraint_expr()?);
        }
        if !self.consume_char(b'E') {
            return None;
        }
        let count = self.parse_number(false);
        if !self.consume_char(b'_') {
            return None;
        }
        self.make(Node::ClosureTypeName {
            template_params,
            requires1,
            params,
            requires2,
            count,
        })
    }

    fn parse_source_name(&mut self) -> Option<NodeId> {
        let len = self.parse_positive_integer()?;
        if self.num_left() < len || len == 0 {
            return None;
        }
        let name = &self.s[self.pos..self.pos + len];
        self.pos += len;
        if name.starts_with(b"_GLOBAL__N") {
            return self.name(b"(anonymous namespace)");
        }
        self.name(name)
    }

    fn parse_operator_encoding(&mut self) -> Option<&'static Op> {
        if self.num_left() < 2 {
            return None;
        }
        let key = [self.s[self.pos], self.s[self.pos + 1]];
        let i = OPS.binary_search_by(|o| o.enc.cmp(&key)).ok()?;
        self.pos += 2;
        Some(&OPS[i])
    }

    fn parse_operator_name(&mut self, state: Option<&mut NameState>) -> Option<NodeId> {
        let save = self.pos;
        if let Some(op) = self.parse_operator_encoding() {
            if op.kind == OpKind::CCast {
                let saved_try = mem::replace(&mut self.try_template_args, false);
                let saved_permit = self.permit_forward;
                self.permit_forward = self.permit_forward || state.is_some();
                let ty = self.parse_type();
                self.try_template_args = saved_try;
                self.permit_forward = saved_permit;
                let ty = ty?;
                if let Some(st) = state {
                    st.ctor_dtor_conversion = true;
                }
                return self.make(Node::ConversionOperatorType(ty));
            }
            if matches!(op.kind, OpKind::NamedCast | OpKind::OfIdOp) {
                return None;
            }
            if op.kind == OpKind::Member && !op.flag {
                return None;
            }
            return self.name(op.name);
        }
        self.pos = save;
        if self.consume_if(b"li") {
            let sn = self.parse_source_name()?;
            return self.make(Node::LiteralOperator(sn));
        }
        if self.consume_char(b'v') {
            if self.look(0).is_ascii_digit() {
                self.pos += 1;
                let sn = self.parse_source_name()?;
                return self.make(Node::ConversionOperatorType(sn));
            }
            return None;
        }
        None
    }

    fn parse_ctor_dtor_name(
        &mut self,
        so_far: &mut NodeId,
        mut state: Option<&mut NameState>,
    ) -> Option<NodeId> {
        if let Node::SpecialSubstitution(k) = *self.kind(*so_far) {
            *so_far = self.make(Node::ExpandedSpecialSubstitution(k))?;
        }
        if self.consume_char(b'C') {
            let inherited = self.consume_char(b'I');
            let c = self.look(0);
            if !(b'1'..=b'5').contains(&c) {
                return None;
            }
            self.pos += 1;
            if let Some(st) = state.as_deref_mut() {
                st.ctor_dtor_conversion = true;
            }
            if inherited {
                self.parse_name(state)?;
            }
            return self.make(Node::CtorDtorName {
                base: *so_far,
                dtor: false,
                variant: c - b'0',
            });
        }
        let c = self.look(1);
        if self.look(0) == b'D' && matches!(c, b'0' | b'1' | b'2' | b'4' | b'5') {
            self.pos += 2;
            if let Some(st) = state {
                st.ctor_dtor_conversion = true;
            }
            return self.make(Node::CtorDtorName {
                base: *so_far,
                dtor: true,
                variant: c - b'0',
            });
        }
        None
    }

    fn parse_nested_name(&mut self, mut state: Option<&mut NameState>) -> Option<NodeId> {
        if !self.consume_char(b'N') {
            return None;
        }
        if !self.consume_char(b'H') {
            let cv = self.parse_cv_qualifiers();
            let ref_qual = if self.consume_char(b'O') {
                RefQual::RValue
            } else if self.consume_char(b'R') {
                RefQual::LValue
            } else {
                RefQual::None
            };
            if let Some(st) = state.as_deref_mut() {
                st.cv = cv;
                st.ref_qual = ref_qual;
            }
        } else if let Some(st) = state.as_deref_mut() {
            st.explicit_object_param = true;
        }
        let mut so_far: Option<NodeId> = None;
        while !self.consume_char(b'E') {
            if let Some(st) = state.as_deref_mut() {
                st.ends_with_template_args = false;
            }
            if self.look(0) == b'T' {
                if so_far.is_some() {
                    return None;
                }
                so_far = Some(self.parse_template_param()?);
            } else if self.look(0) == b'I' {
                let sf = so_far?;
                let args = self.parse_template_args(state.is_some())?;
                if matches!(self.kind(sf), Node::NameWithTemplateArgs { .. }) {
                    return None;
                }
                if let Some(st) = state.as_deref_mut() {
                    st.ends_with_template_args = true;
                }
                so_far = Some(self.make(Node::NameWithTemplateArgs { name: sf, args })?);
            } else if self.look(0) == b'D' && (self.look(1) == b't' || self.look(1) == b'T') {
                if so_far.is_some() {
                    return None;
                }
                so_far = Some(self.parse_decltype()?);
            } else {
                let mut module = None;
                if self.look(0) == b'S' {
                    let s = if self.look(1) == b't' {
                        self.pos += 2;
                        self.name(b"std")?
                    } else {
                        self.parse_substitution()?
                    };
                    if matches!(self.kind(s), Node::ModuleName { .. }) {
                        module = Some(s);
                    } else if so_far.is_some() {
                        return None;
                    } else {
                        so_far = Some(s);
                        continue;
                    }
                }
                so_far = Some(self.parse_unqualified_name(state.as_deref_mut(), so_far, module)?);
            }
            let sf = so_far?;
            self.subs.push(sf);
            self.consume_char(b'M');
        }
        let sf = so_far?;
        if self.subs.is_empty() {
            return None;
        }
        self.subs.pop();
        Some(sf)
    }

    fn parse_simple_id(&mut self) -> Option<NodeId> {
        let sn = self.parse_source_name()?;
        if self.look(0) == b'I' {
            let args = self.parse_template_args(false)?;
            return self.make(Node::NameWithTemplateArgs { name: sn, args });
        }
        Some(sn)
    }

    fn parse_destructor_name(&mut self) -> Option<NodeId> {
        let r = if self.look(0).is_ascii_digit() {
            self.parse_simple_id()?
        } else {
            self.parse_unresolved_type()?
        };
        self.make(Node::DtorName(r))
    }

    fn parse_unresolved_type(&mut self) -> Option<NodeId> {
        if self.look(0) == b'T' {
            let tp = self.parse_template_param()?;
            self.subs.push(tp);
            return Some(tp);
        }
        if self.look(0) == b'D' {
            let dt = self.parse_decltype()?;
            self.subs.push(dt);
            return Some(dt);
        }
        self.parse_substitution()
    }

    fn parse_base_unresolved_name(&mut self) -> Option<NodeId> {
        if self.look(0).is_ascii_digit() {
            return self.parse_simple_id();
        }
        if self.consume_if(b"dn") {
            return self.parse_destructor_name();
        }
        self.consume_if(b"on");
        let oper = self.parse_operator_name(None)?;
        if self.look(0) == b'I' {
            let args = self.parse_template_args(false)?;
            return self.make(Node::NameWithTemplateArgs { name: oper, args });
        }
        Some(oper)
    }

    fn parse_unresolved_name(&mut self, global: bool) -> Option<NodeId> {
        if self.consume_if(b"srN") {
            let mut so_far = self.parse_unresolved_type()?;
            if self.look(0) == b'I' {
                let args = self.parse_template_args(false)?;
                so_far = self.make(Node::NameWithTemplateArgs { name: so_far, args })?;
            }
            while !self.consume_char(b'E') {
                let q = self.parse_simple_id()?;
                so_far = self.make(Node::QualifiedName {
                    qualifier: so_far,
                    name: q,
                })?;
            }
            let base = self.parse_base_unresolved_name()?;
            return self.make(Node::QualifiedName {
                qualifier: so_far,
                name: base,
            });
        }
        if !self.consume_if(b"sr") {
            let mut so_far = self.parse_base_unresolved_name()?;
            if global {
                so_far = self.make(Node::GlobalQualifiedName(so_far))?;
            }
            return Some(so_far);
        }
        let so_far = if self.look(0).is_ascii_digit() {
            let mut so_far: Option<NodeId> = None;
            loop {
                let q = self.parse_simple_id()?;
                so_far = Some(match so_far {
                    Some(sf) => self.make(Node::QualifiedName {
                        qualifier: sf,
                        name: q,
                    })?,
                    None if global => self.make(Node::GlobalQualifiedName(q))?,
                    None => q,
                });
                if self.consume_char(b'E') {
                    break;
                }
            }
            so_far?
        } else {
            let mut sf = self.parse_unresolved_type()?;
            if self.look(0) == b'I' {
                let args = self.parse_template_args(false)?;
                sf = self.make(Node::NameWithTemplateArgs { name: sf, args })?;
            }
            sf
        };
        let base = self.parse_base_unresolved_name()?;
        self.make(Node::QualifiedName {
            qualifier: so_far,
            name: base,
        })
    }

    fn parse_abi_tags(&mut self, mut n: NodeId) -> Option<NodeId> {
        while self.consume_char(b'B') {
            let tag = self.parse_bare_source_name();
            if tag.is_empty() {
                return None;
            }
            n = self.make(Node::AbiTagAttr { base: n, tag })?;
        }
        Some(n)
    }

    // -- Numbers --

    /// `<number> ::= [n] <digits>`; empty if there are no digits.
    fn parse_number(&mut self, allow_negative: bool) -> &'a [u8] {
        let start = self.pos;
        if allow_negative {
            self.consume_char(b'n');
        }
        if self.num_left() == 0 || !self.look(0).is_ascii_digit() {
            return &[];
        }
        while self.num_left() != 0 && self.look(0).is_ascii_digit() {
            self.pos += 1;
        }
        &self.s[start..self.pos]
    }

    fn parse_positive_integer(&mut self) -> Option<usize> {
        if !self.look(0).is_ascii_digit() {
            return None;
        }
        let mut n = 0usize;
        while self.look(0).is_ascii_digit() {
            // Lengths past the input fail anyway; don't overflow.
            n = n
                .saturating_mul(10)
                .saturating_add(usize::from(self.consume() - b'0'));
        }
        Some(n)
    }

    fn parse_bare_source_name(&mut self) -> &'a [u8] {
        let save = self.pos;
        let Some(n) = self.parse_positive_integer() else {
            return &[];
        };
        if self.num_left() < n {
            self.pos = save;
            return &[];
        }
        let r = &self.s[self.pos..self.pos + n];
        self.pos += n;
        r
    }

    fn parse_cv_qualifiers(&mut self) -> u8 {
        let mut q = 0;
        if self.consume_char(b'r') {
            q |= QUAL_RESTRICT;
        }
        if self.consume_char(b'V') {
            q |= QUAL_VOLATILE;
        }
        if self.consume_char(b'K') {
            q |= QUAL_CONST;
        }
        q
    }

    fn parse_seq_id(&mut self) -> Option<usize> {
        let c = self.look(0);
        if !c.is_ascii_digit() && !c.is_ascii_uppercase() {
            return None;
        }
        let mut id = 0usize;
        loop {
            let c = self.look(0);
            let d = if c.is_ascii_digit() {
                c - b'0'
            } else if c.is_ascii_uppercase() {
                c - b'A' + 10
            } else {
                return Some(id);
            };
            id = id.saturating_mul(36).saturating_add(usize::from(d));
            self.pos += 1;
        }
    }

    // -- Types --

    fn parse_function_type(&mut self) -> Option<NodeId> {
        let cv = self.parse_cv_qualifiers();
        let mut exception = None;
        if self.consume_if(b"Do") {
            exception = Some(self.name(b"noexcept")?);
        } else if self.consume_if(b"DO") {
            let e = self.parse_expr()?;
            if !self.consume_char(b'E') {
                return None;
            }
            exception = Some(self.make(Node::NoexceptSpec(e))?);
        } else if self.consume_if(b"Dw") {
            let begin = self.names.len();
            while !self.consume_char(b'E') {
                let t = self.parse_type()?;
                self.names.push(t);
            }
            let l = self.pop_trailing(begin);
            exception = Some(self.make(Node::DynamicExceptionSpec(l))?);
        }
        self.consume_if(b"Dx");
        if !self.consume_char(b'F') {
            return None;
        }
        self.consume_char(b'Y');
        let ret = self.parse_type()?;
        let mut ref_qual = RefQual::None;
        let begin = self.names.len();
        loop {
            if self.consume_char(b'E') {
                break;
            }
            if self.consume_char(b'v') {
                continue;
            }
            if self.consume_if(b"RE") {
                ref_qual = RefQual::LValue;
                break;
            }
            if self.consume_if(b"OE") {
                ref_qual = RefQual::RValue;
                break;
            }
            let t = self.parse_type()?;
            self.names.push(t);
        }
        let params = self.pop_trailing(begin);
        self.make(Node::FunctionType {
            ret,
            params,
            cv,
            ref_qual,
            exception,
        })
    }

    fn parse_vector_type(&mut self) -> Option<NodeId> {
        if !self.consume_if(b"Dv") {
            return None;
        }
        if (b'1'..=b'9').contains(&self.look(0)) {
            let n = self.parse_number(false);
            let dim = self.name(n)?;
            if !self.consume_char(b'_') {
                return None;
            }
            if self.consume_char(b'p') {
                return self.make(Node::PixelVectorType(dim));
            }
            let elem = self.parse_type()?;
            return self.make(Node::VectorType {
                base: elem,
                dimension: Some(dim),
            });
        }
        if !self.consume_char(b'_') {
            let dim = self.parse_expr()?;
            if !self.consume_char(b'_') {
                return None;
            }
            let elem = self.parse_type()?;
            return self.make(Node::VectorType {
                base: elem,
                dimension: Some(dim),
            });
        }
        let elem = self.parse_type()?;
        self.make(Node::VectorType {
            base: elem,
            dimension: None,
        })
    }

    fn parse_decltype(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'D') {
            return None;
        }
        if !self.consume_char(b't') && !self.consume_char(b'T') {
            return None;
        }
        let e = self.parse_expr()?;
        if !self.consume_char(b'E') {
            return None;
        }
        self.make(Node::EnclosingExpr {
            prefix: b"decltype",
            infix: e,
        })
    }

    fn parse_array_type(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'A') {
            return None;
        }
        let mut dimension = None;
        if self.look(0).is_ascii_digit() {
            let n = self.parse_number(false);
            dimension = Some(self.name(n)?);
            if !self.consume_char(b'_') {
                return None;
            }
        } else if !self.consume_char(b'_') {
            let e = self.parse_expr()?;
            if !self.consume_char(b'_') {
                return None;
            }
            dimension = Some(e);
        }
        let base = self.parse_type()?;
        self.make(Node::ArrayType { base, dimension })
    }

    fn parse_pointer_to_member_type(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'M') {
            return None;
        }
        let class = self.parse_type()?;
        let member = self.parse_type()?;
        self.make(Node::PointerToMemberType { class, member })
    }

    fn parse_class_enum_type(&mut self) -> Option<NodeId> {
        let kind: &'static [u8] = if self.consume_if(b"Ts") {
            b"struct"
        } else if self.consume_if(b"Tu") {
            b"union"
        } else if self.consume_if(b"Te") {
            b"enum"
        } else {
            b""
        };
        let name = self.parse_name(None)?;
        if !kind.is_empty() {
            return self.make(Node::ElaboratedTypeSpefType { kind, child: name });
        }
        Some(name)
    }

    fn parse_qualified_type(&mut self) -> Option<NodeId> {
        self.deeper(Goal::QualifiedType, None, |p, _| {
            p.parse_qualified_type_inner()
        })
    }

    fn parse_qualified_type_inner(&mut self) -> Option<NodeId> {
        if self.consume_char(b'U') {
            let qual = self.parse_bare_source_name();
            if qual.is_empty() {
                return None;
            }
            if let Some(rest) = qual.strip_prefix(b"objcproto") {
                // The protocol is a source name within the qualifier.
                let proto = {
                    let (s, pos, end) = (self.s, self.pos, self.end);
                    let start = rest.as_ptr() as usize - s.as_ptr() as usize;
                    self.pos = start;
                    self.end = start + rest.len();
                    let p = self.parse_bare_source_name();
                    self.pos = pos;
                    self.end = end;
                    p
                };
                if proto.is_empty() {
                    return None;
                }
                let child = self.parse_qualified_type()?;
                return self.make(Node::ObjCProtoName {
                    ty: child,
                    protocol: proto,
                });
            }
            let mut args = None;
            if self.look(0) == b'I' {
                args = Some(self.parse_template_args(false)?);
            }
            let child = self.parse_qualified_type()?;
            return self.make(Node::VendorExtQualType {
                ty: child,
                ext: qual,
                args,
            });
        }
        let quals = self.parse_cv_qualifiers();
        let mut ty = self.parse_type()?;
        if quals != 0 {
            ty = self.make(Node::QualType { child: ty, quals })?;
        }
        Some(ty)
    }

    pub fn parse_type(&mut self) -> Option<NodeId> {
        self.deeper(Goal::Type, None, |p, _| p.parse_type_inner())
    }

    fn parse_type_inner(&mut self) -> Option<NodeId> {
        let builtin = |p: &mut Self, n: usize, s: &'static [u8]| {
            p.pos += n;
            p.name(s)
        };
        let result = match self.look(0) {
            b'r' | b'V' | b'K' => {
                let mut after = 0;
                if self.look(after) == b'r' {
                    after += 1;
                }
                if self.look(after) == b'V' {
                    after += 1;
                }
                if self.look(after) == b'K' {
                    after += 1;
                }
                if self.look(after) == b'F'
                    || (self.look(after) == b'D'
                        && matches!(self.look(after + 1), b'o' | b'O' | b'w' | b'x'))
                {
                    self.parse_function_type()?
                } else {
                    self.parse_qualified_type()?
                }
            }
            b'U' => self.parse_qualified_type()?,
            b'v' => return builtin(self, 1, b"void"),
            b'w' => return builtin(self, 1, b"wchar_t"),
            b'b' => return builtin(self, 1, b"bool"),
            b'c' => return builtin(self, 1, b"char"),
            b'a' => return builtin(self, 1, b"signed char"),
            b'h' => return builtin(self, 1, b"unsigned char"),
            b's' => return builtin(self, 1, b"short"),
            b't' => return builtin(self, 1, b"unsigned short"),
            b'i' => return builtin(self, 1, b"int"),
            b'j' => return builtin(self, 1, b"unsigned int"),
            b'l' => return builtin(self, 1, b"long"),
            b'm' => return builtin(self, 1, b"unsigned long"),
            b'x' => return builtin(self, 1, b"long long"),
            b'y' => return builtin(self, 1, b"unsigned long long"),
            b'n' => return builtin(self, 1, b"__int128"),
            b'o' => return builtin(self, 1, b"unsigned __int128"),
            b'f' => return builtin(self, 1, b"float"),
            b'd' => return builtin(self, 1, b"double"),
            b'e' => return builtin(self, 1, b"long double"),
            b'g' => return builtin(self, 1, b"__float128"),
            b'z' => return builtin(self, 1, b"..."),
            b'u' => {
                self.pos += 1;
                let res = self.parse_bare_source_name();
                if res.is_empty() {
                    return None;
                }
                if self.consume_char(b'I') {
                    let base = self.parse_type()?;
                    if !self.consume_char(b'E') {
                        return None;
                    }
                    self.make(Node::TransformedType {
                        transform: res,
                        base,
                    })?
                } else {
                    self.name(res)?
                }
            }
            b'D' => match self.look(1) {
                b'd' => return builtin(self, 2, b"decimal64"),
                b'e' => return builtin(self, 2, b"decimal128"),
                b'f' => return builtin(self, 2, b"decimal32"),
                b'h' => return builtin(self, 2, b"half"),
                b'F' => {
                    self.pos += 2;
                    if self.consume_if(b"16b") {
                        return self.name(b"std::bfloat16_t");
                    }
                    let n = self.parse_number(false);
                    let dim = self.name(n)?;
                    if !self.consume_char(b'_') {
                        return None;
                    }
                    return self.make(Node::BinaryFPType(dim));
                }
                b'A' | b'R' => {
                    let accum = self.look(1) == b'A';
                    let c = self.look(2);
                    self.pos += 3;
                    return self.name(fixed_point(c, accum, false)?);
                }
                b'S' => {
                    self.pos += 2;
                    if self.look(0) != b'D' {
                        return None;
                    }
                    let accum = match self.look(1) {
                        b'A' => true,
                        b'R' => false,
                        _ => return None,
                    };
                    let c = self.look(2);
                    self.pos += 3;
                    return self.name(fixed_point(c, accum, true)?);
                }
                b'B' | b'U' => {
                    let signed = self.look(1) == b'B';
                    self.pos += 2;
                    let size = if self.look(0).is_ascii_digit() {
                        let n = self.parse_number(false);
                        self.name(n)?
                    } else {
                        self.parse_expr()?
                    };
                    if !self.consume_char(b'_') {
                        return None;
                    }
                    self.make(Node::BitIntType { size, signed })?
                }
                b'i' => return builtin(self, 2, b"char32_t"),
                b's' => return builtin(self, 2, b"char16_t"),
                b'u' => return builtin(self, 2, b"char8_t"),
                b'a' => return builtin(self, 2, b"auto"),
                b'c' => return builtin(self, 2, b"decltype(auto)"),
                b'k' | b'K' => {
                    let kind: &'static [u8] = if self.look(1) == b'k' {
                        b" auto"
                    } else {
                        b" decltype(auto)"
                    };
                    self.pos += 2;
                    let constraint = self.parse_name(None)?;
                    return self.make(Node::PostfixQualifiedType {
                        ty: constraint,
                        postfix: kind,
                    });
                }
                b'n' => return builtin(self, 2, b"std::nullptr_t"),
                b't' | b'T' => self.parse_decltype()?,
                b'v' => self.parse_vector_type()?,
                b'p' => {
                    self.pos += 2;
                    let child = self.parse_type()?;
                    self.make(Node::ParameterPackExpansion(child))?
                }
                b'y' => {
                    self.pos += 2;
                    let pattern = self.parse_type()?;
                    let index = self.parse_expr()?;
                    self.make(Node::PackIndexing { pattern, index })?
                }
                b'o' | b'O' | b'w' | b'x' => self.parse_function_type()?,
                _ => return None,
            },
            b'F' => self.parse_function_type()?,
            b'A' => self.parse_array_type()?,
            b'M' => self.parse_pointer_to_member_type()?,
            b'T' => {
                if matches!(self.look(1), b's' | b'u' | b'e') {
                    self.parse_class_enum_type()?
                } else {
                    let mut r = self.parse_template_param()?;
                    if self.try_template_args && self.look(0) == b'I' {
                        self.subs.push(r);
                        let args = self.parse_template_args(false)?;
                        r = self.make(Node::NameWithTemplateArgs { name: r, args })?;
                    }
                    r
                }
            }
            b'P' => {
                self.pos += 1;
                let p = self.parse_type()?;
                self.make(Node::PointerType(p))?
            }
            b'R' => {
                self.pos += 1;
                let p = self.parse_type()?;
                self.make(Node::ReferenceType {
                    pointee: p,
                    rvalue: false,
                })?
            }
            b'O' => {
                self.pos += 1;
                let p = self.parse_type()?;
                self.make(Node::ReferenceType {
                    pointee: p,
                    rvalue: true,
                })?
            }
            b'C' => {
                self.pos += 1;
                let p = self.parse_type()?;
                self.make(Node::PostfixQualifiedType {
                    ty: p,
                    postfix: b" complex",
                })?
            }
            b'G' => {
                self.pos += 1;
                let p = self.parse_type()?;
                self.make(Node::PostfixQualifiedType {
                    ty: p,
                    postfix: b" imaginary",
                })?
            }
            b'S' if self.look(1) != b't' => {
                let mut is_subst = false;
                let mut r = self.parse_unscoped_name(None, Some(&mut is_subst))?;
                if self.look(0) == b'I' && (!is_subst || self.try_template_args) {
                    if !is_subst {
                        self.subs.push(r);
                    }
                    let args = self.parse_template_args(false)?;
                    r = self.make(Node::NameWithTemplateArgs { name: r, args })?;
                } else if is_subst {
                    return Some(r);
                }
                r
            }
            _ => self.parse_class_enum_type()?,
        };
        self.subs.push(result);
        Some(result)
    }

    // -- Expressions --

    fn parse_prefix_expr(&mut self, prefix: &'static [u8], prec: Prec) -> Option<NodeId> {
        let e = self.parse_expr()?;
        self.make_prec(Node::PrefixExpr { prefix, child: e }, prec)
    }

    fn parse_binary_expr(&mut self, op: &'static [u8], prec: Prec) -> Option<NodeId> {
        let lhs = self.parse_expr()?;
        let rhs = self.parse_expr()?;
        self.make_prec(Node::BinaryExpr { lhs, op, rhs }, prec)
    }

    fn parse_integer_literal(&mut self, ty: &'static [u8]) -> Option<NodeId> {
        let value = self.parse_number(true);
        if !value.is_empty() && self.consume_char(b'E') {
            return self.make(Node::IntegerLiteral { ty, value });
        }
        None
    }

    fn parse_function_param(&mut self) -> Option<NodeId> {
        if self.consume_if(b"fpT") {
            return self.name(b"this");
        }
        if self.consume_if(b"fp") {
            self.parse_cv_qualifiers();
            let n = self.parse_number(false);
            if !self.consume_char(b'_') {
                return None;
            }
            return self.make(Node::FunctionParam(n));
        }
        if self.consume_if(b"fL") {
            if self.parse_number(false).is_empty() {
                return None;
            }
            if !self.consume_char(b'p') {
                return None;
            }
            self.parse_cv_qualifiers();
            let n = self.parse_number(false);
            if !self.consume_char(b'_') {
                return None;
            }
            return self.make(Node::FunctionParam(n));
        }
        None
    }

    fn parse_expr_primary(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'L') {
            return None;
        }
        let int = |p: &mut Self, ty: &'static [u8]| {
            p.pos += 1;
            p.parse_integer_literal(ty)
        };
        match self.look(0) {
            b'w' => int(self, b"wchar_t"),
            b'b' => {
                if self.consume_if(b"b0E") {
                    return self.make(Node::BoolExpr(false));
                }
                if self.consume_if(b"b1E") {
                    return self.make(Node::BoolExpr(true));
                }
                None
            }
            b'c' => int(self, b"char"),
            b'a' => int(self, b"signed char"),
            b'h' => int(self, b"unsigned char"),
            b's' => int(self, b"short"),
            b't' => int(self, b"unsigned short"),
            b'i' => int(self, b""),
            b'j' => int(self, b"u"),
            b'l' => int(self, b"l"),
            b'm' => int(self, b"ul"),
            b'x' => int(self, b"ll"),
            b'y' => int(self, b"ull"),
            b'n' => int(self, b"__int128"),
            b'o' => int(self, b"unsigned __int128"),
            b'f' => {
                self.pos += 1;
                self.parse_floating_literal(FloatKind::Float)
            }
            b'd' => {
                self.pos += 1;
                self.parse_floating_literal(FloatKind::Double)
            }
            b'e' => {
                self.pos += 1;
                self.parse_floating_literal(FloatKind::LongDouble)
            }
            b'_' => {
                if self.consume_if(b"_Z") {
                    let r = self.parse_encoding(true)?;
                    if self.consume_char(b'E') {
                        return Some(r);
                    }
                }
                None
            }
            b'A' => {
                let t = self.parse_type()?;
                if self.consume_char(b'E') {
                    return self.make(Node::StringLiteral(t));
                }
                None
            }
            b'T' => None,
            b'U' => {
                if self.look(1) != b'l' {
                    return None;
                }
                let t = self.parse_unnamed_type_name(false)?;
                if !self.consume_char(b'E') {
                    return None;
                }
                self.make(Node::LambdaExpr(t))
            }
            b'D' if self.look(1) == b'n' => {
                if self.consume_if(b"Dn") && {
                    self.consume_char(b'0');
                    self.consume_char(b'E')
                } {
                    return self.name(b"nullptr");
                }
                None
            }
            _ => {
                let ty = self.parse_type()?;
                let n = self.parse_number(true);
                if n.is_empty() || !self.consume_char(b'E') {
                    return None;
                }
                self.make(Node::EnumLiteral { ty, integer: n })
            }
        }
    }

    fn parse_floating_literal(&mut self, kind: FloatKind) -> Option<NodeId> {
        let n = match kind {
            FloatKind::Float => 8,
            FloatKind::Double => 16,
            // x87 80-bit, as on x86 Linux.
            FloatKind::LongDouble => 20,
        };
        if self.num_left() <= n {
            return None;
        }
        let data = &self.s[self.pos..self.pos + n];
        if !data
            .iter()
            .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return None;
        }
        self.pos += n;
        if !self.consume_char(b'E') {
            return None;
        }
        self.make(Node::FloatLiteral {
            kind,
            contents: data,
        })
    }

    fn parse_braced_expr(&mut self) -> Option<NodeId> {
        self.deeper(Goal::BracedExpr, None, |p, _| p.parse_braced_expr_inner())
    }

    fn parse_braced_expr_inner(&mut self) -> Option<NodeId> {
        if self.look(0) == b'd' {
            match self.look(1) {
                b'i' => {
                    self.pos += 2;
                    let field = self.parse_source_name()?;
                    let init = self.parse_braced_expr()?;
                    return self.make(Node::BracedExpr {
                        elem: field,
                        init,
                        array: false,
                    });
                }
                b'x' => {
                    self.pos += 2;
                    let index = self.parse_expr()?;
                    let init = self.parse_braced_expr()?;
                    return self.make(Node::BracedExpr {
                        elem: index,
                        init,
                        array: true,
                    });
                }
                b'X' => {
                    self.pos += 2;
                    let first = self.parse_expr()?;
                    let last = self.parse_expr()?;
                    let init = self.parse_braced_expr()?;
                    return self.make(Node::BracedRangeExpr { first, last, init });
                }
                _ => {}
            }
        }
        self.parse_expr()
    }

    fn parse_fold_expr(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'f') {
            return None;
        }
        let (left, has_init) = match self.look(0) {
            b'L' => (true, true),
            b'R' => (false, true),
            b'l' => (true, false),
            b'r' => (false, false),
            _ => return None,
        };
        self.pos += 1;
        let op = self.parse_operator_encoding()?;
        if !(op.kind == OpKind::Binary || (op.kind == OpKind::Member && op.name.ends_with(b"*"))) {
            return None;
        }
        let mut pack = self.parse_expr()?;
        let mut init = None;
        if has_init {
            init = Some(self.parse_expr()?);
        }
        if left && let Some(i) = init {
            init = Some(pack);
            pack = i;
        }
        self.make(Node::FoldExpr {
            left,
            op: op.symbol(),
            pack,
            init,
        })
    }

    fn parse_pointer_to_member_conversion_expr(&mut self, prec: Prec) -> Option<NodeId> {
        let ty = self.parse_type()?;
        let sub = self.parse_expr()?;
        self.parse_number(true);
        if !self.consume_char(b'E') {
            return None;
        }
        self.make_prec(Node::PointerToMemberConversionExpr { ty, sub }, prec)
    }

    fn parse_subobject_expr(&mut self) -> Option<NodeId> {
        let ty = self.parse_type()?;
        let sub = self.parse_expr()?;
        let offset = self.parse_number(true);
        let begin = self.names.len();
        while self.consume_char(b'_') {
            let n = self.parse_number(false);
            let sel = self.name(n)?;
            self.names.push(sel);
        }
        let one_past_end = self.consume_char(b'p');
        if !self.consume_char(b'E') {
            return None;
        }
        let selectors = self.pop_trailing(begin);
        self.make(Node::SubobjectExpr {
            ty,
            sub,
            offset,
            selectors,
            one_past_end,
        })
    }

    fn parse_constraint_expr(&mut self) -> Option<NodeId> {
        let saved = mem::replace(&mut self.incomplete_tracking, true);
        let r = self.parse_expr();
        self.incomplete_tracking = saved;
        r
    }

    fn parse_requires_expr(&mut self) -> Option<NodeId> {
        let mut params = List::default();
        if self.consume_if(b"rQ") {
            let begin = self.names.len();
            while !self.consume_char(b'_') {
                let t = self.parse_type()?;
                self.names.push(t);
            }
            params = self.pop_trailing(begin);
        } else if !self.consume_if(b"rq") {
            return None;
        }
        let begin = self.names.len();
        loop {
            let constraint = if self.consume_char(b'X') {
                let expr = self.parse_expr()?;
                let noexcept = self.consume_char(b'N');
                let mut req = None;
                if self.consume_char(b'R') {
                    req = Some(self.parse_name(None)?);
                }
                self.make(Node::ExprRequirement {
                    expr,
                    noexcept,
                    constraint: req,
                })?
            } else if self.consume_char(b'T') {
                let t = self.parse_type()?;
                self.make(Node::TypeRequirement(t))?
            } else if self.consume_char(b'Q') {
                let e = self.parse_expr()?;
                self.make(Node::NestedRequirement(e))?
            } else {
                return None;
            };
            self.names.push(constraint);
            if self.consume_char(b'E') {
                break;
            }
        }
        let requirements = self.pop_trailing(begin);
        self.make(Node::RequiresExpr {
            params,
            requirements,
        })
    }

    pub fn parse_expr(&mut self) -> Option<NodeId> {
        self.deeper(Goal::Expr, None, |p, _| p.parse_expr_inner())
    }

    fn parse_expr_inner(&mut self) -> Option<NodeId> {
        let global = self.consume_if(b"gs");
        let save = self.pos;
        if let Some(op) = self.parse_operator_encoding() {
            let sym = op.symbol();
            let prec = op.prec;
            match op.kind {
                OpKind::Binary => return self.parse_binary_expr(sym, prec),
                OpKind::Prefix => return self.parse_prefix_expr(sym, prec),
                OpKind::Postfix => {
                    if self.consume_char(b'_') {
                        return self.parse_prefix_expr(sym, prec);
                    }
                    let e = self.parse_expr()?;
                    return self.make_prec(Node::PostfixExpr { child: e, op: sym }, prec);
                }
                OpKind::Array => {
                    let base = self.parse_expr()?;
                    let index = self.parse_expr()?;
                    return self.make_prec(
                        Node::ArraySubscriptExpr {
                            op1: base,
                            op2: index,
                        },
                        prec,
                    );
                }
                OpKind::Member => {
                    let lhs = self.parse_expr()?;
                    let rhs = self.parse_expr()?;
                    return self.make_prec(
                        Node::MemberExpr {
                            lhs,
                            kind: sym,
                            rhs,
                        },
                        prec,
                    );
                }
                OpKind::New => {
                    let begin = self.names.len();
                    while !self.consume_char(b'_') {
                        let e = self.parse_expr()?;
                        self.names.push(e);
                    }
                    let exprs = self.pop_trailing(begin);
                    let ty = self.parse_type()?;
                    let have_inits = self.consume_if(b"pi");
                    let begin = self.names.len();
                    while !self.consume_char(b'E') {
                        if !have_inits {
                            return None;
                        }
                        let e = self.parse_expr()?;
                        self.names.push(e);
                    }
                    let inits = self.pop_trailing(begin);
                    return self.make_prec(
                        Node::NewExpr {
                            exprs,
                            ty,
                            inits,
                            global,
                            array: op.flag,
                        },
                        prec,
                    );
                }
                OpKind::Del => {
                    let e = self.parse_expr()?;
                    return self.make_prec(
                        Node::DeleteExpr {
                            op: e,
                            global,
                            array: op.flag,
                        },
                        prec,
                    );
                }
                OpKind::Call => {
                    let callee = self.parse_expr()?;
                    let begin = self.names.len();
                    while !self.consume_char(b'E') {
                        let e = self.parse_expr()?;
                        self.names.push(e);
                    }
                    let args = self.pop_trailing(begin);
                    return self.make_prec(
                        Node::CallExpr {
                            callee,
                            args,
                            paren: op.flag,
                        },
                        prec,
                    );
                }
                OpKind::CCast => {
                    let saved = mem::replace(&mut self.try_template_args, false);
                    let ty = self.parse_type();
                    self.try_template_args = saved;
                    let ty = ty?;
                    let begin = self.names.len();
                    let many = self.consume_char(b'_');
                    while !self.consume_char(b'E') {
                        let e = self.parse_expr()?;
                        self.names.push(e);
                        if !many {
                            break;
                        }
                    }
                    let exprs = self.pop_trailing(begin);
                    if !many && exprs.len != 1 {
                        return None;
                    }
                    return self.make_prec(Node::ConversionExpr { ty, exprs }, prec);
                }
                OpKind::Conditional => {
                    let cond = self.parse_expr()?;
                    let then = self.parse_expr()?;
                    let otherwise = self.parse_expr()?;
                    return self.make_prec(
                        Node::ConditionalExpr {
                            cond,
                            then,
                            otherwise,
                        },
                        prec,
                    );
                }
                OpKind::NamedCast => {
                    let to = self.parse_type()?;
                    let from = self.parse_expr()?;
                    return self.make_prec(
                        Node::CastExpr {
                            kind: sym,
                            to,
                            from,
                        },
                        prec,
                    );
                }
                OpKind::OfIdOp => {
                    let arg = if op.flag {
                        self.parse_type()?
                    } else {
                        self.parse_expr()?
                    };
                    return self.make_prec(
                        Node::EnclosingExpr {
                            prefix: sym,
                            infix: arg,
                        },
                        prec,
                    );
                }
                OpKind::NameOnly => return None,
            }
        }
        self.pos = save;
        if self.num_left() < 2 {
            return None;
        }
        match self.look(0) {
            b'L' => return self.parse_expr_primary(),
            b'T' => return self.parse_template_param(),
            b'f' => {
                if self.look(1) == b'p' || (self.look(1) == b'L' && self.look(2).is_ascii_digit()) {
                    return self.parse_function_param();
                }
                return self.parse_fold_expr();
            }
            _ => {}
        }
        if self.consume_if(b"il") {
            let begin = self.names.len();
            while !self.consume_char(b'E') {
                let e = self.parse_braced_expr()?;
                self.names.push(e);
            }
            let inits = self.pop_trailing(begin);
            return self.make(Node::InitListExpr { ty: None, inits });
        }
        if self.consume_if(b"mc") {
            return self.parse_pointer_to_member_conversion_expr(Prec::Unary);
        }
        if self.consume_if(b"nx") {
            let e = self.parse_expr()?;
            return self.make_prec(
                Node::EnclosingExpr {
                    prefix: b"noexcept ",
                    infix: e,
                },
                Prec::Unary,
            );
        }
        if self.look(0) == b'r' && (self.look(1) == b'q' || self.look(1) == b'Q') {
            return self.parse_requires_expr();
        }
        if self.consume_if(b"so") {
            return self.parse_subobject_expr();
        }
        if self.consume_if(b"sp") {
            let child = self.parse_expr()?;
            return self.make(Node::ParameterPackExpansion(child));
        }
        if self.consume_if(b"sy") {
            let pattern = if self.look(0) == b'T' {
                self.parse_template_param()?
            } else {
                self.parse_function_param()?
            };
            let index = self.parse_expr()?;
            return self.make(Node::PackIndexing { pattern, index });
        }
        if self.consume_if(b"sZ") {
            if self.look(0) == b'T' {
                let r = self.parse_template_param()?;
                return self.make(Node::SizeofParamPackExpr(r));
            }
            let fp = self.parse_function_param()?;
            return self.make(Node::EnclosingExpr {
                prefix: b"sizeof... ",
                infix: fp,
            });
        }
        if self.consume_if(b"sP") {
            let begin = self.names.len();
            while !self.consume_char(b'E') {
                let a = self.parse_template_arg()?;
                self.names.push(a);
            }
            let l = self.pop_trailing(begin);
            let pack = self.make(Node::NodeArray(l))?;
            return self.make(Node::EnclosingExpr {
                prefix: b"sizeof... ",
                infix: pack,
            });
        }
        if self.consume_if(b"tl") {
            let ty = self.parse_type()?;
            let begin = self.names.len();
            while !self.consume_char(b'E') {
                let e = self.parse_braced_expr()?;
                self.names.push(e);
            }
            let inits = self.pop_trailing(begin);
            return self.make(Node::InitListExpr {
                ty: Some(ty),
                inits,
            });
        }
        if self.consume_if(b"tr") {
            return self.name(b"throw");
        }
        if self.consume_if(b"tw") {
            let e = self.parse_expr()?;
            return self.make(Node::ThrowExpr(e));
        }
        if self.consume_char(b'u') {
            let name = self.parse_source_name()?;
            let mut uuid = None;
            if self.ast.base_name(name) == b"__uuidof" {
                if self.consume_char(b't') {
                    uuid = Some(self.parse_type());
                } else if self.consume_char(b'z') {
                    uuid = Some(self.parse_expr());
                }
            }
            let begin = self.names.len();
            if let Some(u) = uuid {
                self.names.push(u?);
            } else {
                while !self.consume_char(b'E') {
                    let e = self.parse_template_arg()?;
                    self.names.push(e);
                }
            }
            let args = self.pop_trailing(begin);
            return self.make_prec(
                Node::CallExpr {
                    callee: name,
                    args,
                    paren: false,
                },
                Prec::Postfix,
            );
        }
        self.parse_unresolved_name(global)
    }

    // -- Special names and encodings --

    /// Skips a `<call-offset>`; `false` if malformed.
    fn parse_call_offset(&mut self) -> bool {
        if self.consume_char(b'h') {
            return !self.parse_number(true).is_empty() && self.consume_char(b'_');
        }
        if self.consume_char(b'v') {
            return !self.parse_number(true).is_empty()
                && self.consume_char(b'_')
                && !self.parse_number(true).is_empty()
                && self.consume_char(b'_');
        }
        false
    }

    fn special(&mut self, special: &'static [u8], child: NodeId) -> Option<NodeId> {
        self.make(Node::SpecialName { special, child })
    }

    fn parse_special_name(&mut self) -> Option<NodeId> {
        match self.look(0) {
            b'T' => match self.look(1) {
                b'A' => {
                    self.pos += 2;
                    let a = self.parse_template_arg()?;
                    self.special(b"template parameter object for ", a)
                }
                b'V' => {
                    self.pos += 2;
                    let t = self.parse_type()?;
                    self.special(b"vtable for ", t)
                }
                b'T' => {
                    self.pos += 2;
                    let t = self.parse_type()?;
                    self.special(b"VTT for ", t)
                }
                b'I' => {
                    self.pos += 2;
                    let t = self.parse_type()?;
                    self.special(b"typeinfo for ", t)
                }
                b'S' => {
                    self.pos += 2;
                    let t = self.parse_type()?;
                    self.special(b"typeinfo name for ", t)
                }
                b'c' => {
                    self.pos += 2;
                    if !self.parse_call_offset() || !self.parse_call_offset() {
                        return None;
                    }
                    let e = self.parse_encoding(true)?;
                    self.special(b"covariant return thunk to ", e)
                }
                b'C' => {
                    self.pos += 2;
                    let first = self.parse_type()?;
                    if self.parse_number(true).is_empty() || !self.consume_char(b'_') {
                        return None;
                    }
                    let second = self.parse_type()?;
                    self.make(Node::CtorVtableSpecialName {
                        first: second,
                        second: first,
                    })
                }
                b'W' => {
                    self.pos += 2;
                    let n = self.parse_name(None)?;
                    self.special(b"thread-local wrapper routine for ", n)
                }
                b'H' => {
                    self.pos += 2;
                    let n = self.parse_name(None)?;
                    self.special(b"thread-local initialization routine for ", n)
                }
                _ => {
                    self.pos += 1;
                    let virt = self.look(0) == b'v';
                    if !self.parse_call_offset() {
                        return None;
                    }
                    let e = self.parse_encoding(true)?;
                    if virt {
                        self.special(b"virtual thunk to ", e)
                    } else {
                        self.special(b"non-virtual thunk to ", e)
                    }
                }
            },
            b'G' => match self.look(1) {
                b'V' => {
                    self.pos += 2;
                    let n = self.parse_name(None)?;
                    self.special(b"guard variable for ", n)
                }
                b'R' => {
                    self.pos += 2;
                    let n = self.parse_name(None)?;
                    let parsed_seq = self.parse_seq_id().is_some();
                    if !self.consume_char(b'_') && parsed_seq {
                        return None;
                    }
                    self.special(b"reference temporary for ", n)
                }
                b'I' => {
                    self.pos += 2;
                    let mut module = None;
                    if !self.parse_module_name_opt(&mut module) {
                        return None;
                    }
                    let m = module?;
                    self.special(b"initializer for module ", m)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn resolve_forward_refs(&mut self, begin: usize) -> bool {
        for i in begin..self.forward_refs.len() {
            let (slot, index) = self.forward_refs[i];
            let Some(&tp) = self.tparams.first() else {
                return false;
            };
            let Some(list) = self.tparam_list(tp) else {
                return false;
            };
            let Some(&target) = list.get(index as usize) else {
                return false;
            };
            self.ast.forward[slot as usize] = Some(target);
        }
        self.forward_refs.truncate(begin);
        true
    }

    fn parse_encoding(&mut self, parse_params: bool) -> Option<NodeId> {
        self.deeper(Goal::Encoding(parse_params), None, |p, _| {
            p.with_saved_template_params(|p| p.parse_encoding_inner(parse_params))
        })
    }

    fn is_end_of_encoding(&self) -> bool {
        self.num_left() == 0 || matches!(self.look(0), b'E' | b'.' | b'_')
    }

    fn parse_encoding_inner(&mut self, parse_params: bool) -> Option<NodeId> {
        if self.look(0) == b'G' || self.look(0) == b'T' {
            return self.parse_special_name();
        }
        let mut state = NameState {
            ctor_dtor_conversion: false,
            ends_with_template_args: false,
            cv: 0,
            ref_qual: RefQual::None,
            forward_refs_begin: self.forward_refs.len(),
            explicit_object_param: false,
        };
        let name = self.parse_name(Some(&mut state))?;
        if !self.resolve_forward_refs(state.forward_refs_begin) {
            return None;
        }
        if self.is_end_of_encoding() {
            return Some(name);
        }
        if !parse_params {
            self.pos = self.end;
            return Some(name);
        }
        let mut attrs = None;
        if self.consume_if(b"Ua9enable_ifI") {
            let begin = self.names.len();
            while !self.consume_char(b'E') {
                let a = self.parse_template_arg()?;
                self.names.push(a);
            }
            let l = self.pop_trailing(begin);
            attrs = Some(self.make(Node::EnableIfAttr(l))?);
        }
        let mut ret = None;
        if !state.ctor_dtor_conversion && state.ends_with_template_args {
            ret = Some(self.parse_type()?);
        }
        let mut params = List::default();
        if !self.consume_char(b'v') {
            let begin = self.names.len();
            loop {
                let mut ty = self.parse_type()?;
                if state.explicit_object_param && begin == self.names.len() {
                    ty = self.make(Node::ExplicitObjectParameter(ty))?;
                }
                self.names.push(ty);
                if self.is_end_of_encoding() || self.look(0) == b'Q' {
                    break;
                }
            }
            params = self.pop_trailing(begin);
        }
        let mut requires = None;
        if self.consume_char(b'Q') {
            requires = Some(self.parse_constraint_expr()?);
        }
        self.make(Node::FunctionEncoding {
            ret,
            name,
            params,
            attrs,
            requires,
            cv: state.cv,
            ref_qual: state.ref_qual,
        })
    }

    // -- Substitutions and template parameters --

    fn parse_substitution(&mut self) -> Option<NodeId> {
        if !self.consume_char(b'S') {
            return None;
        }
        if self.look(0).is_ascii_lowercase() {
            let kind = match self.look(0) {
                b'a' => SpecialSub::Allocator,
                b'b' => SpecialSub::BasicString,
                b'd' => SpecialSub::Iostream,
                b'i' => SpecialSub::Istream,
                b'o' => SpecialSub::Ostream,
                b's' => SpecialSub::String,
                _ => return None,
            };
            self.pos += 1;
            let sub = self.make(Node::SpecialSubstitution(kind))?;
            let tagged = self.parse_abi_tags(sub)?;
            if tagged != sub {
                self.subs.push(tagged);
            }
            return Some(tagged);
        }
        if self.consume_char(b'_') {
            return self.subs.first().copied();
        }
        let index = self.parse_seq_id()?.checked_add(1)?;
        if !self.consume_char(b'_') {
            return None;
        }
        self.subs.get(index).copied()
    }

    fn parse_template_param(&mut self) -> Option<NodeId> {
        let begin = self.pos;
        if !self.consume_char(b'T') {
            return None;
        }
        let mut level = 0usize;
        if self.consume_char(b'L') {
            level = self.parse_positive_integer()?.checked_add(1)?;
            if !self.consume_char(b'_') {
                return None;
            }
        }
        let mut index = 0usize;
        if !self.consume_char(b'_') {
            index = self.parse_positive_integer()?.checked_add(1)?;
            if !self.consume_char(b'_') {
                return None;
            }
        }
        if self.incomplete_tracking {
            let text = &self.s[begin..self.pos - 1];
            return self.name(text);
        }
        if self.permit_forward && level == 0 {
            let slot = u32::try_from(self.ast.forward.len()).ok()?;
            self.ast.forward.push(None);
            let index = u32::try_from(index).ok()?;
            let r = self.make(Node::ForwardTemplateReference { index, slot })?;
            self.forward_refs.push((slot, index));
            return Some(r);
        }
        let found = self
            .tparams
            .get(level)
            .and_then(|&tp| self.tparam_list(tp))
            .and_then(|l| l.get(index).copied());
        match found {
            Some(n) => Some(n),
            None => {
                if self.lambda_level == level && level <= self.tparams.len() {
                    if level == self.tparams.len() {
                        self.tparams.push(Tp::Null);
                    }
                    return self.name(b"auto");
                }
                None
            }
        }
    }

    fn is_template_param_decl(&self) -> bool {
        self.look(0) == b'T' && matches!(self.look(1), b'y' | b'p' | b't' | b'n' | b'k')
    }

    fn invent_param_name(&mut self, kind: ParamKind, list: Option<usize>) -> Option<NodeId> {
        let k = kind as usize;
        let index = self.synthetic[k];
        self.synthetic[k] += 1;
        let n = self.make(Node::SyntheticTemplateParamName { kind, index })?;
        if let Some(l) = list
            && let Some(v) = self.scoped.get_mut(l)
        {
            v.push(n);
        }
        Some(n)
    }

    fn parse_template_param_decl(&mut self, list: Option<usize>) -> Option<NodeId> {
        self.deeper(Goal::TemplateParamDecl(list), None, |p, _| {
            p.parse_template_param_decl_inner(list)
        })
    }

    fn parse_template_param_decl_inner(&mut self, list: Option<usize>) -> Option<NodeId> {
        if self.consume_if(b"Ty") {
            let name = self.invent_param_name(ParamKind::Type, list)?;
            return self.make(Node::TypeTemplateParamDecl(name));
        }
        if self.consume_if(b"Tk") {
            let saved = mem::replace(&mut self.incomplete_tracking, true);
            let constraint = self.parse_name(None);
            self.incomplete_tracking = saved;
            let constraint = constraint?;
            let name = self.invent_param_name(ParamKind::Type, list)?;
            return self.make(Node::ConstrainedTypeTemplateParamDecl { constraint, name });
        }
        if self.consume_if(b"Tn") {
            let name = self.invent_param_name(ParamKind::NonType, list)?;
            let ty = self.parse_type()?;
            return self.make(Node::NonTypeTemplateParamDecl { name, ty });
        }
        if self.consume_if(b"Tt") {
            let name = self.invent_param_name(ParamKind::Template, list)?;
            let begin = self.names.len();
            let r = self.with_scoped_list(|p, inner| {
                let mut requires = None;
                while !p.consume_char(b'E') {
                    let d = p.parse_template_param_decl(Some(inner))?;
                    p.names.push(d);
                    if p.consume_char(b'Q') {
                        requires = Some(p.parse_constraint_expr()?);
                        if !p.consume_char(b'E') {
                            return None;
                        }
                        break;
                    }
                }
                Some(requires)
            });
            let requires = r?;
            let params = self.pop_trailing(begin);
            return self.make(Node::TemplateTemplateParamDecl {
                name,
                params,
                requires,
            });
        }
        if self.consume_if(b"Tp") {
            let p = self.parse_template_param_decl(list)?;
            return self.make(Node::TemplateParamPackDecl(p));
        }
        None
    }

    fn parse_template_arg(&mut self) -> Option<NodeId> {
        self.deeper(Goal::TemplateArg, None, |p, _| p.parse_template_arg_inner())
    }

    fn parse_template_arg_inner(&mut self) -> Option<NodeId> {
        match self.look(0) {
            b'X' => {
                self.pos += 1;
                let a = self.parse_expr()?;
                if !self.consume_char(b'E') {
                    return None;
                }
                Some(a)
            }
            b'J' => {
                self.pos += 1;
                let begin = self.names.len();
                while !self.consume_char(b'E') {
                    let a = self.parse_template_arg()?;
                    self.names.push(a);
                }
                let l = self.pop_trailing(begin);
                self.make(Node::TemplateArgumentPack(l))
            }
            b'L' => {
                if self.look(1) == b'Z' {
                    self.pos += 2;
                    let a = self.parse_encoding(true)?;
                    if !self.consume_char(b'E') {
                        return None;
                    }
                    return Some(a);
                }
                self.parse_expr_primary()
            }
            b'T' => {
                if !self.is_template_param_decl() {
                    return self.parse_type();
                }
                let param = self.parse_template_param_decl(None)?;
                let arg = self.parse_template_arg()?;
                self.make(Node::TemplateParamQualifiedArg { param, arg })
            }
            _ => self.parse_type(),
        }
    }

    fn parse_template_args(&mut self, tag_templates: bool) -> Option<NodeId> {
        if !self.consume_char(b'I') {
            return None;
        }
        if tag_templates {
            self.tparams.clear();
            self.tparams.push(Tp::Outer);
            self.outer.clear();
        }
        let begin = self.names.len();
        let mut requires = None;
        while !self.consume_char(b'E') {
            let arg = self.parse_template_arg()?;
            self.names.push(arg);
            if tag_templates {
                let mut entry = arg;
                if let Node::TemplateParamQualifiedArg { arg, .. } = *self.kind(entry) {
                    entry = arg;
                }
                if let Node::TemplateArgumentPack(l) = *self.kind(arg) {
                    entry = self.make(Node::ParameterPack(l))?;
                }
                self.outer.push(entry);
            }
            if self.consume_char(b'Q') {
                requires = Some(self.parse_constraint_expr()?);
                if !self.consume_char(b'E') {
                    return None;
                }
                break;
            }
        }
        let params = self.pop_trailing(begin);
        self.make(Node::TemplateArgs { params, requires })
    }
}

/// The `_Accum`/`_Fract` fixed-point type for size code `c`.
fn fixed_point(c: u8, accum: bool, sat: bool) -> Option<&'static [u8]> {
    let i = match c {
        b's' => 0,
        b't' => 1,
        b'i' => 2,
        b'j' => 3,
        b'l' => 4,
        b'm' => 5,
        _ => return None,
    };
    const ACCUM: [&[u8]; 6] = [
        b"short _Accum",
        b"unsigned short _Accum",
        b"_Accum",
        b"unsigned _Accum",
        b"long _Accum",
        b"unsigned long _Accum",
    ];
    const FRACT: [&[u8]; 6] = [
        b"short _Fract",
        b"unsigned short _Fract",
        b"_Fract",
        b"unsigned _Fract",
        b"long _Fract",
        b"unsigned long _Fract",
    ];
    const SAT_ACCUM: [&[u8]; 6] = [
        b"_Sat short _Accum",
        b"_Sat unsigned short _Accum",
        b"_Sat _Accum",
        b"_Sat unsigned _Accum",
        b"_Sat long _Accum",
        b"_Sat unsigned long _Accum",
    ];
    const SAT_FRACT: [&[u8]; 6] = [
        b"_Sat short _Fract",
        b"_Sat unsigned short _Fract",
        b"_Sat _Fract",
        b"_Sat unsigned _Fract",
        b"_Sat long _Fract",
        b"_Sat unsigned long _Fract",
    ];
    Some(match (accum, sat) {
        (true, false) => ACCUM[i],
        (false, false) => FRACT[i],
        (true, true) => SAT_ACCUM[i],
        (false, true) => SAT_FRACT[i],
    })
}

/// Skips a `<discriminator>` (`_ <digit>`, `__ <number> _`), or trailing
/// digits that end the input.
fn parse_discriminator(s: &[u8], first: usize, last: usize) -> usize {
    if first == last {
        return first;
    }
    if s[first] == b'_' {
        let mut t = first + 1;
        if t != last {
            if s[t].is_ascii_digit() {
                return t + 1;
            }
            if s[t] == b'_' {
                t += 1;
                while t != last && s[t].is_ascii_digit() {
                    t += 1;
                }
                if t != last && s[t] == b'_' {
                    return t + 1;
                }
            }
        }
    } else if s[first].is_ascii_digit() {
        let mut t = first + 1;
        while t != last && s[t].is_ascii_digit() {
            t += 1;
        }
        if t == last {
            return last;
        }
    }
    first
}

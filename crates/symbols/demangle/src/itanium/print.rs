// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Follows the LLVM Project's demangler (see LICENSE-LLVM at the crate root).

//! Printing a tree as C++, by LLVM's rules (`ItaniumDemangle.h`'s
//! `printLeft`/`printRight`, Apache-2.0 WITH LLVM-exception): a declarator
//! prints the part of its type before the name, then the part after
//! (`int (*f(float))(char)`), and expressions are parenthesized by
//! precedence. Unexpanded parameter packs print one element at a time as
//! the enclosing expansion iterates over them.
//!
//! Printing is bounded as parsing is: a tree that nests too deeply, or
//! whose shared subtrees (substitutions) would print too much, fails; and
//! the thread's stack holds a bounded number of levels (see
//! [`Printer::drive`]).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::{self, ManuallyDrop};

use super::ast::*;

/// Printing nested deeper than this fails.
const MAX_DEPTH: u32 = 384;
/// How many levels of nesting the printer recurses through on the
/// thread's stack (a constant bound on what that takes). Deeper levels:
/// see [`Printer::drive`].
pub const NATIVE_DEPTH: u32 = if cfg!(debug_assertions) { 24 } else { 128 };
/// The most work (output and state copied) printing a tree nested past
/// [`NATIVE_DEPTH`] may take, beyond the printing itself.
const MAX_DEEP_WORK: usize = 1 << 24;
/// Output longer than this fails.
const MAX_OUTPUT: usize = 1 << 20;
const NO_PACK: u32 = u32::MAX;

/// Charges `n` to a deep print's work.
fn deep_spent_extra(deep: &mut ManuallyDrop<Option<Box<Deep>>>, n: usize) {
    if let Some(deep) = deep.as_deref_mut() {
        deep.spent += n;
    }
}

/// What [`Printer::has`] asks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Has {
    Rhs,
    Array,
    Function,
}

/// What the printer prints, one level deeper (see [`Printer::boundary`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Goal {
    /// The whole tree, in full or short.
    Print(NodeId),
    TopShort(NodeId),
    Left(NodeId),
    Right(NodeId),
    Short(NodeId),
}

/// The printer's state but its output: at a call, or at its return.
#[derive(Clone, Debug, Default)]
struct State {
    out: usize,
    pack_index: u32,
    pack_max: u32,
    paren_depth: u32,
    inside_template: bool,
    failed: bool,
    /// The nodes being printed (guarded against cycles), at a call.
    guarded: Vec<NodeId>,
}

/// A call past a run's levels, for [`Printer::drive`] to run.
struct Call {
    goal: Goal,
    entry: State,
    /// The output before it (which printing may look at, and which the run
    /// that made it may change as it unwinds).
    prefix: Vec<u8>,
    /// The depth it is called from.
    base: u32,
}

/// A call [`Printer::drive`] has run: the printer after it, and what it
/// wrote.
struct Done {
    goal: Goal,
    exit: State,
    text: Vec<u8>,
}

/// A call [`Printer::drive`] is running, with the results of the calls
/// past its levels it has made so far.
struct Task {
    goal: Goal,
    entry: State,
    /// The output before it, for a call (else the run's own).
    prefix: Option<Vec<u8>>,
    base: u32,
    depth: u32,
    done: Vec<Done>,
}

/// The printer's state while [`Printer::drive`] prints a deep tree.
#[derive(Default)]
struct Deep {
    /// The depth of this run's level 0.
    base: u32,
    /// The results of this run's calls past its levels, in call order, and
    /// how many it has made.
    done: Vec<Done>,
    done_at: usize,
    /// A call past this run's levels with no result yet: the run is
    /// unwinding (as if failed).
    pending: Option<Call>,
    /// Work so far (see [`MAX_DEEP_WORK`]).
    spent: usize,
}

pub struct Printer<'p, 'a> {
    ast: &'p Ast<'a>,
    pub out: Vec<u8>,
    pack_index: u32,
    pack_max: u32,
    paren_depth: u32,
    inside_template: bool,
    /// Guards against cycles through references and forward references.
    printing: Vec<bool>,
    /// Levels of nesting of this run (on the thread's stack).
    depth: u32,
    /// How many there may be before a call goes to [`Printer::boundary`]:
    /// `native_depth`, fewer near [`MAX_DEPTH`], or 0 once a run is
    /// unwinding.
    limit: u32,
    /// [`NATIVE_DEPTH`], or fewer for testing.
    native_depth: u32,
    /// Only while printing a deep tree, which takes it back before
    /// returning. (Not dropped with the printer: a field to drop makes
    /// every name measurably slower.)
    deep: ManuallyDrop<Option<Box<Deep>>>,
    pub failed: bool,
}

impl<'p, 'a> Printer<'p, 'a> {
    pub fn new(ast: &'p Ast<'a>, out: Vec<u8>) -> Self {
        Self {
            ast,
            out,
            pack_index: NO_PACK,
            pack_max: NO_PACK,
            paren_depth: 0,
            inside_template: false,
            printing: vec![false; ast.nodes.len()],
            depth: 0,
            limit: NATIVE_DEPTH,
            native_depth: NATIVE_DEPTH,
            deep: ManuallyDrop::new(None),
            failed: false,
        }
    }

    /// Recurses at most `n` (at least 1) levels on the thread's stack, for
    /// testing.
    pub fn set_native_depth(&mut self, n: u32) {
        self.native_depth = n.clamp(1, MAX_DEPTH);
        self.limit = self.native_depth;
    }

    /// Prints the tree at `id`.
    pub fn print_all(&mut self, id: NodeId) {
        self.top(Goal::Print(id));
    }

    /// Prints the short form of the tree at `id` (see [`Printer::short`]).
    pub fn short_all(&mut self, id: NodeId) {
        self.top(Goal::TopShort(id));
    }

    fn top(&mut self, goal: Goal) {
        let start = self.out.len();
        self.call(goal);
        if self.deep.is_some() {
            self.drive(goal, start);
            // (Dropped here, not with the printer.)
            *self.deep = None;
        }
    }

    fn call(&mut self, goal: Goal) {
        match goal {
            Goal::Print(id) => self.print(id),
            Goal::TopShort(id) => self.short(id),
            Goal::Left(id) => self.left_inner(id),
            Goal::Right(id) => self.right_inner(id),
            Goal::Short(id) => self.short_inner(id),
        }
    }

    /// A call past this run's levels: failing past [`MAX_DEPTH`]; what
    /// [`Printer::drive`] has for it, if it has run it; else the call is
    /// left for it to run, and this run unwinds (as if it had failed).
    #[cold]
    #[inline(never)]
    fn boundary(&mut self, goal: Goal) {
        if self.failed {
            return;
        }
        let depth = self.depth;
        let deep = match self.deep.as_deref_mut() {
            Some(deep) if deep.base + depth >= MAX_DEPTH => {
                self.failed = true;
                return;
            }
            Some(deep) => deep,
            None if depth >= MAX_DEPTH => {
                self.failed = true;
                return;
            }
            None => {
                self.deep = ManuallyDrop::new(Some(Box::default()));
                let Some(deep) = self.deep.as_deref_mut() else {
                    return;
                };
                deep
            }
        };
        if let Some(d) = deep.done.get(deep.done_at) {
            deep.done_at += 1;
            deep.spent += d.text.len() + 1;
            debug_assert_eq!(d.goal, goal);
            if self.out.len() + d.text.len() > MAX_OUTPUT {
                self.failed = true;
                return;
            }
            self.out.extend_from_slice(&d.text);
            let e = &d.exit;
            self.pack_index = e.pack_index;
            self.pack_max = e.pack_max;
            self.paren_depth = e.paren_depth;
            self.inside_template = e.inside_template;
            self.failed = e.failed;
            return;
        }
        let base = deep.base + depth;
        let entry = self.snapshot(true);
        let prefix = self.out.clone();
        if let Some(deep) = self.deep.as_deref_mut() {
            deep.spent += prefix.len();
            deep.pending = Some(Call {
                goal,
                entry,
                prefix,
                base,
            });
        }
        self.limit = 0;
        self.failed = true;
    }

    fn snapshot(&self, guards: bool) -> State {
        let guarded = if guards {
            (0..self.printing.len())
                .filter(|&i| self.printing[i])
                .filter_map(|i| NodeId::try_from(i).ok())
                .collect()
        } else {
            Vec::new()
        };
        State {
            out: self.out.len(),
            pack_index: self.pack_index,
            pack_max: self.pack_max,
            paren_depth: self.paren_depth,
            inside_template: self.inside_template,
            failed: self.failed,
            guarded,
        }
    }

    /// Prints a tree nested past [`NATIVE_DEPTH`], once a run has left a
    /// call for it ([`Printer::boundary`]); as `Parser::drive` parses a
    /// name nested that deep. The thread's stack holds at most
    /// `NATIVE_DEPTH` levels at a time: a call that would go deeper is
    /// instead run here, by itself, from the printer as it was at the
    /// call, and the run that made it is run again from its start. Printing
    /// is deterministic, so that run makes the same calls in the same
    /// order, with the same output so far; each time it reaches a call run
    /// here, it takes what that call wrote (and the printer after it) and
    /// goes on, until it reaches a call not yet run (which runs next) or
    /// its end. The output is what printing on the thread's stack alone
    /// would write. The work is bounded ([`MAX_DEEP_WORK`]).
    #[cold]
    #[inline(never)]
    fn drive(&mut self, root: Goal, start: usize) {
        let mut tasks = vec![Task {
            goal: root,
            entry: State {
                out: start,
                pack_index: NO_PACK,
                pack_max: NO_PACK,
                ..State::default()
            },
            prefix: None,
            base: 0,
            depth: 0,
            done: Vec::new(),
        }];
        loop {
            let Some(deep) = self.deep.as_deref_mut() else {
                return;
            };
            if let Some(call) = deep.pending.take() {
                let Some(top) = tasks.last_mut() else {
                    return;
                };
                top.done = mem::take(&mut deep.done);
                deep.spent += call.entry.guarded.len() + self.printing.len() / 8 + 1;
                tasks.push(Task {
                    goal: call.goal,
                    entry: call.entry,
                    prefix: Some(call.prefix),
                    base: call.base,
                    depth: 1,
                    done: Vec::new(),
                });
            } else {
                let Some(task) = tasks.pop() else {
                    return;
                };
                let Some(parent) = tasks.last_mut() else {
                    return;
                };
                let text = self.out[task.entry.out..].to_vec();
                deep.spent += text.len() + 1;
                parent.done.push(Done {
                    goal: task.goal,
                    exit: self.snapshot(false),
                    text,
                });
            }
            let Some(top) = tasks.last_mut() else {
                return;
            };
            // Back to the printer at the call.
            let e = &top.entry;
            match &top.prefix {
                Some(prefix) => {
                    self.out.clone_from(prefix);
                    deep_spent_extra(&mut self.deep, prefix.len());
                }
                None => self.out.truncate(e.out),
            }
            self.pack_index = e.pack_index;
            self.pack_max = e.pack_max;
            self.paren_depth = e.paren_depth;
            self.inside_template = e.inside_template;
            self.failed = e.failed;
            self.printing.fill(false);
            for &g in &e.guarded {
                self.printing[g as usize] = true;
            }
            let Some(deep) = self.deep.as_deref_mut() else {
                return;
            };
            deep.spent += self.printing.len() / 8 + 1;
            if deep.spent > MAX_DEEP_WORK {
                self.failed = true;
                return;
            }
            deep.base = top.base;
            deep.done = mem::take(&mut top.done);
            deep.done_at = 0;
            self.depth = top.depth;
            self.limit = self.native_depth.min(MAX_DEPTH - top.base);
            let goal = top.goal;
            self.call(goal);
        }
    }

    fn node(&self, id: NodeId) -> Node<'a> {
        *self.ast.node(id)
    }

    fn meta(&self, id: NodeId) -> Meta {
        self.ast.meta[id as usize]
    }

    fn list(&self, l: List) -> &'p [NodeId] {
        let ast: &'p Ast<'a> = self.ast;
        ast.list(l)
    }

    fn push(&mut self, s: &[u8]) {
        if self.out.len() + s.len() > MAX_OUTPUT {
            self.failed = true;
            return;
        }
        self.out.extend_from_slice(s);
    }

    fn push_byte(&mut self, c: u8) {
        self.push(&[c]);
    }

    fn open(&mut self, c: u8) {
        if self.inside_template {
            self.paren_depth = self.paren_depth.wrapping_add(1);
        }
        self.push_byte(c);
    }

    fn close(&mut self, c: u8) {
        if self.inside_template {
            self.paren_depth = self.paren_depth.wrapping_sub(1);
        }
        self.push_byte(c);
    }

    fn push_number(&mut self, n: u64) {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut n = n;
        loop {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.push(&buf[i..]);
    }

    /// A number as mangled (`n` for minus).
    fn push_signed(&mut self, s: &[u8]) {
        match s.split_first() {
            Some((b'n', rest)) => {
                self.push_byte(b'-');
                self.push(rest);
            }
            _ => self.push(s),
        }
    }

    /// The short form of a name, as abseil's demangler (and so bloaty's
    /// `shortsymbols`) prints it: no parameter types (`f()`), no template
    /// arguments (`f<>()`), no return types, qualifiers, or clone
    /// suffixes; closures and unnamed types as `{lambda()#1}` and
    /// `{unnamed type#1}`. Types that are part of a name (conversion
    /// operators, special names) print in full.
    pub fn short(&mut self, id: NodeId) {
        if self.failed || self.depth >= self.limit {
            return self.boundary(Goal::Short(id));
        }
        self.depth += 1;
        self.short_inner(id);
        self.depth -= 1;
    }

    fn short_inner(&mut self, id: NodeId) {
        match self.node(id) {
            Node::DotSuffix { prefix, .. } => self.short(prefix),
            Node::FunctionEncoding { name, .. } => {
                self.short(name);
                self.push(b"()");
            }
            Node::NameWithTemplateArgs { name, .. } => {
                self.short(name);
                self.push(b"<>");
            }
            Node::NestedName { qual, name } => {
                self.short(qual);
                self.push(b"::");
                self.short(name);
            }
            Node::MemberLikeFriendName { qual, name } => {
                self.short(qual);
                self.push(b"::friend ");
                self.short(name);
            }
            Node::LocalName { encoding, entity } => {
                self.short(encoding);
                self.push(b"::");
                self.short(entity);
            }
            Node::QualifiedName { qualifier, name } => {
                self.short(qualifier);
                self.push(b"::");
                self.short(name);
            }
            Node::GlobalQualifiedName(child) => {
                self.push(b"::");
                self.short(child);
            }
            Node::AbiTagAttr { base, tag } => {
                self.short(base);
                self.push(b"[abi:");
                self.push(tag);
                self.push(b"]");
            }
            Node::ModuleEntity { name, .. } => self.short(name),
            Node::SpecialName { special, child } => {
                self.push(special);
                self.short(child);
            }
            Node::ClosureTypeName { count, .. } => {
                self.push(b"{lambda()#");
                self.push_number(discriminator(count));
                self.push(b"}");
            }
            Node::UnnamedTypeName(count) => {
                self.push(b"{unnamed type#");
                self.push_number(discriminator(count));
                self.push(b"}");
            }
            Node::QualType { child, .. } => self.short(child),
            Node::ForwardTemplateReference { slot, .. } => {
                if self.guard(id) {
                    if let Some(t) = self.forward_target(slot) {
                        self.short(t);
                    }
                    self.unguard(id);
                }
            }
            _ => self.print(id),
        }
    }

    pub fn print(&mut self, id: NodeId) {
        self.left(id);
        if self.meta(id).rhs != Cache::No {
            self.right(id);
        }
    }

    fn print_as_operand(&mut self, id: NodeId, prec: Prec, strictly_worse: bool) {
        let paren = self.meta(id).prec as u32 >= prec as u32 + u32::from(strictly_worse);
        if paren {
            self.open(b'(');
        }
        self.print(id);
        if paren {
            self.close(b')');
        }
    }

    fn print_with_comma(&mut self, l: List) {
        let mut first = true;
        for &e in self.list(l) {
            let before = self.out.len();
            if !first {
                self.push(b", ");
            }
            let after = self.out.len();
            self.print_as_operand(e, Prec::Comma, false);
            // An empty pack expansion: take back the comma.
            if self.out.len() == after {
                self.out.truncate(before);
                continue;
            }
            first = false;
        }
    }

    fn guard(&mut self, id: NodeId) -> bool {
        let p = &mut self.printing[id as usize];
        if *p {
            return false;
        }
        *p = true;
        true
    }

    fn unguard(&mut self, id: NodeId) {
        self.printing[id as usize] = false;
    }

    fn forward_target(&mut self, slot: u32) -> Option<NodeId> {
        let t = self.ast.forward.get(slot as usize).copied().flatten();
        if t.is_none() {
            self.failed = true;
        }
        t
    }

    fn init_pack(&mut self, len: u32) {
        if self.pack_max == NO_PACK {
            self.pack_max = len;
            self.pack_index = 0;
        }
    }

    /// The pack element being printed, if any.
    fn pack_element(&mut self, l: List) -> Option<NodeId> {
        self.init_pack(l.len);
        self.list(l).get(self.pack_index as usize).copied()
    }

    fn has_rhs(&mut self, id: NodeId) -> bool {
        self.has(id, Has::Rhs)
    }

    fn has_array(&mut self, id: NodeId) -> bool {
        self.has(id, Has::Array)
    }

    fn has_function(&mut self, id: NodeId) -> bool {
        self.has(id, Has::Function)
    }

    /// Whether `id` has a part after the name, is an array, or is a
    /// function: following qualifiers, pointers (for `Has::Rhs`), pack
    /// elements, and forward references down to a node that knows.
    fn has(&mut self, id: NodeId, what: Has) -> bool {
        let mut id = id;
        // The forward references followed (each guarded on the way).
        let mut guarded = Vec::new();
        let r = loop {
            let m = self.meta(id);
            match match what {
                Has::Rhs => m.rhs,
                Has::Array => m.array,
                Has::Function => m.function,
            } {
                Cache::Yes => break true,
                Cache::No => break false,
                Cache::Unknown => {}
            }
            match (self.node(id), what) {
                (Node::QualType { child, .. }, _) => id = child,
                (Node::PointerType(p) | Node::ReferenceType { pointee: p, .. }, Has::Rhs) => {
                    id = p;
                }
                (Node::PointerToMemberType { member, .. }, Has::Rhs) => id = member,
                (Node::ArrayType { .. }, Has::Rhs | Has::Array)
                | (
                    Node::FunctionType { .. } | Node::FunctionEncoding { .. },
                    Has::Rhs | Has::Function,
                ) => {
                    break true;
                }
                (Node::ParameterPack(l), _) => match self.pack_element(l) {
                    Some(e) => id = e,
                    None => break false,
                },
                (Node::ForwardTemplateReference { slot, .. }, _) => {
                    if !self.guard(id) {
                        break false;
                    }
                    guarded.push(id);
                    match self.forward_target(slot) {
                        Some(t) => id = t,
                        None => break false,
                    }
                }
                _ => break false,
            }
        };
        for g in guarded {
            self.unguard(g);
        }
        r
    }

    /// The node a pack element or forward reference stands for.
    fn syntax_node(&mut self, id: NodeId) -> NodeId {
        let mut id = id;
        let mut guarded = Vec::new();
        let r = loop {
            match self.node(id) {
                Node::ParameterPack(l) => match self.pack_element(l) {
                    Some(e) => id = e,
                    None => break id,
                },
                Node::ForwardTemplateReference { slot, .. } => {
                    if !self.guard(id) {
                        break id;
                    }
                    guarded.push(id);
                    match self.forward_target(slot) {
                        Some(t) => id = t,
                        None => break id,
                    }
                }
                _ => break id,
            }
        };
        for g in guarded {
            self.unguard(g);
        }
        r
    }

    /// A reference to a reference collapses: `&` unless both are `&&`.
    /// `None` on a cycle.
    fn collapse(&mut self, rvalue: bool, pointee: NodeId) -> Option<(bool, NodeId)> {
        let (mut rv, mut p) = (rvalue, pointee);
        let mut prev: Vec<NodeId> = Vec::new();
        loop {
            let sn = self.syntax_node(p);
            let Node::ReferenceType { pointee, rvalue } = self.node(sn) else {
                break;
            };
            p = pointee;
            rv = rv && rvalue;
            prev.push(p);
            if prev.len() > 1 && p == prev[(prev.len() - 1) / 2] {
                return None;
            }
            if self.failed {
                return None;
            }
        }
        Some((rv, p))
    }

    fn is_objc_object(&self, pointee: NodeId) -> Option<&'a [u8]> {
        match self.node(pointee) {
            Node::ObjCProtoName { ty, protocol }
                if self.node(ty) == Node::NameType(b"objc_object") =>
            {
                Some(protocol)
            }
            _ => None,
        }
    }

    fn left(&mut self, id: NodeId) {
        if self.failed || self.depth >= self.limit {
            return self.boundary(Goal::Left(id));
        }
        self.depth += 1;
        self.left_inner(id);
        self.depth -= 1;
    }

    fn right(&mut self, id: NodeId) {
        if self.failed || self.depth >= self.limit {
            return self.boundary(Goal::Right(id));
        }
        self.depth += 1;
        self.right_inner(id);
        self.depth -= 1;
    }

    fn quals(&mut self, q: u8) {
        if q & QUAL_CONST != 0 {
            self.push(b" const");
        }
        if q & QUAL_VOLATILE != 0 {
            self.push(b" volatile");
        }
        if q & QUAL_RESTRICT != 0 {
            self.push(b" restrict");
        }
    }

    fn ref_qual(&mut self, r: RefQual) {
        match r {
            RefQual::None => {}
            RefQual::LValue => self.push(b" &"),
            RefQual::RValue => self.push(b" &&"),
        }
    }

    fn with_template<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let saved = core::mem::replace(&mut self.inside_template, true);
        let r = f(self);
        self.inside_template = saved;
        r
    }

    /// A `ParameterPackExpansion` of `child`: each element of the pack
    /// inside, comma-separated.
    fn pack_expansion(&mut self, child: NodeId) {
        let saved = (self.pack_index, self.pack_max);
        self.pack_index = NO_PACK;
        self.pack_max = NO_PACK;
        let start = self.out.len();
        self.print(child);
        if self.pack_max == NO_PACK {
            self.push(b"...");
        } else if self.pack_max == 0 {
            self.out.truncate(start);
        } else {
            for i in 1..self.pack_max {
                if self.failed {
                    break;
                }
                self.push(b", ");
                self.pack_index = i;
                self.print(child);
            }
        }
        (self.pack_index, self.pack_max) = saved;
    }

    fn closure_declarator(
        &mut self,
        template_params: List,
        requires1: Option<NodeId>,
        params: List,
        requires2: Option<NodeId>,
    ) {
        if !template_params.is_empty() {
            self.with_template(|p| {
                p.push(b"<");
                p.print_with_comma(template_params);
                p.push(b">");
            });
        }
        if let Some(r) = requires1 {
            self.push(b" requires ");
            self.print(r);
            self.push(b" ");
        }
        self.open(b'(');
        self.print_with_comma(params);
        self.close(b')');
        if let Some(r) = requires2 {
            self.push(b" requires ");
            self.print(r);
        }
    }

    fn left_inner(&mut self, id: NodeId) {
        match self.node(id) {
            Node::NodeArray(l) | Node::TemplateArgumentPack(l) => self.print_with_comma(l),
            Node::DotSuffix { prefix, suffix } => {
                self.print(prefix);
                self.push(b" (");
                self.push(suffix);
                self.push(b")");
            }
            Node::VendorExtQualType { ty, ext, args } => {
                self.print(ty);
                self.push(b" ");
                self.push(ext);
                if let Some(a) = args {
                    self.print(a);
                }
            }
            Node::QualType { child, quals } => {
                self.left(child);
                self.quals(quals);
            }
            Node::ConversionOperatorType(ty) => {
                self.push(b"operator ");
                self.print(ty);
            }
            Node::PostfixQualifiedType { ty, postfix } => {
                self.left(ty);
                self.push(postfix);
            }
            Node::ElaboratedTypeSpefType { kind, child } => {
                self.push(kind);
                self.push(b" ");
                self.print(child);
            }
            Node::TransformedType { transform, base } => {
                self.push(transform);
                self.push(b"(");
                self.print(base);
                self.push(b")");
            }
            Node::NameType(n) => self.push(n),
            Node::AbiTagAttr { base, tag } => {
                self.left(base);
                self.push(b"[abi:");
                self.push(tag);
                self.push(b"]");
            }
            Node::EnableIfAttr(l) => {
                self.push(b" [enable_if:");
                self.print_with_comma(l);
                self.push(b"]");
            }
            Node::ObjCProtoName { ty, protocol } => {
                self.print(ty);
                self.push(b"<");
                self.push(protocol);
                self.push(b">");
            }
            Node::PointerType(p) => {
                if let Some(proto) = self.is_objc_object(p) {
                    self.push(b"id<");
                    self.push(proto);
                    self.push(b">");
                } else {
                    self.left(p);
                    let array = self.has_array(p);
                    if array {
                        self.push(b" ");
                    }
                    if array || self.has_function(p) {
                        self.push(b"(");
                    }
                    self.push(b"*");
                }
            }
            Node::ReferenceType { pointee, rvalue } => {
                if !self.guard(id) {
                    return;
                }
                if let Some((rv, p)) = self.collapse(rvalue, pointee) {
                    self.left(p);
                    let array = self.has_array(p);
                    if array {
                        self.push(b" ");
                    }
                    if array || self.has_function(p) {
                        self.push(b"(");
                    }
                    self.push(if rv { b"&&" } else { b"&" });
                }
                self.unguard(id);
            }
            Node::PointerToMemberType { class, member } => {
                self.left(member);
                if self.has_array(member) || self.has_function(member) {
                    self.push(b"(");
                } else {
                    self.push(b" ");
                }
                self.print(class);
                self.push(b"::*");
            }
            Node::ArrayType { base, .. } => self.left(base),
            Node::FunctionType { ret, .. } => {
                self.left(ret);
                self.push(b" ");
            }
            Node::NoexceptSpec(e) => {
                self.push(b"noexcept");
                self.open(b'(');
                self.print_as_operand(e, Prec::Default, false);
                self.close(b')');
            }
            Node::DynamicExceptionSpec(l) => {
                self.push(b"throw");
                self.open(b'(');
                self.print_with_comma(l);
                self.close(b')');
            }
            Node::ExplicitObjectParameter(base) => {
                self.push(b"this ");
                self.print(base);
            }
            Node::FunctionEncoding { ret, name, .. } => {
                if let Some(r) = ret {
                    self.left(r);
                    if !self.has_rhs(r) {
                        self.push(b" ");
                    }
                }
                self.print(name);
            }
            Node::LiteralOperator(op) => {
                self.push(b"operator\"\" ");
                self.print(op);
            }
            Node::SpecialName { special, child } => {
                self.push(special);
                self.print(child);
            }
            Node::CtorVtableSpecialName { first, second } => {
                self.push(b"construction vtable for ");
                self.print(first);
                self.push(b"-in-");
                self.print(second);
            }
            Node::NestedName { qual, name } => {
                self.print(qual);
                self.push(b"::");
                self.print(name);
            }
            Node::MemberLikeFriendName { qual, name } => {
                self.print(qual);
                self.push(b"::friend ");
                self.print(name);
            }
            Node::ModuleName {
                parent,
                name,
                partition,
            } => {
                if let Some(p) = parent {
                    self.print(p);
                }
                if parent.is_some() || partition {
                    self.push_byte(if partition { b':' } else { b'.' });
                }
                self.print(name);
            }
            Node::ModuleEntity { module, name } => {
                self.print(name);
                self.push_byte(b'@');
                self.print(module);
            }
            Node::LocalName { encoding, entity } => {
                self.print(encoding);
                self.push(b"::");
                self.print(entity);
            }
            Node::QualifiedName { qualifier, name } => {
                self.print(qualifier);
                self.push(b"::");
                self.print(name);
            }
            Node::VectorType { base, dimension } => {
                self.print(base);
                self.push(b" vector[");
                if let Some(d) = dimension {
                    self.print(d);
                }
                self.push(b"]");
            }
            Node::PixelVectorType(d) => {
                self.push(b"pixel vector[");
                self.print(d);
                self.push(b"]");
            }
            Node::BinaryFPType(d) => {
                self.push(b"_Float");
                self.print(d);
            }
            Node::BitIntType { size, signed } => {
                if !signed {
                    self.push(b"unsigned ");
                }
                self.push(b"_BitInt");
                self.open(b'(');
                self.print_as_operand(size, Prec::Default, false);
                self.close(b')');
            }
            Node::SyntheticTemplateParamName { kind, index } => {
                self.push(match kind {
                    ParamKind::Type => b"$T",
                    ParamKind::NonType => b"$N",
                    ParamKind::Template => b"$TT",
                });
                if index > 0 {
                    self.push_number(u64::from(index - 1));
                }
            }
            Node::TemplateParamQualifiedArg { arg, .. } => self.print(arg),
            Node::TypeTemplateParamDecl(_) => self.push(b"typename "),
            Node::ConstrainedTypeTemplateParamDecl { constraint, .. } => {
                self.print(constraint);
                self.push(b" ");
            }
            Node::NonTypeTemplateParamDecl { ty, .. } => {
                self.left(ty);
                if !self.has_rhs(ty) {
                    self.push(b" ");
                }
            }
            Node::TemplateTemplateParamDecl { params, .. } => {
                self.with_template(|p| {
                    p.push(b"template<");
                    p.print_with_comma(params);
                    p.push(b"> typename ");
                });
            }
            Node::TemplateParamPackDecl(param) => {
                self.left(param);
                self.push(b"...");
            }
            Node::ParameterPack(l) => {
                if let Some(e) = self.pack_element(l) {
                    self.left(e);
                }
            }
            Node::ParameterPackExpansion(child) => self.pack_expansion(child),
            Node::PackIndexing { pattern, index } => {
                self.open(b'(');
                self.pack_expansion(pattern);
                self.close(b')');
                self.open(b'[');
                self.left(index);
                self.close(b']');
            }
            Node::TemplateArgs { params, .. } => {
                self.with_template(|p| {
                    p.push(b"<");
                    p.print_with_comma(params);
                    p.push(b">");
                });
            }
            Node::ForwardTemplateReference { slot, .. } => {
                if !self.guard(id) {
                    return;
                }
                if let Some(t) = self.forward_target(slot) {
                    self.left(t);
                }
                self.unguard(id);
            }
            Node::NameWithTemplateArgs { name, args } => {
                self.print(name);
                self.print(args);
            }
            Node::GlobalQualifiedName(child) => {
                self.push(b"::");
                self.print(child);
            }
            Node::ExpandedSpecialSubstitution(k) => {
                self.push(b"std::");
                self.push(self.ast.base_name(id));
                if k >= SpecialSub::String {
                    self.push(b"<char, std::char_traits<char>");
                    if k == SpecialSub::String {
                        self.push(b", std::allocator<char>");
                    }
                    self.push(b">");
                }
            }
            Node::SpecialSubstitution(_) => {
                self.push(b"std::");
                self.push(self.ast.base_name(id));
            }
            Node::CtorDtorName { base, dtor, .. } => {
                if dtor {
                    self.push(b"~");
                }
                self.push(self.ast.base_name(base));
            }
            Node::DtorName(base) => {
                self.push(b"~");
                self.left(base);
            }
            Node::UnnamedTypeName(count) => {
                self.push(b"'unnamed");
                self.push(count);
                self.push(b"'");
            }
            Node::ClosureTypeName {
                template_params,
                requires1,
                params,
                requires2,
                count,
            } => {
                self.push(b"'lambda");
                self.push(count);
                self.push(b"'");
                self.closure_declarator(template_params, requires1, params, requires2);
            }
            Node::StructuredBindingName(l) => {
                self.open(b'[');
                self.print_with_comma(l);
                self.close(b']');
            }
            Node::BinaryExpr { lhs, op, rhs } => {
                let prec = self.meta(id).prec;
                let paren_all = self.paren_depth == 0 && (op == b">" || op == b">>");
                if paren_all {
                    self.open(b'(');
                }
                let assign = prec == Prec::Assign;
                self.print_as_operand(lhs, if assign { Prec::OrIf } else { prec }, !assign);
                if op != b"," {
                    self.push(b" ");
                }
                self.push(op);
                self.push(b" ");
                self.print_as_operand(rhs, prec, assign);
                if paren_all {
                    self.close(b')');
                }
            }
            Node::ArraySubscriptExpr { op1, op2 } => {
                let prec = self.meta(id).prec;
                self.print_as_operand(op1, prec, false);
                self.open(b'[');
                self.print_as_operand(op2, Prec::Default, false);
                self.close(b']');
            }
            Node::PostfixExpr { child, op } => {
                let prec = self.meta(id).prec;
                self.print_as_operand(child, prec, true);
                self.push(op);
            }
            Node::ConditionalExpr {
                cond,
                then,
                otherwise,
            } => {
                let prec = self.meta(id).prec;
                self.print_as_operand(cond, prec, false);
                self.push(b" ? ");
                self.print_as_operand(then, Prec::Default, false);
                self.push(b" : ");
                self.print_as_operand(otherwise, Prec::Assign, true);
            }
            Node::MemberExpr { lhs, kind, rhs } => {
                let prec = self.meta(id).prec;
                self.print_as_operand(lhs, prec, true);
                self.push(kind);
                self.print_as_operand(rhs, prec, false);
            }
            Node::SubobjectExpr {
                ty, sub, offset, ..
            } => {
                self.print(sub);
                self.push(b".<");
                self.print(ty);
                self.push(b" at offset ");
                if offset.is_empty() {
                    self.push(b"0");
                } else {
                    self.push_signed(offset);
                }
                self.push(b">");
            }
            Node::EnclosingExpr { prefix, infix } => {
                self.push(prefix);
                self.open(b'(');
                self.print(infix);
                self.close(b')');
            }
            Node::CastExpr { kind, to, from } => {
                self.push(kind);
                self.with_template(|p| {
                    p.push(b"<");
                    p.left(to);
                    p.push(b">");
                });
                self.open(b'(');
                self.print_as_operand(from, Prec::Default, false);
                self.close(b')');
            }
            Node::SizeofParamPackExpr(pack) => {
                self.push(b"sizeof...");
                self.open(b'(');
                self.pack_expansion(pack);
                self.close(b')');
            }
            Node::CallExpr {
                callee,
                args,
                paren,
            } => {
                if paren {
                    self.open(b'(');
                }
                self.print(callee);
                if paren {
                    self.close(b')');
                }
                self.open(b'(');
                self.print_with_comma(args);
                self.close(b')');
            }
            Node::NewExpr {
                exprs,
                ty,
                inits,
                global,
                array,
            } => {
                if global {
                    self.push(b"::");
                }
                self.push(b"new");
                if array {
                    self.push(b"[]");
                }
                if !exprs.is_empty() {
                    self.open(b'(');
                    self.print_with_comma(exprs);
                    self.close(b')');
                }
                self.push(b" ");
                self.print(ty);
                if !inits.is_empty() {
                    self.open(b'(');
                    self.print_with_comma(inits);
                    self.close(b')');
                }
            }
            Node::DeleteExpr { op, global, array } => {
                if global {
                    self.push(b"::");
                }
                self.push(b"delete");
                if array {
                    self.push(b"[]");
                }
                self.push(b" ");
                self.print(op);
            }
            Node::PrefixExpr { prefix, child } => {
                let prec = self.meta(id).prec;
                self.push(prefix);
                self.print_as_operand(child, prec, false);
            }
            Node::FunctionParam(n) => {
                self.push(b"fp");
                self.push(n);
            }
            Node::ConversionExpr { ty, exprs } => {
                self.open(b'(');
                self.print(ty);
                self.close(b')');
                self.open(b'(');
                self.print_with_comma(exprs);
                self.close(b')');
            }
            Node::PointerToMemberConversionExpr { ty, sub } => {
                self.open(b'(');
                self.print(ty);
                self.close(b')');
                self.open(b'(');
                self.print(sub);
                self.close(b')');
            }
            Node::InitListExpr { ty, inits } => {
                if let Some(t) = ty {
                    if self.print_init_list_as_type(t, inits) {
                        return;
                    }
                    self.print(t);
                }
                self.push(b"{");
                self.print_with_comma(inits);
                self.push(b"}");
            }
            Node::FoldExpr {
                left,
                op,
                pack,
                init,
            } => {
                self.open(b'(');
                if !left || init.is_some() {
                    if left {
                        if let Some(i) = init {
                            self.print_as_operand(i, Prec::Cast, true);
                        }
                    } else {
                        self.fold_pack(pack);
                    }
                    self.push(b" ");
                    self.push(op);
                    self.push(b" ");
                }
                self.push(b"...");
                if left || init.is_some() {
                    self.push(b" ");
                    self.push(op);
                    self.push(b" ");
                    if left {
                        self.fold_pack(pack);
                    } else if let Some(i) = init {
                        self.print_as_operand(i, Prec::Cast, true);
                    }
                }
                self.close(b')');
            }
            Node::ThrowExpr(op) => {
                self.push(b"throw ");
                self.print(op);
            }
            Node::BoolExpr(v) => self.push(if v { b"true" } else { b"false" }),
            Node::StringLiteral(ty) => {
                self.push(b"\"<");
                self.print(ty);
                self.push(b">\"");
            }
            Node::LambdaExpr(ty) => {
                self.push(b"[]");
                if let Node::ClosureTypeName {
                    template_params,
                    requires1,
                    params,
                    requires2,
                    ..
                } = self.node(ty)
                {
                    self.closure_declarator(template_params, requires1, params, requires2);
                }
                self.push(b"{...}");
            }
            Node::EnumLiteral { ty, integer } => {
                self.open(b'(');
                self.print(ty);
                self.close(b')');
                self.push_signed(integer);
            }
            Node::IntegerLiteral { ty, value } => {
                if ty.len() > 3 {
                    self.open(b'(');
                    self.push(ty);
                    self.close(b')');
                }
                self.push_signed(value);
                if ty.len() <= 3 {
                    self.push(ty);
                }
            }
            Node::FloatLiteral { kind, contents } => self.float(kind, contents),
            Node::BracedExpr { elem, init, array } => {
                if array {
                    self.push(b"[");
                    self.print(elem);
                    self.push(b"]");
                } else {
                    self.push(b".");
                    self.print(elem);
                }
                if !matches!(
                    self.node(init),
                    Node::BracedExpr { .. } | Node::BracedRangeExpr { .. }
                ) {
                    self.push(b" = ");
                }
                self.print(init);
            }
            Node::BracedRangeExpr { first, last, init } => {
                self.push(b"[");
                self.print(first);
                self.push(b" ... ");
                self.print(last);
                self.push(b"]");
                if !matches!(
                    self.node(init),
                    Node::BracedExpr { .. } | Node::BracedRangeExpr { .. }
                ) {
                    self.push(b" = ");
                }
                self.print(init);
            }
            Node::RequiresExpr {
                params,
                requirements,
            } => {
                self.push(b"requires");
                if !params.is_empty() {
                    self.push(b" ");
                    self.open(b'(');
                    self.print_with_comma(params);
                    self.close(b')');
                }
                self.push(b" ");
                self.open(b'{');
                for &r in self.list(requirements) {
                    self.print(r);
                }
                self.push(b" ");
                self.close(b'}');
            }
            Node::ExprRequirement {
                expr,
                noexcept,
                constraint,
            } => {
                self.push(b" ");
                let braced = noexcept || constraint.is_some();
                if braced {
                    self.open(b'{');
                }
                self.print(expr);
                if braced {
                    self.close(b'}');
                }
                if noexcept {
                    self.push(b" noexcept");
                }
                if let Some(c) = constraint {
                    self.push(b" -> ");
                    self.print(c);
                }
                self.push(b";");
            }
            Node::TypeRequirement(t) => {
                self.push(b" typename ");
                self.print(t);
                self.push(b";");
            }
            Node::NestedRequirement(c) => {
                self.push(b" requires ");
                self.print(c);
                self.push(b";");
            }
        }
    }

    fn fold_pack(&mut self, pack: NodeId) {
        self.open(b'(');
        self.pack_expansion(pack);
        self.close(b')');
    }

    fn right_inner(&mut self, id: NodeId) {
        match self.node(id) {
            Node::QualType { child, .. } => self.right(child),
            Node::PointerType(p) => {
                if self.is_objc_object(p).is_none() {
                    if self.has_array(p) || self.has_function(p) {
                        self.push(b")");
                    }
                    self.right(p);
                }
            }
            Node::ReferenceType { pointee, rvalue } => {
                if !self.guard(id) {
                    return;
                }
                if let Some((_, p)) = self.collapse(rvalue, pointee) {
                    if self.has_array(p) || self.has_function(p) {
                        self.push(b")");
                    }
                    self.right(p);
                }
                self.unguard(id);
            }
            Node::PointerToMemberType { member, .. } => {
                if self.has_array(member) || self.has_function(member) {
                    self.push(b")");
                }
                self.right(member);
            }
            Node::ArrayType { base, dimension } => {
                if self.out.last() != Some(&b']') {
                    self.push(b" ");
                }
                self.push(b"[");
                if let Some(d) = dimension {
                    self.print(d);
                }
                self.push(b"]");
                self.right(base);
            }
            Node::FunctionType {
                ret,
                params,
                cv,
                ref_qual,
                exception,
            } => {
                self.open(b'(');
                self.print_with_comma(params);
                self.close(b')');
                self.right(ret);
                self.quals(cv);
                self.ref_qual(ref_qual);
                if let Some(e) = exception {
                    self.push(b" ");
                    self.print(e);
                }
            }
            Node::FunctionEncoding {
                ret,
                params,
                attrs,
                requires,
                cv,
                ref_qual,
                ..
            } => {
                self.open(b'(');
                self.print_with_comma(params);
                self.close(b')');
                if let Some(r) = ret {
                    self.right(r);
                }
                self.quals(cv);
                self.ref_qual(ref_qual);
                if let Some(a) = attrs {
                    self.print(a);
                }
                if let Some(r) = requires {
                    self.push(b" requires ");
                    self.print(r);
                }
            }
            Node::TypeTemplateParamDecl(name)
            | Node::ConstrainedTypeTemplateParamDecl { name, .. } => self.print(name),
            Node::NonTypeTemplateParamDecl { name, ty } => {
                self.print(name);
                self.right(ty);
            }
            Node::TemplateTemplateParamDecl { name, requires, .. } => {
                self.print(name);
                if let Some(r) = requires {
                    self.push(b" requires ");
                    self.print(r);
                }
            }
            Node::TemplateParamPackDecl(param) => self.right(param),
            Node::ParameterPack(l) => {
                if let Some(e) = self.pack_element(l) {
                    self.right(e);
                }
            }
            Node::ForwardTemplateReference { slot, .. } => {
                if !self.guard(id) {
                    return;
                }
                if let Some(t) = self.forward_target(slot) {
                    self.right(t);
                }
                self.unguard(id);
            }
            _ => {}
        }
    }

    /// `char[N]{...}` of character codes prints as a string literal.
    fn print_init_list_as_type(&mut self, ty: NodeId, inits: List) -> bool {
        let Node::ArrayType { base, .. } = self.node(ty) else {
            return false;
        };
        if self.node(base) != Node::NameType(b"char") {
            return false;
        }
        let start = self.out.len();
        self.push(b"\"");
        let mut last_was_numeric = false;
        for &e in self.list(inits) {
            let Node::IntegerLiteral { value, .. } = self.node(e) else {
                self.out.truncate(start);
                return false;
            };
            let mut v: u32 = 0;
            for &c in value {
                if !c.is_ascii_digit() || v > 25 {
                    self.out.truncate(start);
                    return false;
                }
                v = v * 10 + u32::from(c - b'0');
            }
            if v > 255 {
                self.out.truncate(start);
                return false;
            }
            let Ok(c) = u8::try_from(v) else {
                self.out.truncate(start);
                return false;
            };
            if last_was_numeric && c.is_ascii_hexdigit() {
                self.push(b"\"\"");
            }
            last_was_numeric = false;
            match c {
                0x07 => self.push(b"\\a"),
                0x08 => self.push(b"\\b"),
                0x0C => self.push(b"\\f"),
                b'\n' => self.push(b"\\n"),
                b'\r' => self.push(b"\\r"),
                b'\t' => self.push(b"\\t"),
                0x0B => self.push(b"\\v"),
                b'"' => self.push(b"\\\""),
                b'\\' => self.push(b"\\\\"),
                c if c < 32 || c == 127 => {
                    const HEX: &[u8; 16] = b"0123456789ABCDEF";
                    self.push(b"\\");
                    if c > 7 {
                        self.push(b"x");
                    }
                    if c >= 16 {
                        self.push_byte(HEX[usize::from(c >> 4)]);
                    }
                    self.push_byte(HEX[usize::from(c & 0xF)]);
                    last_was_numeric = true;
                }
                c => self.push_byte(c),
            }
        }
        self.push(b"\"");
        true
    }

    /// A floating literal, as C's `%a` prints it (normalized: `0x1.4p+2`),
    /// with `f` for `float` and `L` for `long double`.
    fn float(&mut self, kind: FloatKind, hex: &[u8]) {
        let Some(bits) = parse_hex(hex) else {
            return;
        };
        match kind {
            FloatKind::Float => {
                let f = f32::from_bits(u32::try_from(bits).unwrap_or(0));
                self.hex_double(f64::from(f).to_bits());
                self.push(b"f");
            }
            FloatKind::Double => self.hex_double(u64::try_from(bits).unwrap_or(0)),
            FloatKind::LongDouble => {
                self.hex_x87(bits);
                self.push(b"L");
            }
        }
    }

    fn hex_double(&mut self, bits: u64) {
        let neg = bits >> 63 != 0;
        let exp = ((bits >> 52) & 0x7FF) as i64;
        let frac = bits & ((1 << 52) - 1);
        if exp == 0x7FF {
            if neg {
                self.push(b"-");
            }
            self.push(if frac == 0 { b"inf" } else { b"nan" });
            return;
        }
        if neg {
            self.push(b"-");
        }
        if exp == 0 && frac == 0 {
            self.push(b"0x0p+0");
            return;
        }
        // Subnormals as glibc writes them: 0x0.<fraction>p-1022.
        let (lead, e) = if exp == 0 {
            (b'0', -1022)
        } else {
            (b'1', exp - 1023)
        };
        self.push(b"0x");
        self.push_byte(lead);
        self.hex_fraction(frac << 12);
        self.exponent(e);
    }

    /// The x87 80-bit format: 16 bits of sign and exponent, then a 64-bit
    /// significand with an explicit integer bit.
    fn hex_x87(&mut self, bits: u128) {
        let mant = u64::try_from(bits & u128::from(u64::MAX)).unwrap_or(0);
        let se = u16::try_from((bits >> 64) & 0xFFFF).unwrap_or(0);
        let neg = se >> 15 != 0;
        let exp = i64::from(se & 0x7FFF);
        if neg {
            self.push(b"-");
        }
        if exp == 0x7FFF {
            self.push(if mant << 1 == 0 { b"inf" } else { b"nan" });
            return;
        }
        if mant == 0 {
            self.push(b"0x0p+0");
            return;
        }
        // Normalize: the leading 1 at the top.
        let shift = mant.leading_zeros();
        let m = mant << shift;
        let e = if exp == 0 { -16382 } else { exp - 16383 } - i64::from(shift);
        self.push(b"0x1");
        self.hex_fraction(m << 1);
        self.exponent(e);
    }

    /// `.` and the hex digits of a left-aligned fraction, trailing zeros
    /// dropped (nothing if it is zero).
    fn hex_fraction(&mut self, frac: u64) {
        if frac == 0 {
            return;
        }
        self.push(b".");
        let mut f = frac;
        while f != 0 {
            let d = (f >> 60) as u8;
            self.push_byte(if d < 10 { b'0' + d } else { b'a' + d - 10 });
            f <<= 4;
        }
    }

    fn exponent(&mut self, e: i64) {
        self.push(if e < 0 { b"p-" } else { b"p+" });
        self.push_number(e.unsigned_abs());
    }
}

/// A closure's or unnamed type's number as abseil shows it: the mangled
/// number plus 2 (none is 1).
fn discriminator(count: &[u8]) -> u64 {
    if count.is_empty() {
        return 1;
    }
    let mut n: u64 = 0;
    for &c in count {
        n = n.saturating_mul(10).saturating_add(u64::from(c - b'0'));
    }
    n.saturating_add(2)
}

fn parse_hex(s: &[u8]) -> Option<u128> {
    let mut v: u128 = 0;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        v = (v << 4) | u128::from(d);
    }
    Some(v)
}

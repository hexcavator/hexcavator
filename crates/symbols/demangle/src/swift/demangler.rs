// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Translated from the Swift project's lib/Demangling/Demangler.cpp (see
// LICENSE-SWIFT at the crate root); the structure and names follow it, so
// that the two can be compared function by function.

//! The demangler for Swift's current mangling (`$s`, `$S`, `_T0`, `$e`, and
//! their `_`-prefixed forms): a stack machine that builds a [`Tree`].

use alloc::string::String;
use alloc::vec::Vec;

use super::kinds::Kind;
use super::node::{NodeId, Tree};
use super::punycode;

type N = Option<NodeId>;

const MAX_NUM_WORDS: usize = 26;
const MAX_IDENTIFIER_LENGTH: usize = 4 * 1024 * 1024;
/// Swift's `SubstitutionMerging::MaxRepeatCount`.
const MAX_REPEAT_COUNT: i32 = 2048;
/// The deepest the demangler recurses (Swift relies on its stack).
pub const MAX_DEPTH: u32 = 1024;

pub const STDLIB_NAME: &str = "Swift";
pub const MANGLING_MODULE_OBJC: &str = "__C";
pub const MANGLING_MODULE_CLANG_IMPORTER: &str = "__C_Synthesized";
const ASYNC_MAIN_ENTRY_POINT_NAME: &str = "async_Main";

pub(crate) fn is_lower_letter(c: u8) -> bool {
    c.is_ascii_lowercase()
}
pub(crate) fn is_upper_letter(c: u8) -> bool {
    c.is_ascii_uppercase()
}
pub(crate) fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}
pub(crate) fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}
fn is_word_start(c: u8) -> bool {
    !is_digit(c) && c != b'_' && c != 0
}
fn is_word_end(c: u8, prev: u8) -> bool {
    c == b'_' || c == 0 || (!is_upper_letter(prev) && is_upper_letter(c))
}

fn is_decl_name(k: Kind) -> bool {
    matches!(
        k,
        Kind::Identifier
            | Kind::LocalDeclName
            | Kind::PrivateDeclName
            | Kind::RelatedEntityDeclName
            | Kind::PrefixOperator
            | Kind::PostfixOperator
            | Kind::InfixOperator
            | Kind::TypeSymbolicReference
            | Kind::ProtocolSymbolicReference
            | Kind::ObjectiveCProtocolSymbolicReference
    )
}

fn is_any_generic(k: Kind) -> bool {
    matches!(
        k,
        Kind::Structure
            | Kind::Class
            | Kind::Enum
            | Kind::Protocol
            | Kind::ProtocolSymbolicReference
            | Kind::ObjectiveCProtocolSymbolicReference
            | Kind::OtherNominalType
            | Kind::TypeAlias
            | Kind::TypeSymbolicReference
            | Kind::BuiltinTupleType
    )
}

/// Swift's `isContext`: the context node kinds, and `BuiltinTupleType`.
pub(crate) fn is_context(k: Kind) -> bool {
    k.is_context() || k == Kind::BuiltinTupleType
}

fn is_entity(k: Kind) -> bool {
    k == Kind::Type || is_context(k)
}

fn is_requirement(k: Kind) -> bool {
    matches!(
        k,
        Kind::DependentGenericParamPackMarker
            | Kind::DependentGenericParamValueMarker
            | Kind::DependentGenericSameTypeRequirement
            | Kind::DependentGenericSameShapeRequirement
            | Kind::DependentGenericLayoutRequirement
            | Kind::DependentGenericConformanceRequirement
            | Kind::DependentGenericInverseConformanceRequirement
    )
}

pub(crate) fn is_function_attr(k: Kind) -> bool {
    matches!(
        k,
        Kind::FunctionSignatureSpecialization
            | Kind::GenericSpecialization
            | Kind::GenericSpecializationPrespecialized
            | Kind::InlinedGenericFunction
            | Kind::GenericSpecializationNotReAbstracted
            | Kind::GenericPartialSpecialization
            | Kind::GenericPartialSpecializationNotReAbstracted
            | Kind::GenericSpecializationInResilienceDomain
            | Kind::ObjCAttribute
            | Kind::NonObjCAttribute
            | Kind::DynamicAttribute
            | Kind::DirectMethodReferenceAttribute
            | Kind::VTableAttribute
            | Kind::PartialApplyForwarder
            | Kind::PartialApplyObjCForwarder
            | Kind::OutlinedVariable
            | Kind::OutlinedReadOnlyObject
            | Kind::OutlinedBridgedMethod
            | Kind::MergedFunction
            | Kind::DistributedThunk
            | Kind::DistributedAccessor
            | Kind::DynamicallyReplaceableFunctionImpl
            | Kind::DynamicallyReplaceableFunctionKey
            | Kind::DynamicallyReplaceableFunctionVar
            | Kind::AsyncFunctionPointer
            | Kind::AsyncAwaitResumePartialFunction
            | Kind::AsyncSuspendResumePartialFunction
            | Kind::AccessibleFunctionRecord
            | Kind::BackDeploymentThunk
            | Kind::BackDeploymentFallback
            | Kind::BackDeploymentCopy
            | Kind::HasSymbolQuery
            | Kind::CoroFunctionPointer
            | Kind::DefaultOverride
    )
}

/// The length of a Swift mangling prefix at the start of `name` (0 if none).
pub fn mangling_prefix_length(name: &[u8]) -> usize {
    const PREFIXES: [&[u8]; 8] = [
        b"_T0",
        b"$S",
        b"_$S",
        b"$s",
        b"_$s",
        b"$e",
        b"_$e",
        b"@__swiftmacro_",
    ];
    PREFIXES
        .iter()
        .find(|p| name.starts_with(p))
        .map_or(0, |p| p.len())
}

/// The length of the async main entry point's name at the start of `name`.
pub fn async_main_entry_point_name_length(name: &[u8]) -> usize {
    let n = ASYNC_MAIN_ENTRY_POINT_NAME.as_bytes();
    if name.starts_with(n) {
        n.len()
    } else if name.first() == Some(&b'_') && name[1..].starts_with(n) {
        n.len() + 1
    } else {
        0
    }
}

/// Whether `name` is in the old mangling (`_T`).
pub fn is_old_function_type_mangling(name: &[u8]) -> bool {
    name.starts_with(b"_T")
}

/// Swift's `isSwiftSymbol`.
pub fn is_swift_symbol(name: &[u8]) -> bool {
    is_old_function_type_mangling(name)
        || async_main_entry_point_name_length(name) != 0
        || mangling_prefix_length(name) != 0
}

/// The demangler's state for one name (Swift's `Demangler`).
pub struct Demangler<'t, 'a> {
    pub tree: &'t mut Tree,
    text: &'a [u8],
    pos: usize,
    is_old_function_type_mangling: bool,
    embedded: bool,
    node_stack: Vec<NodeId>,
    substitutions: Vec<NodeId>,
    words: [(usize, usize); MAX_NUM_WORDS],
    num_words: usize,
    depth: u32,
}

impl<'t, 'a> Demangler<'t, 'a> {
    pub fn new(tree: &'t mut Tree, text: &'a [u8]) -> Self {
        Self {
            tree,
            text,
            pos: 0,
            is_old_function_type_mangling: false,
            embedded: false,
            node_stack: Vec::with_capacity(16),
            substitutions: Vec::with_capacity(16),
            words: [(0, 0); MAX_NUM_WORDS],
            num_words: 0,
            depth: 0,
        }
    }

    // --- Text ------------------------------------------------------------

    fn next_if_str(&mut self, s: &[u8]) -> bool {
        if self.text.get(self.pos..).is_some_and(|t| t.starts_with(s)) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    fn peek_char(&self) -> u8 {
        self.text.get(self.pos).copied().unwrap_or(0)
    }

    fn next_char(&mut self) -> u8 {
        match self.text.get(self.pos) {
            Some(&c) => {
                self.pos += 1;
                c
            }
            None => 0,
        }
    }

    fn next_if(&mut self, c: u8) -> bool {
        if self.peek_char() != c {
            return false;
        }
        self.pos += 1;
        true
    }

    /// (Like Swift's, even at the start: there `Pos` wraps, and every read
    /// past the end gives 0.)
    fn push_back(&mut self) {
        self.pos = self.pos.wrapping_sub(1);
    }

    fn consume_all(&mut self) -> &'a [u8] {
        let s = self.text.get(self.pos..).unwrap_or(&[]);
        self.pos = self.text.len();
        s
    }

    fn remaining(&self) -> usize {
        self.text.len().saturating_sub(self.pos)
    }

    // --- The node stack ----------------------------------------------------

    fn push_node(&mut self, n: NodeId) {
        self.node_stack.push(n);
    }

    fn pop_node(&mut self) -> N {
        self.node_stack.pop()
    }

    fn pop_kind(&mut self, kind: Kind) -> N {
        let &top = self.node_stack.last()?;
        if self.tree.kind(top) != kind {
            return None;
        }
        self.node_stack.pop()
    }

    fn pop_if(&mut self, pred: impl Fn(Kind) -> bool) -> N {
        let &top = self.node_stack.last()?;
        if !pred(self.tree.kind(top)) {
            return None;
        }
        self.node_stack.pop()
    }

    fn add_substitution(&mut self, n: N) {
        if let Some(n) = n {
            self.substitutions.push(n);
        }
    }

    // --- Nodes -------------------------------------------------------------

    fn create(&mut self, k: Kind) -> N {
        self.tree.create(k)
    }

    fn create_text(&mut self, k: Kind, t: &str) -> N {
        self.tree.create_text(k, t)
    }

    fn create_bytes(&mut self, k: Kind, t: &[u8]) -> N {
        let s = String::from_utf8_lossy(t);
        self.tree.create_text(k, &s)
    }

    fn create_index(&mut self, k: Kind, i: u64) -> N {
        self.tree.create_index(k, i)
    }

    fn add_child(&mut self, parent: N, child: N) -> N {
        self.tree.add_child_opt(parent, child)
    }

    fn create_with_child(&mut self, k: Kind, child: N) -> N {
        self.tree.create_with_child(k, child)
    }

    fn create_type(&mut self, child: N) -> N {
        self.create_with_child(Kind::Type, child)
    }

    fn create_with_children(&mut self, k: Kind, children: &[N]) -> N {
        self.tree.create_with_children(k, children)
    }

    fn create_with_popped_type(&mut self, k: Kind) -> N {
        let t = self.pop_kind(Kind::Type);
        self.create_with_child(k, t)
    }

    fn kind(&self, n: NodeId) -> Kind {
        self.tree.kind(n)
    }

    fn num_children(&self, n: NodeId) -> usize {
        self.tree.num_children(n)
    }

    fn child(&self, n: NodeId, i: usize) -> N {
        self.tree.child(n, i)
    }

    fn first_child(&self, n: NodeId) -> N {
        self.tree.first_child(n)
    }

    fn change_kind(&mut self, node: N, new_kind: Kind) -> N {
        let node = node?;
        let new = if self.tree.has_text(node) {
            let t = String::from(self.tree.text(node));
            self.create_text(new_kind, &t)?
        } else if self.tree.has_index(node) {
            let i = self.tree.index(node);
            self.create_index(new_kind, i)?
        } else {
            self.create(new_kind)?
        };
        let children: Vec<NodeId> = self.tree.children(node).to_vec();
        for c in children {
            self.tree.add_child(new, c);
        }
        Some(new)
    }

    fn too_complex(&self) -> bool {
        self.tree.overflow
    }

    // --- Entry points ------------------------------------------------------

    /// Swift's `demangleSymbol`.
    pub fn demangle_symbol(&mut self) -> N {
        let name = self.text;
        if self.next_if_str(b"_Tt") {
            // (Swift passes the whole name, `_Tt` and all.)
            return super::old::demangle_old_symbol_as_node(self.tree, name);
        }
        let prefix = mangling_prefix_length(name);
        if prefix == 0 {
            let len = async_main_entry_point_name_length(name);
            if len == 0 {
                return None;
            }
            self.pos += len;
            let n = self.create(Kind::AsyncMainEntryPoint)?;
            self.push_node(n);
        } else {
            if name.starts_with(b"$e") {
                self.embedded = true;
            }
            self.is_old_function_type_mangling = is_old_function_type_mangling(name);
            self.pos += prefix;
        }
        if !self.parse_and_push_nodes() {
            return None;
        }
        let top = self.create(Kind::Global)?;
        let suffix = self.pop_kind(Kind::Suffix);
        let mut parent = top;
        while let Some(attr) = self.pop_if(is_function_attr) {
            self.tree.add_child(parent, attr);
            if matches!(
                self.kind(attr),
                Kind::PartialApplyForwarder | Kind::PartialApplyObjCForwarder
            ) {
                parent = attr;
            }
        }
        let stack = core::mem::take(&mut self.node_stack);
        for &nd in &stack {
            if self.kind(nd) == Kind::Type {
                let c = self.first_child(nd)?;
                self.tree.add_child(parent, c);
            } else {
                self.tree.add_child(parent, nd);
            }
        }
        self.node_stack = stack;
        if let Some(s) = suffix {
            self.tree.add_child(top, s);
        }
        if self.num_children(top) == 0 || self.too_complex() {
            return None;
        }
        Some(top)
    }

    /// Swift's `demangleType`.
    pub fn demangle_type(&mut self) -> N {
        if !self.parse_and_push_nodes() {
            return None;
        }
        let result = self.pop_node();
        if self.pop_node().is_some() || self.too_complex() {
            return None;
        }
        result
    }

    fn parse_and_push_nodes(&mut self) -> bool {
        while self.pos < self.text.len() {
            if self.peek_char() == 0 {
                return true;
            }
            let Some(n) = self.demangle_operator() else {
                return false;
            };
            if self.too_complex() {
                return false;
            }
            self.push_node(n);
        }
        true
    }

    fn demangle_type_mangling(&mut self) -> N {
        let ty = self.pop_kind(Kind::Type);
        let labels = self.pop_function_param_labels(ty);
        let tm = self.create(Kind::TypeMangling);
        self.add_child(tm, labels);
        self.add_child(tm, ty)
    }

    /// Symbolic references need a resolver, which there isn't: they don't
    /// demangle (as with `swift-demangle`).
    fn demangle_symbolic_reference(&mut self, _raw_kind: u8) -> N {
        if self.pos + 4 > self.text.len() {
            return None;
        }
        self.pos += 4;
        None
    }

    fn demangle_type_annotation(&mut self) -> N {
        match self.next_char() {
            b'a' => self.create(Kind::AsyncAnnotation),
            b'A' => self.create(Kind::IsolatedAnyFunctionType),
            b'b' => self.create(Kind::ConcurrentFunctionType),
            b'c' => {
                let t = self.pop_type_and_get_child();
                self.create_with_child(Kind::GlobalActorFunctionType, t)
            }
            b'C' => self.create(Kind::NonIsolatedCallerFunctionType),
            b'i' => {
                let t = self.pop_type_and_get_child();
                let n = self.create_with_child(Kind::Isolated, t);
                self.create_type(n)
            }
            b'j' => self.demangle_differentiable_function_type(),
            b'k' => {
                let t = self.pop_type_and_get_child();
                let n = self.create_with_child(Kind::NoDerivative, t);
                self.create_type(n)
            }
            b'K' => {
                let t = self.pop_type_and_get_child();
                self.create_with_child(Kind::TypedThrowsAnnotation, t)
            }
            b't' => {
                let t = self.pop_type_and_get_child();
                let n = self.create_with_child(Kind::CompileTimeLiteral, t);
                self.create_type(n)
            }
            b'g' => {
                let t = self.pop_type_and_get_child();
                let n = self.create_with_child(Kind::ConstValue, t);
                self.create_type(n)
            }
            b'T' => self.create(Kind::SendingResultFunctionType),
            b'u' => {
                let t = self.pop_type_and_get_child();
                let n = self.create_with_child(Kind::Sending, t);
                self.create_type(n)
            }
            _ => None,
        }
    }

    pub(crate) fn demangle_operator(&mut self) -> N {
        // (It doesn't recurse; Swift's limit stands, should it ever.)
        if self.depth >= MAX_DEPTH {
            self.tree.overflow = true;
            return None;
        }
        self.depth += 1;
        let r = self.demangle_operator_inner();
        self.depth -= 1;
        r
    }

    fn demangle_operator_inner(&mut self) -> N {
        loop {
            let c = self.next_char();
            return match c {
                0xFF => continue,
                1..=0x0C => self.demangle_symbolic_reference(c),
                b'A' => self.demangle_multi_substitutions(),
                b'B' => self.demangle_builtin_type(),
                b'C' => self.demangle_any_generic_type(Kind::Class),
                b'D' => self.demangle_type_mangling(),
                b'E' => self.demangle_extension_context(),
                b'F' => self.demangle_plain_function(),
                b'G' => self.demangle_bound_generic_type(),
                b'H' => match self.next_char() {
                    b'A' => self.demangle_dependent_protocol_conformance_associated(),
                    b'C' => self.demangle_concrete_protocol_conformance(),
                    b'D' => self.demangle_dependent_protocol_conformance_root(),
                    b'I' => self.demangle_dependent_protocol_conformance_inherited(),
                    b'O' => self.demangle_dependent_protocol_conformance_opaque(),
                    b'P' => {
                        let p = self.pop_protocol();
                        self.create_with_child(Kind::ProtocolConformanceRefInTypeModule, p)
                    }
                    b'p' => {
                        let p = self.pop_protocol();
                        self.create_with_child(Kind::ProtocolConformanceRefInProtocolModule, p)
                    }
                    b'X' => self.demangle_pack_protocol_conformance(),
                    b'c' => {
                        let p = self.pop_protocol_conformance();
                        self.create_with_child(Kind::ProtocolConformanceDescriptorRecord, p)
                    }
                    b'n' => self.create_with_popped_type(Kind::NominalTypeDescriptorRecord),
                    b'o' => {
                        let p = self.pop_node();
                        self.create_with_child(Kind::OpaqueTypeDescriptorRecord, p)
                    }
                    b'r' => {
                        let p = self.pop_protocol();
                        self.create_with_child(Kind::ProtocolDescriptorRecord, p)
                    }
                    b'F' => self.create(Kind::AccessibleFunctionRecord),
                    _ => {
                        self.push_back();
                        self.push_back();
                        self.demangle_identifier()
                    }
                },
                b'I' => self.demangle_impl_function_type(),
                b'K' => self.create(Kind::ThrowsAnnotation),
                b'L' => self.demangle_local_identifier(),
                b'M' => self.demangle_metatype(),
                b'N' => {
                    let t = self.pop_kind(Kind::Type);
                    self.create_with_child(Kind::TypeMetadata, t)
                }
                b'O' => self.demangle_any_generic_type(Kind::Enum),
                b'P' => self.demangle_any_generic_type(Kind::Protocol),
                b'Q' => self.demangle_archetype(),
                b'R' => self.demangle_generic_requirement(),
                b'S' => self.demangle_standard_substitution(),
                b'T' => self.demangle_thunk_or_specialization(),
                b'V' => self.demangle_any_generic_type(Kind::Structure),
                b'W' => self.demangle_witness(),
                b'X' => self.demangle_special_type(),
                b'Y' => self.demangle_type_annotation(),
                b'Z' => {
                    let e = self.pop_if(is_entity);
                    self.create_with_child(Kind::Static, e)
                }
                b'a' => self.demangle_any_generic_type(Kind::TypeAlias),
                b'c' => self.pop_function_type(Kind::FunctionType, false),
                b'd' => self.create(Kind::VariadicMarker),
                b'f' => self.demangle_function_entity(),
                b'g' => self.demangle_retroactive_conformance(),
                b'h' => {
                    let t = self.pop_type_and_get_child();
                    let n = self.create_with_child(Kind::Shared, t);
                    self.create_type(n)
                }
                b'i' => self.demangle_subscript(),
                b'l' => self.demangle_generic_signature(false),
                b'm' => {
                    let t = self.pop_kind(Kind::Type);
                    let n = self.create_with_child(Kind::Metatype, t);
                    self.create_type(n)
                }
                b'n' => {
                    let t = self.pop_type_and_get_child();
                    let n = self.create_with_child(Kind::Owned, t);
                    self.create_type(n)
                }
                b'o' => self.demangle_operator_identifier(),
                b'p' => self.demangle_protocol_list_type(),
                b'q' => {
                    let n = self.demangle_generic_param_index();
                    self.create_type(n)
                }
                b'r' => self.demangle_generic_signature(true),
                b's' => self.create_text(Kind::Module, STDLIB_NAME),
                b't' => self.pop_tuple(),
                b'u' => self.demangle_generic_type(),
                b'v' => self.demangle_variable(),
                b'w' => self.demangle_value_witness(),
                b'x' => {
                    let n = self.get_dependent_generic_param_type(0, 0);
                    self.create_type(n)
                }
                b'y' => self.create(Kind::EmptyList),
                b'z' => {
                    let t = self.pop_type_and_get_child();
                    let n = self.create_with_child(Kind::InOut, t);
                    self.create_type(n)
                }
                b'_' => self.create(Kind::FirstElementMarker),
                b'.' => {
                    self.push_back();
                    let s = self.consume_all();
                    self.create_bytes(Kind::Suffix, s)
                }
                b'$' => self.demangle_integer_type(),
                _ => {
                    self.push_back();
                    self.demangle_identifier()
                }
            };
        }
    }

    fn demangle_natural(&mut self) -> i32 {
        if !is_digit(self.peek_char()) {
            return -1000;
        }
        let mut num: u64 = 0;
        loop {
            let c = self.peek_char();
            if !is_digit(c) {
                return num as i32;
            }
            num = 10 * num + u64::from(c - b'0');
            if num > i32::MAX as u64 {
                return -1000;
            }
            self.next_char();
        }
    }

    fn demangle_index(&mut self) -> i32 {
        if self.next_if(b'_') {
            return 0;
        }
        let num = self.demangle_natural();
        if (0..i32::MAX).contains(&num) && self.next_if(b'_') {
            return num + 1;
        }
        -1000
    }

    fn demangle_index_as_node(&mut self) -> N {
        let idx = self.demangle_index();
        if idx >= 0 {
            return self.create_index(Kind::Number, idx as u64);
        }
        None
    }

    fn demangle_multi_substitutions(&mut self) -> N {
        let mut repeat_count: i32 = -1;
        loop {
            let c = self.next_char();
            if c == 0 {
                return None;
            }
            if is_lower_letter(c) {
                let nd = self.push_multi_substitutions(repeat_count, usize::from(c - b'a'))?;
                self.push_node(nd);
                repeat_count = -1;
                continue;
            }
            if is_upper_letter(c) {
                return self.push_multi_substitutions(repeat_count, usize::from(c - b'A'));
            }
            if c == b'_' {
                let idx = (repeat_count as u32).wrapping_add(27) as usize;
                return self.substitutions.get(idx).copied();
            }
            self.push_back();
            repeat_count = self.demangle_natural();
            if repeat_count < 0 {
                return None;
            }
        }
    }

    fn push_multi_substitutions(&mut self, repeat_count: i32, idx: usize) -> N {
        let &nd = self.substitutions.get(idx)?;
        if repeat_count > MAX_REPEAT_COUNT {
            return None;
        }
        let mut r = repeat_count;
        while r > 1 {
            self.push_node(nd);
            r -= 1;
        }
        Some(nd)
    }

    fn create_swift_type(&mut self, kind: Kind, name: &str) -> N {
        let m = self.create_text(Kind::Module, STDLIB_NAME);
        let i = self.create_text(Kind::Identifier, name);
        let n = self.create_with_children(kind, &[m, i]);
        self.create_type(n)
    }

    fn demangle_standard_substitution(&mut self) -> N {
        match self.next_char() {
            b'o' => self.create_text(Kind::Module, MANGLING_MODULE_OBJC),
            b'C' => self.create_text(Kind::Module, MANGLING_MODULE_CLANG_IMPORTER),
            b'g' => {
                let opt = self.create_swift_type(Kind::Enum, "Optional");
                let t = self.pop_kind(Kind::Type);
                let list = self.create_with_child(Kind::TypeList, t);
                let bge = self.create_with_children(Kind::BoundGenericEnum, &[opt, list]);
                let ty = self.create_type(bge);
                self.add_substitution(ty);
                ty
            }
            _ => {
                self.push_back();
                let repeat_count = self.demangle_natural();
                if repeat_count > MAX_REPEAT_COUNT {
                    return None;
                }
                let second = self.next_if(b'c');
                let c = self.next_char();
                let nd = self.create_standard_substitution(c, second)?;
                let mut r = repeat_count;
                while r > 1 {
                    self.push_node(nd);
                    r -= 1;
                }
                Some(nd)
            }
        }
    }

    fn create_standard_substitution(&mut self, subst: u8, second_level: bool) -> N {
        let (kind, name) = if second_level {
            standard_type_concurrency(subst)?
        } else {
            standard_type(subst)?
        };
        self.create_swift_type(kind, name)
    }

    fn demangle_identifier(&mut self) -> N {
        let mut has_word_substs = false;
        let mut is_punycoded = false;
        let c = self.peek_char();
        if !is_digit(c) {
            return None;
        }
        if c == b'0' {
            self.next_char();
            if self.peek_char() == b'0' {
                self.next_char();
                is_punycoded = true;
            } else {
                has_word_substs = true;
            }
        }
        let mut ident: Vec<u8> = Vec::new();
        loop {
            while has_word_substs && is_letter(self.peek_char()) {
                let c = self.next_char();
                let word_idx = if is_lower_letter(c) {
                    usize::from(c - b'a')
                } else {
                    has_word_substs = false;
                    usize::from(c - b'A')
                };
                if word_idx >= self.num_words {
                    return None;
                }
                let (s, l) = self.words[word_idx];
                ident.extend_from_slice(&self.text[s..s + l]);
                if ident.len() > MAX_IDENTIFIER_LENGTH {
                    return None;
                }
            }
            if self.next_if(b'0') {
                break;
            }
            let num_chars = self.demangle_natural();
            if num_chars <= 0 {
                return None;
            }
            if is_punycoded {
                self.next_if(b'_');
            }
            let num_chars = num_chars as usize;
            if num_chars > self.remaining() {
                return None;
            }
            let start = self.pos;
            let slice = &self.text[start..start + num_chars];
            if is_punycoded {
                let decoded = punycode::decode_utf8(slice)?;
                ident.extend_from_slice(decoded.as_bytes());
                if ident.len() > MAX_IDENTIFIER_LENGTH {
                    return None;
                }
            } else {
                ident.extend_from_slice(slice);
                if ident.len() > MAX_IDENTIFIER_LENGTH {
                    return None;
                }
                let mut word_start: isize = -1;
                for idx in 0..=num_chars {
                    let c = if idx < num_chars { slice[idx] } else { 0 };
                    if word_start >= 0 && is_word_end(c, slice[idx - 1]) {
                        if idx as isize - word_start >= 2 && self.num_words < MAX_NUM_WORDS {
                            self.words[self.num_words] =
                                (start + word_start as usize, idx - word_start as usize);
                            self.num_words += 1;
                        }
                        word_start = -1;
                    }
                    if word_start < 0 && is_word_start(c) {
                        word_start = idx as isize;
                    }
                }
            }
            self.pos += num_chars;
            if !has_word_substs {
                break;
            }
        }
        if ident.is_empty() {
            return None;
        }
        let n = self.create_bytes(Kind::Identifier, &ident);
        self.add_substitution(n);
        n
    }

    fn demangle_operator_identifier(&mut self) -> N {
        let ident = self.pop_kind(Kind::Identifier)?;
        const TABLE: &[u8; 26] = b"& @/= >    <*!|+?%-~   ^ .";
        let mut op: Vec<u8> = Vec::new();
        for &c in self.tree.text(ident).as_bytes() {
            if c >= 0x80 {
                op.push(c);
                continue;
            }
            if !is_lower_letter(c) {
                return None;
            }
            let o = TABLE[usize::from(c - b'a')];
            if o == b' ' {
                return None;
            }
            op.push(o);
        }
        match self.next_char() {
            b'i' => self.create_bytes(Kind::InfixOperator, &op),
            b'p' => self.create_bytes(Kind::PrefixOperator, &op),
            b'P' => self.create_bytes(Kind::PostfixOperator, &op),
            _ => None,
        }
    }

    fn demangle_local_identifier(&mut self) -> N {
        if self.next_if(b'L') {
            let discriminator = self.pop_kind(Kind::Identifier);
            let name = self.pop_if(is_decl_name);
            return self.create_with_children(Kind::PrivateDeclName, &[discriminator, name]);
        }
        if self.next_if(b'l') {
            let discriminator = self.pop_kind(Kind::Identifier);
            return self.create_with_child(Kind::PrivateDeclName, discriminator);
        }
        let p = self.peek_char();
        if (b'a'..=b'j').contains(&p) || (b'A'..=b'J').contains(&p) {
            let k = self.next_char();
            let kind_nd = self.create_bytes(Kind::Identifier, &[k]);
            let name = self.pop_node();
            let result = self.create(Kind::RelatedEntityDeclName);
            self.add_child(result, kind_nd);
            return self.add_child(result, name);
        }
        let discriminator = self.demangle_index_as_node();
        let name = self.pop_if(is_decl_name);
        self.create_with_children(Kind::LocalDeclName, &[discriminator, name])
    }

    fn pop_module(&mut self) -> N {
        if let Some(ident) = self.pop_kind(Kind::Identifier) {
            return self.change_kind(Some(ident), Kind::Module);
        }
        self.pop_kind(Kind::Module)
    }

    fn pop_context(&mut self) -> N {
        if let Some(m) = self.pop_module() {
            return Some(m);
        }
        if let Some(ty) = self.pop_kind(Kind::Type) {
            if self.num_children(ty) != 1 {
                return None;
            }
            let c = self.first_child(ty)?;
            if !is_context(self.kind(c)) {
                return None;
            }
            return Some(c);
        }
        self.pop_if(is_context)
    }

    fn pop_type_and_get_child(&mut self) -> N {
        let ty = self.pop_kind(Kind::Type)?;
        if self.num_children(ty) != 1 {
            return None;
        }
        self.first_child(ty)
    }

    fn pop_type_and_get_any_generic(&mut self) -> N {
        let c = self.pop_type_and_get_child()?;
        if is_any_generic(self.kind(c)) {
            Some(c)
        } else {
            None
        }
    }

    // ===== continued below =====
}

fn standard_type(c: u8) -> Option<(Kind, &'static str)> {
    use Kind::{Enum, Protocol, Structure};
    Some(match c {
        b'A' => (Structure, "AutoreleasingUnsafeMutablePointer"),
        b'a' => (Structure, "Array"),
        b'b' => (Structure, "Bool"),
        b'D' => (Structure, "Dictionary"),
        b'd' => (Structure, "Double"),
        b'f' => (Structure, "Float"),
        b'h' => (Structure, "Set"),
        b'I' => (Structure, "DefaultIndices"),
        b'i' => (Structure, "Int"),
        b'J' => (Structure, "Character"),
        b'N' => (Structure, "ClosedRange"),
        b'n' => (Structure, "Range"),
        b'O' => (Structure, "ObjectIdentifier"),
        b'P' => (Structure, "UnsafePointer"),
        b'p' => (Structure, "UnsafeMutablePointer"),
        b'R' => (Structure, "UnsafeBufferPointer"),
        b'r' => (Structure, "UnsafeMutableBufferPointer"),
        b'S' => (Structure, "String"),
        b's' => (Structure, "Substring"),
        b'u' => (Structure, "UInt"),
        b'V' => (Structure, "UnsafeRawPointer"),
        b'v' => (Structure, "UnsafeMutableRawPointer"),
        b'W' => (Structure, "UnsafeRawBufferPointer"),
        b'w' => (Structure, "UnsafeMutableRawBufferPointer"),
        b'q' => (Enum, "Optional"),
        b'B' => (Protocol, "BinaryFloatingPoint"),
        b'E' => (Protocol, "Encodable"),
        b'e' => (Protocol, "Decodable"),
        b'F' => (Protocol, "FloatingPoint"),
        b'G' => (Protocol, "RandomNumberGenerator"),
        b'H' => (Protocol, "Hashable"),
        b'j' => (Protocol, "Numeric"),
        b'K' => (Protocol, "BidirectionalCollection"),
        b'k' => (Protocol, "RandomAccessCollection"),
        b'L' => (Protocol, "Comparable"),
        b'l' => (Protocol, "Collection"),
        b'M' => (Protocol, "MutableCollection"),
        b'm' => (Protocol, "RangeReplaceableCollection"),
        b'Q' => (Protocol, "Equatable"),
        b'T' => (Protocol, "Sequence"),
        b't' => (Protocol, "IteratorProtocol"),
        b'U' => (Protocol, "UnsignedInteger"),
        b'X' => (Protocol, "RangeExpression"),
        b'x' => (Protocol, "Strideable"),
        b'Y' => (Protocol, "RawRepresentable"),
        b'y' => (Protocol, "StringProtocol"),
        b'Z' => (Protocol, "SignedInteger"),
        b'z' => (Protocol, "BinaryInteger"),
        _ => return None,
    })
}

fn standard_type_concurrency(c: u8) -> Option<(Kind, &'static str)> {
    use Kind::{Class, Protocol, Structure};
    Some(match c {
        b'A' => (Protocol, "Actor"),
        b'C' => (Structure, "CheckedContinuation"),
        b'c' => (Structure, "UnsafeContinuation"),
        b'E' => (Structure, "CancellationError"),
        b'e' => (Structure, "UnownedSerialExecutor"),
        b'F' => (Protocol, "Executor"),
        b'f' => (Protocol, "SerialExecutor"),
        b'G' => (Structure, "TaskGroup"),
        b'g' => (Structure, "ThrowingTaskGroup"),
        b'h' => (Protocol, "TaskExecutor"),
        b'I' => (Protocol, "AsyncIteratorProtocol"),
        b'i' => (Protocol, "AsyncSequence"),
        b'J' => (Structure, "UnownedJob"),
        b'M' => (Class, "MainActor"),
        b'P' => (Structure, "TaskPriority"),
        b'S' => (Structure, "AsyncStream"),
        b's' => (Structure, "AsyncThrowingStream"),
        b'T' => (Structure, "Task"),
        b't' => (Structure, "UnsafeCurrentTask"),
        _ => return None,
    })
}

const BUILTIN_TYPE_NAME_PREFIX: &str = "Builtin.";

impl Demangler<'_, '_> {
    fn demangle_builtin_type(&mut self) -> N {
        const MAX_TYPE_SIZE: i32 = 4096;
        let name = |s: &str| String::from("Builtin.") + s;
        let ty = match self.next_char() {
            b'A' => self.create_text(Kind::BuiltinTypeName, &name("ImplicitActor")),
            b'b' => self.create_text(Kind::BuiltinTypeName, &name("BridgeObject")),
            b'B' => self.create_text(Kind::BuiltinTypeName, &name("UnsafeValueBuffer")),
            b'e' => self.create_text(Kind::BuiltinTypeName, &name("Executor")),
            b'f' => {
                let size = self.demangle_index() - 1;
                if size <= 0 || size > MAX_TYPE_SIZE {
                    return None;
                }
                self.create_text(
                    Kind::BuiltinTypeName,
                    &alloc::format!("Builtin.FPIEEE{size}"),
                )
            }
            b'i' => {
                let size = self.demangle_index() - 1;
                if size <= 0 || size > MAX_TYPE_SIZE {
                    return None;
                }
                self.create_text(Kind::BuiltinTypeName, &alloc::format!("Builtin.Int{size}"))
            }
            b'I' => self.create_text(Kind::BuiltinTypeName, &name("IntLiteral")),
            b'v' => {
                let elts = self.demangle_index() - 1;
                if elts <= 0 || elts > MAX_TYPE_SIZE {
                    return None;
                }
                let elt = self.pop_type_and_get_child()?;
                if self.kind(elt) != Kind::BuiltinTypeName
                    || !self.tree.text(elt).starts_with(BUILTIN_TYPE_NAME_PREFIX)
                {
                    return None;
                }
                let s = alloc::format!(
                    "Builtin.Vec{elts}x{}",
                    &self.tree.text(elt)[BUILTIN_TYPE_NAME_PREFIX.len()..]
                );
                self.create_text(Kind::BuiltinTypeName, &s)
            }
            b'V' => {
                let element = self.pop_kind(Kind::Type)?;
                let size = self.pop_kind(Kind::Type)?;
                let t = self.create(Kind::BuiltinFixedArray)?;
                self.tree.add_child(t, size);
                self.tree.add_child(t, element);
                Some(t)
            }
            b'W' => {
                let referent = self.pop_kind(Kind::Type)?;
                let t = self.create(Kind::BuiltinBorrow)?;
                self.tree.add_child(t, referent);
                Some(t)
            }
            b'O' => self.create_text(Kind::BuiltinTypeName, &name("UnknownObject")),
            b'o' => self.create_text(Kind::BuiltinTypeName, &name("NativeObject")),
            b'p' => self.create_text(Kind::BuiltinTypeName, &name("RawPointer")),
            b'j' => self.create_text(Kind::BuiltinTypeName, &name("Job")),
            b'D' => self.create_text(Kind::BuiltinTypeName, &name("DefaultActorStorage")),
            b'd' => self.create_text(
                Kind::BuiltinTypeName,
                &name("NonDefaultDistributedActorStorage"),
            ),
            b'c' => self.create_text(Kind::BuiltinTypeName, &name("RawUnsafeContinuation")),
            b't' => self.create_text(Kind::BuiltinTypeName, &name("SILToken")),
            b'w' => self.create_text(Kind::BuiltinTypeName, &name("Word")),
            b'P' => self.create_text(Kind::BuiltinTypeName, &name("PackIndex")),
            b'T' => self.create(Kind::BuiltinTupleType),
            _ => return None,
        };
        self.create_type(ty)
    }

    fn demangle_any_generic_type(&mut self, kind: Kind) -> N {
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        let n = self.create_with_children(kind, &[ctx, name]);
        let nty = self.create_type(n);
        self.add_substitution(nty);
        nty
    }

    fn demangle_extension_context(&mut self) -> N {
        let gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        let module = self.pop_module();
        let ty = self.pop_type_and_get_any_generic();
        let mut ext = self.create_with_children(Kind::Extension, &[module, ty]);
        if gen_sig.is_some() {
            ext = self.add_child(ext, gen_sig);
        }
        ext
    }

    /// Swift's `setParentForOpaqueReturnTypeNodes`. The parent's ID is its
    /// remangled name, which only lookups use (the printer shows nothing of
    /// it), so it is left empty here.
    fn set_parent_for_opaque_return_type_nodes(&mut self, parent: N, visited: N) -> N {
        let (parent, visited) = (parent?, visited?);
        self.set_parent_impl(visited, 0);
        Some(parent)
    }

    /// Swift's recursive walk, in the same order, with its stack on the
    /// heap.
    fn set_parent_impl(&mut self, node: NodeId, depth: u32) {
        let mut stack = alloc::vec![(node, depth)];
        while let Some((node, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                continue;
            }
            let k = self.kind(node);
            if k == Kind::OpaqueReturnType {
                if self
                    .tree
                    .last_child(node)
                    .is_some_and(|c| self.kind(c) == Kind::OpaqueReturnTypeParent)
                {
                    continue;
                }
                if let Some(p) = self.create_text(Kind::OpaqueReturnTypeParent, "") {
                    self.tree.add_child(node, p);
                }
                continue;
            }
            if matches!(k, Kind::Function | Kind::Variable | Kind::Subscript) {
                continue;
            }
            // The children as they are now, the first on top.
            let at = stack.len();
            stack.extend(self.tree.children(node).iter().map(|&c| (c, depth + 1)));
            stack[at..].reverse();
        }
    }

    fn demangle_plain_function(&mut self) -> N {
        let gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        let mut ty = self.pop_function_type(Kind::FunctionType, false);
        let label_list = self.pop_function_param_labels(ty);
        if gen_sig.is_some() {
            let d = self.create_with_children(Kind::DependentGenericType, &[gen_sig, ty]);
            ty = self.create_type(d);
        }
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        let result = if label_list.is_some() {
            self.create_with_children(Kind::Function, &[ctx, name, label_list, ty])
        } else {
            self.create_with_children(Kind::Function, &[ctx, name, ty])
        };
        self.set_parent_for_opaque_return_type_nodes(result, ty)
    }

    pub(crate) fn pop_function_type(&mut self, kind: Kind, has_clang_type: bool) -> N {
        let mut func_type = self.create(kind);
        let mut clang_type = None;
        if has_clang_type {
            clang_type = self.demangle_clang_type();
        }
        self.add_child(func_type, clang_type);
        let n = self.pop_kind(Kind::SendingResultFunctionType);
        self.add_child(func_type, n);
        let n = self.pop_if(|k| {
            matches!(
                k,
                Kind::GlobalActorFunctionType
                    | Kind::IsolatedAnyFunctionType
                    | Kind::NonIsolatedCallerFunctionType
            )
        });
        self.add_child(func_type, n);
        let n = self.pop_kind(Kind::DifferentiableFunctionType);
        self.add_child(func_type, n);
        let n = self.pop_if(|k| matches!(k, Kind::ThrowsAnnotation | Kind::TypedThrowsAnnotation));
        self.add_child(func_type, n);
        let n = self.pop_kind(Kind::ConcurrentFunctionType);
        self.add_child(func_type, n);
        let n = self.pop_kind(Kind::AsyncAnnotation);
        self.add_child(func_type, n);
        let n = self.pop_function_params(Kind::ArgumentTuple);
        func_type = self.add_child(func_type, n);
        let n = self.pop_kind(Kind::YieldTypes);
        self.add_child(func_type, n);
        let n = self.pop_function_params(Kind::ReturnType);
        func_type = self.add_child(func_type, n);
        self.create_type(func_type)
    }

    fn pop_function_params(&mut self, kind: Kind) -> N {
        let params = if self.pop_kind(Kind::EmptyList).is_some() {
            let t = self.create(Kind::Tuple);
            self.create_type(t)
        } else {
            self.pop_kind(Kind::Type)
        };
        self.create_with_child(kind, params)
    }

    fn pop_function_param_labels(&mut self, ty: N) -> N {
        if !self.is_old_function_type_mangling && self.pop_kind(Kind::EmptyList).is_some() {
            return self.create(Kind::LabelList);
        }
        let ty = ty?;
        if self.kind(ty) != Kind::Type {
            return None;
        }
        let mut func_type = self.first_child(ty)?;
        if self.kind(func_type) == Kind::DependentGenericType {
            let c = self.child(func_type, 1)?;
            func_type = self.first_child(c)?;
        }
        if !matches!(
            self.kind(func_type),
            Kind::FunctionType
                | Kind::NoEscapeFunctionType
                | Kind::CalledOnceFunctionType
                | Kind::CalledAtMostOnceFunctionType
        ) {
            return None;
        }
        let mut idx = 0;
        for kinds in [
            &[Kind::SendingResultFunctionType][..],
            &[Kind::GlobalActorFunctionType],
            &[Kind::IsolatedAnyFunctionType],
            &[Kind::NonIsolatedCallerFunctionType],
            &[Kind::DifferentiableFunctionType],
            &[Kind::ThrowsAnnotation, Kind::TypedThrowsAnnotation],
            &[Kind::ConcurrentFunctionType],
            &[Kind::AsyncAnnotation],
        ] {
            if self
                .tree
                .child_kind(func_type, idx)
                .is_some_and(|k| kinds.contains(&k))
            {
                idx += 1;
            }
        }
        let parameter_type = self.child(func_type, idx)?;
        if self.kind(parameter_type) != Kind::ArgumentTuple {
            return None;
        }
        let params_type = self.first_child(parameter_type)?;
        if self.kind(params_type) != Kind::Type {
            return None;
        }
        let params = self.first_child(params_type)?;
        let num_params = if self.kind(params) == Kind::Tuple {
            self.num_children(params)
        } else {
            1
        };
        if num_params == 0 {
            return None;
        }
        let label_list = self.create(Kind::LabelList)?;
        let tuple = self
            .first_child(parameter_type)
            .and_then(|t| self.first_child(t));
        if self.is_old_function_type_mangling && tuple.is_none_or(|t| self.kind(t) != Kind::Tuple) {
            return Some(label_list);
        }
        let mut has_labels = false;
        for i in 0..num_params {
            let label = if self.is_old_function_type_mangling {
                let tuple = tuple?;
                let param = self.child(tuple, i)?;
                let found = self
                    .tree
                    .children(param)
                    .iter()
                    .position(|&c| self.kind(c) == Kind::TupleElementName);
                match found {
                    Some(pos) => {
                        let l = self.child(param, pos)?;
                        let text = String::from(self.tree.text(l));
                        self.tree.remove_child_at(param, pos);
                        self.create_text(Kind::Identifier, &text)
                    }
                    None => self.create(Kind::FirstElementMarker),
                }
            } else {
                self.pop_node()
            };
            let label = label?;
            let lk = self.kind(label);
            if lk != Kind::Identifier && lk != Kind::FirstElementMarker {
                return None;
            }
            self.tree.add_child(label_list, label);
            has_labels |= lk != Kind::FirstElementMarker;
        }
        if !has_labels {
            return self.create(Kind::LabelList);
        }
        if !self.is_old_function_type_mangling {
            self.tree.reverse_children(label_list, 0);
        }
        Some(label_list)
    }

    fn pop_tuple(&mut self) -> N {
        let root = self.create(Kind::Tuple)?;
        if self.pop_kind(Kind::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(Kind::FirstElementMarker).is_some();
                let elt = self.create(Kind::TupleElement)?;
                let v = self.pop_kind(Kind::VariadicMarker);
                self.add_child(Some(elt), v);
                if let Some(ident) = self.pop_kind(Kind::Identifier) {
                    let t = String::from(self.tree.text(ident));
                    let name = self.create_text(Kind::TupleElementName, &t)?;
                    self.tree.add_child(elt, name);
                }
                let ty = self.pop_kind(Kind::Type)?;
                self.tree.add_child(elt, ty);
                self.tree.add_child(root, elt);
                if first {
                    break;
                }
            }
            self.tree.reverse_children(root, 0);
        }
        self.create_type(Some(root))
    }

    /// The `[_] type...` lists that end at a `FirstElementMarker` (or are
    /// an `EmptyList`), into `root`, in order.
    fn pop_types_into(&mut self, root: NodeId) -> Option<()> {
        if self.pop_kind(Kind::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(Kind::FirstElementMarker).is_some();
                let ty = self.pop_kind(Kind::Type)?;
                self.tree.add_child(root, ty);
                if first {
                    break;
                }
            }
            self.tree.reverse_children(root, 0);
        }
        Some(())
    }

    fn pop_pack(&mut self) -> N {
        let root = self.create(Kind::Pack)?;
        self.pop_types_into(root)?;
        self.create_type(Some(root))
    }

    fn pop_sil_pack(&mut self) -> N {
        let root = match self.next_char() {
            b'd' => self.create(Kind::SILPackDirect)?,
            b'i' => self.create(Kind::SILPackIndirect)?,
            _ => return None,
        };
        self.pop_types_into(root)?;
        self.create_type(Some(root))
    }

    fn pop_type_list(&mut self) -> N {
        let root = self.create(Kind::TypeList)?;
        self.pop_types_into(root)?;
        Some(root)
    }

    fn pop_protocol(&mut self) -> N {
        if let Some(ty) = self.pop_kind(Kind::Type) {
            if self.num_children(ty) < 1 || !self.is_protocol_node(Some(ty), 0) {
                return None;
            }
            return Some(ty);
        }
        if let Some(r) = self.pop_kind(Kind::ProtocolSymbolicReference) {
            return Some(r);
        }
        if let Some(r) = self.pop_kind(Kind::ObjectiveCProtocolSymbolicReference) {
            return Some(r);
        }
        let name = self.pop_if(is_decl_name);
        let ctx = self.pop_context();
        let proto = self.create_with_children(Kind::Protocol, &[ctx, name]);
        self.create_type(proto)
    }

    /// Swift's `isProtocolNode`.
    fn is_protocol_node(&self, n: N, depth: u32) -> bool {
        let (mut n, mut depth) = (n, depth);
        loop {
            let Some(id) = n else { return false };
            if depth > MAX_DEPTH {
                return false;
            }
            match self.kind(id) {
                Kind::Type => (n, depth) = (self.child(id, 0), depth + 1),
                Kind::Protocol
                | Kind::ProtocolSymbolicReference
                | Kind::ObjectiveCProtocolSymbolicReference => return true,
                _ => return false,
            }
        }
    }

    fn pop_any_protocol_conformance_list(&mut self) -> N {
        let list = self.create(Kind::AnyProtocolConformanceList)?;
        if self.pop_kind(Kind::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(Kind::FirstElementMarker).is_some();
                let c = self.pop_any_protocol_conformance()?;
                self.tree.add_child(list, c);
                if first {
                    break;
                }
            }
            self.tree.reverse_children(list, 0);
        }
        Some(list)
    }

    fn pop_any_protocol_conformance(&mut self) -> N {
        self.pop_if(|k| {
            matches!(
                k,
                Kind::ConcreteProtocolConformance
                    | Kind::PackProtocolConformance
                    | Kind::DependentProtocolConformanceRoot
                    | Kind::DependentProtocolConformanceInherited
                    | Kind::DependentProtocolConformanceAssociated
                    | Kind::DependentProtocolConformanceOpaque
            )
        })
    }

    fn demangle_retroactive_protocol_conformance_ref(&mut self) -> N {
        let module = self.pop_module();
        let proto = self.pop_protocol();
        self.create_with_children(Kind::ProtocolConformanceRefInOtherModule, &[proto, module])
    }
}

/// Swift's `nodeConsumesGenericArgs`.
pub(crate) fn node_consumes_generic_args(k: Kind) -> bool {
    !matches!(
        k,
        Kind::Variable
            | Kind::Subscript
            | Kind::ImplicitClosure
            | Kind::ExplicitClosure
            | Kind::DefaultArgumentInitializer
            | Kind::Initializer
            | Kind::PropertyWrapperBackingInitializer
            | Kind::PropertyWrappedFieldInitAccessor
            | Kind::PropertyWrapperInitFromProjectedValue
            | Kind::Static
    )
}

impl Demangler<'_, '_> {
    fn demangle_concrete_protocol_conformance(&mut self) -> N {
        let conditional = self.pop_any_protocol_conformance_list();
        let mut conformance_ref = self.pop_kind(Kind::ProtocolConformanceRefInTypeModule);
        if conformance_ref.is_none() {
            conformance_ref = self.pop_kind(Kind::ProtocolConformanceRefInProtocolModule);
        }
        if conformance_ref.is_none() {
            conformance_ref = self.demangle_retroactive_protocol_conformance_ref();
        }
        let ty = self.pop_kind(Kind::Type);
        self.create_with_children(
            Kind::ConcreteProtocolConformance,
            &[ty, conformance_ref, conditional],
        )
    }

    fn demangle_pack_protocol_conformance(&mut self) -> N {
        let list = self.pop_any_protocol_conformance_list();
        self.create_with_child(Kind::PackProtocolConformance, list)
    }

    fn pop_dependent_protocol_conformance(&mut self) -> N {
        self.pop_if(|k| {
            matches!(
                k,
                Kind::DependentProtocolConformanceRoot
                    | Kind::DependentProtocolConformanceInherited
                    | Kind::DependentProtocolConformanceAssociated
            )
        })
    }

    fn demangle_dependent_protocol_conformance_root(&mut self) -> N {
        let index = self.demangle_dependent_conformance_index();
        let protocol = self.pop_protocol();
        let dependent_type = self.pop_kind(Kind::Type);
        self.create_with_children(
            Kind::DependentProtocolConformanceRoot,
            &[dependent_type, protocol, index],
        )
    }

    fn demangle_dependent_protocol_conformance_inherited(&mut self) -> N {
        let index = self.demangle_dependent_conformance_index();
        let protocol = self.pop_protocol();
        let nested = self.pop_dependent_protocol_conformance();
        self.create_with_children(
            Kind::DependentProtocolConformanceInherited,
            &[nested, protocol, index],
        )
    }

    fn pop_dependent_associated_conformance(&mut self) -> N {
        let protocol = self.pop_protocol();
        let dependent_type = self.pop_kind(Kind::Type);
        self.create_with_children(
            Kind::DependentAssociatedConformance,
            &[dependent_type, protocol],
        )
    }

    fn demangle_dependent_protocol_conformance_associated(&mut self) -> N {
        let index = self.demangle_dependent_conformance_index();
        let associated = self.pop_dependent_associated_conformance();
        let nested = self.pop_dependent_protocol_conformance();
        self.create_with_children(
            Kind::DependentProtocolConformanceAssociated,
            &[nested, associated, index],
        )
    }

    fn demangle_dependent_conformance_index(&mut self) -> N {
        let index = self.demangle_index();
        if index <= 0 {
            return None;
        }
        if index == 1 {
            return self.create(Kind::UnknownIndex);
        }
        self.create_index(Kind::Index, (index as u32 - 2).into())
    }

    fn demangle_dependent_protocol_conformance_opaque(&mut self) -> N {
        let ty = self.pop_kind(Kind::Type);
        let conformance = self.pop_dependent_protocol_conformance();
        self.create_with_children(Kind::DependentProtocolConformanceOpaque, &[conformance, ty])
    }

    fn demangle_retroactive_conformance(&mut self) -> N {
        let index = self.demangle_index_as_node();
        let conformance = self.pop_any_protocol_conformance();
        self.create_with_children(Kind::RetroactiveConformance, &[index, conformance])
    }

    fn pop_retroactive_conformances(&mut self) -> N {
        let mut list = None;
        while let Some(c) = self.pop_kind(Kind::RetroactiveConformance) {
            if list.is_none() {
                list = self.create(Kind::TypeList);
            }
            self.add_child(list, Some(c));
        }
        if let Some(l) = list {
            self.tree.reverse_children(l, 0);
        }
        list
    }

    fn demangle_bound_generics(&mut self, lists: &mut Vec<NodeId>) -> Option<N> {
        let retroactive = self.pop_retroactive_conformances();
        loop {
            let list = self.create(Kind::TypeList)?;
            lists.push(list);
            while let Some(ty) = self.pop_kind(Kind::Type) {
                self.tree.add_child(list, ty);
            }
            self.tree.reverse_children(list, 0);
            if self.pop_kind(Kind::EmptyList).is_some() {
                break;
            }
            self.pop_kind(Kind::FirstElementMarker)?;
        }
        Some(retroactive)
    }

    fn demangle_bound_generic_type(&mut self) -> N {
        let mut lists = Vec::with_capacity(4);
        let retroactive = self.demangle_bound_generics(&mut lists)?;
        let nominal = self.pop_type_and_get_any_generic()?;
        let bound = self.demangle_bound_generic_args(Some(nominal), &lists, 0, 0)?;
        self.add_child(Some(bound), retroactive);
        let nty = self.create_type(Some(bound));
        self.add_substitution(nty);
        nty
    }

    /// Swift's `demangleBoundGenericArgs`, whose recursion (down a
    /// nominal type's contexts) is here a loop down, then one back up.
    pub(crate) fn demangle_bound_generic_args(
        &mut self,
        nominal: N,
        lists: &[NodeId],
        idx: usize,
        depth: u32,
    ) -> N {
        /// A level whose context's result it waits for.
        struct Level {
            nominal: NodeId,
            kind: Kind,
            consumes: bool,
            args: NodeId,
            /// The context, if an extension (whose second child is bound).
            extension: Option<NodeId>,
        }
        let mut levels: Vec<Level> = Vec::new();
        let (mut nominal, mut idx, mut depth) = (nominal, idx, depth);
        let mut result = loop {
            let Some(nom) = nominal else { break None };
            if idx >= lists.len() || depth > MAX_DEPTH {
                break None;
            }
            let nk = self.kind(nom);
            if nk == Kind::TypeSymbolicReference || nk == Kind::ProtocolSymbolicReference {
                break self.bind_symbolic_reference(nom, &lists[idx..]);
            }
            let Some(context) = self.first_child(nom) else {
                break None;
            };
            let consumes = node_consumes_generic_args(nk);
            let args = lists[idx];
            if consumes {
                idx += 1;
            }
            if idx >= lists.len() {
                break self.bind_generic_args(nom, consumes, args);
            }
            let extension = (self.kind(context) == Kind::Extension).then_some(context);
            nominal = match extension {
                Some(c) => self.child(c, 1),
                None => Some(context),
            };
            levels.push(Level {
                nominal: nom,
                kind: nk,
                consumes,
                args,
                extension,
            });
            depth += 1;
        };
        while let Some(l) = levels.pop() {
            let bound_parent = match l.extension {
                Some(context) => {
                    let c0 = self.first_child(context);
                    let bp = self.create_with_children(Kind::Extension, &[c0, result]);
                    if self.num_children(context) == 3 {
                        let c2 = self.child(context, 2);
                        self.add_child(bp, c2);
                    }
                    bp
                }
                None => result,
            };
            let Some(new_nominal) = self.create_with_child(l.kind, bound_parent) else {
                result = None;
                continue;
            };
            for i in 1..self.num_children(l.nominal) {
                let c = self.child(l.nominal, i);
                self.add_child(Some(new_nominal), c);
            }
            result = self.bind_generic_args(new_nominal, l.consumes, l.args);
        }
        result
    }

    /// A symbolic reference bound to the rest of the argument lists.
    fn bind_symbolic_reference(&mut self, nominal: NodeId, lists: &[NodeId]) -> N {
        let remaining = self.create(Kind::TypeList)?;
        for &list in lists.iter().rev() {
            let children: Vec<NodeId> = self.tree.children(list).to_vec();
            for c in children {
                self.tree.add_child(remaining, c);
            }
        }
        let t = self.create_type(Some(nominal));
        self.create_with_children(Kind::BoundGenericOtherNominalType, &[t, Some(remaining)])
    }

    /// `nominal` with its (bound) context, bound to `args` if it takes them.
    fn bind_generic_args(&mut self, nominal: NodeId, consumes: bool, args: NodeId) -> N {
        if !consumes || self.num_children(args) == 0 {
            return Some(nominal);
        }
        let kind = match self.kind(nominal) {
            Kind::Class => Kind::BoundGenericClass,
            Kind::Structure => Kind::BoundGenericStructure,
            Kind::Enum => Kind::BoundGenericEnum,
            Kind::Protocol => Kind::BoundGenericProtocol,
            Kind::OtherNominalType => Kind::BoundGenericOtherNominalType,
            Kind::TypeAlias => Kind::BoundGenericTypeAlias,
            Kind::Function | Kind::Constructor => {
                return self.create_with_children(
                    Kind::BoundGenericFunction,
                    &[Some(nominal), Some(args)],
                );
            }
            _ => return None,
        };
        let t = self.create_type(Some(nominal));
        self.create_with_children(kind, &[t, Some(args)])
    }

    fn demangle_impl_param_convention(&mut self, conv_kind: Kind) -> N {
        let attr = match self.next_char() {
            b'i' => "@in",
            b'c' => "@in_constant",
            b'l' => "@inout",
            b'b' => "@inout_aliasable",
            b'n' => "@in_guaranteed",
            b'X' => "@in_cxx",
            b'x' => "@owned",
            b'g' => "@guaranteed",
            b'e' => "@deallocating",
            b'y' => "@unowned",
            b'v' => "@pack_owned",
            b'p' => "@pack_guaranteed",
            b'm' => "@pack_inout",
            _ => {
                self.push_back();
                return None;
            }
        };
        let c = self.create_text(Kind::ImplConvention, attr);
        self.create_with_child(conv_kind, c)
    }

    fn demangle_impl_result_convention(&mut self, conv_kind: Kind) -> N {
        let attr = match self.next_char() {
            b'r' => "@out",
            b'o' => "@owned",
            b'd' => "@unowned",
            b'u' => "@unowned_inner_pointer",
            b'a' => "@autoreleased",
            b'k' => "@pack_out",
            b'l' => "@guaranteed_address",
            b'g' => "@guaranteed",
            b'm' => "@inout",
            _ => {
                self.push_back();
                return None;
            }
        };
        let c = self.create_text(Kind::ImplConvention, attr);
        self.create_with_child(conv_kind, c)
    }

    fn demangle_impl_parameter_sending(&mut self) -> N {
        if !self.next_if(b'T') {
            return None;
        }
        self.create_text(Kind::ImplParameterSending, "sending")
    }

    fn demangle_impl_parameter_isolated(&mut self) -> N {
        if !self.next_if(b'I') {
            return None;
        }
        self.create_text(Kind::ImplParameterIsolated, "isolated")
    }

    fn demangle_impl_parameter_implicit_leading(&mut self) -> N {
        if !self.next_if(b'L') {
            return None;
        }
        self.create_text(
            Kind::ImplParameterImplicitLeading,
            "sil_implicit_leading_param",
        )
    }

    fn demangle_impl_parameter_result_differentiability(&mut self) -> N {
        let attr = if self.next_if(b'w') {
            "@noDerivative"
        } else {
            ""
        };
        self.create_text(Kind::ImplParameterResultDifferentiability, attr)
    }

    fn demangle_clang_type(&mut self) -> N {
        let num_chars = self.demangle_natural();
        if num_chars <= 0 || num_chars as usize > self.remaining() {
            return None;
        }
        let n = num_chars as usize;
        let s = &self.text[self.pos..self.pos + n];
        self.pos += n;
        self.create_bytes(Kind::ClangType, s)
    }
}

impl Demangler<'_, '_> {
    fn demangle_impl_function_type(&mut self) -> N {
        let mut ty = self.create(Kind::ImplFunctionType);
        if self.next_if(b's') {
            let mut subs = Vec::new();
            let retro = self.demangle_bound_generics(&mut subs)?;
            let sig = self.pop_kind(Kind::DependentGenericSignature)?;
            let node = self.create(Kind::ImplPatternSubstitutions)?;
            self.tree.add_child(node, sig);
            // (Swift asserts there is one list; it adds the first.)
            let &first = subs.first()?;
            self.tree.add_child(node, first);
            self.add_child(Some(node), retro);
            self.add_child(ty, Some(node));
        }
        if self.next_if(b'I') {
            let mut subs = Vec::new();
            let retro = self.demangle_bound_generics(&mut subs)?;
            let node = self.create(Kind::ImplInvocationSubstitutions)?;
            if subs.len() != 1 {
                return None;
            }
            self.tree.add_child(node, subs[0]);
            self.add_child(Some(node), retro);
            self.add_child(ty, Some(node));
        }
        let mut gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        if gen_sig.is_some() && self.next_if(b'P') {
            gen_sig = self.change_kind(gen_sig, Kind::DependentPseudogenericSignature);
        }
        if self.next_if(b'e') {
            let n = self.create(Kind::ImplEscaping);
            self.add_child(ty, n);
        }
        if self.next_if(b'A') {
            let n = self.create(Kind::ImplErasedIsolation);
            self.add_child(ty, n);
        }
        if self.next_if(b'N') {
            let n = self.create(Kind::ImplNonisolatedNonsendingIsolation);
            self.add_child(ty, n);
        }
        if self.next_if(b'O') {
            let n = if self.next_if(b'o') {
                self.create(Kind::ImplCalledAtMostOnceFunction)
            } else {
                self.create(Kind::ImplCalledOnceFunction)
            };
            self.add_child(ty, n);
        }
        if matches!(self.peek_char(), b'd' | b'l' | b'f' | b'r') {
            let c = self.next_char();
            let n = self.create_index(Kind::ImplDifferentiabilityKind, u64::from(c));
            self.add_child(ty, n);
        }
        let c_attr = match self.next_char() {
            b'y' => "@callee_unowned",
            b'g' => "@callee_guaranteed",
            b'x' => "@callee_owned",
            b't' => "@convention(thin)",
            _ => return None,
        };
        let n = self.create_text(Kind::ImplConvention, c_attr);
        self.add_child(ty, n);
        let mut f_conv = None;
        let mut has_clang_type = false;
        match self.next_char() {
            b'B' => f_conv = Some("block"),
            b'C' => f_conv = Some("c"),
            b'z' => match self.next_char() {
                b'B' => {
                    has_clang_type = true;
                    f_conv = Some("block");
                }
                b'C' => {
                    has_clang_type = true;
                    f_conv = Some("c");
                }
                _ => {
                    self.push_back();
                    self.push_back();
                }
            },
            b'M' => f_conv = Some("method"),
            b'O' => f_conv = Some("objc_method"),
            b'K' => f_conv = Some("closure"),
            b'W' => f_conv = Some("witness_method"),
            b'V' => f_conv = Some("com_method"),
            _ => self.push_back(),
        }
        if let Some(f) = f_conv {
            let attr = self.create(Kind::ImplFunctionConvention);
            let name = self.create_text(Kind::ImplFunctionConventionName, f);
            self.add_child(attr, name);
            if has_clang_type {
                let ct = self.demangle_clang_type();
                self.add_child(attr, ct);
            }
            self.add_child(ty, attr);
        }
        let coro = if self.next_if(b'A') {
            Some("yield_once")
        } else if self.next_if(b'I') {
            Some("yield_once_2")
        } else if self.next_if(b'G') {
            Some("yield_many")
        } else {
            None
        };
        if let Some(c) = coro {
            let n = self.create_text(Kind::ImplCoroutineKind, c);
            self.add_child(ty, n);
        }
        if self.next_if(b'h') {
            let n = self.create_text(Kind::ImplFunctionAttribute, "@Sendable");
            self.add_child(ty, n);
        }
        if self.next_if(b'H') {
            let n = self.create_text(Kind::ImplFunctionAttribute, "@async");
            self.add_child(ty, n);
        }
        if self.next_if(b'T') {
            let n = self.create(Kind::ImplSendingResult);
            self.add_child(ty, n);
        }
        self.add_child(ty, gen_sig);
        let mut num_types_to_add = 0usize;
        while let Some(param) = self.demangle_impl_param_convention(Kind::ImplParameter) {
            ty = self.add_child(ty, Some(param));
            let mut param = Some(param);
            if let Some(d) = self.demangle_impl_parameter_result_differentiability() {
                param = self.add_child(param, Some(d));
            }
            if let Some(s) = self.demangle_impl_parameter_sending() {
                param = self.add_child(param, Some(s));
            }
            if let Some(s) = self.demangle_impl_parameter_isolated() {
                param = self.add_child(param, Some(s));
            }
            if let Some(s) = self.demangle_impl_parameter_implicit_leading() {
                self.add_child(param, Some(s));
            }
            num_types_to_add += 1;
        }
        while let Some(result) = self.demangle_impl_result_convention(Kind::ImplResult) {
            ty = self.add_child(ty, Some(result));
            if let Some(d) = self.demangle_impl_parameter_result_differentiability() {
                self.add_child(Some(result), Some(d));
            }
            num_types_to_add += 1;
        }
        while self.next_if(b'Y') {
            let y = self.demangle_impl_param_convention(Kind::ImplYield)?;
            ty = self.add_child(ty, Some(y));
            num_types_to_add += 1;
        }
        if self.next_if(b'z') {
            let e = self.demangle_impl_result_convention(Kind::ImplErrorResult)?;
            ty = self.add_child(ty, Some(e));
            num_types_to_add += 1;
        }
        if !self.next_if(b'_') {
            return None;
        }
        let t = ty?;
        for idx in 0..num_types_to_add {
            let conv_ty = self.pop_kind(Kind::Type)?;
            let n = self.num_children(t);
            let c = self.child(t, n.checked_sub(idx + 1)?)?;
            self.tree.add_child(c, conv_ty);
        }
        self.create_type(Some(t))
    }

    fn demangle_metatype(&mut self) -> N {
        let popped = |d: &mut Self, k| d.create_with_popped_type(k);
        match self.next_char() {
            b'a' => popped(self, Kind::TypeMetadataAccessFunction),
            b'A' => {
                let c = self.pop_protocol_conformance();
                self.create_with_child(Kind::ReflectionMetadataAssocTypeDescriptor, c)
            }
            b'b' => popped(
                self,
                Kind::CanonicalSpecializedGenericTypeMetadataAccessFunction,
            ),
            b'B' => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_child(Kind::ReflectionMetadataBuiltinDescriptor, t)
            }
            b'c' => {
                let c = self.pop_protocol_conformance();
                self.create_with_child(Kind::ProtocolConformanceDescriptor, c)
            }
            b'C' => {
                let ty = self.pop_kind(Kind::Type)?;
                let c = self.child(ty, 0)?;
                if !is_any_generic(self.kind(c)) {
                    return None;
                }
                self.create_with_child(Kind::ReflectionMetadataSuperclassDescriptor, Some(c))
            }
            b'D' => popped(self, Kind::TypeMetadataDemanglingCache),
            b'f' => popped(self, Kind::FullTypeMetadata),
            b'F' => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_child(Kind::ReflectionMetadataFieldDescriptor, t)
            }
            b'g' => {
                let n = self.pop_node();
                self.create_with_child(Kind::OpaqueTypeDescriptorAccessor, n)
            }
            b'h' => {
                let n = self.pop_node();
                self.create_with_child(Kind::OpaqueTypeDescriptorAccessorImpl, n)
            }
            b'i' => popped(self, Kind::TypeMetadataInstantiationFunction),
            b'I' => popped(self, Kind::TypeMetadataInstantiationCache),
            b'j' => {
                let n = self.pop_node();
                self.create_with_child(Kind::OpaqueTypeDescriptorAccessorKey, n)
            }
            b'J' => {
                let n = self.pop_node();
                self.create_with_child(Kind::NoncanonicalSpecializedGenericTypeMetadataCache, n)
            }
            b'k' => {
                let n = self.pop_node();
                self.create_with_child(Kind::OpaqueTypeDescriptorAccessorVar, n)
            }
            b'K' => {
                let n = self.pop_node();
                self.create_with_child(Kind::MetadataInstantiationCache, n)
            }
            b'l' => popped(self, Kind::TypeMetadataSingletonInitializationCache),
            b'L' => popped(self, Kind::TypeMetadataLazyCache),
            b'm' => popped(self, Kind::Metaclass),
            b'M' => popped(self, Kind::CanonicalSpecializedGenericMetaclass),
            b'n' => popped(self, Kind::NominalTypeDescriptor),
            b'N' => popped(self, Kind::NoncanonicalSpecializedGenericTypeMetadata),
            b'o' => popped(self, Kind::ClassMetadataBaseOffset),
            b'p' => {
                let p = self.pop_protocol();
                self.create_with_child(Kind::ProtocolDescriptor, p)
            }
            b'P' => popped(self, Kind::GenericTypeMetadataPattern),
            b'q' => {
                let n = self.pop_node();
                self.create_with_child(Kind::Uniquable, n)
            }
            b'Q' => {
                let n = self.pop_node();
                self.create_with_child(Kind::OpaqueTypeDescriptor, n)
            }
            b'r' => popped(self, Kind::TypeMetadataCompletionFunction),
            b's' => popped(self, Kind::ObjCResilientClassStub),
            b'S' => {
                let p = self.pop_protocol();
                self.create_with_child(Kind::ProtocolSelfConformanceDescriptor, p)
            }
            b't' => popped(self, Kind::FullObjCResilientClassStub),
            b'u' => popped(self, Kind::MethodLookupFunction),
            b'U' => popped(self, Kind::ObjCMetadataUpdateFunction),
            b'V' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::PropertyDescriptor, e)
            }
            b'X' => self.demangle_private_context_descriptor(),
            b'z' => popped(
                self,
                Kind::CanonicalPrespecializedGenericTypeCachingOnceToken,
            ),
            _ => None,
        }
    }

    fn demangle_private_context_descriptor(&mut self) -> N {
        match self.next_char() {
            b'E' => {
                let ext = self.pop_context()?;
                self.create_with_child(Kind::ExtensionDescriptor, Some(ext))
            }
            b'M' => {
                let m = self.pop_module()?;
                self.create_with_child(Kind::ModuleDescriptor, Some(m))
            }
            b'Y' => {
                let discriminator = self.pop_node()?;
                let context = self.pop_context()?;
                let node = self.create(Kind::AnonymousDescriptor)?;
                self.tree.add_child(node, context);
                self.tree.add_child(node, discriminator);
                Some(node)
            }
            b'X' => {
                let context = self.pop_context()?;
                self.create_with_child(Kind::AnonymousDescriptor, Some(context))
            }
            b'A' => {
                let path = self.pop_assoc_type_path()?;
                let base = self.pop_kind(Kind::Type)?;
                self.create_with_children(
                    Kind::AssociatedTypeGenericParamRef,
                    &[Some(base), Some(path)],
                )
            }
            _ => None,
        }
    }
}

/// A C++ `int` stored in a node's 64-bit index (negatives wrap, as there).
fn idx(i: i32) -> u64 {
    i64::from(i) as u64
}

impl Demangler<'_, '_> {
    fn demangle_archetype(&mut self) -> N {
        match self.next_char() {
            b'a' => {
                let ident = self.pop_kind(Kind::Identifier);
                let arche = self.pop_type_and_get_child();
                let r = self.create_with_children(Kind::AssociatedTypeRef, &[arche, ident]);
                let t = self.create_type(r);
                self.add_substitution(t);
                t
            }
            b'O' => {
                let ctx = self.pop_context();
                self.create_with_child(Kind::OpaqueReturnTypeOf, ctx)
            }
            b'o' => {
                let index = self.demangle_index();
                let mut args = Vec::new();
                let retro = self.demangle_bound_generics(&mut args)?;
                let name = self.pop_node()?;
                let i = self.create_index(Kind::Index, idx(index));
                let opaque = self.create_with_children(Kind::OpaqueType, &[Some(name), i])?;
                let bound = self.create(Kind::TypeList)?;
                for &a in args.iter().rev() {
                    self.tree.add_child(bound, a);
                }
                self.tree.add_child(opaque, bound);
                self.add_child(Some(opaque), retro);
                let t = self.create_type(Some(opaque));
                self.add_substitution(t);
                t
            }
            b'r' => {
                let n = self.create(Kind::OpaqueReturnType);
                self.create_type(n)
            }
            b'R' => {
                let ordinal = self.demangle_index();
                if ordinal < 0 {
                    return None;
                }
                let i = self.create_index(Kind::OpaqueReturnTypeIndex, idx(ordinal));
                let n = self.create_with_child(Kind::OpaqueReturnType, i);
                self.create_type(n)
            }
            b'x' => {
                let t = self.demangle_associated_type_simple(None);
                self.add_substitution(t);
                t
            }
            b'X' => {
                let t = self.demangle_associated_type_compound(None);
                self.add_substitution(t);
                t
            }
            b'y' => {
                let b = self.demangle_generic_param_index();
                let t = self.demangle_associated_type_simple(b);
                self.add_substitution(t);
                t
            }
            b'Y' => {
                let b = self.demangle_generic_param_index();
                let t = self.demangle_associated_type_compound(b);
                self.add_substitution(t);
                t
            }
            b'z' => {
                let b = self.get_dependent_generic_param_type(0, 0);
                let t = self.demangle_associated_type_simple(b);
                self.add_substitution(t);
                t
            }
            b'Z' => {
                let b = self.get_dependent_generic_param_type(0, 0);
                let t = self.demangle_associated_type_compound(b);
                self.add_substitution(t);
                t
            }
            b'p' => {
                let count = self.pop_type_and_get_child();
                let pattern = self.pop_type_and_get_child();
                let n = self.create_with_children(Kind::PackExpansion, &[pattern, count]);
                self.create_type(n)
            }
            b'e' => {
                let pack = self.pop_type_and_get_child();
                let level = self.demangle_index();
                if level < 0 {
                    return None;
                }
                let l = self.create_index(Kind::PackElementLevel, idx(level));
                let n = self.create_with_children(Kind::PackElement, &[pack, l]);
                self.create_type(n)
            }
            b'P' => self.pop_pack(),
            b'S' => self.pop_sil_pack(),
            _ => None,
        }
    }

    fn demangle_associated_type_simple(&mut self, base: N) -> N {
        let at_name = self.pop_assoc_type_name();
        let base_ty = if base.is_some() {
            self.create_type(base)
        } else {
            self.pop_kind(Kind::Type)
        };
        let n = self.create_with_children(Kind::DependentMemberType, &[base_ty, at_name]);
        self.create_type(n)
    }

    fn demangle_associated_type_compound(&mut self, base: N) -> N {
        let mut names = Vec::with_capacity(4);
        loop {
            let first = self.pop_kind(Kind::FirstElementMarker).is_some();
            let name = self.pop_assoc_type_name()?;
            names.push(name);
            if first {
                break;
            }
        }
        let mut base_ty = if base.is_some() {
            self.create_type(base)
        } else {
            self.pop_kind(Kind::Type)
        };
        while let Some(assoc) = names.pop() {
            let dep = self.create(Kind::DependentMemberType);
            let dep = self.add_child(dep, base_ty);
            let dep = self.add_child(dep, Some(assoc));
            base_ty = self.create_type(dep);
        }
        base_ty
    }

    fn pop_assoc_type_name(&mut self) -> N {
        let mut proto = self.pop_kind(Kind::Type);
        if proto.is_some() && !self.is_protocol_node(proto, 0) {
            return None;
        }
        if proto.is_none() {
            proto = self.pop_kind(Kind::ProtocolSymbolicReference);
        }
        if proto.is_none() {
            proto = self.pop_kind(Kind::ObjectiveCProtocolSymbolicReference);
        }
        let id = self.pop_kind(Kind::Identifier);
        let assoc = self.create_with_child(Kind::DependentAssociatedTypeRef, id);
        self.add_child(assoc, proto);
        assoc
    }

    fn pop_assoc_type_path(&mut self) -> N {
        let path = self.create(Kind::AssocTypePath)?;
        loop {
            let first = self.pop_kind(Kind::FirstElementMarker).is_some();
            let a = self.pop_assoc_type_name()?;
            self.tree.add_child(path, a);
            if first {
                break;
            }
        }
        self.tree.reverse_children(path, 0);
        Some(path)
    }

    pub(crate) fn get_dependent_generic_param_type(&mut self, depth: i32, index: i32) -> N {
        if depth < 0 || index < 0 {
            return None;
        }
        let p = self.create(Kind::DependentGenericParamType)?;
        let d = self.create_index(Kind::Index, idx(depth))?;
        let i = self.create_index(Kind::Index, idx(index))?;
        self.tree.add_child(p, d);
        self.tree.add_child(p, i);
        Some(p)
    }

    fn demangle_generic_param_index(&mut self) -> N {
        if self.next_if(b'd') {
            let depth = self.demangle_index().wrapping_add(1);
            let index = self.demangle_index();
            return self.get_dependent_generic_param_type(depth, index);
        }
        if self.next_if(b'z') {
            return self.get_dependent_generic_param_type(0, 0);
        }
        if self.next_if(b's') {
            return self.create(Kind::ConstrainedExistentialSelf);
        }
        let i = self.demangle_index().wrapping_add(1);
        self.get_dependent_generic_param_type(0, i)
    }

    fn pop_protocol_conformance(&mut self) -> N {
        let gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        let module = self.pop_module();
        let proto = self.pop_protocol();
        let mut ty = self.pop_kind(Kind::Type);
        let mut ident = None;
        if ty.is_none() {
            ident = self.pop_kind(Kind::Identifier);
            ty = self.pop_kind(Kind::Type);
        }
        if gen_sig.is_some() {
            let d = self.create_with_children(Kind::DependentGenericType, &[gen_sig, ty]);
            ty = self.create_type(d);
        }
        let conf = self.create_with_children(Kind::ProtocolConformance, &[ty, proto, module]);
        self.add_child(conf, ident);
        conf
    }

    /// Swift's `isGenericParamType`.
    fn is_generic_param_type(&self, n: N, depth: u32) -> bool {
        let (mut n, mut depth) = (n, depth);
        loop {
            let Some(id) = n else { return false };
            if depth > MAX_DEPTH {
                return false;
            }
            match self.kind(id) {
                Kind::Type => (n, depth) = (self.child(id, 0), depth + 1),
                Kind::DependentGenericParamType => return true,
                _ => return false,
            }
        }
    }

    fn pop_associated_conformance_witness_accessor_subject(&mut self) -> N {
        if let Some(ty) = self.pop_kind(Kind::Type) {
            if self.is_generic_param_type(Some(ty), 0) {
                return Some(ty);
            }
            self.push_node(ty);
        }
        self.pop_assoc_type_path()
    }
}

impl Demangler<'_, '_> {
    fn demangle_thunk_or_specialization(&mut self) -> N {
        let c = self.next_char();
        match c {
            b'T' => match self.next_char() {
                b'I' => {
                    let e = self.pop_if(is_entity);
                    self.create_with_child(Kind::SILThunkIdentity, e)
                }
                _ => None,
            },
            b'c' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::CurryThunk, e)
            }
            b'j' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::DispatchThunk, e)
            }
            b'q' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::MethodDescriptor, e)
            }
            b'o' => self.create(Kind::ObjCAttribute),
            b'O' => self.create(Kind::NonObjCAttribute),
            b'D' => self.create(Kind::DynamicAttribute),
            b'd' => self.create(Kind::DirectMethodReferenceAttribute),
            b'E' => self.create(Kind::DistributedThunk),
            b'F' => self.create(Kind::DistributedAccessor),
            b'a' => self.create(Kind::PartialApplyObjCForwarder),
            b'A' => self.create(Kind::PartialApplyForwarder),
            b'm' => self.create(Kind::MergedFunction),
            b'X' => self.create(Kind::DynamicallyReplaceableFunctionVar),
            b'x' => self.create(Kind::DynamicallyReplaceableFunctionKey),
            b'I' => self.create(Kind::DynamicallyReplaceableFunctionImpl),
            b'Y' | b'Q' => {
                let d = self.demangle_index_as_node();
                let k = if c == b'Q' {
                    Kind::AsyncAwaitResumePartialFunction
                } else {
                    Kind::AsyncSuspendResumePartialFunction
                };
                self.create_with_child(k, d)
            }
            b'C' => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_child(Kind::CoroutineContinuationPrototype, t)
            }
            b'z' | b'Z' => {
                let flag_mode = self.demangle_index_as_node();
                let sig = self.pop_kind(Kind::DependentGenericSignature);
                let result_type = self.pop_kind(Kind::Type);
                let impl_type = self.pop_kind(Kind::Type);
                let k = if c == b'z' {
                    Kind::ObjCAsyncCompletionHandlerImpl
                } else {
                    Kind::CheckedObjCAsyncCompletionHandlerImpl
                };
                let node = self.create_with_children(k, &[impl_type, result_type, flag_mode]);
                if sig.is_some() {
                    self.add_child(node, sig);
                }
                node
            }
            b'V' => {
                let base = self.pop_if(is_entity);
                let derived = self.pop_if(is_entity);
                self.create_with_children(Kind::VTableThunk, &[derived, base])
            }
            b'W' => {
                let entity = self.pop_if(is_entity);
                let conf = self.pop_protocol_conformance();
                self.create_with_children(Kind::ProtocolWitness, &[conf, entity])
            }
            b'S' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::ProtocolSelfConformanceWitness, e)
            }
            b'R' | b'r' | b'y' => {
                let kind = match c {
                    b'R' => Kind::ReabstractionThunkHelper,
                    b'y' => Kind::ReabstractionThunkHelperWithSelf,
                    _ => Kind::ReabstractionThunk,
                };
                let thunk = self.create(kind);
                if let Some(sig) = self.pop_kind(Kind::DependentGenericSignature) {
                    self.add_child(thunk, Some(sig));
                }
                if kind == Kind::ReabstractionThunkHelperWithSelf {
                    let t = self.pop_kind(Kind::Type);
                    self.add_child(thunk, t);
                }
                let t = self.pop_kind(Kind::Type);
                self.add_child(thunk, t);
                let t = self.pop_kind(Kind::Type);
                self.add_child(thunk, t);
                thunk
            }
            b'g' => self.demangle_generic_specialization(Kind::GenericSpecialization, None),
            b'G' => self
                .demangle_generic_specialization(Kind::GenericSpecializationNotReAbstracted, None),
            b'B' => self.demangle_generic_specialization(
                Kind::GenericSpecializationInResilienceDomain,
                None,
            ),
            b't' => self.demangle_generic_specialization_with_dropped_arguments(),
            b's' => self
                .demangle_generic_specialization(Kind::GenericSpecializationPrespecialized, None),
            b'i' => self.demangle_generic_specialization(Kind::InlinedGenericFunction, None),
            b'p' | b'P' => {
                let k = if c == b'p' {
                    Kind::GenericPartialSpecialization
                } else {
                    Kind::GenericPartialSpecializationNotReAbstracted
                };
                let spec = self.demangle_spec_attributes(k);
                let t = self.pop_kind(Kind::Type);
                let param = self.create_with_child(Kind::GenericSpecializationParam, t);
                self.add_child(spec, param)
            }
            b'f' => self.demangle_function_specialization(),
            b'K' | b'k' => {
                let node_kind = if self.next_if_str(b"mu") {
                    Kind::KeyPathUnappliedMethodThunkHelper
                } else if self.next_if_str(b"MA") {
                    Kind::KeyPathAppliedMethodThunkHelper
                } else if c == b'K' {
                    Kind::KeyPathGetterThunkHelper
                } else {
                    Kind::KeyPathSetterThunkHelper
                };
                let is_serialized = self.next_if(b'q');
                let mut types = Vec::new();
                let mut node = self.pop_node();
                if node.is_none_or(|n| self.kind(n) != Kind::Type) {
                    return None;
                }
                while let Some(n) = node {
                    if self.kind(n) != Kind::Type {
                        break;
                    }
                    types.push(n);
                    node = self.pop_node();
                }
                let node = node?;
                let result = if self.kind(node) == Kind::DependentGenericSignature {
                    let decl = self.pop_node()?;
                    self.create_with_children(node_kind, &[Some(decl), Some(node)])?
                } else {
                    self.create_with_child(node_kind, Some(node))?
                };
                for &t in types.iter().rev() {
                    self.tree.add_child(result, t);
                }
                if is_serialized {
                    let s = self.create(Kind::IsSerialized);
                    self.add_child(Some(result), s);
                }
                Some(result)
            }
            b'l' => {
                let name = self.pop_assoc_type_name()?;
                self.create_with_child(Kind::AssociatedTypeDescriptor, Some(name))
            }
            b'L' => {
                let p = self.pop_protocol();
                self.create_with_child(Kind::ProtocolRequirementsBaseDescriptor, p)
            }
            b'M' => {
                let n = self.pop_assoc_type_name();
                self.create_with_child(Kind::DefaultAssociatedTypeMetadataAccessor, n)
            }
            b'n' | b'N' => {
                let requirement = self.pop_protocol();
                let subject = self.pop_associated_conformance_witness_accessor_subject();
                let proto = self.pop_kind(Kind::Type);
                let k = if c == b'n' {
                    Kind::AssociatedConformanceDescriptor
                } else {
                    Kind::DefaultAssociatedConformanceAccessor
                };
                self.create_with_children(k, &[proto, subject, requirement])
            }
            b'b' => {
                let requirement = self.pop_protocol();
                let proto = self.pop_kind(Kind::Type);
                self.create_with_children(Kind::BaseConformanceDescriptor, &[proto, requirement])
            }
            b'H' | b'h' => {
                let node_kind = if c == b'H' {
                    Kind::KeyPathEqualsThunkHelper
                } else {
                    Kind::KeyPathHashThunkHelper
                };
                let is_serialized = self.next_if(b'q');
                let mut generic_sig = None;
                let mut types = Vec::new();
                let node = self.pop_node()?;
                match self.kind(node) {
                    Kind::DependentGenericSignature => generic_sig = Some(node),
                    Kind::Type => types.push(node),
                    _ => return None,
                }
                while let Some(n) = self.pop_node() {
                    if self.kind(n) != Kind::Type {
                        return None;
                    }
                    types.push(n);
                }
                let result = self.create(node_kind)?;
                for &t in types.iter().rev() {
                    self.tree.add_child(result, t);
                }
                self.add_child(Some(result), generic_sig);
                if is_serialized {
                    let s = self.create(Kind::IsSerialized);
                    self.add_child(Some(result), s);
                }
                Some(result)
            }
            b'v' => {
                let i = self.demangle_index();
                if i < 0 {
                    return None;
                }
                if self.next_char() == b'r' {
                    return self.create_index(Kind::OutlinedReadOnlyObject, idx(i));
                }
                self.create_index(Kind::OutlinedVariable, idx(i))
            }
            b'e' => {
                let params = self.demangle_bridged_method_params();
                if params.is_empty() {
                    return None;
                }
                self.create_bytes(Kind::OutlinedBridgedMethod, &params)
            }
            b'u' => self.create(Kind::AsyncFunctionPointer),
            b'U' => {
                let global_actor = self.pop_kind(Kind::Type)?;
                let reabstraction = self.pop_node()?;
                let node = self.create(Kind::ReabstractionThunkHelperWithGlobalActor)?;
                self.tree.add_child(node, reabstraction);
                self.tree.add_child(node, global_actor);
                Some(node)
            }
            b'J' => match self.peek_char() {
                b'S' => {
                    self.next_char();
                    self.demangle_auto_diff_subset_parameters_thunk()
                }
                b'O' => {
                    self.next_char();
                    self.demangle_auto_diff_self_reordering_reabstraction_thunk()
                }
                b'V' => {
                    self.next_char();
                    self.demangle_auto_diff_function_or_simple_thunk(
                        Kind::AutoDiffDerivativeVTableThunk,
                    )
                }
                _ => self.demangle_auto_diff_function_or_simple_thunk(Kind::AutoDiffFunction),
            },
            b'w' => match self.next_char() {
                b'a' => self.create(Kind::BackDeploymentCopy),
                b'b' => self.create(Kind::BackDeploymentThunk),
                b'B' => self.create(Kind::BackDeploymentFallback),
                b'c' => self.create(Kind::CoroFunctionPointer),
                b'd' => self.create(Kind::DefaultOverride),
                b'S' => self.create(Kind::HasSymbolQuery),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Swift's `FunctionSigSpecializationParamKind`.
pub(crate) mod spec_param {
    pub const CONSTANT_PROP_FUNCTION: u64 = 0;
    pub const CONSTANT_PROP_GLOBAL: u64 = 1;
    pub const CONSTANT_PROP_INTEGER: u64 = 2;
    pub const CONSTANT_PROP_FLOAT: u64 = 3;
    pub const CONSTANT_PROP_STRING: u64 = 4;
    pub const CLOSURE_PROP: u64 = 5;
    pub const BOX_TO_VALUE: u64 = 6;
    pub const BOX_TO_STACK: u64 = 7;
    pub const IN_OUT_TO_OUT: u64 = 8;
    pub const CONSTANT_PROP_KEY_PATH: u64 = 9;
    pub const CONSTANT_PROP_STRUCT: u64 = 10;
    pub const CLOSURE_PROP_PREVIOUS_ARG: u64 = 11;
    pub const ESCAPING_CLOSURE_PROP: u64 = 12;
    pub const DEAD: u64 = 1 << 6;
    pub const OWNED_TO_GUARANTEED: u64 = 1 << 7;
    pub const SROA: u64 = 1 << 8;
    pub const GUARANTEED_TO_OWNED: u64 = 1 << 9;
    pub const EXISTENTIAL_TO_GENERIC: u64 = 1 << 10;
}

impl Demangler<'_, '_> {
    /// Pops every node into a new node of `kind`, in order.
    fn pop_all_into(&mut self, kind: Kind) -> N {
        let mut result = self.create(kind);
        while let Some(n) = self.pop_node() {
            result = self.add_child(result, Some(n));
        }
        if let Some(r) = result {
            self.tree.reverse_children(r, 0);
        }
        result
    }

    fn demangle_auto_diff_function_or_simple_thunk(&mut self, kind: Kind) -> N {
        let mut result = self.pop_all_into(kind);
        let k = self.demangle_auto_diff_function_kind();
        result = self.add_child(result, k);
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'p') {
            return None;
        }
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'r') {
            return None;
        }
        result
    }

    fn demangle_auto_diff_function_kind(&mut self) -> N {
        let k = self.next_char();
        if !matches!(k, b'f' | b'r' | b'd' | b'p') {
            return None;
        }
        self.create_index(Kind::AutoDiffFunctionKind, u64::from(k))
    }

    fn demangle_auto_diff_subset_parameters_thunk(&mut self) -> N {
        let mut result = self.pop_all_into(Kind::AutoDiffSubsetParametersThunk);
        let k = self.demangle_auto_diff_function_kind();
        result = self.add_child(result, k);
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'p') {
            return None;
        }
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'r') {
            return None;
        }
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'P') {
            return None;
        }
        result
    }

    fn demangle_auto_diff_self_reordering_reabstraction_thunk(&mut self) -> N {
        let mut result = self.create(Kind::AutoDiffSelfReorderingReabstractionThunk);
        let sig = self.pop_kind(Kind::DependentGenericSignature);
        self.add_child(result, sig);
        let t = self.pop_kind(Kind::Type);
        result = self.add_child(result, t);
        let t = self.pop_kind(Kind::Type);
        result = self.add_child(result, t);
        if let Some(r) = result {
            self.tree.reverse_children(r, 0);
        }
        let k = self.demangle_auto_diff_function_kind();
        self.add_child(result, k)
    }

    fn demangle_differentiability_witness(&mut self) -> N {
        let mut result = self.create(Kind::DifferentiabilityWitness);
        let sig = self.pop_kind(Kind::DependentGenericSignature);
        while let Some(n) = self.pop_node() {
            result = self.add_child(result, Some(n));
        }
        if let Some(r) = result {
            self.tree.reverse_children(r, 0);
        }
        let k @ (b'f' | b'r' | b'd' | b'l') = self.next_char() else {
            return None;
        };
        let i = self.create_index(Kind::Index, u64::from(k));
        result = self.add_child(result, i);
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'p') {
            return None;
        }
        let s = self.demangle_index_subset();
        result = self.add_child(result, s);
        if !self.next_if(b'r') {
            return None;
        }
        self.add_child(result, sig);
        result
    }

    fn demangle_index_subset(&mut self) -> N {
        let start = self.pos;
        while matches!(self.peek_char(), b'S' | b'U') {
            self.next_char();
        }
        if self.pos == start {
            return None;
        }
        let s = &self.text[start..self.pos];
        self.create_bytes(Kind::IndexSubset, s)
    }

    fn demangle_differentiable_function_type(&mut self) -> N {
        let k @ (b'f' | b'r' | b'd' | b'l') = self.next_char() else {
            return None;
        };
        self.create_index(Kind::DifferentiableFunctionType, u64::from(k))
    }

    fn demangle_bridged_method_params(&mut self) -> Vec<u8> {
        if self.next_if(b'_') {
            return Vec::new();
        }
        let mut s = Vec::new();
        let k = self.next_char();
        match k {
            b'o' | b'p' | b'a' | b'm' => s.push(k),
            _ => return Vec::new(),
        }
        while !self.next_if(b'_') {
            let c = self.next_char();
            if c != b'n' && c != b'b' && c != b'g' {
                return Vec::new();
            }
            s.push(c);
        }
        s
    }

    fn demangle_generic_specialization(&mut self, spec_kind: Kind, dropped: N) -> N {
        let spec = self.demangle_spec_attributes(spec_kind)?;
        if let Some(d) = dropped {
            let children: Vec<NodeId> = self.tree.children(d).to_vec();
            for a in children {
                self.tree.add_child(spec, a);
            }
        }
        let list = self.pop_type_list()?;
        let tys: Vec<NodeId> = self.tree.children(list).to_vec();
        for ty in tys {
            let p = self.create_with_child(Kind::GenericSpecializationParam, Some(ty))?;
            self.tree.add_child(spec, p);
        }
        Some(spec)
    }

    fn demangle_generic_specialization_with_dropped_arguments(&mut self) -> N {
        self.push_back();
        let tmp = self.create(Kind::GenericSpecialization);
        while self.next_if(b't') {
            let n = self.demangle_natural();
            let v = if n < 0 { 0 } else { n as u64 + 1 };
            let d = self.create_index(Kind::DroppedArgument, v);
            self.add_child(tmp, d);
        }
        let spec_kind = match self.next_char() {
            b'g' => Kind::GenericSpecialization,
            b'G' => Kind::GenericSpecializationNotReAbstracted,
            b'B' => Kind::GenericSpecializationInResilienceDomain,
            _ => return None,
        };
        self.demangle_generic_specialization(spec_kind, tmp)
    }

    fn demangle_function_specialization(&mut self) -> N {
        use spec_param::*;
        let mut spec = self.demangle_spec_attributes(Kind::FunctionSignatureSpecialization);
        if let Some(s) = spec
            && self.tree.child_kind(s, 0) == Some(Kind::RepresentationChanged)
        {
            return spec;
        }
        while spec.is_some() && !self.next_if(b'_') {
            let p = self.demangle_func_spec_param(Kind::FunctionSignatureSpecializationParam);
            spec = self.add_child(spec, p);
        }
        if !self.next_if(b'n') {
            let p = self.demangle_func_spec_param(Kind::FunctionSignatureSpecializationReturn);
            spec = self.add_child(spec, p);
        }
        let spec = spec?;
        let num = self.num_children(spec);
        for i in 0..num {
            let param = self.child(spec, num - i - 1)?;
            if self.kind(param) != Kind::FunctionSignatureSpecializationParam {
                continue;
            }
            let fixed = self.num_children(param);
            let mut to_add = Some(param);
            for ci in 0..fixed {
                let kind_nd = self.child(param, fixed - ci - 1)?;
                if self.kind(kind_nd) != Kind::FunctionSignatureSpecializationParamKind {
                    continue;
                }
                match self.tree.index(kind_nd) {
                    CLOSURE_PROP | ESCAPING_CLOSURE_PROP => {
                        while let Some(ty) = self.pop_kind(Kind::Type) {
                            to_add = self.add_child(to_add, Some(ty));
                        }
                    }
                    CONSTANT_PROP_KEY_PATH => {
                        let t = self.pop_kind(Kind::Type);
                        to_add = self.add_child(to_add, t);
                        let t = self.pop_kind(Kind::Type);
                        to_add = self.add_child(to_add, t);
                    }
                    CONSTANT_PROP_STRUCT => {
                        let t = self.pop_kind(Kind::Type);
                        to_add = self.add_child(to_add, t);
                        continue;
                    }
                    CONSTANT_PROP_FUNCTION | CONSTANT_PROP_GLOBAL | CONSTANT_PROP_STRING => {}
                    _ => continue,
                }
                let id = self.pop_kind(Kind::Identifier);
                to_add = self.add_child(to_add, id);
            }
            to_add?;
            self.tree.reverse_children(param, fixed);
        }
        Some(spec)
    }
}

const MAX_SPECIALIZATION_PASS: i32 = 10;

impl Demangler<'_, '_> {
    fn spec_param_kind(&mut self, value: u64) -> N {
        self.create_index(Kind::FunctionSignatureSpecializationParamKind, value)
    }

    fn demangle_func_spec_param(&mut self, kind: Kind) -> N {
        use spec_param::*;
        let param = self.create(kind);
        match self.next_char() {
            b'n' => param,
            b'c' => {
                let k = self.spec_param_kind(CLOSURE_PROP);
                self.add_child(param, k)
            }
            b'E' => {
                let k = self.spec_param_kind(ESCAPING_CLOSURE_PROP);
                self.add_child(param, k)
            }
            b'C' => {
                let k = self.spec_param_kind(CLOSURE_PROP_PREVIOUS_ARG);
                self.add_child(param, k);
                let prev = self.demangle_natural();
                if prev < 0 {
                    return None;
                }
                let p =
                    self.create_index(Kind::FunctionSignatureSpecializationParamPayload, idx(prev));
                self.add_child(param, p)
            }
            b'p' => loop {
                match self.next_char() {
                    b'S' => {
                        let k = self.spec_param_kind(CONSTANT_PROP_STRUCT);
                        self.add_child(param, k);
                    }
                    b'f' => {
                        let k = self.spec_param_kind(CONSTANT_PROP_FUNCTION);
                        self.add_child(param, k);
                    }
                    b'g' => {
                        let k = self.spec_param_kind(CONSTANT_PROP_GLOBAL);
                        self.add_child(param, k);
                    }
                    b'i' => {
                        self.add_func_spec_param_number(param, CONSTANT_PROP_INTEGER)?;
                    }
                    b'd' => {
                        self.add_func_spec_param_number(param, CONSTANT_PROP_FLOAT)?;
                    }
                    b's' => {
                        let encoding = match self.next_char() {
                            b'b' => "u8",
                            b'w' => "u16",
                            b'c' => "objc",
                            _ => return None,
                        };
                        let k = self.spec_param_kind(CONSTANT_PROP_STRING);
                        self.add_child(param, k);
                        let p = self.create_text(
                            Kind::FunctionSignatureSpecializationParamPayload,
                            encoding,
                        );
                        self.add_child(param, p);
                    }
                    b'k' => {
                        let k = self.spec_param_kind(CONSTANT_PROP_KEY_PATH);
                        self.add_child(param, k);
                    }
                    _ => {
                        self.push_back();
                        return param;
                    }
                }
            },
            b'e' => {
                let mut v = EXISTENTIAL_TO_GENERIC;
                if self.next_if(b'D') {
                    v |= DEAD;
                }
                if self.next_if(b'G') {
                    v |= OWNED_TO_GUARANTEED;
                }
                if self.next_if(b'O') {
                    v |= GUARANTEED_TO_OWNED;
                }
                if self.next_if(b'X') {
                    v |= SROA;
                }
                let k = self.spec_param_kind(v);
                self.add_child(param, k)
            }
            b'd' => {
                let mut v = DEAD;
                if self.next_if(b'G') {
                    v |= OWNED_TO_GUARANTEED;
                }
                if self.next_if(b'O') {
                    v |= GUARANTEED_TO_OWNED;
                }
                if self.next_if(b'X') {
                    v |= SROA;
                }
                let k = self.spec_param_kind(v);
                self.add_child(param, k)
            }
            b'g' => {
                let mut v = OWNED_TO_GUARANTEED;
                if self.next_if(b'X') {
                    v |= SROA;
                }
                let k = self.spec_param_kind(v);
                self.add_child(param, k)
            }
            b'o' => {
                let mut v = GUARANTEED_TO_OWNED;
                if self.next_if(b'X') {
                    v |= SROA;
                }
                let k = self.spec_param_kind(v);
                self.add_child(param, k)
            }
            b'x' => {
                let k = self.spec_param_kind(SROA);
                self.add_child(param, k)
            }
            b'i' => {
                let k = self.spec_param_kind(BOX_TO_VALUE);
                self.add_child(param, k)
            }
            b's' => {
                let k = self.spec_param_kind(BOX_TO_STACK);
                self.add_child(param, k)
            }
            b'r' => {
                let k = self.spec_param_kind(IN_OUT_TO_OUT);
                self.add_child(param, k)
            }
            _ => None,
        }
    }

    fn add_func_spec_param_number(&mut self, param: N, kind: u64) -> N {
        let param = param?;
        let k = self.spec_param_kind(kind)?;
        self.tree.add_child(param, k);
        let start = self.pos;
        while is_digit(self.peek_char()) {
            self.next_char();
        }
        if self.pos == start {
            return None;
        }
        let s = &self.text[start..self.pos];
        let p = self.create_bytes(Kind::FunctionSignatureSpecializationParamPayload, s);
        self.add_child(Some(param), p)
    }

    fn demangle_spec_attributes(&mut self, spec_kind: Kind) -> N {
        let is_serialized = self.next_if(b'q');
        let async_removed = self.next_if(b'a');
        let representation_changed = self.next_if(b'r');
        // (A C `char`, signed.)
        let pass_id = i32::from(self.next_char() as i8) - i32::from(b'0');
        if !(0..MAX_SPECIALIZATION_PASS).contains(&pass_id) {
            return None;
        }
        let spec = self.create(spec_kind)?;
        if is_serialized {
            let n = self.create(Kind::IsSerialized)?;
            self.tree.add_child(spec, n);
        }
        if async_removed {
            let n = self.create(Kind::AsyncRemoved)?;
            self.tree.add_child(spec, n);
        }
        if representation_changed {
            let n = self.create(Kind::RepresentationChanged)?;
            self.tree.add_child(spec, n);
        }
        let n = self.create_index(Kind::SpecializationPassID, idx(pass_id))?;
        self.tree.add_child(spec, n);
        Some(spec)
    }
}

impl Demangler<'_, '_> {
    fn demangle_witness(&mut self) -> N {
        let c = self.next_char();
        match c {
            b'C' => {
                let e = self.pop_if(is_entity);
                self.create_with_child(Kind::EnumCase, e)
            }
            b'V' => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_child(Kind::ValueWitnessTable, t)
            }
            b'v' => {
                let directness = match self.next_char() {
                    b'd' => 0,
                    b'i' => 1,
                    _ => return None,
                };
                let d = self.create_index(Kind::Directness, directness);
                let e = self.pop_if(is_entity);
                self.create_with_children(Kind::FieldOffset, &[d, e])
            }
            b'S' => {
                let p = self.pop_protocol();
                self.create_with_child(Kind::ProtocolSelfConformanceWitnessTable, p)
            }
            b'P' | b'p' | b'G' | b'I' | b'r' | b'a' => {
                let k = match c {
                    b'P' => Kind::ProtocolWitnessTable,
                    b'p' => Kind::ProtocolWitnessTablePattern,
                    b'G' => Kind::GenericProtocolWitnessTable,
                    b'I' => Kind::GenericProtocolWitnessTableInstantiationFunction,
                    b'r' => Kind::ResilientProtocolWitnessTable,
                    _ => Kind::ProtocolWitnessTableAccessor,
                };
                let conf = self.pop_protocol_conformance();
                self.create_with_child(k, conf)
            }
            b'l' | b'L' => {
                let conf = self.pop_protocol_conformance();
                let ty = self.pop_kind(Kind::Type);
                let k = if c == b'l' {
                    Kind::LazyProtocolWitnessTableAccessor
                } else {
                    Kind::LazyProtocolWitnessTableCacheVariable
                };
                self.create_with_children(k, &[ty, conf])
            }
            b't' => {
                let name = self.pop_if(is_decl_name);
                let conf = self.pop_protocol_conformance();
                self.create_with_children(Kind::AssociatedTypeMetadataAccessor, &[conf, name])
            }
            b'T' => {
                let proto = self.pop_kind(Kind::Type);
                let conforming = self.pop_assoc_type_path();
                let conf = self.pop_protocol_conformance();
                self.create_with_children(
                    Kind::AssociatedTypeWitnessTableAccessor,
                    &[conf, conforming, proto],
                )
            }
            b'b' => {
                let proto = self.pop_kind(Kind::Type);
                let conf = self.pop_protocol_conformance();
                self.create_with_children(Kind::BaseWitnessTableAccessor, &[conf, proto])
            }
            b'O' => {
                let oc = self.next_char();
                let k = match oc {
                    b'B' => Kind::OutlinedInitializeWithTakeNoValueWitness,
                    b'C' => Kind::OutlinedInitializeWithCopyNoValueWitness,
                    b'D' => Kind::OutlinedAssignWithTakeNoValueWitness,
                    b'F' => Kind::OutlinedAssignWithCopyNoValueWitness,
                    b'H' => Kind::OutlinedDestroyNoValueWitness,
                    b'y' => Kind::OutlinedCopy,
                    b'e' => Kind::OutlinedConsume,
                    b'r' => Kind::OutlinedRetain,
                    b's' => Kind::OutlinedRelease,
                    b'b' => Kind::OutlinedInitializeWithTake,
                    b'c' => Kind::OutlinedInitializeWithCopy,
                    b'd' => Kind::OutlinedAssignWithTake,
                    b'f' => Kind::OutlinedAssignWithCopy,
                    b'h' => Kind::OutlinedDestroy,
                    b'g' => Kind::OutlinedEnumGetTag,
                    b'i' => Kind::OutlinedEnumTagStore,
                    b'j' => Kind::OutlinedEnumProjectDataForLoad,
                    _ => return None,
                };
                if matches!(oc, b'i' | b'j') {
                    let case_idx = self.demangle_index_as_node();
                    if let Some(sig) = self.pop_kind(Kind::DependentGenericSignature) {
                        let t = self.pop_kind(Kind::Type);
                        return self.create_with_children(k, &[t, Some(sig), case_idx]);
                    }
                    let t = self.pop_kind(Kind::Type);
                    return self.create_with_children(k, &[t, case_idx]);
                }
                if let Some(sig) = self.pop_kind(Kind::DependentGenericSignature) {
                    let t = self.pop_kind(Kind::Type);
                    return self.create_with_children(k, &[t, Some(sig)]);
                }
                let t = self.pop_kind(Kind::Type);
                self.create_with_child(k, t)
            }
            b'Z' | b'z' => {
                let decl_list = self.create(Kind::GlobalVariableOnceDeclList)?;
                let mut vars = Vec::new();
                while self.pop_kind(Kind::FirstElementMarker).is_some() {
                    let ident = self.pop_if(is_decl_name)?;
                    vars.push(ident);
                }
                for &v in vars.iter().rev() {
                    self.tree.add_child(decl_list, v);
                }
                let context = self.pop_context()?;
                let k = if c == b'Z' {
                    Kind::GlobalVariableOnceFunction
                } else {
                    Kind::GlobalVariableOnceToken
                };
                self.create_with_children(k, &[Some(context), Some(decl_list)])
            }
            b'J' => self.demangle_differentiability_witness(),
            _ => None,
        }
    }
}

impl Demangler<'_, '_> {
    fn wrap_popped_type(&mut self, kind: Kind) -> N {
        let t = self.pop_kind(Kind::Type);
        let n = self.create_with_child(kind, t);
        self.create_type(n)
    }

    fn demangle_special_type(&mut self) -> N {
        let special = self.next_char();
        match special {
            b'E' => self.pop_function_type(Kind::NoEscapeFunctionType, false),
            b'A' => self.pop_function_type(Kind::EscapingAutoClosureType, false),
            b'f' => self.pop_function_type(Kind::ThinFunctionType, false),
            b'K' => self.pop_function_type(Kind::AutoClosureType, false),
            b'U' => self.pop_function_type(Kind::UncurriedFunctionType, false),
            b'L' => self.pop_function_type(Kind::EscapingObjCBlock, false),
            b'B' => self.pop_function_type(Kind::ObjCBlock, false),
            b'C' => self.pop_function_type(Kind::CFunctionPointer, false),
            b'O' => {
                if self.next_if(b'o') {
                    self.pop_function_type(Kind::CalledAtMostOnceFunctionType, false)
                } else {
                    self.pop_function_type(Kind::CalledOnceFunctionType, false)
                }
            }
            b'g' | b'G' => self.demangle_extended_existential_shape(special),
            b'j' => self.demangle_symbolic_extended_existential_type(),
            b'y' => {
                let yields = if self.pop_kind(Kind::EmptyList).is_some() {
                    let t = self.create(Kind::Tuple);
                    self.create_type(t)
                } else {
                    self.pop_kind(Kind::Type)
                };
                self.create_with_child(Kind::YieldTypes, yields)
            }
            b'z' => match self.next_char() {
                b'B' => self.pop_function_type(Kind::ObjCBlock, true),
                b'C' => self.pop_function_type(Kind::CFunctionPointer, true),
                _ => None,
            },
            b'o' => self.wrap_popped_type(Kind::Unowned),
            b'u' => self.wrap_popped_type(Kind::Unmanaged),
            b'w' => self.wrap_popped_type(Kind::Weak),
            b'b' => self.wrap_popped_type(Kind::SILBoxType),
            b'D' => self.wrap_popped_type(Kind::DynamicSelf),
            b'M' | b'm' => {
                let mtr = self.demangle_metatype_representation();
                let ty = self.pop_kind(Kind::Type);
                let k = if special == b'M' {
                    Kind::Metatype
                } else {
                    Kind::ExistentialMetatype
                };
                let n = self.create_with_children(k, &[mtr, ty]);
                self.create_type(n)
            }
            b'P' => {
                let reqs = self.demangle_constrained_existential_requirement_list();
                let base = self.pop_kind(Kind::Type);
                let n = self.create_with_children(Kind::ConstrainedExistential, &[base, reqs]);
                self.create_type(n)
            }
            b'p' => self.wrap_popped_type(Kind::ExistentialMetatype),
            b'c' => {
                let superclass = self.pop_kind(Kind::Type);
                let protocols = self.demangle_protocol_list();
                let n = self
                    .create_with_children(Kind::ProtocolListWithClass, &[protocols, superclass]);
                self.create_type(n)
            }
            b'l' => {
                let protocols = self.demangle_protocol_list();
                let n = self.create_with_child(Kind::ProtocolListWithAnyObject, protocols);
                self.create_type(n)
            }
            b'X' | b'x' => {
                let mut signature = None;
                let mut generic_args = None;
                if special == b'X' {
                    signature = Some(self.pop_kind(Kind::DependentGenericSignature)?);
                    generic_args = Some(self.pop_type_list()?);
                }
                let field_types = self.pop_type_list()?;
                let layout = self.create(Kind::SILBoxLayout)?;
                for i in 0..self.num_children(field_types) {
                    let mut field_type = self.child(field_types, i)?;
                    let mut is_mutable = false;
                    let c0 = self.child(field_type, 0)?;
                    if self.kind(c0) == Kind::InOut {
                        is_mutable = true;
                        let inner = self.child(c0, 0);
                        field_type = self.create_type(inner)?;
                    }
                    let field = self.create(if is_mutable {
                        Kind::SILBoxMutableField
                    } else {
                        Kind::SILBoxImmutableField
                    })?;
                    self.tree.add_child(field, field_type);
                    self.tree.add_child(layout, field);
                }
                let box_ty = self.create(Kind::SILBoxTypeWithLayout)?;
                self.tree.add_child(box_ty, layout);
                if let Some(sig) = signature {
                    self.tree.add_child(box_ty, sig);
                    self.add_child(Some(box_ty), generic_args);
                }
                self.create_type(Some(box_ty))
            }
            b'Y' => self.demangle_any_generic_type(Kind::OtherNominalType),
            b'Z' => {
                let types = self.pop_type_list();
                let name = self.pop_kind(Kind::Identifier);
                let parent = self.pop_context();
                let mut anon = self.create(Kind::AnonymousContext);
                anon = self.add_child(anon, name);
                anon = self.add_child(anon, parent);
                self.add_child(anon, types)
            }
            b'e' => {
                let n = self.create(Kind::ErrorType);
                self.create_type(n)
            }
            b'S' => match self.next_char() {
                b'q' => self.wrap_popped_type(Kind::SugaredOptional),
                b'a' => self.wrap_popped_type(Kind::SugaredArray),
                b'A' => {
                    let element = self.pop_kind(Kind::Type);
                    let count = self.pop_kind(Kind::Type);
                    let n = self.create_with_children(Kind::SugaredInlineArray, &[count, element]);
                    self.create_type(n)
                }
                b'D' => {
                    let value = self.pop_kind(Kind::Type);
                    let key = self.pop_kind(Kind::Type);
                    let n = self.create_with_children(Kind::SugaredDictionary, &[key, value]);
                    self.create_type(n)
                }
                b'p' => self.wrap_popped_type(Kind::SugaredParen),
                _ => None,
            },
            _ => None,
        }
    }

    fn demangle_symbolic_extended_existential_type(&mut self) -> N {
        let retro = self.pop_retroactive_conformances();
        let args = self.create(Kind::TypeList)?;
        while let Some(ty) = self.pop_kind(Kind::Type) {
            self.tree.add_child(args, ty);
        }
        self.tree.reverse_children(args, 0);
        let shape = self.pop_node()?;
        if !matches!(
            self.kind(shape),
            Kind::UniqueExtendedExistentialTypeShapeSymbolicReference
                | Kind::NonUniqueExtendedExistentialTypeShapeSymbolicReference
        ) {
            return None;
        }
        let ty = if retro.is_none() {
            self.create_with_children(
                Kind::SymbolicExtendedExistentialType,
                &[Some(shape), Some(args)],
            )
        } else {
            self.create_with_children(
                Kind::SymbolicExtendedExistentialType,
                &[Some(shape), Some(args), retro],
            )
        };
        self.create_type(ty)
    }

    fn demangle_extended_existential_shape(&mut self, kind: u8) -> N {
        let ty = self.pop_kind(Kind::Type);
        let mut gen_sig = None;
        if kind == b'G' {
            gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        }
        if gen_sig.is_some() {
            self.create_with_children(Kind::ExtendedExistentialTypeShape, &[gen_sig, ty])
        } else {
            self.create_with_child(Kind::ExtendedExistentialTypeShape, ty)
        }
    }

    fn demangle_metatype_representation(&mut self) -> N {
        let s = match self.next_char() {
            b't' => "@thin",
            b'T' => "@thick",
            b'o' => "@objc_metatype",
            _ => return None,
        };
        self.create_text(Kind::MetatypeRepresentation, s)
    }

    fn demangle_accessor(&mut self, child: N) -> N {
        let kind = match self.next_char() {
            b'm' => Kind::MaterializeForSet,
            b's' => Kind::Setter,
            b'g' => Kind::Getter,
            b'G' => Kind::GlobalGetter,
            b'w' => Kind::WillSet,
            b'W' => Kind::DidSet,
            b'r' => Kind::ReadAccessor,
            b'y' => Kind::YieldingBorrowAccessor,
            b'M' => Kind::ModifyAccessor,
            b'x' => Kind::YieldingMutateAccessor,
            b'i' => Kind::InitAccessor,
            b'b' => Kind::BorrowAccessor,
            b'z' => Kind::MutateAccessor,
            b'a' => match self.next_char() {
                b'O' => Kind::OwningMutableAddressor,
                b'o' => Kind::NativeOwningMutableAddressor,
                b'P' => Kind::NativePinningMutableAddressor,
                b'u' => Kind::UnsafeMutableAddressor,
                _ => return None,
            },
            b'l' => match self.next_char() {
                b'O' => Kind::OwningAddressor,
                b'o' => Kind::NativeOwningAddressor,
                b'p' => Kind::NativePinningAddressor,
                b'u' => Kind::UnsafeAddressor,
                _ => return None,
            },
            b'p' => return child,
            _ => return None,
        };
        self.create_with_child(kind, child)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntityArgs {
    None,
    TypeAndMaybePrivateName,
    TypeAndIndex,
    Index,
}

impl Demangler<'_, '_> {
    fn demangle_function_entity(&mut self) -> N {
        use EntityArgs as A;
        let (args, kind) = match self.next_char() {
            b'D' => (A::None, Kind::Deallocator),
            b'd' => (A::None, Kind::Destructor),
            b'Z' => (A::None, Kind::IsolatedDeallocator),
            b'E' => (A::None, Kind::IVarDestroyer),
            b'e' => (A::None, Kind::IVarInitializer),
            b'i' => (A::None, Kind::Initializer),
            b'C' => (A::TypeAndMaybePrivateName, Kind::Allocator),
            b'c' => (A::TypeAndMaybePrivateName, Kind::Constructor),
            b'U' => (A::TypeAndIndex, Kind::ExplicitClosure),
            b'u' => (A::TypeAndIndex, Kind::ImplicitClosure),
            b'A' => (A::Index, Kind::DefaultArgumentInitializer),
            b'm' => return self.demangle_entity(Kind::Macro),
            b'M' => return self.demangle_macro_expansion(),
            b'p' => return self.demangle_entity(Kind::GenericTypeParamDecl),
            b'P' => (A::None, Kind::PropertyWrapperBackingInitializer),
            b'F' => (A::None, Kind::PropertyWrappedFieldInitAccessor),
            b'W' => (A::None, Kind::PropertyWrapperInitFromProjectedValue),
            _ => return None,
        };
        let (mut name_or_index, mut param_type, mut label_list) = (None, None, None);
        match args {
            A::None => {}
            A::TypeAndMaybePrivateName => {
                name_or_index = self.pop_kind(Kind::PrivateDeclName);
                param_type = self.pop_kind(Kind::Type);
                label_list = self.pop_function_param_labels(param_type);
            }
            A::TypeAndIndex => {
                name_or_index = self.demangle_index_as_node();
                param_type = self.pop_kind(Kind::Type);
            }
            A::Index => name_or_index = self.demangle_index_as_node(),
        }
        let ctx = self.pop_context();
        let mut entity = self.create_with_child(kind, ctx);
        match args {
            A::None => {}
            A::Index => entity = self.add_child(entity, name_or_index),
            A::TypeAndMaybePrivateName => {
                self.add_child(entity, label_list);
                entity = self.add_child(entity, param_type);
                self.add_child(entity, name_or_index);
            }
            A::TypeAndIndex => {
                entity = self.add_child(entity, name_or_index);
                entity = self.add_child(entity, param_type);
            }
        }
        entity
    }

    fn demangle_entity(&mut self, kind: Kind) -> N {
        let ty = self.pop_kind(Kind::Type);
        let label_list = self.pop_function_param_labels(ty);
        let name = self.pop_if(is_decl_name);
        let context = self.pop_context();
        let result = if label_list.is_some() {
            self.create_with_children(kind, &[context, name, label_list, ty])
        } else {
            self.create_with_children(kind, &[context, name, ty])
        };
        self.set_parent_for_opaque_return_type_nodes(result, ty)
    }

    fn demangle_variable(&mut self) -> N {
        let v = self.demangle_entity(Kind::Variable);
        self.demangle_accessor(v)
    }

    fn demangle_subscript(&mut self) -> N {
        let private_name = self.pop_kind(Kind::PrivateDeclName);
        let ty = self.pop_kind(Kind::Type);
        let label_list = self.pop_function_param_labels(ty);
        let context = self.pop_context();
        ty?;
        let mut sub = self.create(Kind::Subscript);
        sub = self.add_child(sub, context);
        self.add_child(sub, label_list);
        sub = self.add_child(sub, ty);
        self.add_child(sub, private_name);
        sub = self.set_parent_for_opaque_return_type_nodes(sub, ty);
        self.demangle_accessor(sub)
    }

    fn demangle_protocol_list(&mut self) -> N {
        let list = self.create(Kind::TypeList)?;
        let proto_list = self.create_with_child(Kind::ProtocolList, Some(list));
        if self.pop_kind(Kind::EmptyList).is_none() {
            loop {
                let first = self.pop_kind(Kind::FirstElementMarker).is_some();
                let p = self.pop_protocol()?;
                self.tree.add_child(list, p);
                if first {
                    break;
                }
            }
            self.tree.reverse_children(list, 0);
        }
        proto_list
    }

    fn demangle_protocol_list_type(&mut self) -> N {
        let l = self.demangle_protocol_list();
        self.create_type(l)
    }

    fn demangle_constrained_existential_requirement_list(&mut self) -> N {
        let list = self.create(Kind::ConstrainedExistentialRequirementList)?;
        loop {
            let first = self.pop_kind(Kind::FirstElementMarker).is_some();
            let r = self.pop_if(is_requirement)?;
            self.tree.add_child(list, r);
            if first {
                break;
            }
        }
        self.tree.reverse_children(list, 0);
        Some(list)
    }

    fn demangle_generic_signature(&mut self, has_param_counts: bool) -> N {
        let sig = self.create(Kind::DependentGenericSignature)?;
        if has_param_counts {
            while !self.next_if(b'l') {
                let mut count = 0;
                if !self.next_if(b'z') {
                    count = self.demangle_index().wrapping_add(1);
                }
                if count < 0 {
                    return None;
                }
                let c = self.create_index(Kind::DependentGenericParamCount, idx(count))?;
                self.tree.add_child(sig, c);
                if self.pos >= self.text.len() && self.peek_char() == 0 {
                    // (Swift loops on: each `nextIf` fails and each count is
                    // an index of -1000 + 1, which stops it above.)
                }
            }
        } else {
            let c = self.create_index(Kind::DependentGenericParamCount, 1)?;
            self.tree.add_child(sig, c);
        }
        let num_counts = self.num_children(sig);
        while let Some(r) = self.pop_if(is_requirement) {
            self.tree.add_child(sig, r);
        }
        self.tree.reverse_children(sig, num_counts);
        Some(sig)
    }
}

/// Swift's `ValueWitnessKind`s, in order, with their manglings.
pub(crate) const VALUE_WITNESSES: [(&[u8; 2], &str); 24] = [
    (b"al", "allocateBuffer"),
    (b"ca", "assignWithCopy"),
    (b"ta", "assignWithTake"),
    (b"de", "deallocateBuffer"),
    (b"xx", "destroy"),
    (b"XX", "destroyBuffer"),
    (b"Xx", "destroyArray"),
    (b"CP", "initializeBufferWithCopyOfBuffer"),
    (b"Cp", "initializeBufferWithCopy"),
    (b"cp", "initializeWithCopy"),
    (b"Tk", "initializeBufferWithTake"),
    (b"tk", "initializeWithTake"),
    (b"pr", "projectBuffer"),
    (b"TK", "initializeBufferWithTakeOfBuffer"),
    (b"Cc", "initializeArrayWithCopy"),
    (b"Tt", "initializeArrayWithTakeFrontToBack"),
    (b"tT", "initializeArrayWithTakeBackToFront"),
    (b"xs", "storeExtraInhabitant"),
    (b"xg", "getExtraInhabitantIndex"),
    (b"ug", "getEnumTag"),
    (b"up", "destructiveProjectEnumData"),
    (b"ui", "destructiveInjectEnumTag"),
    (b"et", "getEnumTagSinglePayload"),
    (b"st", "storeEnumTagSinglePayload"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeKind {
    Generic,
    Assoc,
    CompoundAssoc,
    Substitution,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstraintKind {
    Protocol,
    BaseClass,
    SameType,
    SameShape,
    Layout,
    PackMarker,
    Inverse,
    ValueMarker,
}

fn is_macro_expansion_node_kind(k: Kind) -> bool {
    matches!(
        k,
        Kind::AccessorAttachedMacroExpansion
            | Kind::MemberAttributeAttachedMacroExpansion
            | Kind::FreestandingMacroExpansion
            | Kind::MemberAttachedMacroExpansion
            | Kind::PeerAttachedMacroExpansion
            | Kind::ConformanceAttachedMacroExpansion
            | Kind::ExtensionAttachedMacroExpansion
            | Kind::MacroExpansionLoc
    )
}

impl Demangler<'_, '_> {
    fn demangle_generic_requirement(&mut self) -> N {
        use ConstraintKind as C;
        use TypeKind as T;
        let mut inverse_kind = None;
        let (ck, tk) = match self.next_char() {
            b'V' => (C::ValueMarker, T::Generic),
            b'v' => (C::PackMarker, T::Generic),
            b'c' => (C::BaseClass, T::Assoc),
            b'C' => (C::BaseClass, T::CompoundAssoc),
            b'b' => (C::BaseClass, T::Generic),
            b'B' => (C::BaseClass, T::Substitution),
            b't' => (C::SameType, T::Assoc),
            b'T' => (C::SameType, T::CompoundAssoc),
            b's' => (C::SameType, T::Generic),
            b'S' => (C::SameType, T::Substitution),
            b'm' => (C::Layout, T::Assoc),
            b'M' => (C::Layout, T::CompoundAssoc),
            b'l' => (C::Layout, T::Generic),
            b'L' => (C::Layout, T::Substitution),
            b'p' => (C::Protocol, T::Assoc),
            b'P' => (C::Protocol, T::CompoundAssoc),
            b'Q' => (C::Protocol, T::Substitution),
            b'h' => (C::SameShape, T::Generic),
            c @ (b'i' | b'I' | b'j' | b'J') => {
                inverse_kind = Some(self.demangle_index_as_node()?);
                let t = match c {
                    b'i' => T::Generic,
                    b'I' => T::Substitution,
                    b'j' => T::Assoc,
                    _ => T::CompoundAssoc,
                };
                (C::Inverse, t)
            }
            _ => {
                self.push_back();
                (C::Protocol, T::Generic)
            }
        };
        let constr_ty = match tk {
            T::Generic => {
                let p = self.demangle_generic_param_index();
                self.create_type(p)
            }
            T::Assoc => {
                let p = self.demangle_generic_param_index();
                let t = self.demangle_associated_type_simple(p);
                self.add_substitution(t);
                t
            }
            T::CompoundAssoc => {
                let p = self.demangle_generic_param_index();
                let t = self.demangle_associated_type_compound(p);
                self.add_substitution(t);
                t
            }
            T::Substitution => self.pop_kind(Kind::Type),
        };
        match ck {
            C::ValueMarker => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_children(Kind::DependentGenericParamValueMarker, &[constr_ty, t])
            }
            C::PackMarker => {
                self.create_with_child(Kind::DependentGenericParamPackMarker, constr_ty)
            }
            C::Protocol => {
                let p = self.pop_protocol();
                self.create_with_children(
                    Kind::DependentGenericConformanceRequirement,
                    &[constr_ty, p],
                )
            }
            C::Inverse => self.create_with_children(
                Kind::DependentGenericInverseConformanceRequirement,
                &[constr_ty, inverse_kind],
            ),
            C::BaseClass => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_children(
                    Kind::DependentGenericConformanceRequirement,
                    &[constr_ty, t],
                )
            }
            C::SameType => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_children(
                    Kind::DependentGenericSameTypeRequirement,
                    &[constr_ty, t],
                )
            }
            C::SameShape => {
                let t = self.pop_kind(Kind::Type);
                self.create_with_children(
                    Kind::DependentGenericSameShapeRequirement,
                    &[constr_ty, t],
                )
            }
            C::Layout => {
                let c = self.next_char();
                let mut size = None;
                let mut alignment = None;
                let name: &str = match c {
                    b'U' => "U",
                    b'R' => "R",
                    b'N' => "N",
                    b'C' => "C",
                    b'D' => "D",
                    b'T' => "T",
                    b'B' => "B",
                    b'E' | b'M' => {
                        size = Some(self.demangle_index_as_node()?);
                        alignment = self.demangle_index_as_node();
                        if c == b'E' { "E" } else { "M" }
                    }
                    b'e' | b'm' | b'S' => {
                        size = Some(self.demangle_index_as_node()?);
                        match c {
                            b'e' => "e",
                            b'm' => "m",
                            _ => "S",
                        }
                    }
                    _ => return None,
                };
                let name_node = self.create_text(Kind::Identifier, name);
                let req = self.create_with_children(
                    Kind::DependentGenericLayoutRequirement,
                    &[constr_ty, name_node],
                );
                self.add_child(req, size);
                self.add_child(req, alignment);
                req
            }
        }
    }

    fn demangle_generic_type(&mut self) -> N {
        let gen_sig = self.pop_kind(Kind::DependentGenericSignature);
        let ty = self.pop_kind(Kind::Type);
        let n = self.create_with_children(Kind::DependentGenericType, &[gen_sig, ty]);
        self.create_type(n)
    }

    fn demangle_value_witness(&mut self) -> N {
        let code = [self.next_char(), self.next_char()];
        let kind = VALUE_WITNESSES.iter().position(|(m, _)| **m == code)?;
        let vw = self.create(Kind::ValueWitness);
        let i = self.create_index(Kind::Index, kind as u64);
        self.add_child(vw, i);
        let t = self.pop_kind(Kind::Type);
        self.add_child(vw, t)
    }

    fn demangle_macro_expansion(&mut self) -> N {
        let (kind, is_attached, is_freestanding) = match self.next_char() {
            b'a' => (Kind::AccessorAttachedMacroExpansion, true, false),
            b'r' => (Kind::MemberAttributeAttachedMacroExpansion, true, false),
            b'm' => (Kind::MemberAttachedMacroExpansion, true, false),
            b'p' => (Kind::PeerAttachedMacroExpansion, true, false),
            b'c' => (Kind::ConformanceAttachedMacroExpansion, true, false),
            b'e' => (Kind::ExtensionAttachedMacroExpansion, true, false),
            b'q' => (Kind::PreambleAttachedMacroExpansion, true, false),
            b'b' => (Kind::BodyAttachedMacroExpansion, true, false),
            b'f' => (Kind::FreestandingMacroExpansion, false, true),
            b'u' => (Kind::MacroExpansionUniqueName, false, false),
            b'X' => {
                let line = self.demangle_index();
                let col = self.demangle_index();
                let line_node = self.create_index(Kind::Index, idx(line));
                let col_node = self.create_index(Kind::Index, idx(col));
                let buffer = self.pop_kind(Kind::Identifier);
                let module = self.pop_kind(Kind::Identifier);
                return self.create_with_children(
                    Kind::MacroExpansionLoc,
                    &[module, buffer, line_node, col_node],
                );
            }
            _ => return None,
        };
        let macro_name = self.pop_kind(Kind::Identifier);
        let mut private_discriminator = None;
        if is_freestanding {
            private_discriminator = self.pop_kind(Kind::PrivateDeclName);
        }
        let mut attached_name = None;
        if is_attached {
            attached_name = self.pop_if(is_decl_name);
        }
        let mut context = self.pop_if(is_macro_expansion_node_kind);
        if context.is_none() {
            context = self.pop_context();
        }
        let discriminator = self.demangle_index_as_node();
        let result = if is_attached && attached_name.is_some() {
            self.create_with_children(kind, &[context, attached_name, macro_name, discriminator])
        } else {
            self.create_with_children(kind, &[context, macro_name, discriminator])
        }?;
        self.add_child(Some(result), private_discriminator);
        Some(result)
    }

    fn demangle_integer_type(&mut self) -> N {
        let integer = if self.peek_char() == b'n' {
            self.next_char();
            let i = self.demangle_index();
            self.create_index(Kind::NegativeInteger, idx(i.wrapping_neg()))
        } else {
            let i = self.demangle_index();
            self.create_index(Kind::Integer, idx(i))
        };
        self.create_type(integer)
    }
}

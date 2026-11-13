// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Translated from the Swift project's lib/Demangling/NodePrinter.cpp (see
// LICENSE-SWIFT at the crate root); the structure and names follow it.

//! Prints a demangling tree as `swift-demangle` does (Swift's
//! `NodePrinter`).
//!
//! Swift's printer assumes the trees its demangler builds; here a child
//! that isn't there reads as a sentinel that makes the output invalid (an
//! empty string, so the caller shows the mangled name, as Swift does when
//! its printer gives up), rather than undefined behavior.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::mem::{self, ManuallyDrop};

use super::demangler::{MANGLING_MODULE_OBJC, STDLIB_NAME, VALUE_WITNESSES};
use super::kinds::Kind;
use super::node::{NodeId, Payload, Tree};

/// Swift's `DemangleOptions`.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub synthesize_sugar_on_types: bool,
    pub qualify_entities: bool,
    pub display_extension_contexts: bool,
    pub display_unmangled_suffix: bool,
    pub display_module_names: bool,
    pub display_generic_specializations: bool,
    pub display_protocol_conformances: bool,
    pub display_where_clauses: bool,
    pub display_entity_types: bool,
    pub display_local_name_contexts: bool,
    pub shorten_partial_apply: bool,
    pub shorten_thunk: bool,
    pub shorten_value_witness: bool,
    pub shorten_archetype: bool,
    pub show_private_discriminators: bool,
    pub show_function_argument_types: bool,
    pub display_debugger_generated_module: bool,
    pub display_stdlib_module: bool,
    pub display_objc_module: bool,
    pub print_for_type_name: bool,
    pub show_async_resume_partial: bool,
    pub show_closure_signature: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            synthesize_sugar_on_types: false,
            qualify_entities: true,
            display_extension_contexts: true,
            display_unmangled_suffix: true,
            display_module_names: true,
            display_generic_specializations: true,
            display_protocol_conformances: true,
            display_where_clauses: true,
            display_entity_types: true,
            display_local_name_contexts: true,
            shorten_partial_apply: false,
            shorten_thunk: false,
            shorten_value_witness: false,
            shorten_archetype: false,
            show_private_discriminators: true,
            show_function_argument_types: true,
            display_debugger_generated_module: true,
            display_stdlib_module: true,
            display_objc_module: true,
            print_for_type_name: false,
            show_async_resume_partial: true,
            show_closure_signature: true,
        }
    }
}

impl Options {
    /// The options `swift-demangle` uses by default: Swift's defaults, with
    /// sugar (`[T]`, `T?`, ...).
    pub fn swift_demangle() -> Self {
        Self {
            synthesize_sugar_on_types: true,
            ..Self::default()
        }
    }

    /// Swift's `SimplifiedUIDemangleOptions` (`swift-demangle -simplified`).
    pub fn simplified() -> Self {
        Self {
            synthesize_sugar_on_types: true,
            qualify_entities: true,
            display_extension_contexts: false,
            display_unmangled_suffix: false,
            display_module_names: false,
            display_generic_specializations: false,
            display_protocol_conformances: false,
            display_where_clauses: false,
            display_entity_types: false,
            shorten_partial_apply: true,
            shorten_thunk: true,
            shorten_value_witness: true,
            shorten_archetype: true,
            show_private_discriminators: false,
            show_function_argument_types: false,
            show_async_resume_partial: false,
            ..Self::default()
        }
    }
}

/// Swift's `genericParameterName`: `A`, `B`, ..., `Z`, `BA`, ... and the
/// depth if it isn't 0.
pub fn generic_parameter_name(out: &mut String, depth: u64, mut index: u64) {
    loop {
        out.push((b'A' + (index % 26) as u8) as char);
        index /= 26;
        if index == 0 {
            break;
        }
    }
    if depth != 0 {
        let _ = write!(out, "{depth}");
    }
}

/// The deepest the printer goes (Swift's `NodePrinter::MaxDepth`).
pub const MAX_DEPTH: u32 = 768;
/// How many levels of nesting the printer recurses through on the
/// thread's stack (a constant bound on what that takes; real names nest
/// far less). Deeper levels: see `Printer::drive`.
pub const NATIVE_DEPTH: u32 = if cfg!(debug_assertions) { 12 } else { 128 };
/// The most work (output copied) printing a name nested past
/// [`NATIVE_DEPTH`] may take, beyond the printing itself.
const MAX_DEEP_WORK: usize = 16 * MAX_OUTPUT;
/// How deeply symbols nested in specializations are demangled.
pub const MAX_NESTING: u32 = 4;
/// The most output one name may produce.
pub const MAX_OUTPUT: usize = 1 << 20;

/// A child that isn't there.
const MISSING: NodeId = NodeId::MAX;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SugarType {
    None,
    Optional,
    ImplicitlyUnwrappedOptional,
    Array,
    Dictionary,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypePrinting {
    NoType,
    WithColon,
    FunctionStyle,
}

/// The printer's state but its output: at a call, or at its return.
#[derive(Clone, Copy)]
struct State {
    /// The output's length.
    out: usize,
    options: Options,
    specialization_prefix_printed: bool,
    valid: bool,
}

/// A call to `print` past a run's levels, for [`Printer::drive`] to run.
struct Call {
    n: NodeId,
    depth: u32,
    as_prefix_context: bool,
    entry: State,
    /// The output before it (which the run that made the call may change
    /// as it unwinds).
    prefix: String,
}

/// A call [`Printer::drive`] has run: what it returned, the printer after
/// it, and what it wrote.
struct Done {
    n: NodeId,
    result: Option<NodeId>,
    exit: State,
    text: String,
}

/// A call [`Printer::drive`] is running (or the root), with the results
/// of the calls past its levels it has made so far.
struct Task {
    call: Option<(NodeId, u32, bool)>,
    entry: State,
    prefix: Option<String>,
    done: Vec<Done>,
}

/// The printer's state while [`Printer::drive`] prints a deep tree.
#[derive(Default)]
struct Deep {
    /// The results of this run's calls past its levels, in call order, and
    /// how many it has made.
    done: Vec<Done>,
    done_at: usize,
    /// A call past this run's levels with no result yet: the run is
    /// unwinding (every call returning at once).
    pending: Option<Call>,
    /// Work so far (see [`MAX_DEEP_WORK`]).
    spent: usize,
}

/// Swift's `NodePrinter`.
pub struct Printer<'t> {
    pub(crate) tree: &'t Tree,
    pub(crate) out: String,
    pub(crate) options: Options,
    pub(crate) specialization_prefix_printed: bool,
    pub(crate) valid: bool,
    /// How many names this one is nested in (the symbols specializations
    /// name are demangled in turn).
    pub(crate) nesting: u32,
    /// Levels of nesting of this run (on the thread's stack).
    level: u32,
    /// How many there may be before a call goes to [`Printer::boundary`]:
    /// `native_depth`, or 0 once a run is unwinding.
    limit: u32,
    /// [`NATIVE_DEPTH`], fewer for a nested symbol's printer (which runs
    /// on top of this one's levels), or fewer for testing.
    pub(crate) native_depth: u32,
    /// Only while printing a deep tree, which takes it back before
    /// returning. (Not dropped with the printer: a field to drop makes
    /// every name slower.)
    deep: ManuallyDrop<Option<Box<Deep>>>,
}

impl<'t> Printer<'t> {
    pub fn new(tree: &'t Tree, options: Options) -> Self {
        Self {
            tree,
            out: String::new(),
            options,
            specialization_prefix_printed: false,
            valid: true,
            nesting: 0,
            level: 0,
            limit: NATIVE_DEPTH,
            native_depth: NATIVE_DEPTH,
            deep: ManuallyDrop::new(None),
        }
    }

    /// Recurses at most `n` (at least 1) levels on the thread's stack.
    pub fn set_native_depth(&mut self, n: u32) {
        self.native_depth = n.max(1);
        self.limit = self.native_depth;
    }

    /// Prints the tree from `root`; the text, or empty if the tree can't be
    /// printed (Swift's `printRoot` and `takeString`).
    pub fn print_root(mut self, root: NodeId) -> String {
        self.valid = true;
        self.print(root, 0, false);
        if self.deep.is_some() {
            self.drive(root);
            // (Dropped here, not with the printer.)
            *self.deep = None;
        }
        if self.valid && self.out.len() <= MAX_OUTPUT {
            self.out
        } else {
            String::new()
        }
    }

    // --- The tree, tolerating missing children -------------------------------

    pub(crate) fn k(&self, n: NodeId) -> Kind {
        if n == MISSING {
            Kind::UnknownIndex
        } else {
            self.tree.kind(n)
        }
    }

    pub(crate) fn nc(&self, n: NodeId) -> usize {
        if n == MISSING {
            0
        } else {
            self.tree.num_children(n)
        }
    }

    /// Child `i`; if there isn't one, the output is invalid.
    pub(crate) fn c(&mut self, n: NodeId, i: usize) -> NodeId {
        if n != MISSING
            && let Some(c) = self.tree.child(n, i)
        {
            return c;
        }
        self.valid = false;
        MISSING
    }

    pub(crate) fn first(&mut self, n: NodeId) -> NodeId {
        self.c(n, 0)
    }

    pub(crate) fn last(&mut self, n: NodeId) -> NodeId {
        let num = self.nc(n);
        match num.checked_sub(1) {
            Some(i) => self.c(n, i),
            None => {
                self.valid = false;
                MISSING
            }
        }
    }

    pub(crate) fn children(&self, n: NodeId) -> &'t [NodeId] {
        if n == MISSING {
            &[]
        } else {
            self.tree.children(n)
        }
    }

    pub(crate) fn text(&self, n: NodeId) -> &'t str {
        if n == MISSING { "" } else { self.tree.text(n) }
    }

    pub(crate) fn has_text(&self, n: NodeId) -> bool {
        n != MISSING && self.tree.has_text(n)
    }

    pub(crate) fn index(&self, n: NodeId) -> u64 {
        if n == MISSING { 0 } else { self.tree.index(n) }
    }

    pub(crate) fn has_index(&self, n: NodeId) -> bool {
        n != MISSING && self.tree.has_index(n)
    }

    pub(crate) fn has_children(&self, n: NodeId) -> bool {
        self.nc(n) != 0
    }

    // --- Output --------------------------------------------------------------

    pub(crate) fn s(&mut self, t: &str) {
        if self.out.len() <= MAX_OUTPUT {
            self.out.push_str(t);
        } else {
            self.valid = false;
        }
    }

    pub(crate) fn num(&mut self, n: u64) {
        let _ = write!(self.out, "{n}");
    }

    pub(crate) fn snum(&mut self, n: i64) {
        let _ = write!(self.out, "{n}");
    }

    /// Swift's `DemanglerPrinter::writeHex`: uppercase, no prefix.
    pub(crate) fn hex(&mut self, n: u64) {
        let _ = write!(self.out, "{n:X}");
    }

    /// Swift's `QuotedString`.
    pub(crate) fn quoted(&mut self, v: &str) {
        let mut s = String::with_capacity(v.len() + 2);
        s.push('"');
        for &c in v.as_bytes() {
            match c {
                b'\\' => s.push_str("\\\\"),
                b'\t' => s.push_str("\\t"),
                b'\n' => s.push_str("\\n"),
                b'\r' => s.push_str("\\r"),
                b'"' => s.push_str("\\\""),
                0 => s.push_str("\\0"),
                c if !(0x20..0x7F).contains(&c) => {
                    let _ = write!(s, "\\x{c:02X}");
                }
                c => s.push(c as char),
            }
        }
        s.push('"');
        self.s(&s);
    }

    pub(crate) fn print_symbolic_reference_payload(&mut self, n: NodeId) {
        if n == MISSING {
            return;
        }
        match self.tree.payload(n) {
            Payload::RemoteAddress(a, _) => self.hex(a),
            Payload::Index(i) => self.hex(i),
            _ => {}
        }
    }

    // --- Helpers ----------------------------------------------------------------

    pub(crate) fn print_children(&mut self, n: NodeId, depth: u32, sep: Option<&str>) {
        let children = self.children(n);
        for (i, &c) in children.iter().enumerate() {
            self.print(c, depth + 1, false);
            if let Some(sep) = sep
                && i + 1 != children.len()
            {
                self.s(sep);
            }
        }
    }

    pub(crate) fn first_child_of_kind(&self, n: NodeId, kind: Kind) -> Option<NodeId> {
        self.children(n)
            .iter()
            .copied()
            .find(|&c| self.k(c) == kind)
    }

    pub(crate) fn print_bound_generic_no_sugar(&mut self, n: NodeId, depth: u32) {
        if self.nc(n) < 2 {
            return;
        }
        let typelist = self.c(n, 1);
        let c0 = self.c(n, 0);
        self.print(c0, depth + 1, false);
        self.s("<");
        self.print_children(typelist, depth, Some(", "));
        self.s(">");
    }

    pub(crate) fn is_existential_type(&self, n: NodeId) -> bool {
        matches!(
            self.k(n),
            Kind::ExistentialMetatype
                | Kind::ProtocolList
                | Kind::ProtocolListWithClass
                | Kind::ProtocolListWithAnyObject
        )
    }

    pub(crate) fn print_optional_index(&mut self, n: NodeId) {
        if self.has_index(n) {
            self.s("#");
            let i = self.index(n);
            self.num(i);
            self.s(" ");
        }
    }

    pub(crate) fn is_swift_module(&self, n: NodeId) -> bool {
        self.k(n) == Kind::Module && self.text(n) == STDLIB_NAME
    }

    pub(crate) fn is_identifier(&self, n: NodeId, desired: &str) -> bool {
        self.k(n) == Kind::Identifier && self.text(n) == desired
    }

    pub(crate) fn print_context(&self, context: NodeId) -> bool {
        if !self.options.qualify_entities {
            return false;
        }
        if self.k(context) == Kind::Module {
            let t = self.text(context);
            if t == STDLIB_NAME {
                return self.options.display_stdlib_module;
            }
            if t == MANGLING_MODULE_OBJC {
                return self.options.display_objc_module;
            }
            // (No module is hidden as "current".)
            if t.starts_with("__lldb_expr_") {
                return self.options.display_debugger_generated_module;
            }
        }
        true
    }

    pub(crate) fn is_simple_type(&mut self, n: NodeId, depth: u32) -> bool {
        use Kind::*;
        match self.k(n) {
            AssociatedType
            | AssociatedTypeRef
            | BoundGenericClass
            | BoundGenericEnum
            | BoundGenericStructure
            | BoundGenericProtocol
            | BoundGenericOtherNominalType
            | BoundGenericTypeAlias
            | BoundGenericFunction
            | BuiltinTypeName
            | BuiltinTupleType
            | BuiltinFixedArray
            | BuiltinBorrow
            | Class
            | DependentGenericType
            | DependentMemberType
            | DependentGenericParamType
            | DynamicSelf
            | Enum
            | ErrorType
            | ExistentialMetatype
            | Metatype
            | MetatypeRepresentation
            | Module
            | Tuple
            | Pack
            | SILPackDirect
            | SILPackIndirect
            | ConstrainedExistentialRequirementList
            | ConstrainedExistentialSelf
            | Protocol
            | ProtocolSymbolicReference
            | ReturnType
            | SILBoxType
            | SILBoxTypeWithLayout
            | Structure
            | OtherNominalType
            | TupleElementName
            | TypeAlias
            | TypeList
            | LabelList
            | TypeSymbolicReference
            | SugaredOptional
            | SugaredArray
            | SugaredInlineArray
            | SugaredDictionary
            | SugaredParen
            | Integer
            | NegativeInteger => true,
            Type => {
                // (Swift recurses; this follows the chain.)
                let mut n = n;
                let mut depth = depth;
                while self.k(n) == Type {
                    if depth > MAX_DEPTH {
                        return false;
                    }
                    n = self.c(n, 0);
                    depth += 1;
                }
                self.is_simple_type(n, depth)
            }
            ProtocolList => {
                let c = self.c(n, 0);
                self.nc(c) <= 1
            }
            ProtocolListWithAnyObject => {
                let c = self.c(n, 0);
                let cc = self.c(c, 0);
                self.nc(cc) == 0
            }
            _ => false,
        }
    }

    pub(crate) fn print_with_parens(&mut self, ty: NodeId, depth: u32) {
        let needs_parens = !self.is_simple_type(ty, 0);
        if needs_parens {
            self.s("(");
        }
        self.print(ty, depth + 1, false);
        if needs_parens {
            self.s(")");
        }
    }

    pub(crate) fn find_sugar(&mut self, n: NodeId, depth: u32) -> SugarType {
        // (Swift recurses through `Type` nodes; this follows the chain.)
        let mut n = n;
        let mut depth = depth;
        while self.nc(n) == 1 && self.k(n) == Kind::Type {
            if depth > MAX_DEPTH {
                return SugarType::None;
            }
            n = self.c(n, 0);
            depth += 1;
        }
        if self.nc(n) != 2 {
            return SugarType::None;
        }
        let nk = self.k(n);
        if nk != Kind::BoundGenericEnum && nk != Kind::BoundGenericStructure {
            return SugarType::None;
        }
        let c0 = self.c(n, 0);
        let unbound = self.c(c0, 0);
        let type_args = self.c(n, 1);
        let u1 = self.c(unbound, 1);
        let u0 = self.c(unbound, 0);
        let nargs = self.nc(type_args);
        if nk == Kind::BoundGenericEnum {
            if self.is_identifier(u1, "Optional") && nargs == 1 && self.is_swift_module(u0) {
                return SugarType::Optional;
            }
            if self.is_identifier(u1, "ImplicitlyUnwrappedOptional")
                && nargs == 1
                && self.is_swift_module(u0)
            {
                return SugarType::ImplicitlyUnwrappedOptional;
            }
            return SugarType::None;
        }
        if self.is_identifier(u1, "Array") && nargs == 1 && self.is_swift_module(u0) {
            return SugarType::Array;
        }
        if self.is_identifier(u1, "Dictionary") && nargs == 2 && self.is_swift_module(u0) {
            return SugarType::Dictionary;
        }
        SugarType::None
    }

    pub(crate) fn print_bound_generic(&mut self, n: NodeId, depth: u32) {
        if self.nc(n) < 2 {
            return;
        }
        if self.nc(n) != 2
            || !self.options.synthesize_sugar_on_types
            || self.k(n) == Kind::BoundGenericClass
        {
            self.print_bound_generic_no_sugar(n, depth);
            return;
        }
        if self.k(n) == Kind::BoundGenericProtocol {
            let c1 = self.c(n, 1);
            self.print_children(c1, depth, None);
            self.s(" as ");
            let c0 = self.c(n, 0);
            self.print(c0, depth + 1, false);
            return;
        }
        let sugar = self.find_sugar(n, 0);
        match sugar {
            SugarType::None => self.print_bound_generic_no_sugar(n, depth),
            SugarType::Optional | SugarType::ImplicitlyUnwrappedOptional => {
                let c1 = self.c(n, 1);
                let ty = self.c(c1, 0);
                self.print_with_parens(ty, depth);
                self.s(if sugar == SugarType::Optional {
                    "?"
                } else {
                    "!"
                });
            }
            SugarType::Array => {
                let c1 = self.c(n, 1);
                let ty = self.c(c1, 0);
                self.s("[");
                self.print(ty, depth + 1, false);
                self.s("]");
            }
            SugarType::Dictionary => {
                let c1 = self.c(n, 1);
                let key = self.c(c1, 0);
                let value = self.c(c1, 1);
                self.s("[");
                self.print(key, depth + 1, false);
                self.s(" : ");
                self.print(value, depth + 1, false);
                self.s("]");
            }
        }
    }

    pub(crate) fn child_if(&self, n: NodeId, kind: Kind) -> Option<NodeId> {
        self.first_child_of_kind(n, kind)
    }

    pub(crate) fn print_function_parameters(
        &mut self,
        label_list: Option<NodeId>,
        parameter_type: NodeId,
        depth: u32,
        show_types: bool,
    ) {
        let pk = self.k(parameter_type);
        if pk != Kind::ArgumentTuple && pk != Kind::YieldTypes {
            self.valid = false;
            return;
        }
        let p = self.first(parameter_type);
        let parameters = self.first(p);
        if self.k(parameters) != Kind::Tuple {
            if show_types {
                self.s("(");
                self.print(parameters, depth + 1, false);
                self.s(")");
            } else {
                self.s("(_:)");
            }
            return;
        }
        let has_labels = label_list.is_some_and(|l| self.nc(l) > 0);
        self.s("(");
        let params = self.children(parameters);
        for (param_index, &param) in params.iter().enumerate() {
            if param_index > 0 && show_types {
                self.s(", ");
            }
            if has_labels {
                let label = self.c(label_list.unwrap_or(MISSING), param_index);
                if self.k(label) == Kind::Identifier {
                    let t = self.text(label);
                    self.s(t);
                } else {
                    self.s("_");
                }
                self.s(":");
            } else if !show_types {
                if let Some(label) = self.child_if(param, Kind::TupleElementName) {
                    let t = self.text(label);
                    self.s(t);
                    self.s(":");
                } else {
                    self.s("_:");
                }
            }
            if has_labels && show_types {
                self.s(" ");
            }
            if show_types {
                self.print(param, depth + 1, false);
            }
        }
        self.s(")");
    }

    pub(crate) fn print_function_type(
        &mut self,
        label_list: Option<NodeId>,
        node: NodeId,
        depth: u32,
    ) {
        if self.nc(node) < 2 {
            self.valid = false;
            return;
        }
        let convention = |p: &mut Self, conv: &str| {
            p.s("@convention(");
            p.s(conv);
            let f = p.first(node);
            if p.k(f) == Kind::ClangType {
                p.s(", mangledCType: \"");
                p.print(f, depth + 1, false);
                p.s("\"");
            }
            p.s(") ");
        };
        match self.k(node) {
            Kind::FunctionType | Kind::UncurriedFunctionType | Kind::NoEscapeFunctionType => {}
            Kind::CalledOnceFunctionType => self.s("@once "),
            Kind::CalledAtMostOnceFunctionType => self.s("@callable(once) "),
            Kind::AutoClosureType | Kind::EscapingAutoClosureType => self.s("@autoclosure "),
            Kind::ThinFunctionType => self.s("@convention(thin) "),
            Kind::CFunctionPointer => convention(self, "c"),
            Kind::EscapingObjCBlock => {
                self.s("@escaping ");
                convention(self, "block");
            }
            Kind::ObjCBlock => convention(self, "block"),
            _ => {}
        }
        let arg_index = self.nc(node) - 2;
        let mut start = 0;
        let mut is_sendable = false;
        let mut is_async = false;
        let mut has_sending_result = false;
        let mut diff_kind = 0u64;
        let ck = |p: &mut Self, i: usize| {
            let c = p.c(node, i);
            (c, p.k(c))
        };
        if ck(self, start).1 == Kind::ClangType {
            start += 1;
        }
        if ck(self, start).1 == Kind::SendingResultFunctionType {
            start += 1;
            has_sending_result = true;
        }
        let (c, k) = ck(self, start);
        if k == Kind::IsolatedAnyFunctionType {
            self.print(c, depth + 1, false);
            start += 1;
        }
        let mut non_isolated_caller = None;
        let (c, k) = ck(self, start);
        if k == Kind::NonIsolatedCallerFunctionType {
            non_isolated_caller = Some(c);
            start += 1;
        }
        let (c, k) = ck(self, start);
        if k == Kind::GlobalActorFunctionType {
            self.print(c, depth + 1, false);
            start += 1;
        }
        let (c, k) = ck(self, start);
        if k == Kind::DifferentiableFunctionType {
            diff_kind = self.index(c);
            start += 1;
        }
        let mut thrown_error = None;
        let (c, k) = ck(self, start);
        if k == Kind::ThrowsAnnotation || k == Kind::TypedThrowsAnnotation {
            thrown_error = Some(c);
            start += 1;
        }
        if ck(self, start).1 == Kind::ConcurrentFunctionType {
            start += 1;
            is_sendable = true;
        }
        if ck(self, start).1 == Kind::AsyncAnnotation {
            is_async = true;
        }
        match diff_kind as u8 {
            b'f' => self.s("@differentiable(_forward) "),
            b'r' => self.s("@differentiable(reverse) "),
            b'l' => self.s("@differentiable(_linear) "),
            b'd' => self.s("@differentiable "),
            _ => {}
        }
        if let Some(n) = non_isolated_caller {
            self.print(n, depth + 1, false);
        }
        if is_sendable {
            self.s("@Sendable ");
        }
        let args = self.c(node, arg_index);
        let show = self.options.show_function_argument_types;
        self.print_function_parameters(label_list, args, depth, show);
        if !show {
            return;
        }
        if is_async {
            self.s(" async");
        }
        if let Some(t) = thrown_error {
            self.print(t, depth + 1, false);
        }
        self.s(" -> ");
        if has_sending_result {
            self.s("sending ");
        }
        let r = self.c(node, arg_index + 1);
        self.print(r, depth + 1, false);
    }

    pub(crate) fn print_impl_function_type(&mut self, f: NodeId, depth: u32) {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        enum State {
            Attrs,
            Inputs,
            Results,
        }
        let mut pattern_subs = None;
        let mut invocation_subs = None;
        let mut sending_result = None;
        let mut state = State::Attrs;
        let transition =
            |p: &mut Self, state: &mut State, to: State, ps: Option<NodeId>, sr: Option<NodeId>| {
                while *state < to {
                    match *state {
                        State::Attrs => {
                            if let Some(ps) = ps {
                                p.s("@substituted ");
                                let c = p.c(ps, 0);
                                p.print(c, depth + 1, false);
                                p.s(" ");
                            }
                            p.s("(");
                            *state = State::Inputs;
                        }
                        State::Inputs => {
                            p.s(") -> ");
                            if let Some(sr) = sr {
                                p.print(sr, depth + 1, false);
                                p.s(" ");
                            }
                            p.s("(");
                            *state = State::Results;
                        }
                        State::Results => break,
                    }
                }
            };
        for &child in self.children(f) {
            match self.k(child) {
                Kind::ImplParameter => {
                    if state == State::Inputs {
                        self.s(", ");
                    }
                    transition(
                        self,
                        &mut state,
                        State::Inputs,
                        pattern_subs,
                        sending_result,
                    );
                    self.print(child, depth + 1, false);
                }
                Kind::ImplResult | Kind::ImplYield | Kind::ImplErrorResult => {
                    if state == State::Results {
                        self.s(", ");
                    }
                    transition(
                        self,
                        &mut state,
                        State::Results,
                        pattern_subs,
                        sending_result,
                    );
                    self.print(child, depth + 1, false);
                }
                Kind::ImplPatternSubstitutions => pattern_subs = Some(child),
                Kind::ImplInvocationSubstitutions => invocation_subs = Some(child),
                Kind::ImplSendingResult => sending_result = Some(child),
                _ => {
                    self.print(child, depth + 1, false);
                    self.s(" ");
                }
            }
        }
        transition(
            self,
            &mut state,
            State::Results,
            pattern_subs,
            sending_result,
        );
        self.s(")");
        if let Some(ps) = pattern_subs {
            self.s(" for <");
            let c = self.c(ps, 1);
            self.print_children(c, depth, None);
            self.s(">");
        }
        if let Some(is) = invocation_subs {
            self.s(" for <");
            let c = self.c(is, 0);
            self.print_children(c, depth, None);
            self.s(">");
        }
    }

    pub(crate) fn print_generic_signature(&mut self, n: NodeId, depth: u32) {
        self.s("<");
        let num_children = self.nc(n);
        let mut num_generic_params = 0;
        while num_generic_params < num_children {
            let c = self.c(n, num_generic_params);
            if self.k(c) != Kind::DependentGenericParamCount {
                break;
            }
            num_generic_params += 1;
        }
        let mut first_requirement = num_generic_params;
        while first_requirement < num_children {
            let mut c = self.c(n, first_requirement);
            if self.k(c) == Kind::Type {
                c = self.c(c, 0);
            }
            let k = self.k(c);
            if k != Kind::DependentGenericParamPackMarker
                && k != Kind::DependentGenericParamValueMarker
            {
                break;
            }
            first_requirement += 1;
        }
        // (Swift compares `index` with the parameter's first child, its
        // depth, and `depth` with its second, its index.)
        let is_pack = |p: &mut Self, depth: u64, index: u64| {
            for i in num_generic_params..first_requirement {
                let mut c = p.c(n, i);
                if p.k(c) != Kind::DependentGenericParamPackMarker {
                    continue;
                }
                c = p.c(c, 0);
                if p.k(c) != Kind::Type {
                    continue;
                }
                c = p.c(c, 0);
                if p.k(c) != Kind::DependentGenericParamType {
                    continue;
                }
                let (c0, c1) = (p.c(c, 0), p.c(c, 1));
                if index == p.index(c0) && depth == p.index(c1) {
                    return true;
                }
            }
            false
        };
        let is_value = |p: &mut Self, depth: u64, index: u64| -> (bool, Option<NodeId>) {
            for i in num_generic_params..first_requirement {
                let mut c = p.c(n, i);
                if p.k(c) != Kind::DependentGenericParamValueMarker {
                    continue;
                }
                c = p.c(c, 0);
                if p.k(c) != Kind::Type {
                    continue;
                }
                let param = p.c(c, 0);
                let ty = p.c(c, 1);
                if p.k(param) != Kind::DependentGenericParamType {
                    continue;
                }
                let (c0, c1) = (p.c(param, 0), p.c(param, 1));
                if index == p.index(c0) && depth == p.index(c1) {
                    return (true, Some(ty));
                }
            }
            (false, None)
        };
        for gp_depth in 0..num_generic_params {
            if gp_depth != 0 {
                self.s("><");
            }
            let c = self.c(n, gp_depth);
            // (An `unsigned` in Swift.)
            let count = self.index(c) as u32;
            for index in 0..count {
                if index != 0 {
                    self.s(", ");
                }
                if index >= 128 {
                    self.s("...");
                    break;
                }
                if is_pack(self, gp_depth as u64, u64::from(index)) {
                    self.s("each ");
                }
                let value = is_value(self, gp_depth as u64, u64::from(index));
                if value.0 {
                    self.s("let ");
                }
                generic_parameter_name(&mut self.out, gp_depth as u64, u64::from(index));
                if let Some(t) = value.1 {
                    self.s(": ");
                    self.print(t, depth + 1, false);
                }
            }
        }
        if first_requirement != num_children && self.options.display_where_clauses {
            self.s(" where ");
            for i in first_requirement..num_children {
                if i > first_requirement {
                    self.s(", ");
                }
                let c = self.c(n, i);
                self.print(c, depth + 1, false);
            }
        }
        self.s(">");
    }

    /// The name of value witness `i`.
    pub(crate) fn value_witness_name(i: u64) -> Option<&'static str> {
        VALUE_WITNESSES.get(i as usize).map(|(_, n)| *n)
    }
}

/// The kinds printed as a fixed prefix and then their first child.
fn prefix_then_child(k: Kind) -> Option<&'static str> {
    use Kind::*;
    Some(match k {
        Static => "static ",
        AsyncRemoved => "async demotion of ",
        RepresentationChanged => "representation changed of ",
        CurryThunk => "curry thunk of ",
        SILThunkIdentity => "identity thunk of ",
        DispatchThunk => "dispatch thunk of ",
        MethodDescriptor => "method descriptor for ",
        MethodLookupFunction => "method lookup function for ",
        ObjCMetadataUpdateFunction => "ObjC metadata update function for ",
        ObjCResilientClassStub => "ObjC resilient class stub for ",
        FullObjCResilientClassStub => "full ObjC resilient class stub for ",
        OutlinedRetain => "outlined retain of ",
        OutlinedRelease => "outlined release of ",
        OutlinedInitializeWithTake | OutlinedInitializeWithTakeNoValueWitness => {
            "outlined init with take of "
        }
        OutlinedInitializeWithCopy | OutlinedInitializeWithCopyNoValueWitness => {
            "outlined init with copy of "
        }
        OutlinedAssignWithTake | OutlinedAssignWithTakeNoValueWitness => {
            "outlined assign with take of "
        }
        OutlinedAssignWithCopy | OutlinedAssignWithCopyNoValueWitness => {
            "outlined assign with copy of "
        }
        OutlinedDestroy | OutlinedDestroyNoValueWitness => "outlined destroy of ",
        OutlinedEnumProjectDataForLoad => "outlined enum project data for load of ",
        OutlinedEnumTagStore => "outlined enum tag store of ",
        OutlinedEnumGetTag => "outlined enum get tag of ",
        DeclContext | Type => "",
        PackExpansion => "repeat ",
        Weak => "weak ",
        Unowned => "unowned ",
        Unmanaged => "unowned(unsafe) ",
        InOut => "inout ",
        Isolated => "isolated ",
        Sending => "sending ",
        CompileTimeLiteral => "_const ",
        ConstValue => "@const ",
        Shared => "__shared ",
        Owned => "__owned ",
        NoDerivative => "@noDerivative ",
        ProtocolSelfConformanceWitnessTable => "protocol self-conformance witness table for ",
        ProtocolWitnessTableAccessor => "protocol witness table accessor for ",
        ProtocolWitnessTable => "protocol witness table for ",
        ProtocolWitnessTablePattern => "protocol witness table pattern for ",
        GenericProtocolWitnessTable => "generic protocol witness table for ",
        GenericProtocolWitnessTableInstantiationFunction => {
            "instantiation function for generic protocol witness table for "
        }
        ResilientProtocolWitnessTable => "resilient protocol witness table for ",
        ProtocolSelfConformanceWitness => "protocol self-conformance witness for ",
        EnumCase => "enum case for ",
        GenericTypeMetadataPattern => "generic type metadata pattern for ",
        Metaclass => "metaclass for ",
        ProtocolSelfConformanceDescriptor => "protocol self-conformance descriptor for ",
        ProtocolConformanceDescriptor => "protocol conformance descriptor for ",
        ProtocolConformanceDescriptorRecord => {
            "protocol conformance descriptor runtime record for "
        }
        ProtocolDescriptor => "protocol descriptor for ",
        ProtocolDescriptorRecord => "protocol descriptor runtime record for ",
        ProtocolRequirementsBaseDescriptor => "protocol requirements base descriptor for ",
        FullTypeMetadata => "full type metadata for ",
        TypeMetadata => "type metadata for ",
        TypeMetadataAccessFunction => "type metadata accessor for ",
        TypeMetadataInstantiationCache => "type metadata instantiation cache for ",
        TypeMetadataInstantiationFunction => "type metadata instantiation function for ",
        TypeMetadataSingletonInitializationCache => {
            "type metadata singleton initialization cache for "
        }
        TypeMetadataCompletionFunction => "type metadata completion function for ",
        TypeMetadataDemanglingCache => "demangling cache variable for type metadata for ",
        TypeMetadataLazyCache => "lazy cache variable for type metadata for ",
        AssociatedTypeDescriptor => "associated type descriptor for ",
        DefaultAssociatedTypeMetadataAccessor => "default associated type metadata accessor for ",
        ClassMetadataBaseOffset => "class metadata base offset for ",
        PropertyDescriptor => "property descriptor for ",
        NominalTypeDescriptor => "nominal type descriptor for ",
        NominalTypeDescriptorRecord => "nominal type descriptor runtime record for ",
        OpaqueTypeDescriptor => "opaque type descriptor for ",
        OpaqueTypeDescriptorRecord => "opaque type descriptor runtime record for ",
        OpaqueTypeDescriptorAccessor => "opaque type descriptor accessor for ",
        OpaqueTypeDescriptorAccessorImpl => "opaque type descriptor accessor impl for ",
        OpaqueTypeDescriptorAccessorKey => "opaque type descriptor accessor key for ",
        OpaqueTypeDescriptorAccessorVar => "opaque type descriptor accessor var for ",
        CoroutineContinuationPrototype => "coroutine continuation prototype for ",
        ValueWitnessTable => "value witness table for ",
        SILBoxType => "@box ",
        ReflectionMetadataBuiltinDescriptor => "reflection metadata builtin descriptor ",
        ReflectionMetadataFieldDescriptor => "reflection metadata field descriptor ",
        ReflectionMetadataAssocTypeDescriptor => "reflection metadata associated type descriptor ",
        ReflectionMetadataSuperclassDescriptor => "reflection metadata superclass descriptor ",
        ModuleDescriptor => "module descriptor ",
        AnonymousDescriptor => "anonymous descriptor ",
        ExtensionDescriptor => "extension descriptor ",
        CanonicalSpecializedGenericMetaclass => "specialized generic metaclass for ",
        CanonicalSpecializedGenericTypeMetadataAccessFunction => {
            "canonical specialized generic type metadata accessor for "
        }
        MetadataInstantiationCache => "metadata instantiation cache for ",
        NoncanonicalSpecializedGenericTypeMetadata => {
            "noncanonical specialized generic type metadata for "
        }
        NoncanonicalSpecializedGenericTypeMetadataCache => {
            "cache variable for noncanonical specialized generic type metadata for "
        }
        CanonicalPrespecializedGenericTypeCachingOnceToken => {
            "flag for loading of canonical specialized generic type metadata for "
        }
        Uniquable => "uniquable ",
        _ => return None,
    })
}

/// The kinds printed as fixed text (and nothing of their children).
fn fixed_text(k: Kind, o: &Options) -> Option<&'static str> {
    use Kind::*;
    Some(match k {
        UnknownIndex => "unknown index",
        NonObjCAttribute => "@nonobjc ",
        ObjCAttribute => "@objc ",
        DirectMethodReferenceAttribute => "super ",
        DynamicAttribute => "dynamic ",
        VTableAttribute => "override ",
        IsSerialized => "serialized",
        BuiltinTupleType => "Builtin.TheTupleType",
        DynamicSelf | ConstrainedExistentialSelf => "Self",
        AssociatedType | LabelList | OpaqueReturnTypeIndex | OpaqueReturnTypeParent => "",
        ImplEscaping => "@escaping",
        ImplNonisolatedNonsendingIsolation => "@caller_isolated",
        ImplErasedIsolation => "@isolated(any)",
        ImplCalledOnceFunction => "@once",
        ImplCalledAtMostOnceFunction => "@callable(once)",
        ImplSendingResult => "sending",
        ErrorType => "<ERROR TYPE>",
        ConcurrentFunctionType => "@Sendable ",
        IsolatedAnyFunctionType => "@isolated(any) ",
        NonIsolatedCallerFunctionType => "nonisolated(nonsending) ",
        SendingResultFunctionType => "sending ",
        AsyncAnnotation => " async",
        ThrowsAnnotation => " throws",
        EmptyList => " empty-list ",
        FirstElementMarker => " first-element-marker ",
        VariadicMarker => " variadic-marker ",
        OpaqueReturnType => "some",
        AsyncFunctionPointer => "async function pointer to ",
        AsyncMainEntryPoint => "async main entry point",
        HasSymbolQuery => "#_hasSymbol query for ",
        CoroFunctionPointer => "coro function pointer to ",
        DefaultOverride => "default override of ",
        BackDeploymentFallback => "back deployment fallback for ",
        BackDeploymentCopy => "back deployment copy of ",
        MergedFunction if !o.shorten_thunk => "merged ",
        DistributedThunk if !o.shorten_thunk => "distributed thunk ",
        DistributedAccessor if !o.shorten_thunk => "distributed accessor for ",
        AccessibleFunctionRecord if !o.shorten_thunk => "accessible function runtime record for ",
        DynamicallyReplaceableFunctionKey if !o.shorten_thunk => "dynamically replaceable key for ",
        DynamicallyReplaceableFunctionImpl if !o.shorten_thunk => {
            "dynamically replaceable thunk for "
        }
        DynamicallyReplaceableFunctionVar if !o.shorten_thunk => {
            "dynamically replaceable variable for "
        }
        BackDeploymentThunk if !o.shorten_thunk => "back deployment thunk for ",
        MergedFunction
        | DistributedThunk
        | DistributedAccessor
        | AccessibleFunctionRecord
        | DynamicallyReplaceableFunctionKey
        | DynamicallyReplaceableFunctionImpl
        | DynamicallyReplaceableFunctionVar
        | BackDeploymentThunk => "",
        _ => return None,
    })
}

/// The kinds printed as their text.
fn is_text_kind(k: Kind) -> bool {
    use Kind::*;
    matches!(
        k,
        Identifier
            | ClangType
            | BuiltinTypeName
            | MetatypeRepresentation
            | ImplConvention
            | ImplFunctionAttribute
    )
}

/// The accessor kinds and the names `printAbstractStorage` gives them.
fn accessor_name(k: Kind) -> Option<&'static str> {
    use Kind::*;
    Some(match k {
        OwningAddressor => "owningAddressor",
        OwningMutableAddressor => "owningMutableAddressor",
        NativeOwningAddressor => "nativeOwningAddressor",
        NativeOwningMutableAddressor => "nativeOwningMutableAddressor",
        NativePinningAddressor => "nativePinningAddressor",
        NativePinningMutableAddressor => "nativePinningMutableAddressor",
        UnsafeAddressor => "unsafeAddressor",
        UnsafeMutableAddressor => "unsafeMutableAddressor",
        GlobalGetter | Getter => "getter",
        Setter => "setter",
        MaterializeForSet => "materializeForSet",
        WillSet => "willset",
        DidSet => "didset",
        ReadAccessor => "read",
        YieldingBorrowAccessor => "yielding_borrow",
        ModifyAccessor => "modify",
        YieldingMutateAccessor => "yielding_mutate",
        InitAccessor => "init",
        BorrowAccessor => "borrow",
        MutateAccessor => "mutate",
        _ => return None,
    })
}

/// The specialization kinds and `printSpecializationPrefix`'s description
/// and parameter prefix.
fn specialization(k: Kind) -> Option<(&'static str, &'static str)> {
    use Kind::*;
    Some(match k {
        FunctionSignatureSpecialization => ("function signature specialization", ""),
        GenericPartialSpecialization => ("generic partial specialization", "Signature = "),
        GenericPartialSpecializationNotReAbstracted => (
            "generic not-reabstracted partial specialization",
            "Signature = ",
        ),
        GenericSpecialization | GenericSpecializationInResilienceDomain => {
            ("generic specialization", "")
        }
        GenericSpecializationPrespecialized => ("generic pre-specialization", ""),
        GenericSpecializationNotReAbstracted => ("generic not re-abstracted specialization", ""),
        InlinedGenericFunction => ("inlined generic function", ""),
        _ => return None,
    })
}

/// Swift's `needSpaceBeforeType`.
fn need_space_before_type(p: &mut Printer<'_>, mut ty: NodeId) -> bool {
    let mut guard = 0;
    loop {
        match p.k(ty) {
            Kind::Type => {
                guard += 1;
                if guard > MAX_DEPTH {
                    return true;
                }
                ty = p.first(ty);
            }
            Kind::FunctionType
            | Kind::NoEscapeFunctionType
            | Kind::UncurriedFunctionType
            | Kind::CalledOnceFunctionType
            | Kind::CalledAtMostOnceFunctionType
            | Kind::DependentGenericType => return false,
            _ => return true,
        }
    }
}

// FunctionSigSpecializationParamKind.
mod fssp {
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

impl Printer<'_> {
    /// Prints child `i` of `n`, one level deeper.
    fn pc(&mut self, n: NodeId, i: usize, depth: u32) {
        let c = self.c(n, i);
        self.print(c, depth + 1, false);
    }

    /// Swift's `demangleSymbolAsString` (default options), for the names
    /// nested in specializations; the name itself if it doesn't demangle.
    fn nested_symbol(&mut self, text: &str) {
        // (Its printer runs on top of this one's levels: it may have what
        // is left of them.)
        let levels = self.native_depth.saturating_sub(self.level).max(1);
        let s = if self.nesting < MAX_NESTING && self.limit != 0 {
            super::demangle_symbol_as_string_nested(
                text,
                Options::default(),
                self.nesting + 1,
                levels,
            )
        } else {
            String::new()
        };
        if s.is_empty() {
            self.s(text);
        } else {
            self.s(&s);
        }
    }

    /// Swift's `nodeToString` (default options): printed by this printer
    /// (so that its levels count with this one's), as a printer of its own
    /// would print it.
    fn node_to_string(&mut self, n: NodeId) -> String {
        if n == MISSING {
            return String::new();
        }
        let saved = (self.options, self.specialization_prefix_printed, self.valid);
        let start = self.out.len();
        self.options = Options::default();
        self.specialization_prefix_printed = false;
        self.valid = true;
        self.print(n, 0, false);
        let text = if self.valid && self.out.len() - start <= MAX_OUTPUT {
            String::from(&self.out[start..])
        } else {
            String::new()
        };
        self.out.truncate(start);
        (self.options, self.specialization_prefix_printed, self.valid) = saved;
        text
    }

    fn print_function_sig_specialization_params(&mut self, n: NodeId, depth: u32) {
        use fssp::*;
        let mut idx = 0;
        let mut arg_idx = 0;
        let end = self.nc(n);
        while idx < end {
            let child = self.c(n, idx);
            if !self.has_index(child) {
                return;
            }
            // (An `unsigned` in Swift.)
            let v = u64::from(self.index(child) as u32);
            match v {
                BOX_TO_VALUE | BOX_TO_STACK | IN_OUT_TO_OUT => {
                    self.pc(n, idx, depth);
                    idx += 1;
                }
                CONSTANT_PROP_FUNCTION | CONSTANT_PROP_GLOBAL => {
                    self.s("[");
                    self.pc(n, idx, depth);
                    idx += 1;
                    self.s(" : ");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s("]");
                }
                CONSTANT_PROP_INTEGER | CONSTANT_PROP_FLOAT => {
                    if idx + 2 > end {
                        return;
                    }
                    self.s("[");
                    self.pc(n, idx, depth);
                    self.s(" : ");
                    self.pc(n, idx + 1, depth);
                    idx += 2;
                    self.s("]");
                }
                CONSTANT_PROP_STRING => {
                    if idx + 2 > end {
                        return;
                    }
                    self.s("[");
                    self.pc(n, idx, depth);
                    self.s(" : ");
                    self.pc(n, idx + 1, depth);
                    idx += 2;
                    self.s("'");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s("']");
                }
                CONSTANT_PROP_KEY_PATH => {
                    self.s("[");
                    self.pc(n, idx, depth);
                    idx += 1;
                    self.s(" : ");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s("<");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s(",");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s(">]");
                }
                CONSTANT_PROP_STRUCT => {
                    self.s("[");
                    self.pc(n, idx, depth);
                    idx += 1;
                    self.s(" : ");
                    self.print_next_param_child_node(n, &mut arg_idx, v, depth);
                    self.s("]");
                }
                CLOSURE_PROP | ESCAPING_CLOSURE_PROP => {
                    if idx + 2 > end {
                        return;
                    }
                    self.s("[");
                    self.pc(n, idx, depth);
                    self.s(" : ");
                    self.pc(n, idx + 1, depth);
                    idx += 2;
                    self.s(", Argument Types : [");
                    while idx < end {
                        let child = self.c(n, idx);
                        if self.k(child) != Kind::Type {
                            break;
                        }
                        self.print(child, depth + 1, false);
                        idx += 1;
                        if idx < end {
                            let next = self.c(n, idx);
                            if self.has_text(next) {
                                self.s(", ");
                            }
                        }
                    }
                    self.s("]");
                }
                CLOSURE_PROP_PREVIOUS_ARG => {
                    if idx + 2 > end {
                        return;
                    }
                    self.s("[");
                    self.pc(n, idx, depth);
                    self.s(" ");
                    self.pc(n, idx + 1, depth);
                    idx += 2;
                    self.s("]");
                }
                _ => {
                    self.pc(n, idx, depth);
                    idx += 1;
                }
            }
        }
    }

    fn print_next_param_child_node(&mut self, n: NodeId, idx: &mut usize, kind: u64, depth: u32) {
        use fssp::*;
        while *idx < self.nc(n) {
            let child = self.c(n, *idx);
            *idx += 1;
            let ck = self.k(child);
            if ck == Kind::FunctionSignatureSpecializationParamKind
                || ck == Kind::FunctionSignatureSpecializationParamPayload
            {
                continue;
            }
            match kind {
                CONSTANT_PROP_INTEGER | CONSTANT_PROP_FLOAT => {
                    if !self.has_text(child) {
                        return;
                    }
                    let t = self.text(child);
                    self.nested_symbol(t);
                }
                CONSTANT_PROP_STRING => {
                    if self.has_text(child) {
                        let t = self.text(child);
                        if let Some(rest) = t.strip_prefix('_') {
                            self.s(rest);
                            return;
                        }
                    }
                    self.print(child, depth + 1, false);
                }
                CONSTANT_PROP_FUNCTION | CONSTANT_PROP_GLOBAL => {
                    let t = self.text(child);
                    self.nested_symbol(t);
                }
                _ => {
                    self.print(child, depth + 1, false);
                }
            }
            return;
        }
    }

    fn print_specialization_prefix(
        &mut self,
        n: NodeId,
        description: &str,
        depth: u32,
        param_prefix: &str,
    ) {
        if !self.options.display_generic_specializations {
            if !self.specialization_prefix_printed {
                self.s("specialized ");
                self.specialization_prefix_printed = true;
            }
            return;
        }
        let f = self.first(n);
        if self.k(f) == Kind::RepresentationChanged {
            self.s("representation changed of ");
            return;
        }
        self.s(description);
        self.s(" <");
        let mut separator = "";
        let mut arg_num = 0u64;
        for &child in self.children(n) {
            match self.k(child) {
                Kind::SpecializationPassID | Kind::DroppedArgument => {}
                Kind::IsSerialized => {
                    self.s(separator);
                    separator = ", ";
                    self.print(child, depth + 1, false);
                }
                ck => {
                    if self.has_children(child) {
                        self.s(separator);
                        self.s(param_prefix);
                        separator = ", ";
                        match ck {
                            Kind::FunctionSignatureSpecializationParam => {
                                self.s("Arg[");
                                self.num(arg_num);
                                self.s("] = ");
                                self.print_function_sig_specialization_params(child, depth);
                            }
                            Kind::FunctionSignatureSpecializationReturn => {
                                self.s("Return = ");
                                self.print_function_sig_specialization_params(child, depth);
                            }
                            _ => {
                                self.print(child, depth + 1, false);
                            }
                        }
                    }
                    arg_num += 1;
                }
            }
        }
        self.s("> of ");
    }

    /// Swift's `NodePrinter::print`: prints `n`, and returns the context
    /// that's left to print after it (`asPrefixContext`).
    pub(crate) fn print(
        &mut self,
        n: NodeId,
        depth: u32,
        as_prefix_context: bool,
    ) -> Option<NodeId> {
        // (Swift's depth limit.)
        if depth > MAX_DEPTH {
            self.s("<<too complex>>");
            return None;
        }
        if self.level >= self.limit {
            return self.boundary(n, depth, as_prefix_context);
        }
        self.level += 1;
        let r = self.print_inner(n, depth, as_prefix_context);
        self.level -= 1;
        r
    }

    fn state(&self) -> State {
        State {
            out: self.out.len(),
            options: self.options,
            specialization_prefix_printed: self.specialization_prefix_printed,
            valid: self.valid,
        }
    }

    /// A call to `print` past this run's levels: what [`Printer::drive`]
    /// has for it, if it has run it; else the call is left for it to run,
    /// and this run unwinds (every call to `print` returning at once).
    #[cold]
    #[inline(never)]
    fn boundary(&mut self, n: NodeId, depth: u32, as_prefix_context: bool) -> Option<NodeId> {
        let deep = match self.deep.as_deref_mut() {
            Some(deep) if deep.pending.is_some() => return None,
            Some(deep) => deep,
            None => {
                self.deep = ManuallyDrop::new(Some(Box::default()));
                self.deep.as_deref_mut()?
            }
        };
        if let Some(d) = deep.done.get(deep.done_at) {
            deep.done_at += 1;
            deep.spent += d.text.len() + 1;
            debug_assert_eq!(d.n, n);
            self.out.push_str(&d.text);
            self.options = d.exit.options;
            self.specialization_prefix_printed = d.exit.specialization_prefix_printed;
            self.valid = d.exit.valid;
            return d.result;
        }
        let entry = self.state();
        let prefix = self.out.clone();
        if let Some(deep) = self.deep.as_deref_mut() {
            deep.spent += prefix.len() + 1;
            deep.pending = Some(Call {
                n,
                depth,
                as_prefix_context,
                entry,
                prefix,
            });
        }
        self.limit = 0;
        None
    }

    /// Prints a tree nested past [`NATIVE_DEPTH`], once a run has left a
    /// call for it ([`Printer::boundary`]). The thread's stack holds at
    /// most `NATIVE_DEPTH` levels at a time: a call that would go deeper
    /// is instead run here, by itself, from the printer as it was at the
    /// call, and the run that made it is run again from its start.
    /// Printing is deterministic, so that run makes the same calls in the
    /// same order with the same output so far; each time it reaches a call
    /// run here, it takes what the call wrote (and the printer after it)
    /// and goes on, until it reaches a call not yet run (which runs next)
    /// or its end. The output is what printing on the thread's stack alone
    /// would write. The work is bounded ([`MAX_DEEP_WORK`]).
    #[cold]
    #[inline(never)]
    fn drive(&mut self, root: NodeId) {
        let mut tasks = alloc::vec![Task {
            call: None,
            entry: State {
                out: 0,
                options: self.options,
                specialization_prefix_printed: false,
                valid: true,
            },
            prefix: Some(String::new()),
            done: Vec::new(),
        }];
        let mut result = None;
        loop {
            let Some(deep) = self.deep.as_deref_mut() else {
                return;
            };
            if let Some(call) = deep.pending.take() {
                let Some(top) = tasks.last_mut() else {
                    return;
                };
                top.done = mem::take(&mut deep.done);
                tasks.push(Task {
                    call: Some((call.n, call.depth, call.as_prefix_context)),
                    entry: call.entry,
                    prefix: Some(call.prefix),
                    done: Vec::new(),
                });
            } else {
                let Some(task) = tasks.pop() else {
                    return;
                };
                let (Some((n, _, _)), Some(parent)) = (task.call, tasks.last_mut()) else {
                    return;
                };
                let text = String::from(self.out.get(task.entry.out..).unwrap_or(""));
                deep.spent += text.len() + 1;
                parent.done.push(Done {
                    n,
                    result,
                    exit: self.state(),
                    text,
                });
            }
            let Some(top) = tasks.last_mut() else {
                return;
            };
            if let Some(prefix) = &top.prefix {
                self.out.clone_from(prefix);
            }
            self.out.truncate(top.entry.out);
            self.options = top.entry.options;
            self.specialization_prefix_printed = top.entry.specialization_prefix_printed;
            self.valid = top.entry.valid;
            let Some(deep) = self.deep.as_deref_mut() else {
                return;
            };
            deep.spent += self.out.len() / 8 + 1;
            if deep.spent > MAX_DEEP_WORK {
                self.valid = false;
                return;
            }
            deep.done = mem::take(&mut top.done);
            deep.done_at = 0;
            self.limit = self.native_depth;
            let start = self.out.len();
            result = match top.call {
                Some((n, depth, apc)) => {
                    self.level = 1;
                    self.print_inner(n, depth, apc)
                }
                None => {
                    self.level = 0;
                    self.print(root, 0, false)
                }
            };
            let work = self.out.len().saturating_sub(start);
            if let Some(deep) = self.deep.as_deref_mut() {
                deep.spent += work;
            }
        }
    }

    fn print_inner(&mut self, n: NodeId, depth: u32, as_prefix_context: bool) -> Option<NodeId> {
        if n == MISSING {
            self.valid = false;
            return None;
        }
        if self.out.len() > MAX_OUTPUT {
            self.valid = false;
            return None;
        }
        let kind = self.k(n);
        if let Some(prefix) = prefix_then_child(kind) {
            self.s(prefix);
            self.pc(n, 0, depth);
            return None;
        }
        if let Some(t) = fixed_text(kind, &self.options) {
            self.s(t);
            return None;
        }
        if is_text_kind(kind) {
            let t = self.text(n);
            self.s(t);
            return None;
        }
        if let Some(name) = accessor_name(kind) {
            let c = self.first(n);
            return self.print_abstract_storage(c, depth, as_prefix_context, name);
        }
        if let Some((description, param_prefix)) = specialization(kind) {
            self.print_specialization_prefix(n, description, depth, param_prefix);
            return None;
        }
        self.print_other(n, kind, depth, as_prefix_context)
    }
}

/// The roles of attached macros, as Swift's `MacroRoles.def` describes them.
fn attached_macro_role(k: Kind) -> Option<&'static str> {
    use Kind::*;
    Some(match k {
        AccessorAttachedMacroExpansion => "accessor",
        MemberAttributeAttachedMacroExpansion => "memberAttribute",
        MemberAttachedMacroExpansion => "member",
        PeerAttachedMacroExpansion => "peer",
        ConformanceAttachedMacroExpansion => "conformance",
        ExtensionAttachedMacroExpansion => "extension",
        PreambleAttachedMacroExpansion => "preamble",
        BodyAttachedMacroExpansion => "body",
        _ => return None,
    })
}

/// Swift's `(int)index + 1` for the closure and macro numbers.
fn plus_one(i: u64) -> i64 {
    i64::from((i as i32).wrapping_add(1))
}

impl Printer<'_> {
    fn print_other(&mut self, n: NodeId, kind: Kind, depth: u32, apc: bool) -> Option<NodeId> {
        use Kind as K;
        use TypePrinting as TP;
        if let Some(role) = attached_macro_role(kind) {
            let name = self.c(n, 2);
            let name = self.node_to_string(name);
            let extra = alloc::format!("{role} macro @{name} expansion #");
            let d = self.c(n, 3);
            let i = plus_one(self.index(d));
            return self.print_entity(n, depth, apc, TP::NoType, true, &extra, i, "");
        }
        match kind {
            K::OutlinedBridgedMethod => {
                self.s("outlined bridged method (");
                let t = self.text(n);
                self.s(t);
                self.s(") of ");
            }
            K::OutlinedCopy | K::OutlinedConsume => {
                self.s(if kind == K::OutlinedCopy {
                    "outlined copy of "
                } else {
                    "outlined consume of "
                });
                self.pc(n, 0, depth);
                if self.nc(n) > 1 {
                    self.pc(n, 1, depth);
                }
            }
            K::OutlinedVariable | K::OutlinedReadOnlyObject => {
                self.s(if kind == K::OutlinedVariable {
                    "outlined variable #"
                } else {
                    "outlined read-only object #"
                });
                let i = self.index(n);
                self.num(i);
                self.s(" of ");
            }
            K::Directness => match self.index(n) {
                0 => self.s("direct "),
                1 => self.s("indirect "),
                _ => self.valid = false,
            },
            K::AnonymousContext => {
                if self.options.qualify_entities && self.options.display_extension_contexts {
                    self.pc(n, 1, depth);
                    self.s(".(unknown context at ");
                    self.pc(n, 0, depth);
                    self.s(")");
                    if self.nc(n) >= 3 {
                        let c2 = self.c(n, 2);
                        if self.nc(c2) > 0 {
                            self.s("<");
                            self.print(c2, depth + 1, false);
                            self.s(">");
                        }
                    }
                }
            }
            K::Extension => {
                if self.options.qualify_entities && self.options.display_extension_contexts {
                    self.s("(extension in ");
                    let c = self.c(n, 0);
                    self.print(c, depth + 1, true);
                    self.s("):");
                }
                self.pc(n, 1, depth);
                if self.nc(n) == 3 && !self.options.print_for_type_name {
                    self.pc(n, 2, depth);
                }
            }
            K::Variable => {
                return self.print_entity(n, depth, apc, TP::WithColon, true, "", -1, "");
            }
            K::Function | K::BoundGenericFunction => {
                return self.print_entity(n, depth, apc, TP::FunctionStyle, true, "", -1, "");
            }
            K::Subscript => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::FunctionStyle,
                    false,
                    "",
                    -1,
                    "subscript",
                );
            }
            K::Macro => {
                let tp = if self.nc(n) == 3 {
                    TP::WithColon
                } else {
                    TP::FunctionStyle
                };
                return self.print_entity(n, depth, apc, tp, true, "", -1, "");
            }
            K::FreestandingMacroExpansion | K::MacroExpansionUniqueName => {
                let extra = if kind == K::FreestandingMacroExpansion {
                    "freestanding macro expansion #"
                } else {
                    "unique name #"
                };
                let d = self.c(n, 2);
                let i = plus_one(self.index(d));
                return self.print_entity(n, depth, apc, TP::NoType, true, extra, i, "");
            }
            K::MacroExpansionLoc => {
                for (i, label) in ["module ", " file ", " line ", " column "]
                    .iter()
                    .enumerate()
                {
                    if self.nc(n) > i {
                        self.s(label);
                        self.pc(n, i, depth);
                    }
                }
            }
            K::GenericTypeParamDecl => {
                return self.print_entity(n, depth, apc, TP::NoType, true, "", -1, "");
            }
            K::ExplicitClosure | K::ImplicitClosure => {
                let tp = if self.options.show_function_argument_types {
                    TP::FunctionStyle
                } else {
                    TP::NoType
                };
                let extra = if kind == K::ExplicitClosure {
                    "closure #"
                } else {
                    "implicit closure #"
                };
                let d = self.c(n, 1);
                let i = plus_one(self.index(d));
                return self.print_entity(n, depth, apc, tp, false, extra, i, "");
            }
            K::Global => self.print_children(n, depth, None),
            K::Suffix => {
                if self.options.display_unmangled_suffix {
                    self.s(" with unmangled suffix ");
                    let t = self.text(n);
                    self.quoted(t);
                }
            }
            K::Initializer => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "variable initialization expression",
                    -1,
                    "",
                );
            }
            K::PropertyWrapperBackingInitializer => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "property wrapper backing initializer",
                    -1,
                    "",
                );
            }
            K::PropertyWrappedFieldInitAccessor => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "property wrapped field init accessor",
                    -1,
                    "",
                );
            }
            K::PropertyWrapperInitFromProjectedValue => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "property wrapper init from projected value",
                    -1,
                    "",
                );
            }
            K::DefaultArgumentInitializer => {
                let d = self.c(n, 1);
                let i = i64::from(self.index(d) as i32);
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "default argument ",
                    i,
                    "",
                );
            }
            K::TypeMangling => {
                let c0 = self.c(n, 0);
                if self.k(c0) == K::LabelList {
                    let c1 = self.c(n, 1);
                    let f = self.first(c1);
                    self.print_function_type(Some(c0), f, depth);
                } else {
                    self.print(c0, depth + 1, false);
                }
            }
            K::Class
            | K::Structure
            | K::Enum
            | K::Protocol
            | K::TypeAlias
            | K::OtherNominalType => {
                return self.print_entity(n, depth, apc, TP::NoType, true, "", -1, "");
            }
            K::LocalDeclName => {
                self.pc(n, 1, depth);
                if self.options.display_local_name_contexts {
                    self.s(" #");
                    let c = self.c(n, 0);
                    let i = self.index(c).wrapping_add(1);
                    self.num(i);
                }
            }
            K::PrivateDeclName => {
                let show = self.options.show_private_discriminators;
                if self.nc(n) > 1 {
                    if show {
                        self.s("(");
                    }
                    self.pc(n, 1, depth);
                    if show {
                        self.s(" in ");
                        let c = self.c(n, 0);
                        let t = self.text(c);
                        self.s(t);
                        self.s(")");
                    }
                } else if show {
                    self.s("(in ");
                    let c = self.c(n, 0);
                    let t = self.text(c);
                    self.s(t);
                    self.s(")");
                }
            }
            K::RelatedEntityDeclName => {
                self.s("related decl '");
                let c = self.first(n);
                let t = self.text(c);
                self.s(t);
                self.s("' for ");
                self.pc(n, 1, depth);
            }
            K::Module => {
                if self.options.display_module_names {
                    let t = self.text(n);
                    self.s(t);
                }
            }
            K::Index | K::SpecializationPassID | K::Number | K::Integer => {
                let i = self.index(n);
                self.num(i);
            }
            K::NegativeInteger => {
                let i = self.index(n) as i64;
                self.snum(i);
            }
            K::FunctionType
            | K::UncurriedFunctionType
            | K::NoEscapeFunctionType
            | K::CalledOnceFunctionType
            | K::CalledAtMostOnceFunctionType
            | K::AutoClosureType
            | K::EscapingAutoClosureType
            | K::ThinFunctionType
            | K::CFunctionPointer
            | K::ObjCBlock
            | K::EscapingObjCBlock => self.print_function_type(None, n, depth),
            K::ArgumentTuple | K::YieldTypes => {
                let show = self.options.show_function_argument_types;
                self.print_function_parameters(None, n, depth, show);
            }
            K::Tuple => {
                self.s("(");
                self.print_children(n, depth, Some(", "));
                self.s(")");
            }
            K::TupleElement => {
                if let Some(label) = self.child_if(n, K::TupleElementName) {
                    let t = self.text(label);
                    self.s(t);
                    self.s(": ");
                }
                match self.child_if(n, K::Type) {
                    Some(ty) => {
                        self.print(ty, depth + 1, false);
                    }
                    None => self.valid = false,
                }
                if self.child_if(n, K::VariadicMarker).is_some() {
                    self.s("...");
                }
            }
            K::TupleElementName => {
                let t = self.text(n);
                self.s(t);
                self.s(": ");
            }
            K::Pack | K::SILPackDirect | K::SILPackIndirect => {
                match kind {
                    K::SILPackDirect => self.s("@direct Pack{"),
                    K::SILPackIndirect => self.s("@indirect Pack{"),
                    _ => self.s("Pack{"),
                }
                self.print_children(n, depth, Some(", "));
                self.s("}");
            }
            K::PackElement => {
                self.s("/* level: ");
                let c = self.c(n, 1);
                let i = self.index(c);
                self.num(i);
                self.s(" */ each ");
                self.pc(n, 0, depth);
            }
            K::ReturnType => {
                if self.nc(n) == 0 {
                    let t = self.text(n);
                    self.s(t);
                } else {
                    self.print_children(n, depth, None);
                }
            }
            K::RetroactiveConformance => {
                if self.nc(n) == 2 {
                    self.s("retroactive @ ");
                    self.pc(n, 0, depth);
                    self.pc(n, 1, depth);
                }
            }
            K::GenericSpecializationParam => {
                self.pc(n, 0, depth);
                for i in 1..self.nc(n) {
                    self.s(if i == 1 { " with " } else { " and " });
                    self.pc(n, i, depth);
                }
            }
            K::DroppedArgument => {
                self.s("param");
                let i = self.index(n);
                self.num(i);
                self.s("-removed");
            }
            K::FunctionSignatureSpecializationParamPayload => {
                if self.has_text(n) {
                    let t = self.text(n);
                    self.nested_symbol(t);
                } else if self.has_index(n) {
                    let i = self.index(n);
                    self.num(i);
                }
            }
            K::FunctionSignatureSpecializationParamKind => self.print_fssp_kind(n),
            K::BuiltinFixedArray => {
                self.s("Builtin.FixedArray<");
                self.pc(n, 0, depth);
                self.s(", ");
                self.pc(n, 1, depth);
                self.s(">");
            }
            K::BuiltinBorrow => {
                self.s("Builtin.Borrow<");
                self.pc(n, 0, depth);
                self.s(">");
            }
            K::InfixOperator | K::PrefixOperator | K::PostfixOperator => {
                let t = self.text(n);
                self.s(t);
                self.s(match kind {
                    K::InfixOperator => " infix",
                    K::PrefixOperator => " prefix",
                    _ => " postfix",
                });
            }
            K::LazyProtocolWitnessTableAccessor | K::LazyProtocolWitnessTableCacheVariable => {
                self.s(if kind == K::LazyProtocolWitnessTableAccessor {
                    "lazy protocol witness table accessor for type "
                } else {
                    "lazy protocol witness table cache variable for type "
                });
                self.pc(n, 0, depth);
                self.s(" and conformance ");
                self.pc(n, 1, depth);
            }
            K::VTableThunk => {
                self.s("vtable thunk for ");
                self.pc(n, 1, depth);
                self.s(" dispatching to ");
                self.pc(n, 0, depth);
            }
            K::ProtocolWitness => {
                self.s("protocol witness for ");
                self.pc(n, 1, depth);
                self.s(" in conformance ");
                self.pc(n, 0, depth);
            }
            K::PartialApplyForwarder | K::PartialApplyObjCForwarder => {
                if self.options.shorten_partial_apply {
                    self.s("partial apply");
                } else if kind == K::PartialApplyForwarder {
                    self.s("partial apply forwarder");
                } else {
                    self.s("partial apply ObjC forwarder");
                }
                if self.has_children(n) {
                    self.s(" for ");
                    self.print_children(n, depth, None);
                }
            }
            K::KeyPathGetterThunkHelper
            | K::KeyPathSetterThunkHelper
            | K::KeyPathUnappliedMethodThunkHelper
            | K::KeyPathAppliedMethodThunkHelper => {
                self.s(match kind {
                    K::KeyPathGetterThunkHelper => "key path getter for ",
                    K::KeyPathSetterThunkHelper => "key path setter for ",
                    K::KeyPathUnappliedMethodThunkHelper => "key path unapplied method ",
                    _ => "key path applied method ",
                });
                self.pc(n, 0, depth);
                self.s(" : ");
                for &child in self.children(n).get(1..).unwrap_or(&[]) {
                    if self.k(child) == K::IsSerialized {
                        self.s(", ");
                    }
                    self.print(child, depth + 1, false);
                }
            }
            K::KeyPathEqualsThunkHelper | K::KeyPathHashThunkHelper => {
                self.s("key path index ");
                self.s(if kind == K::KeyPathEqualsThunkHelper {
                    "equality"
                } else {
                    "hash"
                });
                self.s(" operator for ");
                let mut last_index = self.nc(n);
                let mut last = self.last(n);
                if self.k(last) == K::IsSerialized {
                    last_index -= 1;
                    last = match last_index.checked_sub(1) {
                        Some(i) => self.c(n, i),
                        None => {
                            self.valid = false;
                            return None;
                        }
                    };
                }
                if self.k(last) == K::DependentGenericSignature {
                    self.print(last, depth + 1, false);
                    last_index -= 1;
                }
                self.s("(");
                for i in 0..last_index {
                    if i != 0 {
                        self.s(", ");
                    }
                    self.pc(n, i, depth);
                }
                self.s(")");
            }
            K::FieldOffset => {
                self.pc(n, 0, depth);
                self.s("field offset for ");
                self.pc(n, 1, depth);
            }
            K::ReabstractionThunk | K::ReabstractionThunkHelper => {
                if self.options.shorten_thunk {
                    self.s("thunk for ");
                    let l = self.last(n);
                    self.print(l, depth + 1, false);
                    return None;
                }
                self.s("reabstraction thunk ");
                if kind == K::ReabstractionThunkHelper {
                    self.s("helper ");
                }
                let mut idx = 0;
                if self.nc(n) == 3 {
                    idx = 1;
                    self.pc(n, 0, depth);
                    self.s(" ");
                }
                self.s("from ");
                self.pc(n, idx + 1, depth);
                self.s(" to ");
                self.pc(n, idx, depth);
            }
            K::ReabstractionThunkHelperWithGlobalActor => {
                self.pc(n, 0, depth);
                self.s(" with global actor constraint ");
                self.pc(n, 1, depth);
            }
            K::ReabstractionThunkHelperWithSelf => {
                self.s("reabstraction thunk ");
                let mut idx = 0;
                if self.nc(n) == 4 {
                    idx = 1;
                    self.pc(n, 0, depth);
                    self.s(" ");
                }
                self.s("from ");
                self.pc(n, idx + 2, depth);
                self.s(" to ");
                self.pc(n, idx + 1, depth);
                self.s(" self ");
                self.pc(n, idx, depth);
            }
            K::AutoDiffFunction | K::AutoDiffDerivativeVTableThunk => {
                let num = self.nc(n);
                let mut prefix_end = 0;
                while prefix_end != num {
                    let c = self.c(n, prefix_end);
                    if self.k(c) == K::AutoDiffFunctionKind {
                        break;
                    }
                    prefix_end += 1;
                }
                let func_kind = self.c(n, prefix_end);
                let param_indices = self.c(n, prefix_end + 1);
                let result_indices = self.c(n, prefix_end + 2);
                if kind == K::AutoDiffDerivativeVTableThunk {
                    self.s("vtable thunk for ");
                }
                self.print(func_kind, depth + 1, false);
                self.s(" of ");
                let mut optional_gen_sig = None;
                for i in 0..prefix_end {
                    let c = self.c(n, i);
                    if i == prefix_end - 1 && self.k(c) == K::DependentGenericSignature {
                        optional_gen_sig = Some(c);
                        break;
                    }
                    self.print(c, depth + 1, false);
                }
                if self.options.shorten_thunk {
                    return None;
                }
                self.s(" with respect to parameters ");
                self.print(param_indices, depth + 1, false);
                self.s(" and results ");
                self.print(result_indices, depth + 1, false);
                if let Some(g) = optional_gen_sig
                    && self.options.display_where_clauses
                {
                    self.s(" with ");
                    self.print(g, depth + 1, false);
                }
            }
            K::AutoDiffSelfReorderingReabstractionThunk => {
                self.s("autodiff self-reordering reabstraction thunk ");
                let from = self.c(n, 0);
                let to = self.c(n, 1);
                if self.options.shorten_thunk {
                    self.s("for ");
                    self.print(from, depth + 1, false);
                    return None;
                }
                let mut i = 2;
                let c = self.c(n, i);
                let gen_sig = if self.k(c) == K::DependentGenericSignature {
                    i += 1;
                    Some(c)
                } else {
                    None
                };
                self.s("for ");
                self.pc(n, i, depth);
                if let Some(g) = gen_sig {
                    self.print(g, depth + 1, false);
                    self.s(" ");
                }
                self.s(" from ");
                self.print(from, depth + 1, false);
                self.s(" to ");
                self.print(to, depth + 1, false);
            }
            K::AutoDiffSubsetParametersThunk => {
                let num = self.nc(n);
                if num < 5 {
                    self.valid = false;
                    return None;
                }
                self.s("autodiff subset parameters thunk for ");
                let to_param_indices = self.c(n, num - 1);
                let result_indices = self.c(n, num - 2);
                let param_indices = self.c(n, num - 3);
                let kind_node = self.c(n, num - 4);
                let current = num - 5;
                self.print(kind_node, depth + 1, false);
                self.s(" from ");
                if current == 0 {
                    self.pc(n, 0, depth);
                } else {
                    for i in 0..current {
                        self.pc(n, i, depth);
                    }
                }
                if self.options.shorten_thunk {
                    return None;
                }
                self.s(" with respect to parameters ");
                self.print(param_indices, depth + 1, false);
                self.s(" and results ");
                self.print(result_indices, depth + 1, false);
                self.s(" to parameters ");
                self.print(to_param_indices, depth + 1, false);
                if current > 0 {
                    self.s(" of type ");
                    self.pc(n, current, depth);
                }
            }
            K::AutoDiffFunctionKind => match self.index(n) as u8 {
                b'f' => self.s("forward-mode derivative"),
                b'r' => self.s("reverse-mode derivative"),
                b'd' => self.s("differential"),
                b'p' => self.s("pullback"),
                _ => {}
            },
            K::DifferentiabilityWitness => {
                let num = self.nc(n);
                let last = self.last(n);
                let back = if self.k(last) == K::DependentGenericSignature {
                    4
                } else {
                    3
                };
                let Some(kind_index) = num.checked_sub(back) else {
                    self.valid = false;
                    return None;
                };
                let kn = self.c(n, kind_index);
                match self.index(kn) as u8 {
                    b'f' => self.s("forward-mode"),
                    b'r' => self.s("reverse-mode"),
                    b'd' => self.s("normal"),
                    b'l' => self.s("linear"),
                    _ => {}
                }
                self.s(" differentiability witness for ");
                let mut idx = 0;
                while idx < num {
                    let c = self.c(n, idx);
                    if self.k(c) == K::Index {
                        break;
                    }
                    self.print(c, depth + 1, false);
                    idx += 1;
                }
                idx += 1;
                self.s(" with respect to parameters ");
                self.pc(n, idx, depth);
                self.s(" and results ");
                self.pc(n, idx + 1, depth);
                idx += 2;
                if idx < num {
                    self.s(" with ");
                    self.pc(n, idx, depth);
                }
            }
            K::IndexSubset => {
                self.s("{");
                let t = self.text(n);
                let mut any = false;
                for (i, c) in t.bytes().enumerate() {
                    if c != b'S' {
                        continue;
                    }
                    if any {
                        self.s(", ");
                    }
                    self.num(i as u64);
                    any = true;
                }
                self.s("}");
            }
            K::TypeSymbolicReference | K::OpaqueTypeDescriptorSymbolicReference => {
                self.s(if kind == K::TypeSymbolicReference {
                    "type symbolic reference 0x"
                } else {
                    "opaque type symbolic reference 0x"
                });
                match self.tree.payload(n) {
                    Payload::RemoteAddress(a, space) => {
                        self.hex(a);
                        self.s(" (");
                        self.num(u64::from(space));
                        self.s(")");
                    }
                    Payload::Index(i) => self.hex(i),
                    _ => {}
                }
            }
            K::ProtocolSymbolicReference => {
                self.s("protocol symbolic reference 0x");
                let i = self.index(n);
                self.hex(i);
            }
            K::AssociatedConformanceDescriptor | K::DefaultAssociatedConformanceAccessor => {
                self.s(if kind == K::AssociatedConformanceDescriptor {
                    "associated conformance descriptor for "
                } else {
                    "default associated conformance accessor for "
                });
                self.pc(n, 0, depth);
                self.s(".");
                self.pc(n, 1, depth);
                self.s(": ");
                self.pc(n, 2, depth);
            }
            K::AssociatedTypeMetadataAccessor => {
                self.s("associated type metadata accessor for ");
                self.pc(n, 1, depth);
                self.s(" in ");
                self.pc(n, 0, depth);
            }
            K::BaseConformanceDescriptor => {
                self.s("base conformance descriptor for ");
                self.pc(n, 0, depth);
                self.s(": ");
                self.pc(n, 1, depth);
            }
            K::AssociatedTypeWitnessTableAccessor => {
                self.s("associated type witness table accessor for ");
                self.pc(n, 1, depth);
                self.s(" : ");
                self.pc(n, 2, depth);
                self.s(" in ");
                self.pc(n, 0, depth);
            }
            K::BaseWitnessTableAccessor => {
                self.s("base witness table accessor for ");
                self.pc(n, 1, depth);
                self.s(" in ");
                self.pc(n, 0, depth);
            }
            K::ValueWitness => {
                let c = self.first(n);
                match Self::value_witness_name(self.index(c)) {
                    Some(name) => self.s(name),
                    None => self.valid = false,
                }
                self.s(if self.options.shorten_value_witness {
                    " for "
                } else {
                    " value witness for "
                });
                self.pc(n, 1, depth);
            }
            K::BoundGenericClass
            | K::BoundGenericStructure
            | K::BoundGenericEnum
            | K::BoundGenericProtocol
            | K::BoundGenericOtherNominalType
            | K::BoundGenericTypeAlias => self.print_bound_generic(n, depth),
            K::Metatype => {
                let mut idx = 0;
                if self.nc(n) == 2 {
                    self.pc(n, 0, depth);
                    self.s(" ");
                    idx = 1;
                }
                let c = self.c(n, idx);
                let ty = self.c(c, 0);
                self.print_with_parens(ty, depth);
                self.s(if self.is_existential_type(ty) {
                    ".Protocol"
                } else {
                    ".Type"
                });
            }
            K::ConstrainedExistential => {
                self.s("any ");
                self.pc(n, 0, depth);
                self.s("<");
                self.pc(n, 1, depth);
                self.s(">");
            }
            K::ConstrainedExistentialRequirementList => self.print_children(n, depth, Some(", ")),
            K::ExistentialMetatype => {
                let mut idx = 0;
                if self.nc(n) == 2 {
                    self.pc(n, 0, depth);
                    self.s(" ");
                    idx = 1;
                }
                self.pc(n, idx, depth);
                self.s(".Type");
            }
            K::AssociatedTypeRef => {
                self.pc(n, 0, depth);
                self.s(".");
                let c = self.c(n, 1);
                let t = self.text(c);
                self.s(t);
            }
            K::ProtocolList => {
                let type_list = self.c(n, 0);
                if self.nc(type_list) == 0 {
                    self.s("Any");
                } else {
                    self.print_children(type_list, depth, Some(" & "));
                }
            }
            K::ProtocolListWithClass => {
                if self.nc(n) < 2 {
                    return None;
                }
                let protocols = self.c(n, 0);
                self.pc(n, 1, depth);
                self.s(" & ");
                if self.nc(protocols) < 1 {
                    return None;
                }
                let type_list = self.c(protocols, 0);
                self.print_children(type_list, depth, Some(" & "));
            }
            K::ProtocolListWithAnyObject => {
                if self.nc(n) < 1 {
                    return None;
                }
                let protocols = self.c(n, 0);
                if self.nc(protocols) < 1 {
                    return None;
                }
                let type_list = self.c(protocols, 0);
                if self.nc(type_list) > 0 {
                    self.print_children(type_list, depth, Some(" & "));
                    self.s(" & ");
                }
                if self.options.qualify_entities && self.options.display_stdlib_module {
                    self.s(STDLIB_NAME);
                    self.s(".");
                }
                self.s("AnyObject");
            }
            K::Allocator => {
                let c = self.c(n, 0);
                let name = if self.k(c) == K::Class {
                    "__allocating_init"
                } else {
                    "init"
                };
                return self.print_entity(n, depth, apc, TP::FunctionStyle, false, name, -1, "");
            }
            K::Constructor => {
                let has_name = self.nc(n) > 2;
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::FunctionStyle,
                    has_name,
                    "init",
                    -1,
                    "",
                );
            }
            K::Destructor => {
                return self.print_entity(n, depth, apc, TP::NoType, false, "deinit", -1, "");
            }
            K::Deallocator | K::IsolatedDeallocator => {
                let c = self.c(n, 0);
                let name = match (self.k(c) == K::Class, kind == K::Deallocator) {
                    (true, true) => "__deallocating_deinit",
                    (true, false) => "__isolated_deallocating_deinit",
                    _ => "deinit",
                };
                return self.print_entity(n, depth, apc, TP::NoType, false, name, -1, "");
            }
            K::IVarInitializer => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "__ivar_initializer",
                    -1,
                    "",
                );
            }
            K::IVarDestroyer => {
                return self.print_entity(
                    n,
                    depth,
                    apc,
                    TP::NoType,
                    false,
                    "__ivar_destroyer",
                    -1,
                    "",
                );
            }
            K::ProtocolConformance => {
                let c0 = self.c(n, 0);
                let c1 = self.c(n, 1);
                let c2 = self.c(n, 2);
                if self.nc(n) == 4 {
                    self.s("property behavior storage of ");
                    self.print(c2, depth + 1, false);
                    self.s(" in ");
                    self.print(c0, depth + 1, false);
                    self.s(" : ");
                    self.print(c1, depth + 1, false);
                } else {
                    self.print(c0, depth + 1, false);
                    if self.options.display_protocol_conformances {
                        self.s(" : ");
                        self.print(c1, depth + 1, false);
                        self.s(" in ");
                        self.print(c2, depth + 1, false);
                    }
                }
            }
            K::TypeList => self.print_children(n, depth, None),
            K::ImplDifferentiabilityKind => {
                self.s("@differentiable");
                match self.index(n) as u8 {
                    b'l' => self.s("(_linear)"),
                    b'f' => self.s("(_forward)"),
                    b'r' => self.s("(reverse)"),
                    _ => {}
                }
            }
            K::ImplCoroutineKind => {
                let t = self.text(n);
                if !t.is_empty() {
                    self.s("@");
                    self.s(t);
                }
            }
            K::ImplParameterResultDifferentiability
            | K::ImplParameterSending
            | K::ImplParameterIsolated
            | K::ImplParameterImplicitLeading => {
                let t = self.text(n);
                if !t.is_empty() {
                    self.s(t);
                    self.s(" ");
                }
            }
            K::ImplFunctionConvention => {
                self.s("@convention(");
                match self.nc(n) {
                    1 => {
                        let c = self.c(n, 0);
                        let t = self.text(c);
                        self.s(t);
                    }
                    2 => {
                        let c = self.c(n, 0);
                        let t = self.text(c);
                        self.s(t);
                        self.s(", mangledCType: \"");
                        self.pc(n, 1, depth);
                        self.s("\"");
                    }
                    _ => {}
                }
                self.s(")");
            }
            K::ImplFunctionConventionName => {}
            K::ImplErrorResult | K::ImplYield => {
                self.s(if kind == K::ImplErrorResult {
                    "@error "
                } else {
                    "@yields "
                });
                self.print_children(n, depth, Some(" "));
            }
            K::ImplParameter | K::ImplResult => {
                self.pc(n, 0, depth);
                self.s(" ");
                if self.nc(n) == 3 {
                    self.pc(n, 1, depth);
                }
                if self.nc(n) == 4 {
                    self.pc(n, 1, depth);
                    self.pc(n, 2, depth);
                }
                let l = self.last(n);
                self.print(l, depth + 1, false);
            }
            K::ImplFunctionType => self.print_impl_function_type(n, depth),
            K::ImplInvocationSubstitutions => {
                self.s("for <");
                let c = self.c(n, 0);
                self.print_children(c, depth, Some(", "));
                self.s(">");
            }
            K::ImplPatternSubstitutions => {
                self.s("@substituted ");
                self.pc(n, 0, depth);
                self.s(" for <");
                let c = self.c(n, 1);
                self.print_children(c, depth, Some(", "));
                self.s(">");
            }
            K::DependentPseudogenericSignature | K::DependentGenericSignature => {
                self.print_generic_signature(n, depth);
            }
            K::DependentGenericConformanceRequirement => {
                self.pc(n, 0, depth);
                self.s(": ");
                self.pc(n, 1, depth);
            }
            K::DependentGenericInverseConformanceRequirement => {
                self.pc(n, 0, depth);
                self.s(": ~");
                let c = self.c(n, 1);
                match self.index(c) {
                    0 => self.s("Swift.Copyable"),
                    1 => self.s("Swift.Escapable"),
                    2 => self.s("Swift.Deinitable"),
                    i => {
                        self.s("Swift.<bit ");
                        self.num(i);
                        self.s(">");
                    }
                }
            }
            K::DependentGenericLayoutRequirement => {
                self.pc(n, 0, depth);
                self.s(": ");
                let layout = self.c(n, 1);
                let name = match self.text(layout).as_bytes().first() {
                    Some(b'U') => "_UnknownLayout",
                    Some(b'R') => "_RefCountedObject",
                    Some(b'N') => "_NativeRefCountedObject",
                    Some(b'C') => "AnyObject",
                    Some(b'D') => "_NativeClass",
                    Some(b'T' | b'E' | b'e') => "_Trivial",
                    Some(b'M' | b'm') => "_TrivialAtMost",
                    _ => "",
                };
                self.s(name);
                if self.nc(n) > 2 {
                    self.s("(");
                    self.pc(n, 2, depth);
                    if self.nc(n) > 3 {
                        self.s(", ");
                        self.pc(n, 3, depth);
                    }
                    self.s(")");
                }
            }
            K::DependentGenericSameTypeRequirement => {
                self.pc(n, 0, depth);
                self.s(" == ");
                self.pc(n, 1, depth);
            }
            K::DependentGenericSameShapeRequirement => {
                self.pc(n, 0, depth);
                self.s(".shape == ");
                self.pc(n, 1, depth);
                self.s(".shape");
            }
            K::DependentGenericParamType => {
                // (`unsigned`s in Swift.)
                let c1 = self.c(n, 1);
                let index = u64::from(self.index(c1) as u32);
                let c0 = self.c(n, 0);
                let d = u64::from(self.index(c0) as u32);
                generic_parameter_name(&mut self.out, d, index);
            }
            K::DependentGenericType => {
                self.pc(n, 0, depth);
                let dep_ty = self.c(n, 1);
                if need_space_before_type(self, dep_ty) {
                    self.s(" ");
                }
                self.print(dep_ty, depth + 1, false);
            }
            K::DependentMemberType => {
                self.pc(n, 0, depth);
                self.s(".");
                self.pc(n, 1, depth);
            }
            K::DependentAssociatedTypeRef => {
                if self.nc(n) > 1 {
                    self.pc(n, 1, depth);
                    self.s(".");
                }
                self.pc(n, 0, depth);
            }
            K::DifferentiableFunctionType => {
                self.s("@differentiable");
                match self.index(n) as u8 {
                    b'f' => self.s("(_forward)"),
                    b'r' => self.s("(reverse)"),
                    b'l' => self.s("(_linear)"),
                    _ => {}
                }
                self.s(" ");
            }
            K::GlobalActorFunctionType => {
                if self.nc(n) > 0 {
                    self.s("@");
                    self.pc(n, 0, depth);
                    self.s(" ");
                }
            }
            K::TypedThrowsAnnotation => {
                self.s(" throws(");
                if self.nc(n) == 1 {
                    self.pc(n, 0, depth);
                }
                self.s(")");
            }
            K::SILBoxTypeWithLayout => {
                let layout = self.c(n, 0);
                let mut generic_args = None;
                if self.nc(n) == 3 {
                    self.pc(n, 1, depth);
                    self.s(" ");
                    generic_args = Some(self.c(n, 2));
                }
                self.print(layout, depth + 1, false);
                if let Some(args) = generic_args {
                    self.s(" <");
                    self.print_children(args, depth, Some(", "));
                    self.s(">");
                }
            }
            K::SILBoxLayout => {
                self.s("{");
                for i in 0..self.nc(n) {
                    if i > 0 {
                        self.s(",");
                    }
                    self.s(" ");
                    self.pc(n, i, depth);
                }
                self.s(" }");
            }
            K::SILBoxImmutableField | K::SILBoxMutableField => {
                self.s(if kind == K::SILBoxImmutableField {
                    "let "
                } else {
                    "var "
                });
                self.pc(n, 0, depth);
            }
            K::AssocTypePath => self.print_children(n, depth, Some(".")),
            K::AssociatedTypeGenericParamRef => {
                self.s("generic parameter reference for associated type ");
                self.print_children(n, depth, None);
            }
            K::AnyProtocolConformanceList => {
                if self.nc(n) > 0 {
                    self.s("(");
                    self.print_children(n, depth, Some(", "));
                    self.s(")");
                }
            }
            K::ConcreteProtocolConformance => {
                self.s("concrete protocol conformance ");
                if self.has_index(n) {
                    self.s("#");
                    let i = self.index(n);
                    self.num(i);
                    self.s(" ");
                }
                self.pc(n, 0, depth);
                self.s(" to ");
                self.pc(n, 1, depth);
                if self.nc(n) > 2 {
                    let c2 = self.c(n, 2);
                    if self.nc(c2) > 0 {
                        self.s(" with conditional requirements: ");
                        self.print(c2, depth + 1, false);
                    }
                }
            }
            K::PackProtocolConformance
            | K::DependentAssociatedConformance
            | K::ProtocolConformanceRefInTypeModule
            | K::ProtocolConformanceRefInProtocolModule
            | K::ProtocolConformanceRefInOtherModule => {
                self.s(match kind {
                    K::PackProtocolConformance => "pack protocol conformance ",
                    K::DependentAssociatedConformance => "dependent associated conformance ",
                    K::ProtocolConformanceRefInTypeModule => {
                        "protocol conformance ref (type's module) "
                    }
                    K::ProtocolConformanceRefInProtocolModule => {
                        "protocol conformance ref (protocol's module) "
                    }
                    _ => "protocol conformance ref (retroactive) ",
                });
                self.print_children(n, depth, None);
            }
            K::DependentProtocolConformanceAssociated
            | K::DependentProtocolConformanceInherited
            | K::DependentProtocolConformanceRoot => {
                self.s(match kind {
                    K::DependentProtocolConformanceAssociated => {
                        "dependent associated protocol conformance "
                    }
                    K::DependentProtocolConformanceInherited => {
                        "dependent inherited protocol conformance "
                    }
                    _ => "dependent root protocol conformance ",
                });
                let c2 = self.c(n, 2);
                self.print_optional_index(c2);
                self.pc(n, 0, depth);
                self.s(" to ");
                self.pc(n, 1, depth);
            }
            K::DependentProtocolConformanceOpaque => {
                self.s("opaque result conformance ");
                self.pc(n, 0, depth);
                self.s(" of ");
                self.pc(n, 1, depth);
            }
            K::SugaredOptional => {
                let c = self.c(n, 0);
                self.print_with_parens(c, depth);
                self.s("?");
            }
            K::SugaredArray => {
                self.s("[");
                self.pc(n, 0, depth);
                self.s("]");
            }
            K::SugaredInlineArray | K::SugaredDictionary => {
                self.s("[");
                self.pc(n, 0, depth);
                self.s(if kind == K::SugaredInlineArray {
                    " of "
                } else {
                    " : "
                });
                self.pc(n, 1, depth);
                self.s("]");
            }
            K::SugaredParen => {
                self.s("(");
                self.pc(n, 0, depth);
                self.s(")");
            }
            K::OpaqueReturnTypeOf => {
                self.s("<<opaque return type of ");
                self.print_children(n, depth, None);
                self.s(">>");
            }
            K::OpaqueType => {
                self.pc(n, 0, depth);
                self.s(".");
                self.pc(n, 1, depth);
            }
            K::AccessorFunctionReference => {
                self.s("accessor function at ");
                let i = self.index(n);
                self.num(i);
            }
            K::GlobalVariableOnceToken | K::GlobalVariableOnceFunction => {
                self.s(if kind == K::GlobalVariableOnceToken {
                    "one-time initialization token for "
                } else {
                    "one-time initialization function for "
                });
                // (Swift calls `printContext` here and ignores its answer.)
                self.pc(n, 1, depth);
            }
            K::GlobalVariableOnceDeclList => {
                if self.nc(n) == 1 {
                    self.pc(n, 0, depth);
                } else {
                    self.s("(");
                    self.print_children(n, depth, Some(", "));
                    self.s(")");
                }
            }
            K::CheckedObjCAsyncCompletionHandlerImpl | K::ObjCAsyncCompletionHandlerImpl => {
                if kind == K::CheckedObjCAsyncCompletionHandlerImpl {
                    self.s("checked ");
                }
                self.s("@objc completion handler block implementation for ");
                if self.nc(n) >= 4 {
                    self.pc(n, 3, depth);
                }
                self.pc(n, 0, depth);
                self.s(" with result type ");
                self.pc(n, 1, depth);
                let c = self.c(n, 2);
                match self.index(c) {
                    0 => {}
                    1 => self.s(" nonzero on error"),
                    2 => self.s(" zero on error"),
                    _ => self.s(" <invalid error flag>"),
                }
            }
            K::AsyncAwaitResumePartialFunction | K::AsyncSuspendResumePartialFunction => {
                if self.options.show_async_resume_partial {
                    self.s("(");
                    self.pc(n, 0, depth);
                    self.s(")");
                    self.s(if kind == K::AsyncAwaitResumePartialFunction {
                        " await resume partial function for "
                    } else {
                        " suspend resume partial function for "
                    });
                }
            }
            K::ExtendedExistentialTypeShape => {
                // Swift reads children 1 and 2 here, past the end of the
                // node its demangler builds; the signature (if any) is the
                // first child and the type the last.
                let saved = self.options.display_where_clauses;
                self.options.display_where_clauses = true;
                let gen_sig = if self.nc(n) == 2 {
                    Some(self.c(n, 0))
                } else {
                    None
                };
                let ty = self.last(n);
                self.s("existential shape for ");
                if let Some(g) = gen_sig {
                    self.print(g, depth + 1, false);
                    self.s(" ");
                }
                self.s("any ");
                self.print(ty, depth + 1, false);
                self.options.display_where_clauses = saved;
            }
            K::UniqueExtendedExistentialTypeShapeSymbolicReference
            | K::NonUniqueExtendedExistentialTypeShapeSymbolicReference
            | K::ObjectiveCProtocolSymbolicReference => {
                self.s(match kind {
                    K::UniqueExtendedExistentialTypeShapeSymbolicReference => {
                        "unique existential shape symbolic reference 0x"
                    }
                    K::NonUniqueExtendedExistentialTypeShapeSymbolicReference => {
                        "non-unique existential shape symbolic reference 0x"
                    }
                    _ => "objective-c protocol symbolic reference 0x",
                });
                self.print_symbolic_reference_payload(n);
            }
            K::SymbolicExtendedExistentialType => {
                let shape = self.c(n, 0);
                let unique =
                    self.k(shape) == K::UniqueExtendedExistentialTypeShapeSymbolicReference;
                self.s("symbolic existential type (");
                self.s(if unique { "" } else { "non-" });
                self.s("unique) 0x");
                self.print_symbolic_reference_payload(shape);
                self.s(" <");
                self.pc(n, 1, depth);
                if self.nc(n) > 2 {
                    self.s(", ");
                    self.pc(n, 2, depth);
                }
                self.s(">");
            }
            // The kinds printed only as parts of others (Swift aborts).
            _ => self.valid = false,
        }
        None
    }

    fn print_fssp_kind(&mut self, n: NodeId) {
        use fssp::*;
        let raw = self.index(n);
        let mut printed = false;
        for (bit, text) in [
            (
                EXISTENTIAL_TO_GENERIC,
                "Existential To Protocol Constrained Generic",
            ),
            (DEAD, "Dead"),
            (OWNED_TO_GUARANTEED, "Owned To Guaranteed"),
            (GUARANTEED_TO_OWNED, "Guaranteed To Owned"),
        ] {
            if raw & bit != 0 {
                if printed {
                    self.s(" and ");
                }
                printed = true;
                self.s(text);
            }
        }
        if raw & SROA != 0 {
            if printed {
                self.s(" and ");
            }
            self.s("Exploded");
            return;
        }
        if printed {
            return;
        }
        let t = match raw {
            BOX_TO_VALUE => "Value Promoted from Box",
            BOX_TO_STACK => "Stack Promoted from Box",
            IN_OUT_TO_OUT => "InOut Converted to Out",
            CONSTANT_PROP_FUNCTION => "Constant Propagated Function",
            CONSTANT_PROP_GLOBAL => "Constant Propagated Global",
            CONSTANT_PROP_INTEGER => "Constant Propagated Integer",
            CONSTANT_PROP_FLOAT => "Constant Propagated Float",
            CONSTANT_PROP_STRING => "Constant Propagated String",
            CONSTANT_PROP_KEY_PATH => "Constant Propagated KeyPath",
            CONSTANT_PROP_STRUCT => "Constant Propagated Struct",
            CLOSURE_PROP => "Closure Propagated",
            ESCAPING_CLOSURE_PROP => "Escaping Closure Propagated",
            CLOSURE_PROP_PREVIOUS_ARG => "Same As Argument",
            _ => "",
        };
        self.s(t);
    }

    fn print_abstract_storage(
        &mut self,
        n: NodeId,
        depth: u32,
        apc: bool,
        extra_name: &str,
    ) -> Option<NodeId> {
        match self.k(n) {
            Kind::Variable => self.print_entity(
                n,
                depth,
                apc,
                TypePrinting::WithColon,
                true,
                extra_name,
                -1,
                "",
            ),
            Kind::Subscript => self.print_entity(
                n,
                depth,
                apc,
                TypePrinting::WithColon,
                false,
                extra_name,
                -1,
                "subscript",
            ),
            _ => {
                self.valid = false;
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn print_entity(
        &mut self,
        mut entity: NodeId,
        depth: u32,
        apc: bool,
        mut tp: TypePrinting,
        has_name: bool,
        extra_name: &str,
        extra_index: i64,
        overwrite_name: &str,
    ) -> Option<NodeId> {
        let mut generic_function_type_list = None;
        if self.k(entity) == Kind::BoundGenericFunction {
            generic_function_type_list = Some(self.c(entity, 1));
            entity = self.first(entity);
        }
        let mut multi_word_name = extra_name.contains(' ');
        let local_name = has_name && {
            let c = self.c(entity, 1);
            self.k(c) == Kind::LocalDeclName
        };
        if local_name && self.options.display_local_name_contexts {
            multi_word_name = true;
        }
        if apc && (tp != TypePrinting::NoType || multi_word_name) {
            return Some(entity);
        }
        let mut postfix_context = None;
        let context = self.c(entity, 0);
        if self.print_context(context) {
            if multi_word_name {
                postfix_context = Some(context);
            } else {
                let pos = self.out.len();
                postfix_context = self.print(context, depth + 1, true);
                if self.out.len() != pos {
                    self.s(".");
                }
            }
        }
        self.print_function_name(
            has_name,
            overwrite_name,
            extra_name,
            multi_word_name,
            extra_index,
            entity,
            depth,
        );
        if tp != TypePrinting::NoType {
            let Some(ty) = self.child_if(entity, Kind::Type) else {
                self.valid = false;
                return None;
            };
            let ty = self.c(ty, 0);
            if tp == TypePrinting::FunctionStyle {
                let mut t = ty;
                let mut guard = 0;
                while self.k(t) == Kind::DependentGenericType {
                    guard += 1;
                    if guard > MAX_DEPTH {
                        self.valid = false;
                        return None;
                    }
                    let c = self.c(t, 1);
                    t = self.c(c, 0);
                }
                if !matches!(
                    self.k(t),
                    Kind::FunctionType
                        | Kind::NoEscapeFunctionType
                        | Kind::UncurriedFunctionType
                        | Kind::CFunctionPointer
                        | Kind::ThinFunctionType
                        | Kind::CalledOnceFunctionType
                        | Kind::CalledAtMostOnceFunctionType
                ) {
                    tp = TypePrinting::WithColon;
                }
            }
            if tp == TypePrinting::WithColon {
                if self.options.display_entity_types {
                    self.s(" : ");
                    self.print_entity_type(entity, ty, generic_function_type_list, depth);
                }
            } else {
                let ek = self.k(entity);
                let show = !matches!(ek, Kind::ExplicitClosure | Kind::ImplicitClosure)
                    || self.options.show_closure_signature;
                if show {
                    if multi_word_name || need_space_before_type(self, ty) {
                        self.s(" ");
                    }
                    self.print_entity_type(entity, ty, generic_function_type_list, depth);
                }
            }
        }
        if !apc
            && let Some(pc) = postfix_context
            && (!local_name || self.options.display_local_name_contexts)
        {
            let of = matches!(
                self.k(entity),
                Kind::DefaultArgumentInitializer
                    | Kind::Initializer
                    | Kind::PropertyWrapperBackingInitializer
                    | Kind::PropertyWrappedFieldInitAccessor
                    | Kind::PropertyWrapperInitFromProjectedValue
            );
            self.s(if of { " of " } else { " in " });
            self.print(pc, depth + 1, false);
            postfix_context = None;
        }
        postfix_context
    }

    #[allow(clippy::too_many_arguments)]
    fn print_function_name(
        &mut self,
        has_name: bool,
        overwrite_name: &str,
        mut extra_name: &str,
        multi_word_name: bool,
        mut extra_index: i64,
        entity: NodeId,
        depth: u32,
    ) {
        if has_name || !overwrite_name.is_empty() {
            if !extra_name.is_empty() && multi_word_name {
                self.s(extra_name);
                if extra_index >= 0 {
                    self.snum(extra_index);
                }
                self.s(" of ");
                extra_name = "";
                extra_index = -1;
            }
            let pos = self.out.len();
            if overwrite_name.is_empty() {
                let name = self.c(entity, 1);
                if self.k(name) != Kind::PrivateDeclName {
                    self.print(name, depth + 1, false);
                }
                if let Some(private_name) = self.child_if(entity, Kind::PrivateDeclName) {
                    self.print(private_name, depth + 1, false);
                }
            } else {
                self.s(overwrite_name);
            }
            if self.out.len() != pos && !extra_name.is_empty() {
                self.s(".");
            }
        }
        if !extra_name.is_empty() {
            self.s(extra_name);
            if extra_index >= 0 {
                self.snum(extra_index);
            }
        }
    }

    fn print_entity_type(
        &mut self,
        entity: NodeId,
        mut ty: NodeId,
        generic_function_type_list: Option<NodeId>,
        depth: u32,
    ) {
        let label_list = self.child_if(entity, Kind::LabelList);
        if label_list.is_some() || generic_function_type_list.is_some() {
            if let Some(g) = generic_function_type_list {
                self.s("<");
                self.print_children(g, depth, Some(", "));
                self.s(">");
            }
            if self.k(ty) == Kind::DependentGenericType {
                if generic_function_type_list.is_none() {
                    self.pc(ty, 0, depth);
                }
                let dependent_type = self.c(ty, 1);
                if need_space_before_type(self, dependent_type) {
                    self.s(" ");
                }
                ty = self.first(dependent_type);
            }
            self.print_function_type(label_list, ty, depth);
        } else {
            self.print(ty, depth + 1, false);
        }
    }
}

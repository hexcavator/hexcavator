// SPDX-License-Identifier: Apache-2.0 WITH Swift-exception
// Translated from the Swift project's lib/Demangling/OldDemangler.cpp (see
// LICENSE-SWIFT at the crate root); the structure and names follow it.

//! The demangler for Swift's old mangling (`_T`, before Swift 4).

use alloc::string::String;
use alloc::vec::Vec;

use super::demangler::{
    MANGLING_MODULE_CLANG_IMPORTER, MANGLING_MODULE_OBJC, STDLIB_NAME, VALUE_WITNESSES,
};
use super::kinds::Kind;
use super::node::{NodeId, Tree};
use super::punycode;

type N = Option<NodeId>;

/// The deepest the demangler recurses: Swift's `OldDemangler::MaxDepth` is
/// 1024, but this recursion is on the thread's stack, so it stops sooner
/// (and fails the name) at a constant depth. Real names nest far less (the
/// deepest of Swift's test manglings is 14 levels).
const MAX_DEPTH: u32 = 64;

/// Swift's `demangleOldSymbolAsNode`.
pub fn demangle_old_symbol_as_node(tree: &mut Tree, name: &[u8]) -> Option<NodeId> {
    let mut d = OldDemangler {
        tree,
        text: name,
        pos: 0,
        subs: Vec::new(),
    };
    let root = d.demangle_top_level();
    if d.tree.overflow {
        return None;
    }
    root
}

fn is_start_of_identifier(c: u8) -> bool {
    c.is_ascii_digit() || c == b'o'
}

fn is_start_of_nominal_type(c: u8) -> bool {
    matches!(c, b'C' | b'V' | b'O')
}

fn is_start_of_entity(c: u8) -> bool {
    matches!(c, b'F' | b'I' | b'v' | b'P' | b's' | b'Z') || is_start_of_nominal_type(c)
}

fn nominal_type_marker_to_node_kind(c: u8) -> Kind {
    match c {
        b'C' => Kind::Class,
        b'V' => Kind::Structure,
        b'O' => Kind::Enum,
        _ => Kind::Identifier,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IsVariadic {
    Yes,
    No,
}

// FunctionSigSpecializationParamKind.
const FSSP_CONSTANT_PROP_FUNCTION: u64 = 0;
const FSSP_CONSTANT_PROP_GLOBAL: u64 = 1;
const FSSP_CONSTANT_PROP_INTEGER: u64 = 2;
const FSSP_CONSTANT_PROP_FLOAT: u64 = 3;
const FSSP_CONSTANT_PROP_STRING: u64 = 4;
const FSSP_CLOSURE_PROP: u64 = 5;
const FSSP_BOX_TO_VALUE: u64 = 6;
const FSSP_BOX_TO_STACK: u64 = 7;
const FSSP_IN_OUT_TO_OUT: u64 = 8;
const FSSP_DEAD: u64 = 1 << 6;
const FSSP_OWNED_TO_GUARANTEED: u64 = 1 << 7;
const FSSP_SROA: u64 = 1 << 8;
const FSSP_GUARANTEED_TO_OWNED: u64 = 1 << 9;

/// Swift's `OldDemangler` (with its `NameSource`).
struct OldDemangler<'t, 'a> {
    tree: &'t mut Tree,
    text: &'a [u8],
    pos: usize,
    subs: Vec<NodeId>,
}

impl OldDemangler<'_, '_> {
    /// Whether recursion has gone too deep ([`MAX_DEPTH`]): the name fails
    /// outright, as too complex.
    fn too_deep(&mut self, depth: u32) -> bool {
        if depth > MAX_DEPTH {
            self.tree.overflow = true;
            return true;
        }
        false
    }

    // --- NameSource ----------------------------------------------------------

    fn rest(&self) -> &[u8] {
        &self.text[self.pos..]
    }

    fn has_at_least(&self, len: u64) -> bool {
        len <= (self.text.len() - self.pos) as u64
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.text.len()
    }

    fn peek(&self) -> u8 {
        // ('.' is otherwise unused, so a malformed name stops there.)
        self.text.get(self.pos).copied().unwrap_or(b'.')
    }

    fn next(&mut self) -> u8 {
        let c = self.peek();
        if !self.is_empty() {
            self.pos += 1;
        }
        c
    }

    fn next_if(&mut self, c: u8) -> bool {
        if self.is_empty() || self.peek() != c {
            return false;
        }
        self.pos += 1;
        true
    }

    fn next_if_str(&mut self, s: &str) -> bool {
        if !self.rest().starts_with(s.as_bytes()) {
            return false;
        }
        self.pos += s.len();
        true
    }

    fn get_string(&mut self) -> &[u8] {
        let start = self.pos;
        self.pos = self.text.len();
        &self.text[start..]
    }

    /// Reads up to `c`; whether `c` was found (Swift's `readUntil`, which
    /// is also true if the last character read was `c`, so never).
    fn read_until(&mut self, c: u8) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut last = None;
        while !self.is_empty() {
            let c2 = self.peek();
            last = Some(c2);
            if c2 == c {
                break;
            }
            out.push(c2);
            self.pos += 1;
        }
        (last == Some(c)).then_some(out)
    }

    // --- Nodes ---------------------------------------------------------------

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

    fn add(&mut self, parent: NodeId, child: NodeId) {
        self.tree.add_child(parent, child);
    }

    fn kind(&self, n: NodeId) -> Kind {
        self.tree.kind(n)
    }

    // --- The grammar ---------------------------------------------------------

    fn demangle_top_level(&mut self) -> N {
        if !self.next_if_str("_T") {
            return None;
        }
        let top = self.create(Kind::Global)?;
        if self.next_if_str("TS") {
            loop {
                let c = self.demangle_specialized_attribute(0)?;
                self.add(top, c);
                // (The substitutions of a specialization are its own.)
                self.subs.clear();
                if !self.next_if_str("_TTS") {
                    break;
                }
            }
            if !self.next_if_str("_T") {
                return None;
            }
        } else {
            let attr = if self.next_if_str("To") {
                Some(Kind::ObjCAttribute)
            } else if self.next_if_str("TO") {
                Some(Kind::NonObjCAttribute)
            } else if self.next_if_str("TD") {
                Some(Kind::DynamicAttribute)
            } else if self.next_if_str("Td") {
                Some(Kind::DirectMethodReferenceAttribute)
            } else if self.next_if_str("TV") {
                Some(Kind::VTableAttribute)
            } else {
                None
            };
            if let Some(k) = attr {
                let a = self.create(k)?;
                self.add(top, a);
            }
        }
        let g = self.demangle_global(0)?;
        self.add(top, g);
        if !self.is_empty() {
            let rest = self.get_string();
            let rest = String::from_utf8_lossy(rest).into_owned();
            let s = self.create_text(Kind::Suffix, &rest)?;
            self.add(top, s);
        }
        Some(top)
    }

    fn demangle_directness(&mut self) -> Option<u64> {
        if self.next_if(b'd') {
            Some(0)
        } else if self.next_if(b'i') {
            Some(1)
        } else {
            None
        }
    }

    fn demangle_natural(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let c = self.next();
        if !c.is_ascii_digit() {
            return None;
        }
        let mut num = u64::from(c - b'0');
        while !self.is_empty() {
            let c = self.peek();
            if !c.is_ascii_digit() {
                break;
            }
            num = num.wrapping_mul(10).wrapping_add(u64::from(c - b'0'));
            self.next();
        }
        Some(num)
    }

    fn demangle_builtin_size(&mut self) -> Option<u64> {
        let n = self.demangle_natural()?;
        self.next_if(b'_').then_some(n)
    }

    fn demangle_value_witness_kind(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let c0 = self.next();
        if self.is_empty() {
            return None;
        }
        let c1 = self.next();
        VALUE_WITNESSES
            .iter()
            .position(|(m, _)| **m == [c0, c1])
            .map(|i| i as u64)
    }

    /// `kind` with one child, demangled by `f`.
    fn with_child(&mut self, kind: Kind, f: impl FnOnce(&mut Self) -> N) -> N {
        let n = self.create(kind)?;
        let c = f(self)?;
        self.add(n, c);
        Some(n)
    }

    fn demangle_global(&mut self, depth: u32) -> N {
        if self.too_deep(depth) || self.is_empty() {
            return None;
        }
        let d = depth + 1;
        if self.next_if(b'M') {
            let kind = if self.next_if(b'P') {
                Kind::GenericTypeMetadataPattern
            } else if self.next_if(b'a') {
                Kind::TypeMetadataAccessFunction
            } else if self.next_if(b'L') {
                Kind::TypeMetadataLazyCache
            } else if self.next_if(b'm') {
                Kind::Metaclass
            } else if self.next_if(b'n') {
                Kind::NominalTypeDescriptor
            } else if self.next_if(b'f') {
                Kind::FullTypeMetadata
            } else if self.next_if(b'p') {
                return self.with_child(Kind::ProtocolDescriptor, |s| s.demangle_protocol_name(d));
            } else {
                Kind::TypeMetadata
            };
            return self.with_child(kind, |s| s.demangle_type(d));
        }
        if self.next_if_str("PA") {
            let kind = if self.next_if(b'o') {
                Kind::PartialApplyObjCForwarder
            } else {
                Kind::PartialApplyForwarder
            };
            let forwarder = self.create(kind)?;
            if self.next_if_str("__T") {
                let g = self.demangle_global(d)?;
                self.add(forwarder, g);
            }
            return Some(forwarder);
        }
        if self.next_if(b't') {
            return self.with_child(Kind::TypeMangling, |s| s.demangle_type(d));
        }
        if self.next_if(b'w') {
            let w = self.demangle_value_witness_kind()?;
            let witness = self.create(Kind::ValueWitness)?;
            let i = self.create_index(Kind::Index, w)?;
            self.add(witness, i);
            let t = self.demangle_type(d)?;
            self.add(witness, t);
            return Some(witness);
        }
        if self.next_if(b'W') {
            if self.next_if(b'V') {
                return self.with_child(Kind::ValueWitnessTable, |s| s.demangle_type(d));
            }
            if self.next_if(b'v') {
                let field_offset = self.create(Kind::FieldOffset)?;
                let dir = self.demangle_directness()?;
                let dn = self.create_index(Kind::Directness, dir)?;
                self.add(field_offset, dn);
                let e = self.demangle_entity(d)?;
                self.add(field_offset, e);
                return Some(field_offset);
            }
            let simple = if self.next_if(b'P') {
                Some(Kind::ProtocolWitnessTable)
            } else if self.next_if(b'G') {
                Some(Kind::GenericProtocolWitnessTable)
            } else if self.next_if(b'I') {
                Some(Kind::GenericProtocolWitnessTableInstantiationFunction)
            } else if self.next_if(b'a') {
                Some(Kind::ProtocolWitnessTableAccessor)
            } else {
                None
            };
            if let Some(kind) = simple {
                return self.with_child(kind, |s| s.demangle_protocol_conformance(d));
            }
            let lazy = if self.next_if(b'l') {
                Some(Kind::LazyProtocolWitnessTableAccessor)
            } else if self.next_if(b'L') {
                Some(Kind::LazyProtocolWitnessTableCacheVariable)
            } else {
                None
            };
            if let Some(kind) = lazy {
                let accessor = self.create(kind)?;
                let t = self.demangle_type(d)?;
                self.add(accessor, t);
                let c = self.demangle_protocol_conformance(d)?;
                self.add(accessor, c);
                return Some(accessor);
            }
            if self.next_if(b't') {
                let accessor = self.create(Kind::AssociatedTypeMetadataAccessor)?;
                let c = self.demangle_protocol_conformance(d)?;
                self.add(accessor, c);
                let n = self.demangle_decl_name(d)?;
                self.add(accessor, n);
                return Some(accessor);
            }
            if self.next_if(b'T') {
                let accessor = self.create(Kind::AssociatedTypeWitnessTableAccessor)?;
                let c = self.demangle_protocol_conformance(d)?;
                self.add(accessor, c);
                let n = self.demangle_decl_name(d)?;
                self.add(accessor, n);
                let p = self.demangle_protocol_name(d)?;
                self.add(accessor, p);
                return Some(accessor);
            }
            return None;
        }
        if self.next_if(b'T') {
            let reabstraction = if self.next_if(b'R') {
                Some(Kind::ReabstractionThunkHelper)
            } else if self.next_if(b'r') {
                Some(Kind::ReabstractionThunk)
            } else {
                None
            };
            if let Some(kind) = reabstraction {
                let thunk = self.create(kind)?;
                self.demangle_reabstract_signature(thunk, d)?;
                return Some(thunk);
            }
            if self.next_if(b'W') {
                let thunk = self.create(Kind::ProtocolWitness)?;
                let c = self.demangle_protocol_conformance(d)?;
                self.add(thunk, c);
                let e = self.demangle_entity(d)?;
                self.add(thunk, e);
                return Some(thunk);
            }
            return None;
        }
        self.demangle_entity(d)
    }

    fn demangle_generic_specialization(&mut self, spec: NodeId, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        while !self.next_if(b'_') {
            let param = self.create(Kind::GenericSpecializationParam)?;
            let t = self.demangle_type(depth + 1)?;
            self.add(param, t);
            while !self.next_if(b'_') {
                let c = self.demangle_protocol_conformance(depth + 1)?;
                self.add(param, c);
            }
            self.add(spec, param);
        }
        Some(spec)
    }

    fn param_kind(&mut self, parent: NodeId, kind: u64) -> Option<()> {
        let k = self.create_index(Kind::FunctionSignatureSpecializationParamKind, kind)?;
        self.add(parent, k);
        Some(())
    }

    fn param_payload(&mut self, parent: NodeId, payload: &[u8]) -> Option<()> {
        let p = self.create_bytes(Kind::FunctionSignatureSpecializationParamPayload, payload)?;
        self.add(parent, p);
        Some(())
    }

    fn demangle_func_sig_specialization_constant_prop(
        &mut self,
        parent: NodeId,
        depth: u32,
    ) -> Option<()> {
        let named = if self.next_if_str("fr") {
            Some(FSSP_CONSTANT_PROP_FUNCTION)
        } else if self.next_if(b'g') {
            Some(FSSP_CONSTANT_PROP_GLOBAL)
        } else {
            None
        };
        if let Some(kind) = named {
            let name = self.demangle_identifier(depth + 1, None)?;
            if !self.next_if(b'_') {
                return None;
            }
            self.param_kind(parent, kind)?;
            let t = String::from(self.tree.text(name));
            let pl = self.create_text(Kind::Identifier, &t)?;
            self.add(parent, pl);
            return Some(());
        }
        let number = if self.next_if(b'i') {
            Some(FSSP_CONSTANT_PROP_INTEGER)
        } else if self.next_if_str("fl") {
            Some(FSSP_CONSTANT_PROP_FLOAT)
        } else {
            None
        };
        if let Some(kind) = number {
            let s = self.read_until(b'_')?;
            if !self.next_if(b'_') {
                return None;
            }
            self.param_kind(parent, kind)?;
            self.param_payload(parent, &s)?;
            return Some(());
        }
        if self.next_if(b's') {
            if !self.next_if(b'e') {
                return None;
            }
            let encoding = match self.peek() {
                b'0' => "u8",
                b'1' => "u16",
                _ => return None,
            };
            self.pos += 1;
            if !self.next_if(b'v') {
                return None;
            }
            let s = self.demangle_identifier(depth + 1, None)?;
            if !self.next_if(b'_') {
                return None;
            }
            self.param_kind(parent, FSSP_CONSTANT_PROP_STRING)?;
            self.param_payload(parent, encoding.as_bytes())?;
            let t = String::from(self.tree.text(s));
            let pl = self.create_text(Kind::Identifier, &t)?;
            self.add(parent, pl);
            return Some(());
        }
        None
    }

    fn demangle_func_sig_specialization_closure_prop(
        &mut self,
        parent: NodeId,
        depth: u32,
    ) -> Option<()> {
        let name = self.demangle_identifier(depth + 1, None)?;
        self.param_kind(parent, FSSP_CLOSURE_PROP)?;
        let t = String::from(self.tree.text(name));
        self.param_payload(parent, t.as_bytes())?;
        while self.peek() != b'_' {
            let Some(ty) = self.demangle_type(depth + 1) else {
                break;
            };
            self.add(parent, ty);
        }
        self.next_if(b'_').then_some(())
    }

    fn demangle_function_signature_specialization(&mut self, spec: NodeId, depth: u32) -> N {
        while !self.next_if(b'_') {
            let param = self.create(Kind::FunctionSignatureSpecializationParam)?;
            if self.next_if_str("n_") {
            } else if self.next_if_str("cp") {
                self.demangle_func_sig_specialization_constant_prop(param, depth + 1)?;
            } else if self.next_if_str("cl") {
                self.demangle_func_sig_specialization_closure_prop(param, depth + 1)?;
            } else if self.next_if_str("i_") {
                self.param_kind(param, FSSP_BOX_TO_VALUE)?;
            } else if self.next_if_str("k_") {
                self.param_kind(param, FSSP_BOX_TO_STACK)?;
            } else if self.next_if_str("r_") {
                self.param_kind(param, FSSP_IN_OUT_TO_OUT)?;
            } else {
                let mut value = 0;
                if self.next_if(b'd') {
                    value |= FSSP_DEAD;
                }
                if self.next_if(b'g') {
                    value |= FSSP_OWNED_TO_GUARANTEED;
                }
                if self.next_if(b'o') {
                    value |= FSSP_GUARANTEED_TO_OWNED;
                }
                if self.next_if(b's') {
                    value |= FSSP_SROA;
                }
                if !self.next_if(b'_') || value == 0 {
                    return None;
                }
                self.param_kind(param, value)?;
            }
            self.add(spec, param);
        }
        Some(spec)
    }

    /// The pass ID: Swift's `unsigned(Mangled.next() - 48)`.
    fn pass_id(&mut self) -> N {
        let c = self.next();
        let id = u64::from((i32::from(c) - 48) as u32);
        self.create_index(Kind::SpecializationPassID, id)
    }

    fn demangle_specialized_attribute(&mut self, depth: u32) -> N {
        let generic = if self.next_if(b'g') {
            Some(Kind::GenericSpecialization)
        } else if self.next_if(b'r') {
            Some(Kind::GenericSpecializationNotReAbstracted)
        } else {
            None
        };
        if let Some(kind) = generic {
            let spec = self.create(kind)?;
            if self.next_if(b'q') {
                let s = self.create(Kind::IsSerialized)?;
                self.add(spec, s);
            }
            let p = self.pass_id()?;
            self.add(spec, p);
            return self.demangle_generic_specialization(spec, depth + 1);
        }
        if self.next_if(b'f') {
            let spec = self.create(Kind::FunctionSignatureSpecialization)?;
            if self.next_if(b'q') {
                let s = self.create(Kind::IsSerialized)?;
                self.add(spec, s);
            }
            let p = self.pass_id()?;
            self.add(spec, p);
            return self.demangle_function_signature_specialization(spec, depth + 1);
        }
        None
    }

    fn demangle_decl_name(&mut self, depth: u32) -> N {
        if self.next_if(b'L') {
            let discriminator = self.demangle_index_as_node(Kind::Number)?;
            let name = self.demangle_identifier(depth + 1, None)?;
            let local = self.create(Kind::LocalDeclName)?;
            self.add(local, discriminator);
            self.add(local, name);
            return Some(local);
        }
        if self.next_if(b'P') {
            let discriminator = self.demangle_identifier(depth + 1, None)?;
            let name = self.demangle_identifier(depth + 1, None)?;
            let private = self.create(Kind::PrivateDeclName)?;
            self.add(private, discriminator);
            self.add(private, name);
            return Some(private);
        }
        self.demangle_identifier(depth + 1, None)
    }

    fn demangle_identifier(&mut self, _depth: u32, kind: Option<Kind>) -> N {
        if self.is_empty() {
            return None;
        }
        let is_punycoded = self.next_if(b'X');
        let mut kind = kind;
        let mut is_operator = false;
        if self.next_if(b'o') {
            is_operator = true;
            if kind.is_some() {
                return None;
            }
            kind = Some(match self.next() {
                b'p' => Kind::PrefixOperator,
                b'P' => Kind::PostfixOperator,
                b'i' => Kind::InfixOperator,
                _ => return None,
            });
        }
        let kind = kind.unwrap_or(Kind::Identifier);
        let length = self.demangle_natural()?;
        if !self.has_at_least(length) {
            return None;
        }
        let start = self.pos;
        self.pos += length as usize;
        let raw = &self.text[start..self.pos];
        let decoded;
        let identifier: &[u8] = if is_punycoded {
            decoded = punycode::decode_utf8(raw)?;
            decoded.as_bytes()
        } else {
            raw
        };
        if identifier.is_empty() {
            return None;
        }
        if is_operator {
            //                       abcdefghijklmnopqrstuvwxyz
            const OP_CHAR_TABLE: &[u8; 26] = b"& @/= >    <*!|+?%-~   ^ .";
            let mut op = Vec::with_capacity(identifier.len());
            for &c in identifier {
                if c >= 0x80 {
                    op.push(c);
                    continue;
                }
                if !c.is_ascii_lowercase() {
                    return None;
                }
                let o = OP_CHAR_TABLE[usize::from(c - b'a')];
                if o == b' ' {
                    return None;
                }
                op.push(o);
            }
            return self.create_bytes(kind, &op);
        }
        let identifier = identifier.to_vec();
        self.create_bytes(kind, &identifier)
    }

    fn demangle_index(&mut self) -> Option<u64> {
        if self.next_if(b'_') {
            return Some(0);
        }
        let n = self.demangle_natural()?;
        if !self.next_if(b'_') {
            return None;
        }
        Some(n.wrapping_add(1))
    }

    fn demangle_index_as_node(&mut self, kind: Kind) -> N {
        let i = self.demangle_index()?;
        self.create_index(kind, i)
    }

    fn create_swift_type(&mut self, kind: Kind, name: &str) -> N {
        let ty = self.create(kind)?;
        let m = self.create_text(Kind::Module, STDLIB_NAME)?;
        self.add(ty, m);
        let i = self.create_text(Kind::Identifier, name)?;
        self.add(ty, i);
        Some(ty)
    }

    fn demangle_substitution_index(&mut self) -> N {
        if self.is_empty() {
            return None;
        }
        let (kind, name) = match self.peek() {
            b'o' => {
                self.pos += 1;
                return self.create_text(Kind::Module, MANGLING_MODULE_OBJC);
            }
            b'C' => {
                self.pos += 1;
                return self.create_text(Kind::Module, MANGLING_MODULE_CLANG_IMPORTER);
            }
            b'a' => (Kind::Structure, "Array"),
            b'b' => (Kind::Structure, "Bool"),
            b'c' => (Kind::Structure, "UnicodeScalar"),
            b'd' => (Kind::Structure, "Double"),
            b'f' => (Kind::Structure, "Float"),
            b'i' => (Kind::Structure, "Int"),
            b'V' => (Kind::Structure, "UnsafeRawPointer"),
            b'v' => (Kind::Structure, "UnsafeMutableRawPointer"),
            b'P' => (Kind::Structure, "UnsafePointer"),
            b'p' => (Kind::Structure, "UnsafeMutablePointer"),
            b'q' => (Kind::Enum, "Optional"),
            b'Q' => (Kind::Enum, "ImplicitlyUnwrappedOptional"),
            b'R' => (Kind::Structure, "UnsafeBufferPointer"),
            b'r' => (Kind::Structure, "UnsafeMutableBufferPointer"),
            b'S' => (Kind::Structure, "String"),
            b'u' => (Kind::Structure, "UInt"),
            _ => {
                let i = self.demangle_index()?;
                return usize::try_from(i)
                    .ok()
                    .and_then(|i| self.subs.get(i).copied());
            }
        };
        self.pos += 1;
        self.create_swift_type(kind, name)
    }

    fn demangle_module(&mut self, depth: u32) -> N {
        if self.next_if(b's') {
            return self.create_text(Kind::Module, STDLIB_NAME);
        }
        if self.next_if(b'S') {
            let m = self.demangle_substitution_index()?;
            return (self.kind(m) == Kind::Module).then_some(m);
        }
        let m = self.demangle_identifier(depth + 1, Some(Kind::Module))?;
        self.subs.push(m);
        Some(m)
    }

    fn demangle_declaration_name(&mut self, kind: Kind, depth: u32) -> N {
        let context = self.demangle_context(depth + 1)?;
        let name = self.demangle_decl_name(depth + 1)?;
        let decl = self.create(kind)?;
        self.add(decl, context);
        self.add(decl, name);
        self.subs.push(decl);
        Some(decl)
    }

    fn demangle_protocol_name(&mut self, depth: u32) -> N {
        let proto = self.demangle_protocol_name_impl(depth)?;
        let ty = self.create(Kind::Type)?;
        self.add(ty, proto);
        Some(ty)
    }

    fn demangle_protocol_name_given_context(&mut self, context: NodeId, depth: u32) -> N {
        let name = self.demangle_decl_name(depth + 1)?;
        let proto = self.create(Kind::Protocol)?;
        self.add(proto, context);
        self.add(proto, name);
        self.subs.push(proto);
        Some(proto)
    }

    fn demangle_protocol_name_impl(&mut self, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        if self.next_if(b'S') {
            let sub = self.demangle_substitution_index()?;
            return match self.kind(sub) {
                Kind::Protocol => Some(sub),
                Kind::Module => self.demangle_protocol_name_given_context(sub, depth + 1),
                _ => None,
            };
        }
        if self.next_if(b's') {
            let stdlib = self.create_text(Kind::Module, STDLIB_NAME)?;
            return self.demangle_protocol_name_given_context(stdlib, depth + 1);
        }
        self.demangle_declaration_name(Kind::Protocol, depth + 1)
    }

    fn demangle_nominal_type(&mut self, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        let kind = match self.peek() {
            b'S' => {
                self.pos += 1;
                return self.demangle_substitution_index();
            }
            b'V' => Kind::Structure,
            b'O' => Kind::Enum,
            b'C' => Kind::Class,
            b'P' => Kind::Protocol,
            _ => return None,
        };
        self.pos += 1;
        self.demangle_declaration_name(kind, depth + 1)
    }

    fn demangle_bound_generic_args(&mut self, mut nominal_type: NodeId, depth: u32) -> N {
        if self.too_deep(depth) || self.tree.num_children(nominal_type) == 0 {
            return None;
        }
        let parent_or_module = self.tree.child(nominal_type, 0)?;
        if !matches!(
            self.kind(parent_or_module),
            Kind::Module | Kind::Function | Kind::Extension
        ) {
            let parent = self.demangle_bound_generic_args(parent_or_module, depth + 1)?;
            let result = self.create(self.kind(nominal_type))?;
            self.add(result, parent);
            let rest: Vec<NodeId> = self.tree.children(nominal_type)[1..].to_vec();
            for c in rest {
                self.add(result, c);
            }
            nominal_type = result;
        }
        let args = self.create(Kind::TypeList)?;
        while !self.next_if(b'_') {
            let t = self.demangle_type(depth + 1)?;
            self.add(args, t);
            if self.is_empty() {
                return None;
            }
        }
        if self.tree.num_children(args) == 0 {
            return Some(nominal_type);
        }
        let unbound = self.create(Kind::Type)?;
        self.add(unbound, nominal_type);
        let kind = match self.kind(nominal_type) {
            Kind::Class => Kind::BoundGenericClass,
            Kind::Structure => Kind::BoundGenericStructure,
            Kind::Enum => Kind::BoundGenericEnum,
            _ => return None,
        };
        let result = self.create(kind)?;
        self.add(result, unbound);
        self.add(result, args);
        Some(result)
    }

    fn demangle_bound_generic_type(&mut self, depth: u32) -> N {
        let nominal = self.demangle_nominal_type(depth + 1)?;
        self.demangle_bound_generic_args(nominal, depth + 1)
    }

    fn demangle_context(&mut self, depth: u32) -> N {
        if self.too_deep(depth) || self.is_empty() {
            return None;
        }
        if self.next_if(b'E') {
            let ext = self.create(Kind::Extension)?;
            let def_module = self.demangle_module(depth + 1)?;
            let ty = self.demangle_context(depth + 1)?;
            self.add(ext, def_module);
            self.add(ext, ty);
            return Some(ext);
        }
        if self.next_if(b'e') {
            let ext = self.create(Kind::Extension)?;
            let def_module = self.demangle_module(depth + 1)?;
            let sig = self.demangle_generic_signature(depth + 1, false)?;
            let ty = self.demangle_context(depth + 1)?;
            self.add(ext, def_module);
            self.add(ext, ty);
            self.add(ext, sig);
            return Some(ext);
        }
        if self.next_if(b'S') {
            return self.demangle_substitution_index();
        }
        if self.next_if(b's') {
            return self.create_text(Kind::Module, STDLIB_NAME);
        }
        if self.next_if(b'G') {
            return self.demangle_bound_generic_type(depth + 1);
        }
        if is_start_of_entity(self.peek()) {
            return self.demangle_entity(depth + 1);
        }
        self.demangle_module(depth + 1)
    }

    fn demangle_protocol_list(&mut self, depth: u32) -> N {
        let proto_list = self.create(Kind::ProtocolList)?;
        let type_list = self.create(Kind::TypeList)?;
        self.add(proto_list, type_list);
        while !self.next_if(b'_') {
            let p = self.demangle_protocol_name(depth + 1)?;
            self.add(type_list, p);
        }
        Some(proto_list)
    }

    fn demangle_protocol_conformance(&mut self, depth: u32) -> N {
        let ty = self.demangle_type(depth + 1)?;
        let protocol = self.demangle_protocol_name(depth + 1)?;
        let context = self.demangle_context(depth + 1)?;
        let c = self.create(Kind::ProtocolConformance)?;
        self.add(c, ty);
        self.add(c, protocol);
        self.add(c, context);
        Some(c)
    }

    fn demangle_entity(&mut self, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        let is_static = self.next_if(b'Z');
        let basic = match self.peek() {
            b'F' => Kind::Function,
            b'v' => Kind::Variable,
            b'I' => Kind::Initializer,
            b'i' => Kind::Subscript,
            _ => return self.demangle_nominal_type(depth + 1),
        };
        self.pos += 1;
        let context = self.demangle_context(depth + 1)?;
        let mut has_type = true;
        let mut wrap_entity = false;
        let mut name = None;
        let c = self.peek();
        let consumed = !self.is_empty();
        self.pos += usize::from(consumed);
        let entity_kind = match c {
            b'D' => {
                has_type = false;
                Kind::Deallocator
            }
            b'Z' => {
                has_type = false;
                Kind::IsolatedDeallocator
            }
            b'd' => {
                has_type = false;
                Kind::Destructor
            }
            b'e' => {
                has_type = false;
                Kind::IVarInitializer
            }
            b'E' => {
                has_type = false;
                Kind::IVarDestroyer
            }
            b'C' => Kind::Allocator,
            b'c' => Kind::Constructor,
            b'a' | b'l' => {
                wrap_entity = true;
                let mutable = c == b'a';
                let k = match (self.next(), mutable) {
                    (b'O', true) => Kind::OwningMutableAddressor,
                    (b'o', true) => Kind::NativeOwningMutableAddressor,
                    (b'p', true) => Kind::NativePinningMutableAddressor,
                    (b'u', true) => Kind::UnsafeMutableAddressor,
                    (b'O', false) => Kind::OwningAddressor,
                    (b'o', false) => Kind::NativeOwningAddressor,
                    (b'p', false) => Kind::NativePinningAddressor,
                    (b'u', false) => Kind::UnsafeAddressor,
                    _ => return None,
                };
                name = Some(self.demangle_decl_name(depth + 1)?);
                k
            }
            b'g' | b'G' | b's' | b'm' | b'w' | b'W' | b'r' | b'M' => {
                wrap_entity = true;
                name = Some(self.demangle_decl_name(depth + 1)?);
                match c {
                    b'g' => Kind::Getter,
                    b'G' => Kind::GlobalGetter,
                    b's' => Kind::Setter,
                    b'm' => Kind::MaterializeForSet,
                    b'w' => Kind::WillSet,
                    b'W' => Kind::DidSet,
                    b'r' => Kind::ReadAccessor,
                    _ => Kind::ModifyAccessor,
                }
            }
            b'U' => {
                name = Some(self.demangle_index_as_node(Kind::Number)?);
                Kind::ExplicitClosure
            }
            b'u' => {
                name = Some(self.demangle_index_as_node(Kind::Number)?);
                Kind::ImplicitClosure
            }
            _ if basic == Kind::Initializer => {
                has_type = false;
                match c {
                    b'A' => {
                        name = Some(self.demangle_index_as_node(Kind::Number)?);
                        Kind::DefaultArgumentInitializer
                    }
                    b'i' => Kind::Initializer,
                    _ => return None,
                }
            }
            _ => {
                // (Not one of the above: put it back.)
                if consumed {
                    self.pos -= 1;
                }
                name = Some(self.demangle_decl_name(depth + 1)?);
                basic
            }
        };
        let entity = self.create(entity_kind)?;
        if wrap_entity {
            let mut name = name;
            let mut is_subscript = false;
            if let Some(nm) = name {
                match self.kind(nm) {
                    Kind::Identifier => {
                        if self.tree.text(nm) == "subscript" {
                            is_subscript = true;
                            name = None;
                        }
                    }
                    Kind::PrivateDeclName if self.tree.num_children(nm) > 1 => {
                        let c1 = self.tree.child(nm, 1)?;
                        if self.tree.text(c1) == "subscript" {
                            is_subscript = true;
                            let discriminator = self.tree.child(nm, 0)?;
                            let p = self.create(Kind::PrivateDeclName)?;
                            self.add(p, discriminator);
                            name = Some(p);
                        }
                    }
                    _ => {}
                }
            }
            let wrapped = self.create(if is_subscript {
                Kind::Subscript
            } else {
                Kind::Variable
            })?;
            self.add(wrapped, context);
            if !is_subscript && let Some(nm) = name {
                self.add(wrapped, nm);
            }
            if has_type {
                let t = self.demangle_type(depth + 1)?;
                self.add(wrapped, t);
            }
            if is_subscript && let Some(nm) = name {
                self.add(wrapped, nm);
            }
            self.add(entity, wrapped);
        } else {
            self.add(entity, context);
            if let Some(nm) = name {
                self.add(entity, nm);
            }
            if has_type {
                let t = self.demangle_type(depth + 1)?;
                self.add(entity, t);
            }
        }
        if is_static {
            let s = self.create(Kind::Static)?;
            self.add(s, entity);
            return Some(s);
        }
        Some(entity)
    }

    fn get_dependent_generic_param_type(&mut self, depth: u64, index: u64) -> N {
        // (`unsigned`s in Swift.)
        let param = self.create(Kind::DependentGenericParamType)?;
        let d = self.create_index(Kind::Index, u64::from(depth as u32))?;
        self.add(param, d);
        let i = self.create_index(Kind::Index, u64::from(index as u32))?;
        self.add(param, i);
        Some(param)
    }

    fn demangle_generic_param_index(&mut self) -> N {
        let (depth, index) = if self.next_if(b'd') {
            let d = self.demangle_index()?.wrapping_add(1);
            let i = self.demangle_index()?;
            (d, i)
        } else if self.next_if(b'x') {
            (0, 0)
        } else {
            (0, self.demangle_index()?.wrapping_add(1))
        };
        self.get_dependent_generic_param_type(depth, index)
    }

    fn demangle_dependent_member_type_name(&mut self, base: NodeId, depth: u32) -> N {
        let assoc_ty = if self.next_if(b'S') {
            let a = self.demangle_substitution_index()?;
            if self.kind(a) != Kind::DependentAssociatedTypeRef {
                return None;
            }
            a
        } else {
            let mut protocol = None;
            if self.next_if(b'P') {
                protocol = Some(self.demangle_protocol_name(depth + 1)?);
            }
            let id = self.demangle_identifier(depth + 1, None)?;
            let a = self.create(Kind::DependentAssociatedTypeRef)?;
            self.add(a, id);
            if let Some(p) = protocol {
                self.add(a, p);
            }
            self.subs.push(a);
            a
        };
        let dep = self.create(Kind::DependentMemberType)?;
        self.add(dep, base);
        self.add(dep, assoc_ty);
        Some(dep)
    }

    fn demangle_associated_type_simple(&mut self, depth: u32) -> N {
        let base = self.demangle_generic_param_index()?;
        let ty = self.create(Kind::Type)?;
        self.add(ty, base);
        self.demangle_dependent_member_type_name(ty, depth + 1)
    }

    fn demangle_associated_type_compound(&mut self, depth: u32) -> N {
        let mut base = self.demangle_generic_param_index()?;
        while !self.next_if(b'_') {
            let ty = self.create(Kind::Type)?;
            self.add(ty, base);
            base = self.demangle_dependent_member_type_name(ty, depth + 1)?;
        }
        Some(base)
    }

    fn demangle_dependent_type(&mut self, depth: u32) -> N {
        if self.is_empty() {
            return None;
        }
        let c = self.peek();
        if c != b'd' && c != b'_' && !c.is_ascii_digit() {
            let base = self.demangle_type(depth + 1)?;
            return self.demangle_dependent_member_type_name(base, depth + 1);
        }
        self.demangle_generic_param_index()
    }

    fn demangle_constrained_type(&mut self, depth: u32) -> N {
        let t = if self.next_if(b'w') {
            self.demangle_associated_type_simple(depth + 1)
        } else if self.next_if(b'W') {
            self.demangle_associated_type_compound(depth + 1)
        } else {
            self.demangle_generic_param_index()
        }?;
        let ty = self.create(Kind::Type)?;
        self.add(ty, t);
        Some(ty)
    }

    fn demangle_generic_signature(&mut self, depth: u32, is_pseudogeneric: bool) -> N {
        let sig = self.create(if is_pseudogeneric {
            Kind::DependentPseudogenericSignature
        } else {
            Kind::DependentGenericSignature
        })?;
        let mut count = u64::MAX;
        while self.peek() != b'R' && self.peek() != b'r' {
            if self.next_if(b'z') {
                count = 0;
            } else {
                count = self.demangle_index()?.wrapping_add(1);
            }
            let c = self.create_index(Kind::DependentGenericParamCount, count)?;
            self.add(sig, c);
        }
        if count == u64::MAX {
            let c = self.create_index(Kind::DependentGenericParamCount, 1)?;
            self.add(sig, c);
        }
        if self.next_if(b'r') {
            return Some(sig);
        }
        if !self.next_if(b'R') {
            return None;
        }
        while !self.next_if(b'r') {
            let r = self.demangle_generic_requirement(depth + 1)?;
            self.add(sig, r);
        }
        Some(sig)
    }

    fn demangle_metatype_representation(&mut self) -> N {
        let t = match self.peek() {
            b't' => "@thin",
            b'T' => "@thick",
            b'o' => "@objc_metatype",
            _ => return None,
        };
        self.pos += 1;
        self.create_text(Kind::MetatypeRepresentation, t)
    }

    fn demangle_generic_requirement(&mut self, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        let constrained = self.demangle_constrained_type(depth + 1)?;
        if self.next_if(b'z') {
            let second = self.demangle_type(depth + 1)?;
            let r = self.create(Kind::DependentGenericSameTypeRequirement)?;
            self.add(r, constrained);
            self.add(r, second);
            return Some(r);
        }
        if self.next_if(b'l') {
            // (`SIZE_MAX` is "none" in Swift.)
            const NONE: u64 = u64::MAX;
            let mut size = NONE;
            let mut alignment = NONE;
            let c = self.next();
            let name = match c {
                b'U' | b'R' | b'N' | b'T' | b'B' => c,
                b'E' | b'M' => {
                    size = self.demangle_natural()?;
                    if !self.next_if(b'_') {
                        return None;
                    }
                    alignment = self.demangle_natural()?;
                    c
                }
                b'e' | b'm' | b'S' => {
                    size = self.demangle_natural()?;
                    c
                }
                _ => return None,
            };
            let second = self.create_bytes(Kind::Identifier, &[name])?;
            let r = self.create(Kind::DependentGenericLayoutRequirement)?;
            self.add(r, constrained);
            self.add(r, second);
            if size != NONE {
                let s = self.create_index(Kind::Number, size)?;
                self.add(r, s);
                if alignment != NONE {
                    let a = self.create_index(Kind::Number, alignment)?;
                    self.add(r, a);
                }
            }
            return Some(r);
        }
        if self.is_empty() {
            return None;
        }
        let constraint = match self.peek() {
            b'C' => self.demangle_type(depth + 1)?,
            b'S' => {
                self.pos += 1;
                let sub = self.demangle_substitution_index()?;
                let type_name = match self.kind(sub) {
                    Kind::Protocol | Kind::Class => sub,
                    Kind::Module => self.demangle_protocol_name_given_context(sub, depth + 1)?,
                    _ => return None,
                };
                let ty = self.create(Kind::Type)?;
                self.add(ty, type_name);
                ty
            }
            _ => self.demangle_protocol_name(depth + 1)?,
        };
        let r = self.create(Kind::DependentGenericConformanceRequirement)?;
        self.add(r, constrained);
        self.add(r, constraint);
        Some(r)
    }

    fn demangle_archetype_type(&mut self, depth: u32) -> N {
        if self.too_deep(depth) {
            return None;
        }
        let root = if self.next_if(b'Q') {
            self.demangle_archetype_type(depth + 1)?
        } else if self.next_if(b'S') {
            self.demangle_substitution_index()?
        } else if self.next_if(b's') {
            self.create_text(Kind::Module, STDLIB_NAME)?
        } else {
            return None;
        };
        let name = self.demangle_identifier(depth + 1, None)?;
        let assoc = self.create(Kind::AssociatedTypeRef)?;
        self.add(assoc, root);
        self.add(assoc, name);
        self.subs.push(assoc);
        Some(assoc)
    }

    fn demangle_tuple(&mut self, is_v: IsVariadic, depth: u32) -> N {
        let tuple = self.create(Kind::Tuple)?;
        let mut elt = None;
        while !self.next_if(b'_') {
            if self.is_empty() {
                return None;
            }
            let e = self.create(Kind::TupleElement)?;
            elt = Some(e);
            if is_start_of_identifier(self.peek()) {
                let label = self.demangle_identifier(depth + 1, Some(Kind::TupleElementName))?;
                self.add(e, label);
            }
            let t = self.demangle_type(depth + 1)?;
            self.add(e, t);
            self.add(tuple, e);
        }
        if is_v == IsVariadic::Yes
            && let Some(e) = elt
        {
            let marker = self.create(Kind::VariadicMarker)?;
            self.tree.insert_child(e, 0, marker);
        }
        Some(tuple)
    }

    fn post_process_return_type_node(&mut self, out_args: NodeId) -> N {
        let n = self.create(Kind::ReturnType)?;
        self.add(n, out_args);
        Some(n)
    }

    fn demangle_type(&mut self, depth: u32) -> N {
        let t = self.demangle_type_impl(depth)?;
        let ty = self.create(Kind::Type)?;
        self.add(ty, t);
        Some(ty)
    }

    fn demangle_function_type(&mut self, kind: Kind, depth: u32) -> N {
        let mut throws = false;
        let mut concurrent = false;
        let mut is_async = false;
        let mut diff_kind = 0u8;
        let mut global_actor = None;
        if !self.is_empty() {
            throws = self.next_if(b'z');
            concurrent = self.next_if(b'y');
            is_async = self.next_if(b'Z');
            if self.next_if(b'D') {
                let k = self.next();
                if matches!(k, b'f' | b'r' | b'd' | b'l') {
                    diff_kind = k;
                }
            }
            if self.next_if(b'Y') {
                global_actor = Some(self.demangle_type(depth + 1)?);
            }
        }
        let in_args = self.demangle_type(depth + 1)?;
        let out_args = self.demangle_type(depth + 1)?;
        let block = self.create(kind)?;
        if throws {
            let t = self.create(Kind::ThrowsAnnotation)?;
            self.add(block, t);
        }
        if is_async {
            let a = self.create(Kind::AsyncAnnotation)?;
            self.add(block, a);
        }
        if concurrent {
            let c = self.create(Kind::ConcurrentFunctionType)?;
            self.add(block, c);
        }
        if diff_kind != 0 {
            let d = self.create_index(Kind::DifferentiableFunctionType, u64::from(diff_kind))?;
            self.add(block, d);
        }
        if let Some(g) = global_actor {
            let n = self.create(Kind::GlobalActorFunctionType)?;
            self.add(n, g);
            self.add(block, n);
        }
        let in_node = self.create(Kind::ArgumentTuple)?;
        self.add(block, in_node);
        self.add(in_node, in_args);
        let r = self.post_process_return_type_node(out_args)?;
        self.add(block, r);
        Some(block)
    }

    fn builtin(&mut self, name: &str) -> N {
        self.create_text(Kind::BuiltinTypeName, name)
    }

    fn with_type(&mut self, kind: Kind, depth: u32) -> N {
        let t = self.demangle_type(depth + 1)?;
        let n = self.create(kind)?;
        self.add(n, t);
        Some(n)
    }

    fn demangle_type_impl(&mut self, depth: u32) -> N {
        if self.too_deep(depth) || self.is_empty() {
            return None;
        }
        let c = self.next();
        match c {
            b'B' => {
                if self.is_empty() {
                    return None;
                }
                match self.next() {
                    b'b' => return self.builtin("Builtin.BridgeObject"),
                    b'B' => return self.builtin("Builtin.UnsafeValueBuffer"),
                    b'f' => {
                        if let Some(size) = self.demangle_builtin_size() {
                            return self.builtin(&alloc::format!("Builtin.FPIEEE{size}"));
                        }
                    }
                    b'i' => {
                        if let Some(size) = self.demangle_builtin_size() {
                            return self.builtin(&alloc::format!("Builtin.Int{size}"));
                        }
                    }
                    b'v' => {
                        if let Some(elts) = self.demangle_natural() {
                            if !self.next_if(b'B') {
                                return None;
                            }
                            if self.next_if(b'i') {
                                let size = self.demangle_builtin_size()?;
                                return self
                                    .builtin(&alloc::format!("Builtin.Vec{elts}xInt{size}"));
                            }
                            if self.next_if(b'f') {
                                let size = self.demangle_builtin_size()?;
                                return self
                                    .builtin(&alloc::format!("Builtin.Vec{elts}xFPIEEE{size}"));
                            }
                            if self.next_if(b'p') {
                                return self
                                    .builtin(&alloc::format!("Builtin.Vec{elts}xRawPointer"));
                            }
                        }
                    }
                    b'O' => return self.builtin("Builtin.UnknownObject"),
                    b'o' => return self.builtin("Builtin.NativeObject"),
                    b'p' => return self.builtin("Builtin.RawPointer"),
                    b't' => return self.builtin("Builtin.SILToken"),
                    b'w' => return self.builtin("Builtin.Word"),
                    _ => {}
                }
                None
            }
            b'a' => self.demangle_declaration_name(Kind::TypeAlias, depth + 1),
            b'b' => self.demangle_function_type(Kind::ObjCBlock, depth + 1),
            b'c' => self.demangle_function_type(Kind::CFunctionPointer, depth + 1),
            b'D' => self.with_type(Kind::DynamicSelf, depth),
            b'E' => {
                if !self.next_if(b'R') || !self.next_if(b'R') {
                    return None;
                }
                self.create_text(Kind::ErrorType, "")
            }
            b'F' => self.demangle_function_type(Kind::FunctionType, depth + 1),
            b'f' => self.demangle_function_type(Kind::UncurriedFunctionType, depth + 1),
            b'G' => self.demangle_bound_generic_type(depth + 1),
            b'X' => self.demangle_x_type(depth),
            b'K' => self.demangle_function_type(Kind::AutoClosureType, depth + 1),
            b'M' => self.with_type(Kind::Metatype, depth),
            b'P' => {
                if self.next_if(b'M') {
                    return self.with_type(Kind::ExistentialMetatype, depth);
                }
                self.demangle_protocol_list(depth + 1)
            }
            b'Q' => {
                if self.next_if(b'u') {
                    return self.create(Kind::OpaqueReturnType);
                }
                if self.next_if(b'U') {
                    let ordinal = self.demangle_index()?;
                    let r = self.create(Kind::OpaqueReturnType)?;
                    let i = self.create_index(Kind::OpaqueReturnTypeIndex, ordinal)?;
                    self.add(r, i);
                    return Some(r);
                }
                self.demangle_archetype_type(depth + 1)
            }
            b'q' => self.demangle_dependent_type(depth + 1),
            b'x' => self.get_dependent_generic_param_type(0, 0),
            b'w' => self.demangle_associated_type_simple(depth + 1),
            b'W' => self.demangle_associated_type_compound(depth + 1),
            b'R' | b'k' => {
                let n = self.create(if c == b'R' {
                    Kind::InOut
                } else {
                    Kind::NoDerivative
                })?;
                let t = self.demangle_type_impl(depth + 1)?;
                self.add(n, t);
                Some(n)
            }
            b'S' => self.demangle_substitution_index(),
            b'T' => self.demangle_tuple(IsVariadic::No, depth + 1),
            b't' => self.demangle_tuple(IsVariadic::Yes, depth + 1),
            b'u' => {
                let sig = self.demangle_generic_signature(depth + 1, false)?;
                let sub = self.demangle_type(depth + 1)?;
                let n = self.create(Kind::DependentGenericType)?;
                self.add(n, sig);
                self.add(n, sub);
                Some(n)
            }
            _ if is_start_of_nominal_type(c) => {
                self.demangle_declaration_name(nominal_type_marker_to_node_kind(c), depth + 1)
            }
            _ => None,
        }
    }

    /// The types that start with `X` (Swift tests for them in several
    /// places, in this order).
    fn demangle_x_type(&mut self, depth: u32) -> N {
        if self.next_if(b'b') {
            return self.with_type(Kind::SILBoxType, depth);
        }
        if self.next_if(b'B') {
            let mut signature = None;
            if self.next_if(b'G') {
                signature = Some(self.demangle_generic_signature(depth, false)?);
            }
            let layout = self.create(Kind::SILBoxLayout)?;
            while !self.next_if(b'_') {
                let kind = if self.next_if(b'm') {
                    Kind::SILBoxMutableField
                } else if self.next_if(b'i') {
                    Kind::SILBoxImmutableField
                } else {
                    return None;
                };
                let t = self.demangle_type(depth + 1)?;
                let field = self.create(kind)?;
                self.add(field, t);
                self.add(layout, field);
            }
            let mut generic_args = None;
            if signature.is_some() {
                let args = self.create(Kind::TypeList)?;
                while !self.next_if(b'_') {
                    let t = self.demangle_type(depth + 1)?;
                    self.add(args, t);
                }
                generic_args = Some(args);
            }
            let box_type = self.create(Kind::SILBoxTypeWithLayout)?;
            self.add(box_type, layout);
            if let (Some(sig), Some(args)) = (signature, generic_args) {
                self.add(box_type, sig);
                self.add(box_type, args);
            }
            return Some(box_type);
        }
        if self.next_if(b'M') {
            let repr = self.demangle_metatype_representation()?;
            let t = self.demangle_type(depth + 1)?;
            let m = self.create(Kind::Metatype)?;
            self.add(m, repr);
            self.add(m, t);
            return Some(m);
        }
        if self.next_if(b'P') {
            if self.next_if(b'M') {
                let repr = self.demangle_metatype_representation()?;
                let t = self.demangle_type(depth + 1)?;
                let m = self.create(Kind::ExistentialMetatype)?;
                self.add(m, repr);
                self.add(m, t);
                return Some(m);
            }
            return self.demangle_protocol_list(depth + 1);
        }
        if self.next_if(b'f') {
            return self.demangle_function_type(Kind::ThinFunctionType, depth + 1);
        }
        let storage = match self.peek() {
            b'o' => Some(Kind::Unowned),
            b'u' => Some(Kind::Unmanaged),
            b'w' => Some(Kind::Weak),
            _ => None,
        };
        if let Some(kind) = storage {
            self.pos += 1;
            return self.with_type(kind, depth);
        }
        if self.next_if(b'F') {
            return self.demangle_impl_function_type(depth + 1);
        }
        None
    }

    fn demangle_reabstract_signature(&mut self, signature: NodeId, depth: u32) -> Option<()> {
        if self.next_if(b'G') {
            let g = self.demangle_generic_signature(depth + 1, false)?;
            self.add(signature, g);
        }
        let src = self.demangle_type(depth + 1)?;
        self.add(signature, src);
        let dest = self.demangle_type(depth + 1)?;
        self.add(signature, dest);
        Some(())
    }

    fn demangle_impl_function_type(&mut self, depth: u32) -> N {
        let ty = self.create(Kind::ImplFunctionType)?;
        self.demangle_impl_callee_convention(ty)?;
        if self.next_if(b'C') {
            let conv = match self.next() {
                b'b' => "block",
                b'c' => "c",
                b'm' => "method",
                b'O' => "objc_method",
                b'w' => "witness_method",
                _ => return None,
            };
            let attr = self.create(Kind::ImplFunctionConvention)?;
            let name = self.create_text(Kind::ImplFunctionConventionName, conv)?;
            self.add(attr, name);
            self.add(ty, attr);
        }
        if self.next_if(b'h') {
            let a = self.create_text(Kind::ImplFunctionAttribute, "@Sendable")?;
            self.add(ty, a);
        }
        if self.next_if(b'H') {
            let a = self.create_text(Kind::ImplFunctionAttribute, "@async")?;
            self.add(ty, a);
        }
        let generic = if self.next_if(b'G') {
            Some(false)
        } else if self.next_if(b'g') {
            Some(true)
        } else {
            None
        };
        if let Some(pseudo) = generic {
            let g = self.demangle_generic_signature(depth + 1, pseudo)?;
            self.add(ty, g);
        }
        if !self.next_if(b'_') {
            return None;
        }
        while !self.next_if(b'_') {
            let p = self.demangle_impl_parameter_or_result(Kind::ImplParameter, depth + 1)?;
            self.add(ty, p);
        }
        while !self.next_if(b'_') {
            let r = self.demangle_impl_parameter_or_result(Kind::ImplResult, depth + 1)?;
            self.add(ty, r);
        }
        Some(ty)
    }

    /// Swift's `demangleImplConvention`: for the callee (0), a parameter
    /// (1) or a result (2); `None` if there is none.
    fn demangle_impl_convention(&mut self, ctxt: usize) -> Option<&'static str> {
        const TABLE: [(u8, [&str; 3]); 8] = [
            (b'a', ["", "", "@autoreleased"]),
            (b'd', ["@callee_unowned", "@unowned", "@unowned"]),
            (b'D', ["", "", "@unowned_inner_pointer"]),
            (b'g', ["@callee_guaranteed", "@guaranteed", ""]),
            (b'e', ["", "@deallocating", ""]),
            (b'i', ["", "@in", "@out"]),
            (b'l', ["", "@inout", ""]),
            (b'o', ["@callee_owned", "@owned", "@owned"]),
        ];
        if self.is_empty() {
            return None;
        }
        let c = self.peek();
        let (_, names) = TABLE.iter().find(|(m, _)| *m == c)?;
        self.pos += 1;
        let name = names[ctxt];
        (!name.is_empty()).then_some(name)
    }

    fn demangle_impl_callee_convention(&mut self, ty: NodeId) -> Option<()> {
        let attr = if self.next_if(b't') {
            "@convention(thin)"
        } else {
            self.demangle_impl_convention(0)?
        };
        let c = self.create_text(Kind::ImplConvention, attr)?;
        self.add(ty, c);
        Some(())
    }

    fn demangle_impl_parameter_or_result(&mut self, mut kind: Kind, depth: u32) -> N {
        if self.next_if(b'z') {
            if kind != Kind::ImplResult {
                return None;
            }
            kind = Kind::ImplErrorResult;
        }
        let ctxt = if kind == Kind::ImplParameter { 1 } else { 2 };
        let convention = self.demangle_impl_convention(ctxt)?;
        let t = self.demangle_type(depth + 1)?;
        let n = self.create(kind)?;
        let c = self.create_text(Kind::ImplConvention, convention)?;
        self.add(n, c);
        self.add(n, t);
        Some(n)
    }
}

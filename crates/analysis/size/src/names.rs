//! Naming types and functions as SizeBench does.
//!
//! SizeBench names a function `Parent::name(argument types) const`, and
//! spells types its own way: `int64` rather than `__int64`, `WCHAR` for
//! `wchar_t`, `enum E`, and a function type as `R (*function)(args)` (so a
//! pointer to one is `R (*function)(args)*`). Its qualified-name prefix is
//! the debug information's, so the name is the recorded name plus the
//! signature.

use std::collections::HashMap;

use hexcavator_debuginfo::{BasicType, DebugInfo, PointerKind, Qualifiers, TypeRef, TypeShape};

/// Bounds the nesting of type references followed (types are untrusted).
const MAX_DEPTH: u32 = 64;
/// The longest type name made.
const MAX_NAME: usize = 4096;

/// What a function type contributes to a function's name: its class (for
/// member functions), and `(args) const`.
struct Signature {
    class: Option<String>,
    suffix: String,
}

/// Names types and function signatures, caching names by type.
pub struct Namer<'d, 'data> {
    debug: &'d DebugInfo<'data>,
    cache: HashMap<TypeRef, String>,
    signatures: HashMap<TypeRef, Signature>,
}

impl<'d, 'data> Namer<'d, 'data> {
    pub fn new(debug: &'d DebugInfo<'data>) -> Self {
        Self {
            debug,
            cache: HashMap::new(),
            signatures: HashMap::new(),
        }
    }

    /// `name` with the argument types and qualifiers of function type
    /// `ty`: `name(int, const char*) const`. If `ty` is not a function
    /// type, `name()`.
    pub fn function(&mut self, name: &str, ty: TypeRef) -> String {
        // DIA leaves `__ptr64` out of names, and so SizeBench's.
        let name = strip_ptr64(name);
        if !self.signatures.contains_key(&ty) {
            let signature = self.signature(ty);
            self.signatures.insert(ty, signature);
        }
        let signature = &self.signatures[&ty];
        let mut out = String::with_capacity(name.len() + signature.suffix.len() + 8);
        // A member function is named `Class::name`: the class's name (an
        // enum's, for a Rust method, is `enum E`), then the name without
        // the class's prefix. When the recorded name doesn't start with
        // the class's name (local classes, lambdas), it is kept whole.
        match &signature.class {
            Some(class) if !class.is_empty() => {
                let rest = name
                    .strip_prefix(class.as_str())
                    .and_then(|r| r.strip_prefix("::"))
                    .unwrap_or(&name);
                out.push_str(class);
                out.push_str("::");
                out.push_str(rest);
            }
            _ => out.push_str(&name),
        }
        out.push_str(&signature.suffix);
        out
    }

    /// The function `name` of type `ty` as SizeBench writes it in full:
    /// `[static ]Ret Class::name(Type arg, ...) const`, where an argument
    /// is named if the parameter at its position (of `params`) has its
    /// type. (SizeBench also writes `virtual`, `override`, and `final`;
    /// these are not, yet.)
    pub fn qualified_function(
        &mut self,
        name: &str,
        ty: TypeRef,
        params: &[(String, TypeRef)],
    ) -> String {
        let TypeShape::Function {
            ret,
            args,
            class,
            this_qualifiers,
        } = self.debug.type_shape(ty)
        else {
            return self.function(name, ty);
        };
        let short = self.function(name, ty);
        let mut out = String::new();
        if class.is_some() && this_qualifiers.is_none() {
            out.push_str("static ");
        }
        out.push_str(&self.type_name(ret));
        out.push(' ');
        if params.is_empty() {
            out.push_str(&short);
            return out;
        }
        // `short` is `prefix(args)suffix`: rebuild the argument list with
        // names.
        let open = short.len() - self.signatures[&ty].suffix.len();
        out.push_str(&short[..open]);
        out.push('(');
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&self.type_name(*a));
            if let Some((n, t)) = params.get(i)
                && t == a
            {
                out.push(' ');
                out.push_str(n);
            }
        }
        out.push(')');
        let suffix = &self.signatures[&ty].suffix;
        let close = suffix.rfind(')').map_or(suffix.len(), |c| c + 1);
        out.push_str(&suffix[close..]);
        out
    }

    /// `(argument types) const` of function type `ty` (`()` if `ty` is not
    /// a function type).
    pub fn signature_suffix(&mut self, ty: TypeRef) -> String {
        if !self.signatures.contains_key(&ty) {
            let signature = self.signature(ty);
            self.signatures.insert(ty, signature);
        }
        self.signatures[&ty].suffix.clone()
    }

    fn signature(&mut self, ty: TypeRef) -> Signature {
        let TypeShape::Function {
            args,
            class,
            this_qualifiers,
            ..
        } = self.debug.type_shape(ty)
        else {
            return Signature {
                class: None,
                suffix: "()".into(),
            };
        };
        let mut suffix = String::from("(");
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                suffix.push_str(", ");
            }
            suffix.push_str(&self.type_name(*a));
        }
        suffix.push(')');
        if let Some(q) = this_qualifiers {
            if q.is_const {
                suffix.push_str(" const");
            }
            if q.is_volatile {
                suffix.push_str(" volatile");
            }
        }
        Signature {
            class: class.map(|c| self.type_name(c)),
            suffix,
        }
    }

    /// The name of type `ty`.
    pub fn type_name(&mut self, ty: TypeRef) -> String {
        self.name_at(ty, 0)
    }

    fn name_at(&mut self, ty: TypeRef, depth: u32) -> String {
        if let Some(n) = self.cache.get(&ty) {
            return n.clone();
        }
        if depth > MAX_DEPTH {
            return "...".into();
        }
        let shape = self.debug.type_shape(ty);
        let mut name = self.shape_name(&shape, depth);
        // (A function type whose parameters are a function type whose ...
        // would double in length at each level: names stop.)
        if name.len() > MAX_NAME {
            let mut end = MAX_NAME;
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name.truncate(end);
            name.push_str("...");
        }
        self.cache.insert(ty, name.clone());
        name
    }

    fn shape_name(&mut self, shape: &TypeShape, depth: u32) -> String {
        match shape {
            TypeShape::Basic { kind, size } => basic_name(*kind, *size),
            TypeShape::Pointer {
                target,
                kind,
                qualifiers,
                ..
            } => {
                let mut out = self.name_at(*target, depth + 1);
                // SizeBench spells rvalue references (and pointers to
                // members) as pointers.
                out.push(if *kind == PointerKind::LValueReference {
                    '&'
                } else {
                    '*'
                });
                suffix_qualifiers(&mut out, *qualifiers);
                out
            }
            TypeShape::Modified { base, qualifiers } => {
                let mut out = String::new();
                prefix_qualifiers(&mut out, *qualifiers);
                out.push_str(&self.name_at(*base, depth + 1));
                out
            }
            TypeShape::Udt { name } => name.clone(),
            TypeShape::Enum { name } => format!("enum {name}"),
            TypeShape::Array { .. } => self.array_name(shape, depth),
            TypeShape::Function {
                ret,
                args,
                this_qualifiers,
                ..
            } => {
                let mut out = self.name_at(*ret, depth + 1);
                out.push_str(" (*function)(");
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&self.name_at(*a, depth + 1));
                }
                out.push(')');
                if let Some(q) = this_qualifiers {
                    if q.is_const {
                        out.push_str(" const");
                    }
                    if q.is_volatile {
                        out.push_str(" volatile");
                    }
                    if q.is_unaligned {
                        out.push_str(" __unaligned");
                    }
                }
                out
            }
            // (Shapes other debug formats will add: unknown here.)
            _ => "<unknown type>".into(),
        }
    }

    /// `element[n][m]...`: the innermost element's name, then each
    /// dimension, outermost first.
    fn array_name(&mut self, shape: &TypeShape, depth: u32) -> String {
        let mut dims = Vec::new();
        let mut current = shape.clone();
        let mut element_name = String::new();
        for _ in 0..MAX_DEPTH {
            let TypeShape::Array { element, size } = current else {
                break;
            };
            let element_size = self.debug.type_size(element).unwrap_or(0);
            dims.push(size.checked_div(element_size).unwrap_or(size));
            current = self.debug.type_shape(element);
            if !matches!(current, TypeShape::Array { .. }) {
                element_name = self.name_at(element, depth + 1);
            }
        }
        let mut out = element_name;
        for d in dims {
            out.push_str(&format!("[{d}]"));
        }
        out
    }
}

/// `name` without its ` __ptr64` qualifiers.
pub fn strip_ptr64(name: &str) -> std::borrow::Cow<'_, str> {
    if name.contains(" __ptr64") {
        name.replace(" __ptr64", "").into()
    } else {
        name.into()
    }
}

fn prefix_qualifiers(out: &mut String, q: Qualifiers) {
    if q.is_const {
        out.push_str("const ");
    }
    if q.is_volatile {
        out.push_str("volatile ");
    }
    if q.is_unaligned {
        out.push_str("__unaligned ");
    }
    if q.is_restrict {
        out.push_str("__restrict ");
    }
}

fn suffix_qualifiers(out: &mut String, q: Qualifiers) {
    if q.is_const {
        out.push_str(" const");
    }
    if q.is_volatile {
        out.push_str(" volatile");
    }
    if q.is_unaligned {
        out.push_str(" __unaligned");
    }
    if q.is_restrict {
        out.push_str(" __restrict");
    }
}

/// SizeBench's name for a basic type.
pub fn basic_name(kind: BasicType, size: u64) -> String {
    let int = |size: u64| match size {
        1 => "char",
        2 => "short",
        4 => "int",
        8 => "int64",
        16 => "int128",
        _ => "int?",
    };
    match kind {
        BasicType::None => "NoType".into(),
        BasicType::Void => "void".into(),
        BasicType::Char => "char".into(),
        BasicType::WideChar => "WCHAR".into(),
        BasicType::Char8 => "char8_t".into(),
        BasicType::Char16 => "char16_t".into(),
        BasicType::Char32 => "char32_t".into(),
        BasicType::Int => int(size).into(),
        BasicType::UInt => format!("unsigned {}", int(size)),
        BasicType::Long => "long".into(),
        BasicType::ULong => "unsigned long".into(),
        BasicType::Bool => "bool".into(),
        BasicType::HResult => "HRESULT".into(),
        BasicType::Float => match size {
            2 => "_Float16",
            4 => "float",
            8 => "double",
            10 => "__float80",
            16 => "__float128",
            _ => "float?",
        }
        .into(),
        // (Basic types other debug formats will add.)
        _ => "<unknown basic type>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_names() {
        assert_eq!(basic_name(BasicType::Int, 4), "int");
        assert_eq!(basic_name(BasicType::UInt, 8), "unsigned int64");
        assert_eq!(basic_name(BasicType::Int, 1), "char");
        assert_eq!(basic_name(BasicType::UInt, 1), "unsigned char");
        assert_eq!(basic_name(BasicType::WideChar, 2), "WCHAR");
        assert_eq!(basic_name(BasicType::ULong, 4), "unsigned long");
        assert_eq!(basic_name(BasicType::Float, 8), "double");
        assert_eq!(basic_name(BasicType::Float, 10), "__float80");
        assert_eq!(basic_name(BasicType::None, 0), "NoType");
        assert_eq!(basic_name(BasicType::Int, 3), "int?");
    }

    #[test]
    fn qualifiers() {
        let q = Qualifiers {
            is_const: true,
            is_volatile: true,
            is_unaligned: false,
            is_restrict: false,
        };
        let mut s = String::new();
        prefix_qualifiers(&mut s, q);
        assert_eq!(s, "const volatile ");
        let mut s = String::from("T*");
        suffix_qualifiers(&mut s, q);
        assert_eq!(s, "T* const volatile");
    }
}

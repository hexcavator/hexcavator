//! Microsoft C++ name undecoration.
//!
//! [`parse_in`] (or [`Demangler::parse`]) turns a decorated name
//! (`?foo@@YAHH@Z`) into a [`Symbol`]: a syntax tree of its qualified name,
//! template arguments, and type, for programs that ask questions of names
//! ("which symbols specialize `template <typename T> void f()`?").
//! [`Symbol::display`] renders the tree exactly as Windows'
//! `UnDecorateSymbolName` (and so dumpbin and `undname`) would;
//! [`demangle`] does both.

mod ast;
mod parse;
mod print;

pub use ast::*;
pub use bumpalo::Bump as Arena;

use alloc::string::String;

/// `UNDNAME_*` flags, for [`Symbol::display`].
pub mod flags {
    pub const COMPLETE: u32 = 0;
    pub const NO_LEADING_UNDERSCORES: u32 = 0x0001;
    pub const NO_MS_KEYWORDS: u32 = 0x0002;
    pub const NO_FUNCTION_RETURNS: u32 = 0x0004;
    pub const NO_ALLOCATION_MODEL: u32 = 0x0008;
    pub const NO_ALLOCATION_LANGUAGE: u32 = 0x0010;
    pub const NO_MS_THISTYPE: u32 = 0x0020;
    pub const NO_CV_THISTYPE: u32 = 0x0040;
    pub const NO_THISTYPE: u32 = 0x0060;
    pub const NO_ACCESS_SPECIFIERS: u32 = 0x0080;
    pub const NO_THROW_SIGNATURES: u32 = 0x0100;
    pub const NO_MEMBER_TYPE: u32 = 0x0200;
    pub const NO_RETURN_UDT_MODEL: u32 = 0x0400;
    pub const DECODE_32_BIT: u32 = 0x0800;
    pub const NAME_ONLY: u32 = 0x1000;
    pub const NO_ARGUMENTS: u32 = 0x2000;
    pub const NO_SPECIAL_SYMS: u32 = 0x4000;
    /// No `class`, `struct`, `union`, or `enum` keywords (undname's
    /// undocumented `UNDNAME_NO_ECSU`).
    pub const NO_ECSU: u32 = 0x8000;
    pub const NO_PTR64: u32 = 0x2_0000;
}

/// Undecorates names, reusing its memory from one name to the next: after
/// the first few names, parsing allocates nothing.
#[derive(Default)]
pub struct Demangler {
    arena: Arena,
    scratch: Option<parse::Scratch<'static>>,
}

impl Demangler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a decorated name, or returns `None` if it is not one (or is
    /// malformed). The result borrows the demangler until the next call.
    pub fn parse<'a>(&'a mut self, name: &'a str) -> Option<Symbol<'a>> {
        self.arena.reset();
        let scratch = self.scratch.take().unwrap_or_default().recycle();
        let (sym, scratch) = parse::parse(&self.arena, name, scratch);
        self.scratch = Some(scratch.recycle());
        sym
    }

    /// Parses only a decorated name's qualified name, not its type: cheaper,
    /// for filtering many names before parsing the interesting ones fully.
    pub fn parse_name<'a>(&'a mut self, name: &'a str) -> Option<QualifiedName<'a>> {
        self.arena.reset();
        let scratch = self.scratch.take().unwrap_or_default().recycle();
        let (q, scratch) = parse::parse_name(&self.arena, name, scratch);
        self.scratch = Some(scratch.recycle());
        q
    }

    /// Undecorates `name` with `flags`, or returns `None` if it is not a
    /// decorated name.
    pub fn demangle(&mut self, name: &str, flags: u32) -> Option<String> {
        let mut out = String::new();
        self.demangle_into(name, flags, &mut out).then_some(out)
    }

    /// Appends `name` undecorated to `out`; returns `false` (appending
    /// nothing) if it is not a decorated name.
    pub fn demangle_into(&mut self, name: &str, flags: u32, out: &mut String) -> bool {
        let start = out.len();
        let printer = print::Printer::new(flags);
        if let Some(s) = self.parse(name) {
            printer.write_symbol(out, &s);
        } else if flags & flags::NAME_ONLY != 0 {
            // Only the name is wanted: the type need not make sense.
            let Some(q) = self.parse_name(name) else {
                return false;
            };
            printer.write_qualified(out, &q, None);
        } else {
            return false;
        }
        collapse_spaces(out, start);
        true
    }
}

/// Parses `name` into `arena`, where the tree lives as long as the arena
/// is borrowed (to keep many symbols at once).
pub fn parse_in<'a>(arena: &'a Arena, name: &'a str) -> Option<Symbol<'a>> {
    parse::parse(arena, name, parse::Scratch::default()).0
}

/// Undecorates `name` (with a fresh [`Demangler`]; keep one to undecorate
/// many names quickly).
pub fn demangle(name: &str, flags: u32) -> Option<String> {
    Demangler::new().demangle(name, flags)
}

/// Parses `name` with the parser's fast paths off: what the machine alone
/// builds (for testing that the fast paths build the same).
#[doc(hidden)]
pub fn parse_slowly_in<'a>(arena: &'a Arena, name: &'a str) -> Option<Symbol<'a>> {
    parse::parse_slowly(arena, name)
}

/// Where parsing `name` fails, if it does (for testing the parser).
#[doc(hidden)]
pub fn failure_position(name: &str) -> Option<usize> {
    parse::failure_position(name)
}

impl Symbol<'_> {
    /// The symbol as `UnDecorateSymbolName` shows it with `flags`.
    pub fn display(&self, flags: u32) -> String {
        let mut out = print::Printer::new(flags).symbol(self);
        collapse_spaces(&mut out, 0);
        out
    }

    /// [`Self::display`] by the printer's machine alone (for testing that
    /// the recursive printer writes the same).
    #[doc(hidden)]
    pub fn display_by_machine(&self, flags: u32) -> String {
        let mut out = print::Printer::machine(flags).symbol(self);
        collapse_spaces(&mut out, 0);
        out
    }
}

/// Like undname, collapses runs of spaces in `s[start..]`.
fn collapse_spaces(s: &mut String, start: usize) {
    if !s[start..].contains("  ") {
        return;
    }
    let tail: String = s[start..].into();
    s.truncate(start);
    for c in tail.chars() {
        if !(c == ' ' && s.ends_with(' ')) {
            s.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> String {
        demangle(s, flags::COMPLETE).unwrap()
    }

    #[test]
    fn basics() {
        assert_eq!(d("?foo@@YAHH@Z"), "int __cdecl foo(int)");
        assert_eq!(
            d("??0exception@std@@QEAA@AEBQEBD@Z"),
            "public: __cdecl std::exception::exception(char const * __ptr64 const & __ptr64) __ptr64"
        );
        assert_eq!(d("??_7type_info@@6B@"), "const type_info::`vftable'");
        assert_eq!(d("?x@@3PEAHEA"), "int * __ptr64 __ptr64 x");
    }

    /// Deep nesting fails cleanly instead of overflowing the stack.
    #[test]
    fn deep_nesting_is_rejected() {
        let mut name = String::from("?x@@3");
        for _ in 0..100_000 {
            name.push_str("PEA");
        }
        name.push_str("HEA");
        assert!(Demangler::new().parse(&name).is_none());
        // Moderate nesting is fine.
        assert_eq!(
            d("?x@@3PEAPEAPEAHEA"),
            "int * __ptr64 * __ptr64 * __ptr64 __ptr64 x"
        );
    }

    /// Back-references that double the tree at each step are cut off.
    #[test]
    fn exponential_back_references_are_rejected() {
        // Each function pointer type takes the previous one twice.
        let mut name = String::from("?f@@YAXP6AXH@Z");
        for i in 0..9 {
            name.push_str(&alloc::format!("P6AX{i}{i}@Z"));
        }
        // Type 9 is now about 2^10 nodes: a few uses are fine...
        let small = alloc::format!("{name}99@Z");
        assert!(Demangler::new().parse(&small).is_some());
        // ...but thousands of them exceed the budget.
        let mut big = name.clone();
        for _ in 0..10_000 {
            big.push('9');
        }
        big.push_str("@Z");
        assert!(Demangler::new().parse(&big).is_none());
    }

    /// Finding specializations of `template <typename T> void f()`.
    #[test]
    fn query_function_template_specializations() {
        let is_f_of_t = |s: &Symbol| {
            let SymbolKind::Function(func) = &s.kind else {
                return false;
            };
            let [Name::Template { name, args }] = s.name.0 else {
                return false;
            };
            **name == Name::Identifier("f")
                && matches!(args, [TemplateArg::Type(_)])
                && func.signature.returns == Some(Type::Builtin(Builtin::Void))
                && func.signature.params.is_empty()
                && !func.signature.variadic
        };
        let arena = Arena::new();
        let yes = parse_in(&arena, "??$f@H@@YAXXZ").unwrap(); // void f<int>(void)
        let no_args = parse_in(&arena, "??$f@H$00@@YAXXZ").unwrap(); // f<int,1>
        let no_name = parse_in(&arena, "??$g@H@@YAXXZ").unwrap();
        assert!(is_f_of_t(&yes));
        assert!(!is_f_of_t(&no_args));
        assert!(!is_f_of_t(&no_name));
    }
}

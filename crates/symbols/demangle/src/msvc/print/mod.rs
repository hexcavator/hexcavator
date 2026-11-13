//! Syntax tree to `UnDecorateSymbolName`'s text, in two halves that write
//! the same: the original recursive printer (`native.rs`) for the first
//! `NATIVE_DEPTH` levels of nesting, and below that the machine
//! (`machine.rs`), whose recursion is on a stack of its own.

use core::fmt::Write as _;

use core::cell::Cell;

use crate::msvc::ast::*;
use crate::msvc::flags;

mod machine;
mod native;

/// How many levels of nesting the recursive printer writes, on the
/// thread's stack (a constant bound on what that takes).
const NATIVE_DEPTH: u32 = 16;

pub struct Printer {
    pub flags: u32,
    /// The recursive printer's levels so far.
    depth: Cell<u32>,
    /// How many there may be ([`NATIVE_DEPTH`], or 0 to test the machine).
    native_depth: u32,
}

fn cv_text(cv: Cv) -> &'static str {
    match (cv.is_const, cv.is_volatile) {
        (false, false) => "",
        (true, false) => "const",
        (false, true) => "volatile",
        (true, true) => "const volatile",
    }
}

fn builtin(b: Builtin) -> &'static str {
    use Builtin::*;
    match b {
        Void => "void",
        SignedChar => "signed char",
        Char => "char",
        UnsignedChar => "unsigned char",
        Short => "short",
        UnsignedShort => "unsigned short",
        Int => "int",
        UnsignedInt => "unsigned int",
        Long => "long",
        UnsignedLong => "unsigned long",
        Float => "float",
        Double => "double",
        LongDouble => "long double",
        Int8 => "__int8",
        UnsignedInt8 => "unsigned __int8",
        Int16 => "__int16",
        UnsignedInt16 => "unsigned __int16",
        Int32 => "__int32",
        UnsignedInt32 => "unsigned __int32",
        Int64 => "__int64",
        UnsignedInt64 => "unsigned __int64",
        Int128 => "__int128",
        UnsignedInt128 => "unsigned __int128",
        Bool => "bool",
        Char8 => "char8_t",
        Char16 => "char16_t",
        Char32 => "char32_t",
        WChar => "wchar_t",
        Nullptr => "std::nullptr_t",
        Auto => "auto",
        DecltypeAuto => "decltype(auto)",
    }
}

fn indirection(kind: Indirection) -> &'static str {
    match kind {
        Indirection::Pointer => "*",
        Indirection::Reference => "&",
        Indirection::RvalueReference => "&&",
        Indirection::Handle => "^",
        Indirection::TrackingReference => "%",
    }
}

impl Printer {
    pub fn new(flags: u32) -> Self {
        Self {
            flags,
            depth: Cell::new(0),
            native_depth: NATIVE_DEPTH,
        }
    }

    /// A printer that writes everything with the machine (for testing).
    pub fn machine(flags: u32) -> Self {
        Self {
            native_depth: 0,
            ..Self::new(flags)
        }
    }

    fn ptr64(&self) -> bool {
        self.flags & (flags::NO_PTR64 | flags::NO_MS_KEYWORDS) == 0
    }

    fn keywords(&self) -> bool {
        self.flags & flags::NO_MS_KEYWORDS == 0
    }

    /// A Microsoft keyword (`__cdecl`, `__ptr64`, ...) as shown: without
    /// its underscores under `NO_LEADING_UNDERSCORES`. (Under
    /// `NO_MS_KEYWORDS` the callers leave it out.)
    fn kw(&self, keyword: &'static str) -> &'static str {
        if self.flags & flags::NO_LEADING_UNDERSCORES != 0 {
            keyword.strip_prefix("__").unwrap_or(keyword)
        } else {
            keyword
        }
    }

    /// Whether class, struct, union, and enum keywords are shown.
    fn ecsu(&self) -> bool {
        self.flags & flags::NO_ECSU == 0 && !self.name_only()
    }

    fn name_only(&self) -> bool {
        self.flags & flags::NAME_ONLY != 0
    }

    fn access(&self, a: Option<Access>) -> &'static str {
        if self.flags & flags::NO_ACCESS_SPECIFIERS != 0 {
            return "";
        }
        match a {
            Some(Access::Private) => "private: ",
            Some(Access::Protected) => "protected: ",
            Some(Access::Public) => "public: ",
            None => "",
        }
    }

    /// A function type's calling convention.
    fn cc(&self, f: &FunctionType<'_>) -> &'static str {
        if self.keywords() {
            self.kw(f.calling_convention)
        } else {
            ""
        }
    }

    /// A declared function's own calling convention, which
    /// `NO_ALLOCATION_LANGUAGE` also leaves out.
    fn decl_cc(&self, f: &FunctionType<'_>) -> &'static str {
        if self.flags & flags::NO_ALLOCATION_LANGUAGE != 0 {
            ""
        } else {
            self.cc(f)
        }
    }

    /// A variable's own qualifiers: cv, then `__ptr64`.
    fn storage(&self, cv: Cv, m: PointerModifiers) -> &'static str {
        let ptr64 = m.ptr64 && self.ptr64();
        let under = self.flags & flags::NO_LEADING_UNDERSCORES == 0;
        match (cv_text(cv), ptr64, under) {
            (s, false, _) => s,
            ("", true, true) => "__ptr64",
            ("", true, false) => "ptr64",
            ("const", true, true) => "const __ptr64",
            ("const", true, false) => "const ptr64",
            ("volatile", true, true) => "volatile __ptr64",
            ("volatile", true, false) => "volatile ptr64",
            (_, true, true) => "const volatile __ptr64",
            (_, true, false) => "const volatile ptr64",
        }
    }
}

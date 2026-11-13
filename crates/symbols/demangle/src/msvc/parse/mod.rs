//! Decorated name to syntax tree. Names come from untrusted files, so the
//! parser mustn't recurse on the thread's stack as deeply as a name nests;
//! but recursion is what parses fastest. So it does both: recursive descent
//! (`descent.rs`) for the first `NATIVE_DEPTH` levels, as nearly every name
//! needs, and below that a machine whose recursion is on a stack of its
//! own (`machine.rs`). Each implements the whole grammar, and a test
//! checks that the machine alone builds the trees they build together.
//! What both use (the input, the tree's allocation, the back-reference
//! tables, the small decoders) is here.

mod descent;
mod machine;

use alloc::vec::Vec;

use bumpalo::Bump as Arena;

use crate::msvc::ast::*;

use machine::{Frame, Goal};

struct Error;

type R<T> = Result<T, Error>;

/// The most productions that may wait at once: the deepest nesting
/// accepted (a level of nesting takes one to a few). Names come from
/// untrusted files; the frames are on a stack of the parser's own, not the
/// thread's.
const MAX_FRAMES: usize = 512;

/// How many levels of nesting are parsed by recursive descent, on the
/// thread's stack (a constant bound on what that takes); the machine
/// parses the rest.
const NATIVE_DEPTH: u32 = 12;

/// The most tree nodes one name may produce. A back-reference copies an
/// earlier type, so a name can describe a tree exponentially larger than
/// itself; this bounds the work and memory.
const MAX_NODES: usize = 1 << 18;

/// Stacks for building lists, kept between names so that parsing does not
/// allocate once they have grown.
#[derive(Default)]
pub struct Scratch<'a> {
    names: Vec<Name<'a>>,
    args: Vec<TemplateArg<'a>>,
    types: Vec<Type<'a>>,
    qualified: Vec<QualifiedName<'a>>,
    ints: Vec<i64>,
    dims: Vec<u64>,
    frames: Vec<Frame<'a>>,
    saved: Vec<(usize, usize)>,
    name_refs: Vec<(Name<'a>, usize)>,
    type_refs: Vec<(Type<'a>, usize)>,
}

/// Reuses `v`'s allocation for a vector of the same type with another
/// lifetime (`collect` reuses it in place, as the layouts match).
fn recycle<T, U>(mut v: Vec<T>) -> Vec<U> {
    v.clear();
    v.into_iter().map(|_| unreachable!()).collect()
}

impl Scratch<'_> {
    pub fn recycle<'b>(self) -> Scratch<'b> {
        Scratch {
            names: recycle(self.names),
            args: recycle(self.args),
            types: recycle(self.types),
            qualified: recycle(self.qualified),
            ints: self.ints,
            dims: self.dims,
            frames: recycle(self.frames),
            saved: self.saved,
            name_refs: recycle(self.name_refs),
            type_refs: recycle(self.type_refs),
        }
    }
}

/// Parses `name` into `arena`. Returns the scratch stacks for reuse.
pub fn parse<'a>(
    arena: &'a Arena,
    name: &'a str,
    scratch: Scratch<'a>,
) -> (Option<Symbol<'a>>, Scratch<'a>) {
    let Some(mut p) = Parser::new(arena, name, scratch) else {
        return (None, Scratch::default());
    };
    let sym = p.r_symbol().ok().filter(|_| p.pos == p.s.len());
    (sym, p.finish())
}

/// Parses `name` with the fast paths off (for testing that they build the
/// same trees as the machine).
pub fn parse_slowly<'a>(arena: &'a Arena, name: &'a str) -> Option<Symbol<'a>> {
    let mut p = Parser::new(arena, name, Scratch::default())?;
    p.native_depth = 0;
    p.r_symbol().ok().filter(|_| p.pos == p.s.len())
}

/// Where parsing fails (for testing).
pub fn failure_position(name: &str) -> Option<usize> {
    let arena = Arena::new();
    let mut p = Parser::new(&arena, name, Scratch::default())?;
    match p.r_symbol() {
        Err(_) => Some(p.pos),
        Ok(_) if p.pos != p.s.len() => Some(p.pos),
        Ok(_) => None,
    }
}

/// Just the qualified name, without the type encoding after it.
pub fn parse_name<'a>(
    arena: &'a Arena,
    name: &'a str,
    scratch: Scratch<'a>,
) -> (Option<QualifiedName<'a>>, Scratch<'a>) {
    let Some(mut p) = Parser::new(arena, name, scratch) else {
        return (None, Scratch::default());
    };
    let q = (|| {
        p.expect(b'?')?;
        if p.peek() == Some(b'?') && p.peek_at(1) == Some(b'@') {
            return Err(Error);
        }
        let (first, _) = p.r_symbol_name()?;
        p.r_qualified_rest(first)
    })();
    (q.ok(), p.finish())
}

/// A back-reference table: up to ten entries (with their sizes in nodes)
/// in each scope (a template name's, say, has its own). The scopes'
/// entries are one stack: a scope sees those from its `base` on, and
/// leaving it drops them, so entering and leaving copy nothing.
struct Refs<T> {
    items: Vec<(T, usize)>,
    base: usize,
}

impl<T: Copy> Refs<T> {
    fn new(mut items: Vec<(T, usize)>) -> Self {
        items.clear();
        Self { items, base: 0 }
    }

    fn push(&mut self, item: T, size: usize) {
        if self.items.len() - self.base < 10 {
            self.items.push((item, size));
        }
    }

    fn get(&self, i: u8) -> Option<(T, usize)> {
        self.items[self.base..].get(usize::from(i)).copied()
    }

    /// Starts an empty scope; returns the one it hides.
    fn enter(&mut self) -> usize {
        core::mem::replace(&mut self.base, self.items.len())
    }

    /// Ends the scope, back to `base` (from [`Self::enter`]).
    fn leave(&mut self, base: usize) {
        self.items.truncate(self.base);
        self.base = base;
    }
}

struct Parser<'a> {
    arena: &'a Arena,
    text: &'a str,
    s: &'a [u8],
    pos: usize,
    /// Name back-references (`0`-`9` in names).
    names: Refs<Name<'a>>,
    /// Type back-references (`0`-`9` in parameter lists).
    types: Refs<Type<'a>>,
    scratch: Scratch<'a>,
    /// Productions waiting for others' values (see [`Parser::run`]).
    frames: Vec<Frame<'a>>,
    /// The scopes [`Parser::isolate`] hides, to be restored by frames.
    saved: Vec<(usize, usize)>,
    /// A symbol or symbol kind just parsed (see [`machine::Value::Symbol`]).
    symbol: Option<Symbol<'a>>,
    kind: Option<SymbolKind<'a>>,
    /// Whether the symbol being read is a variable template, whose name
    /// counts as a back-reference (a function template's does not).
    variable_template: bool,
    /// Nodes built so far (see `MAX_NODES`).
    nodes: usize,
    /// The levels of recursive descent so far.
    depth: u32,
    /// How many there may be ([`NATIVE_DEPTH`], or 0 to test the machine).
    native_depth: u32,
}

/// What kind of name a symbol's first component is, for its encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Special {
    None,
    /// `` `vftable' `` and similar: qualifiers and a list of bases.
    Table,
    /// `` `RTTI Type Descriptor' ``: a type, then `8`.
    TypeDescriptor,
    /// Nothing follows (string literals).
    Literal,
}

const CV_NONE: Cv = Cv {
    is_const: false,
    is_volatile: false,
};

const CV_VOLATILE: Cv = Cv {
    is_const: false,
    is_volatile: true,
};

fn cv(c: u8) -> R<Cv> {
    Ok(match c {
        b'A' => CV_NONE,
        b'B' => Cv {
            is_const: true,
            is_volatile: false,
        },
        b'C' => Cv {
            is_const: false,
            is_volatile: true,
        },
        b'D' => Cv {
            is_const: true,
            is_volatile: true,
        },
        _ => return Err(Error),
    })
}

fn basic(c: u8) -> Option<Builtin> {
    use Builtin::*;
    Some(match c {
        b'C' => SignedChar,
        b'D' => Char,
        b'E' => UnsignedChar,
        b'F' => Short,
        b'G' => UnsignedShort,
        b'H' => Int,
        b'I' => UnsignedInt,
        b'J' => Long,
        b'K' => UnsignedLong,
        b'M' => Float,
        b'N' => Double,
        b'O' => LongDouble,
        b'X' => Void,
        _ => return None,
    })
}

fn extended(c: u8) -> Option<Builtin> {
    use Builtin::*;
    Some(match c {
        b'D' => Int8,
        b'E' => UnsignedInt8,
        b'F' => Int16,
        b'G' => UnsignedInt16,
        b'H' => Int32,
        b'I' => UnsignedInt32,
        b'J' => Int64,
        b'K' => UnsignedInt64,
        b'L' => Int128,
        b'M' => UnsignedInt128,
        b'N' => Bool,
        b'Q' => Char8,
        b'S' => Char16,
        b'U' => Char32,
        b'W' => WChar,
        b'P' => Auto,
        b'T' => DecltypeAuto,
        _ => return None,
    })
}

impl<'a> Parser<'a> {
    fn new(arena: &'a Arena, text: &'a str, mut scratch: Scratch<'a>) -> Option<Self> {
        if !text.starts_with('?') {
            return None;
        }
        let mut frames = core::mem::take(&mut scratch.frames);
        let mut saved = core::mem::take(&mut scratch.saved);
        frames.clear();
        saved.clear();
        let names = Refs::new(core::mem::take(&mut scratch.name_refs));
        let types = Refs::new(core::mem::take(&mut scratch.type_refs));
        Some(Self {
            arena,
            text,
            s: text.as_bytes(),
            pos: 0,
            names,
            types,
            scratch,
            frames,
            saved,
            symbol: None,
            kind: None,
            depth: 0,
            native_depth: NATIVE_DEPTH,
            variable_template: false,
            nodes: 0,
        })
    }

    /// The scratch stacks, for the next name.
    fn finish(self) -> Scratch<'a> {
        let mut scratch = self.scratch;
        scratch.frames = self.frames;
        scratch.saved = self.saved;
        scratch.name_refs = self.names.items;
        scratch.type_refs = self.types.items;
        scratch
    }

    fn alloc<T: Copy>(&self, value: T) -> &'a T {
        self.arena.alloc(value)
    }

    fn alloc_slice<T: Copy>(&self, values: &[T]) -> &'a [T] {
        self.arena.alloc_slice_copy(values)
    }

    fn qualified(&self, cv: Cv, ty: Type<'a>) -> Type<'a> {
        if cv.is_empty() {
            ty
        } else {
            Type::Qualified(cv, self.alloc(ty))
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.s.get(self.pos + n).copied()
    }

    fn next(&mut self) -> R<u8> {
        let c = self.peek().ok_or(Error)?;
        self.pos += 1;
        Ok(c)
    }

    fn eat(&mut self, c: u8) -> bool {
        let yes = self.peek() == Some(c);
        self.pos += usize::from(yes);
        yes
    }

    fn eat_str(&mut self, s: &str) -> bool {
        let yes = self.s[self.pos..].starts_with(s.as_bytes());
        if yes {
            self.pos += s.len();
        }
        yes
    }

    fn expect(&mut self, c: u8) -> R<()> {
        if self.eat(c) { Ok(()) } else { Err(Error) }
    }

    /// Counts `n` more nodes.
    fn charge(&mut self, n: usize) -> R<()> {
        self.nodes += n;
        if self.nodes > MAX_NODES {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Remembers a name built since `nodes` was `start_nodes`.
    fn remember_name(&mut self, name: &Name<'a>, start_nodes: usize) {
        self.names.push(*name, self.nodes - start_nodes);
    }

    fn name_ref(&mut self, index: u8) -> R<Name<'a>> {
        let (name, size) = self.names.get(index).ok_or(Error)?;
        self.charge(size)?;
        Ok(name)
    }

    /// Remembers a type that took more than one character to write.
    fn remember_type(&mut self, start: usize, start_nodes: usize, ty: &Type<'a>) {
        if self.pos - start > 1 {
            self.types.push(*ty, self.nodes - start_nodes);
        }
    }

    fn type_ref(&mut self, index: u8) -> R<Type<'a>> {
        let (ty, size) = self.types.get(index).ok_or(Error)?;
        self.charge(size)?;
        Ok(ty)
    }

    /// An encoded number: `0`-`9` for 1-10, or hex digits `A`-`P` ending
    /// in `@`, after an optional `?` for negative.
    fn number(&mut self) -> R<(bool, u64)> {
        let negative = self.eat(b'?');
        let c = self.next()?;
        if c.is_ascii_digit() {
            return Ok((negative, u64::from(c - b'0') + 1));
        }
        let mut value = 0u64;
        let mut c = c;
        while c != b'@' {
            if !(b'A'..=b'P').contains(&c) {
                return Err(Error);
            }
            value = value.wrapping_mul(16) | u64::from(c - b'A');
            c = self.next()?;
        }
        Ok((negative, value))
    }

    /// `n` signed numbers.
    fn ints(&mut self, n: usize) -> R<&'a [i64]> {
        let base = self.scratch.ints.len();
        let mut result = Ok(());
        for _ in 0..n {
            match self.signed() {
                Ok(v) => self.scratch.ints.push(v),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let v = self.alloc_slice(&self.scratch.ints[base..]);
        self.scratch.ints.truncate(base);
        result.map(|()| v)
    }

    fn signed(&mut self) -> R<i64> {
        let (neg, v) = self.number()?;
        let v = v as i64;
        Ok(if neg { v.wrapping_neg() } else { v })
    }

    fn unsigned(&mut self) -> R<u64> {
        Ok(self.number()?.1)
    }

    /// An identifier ending in `@`.
    fn identifier(&mut self) -> R<&'a str> {
        let start = self.pos;
        let len = self.s[start..]
            .iter()
            .position(|&c| c == b'@')
            .ok_or(Error)?;
        self.pos += len + 1;
        self.text.get(start..start + len).ok_or(Error)
    }

    // ---- The machine -----------------------------------------------------
    //
    // The grammar is recursive (a type's pointee is a type, a template
    // argument is a symbol, ...), and names come from untrusted files, so
    // the recursion is kept on a stack of our own rather than the thread's:
    // each production that needs another is a goal, and what it does with
    // the other's value is a frame, pushed while the other is parsed.

    /// Fresh back-reference tables, until [`Self::unhide`].
    fn hide(&mut self) {
        let hidden = (self.names.enter(), self.types.enter());
        self.saved.push(hidden);
    }

    /// The back-reference tables [`Self::hide`] hid.
    fn unhide(&mut self) -> R<()> {
        let (names, types) = self.saved.pop().ok_or(Error)?;
        self.names.leave(names);
        self.types.leave(types);
        Ok(())
    }

    fn rtti(&mut self) -> R<(Name<'a>, Special)> {
        match self.next()? {
            b'0' => Ok((
                Name::Special("`RTTI Type Descriptor'"),
                Special::TypeDescriptor,
            )),
            b'1' => {
                let a = self.signed()?;
                let b = self.signed()?;
                let c = self.signed()?;
                let d = self.unsigned()?;
                Ok((Name::BaseClassDescriptor([a, b, c], d), Special::None))
            }
            b'2' => Ok((Name::Special("`RTTI Base Class Array'"), Special::None)),
            b'3' => Ok((
                Name::Special("`RTTI Class Hierarchy Descriptor'"),
                Special::None,
            )),
            b'4' => Ok((
                Name::Special("`RTTI Complete Object Locator'"),
                Special::Table,
            )),
            _ => Err(Error),
        }
    }

    // ---- Encodings -----------------------------------------------------

    fn modifiers(&mut self) -> PointerModifiers {
        let mut m = PointerModifiers::default();
        loop {
            match self.peek() {
                Some(b'E') => m.ptr64 = true,
                Some(b'F') => m.unaligned = true,
                Some(b'I') => m.restrict = true,
                _ => return m,
            }
            self.pos += 1;
        }
    }

    /// A variable's storage class: modifiers and cv.
    fn storage(&mut self) -> R<(PointerModifiers, Cv)> {
        let m = self.modifiers();
        Ok((m, cv(self.next()?)?))
    }

    fn this_qualifiers(&mut self) -> R<ThisQualifiers> {
        let mut this = ThisQualifiers::default();
        loop {
            match self.peek() {
                Some(b'E') => this.modifiers.ptr64 = true,
                Some(b'F') => this.modifiers.unaligned = true,
                Some(b'I') => this.modifiers.restrict = true,
                Some(b'G') => this.reference = Some(Indirection::Reference),
                Some(b'H') => this.reference = Some(Indirection::RvalueReference),
                // A C++/CLI `this` (a handle): written as usual.
                Some(b'$') if self.peek_at(1) == Some(b'A') => self.pos += 1,
                _ => break,
            }
            self.pos += 1;
        }
        this.cv = cv(self.next()?)?;
        Ok(this)
    }

    fn calling_convention(&mut self) -> R<&'static str> {
        Ok(match self.next()? {
            b'A' | b'B' => "__cdecl",
            b'C' | b'D' => "__pascal",
            b'E' | b'F' => "__thiscall",
            b'G' | b'H' => "__stdcall",
            b'I' | b'J' => "__fastcall",
            b'M' | b'N' => "__clrcall",
            b'O' | b'P' => "__eabi",
            b'Q' => "__vectorcall",
            b'S' => "__swift_1",
            b'T' => "__swift_2",
            b'W' => "__swift_3",
            _ => return Err(Error),
        })
    }
}

/// The operator `?<c>` names (`?0`, `?1`, `?B` and `?_` aside).
fn operator_name(c: u8) -> Option<&'static str> {
    Some(match c {
        b'2' => "operator new",
        b'3' => "operator delete",
        b'4' => "operator=",
        b'5' => "operator>>",
        b'6' => "operator<<",
        b'7' => "operator!",
        b'8' => "operator==",
        b'9' => "operator!=",
        b'A' => "operator[]",
        b'C' => "operator->",
        b'D' => "operator*",
        b'E' => "operator++",
        b'F' => "operator--",
        b'G' => "operator-",
        b'H' => "operator+",
        b'I' => "operator&",
        b'J' => "operator->*",
        b'K' => "operator/",
        b'L' => "operator%",
        b'M' => "operator<",
        b'N' => "operator<=",
        b'O' => "operator>",
        b'P' => "operator>=",
        b'Q' => "operator,",
        b'R' => "operator()",
        b'S' => "operator~",
        b'T' => "operator^",
        b'U' => "operator|",
        b'V' => "operator&&",
        b'W' => "operator||",
        b'X' => "operator*=",
        b'Y' => "operator+=",
        b'Z' => "operator-=",
        _ => return None,
    })
}

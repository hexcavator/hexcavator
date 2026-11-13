// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Follows the LLVM Project's demangler (see LICENSE-LLVM at the crate root).

//! Rust symbol demangling: the v0 mangling (`_RNvCs1234_5crate4name`, RFC
//! 2603) and the legacy one (`_ZN5crate4name17h0123456789abcdefE`, Itanium
//! in shape).
//!
//! v0 output is exactly what LLVM's `llvm::rustDemangle` (and so
//! `llvm-cxxfilt`) gives, which the tests check against; the grammar and
//! printing rules follow LLVM's `RustDemangle.cpp` (part of the LLVM
//! Project, under the Apache License v2.0 with LLVM Exceptions; see
//! the crate's `LICENSE-LLVM`). Legacy output follows `rustc-demangle`'s
//! alternate form: the path, escapes decoded, without the hash.
//!
//! Both are bounded: nesting is limited, and so is the output (a backref
//! can repeat what it refers to, so a short name can ask for a lot); and
//! the thread's stack holds a bounded number of levels (see
//! `Printer::drive`).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::{self, ManuallyDrop};

/// The deepest nesting of paths, types, and constants.
const MAX_DEPTH: u32 = 500;
/// How many levels of nesting the v0 printer recurses through on the
/// thread's stack (a constant bound on what that takes). Deeper levels:
/// see `Printer::drive`.
const NATIVE_DEPTH: u32 = if cfg!(debug_assertions) { 128 } else { 256 };
/// The most work (output copied) a name nested past [`NATIVE_DEPTH`] may
/// take, beyond the printing itself: this much per byte of the name (and
/// a few times the most output).
const DEEP_WORK_PER_BYTE: usize = 64;
/// The most output one name may produce.
const MAX_OUTPUT: usize = 1 << 20;

/// Whether `name` is a Rust symbol: v0 (`_R`, or `R`/`__R`), or legacy
/// (`_ZN...E` whose last element is the `h` + 16 hex digit hash rustc
/// always adds).
pub fn is_rust(name: &str) -> bool {
    v0_input(name).is_some() || legacy_elements(name).is_some()
}

/// Appends the demangled form of a Rust symbol to `out`; returns `false`
/// (appending nothing) if `name` isn't one.
pub fn demangle_into(name: &str, out: &mut String) -> bool {
    demangle_with_native_depth(name, out, NATIVE_DEPTH)
}

/// [`demangle_into`], recursing at most `levels` levels on the thread's
/// stack (for testing the handling of deeper names: the output is the
/// same, whatever the levels).
#[doc(hidden)]
pub fn demangle_with_native_depth(name: &str, out: &mut String, levels: u32) -> bool {
    let start = out.len();
    let ok = if let Some(input) = v0_input(name) {
        v0(input, out, levels.clamp(1, MAX_DEPTH))
    } else if let Some((elements, suffix)) = legacy_elements(name) {
        legacy(elements, suffix, out)
    } else {
        false
    };
    if !ok || out.len() - start > MAX_OUTPUT {
        out.truncate(start);
        return false;
    }
    true
}

// ---------------------------------------------------------------- legacy

/// The elements of a legacy name (the hash dropped) and what follows its
/// `E` (a `.llvm.` or other suffix), if it is one.
fn legacy_elements(name: &str) -> Option<(alloc::vec::Vec<&str>, &str)> {
    // LLVM's `.llvm.<hash>` (rustc-demangle drops it).
    let name = match name.find(".llvm.") {
        Some(i)
            if name[i + 6..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b) || b == b'@') =>
        {
            &name[..i]
        }
        _ => name,
    };
    let inner = name
        .strip_prefix("_ZN")
        .or_else(|| name.strip_prefix("__ZN"))
        .or_else(|| name.strip_prefix("ZN"))?;
    if !inner.is_ascii() {
        return None;
    }
    let mut elements = alloc::vec::Vec::new();
    let mut rest = inner;
    while !rest.starts_with('E') {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || (digits > 1 && rest.starts_with('0')) {
            return None;
        }
        let len: usize = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let element = rest.get(..len)?;
        rest = &rest[len..];
        elements.push(element);
    }
    let suffix = &rest[1..];
    if !(suffix.is_empty() || suffix.starts_with('.')) {
        return None;
    }
    let hash = elements.pop()?;
    let is_hash = hash.len() == 17
        && hash.starts_with('h')
        && hash[1..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if !is_hash || elements.is_empty() {
        return None;
    }
    Some((elements, suffix))
}

fn legacy(elements: alloc::vec::Vec<&str>, suffix: &str, out: &mut String) -> bool {
    for (i, element) in elements.iter().enumerate() {
        if i > 0 {
            out.push_str("::");
        }
        // `_$` marks an element that starts with an escape: drop the `_`.
        let mut rest = if element.starts_with("_$") {
            &element[1..]
        } else {
            element
        };
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix("..") {
                out.push_str("::");
                rest = after;
            } else if let Some(after) = rest.strip_prefix('.') {
                out.push('.');
                rest = after;
            } else if rest.starts_with('$') {
                let Some(end) = rest[1..].find('$') else {
                    break;
                };
                let escape = &rest[1..=end];
                let c = match escape {
                    "SP" => '@',
                    "BP" => '*',
                    "RF" => '&',
                    "LT" => '<',
                    "GT" => '>',
                    "LP" => '(',
                    "RP" => ')',
                    "C" => ',',
                    _ => {
                        let code = escape
                            .strip_prefix('u')
                            .filter(|d| {
                                d.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            })
                            .and_then(|d| u32::from_str_radix(d, 16).ok())
                            .and_then(char::from_u32)
                            .filter(|c| !c.is_control());
                        match code {
                            Some(c) => c,
                            None => break,
                        }
                    }
                };
                out.push(c);
                rest = &rest[end + 2..];
            } else if let Some(i) = rest.find(['$', '.']) {
                out.push_str(&rest[..i]);
                rest = &rest[i..];
            } else {
                break;
            }
        }
        out.push_str(rest);
    }
    out.push_str(suffix);
    true
}

// -------------------------------------------------------------------- v0

/// A v0 name without its `_R` prefix (Mach-O adds an underscore; `R`
/// alone is allowed too).
fn v0_input(name: &str) -> Option<&str> {
    let rest = name
        .strip_prefix("_R")
        .or_else(|| name.strip_prefix("__R"))
        .or_else(|| name.strip_prefix('R'))?;
    // A path starts with an uppercase tag; `R` alone is too loose otherwise.
    rest.starts_with(|c: char| c.is_ascii_uppercase())
        .then_some(rest)
}

fn v0(mangled: &str, out: &mut String, levels: u32) -> bool {
    let (input, suffix) = match mangled.find('.') {
        Some(i) => (&mangled[..i], Some(&mangled[i..])),
        None => (mangled, None),
    };
    let mut p = Printer {
        input: input.as_bytes(),
        pos: 0,
        out,
        print: true,
        error: false,
        depth: 0,
        limit: levels,
        native_depth: levels,
        deep: ManuallyDrop::new(None),
        bound_lifetimes: 0,
        start: 0,
    };
    p.start = p.out.len();
    p.whole();
    if p.deep.is_some() {
        p.drive();
        // (Dropped here, not with the printer.)
        *p.deep = None;
    }
    if let Some(s) = suffix {
        p.push(" (");
        p.push(s);
        p.push(")");
    }
    !p.error
}

#[derive(Clone, Copy)]
enum Basic {
    Named,
    Placeholder,
    Integer,
    Bool,
    Char,
}

fn basic_type(c: u8) -> Option<(&'static str, Basic)> {
    let name = match c {
        b'a' => "i8",
        b'b' => "bool",
        b'c' => "char",
        b'd' => "f64",
        b'e' => "str",
        b'f' => "f32",
        b'h' => "u8",
        b'i' => "isize",
        b'j' => "usize",
        b'l' => "i32",
        b'm' => "u32",
        b'n' => "i128",
        b'o' => "u128",
        b'p' => "_",
        b's' => "i16",
        b't' => "u16",
        b'u' => "()",
        b'v' => "...",
        b'x' => "i64",
        b'y' => "u64",
        b'z' => "!",
        _ => return None,
    };
    let kind = match c {
        b'a' | b'h' | b'i' | b'j' | b'l' | b'm' | b'n' | b'o' | b's' | b't' | b'x' | b'y' => {
            Basic::Integer
        }
        b'b' => Basic::Bool,
        b'c' => Basic::Char,
        b'p' => Basic::Placeholder,
        _ => Basic::Named,
    };
    Some((name, kind))
}

/// A production called one level deeper (see `Printer::boundary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Goal {
    Path { in_type: bool, leave_open: bool },
    Ty,
    Konst,
}

/// The printer's state but its output: at a call, or at its return.
#[derive(Clone, Copy, Debug)]
struct State {
    pos: usize,
    /// The output's length.
    out: usize,
    print: bool,
    error: bool,
    bound_lifetimes: u64,
}

/// A call past a run's levels, for `Printer::drive` to run.
struct Call {
    goal: Goal,
    entry: State,
    /// The depth it is called from.
    base: u32,
}

/// A call `Printer::drive` has run: what it returned, the printer after
/// it, and what it wrote.
struct Done {
    goal: Goal,
    open: bool,
    exit: State,
    text: String,
}

/// A call `Printer::drive` is running (or the whole name), with the
/// results of the calls past its levels it has made so far.
struct Task {
    goal: Option<Goal>,
    entry: State,
    base: u32,
    depth: u32,
    done: Vec<Done>,
}

/// The printer's state while `Printer::drive` prints a deep name.
#[derive(Default)]
struct Deep {
    /// The depth of this run's level 0.
    base: u32,
    /// The results of this run's calls past its levels, in call order, and
    /// how many it has made.
    done: Vec<Done>,
    done_at: usize,
    /// A call past this run's levels with no result yet: the run is
    /// unwinding (as if in error, which writes nothing).
    pending: Option<Call>,
    /// Work so far (see [`DEEP_WORK_PER_BYTE`]).
    spent: usize,
}

struct Printer<'a, 'o> {
    input: &'a [u8],
    pos: usize,
    out: &'o mut String,
    /// Whether output is wanted (impl paths and the instantiating crate are
    /// parsed but not printed).
    print: bool,
    error: bool,
    /// Levels of nesting of this run (on the thread's stack).
    depth: u32,
    /// How many there may be before a call goes to `Printer::boundary`:
    /// `native_depth`, fewer near [`MAX_DEPTH`], or 0 once a run is
    /// unwinding.
    limit: u32,
    /// [`NATIVE_DEPTH`], or fewer for testing.
    native_depth: u32,
    /// Only while printing a deep name, which takes it back before
    /// returning. (Not dropped with the printer: a field to drop makes
    /// every name slower.)
    deep: ManuallyDrop<Option<Box<Deep>>>,
    bound_lifetimes: u64,
    /// Where this name's output starts in `out`.
    start: usize,
}

impl<'a> Printer<'a, '_> {
    fn push(&mut self, s: &str) {
        if self.error || !self.print {
            return;
        }
        if self.out.len() - self.start + s.len() > MAX_OUTPUT {
            self.error = true;
            return;
        }
        self.out.push_str(s);
    }

    fn push_char(&mut self, c: char) {
        let mut b = [0u8; 4];
        self.push(c.encode_utf8(&mut b));
    }

    fn push_number(&mut self, n: u64) {
        let mut b = [0u8; 20];
        let mut i = b.len();
        let mut n = n;
        loop {
            i -= 1;
            b[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        // ASCII digits.
        self.push(core::str::from_utf8(&b[i..]).unwrap_or("0"));
    }

    fn look(&self) -> u8 {
        if self.error {
            return 0;
        }
        self.input.get(self.pos).copied().unwrap_or(0)
    }

    fn next(&mut self) -> u8 {
        if self.error || self.pos >= self.input.len() {
            self.error = true;
            return 0;
        }
        self.pos += 1;
        self.input[self.pos - 1]
    }

    fn eat(&mut self, c: u8) -> bool {
        if !self.error && self.input.get(self.pos) == Some(&c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// The whole name: its path, and the instantiating crate's.
    fn whole(&mut self) {
        self.path(false, false);
        if self.pos != self.input.len() {
            // The instantiating crate.
            self.print = false;
            self.path(false, false);
            self.print = true;
        }
        if self.pos != self.input.len() {
            self.error = true;
        }
    }

    fn call(&mut self, goal: Goal) -> bool {
        match goal {
            Goal::Path {
                in_type,
                leave_open,
            } => self.path_inner(in_type, leave_open),
            Goal::Ty => {
                self.ty_inner();
                false
            }
            Goal::Konst => {
                self.konst_inner();
                false
            }
        }
    }

    fn state(&self) -> State {
        State {
            pos: self.pos,
            out: self.out.len(),
            print: self.print,
            error: self.error,
            bound_lifetimes: self.bound_lifetimes,
        }
    }

    /// A call past this run's levels: an error past [`MAX_DEPTH`]; what
    /// `Printer::drive` has for it, if it has run it; else the call is
    /// left for it to run, and this run unwinds (as if in error, which
    /// writes nothing more).
    #[cold]
    #[inline(never)]
    fn boundary(&mut self, goal: Goal) -> bool {
        if self.error {
            return false;
        }
        let depth = self.depth;
        let deep = match self.deep.as_deref_mut() {
            Some(deep) if deep.base + depth < MAX_DEPTH => deep,
            None if depth < MAX_DEPTH => {
                self.deep = ManuallyDrop::new(Some(Box::default()));
                let Some(deep) = self.deep.as_deref_mut() else {
                    return false;
                };
                deep
            }
            _ => {
                self.error = true;
                return false;
            }
        };
        if let Some(d) = deep.done.get(deep.done_at) {
            deep.done_at += 1;
            deep.spent += d.text.len() + 1;
            debug_assert_eq!(d.goal, goal);
            self.out.push_str(&d.text);
            self.pos = d.exit.pos;
            self.print = d.exit.print;
            self.error = d.exit.error;
            self.bound_lifetimes = d.exit.bound_lifetimes;
            return d.open;
        }
        let base = deep.base + depth;
        let entry = self.state();
        if let Some(deep) = self.deep.as_deref_mut() {
            deep.pending = Some(Call { goal, entry, base });
        }
        self.limit = 0;
        self.error = true;
        false
    }

    /// Prints a name nested past [`NATIVE_DEPTH`], once a run has left a
    /// call for it (`Printer::boundary`): the thread's stack holds at most
    /// `NATIVE_DEPTH` levels at a time. A call that would go deeper is
    /// instead run here, by itself, from the printer as it was at the
    /// call, and the run that made it is run again from its start.
    /// Printing is deterministic, so that run makes the same calls in the
    /// same order with the same output so far; each time it reaches a call
    /// run here, it takes what the call wrote (and the printer after it)
    /// and goes on, until it reaches a call not yet run (which runs next)
    /// or its end. The output is what printing on the thread's stack alone
    /// would write. The work is bounded ([`DEEP_WORK_PER_BYTE`]).
    #[cold]
    #[inline(never)]
    fn drive(&mut self) {
        let mut tasks = alloc::vec![Task {
            goal: None,
            entry: State {
                pos: 0,
                out: self.start,
                print: true,
                error: false,
                bound_lifetimes: 0,
            },
            base: 0,
            depth: 0,
            done: Vec::new(),
        }];
        let mut open = false;
        // (Output can be far longer than the name: backrefs repeat.)
        let budget = self.input.len() * DEEP_WORK_PER_BYTE + 8 * MAX_OUTPUT;
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
                    goal: Some(call.goal),
                    entry: call.entry,
                    base: call.base,
                    depth: 1,
                    done: Vec::new(),
                });
            } else {
                let Some(task) = tasks.pop() else {
                    return;
                };
                let (Some(goal), Some(parent)) = (task.goal, tasks.last_mut()) else {
                    return;
                };
                let text = String::from(&self.out[task.entry.out..]);
                deep.spent += text.len() + 1;
                parent.done.push(Done {
                    goal,
                    open,
                    exit: self.state(),
                    text,
                });
            }
            let Some(top) = tasks.last_mut() else {
                return;
            };
            let e = top.entry;
            self.out.truncate(e.out);
            self.pos = e.pos;
            self.print = e.print;
            self.error = e.error;
            self.bound_lifetimes = e.bound_lifetimes;
            let Some(deep) = self.deep.as_deref_mut() else {
                return;
            };
            deep.spent += 1;
            if deep.spent > budget {
                self.error = true;
                return;
            }
            deep.base = top.base;
            deep.done = mem::take(&mut top.done);
            deep.done_at = 0;
            self.depth = top.depth;
            self.limit = self.native_depth.min(MAX_DEPTH - top.base);
            open = match top.goal {
                Some(goal) => self.call(goal),
                None => {
                    self.whole();
                    false
                }
            };
            // The run's work: what it read and wrote.
            let work = self.pos.abs_diff(e.pos) + (self.out.len() - e.out);
            if let Some(deep) = self.deep.as_deref_mut() {
                deep.spent += work;
            }
        }
    }

    /// `<path>`. `in_type`: whether `::` before generic arguments is
    /// omitted. `leave_open`: leave generic arguments open (for a `dyn`
    /// trait's associated bindings); returns whether it did.
    fn path(&mut self, in_type: bool, leave_open: bool) -> bool {
        if self.error || self.depth >= self.limit {
            return self.boundary(Goal::Path {
                in_type,
                leave_open,
            });
        }
        self.depth += 1;
        let open = self.path_inner(in_type, leave_open);
        self.depth -= 1;
        open
    }

    fn path_inner(&mut self, in_type: bool, leave_open: bool) -> bool {
        let mut open = false;
        match self.next() {
            b'C' => {
                self.optional_base62(b's');
                let id = self.identifier();
                self.print_identifier(id);
            }
            b'M' => {
                self.impl_path(in_type);
                self.push("<");
                self.ty();
                self.push(">");
            }
            b'X' => {
                self.impl_path(in_type);
                self.push("<");
                self.ty();
                self.push(" as ");
                self.path(true, false);
                self.push(">");
            }
            b'Y' => {
                self.push("<");
                self.ty();
                self.push(" as ");
                self.path(true, false);
                self.push(">");
            }
            b'N' => {
                let ns = self.next();
                if ns.is_ascii_alphabetic() {
                    self.path(in_type, false);
                    let disambiguator = self.optional_base62(b's');
                    let id = self.identifier();
                    if ns.is_ascii_uppercase() {
                        self.push("::{");
                        match ns {
                            b'C' => self.push("closure"),
                            b'S' => self.push("shim"),
                            c => self.push_char(char::from(c)),
                        }
                        if !id.0.is_empty() {
                            self.push(":");
                            self.print_identifier(id);
                        }
                        self.push("#");
                        self.push_number(disambiguator);
                        self.push("}");
                    } else if !id.0.is_empty() {
                        self.push("::");
                        self.print_identifier(id);
                    }
                } else {
                    self.error = true;
                }
            }
            b'I' => {
                self.path(in_type, false);
                if !in_type {
                    self.push("::");
                }
                self.push("<");
                let mut i = 0;
                while !self.error && !self.eat(b'E') {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.generic_arg();
                    i += 1;
                }
                if leave_open {
                    open = true;
                } else {
                    self.push(">");
                }
            }
            b'B' => {
                open = self.backref(|p| p.path(in_type, leave_open));
            }
            _ => self.error = true,
        }
        open
    }

    /// `<impl-path>`: parsed, not printed.
    fn impl_path(&mut self, in_type: bool) {
        let print = core::mem::replace(&mut self.print, false);
        self.optional_base62(b's');
        self.path(in_type, false);
        self.print = print;
    }

    /// `<backref>`: prints what an earlier position gives (when printing).
    fn backref(&mut self, f: impl FnOnce(&mut Self) -> bool) -> bool {
        let target = self.base62();
        if self.error || target >= self.pos as u64 {
            self.error = true;
            return false;
        }
        if !self.print {
            return false;
        }
        let save = self.pos;
        // Less than `pos`, so it fits.
        self.pos = usize::try_from(target).unwrap_or(0);
        let r = f(self);
        self.pos = save;
        r
    }

    fn generic_arg(&mut self) {
        if self.eat(b'L') {
            let n = self.base62();
            self.lifetime(n);
        } else if self.eat(b'K') {
            self.konst();
        } else {
            self.ty();
        }
    }

    fn ty(&mut self) {
        if self.error || self.depth >= self.limit {
            self.boundary(Goal::Ty);
            return;
        }
        self.depth += 1;
        self.ty_inner();
        self.depth -= 1;
    }

    fn ty_inner(&mut self) {
        let start = self.pos;
        let c = self.next();
        if let Some((name, _)) = basic_type(c) {
            self.push(name);
            return;
        }
        match c {
            b'A' => {
                self.push("[");
                self.ty();
                self.push("; ");
                self.konst();
                self.push("]");
            }
            b'S' => {
                self.push("[");
                self.ty();
                self.push("]");
            }
            b'T' => {
                self.push("(");
                let mut i = 0;
                while !self.error && !self.eat(b'E') {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.ty();
                    i += 1;
                }
                if i == 1 {
                    self.push(",");
                }
                self.push(")");
            }
            b'R' | b'Q' => {
                self.push("&");
                if self.eat(b'L') {
                    let n = self.base62();
                    if n != 0 {
                        self.lifetime(n);
                        self.push(" ");
                    }
                }
                if c == b'Q' {
                    self.push("mut ");
                }
                self.ty();
            }
            b'P' => {
                self.push("*const ");
                self.ty();
            }
            b'O' => {
                self.push("*mut ");
                self.ty();
            }
            b'F' => self.fn_sig(),
            b'D' => {
                self.dyn_bounds();
                if self.eat(b'L') {
                    let n = self.base62();
                    if n != 0 {
                        self.push(" + ");
                        self.lifetime(n);
                    }
                } else {
                    self.error = true;
                }
            }
            b'B' => {
                self.backref(|p| {
                    p.ty();
                    false
                });
            }
            _ => {
                self.pos = start;
                self.path(true, false);
            }
        }
    }

    fn fn_sig(&mut self) {
        let saved = self.bound_lifetimes;
        self.binder();
        if self.eat(b'U') {
            self.push("unsafe ");
        }
        if self.eat(b'K') {
            self.push("extern \"");
            if self.eat(b'C') {
                self.push("C");
            } else {
                let (name, punycode) = self.identifier();
                if punycode {
                    self.error = true;
                }
                // `-` in an ABI's name is mangled as `_`.
                for c in name.chars() {
                    self.push_char(if c == '_' { '-' } else { c });
                }
            }
            self.push("\" ");
        }
        self.push("fn(");
        let mut i = 0;
        while !self.error && !self.eat(b'E') {
            if i > 0 {
                self.push(", ");
            }
            self.ty();
            i += 1;
        }
        self.push(")");
        if !self.eat(b'u') {
            self.push(" -> ");
            self.ty();
        }
        self.bound_lifetimes = saved;
    }

    fn dyn_bounds(&mut self) {
        let saved = self.bound_lifetimes;
        self.push("dyn ");
        self.binder();
        let mut i = 0;
        while !self.error && !self.eat(b'E') {
            if i > 0 {
                self.push(" + ");
            }
            self.dyn_trait();
            i += 1;
        }
        self.bound_lifetimes = saved;
    }

    fn dyn_trait(&mut self) {
        let mut open = self.path(true, true);
        while !self.error && self.eat(b'p') {
            if open {
                self.push(", ");
            } else {
                open = true;
                self.push("<");
            }
            let (name, _) = self.identifier();
            self.push(name);
            self.push(" = ");
            self.ty();
        }
        if open {
            self.push(">");
        }
    }

    /// `<binder>`: `for<'a, 'b>`.
    fn binder(&mut self) {
        let n = self.optional_base62(b'G');
        if self.error || n == 0 {
            return;
        }
        // Each bound lifetime is used later, a byte at least each: more than
        // the input can use is malformed (and would print endlessly).
        if n >= (self.input.len() as u64).saturating_sub(self.bound_lifetimes) {
            self.error = true;
            return;
        }
        self.push("for<");
        for i in 0..n {
            self.bound_lifetimes += 1;
            if i > 0 {
                self.push(", ");
            }
            self.lifetime(1);
        }
        self.push("> ");
    }

    fn konst(&mut self) {
        if self.error || self.depth >= self.limit {
            self.boundary(Goal::Konst);
            return;
        }
        self.depth += 1;
        self.konst_inner();
        self.depth -= 1;
    }

    fn konst_inner(&mut self) {
        let c = self.next();
        match basic_type(c) {
            Some((_, Basic::Integer)) => {
                if self.eat(b'n') {
                    self.push("-");
                }
                let (value, digits) = self.hex();
                if digits.len() <= 16 {
                    self.push_number(value);
                } else {
                    self.push("0x");
                    self.push(digits);
                }
            }
            Some((_, Basic::Bool)) => match self.hex().1 {
                "0" => self.push("false"),
                "1" => self.push("true"),
                _ => self.error = true,
            },
            Some((_, Basic::Char)) => {
                let (code, digits) = self.hex();
                if self.error || digits.len() > 6 {
                    self.error = true;
                } else {
                    self.push("'");
                    match code {
                        0x09 => self.push("\\t"),
                        0x0D => self.push("\\r"),
                        0x0A => self.push("\\n"),
                        0x5C => self.push("\\\\"),
                        0x22 => self.push("\""),
                        0x27 => self.push("\\'"),
                        0x20..=0x7E => self.push_char(
                            char::from_u32(u32::try_from(code).unwrap_or(0)).unwrap_or('?'),
                        ),
                        _ => {
                            self.push("\\u{");
                            self.push(digits);
                            self.push("}");
                        }
                    }
                    self.push("'");
                }
            }
            Some((_, Basic::Placeholder)) => self.push("_"),
            Some((_, Basic::Named)) => self.error = true,
            None if c == b'B' => {
                self.backref(|p| {
                    p.konst();
                    false
                });
            }
            None => self.error = true,
        }
    }

    /// `<undisambiguated-identifier>`: the bytes, and whether they are
    /// Punycode.
    fn identifier(&mut self) -> (&'a str, bool) {
        let punycode = self.eat(b'u');
        let len = self.decimal();
        self.eat(b'_');
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if self.error || len > self.input.len() - self.pos {
            self.error = true;
            return ("", false);
        }
        let input: &'a [u8] = self.input;
        let bytes = &input[self.pos..self.pos + len];
        self.pos += len;
        if !bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
        {
            self.error = true;
            return ("", false);
        }
        // ASCII, checked above.
        (core::str::from_utf8(bytes).unwrap_or(""), punycode)
    }

    fn print_identifier(&mut self, (name, punycode): (&str, bool)) {
        if self.error || !self.print {
            return;
        }
        if punycode {
            let mut decoded = String::new();
            if punycode_decode(name, &mut decoded) {
                self.push(&decoded);
            } else {
                self.error = true;
            }
        } else {
            self.push(name);
        }
    }

    fn lifetime(&mut self, index: u64) {
        if index == 0 {
            self.push("'_");
            return;
        }
        if index > self.bound_lifetimes {
            self.error = true;
            return;
        }
        let depth = self.bound_lifetimes - index;
        self.push("'");
        if depth < 26 {
            // Below 26.
            self.push_char(char::from(b'a' + u8::try_from(depth).unwrap_or(0)));
        } else {
            self.push("z");
            self.push_number(depth - 26 + 1);
        }
    }

    /// `<base-62-number>`: `_` is 0, `0_` is 1, ...
    fn base62(&mut self) -> u64 {
        if self.eat(b'_') {
            return 0;
        }
        let mut value: u64 = 0;
        loop {
            let c = self.next();
            let digit = match c {
                b'_' => break,
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => 10 + (c - b'a'),
                b'A'..=b'Z' => 36 + (c - b'A'),
                _ => {
                    self.error = true;
                    return 0;
                }
            };
            match value
                .checked_mul(62)
                .and_then(|v| v.checked_add(u64::from(digit)))
            {
                Some(v) => value = v,
                None => {
                    self.error = true;
                    return 0;
                }
            }
        }
        match value.checked_add(1) {
            Some(v) => v,
            None => {
                self.error = true;
                0
            }
        }
    }

    /// A base-62 number after `tag`, plus one; 0 without the tag.
    fn optional_base62(&mut self, tag: u8) -> u64 {
        if !self.eat(tag) {
            return 0;
        }
        let n = self.base62();
        if self.error {
            return 0;
        }
        match n.checked_add(1) {
            Some(v) => v,
            None => {
                self.error = true;
                0
            }
        }
    }

    fn decimal(&mut self) -> u64 {
        let c = self.look();
        if !c.is_ascii_digit() {
            self.error = true;
            return 0;
        }
        if c == b'0' {
            self.pos += 1;
            return 0;
        }
        let mut value: u64 = 0;
        while self.look().is_ascii_digit() {
            let d = u64::from(self.next() - b'0');
            match value.checked_mul(10).and_then(|v| v.checked_add(d)) {
                Some(v) => value = v,
                None => {
                    self.error = true;
                    return 0;
                }
            }
        }
        value
    }

    /// `<hex-number>`: its value (unspecified past 16 digits) and digits.
    fn hex(&mut self) -> (u64, &'a str) {
        let start = self.pos;
        let mut value: u64 = 0;
        let c = self.look();
        if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            self.error = true;
        }
        if self.eat(b'0') {
            if !self.eat(b'_') {
                self.error = true;
            }
        } else {
            while !self.error && !self.eat(b'_') {
                let c = self.next();
                let d = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => 10 + (c - b'a'),
                    _ => {
                        self.error = true;
                        0
                    }
                };
                value = value.wrapping_mul(16).wrapping_add(u64::from(d));
            }
        }
        if self.error {
            return (0, "");
        }
        let input: &'a [u8] = self.input;
        (
            value,
            core::str::from_utf8(&input[start..self.pos - 1]).unwrap_or(""),
        )
    }
}

/// RFC 3492 Punycode, with `_` (not `-`) before the encoded part, as Rust
/// writes it; appends to `out`.
fn punycode_decode(input: &str, out: &mut String) -> bool {
    let (basic, encoded) = match input.rfind('_') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    let mut chars: alloc::vec::Vec<char> = alloc::vec::Vec::new();
    for c in basic.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
        chars.push(c);
    }
    const BASE: u64 = 36;
    const TMIN: u64 = 1;
    const TMAX: u64 = 26;
    const SKEW: u64 = 38;
    let mut damp = 700;
    let mut bias = 72;
    let mut n: u64 = 0x80;
    let mut i: u64 = 0;
    let mut bytes = encoded.bytes().peekable();
    while bytes.peek().is_some() {
        let old_i = i;
        let mut w: u64 = 1;
        let mut k = BASE;
        loop {
            let Some(c) = bytes.next() else {
                return false;
            };
            let digit = match c {
                b'a'..=b'z' => u64::from(c - b'a'),
                b'0'..=b'9' => 26 + u64::from(c - b'0'),
                _ => return false,
            };
            let Some(next) = digit.checked_mul(w).and_then(|d| i.checked_add(d)) else {
                return false;
            };
            i = next;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            let Some(nw) = w.checked_mul(BASE - t) else {
                return false;
            };
            w = nw;
            k += BASE;
        }
        let points = chars.len() as u64 + 1;
        // Adapt the bias.
        let mut delta = (i - old_i) / damp;
        damp = 2;
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        bias = k + ((BASE - TMIN + 1) * delta) / (delta + SKEW);
        let Some(nn) = n.checked_add(i / points) else {
            return false;
        };
        n = nn;
        i %= points;
        let Some(c) = u32::try_from(n).ok().and_then(char::from_u32) else {
            return false;
        };
        if chars.len() >= MAX_OUTPUT {
            return false;
        }
        // Below `points`, which counts `chars`.
        chars.insert(usize::try_from(i).unwrap_or(chars.len()), c);
        i += 1;
    }
    out.extend(chars);
    true
}

//! A format-independent view of debug information.
//!
//! [`DebugInfo`] wraps a format-specific reader (PDB, or DWARF in an ELF,
//! Mach-O, or WebAssembly file) and presents what analyses that are not
//! format-specific need:
//!
//! - [`Compiland`]s: the translation units (objects) linked into the image,
//!   and the libraries they came from;
//! - [`Contribution`]s: which address ranges of the image each compiland
//!   contributed;
//! - [`Group`]s: named subdivisions of sections, such as COFF groups
//!   (`.text$mn`, `.CRT$XCU`, ...), which the linker sorts input sections by.
//!
//! Addresses follow `hexcavator-image`'s convention: RVAs for PE images,
//! virtual addresses for ELF and Mach-O, code section offsets for
//! WebAssembly.

#![warn(missing_docs)]

pub mod decompress;
pub mod dwarf_backend;
pub mod layout;
mod pdb_backend;
pub mod value;

use hexcavator_core::Result;
use hexcavator_image::DebugId;

pub use pdb_backend::{LINKER_MODULE, LinkerInfo};

/// A translation unit linked into an image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiland {
    /// Its name: normally the path of its object file (`* Linker *` for
    /// what the linker itself produced).
    pub name: String,
    /// The library (archive) it came from; for objects given to the linker
    /// directly, normally the object path again; empty if unknown.
    pub library: String,
}

/// A range of an image contributed by a compiland.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Contribution {
    /// Its address.
    pub addr: u64,
    /// Its size in bytes.
    pub size: u64,
    /// The index of the contributing compiland in [`DebugInfo::compilands`].
    pub compiland: u32,
    /// The characteristics of the input section (PE section flags).
    pub characteristics: u32,
}

/// An inlined copy of a function: what was inlined, where, and the code
/// it occupies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineSite {
    /// The inlined function: an index into [`InlineSites::inlinees`].
    pub inlinee: u32,
    /// The start of the function it was inlined into (its outermost
    /// enclosing procedure).
    pub function: u64,
    /// Its code: (address, size), in order. Nested sites' code may be in
    /// these too (see [`exclusive_sizes`]).
    pub ranges: Vec<(u64, u64)>,
    /// The compiland it is in.
    pub compiland: u32,
    /// How many inline sites enclose it (0: inlined into a function).
    pub depth: u32,
}

/// Every inline site, and the inlined functions' names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InlineSites {
    /// The inlined functions' qualified names.
    pub inlinees: Vec<String>,
    /// The sites.
    pub sites: Vec<InlineSite>,
}

impl InlineSite {
    /// The bytes its ranges cover.
    pub fn size(&self) -> u64 {
        self.ranges.iter().map(|r| r.1).sum()
    }
}

/// The inline sites with copies of one function's sites (identical code
/// folding leaves one record per module at the same address) removed, and
/// each one's own bytes: every byte goes to the deepest site covering it
/// (a nested site's code is its own, not its caller's), once.
pub fn exclusive_sizes(mut sites: Vec<InlineSite>) -> Vec<(InlineSite, u64)> {
    let first = |s: &InlineSite| s.ranges.first().map_or(0, |r| r.0);
    sites.sort_unstable_by_key(|s| (s.function, first(s), s.inlinee, s.ranges.len(), s.depth));
    sites.dedup_by(|a, b| {
        a.function == b.function && a.ranges == b.ranges && a.inlinee == b.inlinee
    });
    let mut own = vec![0u64; sites.len()];
    // One function at a time, deepest first, then by address (a nested
    // site claims its bytes before the site it is in); every byte once,
    // across functions too (two procedure records can cover one piece of
    // code).
    let mut claimed: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut touched: Vec<(u64, u64)> = Vec::new();
    let mut order: Vec<usize> = Vec::new();
    let mut start = 0;
    while start < sites.len() {
        let mut end = start + 1;
        while end < sites.len() && sites[end].function == sites[start].function {
            end += 1;
        }
        order.clear();
        order.extend(start..end);
        order.sort_unstable_by_key(|&i| (std::cmp::Reverse(sites[i].depth), first(&sites[i])));
        for &i in &order {
            for &(at, size) in &sites[i].ranges {
                own[i] += claim(&mut claimed, &mut touched, at, at.saturating_add(size));
            }
        }
        start = end;
    }
    sites.into_iter().zip(own).collect()
}

/// Claims `[start, end)` in `claimed` (disjoint intervals, start to end),
/// and returns how many of its bytes weren't claimed before. (`touched` is
/// scratch space.)
fn claim(
    claimed: &mut std::collections::BTreeMap<u64, u64>,
    touched: &mut Vec<(u64, u64)>,
    start: u64,
    end: u64,
) -> u64 {
    if end <= start {
        return 0;
    }
    // The intervals touching [start, end): from the last starting at or
    // before it.
    let from = match claimed.range(..=start).next_back() {
        Some((&s, &e)) if e >= start => s,
        _ => start,
    };
    touched.clear();
    touched.extend(claimed.range(from..=end).map(|(&s, &e)| (s, e)));
    let mut covered = 0;
    let (mut lo, mut hi) = (start, end);
    for &(s, e) in touched.iter() {
        covered += e.min(end).saturating_sub(s.max(start));
        lo = lo.min(s);
        hi = hi.max(e);
        claimed.remove(&s);
    }
    claimed.insert(lo, hi);
    (end - start) - covered
}

/// The source line some code came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineSpan {
    /// Its code's address.
    pub addr: u64,
    /// Its code's size in bytes.
    pub size: u64,
    /// An index into [`SourceLines::files`].
    pub file: u32,
    /// The line number.
    pub line: u32,
    /// The compiland whose line table it is in.
    pub compiland: u32,
}

/// Where a variable lives over a range of code.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Place {
    /// In a register, by the format's number for it (PDB: CodeView's
    /// `CV_REG_*`; DWARF: the ABI's DWARF number). See
    /// [`DebugInfo::register_name`].
    Register(u16),
    /// In memory, at an offset from a register.
    Relative {
        /// The register (by number).
        register: u16,
        /// The offset from it.
        offset: i32,
    },
    /// In memory, at an offset from the function's frame pointer (which
    /// register that is: [`FunctionVariables::frame`]).
    Frame {
        /// The offset from the frame pointer.
        offset: i32,
        /// Whether it is a parameter's (whose frame pointer may differ).
        param: bool,
    },
    /// A field of the variable (at `field` bytes into it) in a register.
    Field {
        /// The register (by number).
        register: u16,
        /// The field's offset in the variable.
        field: u32,
    },
    /// In memory, at an offset from the canonical frame address (the
    /// stack pointer's value at the call; DWARF's `DW_OP_call_frame_cfa`).
    Cfa {
        /// The offset from the CFA.
        offset: i32,
    },
}

/// A variable's place over the code from `start` to `end` (addresses),
/// but for its gaps (start, length).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarRange {
    /// The first address of the code it holds over.
    pub start: u64,
    /// The address past it.
    pub end: u64,
    /// Where in that it doesn't hold: (address, length).
    pub gaps: Vec<(u64, u64)>,
    /// Where the variable is.
    pub place: Place,
}

/// A parameter or local of a function (or of a function inlined into it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable {
    /// Its name.
    pub name: String,
    /// The format's type reference (PDB: the type index).
    pub type_index: u64,
    /// Whether it is a parameter.
    pub param: bool,
    /// Declared in a function inlined into this one.
    pub inlined: bool,
    /// Where it lives, over its function's code.
    pub ranges: Vec<VarRange>,
}

/// A function's variables, and how its frame is reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionVariables {
    /// The function's first address.
    pub start: u64,
    /// The address past its code.
    pub end: u64,
    /// The frame pointers (S_FRAMEPROC's encoding: 0 none, 1 the stack
    /// pointer, 2 the frame pointer, 3 the base pointer), for locals and
    /// for parameters.
    pub frame: (u8, u8),
    /// Its parameters and locals.
    pub variables: Vec<Variable>,
}

/// An annotation: strings the code attached to an address (MSVC's
/// `__annotation` intrinsic). It takes no space in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation {
    /// Its address.
    pub addr: u64,
    /// Its strings.
    pub strings: Vec<String>,
    /// The compiland whose code it annotates.
    pub compiland: u32,
    /// Whether its address is in an inlined copy of a function's code (it
    /// is in that copy, or annotates a call to it: the records don't tell
    /// the two apart).
    pub inlined: bool,
}

/// The line tables: which source line each piece of code came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceLines {
    /// The source files' paths.
    pub files: Vec<String>,
    /// Sorted by address.
    pub spans: Vec<LineSpan>,
}

/// What a [`Symbol`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SymbolKind {
    /// A function (its main block of code).
    Function,
    /// A block of a function's code separated from its body (by PGO, say);
    /// see [`Symbol::parent`]. Its name and type are its function's.
    SeparatedBlock,
    /// A lexical block within a function.
    Block,
    /// A thunk: a stub that jumps elsewhere (import thunks, adjustor
    /// thunks, incremental-linking thunks, ...).
    Thunk,
    /// A variable.
    Data,
    /// A label within code.
    Label,
    /// A public (linker-visible) symbol; its name is the decorated name.
    Public,
}

/// A symbol: a named address with, usually, a size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// What it is.
    pub kind: SymbolKind,
    /// Its address (for thread-local data, its offset in the TLS template).
    pub addr: u64,
    /// The size, if the debug information gives one. For data, this is the
    /// size of its type (see [`DebugInfo::symbols`]).
    pub size: Option<u64>,
    /// As recorded: qualified but undecorated for functions and data in
    /// PDBs, decorated for publics.
    pub name: String,
    /// The compiland whose debug information holds the symbol, if any
    /// (global data and publics live in shared streams).
    pub compiland: Option<u32>,
    /// External linkage (a global function or variable).
    pub global: bool,
    /// Thread-local storage (data only; `addr` is then an offset in the
    /// TLS template, as for other data).
    pub thread_local: bool,
    /// For a separated block: its function's address. For data declared
    /// in a function (a function's `static`), the function's address.
    pub parent: Option<u64>,
    /// For data declared in a function: the function.
    pub function: Option<Box<EnclosingFunction>>,
    /// The format's type reference (PDB: the type index), or 0.
    pub type_index: u64,
    /// Format-specific flags (PDB publics: `CV_PUBSYMFLAGS`; procedures:
    /// `CV_PROCFLAGS`).
    pub flags: u32,
}

/// The function a variable is declared in: the innermost function whose
/// code holds the declaration, an inlined function if it is in an inlined
/// copy of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclosingFunction {
    /// Qualified and undecorated.
    pub name: String,
    /// Its type.
    pub ty: TypeRef,
    /// Its parameters, in order, with their types (`this` is not one).
    pub params: Vec<(String, TypeRef)>,
}

/// How a method is declared (CodeView's method properties).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MethodKind {
    /// Not virtual.
    Plain,
    /// Overrides a virtual function of a base.
    Virtual,
    /// A static member function.
    Static,
    /// A friend function.
    Friend,
    /// Introduces a virtual function.
    IntroVirtual,
    /// Pure, overriding a base's.
    PureVirtual,
    /// Introduces a pure virtual function.
    PureIntroVirtual,
}

impl MethodKind {
    /// Whether it is virtual (introducing, overriding, or pure).
    pub fn is_virtual(self) -> bool {
        matches!(
            self,
            MethodKind::Virtual
                | MethodKind::IntroVirtual
                | MethodKind::PureVirtual
                | MethodKind::PureIntroVirtual
        )
    }

    /// Whether it is pure virtual.
    pub fn is_pure(self) -> bool {
        matches!(self, MethodKind::PureVirtual | MethodKind::PureIntroVirtual)
    }
}

/// A method a class declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    /// Unqualified.
    pub name: String,
    /// Its function type.
    pub ty: TypeRef,
    /// How it is declared.
    pub kind: MethodKind,
}

/// A class (or struct, or interface) definition: its direct bases and
/// its methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    /// Its qualified name.
    pub name: String,
    /// Its type.
    pub ty: TypeRef,
    /// Direct base classes (virtual ones included), as definitions.
    pub bases: Vec<TypeRef>,
    /// Its methods, in declaration order.
    pub methods: Vec<Method>,
}

/// A reference to a type in the debug information (PDB: a type index;
/// DWARF: a DIE's offset, and which file and section it is in: see
/// [`dwarf_backend`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeRef(pub u64);

impl TypeRef {
    /// As a PDB type index (one too wide for any is no type, 0).
    pub fn pdb_index(self) -> hexcavator_codeview::TypeIndex {
        hexcavator_codeview::TypeIndex(u32::try_from(self.0).unwrap_or(0))
    }
}

/// A built-in type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BasicType {
    /// No type: the `...` of a variadic function, or an unknown type.
    None,
    /// `void`.
    Void,
    /// `char`, which is distinct from `signed char` and `unsigned char`.
    Char,
    /// `wchar_t`.
    WideChar,
    /// `char8_t`.
    Char8,
    /// `char16_t`.
    Char16,
    /// `char32_t`.
    Char32,
    /// A signed integer of the type's size (`signed char` for 1 byte).
    Int,
    /// An unsigned integer of the type's size.
    UInt,
    /// `long`, which Windows keeps distinct from `int`.
    Long,
    /// `unsigned long`.
    ULong,
    /// `bool`.
    Bool,
    /// A floating-point number of the type's size.
    Float,
    /// `HRESULT` (which PDBs keep distinct).
    HResult,
}

/// Whether a pointer is a pointer or a reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PointerKind {
    /// `T*`.
    Pointer,
    /// `T&`.
    LValueReference,
    /// `T&&`.
    RValueReference,
    /// A pointer to a data or function member.
    Member,
}

/// cv-qualifiers and the other modifiers a type can have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Qualifiers {
    /// `const`.
    pub is_const: bool,
    /// `volatile`.
    pub is_volatile: bool,
    /// `__unaligned`.
    pub is_unaligned: bool,
    /// `restrict`.
    pub is_restrict: bool,
}

/// The structure of a type: enough to name it in any style.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeShape {
    /// A built-in type.
    Basic {
        /// Which.
        kind: BasicType,
        /// The size in bytes (0 for `void` and none).
        size: u64,
    },
    /// A pointer or reference.
    Pointer {
        /// What it points to.
        target: TypeRef,
        /// Which kind.
        kind: PointerKind,
        /// Qualifiers of the pointer itself (`T* const`).
        qualifiers: Qualifiers,
        /// Its size in bytes.
        size: u64,
    },
    /// A qualified type (`const T`).
    Modified {
        /// The type qualified.
        base: TypeRef,
        /// Its qualifiers.
        qualifiers: Qualifiers,
    },
    /// A class, struct, union, or interface, by name.
    Udt {
        /// Its qualified name.
        name: String,
    },
    /// An enumeration, by name.
    Enum {
        /// Its qualified name.
        name: String,
    },
    /// An array.
    Array {
        /// Its elements' type.
        element: TypeRef,
        /// The array's size in bytes.
        size: u64,
    },
    /// A function type.
    Function {
        /// Its return type.
        ret: TypeRef,
        /// Its parameters' types.
        args: Vec<TypeRef>,
        /// For member functions: the class.
        class: Option<TypeRef>,
        /// For member functions: the qualifiers of `this`'s pointee
        /// (`const` for a `const` member function).
        this_qualifiers: Option<Qualifiers>,
    },
    /// Something not described yet, or a reference that leads nowhere.
    Unknown,
}

/// An enumeration's values: whether its underlying type is signed, and
/// each enumerator's name and value (as its underlying type's bits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enumerators {
    /// Whether its underlying type is signed (values are then two's complement).
    pub signed: bool,
    /// Its enumerators: names and values, in order.
    pub values: Vec<(String, u64)>,
}

/// A named subdivision of a section, such as a COFF group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Its name (`.text$mn`).
    pub name: String,
    /// Its address.
    pub addr: u64,
    /// Its size in bytes.
    pub size: u64,
    /// PE section flags.
    pub characteristics: u32,
}

/// Where to look for the debug information that `id` names, for an image
/// at `image_path`, in order. (Callers check each with
/// [`DebugInfo::matches`].)
///
/// - A PDB, or dwz's supplementary file: the path the linker recorded,
///   then a file of that name next to the image.
/// - A `.gnu_debuglink` name (or WebAssembly's `external_debug_info`):
///   next to the image, in `.debug` there, and under `/usr/lib/debug` by
///   the image's directory, as GDB looks.
/// - A build ID: `.build-id/xx/yyyy.debug`, next to the image and under
///   `/usr/lib/debug`.
/// - A build ID: also the image's name with `.debug` or `.dbg` added, as
///   `objcopy --only-keep-debug` users and .NET name them.
/// - A Mach-O UUID: the image's dSYM bundle
///   (`app.dSYM/Contents/Resources/DWARF/app`), then a lone DWARF file
///   beside it (`app.dwarf`, as symbol servers name them).
///
/// [`candidate_paths_in`] adds the symbol directories (see
/// [`symbol_dirs`]).
pub fn candidate_paths(image_path: &std::path::Path, id: &DebugId<'_>) -> Vec<std::path::PathBuf> {
    let mut out = beside(image_path, id);
    let with = |ext: &str| {
        let mut p = image_path.as_os_str().to_owned();
        p.push(ext);
        std::path::PathBuf::from(p)
    };
    let more: &[&str] = match id {
        DebugId::BuildId(b) if b.len() >= 2 => &[".debug", ".dbg"],
        DebugId::Uuid(_) if image_path.file_name().is_some() => &[".dwarf"],
        _ => &[],
    };
    for ext in more {
        let p = with(ext);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// [`candidate_paths`], then where each of `dirs` would hold the file:
///
/// - a symbol server's layout (as its local caches and `symstore` keep
///   files: `app.pdb/<GUID><age>/app.pdb`,
///   `_.debug/elf-buildid-sym-<id>/_.debug`,
///   `_.dwarf/mach-uuid-sym-<uuid>/_.dwarf`);
/// - debuginfod's cache (`<id>/debuginfo`);
/// - a `.build-id` tree (`.build-id/xx/yyyy.debug`, or `xx/yyyy.debug`);
/// - a dSYM bundle (`app.dSYM/Contents/Resources/DWARF/app`);
/// - the file's name alone (a PDB's, or a debug link's).
pub fn candidate_paths_in(
    image_path: &std::path::Path,
    id: &DebugId<'_>,
    dirs: &[std::path::PathBuf],
) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out = candidate_paths(image_path, id);
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for dir in dirs {
        match *id {
            DebugId::Pdb { guid, age, path } => {
                let Some(name) = file_name_of(path) else {
                    continue;
                };
                let key = symbol_store_key(&guid, age);
                push(dir.join(&name).join(&key).join(&name));
                let lower = name.to_ascii_lowercase();
                push(dir.join(&lower).join(&key).join(&lower));
                push(dir.join(&name));
            }
            DebugId::Pdb20 {
                signature,
                age,
                path,
            } => {
                let Some(name) = file_name_of(path) else {
                    continue;
                };
                let key = format!("{signature:08X}{age:X}");
                push(dir.join(&name).join(&key).join(&name));
                push(dir.join(&name));
            }
            DebugId::BuildId(b) | DebugId::AltLink { build_id: b, .. } if b.len() >= 2 => {
                let h = hex(b);
                push(
                    dir.join("_.debug")
                        .join(format!("elf-buildid-sym-{h}"))
                        .join("_.debug"),
                );
                push(dir.join(&h).join("debuginfo"));
                let file = format!("{}.debug", &h[2..]);
                push(dir.join(".build-id").join(&h[..2]).join(&file));
                push(dir.join(&h[..2]).join(&file));
            }
            DebugId::Uuid(u) => {
                push(
                    dir.join("_.dwarf")
                        .join(format!("mach-uuid-sym-{}", hex(&u)))
                        .join("_.dwarf"),
                );
                if let Some(name) = image_path.file_name() {
                    let mut bundle = name.to_owned();
                    bundle.push(".dSYM");
                    push(
                        dir.join(bundle)
                            .join("Contents")
                            .join("Resources")
                            .join("DWARF")
                            .join(name),
                    );
                }
            }
            DebugId::DebugLink { path, .. } => {
                let name = String::from_utf8_lossy(path);
                if !name.is_empty() && !name.contains(['/', '\\']) {
                    push(dir.join(&*name));
                }
            }
            _ => {}
        }
    }
    out
}

/// The last part of a recorded path (either separator), if it names a
/// file: `..` and the like aren't followed.
fn file_name_of(path: &[u8]) -> Option<String> {
    let path = String::from_utf8_lossy(path);
    let name = path.rsplit(['/', '\\']).next()?;
    (!name.is_empty() && name != "." && name != "..").then(|| name.to_owned())
}

/// The directories to look for debug information in, besides the image's
/// own, from the environment:
///
/// - `HEXC_SYMBOL_PATH`: directories, separated as `PATH`'s are;
/// - `_NT_SYMBOL_PATH`: its local directories and symbol-server caches
///   (`srv*C:\symbols*https://...` gives `C:\symbols`; servers on the
///   network aren't asked);
/// - debuginfod's cache: `DEBUGINFOD_CACHE_PATH`, else
///   `$XDG_CACHE_HOME/debuginfod_client`, else (on Unix)
///   `~/.cache/debuginfod_client`.
pub fn symbol_dirs() -> Vec<std::path::PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    symbol_dirs_from(
        var("HEXC_SYMBOL_PATH").as_deref(),
        var("_NT_SYMBOL_PATH")
            .and_then(|v| v.into_string().ok())
            .as_deref(),
        var("DEBUGINFOD_CACHE_PATH")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                var("XDG_CACHE_HOME").map(|c| std::path::Path::new(&c).join("debuginfod_client"))
            })
            .or_else(|| {
                // (debuginfod's default is a Unix one.)
                var("HOME").filter(|_| cfg!(unix)).map(|h| {
                    std::path::Path::new(&h)
                        .join(".cache")
                        .join("debuginfod_client")
                })
            }),
    )
}

/// [`symbol_dirs`] from the values given (for testing).
pub fn symbol_dirs_from(
    hexc: Option<&std::ffi::OsStr>,
    nt: Option<&str>,
    debuginfod: Option<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !p.as_os_str().is_empty() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(h) = hexc {
        std::env::split_paths(h).for_each(&mut push);
    }
    nt_symbol_dirs(nt.unwrap_or(""))
        .into_iter()
        .for_each(&mut push);
    if let Some(d) = debuginfod {
        push(d);
    }
    out
}

/// The local directories of a Windows symbol path (`_NT_SYMBOL_PATH`'s
/// form): plain directories, and the caches of `srv*`, `symsrv*`, and
/// `cache*` entries. Servers (URLs) are left out.
pub fn nt_symbol_dirs(path: &str) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    for entry in path.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("srv*") || lower.starts_with("cache*") || lower.starts_with("symsrv*")
        {
            for part in entry.split('*').skip(1) {
                let p = part.to_ascii_lowercase();
                if !part.is_empty() && !p.contains("://") && !p.ends_with(".dll") {
                    dirs.push(std::path::PathBuf::from(part));
                }
            }
        } else if !entry.contains('*') {
            dirs.push(std::path::PathBuf::from(entry));
        }
    }
    dirs
}

/// The directory a symbol store keeps a PDB in: the GUID in hex as its
/// registry form reads (without dashes), then the age.
pub fn symbol_store_key(guid: &[u8; 16], age: u32) -> String {
    use std::fmt::Write as _;
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let mut s = format!("{d1:08X}{d2:04X}{d3:04X}");
    for b in &guid[8..] {
        let _ = write!(s, "{b:02X}");
    }
    let _ = write!(s, "{age:X}");
    s
}

fn beside(image_path: &std::path::Path, id: &DebugId<'_>) -> Vec<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
    let dir = image_path.parent().unwrap_or(Path::new(""));
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    match *id {
        DebugId::DebugLink { path, .. } => {
            let name = String::from_utf8_lossy(path).into_owned();
            if name.is_empty() || name.contains(['/', '\\']) {
                // (A name, not a path: anything else isn't followed.)
                return out;
            }
            push(dir.join(&name));
            push(dir.join(".debug").join(&name));
            if dir.has_root() {
                let rel: PathBuf = dir
                    .components()
                    .filter(|c| matches!(c, std::path::Component::Normal(_)))
                    .collect();
                push(Path::new("/usr/lib/debug").join(rel).join(&name));
            }
            return out;
        }
        DebugId::BuildId(build_id) => {
            if build_id.len() < 2 {
                return out;
            }
            let hex: String = build_id.iter().map(|b| format!("{b:02x}")).collect();
            let rel = Path::new(".build-id")
                .join(&hex[..2])
                .join(format!("{}.debug", &hex[2..]));
            push(dir.join(&rel));
            push(Path::new("/usr/lib/debug").join(&rel));
            return out;
        }
        DebugId::Uuid(_) => {
            if let Some(name) = image_path.file_name() {
                let mut bundle = image_path.as_os_str().to_owned();
                bundle.push(".dSYM");
                push(
                    PathBuf::from(bundle)
                        .join("Contents")
                        .join("Resources")
                        .join("DWARF")
                        .join(name),
                );
            }
            return out;
        }
        _ => {}
    }
    let recorded = match id {
        DebugId::Pdb { path, .. } | DebugId::Pdb20 { path, .. } | DebugId::AltLink { path, .. } => {
            std::path::PathBuf::from(String::from_utf8_lossy(path).into_owned())
        }
        _ => std::path::PathBuf::new(),
    };
    let mut out = Vec::new();
    if !recorded.as_os_str().is_empty() {
        out.push(recorded.clone());
    }
    // The recorded path is often from another machine, and may use either
    // separator whatever the host's.
    let recorded = recorded.to_string_lossy().replace('\\', "/");
    if let Some(name) = recorded.rsplit('/').next().filter(|n| !n.is_empty()) {
        let beside = match image_path.parent() {
            Some(dir) => dir.join(name),
            None => std::path::PathBuf::from(name),
        };
        if !out.contains(&beside) {
            out.push(beside);
        }
    }
    out
}

/// Debug information for an image, of any supported format.
#[non_exhaustive]
pub enum DebugInfo<'data> {
    /// A PDB.
    Pdb(Box<pdb_backend::PdbInfo<'data>>),
    /// DWARF (in the image, or a separate debug file).
    Dwarf(Box<dwarf_backend::DwarfInfo<'data>>),
}

impl<'data> DebugInfo<'data> {
    /// Parses `data`, detecting its format.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        if hexcavator_pdb::check(data).is_ok() {
            return pdb_backend::PdbInfo::parse(data).map(|p| DebugInfo::Pdb(Box::new(p)));
        }
        match dwarf_backend::DwarfInfo::parse(data) {
            Ok(d) => Ok(DebugInfo::Dwarf(Box::new(d))),
            // Neither: say what a PDB would have said (an old PDB, say).
            Err(_) => pdb_backend::PdbInfo::parse(data).map(|p| DebugInfo::Pdb(Box::new(p))),
        }
    }

    /// The name of register `n` (by the format's numbering: see
    /// [`Place::Register`]) of `arch`.
    pub fn register_name(&self, arch: hexcavator_core::Arch, n: u16) -> Option<String> {
        match self {
            DebugInfo::Pdb(_) => hexcavator_codeview::registers::name(arch, n),
            DebugInfo::Dwarf(_) => hexcavator_dwarf::registers::name(arch, n),
        }
    }

    /// The underlying DWARF reader, if this is DWARF.
    pub fn dwarf(&self) -> Option<&dwarf_backend::DwarfInfo<'data>> {
        match self {
            DebugInfo::Dwarf(d) => Some(d),
            DebugInfo::Pdb(_) => None,
        }
    }

    /// The underlying DWARF reader, to add split files to.
    pub fn dwarf_mut(&mut self) -> Option<&mut dwarf_backend::DwarfInfo<'data>> {
        match self {
            DebugInfo::Dwarf(d) => Some(d),
            DebugInfo::Pdb(_) => None,
        }
    }

    /// Whether this debug information is the one an image's `id` refers to.
    pub fn matches(&self, id: &DebugId<'_>) -> bool {
        match self {
            DebugInfo::Pdb(p) => p.matches(id),
            DebugInfo::Dwarf(d) => d.matches(id),
        }
    }

    /// The compilands, in the order the debug information lists them.
    pub fn compilands(&self) -> Result<Vec<Compiland>> {
        match self {
            DebugInfo::Pdb(p) => p.compilands(),
            DebugInfo::Dwarf(d) => d.compilands(),
        }
    }

    /// The contributions, sorted by address. Contributions whose address
    /// cannot be determined (an unknown section) are left out.
    pub fn contributions(&self) -> Result<Vec<Contribution>> {
        match self {
            DebugInfo::Pdb(p) => p.contributions(),
            DebugInfo::Dwarf(d) => d.contributions(),
        }
    }

    /// Every inline site, with its code.
    pub fn inline_sites(&self) -> Result<InlineSites> {
        match self {
            DebugInfo::Pdb(p) => p.inline_sites(),
            DebugInfo::Dwarf(d) => d.inline_sites(),
        }
    }

    /// The line tables: each piece of code's source file and line.
    pub fn source_lines(&self) -> Result<SourceLines> {
        match self {
            DebugInfo::Pdb(p) => p.source_lines(),
            DebugInfo::Dwarf(d) => d.source_lines(),
        }
    }

    /// The parameters and locals of the function whose code starts at
    /// `addr`, with where each lives (looked for in `compiland` first),
    /// or `None` if no function starts there.
    pub fn variables(
        &self,
        compiland: Option<u32>,
        addr: u64,
    ) -> Result<Option<FunctionVariables>> {
        match self {
            DebugInfo::Pdb(p) => p.variables(compiland, addr),
            DebugInfo::Dwarf(d) => d.variables(compiland, addr),
        }
    }

    /// Every annotation, by address.
    pub fn annotations(&self) -> Result<Vec<Annotation>> {
        match self {
            DebugInfo::Pdb(p) => p.annotations(),
            DebugInfo::Dwarf(_) => Ok(Vec::new()),
        }
    }

    /// The groups, sorted by address.
    pub fn groups(&self) -> Result<Vec<Group>> {
        match self {
            DebugInfo::Pdb(p) => p.groups(),
            DebugInfo::Dwarf(_) => Ok(Vec::new()),
        }
    }

    /// Every symbol with an address, sorted by address (then kind, then
    /// name): procedures, separated and lexical blocks, thunks, labels,
    /// data (module-local and global), and publics. A symbol recorded in
    /// more than one place (a static both in its module and in the global
    /// symbols, say) appears once. Data sizes come from their types;
    /// symbols whose section is unknown are left out.
    pub fn symbols(&self) -> Result<Vec<Symbol>> {
        match self {
            DebugInfo::Pdb(p) => p.symbols(),
            DebugInfo::Dwarf(d) => d.symbols(),
        }
    }

    /// Every class definition, with its direct bases and its methods.
    pub fn classes(&self) -> Result<Vec<Class>> {
        match self {
            DebugInfo::Pdb(p) => p.classes(),
            DebugInfo::Dwarf(d) => d.classes(),
        }
    }

    /// The structure of type `ty`.
    pub fn type_shape(&self, ty: TypeRef) -> TypeShape {
        match self {
            DebugInfo::Pdb(p) => p.type_shape(ty),
            DebugInfo::Dwarf(d) => d.type_shape(ty),
        }
    }

    /// The size in bytes of type `ty`, if known.
    pub fn type_size(&self, ty: TypeRef) -> Option<u64> {
        match self {
            DebugInfo::Pdb(p) => p.type_size(ty),
            DebugInfo::Dwarf(d) => d.type_size(ty),
        }
    }

    /// The enumerators of the enumeration `ty`, if it is one.
    pub fn enumerators(&self, ty: TypeRef) -> Option<Enumerators> {
        match self {
            DebugInfo::Pdb(p) => p.enumerators(ty),
            DebugInfo::Dwarf(d) => d.enumerators(ty),
        }
    }

    /// The name of type `ty`, as C++.
    pub fn type_name(&self, ty: TypeRef) -> String {
        match self {
            DebugInfo::Pdb(p) => p.type_name(ty),
            DebugInfo::Dwarf(d) => d.type_name(ty),
        }
    }

    /// The layout of the class, structure, or union `ty`, if it is one with
    /// a definition here.
    pub fn layout(&self, ty: TypeRef) -> Option<layout::Layout> {
        match self {
            DebugInfo::Pdb(p) => p.layout(ty),
            DebugInfo::Dwarf(d) => d.layout(ty),
        }
    }

    /// Every defined class, structure, and union (one per key), with its
    /// layout. (PDB layouts' parts here are unnamed: [`DebugInfo::layout`]
    /// names them.)
    pub fn layouts(&self) -> Result<Vec<layout::Layout>> {
        match self {
            DebugInfo::Pdb(p) => p.layouts(),
            DebugInfo::Dwarf(d) => d.layouts(),
        }
    }

    /// Where type `ty` is defined: its source file and line, if the debug
    /// information records them (a PDB's `LF_UDT_SRC_LINE` records; DWARF's
    /// `DW_AT_decl_file` and `DW_AT_decl_line`).
    pub fn type_definition(&self, ty: TypeRef) -> Option<(String, u32)> {
        match self {
            DebugInfo::Pdb(p) => p.type_definition(ty),
            DebugInfo::Dwarf(d) => d.type_definition(ty),
        }
    }

    /// What the debug information records about the link.
    pub fn linker_info(&self) -> Result<LinkerInfo> {
        match self {
            DebugInfo::Pdb(p) => p.linker_info(),
            DebugInfo::Dwarf(_) => Ok(LinkerInfo::default()),
        }
    }

    /// The underlying PDB reader, if this is a PDB.
    pub fn pdb(&self) -> Option<&hexcavator_pdb::Pdb<'data>> {
        match self {
            DebugInfo::Pdb(p) => Some(p.pdb()),
            DebugInfo::Dwarf(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(inlinee: &str, function: u64, ranges: &[(u64, u64)], depth: u32) -> InlineSite {
        let names = [
            "outer", "inner", "a", "b", "f", "x", "y", "deep1", "deep2", "wide", "big", "in", "h",
        ];
        InlineSite {
            inlinee: u32::try_from(names.iter().position(|n| *n == inlinee).unwrap()).unwrap(),
            function,
            ranges: ranges.to_vec(),
            compiland: 0,
            depth,
        }
    }

    fn sizes(sites: Vec<InlineSite>) -> Vec<(String, u64)> {
        let names = [
            "outer", "inner", "a", "b", "f", "x", "y", "deep1", "deep2", "wide", "big", "in", "h",
        ];
        let mut v: Vec<(String, u64)> = exclusive_sizes(sites)
            .into_iter()
            .map(|(s, b)| (names[s.inlinee as usize].to_string(), b))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn nested_sites_own_their_bytes() {
        // outer covers 0x100-0x140; inner, nested, 0x110-0x120.
        let got = sizes(vec![
            site("outer", 0x100, &[(0x100, 0x40)], 0),
            site("inner", 0x100, &[(0x110, 0x10)], 1),
        ]);
        assert_eq!(got, [("inner".into(), 0x10), ("outer".into(), 0x30)]);
        // Disjoint ranges count whole; a site adjacent to another too.
        let got = sizes(vec![
            site("a", 0, &[(0, 4), (8, 4)], 0),
            site("b", 0, &[(4, 4)], 0),
        ]);
        assert_eq!(got, [("a".into(), 8), ("b".into(), 4)]);
    }

    #[test]
    fn folded_copies_count_once() {
        // Two modules' records of one folded function: one site.
        let got = sizes(vec![
            site("f", 0x10, &[(0x10, 8)], 0),
            site("f", 0x10, &[(0x10, 8)], 0),
        ]);
        assert_eq!(got, [("f".into(), 8)]);
        // Different inlinees over the same bytes, same depth: the bytes go
        // to one of them.
        let got = exclusive_sizes(vec![site("x", 0, &[(0, 8)], 0), site("y", 0, &[(0, 8)], 0)]);
        assert_eq!(got.iter().map(|g| g.1).sum::<u64>(), 8);
    }

    #[test]
    fn overlaps_of_every_shape() {
        // Claimed [10, 20) and [30, 40); then [5, 45): 5 + 10 + 5 bytes new.
        let got = exclusive_sizes(vec![
            site("deep1", 0, &[(10, 10)], 2),
            site("deep2", 0, &[(30, 10)], 2),
            site("wide", 0, &[(5, 40)], 1),
        ]);
        let wide = got.iter().find(|g| g.0.inlinee == 9).unwrap().1;
        assert_eq!(wide, 20);
        // A range inside a claimed one: nothing; an empty one: nothing.
        let got = sizes(vec![
            site("big", 0, &[(0, 100)], 1),
            site("in", 0, &[(10, 5), (50, 0)], 0),
        ]);
        assert_eq!(got, [("big".into(), 100), ("in".into(), 0)]);
        assert!(exclusive_sizes(Vec::new()).is_empty());
        // Hostile: a range running past the address space.
        let got = exclusive_sizes(vec![site("h", 0, &[(u64::MAX - 4, 100)], 0)]);
        assert_eq!(got[0].1, 4);
    }
}

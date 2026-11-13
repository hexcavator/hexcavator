//! Objective-C metadata (the modern runtime's, "objc2"): the classes,
//! categories, and protocols an image defines (`__objc_classlist`,
//! `__objc_catlist`, `__objc_protolist`), with their methods, instance
//! variables, and properties, and its `__objc_imageinfo`.
//!
//! For linked images (executables, dylibs, bundles): pointers are read
//! through the image's fixups (chained, or the older opcodes), so a
//! superclass or category's class in another image is named by its import.
//! Objects (whose pointers are relocations) give nothing.
//!
//! Bounded: lists' entries are no smaller than their structures, and at
//! most [`MAX_ENTRIES`] entries and [`MAX_STRING_BYTES`] bytes of names in
//! all are read (then [`Objc::truncated`] is set); damage ends a list or
//! leaves a field empty.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{FixupKind, MachO, Segment};

/// How many list entries (methods, variables, properties, protocols,
/// classes) are read at most, in all.
pub const MAX_ENTRIES: usize = 1 << 21;
/// How many bytes of names and types are read at most, in all.
pub const MAX_STRING_BYTES: usize = 64 << 20;
/// How long one name or type is at most (longer ones are cut).
const MAX_STRING: usize = 4096;

/// A method list entry flag: offsets (relative to the field) for pointers.
const RELATIVE: u32 = 0x8000_0000;
/// With [`RELATIVE`]: names are offsets to the names (the shared cache's),
/// not to selector references.
const DIRECT_SELECTORS: u32 = 0x4000_0000;
/// `OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES`: categories have a class
/// properties field.
const HAS_CATEGORY_CLASS_PROPERTIES: u32 = 0x40;
/// The class name prefix of a class's symbol.
const CLASS_PREFIX: &[u8] = b"_OBJC_CLASS_$_";

/// An image's Objective-C metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Objc {
    /// The classes it defines (`__objc_classlist`), in order.
    pub classes: Vec<Class>,
    /// Its categories (`__objc_catlist`), in order.
    pub categories: Vec<Category>,
    /// Its protocols (`__objc_protolist`), in order.
    pub protocols: Vec<Protocol>,
    /// `__objc_imageinfo`: (version, flags), if it has one.
    pub image_info: Option<(u32, u32)>,
    /// Whether the limits were reached, and some metadata left out.
    pub truncated: bool,
}

/// A class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Class {
    /// Its address (its `class_t`).
    pub addr: u64,
    pub name: String,
    /// Its superclass's name (an imported one's, by its symbol), if it
    /// has one.
    pub superclass: Option<String>,
    /// `class_ro_t`'s flags (`RO_ROOT`, ...).
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub methods: Vec<Method>,
    /// Its metaclass's methods.
    pub class_methods: Vec<Method>,
    /// The protocols it adopts, by name.
    pub protocols: Vec<String>,
    pub ivars: Vec<Ivar>,
    pub properties: Vec<Property>,
    /// Its metaclass's properties.
    pub class_properties: Vec<Property>,
    /// Whether it is a Swift class (its data pointer's flag bits).
    pub swift: bool,
}

/// A method.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Method {
    /// Its selector.
    pub name: String,
    /// Its type encoding (`v24@0:8i16i20`).
    pub types: String,
    /// Its code's address (0 for a protocol's).
    pub imp: u64,
}

/// An instance variable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ivar {
    pub name: String,
    /// Its type encoding.
    pub types: String,
    /// Its offset in the instance (from the offset variable), if known.
    pub offset: Option<u32>,
    /// Its alignment, as a power of two.
    pub alignment: u32,
    pub size: u32,
}

/// A property.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    /// Its attributes (`Ti,N,V_sides`).
    pub attributes: String,
}

/// A category.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Category {
    /// Its address (its `category_t`).
    pub addr: u64,
    pub name: String,
    /// The class it extends, by name (an imported one's, by its symbol).
    pub class: Option<String>,
    pub methods: Vec<Method>,
    pub class_methods: Vec<Method>,
    pub protocols: Vec<String>,
    pub properties: Vec<Property>,
    pub class_properties: Vec<Property>,
}

/// A protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Protocol {
    /// Its address (its `protocol_t`).
    pub addr: u64,
    pub name: String,
    /// The protocols it adopts, by name.
    pub protocols: Vec<String>,
    pub methods: Vec<Method>,
    pub class_methods: Vec<Method>,
    pub optional_methods: Vec<Method>,
    pub optional_class_methods: Vec<Method>,
    pub properties: Vec<Property>,
    pub class_properties: Vec<Property>,
}

/// A pointer, as dyld leaves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ptr<'d> {
    Null,
    Addr(u64),
    Import(&'d [u8]),
}

impl Ptr<'_> {
    fn addr(self) -> Option<u64> {
        match self {
            Ptr::Addr(a) => Some(a),
            _ => None,
        }
    }
}

struct Reader<'a, 'd> {
    macho: &'a MachO<'d>,
    segments: Vec<Segment<'d>>,
    fixups: BTreeMap<u64, FixupKind<'d>>,
    /// The pointer width.
    w: u64,
    entries: usize,
    string_bytes: usize,
    truncated: bool,
}

impl<'d> Reader<'_, 'd> {
    /// The image's bytes at `addr`, through its segment's end.
    fn bytes(&self, addr: u64) -> Option<&'d [u8]> {
        let s = self
            .segments
            .iter()
            .find(|s| addr >= s.vmaddr && addr - s.vmaddr < s.filesize)?;
        let at = s.fileoff.checked_add(addr - s.vmaddr)?;
        let end = s.fileoff.checked_add(s.filesize)?;
        self.macho
            .data()
            .get(usize::try_from(at).ok()?..usize::try_from(end).ok()?)
    }

    fn uint(&self, addr: u64, n: u64) -> Option<u64> {
        let b = self.bytes(addr)?.get(..usize::try_from(n).ok()?)?;
        Some(match self.macho.endian() {
            hexcavator_core::Endian::Little => {
                b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x))
            }
            hexcavator_core::Endian::Big => b.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)),
        })
    }

    fn u32(&self, addr: u64) -> Option<u32> {
        u32::try_from(self.uint(addr, 4)?).ok()
    }

    /// A field `i` pointers into the structure at `addr`.
    fn field(addr: u64, i: u64, w: u64) -> Option<u64> {
        addr.checked_add(i.checked_mul(w)?)
    }

    /// The pointer at `addr`.
    fn pointer(&self, addr: u64) -> Ptr<'d> {
        match self.fixups.get(&addr) {
            Some(FixupKind::Rebase { target }) => Ptr::Addr(*target),
            Some(FixupKind::Bind { symbol, .. }) => Ptr::Import(symbol),
            None => match self.uint(addr, self.w) {
                None | Some(0) => Ptr::Null,
                Some(v) => Ptr::Addr(v),
            },
        }
    }

    /// The pointer at field `i` of the structure at `addr`.
    fn pointer_field(&self, addr: u64, i: u64) -> Ptr<'d> {
        Self::field(addr, i, self.w).map_or(Ptr::Null, |a| self.pointer(a))
    }

    /// The C string at `addr`, cut at [`MAX_STRING`] bytes.
    fn string(&mut self, addr: Option<u64>) -> String {
        let Some(b) = addr.and_then(|a| self.bytes(a)) else {
            return String::new();
        };
        let b = &b[..b.len().min(MAX_STRING)];
        let b = b.iter().position(|&c| c == 0).map_or(b, |n| &b[..n]);
        if self.string_bytes + b.len() > MAX_STRING_BYTES {
            self.truncated = true;
            return String::new();
        }
        self.string_bytes += b.len();
        String::from_utf8_lossy(b).into_owned()
    }

    /// Takes one entry from the budget: whether there was one.
    fn take(&mut self) -> bool {
        if self.entries >= MAX_ENTRIES {
            self.truncated = true;
            return false;
        }
        self.entries += 1;
        true
    }

    /// A list's header (`entsizeAndFlags`, `count`) at `addr`: its flags,
    /// entry size, count, and first entry; `None` if its entries would be
    /// smaller than `min`.
    fn list(&self, addr: u64, min: u64) -> Option<(u32, u64, u64, u64)> {
        let word = self.u32(addr)?;
        let count = u64::from(self.u32(addr.checked_add(4)?)?);
        let flags = word & 0xFFFF_0003;
        let size = u64::from(word & 0xFFFC);
        if size < min {
            return None;
        }
        Some((flags, size, count, addr.checked_add(8)?))
    }

    /// The method list at `list`.
    fn methods(&mut self, list: Ptr<'d>) -> Vec<Method> {
        let mut out = Vec::new();
        let Some(addr) = list.addr() else { return out };
        // (Relative entries are three 32-bit offsets, at least.)
        let Some((flags, size, count, first)) = self.list(addr, 12) else {
            return out;
        };
        let relative = flags & RELATIVE != 0;
        if !relative && size < 3 * self.w {
            return out;
        }
        for i in 0..count {
            let Some(at) = i.checked_mul(size).and_then(|o| first.checked_add(o)) else {
                break;
            };
            if self.bytes(at).is_none_or(|b| (b.len() as u64) < size) || !self.take() {
                break;
            }
            let m = if relative {
                // (An offset of 0 is none.)
                let rel = |r: &Self, field: u64| -> Option<u64> {
                    let at = at.checked_add(field)?;
                    let off = i32::from_ne_bytes(r.u32(at)?.to_ne_bytes());
                    (off != 0).then(|| at.checked_add_signed(i64::from(off)))?
                };
                let name = if flags & DIRECT_SELECTORS != 0 {
                    rel(self, 0)
                } else {
                    rel(self, 0).and_then(|r| self.pointer(r).addr())
                };
                let types = rel(self, 4);
                let imp = rel(self, 8);
                Method {
                    name: self.string(name),
                    types: self.string(types),
                    imp: imp.unwrap_or(0),
                }
            } else {
                let name = self.pointer_field(at, 0).addr();
                let types = self.pointer_field(at, 1).addr();
                Method {
                    name: self.string(name),
                    types: self.string(types),
                    imp: self.pointer_field(at, 2).addr().unwrap_or(0),
                }
            };
            out.push(m);
        }
        out
    }

    /// The instance variable list at `list`.
    fn ivars(&mut self, list: Ptr<'d>) -> Vec<Ivar> {
        let mut out = Vec::new();
        let Some(addr) = list.addr() else { return out };
        let Some((_, size, count, first)) = self.list(addr, 3 * self.w + 8) else {
            return out;
        };
        for i in 0..count {
            let Some(at) = i.checked_mul(size).and_then(|o| first.checked_add(o)) else {
                break;
            };
            if self.bytes(at).is_none_or(|b| (b.len() as u64) < size) || !self.take() {
                break;
            }
            let offset = self.pointer_field(at, 0).addr().and_then(|a| self.u32(a));
            let name = self.pointer_field(at, 1).addr();
            let types = self.pointer_field(at, 2).addr();
            let tail = Self::field(at, 3, self.w).unwrap_or(u64::MAX);
            let alignment = self.u32(tail).unwrap_or(0);
            out.push(Ivar {
                name: self.string(name),
                types: self.string(types),
                offset,
                // (`~0` means the type's own; dyld reads it as a pointer's.)
                alignment: if alignment == u32::MAX {
                    self.w.trailing_zeros()
                } else {
                    alignment
                },
                size: tail.checked_add(4).and_then(|a| self.u32(a)).unwrap_or(0),
            });
        }
        out
    }

    /// The property list at `list`.
    fn properties(&mut self, list: Ptr<'d>) -> Vec<Property> {
        let mut out = Vec::new();
        let Some(addr) = list.addr() else { return out };
        let Some((_, size, count, first)) = self.list(addr, 2 * self.w) else {
            return out;
        };
        for i in 0..count {
            let Some(at) = i.checked_mul(size).and_then(|o| first.checked_add(o)) else {
                break;
            };
            if self.bytes(at).is_none_or(|b| (b.len() as u64) < size) || !self.take() {
                break;
            }
            let name = self.pointer_field(at, 0).addr();
            let attributes = self.pointer_field(at, 1).addr();
            out.push(Property {
                name: self.string(name),
                attributes: self.string(attributes),
            });
        }
        out
    }

    /// The names of the protocols in the protocol list at `list`.
    fn protocol_names(&mut self, list: Ptr<'d>) -> Vec<String> {
        let mut out = Vec::new();
        let Some(addr) = list.addr() else { return out };
        let Some(count) = self.uint(addr, self.w) else {
            return out;
        };
        for i in 0..count {
            let Some(at) = Self::field(addr, i + 1, self.w) else {
                break;
            };
            if self.bytes(at).is_none() || !self.take() {
                break;
            }
            let name = match self.pointer(at) {
                Ptr::Addr(p) => self.pointer_field(p, 1).addr(),
                _ => None,
            };
            out.push(self.string(name));
        }
        out
    }

    /// A class's name: its `class_ro_t`'s, or its import's.
    fn class_name(&mut self, class: Ptr<'d>) -> Option<String> {
        match class {
            Ptr::Null => None,
            Ptr::Import(symbol) => Some(
                String::from_utf8_lossy(symbol.strip_prefix(CLASS_PREFIX).unwrap_or(symbol))
                    .into_owned(),
            ),
            Ptr::Addr(c) => {
                let ro = self.ro(c)?;
                let name = self.ro_field(ro, 1).addr();
                Some(self.string(name))
            }
        }
    }

    /// Pointer field `i` of the `class_ro_t` at `ro`: after its flags,
    /// instanceStart, instanceSize (and, in 64-bit images, reserved)
    /// come ivarLayout, name, baseMethods, baseProtocols, ivars,
    /// weakIvarLayout, and baseProperties.
    fn ro_field(&self, ro: u64, i: u64) -> Ptr<'d> {
        let header = if self.w == 8 { 16 } else { 12 };
        ro.checked_add(header)
            .and_then(|a| Self::field(a, i, self.w))
            .map_or(Ptr::Null, |a| self.pointer(a))
    }

    /// The address of the `class_ro_t` of the class at `c`.
    fn ro(&self, c: u64) -> Option<u64> {
        let data = self.pointer_field(c, 4).addr()?;
        Some(data & !(if self.w == 8 { 7 } else { 3 }))
    }

    fn class(&mut self, c: u64) -> Option<Class> {
        if !self.take() {
            return None;
        }
        let raw_data = self.pointer_field(c, 4).addr()?;
        let ro = self.ro(c)?;
        let p = |r: &Self, i: u64| r.ro_field(ro, i);
        let mut class = Class {
            addr: c,
            flags: self.u32(ro)?,
            swift: raw_data & 3 != 0,
            ..Class::default()
        };
        let (start, size) = (ro.checked_add(4), ro.checked_add(8));
        class.instance_start = start.and_then(|a| self.u32(a)).unwrap_or(0);
        class.instance_size = size.and_then(|a| self.u32(a)).unwrap_or(0);
        let name = p(self, 1).addr();
        class.name = self.string(name);
        class.methods = self.methods(p(self, 2));
        class.protocols = self.protocol_names(p(self, 3));
        class.ivars = self.ivars(p(self, 4));
        class.properties = self.properties(p(self, 6));
        let superclass = self.pointer_field(c, 1);
        class.superclass = self.class_name(superclass);
        if let Some(meta) = self.pointer_field(c, 0).addr()
            && let Some(mro) = self.ro(meta)
        {
            let m = |r: &Self, i: u64| r.ro_field(mro, i);
            class.class_methods = self.methods(m(self, 2));
            class.class_properties = self.properties(m(self, 6));
        }
        Some(class)
    }

    fn category(&mut self, at: u64, class_properties: bool) -> Option<Category> {
        if !self.take() {
            return None;
        }
        let p = |r: &Self, i: u64| r.pointer_field(at, i);
        let name = p(self, 0).addr();
        let mut cat = Category {
            addr: at,
            name: self.string(name),
            ..Category::default()
        };
        cat.class = self.class_name(p(self, 1));
        cat.methods = self.methods(p(self, 2));
        cat.class_methods = self.methods(p(self, 3));
        cat.protocols = self.protocol_names(p(self, 4));
        cat.properties = self.properties(p(self, 5));
        if class_properties {
            cat.class_properties = self.properties(p(self, 6));
        }
        Some(cat)
    }

    fn protocol(&mut self, at: u64) -> Option<Protocol> {
        if !self.take() {
            return None;
        }
        // protocol_t: isa, name, protocols, instanceMethods, classMethods,
        // optionalInstanceMethods, optionalClassMethods, instanceProperties,
        // size and flags (32-bit each), extendedMethodTypes,
        // demangledName, classProperties (if its size reaches them).
        let p = |r: &Self, i: u64| r.pointer_field(at, i);
        let name = p(self, 1).addr();
        let mut proto = Protocol {
            addr: at,
            name: self.string(name),
            ..Protocol::default()
        };
        proto.protocols = self.protocol_names(p(self, 2));
        proto.methods = self.methods(p(self, 3));
        proto.class_methods = self.methods(p(self, 4));
        proto.optional_methods = self.methods(p(self, 5));
        proto.optional_class_methods = self.methods(p(self, 6));
        proto.properties = self.properties(p(self, 7));
        let size = Self::field(at, 8, self.w)
            .and_then(|a| self.u32(a))
            .unwrap_or(0);
        // (classProperties: after size and flags, and two pointers.)
        let class_properties = 8 * self.w + 8 + 2 * self.w;
        if u64::from(size) >= class_properties + self.w {
            let list = at
                .checked_add(class_properties)
                .map_or(Ptr::Null, |a| self.pointer(a));
            proto.class_properties = self.properties(list);
        }
        Some(proto)
    }

    /// The pointers of the section `name` (in any segment).
    fn section_pointers(&self, name: &[u8]) -> Vec<u64> {
        let mut out = Vec::new();
        for s in self.segments.iter().flat_map(|s| &s.sections) {
            if s.sectname != name || s.is_zerofill() {
                continue;
            }
            let n = s.size / self.w;
            for i in 0..n.min(MAX_ENTRIES as u64) {
                if let Some(a) = Self::field(s.addr, i, self.w)
                    && let Ptr::Addr(p) = self.pointer(a)
                {
                    out.push(p);
                }
            }
        }
        out
    }
}

impl MachO<'_> {
    /// The image's Objective-C metadata (empty for an object, or an image
    /// without any).
    pub fn objc(&self) -> Objc {
        let mut out = Objc::default();
        if self.is_object() {
            return out;
        }
        let mut r = Reader {
            macho: self,
            segments: self.segments(),
            fixups: self
                .fixups()
                .into_iter()
                .map(|f| (f.addr, f.kind))
                .collect(),
            w: u64::from(self.pointer_width()),
            entries: 0,
            string_bytes: 0,
            truncated: false,
        };
        for s in r.segments.iter().flat_map(|s| &s.sections) {
            if s.sectname == b"__objc_imageinfo" {
                out.image_info = r
                    .u32(s.addr)
                    .zip(s.addr.checked_add(4).and_then(|a| r.u32(a)));
            }
        }
        let category_class_properties = out
            .image_info
            .is_some_and(|(_, f)| f & HAS_CATEGORY_CLASS_PROPERTIES != 0);
        for c in r.section_pointers(b"__objc_classlist") {
            match r.class(c) {
                Some(c) => out.classes.push(c),
                None if r.truncated => break,
                None => {}
            }
        }
        for c in r.section_pointers(b"__objc_catlist") {
            match r.category(c, category_class_properties) {
                Some(c) => out.categories.push(c),
                None if r.truncated => break,
                None => {}
            }
        }
        for p in r.section_pointers(b"__objc_protolist") {
            match r.protocol(p) {
                Some(p) => out.protocols.push(p),
                None if r.truncated => break,
                None => {}
            }
        }
        out.truncated = r.truncated;
        out
    }
}

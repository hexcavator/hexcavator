//! Instrumentation manifests: the `WEVT_TEMPLATE` resource that a
//! manifest-based provider's binary carries, which describes its events.
//!
//! The layout follows the public description of the format in libyal's
//! libfwevt documentation (implemented from the description, not from its
//! code), with what that description leaves open settled by comparison
//! with TDH:
//!
//! - an item descriptor's first byte holds flags: `0x01` a struct, `0x02` a
//!   fixed length, `0x04` a length taken from another property, `0x08` a
//!   fixed count, `0x10` a count taken from another property;
//! - the count (or the index of the property holding it) is the 16 bits at
//!   offset 12, the length (or its property's index) those at offset 14;
//! - a struct's type bytes (offsets 4 to 7) hold its first member's index
//!   and its member count;
//! - a template's first count is its top-level items, its second all its
//!   descriptors, struct members included (they follow the top level).
//!
//! All offsets in the resource are relative to its start (the `CRIM`
//! header).

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_etl::Guid;

use crate::schema::{Field, Property};

/// A manifest: the providers it describes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The providers.
    pub providers: Vec<ProviderManifest>,
}

/// One provider's events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderManifest {
    /// The provider.
    pub guid: Guid,
    /// Its events.
    pub events: Vec<EventDef>,
    /// Its templates (payload layouts), which events refer to by index.
    pub templates: Vec<Template>,
    /// Task names, by task value.
    pub tasks: Vec<(u32, String)>,
    /// Opcode names, by opcode value (the high 16 bits may hold a task).
    pub opcodes: Vec<(u32, String)>,
}

/// An event's definition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventDef {
    /// The event ID.
    pub id: u16,
    /// The version.
    pub version: u8,
    /// The channel.
    pub channel: u8,
    /// The level.
    pub level: u8,
    /// The opcode.
    pub opcode: u8,
    /// The task.
    pub task: u16,
    /// The keywords.
    pub keywords: u64,
    /// The index of its template, if its payload has fields.
    pub template: Option<usize>,
}

/// A payload layout: its properties in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Template {
    /// The top-level properties.
    pub items: Vec<Item>,
}

/// One property of a template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Item {
    /// The property's name.
    pub name: String,
    /// The input type (`TDH_INTYPE_*`); 0 for a struct.
    pub in_type: u8,
    /// The output type (`TDH_OUTTYPE_*`).
    pub out_type: u8,
    /// How many values: a fixed count, or the index of the property that
    /// holds it.
    pub count: Size,
    /// Each value's size, for types whose size isn't implied: fixed, or the
    /// index of the property that holds it.
    pub length: Size,
    /// For a struct, its members.
    pub members: Vec<Item>,
    /// The descriptor's raw bytes, for diagnosing the format.
    pub raw: [u8; 20],
}

/// A count or length: fixed, or another property's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Size {
    /// A fixed value.
    Fixed(u16),
    /// The value of the property with this index.
    Property(u16),
    /// Not given.
    #[default]
    None,
}

/// The `WEVT_TEMPLATE` resource of a PE image, if it has one.
pub fn wevt_template(image: &[u8]) -> Option<&[u8]> {
    use hexcavator_pe::resources::{ResourceName, ResourceTarget};
    let pe = hexcavator_pe::PeFile::parse(image).ok()?;
    let root = pe.resource_root()?;
    let by_type = root.iter().find(|e| {
        matches!(e.name, Some(ResourceName::Name { .. }))
            && e.name.as_ref().is_some_and(|n| n.text() == "WEVT_TEMPLATE")
    })?;
    // Type, then name, then language: take the first of each.
    let mut target = by_type.target;
    for _ in 0..2 {
        let ResourceTarget::Directory(rva) = target else {
            return None;
        };
        target = pe
            .resource_directory(root.base(), rva)?
            .iter()
            .next()?
            .target;
    }
    let ResourceTarget::Data(rva) = target else {
        return None;
    };
    let entry = pe.resource_data_entry(rva)?;
    pe.bytes_at_rva(hexcavator_core::Rva(entry.data.get()), entry.size.get())
        .ok()
}

struct R<'a> {
    data: &'a [u8],
}

impl<'a> R<'a> {
    fn err(&self, at: usize, what: &'static str) -> Error {
        Error::new(ErrorKind::Malformed, at as u64, what)
    }
    fn bytes(&self, at: usize, n: usize, what: &'static str) -> Result<&'a [u8]> {
        at.checked_add(n)
            .and_then(|end| self.data.get(at..end))
            .ok_or(Error::new(ErrorKind::Truncated, at as u64, what))
    }
    fn u8(&self, at: usize) -> Result<u8> {
        Ok(self.bytes(at, 1, "u8")?[0])
    }
    fn u16(&self, at: usize) -> Result<u16> {
        let b = self.bytes(at, 2, "u16")?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&self, at: usize) -> Result<u32> {
        let b = self.bytes(at, 4, "u32")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&self, at: usize) -> Result<u64> {
        let b = self.bytes(at, 8, "u64")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn off(&self, at: usize) -> Result<usize> {
        Ok(self.u32(at)? as usize)
    }
    fn sig(&self, at: usize, sig: &[u8; 4], what: &'static str) -> Result<()> {
        if self.bytes(at, 4, what)? != sig {
            return Err(self.err(at, what));
        }
        Ok(())
    }
    /// A string: a 32-bit size (itself included), then UTF-16 with a NUL.
    fn string(&self, at: usize) -> Result<String> {
        let size = self.off(at)?;
        if size < 4 {
            return Err(self.err(at, "manifest string size"));
        }
        let b = self.bytes(at + 4, size - 4, "manifest string")?;
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
    /// A count of `item`-byte entries that must fit in the data.
    fn count(&self, at: usize, item: usize, what: &'static str) -> Result<usize> {
        let n = self.off(at)?;
        if n.checked_mul(item).is_none_or(|b| b > self.data.len()) {
            return Err(self.err(at, what));
        }
        Ok(n)
    }
}

/// How deeply structs may nest.
const MAX_NESTING: usize = 8;

impl Manifest {
    /// Parses a `WEVT_TEMPLATE` resource.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let r = R { data };
        r.sig(0, b"CRIM", "CRIM signature")?;
        let n = r.count(12, 20, "provider count")?;
        let mut providers = Vec::with_capacity(n);
        for i in 0..n {
            let at = 16 + 20 * i;
            let g = r.bytes(at, 16, "provider GUID")?;
            let mut a = [0u8; 16];
            a.copy_from_slice(g);
            let guid = Guid::from_bytes(&a);
            let offset = r.off(at + 16)?;
            providers.push(provider(&r, guid, offset)?);
        }
        Ok(Self { providers })
    }

    /// The manifest of `guid`.
    pub fn provider(&self, guid: &Guid) -> Option<&ProviderManifest> {
        self.providers.iter().find(|p| p.guid == *guid)
    }
}

impl ProviderManifest {
    /// The definition of event `id` with `version`.
    pub fn event(&self, id: u16, version: u8) -> Option<&EventDef> {
        self.events
            .iter()
            .find(|e| e.id == id && e.version == version)
    }

    /// The template of an event.
    pub fn template(&self, event: &EventDef) -> Option<&Template> {
        event.template.and_then(|t| self.templates.get(t))
    }
}

fn provider(r: &R<'_>, guid: Guid, at: usize) -> Result<ProviderManifest> {
    r.sig(at, b"WEVT", "WEVT signature")?;
    let n = r.count(at + 12, 8, "element count")?;
    let mut p = ProviderManifest {
        guid,
        ..ProviderManifest::default()
    };
    let mut template_offsets: Vec<usize> = Vec::new();
    let mut events: Vec<(EventDef, usize)> = Vec::new();
    for i in 0..n {
        let e = r.off(at + 20 + 8 * i)?;
        match r.bytes(e, 4, "element signature")? {
            b"TTBL" => {
                let count = r.count(e + 8, 40, "template count")?;
                // Templates follow the header, one after another.
                let mut t = e + 12;
                for _ in 0..count {
                    r.sig(t, b"TEMP", "TEMP signature")?;
                    template_offsets.push(t);
                    let size = r.off(t + 4)?;
                    if size < 40 {
                        return Err(r.err(t, "template size"));
                    }
                    t = t.checked_add(size).ok_or(r.err(t, "template size"))?;
                }
            }
            b"EVNT" => {
                let count = r.count(e + 8, 48, "event count")?;
                for j in 0..count {
                    let d = e + 16 + 48 * j;
                    events.push((
                        EventDef {
                            id: r.u16(d)?,
                            version: r.u8(d + 2)?,
                            channel: r.u8(d + 3)?,
                            level: r.u8(d + 4)?,
                            opcode: r.u8(d + 5)?,
                            task: r.u16(d + 6)?,
                            keywords: r.u64(d + 8)?,
                            template: None,
                        },
                        r.off(d + 20)?,
                    ));
                }
            }
            b"TASK" => {
                let count = r.count(e + 8, 28, "task count")?;
                for j in 0..count {
                    let d = e + 12 + 28 * j;
                    p.tasks.push((r.u32(d)?, r.string(r.off(d + 24)?)?));
                }
            }
            b"OPCO" => {
                let count = r.count(e + 8, 12, "opcode count")?;
                for j in 0..count {
                    let d = e + 12 + 12 * j;
                    p.opcodes.push((r.u32(d)?, r.string(r.off(d + 8)?)?));
                }
            }
            _ => {}
        }
    }
    for t in &template_offsets {
        p.templates.push(template(r, *t)?);
    }
    for (mut def, toff) in events {
        if toff != 0 {
            def.template = template_offsets.iter().position(|&t| t == toff);
        }
        p.events.push(def);
    }
    Ok(p)
}

fn template(r: &R<'_>, at: usize) -> Result<Template> {
    let top = r.count(at + 8, 20, "item count")?;
    let total = r.count(at + 12, 20, "descriptor count")?.max(top);
    let items_at = r.off(at + 16)?;
    let mut all = Vec::with_capacity(total);
    for i in 0..total {
        all.push(item(r, items_at + 20 * i)?);
    }
    Ok(Template {
        items: nest(&all, 0..top, 0)?,
    })
}

fn item(r: &R<'_>, at: usize) -> Result<Item> {
    let raw_bytes = r.bytes(at, 20, "item")?;
    let mut raw = [0u8; 20];
    raw.copy_from_slice(raw_bytes);
    let flags = raw[0];
    let count_field = r.u16(at + 12)?;
    let length_field = r.u16(at + 14)?;
    let count = if flags & FLAG_COUNT_PARAM != 0 {
        Size::Property(count_field)
    } else if flags & FLAG_FIXED_COUNT != 0 {
        Size::Fixed(count_field)
    } else {
        Size::None
    };
    let length = if flags & FLAG_LENGTH_PARAM != 0 {
        Size::Property(length_field)
    } else if flags & FLAG_FIXED_LENGTH != 0 {
        Size::Fixed(length_field)
    } else {
        Size::None
    };
    Ok(Item {
        name: r.string(r.off(at + 16)?)?,
        in_type: raw[4],
        out_type: raw[5],
        count,
        length,
        members: Vec::new(),
        raw,
    })
}

/// Item flags (the descriptor's first byte).
const FLAG_STRUCT: u8 = 0x01;
const FLAG_FIXED_LENGTH: u8 = 0x02;
const FLAG_LENGTH_PARAM: u8 = 0x04;
const FLAG_FIXED_COUNT: u8 = 0x08;
const FLAG_COUNT_PARAM: u8 = 0x10;

/// The items `range` of `all`, with each struct's members (which it names
/// by index into `all`) under it.
fn nest(all: &[Item], range: std::ops::Range<usize>, depth: usize) -> Result<Vec<Item>> {
    if depth > MAX_NESTING {
        return Err(Error::new(ErrorKind::Malformed, 0, "struct nesting"));
    }
    let mut out = Vec::with_capacity(range.len());
    for i in range {
        let mut it = all
            .get(i)
            .ok_or(Error::new(ErrorKind::Malformed, 0, "struct members"))?
            .clone();
        if it.raw[0] & FLAG_STRUCT != 0 {
            let first = usize::from(u16::from_le_bytes([it.raw[4], it.raw[5]]));
            let count = usize::from(u16::from_le_bytes([it.raw[6], it.raw[7]]));
            let end = first
                .checked_add(count)
                .filter(|&e| e <= all.len() && first > i)
                .ok_or(Error::new(ErrorKind::Malformed, 0, "struct members"))?;
            it.in_type = 0;
            it.out_type = 0;
            it.members = nest(all, first..end, depth + 1)?;
        }
        out.push(it);
    }
    Ok(out)
}

/// Decodes a payload by a template: each top-level property's bytes (an
/// array's or a struct's, all of its values together). `ptr` is the
/// pointer size.
pub fn decode<'a>(template: &Template, data: &'a [u8], ptr: usize) -> Result<Vec<Property<'a>>> {
    let mut d = Decoder { data, pos: 0, ptr };
    let mut out: Vec<Property<'a>> = Vec::with_capacity(template.items.len());
    let mut values: Vec<u64> = Vec::with_capacity(template.items.len());
    for item in &template.items {
        let start = d.pos;
        d.item(item, &values, 0)?;
        let bytes = &data[start..d.pos];
        values.push(int_value(item.in_type, bytes));
        out.push(Property {
            name: item.name.clone(),
            field: Field::Typed {
                in_type: item.in_type,
                out_type: item.out_type,
            },
            data: bytes,
        });
    }
    Ok(out)
}

/// A property's value as an integer, for counts and lengths that refer to
/// it (0 for what isn't an integer).
fn int_value(in_type: u8, b: &[u8]) -> u64 {
    let n = match in_type {
        3 | 4 => 1,
        5 | 6 => 2,
        7 | 8 | 13 | 20 => 4,
        9 | 10 | 21 => 8,
        _ => return 0,
    };
    let mut a = [0u8; 8];
    if b.len() >= n {
        a[..n].copy_from_slice(&b[..n]);
    }
    u64::from_le_bytes(a)
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    ptr: usize,
}

impl Decoder<'_> {
    fn err(&self, what: &'static str) -> Error {
        Error::new(ErrorKind::Truncated, self.pos as u64, what)
    }

    fn take(&mut self, n: usize) -> Result<()> {
        if n > self.data.len() - self.pos {
            return Err(self.err("manifest property"));
        }
        self.pos += n;
        Ok(())
    }

    fn resolve(size: Size, values: &[u64]) -> Option<u64> {
        match size {
            Size::Fixed(n) => Some(u64::from(n)),
            Size::Property(i) => values.get(usize::from(i)).copied(),
            Size::None => None,
        }
    }

    /// One property: `count` values (one if none), or a struct's members
    /// `count` times.
    fn item(&mut self, item: &Item, values: &[u64], depth: usize) -> Result<()> {
        if depth > MAX_NESTING {
            return Err(self.err("struct nesting"));
        }
        let count = Self::resolve(item.count, values).unwrap_or(1);
        let length = Self::resolve(item.length, values);
        for _ in 0..count {
            let before = self.pos;
            if item.members.is_empty() && item.in_type != 0 {
                self.value(item.in_type, length)?;
            } else {
                // Members' counts and lengths refer to the struct's own
                // members.
                let mut inner: Vec<u64> = Vec::with_capacity(item.members.len());
                for m in &item.members {
                    let start = self.pos;
                    self.item(m, &inner, depth + 1)?;
                    inner.push(int_value(m.in_type, &self.data[start..self.pos]));
                }
            }
            // A value that takes no bytes would repeat forever under a
            // hostile count.
            if self.pos == before {
                break;
            }
        }
        Ok(())
    }

    /// One value of `in_type`; `length` is its length where the type needs
    /// one (characters for strings, bytes otherwise).
    fn value(&mut self, in_type: u8, length: Option<u64>) -> Result<()> {
        let rest = &self.data[self.pos..];
        let len = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
        let n = match in_type {
            // Unicode string: `length` characters, or to a NUL.
            1 => match length {
                Some(chars) => len(chars).saturating_mul(2),
                None => utf16z_len(rest),
            },
            // ANSI string: `length` bytes, or to a NUL.
            2 => match length {
                Some(bytes) => len(bytes),
                None => rest
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(rest.len(), |i| i + 1),
            },
            3 | 4 | 29 => 1,
            5 | 6 | 28 => 2,
            7 | 8 | 11 | 13 | 20 => 4,
            9 | 10 | 12 | 17 | 21 => 8,
            15 | 18 => 16,
            16 | 30 => self.ptr,
            // Binary and hex dumps: `length` bytes.
            14 => len(length.ok_or(self.err("binary without a length"))?),
            // A SID: 8 bytes, then 4 per sub-authority.
            19 => {
                let subs = usize::from(*rest.get(1).ok_or(self.err("SID"))?);
                8 + 4 * subs
            }
            // Counted strings: a 16-bit byte count, then the text.
            22 | 23 => {
                let b = rest.get(..2).ok_or(self.err("counted string"))?;
                2 + usize::from(u16::from_le_bytes([b[0], b[1]]))
            }
            // Reversed (big-endian) counts.
            24 | 25 => {
                let b = rest.get(..2).ok_or(self.err("counted string"))?;
                2 + usize::from(u16::from_be_bytes([b[0], b[1]]))
            }
            // Strings to the end of the payload.
            26 | 27 => rest.len(),
            // A hex dump: a 32-bit byte count, then the bytes.
            31 => {
                let b = rest.get(..4).ok_or(self.err("hex dump"))?;
                4 + len(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    self.pos as u64,
                    "input type",
                ));
            }
        };
        self.take(n)
    }
}

/// The length of a NUL-terminated UTF-16 string, NUL included; an
/// unterminated one runs to the end.
fn utf16z_len(b: &[u8]) -> usize {
    let mut i = 0;
    while i + 2 <= b.len() {
        i += 2;
        if b[i - 2] == 0 && b[i - 1] == 0 {
            return i;
        }
    }
    b.len() & !1
}

/// Manifests by provider, gathered from binaries.
#[derive(Clone, Debug, Default)]
pub struct Manifests {
    providers: std::collections::HashMap<Guid, ProviderManifest>,
}

impl Manifests {
    /// Adds the providers of a `WEVT_TEMPLATE` resource; returns how many.
    pub fn add_wevt(&mut self, wevt: &[u8]) -> Result<usize> {
        let m = Manifest::parse(wevt)?;
        let n = m.providers.len();
        for p in m.providers {
            self.providers.insert(p.guid, p);
        }
        Ok(n)
    }

    /// Adds the providers of a PE image's manifest, if it has one.
    pub fn add_image(&mut self, image: &[u8]) -> Result<usize> {
        match wevt_template(image) {
            Some(w) => self.add_wevt(w),
            None => Ok(0),
        }
    }

    /// The manifest of `guid`.
    pub fn get(&self, guid: &Guid) -> Option<&ProviderManifest> {
        self.providers.get(guid)
    }

    /// The number of providers.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Decodes a manifest-based event's payload, if its provider's manifest
    /// defines the event.
    pub fn decode<'a>(
        &self,
        event: &hexcavator_etl::Event<'a>,
    ) -> Option<Result<Vec<Property<'a>>>> {
        let provider = self.get(&event.provider)?;
        let def = provider.event(event.descriptor.id, event.descriptor.version)?;
        let Some(template) = provider.template(def) else {
            return Some(Ok(Vec::new()));
        };
        let ptr = crate::schema::pointer_size(event);
        Some(decode(template, event.user_data, ptr))
    }
}

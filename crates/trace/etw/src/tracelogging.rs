//! TraceLogging: events that describe themselves. Each carries its schema
//! in an extended data item (`EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL`), as
//! `TraceLoggingProvider.h` lays it out:
//!
//! - the schema's size (16 bits, itself included);
//! - the event's tags: bytes of 7 bits each, the high bit saying another
//!   follows;
//! - the event's name, NUL-terminated UTF-8;
//! - each field: its name (NUL-terminated UTF-8), its input type byte (the
//!   type in the low 5 bits; `0x20` a constant-count array, `0x40` a
//!   variable-count array, `0x60` a custom-serialized value; `0x80` an
//!   output type byte follows), the output type byte (`0x80`: field tags
//!   follow, as the event's), then for a constant-count array its count
//!   (16 bits), and for a custom value its protocol, schema size and
//!   schema. A struct (input type 24) holds the next fields, as many as
//!   its output type byte says.
//!
//! In the payload, a variable-count array starts with its count (16 bits),
//! binary values with their size in bytes (16 bits), counted strings with
//! theirs. A schema becomes a [`Template`] with those counts and sizes as
//! properties of their own (`<name>.Count`, `<name>.Length`), as TDH shows
//! them, so the manifest decoder reads it.

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_etl::Event;
use hexcavator_etl::event::ext_type;

use crate::manifest::{Decoded, Item, Size, Template, decode_partial};

/// An event's own description.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schema {
    /// The event's name.
    pub name: String,
    /// The event's tags.
    pub tags: u32,
    /// The payload's layout.
    pub template: Template,
}

/// Input types.
const STRUCT: u8 = 24;
const BINARY: u8 = 14;
const COUNTED_BINARY: u8 = 25;
/// Input type flags.
const TYPE_MASK: u8 = 0x1f;
const COUNT_MASK: u8 = 0x60;
const CONSTANT_COUNT: u8 = 0x20;
const VARIABLE_COUNT: u8 = 0x40;
const CUSTOM: u8 = 0x60;
const CHAIN: u8 = 0x80;
/// How deeply structs may nest.
const MAX_NESTING: usize = 8;

impl Schema {
    /// The schema `event` carries, if it is a TraceLogging event.
    pub fn of(event: &Event<'_>) -> Option<Result<Self>> {
        let item = event
            .extended_data()
            .flatten()
            .find(|x| x.ext_type == ext_type::EVENT_SCHEMA_TL)?;
        Some(Self::parse(item.data))
    }

    /// Reads a schema.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let size = usize::from(u16::from_le_bytes([
            *data.first().ok_or(err(0, "TraceLogging schema"))?,
            *data.get(1).ok_or(err(1, "TraceLogging schema"))?,
        ]));
        if size < 2 || size > data.len() {
            return Err(err(0, "TraceLogging schema size"));
        }
        let mut r = R {
            data: &data[..size],
            pos: 2,
        };
        let tags = r.tags()?;
        let name = r.str()?;
        let mut fields = Vec::new();
        while r.pos < r.data.len() {
            fields.push(r.field()?);
        }
        let mut at = 0;
        let items = items(&fields, &mut at, None, 0)?;
        Ok(Self {
            name,
            tags,
            template: Template { items },
        })
    }

    /// Decodes `event`'s payload by this schema, as far as it goes.
    pub fn decode<'a>(&self, event: &Event<'a>) -> Decoded<'a> {
        decode_partial(
            &self.template,
            event.user_data,
            crate::schema::pointer_size(event),
        )
    }
}

/// One field as the schema has it.
struct Field {
    name: String,
    in_type: u8,
    out_type: u8,
    count: Option<u16>,
}

/// The template items of `n` fields from `fields[*at..]` (all that are
/// left, for none: the top level); a struct's members follow it.
fn items(fields: &[Field], at: &mut usize, n: Option<usize>, depth: usize) -> Result<Vec<Item>> {
    if depth > MAX_NESTING {
        return Err(err(0, "TraceLogging struct nesting"));
    }
    let mut out = Vec::new();
    let mut taken = 0;
    while n.map_or(*at < fields.len(), |n| taken < n) {
        taken += 1;
        let f = fields
            .get(*at)
            .ok_or(err(0, "TraceLogging struct fields"))?;
        *at += 1;
        let base = f.in_type & TYPE_MASK;
        let mut item = Item {
            name: f.name.clone(),
            ..Item::default()
        };
        // An array's count: fixed, or a property of its own just before.
        match f.in_type & COUNT_MASK {
            CONSTANT_COUNT => item.count = Size::Fixed(f.count.unwrap_or(0)),
            VARIABLE_COUNT => {
                out.push(Item {
                    name: format!("{}.Count", f.name),
                    in_type: 6,
                    ..Item::default()
                });
                item.count = Size::Property(index(out.len() - 1)?);
            }
            _ => {}
        }
        if base == STRUCT {
            let members = usize::from(f.out_type & !CHAIN);
            item.members = items(fields, at, Some(members), depth + 1)?;
        } else if base == BINARY || base == COUNTED_BINARY {
            // Its size, a property of its own just before (one size for
            // all of an array's values: a TDH limit too).
            out.push(Item {
                name: format!("{}.Length", f.name),
                in_type: 6,
                ..Item::default()
            });
            item.in_type = BINARY;
            item.length = Size::Property(index(out.len() - 1)?);
            item.out_type = f.out_type & !CHAIN;
        } else {
            item.in_type = base;
            item.out_type = f.out_type & !CHAIN;
        }
        out.push(item);
    }
    Ok(out)
}

fn index(i: usize) -> Result<u16> {
    u16::try_from(i).map_err(|_| err(0, "TraceLogging field count"))
}

fn err(at: usize, what: &'static str) -> Error {
    Error::new(ErrorKind::Malformed, at as u64, what)
}

struct R<'a> {
    data: &'a [u8],
    pos: usize,
}

impl R<'_> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or(Error::new(
            ErrorKind::Truncated,
            self.pos as u64,
            "TraceLogging schema",
        ))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }

    /// Tags: 7 bits a byte, the high bit saying another follows (up to
    /// four bytes, 28 bits).
    fn tags(&mut self) -> Result<u32> {
        let mut tags = 0u32;
        for i in 0..4 {
            let b = self.u8()?;
            tags |= u32::from(b & 0x7f) << (21 - 7 * i);
            if b & 0x80 == 0 {
                return Ok(tags);
            }
        }
        Err(err(self.pos, "TraceLogging tags"))
    }

    fn str(&mut self) -> Result<String> {
        let rest = &self.data[self.pos..];
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(err(self.pos, "TraceLogging name"))?;
        let s = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.pos += end + 1;
        Ok(s)
    }

    fn field(&mut self) -> Result<Field> {
        let name = self.str()?;
        let in_type = self.u8()?;
        let mut out_type = 0;
        if in_type & CHAIN != 0 {
            out_type = self.u8()?;
            if out_type & CHAIN != 0 {
                self.tags()?;
            }
        }
        let mut count = None;
        match in_type & COUNT_MASK {
            CONSTANT_COUNT => count = Some(self.u16()?),
            CUSTOM => {
                // (A custom serializer's protocol and schema: its values
                // can't be decoded without it.)
                let _protocol = self.u16()?;
                let size = usize::from(self.u16()?);
                if size > self.data.len() - self.pos {
                    return Err(err(self.pos, "TraceLogging custom schema"));
                }
                self.pos += size;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    self.pos as u64,
                    "TraceLogging custom-serialized field",
                ));
            }
            _ => {}
        }
        Ok(Field {
            name,
            in_type: in_type & !CHAIN,
            out_type,
            count,
        })
    }
}

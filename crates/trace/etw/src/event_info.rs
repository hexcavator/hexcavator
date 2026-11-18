//! Events described as TDH describes them (`TRACE_EVENT_INFO`): what WPR
//! and xperf record when they merge a trace, as `EventMetadata` events, for
//! each kind of event in it whose provider was registered on the machine
//! that recorded it. With them a trace's events decode anywhere, without
//! the providers' manifests (the schemas are captured at record time).
//!
//! The layout is TDH's (`tdh.h`): the provider and event GUIDs, the event
//! descriptor, the decoding source, offsets of names (UTF-16, from the
//! start), the property counts and flags, then the properties
//! (`EVENT_PROPERTY_INFO`, 24 bytes each: flags, name offset, in and out
//! types or a struct's first member and member count, a map name or
//! custom schema offset, count, length, tags). The first
//! `TopLevelPropertyCount` properties are the top level; a struct names
//! its members by their index in the array, and a count or length that is
//! another property's value names that property by its index.

use std::collections::HashMap;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_etl::{Event, Guid};

use crate::manifest::{Decoded, Item, Size, Template, decode, decode_partial};
use crate::schema::Property;

/// The `EventMetadata` events' opcode for an event's `TRACE_EVENT_INFO`.
pub const EVENT_INFO_OPCODE: u8 = 32;

/// An event's description.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventInfo {
    /// The provider.
    pub provider: Guid,
    /// The event's GUID (classic events: their class).
    pub event_guid: Guid,
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
    /// Where the description came from (`DECODING_SOURCE`: 0 a manifest,
    /// 1 WMI (MOF), 2 WPP, 3 TraceLogging).
    pub decoding_source: u32,
    /// The provider's name.
    pub provider_name: Option<String>,
    /// The level's name.
    pub level_name: Option<String>,
    /// The channel's name.
    pub channel_name: Option<String>,
    /// The keywords' names.
    pub keywords_name: Option<String>,
    /// The task's name.
    pub task_name: Option<String>,
    /// The opcode's name.
    pub opcode_name: Option<String>,
    /// The event's name (manifest and TraceLogging events).
    pub event_name: Option<String>,
    /// The payload's layout.
    pub template: Template,
}

/// Property flags (`PROPERTY_FLAGS`).
const STRUCT: u32 = 0x1;
const PARAM_LENGTH: u32 = 0x2;
const PARAM_COUNT: u32 = 0x4;
const FIXED_LENGTH: u32 = 0x10;
const FIXED_COUNT: u32 = 0x20;

/// The header's size, before the properties.
const HEADER: usize = 112;
/// A property's size.
const PROPERTY: usize = 24;
/// How deeply structs may nest.
const MAX_NESTING: usize = 8;

/// One property as the array has it.
struct Raw {
    flags: u32,
    name: String,
    in_type: u16,
    out_type: u16,
    first: u16,
    members: u16,
    count: u16,
    length: u16,
}

impl EventInfo {
    /// Reads a `TRACE_EVENT_INFO`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let r = R { data };
        let mut info = Self {
            provider: r.guid(0)?,
            event_guid: r.guid(16)?,
            id: r.u16(32)?,
            version: r.u8(34)?,
            channel: r.u8(35)?,
            level: r.u8(36)?,
            opcode: r.u8(37)?,
            task: r.u16(38)?,
            keywords: r.u64(40)?,
            decoding_source: r.u32(48)?,
            provider_name: r.name_at(52)?,
            level_name: r.name_at(56)?,
            channel_name: r.name_at(60)?,
            keywords_name: r.name_at(64)?,
            task_name: r.name_at(68)?,
            opcode_name: r.name_at(72)?,
            ..Self::default()
        };
        // (The event's name, for the sources that have one; for WMI, an
        // activity ID's name.)
        if info.decoding_source != 1 {
            info.event_name = r.name_at(92)?;
        }
        let count = r.u32(100)? as usize;
        let top = r.u32(104)? as usize;
        if count > (data.len().saturating_sub(HEADER)) / PROPERTY || top > count {
            return Err(Error::new(
                ErrorKind::Malformed,
                100,
                "event info property count",
            ));
        }
        let mut all = Vec::with_capacity(count);
        for i in 0..count {
            let at = HEADER + PROPERTY * i;
            let flags = r.u32(at)?;
            all.push(Raw {
                flags,
                name: r.name_at(at + 4)?.unwrap_or_default(),
                in_type: r.u16(at + 8)?,
                out_type: r.u16(at + 10)?,
                first: r.u16(at + 8)?,
                members: r.u16(at + 10)?,
                count: r.u16(at + 16)?,
                length: r.u16(at + 18)?,
            });
        }
        info.template = Template {
            items: items(&all, 0..top, 0)?,
        };
        Ok(info)
    }

    /// Decodes `event`'s payload by this description: each top-level
    /// property's bytes; an error if one doesn't fit.
    pub fn decode<'a>(&self, event: &Event<'a>) -> Result<Vec<Property<'a>>> {
        decode(
            &self.template,
            event.user_data,
            crate::schema::pointer_size(event),
        )
    }

    /// Decodes `event`'s payload as far as it goes (see
    /// [`decode_partial`]): a sender of an older layout leaves out the last
    /// properties, a newer one adds bytes after them.
    pub fn decode_partial<'a>(&self, event: &Event<'a>) -> Decoded<'a> {
        decode_partial(
            &self.template,
            event.user_data,
            crate::schema::pointer_size(event),
        )
    }
}

/// The properties `range` of `all`, a struct's members under it. Counts
/// and lengths that name other properties are made relative to the range
/// (the decoder reads them among the properties before, at that level).
fn items(all: &[Raw], range: std::ops::Range<usize>, depth: usize) -> Result<Vec<Item>> {
    if depth > MAX_NESTING {
        return Err(Error::new(
            ErrorKind::Malformed,
            0,
            "event info struct nesting",
        ));
    }
    let base = range.start;
    let relative = |i: u16| {
        usize::from(i)
            .checked_sub(base)
            .and_then(|r| u16::try_from(r).ok())
            .map_or(Size::None, Size::Property)
    };
    let mut out = Vec::with_capacity(range.len());
    for i in range {
        let p = all
            .get(i)
            .ok_or(Error::new(ErrorKind::Malformed, 0, "event info property"))?;
        let count = if p.flags & PARAM_COUNT != 0 {
            relative(p.count)
        } else if p.flags & FIXED_COUNT != 0 || p.count > 1 {
            Size::Fixed(p.count)
        } else {
            Size::None
        };
        let mut item = Item {
            name: p.name.clone(),
            count,
            ..Item::default()
        };
        if p.flags & STRUCT != 0 {
            let first = usize::from(p.first);
            let end = first
                .checked_add(usize::from(p.members))
                .filter(|&e| e <= all.len() && first > i)
                .ok_or(Error::new(
                    ErrorKind::Malformed,
                    0,
                    "event info struct members",
                ))?;
            item.members = items(all, first..end, depth + 1)?;
        } else {
            item.in_type = u8::try_from(p.in_type)
                .map_err(|_| Error::new(ErrorKind::Unsupported, 0, "event info input type"))?;
            item.out_type = u8::try_from(p.out_type).unwrap_or(0);
            item.length = if p.flags & PARAM_LENGTH != 0 {
                relative(p.length)
            } else if p.flags & FIXED_LENGTH != 0
                || (p.length > 0 && matches!(item.in_type, 1 | 2 | 14))
            {
                // (A string's or binary's fixed length; other types'
                // lengths are their sizes.)
                Size::Fixed(p.length)
            } else {
                Size::None
            };
        }
        out.push(item);
    }
    Ok(out)
}

struct R<'a> {
    data: &'a [u8],
}

impl R<'_> {
    fn bytes(&self, at: usize, n: usize) -> Result<&[u8]> {
        self.data.get(at..at.saturating_add(n)).ok_or(Error::new(
            ErrorKind::Truncated,
            at as u64,
            "event info",
        ))
    }
    fn u8(&self, at: usize) -> Result<u8> {
        Ok(self.bytes(at, 1)?[0])
    }
    fn u16(&self, at: usize) -> Result<u16> {
        let b = self.bytes(at, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&self, at: usize) -> Result<u32> {
        let b = self.bytes(at, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&self, at: usize) -> Result<u64> {
        let b = self.bytes(at, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn guid(&self, at: usize) -> Result<Guid> {
        let b: [u8; 16] = self.bytes(at, 16)?.try_into().expect("16 bytes");
        Ok(Guid::from_bytes(&b))
    }
    /// The NUL-terminated UTF-16 name at the offset stored at `at` (none
    /// for offset 0).
    fn name_at(&self, at: usize) -> Result<Option<String>> {
        let off = self.u32(at)? as usize;
        if off == 0 {
            return Ok(None);
        }
        let rest = self.data.get(off..).ok_or(Error::new(
            ErrorKind::Malformed,
            at as u64,
            "event info name offset",
        ))?;
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        Ok(Some(String::from_utf16_lossy(&units)))
    }
}

/// Event descriptions by kind: (provider, ID, version, opcode). (Classic
/// events all have ID 0: their opcode tells them apart.)
#[derive(Clone, Debug, Default)]
pub struct EventInfos {
    infos: HashMap<(Guid, u16, u8, u8), EventInfo>,
}

impl EventInfos {
    /// Adds a description (replacing one of the same kind).
    pub fn add(&mut self, info: EventInfo) {
        self.infos
            .insert((info.provider, info.id, info.version, info.opcode), info);
    }

    /// Adds `event`'s description if it is an `EventMetadata` event that
    /// carries one; whether it did.
    pub fn add_metadata(&mut self, event: &Event<'_>) -> Result<bool> {
        if event.provider != crate::guids::EVENT_METADATA
            || event.descriptor.opcode != EVENT_INFO_OPCODE
        {
            return Ok(false);
        }
        self.add(EventInfo::parse(event.user_data)?);
        Ok(true)
    }

    /// The description of `event`'s kind.
    pub fn get(&self, event: &Event<'_>) -> Option<&EventInfo> {
        let d = &event.descriptor;
        self.infos.get(&(event.provider, d.id, d.version, d.opcode))
    }

    /// The descriptions, in no order.
    pub fn iter(&self) -> impl Iterator<Item = &EventInfo> {
        self.infos.values()
    }

    /// How many.
    pub fn len(&self) -> usize {
        self.infos.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }
}

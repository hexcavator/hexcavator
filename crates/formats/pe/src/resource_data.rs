//! What resources hold, decoded: string tables, message tables, dialogs,
//! menus, accelerator tables, icon and cursor groups (and the `.ico` and
//! `.cur` files they make with their images), and bitmaps (as `.bmp`
//! files). The layouts are the resource compiler's (`winuser.h`'s
//! `DLGTEMPLATE`, `MENUITEMTEMPLATE`, `ACCEL`; `winnt.h`'s
//! `MESSAGE_RESOURCE_DATA`; the icon group's `NEWHEADER`).
//!
//! Hostile data ends a decoding (with what was read before it), never
//! panics; counts in headers bound nothing that's allocated.

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::Reader;

/// The most items read of one resource (strings, messages, controls, menu
/// items, accelerators, images).
const MAX_ITEMS: usize = 1 << 16;
/// How deep menus nest at most.
const MAX_MENU_DEPTH: usize = 32;

/// A name, or an ordinal (`sz_Or_Ord`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameOrId {
    None,
    Id(u16),
    Name(String),
}

/// A NUL-terminated UTF-16 string at `r`, its terminator read too.
fn wstr(r: &mut Reader<'_>) -> Option<String> {
    let mut units = Vec::new();
    loop {
        let u = r.u16_le().ok()?;
        if u == 0 {
            break;
        }
        units.push(u);
        if units.len() > 1 << 16 {
            return None;
        }
    }
    Some(String::from_utf16_lossy(&units))
}

/// An `sz_Or_Ord`: 0 (none), `0xFFFF` and an ordinal, or a string.
fn name_or_id(r: &mut Reader<'_>) -> Option<NameOrId> {
    let first = r.remaining().get(..2)?;
    match u16::from_le_bytes([first[0], first[1]]) {
        0 => {
            r.skip(2).ok()?;
            Some(NameOrId::None)
        }
        0xFFFF => {
            r.skip(2).ok()?;
            Some(NameOrId::Id(r.u16_le().ok()?))
        }
        _ => Some(NameOrId::Name(wstr(r)?)),
    }
}

fn align4(r: &mut Reader<'_>) -> Option<()> {
    let at = r.position();
    let to = at.checked_add(3)? & !3;
    if to > at {
        r.skip(to - at).ok()?;
    }
    Some(())
}

/// A string table block (`RT_STRING`): resource `block` holds the strings
/// with IDs `(block - 1) * 16` to `+ 15`, each a count and its UTF-16
/// characters. Empty strings (absent IDs) are left out.
pub fn string_table(data: &[u8], block: u16) -> Vec<(u32, String)> {
    let mut r = Reader::new(data);
    let first = u32::from(block.saturating_sub(1)) * 16;
    let mut out = Vec::new();
    for i in 0..16 {
        let Ok(len) = r.u16_le() else { break };
        let Ok(units) = r.bytes(usize::from(len) * 2) else {
            break;
        };
        if len > 0 {
            let units: Vec<u16> = units
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            out.push((first + i, String::from_utf16_lossy(&units)));
        }
    }
    out
}

/// A message (`RT_MESSAGETABLE`): its ID and text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u32,
    pub text: String,
}

/// A message table: blocks of ID ranges, each range's entries a length,
/// flags (1: UTF-16, else ANSI), and text.
pub fn message_table(data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    let Ok(blocks) = r.u32_le() else { return out };
    for b in 0..blocks.min(u32::try_from(MAX_ITEMS).unwrap_or(u32::MAX)) {
        let Some(head) = data.get(4 + b as usize * 12..4 + b as usize * 12 + 12) else {
            break;
        };
        let word = |i: usize| u32::from_le_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
        let (low, high, offset) = (word(0), word(4), word(8));
        let mut e = Reader::new(data);
        if e.skip(offset as usize).is_err() {
            continue;
        }
        let mut id = low;
        while id <= high && out.len() < MAX_ITEMS {
            let (Ok(len), Ok(flags)) = (e.u16_le(), e.u16_le()) else {
                break;
            };
            let Some(text) = usize::from(len)
                .checked_sub(4)
                .and_then(|n| e.bytes(n).ok())
            else {
                break;
            };
            let text = if flags & 1 != 0 {
                let units: Vec<u16> = text
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .take_while(|&u| u != 0)
                    .collect();
                String::from_utf16_lossy(&units)
            } else {
                let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
                String::from_utf8_lossy(&text[..end]).into_owned()
            };
            out.push(Message {
                id,
                text: String::from(text.trim_end_matches(['\r', '\n'])),
            });
            let Some(next) = id.checked_add(1) else { break };
            id = next;
        }
    }
    out
}

/// A dialog (`RT_DIALOG`, `DLGTEMPLATE` or `DLGTEMPLATEEX`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dialog {
    /// Whether it is a `DLGTEMPLATEEX`.
    pub extended: bool,
    pub style: u32,
    pub ex_style: u32,
    /// Its place and size, in dialog units.
    pub rect: (i16, i16, i16, i16),
    pub menu: NameOrId,
    pub class: NameOrId,
    pub title: String,
    /// Its font: size in points, weight, italic, face (with `DS_SETFONT`).
    pub font: Option<(u16, u16, bool, String)>,
    pub controls: Vec<Control>,
}

/// One of a dialog's controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub id: u32,
    pub style: u32,
    pub ex_style: u32,
    /// Its place and size, in dialog units.
    pub rect: (i16, i16, i16, i16),
    /// Its window class: a name, or a predefined class's atom (see
    /// [`control_class`]).
    pub class: NameOrId,
    /// Its text, or a resource (an icon's, a bitmap's) by ID.
    pub text: NameOrId,
}

/// `DS_SETFONT` and `DS_SHELLFONT` (`DS_SETFONT | DS_FIXEDSYS`).
const DS_SETFONT: u32 = 0x40;

/// A predefined control class's name, by its atom.
pub fn control_class(atom: u16) -> Option<&'static str> {
    Some(match atom {
        0x80 => "Button",
        0x81 => "Edit",
        0x82 => "Static",
        0x83 => "ListBox",
        0x84 => "ScrollBar",
        0x85 => "ComboBox",
        _ => return None,
    })
}

fn rect(r: &mut Reader<'_>) -> Option<(i16, i16, i16, i16)> {
    let mut v = [0i16; 4];
    for x in &mut v {
        *x = r.u16_le().ok()? as i16;
    }
    Some((v[0], v[1], v[2], v[3]))
}

/// Decodes a dialog template.
pub fn dialog(data: &[u8]) -> Option<Dialog> {
    let mut r = Reader::new(data);
    let extended = data.get(..4) == Some(&[1, 0, 0xFF, 0xFF]);
    let (style, ex_style, count, rect_) = if extended {
        r.skip(4).ok()?;
        let _help = r.u32_le().ok()?;
        let ex = r.u32_le().ok()?;
        let style = r.u32_le().ok()?;
        let count = r.u16_le().ok()?;
        (style, ex, count, rect(&mut r)?)
    } else {
        let style = r.u32_le().ok()?;
        let ex = r.u32_le().ok()?;
        let count = r.u16_le().ok()?;
        (style, ex, count, rect(&mut r)?)
    };
    let menu = name_or_id(&mut r)?;
    let class = name_or_id(&mut r)?;
    let title = wstr(&mut r)?;
    let font = if style & DS_SETFONT != 0 {
        let size = r.u16_le().ok()?;
        let (weight, italic) = if extended {
            let weight = r.u16_le().ok()?;
            let italic = r.u8().ok()? != 0;
            let _charset = r.u8().ok()?;
            (weight, italic)
        } else {
            (0, false)
        };
        Some((size, weight, italic, wstr(&mut r)?))
    } else {
        None
    };
    let mut controls = Vec::new();
    for _ in 0..usize::from(count).min(MAX_ITEMS) {
        let Some(c) = control(&mut r, extended) else {
            break;
        };
        controls.push(c);
    }
    Some(Dialog {
        extended,
        style,
        ex_style,
        rect: rect_,
        menu,
        class,
        title,
        font,
        controls,
    })
}

fn control(r: &mut Reader<'_>, extended: bool) -> Option<Control> {
    align4(r)?;
    let (style, ex_style, rect_, id) = if extended {
        let _help = r.u32_le().ok()?;
        let ex = r.u32_le().ok()?;
        let style = r.u32_le().ok()?;
        let rect_ = rect(r)?;
        (style, ex, rect_, r.u32_le().ok()?)
    } else {
        let style = r.u32_le().ok()?;
        let ex = r.u32_le().ok()?;
        let rect_ = rect(r)?;
        (style, ex, rect_, u32::from(r.u16_le().ok()?))
    };
    let class = name_or_id(r)?;
    let text = name_or_id(r)?;
    let extra = r.u16_le().ok()?;
    r.skip(usize::from(extra)).ok()?;
    Some(Control {
        id,
        style,
        ex_style,
        rect: rect_,
        class,
        text,
    })
}

/// A menu's item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MenuItem {
    /// A command: its text (tabs and accelerators as written) and ID.
    Command {
        text: String,
        id: u32,
        flags: u32,
    },
    /// A submenu: its text and items.
    Popup {
        text: String,
        items: Vec<MenuItem>,
        flags: u32,
    },
    Separator,
}

/// `MF_POPUP`, `MF_END`; `MENUEX`'s `MFT_SEPARATOR`.
const MF_POPUP: u16 = 0x10;
const MF_END: u16 = 0x80;
const MFT_SEPARATOR: u32 = 0x800;

/// Decodes a menu (`RT_MENU`: `MENUITEMTEMPLATE`s, or `MENUEX`'s).
pub fn menu(data: &[u8]) -> Option<Vec<MenuItem>> {
    let mut r = Reader::new(data);
    let version = r.u16_le().ok()?;
    let offset = r.u16_le().ok()?;
    let mut budget = MAX_ITEMS;
    match version {
        0 => {
            r.skip(usize::from(offset)).ok()?;
            Some(menu_items(&mut r, 0, &mut budget))
        }
        1 => {
            // (The offset is from the end of the offset's own field:
            // past the header's help ID, normally.)
            let mut r = Reader::new(data);
            r.skip(4 + usize::from(offset)).ok()?;
            Some(menuex_items(&mut r, 0, &mut budget))
        }
        _ => None,
    }
}

fn menu_items(r: &mut Reader<'_>, depth: usize, budget: &mut usize) -> Vec<MenuItem> {
    let mut out = Vec::new();
    while *budget > 0 {
        *budget -= 1;
        let Ok(flags) = r.u16_le() else { break };
        let item = if flags & MF_POPUP != 0 {
            let Some(text) = wstr(r) else { break };
            let items = if depth < MAX_MENU_DEPTH {
                menu_items(r, depth + 1, budget)
            } else {
                Vec::new()
            };
            MenuItem::Popup {
                text,
                items,
                flags: u32::from(flags),
            }
        } else {
            let (Ok(id), Some(text)) = (r.u16_le(), wstr(r)) else {
                break;
            };
            if id == 0 && text.is_empty() && flags & !MF_END == 0 {
                MenuItem::Separator
            } else {
                MenuItem::Command {
                    text,
                    id: u32::from(id),
                    flags: u32::from(flags),
                }
            }
        };
        out.push(item);
        if flags & MF_END != 0 {
            break;
        }
    }
    out
}

fn menuex_items(r: &mut Reader<'_>, depth: usize, budget: &mut usize) -> Vec<MenuItem> {
    let mut out = Vec::new();
    while *budget > 0 {
        *budget -= 1;
        let (Ok(kind), Ok(state), Ok(id), Ok(info)) =
            (r.u32_le(), r.u32_le(), r.u32_le(), r.u16_le())
        else {
            break;
        };
        let Some(text) = wstr(r) else { break };
        if align4(r).is_none() {
            break;
        }
        let item = if info & 1 != 0 {
            let _help = r.u32_le();
            let items = if depth < MAX_MENU_DEPTH {
                menuex_items(r, depth + 1, budget)
            } else {
                Vec::new()
            };
            MenuItem::Popup {
                text,
                items,
                flags: state,
            }
        } else if kind & MFT_SEPARATOR != 0 {
            MenuItem::Separator
        } else {
            MenuItem::Command {
                text,
                id,
                flags: state,
            }
        };
        out.push(item);
        if info & MF_END != 0 {
            break;
        }
    }
    out
}

/// An accelerator (`RT_ACCELERATOR`'s `ACCEL`): flags (`FVIRTKEY` 1,
/// `FSHIFT` 4, `FCONTROL` 8, `FALT` 0x10), the key (a virtual key, or a
/// character), and the command's ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accelerator {
    pub flags: u16,
    pub key: u16,
    pub id: u16,
}

/// Decodes an accelerator table: entries of 8 bytes, the last flagged.
pub fn accelerators(data: &[u8]) -> Vec<Accelerator> {
    let mut out = Vec::new();
    for e in data.as_chunks::<8>().0.iter().take(MAX_ITEMS) {
        let w = |i: usize| u16::from_le_bytes([e[i], e[i + 1]]);
        out.push(Accelerator {
            flags: w(0) & !0x80,
            key: w(2),
            id: w(4),
        });
        if w(0) & 0x80 != 0 {
            break;
        }
    }
    out
}

/// An icon or cursor group's image (`GRPICONDIRENTRY`): its size, colors
/// (icons), planes and bits per pixel (a cursor's, of its bitmap), its
/// bytes, and its `RT_ICON` or `RT_CURSOR` resource's ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupImage {
    pub width: u16,
    pub height: u16,
    pub colors: u8,
    pub planes: u16,
    pub bits: u16,
    pub bytes: u32,
    pub id: u16,
}

/// An icon or cursor group (`RT_GROUP_ICON`, `RT_GROUP_CURSOR`): whether it
/// is a cursor's, and its images.
pub fn group(data: &[u8]) -> Option<(bool, Vec<GroupImage>)> {
    let mut r = Reader::new(data);
    let _reserved = r.u16_le().ok()?;
    let kind = r.u16_le().ok()?;
    let count = r.u16_le().ok()?;
    let cursor = match kind {
        1 => false,
        2 => true,
        _ => return None,
    };
    let mut out = Vec::new();
    for _ in 0..count {
        let Ok(e) = r.bytes(14) else { break };
        let w = |i: usize| u16::from_le_bytes([e[i], e[i + 1]]);
        let bytes = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
        out.push(if cursor {
            // (A cursor's height is its bitmap's: the image and its mask.)
            GroupImage {
                width: w(0),
                height: w(2) / 2,
                colors: 0,
                planes: w(4),
                bits: w(6),
                bytes,
                id: w(12),
            }
        } else {
            // (A width or height of 0 is 256.)
            let size = |b: u8| if b == 0 { 256 } else { u16::from(b) };
            GroupImage {
                width: size(e[0]),
                height: size(e[1]),
                colors: e[2],
                planes: w(4),
                bits: w(6),
                bytes,
                id: w(12),
            }
        });
    }
    Some((cursor, out))
}

/// The `.ico` (or, `cursor`, `.cur`) file of a group's images and their
/// resources' bytes: an `ICONDIR`, its entries, then each image. A
/// cursor's resource starts with its hot spot (two 16-bit values), which
/// its entry holds in the file.
pub fn icon_file(cursor: bool, images: &[(GroupImage, &[u8])]) -> Vec<u8> {
    let mut head = Vec::new();
    let mut body = Vec::new();
    let count = u16::try_from(images.len()).unwrap_or(u16::MAX);
    head.extend_from_slice(&0u16.to_le_bytes());
    head.extend_from_slice(&(if cursor { 2u16 } else { 1u16 }).to_le_bytes());
    head.extend_from_slice(&count.to_le_bytes());
    let mut offset = 6 + 16 * u32::from(count);
    for (g, data) in &images[..usize::from(count)] {
        let (hot, bits) = if cursor && data.len() >= 4 {
            (
                (
                    u16::from_le_bytes([data[0], data[1]]),
                    u16::from_le_bytes([data[2], data[3]]),
                ),
                &data[4..],
            )
        } else {
            ((g.planes, g.bits), *data)
        };
        let byte = |v: u16| u8::try_from(v).unwrap_or(0);
        head.push(byte(g.width));
        head.push(byte(g.height));
        head.push(g.colors);
        head.push(0);
        head.extend_from_slice(&hot.0.to_le_bytes());
        head.extend_from_slice(&hot.1.to_le_bytes());
        let size = u32::try_from(bits.len()).unwrap_or(u32::MAX);
        head.extend_from_slice(&size.to_le_bytes());
        head.extend_from_slice(&offset.to_le_bytes());
        offset = offset.saturating_add(size);
        body.extend_from_slice(bits);
    }
    head.extend(body);
    head
}

/// The `.bmp` file of a bitmap resource (a DIB): a `BITMAPFILEHEADER`
/// whose offset is past the header, its color masks, and its palette.
/// `None` if `dib` isn't one.
pub fn bmp_file(dib: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(dib);
    let header = r.u32_le().ok()?;
    if !matches!(header, 12 | 40 | 52 | 56 | 64 | 108 | 124) || dib.len() < header as usize {
        return None;
    }
    let (bits, compression, used) = if header == 12 {
        // BITMAPCOREHEADER: width and height 16-bit, palette entries 3 bytes.
        r.skip(6).ok()?;
        (r.u16_le().ok()?, 0, 0)
    } else {
        r.skip(10).ok()?;
        let bits = r.u16_le().ok()?;
        let compression = r.u32_le().ok()?;
        r.skip(12).ok()?;
        (bits, compression, r.u32_le().ok()?)
    };
    let entry = if header == 12 { 3 } else { 4 };
    let colors = if used != 0 {
        used.min(256)
    } else if bits <= 8 {
        1 << bits
    } else {
        0
    };
    // (BI_BITFIELDS or BI_ALPHABITFIELDS with a BITMAPINFOHEADER: its masks
    // follow it.)
    let masks = match (header, compression) {
        (40, 3) => 12,
        (40, 6) => 16,
        _ => 0,
    };
    let offset = 14 + header + masks + colors * entry;
    let size = u32::try_from(14 + dib.len()).ok()?;
    let mut out = Vec::with_capacity(14 + dib.len());
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&offset.min(size).to_le_bytes());
    out.extend_from_slice(dib);
    Some(out)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, reason = "small test data")]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    fn w16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn w32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn wsz(out: &mut Vec<u8>, s: &str) {
        for u in s.encode_utf16() {
            w16(out, u);
        }
        w16(out, 0);
    }
    fn pad4(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    #[test]
    fn string_tables() {
        let mut d = Vec::new();
        for i in 0..16u16 {
            let s = if i == 3 {
                ""
            } else if i % 2 == 0 {
                "even"
            } else {
                "odd one"
            };
            w16(&mut d, s.encode_utf16().count() as u16);
            for u in s.encode_utf16() {
                w16(&mut d, u);
            }
        }
        let t = string_table(&d, 7);
        assert_eq!(t.len(), 15);
        assert_eq!(t[0], (96, "even".into()));
        assert_eq!(t[1], (97, "odd one".into()));
        assert_eq!(t[3].0, 100);
        // Cut short: what's there.
        assert_eq!(string_table(&d[..11], 1), [(0, String::from("even"))]);
        assert!(string_table(&d[..9], 1).is_empty());
        assert!(string_table(&[0xFF, 0xFF], 1).is_empty());
    }

    #[test]
    fn message_tables() {
        let mut d = Vec::new();
        w32(&mut d, 1);
        w32(&mut d, 100);
        w32(&mut d, 101);
        w32(&mut d, 16);
        // ANSI, then UTF-16.
        w16(&mut d, 4 + 8);
        w16(&mut d, 0);
        d.extend_from_slice(b"Hi %1\r\n\0");
        let wide: Vec<u8> = "Wide\r\n\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        w16(&mut d, 4 + wide.len() as u16);
        w16(&mut d, 1);
        d.extend_from_slice(&wide);
        let m = message_table(&d);
        assert_eq!(
            m,
            [
                Message {
                    id: 100,
                    text: "Hi %1".into()
                },
                Message {
                    id: 101,
                    text: "Wide".into()
                }
            ]
        );
        // Hostile: a count past the data, offsets past it, a length short of
        // its header, a range to u32::MAX.
        let mut h = Vec::new();
        w32(&mut h, u32::MAX);
        w32(&mut h, 0);
        w32(&mut h, u32::MAX);
        w32(&mut h, 16);
        w16(&mut h, 2);
        w16(&mut h, 0);
        assert!(message_table(&h).is_empty());
        assert!(message_table(&[]).is_empty());
    }

    /// A DLGTEMPLATE (or EX) of one button and one static icon.
    fn dialog_template(extended: bool) -> Vec<u8> {
        let mut d = Vec::new();
        let style = 0x80C8_00C0u32 | DS_SETFONT;
        if extended {
            w16(&mut d, 1);
            w16(&mut d, 0xFFFF);
            w32(&mut d, 0);
            w32(&mut d, 0);
            w32(&mut d, style);
        } else {
            w32(&mut d, style);
            w32(&mut d, 0);
        }
        w16(&mut d, 2);
        for v in [10u16, 20, 200, 100] {
            w16(&mut d, v);
        }
        w16(&mut d, 0);
        w16(&mut d, 0);
        wsz(&mut d, "About");
        w16(&mut d, 8);
        if extended {
            w16(&mut d, 400);
            d.push(1);
            d.push(1);
        }
        wsz(&mut d, "MS Shell Dlg");
        for (id, class, text) in [(1u32, 0x80u16, Some("OK")), (2, 0x82, None)] {
            pad4(&mut d);
            if extended {
                w32(&mut d, 0);
                w32(&mut d, 0);
                w32(&mut d, 0x5001_0000);
            } else {
                w32(&mut d, 0x5001_0000);
                w32(&mut d, 0);
            }
            for v in [5u16, 6, 50, 14] {
                w16(&mut d, v);
            }
            if extended {
                w32(&mut d, id);
            } else {
                w16(&mut d, id as u16);
            }
            w16(&mut d, 0xFFFF);
            w16(&mut d, class);
            match text {
                Some(t) => wsz(&mut d, t),
                None => {
                    w16(&mut d, 0xFFFF);
                    w16(&mut d, 128);
                }
            }
            w16(&mut d, 0);
        }
        d
    }

    #[test]
    fn dialogs() {
        for extended in [false, true] {
            let d = dialog(&dialog_template(extended)).unwrap();
            assert_eq!(d.extended, extended);
            assert_eq!(d.title, "About");
            assert_eq!(d.rect, (10, 20, 200, 100));
            assert_eq!(d.font.as_ref().unwrap().3, "MS Shell Dlg");
            assert_eq!(d.controls.len(), 2);
            assert_eq!(d.controls[0].class, NameOrId::Id(0x80));
            assert_eq!(d.controls[0].text, NameOrId::Name("OK".into()));
            assert_eq!(d.controls[1].text, NameOrId::Id(128));
            assert_eq!(control_class(0x82), Some("Static"));
        }
        // Cut short anywhere: what's there, or nothing; never a panic.
        let t = dialog_template(true);
        for n in 0..t.len() {
            let _ = dialog(&t[..n]);
        }
        assert!(dialog(&[]).is_none());
    }

    #[test]
    fn menus() {
        // &File > Open (100), separator, Exit (101); &Help (200).
        let mut d = Vec::new();
        w16(&mut d, 0);
        w16(&mut d, 0);
        w16(&mut d, MF_POPUP);
        wsz(&mut d, "&File");
        w16(&mut d, 0);
        w16(&mut d, 100);
        wsz(&mut d, "&Open\tCtrl+O");
        w16(&mut d, 0);
        w16(&mut d, 0);
        wsz(&mut d, "");
        w16(&mut d, MF_END);
        w16(&mut d, 101);
        wsz(&mut d, "E&xit");
        w16(&mut d, MF_END);
        w16(&mut d, 200);
        wsz(&mut d, "&Help");
        let m = menu(&d).unwrap();
        assert_eq!(m.len(), 2);
        let MenuItem::Popup { text, items, .. } = &m[0] else {
            panic!()
        };
        assert_eq!(text, "&File");
        assert_eq!(items.len(), 3);
        assert_eq!(items[1], MenuItem::Separator);
        assert!(matches!(&m[1], MenuItem::Command { id: 200, .. }));
        // MENUEX: a popup and its item.
        let mut x = Vec::new();
        w16(&mut x, 1);
        w16(&mut x, 4);
        w32(&mut x, 0);
        for (kind, id, info, text, popup) in [
            (0u32, 0u32, 0x81u16, "&View", true),
            (0, 7, 0x80, "&Zoom", false),
        ] {
            w32(&mut x, kind);
            w32(&mut x, 0);
            w32(&mut x, id);
            w16(&mut x, info);
            wsz(&mut x, text);
            pad4(&mut x);
            if popup {
                w32(&mut x, 0);
            }
        }
        let m = menu(&x).unwrap();
        let MenuItem::Popup { items, .. } = &m[0] else {
            panic!("{m:?}")
        };
        assert!(matches!(&items[0], MenuItem::Command { id: 7, text, .. } if text == "&Zoom"));
        // Hostile: unending popups nest only so deep; a bad version is none.
        let mut deep = vec![0u8; 4];
        for _ in 0..10_000 {
            w16(&mut deep, MF_POPUP);
            wsz(&mut deep, "x");
        }
        assert!(menu(&deep).is_some());
        assert!(menu(&[9, 0, 0, 0]).is_none());
    }

    #[test]
    fn accelerator_tables() {
        let mut d = Vec::new();
        for (flags, key, id) in [(0x09u16, u16::from(b'O'), 100u16), (0x81, 0x70, 101)] {
            w16(&mut d, flags);
            w16(&mut d, key);
            w16(&mut d, id);
            w16(&mut d, 0);
        }
        d.extend_from_slice(&[1; 8]);
        let a = accelerators(&d);
        assert_eq!(a.len(), 2);
        assert_eq!(
            a[1],
            Accelerator {
                flags: 1,
                key: 0x70,
                id: 101
            }
        );
    }

    #[test]
    fn icons_cursors_and_bitmaps() {
        // A group of two icons (one 256 by 256), and its .ico.
        let mut g = Vec::new();
        w16(&mut g, 0);
        w16(&mut g, 1);
        w16(&mut g, 2);
        for (size, id) in [(16u8, 1u16), (0, 2)] {
            g.extend_from_slice(&[size, size, 0, 0]);
            w16(&mut g, 1);
            w16(&mut g, 32);
            w32(&mut g, 4);
            w16(&mut g, id);
        }
        let (cursor, images) = group(&g).unwrap();
        assert!(!cursor);
        assert_eq!((images[1].width, images[1].id), (256, 2));
        let ico = icon_file(false, &[(images[0], b"aaaa"), (images[1], b"\x89PNG")]);
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 2, 0]);
        assert_eq!(ico[6 + 16], 0, "256 is 0");
        assert_eq!(u32::from_le_bytes(ico[18..22].try_into().unwrap()), 6 + 32);
        assert_eq!(&ico[38..], b"aaaa\x89PNG");
        // A cursor: its hot spot to its entry.
        let mut c = Vec::new();
        w16(&mut c, 0);
        w16(&mut c, 2);
        w16(&mut c, 1);
        w16(&mut c, 32);
        w16(&mut c, 64);
        w16(&mut c, 1);
        w16(&mut c, 1);
        w32(&mut c, 8);
        w16(&mut c, 5);
        let (cursor, images) = group(&c).unwrap();
        assert!(cursor && images[0].height == 32);
        let cur = icon_file(true, &[(images[0], &[3, 0, 4, 0, 1, 2, 3, 4])]);
        assert_eq!(&cur[10..14], &[3, 0, 4, 0]);
        assert_eq!(&cur[22..], &[1, 2, 3, 4]);
        // A bitmap: 8 bits per pixel, a palette of 256.
        let mut dib = Vec::new();
        w32(&mut dib, 40);
        w32(&mut dib, 1);
        w32(&mut dib, 1);
        w16(&mut dib, 1);
        w16(&mut dib, 8);
        dib.extend_from_slice(&[0; 24]);
        dib.extend_from_slice(&[0; 1024 + 4]);
        let bmp = bmp_file(&dib).unwrap();
        assert_eq!(&bmp[..2], b"BM");
        assert_eq!(
            u32::from_le_bytes(bmp[10..14].try_into().unwrap()),
            14 + 40 + 1024
        );
        // Not one; hostile groups.
        assert!(bmp_file(&[1, 2, 3]).is_none());
        assert!(group(&[0, 0, 3, 0, 1, 0]).is_none());
        let mut many = Vec::new();
        w16(&mut many, 0);
        w16(&mut many, 1);
        w16(&mut many, u16::MAX);
        assert!(group(&many).unwrap().1.is_empty());
    }
}

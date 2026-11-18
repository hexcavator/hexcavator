//! Properties' values as text, as a generic events table shows them: by
//! TDH's input and output types (manifest, TraceLogging and recorded
//! descriptions) or by the kernel schemas' field types. An array's values
//! are listed in brackets.

use hexcavator_etl::Guid;

use crate::schema::{Field, Property};

/// How many values of an array are shown (then how many more).
const MAX_VALUES: usize = 16;
/// How many bytes of binary data are shown (then how many more).
const MAX_BYTES: usize = 64;

/// `p`'s value as text; `ptr` is the event's pointer size.
pub fn format(p: &Property<'_>, ptr: usize) -> String {
    match p.field {
        Field::Typed { in_type, out_type } => typed(in_type, out_type, p.data, ptr),
        Field::U8 => int(p.data, 1, false, 0),
        Field::I8 => int(p.data, 1, true, 0),
        Field::U16 => int(p.data, 2, false, 0),
        Field::U32 => int(p.data, 4, false, 0),
        Field::I32 => int(p.data, 4, true, 0),
        Field::U64 => int(p.data, 8, false, 0),
        Field::Ptr | Field::Pointers => hex_values(p.data, ptr),
        Field::Guid => guid(p.data),
        Field::Utf16z => utf16(p.data),
        Field::Ansiz => ansi(p.data),
        Field::Sid => sid(p
            .data
            .get(if p.data.len() > 4 { 8 + ptr } else { 0 }..)
            .unwrap_or(&[])),
        Field::Bytes(_) | Field::Padding(_) => bytes(p.data),
    }
}

/// A value (or an array of them) by TDH's input and output types.
fn typed(in_type: u8, out_type: u8, data: &[u8], ptr: usize) -> String {
    // Output types that change how an integer reads: hex, a Win32 error or
    // HRESULT or NTSTATUS (hex), a boolean, an IPv4 or IPv6 address, a
    // port.
    let hex = matches!(out_type, 20 | 21 | 22 | 26 | 27 | 35);
    let size = match in_type {
        3 | 4 | 29 => 1,
        5 | 6 | 28 => 2,
        7 | 8 | 11 | 13 | 20 => 4,
        9 | 10 | 12 | 17 | 21 => 8,
        15 | 18 => 16,
        16 | 30 => ptr,
        _ => 0,
    };
    if size > 0 && data.len() > size && data.len().is_multiple_of(size) {
        // An array: each value alike.
        let shown: Vec<String> = data
            .chunks(size)
            .take(MAX_VALUES)
            .map(|v| typed(in_type, out_type, v, ptr))
            .collect();
        let n = data.len() / size;
        let more = if n > MAX_VALUES {
            format!(", … {} more", n - MAX_VALUES)
        } else {
            String::new()
        };
        return format!("[{}{more}]", shown.join(", "));
    }
    match in_type {
        1 | 22 | 24 => utf16(strip_count(in_type, data)),
        2 | 23 | 25 => ansi(strip_count(in_type, data)),
        26 => utf16(data),
        27 => ansi(data),
        3 => int(data, 1, true, 0),
        4 if out_type == 13 => boolean(data),
        4 => int(data, 1, false, if hex { 2 } else { 0 }),
        5 => int(data, 2, true, 0),
        6 if out_type == 32 => data.get(..2).map_or_else(String::new, |b| {
            u16::from_be_bytes([b[0], b[1]]).to_string()
        }),
        6 => int(data, 2, false, if hex { 4 } else { 0 }),
        7 => int(data, 4, true, 0),
        8 if out_type == 30 => ipv4(data),
        8 | 20 => int(data, 4, false, if hex || in_type == 20 { 8 } else { 0 }),
        9 => int(data, 8, true, 0),
        10 | 21 => int(data, 8, false, if hex || in_type == 21 { 16 } else { 0 }),
        11 => data.get(..4).map_or_else(String::new, |b| {
            f32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string()
        }),
        12 => data.get(..8).map_or_else(String::new, |b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            f64::from_le_bytes(a).to_string()
        }),
        13 => boolean(data),
        14 if out_type == 31 && data.len() == 16 => ipv6(data),
        14 | 31 => bytes(if in_type == 31 {
            data.get(4..).unwrap_or(&[])
        } else {
            data
        }),
        15 => guid(data),
        16 | 30 => hex_values(data, ptr),
        17 => filetime(data),
        18 => systemtime(data),
        19 => sid(data),
        28 => int(data, 2, false, 0),
        29 => int(data, 1, false, 0),
        _ => bytes(data),
    }
}

/// A counted string's text (its 16-bit count dropped).
fn strip_count(in_type: u8, data: &[u8]) -> &[u8] {
    if matches!(in_type, 22..=25) {
        data.get(2..).unwrap_or(&[])
    } else {
        data
    }
}

/// A little-endian integer of `size` bytes, signed or not, in decimal or
/// as `digits` hex digits.
fn int(data: &[u8], size: usize, signed: bool, digits: usize) -> String {
    let Some(b) = data.get(..size) else {
        return bytes(data);
    };
    let mut a = [0u8; 8];
    a[..size].copy_from_slice(b);
    let u = u64::from_le_bytes(a);
    if digits > 0 {
        return format!("0x{u:0digits$x}");
    }
    if signed {
        // (Sign-extended from `size` bytes.)
        let shift = 64 - 8 * u32::try_from(size).unwrap_or(8);
        let i = i64::from_ne_bytes((u << shift).to_ne_bytes()) >> shift;
        i.to_string()
    } else {
        u.to_string()
    }
}

fn hex_values(data: &[u8], ptr: usize) -> String {
    let ptr = ptr.clamp(1, 8);
    let shown: Vec<String> = data
        .chunks(ptr)
        .take(MAX_VALUES)
        .map(|v| int(v, v.len(), false, 2 * ptr))
        .collect();
    if data.len() <= ptr {
        return shown.into_iter().next().unwrap_or_default();
    }
    let n = data.len().div_ceil(ptr);
    let more = if n > MAX_VALUES {
        format!(", … {} more", n - MAX_VALUES)
    } else {
        String::new()
    };
    format!("[{}{more}]", shown.join(", "))
}

fn boolean(data: &[u8]) -> String {
    if data.iter().any(|&b| b != 0) {
        "true"
    } else {
        "false"
    }
    .to_string()
}

/// UTF-16 text, to its first NUL.
fn utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// 8-bit text, to its first NUL (as UTF-8 where it is, else Latin-1).
fn ansi(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let b = &data[..end];
    std::str::from_utf8(b).map_or_else(
        |_| b.iter().map(|&c| char::from(c)).collect(),
        str::to_string,
    )
}

fn guid(data: &[u8]) -> String {
    match <&[u8; 16]>::try_from(data.get(..16).unwrap_or(&[])) {
        Ok(b) => format!("{{{}}}", Guid::from_bytes(b)),
        Err(_) => bytes(data),
    }
}

fn bytes(data: &[u8]) -> String {
    let mut s: String = data
        .iter()
        .take(MAX_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect();
    if data.len() > MAX_BYTES {
        s.push_str(&format!("… ({} bytes)", data.len()));
    }
    s
}

fn ipv4(data: &[u8]) -> String {
    match data.get(..4) {
        Some(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        None => bytes(data),
    }
}

fn ipv6(data: &[u8]) -> String {
    let words: Vec<String> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| format!("{:x}", u16::from_be_bytes(*w)))
        .collect();
    words.join(":")
}

/// A FILETIME (100 ns ticks since 1601) as UTC.
fn filetime(data: &[u8]) -> String {
    let Some(b) = data.get(..8) else {
        return bytes(data);
    };
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    let ticks = u64::from_le_bytes(a);
    // Days since 1601-01-01, then the civil date.
    let secs = ticks / 10_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil(i64::try_from(days).unwrap_or(0) - 134_774); // (1601 to 1970)
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:07}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        ticks % 10_000_000
    )
}

/// A SYSTEMTIME (year, month, weekday, day, hour, minute, second, ms).
fn systemtime(data: &[u8]) -> String {
    if data.len() < 16 {
        return bytes(data);
    }
    let w = |i: usize| u16::from_le_bytes([data[2 * i], data[2 * i + 1]]);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        w(0),
        w(1),
        w(3),
        w(4),
        w(5),
        w(6),
        w(7)
    )
}

/// The civil date of `days` since 1970-01-01 (Howard Hinnant's method).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A SID: S-revision-authority-subauthorities.
fn sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return bytes(data);
    }
    let subs = usize::from(data[1]);
    if data.len() < 8 + 4 * subs {
        return bytes(data);
    }
    let mut a = [0u8; 8];
    a[2..].copy_from_slice(&data[2..8]);
    let mut s = format!("S-{}-{}", data[0], u64::from_be_bytes(a));
    for i in 0..subs {
        let at = 8 + 4 * i;
        s.push_str(&format!(
            "-{}",
            u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
        ));
    }
    s
}

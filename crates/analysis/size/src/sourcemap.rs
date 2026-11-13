//! Source maps (revision 3), as WebAssembly toolchains (Emscripten, wasm-pack)
//! write them: one generated "line" whose "columns" are offsets in the
//! module, each segment naming the source file, line, and column that the
//! bytes from its offset to the next segment's came from.
//!
//! bloaty's reader (`source_map.cc`) is used as the reference, but this one
//! reads the JSON properly (escapes, `sourceRoot`, `null` sources), and the
//! WebAssembly sources (in `wasm.rs`) keep the last segment, which bloaty
//! drops for want of a next one.

use serde::Deserialize;

/// A decoded source map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceMap {
    /// The source file names, `sourceRoot` applied.
    pub sources: Vec<String>,
    /// The segments, by offset (as the map lists them; offsets only grow
    /// when the map is well formed).
    pub segments: Vec<Segment>,
}

/// One mapping segment: where its bytes start, and where they came from
/// (none for bytes the map says have no source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub offset: u64,
    pub source: Option<Origin>,
}

/// A source position: an index into [`SourceMap::sources`], and a
/// zero-based line and column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub file: u32,
    pub line: u32,
    pub column: u32,
}

#[derive(Deserialize)]
struct Raw {
    version: Option<u32>,
    #[serde(rename = "sourceRoot", default)]
    source_root: Option<String>,
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(default)]
    mappings: Option<String>,
    // An index map (of other maps) has `sections` instead of `mappings`.
    #[serde(default)]
    sections: Option<serde_json::Value>,
}

/// Parses a source map.
pub fn parse(text: &[u8]) -> Result<SourceMap, String> {
    let raw: Raw = serde_json::from_slice(text).map_err(|e| format!("source map: {e}"))?;
    if raw.version.is_some_and(|v| v != 3) {
        return Err(format!(
            "source map: version {} (only 3 is supported)",
            raw.version.unwrap_or(0)
        ));
    }
    if raw.sections.is_some() {
        return Err("source map: index maps (with sections) are not supported".into());
    }
    let root = raw.source_root.unwrap_or_default();
    let sources: Vec<String> = raw
        .sources
        .into_iter()
        .map(|s| {
            let s = s.unwrap_or_default();
            if root.is_empty() || s.contains("://") || s.starts_with('/') {
                s
            } else if root.ends_with('/') {
                format!("{root}{s}")
            } else {
                format!("{root}/{s}")
            }
        })
        .collect();
    let segments = mappings(raw.mappings.as_deref().unwrap_or(""), sources.len())?;
    Ok(SourceMap { sources, segments })
}

/// Decodes `mappings`: comma-separated segments of 1, 4, or 5 VLQ fields,
/// each relative to the previous segment's. A module is one generated line:
/// segments past a `;` would be at offsets of a line that doesn't exist.
fn mappings(text: &str, sources: usize) -> Result<Vec<Segment>, String> {
    let (first, rest) = text.split_once(';').unwrap_or((text, ""));
    if rest.bytes().any(|b| b != b';') {
        return Err("source map: more than one generated line (not for a module?)".into());
    }
    let mut out = Vec::new();
    let mut state = [0i64; 4];
    for segment in first.split(',') {
        if segment.is_empty() {
            continue;
        }
        let mut fields = [0i64; 5];
        let mut n = 0;
        let mut bytes = segment.bytes();
        while bytes.len() > 0 {
            if n == 5 {
                return Err(format!(
                    "source map: segment {segment:?} has more than 5 fields"
                ));
            }
            fields[n] =
                vlq(&mut bytes).ok_or_else(|| format!("source map: bad VLQ in {segment:?}"))?;
            n += 1;
        }
        if !matches!(n, 1 | 4 | 5) {
            return Err(format!("source map: segment {segment:?} has {n} fields"));
        }
        let fields_used = n.min(4);
        for (s, f) in state.iter_mut().zip(&fields[..fields_used]) {
            *s = s.checked_add(*f).ok_or("source map: offset overflow")?;
        }
        let offset = u64::try_from(state[0]).map_err(|_| "source map: negative offset")?;
        let source = if n >= 4 {
            let [_, file, line, column] = state;
            let field = |v: i64| u32::try_from(v).map_err(|_| "source map: position out of range");
            let file = field(file)?;
            if file as usize >= sources {
                return Err(format!("source map: source {file} of {sources}"));
            }
            Some(Origin {
                file,
                line: field(line)?,
                column: field(column)?,
            })
        } else {
            None
        };
        out.push(Segment { offset, source });
    }
    Ok(out)
}

/// One Base64 VLQ: 5 bits a digit, least significant first, the sixth bit
/// continuing, the lowest bit of the whole the sign.
fn vlq(bytes: &mut std::str::Bytes<'_>) -> Option<i64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let d = match bytes.next()? {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'a'..=b'z' => c - b'a' + 26,
            c @ b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        if shift > 60 {
            return None;
        }
        value |= u64::from(d & 31) << shift;
        shift += 5;
        if d & 32 == 0 {
            break;
        }
    }
    let magnitude = i64::try_from(value >> 1).ok()?;
    Some(if value & 1 == 1 {
        -magnitude
    } else {
        magnitude
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(s: &str) -> Option<Vec<i64>> {
        let mut b = s.bytes();
        let mut out = Vec::new();
        while b.len() > 0 {
            out.push(vlq(&mut b)?);
        }
        Some(out)
    }

    #[test]
    fn vlqs() {
        assert_eq!(decode("A"), Some(vec![0]));
        assert_eq!(decode("C"), Some(vec![1]));
        assert_eq!(decode("D"), Some(vec![-1]));
        assert_eq!(decode("E"), Some(vec![2]));
        assert_eq!(decode("F"), Some(vec![-2]));
        assert_eq!(decode("e"), Some(vec![15]));
        assert_eq!(decode("f"), Some(vec![-15]));
        assert_eq!(decode("gB"), Some(vec![16]));
        assert_eq!(decode("hB"), Some(vec![-16]));
        assert_eq!(decode("2H"), Some(vec![123]));
        // The source map spec's example segment.
        assert_eq!(decode("AAgBC"), Some(vec![0, 0, 16, 1]));
        assert_eq!(decode("ACDE"), Some(vec![0, 1, -1, 2]));
        // Unterminated, invalid digits, and too long.
        assert_eq!(decode("g"), None);
        assert_eq!(decode("A!"), None);
        assert_eq!(decode(&"g".repeat(14)), None);
    }

    #[test]
    fn maps() {
        let m = parse(
            br#"{"version":3,"sourceRoot":"src","sources":["a.c","b.c",null],
                "names":[],"mappings":"gBACE,GAAA,ECCD,C,EAAEC"}"#,
        )
        .unwrap();
        assert_eq!(m.sources, ["src/a.c", "src/b.c", "src/"]);
        let o = |file, line, column| Some(Origin { file, line, column });
        assert_eq!(
            m.segments,
            [
                Segment {
                    offset: 16,
                    source: o(0, 1, 2)
                },
                Segment {
                    offset: 19,
                    source: o(0, 1, 2)
                },
                Segment {
                    offset: 21,
                    source: o(1, 2, 1)
                },
                Segment {
                    offset: 22,
                    source: None
                },
                Segment {
                    offset: 24,
                    source: o(1, 2, 3)
                },
            ]
        );
        // Absolute sources, and URLs, aren't under the root.
        let m = parse(br#"{"version":3,"sourceRoot":"r/","sources":["/abs.c","http://x/y.c","z.c"],"mappings":""}"#).unwrap();
        assert_eq!(m.sources, ["/abs.c", "http://x/y.c", "r/z.c"]);
        assert!(m.segments.is_empty());
        // A trailing line separator is harmless.
        assert_eq!(
            parse(br#"{"sources":["a"],"mappings":"AAAA;;"}"#)
                .unwrap()
                .segments
                .len(),
            1
        );
    }

    #[test]
    fn malformed() {
        for bad in [
            &br"not json"[..],
            br#"{"version":2,"sources":[],"mappings":""}"#,
            br#"{"version":3,"sections":[]}"#,
            br#"{"sources":["a"],"mappings":"AAAA;AAAA"}"#,
            br#"{"sources":["a"],"mappings":"AA"}"#,
            br#"{"sources":["a"],"mappings":"AAAAAA"}"#,
            br#"{"sources":["a"],"mappings":"ACAA"}"#,
            br#"{"sources":["a"],"mappings":"D"}"#,
            br#"{"sources":["a"],"mappings":"A!AA"}"#,
            br#"{"sources":["a"],"mappings":"AADA"}"#,
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // Every truncation of a good map fails cleanly or parses.
        let good = br#"{"version":3,"sources":["a.c"],"mappings":"gBACE,GAAA,C,EAAE"}"#;
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
    }
}

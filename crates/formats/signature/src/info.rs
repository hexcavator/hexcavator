//! What a binary says it is, as `sigcheck` shows beside its signature: a
//! PE image's version resource (company, description, product, versions,
//! copyright); a Mach-O image's versions (its dylib's, its source's) and
//! embedded Info.plist (bundle identifier, name, versions, copyright).

use hexcavator_macho::MachO;
use hexcavator_pe::PeFile;
use hexcavator_pe::version::dotted;

/// Labeled details, in the order shown.
pub type Details = Vec<(String, String)>;

/// A PE image's details, from its version resource.
pub fn pe(pe: &PeFile<'_>) -> Details {
    let mut out: Details = Vec::new();
    let Some(v) = pe.version_info() else {
        return out;
    };
    let mut put = |label: &str, value: Option<String>| {
        if let Some(value) = value
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            out.push((label.to_string(), value));
        }
    };
    let s = |name: &str| v.get(name).map(str::to_string);
    put("Company", s("CompanyName"));
    put("Description", s("FileDescription"));
    put("Product", s("ProductName"));
    put("Product version", s("ProductVersion"));
    put("File version", s("FileVersion"));
    if let Some(f) = &v.fixed {
        // (0.0.0.0, as some write, says nothing.)
        put(
            "File version (binary)",
            (f.file_version != [0; 4]).then(|| dotted(f.file_version)),
        );
        put(
            "Product version (binary)",
            (f.product_version != [0; 4]).then(|| dotted(f.product_version)),
        );
        put(
            "File type",
            (f.file_type != 0).then(|| f.type_name().to_string()),
        );
        let flags = f.flag_names();
        put("Flags", (!flags.is_empty()).then(|| flags.join(", ")));
    }
    put("Original file name", s("OriginalFilename"));
    put("Internal name", s("InternalName"));
    put("Copyright", s("LegalCopyright"));
    put("Trademarks", s("LegalTrademarks"));
    put("Comments", s("Comments"));
    put("Private build", s("PrivateBuild"));
    put("Special build", s("SpecialBuild"));
    if let Some((lang, cp)) = v.translations.first() {
        put("Language", Some(format!("{lang:#06x}, code page {cp}")));
    }
    out
}

/// A Mach-O image's details: its versions, and its Info.plist's.
pub fn macho(m: &MachO<'_>) -> Details {
    let mut out: Details = Vec::new();
    let data = m.data();
    let little = matches!(m.endian(), hexcavator_core::Endian::Little);
    let u32_at = |at: u64| -> Option<u32> {
        let at = usize::try_from(at).ok()?;
        let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let u64_at = |at: u64| -> Option<u64> {
        let at = usize::try_from(at).ok()?;
        let b: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    };
    // (Packed xxxx.yy.zz.)
    let version = |v: u32| format!("{}.{}.{}", v >> 16, (v >> 8) & 0xFF, v & 0xFF);
    for lc in m.load_commands() {
        match lc.cmd {
            hexcavator_macho::consts::LC_ID_DYLIB if lc.size >= 24 => {
                // (0.0.0, as many write, says nothing.)
                for (at, label) in [(16, "Current version"), (20, "Compatibility version")] {
                    if let Some(v) = u32_at(lc.offset + at).filter(|&v| v != 0) {
                        out.push((label.into(), version(v)));
                    }
                }
            }
            hexcavator_macho::consts::LC_SOURCE_VERSION if lc.size >= 16 => {
                if let Some(v) = u64_at(lc.offset + 8).filter(|&v| v != 0) {
                    // (Packed a.b.c.d.e in 24.10.10.10.10 bits.)
                    let parts = [
                        v >> 40,
                        (v >> 30) & 0x3FF,
                        (v >> 20) & 0x3FF,
                        (v >> 10) & 0x3FF,
                        v & 0x3FF,
                    ];
                    let n = parts
                        .iter()
                        .rposition(|&p| p != 0)
                        .map_or(1, |i| (i + 1).max(2));
                    out.push((
                        "Source version".into(),
                        parts[..n]
                            .iter()
                            .map(u64::to_string)
                            .collect::<Vec<_>>()
                            .join("."),
                    ));
                }
            }
            _ => {}
        }
    }
    // The embedded Info.plist (__TEXT,__info_plist), if any.
    if let Some(s) = m
        .sections()
        .into_iter()
        .find(|s| s.sectname == b"__info_plist")
    {
        let start = s.offset as usize;
        let len = usize::try_from(s.size).unwrap_or(0).min(1 << 20);
        if let Some(text) = data.get(start..start.saturating_add(len)) {
            let text = String::from_utf8_lossy(text);
            for (key, label) in [
                ("CFBundleIdentifier", "Bundle identifier"),
                ("CFBundleName", "Bundle name"),
                ("CFBundleShortVersionString", "Version"),
                ("CFBundleVersion", "Build"),
                ("NSHumanReadableCopyright", "Copyright"),
            ] {
                if let Some(v) = plist_string(&text, key) {
                    out.push((label.into(), v));
                }
            }
        }
    }
    out
}

/// A property list's string for `key` (`<key>K</key><string>V</string>`),
/// its XML entities decoded.
fn plist_string(text: &str, key: &str) -> Option<String> {
    let k = format!("<key>{key}</key>");
    let rest = &text[text.find(&k)? + k.len()..];
    let rest = rest.trim_start().strip_prefix("<string>")?;
    let v = &rest[..rest.find("</string>")?];
    Some(
        v.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_strings() {
        let t = "<dict>\n\t<key>CFBundleIdentifier</key>\n\t<string>com.example.a&amp;b</string>\n</dict>";
        assert_eq!(
            super::plist_string(t, "CFBundleIdentifier").unwrap(),
            "com.example.a&b"
        );
        assert!(super::plist_string(t, "CFBundleVersion").is_none());
        assert!(super::plist_string("<key>CFBundleName</key><string>x", "CFBundleName").is_none());
    }
}

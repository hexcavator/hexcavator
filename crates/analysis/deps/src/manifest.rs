//! Side-by-side manifests (`RT_MANIFEST`): the assemblies an image depends
//! on (`<dependentAssembly><assemblyIdentity .../>`), and where Windows
//! keeps them (`WinSxS`).

use std::path::{Path, PathBuf};

/// An assembly a manifest depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Assembly {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub token: String,
}

impl Assembly {
    /// How it's shown: its name and version.
    pub fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// The most of a manifest read.
const MAX_MANIFEST: usize = 1 << 20;

/// The assemblies the manifest `data` (UTF-8, or UTF-16 with a byte order
/// mark) depends on.
pub(crate) fn dependencies(data: &[u8]) -> Vec<Assembly> {
    let data = &data[..data.len().min(MAX_MANIFEST)];
    let text = match data {
        [0xFF, 0xFE, rest @ ..] => String::from_utf16_lossy(
            &rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        ),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(data).into_owned(),
    };
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = lower[at..].find("dependentassembly") {
        let start = at + i;
        // To the closing tag (past the opening one's end).
        let open = lower[start..]
            .find('>')
            .map_or(lower.len(), |e| start + e + 1);
        let end = lower[open..]
            .find("dependentassembly")
            .map_or(lower.len(), |e| open + e)
            .max(start + 1);
        let block = &text[start..end.min(text.len())];
        if let Some(identity) = tag(block, "assemblyidentity") {
            let get = |k: &str| attribute(identity, k).unwrap_or_default();
            let name = get("name");
            if !name.is_empty() && out.len() < 64 {
                out.push(Assembly {
                    name,
                    version: get("version"),
                    arch: get("processorarchitecture"),
                    token: get("publickeytoken").to_ascii_lowercase(),
                });
            }
        }
        at = end.max(start + 1);
    }
    out.dedup();
    out
}

/// The text of the first `<…name …>` tag in `text` (any namespace prefix,
/// case aside).
fn tag<'t>(text: &'t str, name: &str) -> Option<&'t str> {
    let lower = text.to_ascii_lowercase();
    let mut at = 0;
    while let Some(i) = lower[at..].find(name) {
        let start = at + i;
        // (Preceded by `<` or a prefix's `:`.)
        let before = lower[..start].trim_end_matches(|c: char| c.is_ascii_alphanumeric());
        if before.ends_with('<') || before.ends_with(':') {
            let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
            return text.get(start..end);
        }
        at = start + name.len();
    }
    None
}

/// The value of attribute `key` (case aside) in a tag's text.
fn attribute(tag: &str, key: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut at = 0;
    while let Some(i) = lower[at..].find(key) {
        let start = at + i;
        at = start + key.len();
        let boundary = start == 0 || !lower.as_bytes()[start - 1].is_ascii_alphanumeric();
        let rest = lower[at..].trim_start();
        if !boundary || !rest.starts_with('=') {
            continue;
        }
        let value = tag[tag.len() - rest.len() + 1..].trim_start();
        let quote = value.chars().next().filter(|&c| c == '"' || c == '\'')?;
        let v = &value[1..];
        return Some(v[..v.find(quote)?].to_string());
    }
    None
}

/// The directory of `assembly` in `winsxs` for an image of `arch`
/// (`amd64`, `x86`, `arm64`, `arm`), from its entries (lower case): the
/// highest version of the same major version (publisher policy redirects
/// within it).
pub(crate) fn find(
    winsxs: &Path,
    entries: &[String],
    assembly: &Assembly,
    arch: &str,
) -> Option<PathBuf> {
    let arch = match assembly.arch.to_ascii_lowercase().as_str() {
        "" | "*" => arch.to_string(),
        a => a.to_string(),
    };
    let prefix = format!(
        "{arch}_{}_{}_",
        assembly.name.to_ascii_lowercase(),
        assembly.token
    );
    let major = assembly.version.split('.').next().unwrap_or("");
    let version = |e: &str| -> Option<Vec<u32>> {
        let v = e.strip_prefix(&prefix)?.split('_').next()?;
        v.split('.').map(|p| p.parse().ok()).collect()
    };
    entries
        .iter()
        .filter(|e| {
            version(e).is_some_and(|v| v.first().map(u32::to_string).as_deref() == Some(major))
        })
        .max_by_key(|e| version(e))
        .map(|e| winsxs.join(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMCTL: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <asmv3:dependency><asmv3:dependentAssembly><asmv3:assemblyIdentity name='Other.Assembly' version='1.2.3.4' processorArchitecture='amd64' publicKeyToken='ABC'/></asmv3:dependentAssembly></asmv3:dependency>
</assembly>"#;

    #[test]
    fn dependent_assemblies() {
        let deps = dependencies(COMCTL.as_bytes());
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "Microsoft.Windows.Common-Controls");
        assert_eq!(deps[0].version, "6.0.0.0");
        assert_eq!(deps[0].arch, "*");
        assert_eq!(deps[0].token, "6595b64144ccf1df");
        assert_eq!(deps[1].name, "Other.Assembly");
        assert_eq!(deps[1].token, "abc");
        // UTF-16, with its mark.
        let mut wide = vec![0xFF, 0xFE];
        wide.extend(COMCTL.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(dependencies(&wide), deps);
        // Hostile: unterminated, attributes without values, none at all.
        for bad in [
            "<dependentAssembly><assemblyIdentity name=",
            "<dependentAssembly",
            "dependentassembly name='x'",
            "",
            "<assemblyIdentity name='x'/>",
        ] {
            let _ = dependencies(bad.as_bytes());
        }
        assert!(dependencies(b"<dependentAssembly><assemblyIdentity name=\"\"/>").is_empty());
    }

    #[test]
    fn winsxs_directories() {
        let entries: Vec<String> = [
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.26100.1_none_aa",
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.1_none_bb",
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.300_none_cc",
            "x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.999_none_dd",
        ]
        .map(String::from)
        .to_vec();
        let a = &dependencies(COMCTL.as_bytes())[0];
        let found = find(Path::new("W"), &entries, a, "amd64").unwrap();
        assert!(found.ends_with(
            "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.26100.300_none_cc"
        ));
        assert!(
            find(Path::new("W"), &entries, a, "x86")
                .unwrap()
                .to_string_lossy()
                .contains("6.0.26100.999")
        );
        assert!(find(Path::new("W"), &entries, a, "arm64").is_none());
    }
}

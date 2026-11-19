//! `hexc resources`: what a binary holds besides its code and data, and
//! what it says of itself: a PE image's resources, decoded (version
//! information, manifests, string and message tables, dialogs, menus,
//! accelerators, icons, cursors, bitmaps); a Mach-O image's Info.plist,
//! entitlements, and versions; an ELF image's notes and `.comment`; a
//! WebAssembly module's producers and custom sections; a 16-bit (NE)
//! image's resources.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hexcavator_mmap::Mmap;
use hexcavator_pe::resource_data::{self as rd, MenuItem, NameOrId};
use hexcavator_pe::resources::{ResourceName, ResourceTarget};
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc resources [options] <image>

What a binary holds besides its code, and what it says of itself:

  PE: its resources (version information, manifests, string and message
      tables, dialogs, menus, accelerators, icons, cursors, bitmaps, HTML,
      raw data), by type, name, and language.
  Mach-O: its Info.plist, entitlements, and versions (build, source,
      library).
  ELF: its notes (build ID, ABI tag, package metadata, ...) and .comment.
  WebAssembly: its producers, target features, and custom sections.
  16-bit (NE): its resources.

Without options, a list: each with its size and what it says, in a line.

options:
  -show <id>       one of them, decoded in full (its id, as listed:
                   VERSION/#1/1033, Info.plist, ...)
  -all             all of them, decoded in full
  -save <id> <file>  write one out: an icon or cursor group as an .ico or
                   .cur file, a bitmap as a .bmp file, the rest as stored
  -json            as JSON (with -show: a group's file, a bitmap, as base64)";

struct Options {
    image: Option<String>,
    show: Option<String>,
    save: Option<(String, PathBuf)>,
    json: bool,
    all: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        image: None,
        show: None,
        save: None,
        json: false,
        all: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-show" | "/show" => o.show = Some(it.next().ok_or("-show needs an id")?.clone()),
            "-save" | "/save" => {
                let id = it.next().ok_or("-save needs an id and a file")?.clone();
                let file = it.next().ok_or("-save needs an id and a file")?;
                o.save = Some((id, PathBuf::from(file)));
            }
            "-json" | "/json" => o.json = true,
            "-all" | "/all" => o.all = true,
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s if o.image.is_none() => o.image = Some(s.to_string()),
            _ => return Err("give one image".into()),
        }
    }
    if o.image.is_none() {
        return Err("no image given".into());
    }
    Ok(o)
}

pub fn run(args: &[String]) -> ExitCode {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc resources: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let path = o.image.clone().unwrap_or_default();
    let map = match Mmap::open(&path) {
        Ok(m) => m,
        Err(e) => {
            ereport!("hexc resources: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let items = match items(&map) {
        Ok(i) => i,
        Err(e) => {
            ereport!("hexc resources: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let file = Path::new(&path)
        .file_name()
        .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
    let found = |id: &str| -> Result<&Item<'_>, String> {
        items
            .iter()
            .find(|i| i.id == id)
            .or_else(|| items.iter().find(|i| i.id.eq_ignore_ascii_case(id)))
            .ok_or_else(|| {
                format!("{file} has no resource '{id}' (hexc resources {path} lists them)")
            })
    };
    let text = if let Some((id, out)) = &o.save {
        let item = match found(id) {
            Ok(i) => i,
            Err(e) => {
                ereport!("hexc resources: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bytes = saved(item, &items);
        if let Err(e) = std::fs::write(out, &bytes) {
            ereport!("hexc resources: {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
        format!("{}: {} bytes to {}\n", item.id, bytes.len(), out.display())
    } else if let Some(id) = &o.show {
        let item = match found(id) {
            Ok(i) => i,
            Err(e) => {
                ereport!("hexc resources: {e}");
                return ExitCode::FAILURE;
            }
        };
        let detail = detail(item, &items);
        if o.json {
            format!(
                "{}\n",
                serde_json::to_string_pretty(&detail).unwrap_or_default()
            )
        } else {
            detail_text(item, &detail)
        }
    } else if o.all {
        if o.json {
            let all: Vec<Value> = items.iter().map(|i| detail(i, &items)).collect();
            format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({ "file": file, "items": all }))
                    .unwrap_or_default()
            )
        } else {
            let mut out = list_text(&file, &items);
            for i in &items {
                out.push('\n');
                out.push_str(&detail_text(i, &detail(i, &items)));
            }
            out
        }
    } else if o.json {
        let list: Vec<Value> = items
            .iter()
            .map(|i| {
                json!({
                    "id": i.id,
                    "group": i.group,
                    "name": i.name,
                    "language": i.language.map(language),
                    "size": i.data.len(),
                    "summary": summary(i, &items),
                    "view": i.view.name(),
                })
            })
            .collect();
        format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({ "file": file, "items": list }))
                .unwrap_or_default()
        )
    } else {
        list_text(&file, &items)
    };
    crate::out::print(text.as_bytes())
}

/// How an item is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Version,
    Text,
    Strings,
    Messages,
    Dialog,
    Menu,
    Accelerators,
    /// An icon or cursor group (of `RT_ICON`s or `RT_CURSOR`s).
    Group,
    /// One icon or cursor image.
    Image {
        cursor: bool,
    },
    Bitmap,
    /// Name and value pairs.
    Table,
    Hex,
}

impl View {
    fn name(self) -> &'static str {
        match self {
            View::Version => "version",
            View::Text => "text",
            View::Strings => "strings",
            View::Messages => "messages",
            View::Dialog => "dialog",
            View::Menu => "menu",
            View::Accelerators => "accelerators",
            View::Group => "group",
            View::Image { .. } => "image",
            View::Bitmap => "bitmap",
            View::Table => "table",
            View::Hex => "hex",
        }
    }
}

/// What a binary holds: one resource, note, or section.
struct Item<'d> {
    /// How it's named on the command line (`TYPE/NAME/LANGUAGE`, or a
    /// name).
    id: String,
    /// Its group (a resource's type, or what it is).
    group: String,
    name: String,
    language: Option<u16>,
    data: &'d [u8],
    view: View,
    /// A resource's type and name, if they're IDs.
    type_id: Option<u16>,
    name_id: Option<u16>,
    /// What it holds, if it's made rather than stored (versions, notes).
    pairs: Vec<(String, String)>,
}

impl<'d> Item<'d> {
    fn new(id: String, group: &str, name: &str, data: &'d [u8], view: View) -> Self {
        Item {
            id,
            group: group.to_string(),
            name: name.to_string(),
            language: None,
            data,
            view,
            type_id: None,
            name_id: None,
            pairs: Vec::new(),
        }
    }
}

/// The most items listed.
const MAX_ITEMS: usize = 1 << 16;

fn language(lcid: u16) -> String {
    hexcavator_size::lcid::language_name(lcid).to_string()
}

/// A predefined resource type's name.
fn type_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        240 => "DLGINIT",
        241 => "TOOLBAR",
        _ => return None,
    })
}

fn name_text(n: Option<ResourceName<'_>>) -> (String, Option<u16>) {
    match n {
        Some(ResourceName::Id(id)) => (format!("#{id}"), Some(id)),
        Some(other) => (other.text(), None),
        None => ("?".into(), None),
    }
}

/// What `data` holds.
fn items(data: &[u8]) -> Result<Vec<Item<'_>>, String> {
    if let Ok(pe) = hexcavator_pe::PeFile::parse_image(data) {
        return Ok(pe_items(&pe));
    }
    if let Ok(image) = hexcavator_image::Image::parse(data) {
        if let Some(m) = image.macho() {
            return Ok(macho_items(m));
        }
        if let Some(e) = image.elf() {
            return Ok(elf_items(e));
        }
        if let Some(w) = image.wasm() {
            return Ok(wasm_items(w));
        }
    }
    if let Ok(ne) = hexcavator_ne::NeFile::parse(data) {
        return Ok(ne_items(&ne));
    }
    Err("not a PE, Mach-O, ELF, WebAssembly, or NE image".into())
}

fn pe_items<'d>(pe: &hexcavator_pe::PeFile<'d>) -> Vec<Item<'d>> {
    let mut out = Vec::new();
    let Some(root) = pe.resource_root() else {
        return out;
    };
    for t in root.iter() {
        let ResourceTarget::Directory(names) = t.target else {
            continue;
        };
        let (tname, type_id) = name_text(t.name);
        let group = type_id
            .and_then(type_name)
            .map_or(tname.clone(), str::to_string);
        let Some(names) = pe.resource_directory(root.base(), names) else {
            continue;
        };
        for n in names.iter() {
            let ResourceTarget::Directory(langs) = n.target else {
                continue;
            };
            let (name, name_id) = name_text(n.name);
            let Some(langs) = pe.resource_directory(root.base(), langs) else {
                continue;
            };
            for l in langs.iter() {
                let ResourceTarget::Data(entry) = l.target else {
                    continue;
                };
                let lang = match l.name {
                    Some(ResourceName::Id(id)) => id,
                    _ => 0,
                };
                let data = pe
                    .resource_data_entry(entry)
                    .and_then(|e| {
                        pe.bytes_at_rva(hexcavator_core::Rva(e.data.get()), e.size.get())
                            .ok()
                    })
                    .unwrap_or_default();
                let view = match type_id {
                    Some(1) => View::Image { cursor: true },
                    Some(2) => View::Bitmap,
                    Some(3) => View::Image { cursor: false },
                    Some(4) => View::Menu,
                    Some(5) => View::Dialog,
                    Some(6) => View::Strings,
                    Some(9) => View::Accelerators,
                    Some(11) => View::Messages,
                    Some(12 | 14) => View::Group,
                    Some(16) => View::Version,
                    Some(17 | 23 | 24) => View::Text,
                    _ if looks_like_text(data) => View::Text,
                    _ => View::Hex,
                };
                out.push(Item {
                    id: format!("{group}/{name}/{lang}"),
                    group: group.clone(),
                    name: name.clone(),
                    language: Some(lang),
                    data,
                    view,
                    type_id,
                    name_id,
                    pairs: Vec::new(),
                });
                if out.len() >= MAX_ITEMS {
                    return out;
                }
            }
        }
    }
    out
}

/// Whether `data` reads as text (UTF-8, or UTF-16 with its mark).
fn looks_like_text(data: &[u8]) -> bool {
    if data.starts_with(&[0xFF, 0xFE]) || data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return true;
    }
    let head = &data[..data.len().min(512)];
    !head.is_empty()
        && std::str::from_utf8(head)
            .is_ok_and(|s| s.chars().all(|c| !c.is_control() || c.is_whitespace()))
}

/// `data` as text: UTF-16 (with its mark), else UTF-8.
fn text_of(data: &[u8]) -> String {
    let data = &data[..data.len().min(1 << 22)];
    match data {
        [0xFF, 0xFE, rest @ ..] => String::from_utf16_lossy(
            &rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        ),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(data)
            .trim_end_matches('\0')
            .to_string(),
    }
}

fn macho_items<'d>(m: &hexcavator_macho::MachO<'d>) -> Vec<Item<'d>> {
    let mut out = Vec::new();
    let data = m.data();
    if let Some(s) = m
        .sections()
        .into_iter()
        .find(|s| s.sectname == b"__info_plist")
    {
        let start = s.offset as usize;
        let len = usize::try_from(s.size).unwrap_or(0);
        if let Some(bytes) = data.get(start..start.saturating_add(len)) {
            out.push(Item::new(
                "Info.plist".into(),
                "Info.plist",
                "__TEXT,__info_plist",
                bytes,
                View::Text,
            ));
        }
    }
    if let Some(sig) = m.code_signature() {
        let (off, size) = m
            .load_commands()
            .into_iter()
            .find(|c| c.cmd == hexcavator_macho::consts::LC_CODE_SIGNATURE)
            .and_then(|lc| m.linkedit_data(&lc))
            .unwrap_or((0, 0));
        let blobs = data
            .get(off as usize..(off as usize).saturating_add(size as usize))
            .unwrap_or_default();
        for b in &sig.blobs {
            let (name, view) = match b.magic {
                0xFADE_7171 => ("Entitlements", View::Text),
                0xFADE_7172 => ("Entitlements (DER)", View::Hex),
                _ => continue,
            };
            // (A blob: its magic and length, then its contents.)
            let start = b.offset as usize + 8;
            let end = (b.offset as usize).saturating_add(b.length as usize);
            if let Some(bytes) = blobs.get(start..end) {
                out.push(Item::new(name.into(), "Code signature", name, bytes, view));
            }
        }
    }
    let mut pairs = Vec::new();
    for b in m.build_versions() {
        let platform = match b.platform {
            1 => "macOS",
            2 => "iOS",
            3 => "tvOS",
            4 => "watchOS",
            5 => "bridgeOS",
            6 => "Mac Catalyst",
            7 => "iOS Simulator",
            8 => "tvOS Simulator",
            9 => "watchOS Simulator",
            10 => "DriverKit",
            11 => "visionOS",
            12 => "visionOS Simulator",
            _ => "an unknown platform",
        };
        let v = hexcavator_macho::version_string;
        pairs.push(("Platform".into(), platform.into()));
        pairs.push(("Minimum OS".into(), v(b.minos)));
        pairs.push(("SDK".into(), v(b.sdk)));
        // (The tools that built it: its compiler and linker, by version.)
        let tools: Vec<String> = b
            .tools
            .iter()
            .map(|t| match t.name() {
                Some(n) => format!("{n} {}", v(t.version)),
                None => format!("tool {} {}", t.tool, v(t.version)),
            })
            .collect();
        if !tools.is_empty() {
            pairs.push(("Built with".into(), tools.join(", ")));
        }
    }
    if let Some(u) = m.uuid() {
        let hex: String = u.iter().map(|b| format!("{b:02X}")).collect();
        let dashed = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        pairs.push(("UUID".into(), dashed));
    }
    pairs.extend(hexcavator_signature::info::macho(m));
    if !pairs.is_empty() {
        let mut item = Item::new(
            "Versions".into(),
            "Versions",
            "load commands",
            &[],
            View::Table,
        );
        item.pairs = pairs;
        out.push(item);
    }
    out
}

fn elf_items<'d>(e: &hexcavator_elf::ElfFile<'d>) -> Vec<Item<'d>> {
    use hexcavator_elf::consts::*;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in e.sections().filter(|s| s.kind == SHT_NOTE) {
        let bytes = e.section_data(&s);
        for (i, n) in e.notes(bytes).into_iter().enumerate() {
            let owner = String::from_utf8_lossy(n.name)
                .trim_end_matches('\0')
                .to_string();
            let (name, pairs) = note(&owner, n.kind, n.desc, e.endian(), e.class());
            let id = format!("{}#{i}", String::from_utf8_lossy(s.name));
            if !seen.insert((owner.clone(), n.kind, n.desc.to_vec())) {
                continue;
            }
            let mut item = Item::new(
                id,
                "Notes",
                &name,
                n.desc,
                if pairs.is_empty() {
                    View::Hex
                } else {
                    View::Table
                },
            );
            item.pairs = pairs;
            out.push(item);
        }
    }
    for s in e.sections() {
        let name = String::from_utf8_lossy(s.name).into_owned();
        if name == ".comment" {
            // (Strings, each ended with a NUL: one per tool that made it.)
            let bytes = e.section_data(&s);
            let mut item = Item::new(name.clone(), "Sections", &name, bytes, View::Table);
            let mut strings: Vec<String> = bytes
                .split(|&b| b == 0)
                .filter(|x| !x.is_empty())
                .map(|x| String::from_utf8_lossy(x).into_owned())
                .collect();
            strings.dedup();
            item.pairs = strings
                .into_iter()
                .take(256)
                .map(|x| ("Tool".to_string(), x))
                .collect();
            out.push(item);
        } else if name == ".gnu_debuglink" {
            let bytes = e.section_data(&s);
            let file = bytes.split(|&b| b == 0).next().unwrap_or_default();
            let mut item = Item::new(name.clone(), "Sections", &name, bytes, View::Table);
            item.pairs.push((
                "Debug file".into(),
                String::from_utf8_lossy(file).into_owned(),
            ));
            out.push(item);
        }
    }
    out
}

/// A note's name and what it says, decoded where its kind is known.
fn note(
    owner: &str,
    kind: u32,
    desc: &[u8],
    endian: hexcavator_core::Endian,
    class: hexcavator_elf::Class,
) -> (String, Vec<(String, String)>) {
    let w = |i: usize| word(desc, i, endian);
    match (owner, kind) {
        ("GNU", 3) => (
            "GNU build ID".into(),
            vec![(
                "Build ID".into(),
                desc.iter().map(|b| format!("{b:02x}")).collect(),
            )],
        ),
        ("GNU", 1) => {
            let os = match w(0) {
                Some(0) => "Linux",
                Some(1) => "GNU Hurd",
                Some(2) => "Solaris",
                Some(3) => "FreeBSD",
                _ => "an unknown OS",
            };
            let version = format!(
                "{}.{}.{}",
                w(4).unwrap_or(0),
                w(8).unwrap_or(0),
                w(12).unwrap_or(0)
            );
            (
                "ABI tag".into(),
                vec![("OS".into(), os.into()), ("Minimum kernel".into(), version)],
            )
        }
        ("GNU", 4) => (
            "gold version".into(),
            vec![(
                "Linker".into(),
                String::from_utf8_lossy(desc)
                    .trim_end_matches('\0')
                    .to_string(),
            )],
        ),
        ("GNU", 5) => ("GNU properties".into(), properties(desc, endian, class)),
        // FDO's package metadata: JSON.
        ("FDO", 0xCAFE_1A7E) => (
            "Package metadata".into(),
            vec![(
                "JSON".into(),
                String::from_utf8_lossy(desc)
                    .trim_end_matches('\0')
                    .to_string(),
            )],
        ),
        ("Android", 1) => (
            "Android ident".into(),
            vec![("API level".into(), w(0).unwrap_or(0).to_string())],
        ),
        _ => (format!("{owner} note {kind}"), Vec::new()),
    }
}

fn word(data: &[u8], at: usize, endian: hexcavator_core::Endian) -> Option<u32> {
    let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(match endian {
        hexcavator_core::Endian::Little => u32::from_le_bytes(b),
        hexcavator_core::Endian::Big => u32::from_be_bytes(b),
    })
}

/// A GNU property note's properties (each a type, a size, and its data,
/// aligned to the class's word): the ones a hardened build sets, named.
fn properties(
    desc: &[u8],
    endian: hexcavator_core::Endian,
    class: hexcavator_elf::Class,
) -> Vec<(String, String)> {
    let align = if matches!(class, hexcavator_elf::Class::Elf64) {
        8
    } else {
        4
    };
    let bits = |x: u32, names: &[(u32, &str)]| -> String {
        let mut v: Vec<String> = names
            .iter()
            .filter(|(b, _)| x & b != 0)
            .map(|(_, n)| (*n).to_string())
            .collect();
        let rest = names.iter().fold(x, |x, (b, _)| x & !b);
        if rest != 0 {
            v.push(format!("{rest:#x}"));
        }
        if v.is_empty() {
            "none".into()
        } else {
            v.join(", ")
        }
    };
    let isa = [(1, "baseline"), (2, "v2"), (4, "v3"), (8, "v4")];
    let mut out = Vec::new();
    let mut at = 0usize;
    while out.len() < 64 {
        let (Some(kind), Some(size)) = (word(desc, at, endian), word(desc, at + 4, endian)) else {
            break;
        };
        let start = at + 8;
        let Some(end) = start
            .checked_add(size as usize)
            .filter(|&e| e <= desc.len())
        else {
            break;
        };
        let x = word(desc, start, endian).unwrap_or(0);
        let entry = match kind {
            0xC000_0000 => (
                "AArch64 features".to_string(),
                bits(x, &[(1, "BTI"), (2, "PAC"), (4, "GCS")]),
            ),
            0xC000_0002 => (
                "x86 features".to_string(),
                bits(
                    x,
                    &[(1, "IBT"), (2, "SHSTK"), (4, "LAM_U48"), (8, "LAM_U57")],
                ),
            ),
            0xC000_8002 => ("x86 ISA needed".to_string(), bits(x, &isa)),
            0xC001_0002 => ("x86 ISA used".to_string(), bits(x, &isa)),
            0xC000_8001 | 0xC001_0001 => ("x86 features used".to_string(), format!("{x:#x}")),
            1 => ("Stack size".to_string(), format!("{x} bytes")),
            2 => ("No copy relocations".to_string(), "yes".to_string()),
            _ => (
                format!("Property {kind:#x}"),
                desc[start..end]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            ),
        };
        out.push(entry);
        at = end.next_multiple_of(align);
    }
    out
}

fn wasm_items<'d>(m: &hexcavator_wasm::Module<'d>) -> Vec<Item<'d>> {
    let mut out = Vec::new();
    let data = m.data();
    for s in m.sections().iter().filter(|s| s.id == 0) {
        let name = String::from_utf8_lossy(s.name).into_owned();
        let start = usize::try_from(s.data_offset).unwrap_or(usize::MAX);
        let end = usize::try_from(s.contents_offset + s.contents_size).unwrap_or(0);
        let bytes = data.get(start..end).unwrap_or_default();
        let mut item = Item::new(name.clone(), "Custom sections", &name, bytes, View::Hex);
        if name == "producers" {
            item.pairs = producers(bytes);
            item.view = View::Table;
        } else if name == "target_features" {
            item.pairs = target_features(bytes);
            item.view = View::Table;
        } else if name.starts_with(".debug")
            || name == "name"
            || name == "linking"
            || name.starts_with("reloc.")
        {
            // (Shown elsewhere: hexc dwarf, hexc dump.)
            continue;
        } else if looks_like_text(bytes) {
            item.view = View::Text;
        }
        out.push(item);
    }
    out
}

/// A LEB128 number, and where the reader is after it.
fn leb(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *data.get(*at)?;
        *at += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn wasm_name(data: &[u8], at: &mut usize) -> Option<String> {
    let n = usize::try_from(leb(data, at)?).ok()?;
    let s = data.get(*at..at.checked_add(n)?)?;
    *at += n;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// The `producers` section: fields (language, processed-by, sdk), each
/// with names and versions.
fn producers(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    let Some(fields) = leb(data, &mut at) else {
        return out;
    };
    for _ in 0..fields.min(64) {
        let Some(field) = wasm_name(data, &mut at) else {
            break;
        };
        let Some(count) = leb(data, &mut at) else {
            break;
        };
        let mut values = Vec::new();
        for _ in 0..count.min(256) {
            let (Some(name), Some(version)) = (wasm_name(data, &mut at), wasm_name(data, &mut at))
            else {
                break;
            };
            values.push(if version.is_empty() {
                name
            } else {
                format!("{name} {version}")
            });
        }
        out.push((field, values.join(", ")));
    }
    out
}

/// The `target_features` section: each feature, and whether it's used
/// (`+`), required (`=`), or disallowed (`-`).
fn target_features(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    let Some(count) = leb(data, &mut at) else {
        return out;
    };
    for _ in 0..count.min(256) {
        let Some(&prefix) = data.get(at) else { break };
        at += 1;
        let Some(name) = wasm_name(data, &mut at) else {
            break;
        };
        let how = match prefix {
            b'+' => "used",
            b'=' => "required",
            b'-' => "disallowed",
            _ => "?",
        };
        out.push((name, how.into()));
    }
    out
}

fn ne_items<'d>(ne: &hexcavator_ne::NeFile<'d>) -> Vec<Item<'d>> {
    let id = |i: &hexcavator_ne::Id| match i {
        hexcavator_ne::Id::Int(n) => (format!("#{n}"), Some(*n)),
        hexcavator_ne::Id::Name(s) => (s.clone(), None),
    };
    ne.resources()
        .iter()
        .take(MAX_ITEMS)
        .map(|r| {
            let (t, type_id) = id(&r.kind);
            let group = type_id.and_then(type_name).map_or(t, str::to_string);
            let (name, name_id) = id(&r.id);
            let data = ne.resource_data(r);
            let view = match type_id {
                Some(6) => View::Strings,
                _ if looks_like_text(data) => View::Text,
                _ => View::Hex,
            };
            let mut item = Item::new(format!("{group}/{name}"), &group, &name, data, view);
            item.type_id = type_id;
            item.name_id = name_id;
            item
        })
        .collect()
}

/// An icon or cursor image: its group's entry, and its resource's bytes.
type Image<'a> = (rd::GroupImage, &'a [u8]);

/// The images of an icon or cursor group, with their resources' bytes.
fn group_images<'a>(item: &Item<'a>, items: &'a [Item<'a>]) -> Option<(bool, Vec<Image<'a>>)> {
    let (cursor, images) = rd::group(item.data)?;
    let kind = if cursor { 1 } else { 3 };
    let found = images
        .into_iter()
        .filter_map(|g| {
            let data = items
                .iter()
                .find(|i| {
                    i.type_id == Some(kind)
                        && i.name_id == Some(g.id)
                        && i.language == item.language
                })
                .or_else(|| {
                    items
                        .iter()
                        .find(|i| i.type_id == Some(kind) && i.name_id == Some(g.id))
                })?
                .data;
            Some((g, data))
        })
        .collect();
    Some((cursor, found))
}

/// One icon or cursor image's size and bits per pixel: a PNG's, or its
/// bitmap's (whose height is the image's and its mask's).
fn image_size(data: &[u8]) -> Option<(u32, u32, u16)> {
    if data.starts_with(b"\x89PNG") {
        let be = |i: usize| u32::from_be_bytes(data.get(i..i + 4)?.try_into().ok()?).into();
        let be: &dyn Fn(usize) -> Option<u32> = &be;
        return Some((be(16)?, be(20)?, u16::from(*data.get(24)?) * 4));
    }
    let le = |i: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(i..i + 4)?.try_into().ok()?))
    };
    let bits = u16::from_le_bytes(data.get(14..16)?.try_into().ok()?);
    Some((le(4)?, le(8)? / 2, bits))
}

/// The bytes `-save` writes: a group's file, a bitmap's, else as stored.
fn saved(item: &Item<'_>, items: &[Item<'_>]) -> Vec<u8> {
    match item.view {
        View::Group => match group_images(item, items) {
            Some((cursor, images)) => rd::icon_file(cursor, &images),
            None => item.data.to_vec(),
        },
        View::Image { cursor } => single_image(item.data, cursor),
        View::Bitmap => rd::bmp_file(item.data).unwrap_or_else(|| item.data.to_vec()),
        View::Table => item
            .pairs
            .iter()
            .map(|(k, v)| format!("{k}: {v}\n"))
            .collect::<String>()
            .into_bytes(),
        _ => item.data.to_vec(),
    }
}

/// One icon or cursor image as an `.ico` or `.cur` file of its own.
fn single_image(data: &[u8], cursor: bool) -> Vec<u8> {
    let bits = if cursor && data.len() >= 4 {
        &data[4..]
    } else {
        data
    };
    let (w, h, bpp) = image_size(bits).unwrap_or((0, 0, 0));
    let g = rd::GroupImage {
        width: u16::try_from(w).unwrap_or(0),
        height: u16::try_from(h).unwrap_or(0),
        colors: 0,
        planes: 1,
        bits: bpp,
        bytes: u32::try_from(bits.len()).unwrap_or(0),
        id: 0,
    };
    rd::icon_file(cursor, &[(g, data)])
}

/// What an item says, in a line.
fn summary(item: &Item<'_>, items: &[Item<'_>]) -> String {
    let data = item.data;
    match item.view {
        View::Version => match hexcavator_pe::version::VersionInfo::parse(data) {
            Some(v) => {
                let mut s = Vec::new();
                for key in ["ProductName", "FileDescription"] {
                    if let Some(x) = v.get(key) {
                        s.push(x.to_string());
                        break;
                    }
                }
                if let Some(f) = &v.fixed {
                    s.push(hexcavator_pe::version::dotted(f.file_version));
                }
                if let Some(c) = v.get("CompanyName") {
                    s.push(format!("({c})"));
                }
                s.join(" ")
            }
            None => "(not a version resource)".into(),
        },
        View::Text => {
            let text = text_of(data);
            if item.group == "MANIFEST" {
                manifest_summary(&text)
            } else if text.contains("<plist") {
                plist_summary(&text)
            } else {
                one_line(&text)
            }
        }
        View::Strings => {
            let strings = rd::string_table(data, item.name_id.unwrap_or(1));
            let n = strings.len();
            let first = strings
                .first()
                .map(|(_, s)| format!(": {}", one_line(s)))
                .unwrap_or_default();
            format!("{n} string{}{first}", if n == 1 { "" } else { "s" })
        }
        View::Messages => {
            let m = rd::message_table(data);
            let first = m
                .first()
                .map(|m| format!(": {}", one_line(&m.text)))
                .unwrap_or_default();
            format!("{} messages{first}", m.len())
        }
        View::Dialog => match rd::dialog(data) {
            Some(d) => format!(
                "\"{}\": {} controls, {}×{} units",
                d.title,
                d.controls.len(),
                d.rect.2,
                d.rect.3
            ),
            None => "(not a dialog)".into(),
        },
        View::Menu => match rd::menu(data) {
            Some(m) => {
                // (A shortcut menu: one popup, unnamed, of its items.)
                let m = match m.as_slice() {
                    [MenuItem::Popup { text, items, .. }] if text.is_empty() => items.clone(),
                    _ => m,
                };
                let names: Vec<String> = m
                    .iter()
                    .take(16)
                    .map(|i| match i {
                        MenuItem::Popup { text, .. } | MenuItem::Command { text, .. } => {
                            text.replace('&', "")
                        }
                        MenuItem::Separator => "-".into(),
                    })
                    .collect();
                names.join(" ")
            }
            None => "(not a menu)".into(),
        },
        View::Accelerators => format!("{} accelerators", rd::accelerators(data).len()),
        View::Group => match group_images(item, items) {
            Some((cursor, images)) => {
                let sizes: Vec<String> = images
                    .iter()
                    .map(|(g, d)| {
                        format!(
                            "{}×{}{}",
                            g.width,
                            g.height,
                            if d.starts_with(b"\x89PNG") {
                                " PNG"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect();
                let what = match (cursor, images.len()) {
                    (true, 1) => "cursor",
                    (true, _) => "cursors",
                    (false, 1) => "image",
                    (false, _) => "images",
                };
                format!("{} {what}: {}", images.len(), sizes.join(", "))
            }
            None => "(not an icon group)".into(),
        },
        View::Image { cursor } => {
            let bits = if cursor && data.len() >= 4 {
                &data[4..]
            } else {
                data
            };
            match image_size(bits) {
                Some((w, h, b)) => format!(
                    "{w}×{h}, {b} bits{}",
                    if bits.starts_with(b"\x89PNG") {
                        ", PNG"
                    } else {
                        ""
                    }
                ),
                None => String::new(),
            }
        }
        View::Bitmap => {
            let le = |i: usize| {
                data.get(i..i + 4)
                    .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            };
            match (le(4), le(8), data.get(14..16)) {
                (Some(w), Some(h), Some(b)) => format!(
                    "{w}×{}, {} bits",
                    h.unsigned_abs(),
                    u16::from_le_bytes([b[0], b[1]])
                ),
                _ => String::new(),
            }
        }
        // (Values of one kind: the values.)
        View::Table if !item.pairs.is_empty() && item.pairs.iter().all(|(k, _)| k == "Tool") => {
            one_line(
                &item
                    .pairs
                    .iter()
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
        View::Table => item
            .pairs
            .iter()
            .take(3)
            .map(|(k, v)| format!("{k}: {}", one_line(v)))
            .collect::<Vec<_>>()
            .join("; "),
        View::Hex => String::new(),
    }
}

/// The first line of `text`, trimmed, at most 100 characters.
fn one_line(text: &str) -> String {
    let trim = |l: &str| {
        l.trim_matches(|c: char| c.is_whitespace() || c == '\0')
            .to_string()
    };
    let line = text
        .lines()
        .map(trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    let line = line.as_str();
    let mut s: String = line.chars().take(100).collect();
    if line.chars().count() > 100 {
        s.push('…');
    }
    s
}

/// A property list's gist: its keys.
fn plist_summary(text: &str) -> String {
    let keys: Vec<&str> = text
        .split("<key>")
        .skip(1)
        .filter_map(|k| k.split_once("</key>").map(|(k, _)| k.trim()))
        .collect();
    one_line(&keys.join(", "))
}

/// A manifest's gist: the assemblies it depends on, and the execution
/// level it requests.
fn manifest_summary(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut parts = Vec::new();
    let mut at = 0;
    while let Some(i) = lower[at..].find("dependentassembly") {
        let start = at + i;
        if let Some(n) = lower[start..].find("name=") {
            let rest = &text[start + n + 5..];
            let q = rest.chars().next().unwrap_or('"');
            if let Some(end) = rest[1..].find(q) {
                parts.push(format!("needs {}", &rest[1..=end]));
            }
        }
        at = start + "dependentassembly".len();
        if parts.len() >= 8 {
            break;
        }
    }
    parts.dedup();
    if let Some(i) = lower.find("requestedexecutionlevel")
        && let Some(n) = lower[i..].find("level=")
    {
        let rest = &text[i + n + 6..];
        let q = rest.chars().next().unwrap_or('"');
        if let Some(end) = rest[1..].find(q) {
            parts.push(format!("runs {}", &rest[1..=end]));
        }
    }
    if lower.contains("dpiaware") || lower.contains("dpiawareness") {
        parts.push("DPI-aware".into());
    }
    if parts.is_empty() {
        one_line(text)
    } else {
        parts.join("; ")
    }
}

/// Base64 (RFC 4648), for images in JSON.
fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn name_or_id(n: &NameOrId) -> Value {
    match n {
        NameOrId::None => Value::Null,
        NameOrId::Id(i) => json!(format!("#{i}")),
        NameOrId::Name(s) => json!(s),
    }
}

fn menu_json(items: &[MenuItem]) -> Vec<Value> {
    items
        .iter()
        .map(|i| match i {
            MenuItem::Command { text, id, .. } => json!({ "text": text, "id": id }),
            MenuItem::Popup { text, items, .. } => {
                json!({ "text": text, "items": menu_json(items) })
            }
            MenuItem::Separator => json!({ "separator": true }),
        })
        .collect()
}

/// A virtual key's name (for accelerators).
fn key_name(key: u16, virtual_key: bool) -> String {
    if !virtual_key {
        return match char::from_u32(u32::from(key)) {
            Some(c) if !c.is_control() => format!("'{c}'"),
            _ => format!("{key:#x}"),
        };
    }
    match key {
        0x08 => "Backspace".into(),
        0x09 => "Tab".into(),
        0x0D => "Enter".into(),
        0x1B => "Esc".into(),
        0x20 => "Space".into(),
        0x21 => "PageUp".into(),
        0x22 => "PageDown".into(),
        0x23 => "End".into(),
        0x24 => "Home".into(),
        0x25 => "Left".into(),
        0x26 => "Up".into(),
        0x27 => "Right".into(),
        0x28 => "Down".into(),
        0x2D => "Insert".into(),
        0x2E => "Delete".into(),
        0x30..=0x39 | 0x41..=0x5A => {
            char::from_u32(u32::from(key)).map_or_else(String::new, String::from)
        }
        0x70..=0x87 => format!("F{}", key - 0x6F),
        _ => format!("VK {key:#04x}"),
    }
}

/// An item decoded, as JSON.
fn detail(item: &Item<'_>, items: &[Item<'_>]) -> Value {
    let data = item.data;
    let mut v = json!({
        "id": item.id,
        "group": item.group,
        "name": item.name,
        "language": item.language.map(language),
        "size": data.len(),
        "view": item.view.name(),
    });
    match item.view {
        View::Version => {
            if let Some(info) = hexcavator_pe::version::VersionInfo::parse(data) {
                let fixed = info.fixed.as_ref().map(|f| {
                    json!({
                        "fileVersion": hexcavator_pe::version::dotted(f.file_version),
                        "productVersion": hexcavator_pe::version::dotted(f.product_version),
                        "flags": f.flag_names(),
                        "type": f.type_name(),
                    })
                });
                v["fixed"] = fixed.into();
                v["tables"] = info
                    .tables
                    .iter()
                    .map(|t| json!({ "key": t.key, "strings": t.strings }))
                    .collect::<Vec<_>>()
                    .into();
                v["translations"] = info
                    .translations
                    .iter()
                    .map(|(l, c)| json!({ "language": language(*l), "codePage": c }))
                    .collect::<Vec<_>>()
                    .into();
            }
        }
        View::Text => v["text"] = text_of(data).into(),
        View::Strings => {
            v["strings"] = rd::string_table(data, item.name_id.unwrap_or(1))
                .into_iter()
                .map(|(id, s)| json!([id, s.trim_end_matches('\0')]))
                .collect::<Vec<_>>()
                .into();
        }
        View::Messages => {
            v["messages"] = rd::message_table(data)
                .into_iter()
                .map(|m| json!([m.id, m.text.trim_end_matches(['\0', '\r', '\n'])]))
                .collect::<Vec<_>>()
                .into();
        }
        View::Dialog => {
            if let Some(d) = rd::dialog(data) {
                v["dialog"] = json!({
                    "title": d.title,
                    "rect": [d.rect.0, d.rect.1, d.rect.2, d.rect.3],
                    "style": format!("{:#010x}", d.style),
                    "exStyle": format!("{:#010x}", d.ex_style),
                    "font": d.font.as_ref().map(|f| json!({ "size": f.0, "weight": f.1, "italic": f.2, "face": f.3 })),
                    "menu": name_or_id(&d.menu),
                    "class": name_or_id(&d.class),
                    "controls": d.controls.iter().map(|c| json!({
                        "id": if c.id == 0xFFFF || c.id == u32::MAX { -1 } else { i64::from(c.id) },
                        "class": match &c.class {
                            NameOrId::Id(a) => rd::control_class(*a).map_or_else(|| json!(format!("#{a}")), |n| json!(n)),
                            other => name_or_id(other),
                        },
                        "text": name_or_id(&c.text),
                        "rect": [c.rect.0, c.rect.1, c.rect.2, c.rect.3],
                        "style": format!("{:#010x}", c.style),
                    })).collect::<Vec<_>>(),
                });
            }
        }
        View::Menu => v["menu"] = rd::menu(data).map(|m| menu_json(&m)).into(),
        View::Accelerators => {
            v["accelerators"] = rd::accelerators(data)
                .into_iter()
                .map(|a| {
                    let mut keys = Vec::new();
                    for (bit, name) in [(8, "Ctrl"), (0x10, "Alt"), (4, "Shift")] {
                        if a.flags & bit != 0 {
                            keys.push(name.to_string());
                        }
                    }
                    keys.push(key_name(a.key, a.flags & 1 != 0));
                    json!({ "keys": keys.join("+"), "id": a.id })
                })
                .collect::<Vec<_>>()
                .into();
        }
        View::Group => {
            if let Some((cursor, images)) = group_images(item, items) {
                v["cursor"] = cursor.into();
                v["images"] = images
                    .iter()
                    .map(|(g, d)| {
                        let bits = if cursor && d.len() >= 4 { &d[4..] } else { d };
                        json!({ "width": g.width, "height": g.height, "bits": g.bits, "bytes": d.len(), "id": g.id, "png": bits.starts_with(b"\x89PNG"), "file": base64(&single_image(d, cursor)) })
                    })
                    .collect::<Vec<_>>()
                    .into();
                v["file"] = base64(&rd::icon_file(cursor, &images)).into();
                v["mime"] = "image/x-icon".into();
            }
        }
        View::Image { cursor } => {
            v["file"] = base64(&single_image(data, cursor)).into();
            v["mime"] = "image/x-icon".into();
            v["summary"] = summary(item, items).into();
        }
        View::Bitmap => {
            if let Some(bmp) = rd::bmp_file(data) {
                v["file"] = base64(&bmp).into();
                v["mime"] = "image/bmp".into();
            }
            v["summary"] = summary(item, items).into();
        }
        View::Table => {
            v["pairs"] = item
                .pairs
                .iter()
                .map(|(k, x)| json!([k, x]))
                .collect::<Vec<_>>()
                .into();
        }
        View::Hex => {
            // (The first 64 KB.)
            v["hex"] = base64(&data[..data.len().min(1 << 16)]).into();
            v["truncated"] = (data.len() > 1 << 16).into();
        }
    }
    v
}

fn detail_text(item: &Item<'_>, v: &Value) -> String {
    let mut out = String::new();
    let lang = item
        .language
        .map(|l| format!("  {}", language(l)))
        .unwrap_or_default();
    if item.data.is_empty() && !item.pairs.is_empty() {
        let _ = writeln!(out, "{}{lang}\n", item.id);
    } else {
        let _ = writeln!(out, "{}  {} bytes{lang}\n", item.id, item.data.len());
    }
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    match item.view {
        View::Version => {
            if let Some(f) = v["fixed"].as_object() {
                let _ = writeln!(out, "File version     {}", s(&f["fileVersion"]));
                let _ = writeln!(out, "Product version  {}", s(&f["productVersion"]));
                let _ = writeln!(out, "Type             {}", s(&f["type"]));
                let flags: Vec<String> = f["flags"]
                    .as_array()
                    .map(|a| a.iter().map(s).collect())
                    .unwrap_or_default();
                if !flags.is_empty() {
                    let _ = writeln!(out, "Flags            {}", flags.join(", "));
                }
            }
            for t in v["tables"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "\n{}:", s(&t["key"]));
                for p in t["strings"].as_array().into_iter().flatten() {
                    let _ = writeln!(out, "  {:<20} {}", s(&p[0]), s(&p[1]));
                }
            }
        }
        View::Text => out.push_str(&s(&v["text"])),
        View::Strings | View::Messages => {
            let key = if item.view == View::Strings {
                "strings"
            } else {
                "messages"
            };
            for p in v[key].as_array().into_iter().flatten() {
                let _ = writeln!(out, "{:>8}  {}", p[0].as_u64().unwrap_or(0), s(&p[1]));
            }
        }
        View::Dialog => {
            let d = &v["dialog"];
            let _ = writeln!(
                out,
                "\"{}\"  at {} (dialog units), style {}",
                s(&d["title"]),
                d["rect"],
                s(&d["style"])
            );
            if d["font"].is_object() {
                let _ = writeln!(
                    out,
                    "font: {} {} pt",
                    s(&d["font"]["face"]),
                    d["font"]["size"]
                );
            }
            for c in d["controls"].as_array().into_iter().flatten() {
                let text = if c["text"].is_null() {
                    String::new()
                } else {
                    format!(" {}", c["text"])
                };
                let id = c["id"].to_string();
                let _ = writeln!(
                    out,
                    "  {id:>6}  {:<12}{text}  at {}",
                    s(&c["class"]),
                    c["rect"]
                );
            }
        }
        View::Menu => {
            fn walk(out: &mut String, items: &[Value], depth: usize) {
                for i in items {
                    let pad = "  ".repeat(depth);
                    if i["separator"] == true {
                        let _ = writeln!(out, "{pad}--------");
                    } else if let Some(sub) = i["items"].as_array() {
                        let text = i["text"].as_str().unwrap_or("");
                        let _ = writeln!(
                            out,
                            "{pad}{}",
                            if text.is_empty() { "(popup)" } else { text }
                        );
                        walk(out, sub, depth + 1);
                    } else {
                        let _ = writeln!(
                            out,
                            "{pad}{}  ({})",
                            i["text"].as_str().unwrap_or(""),
                            i["id"]
                        );
                    }
                }
            }
            walk(
                &mut out,
                v["menu"].as_array().map_or(&[][..], Vec::as_slice),
                0,
            );
        }
        View::Accelerators => {
            for a in v["accelerators"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "  {:<20} {}", s(&a["keys"]), a["id"]);
            }
        }
        View::Group => {
            for i in v["images"].as_array().into_iter().flatten() {
                let _ = writeln!(
                    out,
                    "  #{:<6} {}×{}, {} bits, {} bytes{}",
                    i["id"],
                    i["width"],
                    i["height"],
                    i["bits"],
                    i["bytes"],
                    if i["png"] == true { " (PNG)" } else { "" }
                );
            }
            let _ = writeln!(
                out,
                "\n(hexc resources -save {} <file.ico> writes it out)",
                item.id
            );
        }
        View::Image { .. } | View::Bitmap => {
            let _ = writeln!(
                out,
                "{}\n(hexc resources -save {} <file> writes it out)",
                s(&v["summary"]),
                item.id
            );
        }
        View::Table => {
            for p in v["pairs"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "{:<22} {}", s(&p[0]), s(&p[1]));
            }
        }
        View::Hex => {
            for (i, row) in item.data.chunks(16).take(256).enumerate() {
                let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
                let text: String = row
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7F).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let _ = writeln!(out, "{:08x}  {:<48} {text}", i * 16, hex.join(" "));
            }
            if item.data.len() > 4096 {
                let _ = writeln!(out, "… ({} bytes more)", item.data.len() - 4096);
            }
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn list_text(file: &str, items: &[Item<'_>]) -> String {
    let mut out = String::new();
    let total: usize = items.iter().map(|i| i.data.len()).sum();
    if items.is_empty() {
        let _ = writeln!(out, "{file}: no resources or metadata");
        return out;
    }
    let _ = writeln!(out, "{file}: {} items, {total} bytes", items.len());
    let mut group = "";
    for i in items {
        if i.group != group {
            group = &i.group;
            let n = items.iter().filter(|x| x.group == group).count();
            let _ = writeln!(out, "\n{group} ({n})");
        }
        let lang = i.language.map(language).unwrap_or_default();
        let size = if i.data.is_empty() && !i.pairs.is_empty() {
            String::new()
        } else {
            format!("{} bytes", i.data.len())
        };
        let _ = writeln!(
            out,
            "  {:<24} {:<28} {:>12}  {}",
            i.id,
            lang,
            size,
            summary(i, items)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encodes() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn manifests_in_a_line() {
        let m = r#"<assembly><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"/></dependentAssembly></dependency>
<trustInfo><security><requestedPrivileges><requestedExecutionLevel level='asInvoker' uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>"#;
        assert_eq!(
            manifest_summary(m),
            "needs Microsoft.Windows.Common-Controls; runs asInvoker"
        );
        assert_eq!(manifest_summary("<assembly/>"), "<assembly/>");
    }

    #[test]
    fn wasm_producers_and_features() {
        let mut p = vec![2u8];
        for (field, values) in [
            ("language", &[("C", "")][..]),
            ("processed-by", &[("clang", "19.0")][..]),
        ] {
            p.push(u8::try_from(field.len()).unwrap());
            p.extend_from_slice(field.as_bytes());
            p.push(u8::try_from(values.len()).unwrap());
            for (n, v) in values {
                p.push(u8::try_from(n.len()).unwrap());
                p.extend_from_slice(n.as_bytes());
                p.push(u8::try_from(v.len()).unwrap());
                p.extend_from_slice(v.as_bytes());
            }
        }
        assert_eq!(
            producers(&p),
            [
                ("language".into(), "C".into()),
                ("processed-by".into(), "clang 19.0".into())
            ]
        );
        assert_eq!(
            target_features(&[1, b'+', 4, b's', b'i', b'm', b'd']),
            [("simd".into(), "used".into())]
        );
        // Hostile: counts past the data.
        assert!(producers(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).is_empty());
        let _ = target_features(&[0xFF, 0x01, b'+']);
    }

    #[test]
    fn notes_decoded() {
        use hexcavator_core::Endian::{Big, Little};
        use hexcavator_elf::Class::Elf64;
        let note = |o, k, d| super::note(o, k, d, Little, Elf64);
        let (name, pairs) = note("GNU", 1, &[0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(name, "ABI tag");
        assert_eq!(pairs[1].1, "3.2.0");
        let (name, pairs) = note("GNU", 3, &[0xAB, 0xCD]);
        assert_eq!(
            (name.as_str(), pairs[0].1.as_str()),
            ("GNU build ID", "abcd")
        );
        assert!(note("XYZ", 9, &[]).1.is_empty());
        // Properties: IBT and SHSTK; an AArch64 one, big-endian; hostile sizes.
        let p = properties(
            &[2, 0, 0, 0xC0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0],
            Little,
            Elf64,
        );
        assert_eq!(p, [("x86 features".to_string(), "IBT, SHSTK".to_string())]);
        let p = properties(
            &[0xC0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0x11, 0, 0, 0, 0],
            Big,
            Elf64,
        );
        assert_eq!(
            p,
            [("AArch64 features".to_string(), "BTI, 0x10".to_string())]
        );
        assert!(properties(&[2, 0, 0, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 3], Little, Elf64).is_empty());
    }

    #[test]
    fn keys_named() {
        assert_eq!(key_name(0x70, true), "F1");
        assert_eq!(key_name(u16::from(b'O'), true), "O");
        assert_eq!(key_name(u16::from(b'o'), false), "'o'");
        assert_eq!(key_name(0xFF, true), "VK 0xff");
    }
}

//! Symbols for Win32 resources (`.rsrc`), named as SizeBench names them:
//! the directory tables, their name strings, the data entries, and the
//! resources' data.
//!
//! An icon or cursor group (`GROUP_ICON`, `GROUP_CURSOR`) is shown with
//! the images it lists, which resource compilers write just before it;
//! string tables next to one another (16 strings each) are shown as one.
//!
//! Where SizeBench goes wrong, these don't follow it:
//!
//! - A group's images are found by their IDs and checked to be where the
//!   group's layout puts them; images that aren't (or that no group lists)
//!   are shown on their own instead of being left out.
//! - Each run of string tables is shown whole (SizeBench drops the first
//!   table after a gap), and tables are adjacent when the next starts at
//!   the first 8-byte boundary after the previous one ends.
//! - A resource type is a predefined type only if it is an ID (not a name
//!   whose string offset happens to match one), and a language given by
//!   name is shown by that name.
//! - A name is read to its full 16-bit length (not its low 8 bits).

use std::collections::{HashMap, HashSet};

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::resources::{
    DATA_ENTRY_SIZE, ResourceEntry, ResourceName, ResourceTarget, resource_type as rt,
};

use crate::Size;
use crate::lcid::language_name;
use crate::symbols::{Symbol, SymbolKind};

/// At most this many directory tables are walked.
const MAX_DIRECTORIES: usize = 0x10_0000;

/// SizeBench's name for a predefined resource type.
fn type_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRINGTABLE",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        13 => "NEWBITMAP",
        14 => "GROUP_ICON",
        15 => "MENUEX",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        18 => "DIALOGEX",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        28 => "RIBBON_XML",
        240 => "DLGINIT",
        241 => "TOOLBAR",
        _ => return None,
    })
}

/// One resource's data, found while walking the tree.
struct Resource {
    /// The predefined type, if it is one.
    kind: Option<u16>,
    type_name: String,
    /// The resource's ID, if it has one.
    id: Option<u16>,
    name: String,
    language: String,
    data: u32,
    size: u32,
}

struct Walker<'a, 'data> {
    pe: &'a PeFile<'data>,
    base: Rva,
    seen: HashSet<u64>,
    directories: HashSet<u32>,
    out: Vec<Symbol>,
    resources: Vec<Resource>,
}

impl Walker<'_, '_> {
    fn add(&mut self, kind: SymbolKind, rva: u32, size: u64, name: String) {
        if !self.seen.insert(u64::from(rva)) {
            return;
        }
        self.out.push(Symbol {
            addr: u64::from(rva),
            size: Size::new(size, size),
            kind,
            folded: false,
            name,
            compiland: None,
            file_static: false,
        });
    }

    fn walk(
        &mut self,
        rva: Rva,
        depth: u32,
        type_entry: Option<ResourceEntry<'_>>,
        name_entry: Option<ResourceEntry<'_>>,
    ) {
        if depth > 2
            || self.directories.len() >= MAX_DIRECTORIES
            || !self.directories.insert(rva.get())
        {
            return;
        }
        let Some(dir) = self.pe.resource_directory(self.base, rva) else {
            return;
        };
        let (kind, type_name) = match type_entry.and_then(|e| e.name) {
            Some(ResourceName::Id(id)) => match type_name(id) {
                Some(n) => (Some(id), n.to_string()),
                None => (None, format!("#{id}")),
            },
            Some(n) => (None, n.text()),
            None => (None, "Unknown".to_string()),
        };
        let name = name_entry.and_then(|e| e.name);
        let label = match depth {
            0 => "[rsrc directory] L0 (Root)".to_string(),
            1 => format!("[rsrc directory] L1 ({type_name})"),
            _ => format!(
                "[rsrc directory] L2 ({type_name}, {})",
                name.map_or("unknown name".to_string(), |n| n.text())
            ),
        };
        self.add(
            SymbolKind::RsrcDirectory,
            rva.get(),
            u64::from(dir.size()),
            label,
        );

        let (mut type_entry, mut name_entry) = (type_entry, name_entry);
        for entry in dir.iter() {
            if let Some(ResourceName::Name { rva, units }) = entry.name {
                self.add(
                    SymbolKind::RsrcString,
                    rva.get(),
                    2 + 2 * units.len() as u64,
                    format!("[rsrc string] \"{}\"", entry.name.unwrap().text()),
                );
            }
            match entry.target {
                ResourceTarget::Directory(sub) => {
                    match depth {
                        0 => type_entry = Some(entry),
                        1 => name_entry = Some(entry),
                        _ => {}
                    }
                    self.walk(sub, depth + 1, type_entry, name_entry);
                }
                ResourceTarget::Data(at) => {
                    let language = match entry.name {
                        Some(ResourceName::Id(id)) => language_name(id).to_string(),
                        Some(n) => n.text(),
                        None => "Unknown language".to_string(),
                    };
                    let resource_name =
                        name.map_or("<unknown rsrc name>".to_string(), |n| n.text());
                    self.add(
                        SymbolKind::RsrcDataEntry,
                        at.get(),
                        u64::from(DATA_ENTRY_SIZE),
                        format!(
                            "[rsrc data entry] L{depth} ({type_name}, {resource_name}, {language})"
                        ),
                    );
                    if let Some(d) = self.pe.resource_data_entry(at) {
                        self.resources.push(Resource {
                            kind,
                            type_name: type_name.clone(),
                            id: match name {
                                Some(ResourceName::Id(id)) => Some(id),
                                _ => None,
                            },
                            name: resource_name,
                            language,
                            data: d.data.get(),
                            size: d.size.get(),
                        });
                    }
                }
            }
        }
    }

    fn data(&mut self, kind: SymbolKind, rva: u32, size: u64, r: &Resource, type_name: &str) {
        self.add(
            kind,
            rva,
            size,
            format!("Resource '{}' ({type_name}, {})", r.name, r.language),
        );
    }

    /// The images a group lists, as one symbol with the group, if they are
    /// where the group's layout puts them: each just before the next, at
    /// 8-byte boundaries, the last just before the group. Returns the
    /// images' indexes in `self.resources`.
    fn group_images(
        &self,
        group: &Resource,
        image_kind: u16,
        images: &HashMap<u16, Vec<usize>>,
    ) -> Option<(u32, u64, Vec<usize>)> {
        let bytes = self.pe.bytes_at_rva(Rva(group.data), group.size).ok()?;
        let count = usize::from(u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?));
        let header = 6 + 14 * count;
        if count == 0 || bytes.len() < header {
            return None;
        }
        let mut at = group.data;
        let mut total = header as u64;
        let mut members = Vec::with_capacity(count);
        for i in (0..count).rev() {
            let e = &bytes[6 + 14 * i..6 + 14 * (i + 1)];
            let size = u32::from_le_bytes(e[8..12].try_into().ok()?);
            let id = u16::from_le_bytes(e[12..14].try_into().ok()?);
            let rounded = size.checked_next_multiple_of(8)?;
            at = at.checked_sub(rounded)?;
            total += u64::from(rounded);
            // The image with this ID, preferring the group's language.
            let candidates = images.get(&id)?;
            let found = candidates
                .iter()
                .copied()
                .filter(|&j| {
                    let r = &self.resources[j];
                    r.kind == Some(image_kind) && r.data == at && r.size == size
                })
                .min_by_key(|&j| self.resources[j].language != group.language)?;
            members.push(found);
        }
        Some((at, total, members))
    }

    fn data_symbols(&mut self) {
        let mut images: HashMap<u16, Vec<usize>> = HashMap::new();
        for (i, r) in self.resources.iter().enumerate() {
            if matches!(r.kind, Some(rt::ICON | rt::CURSOR))
                && let Some(id) = r.id
            {
                images.entry(id).or_default().push(i);
            }
        }
        let mut covered = vec![false; self.resources.len()];
        let mut groups = Vec::new();
        for (i, r) in self.resources.iter().enumerate() {
            let (image, kind) = match r.kind {
                Some(rt::GROUP_ICON) => (rt::ICON, SymbolKind::RsrcGroupIcon),
                Some(rt::GROUP_CURSOR) => (rt::CURSOR, SymbolKind::RsrcGroupCursor),
                _ => continue,
            };
            match self.group_images(r, image, &images) {
                Some((at, size, members)) if members.iter().all(|&m| !covered[m]) => {
                    for m in members {
                        covered[m] = true;
                    }
                    groups.push((i, kind, at, size));
                }
                _ => groups.push((i, kind, r.data, u64::from(r.size))),
            }
        }
        let resources = std::mem::take(&mut self.resources);
        let type_of = |kind: SymbolKind| match kind {
            SymbolKind::RsrcGroupIcon => "GROUP_ICON",
            _ => "GROUP_CURSOR",
        };
        for &(i, kind, at, size) in &groups {
            self.data(kind, at, size, &resources[i], type_of(kind));
        }
        // String tables, in runs.
        let mut tables: Vec<&Resource> = resources
            .iter()
            .filter(|r| r.kind == Some(rt::STRING))
            .collect();
        tables.sort_by_key(|r| r.data);
        let mut run: Vec<&Resource> = Vec::new();
        let flush = |w: &mut Self, run: &mut Vec<&Resource>| {
            if let Some(first) = run.first() {
                let size = run.iter().map(|r| u64::from(r.size)).sum();
                w.add(
                    SymbolKind::RsrcStringTables,
                    first.data,
                    size,
                    format!("Resource '<strings>' (STRINGTABLE, {})", first.language),
                );
            }
            run.clear();
        };
        for t in tables {
            if let Some(last) = run.last() {
                let next = (u64::from(last.data) + u64::from(last.size)).next_multiple_of(8);
                if next != u64::from(t.data) || last.language != t.language {
                    flush(self, &mut run);
                }
            }
            run.push(t);
        }
        flush(self, &mut run);
        // Everything else.
        for (i, r) in resources.iter().enumerate() {
            if covered[i] || matches!(r.kind, Some(rt::STRING | rt::GROUP_ICON | rt::GROUP_CURSOR))
            {
                continue;
            }
            self.data(
                SymbolKind::RsrcData,
                r.data,
                u64::from(r.size),
                r,
                &r.type_name,
            );
        }
    }
}

/// The range of the resource directory, if there is one.
pub fn resource_range(pe: &PeFile<'_>) -> Option<(u64, u64)> {
    let d = pe.data_directory(hexcavator_pe::consts::directory::RESOURCE)?;
    let start = u64::from(d.virtual_address.get());
    (start != 0).then(|| (start, start + u64::from(d.size.get())))
}

/// The resource symbols of `pe`, sorted by address.
pub fn symbols(pe: &PeFile<'_>) -> Vec<Symbol> {
    let Some(root) = pe.resource_root() else {
        return Vec::new();
    };
    let mut w = Walker {
        pe,
        base: root.base(),
        seen: HashSet::new(),
        directories: HashSet::new(),
        out: Vec::new(),
        resources: Vec::new(),
    };
    w.walk(root.rva, 0, None, None);
    w.data_symbols();
    let mut out = w.out;
    out.sort_by_key(|s| s.addr);
    out
}

#[cfg(test)]
#[path = "rsrc_tests.rs"]
mod tests;

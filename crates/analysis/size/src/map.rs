//! A size model and symbols from an image and its linker map, for images
//! without a PDB (or whose PDB is lost or stripped).
//!
//! The map gives the COFF groups, and every public and static symbol with
//! its address and object: each symbol is taken to run to the next one in
//! its group (or the group's end), and to belong to its object, and that
//! object to its library. That is coarser than a PDB's contributions (a
//! function's unnamed data, string literals, and padding go to the symbol
//! before them) but needs nothing but the map.

use std::collections::HashMap;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_debuginfo::{Compiland, Contribution, Group as DebugGroup};
use hexcavator_image::Image;
use hexcavator_linkmap::{LinkMap, MapSource};
use hexcavator_pe::consts::section_characteristics as sc;

use crate::pe::{PeInputs, extract_image};
use crate::symbols::{Symbol, SymbolKind};
use crate::{Model, Size};

/// The compiland a map symbol belongs to: `(name, library)` as
/// [`Compiland`]s name them (an object given to the linker directly is its
/// own library).
fn compiland_of(source: &MapSource) -> (String, String) {
    match source {
        MapSource::Object {
            library: Some(lib),
            object,
        } => {
            let lib = if lib.to_ascii_lowercase().ends_with(".lib") {
                lib.clone()
            } else {
                format!("{lib}.lib")
            };
            (object.clone(), lib)
        }
        MapSource::Object {
            library: None,
            object,
        } => (object.clone(), object.clone()),
        MapSource::Special(s) => (s.clone(), String::new()),
    }
}

/// The inputs to [`crate::pe::build`] from an image and its map, and the
/// map's symbols with their sizes.
pub fn inputs(image: &Image<'_>, map: &LinkMap) -> Result<(PeInputs, Vec<Symbol>)> {
    let mut inputs = extract_image(image)?;
    let section_rva = |section: u16| -> Option<u64> {
        let s = inputs.sections.get(usize::from(section).checked_sub(1)?)?;
        Some(s.addr)
    };
    // Groups, at RVAs.
    for g in &map.groups {
        let Some(base) = section_rva(g.section) else {
            continue;
        };
        let section = &inputs.sections[usize::from(g.section) - 1];
        let characteristics = if g.name.starts_with(".bss") {
            sc::CNT_UNINITIALIZED_DATA | sc::MEM_READ | sc::MEM_WRITE
        } else {
            section.characteristics
        };
        inputs.groups.push(DebugGroup {
            name: g.name.clone(),
            addr: base + u64::from(g.offset),
            size: u64::from(g.length),
            characteristics,
        });
    }
    let mut groups: Vec<&DebugGroup> = inputs.groups.iter().filter(|g| g.size > 0).collect();
    groups.sort_by_key(|g| g.addr);
    let group_at = |rva: u64| -> Option<&DebugGroup> {
        let i = groups.partition_point(|g| g.addr <= rva);
        let g = *groups.get(i.checked_sub(1)?)?;
        (rva < g.addr + g.size).then_some(g)
    };
    // Symbols at RVAs, by address (aliases: the first listed).
    let mut located: Vec<(u64, usize)> = map
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.section != 0)
        .filter_map(|(i, s)| Some((section_rva(s.section)? + u64::from(s.offset), i)))
        .collect();
    located.sort();
    located.dedup_by_key(|l| l.0);
    let mut compilands: HashMap<(String, String), u32> = HashMap::new();
    let mut symbols = Vec::new();
    let mut demangler = hexcavator_demangle::msvc::Demangler::default();
    for (k, &(rva, i)) in located.iter().enumerate() {
        let Some(group) = group_at(rva) else { continue };
        let group_end = group.addr + group.size;
        let end = located.get(k + 1).map_or(group_end, |n| n.0.min(group_end));
        if end <= rva {
            continue;
        }
        let s = &map.symbols[i];
        let key = compiland_of(&s.source);
        let next = u32::try_from(compilands.len()).unwrap_or(u32::MAX);
        let compiland = *compilands.entry(key.clone()).or_insert_with(|| {
            inputs.compilands.push(Compiland {
                name: key.0.clone(),
                library: key.1.clone(),
            });
            next
        });
        inputs.contributions.push(Contribution {
            addr: rva,
            size: end - rva,
            compiland,
            characteristics: group.characteristics,
        });
        let zero_fill = group.characteristics & sc::CNT_UNINITIALIZED_DATA != 0
            && group.characteristics & sc::CNT_INITIALIZED_DATA == 0;
        let len = end - rva;
        let name = if s.name.starts_with('?') {
            demangler
                .demangle(&s.name, hexcavator_demangle::msvc::flags::NO_PTR64)
                .unwrap_or_else(|| s.name.clone())
        } else {
            hexcavator_demangle::swift::demangle(&s.name).unwrap_or_else(|| s.name.clone())
        };
        symbols.push(Symbol {
            addr: rva,
            size: if zero_fill {
                Size::new(0, len)
            } else {
                Size::new(len, len)
            },
            kind: if s.function {
                SymbolKind::Function
            } else {
                SymbolKind::Data
            },
            folded: false,
            name,
            compiland: Some(compiland),
            file_static: false,
        });
    }
    Ok((inputs, symbols))
}

/// The size model of an image from its map, and the map's symbols.
pub fn model(image: &Image<'_>, map: &LinkMap) -> Result<(Model, Vec<Symbol>)> {
    if image.pe().is_none() {
        return Err(Error::new(ErrorKind::Unsupported, 0, "not a PE image"));
    }
    let (inputs, symbols) = inputs(image, map)?;
    Ok((crate::pe::build(&inputs), symbols))
}

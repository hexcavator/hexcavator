//! Writing a [`Model`] out.

use std::collections::BTreeMap;

use crate::{GroupOrigin, Model, NO_GROUP, Size, TableKind};

/// The name of an `IMAGE_DEBUG_TYPE_*` value.
pub fn debug_type_name(kind: u32) -> &'static str {
    match kind {
        0 => "Unknown",
        1 => "COFF",
        2 => "CodeView",
        3 => "FPO",
        4 => "Misc",
        5 => "Exception",
        6 => "Fixup",
        7 => "OmapToSrc",
        8 => "OmapFromSrc",
        9 => "Borland",
        10 => "Reserved10",
        11 => "Clsid",
        12 => "VCFeature",
        13 => "POGO",
        14 => "ILTCG",
        15 => "MPX",
        16 => "Repro",
        17 => "EmbeddedPortablePDB",
        18 => "SPGO",
        19 => "PDBChecksum",
        20 => "ExtendedDllCharacteristics",
        _ => "Other",
    }
}

/// The name SizeBench gives a group it synthesizes for `kind`.
fn sizebench_table_name(kind: TableKind) -> String {
    const DIR: &str = ".sizebench-synthesized-PE-directory-";
    let numbered = |base: &str, i: u32| {
        if i == 0 {
            format!(".sizebench-synthesized-{base}")
        } else {
            format!(".sizebench-synthesized-{base}-{i}")
        }
    };
    match kind {
        TableKind::Exports => format!("{DIR}Exports"),
        TableKind::BaseRelocations => format!("{DIR}BaseRelocationTable"),
        TableKind::LoadConfig => format!("{DIR}LoadConfig"),
        TableKind::DebugDirectory => format!("{DIR}Debug"),
        TableKind::DebugData(t) => format!("{DIR}[DebugDirectory]{}", debug_type_name(t)),
        TableKind::DelayImportDescriptors => format!("{DIR}DelayLoadImports"),
        TableKind::CfgFunctions => ".gfids".into(),
        TableKind::CfgAddressTakenImports => ".giats".into(),
        TableKind::DelayImportThunks(i) => numbered("delay-load-import-thunks", i),
        TableKind::DelayImportNames(i) => numbered("delay-load-import-strings", i),
        TableKind::DelayImportHandles(i) => numbered("delay-load-module-handles", i),
    }
}

/// The lines `tools/sizebench-oracle` prints for the same image, in the
/// same order (sorted), for the parts of the model SizeBench also has:
/// sections, COFF groups, libraries, compilands, and their contributions.
/// Names are SizeBench's: `...no name found...` for an empty library or
/// compiland name, and SizeBench's names for groups it synthesizes.
pub fn sizebench_lines(model: &Model) -> Vec<String> {
    const UNKNOWN: &str = "...no name found...";
    let shown = |s: &str| {
        if s.is_empty() {
            UNKNOWN.to_string()
        } else {
            s.to_string()
        }
    };
    let group_name = |i: u32| {
        let g = &model.groups[i as usize];
        match g.origin {
            GroupOrigin::Table(kind) => {
                // A name SizeBench made unique keeps its suffix.
                let suffix = g.name.strip_prefix(&kind.label()).unwrap_or("");
                format!("{}{suffix}", sizebench_table_name(kind))
            }
            _ => g.name.clone(),
        }
    };
    let mut lines = Vec::new();

    for s in &model.sections {
        lines.push(format!(
            "SECTION {} rva={:x} size={} vsize={} vsizepad={} chars={:x}",
            s.name,
            s.addr,
            s.size.file,
            s.size.vm,
            s.size.vm + s.vm_padding,
            s.characteristics
        ));
    }
    for (i, g) in model.groups.iter().enumerate() {
        lines.push(format!(
            "COFFGROUP {} {} rva={:x} size={} vsize={} vsizepad={} chars={:x}",
            model.sections[g.section as usize].name,
            group_name(i as u32),
            g.addr,
            g.size.file,
            g.size.vm,
            (g.size.vm as u32).wrapping_add(g.padding.vm as u32),
            g.characteristics
        ));
    }

    let lib_name = |l: u32| shown(&model.libraries[l as usize].name);
    let comp_id = |c: u32| {
        let comp = &model.compilands[c as usize];
        format!("{} | {}", lib_name(comp.library), shown(&comp.name))
    };
    let size = |s: Size| format!("size={} vsize={}", s.file, s.vm);

    // Compilands: totals by section and by group.
    let by_section = model.totals(|p| Some((p.compiland, p.section)));
    let by_group = model.totals(|p| (p.group != NO_GROUP).then_some((p.compiland, p.group)));
    let mut compiland_size: BTreeMap<u32, Size> = BTreeMap::new();
    for (&(c, s), t) in &by_section {
        *compiland_size.entry(c).or_default() += t.size;
        let id = comp_id(c);
        lines.push(format!(
            "COMPILANDSECTION {id} | {} {}",
            model.sections[s as usize].name,
            size(t.size)
        ));
        for r in &t.ranges {
            lines.push(format!(
                "RANGE {id} {:08x} {} {}",
                r.addr,
                r.len,
                u8::from(r.zero_fill)
            ));
        }
    }
    for (&(c, g), t) in &by_group {
        lines.push(format!(
            "COMPILANDCOFFGROUP {} | {} {}",
            comp_id(c),
            group_name(g),
            size(t.size)
        ));
    }
    let mut library_size: BTreeMap<u32, Size> = BTreeMap::new();
    for (&c, &s) in &compiland_size {
        lines.push(format!("COMPILAND {} {}", comp_id(c), size(s)));
        *library_size.entry(model.library_of(c)).or_default() += s;
    }

    // Libraries: the sum of their compilands, and their merged ranges by
    // section and group.
    for (&l, &s) in &library_size {
        lines.push(format!("LIB {} {}", lib_name(l), size(s)));
    }
    let lib_by_section = model.totals(|p| Some((model.library_of(p.compiland), p.section)));
    for (&(l, s), t) in &lib_by_section {
        lines.push(format!(
            "LIBSECTION {} | {} {}",
            lib_name(l),
            model.sections[s as usize].name,
            size(t.size)
        ));
    }
    let lib_by_group =
        model.totals(|p| (p.group != NO_GROUP).then_some((model.library_of(p.compiland), p.group)));
    for (&(l, g), t) in &lib_by_group {
        lines.push(format!(
            "LIBCOFFGROUP {} | {} {}",
            lib_name(l),
            group_name(g),
            size(t.size)
        ));
    }

    lines.sort();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_types() {
        assert_eq!(debug_type_name(2), "CodeView");
        assert_eq!(debug_type_name(16), "Repro");
        assert_eq!(debug_type_name(20), "ExtendedDllCharacteristics");
        assert_eq!(debug_type_name(99), "Other");
    }

    #[test]
    fn sizebench_names() {
        assert_eq!(
            sizebench_table_name(TableKind::BaseRelocations),
            ".sizebench-synthesized-PE-directory-BaseRelocationTable"
        );
        assert_eq!(
            sizebench_table_name(TableKind::DebugData(2)),
            ".sizebench-synthesized-PE-directory-[DebugDirectory]CodeView"
        );
        assert_eq!(sizebench_table_name(TableKind::CfgFunctions), ".gfids");
        assert_eq!(
            sizebench_table_name(TableKind::DelayImportThunks(0)),
            ".sizebench-synthesized-delay-load-import-thunks"
        );
        assert_eq!(
            sizebench_table_name(TableKind::DelayImportNames(2)),
            ".sizebench-synthesized-delay-load-import-strings-2"
        );
    }
}

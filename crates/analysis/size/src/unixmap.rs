//! An ELF, Mach-O, or WebAssembly image's inputs, from its Unix linker's
//! map (lld's, GNU ld's, ld64's: see `hexcavator_linkmap::unix`): the
//! `compileunits` source labels each input's contributions by the object
//! (`main.o`, `lib.a(used.o)`), as a PE image's compilands are, and
//! `libraries` by its archive (`lib.a`; `[no library]` for objects linked
//! directly), without debug information. The rest of the image keeps the
//! base's labels.

use hexcavator_linkmap::unix::{UnixMap, split_member};

use crate::rangemap::DualMap;
use crate::sources::{Maps, Source};

/// Relabels `maps`' `compileunits` and `libraries` from `link`.
pub fn apply(maps: &mut Maps, link: &UnixMap) {
    for (source, map) in &mut maps.sources {
        let by_library = match source {
            Source::CompileUnits => false,
            Source::Libraries => true,
            _ => continue,
        };
        let mut m = DualMap::default();
        for p in &link.pieces {
            if p.size == 0 {
                continue;
            }
            let input = link.files.get(p.file).map_or("", String::as_str);
            let name = if input.starts_with('<') || input == "linker synthesized" {
                "[linker]"
            } else if by_library {
                split_member(input).0.unwrap_or("[no library]")
            } else {
                input
            };
            let l = maps.labels.intern(name);
            m.add_vm(p.addr, p.addr.saturating_add(p.size), l, &maps.base);
        }
        m.fill_from(&maps.base, |l| l);
        m.vm.compress();
        m.file.compress();
        *map = m;
    }
}

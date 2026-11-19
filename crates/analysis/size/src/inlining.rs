//! Inlining weighed: for each function inlined into an image's code, what
//! its inlined copies cost, against what calling one out-of-line copy of
//! it instead would ([`weigh`]).
//!
//! A copy's cost is its own bytes ([`hexcavator_debuginfo::exclusive_sizes`]:
//! not those of functions inlined into it, which are weighed as theirs).
//! A call's is estimated ([`CallCost`]): the call instruction, putting each
//! argument in its register (a constant or an address as often as another
//! register's value), and keeping a value live across it (a save and a
//! restore). The out-of-line copy is free if the image already has one
//! (a function of its name), and otherwise as large as the largest copy
//! with a return. So a function is worth calling, not inlining, when
//!
//! ```text
//! copies' bytes > copies × call + (out-of-line copy ? 0 : largest + return)
//! ```
//!
//! This is an estimate either way: an out-of-line copy can't use what's
//! known at each call (its constants), which can make it larger than any
//! copy; and a call can cost more registers' saving than allowed for, or
//! fewer argument moves (arguments already where they go).

use hexcavator_core::Arch;
use hexcavator_debuginfo::{InlineSites, exclusive_sizes};
use rustc_hash::{FxHashMap, FxHashSet};

/// What a call costs, in bytes, on an architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallCost {
    /// The call instruction (`call rel32`, `bl`).
    pub call: u64,
    /// Putting an argument in its register (or pushing it): on average, for
    /// a register's value, a constant, or an address.
    pub argument: u64,
    /// Keeping a value live across the call: a save and a restore (and,
    /// for 32-bit x86, popping the arguments).
    pub around: u64,
    /// A return, for an out-of-line copy.
    pub ret: u64,
}

impl CallCost {
    /// The costs on `arch`, if known: x86-64 (`call rel32`; an argument by
    /// `mov` from a register, 3 bytes, of a constant, 5, or by `lea`, 5 to
    /// 7; a store and a load around it), x86 (`call`, `push`, `add esp`),
    /// ARM64 (`bl`; `mov`, or `adrp` and `add` for an address; `stp` and
    /// `ldp`), and ARM's Thumb-2 (`bl`, `mov`s, `push` and `pop`).
    pub fn of(arch: Arch) -> Option<CallCost> {
        Some(match arch {
            Arch::X64 => CallCost {
                call: 5,
                argument: 5,
                around: 8,
                ret: 1,
            },
            Arch::X86 => CallCost {
                call: 5,
                argument: 3,
                around: 5,
                ret: 1,
            },
            Arch::Arm64 => CallCost {
                call: 4,
                argument: 6,
                around: 8,
                ret: 4,
            },
            Arch::Arm => CallCost {
                call: 4,
                argument: 3,
                around: 4,
                ret: 2,
            },
            _ => return None,
        })
    }

    /// One call's cost, with `arguments` arguments (4 if not known: more
    /// than most functions take, so that what calls would cost isn't
    /// underestimated).
    pub fn per_call(&self, arguments: Option<u32>) -> u64 {
        self.call + self.argument * u64::from(arguments.unwrap_or(4)) + self.around
    }
}

/// One inlined function, weighed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inlinee {
    /// Its name.
    pub name: String,
    /// How many copies of it there are, in how many functions.
    pub copies: u64,
    pub functions: u64,
    /// Its parameters, if known (`this` among them).
    pub parameters: Option<u32>,
    /// The copies' own bytes, and the largest copy's.
    pub inlined: u64,
    pub largest: u64,
    /// Whether the image has an out-of-line copy of it already.
    pub out_of_line: bool,
    /// What calling one copy instead would cost: the calls, and the copy
    /// (nothing if it's already there).
    pub calls: u64,
    pub body: u64,
}

impl Inlinee {
    /// What calling one copy instead of inlining would save (negative:
    /// inlining saves this much).
    pub fn saving(&self) -> i64 {
        let inlined = i64::try_from(self.inlined).unwrap_or(i64::MAX);
        let instead = i64::try_from(self.calls.saturating_add(self.body)).unwrap_or(i64::MAX);
        inlined - instead
    }
}

/// The inlined functions of `sites`, each weighed ([`Inlinee`]), on `arch`
/// (none if its calls' costs aren't known); `defined` says whether a
/// function of a name (an inlinee's) is in the image out of line. Largest
/// saving first.
pub fn weigh(sites: InlineSites, arch: Arch, defined: &dyn Fn(&str) -> bool) -> Vec<Inlinee> {
    let Some(cost) = CallCost::of(arch) else {
        return Vec::new();
    };
    struct Acc {
        copies: u64,
        functions: FxHashSet<u64>,
        inlined: u64,
        largest: u64,
    }
    let mut by: FxHashMap<u32, Acc> = FxHashMap::default();
    for (site, own) in exclusive_sizes(sites.sites) {
        let a = by.entry(site.inlinee).or_insert_with(|| Acc {
            copies: 0,
            functions: FxHashSet::default(),
            inlined: 0,
            largest: 0,
        });
        a.copies += 1;
        a.functions.insert(site.function);
        a.inlined += own;
        a.largest = a.largest.max(own);
    }
    let mut out: Vec<Inlinee> = by
        .into_iter()
        .map(|(i, a)| {
            let name = sites.inlinees.get(i as usize).cloned().unwrap_or_default();
            let parameters = sites.params.get(i as usize).copied().flatten();
            let out_of_line = defined(&name);
            Inlinee {
                calls: a.copies * cost.per_call(parameters),
                body: if out_of_line { 0 } else { a.largest + cost.ret },
                name,
                copies: a.copies,
                functions: a.functions.len() as u64,
                parameters,
                inlined: a.inlined,
                largest: a.largest,
                out_of_line,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.saving()
            .cmp(&a.saving())
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexcavator_debuginfo::InlineSite;

    fn site(inlinee: u32, function: u64, at: u64, size: u64) -> InlineSite {
        InlineSite {
            inlinee,
            function,
            ranges: vec![(at, size)],
            compiland: 0,
            depth: 0,
        }
    }

    #[test]
    fn weighed() {
        // big (one parameter): 10 copies of 40 bytes; small (two): 10 of 6;
        // once (three): 1 copy of 100 bytes, defined out of line too.
        let mut sites = Vec::new();
        for i in 0..10u64 {
            sites.push(site(0, 0x1000 * (i + 1), 0x1000 * (i + 1) + 0x10, 40));
            sites.push(site(1, 0x1000 * (i + 1), 0x1000 * (i + 1) + 0x80, 6));
        }
        sites.push(site(2, 0x20000, 0x20010, 100));
        let s = InlineSites {
            inlinees: vec!["big".into(), "small".into(), "once".into()],
            params: vec![Some(1), Some(2), Some(3)],
            sites,
        };
        let w = weigh(s, Arch::X64, &|n| n == "once");
        let get = |n: &str| w.iter().find(|i| i.name == n).unwrap();
        // big: 400 bytes inlined; as calls, 10 × (5 + 5 + 8) = 180, and a
        // copy of 40 + 1: 179 saved.
        let big = get("big");
        assert_eq!((big.copies, big.functions, big.inlined), (10, 10, 400));
        assert_eq!((big.calls, big.body, big.saving()), (180, 41, 179));
        // small: 60 inlined; as calls 10 × 23 = 230 and 7: inlining saves.
        assert!(get("small").saving() < 0);
        // once: already out of line, one copy: 100 - 28.
        let once = get("once");
        assert!(once.out_of_line);
        assert_eq!((once.body, once.saving()), (0, 100 - 28));
        assert_eq!(w[0].name, "big");
        // Without known call costs: nothing.
        let none = InlineSites::default();
        assert!(weigh(none, Arch::Mips, &|_| false).is_empty());
        // Unknown parameters: four.
        assert_eq!(
            CallCost::of(Arch::Arm64).unwrap().per_call(None),
            4 + 24 + 8
        );
    }
}

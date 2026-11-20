//! How an image's objects were compiled, where the debug information
//! records it ([`hexcavator_debuginfo::options`]), as it matters to its
//! size: whether each object's functions are in sections of their own,
//! which a linker can drop (`--gc-sections`) or fold (ICF) one by one.

use hexcavator_debuginfo::{CompileOptions, DebugInfo};

/// The compile options of an image's compilands, by index.
#[derive(Clone, Debug, Default)]
pub struct Compiled {
    /// Each compiland's, in [`DebugInfo::compilands`]' order.
    pub options: Vec<CompileOptions>,
}

impl Compiled {
    /// The compile options `debug` records (none if it can't be read).
    pub fn of(debug: &DebugInfo<'_>) -> Compiled {
        Compiled {
            options: debug.compile_options().unwrap_or_default(),
        }
    }

    /// Whether compiland `c`'s functions are each in a section of its own
    /// (GCC's and clang's `-ffunction-sections`, the last of it and
    /// `-fno-function-sections`), if its options say: they are with LTO
    /// (`-flto`: the linker compiles them, in sections of their own) and
    /// from rustc (by default); they aren't otherwise, when its arguments
    /// are recorded.
    pub fn function_sections(&self, c: u32) -> Option<bool> {
        self.sections(c, "-ffunction-sections", "-fno-function-sections")
    }

    /// Whether compiland `c`'s data is in sections of its own
    /// (`-fdata-sections`), as [`Compiled::function_sections`] says.
    pub fn data_sections(&self, c: u32) -> Option<bool> {
        self.sections(c, "-fdata-sections", "-fno-data-sections")
    }

    fn sections(&self, c: u32, on: &str, off: &str) -> Option<bool> {
        let o = self.options.get(c as usize)?;
        if o.compiler.contains("rustc version") {
            return Some(true);
        }
        let args = o.args.as_ref()?;
        if let Some(last) = o.last_of(&[on, off]) {
            return Some(last == on);
        }
        Some(
            args.iter().any(|a| a == "-flto" || a.starts_with("-flto="))
                && o.last_of(&["-fno-lto"]).is_none(),
        )
    }

    /// Whether every compiland whose options are recorded was compiled
    /// without functions in sections of their own, and at least one's
    /// are: a link can then neither collect nor fold functions, so what
    /// it left can't show whether it was asked to.
    pub fn no_function_sections(&self) -> bool {
        let mut known = false;
        for c in 0..self.options.len() as u32 {
            match self.function_sections(c) {
                Some(true) => return false,
                Some(false) => known = true,
                None => {}
            }
        }
        known
    }

    /// Whether every compiland whose options are recorded (at least one)
    /// was compiled at `-O0` or `-O1` (or without `-O`, which is `-O0`):
    /// clang then links with Apple's ld `-no_deduplicate`, if it links at
    /// the same level.
    pub fn unoptimized(&self) -> bool {
        let mut known = false;
        for o in &self.options {
            if o.args.is_none() {
                continue;
            }
            known = true;
            let level = o.args.iter().flatten().rev().find(|a| a.starts_with("-O"));
            if !matches!(level.map(String::as_str), None | Some("-O0" | "-O1")) {
                return false;
            }
        }
        known
    }

    /// The compilands compiled without functions in sections of their own
    /// (their arguments recorded), by index.
    pub fn without_function_sections(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.options.len() as u32).filter(|&c| self.function_sections(c) == Some(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(args: Option<&[&str]>) -> CompileOptions {
        CompileOptions {
            compiler: "GNU C17 13.2.0".into(),
            args: args.map(|a| a.iter().map(ToString::to_string).collect()),
        }
    }

    #[test]
    fn function_sections() {
        let c = Compiled {
            options: vec![
                opts(Some(&["-O2", "-ffunction-sections"])),
                opts(Some(&["-ffunction-sections", "-fno-function-sections"])),
                opts(Some(&["-O2"])),
                opts(None),
                opts(Some(&["-flto=thin", "-O2"])),
                CompileOptions {
                    compiler: "clang LLVM (rustc version 1.80.0 (051478957 2024-07-21))".into(),
                    args: None,
                },
                opts(Some(&["-fdata-sections"])),
            ],
        };
        let f: Vec<Option<bool>> = (0..8).map(|i| c.function_sections(i)).collect();
        assert_eq!(
            f,
            [
                Some(true),
                Some(false),
                Some(false),
                None,
                Some(true),
                Some(true),
                Some(false),
                None
            ]
        );
        assert_eq!(c.data_sections(6), Some(true));
        assert_eq!(c.data_sections(0), Some(false));
        assert!(!c.no_function_sections());
        assert_eq!(c.without_function_sections().collect::<Vec<_>>(), [1, 2, 6]);
        let none = Compiled {
            options: vec![opts(Some(&["-O2"])), opts(None)],
        };
        assert!(none.no_function_sections());
        // Nothing recorded: not known.
        assert!(
            !Compiled {
                options: vec![opts(None)]
            }
            .no_function_sections()
        );
        assert!(!Compiled::default().no_function_sections());
    }

    #[test]
    fn unoptimized() {
        let c = |v: Vec<Option<&[&str]>>| Compiled {
            options: v.into_iter().map(opts).collect(),
        };
        assert!(
            c(vec![
                Some(&["-O0"]),
                Some(&["-c"]),
                None,
                Some(&["-O2", "-O1"])
            ])
            .unoptimized()
        );
        assert!(!c(vec![Some(&["-O0"]), Some(&["-Os"])]).unoptimized());
        assert!(!c(vec![Some(&["-Ofast"])]).unoptimized());
        assert!(!c(vec![Some(&["-O1", "-O3"])]).unoptimized());
        // Nothing recorded: not known.
        assert!(!c(vec![None]).unoptimized());
    }
}

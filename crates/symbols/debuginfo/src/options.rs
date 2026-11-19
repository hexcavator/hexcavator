//! How a compiland was compiled, as its debug information records it: the
//! compiler, and its arguments if they're recorded ([`CompileOptions`]).
//!
//! - GCC records its switches in `DW_AT_producer` by default
//!   (`-grecord-gcc-switches`): `GNU C17 13.2.0 -mtune=generic -O2 ...`.
//! - Clang records its whole command line in `DW_AT_producer` with
//!   `-grecord-command-line` (`clang version 19.1.0 (...) /usr/bin/clang
//!   -O2 ...`), or in a `.GCC.command.line` section with
//!   `-frecord-command-line` (one string per object, merged by the linker),
//!   escaping spaces and backslashes in each argument with a backslash.
//! - MSVC records the compiler's arguments in the PDB (`S_BUILDINFO`'s
//!   `LF_BUILDINFO`), and its version in `S_COMPILE3`.

/// How a compiland was compiled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompileOptions {
    /// The compiler, as it names itself: `GNU C17 13.2.0`, `clang version
    /// 19.1.0 (...)`, `Microsoft (R) Optimizing Compiler 19.40.33811.0`.
    pub compiler: String,
    /// Its arguments, unescaped, if recorded (not the program's path):
    /// `None` when the debug information doesn't record them.
    pub args: Option<Vec<String>>,
}

impl CompileOptions {
    /// Whether an argument is recorded exactly so.
    pub fn has(&self, arg: &str) -> bool {
        self.args
            .as_ref()
            .is_some_and(|a| a.iter().any(|x| x == arg))
    }

    /// Which of `choices` is given last (the compiler takes the last of
    /// conflicting switches), if any is: each is matched exactly, or as a
    /// prefix when it ends with `=` or `:`, or (MSVC's) the switch given
    /// with `/` or `-`.
    pub fn last_of<'a>(&'a self, choices: &[&str]) -> Option<&'a str> {
        let args = self.args.as_ref()?;
        args.iter()
            .rev()
            .find_map(|a| choices.iter().any(|c| matches(a, c)).then_some(a.as_str()))
    }
}

fn matches(arg: &str, choice: &str) -> bool {
    let same = |a: &str| {
        if choice.ends_with(['=', ':']) {
            a.starts_with(choice)
        } else {
            a == choice
        }
    };
    if same(arg) {
        return true;
    }
    // MSVC's `/Gy` is also `-Gy`.
    match (arg.strip_prefix('/'), choice.strip_prefix('-')) {
        (Some(a), Some(c)) if !choice.starts_with("--") => {
            if choice.ends_with([':', '=']) {
                a.starts_with(c)
            } else {
                a == c
            }
        }
        _ => false,
    }
}

/// Whether a producer is clang's (whose recorded arguments are escaped).
fn is_clang(producer: &str) -> bool {
    producer.contains("clang version")
}

/// The options a `DW_AT_producer` records: the compiler's name and
/// version, then (GCC's switches, or clang's command line with its
/// program's path) the arguments, from the first that starts with `-`.
pub fn parse_producer(producer: &str) -> CompileOptions {
    // Clang with -fno-ident names no version: its recorded command line
    // follows the empty name.
    if let Some(line) = producer.strip_prefix(' ') {
        let args = parse_command_line(line);
        return CompileOptions {
            compiler: String::new(),
            args: (!args.is_empty()).then_some(args),
        };
    }
    let clang = is_clang(producer);
    let words = split(producer, clang);
    let first = words.iter().position(|w| w.starts_with('-'));
    let head = &words[..first.unwrap_or(words.len())];
    // Clang's recorded command line starts with the program's path, after
    // the version (and its parenthesized repository and revision).
    let name_len = if clang && first.is_some() {
        match head.iter().rposition(|w| w.ends_with(')')) {
            Some(i) => i + 1,
            None => head
                .iter()
                .position(|w| w == "version")
                .map_or(head.len(), |v| (v + 2).min(head.len())),
        }
    } else {
        head.len()
    };
    CompileOptions {
        compiler: head[..name_len].join(" "),
        args: first.map(|i| words[i..].to_vec()),
    }
}

/// A clang command line as `-frecord-command-line` records it (in
/// `.GCC.command.line`): the program's path, then its arguments.
pub fn parse_command_line(line: &str) -> Vec<String> {
    let mut words = split(line, true);
    if !words.is_empty() {
        words.remove(0);
    }
    words
}

/// An MSVC command line's arguments (`LF_BUILDINFO`'s): split at spaces,
/// except inside double quotes, which are removed (`\"` is a quote).
pub fn parse_msvc_command_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut arg = String::new();
    let (mut quoted, mut any) = (false, false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                arg.push('"');
                chars.next();
                any = true;
            }
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut arg));
                    any = false;
                }
            }
            c => {
                arg.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(arg);
    }
    out
}

/// Splits at spaces; with `escaped` (clang's), a backslash makes the next
/// character literal.
fn split(s: &str, escaped: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if escaped => {
                if let Some(n) = chars.next() {
                    word.push(n);
                }
            }
            c if c.is_whitespace() => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// The file name of a path (either separator).
pub(crate) fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Which of `lines` (clang's recorded command lines) compiled `source` (a
/// unit's name): the one naming it exactly, or else the only one naming a
/// file of its name.
pub(crate) fn command_line_for<'a>(lines: &'a [Vec<String>], source: &str) -> Option<&'a [String]> {
    let names =
        |l: &Vec<String>, f: &dyn Fn(&str) -> bool| l.iter().any(|a| !a.starts_with('-') && f(a));
    if let Some(l) = lines.iter().find(|l| names(l, &|a| a == source)) {
        return Some(l);
    }
    let file = base_name(source);
    let mut same = lines.iter().filter(|l| names(l, &|a| base_name(a) == file));
    match (same.next(), same.next()) {
        (Some(l), None) => Some(l),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcc_producer() {
        let o = parse_producer(
            "GNU C17 13.2.0 -mtune=generic -march=x86-64 -g -O2 -ffunction-sections",
        );
        assert_eq!(o.compiler, "GNU C17 13.2.0");
        assert_eq!(
            o.args.as_deref().unwrap(),
            [
                "-mtune=generic",
                "-march=x86-64",
                "-g",
                "-O2",
                "-ffunction-sections"
            ]
        );
        assert!(o.has("-ffunction-sections"));
        assert_eq!(o.last_of(&["-O"]), None);
        assert_eq!(o.last_of(&["-march="]), Some("-march=x86-64"));
        // Without its switches (-gno-record-gcc-switches): none recorded.
        let o = parse_producer("GNU C++17 13.2.0");
        assert_eq!(o.compiler, "GNU C++17 13.2.0");
        assert_eq!(o.args, None);
    }

    #[test]
    fn clang_producer() {
        let o = parse_producer(
            r"clang version 24.0.0git (https://github.com/llvm/llvm-project.git c74b358f) C:\\jm\\llvm\\bin\\clang.exe --target=x86_64-linux-gnu -O2 -g -I C:\\my\ dir -ffunction-sections -c a.c -o g.o",
        );
        assert_eq!(
            o.compiler,
            "clang version 24.0.0git (https://github.com/llvm/llvm-project.git c74b358f)"
        );
        let args = o.args.as_deref().unwrap();
        assert_eq!(args[0], "--target=x86_64-linux-gnu");
        assert!(args.contains(&r"C:\my dir".to_string()), "{args:?}");
        assert_eq!(args.last().unwrap(), "g.o");
        // Without -grecord-command-line.
        let o = parse_producer(
            "clang version 19.1.0 (https://github.com/llvm/llvm-project.git a4bf6cd7)",
        );
        assert_eq!(o.args, None);
        assert!(o.compiler.ends_with("a4bf6cd7)"));
        // Apple's, and one without a parenthesized revision.
        let o =
            parse_producer("Apple clang version 15.0.0 (clang-1500.0.40.1) /usr/bin/clang -Os x.c");
        assert_eq!(o.compiler, "Apple clang version 15.0.0 (clang-1500.0.40.1)");
        assert_eq!(o.args.unwrap(), ["-Os", "x.c"]);
        let o = parse_producer("clang version 18.1.3 /usr/bin/clang-18 -O2 x.c");
        assert_eq!(o.compiler, "clang version 18.1.3");
        assert_eq!(o.args.unwrap(), ["-O2", "x.c"]);
        // -fno-ident: no version, then the command line.
        let o = parse_producer(r" /usr/bin/clang -O2 -I a\ b x.c");
        assert_eq!(o.compiler, "");
        assert_eq!(o.args.unwrap(), ["-O2", "-I", "a b", "x.c"]);
        assert_eq!(parse_producer("").args, None);
        assert_eq!(parse_producer(" ").args, None);
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            parse_command_line(r"/usr/bin/clang -O2 -I /a\ b -c x.c"),
            ["-O2", "-I", "/a b", "-c", "x.c"]
        );
        assert_eq!(
            parse_msvc_command_line(r#"-c -Zi -Gy -I"C:\Program Files\x" -DX=\"y\" -O2"#),
            [
                "-c",
                "-Zi",
                "-Gy",
                r"-IC:\Program Files\x",
                r#"-DX="y""#,
                "-O2"
            ]
        );
        assert_eq!(parse_msvc_command_line(r#"  "" a "#), ["", "a"]);
        let lines = vec![
            parse_command_line("clang -c src/a.c -o a.o"),
            parse_command_line("clang -c lib/b.c -o b.o"),
            parse_command_line("clang -c other/b.c -o b2.o"),
        ];
        assert_eq!(command_line_for(&lines, "src/a.c").unwrap()[1], "src/a.c");
        assert_eq!(
            command_line_for(&lines, "/build/src/a.c").unwrap()[1],
            "src/a.c"
        );
        assert_eq!(command_line_for(&lines, "lib/b.c").unwrap()[1], "lib/b.c");
        // (Two of its name, neither exactly: not known.)
        assert_eq!(command_line_for(&lines, "/x/b.c"), None);
        assert_eq!(command_line_for(&lines, "c.c"), None);
    }

    #[test]
    fn last_switch_wins() {
        let o = CompileOptions {
            compiler: String::new(),
            args: Some(
                [
                    "-ffunction-sections",
                    "-O2",
                    "-fno-function-sections",
                    "/Gy",
                    "/O1",
                ]
                .map(String::from)
                .to_vec(),
            ),
        };
        assert_eq!(
            o.last_of(&["-ffunction-sections", "-fno-function-sections"]),
            Some("-fno-function-sections")
        );
        assert_eq!(o.last_of(&["-Gy", "-Gy-"]), Some("/Gy"));
        assert_eq!(o.last_of(&["-O", "-O1", "-O2"]), Some("/O1"));
        assert!(CompileOptions::default().last_of(&["-O2"]).is_none());
    }
}

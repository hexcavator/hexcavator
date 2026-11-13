use super::*;

const SAMPLE: &str = r#"
Starting pass 1
Processed /DEFAULTLIB:libcpmt
Processed /DEFAULTLIB:LIBCMT
Searching libraries
    Searching C:\VC\lib\x64\libcpmt.lib:
      Found "void __cdecl std::_Xlength_error(char const *)" (?_Xlength_error@std@@YAXPEBD@Z)
        Referenced in main.obj
        Loaded libcpmt.lib(xthrow.obj)
    Searching C:\VC\lib\x64\LIBCMT.lib:
      Found __security_check_cookie
        Referenced in main.obj
        Referenced in LIBCMT.lib(gshandler.obj)
        Loaded LIBCMT.lib(amdsecgs.obj)
      Found __GSHandlerCheck
        Referenced in libcpmt.lib(xthrow.obj)
        Loaded LIBCMT.lib(gshandler.obj)
      Found _already
        Referenced in main.obj
Finished searching libraries
Finished pass 1

Unused libraries:
  C:\VC\lib\x64\OLDNAMES.lib

    Discarded "int __cdecl unused(int)" (?unused@@YAHH@Z) from main.obj
    Discarded _Fenv1 from libucrt.lib(output.obj)
    Discarded "`string'" (??_C@_0BC@DPJNKNAF@bad?5function?5call@) from libcpmt.lib(xthrow.obj)
    Selected symbol:
        _matherr from LIBCMT.lib(matherr.obj)
    Replaced symbol(s):
        _get_startup_new_mode from LIBCMT.lib(new_mode.obj)
        "public: static void __cdecl A::f(void)" (?f@A@@SAXXZ) from a.obj

Starting pass 2
     main.obj
     libcpmt.lib(xthrow.obj)
Finished pass 2
"#;

#[test]
fn parses_every_part() {
    let log = parse(SAMPLE);
    assert_eq!(log.default_libraries, ["libcpmt", "LIBCMT"]);
    assert_eq!(log.loads.len(), 4);
    let first = &log.loads[0];
    assert_eq!(first.library, r"C:\VC\lib\x64\libcpmt.lib");
    assert_eq!(first.symbol.name, "?_Xlength_error@std@@YAXPEBD@Z");
    assert_eq!(
        first.symbol.shown(),
        "void __cdecl std::_Xlength_error(char const *)"
    );
    assert_eq!(first.referenced_in, ["main.obj"]);
    assert_eq!(first.loaded.as_deref(), Some("libcpmt.lib(xthrow.obj)"));
    assert_eq!(log.loads[1].referenced_in.len(), 2);
    assert_eq!(log.loads[3].loaded, None);
    assert_eq!(log.unused_libraries, [r"C:\VC\lib\x64\OLDNAMES.lib"]);
    assert_eq!(log.discarded.len(), 3);
    assert_eq!(log.discarded[0].symbol.name, "?unused@@YAHH@Z");
    assert_eq!(log.discarded[0].input, "main.obj");
    assert_eq!(log.discarded[1].symbol.name, "_Fenv1");
    assert_eq!(log.discarded[1].symbol.display, None);
    assert_eq!(log.discarded[1].input, "libucrt.lib(output.obj)");
    assert_eq!(log.discarded[2].symbol.shown(), "`string'");
    assert_eq!(log.folds.len(), 1);
    assert_eq!(log.folds[0].selected.symbol.name, "_matherr");
    assert_eq!(log.folds[0].replaced.len(), 2);
    assert_eq!(log.folds[0].replaced[1].symbol.name, "?f@A@@SAXXZ");
    assert_eq!(log.folds[0].replaced[1].input, "a.obj");
    assert_eq!(log.linked, ["main.obj", "libcpmt.lib(xthrow.obj)"]);
}

#[test]
fn why_follows_references_back() {
    let log = parse(SAMPLE);
    let why = log.why("LIBCMT.lib(gshandler.obj)");
    let chain: Vec<&str> = why.iter().map(|r| r.input).collect();
    assert_eq!(
        chain,
        ["LIBCMT.lib(gshandler.obj)", "libcpmt.lib(xthrow.obj)"]
    );
    assert_eq!(why[0].symbol.name, "__GSHandlerCheck");
    assert_eq!(why[1].referenced_in, ["main.obj"]);
    // By member name alone, any case.
    assert_eq!(log.why("GSHANDLER.OBJ").len(), 2);
    assert!(log.why("main.obj").is_empty());
    assert!(log.why("nothing.obj").is_empty());
    let by_lib = log.members_by_library();
    assert_eq!(by_lib[0], ("libcpmt.lib", vec!["libcpmt.lib(xthrow.obj)"]));
    assert_eq!(by_lib[1].1.len(), 2);
}

#[test]
fn cycles_and_damage_end() {
    let looped = "\
Searching libraries
    Searching a.lib:
      Found x
        Referenced in a.lib(y.obj)
        Loaded a.lib(x.obj)
      Found y
        Referenced in a.lib(x.obj)
        Loaded a.lib(y.obj)
";
    let log = parse(looped);
    assert_eq!(log.why("x.obj").len(), 2);
    // Damaged lines are skipped.
    let damaged = "\
    Discarded \"unterminated (?x@@YAXXZ from a.obj
    Discarded \"name\" (unbalanced from a.obj
    Discarded  from a.obj
    Selected symbol:
        no input here
    Replaced symbol(s):
        y from b.obj
Searching libraries
        Referenced in orphan.obj
        Loaded orphan.lib(o.obj)
      Found
";
    let log = parse(damaged);
    assert!(log.discarded.is_empty(), "{:?}", log.discarded);
    assert!(log.folds.is_empty());
    assert!(log.loads.is_empty());
    let mut text = String::new();
    for i in 0..2000 {
        text.push_str(match i % 7 {
            0 => "Searching libraries\n",
            1 => "    Searching x.lib:\n",
            2 => "      Found \"a (\n",
            3 => "        Loaded \n",
            4 => "    Selected symbol:\n",
            5 => "\u{1F600} from \u{e9}\n",
            _ => "\n",
        });
    }
    let _ = parse(&text);
}

#[test]
fn a_real_log() {
    let text = std::fs::read_to_string(format!(
        "{}/../../../testdata/linkerlog/verbose.txt",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let log = parse(&text);
    assert_eq!(log.discarded.len(), 300);
    assert!(log.loads.len() > 100, "{}", log.loads.len());
    // Loads without referrers are the linker's own: the entry point and
    // the load configuration.
    let roots: Vec<&str> = log
        .loads
        .iter()
        .filter(|l| l.referenced_in.is_empty())
        .map(|l| l.symbol.name.as_str())
        .collect();
    assert_eq!(roots, ["mainCRTStartup", "_load_config_used"]);
    assert!(log.folds.len() > 20, "{}", log.folds.len());
    assert!(
        log.linked.first().is_some_and(|l| l == "main.obj"),
        "{:?}",
        log.linked.first()
    );
    assert!(
        log.unused_libraries
            .iter()
            .any(|l| l.ends_with("OLDNAMES.lib"))
    );
    // Every member loaded is linked, and its explanation ends at main.obj
    // (or at the linker's own references).
    for l in &log.loads {
        if let Some(m) = &l.loaded {
            assert!(log.linked.contains(m), "{m} not linked");
            let why = log.why(m);
            assert!(!why.is_empty(), "{m}");
            let root = why
                .last()
                .unwrap()
                .referenced_in
                .first()
                .map(String::as_str);
            assert!(root == Some("main.obj") || root.is_none(), "{m}: {root:?}");
        }
    }
    let why = log.why("xthrow.obj");
    assert_eq!(why[0].input, "libcpmt.lib(xthrow.obj)");
    assert_eq!(why[0].symbol.name, "?_Xlength_error@std@@YAXPEBD@Z");
}

/// The Unix linkers' logs: lld's (ELF) and lld's Mach-O port's, from
/// testdata/linkmap (tools/linkmap/build.cmd), and GNU ld's, as it writes
/// them.
fn linkmap(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/linkmap")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn lld_why_extract_why_live_and_gc_sections() {
    let mut text = linkmap("elf.why");
    text.push_str(&linkmap("elf.log"));
    let log = parse(&text);
    assert_eq!(log.loads.len(), 1);
    let l = &log.loads[0];
    assert_eq!(
        (l.library.as_str(), l.symbol.name.as_str()),
        ("lib.a", "used_helper")
    );
    assert_eq!(l.loaded.as_deref(), Some("lib.a(used.o)"));
    assert_eq!(l.referenced_in, ["main.o"]);
    assert_eq!(log.why("lib.a(used.o)").len(), 1);
    assert_eq!(log.live.len(), 2);
    assert_eq!(log.live[0].symbol, "lib.a(used.o):(used_helper)");
    assert_eq!(log.live[0].chain, ["main.o:(_start) (entry point)"]);
    let removed: Vec<(&str, &str)> = log
        .discarded
        .iter()
        .map(|d| (d.input.as_str(), d.symbol.name.as_str()))
        .collect();
    assert!(
        removed.contains(&("main.o", ".text.unused_here")),
        "{removed:?}"
    );
    assert!(
        removed.contains(&("lib.a(used.o)", ".text.dead_in_used")),
        "{removed:?}"
    );
}

#[test]
fn ld64_why_load_and_why_live() {
    let log = parse(&linkmap("macho.log"));
    assert_eq!(log.loads.len(), 1);
    assert_eq!(log.loads[0].loaded.as_deref(), Some("lib.a(used.o)"));
    assert_eq!(log.loads[0].symbol.name, "_used_helper");
    assert_eq!(log.live.len(), 2);
    let used = log
        .live
        .iter()
        .find(|l| l.symbol == "lib.a(used.o):(_used_helper)")
        .unwrap();
    assert_eq!(used.chain, ["main.o:(__start)"]);
}

#[test]
fn gnu_ld_map_members_and_gc_sections() {
    let text = "\
Archive member included to satisfy reference by file (symbol)

/usr/lib/x86_64-linux-gnu/libc.a(printf.o)
                              main.o (printf)
/usr/lib/x86_64-linux-gnu/libc.a(vfprintf-internal.o)
                              /usr/lib/x86_64-linux-gnu/libc.a(printf.o) (__vfprintf_internal)
libfoo.a(foo.o)               main.o (foo)

Discarded input sections

 .note.GNU-stack
                0x0000000000000000        0x0 main.o
/usr/bin/ld: removing unused section '.text.unused' in file 'main.o'
";
    let log = parse(text);
    let got: Vec<(&str, &str, &str)> = log
        .loads
        .iter()
        .map(|l| {
            (
                l.loaded.as_deref().unwrap(),
                l.symbol.name.as_str(),
                l.referenced_in[0].as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                "/usr/lib/x86_64-linux-gnu/libc.a(printf.o)",
                "printf",
                "main.o"
            ),
            (
                "/usr/lib/x86_64-linux-gnu/libc.a(vfprintf-internal.o)",
                "__vfprintf_internal",
                "/usr/lib/x86_64-linux-gnu/libc.a(printf.o)"
            ),
            ("libfoo.a(foo.o)", "foo", "main.o"),
        ]
    );
    // Why vfprintf is there: printf.o wanted it, and main.o wanted printf.
    let why = log.why("/usr/lib/x86_64-linux-gnu/libc.a(vfprintf-internal.o)");
    assert_eq!(why.len(), 2, "{why:?}");
    assert_eq!(log.discarded.len(), 1);
    assert_eq!(log.discarded[0].symbol.name, ".text.unused");
}

#[test]
fn unix_damage() {
    for text in [
        "live symbol: \n>>> referenced by: ",
        "x forced load of ",
        "Archive member included to satisfy reference by file (symbol)\n(\n ( (",
        "removing unused section :(",
        "reference\textracted\tsymbol\n\t\t\n",
    ] {
        let _ = parse(text);
        for n in 0..text.len() {
            if text.is_char_boundary(n) {
                let _ = parse(&text[..n]);
            }
        }
    }
}

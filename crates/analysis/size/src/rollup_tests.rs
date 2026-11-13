use super::*;

/// A rollup from (labels, vm, file) leaves.
fn rollup(leaves: &[(&[&str], i64, i64)]) -> Rollup {
    let mut r = Rollup::default();
    for (names, vm, file) in leaves {
        let names: Vec<Arc<str>> = names.iter().map(|n| Arc::from(*n)).collect();
        let refs: Vec<&Arc<str>> = names.iter().collect();
        r.add(&refs, *vm, true);
        r.add(&refs, *file, false);
    }
    r
}

fn names(rows: &[Row]) -> Vec<&str> {
    rows.iter().map(|r| r.name.as_str()).collect()
}

#[test]
fn sizes_print_like_bloaty() {
    assert_eq!(si(0, false), "      0");
    assert_eq!(si(1000, false), "   1000");
    assert_eq!(si(1024, false), "   1024");
    assert_eq!(si(1025, false), " 1.00Ki");
    assert_eq!(si(10 * 1024 + 512, false), " 10.5Ki");
    assert_eq!(si(911 * 1024, false), "  911Ki");
    assert_eq!(si(105 * 1024 * 1024, false), "  105Mi");
    assert_eq!(si(3 * 1024 * 1024 * 1024 * 1024, false), " 3072Gi");
    assert_eq!(si(-2048, true), "-2.00Ki");
    assert_eq!(si(2048, true), "+2.00Ki");
    assert_eq!(si(500, true), "   +500");
    assert_eq!(si(-500, true), "   -500");
}

#[test]
fn small_rows_fold_into_others_by_a_threshold() {
    assert_eq!(Threshold::parse("512"), Some(Threshold::Bytes(512)));
    assert_eq!(Threshold::parse("4k"), Some(Threshold::Bytes(4096)));
    assert_eq!(Threshold::parse("1.5M"), Some(Threshold::Bytes(1_572_864)));
    assert_eq!(Threshold::parse(" 0.5% "), Some(Threshold::Percent(0.5)));
    for bad in ["", "k", "-1", "x%", "1q", "nan"] {
        assert_eq!(Threshold::parse(bad), None, "{bad}");
    }
    let r = rollup(&[
        (&["a"], 1000, 1000),
        (&["b"], 400, 400),
        (&["c"], 50, 50),
        (&["d"], 30, 30),
        (&["e"], 20, 20),
    ]);
    let report = |min| {
        let options = Options {
            max_rows: usize::MAX,
            min,
            ..Options::default()
        };
        names(&Report::new(&["x"], &r, None, &options).total.children)
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(report(Threshold::Bytes(100)), ["a", "b", "[3 Others]"]);
    // 5% of 1500 is 75.
    assert_eq!(report(Threshold::Percent(5.0)), ["a", "b", "[3 Others]"]);
    assert_eq!(
        report(Threshold::Percent(2.5)),
        ["a", "b", "[2 Others]", "c"]
    );
    // One row alone isn't folded.
    assert_eq!(report(Threshold::Bytes(25)), ["a", "b", "c", "d", "e"]);
    assert_eq!(report(Threshold::None).len(), 5);
}

#[test]
fn percentages_print_like_bloaty() {
    assert_eq!(percent_string(100.0, false), "100.0%");
    assert_eq!(percent_string(5.25, false), "  5.2%");
    assert_eq!(percent_string(f64::NAN, false), "  NAN%");
    assert_eq!(percent_string(0.0, true), " [ = ]");
    assert_eq!(percent_string(f64::NAN, true), " [ = ]");
    assert_eq!(percent_string(-100.0, true), " [DEL]");
    assert_eq!(percent_string(f64::INFINITY, true), " [NEW]");
    assert_eq!(percent_string(5.0, true), " +5.0%");
    assert_eq!(percent_string(-5.0, true), " -5.0%");
    assert_eq!(percent_string(50.0, true), "  +50%");
    assert_eq!(percent_string(5000.0, true), "+50e2%");
}

#[test]
fn rows_sort_and_fold_into_others() {
    let r = rollup(&[
        (&[".text", "a"], 100, 100),
        (&[".text", "b"], 300, 300),
        (&[".text", "c"], 50, 60),
        (&[".text", "d"], 50, 60),
        (&[".bss"], 1000, 0),
        (&[".data"], 10, 2000),
    ]);
    let options = Options {
        max_rows: 2,
        ..Options::default()
    };
    let report = Report::new(&["sections", "symbols"], &r, None, &options);
    assert_eq!((report.total.vm, report.total.file), (1510, 2520));
    // By the larger of the two sizes: .data (2000 file), .bss (1000 vm);
    // the rest (.text) is Others.
    assert_eq!(
        names(&report.total.children),
        [".data", ".bss", "[1 Others]"]
    );
    let others = &report.total.children[2];
    assert_eq!((others.vm, others.file, others.other_count), (500, 520, 1));
    assert!(others.children.is_empty());
    let options = Options {
        max_rows: 20,
        sort_by: SortBy::Vm,
        ..Options::default()
    };
    let report = Report::new(&["sections", "symbols"], &r, None, &options);
    assert_eq!(names(&report.total.children), [".bss", ".text", ".data"]);
    let text = &report.total.children[1];
    // Ties go by name.
    assert_eq!(names(&text.children), ["b", "a", "c", "d"]);
    assert!((text.children[0].vm_percent - 300.0 / 500.0 * 100.0).abs() < 1e-9);
    // A lone child with its parent's label isn't shown.
    let r = rollup(&[(&[".data", ".data"], 10, 10)]);
    let report = Report::new(&["a", "b"], &r, None, &Options::default());
    assert!(report.total.children[0].children.is_empty());
    // Nor a lone [None] below the top.
    let r = rollup(&[(&[".data", "[None]"], 10, 10)]);
    let report = Report::new(&["a", "b"], &r, None, &Options::default());
    assert!(report.total.children[0].children.is_empty());
}

#[test]
fn pretty_output() {
    let r = rollup(&[
        (&[".text", "f"], 1024, 1024),
        (&[".text", "[section .text]"], 0, 512),
        (&[".bss", "[section .bss]"], 2048, 0),
    ]);
    let options = Options::default();
    let report = Report::new(&["sections", "symbols"], &r, None, &options);
    assert_eq!(
        report.pretty(&options),
        [
            "    FILE SIZE        VM SIZE    ",
            " --------------  -------------- ",
            "   0.0%       0  66.7%  2.00Ki    .bss",
            " 100.0%  1.50Ki  33.3%    1024    .text",
            "    66.7%    1024 100.0%    1024    f",
            "    33.3%     512   0.0%       0    [section .text]",
            " 100.0%  1.50Ki 100.0%  3.00Ki    TOTAL",
            "",
        ]
        .join("\n")
    );
    // Only memory sizes: rows without any are left out.
    let vm = Options {
        domain: Domain::Vm,
        ..Options::default()
    };
    let text = report.pretty(&vm);
    assert!(text.starts_with("     VM SIZE    \n -------------- \n"));
    assert!(!text.contains("[section .text]"), "{text}");
}

#[test]
fn diffs() {
    let old = rollup(&[
        (&[".text"], 100, 100),
        (&[".data"], 50, 50),
        (&[".gone"], 10, 10),
    ]);
    let new = rollup(&[
        (&[".text"], 150, 150),
        (&[".data"], 50, 50),
        (&[".new"], 5, 5),
    ]);
    let options = Options::default();
    let report = Report::new(&["sections"], &new, Some(&old), &options);
    assert!(report.diff);
    assert_eq!((report.total.vm, report.total.file), (45, 45));
    assert_eq!(names(&report.total.children), [".text", ".new", ".gone"]);
    let gone = &report.total.children[2];
    assert_eq!((gone.vm, gone.old_vm), (-10, 10));
    assert_eq!(gone.vm_percent, -100.0);
    assert!(report.total.children[1].vm_percent.is_infinite());
    assert_eq!(report.total.children[0].vm_percent, 50.0);
    let text = report.pretty(&options);
    assert!(
        text.contains("   +50%     +50   +50%     +50    .text"),
        "{text}"
    );
    assert!(
        text.contains("  [DEL]     -10  [DEL]     -10    .gone"),
        "{text}"
    );
    assert!(
        text.contains("  [NEW]      +5  [NEW]      +5    .new"),
        "{text}"
    );
    let csv = report.csv(false);
    assert_eq!(
        csv.lines().next(),
        Some(
            "sections,vmsize,filesize,original_vmsize,original_filesize,current_vmsize,current_filesize"
        )
    );
    assert!(csv.contains("\n.gone,-10,-10,10,10,0,0\n"), "{csv}");
}

#[test]
fn csv_tsv_and_json() {
    let r = rollup(&[
        (&[".text", "f(int, char)"], 10, 12),
        (&[".text", "say \"hi\""], 5, 5),
        (&[".data"], 3, 4),
    ]);
    let report = Report::new(&["sections", "symbols"], &r, None, &Options::default());
    assert_eq!(
        report.csv(false),
        "sections,symbols,vmsize,filesize\n\
         .text,\"f(int, char)\",10,12\n\
         .text,\"say \"\"hi\"\"\",5,5\n\
         .data,,3,4\n"
    );
    assert_eq!(
        report.csv(true),
        "sections\tsymbols\tvmsize\tfilesize\n\
         .text\tf(int, char)\t10\t12\n\
         .text\tsay \"hi\"\t5\t5\n\
         .data\t\t3\t4\n"
    );
    let json = report.json();
    assert!(json.starts_with(
        "{\"sources\":[\"sections\",\"symbols\"],\"diff\":false,\"total\":{\"name\":\"TOTAL\",\"vm\":18,\"file\":21,\"children\":["
    ));
    assert!(
        json.contains("{\"name\":\"say \\\"hi\\\"\",\"vm\":5,\"file\":5}"),
        "{json}"
    );
}

#[test]
fn json_escapes_control_characters() {
    // Labels are escaped as serde_json escapes them.
    let out = serde_json::to_string("a\nb\t\\\u{1}é").unwrap();
    assert_eq!(out, "\"a\\nb\\t\\\\\\u0001é\"");
    assert_eq!(csv_escape("plain"), "plain");
}

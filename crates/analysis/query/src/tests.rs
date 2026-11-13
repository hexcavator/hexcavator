use super::*;

const COLUMNS: [Column; 5] = [
    Column {
        name: "name",
        kind: Kind::Str,
        summable: false,
        doc: "",
    },
    Column {
        name: "kind",
        kind: Kind::Str,
        summable: false,
        doc: "",
    },
    Column {
        name: "size",
        kind: Kind::Int,
        summable: true,
        doc: "",
    },
    Column {
        name: "lib",
        kind: Kind::Str,
        summable: false,
        doc: "",
    },
    Column {
        name: "folded",
        kind: Kind::Bool,
        summable: false,
        doc: "",
    },
];

struct Rows(Vec<(&'static str, &'static str, u64, Option<&'static str>, bool)>);

impl Table for Rows {
    fn columns(&self) -> &[Column] {
        &COLUMNS
    }
    fn rows(&self) -> usize {
        self.0.len()
    }
    fn cell(&self, row: usize, column: usize) -> Value<'_> {
        let r = &self.0[row];
        match column {
            0 => Value::Str(r.0.into()),
            1 => Value::Str(r.1.into()),
            2 => Value::Int(r.2),
            3 => r.3.map_or(Value::Null, |l| Value::Str(l.into())),
            _ => Value::Bool(r.4),
        }
    }
}

fn table() -> Rows {
    Rows(vec![
        (
            "std::vector<int>::push_back",
            "function",
            300,
            Some("libcpmt"),
            false,
        ),
        (
            "std::vector<long>::push_back",
            "function",
            300,
            Some("libcpmt"),
            true,
        ),
        ("main", "function", 2000, None, false),
        ("table", "data", 5000, Some("app"), false),
        ("helper", "function", 40, Some("app"), false),
        ("`string'", "string", 12, Some("app"), false),
    ])
}

fn names(q: &str) -> Vec<String> {
    let query = parse(q, &COLUMNS).unwrap_or_else(|e| panic!("{q}: {e}"));
    let out = run(&query, &table()).unwrap();
    let i = out.columns.iter().position(|c| c == "name").unwrap();
    out.rows.iter().map(|r| r[i].text().into_owned()).collect()
}

#[test]
fn filters() {
    assert_eq!(names("kind=data"), ["table"]);
    assert_eq!(
        names("kind = function size>=300 not folded"),
        ["std::vector<int>::push_back", "main"]
    );
    assert_eq!(names("size > 1k"), ["main", "table"]);
    assert_eq!(names("size>0x7CF and size<=2000"), ["main"]);
    assert_eq!(
        names("name~'^std::' or kind=data"),
        [
            "std::vector<int>::push_back",
            "std::vector<long>::push_back",
            "table"
        ]
    );
    assert_eq!(
        names("name!~'push' (kind=data or size<50)"),
        ["table", "helper", "`string'"]
    );
    assert_eq!(names("folded"), ["std::vector<long>::push_back"]);
    assert_eq!(
        names("folded=false lib='app'"),
        ["table", "helper", "`string'"]
    );
    assert_eq!(names("name=\"`string'\""), ["`string'"]);
    assert_eq!(names("name~'(?i)MAIN'"), ["main"]);
    // An unknown value equals nothing, and differs from everything.
    assert_eq!(names("lib=app or lib!=app").len(), 6);
    assert_eq!(names("lib=libcpmt").len(), 2);
    assert!(names("lib!=libcpmt").contains(&"main".to_string()));
    assert!(!names("lib~'.'").contains(&"main".to_string()));
    assert!(names("lib!~'cpmt'").contains(&"main".to_string()));
    // No filter: everything.
    assert_eq!(names("").len(), 6);
    assert_eq!(names("NAME=main KIND=function"), ["main"]);
}

#[test]
fn grouping_sorting_limits() {
    let out = run(&parse("group by lib", &COLUMNS).unwrap(), &table()).unwrap();
    assert_eq!(out.columns, ["lib", "count", "size"]);
    // By size, largest first; an unknown library is a group of its own.
    assert_eq!(
        out.rows,
        [
            vec![Value::Str("app".into()), Value::Int(3), Value::Int(5052)],
            vec![Value::Null, Value::Int(1), Value::Int(2000)],
            vec![Value::Str("libcpmt".into()), Value::Int(2), Value::Int(600)],
        ]
    );
    assert_eq!(out.matched, 6);
    let out = run(
        &parse(
            "kind=function group by lib, kind sort by count desc, lib limit 1",
            &COLUMNS,
        )
        .unwrap(),
        &table(),
    )
    .unwrap();
    assert_eq!(out.columns, ["lib", "kind", "count", "size"]);
    assert_eq!(
        out.rows,
        [vec![
            Value::Str("libcpmt".into()),
            Value::Str("function".into()),
            Value::Int(2),
            Value::Int(600)
        ]]
    );
    assert_eq!(out.matched, 4);
    let out = run(
        &parse("select name, size sort by size, name limit 3", &COLUMNS).unwrap(),
        &table(),
    )
    .unwrap();
    assert_eq!(out.columns, ["name", "size"]);
    assert_eq!(
        out.rows,
        [
            vec![Value::Str("`string'".into()), Value::Int(12)],
            vec![Value::Str("helper".into()), Value::Int(40)],
            vec![
                Value::Str("std::vector<int>::push_back".into()),
                Value::Int(300)
            ],
        ]
    );
    assert_eq!(names("sort by size desc limit 2"), ["table", "main"]);
    assert_eq!(names("limit 0"), Vec::<String>::new());
    let err = run(&parse("sort by nope", &COLUMNS).unwrap(), &table()).unwrap_err();
    assert!(err.message.contains("can't sort by 'nope'"), "{err}");
}

#[test]
fn errors() {
    let e = |q: &str| parse(q, &COLUMNS).unwrap_err();
    assert_eq!(e("nope=1").at, 0);
    assert!(
        e("nope=1")
            .message
            .contains("no column 'nope' (the columns are name, kind, size, lib, folded)")
    );
    assert!(e("size=big").message.contains("'size' is a number"));
    assert_eq!(e("size=big").at, 5);
    assert!(e("size~'1'").message.contains("~ and !~ match text"));
    assert!(e("name~'('").message.contains("not a regular expression"));
    assert!(e("name").message.contains("an operator after 'name'"));
    assert!(e("name=").message.contains("a value to compare"));
    assert!(e("name='open").message.contains("no closing quote"));
    assert!(e("(name=a").message.contains("a ')'"));
    assert!(e("name=a)").message.contains("no '('"));
    assert!(e("group lib").message.contains("'by' after 'group'"));
    assert!(e("limit many").message.contains("not a number"));
    assert!(e("folded=maybe").message.contains("true or false"));
    assert!(e("name ! a").message.contains("'!' needs"));
    assert!(
        e("group by lib select name")
            .message
            .contains("don't go together")
    );
    assert_eq!(e("kind=a or").at, 9);
    // Numbers that overflow are not numbers.
    assert!(
        e("size=99999999999999999999")
            .message
            .contains("is a number")
    );
    assert!(e("size=99999999999G").message.contains("is a number"));
}

#[test]
fn values() {
    assert_eq!(Value::Null.text(), "-");
    assert_eq!(Value::Bool(true).text(), "true");
    assert_eq!(Value::Int(7).text(), "7");
    let q = parse("size=4k", &COLUMNS).unwrap();
    assert!(matches!(
        q.filter,
        Some(Expr::Cmp {
            value: Literal::Int(4096),
            ..
        })
    ));
}

/// Queries built to nest deeply or to chain many comparisons fail to
/// parse (on a small stack), rather than recursing without bound in the
/// parser, or in evaluating or dropping the expression.
#[test]
fn hostile_queries() {
    std::thread::Builder::new()
        .stack_size(128 << 10)
        .spawn(|| {
            let e = |q: &str| parse(q, &COLUMNS).unwrap_err().message;
            assert!(e(&format!("{}folded", "not ".repeat(100_000))).contains("nested"));
            assert!(
                e(&format!(
                    "{}folded{}",
                    "(".repeat(100_000),
                    ")".repeat(100_000)
                ))
                .contains("nested")
            );
            let chain = |n: usize, sep: &str| vec!["size>1"; n].join(sep);
            assert!(e(&chain(100_000, " and ")).contains("comparisons"));
            assert!(e(&chain(100_000, " or ")).contains("comparisons"));
            assert!(e(&chain(100_000, " ")).contains("comparisons"));
            // At the bounds, they parse and evaluate.
            let q = parse(
                &format!("{}folded{}", "(".repeat(16), ")".repeat(16)),
                &COLUMNS,
            );
            assert!(q.is_ok());
            assert!(parse(&chain(1024, " and "), &COLUMNS).is_ok());
        })
        .unwrap()
        .join()
        .unwrap();
}

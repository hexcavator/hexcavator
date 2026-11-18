//! WPA's filter queries: read, and held (or not) by rows.

use hexcavator_trace_analysis::wpa_query::{Cell, Op, Query};

/// Whether a row of `(column, cell)` holds `query`.
fn holds(query: &str, row: &[(&str, Cell)]) -> bool {
    let q = Query::parse(query).unwrap_or_else(|e| panic!("{query}: {e}"));
    q.holds(&|c: &str| {
        row.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(c))
            .map(|(_, v)| v.clone())
    })
}

fn text(s: &str) -> Cell {
    Cell::Text(s.to_string())
}

#[test]
fn reads_conditions_and_joins() {
    assert_eq!(
        Query::parse(r#"[Process Name]:="a ""b"" c""#).unwrap(),
        Query::Is {
            column: "Process Name".into(),
            op: Op::Equal,
            value: r#"a "b" c"#.into()
        }
    );
    let q = Query::parse("([Task Name]:=A [Opcode Name]:=\"win:Stop\") OR NOT [Id]:>=5").unwrap();
    let Query::Any(terms) = &q else {
        panic!("{q:?}")
    };
    assert!(matches!(&terms[0], Query::All(f) if f.len() == 2));
    assert!(matches!(&terms[1], Query::Not(_)));
    assert_eq!(q.columns(), ["Task Name", "Opcode Name", "Id"]);
    // Every operator.
    for (text, op) in [
        (":=", Op::Equal),
        (":<>", Op::NotEqual),
        (":~=", Op::Contains),
        (":~<", Op::StartsWith),
        (":~>", Op::EndsWith),
        (":&=", Op::AnyBits),
        (":<", Op::Less),
        (":<=", Op::LessOrEqual),
        (":>", Op::Greater),
        (":>=", Op::GreaterOrEqual),
    ] {
        let q = Query::parse(&format!("[C]{text}1")).unwrap();
        assert!(matches!(q, Query::Is { op: o, .. } if o == op), "{text}");
    }
    // AND, && and || are words for side by side and OR.
    assert_eq!(
        Query::parse("[A]:=1 AND [B]:=2").unwrap(),
        Query::parse("[A]:=1 [B]:=2").unwrap()
    );
    assert_eq!(
        Query::parse("[A]:=1 && [B]:=2 || [C]:=3").unwrap(),
        Query::parse("[A]:=1 [B]:=2 OR [C]:=3").unwrap()
    );
}

#[test]
fn bad_queries_are_errors() {
    for q in [
        "",
        "[A]",
        "[A]:=",
        "[A:=1",
        "[A]:=\"open",
        "([A]:=1",
        "[A]:=1 OR",
        "A:=1",
        "[A]:=1)",
        &"(".repeat(100),
    ] {
        assert!(Query::parse(q).is_err(), "{q:?}");
    }
}

#[test]
fn rows_hold_queries() {
    let row = [
        ("Process Name", text("App.EXE")),
        ("IO Type", text("Write")),
        ("Size", Cell::Number(4096.0)),
        ("Keyword", text("0x8000000000000010")),
        ("Thread Name", text("")),
    ];
    // Text: without case.
    assert!(holds(r#"[Process Name]:="app.exe""#, &row));
    assert!(holds("[IO Type]:=Write", &row));
    assert!(!holds("[IO Type]:=Read", &row));
    assert!(holds("[IO Type]:<>Read", &row));
    assert!(holds("[Process Name]:~=PP.e", &row));
    assert!(holds("[Process Name]:~<app", &row));
    assert!(holds("[Process Name]:~>.exe", &row));
    assert!(!holds("[Process Name]:~<exe", &row));
    // Numbers: as numbers.
    assert!(holds("[Size]:>=4096", &row));
    assert!(
        holds("[Size]:>1000", &row),
        "not as text: '4096' < '1000' isn't the question"
    );
    assert!(holds("[Size]:=0x1000", &row));
    assert!(!holds("[Size]:<4096", &row));
    assert!(holds("[Keyword]:&=0x10", &row));
    assert!(!holds("[Keyword]:&=0x20", &row));
    assert!(!holds("[Keyword]:&=x", &row));
    // Joins.
    assert!(holds("[IO Type]:=Read OR [IO Type]:=Write", &row));
    assert!(!holds("[IO Type]:=Write [Size]:<10", &row));
    assert!(holds("NOT [IO Type]:=Read", &row));
    assert!(holds(
        "([IO Type]:=Read [Size]:<10) OR ([IO Type]:=Write [Size]:>10)",
        &row
    ));
    // A column the row hasn't: only "not equal" holds.
    assert!(!holds("[Missing]:=1", &row));
    assert!(holds("[Missing]:<>1", &row));
    // An empty value.
    assert!(holds(r#"[Thread Name]:="""#, &row));
}

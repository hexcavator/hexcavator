//! WPA profiles, mapped to Stackrabbit's tabs and parameters.

use hexcavator_trace_analysis::wpa_profile::{Column, Graph, Preset};
use serde_json::json;
use stackrabbit::profile::map;

fn graph(table: Option<&str>, item: Option<&str>, keys: &[&str], others: &[&str]) -> Graph {
    let column = |n: &&str| Column {
        name: (*n).to_string(),
        visible: true,
        ..Column::default()
    };
    Graph {
        table: table.map(str::to_string),
        item: item.map(str::to_string),
        preset: Preset {
            name: "p".into(),
            columns: keys.iter().chain(others).map(column).collect(),
            key_columns: keys.len(),
            ..Preset::default()
        },
    }
}

#[test]
fn cpu_presets_group_the_stack_tree() {
    let m = map(&graph(
        None,
        Some("CpuSamplingGraphTreeItem"),
        &[
            "Process Name",
            "Process",
            "Thread Name",
            "Thread Activity Tag",
            "Stack",
            "Module",
        ],
        &["Weight"],
    ));
    assert_eq!(
        (m.table.as_str(), m.tab),
        ("CPU Usage (Sampled)", Some("stacks"))
    );
    assert_eq!(
        m.params,
        json!({"source": "samples", "groupBy": ["process", "thread", "tag"]})
    );
    assert!(m.skipped.is_empty(), "{:?}", m.skipped);
    // Precise, by its GUID; a column it can't group by is said.
    let m = map(&graph(
        Some("c58f5fea-0319-4046-932d-e695ebe20b47"),
        None,
        &["New Process Name", "Switch-In Time", "New Thread Stack"],
        &[],
    ));
    assert_eq!(m.params["source"], "running");
    assert_eq!(m.params["groupBy"], json!(["process"]));
    assert_eq!(m.skipped, ["grouping by Switch-In Time"]);
    // Functions without stacks: the functions tab.
    let m = map(&graph(
        None,
        Some("CpuSamplingGraphTreeItem"),
        &["Module", "Function"],
        &[],
    ));
    assert_eq!(m.tab, Some("functions"));
    assert!(m.skipped.is_empty(), "{:?}", m.skipped);
}

#[test]
fn summary_presets_choose_the_grouping() {
    let disk = Some("12c5387c-58ca-45d4-a5c6-450475c30e06");
    let m = map(&graph(
        disk,
        None,
        &["Process Name", "Process", "IO Type"],
        &["Size"],
    ));
    assert_eq!(
        (m.tab, &m.params),
        (Some("disk"), &json!({"by": "process"}))
    );
    assert_eq!(
        m.skipped,
        ["grouping further by IO Type"],
        "Process is Process Name's grouping"
    );
    let m = map(&graph(disk, None, &["Thread ID", "Path Name"], &[]));
    assert_eq!(m.params, json!({"by": "file"}));
    assert_eq!(m.skipped, ["grouping first by Thread ID"]);
    let m = map(&graph(
        Some("3dd69094-4675-4607-9fb4-0042b9e1a610"),
        None,
        &["Process Name"],
        &[],
    ));
    assert_eq!((m.tab, &m.params), (Some("memory"), &json!({"by": "name"})));
    let m = map(&graph(
        Some("7c60aeff-a47f-4ba8-942c-d2b154087ab9"),
        None,
        &["File Name"],
        &[],
    ));
    assert_eq!(
        (m.tab, &m.params),
        (Some("hardfaults"), &json!({"by": "file"}))
    );
    let m = map(&graph(
        None,
        Some("CommitLifetimeGraphTreeItem"),
        &["Process Name", "Impacting Type"],
        &[],
    ));
    assert_eq!(m.tab, Some("vmem"));
    assert_eq!(m.skipped, ["grouping further by Impacting Type"]);
    let m = map(&graph(
        None,
        Some("FullHeapGraphTreeItem"),
        &["Thread ID"],
        &[],
    ));
    assert_eq!((m.tab, &m.params), (Some("heap"), &json!({"by": "thread"})));
}

#[test]
fn other_tabs_list_their_rows_and_say_what_they_dont() {
    let mut g = graph(
        None,
        Some("GenericEventsGraphTreeItem"),
        &["Provider Name", "Task Name", "Process"],
        &[],
    );
    g.preset.filter = Some("[Provider Name]:=\"Microsoft-Windows-Foo\"".into());
    g.preset.highlights = 2;
    let m = map(&g);
    assert_eq!(
        (m.tab, &m.params),
        (
            Some("events"),
            &json!({"filter": "[Provider Name]:=\"Microsoft-Windows-Foo\""})
        )
    );
    assert_eq!(
        m.skipped,
        ["grouping by Process", "its 2 highlight(s)"],
        "the filter is applied"
    );
    // A filter on columns the tab has: applied, whatever it is.
    g.preset.filter = Some("([Task Name]:=X [Opcode Name]:=\"win:Stop\") OR [Id]:=5".into());
    assert!(map(&g).params.get("filter").is_some());
    // One on a column it lacks, one it can't read, one on a tab without
    // filters: said, with why.
    g.preset.filter = Some("[Process]:=x".into());
    let m = map(&g);
    assert_eq!(m.params, json!({}));
    assert!(
        m.skipped
            .contains(&"its filter ([Process]:=x): no Process column here".to_string()),
        "{:?}",
        m.skipped
    );
    g.preset.filter = Some("[Task Name]:=".into());
    assert!(map(&g).skipped.iter().any(|s| s.contains("unreadable")));
    let mut d = graph(
        Some("12c5387c-58ca-45d4-a5c6-450475c30e06"),
        None,
        &["IO Type"],
        &[],
    );
    d.preset.filter = Some("[IO Type]:=Write".into());
    assert_eq!(
        map(&d).params,
        json!({"by": "type", "filter": "[IO Type]:=Write"})
    );
    let mut t = graph(
        None,
        Some("CpuSamplingGraphTreeItem"),
        &["Process Name"],
        &[],
    );
    t.preset.filter = Some("[Process Name]:=Idle".into());
    assert!(map(&t).skipped.iter().any(|s| s.contains("takes none yet")));
    let m = map(&graph(
        None,
        Some("RegionsGraphTreeItem"),
        &["Region Friendly Name", "Region"],
        &[],
    ));
    assert_eq!(m.tab, Some("regions"));
    assert!(m.skipped.is_empty());
    let m = map(&graph(
        Some("b186f02d-8d06-4bbb-9ad1-abf7985fb61a"),
        None,
        &["Process Name", "Creation Stack"],
        &[],
    ));
    assert_eq!(m.tab, Some("processes"));
    assert_eq!(m.skipped, ["grouping by Creation Stack"]);
}

#[test]
fn tables_stackrabbit_lacks_are_skipped_by_name() {
    let m = map(&graph(
        Some("a1df89f9-5b2a-449e-aaab-1bcc3fd25c84"),
        None,
        &[],
        &[],
    ));
    assert_eq!((m.table.as_str(), m.tab), ("Images", None));
    assert_eq!(m.skipped, ["Images: Stackrabbit has no such table yet"]);
    let m = map(&graph(
        Some("00000000-1111-2222-3333-444444444444"),
        None,
        &[],
        &[],
    ));
    assert_eq!(m.table, "00000000-1111-2222-3333-444444444444");
    assert_eq!(m.skipped, ["a table Stackrabbit doesn't know"]);
}

#[test]
fn the_command_reports_a_profile() {
    let dir = crate::common::scratch("cli-profile");
    let file = dir.join("p.wpaProfile");
    std::fs::write(
        &file,
        r#"<WpaProfileContainer><Content><Views><View Title="Disk"><Graphs><Graph Guid="12C5387C-58CA-45D4-A5C6-450475C30E06"><Preset Name="By Type" KeyColumnCount="1"><Columns><Column Name="IO Type"/></Columns></Preset></Graph><Graph Guid="a1df89f9-5b2a-449e-aaab-1bcc3fd25c84"><Preset Name="Images"/></Graph></Graphs></View></Views></Content></WpaProfileContainer>"#,
    )
    .unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_stackrabbit"))
            .args(args)
            .output()
            .unwrap()
    };
    let o = run(&["profile", file.to_str().unwrap()]);
    assert!(o.status.success());
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("1 of 2 graphs shown"), "{text}");
    assert!(
        text.contains(r#"Disk Usage / By Type: -> disk {"by":"type"}"#),
        "{text}"
    );
    assert!(
        text.contains("skipped: Images: Stackrabbit has no such table yet"),
        "{text}"
    );
    let o = run(&["profile", "-json", file.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        (v["graphs"].as_u64(), v["shown"].as_u64()),
        (Some(2), Some(1))
    );
    assert_eq!(v["views"][0]["graphs"][0]["tab"], "disk");
    let o = run(&["profile", dir.join("missing.wpaProfile").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    let o = run(&["profile"]);
    assert_eq!(o.status.code(), Some(2));
}

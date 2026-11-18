//! WPA profiles, mapped: each graph of each view of a `.wpaProfile`, the
//! Stackrabbit tab that shows its table and the parameters that show its
//! preset (its grouping, its source), with what of the preset was applied
//! and what wasn't (and why). Tables Stackrabbit doesn't have are named
//! where WPA's own profiles make clear what they are, and skipped.
//!
//! `stackrabbit profile <file>` prints the mapping; the extension applies
//! a graph's tab and parameters.

use std::process::ExitCode;

use hexcavator_trace_analysis::wpa_profile::{Column, Graph, Preset, Profile};
use serde_json::{Map, Value, json};

/// What Stackrabbit shows a table as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shown {
    /// The stack tree, from this source.
    Tree(&'static str),
    /// A summary tab (its name is its request's): its first key column
    /// chooses its grouping, by this map of column names.
    Summary(&'static str, &'static [(&'static str, &'static str)]),
    /// Another tab, as it is.
    Tab(&'static str),
    /// Nothing (yet).
    None,
}

const PROCESS: &[&str] = &[
    "Process",
    "Process Name",
    "Display Name",
    "New Process",
    "New Process Name",
];
const THREAD: &[&str] = &[
    "Thread ID",
    "Thread Id",
    "Thread Name",
    "New Thread Id",
    "ThreadId",
];

const DISK_BY: &[(&str, &str)] = &[
    ("Process", "process"),
    ("Process Name", "process"),
    ("Path Name", "file"),
    ("Path Tree", "file"),
    ("File Extension", "file"),
    ("Path Ext", "file"),
    ("Disk", "disk"),
    ("IO Type", "type"),
];
const FAULTS_BY: &[(&str, &str)] = &[
    ("Process", "process"),
    ("Process Name", "process"),
    ("File Name", "file"),
    ("Path Tree", "file"),
    ("Thread ID", "thread"),
    ("Thread Name", "thread"),
];
const MEMORY_BY: &[(&str, &str)] = &[("Process", "process"), ("Process Name", "name")];
const ALLOCS_BY: &[(&str, &str)] = &[
    ("Process", "process"),
    ("Process Name", "process"),
    ("Thread ID", "thread"),
    ("Thread Name", "thread"),
];

/// The key columns a tab lists its rows by already (applied as they
/// are), by tab.
const NATIVE: &[(&str, &[&str])] = &[
    (
        "regions",
        &["Region", "Region Friendly Name", "Instance Name"],
    ),
    (
        "events",
        &[
            "Provider Name",
            "Provider Id",
            "Task Name",
            "Opcode Name",
            "Opcode/Type",
            "Opcode",
            "Id",
            "Version",
        ],
    ),
    (
        "processes",
        &[
            "Process Name",
            "Process ID",
            "Process",
            "Session ID",
            "Parent Process ID",
            "Parent Process Name",
            "Parent Process",
            "Lifetime",
            "Thread ID",
            "Thread Start Module",
            "Thread Start Function",
            "Thread Start Address",
        ],
    ),
];

/// The tables Stackrabbit knows: by GUID, by XAML graph item, WPA's name
/// for them, and how they're shown.
const TABLES: &[(&str, &str, &str, Shown)] = &[
    (
        "b855361e-7be0-4bc8-a754-3e8507715ca5",
        "CpuSamplingGraphTreeItem",
        "CPU Usage (Sampled)",
        Shown::Tree("samples"),
    ),
    (
        "c58f5fea-0319-4046-932d-e695ebe20b47",
        "CpuSchedulingWithReadyThreadGraphTreeItem",
        "CPU Usage (Precise)",
        Shown::Tree("running"),
    ),
    (
        "4237fcb5-808e-4868-ae15-96772fb57e41",
        "TaggedCpuUsageGraphTreeItem",
        "CPU Usage (Precise), by thread activity",
        Shown::Tree("running"),
    ),
    (
        "12c5387c-58ca-45d4-a5c6-450475c30e06",
        "DiskIOGraphTreeItem",
        "Disk Usage",
        Shown::Summary("disk", DISK_BY),
    ),
    (
        "a4a4ee28-f3e3-43f0-8b35-6fc4e37e8675",
        "",
        "Disk Usage",
        Shown::Summary("disk", DISK_BY),
    ),
    (
        "7c60aeff-a47f-4ba8-942c-d2b154087ab9",
        "",
        "Hard Faults",
        Shown::Summary("hardfaults", FAULTS_BY),
    ),
    (
        "3dd69094-4675-4607-9fb4-0042b9e1a610",
        "",
        "Virtual Memory Snapshots",
        Shown::Summary("memory", MEMORY_BY),
    ),
    (
        "1a64d983-f796-45f8-aa64-ac50b95d0e45",
        "FullHeapGraphTreeItem",
        "Heap Allocations",
        Shown::Summary("heap", ALLOCS_BY),
    ),
    (
        "e6a4a964-3a87-46ef-9762-f9d9b9208051",
        "CommitLifetimeGraphTreeItem",
        "VirtualAlloc Commit Lifetimes",
        Shown::Summary("vmem", ALLOCS_BY),
    ),
    (
        "1ce7fd53-2344-4ea8-acd6-1a0722a51427",
        "RegionsGraphTreeItem",
        "Regions of Interest",
        Shown::Tab("regions"),
    ),
    (
        "04f69f98-176e-4d1c-b44e-97f734996ab8",
        "GenericEventsGraphTreeItem",
        "Generic Events",
        Shown::Tab("events"),
    ),
    (
        "b186f02d-8d06-4bbb-9ad1-abf7985fb61a",
        "",
        "Processes",
        Shown::Tab("processes"),
    ),
    (
        "faa52878-623e-4f74-9ed9-a65e379ccdd5",
        "",
        "Thread Lifetimes",
        Shown::Tab("processes"),
    ),
    // Known, not shown (yet).
    (
        "a1df89f9-5b2a-449e-aaab-1bcc3fd25c84",
        "",
        "Images",
        Shown::None,
    ),
    (
        "cb079a8b-de14-4516-9f83-6c5695b0845a",
        "",
        "Memory Utilization (system-wide)",
        Shown::None,
    ),
    (
        "9cfb2296-2c89-45af-a5bd-23b4885dcbab",
        "",
        "CPU Frequency",
        Shown::None,
    ),
    (
        "04109c2c-d66b-46cf-8fd7-a7ea67c64cb0",
        "",
        "Services",
        Shown::None,
    ),
    (
        "bc4f0890-4a76-4fe7-b014-6ae70677f8f5",
        "ReferenceSetGraphTreeItem",
        "Reference Set",
        Shown::None,
    ),
    (
        "bc84c7f5-2307-4842-944f-39b7daab7df4",
        "TraceLoggingGraphTreeItem",
        "TraceLogging Activities",
        Shown::None,
    ),
    (
        "",
        "JSHeapSnapshotGraphTreeItem",
        "JavaScript Heap Snapshots",
        Shown::None,
    ),
];

/// One graph, mapped.
#[derive(Clone, Debug, PartialEq)]
pub struct Mapped {
    /// WPA's name for its table (or its GUID or item type, if unknown).
    pub table: String,
    /// The preset's name.
    pub preset: String,
    /// The Stackrabbit tab (`stacks`, `disk`, ...), if there is one.
    pub tab: Option<&'static str>,
    /// The parameters that show the preset there.
    pub params: Value,
    /// What of the preset was applied.
    pub applied: Vec<String>,
    /// What wasn't, and why.
    pub skipped: Vec<String>,
}

fn names(columns: &[Column]) -> String {
    columns
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `name` is a stack column (`Stack`, `New Thread Stack`, ...).
fn is_stack(name: &str) -> bool {
    name == "Stack" || name.ends_with(" Stack")
}

/// `graph`, mapped.
pub fn map(graph: &Graph) -> Mapped {
    let found = TABLES.iter().find(|(guid, item, _, _)| {
        graph
            .table
            .as_deref()
            .is_some_and(|t| !guid.is_empty() && t == *guid)
            || graph
                .item
                .as_deref()
                .is_some_and(|i| !item.is_empty() && i == *item)
    });
    let preset = &graph.preset;
    let mut m = Mapped {
        table: found.map_or_else(
            || {
                graph
                    .table
                    .clone()
                    .or_else(|| graph.item.clone())
                    .unwrap_or_else(|| "an unnamed table".to_string())
            },
            |f| f.2.to_string(),
        ),
        preset: preset.name.clone(),
        tab: None,
        params: json!({}),
        applied: Vec::new(),
        skipped: Vec::new(),
    };
    let shown = found.map_or(Shown::None, |f| f.3);
    match shown {
        Shown::None => {
            m.skipped.push(if found.is_some() {
                format!("{}: Stackrabbit has no such table yet", m.table)
            } else {
                "a table Stackrabbit doesn't know".to_string()
            });
            return m;
        }
        Shown::Tree(source) => tree(preset, source, &mut m),
        Shown::Summary(tab, by) => summary(preset, tab, by, &mut m),
        Shown::Tab(tab) => {
            m.tab = Some(tab);
            if tab == "events" {
                events(preset, &mut m);
            }
            let native = NATIVE
                .iter()
                .find(|(t, _)| *t == tab)
                .map_or(&[][..], |n| n.1);
            let (listed, other): (Vec<&Column>, Vec<&Column>) = preset
                .keys()
                .iter()
                .partition(|c| native.contains(&c.name.trim()));
            if !listed.is_empty() {
                m.applied.push(format!(
                    "rows by {}, as the tab lists them",
                    listed
                        .iter()
                        .map(|c| c.name.trim())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !other.is_empty() {
                m.skipped.push(format!(
                    "grouping by {}",
                    other
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    if let Some(f) = &preset.filter
        && !(m.tab == Some("events") && m.params.get("provider").is_some())
    {
        m.skipped.push(format!("its filter ({f})"));
    }
    if preset.highlights > 0 {
        m.skipped
            .push(format!("its {} highlight(s)", preset.highlights));
    }
    m
}

/// A stack tree preset: its key columns before the stack, as groupings.
fn tree(preset: &Preset, source: &'static str, m: &mut Mapped) {
    m.tab = Some("stacks");
    let mut groups: Vec<&str> = Vec::new();
    let mut unknown = Vec::new();
    let keys = preset.keys();
    let stack = keys.iter().position(|c| is_stack(&c.name));
    for c in &keys[..stack.unwrap_or(keys.len())] {
        let g = if PROCESS.contains(&c.name.as_str()) {
            Some("process")
        } else if THREAD.contains(&c.name.as_str()) {
            Some("thread")
        } else if c.name == "CPU" {
            Some("cpu")
        } else if c.name == "Thread Activity Tag" || c.name == "Stack Tag" {
            Some("tag")
        } else {
            None
        };
        match g {
            Some(g) if groups.last() != Some(&g) && !groups.contains(&g) => groups.push(g),
            Some(_) => {}
            // (Frames: the tree's, or the functions tab's.)
            None if c.name == "Module" || c.name == "Function" => {}
            None => unknown.push(c.name.clone()),
        }
    }
    let mut params = Map::new();
    params.insert("source".into(), json!(source));
    params.insert("groupBy".into(), json!(groups));
    m.applied.push(format!(
        "{} by {}",
        if source == "samples" {
            "samples"
        } else {
            "running time"
        },
        if groups.is_empty() {
            "nothing".to_string()
        } else {
            groups.join(", ")
        }
    ));
    if stack.is_some() {
        m.applied.push("its stacks".into());
    } else if keys
        .iter()
        .any(|c| c.name == "Module" || c.name == "Function")
    {
        // (Hot functions or modules, without stacks.)
        m.tab = Some("functions");
        m.applied.push("functions, without stacks".into());
    }
    if !unknown.is_empty() {
        m.skipped
            .push(format!("grouping by {}", unknown.join(", ")));
    }
    m.params = Value::Object(params);
}

/// A summary preset: its first key column, as the tab's grouping.
fn summary(preset: &Preset, tab: &'static str, by: &[(&str, &str)], m: &mut Mapped) {
    m.tab = Some(tab);
    let keys = preset.keys();
    let first = keys
        .iter()
        .position(|c| by.iter().any(|(n, _)| *n == c.name));
    match first {
        Some(i) => {
            let g = by
                .iter()
                .find(|(n, _)| *n == keys[i].name)
                .map_or("", |b| b.1);
            m.params = json!({"by": g});
            m.applied.push(format!("grouped by {g} ({})", keys[i].name));
            if i > 0 {
                m.skipped
                    .push(format!("grouping first by {}", names(&keys[..i])));
            }
            // (Later keys that group the same way are that grouping.)
            let rest: Vec<&Column> = keys[i + 1..]
                .iter()
                .filter(|c| {
                    by.iter()
                        .find(|(n, _)| *n == c.name)
                        .is_none_or(|b| b.1 != g)
                })
                .collect();
            if !rest.is_empty() {
                m.skipped.push(format!(
                    "grouping further by {}",
                    rest.iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        None => {
            if !keys.is_empty() {
                m.skipped.push(format!("grouping by {}", names(keys)));
            }
        }
    }
}

/// A generic events preset: a filter that names one provider lists its
/// events.
fn events(preset: &Preset, m: &mut Mapped) {
    if let Some(p) = preset.filter.as_deref().and_then(single_provider) {
        m.params = json!({"provider": p});
        m.applied.push(format!("the events of {p}"));
    }
}

/// The provider a filter names, if it is just `[Provider Name]:="X"`.
fn single_provider(filter: &str) -> Option<String> {
    let rest = filter.trim().strip_prefix("[Provider Name]:=")?;
    let name = rest.strip_prefix('"')?.strip_suffix('"')?;
    (!name.contains('"')).then(|| name.to_string())
}

/// A profile's views, mapped: `{views: [{title, graphs: [{table, preset,
/// tab, params, applied, skipped}]}], graphs, shown, skipped}`.
pub fn mapped(profile: &Profile) -> Value {
    let mut shown = 0;
    let mut total = 0;
    let views: Vec<Value> = profile
        .views
        .iter()
        .map(|v| {
            let graphs: Vec<Value> = v
                .graphs
                .iter()
                .map(|g| {
                    let m = map(g);
                    total += 1;
                    shown += usize::from(m.tab.is_some());
                    json!({
                        "table": m.table,
                        "preset": m.preset,
                        "tab": m.tab,
                        "params": m.params,
                        "applied": m.applied,
                        "skipped": m.skipped,
                    })
                })
                .collect();
            json!({"title": v.title, "graphs": graphs})
        })
        .collect();
    json!({"views": views, "graphs": total, "shown": shown})
}

/// The profile at `path`, read and mapped.
pub fn read(path: &str) -> Result<Value, String> {
    let text = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    // (WPA writes UTF-8, with or without a byte order mark.)
    let text = String::from_utf8_lossy(&text);
    let profile = Profile::from_xml(&text).map_err(|e| format!("{path}: {e}"))?;
    Ok(mapped(&profile))
}

const USAGE: &str = "\
usage: stackrabbit profile [-json] <file.wpaProfile>...

Reads WPA profiles and prints, for each graph of each view, the Stackrabbit
tab that shows its table and how its preset is shown there: what of it is
applied, and what isn't (and why). With -json, the mapping as JSON.";

/// Runs `stackrabbit profile`.
pub fn run(args: &[String]) -> ExitCode {
    let json_out = args.iter().any(|a| a == "-json" || a == "--json");
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if files.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut failed = false;
    for f in files {
        match read(f) {
            Ok(m) if json_out => {
                println!("{}", serde_json::to_string_pretty(&m).unwrap_or_default());
            }
            Ok(m) => print!("{}", report(f, &m)),
            Err(e) => {
                eprintln!("stackrabbit profile: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// A mapping as text.
fn report(file: &str, m: &Value) -> String {
    let mut out = format!("{file}: {} of {} graphs shown\n", m["shown"], m["graphs"]);
    for v in m["views"].as_array().into_iter().flatten() {
        out.push_str(&format!("  {}\n", v["title"].as_str().unwrap_or("")));
        for g in v["graphs"].as_array().into_iter().flatten() {
            let tab = g["tab"].as_str().map_or_else(
                || "not shown".to_string(),
                |t| format!("-> {t} {}", g["params"]),
            );
            out.push_str(&format!(
                "    {} / {}: {tab}\n",
                g["table"].as_str().unwrap_or(""),
                g["preset"].as_str().unwrap_or("")
            ));
            for s in g["skipped"].as_array().into_iter().flatten() {
                out.push_str(&format!("      skipped: {}\n", s.as_str().unwrap_or("")));
            }
        }
    }
    out
}

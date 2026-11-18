//! WPA profiles (`.wpaProfile`): the views a profile opens, each a list
//! of graphs, each a table (by its GUID) and the preset it shows: the
//! table's columns in order (the first `key_columns` group its rows), how
//! they sort, and its filter. Both of WPA's formats:
//!
//! - `WpaProfile` (XAML): `WpaProfile.Views/AnalysisView`, each with
//!   graph items: a type per table (`CpuSamplingGraphTreeItem`, ...), or
//!   a generic one naming its table by `ClsID`; each item's
//!   `HdvViewModelPreset` (`HdvColumnViewModelPreset` columns).
//! - `WpaProfileContainer` (version 2): `Content/Views/View/Graphs/Graph`,
//!   each naming its table by `Guid`, with its `Preset` (`Columns/Column`).
//!
//! The format isn't documented: this reads what WPA's own profiles hold,
//! and reports what it doesn't know rather than guess.

use crate::xml::{Element, parse};

/// A profile: its views.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    /// The views, in order.
    pub views: Vec<View>,
}

/// A view (a tab of WPA's analysis window): its title and graphs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// Its title.
    pub title: String,
    /// Its graphs, in order.
    pub graphs: Vec<Graph>,
}

/// A graph: a table and the preset it shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    /// The table: its GUID (lowercase), if the profile names it.
    pub table: Option<String>,
    /// The graph item's type (the XAML format's), e.g.
    /// `CpuSamplingGraphTreeItem`.
    pub item: Option<String>,
    /// The preset.
    pub preset: Preset,
}

/// A preset: a table's columns and how it shows them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Preset {
    /// Its name.
    pub name: String,
    /// Its columns, in order.
    pub columns: Vec<Column>,
    /// How many of the first columns group its rows (left of WPA's gold
    /// bar).
    pub key_columns: usize,
    /// Its filter (WPA's query language), if any.
    pub filter: Option<String>,
    /// How many highlight entries it has.
    pub highlights: usize,
}

impl Preset {
    /// The columns its rows are grouped by, in order.
    pub fn keys(&self) -> &[Column] {
        &self.columns[..self.key_columns.min(self.columns.len())]
    }
}

/// A column of a preset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Column {
    /// Its name.
    pub name: String,
    /// Its GUID (lowercase).
    pub guid: String,
    /// Whether it's shown.
    pub visible: bool,
    /// Its sort priority (lower sorts first), if it sorts.
    pub sort_priority: Option<i64>,
    /// Whether it sorts descending.
    pub descending: bool,
    /// How it aggregates (`Sum`, `Max`, ...), if it says.
    pub aggregation: Option<String>,
}

/// An element's name without its namespace prefix.
fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Every element under `e` (depth first), `e` too.
fn descendants(e: &Element) -> Vec<&Element> {
    let mut out = vec![e];
    let mut i = 0;
    while i < out.len() {
        let next = out[i];
        out.extend(next.children.iter());
        i += 1;
    }
    out
}

fn children<'a>(e: &'a Element, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
    e.children.iter().filter(move |c| local(&c.name) == name)
}

fn child<'a>(e: &'a Element, name: &str) -> Option<&'a Element> {
    e.children.iter().find(|c| local(&c.name) == name)
}

impl Profile {
    /// Reads a profile's text (either format).
    pub fn from_xml(text: &str) -> Result<Self, String> {
        let root = parse(text.trim_start_matches('\u{feff}'))?;
        match local(&root.name) {
            "WpaProfile" => Ok(Self::from_xaml(&root)),
            "WpaProfileContainer" => Ok(Self::from_container(&root)),
            other => Err(format!("not a WPA profile (its root is {other})")),
        }
    }

    fn from_xaml(root: &Element) -> Self {
        let views = child(root, "WpaProfile.Views")
            .map(|v| {
                children(v, "AnalysisView")
                    .map(|view| {
                        let title = child(view, "AnalysisView.Title")
                            .and_then(|t| child(t, "ViewTitle"))
                            .and_then(|t| t.attribute("Title"))
                            .unwrap_or("")
                            .to_string();
                        let graphs = view
                            .children
                            .iter()
                            .filter(|g| local(&g.name).ends_with("GraphTreeItem"))
                            .map(|g| {
                                let item = local(&g.name).to_string();
                                let preset = descendants(g)
                                    .into_iter()
                                    .find(|p| local(&p.name) == "HdvViewModelPreset")
                                    .map(preset_xaml)
                                    .unwrap_or_default();
                                Graph {
                                    table: g.attribute("ClsID").map(str::to_ascii_lowercase),
                                    item: Some(item),
                                    preset,
                                }
                            })
                            .collect();
                        View { title, graphs }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { views }
    }

    fn from_container(root: &Element) -> Self {
        let views = child(root, "Content")
            .and_then(|c| child(c, "Views"))
            .map(|v| {
                children(v, "View")
                    .map(|view| View {
                        title: view.attribute("Title").unwrap_or("").to_string(),
                        graphs: child(view, "Graphs")
                            .map(|gs| {
                                children(gs, "Graph")
                                    .map(|g| Graph {
                                        table: g.attribute("Guid").map(str::to_ascii_lowercase),
                                        item: None,
                                        preset: child(g, "Preset")
                                            .map(preset_container)
                                            .unwrap_or_default(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { views }
    }
}

fn number(e: &Element, name: &str) -> Option<i64> {
    e.attribute(name).and_then(|v| v.trim().parse().ok())
}

fn flag(e: &Element, name: &str) -> Option<bool> {
    e.attribute(name).map(|v| v.eq_ignore_ascii_case("true"))
}

fn filter_of(p: &Element) -> Option<String> {
    p.attribute("InitialFilterQuery")
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(str::to_string)
}

fn column(c: &Element) -> Column {
    Column {
        name: c.attribute("Name").unwrap_or("").to_string(),
        guid: c.attribute("Guid").unwrap_or("").to_ascii_lowercase(),
        // (A column that doesn't say is shown.)
        visible: flag(c, "IsVisible").unwrap_or(true),
        sort_priority: number(c, "SortPriority"),
        descending: c
            .attribute("SortOrder")
            .is_some_and(|o| o.eq_ignore_ascii_case("descending")),
        aggregation: c.attribute("AggregationMode").map(str::to_string),
    }
}

fn preset_xaml(p: &Element) -> Preset {
    let columns = child(p, "HdvViewModelPreset.ConfigurableColumns")
        .map(|cs| {
            children(cs, "HdvColumnViewModelPreset")
                .map(column)
                .collect()
        })
        .unwrap_or_default();
    Preset {
        name: p.attribute("Name").unwrap_or("").to_string(),
        columns,
        key_columns: number(p, "KeyColumnCount")
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0),
        filter: filter_of(p),
        highlights: child(p, "HdvViewModelPreset.HighlightEntries").map_or(0, |h| h.children.len()),
    }
}

fn preset_container(p: &Element) -> Preset {
    let columns = child(p, "Columns")
        .map(|cs| children(cs, "Column").map(column).collect())
        .unwrap_or_default();
    Preset {
        name: p.attribute("Name").unwrap_or("").to_string(),
        columns,
        key_columns: number(p, "KeyColumnCount")
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0),
        filter: filter_of(p),
        highlights: child(p, "HighlightEntries").map_or(0, |h| h.children.len()),
    }
}

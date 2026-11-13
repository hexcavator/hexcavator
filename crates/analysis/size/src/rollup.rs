//! bloaty-style reports: sizes rolled up by the labels of one or more data
//! sources (`-d sections,symbols`), as a tree of rows, printed as bloaty
//! prints them (or as CSV, TSV, or JSON), optionally as a diff against a
//! base image.
//!
//! Row rules follow bloaty: children are sorted by size (largest first,
//! then by name), all but the first `max_rows` are folded into
//! `[N Others]`, a lone `[None]` or `[Unmapped]` child of a row isn't
//! shown, nor a lone child with its parent's label, and percentages are of
//! the parent (or, in a diff, of the label's old size).

use std::fmt::Write as _;
use std::sync::Arc;

use crate::rangemap::sweep;
use crate::sources::Maps;
use rustc_hash::FxHashMap;

/// Sizes rolled up by label, one level per source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rollup {
    pub vm: i64,
    pub file: i64,
    pub children: FxHashMap<Arc<str>, Rollup>,
    /// Bytes a source filter left out (top level only).
    pub filtered_vm: i64,
    pub filtered_file: i64,
}

impl Rollup {
    /// Rolls up `maps` (all of their sources, in order).
    pub fn new(maps: &Maps) -> Self {
        let mut r = Rollup::default();
        r.add_maps(maps);
        r
    }

    /// Rolls up only the regions some label of which (at any level)
    /// `filter` matches, as bloaty's `--source-filter`; the rest are counted
    /// in `filtered_vm` and `filtered_file`.
    pub fn filtered(maps: &Maps, filter: Option<&regex::Regex>) -> Self {
        let mut r = Rollup::default();
        r.add_maps_filtered(maps, filter);
        r
    }

    /// Adds `maps`' sizes (several images make one rollup).
    pub fn add_maps(&mut self, maps: &Maps) {
        self.add_maps_filtered(maps, None);
    }

    /// [`Rollup::add_maps`], with a source filter.
    pub fn add_maps_filtered(&mut self, maps: &Maps, filter: Option<&regex::Regex>) {
        let all: Vec<usize> = (0..maps.sources.len()).collect();
        self.add_sources(maps, &all, filter);
    }

    /// Rolls up `maps` by the sources at `which` (indexes into its sources,
    /// one level each, in that order).
    pub fn of_sources(maps: &Maps, which: &[usize]) -> Self {
        let mut r = Rollup::default();
        r.add_sources(maps, which, None);
        r
    }

    fn add_sources(&mut self, maps: &Maps, which: &[usize], filter: Option<&regex::Regex>) {
        let chosen: Vec<&crate::rangemap::DualMap> =
            which.iter().map(|&k| &maps.sources[k].1).collect();
        // Whether the filter matches each label, decided once per label.
        let mut matches: FxHashMap<crate::rangemap::Label, bool> = FxHashMap::default();
        for vm in [true, false] {
            fn domain(d: &crate::rangemap::DualMap, vm: bool) -> &crate::rangemap::RangeMap {
                if vm { &d.vm } else { &d.file }
            }
            // Each source's short fallback ranges after a labeled one count
            // as its padding, as bloaty counts them (where bloaty is what
            // reports follow).
            let absorbed: Vec<crate::rangemap::RangeMap> = if maps.absorb_padding {
                chosen
                    .iter()
                    .map(|m| {
                        domain(m, vm).with_padding_absorbed(domain(&maps.base, vm), |l| {
                            maps.labels.name(l).starts_with('[')
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let mut all = vec![domain(&maps.base, vm)];
            if maps.absorb_padding {
                all.extend(absorbed.iter());
            } else {
                all.extend(chosen.iter().map(|m| domain(m, vm)));
            }
            let none: Arc<str> = "[None]".into();
            let mut names: Vec<&Arc<str>> = Vec::new();
            sweep(&all, |start, end, labels| {
                if let Some(re) = filter {
                    let keep = labels[1..].iter().any(|l| {
                        l.is_some_and(|l| {
                            *matches
                                .entry(l)
                                .or_insert_with(|| re.is_match(maps.labels.name(l)))
                        })
                    }) || labels[1..]
                        .iter()
                        .any(|l| l.is_none() && re.is_match("[None]"));
                    if !keep {
                        let n = (end - start) as i64;
                        if vm {
                            self.filtered_vm += n;
                        } else {
                            self.filtered_file += n;
                        }
                        return;
                    }
                }
                names.clear();
                names.extend(
                    labels[1..]
                        .iter()
                        .map(|l| l.map_or(&none, |l| maps.labels.shared(l))),
                );
                self.add(&names, (end - start) as i64, vm);
            });
        }
    }

    fn add(&mut self, names: &[&Arc<str>], size: i64, vm: bool) {
        if vm {
            self.vm += size;
        } else {
            self.file += size;
        }
        if let Some((first, rest)) = names.split_first() {
            match self.children.get_mut(&***first) {
                Some(child) => child.add(rest, size, vm),
                None => {
                    let mut child = Rollup::default();
                    child.add(rest, size, vm);
                    self.children.insert(Arc::clone(first), child);
                }
            }
        }
    }
}

/// How rows are sorted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortBy {
    Vm,
    File,
    /// The larger of the two (bloaty's default).
    #[default]
    Both,
}

/// Which sizes are shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Domain {
    Vm,
    File,
    #[default]
    Both,
}

/// The smallest a row may be not to be folded into `[N Others]`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Threshold {
    #[default]
    None,
    /// Bytes (or, in a diff, bytes of change).
    Bytes(i64),
    /// A percentage of the rows beside it, summed.
    Percent(f64),
}

impl Threshold {
    /// `512`, `4k`, `1M` (bytes), or `0.5%`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if let Some(p) = s.strip_suffix('%') {
            let p: f64 = p.trim().parse().ok()?;
            return (p.is_finite() && p >= 0.0).then_some(Self::Percent(p));
        }
        let (digits, scale) = match s.char_indices().last()? {
            (i, 'k' | 'K') => (&s[..i], 1024),
            (i, 'm' | 'M') => (&s[..i], 1024 * 1024),
            (i, 'g' | 'G') => (&s[..i], 1024 * 1024 * 1024),
            _ => (s, 1),
        };
        let n: f64 = digits.trim().parse().ok()?;
        (n.is_finite() && n >= 0.0).then_some(Self::Bytes((n * f64::from(scale)) as i64))
    }
}

/// Report options.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Rows per level before the rest are folded into `[N Others]`.
    pub max_rows: usize,
    /// Rows smaller than this are folded into `[N Others]` too.
    pub min: Threshold,
    pub sort_by: SortBy,
    pub domain: Domain,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_rows: 20,
            min: Threshold::None,
            sort_by: SortBy::Both,
            domain: Domain::Both,
        }
    }
}

/// One row of a report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    pub name: String,
    pub vm: i64,
    pub file: i64,
    /// In a diff, the label's size in the base.
    pub old_vm: i64,
    pub old_file: i64,
    pub vm_percent: f64,
    pub file_percent: f64,
    /// For `[N Others]`, N.
    pub other_count: usize,
    pub children: Vec<Row>,
}

/// A report: its rows under a `TOTAL` row.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// The sources, in order (one level of rows each).
    pub sources: Vec<String>,
    pub total: Row,
    pub diff: bool,
    /// Bytes a source filter left out (file, VM).
    pub filtered: (i64, i64),
}

fn percent(part: i64, whole: i64) -> f64 {
    if whole == 0 {
        match part {
            0 => f64::NAN,
            p if p > 0 => f64::INFINITY,
            _ => f64::NEG_INFINITY,
        }
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

static EMPTY: std::sync::LazyLock<Rollup> = std::sync::LazyLock::new(Rollup::default);

impl Report {
    /// The report of `rollup`, or of its difference from `base`.
    pub fn new(
        sources: &[&str],
        rollup: &Rollup,
        base: Option<&Rollup>,
        options: &Options,
    ) -> Self {
        let mut total = Row {
            name: "TOTAL".into(),
            vm: rollup.vm - base.map_or(0, |b| b.vm),
            file: rollup.file - base.map_or(0, |b| b.file),
            ..Row::default()
        };
        if let Some(b) = base {
            total.old_vm = b.vm;
            total.old_file = b.file;
        } else {
            total.vm_percent = 100.0;
            total.file_percent = 100.0;
        }
        create_rows(&mut total, rollup, base, options, true);
        Report {
            sources: sources
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            total,
            diff: base.is_some(),
            filtered: (rollup.filtered_file, rollup.filtered_vm),
        }
    }

    /// The report as bloaty prints it.
    pub fn pretty(&self, options: &Options) -> String {
        let (file, vm) = shown(options);
        let mut out = String::new();
        if file {
            out.push_str("    FILE SIZE   ");
        }
        if vm {
            out.push_str("     VM SIZE    ");
        }
        out.push('\n');
        if file {
            out.push_str(" -------------- ");
        }
        if vm {
            out.push_str(" -------------- ");
        }
        out.push('\n');
        for child in &self.total.children {
            self.pretty_tree(&mut out, child, 0, options);
        }
        self.pretty_row(&mut out, &self.total, 0, options, true);
        // bloaty means to print this, but its counts are never set.
        let (ff, fv) = (
            if file { self.filtered.0 } else { 0 },
            if vm { self.filtered.1 } else { 0 },
        );
        if ff > 0 || fv > 0 {
            out.push_str("Filtering enabled (source_filter); omitted");
            if ff > 0 && fv > 0 {
                let _ = write!(out, " file ={}, vm ={}", si(ff, false), si(fv, false));
            } else {
                out.push_str(&si(ff.max(fv), false));
            }
            out.push_str(" of entries\n");
        }
        out
    }

    fn pretty_row(&self, out: &mut String, row: &Row, indent: usize, options: &Options, top: bool) {
        let (file, vm) = shown(options);
        if !top && ((!file && row.vm == 0) || (!vm && row.file == 0)) {
            return;
        }
        out.push_str(&" ".repeat(indent));
        out.push(' ');
        if file {
            let _ = write!(
                out,
                "{} {} ",
                percent_string(row.file_percent, self.diff),
                si(row.file, self.diff)
            );
        }
        if vm {
            let _ = write!(
                out,
                "{} {} ",
                percent_string(row.vm_percent, self.diff),
                si(row.vm, self.diff)
            );
        }
        let _ = writeln!(out, "   {}", row.name);
    }

    fn pretty_tree(&self, out: &mut String, row: &Row, indent: usize, options: &Options) {
        self.pretty_row(out, row, indent, options, false);
        if row.vm == 0 && row.file == 0 {
            return;
        }
        if row.children.len() == 1
            && row.children[0].children.is_empty()
            && same_label(&row.name, &row.children[0].name)
        {
            return;
        }
        for child in &row.children {
            self.pretty_tree(out, child, indent + 2, options);
        }
    }

    /// The report as CSV (or, with `tabs`, TSV): one line per leaf row,
    /// with its labels, VM size, and file size (and, in a diff, the old
    /// and new sizes).
    pub fn csv(&self, tabs: bool) -> String {
        let sep = if tabs { "\t" } else { "," };
        let mut header: Vec<String> = self.sources.clone();
        header.extend(["vmsize".into(), "filesize".into()]);
        if self.diff {
            header.extend([
                "original_vmsize".into(),
                "original_filesize".into(),
                "current_vmsize".into(),
                "current_filesize".into(),
            ]);
        }
        let mut out = header.join(sep);
        out.push('\n');
        for child in &self.total.children {
            self.csv_tree(&mut out, child, Vec::new(), tabs);
        }
        out
    }

    fn csv_tree(&self, out: &mut String, row: &Row, mut labels: Vec<String>, tabs: bool) {
        labels.push(if tabs {
            row.name.clone()
        } else {
            csv_escape(&row.name)
        });
        if !row.children.is_empty() {
            for child in &row.children {
                self.csv_tree(out, child, labels.clone(), tabs);
            }
            return;
        }
        while labels.len() < self.sources.len() {
            labels.push(String::new());
        }
        labels.push(row.vm.to_string());
        labels.push(row.file.to_string());
        if self.diff {
            labels.push(row.old_vm.to_string());
            labels.push(row.old_file.to_string());
            labels.push((row.old_vm + row.vm).to_string());
            labels.push((row.old_file + row.file).to_string());
        }
        out.push_str(&labels.join(if tabs { "\t" } else { "," }));
        out.push('\n');
    }

    /// The report as JSON: `{"sources": [...], "diff": bool, "total": row}`,
    /// each row `{"name", "vm", "file", ("old_vm", "old_file",)
    /// "children"}`.
    pub fn json(&self) -> String {
        let report = JsonReport {
            sources: &self.sources,
            diff: self.diff,
            total: self.json_row(&self.total),
            filtered: (self.filtered != (0, 0)).then_some(Filtered {
                vm: self.filtered.1,
                file: self.filtered.0,
            }),
        };
        let mut out = serde_json::to_string(&report).unwrap_or_default();
        out.push('\n');
        out
    }

    fn json_row<'r>(&self, row: &'r Row) -> JsonRow<'r> {
        JsonRow {
            name: &row.name,
            vm: row.vm,
            file: row.file,
            old_vm: self.diff.then_some(row.old_vm),
            old_file: self.diff.then_some(row.old_file),
            other_count: (row.other_count > 0).then_some(row.other_count),
            children: row.children.iter().map(|c| self.json_row(c)).collect(),
        }
    }
}

/// A report as JSON: its sources, whether it is a diff, its rows from the
/// `TOTAL` down, and what a source filter left out.
#[derive(serde::Serialize)]
struct JsonReport<'r> {
    sources: &'r [String],
    diff: bool,
    total: JsonRow<'r>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filtered: Option<Filtered>,
}

#[derive(serde::Serialize)]
struct Filtered {
    vm: i64,
    file: i64,
}

/// A row as JSON: its sizes (in a diff, the change and the old sizes), for
/// `[N Others]` the N, and its children.
#[derive(serde::Serialize)]
struct JsonRow<'r> {
    name: &'r str,
    vm: i64,
    file: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_vm: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_file: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    other_count: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<JsonRow<'r>>,
}

fn shown(options: &Options) -> (bool, bool) {
    (options.domain != Domain::Vm, options.domain != Domain::File)
}

/// Whether bloaty would treat `a` and `b` as one label (`x` and
/// `[section x]`).
fn same_label(a: &str, b: &str) -> bool {
    a == b || b.ends_with(&format!("{a}]")) || a.ends_with(&format!("{b}]"))
}

/// A child of a row before it becomes a [`Row`]: its label, its sizes
/// (the difference, in a diff), and its rollups.
struct Candidate<'a> {
    name: &'a Arc<str>,
    vm: i64,
    file: i64,
    rollup: &'a Rollup,
    base: Option<&'a Rollup>,
}

fn create_rows(
    row: &mut Row,
    rollup: &Rollup,
    base: Option<&Rollup>,
    options: &Options,
    top: bool,
) {
    if let Some(b) = base {
        row.vm_percent = percent(rollup.vm - b.vm, b.vm);
        row.file_percent = percent(rollup.file - b.file, b.file);
    }
    // Children, with labels the base has but this rollup lost.
    let mut children: Vec<Candidate<'_>> = Vec::with_capacity(rollup.children.len());
    let delta = |child: &Rollup, old: Option<&Rollup>| {
        let vm = child.vm - old.map_or(0, |o| o.vm);
        let file = child.file - old.map_or(0, |o| o.file);
        (vm != 0 || file != 0).then_some((vm, file))
    };
    for (name, child) in &rollup.children {
        let old = base.map(|b| b.children.get(name).unwrap_or(&EMPTY));
        if let Some((vm, file)) = delta(child, old) {
            children.push(Candidate {
                name,
                vm,
                file,
                rollup: child,
                base: old,
            });
        }
    }
    if let Some(b) = base {
        for (name, old) in b
            .children
            .iter()
            .filter(|(k, _)| !rollup.children.contains_key(*k))
        {
            if let Some((vm, file)) = delta(&EMPTY, Some(old)) {
                children.push(Candidate {
                    name,
                    vm,
                    file,
                    rollup: &EMPTY,
                    base: Some(old),
                });
            }
        }
    }
    sort_and_aggregate(row, children, base.is_some(), options, top);
}

fn key(vm: i64, file: i64, by: SortBy, magnitude: bool) -> i64 {
    let (v, f) = if magnitude {
        (vm.saturating_abs(), file.saturating_abs())
    } else {
        (vm, file)
    };
    match by {
        SortBy::Vm => v,
        SortBy::File => f,
        SortBy::Both if magnitude => v.max(f),
        SortBy::Both => {
            if vm.saturating_abs() > file.saturating_abs() {
                vm
            } else {
                file
            }
        }
    }
}

fn order(a: (i64, &str), b: (i64, &str)) -> std::cmp::Ordering {
    b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1))
}

/// A row's rollup and, in a diff, its base's.
type Rollups<'a> = (&'a Rollup, Option<&'a Rollup>);

fn sort_and_aggregate(
    row: &mut Row,
    mut children: Vec<Candidate<'_>>,
    diff: bool,
    options: &Options,
    top: bool,
) {
    if !top
        && children.len() == 1
        && (&**children[0].name == "[None]" || &**children[0].name == "[Unmapped]")
    {
        children.clear();
    }
    if children.len() == 1 && **children[0].name == *row.name {
        children.clear();
    }
    if children.is_empty() {
        return;
    }
    // The largest `max_rows` (by magnitude), in order; the rest are Others.
    let by = options.sort_by;
    let cmp = |a: &Candidate<'_>, b: &Candidate<'_>| {
        order(
            (key(a.vm, a.file, by, true), a.name),
            (key(b.vm, b.file, by, true), b.name),
        )
    };
    if children.len() > options.max_rows && options.max_rows > 0 {
        children.select_nth_unstable_by(options.max_rows - 1, cmp);
    }
    // Those under the threshold, by magnitude (of the size, or of the
    // change), against all of them together for a percentage.
    let floor = match options.min {
        Threshold::None => 0,
        Threshold::Bytes(b) => b,
        Threshold::Percent(p) => {
            let all: i64 = children.iter().map(|c| key(c.vm, c.file, by, true)).sum();
            (all as f64 * p / 100.0).ceil() as i64
        }
    };
    let mut rest = if children.len() > options.max_rows {
        children.split_off(options.max_rows)
    } else {
        Vec::new()
    };
    if floor > 0 {
        let (keep, small): (Vec<_>, Vec<_>) = children
            .into_iter()
            .partition(|c| key(c.vm, c.file, by, true) >= floor);
        children = keep;
        rest.extend(small);
        // (One row alone in Others would be no shorter.)
        if rest.len() == 1 && children.len() < options.max_rows.max(1) {
            children.append(&mut rest);
        }
    }
    let mut others = Rollup::default();
    let mut others_base = Rollup::default();
    let mut others_row = Row::default();
    for c in &rest {
        others_row.vm += c.vm;
        others_row.file += c.file;
        others_row.other_count += 1;
        if let Some(b) = c.base {
            others_base.vm += b.vm;
            others_base.file += b.file;
        }
    }
    let mut rows: Vec<(Row, Option<Rollups<'_>>)> = children
        .iter()
        .map(|c| {
            (
                Row {
                    name: c.name.to_string(),
                    vm: c.vm,
                    file: c.file,
                    old_vm: c.base.map_or(0, |b| b.vm),
                    old_file: c.base.map_or(0, |b| b.file),
                    ..Row::default()
                },
                Some((c.rollup, c.base)),
            )
        })
        .collect();
    if others_row.vm != 0 || others_row.file != 0 {
        others_row.name = format!("[{} Others]", others_row.other_count);
        others.vm = others_row.vm;
        others.file = others_row.file;
        if diff {
            // Others' percentage is of the old sizes of the rows it holds
            // (bloaty compares the difference less the old sizes).
            others.vm += others_base.vm;
            others.file += others_base.file;
            others_row.old_vm = others_base.vm;
            others_row.old_file = others_base.file;
        }
        rows.push((others_row, None));
    }
    rows.sort_by(|a, b| {
        order(
            (key(a.0.vm, a.0.file, by, false), &a.0.name),
            (key(b.0.vm, b.0.file, by, false), &b.0.name),
        )
    });
    for (r, source) in &mut rows {
        if !diff {
            r.vm_percent = percent(r.vm, row.vm);
            r.file_percent = percent(r.file, row.file);
        }
        match source {
            Some((rollup, b)) => create_rows(r, rollup, *b, options, false),
            None => create_rows(r, &others, diff.then_some(&others_base), options, false),
        }
    }
    row.children = rows.into_iter().map(|(r, _)| r).collect();
}

/// A size as bloaty prints it: 1024-based units, three or so significant
/// digits, right-aligned in 7 columns (with a sign in diffs).
pub fn si(size: i64, sign: bool) -> String {
    const PREFIXES: [&str; 5] = ["", "Ki", "Mi", "Gi", "Ti"];
    let mut n = 0;
    let mut d = size as f64;
    while d.abs() > 1024.0 && n < PREFIXES.len() - 2 {
        d /= 1024.0;
        n += 1;
    }
    let s = if d.abs() > 100.0 || n == 0 {
        let v = d as i64;
        if sign && size > 0 {
            format!("+{v}{}", PREFIXES[n])
        } else {
            format!("{v}{}", PREFIXES[n])
        }
    } else if d.abs() > 10.0 {
        if sign {
            format!("{d:+.1}{}", PREFIXES[n])
        } else {
            format!("{d:.1}{}", PREFIXES[n])
        }
    } else if sign {
        format!("{d:+.2}{}", PREFIXES[n])
    } else {
        format!("{d:.2}{}", PREFIXES[n])
    };
    format!("{s:>7}")
}

/// A percentage as bloaty prints it.
pub fn percent_string(p: f64, diff: bool) -> String {
    if !diff {
        // (C's `%5.1F` prints NAN and INF.)
        return if p.is_nan() {
            "  NAN%".into()
        } else if p.is_infinite() {
            format!("{:>5}%", if p > 0.0 { "INF" } else { "-INF" })
        } else {
            format!("{p:5.1}%")
        };
    }
    let s = if p == 0.0 || p.is_nan() {
        return " [ = ]".into();
    } else if p == -100.0 {
        return " [DEL]".into();
    } else if p.is_infinite() {
        return " [NEW]".into();
    } else if p > 1000.0 {
        let digits = p.log10() as i32 - 1;
        format!("{:+2.0}e{digits}%", p / 10f64.powi(digits))
    } else if p > 10.0 {
        format!("{p:+4.0}%")
    } else {
        format!("{p:+5.1}%")
    };
    format!("{s:>6}")
}

fn csv_escape(s: &str) -> String {
    if s.contains(['"', ',']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Every source's labels at once: for each distinct tuple of labels (one
/// per source of `maps`, in their order; `None` where a source labels
/// nothing), its file and VM sizes. A rollup by any of the sources, in any
/// order, is these rows summed by those sources' labels (so that a viewer
/// can regroup without asking again). Padding is absorbed as rollups
/// absorb it.
pub fn table(maps: &Maps) -> Vec<(Vec<Option<crate::rangemap::Label>>, i64, i64)> {
    let n = maps.sources.len();
    let mut rows: FxHashMap<Vec<Option<crate::rangemap::Label>>, (i64, i64)> = FxHashMap::default();
    for vm in [true, false] {
        fn domain(d: &crate::rangemap::DualMap, vm: bool) -> &crate::rangemap::RangeMap {
            if vm { &d.vm } else { &d.file }
        }
        let absorbed: Vec<crate::rangemap::RangeMap> = if maps.absorb_padding {
            maps.sources
                .iter()
                .map(|(_, m)| {
                    domain(m, vm).with_padding_absorbed(domain(&maps.base, vm), |l| {
                        maps.labels.name(l).starts_with('[')
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut all = vec![domain(&maps.base, vm)];
        if maps.absorb_padding {
            all.extend(absorbed.iter());
        } else {
            all.extend(maps.sources.iter().map(|(_, m)| domain(m, vm)));
        }
        sweep(&all, |start, end, labels| {
            let size = (end - start) as i64;
            let key = &labels[1..=n];
            match rows.get_mut(key) {
                Some(r) => {
                    if vm {
                        r.1 += size;
                    } else {
                        r.0 += size;
                    }
                }
                None => {
                    rows.insert(key.to_vec(), if vm { (0, size) } else { (size, 0) });
                }
            }
        });
    }
    rows.into_iter()
        .map(|(k, (file, vm))| (k, file, vm))
        .collect()
}

#[cfg(test)]
#[path = "rollup_tests.rs"]
mod tests;

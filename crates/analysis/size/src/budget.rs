//! Size budgets, for CI: limits on an image's sizes, and on how much they
//! may grow from a base image, checked against bloaty-style rollups.
//!
//! A budget is JSON:
//!
//! ```json
//! {
//!   "rules": [
//!     { "name": "image", "max_file": "120 MiB" },
//!     { "source": "sections", "match": "^\\.text$", "max_vm": "90MiB" },
//!     { "source": "symbols", "max_growth_file": "4 KiB" },
//!     { "source": "compileunits", "match": "third_party/", "sum": true,
//!       "max_growth_file": 0 }
//!   ]
//! }
//! ```
//!
//! A rule without a `source` limits the whole image. With one, it limits
//! each label of that source that `match` (a regular expression; default:
//! every label) matches, or, with `sum`, all of them together. `max_file`
//! and `max_vm` bound sizes; `max_growth_file` and `max_growth_vm` bound
//! the change from the base (a label the base lacks grows by all of it), so
//! need one. Sizes are byte counts or strings with a unit (`KiB`, `MiB`,
//! `GiB`, `KB`, `MB`, `GB`; `K`/`M`/`G` are binary).

use std::collections::BTreeMap;

use serde::Deserialize;

/// A budget: its rules, all of which must hold.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// What to call the rule in the report (default: a description).
    #[serde(default)]
    pub name: Option<String>,
    /// The data source whose labels it limits (default: the whole image).
    #[serde(default)]
    pub source: Option<String>,
    /// Which labels (a regular expression; default: all).
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    /// Limit the matching labels together rather than each.
    #[serde(default)]
    pub sum: bool,
    #[serde(default)]
    pub max_file: Option<Bytes>,
    #[serde(default)]
    pub max_vm: Option<Bytes>,
    #[serde(default)]
    pub max_growth_file: Option<Bytes>,
    #[serde(default)]
    pub max_growth_vm: Option<Bytes>,
}

/// A byte count, as a number or a string with a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes(pub i64);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(i64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Number(n) => Ok(Bytes(n)),
            Raw::Text(s) => parse_bytes(&s).map(Bytes).ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "not a size: '{s}' (say 12345, \"64 KiB\", \"2MB\")"
                ))
            }),
        }
    }
}

/// `"64 KiB"`, `"1.5MB"`, `"-4K"`, `"100"`: bytes.
pub fn parse_bytes(s: &str) -> Option<i64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    let number: f64 = number.trim().parse().ok()?;
    let scale: f64 = match unit.trim() {
        "" | "B" => 1.0,
        "K" | "KiB" | "k" => 1024.0,
        "M" | "MiB" => 1024.0 * 1024.0,
        "G" | "GiB" => 1024.0 * 1024.0 * 1024.0,
        "KB" | "kB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        _ => return None,
    };
    let v = (number * scale).round();
    (v.is_finite() && v.abs() < 9.0e18).then_some(v as i64)
}

/// Sizes to check: the image's total, and each source's labels (by the
/// source's name).
#[derive(Clone, Debug, Default)]
pub struct Totals {
    pub file: i64,
    pub vm: i64,
    pub by_source: BTreeMap<String, BTreeMap<String, (i64, i64)>>,
}

/// What a rule measures: a label (none for a total or sum), and its file
/// and memory sizes now and in the base.
type Measured = (Option<String>, (i64, i64), (i64, i64));

/// One limit exceeded.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Violation {
    pub rule: String,
    /// The label, for a per-label rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `file`, `vm`, `file growth`, or `vm growth`.
    pub measure: &'static str,
    pub limit: i64,
    pub actual: i64,
}

impl Budget {
    pub fn parse(text: &str) -> Result<Self, String> {
        let b: Budget = serde_json::from_str(text).map_err(|e| e.to_string())?;
        for (i, r) in b.rules.iter().enumerate() {
            let what = r.title(i);
            if r.max_file.is_none()
                && r.max_vm.is_none()
                && r.max_growth_file.is_none()
                && r.max_growth_vm.is_none()
            {
                return Err(format!(
                    "{what}: no limit (max_file, max_vm, max_growth_file, max_growth_vm)"
                ));
            }
            if r.source.is_none() && (r.pattern.is_some() || r.sum) {
                return Err(format!("{what}: match and sum need a source"));
            }
            if let Some(p) = &r.pattern {
                regex::Regex::new(p).map_err(|e| format!("{what}: {e}"))?;
            }
        }
        Ok(b)
    }

    /// The sources the rules name, each once.
    pub fn sources(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in self.rules.iter().filter_map(|r| r.source.clone()) {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// Whether any rule limits growth (and so needs a base).
    pub fn needs_base(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.max_growth_file.is_some() || r.max_growth_vm.is_some())
    }

    /// The limits `current` (and, for growth, `base`) exceed.
    pub fn check(&self, current: &Totals, base: Option<&Totals>) -> Result<Vec<Violation>, String> {
        let mut out = Vec::new();
        let empty = BTreeMap::new();
        for (i, r) in self.rules.iter().enumerate() {
            let title = r.title(i);
            let growth = r.max_growth_file.is_some() || r.max_growth_vm.is_some();
            if growth && base.is_none() {
                return Err(format!(
                    "{title}: limits growth, so needs a base image (-- <base>)"
                ));
            }
            // What the rule measures: (label, current, base) sizes.
            let mut measured: Vec<Measured> = Vec::new();
            match &r.source {
                None => measured.push((
                    None,
                    (current.file, current.vm),
                    base.map_or((0, 0), |b| (b.file, b.vm)),
                )),
                Some(source) => {
                    let re = r
                        .pattern
                        .as_deref()
                        .map(regex::Regex::new)
                        .transpose()
                        .map_err(|e| e.to_string())?;
                    let cur = current.by_source.get(source).unwrap_or(&empty);
                    let old = base.and_then(|b| b.by_source.get(source)).unwrap_or(&empty);
                    let wanted = |l: &str| re.as_ref().is_none_or(|re| re.is_match(l));
                    // Labels in either image: one that disappeared shrank.
                    let mut labels: Vec<&String> =
                        cur.keys().chain(old.keys()).filter(|l| wanted(l)).collect();
                    labels.sort();
                    labels.dedup();
                    let get = |m: &BTreeMap<String, (i64, i64)>, l: &str| {
                        m.get(l).copied().unwrap_or((0, 0))
                    };
                    if r.sum {
                        let add = |m: &BTreeMap<String, (i64, i64)>| {
                            labels.iter().fold((0, 0), |(f, v), l| {
                                let (a, b) = get(m, l);
                                (f + a, v + b)
                            })
                        };
                        measured.push((None, add(cur), add(old)));
                    } else {
                        for l in labels {
                            measured.push((Some(l.clone()), get(cur, l), get(old, l)));
                        }
                    }
                }
            }
            for (label, (file, vm), (old_file, old_vm)) in measured {
                for (limit, measure, actual) in [
                    (r.max_file, "file", file),
                    (r.max_vm, "vm", vm),
                    (r.max_growth_file, "file growth", file - old_file),
                    (r.max_growth_vm, "vm growth", vm - old_vm),
                ] {
                    if let Some(Bytes(limit)) = limit
                        && actual > limit
                    {
                        out.push(Violation {
                            rule: title.clone(),
                            label: label.clone(),
                            measure,
                            limit,
                            actual,
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}

impl Rule {
    fn title(&self, i: usize) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        let mut s = format!("rule {}", i + 1);
        if let Some(src) = &self.source {
            s.push_str(&format!(" ({src}"));
            if let Some(p) = &self.pattern {
                s.push_str(&format!(" matching {p}"));
            }
            s.push(')');
        }
        s
    }
}

/// `-1,234,567`.
fn number(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

/// A report of a check: one line per violation, then a verdict.
pub fn report(rules: usize, violations: &[Violation]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for v in violations {
        let what = match &v.label {
            Some(l) => format!("{}: {l}", v.rule),
            None => v.rule.clone(),
        };
        let _ = writeln!(
            out,
            "FAIL  {what}: {} {} > {}",
            v.measure,
            number(v.actual),
            number(v.limit)
        );
    }
    let failed: std::collections::BTreeSet<&str> =
        violations.iter().map(|v| v.rule.as_str()).collect();
    let _ = if violations.is_empty() {
        writeln!(out, "Budget met: {rules} rules")
    } else {
        writeln!(
            out,
            "Budget exceeded: {} of {rules} rules, {} limits",
            failed.len(),
            violations.len()
        )
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_bytes("100"), Some(100));
        assert_eq!(parse_bytes("64 KiB"), Some(65536));
        assert_eq!(parse_bytes("1.5MB"), Some(1_500_000));
        assert_eq!(parse_bytes("2M"), Some(2 << 20));
        assert_eq!(parse_bytes("-4K"), Some(-4096));
        assert_eq!(parse_bytes("1 GiB"), Some(1 << 30));
        assert_eq!(parse_bytes("12 parsecs"), None);
        assert_eq!(parse_bytes(""), None);
        assert_eq!(parse_bytes("1e40 GB"), None);
    }

    fn totals(file: i64, rows: &[(&str, &str, i64, i64)]) -> Totals {
        let mut t = Totals {
            file,
            vm: file,
            ..Totals::default()
        };
        for &(s, l, f, v) in rows {
            t.by_source
                .entry(s.into())
                .or_default()
                .insert(l.into(), (f, v));
        }
        t
    }

    #[test]
    fn checks() {
        let b = Budget::parse(
            r#"{"rules": [
                {"name": "image", "max_file": "1 KiB"},
                {"source": "sections", "match": "^\\.text$", "max_vm": 100},
                {"source": "symbols", "max_growth_file": 10},
                {"name": "third party", "source": "symbols", "match": "^tp::", "sum": true, "max_growth_vm": 0}
            ]}"#,
        )
        .unwrap();
        assert_eq!(b.sources(), ["sections", "symbols"]);
        assert!(b.needs_base());
        let cur = totals(
            2000,
            &[
                ("sections", ".text", 150, 150),
                ("sections", ".data", 500, 500),
                ("symbols", "f", 30, 30),
                ("symbols", "g", 5, 5),
                ("symbols", "new", 11, 11),
                ("symbols", "tp::a", 4, 4),
            ],
        );
        let old = totals(
            1000,
            &[
                ("symbols", "f", 10, 10),
                ("symbols", "g", 50, 50),
                ("symbols", "tp::a", 1, 1),
                ("symbols", "tp::gone", 1, 1),
            ],
        );
        let v = b.check(&cur, Some(&old)).unwrap();
        let got: Vec<(String, Option<String>, &str, i64)> = v
            .iter()
            .map(|v| (v.rule.clone(), v.label.clone(), v.measure, v.actual))
            .collect();
        assert_eq!(
            got,
            [
                ("image".to_string(), None, "file", 2000),
                (
                    "rule 2 (sections matching ^\\.text$)".to_string(),
                    Some(".text".into()),
                    "vm",
                    150
                ),
                (
                    "rule 3 (symbols)".to_string(),
                    Some("f".into()),
                    "file growth",
                    20
                ),
                (
                    "rule 3 (symbols)".to_string(),
                    Some("new".into()),
                    "file growth",
                    11
                ),
                ("third party".to_string(), None, "vm growth", 2),
            ]
        );
        let text = report(b.rules.len(), &v);
        assert!(
            text.ends_with("Budget exceeded: 4 of 4 rules, 5 limits\n"),
            "{text}"
        );
        assert!(
            text.contains("FAIL  rule 3 (symbols): f: file growth 20 > 10"),
            "{text}"
        );
        // Growth limits need a base.
        assert!(b.check(&cur, None).is_err());
        // Within budget.
        let ok = Budget::parse(r#"{"rules": [{"max_file": 5000, "max_vm": "5000"}]}"#).unwrap();
        assert_eq!(ok.check(&cur, None).unwrap(), []);
        assert_eq!(report(1, &[]), "Budget met: 1 rules\n");
    }

    #[test]
    fn malformed_budgets() {
        for bad in [
            "not json",
            r#"{"rules": [{}]}"#,
            r#"{"rules": [{"max_file": "lots"}]}"#,
            r#"{"rules": [{"source": "symbols", "match": "(", "max_file": 1}]}"#,
            r#"{"rules": [{"match": "x", "max_file": 1}]}"#,
            r#"{"rules": [{"max_flie": 1}]}"#,
            r#"{"rulez": []}"#,
        ] {
            assert!(Budget::parse(bad).is_err(), "{bad}");
        }
    }
}

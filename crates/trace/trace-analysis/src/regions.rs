//! Regions of interest, as WPA defines them in an XML file
//! (`InstrumentationManifest/Instrumentation/Regions/RegionRoot/Region`):
//! intervals between a start event and a stop event, paired by thread,
//! process, activity or payload fields, named by a payload field, nested.
//!
//! What is read: each region's `Guid`, `Name` and `FriendlyName`; its
//! `Start` and `Stop` (an `Event` by `Provider`, `Id` and `Version`, with
//! `PayloadIdentifier` filters: `FieldName`, `FieldValue` and
//! `FieldValueRelationship` `IsEqual` or `DoesNotContain`); `Match`
//! (`Event` with `TID`, `PID` and `AID`, and `Payload` fields, with
//! `TargetFieldName` for the stop's); `Naming` (`PayloadBased` with
//! `NameField` and `InstanceEndpoint`); and its child regions. A region
//! with neither start nor stop is a container: one instance from its
//! children's first start to their last stop. What isn't: `Duration`
//! endpoints, endpoints that are other regions, `Parent` and `SelfNest`
//! matching, `Filter` and region-based naming. A region using them says so
//! ([`RegionDef::unsupported`]) and has no instances, rather than wrong
//! ones.
//!
//! Pairing: in time order, a stop ends the latest open start with the same
//! key (the start's thread, process, activity and match fields, as the
//! region asks): nested instances pair inside out. Starts and stops left
//! unpaired are counted.

use hexcavator_etl::Guid;

use crate::xml::{Element, parse};

/// An event a region starts or stops at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The provider.
    pub provider: Guid,
    /// The event ID.
    pub id: u16,
    /// The version.
    pub version: u8,
    /// Payload filters, all of which must hold.
    pub filters: Vec<PayloadFilter>,
}

/// A payload field's value an endpoint requires (or forbids).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFilter {
    /// The field.
    pub field: String,
    /// The value.
    pub value: String,
    /// Equal to it (`IsEqual`), or else not containing it
    /// (`DoesNotContain`).
    pub equal: bool,
}

/// How a region pairs a stop with a start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matching {
    /// The same thread.
    pub thread: bool,
    /// The same process.
    pub process: bool,
    /// The same activity ID.
    pub activity: bool,
    /// Payload fields: the start's field, and the stop's that must equal
    /// it.
    pub payload: Vec<(String, String)>,
}

/// A region's definition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionDef {
    /// Its GUID, as written.
    pub guid: String,
    /// Its name.
    pub name: String,
    /// Its display name.
    pub friendly_name: Option<String>,
    /// Where it starts (none: a container).
    pub start: Option<Endpoint>,
    /// Where it stops.
    pub stop: Option<Endpoint>,
    /// How stops pair with starts.
    pub matching: Matching,
    /// The payload field that names each instance, and whether from the
    /// stop event first (else the start's, then the stop's).
    pub naming: Option<(String, bool)>,
    /// Its parent region (an index of [`Regions::regions`]).
    pub parent: Option<usize>,
    /// What it uses that isn't supported (and so has no instances).
    pub unsupported: Option<String>,
}

impl RegionDef {
    /// The name to show: its friendly name, else its name.
    pub fn display_name(&self) -> &str {
        self.friendly_name.as_deref().unwrap_or(&self.name)
    }
}

/// A file's regions, parents before their children.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Regions {
    /// The regions (each `RegionRoot` and each `Region` under it).
    pub regions: Vec<RegionDef>,
}

impl Regions {
    /// Reads a regions file.
    pub fn from_xml(text: &str) -> Result<Self, String> {
        let root = parse(text)?;
        if root.name != "InstrumentationManifest" {
            return Err(format!(
                "expected InstrumentationManifest, found {}",
                root.name
            ));
        }
        let mut out = Self::default();
        let regions = root
            .children
            .iter()
            .filter(|c| c.name == "Instrumentation")
            .flat_map(|i| i.children.iter().filter(|c| c.name == "Regions"));
        for r in regions {
            for root in r.children.iter().filter(|c| c.name == "RegionRoot") {
                out.add(root, None)?;
            }
        }
        if out.regions.is_empty() {
            return Err(
                "no regions (InstrumentationManifest/Instrumentation/Regions/RegionRoot)"
                    .to_string(),
            );
        }
        Ok(out)
    }

    fn add(&mut self, e: &Element, parent: Option<usize>) -> Result<(), String> {
        let name = e
            .attribute("Name")
            .ok_or_else(|| format!("a {} without a Name", e.name))?
            .to_string();
        let mut def = RegionDef {
            guid: e.attribute("Guid").unwrap_or_default().to_string(),
            name: name.clone(),
            friendly_name: e.attribute("FriendlyName").map(str::to_string),
            parent,
            ..RegionDef::default()
        };
        let mut unsupported: Vec<&str> = Vec::new();
        for c in &e.children {
            match c.name.as_str() {
                "Start" | "Stop" => {
                    let end = endpoint(c, &mut unsupported).map_err(|m| format!("{name}: {m}"))?;
                    if c.name == "Start" {
                        def.start = end;
                    } else {
                        def.stop = end;
                    }
                }
                "Match" => {
                    for m in &c.children {
                        match m.name.as_str() {
                            "Event" => {
                                let yes = |a: &str| {
                                    m.attribute(a)
                                        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                                };
                                def.matching.thread = yes("TID");
                                def.matching.process = yes("PID");
                                def.matching.activity = yes("AID");
                                for p in m.children.iter().filter(|p| p.name == "Payload") {
                                    let field = p.attribute("FieldName").ok_or_else(|| {
                                        format!("{name}: a Payload without a FieldName")
                                    })?;
                                    let target = p.attribute("TargetFieldName").unwrap_or(field);
                                    def.matching
                                        .payload
                                        .push((field.to_string(), target.to_string()));
                                }
                            }
                            "Parent" => unsupported.push("Parent matching"),
                            "SelfNest" => unsupported.push("SelfNest"),
                            _ => {}
                        }
                    }
                }
                "Naming" => {
                    for n in &c.children {
                        match n.name.as_str() {
                            "PayloadBased" => {
                                let field = n.attribute("NameField").ok_or_else(|| {
                                    format!("{name}: PayloadBased without a NameField")
                                })?;
                                let from_stop = n.attribute("InstanceEndpoint") == Some("Stop");
                                def.naming = Some((field.to_string(), from_stop));
                            }
                            "RegionBased" => unsupported.push("region-based naming"),
                            _ => {}
                        }
                    }
                }
                "Filter" => unsupported.push("Filter"),
                _ => {}
            }
        }
        if def.start.is_some() != def.stop.is_some() && unsupported.is_empty() {
            unsupported.push("a start without a stop, or a stop without a start");
        }
        if !unsupported.is_empty() {
            unsupported.dedup();
            def.unsupported = Some(unsupported.join(", "));
        }
        let me = self.regions.len();
        self.regions.push(def);
        for c in e.children.iter().filter(|c| c.name == "Region") {
            self.add(c, Some(me))?;
        }
        Ok(())
    }
}

/// An endpoint (`Start` or `Stop`): its event and filters; none if it is
/// something unsupported (noted).
fn endpoint(e: &Element, unsupported: &mut Vec<&'static str>) -> Result<Option<Endpoint>, String> {
    let mut out = None;
    let mut filters = Vec::new();
    for c in &e.children {
        match c.name.as_str() {
            "Event" => {
                let provider = c
                    .attribute("Provider")
                    .and_then(|p| Guid::parse(p.trim_matches(|ch| ch == '{' || ch == '}')))
                    .ok_or("an Event without a Provider GUID")?;
                let num = |a: &str| -> Result<u32, String> {
                    match c.attribute(a) {
                        None => Ok(0),
                        Some(v) => v
                            .trim()
                            .parse()
                            .map_err(|_| format!("{a}: not a number: {v}")),
                    }
                };
                out = Some(Endpoint {
                    provider,
                    id: u16::try_from(num("Id")?).map_err(|_| "Id: too large")?,
                    version: u8::try_from(num("Version")?).map_err(|_| "Version: too large")?,
                    filters: Vec::new(),
                });
            }
            "PayloadIdentifier" => {
                let field = c
                    .attribute("FieldName")
                    .ok_or("a PayloadIdentifier without a FieldName")?;
                let value = c
                    .attribute("FieldValue")
                    .ok_or("a PayloadIdentifier without a FieldValue")?;
                let equal = match c.attribute("FieldValueRelationship") {
                    None | Some("IsEqual") => true,
                    Some("DoesNotContain") => false,
                    Some(other) => return Err(format!("FieldValueRelationship: unknown {other}")),
                };
                filters.push(PayloadFilter {
                    field: field.to_string(),
                    value: value.to_string(),
                    equal,
                });
            }
            "Duration" => unsupported.push("Duration endpoints"),
            "Region" => unsupported.push("endpoints that are other regions"),
            _ => {}
        }
    }
    if let Some(o) = &mut out {
        o.filters = filters;
    }
    Ok(out)
}

/// An event a region may start or stop at.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Occurrence {
    /// Its timestamp.
    pub time: i64,
    /// Its process.
    pub process_id: u32,
    /// Its thread.
    pub thread_id: u32,
    /// Its activity ID.
    pub activity: Guid,
    /// Its payload's fields, as text.
    pub fields: Vec<(String, String)>,
}

impl Occurrence {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether it passes `filters`.
    fn passes(&self, filters: &[PayloadFilter]) -> bool {
        filters.iter().all(|f| {
            let v = self.field(&f.field);
            if f.equal {
                v == Some(f.value.as_str())
            } else {
                v.is_none_or(|v| !v.contains(&f.value))
            }
        })
    }
}

/// A region's instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    /// Its region (an index of [`Regions::regions`]).
    pub region: usize,
    /// Its name, if the region names its instances.
    pub name: Option<String>,
    /// When it started.
    pub start: i64,
    /// When it stopped.
    pub stop: i64,
    /// Its start event's process.
    pub process_id: u32,
    /// Its start event's thread.
    pub thread_id: u32,
}

/// What pairing found for a region.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unpaired {
    /// Starts never stopped.
    pub starts: u64,
    /// Stops with no start.
    pub stops: u64,
}

/// Every region's instances, in start order, and each region's unpaired
/// starts and stops. `occurrences(endpoint)` gives the events of an
/// endpoint's kind (the filters are applied here), in any order.
pub fn instances(
    regions: &Regions,
    occurrences: impl Fn(&Endpoint) -> Vec<Occurrence>,
) -> (Vec<Instance>, Vec<Unpaired>) {
    let n = regions.regions.len();
    let mut by_region: Vec<Vec<Instance>> = vec![Vec::new(); n];
    let mut unpaired = vec![Unpaired::default(); n];
    for (r, def) in regions.regions.iter().enumerate() {
        if def.unsupported.is_some() {
            continue;
        }
        let (Some(start), Some(stop)) = (&def.start, &def.stop) else {
            continue;
        };
        // In time order; a start before a stop at the same time.
        let mut events: Vec<(i64, bool, Occurrence)> = Vec::new();
        events.extend(
            occurrences(start)
                .into_iter()
                .filter(|o| o.passes(&start.filters))
                .map(|o| (o.time, true, o)),
        );
        events.extend(
            occurrences(stop)
                .into_iter()
                .filter(|o| o.passes(&stop.filters))
                .map(|o| (o.time, false, o)),
        );
        events.sort_by_key(|(t, is_start, _)| (*t, !*is_start));
        let m = &def.matching;
        let pairs = |a: &Occurrence, b: &Occurrence| {
            (!m.thread || a.thread_id == b.thread_id)
                && (!m.process || a.process_id == b.process_id)
                && (!m.activity || a.activity == b.activity)
                && m.payload.iter().all(|(sf, tf)| {
                    let x = a.field(sf);
                    x.is_some() && x == b.field(tf)
                })
        };
        let mut open: Vec<Occurrence> = Vec::new();
        for (time, is_start, o) in events {
            if is_start {
                open.push(o);
                continue;
            }
            match open.iter().rposition(|s| pairs(s, &o)) {
                Some(i) => {
                    let s = open.remove(i);
                    let name = def.naming.as_ref().and_then(|(field, from_stop)| {
                        let (first, second) = if *from_stop { (&o, &s) } else { (&s, &o) };
                        first
                            .field(field)
                            .or_else(|| second.field(field))
                            .map(str::to_string)
                    });
                    by_region[r].push(Instance {
                        region: r,
                        name,
                        start: s.time,
                        stop: time,
                        process_id: s.process_id,
                        thread_id: s.thread_id,
                    });
                }
                None => unpaired[r].stops += 1,
            }
        }
        unpaired[r].starts = open.len() as u64;
    }
    // Containers, children first (children come after their parents): one
    // instance spanning their descendants'.
    for r in (0..n).rev() {
        let def = &regions.regions[r];
        if def.unsupported.is_some() || def.start.is_some() || def.stop.is_some() {
            continue;
        }
        let span = (r + 1..n)
            .filter(|&c| regions.regions[c].parent == Some(r))
            .flat_map(|c| by_region[c].iter())
            .fold(None, |acc: Option<(i64, i64)>, i| {
                Some(acc.map_or((i.start, i.stop), |(a, b)| (a.min(i.start), b.max(i.stop))))
            });
        if let Some((start, stop)) = span {
            by_region[r].push(Instance {
                region: r,
                name: None,
                start,
                stop,
                process_id: u32::MAX,
                thread_id: u32::MAX,
            });
        }
    }
    let mut all: Vec<Instance> = by_region.into_iter().flatten().collect();
    all.sort_by_key(|i| (i.start, i.region, i.stop));
    (all, unpaired)
}

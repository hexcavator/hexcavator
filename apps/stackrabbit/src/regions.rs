//! Regions of interest over a trace: a WPA regions file's regions, and
//! their instances, from the events they start and stop at (read from the
//! trace file).

use std::path::Path;

use hexcavator_trace::Trace;
use hexcavator_trace_analysis::regions::{Regions, instances};
use serde_json::{Value, json};

/// How many instances are listed.
const MAX_INSTANCES: usize = 20_000;

/// The regions `file` defines over `trace` (read from `path`), as the
/// `regions` request answers.
pub fn regions(trace: &Trace, path: &Path, file: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let defs = Regions::from_xml(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut wanted = Vec::new();
    for d in &defs.regions {
        for e in [&d.start, &d.stop].into_iter().flatten() {
            let k = (e.provider, e.id, e.version);
            if !wanted.contains(&k) {
                wanted.push(k);
            }
        }
    }
    let found = crate::generic::occurrences(trace, path, &wanted)?;
    let (all, unpaired) = instances(&defs, |e| {
        found
            .get(&(e.provider, e.id, e.version))
            .cloned()
            .unwrap_or_default()
    });
    let known = |id: u32| (id != u32::MAX).then_some(id);
    let regions: Vec<Value> = defs
        .regions
        .iter()
        .enumerate()
        .map(|(r, d)| {
            let mine = all.iter().filter(|i| i.region == r);
            let total: i64 = mine.clone().map(|i| i.stop - i.start).sum();
            json!({
                "name": d.name,
                "displayName": d.display_name(),
                "parent": d.parent,
                "unsupported": d.unsupported,
                "count": mine.count(),
                "totalNs": trace.clock.nanos(trace.clock.origin + total),
                "unpairedStarts": unpaired[r].starts,
                "unpairedStops": unpaired[r].stops,
            })
        })
        .collect();
    let instances: Vec<Value> = all
        .iter()
        .take(MAX_INSTANCES)
        .map(|i| {
            json!({
                "region": i.region,
                "name": i.name,
                "startNs": trace.clock.nanos(i.start),
                "stopNs": trace.clock.nanos(i.stop),
                "durationNs": trace.clock.nanos(trace.clock.origin + (i.stop - i.start)),
                "pid": known(i.process_id),
                "tid": known(i.thread_id),
            })
        })
        .collect();
    Ok(json!({
        "regions": regions,
        "instances": instances,
        "truncated": all.len() > MAX_INSTANCES,
    }))
}

//! Generic events: one kind of event's occurrences, read from the trace
//! file and decoded, in time order, a page at a time (as WPA's Generic
//! Events table shows them). Payloads decode by the description recorded
//! with the trace, else the kernel's schema, else show as bytes.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hexcavator_etl::{Buffer, Etl, Event, Guid, merge::for_each_event};
use hexcavator_etw::event_info::{EventInfo, EventInfos};
use hexcavator_etw::schema::{Properties, Property, pointer_size};
use hexcavator_etw::values;
use hexcavator_mmap::Mmap;
use hexcavator_trace::{BufferSpan, Trace};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

/// A kind of event: provider, ID, version, opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind {
    /// The provider.
    pub provider: Guid,
    /// The event ID.
    pub id: u16,
    /// The version.
    pub version: u8,
    /// The opcode.
    pub opcode: u8,
}

/// One event, decoded.
struct Row {
    timestamp: i64,
    processor: u16,
    process_id: u32,
    thread_id: u32,
    fields: Vec<(String, String)>,
    /// Properties the payload ended before.
    missing: usize,
    /// Payload bytes after the last property.
    extra: usize,
}

/// Buffers a worker reads at a time.
const CHUNK: usize = 64;

/// The events of `kind` in `trace` (read from the file at `path`), in
/// `[start, end)` clock ticks (all, if none), in time order: how many, and
/// those from `offset`, `limit` of them, decoded. Only the buffers the
/// trace's buffer index says hold the kind in the range are read, the
/// earliest first, in batches on every core; without a range, reading
/// stops once the next buffer starts after the last event to list (the
/// count is the trace's).
pub fn list(
    trace: &Trace,
    path: &Path,
    kind: Kind,
    time: Option<(i64, i64)>,
    offset: usize,
    limit: usize,
) -> Result<Value, String> {
    let map = Mmap::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let etl = Etl::parse(map.as_slice()).map_err(|e| format!("{}: {e}", path.display()))?;
    let max = usize::try_from(etl.header().buffer_size)
        .unwrap_or(1 << 20)
        .max(1 << 16);
    let mut infos = EventInfos::default();
    for b in &trace.event_infos {
        if let Ok(i) = EventInfo::parse(b) {
            infos.add(i);
        }
    }
    let (start, end) = time.unwrap_or((i64::MIN, i64::MAX));
    let keep = offset.saturating_add(limit);
    // The kind's entries in the trace's event kinds (one a task).
    let kinds: Vec<u32> = trace
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            (e.provider, e.id, e.version, e.opcode)
                == (kind.provider, kind.id, kind.version, kind.opcode)
        })
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect();
    // The buffers to read: those the kind is in, in the time range, the
    // earliest first (every buffer, for a trace without the buffers'
    // index).
    let buffers: Vec<Buffer<'_>> = if trace.buffers.is_empty() {
        etl.buffers().flatten().collect()
    } else {
        let mut spans: Vec<&BufferSpan> = trace
            .buffers
            .iter()
            .filter(|b| {
                b.kinds.iter().any(|k| kinds.contains(k)) && b.last >= start && b.first < end
            })
            .collect();
        spans.sort_by_key(|b| (b.first, b.offset));
        spans
            .into_iter()
            .filter_map(|b| etl.buffer_at(b.offset, b.index).ok())
            .collect()
    };
    let firsts: Vec<i64> = if trace.buffers.is_empty() {
        Vec::new()
    } else {
        let by_offset: FxHashMap<u64, i64> =
            trace.buffers.iter().map(|b| (b.offset, b.first)).collect();
        buffers
            .iter()
            .map(|b| by_offset.get(&b.file_offset).copied().unwrap_or(i64::MIN))
            .collect()
    };
    // Without a time range, how many is known, and reading can stop once
    // the next buffer starts after the last event kept; with one, every
    // buffer in it is read, to count.
    let known_total: Option<u64> = (time.is_none() && !trace.buffers.is_empty())
        .then(|| kinds.iter().map(|&k| trace.events[k as usize].count).sum());
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let batch = if known_total.is_some() {
        (threads * 8).max(CHUNK)
    } else {
        buffers.len().max(1)
    };
    let mut total = 0u64;
    let mut rows: Vec<Row> = Vec::new();
    let mut at = 0;
    while at < buffers.len() {
        let these = &buffers[at..(at + batch).min(buffers.len())];
        let (n, mut found) = scan(these, max, kind, (start, end), keep, &infos, threads);
        total += n;
        rows.append(&mut found);
        rows.sort_by_key(|r| (r.timestamp, r.processor, r.thread_id));
        rows.truncate(keep);
        at += these.len();
        if known_total.is_some()
            && rows.len() >= keep
            && let Some(&next_first) = firsts.get(at)
            && next_first > rows.last().map_or(i64::MAX, |r| r.timestamp)
        {
            break;
        }
    }
    let total = known_total.unwrap_or(total);
    let rows: Vec<&Row> = rows.iter().skip(offset).take(limit).collect();
    // The columns: every field name, in the order first seen.
    let mut columns: Vec<&str> = Vec::new();
    for r in &rows {
        for (name, _) in &r.fields {
            if !columns.contains(&name.as_str()) {
                columns.push(name);
            }
        }
    }
    let process_names: FxHashMap<u32, &str> = trace
        .processes
        .iter()
        .map(|p| (p.pid, p.name.as_str()))
        .collect();
    let known = |id: u32| (id != u32::MAX).then_some(id);
    Ok(json!({
        "total": total,
        "offset": offset,
        "columns": columns,
        "rows": rows.iter().map(|r| json!({
            "timeNs": trace.clock.nanos(r.timestamp),
            "cpu": r.processor,
            "pid": known(r.process_id),
            "process": known(r.process_id).and_then(|p| process_names.get(&p).copied()),
            "tid": known(r.thread_id),
            "fields": r.fields.iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>(),
            "missing": r.missing,
            "extra": r.extra,
        })).collect::<Vec<_>>(),
    }))
}

/// Reads `buffers` on up to `threads` threads, a chunk at a time: how many
/// events of `kind` in `[start, end)` they hold, and the earliest `keep`
/// of them (by time, processor, thread), decoded. Each worker decodes only
/// events that can still be among its earliest `keep`.
fn scan(
    buffers: &[Buffer<'_>],
    max: usize,
    kind: Kind,
    (start, end): (i64, i64),
    keep: usize,
    infos: &EventInfos,
    threads: usize,
) -> (u64, Vec<Row>) {
    let next = AtomicUsize::new(0);
    let found: Mutex<(u64, Vec<Row>)> = Mutex::new((0, Vec::new()));
    let threads = threads.min(buffers.len().div_ceil(CHUNK).max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut rows: Vec<Row> = Vec::new();
                let mut count = 0u64;
                let mut cutoff = i64::MAX;
                loop {
                    let c = next.fetch_add(1, Ordering::Relaxed);
                    let from = c.saturating_mul(CHUNK);
                    if from >= buffers.len() {
                        break;
                    }
                    for buffer in &buffers[from..(from + CHUNK).min(buffers.len())] {
                        let _ = for_each_event(buffer, max, &mut scratch, |e| {
                            let d = &e.descriptor;
                            if e.provider != kind.provider
                                || d.id != kind.id
                                || d.version != kind.version
                                || d.opcode != kind.opcode
                                || e.timestamp < start
                                || e.timestamp >= end
                            {
                                return;
                            }
                            count += 1;
                            // (Once `keep` are at or before `cutoff`,
                            // nothing after it can be one, and isn't
                            // decoded.)
                            if e.timestamp > cutoff {
                                return;
                            }
                            rows.push(decode(e, infos));
                            if rows.len() >= 2 * keep.max(1) {
                                rows.sort_by_key(|r| (r.timestamp, r.processor, r.thread_id));
                                rows.truncate(keep);
                                cutoff = rows.last().map_or(i64::MAX, |r| r.timestamp);
                            }
                        });
                    }
                }
                rows.sort_by_key(|r| (r.timestamp, r.processor, r.thread_id));
                rows.truncate(keep);
                let mut f = found
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                f.0 += count;
                f.1.append(&mut rows);
            });
        }
    });
    found
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One event decoded: by its own schema (TraceLogging), else its recorded
/// description, else the kernel's schema, else its payload as bytes.
fn decode(e: &Event<'_>, infos: &EventInfos) -> Row {
    let ptr = pointer_size(e);
    let show = |props: &[Property<'_>]| -> Vec<(String, String)> {
        props
            .iter()
            .map(|p| (p.name.clone(), values::format(p, ptr)))
            .collect()
    };
    let (fields, missing, extra) =
        if let Some(Ok(schema)) = hexcavator_etw::tracelogging::Schema::of(e) {
            let d = schema.decode(e);
            (show(&d.properties), d.missing, d.rest.len())
        } else if let Some(info) = infos.get(e) {
            let d = info.decode_partial(e);
            (show(&d.properties), d.missing, d.rest.len())
        } else if let Some(Ok(p)) = Properties::of(e) {
            (show(&p.properties), 0, p.rest.len())
        } else {
            let payload = Property {
                name: "Payload".to_string(),
                field: hexcavator_etw::schema::Field::Bytes(e.user_data.len()),
                data: e.user_data,
            };
            (show(&[payload]), 0, 0)
        };
    Row {
        timestamp: e.timestamp,
        processor: e.context.processor,
        process_id: e.process_id,
        thread_id: e.thread_id,
        fields,
        missing,
        extra,
    }
}

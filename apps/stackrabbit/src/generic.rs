//! Generic events: one kind of event's occurrences, read from the trace
//! file and decoded, in time order, a page at a time (as WPA's Generic
//! Events table shows them). Payloads decode by the description recorded
//! with the trace, else the kernel's schema, else show as bytes.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use hexcavator_etl::{Buffer, Etl, Event, Guid, merge::for_each_event};
use hexcavator_etw::KernelEvent;
use hexcavator_etw::event_info::{EventInfo, EventInfos};
use hexcavator_etw::schema::{Properties, Property, pointer_size};
use hexcavator_etw::values;
use hexcavator_mmap::Mmap;
use hexcavator_trace::{BufferSpan, ProcessIx, Trace};
use hexcavator_trace_analysis::{Resolver, Symbolizer};
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
    activity: Guid,
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
    stacks: Option<(&Resolver, &dyn Symbolizer)>,
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
    // Their stacks, if asked for.
    let found_stacks: Vec<Option<Vec<String>>> = match stacks {
        Some((resolver, symbols)) => stacks_of(trace, &etl, max, &rows, resolver, symbols),
        None => Vec::new(),
    };
    Ok(json!({
        "total": total,
        "offset": offset,
        "columns": columns,
        "rows": rows.iter().enumerate().map(|(i, r)| json!({
            "stack": found_stacks.get(i).cloned().flatten(),
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

/// Occurrences of events by kind (provider, ID, version).
pub type Occurrences =
    FxHashMap<(Guid, u16, u8), Vec<hexcavator_trace_analysis::regions::Occurrence>>;

/// Every occurrence of the kinds `wanted` names (provider, ID, version:
/// any opcode), with its payload's fields as text: read from the buffers
/// holding them, on every core, in time order for each kind.
pub fn occurrences(
    trace: &Trace,
    path: &Path,
    wanted: &[(Guid, u16, u8)],
) -> Result<Occurrences, String> {
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
    let kinds: Vec<u32> = trace
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| wanted.contains(&(e.provider, e.id, e.version)))
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect();
    let buffers: Vec<Buffer<'_>> = if trace.buffers.is_empty() {
        etl.buffers().flatten().collect()
    } else {
        trace
            .buffers
            .iter()
            .filter(|b| b.kinds.iter().any(|k| kinds.contains(k)))
            .filter_map(|b| etl.buffer_at(b.offset, b.index).ok())
            .collect()
    };
    type Found = Occurrences;
    let next = AtomicUsize::new(0);
    let all: Mutex<Found> = Mutex::default();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(buffers.len().div_ceil(CHUNK).max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut mine: Found = FxHashMap::default();
                loop {
                    let c = next.fetch_add(1, Ordering::Relaxed);
                    let from = c.saturating_mul(CHUNK);
                    if from >= buffers.len() {
                        break;
                    }
                    for buffer in &buffers[from..(from + CHUNK).min(buffers.len())] {
                        let _ = for_each_event(buffer, max, &mut scratch, |e| {
                            let key = (e.provider, e.descriptor.id, e.descriptor.version);
                            if !wanted.contains(&key) {
                                return;
                            }
                            let r = decode(e, &infos);
                            mine.entry(key).or_default().push(
                                hexcavator_trace_analysis::regions::Occurrence {
                                    time: r.timestamp,
                                    process_id: r.process_id,
                                    thread_id: r.thread_id,
                                    activity: r.activity,
                                    fields: r.fields,
                                },
                            );
                        });
                    }
                }
                let mut all = all
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for (k, mut v) in mine {
                    all.entry(k).or_default().append(&mut v);
                }
            });
        }
    });
    let mut all = all
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for v in all.values_mut() {
        v.sort_by_key(|o| (o.time, o.thread_id));
    }
    Ok(all)
}

/// How long after its event a stack's second (user-mode) part may come:
/// the import's window, in seconds.
const STACK_WINDOW_SECONDS: u64 = 5;

/// The stacks of `rows` (each's frames, innermost first, named by
/// `symbols`; none for an event without one): their pieces are the
/// StackWalk events naming each row's timestamp (and its thread, where
/// several rows share one), the kernel part and then the user part; read
/// from the buffers holding stacks, from the first row's time to a window
/// after the last's, on every core.
fn stacks_of(
    trace: &Trace,
    etl: &Etl<'_>,
    max: usize,
    rows: &[&Row],
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
) -> Vec<Option<Vec<String>>> {
    if rows.is_empty() {
        return Vec::new();
    }
    let stack_kinds: Vec<u32> = trace
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.provider == hexcavator_etw::guids::STACK_WALK)
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect();
    let first = rows.iter().map(|r| r.timestamp).min().unwrap_or(0);
    let window = i64::try_from(
        trace
            .clock
            .ticks_per_second
            .saturating_mul(STACK_WINDOW_SECONDS),
    )
    .unwrap_or(i64::MAX);
    let last = rows
        .iter()
        .map(|r| r.timestamp)
        .max()
        .unwrap_or(0)
        .saturating_add(window);
    let buffers: Vec<Buffer<'_>> = if trace.buffers.is_empty() {
        etl.buffers().flatten().collect()
    } else {
        trace
            .buffers
            .iter()
            .filter(|b| {
                b.kinds.iter().any(|k| stack_kinds.contains(k))
                    && b.last >= first
                    && b.first <= last
            })
            .filter_map(|b| etl.buffer_at(b.offset, b.index).ok())
            .collect()
    };
    // The rows by timestamp.
    let mut by_time: FxHashMap<i64, Vec<usize>> = FxHashMap::default();
    for (i, r) in rows.iter().enumerate() {
        by_time.entry(r.timestamp).or_default().push(i);
    }
    // Each piece found: (row, the piece's own timestamp, its process, its
    // frames).
    type Piece = (usize, i64, u32, Vec<u64>);
    let next = AtomicUsize::new(0);
    let pieces: Mutex<Vec<Piece>> = Mutex::default();
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(buffers.len().div_ceil(CHUNK).max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut scratch = Vec::new();
                let mut mine: Vec<Piece> = Vec::new();
                loop {
                    let c = next.fetch_add(1, Ordering::Relaxed);
                    let from = c.saturating_mul(CHUNK);
                    if from >= buffers.len() {
                        break;
                    }
                    for buffer in &buffers[from..(from + CHUNK).min(buffers.len())] {
                        let _ = for_each_event(buffer, max, &mut scratch, |e| {
                            if e.provider != hexcavator_etw::guids::STACK_WALK
                                || e.timestamp < first
                                || e.timestamp > last
                            {
                                return;
                            }
                            let Some(Ok(KernelEvent::Stack(st))) = hexcavator_etw::decode(e) else {
                                return;
                            };
                            let Some(candidates) = by_time.get(&st.event_timestamp) else {
                                return;
                            };
                            // (Several rows at that time: the one on the
                            // stack's thread, else the first.)
                            let row = candidates
                                .iter()
                                .copied()
                                .find(|&i| rows[i].thread_id == st.thread_id)
                                .unwrap_or(candidates[0]);
                            mine.push((
                                row,
                                e.timestamp,
                                st.process_id,
                                st.frames.iter().collect(),
                            ));
                        });
                    }
                }
                pieces
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .append(&mut mine);
            });
        }
    });
    let mut pieces = pieces
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Each row's pieces in the order they were logged: the kernel part,
    // then the user part.
    pieces.sort_by_key(|p| (p.0, p.1));
    let mut out: Vec<Option<Vec<String>>> = vec![None; rows.len()];
    let mut framer_cache: FxHashMap<(ProcessIx, u64), String> = FxHashMap::default();
    for (row, _, pid, frames) in pieces {
        let process = process_at(trace, pid, rows[row].timestamp);
        let stack = out[row].get_or_insert_with(Vec::new);
        for (j, f) in frames.into_iter().enumerate() {
            // (Return addresses, all but the innermost: looked up a byte
            // back, as trees do.)
            let lookup = if j == 0 && stack.is_empty() {
                f
            } else {
                f.wrapping_sub(1)
            };
            let text = framer_cache
                .entry((process, lookup))
                .or_insert_with(|| frame_label(trace, resolver, symbols, process, lookup, f))
                .clone();
            stack.push(text);
        }
    }
    out
}

/// The process with ID `pid` at `time`: the one alive then, else the
/// last with that ID.
fn process_at(trace: &Trace, pid: u32, time: i64) -> ProcessIx {
    let mut last = ProcessIx::NONE;
    for (i, p) in trace.processes.iter().enumerate() {
        if p.pid != pid {
            continue;
        }
        let ix = ProcessIx(u32::try_from(i).unwrap_or(u32::MAX));
        if p.start.is_none_or(|s| s <= time) && p.end.is_none_or(|e| e >= time) {
            return ix;
        }
        last = ix;
    }
    last
}

/// A frame's text: its function (and offset in it), else its module and
/// offset, else its address.
fn frame_label(
    trace: &Trace,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    process: ProcessIx,
    lookup: u64,
    address: u64,
) -> String {
    let Some(image) = resolver.image(process, lookup) else {
        return format!("{address:#x}");
    };
    let offset = lookup - trace.images[image.index()].base;
    let file = trace.images[image.index()].file_name();
    match symbols.function(trace, image, offset) {
        Some((start, name)) => format!(
            "{file}!{name}+{:#x}",
            address - trace.images[image.index()].base - start
        ),
        None => format!("{file}+{:#x}", address - trace.images[image.index()].base),
    }
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
        activity: e.activity_id,
        processor: e.context.processor,
        process_id: e.process_id,
        thread_id: e.thread_id,
        fields,
        missing,
        extra,
    }
}

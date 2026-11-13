//! How well `StackMatcher` pairs a trace's stacks with their events: counts
//! of matched pieces, continuations and misses, by event kind. Prints
//! aggregate counts only.
//!
//!     cargo run --release -p hexcavator-etw --example stackstat -- trace.etl

use std::collections::{BTreeMap, HashMap};

use hexcavator_etl::Etl;
use hexcavator_etw::stacks::StackMatcher;
use hexcavator_etw::{KernelEvent, decode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: stackstat trace.etl")?;
    let map = hexcavator_mmap::Mmap::open(path)?;
    let etl = Etl::parse(&map)?;
    let freq = etl.header().ticks_per_second().unwrap_or(10_000_000);
    let mut cursor = etl.events()?;
    let mut matcher = StackMatcher::new(i64::try_from(freq * 5).unwrap_or(i64::MAX));
    let mut kinds: HashMap<u64, String> = HashMap::new();
    let mut stats: BTreeMap<String, u64> = BTreeMap::new();
    let mut id = 0u64;
    let start = std::time::Instant::now();
    while let Some(e) = cursor.next() {
        let e = e?;
        id += 1;
        let decoded = decode(&e).and_then(Result::ok);
        if let Some(KernelEvent::Stack(s)) = &decoded {
            let label = match matcher.stack(e.context.processor, e.timestamp, s) {
                Some(m) => format!(
                    "{} {}",
                    if m.continuation {
                        "continues"
                    } else {
                        "matches"
                    },
                    kinds.get(&m.id).map_or("?", String::as_str)
                ),
                None => "unmatched".to_string(),
            };
            *stats.entry(label).or_default() += 1;
            continue;
        }
        matcher.event(id, &e, decoded.as_ref());
        kinds.insert(id, format!("{}/{}", e.provider, e.descriptor.opcode));
    }
    for (k, v) in &stats {
        println!("{v:>10}  {k}");
    }
    println!("{:.2} s", start.elapsed().as_secs_f64());
    Ok(())
}

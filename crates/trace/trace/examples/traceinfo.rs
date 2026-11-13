//! Imports a trace and prints counts and consistency checks (no names or
//! paths, so the output is safe to share).
//!
//!     cargo run --release -p hexcavator-trace --example traceinfo -- trace.etl [index.hxtrace]
//!
//! With a second argument, also writes the index there and times reading it.

use hexcavator_etl::Etl;
use hexcavator_trace::{ThreadIx, etw};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: traceinfo trace.etl")?;
    let map = hexcavator_mmap::Mmap::open(path)?;
    let etl = Etl::parse(&map)?;
    let start = std::time::Instant::now();
    let (trace, stats) = etw::import(&etl)?;
    let secs = start.elapsed().as_secs_f64();
    println!("imported in {secs:.2} s: {stats:?}");
    if let Some(out) = std::env::args().nth(2) {
        let t = std::time::Instant::now();
        let source = hexcavator_trace::index::Source::of(&map);
        let bytes = hexcavator_trace::index::write(&trace, source);
        std::fs::write(&out, &bytes)?;
        let written = t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        let saved = hexcavator_mmap::Mmap::open(&out)?;
        let back =
            hexcavator_trace::index::read(&saved, Some(hexcavator_trace::index::Source::of(&map)))?;
        println!(
            "index: {} MB written in {written:.2} s, read back in {:.2} s ({} switches)",
            bytes.len() >> 20,
            t.elapsed().as_secs_f64(),
            back.switches.len()
        );
    }
    println!(
        "processes {} threads {} images {} (with PDB ids {})",
        trace.processes.len(),
        trace.threads.len(),
        trace.images.len(),
        trace.images.iter().filter(|i| i.debug_id.is_some()).count()
    );
    let s = &trace.samples;
    let with_stack = s.stack.iter().filter(|x| !x.is_empty()).count();
    println!("samples {} (with stacks {with_stack})", s.len());
    let sw = &trace.switches;
    let with_ready = sw.ready.iter().filter(|r| r.is_some()).count();
    println!(
        "switches {} (with stacks {}, with readying event {with_ready}); readies {} (with stacks {})",
        sw.len(),
        sw.stack.iter().filter(|x| !x.is_empty()).count(),
        trace.readies.len(),
        trace.readies.stack.iter().filter(|x| !x.is_empty()).count()
    );
    println!("stack trie nodes {}", trace.stacks.len());

    // Each processor's switches chain: the thread switched out is the one
    // the previous switch on that processor switched in.
    let mut last: Vec<ThreadIx> = vec![ThreadIx::NONE; trace.processors as usize + 1];
    let (mut chained, mut broken) = (0u64, 0u64);
    for i in 0..sw.len() {
        let cpu = usize::from(sw.cpu[i]);
        if cpu >= last.len() {
            last.resize(cpu + 1, ThreadIx::NONE);
        }
        if last[cpu].is_some() {
            if sw.old_thread[i] == last[cpu] {
                chained += 1;
            } else {
                broken += 1;
            }
        }
        last[cpu] = sw.new_thread[i];
    }
    println!("switch chains: {chained} consistent, {broken} broken");

    // Samples should mostly land in a known image of the sampled thread's
    // process (or the kernel's).
    let unknown_thread = s
        .thread
        .iter()
        .filter(|t| trace.threads[t.index()].process.0 == u32::MAX)
        .count();
    println!("samples on threads of unknown process: {unknown_thread}");
    Ok(())
}

//! Prints the events and templates of a binary's instrumentation manifest
//! (`WEVT_TEMPLATE`), with each item descriptor's raw bytes.
//!
//!     cargo run -p hexcavator-etw --example manifestdump -- provider.dll [event-id ...]

use hexcavator_etw::manifest::{Item, Manifest, wevt_template};

fn print(items: &[Item], depth: usize) {
    for it in items {
        let raw: Vec<String> = it.raw.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{:indent$}{} in={} out={} count={:?} len={:?}  raw={}",
            "",
            it.name,
            it.in_type,
            it.out_type,
            it.count,
            it.length,
            raw.join(" "),
            indent = 4 + 2 * depth
        );
        print(&it.members, depth + 1);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let data = std::fs::read(&args[0])?;
    let wevt = wevt_template(&data).ok_or("no WEVT_TEMPLATE")?;
    let m = Manifest::parse(wevt)?;
    let ids: Vec<u16> = args[1..].iter().filter_map(|a| a.parse().ok()).collect();
    for p in &m.providers {
        println!(
            "provider {} events {} templates {}",
            p.guid,
            p.events.len(),
            p.templates.len()
        );
        for e in &p.events {
            if !ids.is_empty() && !ids.contains(&e.id) {
                continue;
            }
            println!(
                "  event {} v{} op {} task {} template {:?}",
                e.id, e.version, e.opcode, e.task, e.template
            );
            if let Some(t) = p.template(e) {
                print(&t.items, 0);
            }
        }
    }
    Ok(())
}

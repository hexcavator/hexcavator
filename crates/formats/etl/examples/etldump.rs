//! Prints a trace's events in the line format of `tools/etwdump`, for
//! comparison with Windows' `ProcessTrace`.
//!
//!     cargo run --release -p hexcavator-etl --example etldump -- trace.etl [-buffers | -raw]
//!
//! `-count` only counts events and times the read. `-buffers` prints each buffer's header instead; `-raw` prints events in
//! file order rather than timestamp order, with each record's hook ID.

use std::io::{BufWriter, Write};

use hexcavator_etl::{Etl, Event};

fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn line(out: &mut impl Write, e: &Event<'_>, raw: bool) -> std::io::Result<()> {
    let d = &e.descriptor;
    write!(
        out,
        "E {} {} id={} v={} ch={} lvl={} op={} task={} kw={:x} f={:x} p={:x} pid={} tid={} cpu={} lg={} pt={:x} act={} len={} h={:016x}",
        e.timestamp,
        e.provider,
        d.id,
        d.version,
        d.channel,
        d.level,
        d.opcode,
        d.task,
        d.keyword,
        e.flags,
        e.event_property,
        e.process_id,
        e.thread_id,
        e.context.processor,
        e.context.logger_id,
        e.processor_time,
        e.activity_id,
        e.user_data.len(),
        fnv(e.user_data),
    )?;
    for item in e.extended_data() {
        match item {
            Ok(x) => write!(
                out,
                " x={}:{}:{:016x}",
                x.ext_type,
                x.data.len(),
                fnv(x.data)
            )?,
            Err(err) => write!(out, " x=error({err})")?,
        }
    }
    if raw {
        write!(
            out,
            " hook={:?} at={:#x} kind={:?}",
            e.hook, e.file_offset, e.kind
        )?;
    }
    writeln!(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or("usage: etldump trace.etl")?;
    let map = hexcavator_mmap::Mmap::open(path)?;
    let etl = Etl::parse(&map)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::with_capacity(1 << 20, stdout.lock());
    let h = etl.header();
    writeln!(
        out,
        "H buffersize={} version={:08x} provider={} cpus={} end={} res={} maxsize={} mode={:08x} written={} ptr={} lost={} mhz={} boot={} freq={} start={} clock={} buflost={}",
        h.buffer_size,
        h.version,
        h.provider_version,
        h.number_of_processors,
        h.end_time,
        h.timer_resolution,
        h.maximum_file_size,
        h.log_file_mode,
        h.buffers_written,
        h.pointer_size,
        h.events_lost,
        h.cpu_speed_mhz,
        h.boot_time,
        h.perf_freq,
        h.start_time,
        h.reserved_flags,
        h.buffers_lost
    )?;
    let mut events = 0u64;
    let mut buffers = 0u64;
    if args.iter().any(|a| a == "-count") {
        let start = std::time::Instant::now();
        let mut cursor = etl.events()?;
        let mut bytes = 0usize;
        while let Some(e) = cursor.next() {
            bytes += e?.user_data.len();
            events += 1;
        }
        let secs = start.elapsed().as_secs_f64();
        writeln!(out, "T events={events} payload={bytes} seconds={secs:.3}")?;
        return Ok(());
    }
    if args.iter().any(|a| a == "-buffers") {
        for b in etl.buffers() {
            let b = b?;
            writeln!(out, "B {} {:#x} {:?}", b.index, b.file_offset, b.header)?;
        }
        return Ok(());
    }
    if args.iter().any(|a| a == "-raw") {
        for b in etl.buffers() {
            let b = b?;
            buffers += 1;
            if b.header.is_compressed() {
                writeln!(out, "B {} compressed", b.index)?;
                continue;
            }
            for e in b.records()? {
                match e {
                    Ok(e) => {
                        line(&mut out, &e, true)?;
                        events += 1;
                    }
                    Err(err) => writeln!(out, "error {err}")?,
                }
            }
        }
    } else {
        let mut cursor = etl.events()?;
        while let Some(e) = cursor.next() {
            match e {
                Ok(e) => {
                    line(&mut out, &e, false)?;
                    events += 1;
                }
                Err(err) => writeln!(out, "error {err}")?,
            }
        }
        buffers = etl.buffers().count() as u64;
    }
    writeln!(out, "T events={events} buffers={buffers} status=0")?;
    Ok(())
}

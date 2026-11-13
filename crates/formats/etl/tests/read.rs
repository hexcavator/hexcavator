//! Hermetic tests of the ETL reader, on traces built by `write`.

// Test inputs are small: their sizes and indexes fit any integer type.
#![allow(clippy::cast_possible_truncation)]

use hexcavator_etl::event::{ext_type, flags};
use hexcavator_etl::write::{self, Classic, EventFields, Kernel, Writer, WriterOptions};
use hexcavator_etl::{ClockType, Etl, Guid, HeaderKind, classic};

const PERFINFO: u16 = 0x0f;
const THREAD: u16 = 0x05;

fn provider() -> Guid {
    Guid::parse("331c3b3a-2005-44c2-ac5e-77220c37d6b4").unwrap()
}

/// Every event of `data`, as (timestamp, processor, opcode, payload).
fn read_all(data: &[u8]) -> Vec<(i64, u16, u8, Vec<u8>)> {
    let etl = Etl::parse(data).expect("parse");
    let mut cursor = etl.events().expect("events");
    let mut out = Vec::new();
    while let Some(e) = cursor.next() {
        let e = e.expect("event");
        out.push((
            e.timestamp,
            e.context.processor,
            e.descriptor.opcode,
            e.user_data.to_vec(),
        ));
    }
    out
}

fn kernel(hook: u16, ts: i64) -> Kernel {
    Kernel {
        hook,
        version: 2,
        thread_id: 100,
        process_id: 200,
        timestamp: ts,
        kernel_time: 3,
        user_time: 4,
    }
}

#[test]
fn logfile_header() {
    let data = Writer::new(WriterOptions::default()).finish();
    let etl = Etl::parse(&data).unwrap();
    let h = etl.header();
    assert_eq!(h.pointer_size, 8);
    assert_eq!(h.number_of_processors, 2);
    assert_eq!(h.buffer_size, 0x1000);
    assert_eq!(h.perf_freq, 10_000_000);
    assert_eq!(h.clock_type(), ClockType::PerformanceCounter);
    assert_eq!(h.ticks_per_second(), Some(10_000_000));
    assert_eq!(h.logger_name, "Test Session");
    assert_eq!(h.log_file_name, "test.etl");
    assert_eq!(h.provider_version, 26100);

    // The header event itself is delivered, as ProcessTrace does.
    let mut cursor = etl.events().unwrap();
    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.hook, Some(0));
    assert_eq!(e.provider, classic::group_guid(0).unwrap());
    assert!(cursor.next().is_none());
}

#[test]
fn logfile_header_32bit() {
    let data = Writer::new(WriterOptions {
        pointer_size: 4,
        clock_type: 2,
        ..WriterOptions::default()
    })
    .finish();
    let etl = Etl::parse(&data).unwrap();
    let h = etl.header();
    assert_eq!(h.pointer_size, 4);
    assert_eq!(h.perf_freq, 10_000_000);
    assert_eq!(h.clock_type(), ClockType::SystemTime);
    assert_eq!(h.logger_name, "Test Session");
}

#[test]
fn every_record_kind() {
    let mut w = Writer::new(WriterOptions::default());
    // Kernel records, 64- and 32-bit.
    w.record(
        0,
        &write::system(&kernel(THREAD << 8 | 0x24, 10), true, b"system"),
    );
    w.record(
        0,
        &write::compact(&kernel(THREAD << 8 | 0x32, 11), false, b"compact"),
    );
    w.record(
        0,
        &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, 12), true, b"perfinfo"),
    );
    // An image load, logged in the process group.
    w.record(0, &write::system(&kernel(0x030a, 13), true, b"image"));
    let fields = EventFields {
        flags: flags::BIT64_HEADER,
        event_property: 0x10,
        thread_id: 7,
        process_id: 8,
        timestamp: 14,
        provider: provider(),
        id: 557,
        version: 1,
        channel: 16,
        level: 4,
        opcode: 9,
        task: 259,
        keyword: 0x4000_0000_0000_0004,
        processor_time: 0x5_0000_0006,
        activity_id: Guid::parse("00000001-0002-0003-0405-060708090a0b").unwrap(),
    };
    let traits: &[u8] = b"\x16\x00\x00traits-------------";
    let key: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    w.record(
        0,
        &write::event(
            &fields,
            true,
            &[
                (ext_type::PROV_TRAITS, traits),
                (ext_type::STACK_KEY64, key),
            ],
            b"event",
        ),
    );
    let classic_fields = Classic {
        provider: provider(),
        opcode: 3,
        level: 5,
        version: 0x102,
        thread_id: 9,
        process_id: 10,
        timestamp: 15,
        processor_time: 0x1_0000_0002,
    };
    w.record(0, &write::classic(&classic_fields, false, b"classic"));
    let data = w.finish();

    let etl = Etl::parse(&data).unwrap();
    let mut cursor = etl.events().unwrap();
    cursor.next().unwrap().unwrap(); // the header

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.kind, HeaderKind::System);
    assert!(e.is_64bit);
    assert_eq!(e.provider, classic::group_guid(THREAD).unwrap());
    assert_eq!(e.hook, Some(0x0524));
    assert_eq!((e.descriptor.opcode, e.descriptor.version), (0x24, 2));
    assert_eq!(e.flags, 0x340);
    assert_eq!((e.process_id, e.thread_id), (200, 100));
    assert_eq!(e.processor_time, 0x4_0000_0003);
    assert_eq!(e.user_data, b"system");

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.kind, HeaderKind::Compact);
    assert!(!e.is_64bit);
    assert_eq!(
        e.flags,
        flags::CLASSIC_HEADER | flags::PROCESSOR_INDEX | flags::BIT32_HEADER | flags::NO_CPUTIME
    );
    assert_eq!((e.process_id, e.thread_id), (200, 100));
    assert_eq!(e.processor_time, 0);
    assert_eq!(e.user_data, b"compact");

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.kind, HeaderKind::PerfInfo);
    assert_eq!(e.provider, classic::group_guid(PERFINFO).unwrap());
    assert_eq!(e.flags, 0x350);
    assert_eq!((e.process_id, e.thread_id), (u32::MAX, u32::MAX));
    assert_eq!(e.timestamp, 12);
    assert_eq!(e.user_data, b"perfinfo");

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(
        e.provider,
        classic::group_guid(0x14).unwrap(),
        "image loads"
    );
    assert_eq!(e.descriptor.opcode, 10);

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.kind, HeaderKind::Event);
    assert_eq!(e.provider, provider());
    let d = e.descriptor;
    assert_eq!(
        (
            d.id, d.version, d.channel, d.level, d.opcode, d.task, d.keyword
        ),
        (557, 1, 16, 4, 9, 259, 0x4000_0000_0000_0004)
    );
    assert_eq!(
        e.flags,
        flags::BIT64_HEADER | flags::EXTENDED_INFO | flags::PROCESSOR_INDEX
    );
    assert_eq!(e.event_property, 0x10);
    assert_eq!((e.process_id, e.thread_id), (8, 7));
    assert_eq!(e.processor_time, 0x5_0000_0006);
    assert_eq!(e.activity_id, fields.activity_id);
    assert_eq!(e.user_data, b"event");
    let items: Vec<_> = e.extended_data().map(Result::unwrap).collect();
    assert_eq!(items.len(), 2);
    assert_eq!(
        (items[0].ext_type, items[0].data),
        (ext_type::PROV_TRAITS, traits)
    );
    assert_eq!(
        (items[1].ext_type, items[1].data),
        (ext_type::STACK_KEY64, key)
    );

    let e = cursor.next().unwrap().unwrap();
    assert_eq!(e.kind, HeaderKind::Full);
    assert_eq!(e.provider, provider());
    assert_eq!(
        (
            e.descriptor.opcode,
            e.descriptor.level,
            e.descriptor.version
        ),
        (3, 5, 2)
    );
    assert_eq!(
        e.flags,
        flags::CLASSIC_HEADER | flags::PROCESSOR_INDEX | flags::BIT32_HEADER
    );
    assert_eq!(e.processor_time, 0x1_0000_0002);
    assert_eq!(e.user_data, b"classic");

    assert!(cursor.next().is_none());
}

/// Writes events at `times[cpu]` on each processor, with small buffers so
/// that each processor has several.
fn interleaved(compress: bool, times: &[&[i64]]) -> Vec<u8> {
    let mut w = Writer::new(WriterOptions {
        buffer_size: 0x100,
        processors: times.len() as u32,
        compress,
        ..WriterOptions::default()
    });
    for (cpu, ts) in times.iter().enumerate() {
        for &t in *ts {
            let payload = format!("{cpu}:{t}");
            w.record(
                cpu as u16,
                &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, t), true, payload.as_bytes()),
            );
        }
    }
    w.finish()
}

#[test]
fn merges_processors_by_timestamp() {
    let a: Vec<i64> = (0..40).map(|i| i * 3).collect();
    let b: Vec<i64> = (0..40).map(|i| i * 3 + 1).collect();
    let c: Vec<i64> = (0..40).map(|i| i * 3 + 2).collect();
    let data = interleaved(false, &[&a, &b, &c]);
    let etl = Etl::parse(&data).unwrap();
    assert!(etl.buffers().count() > 10, "several buffers per processor");
    let events = read_all(&data);
    let times: Vec<i64> = events.iter().skip(1).map(|e| e.0).collect();
    assert_eq!(times, (0..120).collect::<Vec<_>>());
    for (t, cpu, _, payload) in &events[1..] {
        assert_eq!(i64::from(*cpu), t % 3);
        assert_eq!(payload, format!("{cpu}:{t}").as_bytes());
    }
}

#[test]
fn ties_keep_the_current_stream() {
    // Processor 1 gives 5 first; at the tie on 6, it keeps going.
    let data = interleaved(false, &[&[6, 6, 9], &[5, 6, 6, 7]]);
    let order: Vec<(i64, u16)> = read_all(&data).iter().skip(1).map(|e| (e.0, e.1)).collect();
    assert_eq!(
        order,
        [(5, 1), (6, 1), (6, 1), (6, 0), (6, 0), (7, 1), (9, 0)]
    );
}

#[test]
fn compressed_buffers() {
    let a: Vec<i64> = (0..50).map(|i| i * 2).collect();
    let b: Vec<i64> = (0..50).map(|i| i * 2 + 1).collect();
    let plain = interleaved(false, &[&a, &b]);
    let packed = interleaved(true, &[&a, &b]);
    let etl = Etl::parse(&packed).unwrap();
    assert!(
        etl.buffers()
            .skip(1)
            .all(|b| b.unwrap().header.is_compressed())
    );
    assert_eq!(read_all(&plain), read_all(&packed));
}

#[test]
fn buffers_with_their_own_sizes() {
    // Compressed buffers have the sizes they compressed to, so buffers are
    // found by each one's size, not the session's.
    let data = interleaved(true, &[&[1, 2, 3], &[4]]);
    let etl = Etl::parse(&data).unwrap();
    let sizes: Vec<u32> = etl
        .buffers()
        .map(|b| b.unwrap().header.buffer_size)
        .collect();
    assert_eq!(sizes.len(), 3);
    assert!(sizes[1] != 0x100 && sizes[1] != sizes[2]);
}

#[test]
fn malformed_record_skips_its_buffer() {
    let mut w = Writer::new(WriterOptions::default());
    w.record(
        0,
        &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, 1), true, b"a"),
    );
    let mut bad = write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, 2), true, b"b");
    bad[2] = 0x7f; // an unknown header type
    w.record(0, &bad);
    w.record(
        0,
        &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, 3), true, b"lost"),
    );
    w.record(
        1,
        &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, 4), true, b"kept"),
    );
    let data = w.finish();
    let etl = Etl::parse(&data).unwrap();
    let mut cursor = etl.events().unwrap();
    let mut seen = Vec::new();
    let mut errors = 0;
    while let Some(e) = cursor.next() {
        match e {
            Ok(e) => seen.push(e.user_data.to_vec()),
            Err(_) => errors += 1,
        }
    }
    assert_eq!(errors, 1);
    assert_eq!(seen.last().unwrap(), b"kept");
    assert!(!seen.iter().any(|p| p == b"lost"));
}

#[test]
fn rejects_what_is_not_an_etl_file() {
    assert!(Etl::parse(&[]).is_err());
    assert!(Etl::parse(&[0; 0x47]).is_err());
    assert!(Etl::parse(&[0xff; 0x1000]).is_err());
    // A buffer whose first event isn't the logfile header.
    let mut data = Writer::new(WriterOptions::default()).finish();
    data[0x48 + 6] = 1; // hook 0x0001
    assert!(Etl::parse(&data).is_err());
}

/// A small trace with every record kind, two processors and several
/// buffers, for the malformed-input tests.
fn sample(compress: bool) -> Vec<u8> {
    let mut w = Writer::new(WriterOptions {
        buffer_size: 0x180,
        compress,
        ..WriterOptions::default()
    });
    for i in 0..6 {
        let cpu = (i % 2) as u16;
        w.record(
            cpu,
            &write::system(&kernel(THREAD << 8 | 0x24, i * 10), true, b"sys"),
        );
        w.record(
            cpu,
            &write::perfinfo(&kernel(PERFINFO << 8 | 0x2e, i * 10 + 1), false, b"pi"),
        );
        let fields = EventFields {
            timestamp: i * 10 + 2,
            provider: provider(),
            ..EventFields::default()
        };
        w.record(
            cpu,
            &write::event(
                &fields,
                true,
                &[(ext_type::STACK_KEY64, &[0; 8]), (ext_type::SID, b"x")],
                b"ev",
            ),
        );
        let c = Classic {
            timestamp: i * 10 + 3,
            provider: provider(),
            ..Classic::default()
        };
        w.record(cpu, &write::classic(&c, true, b"cl"));
    }
    w.finish()
}

/// Reads everything `data` holds, ignoring errors; it must return.
fn exercise(data: &[u8]) -> usize {
    let Ok(etl) = Etl::parse(data) else {
        return 0;
    };
    let mut n = 0;
    for b in etl.buffers() {
        let Ok(b) = b else { break };
        if let Ok(records) = b.records() {
            for e in records.flatten() {
                n += e.extended_data().count();
            }
        }
    }
    if let Ok(mut cursor) = etl.events() {
        while let Some(e) = cursor.next() {
            if let Ok(e) = e {
                n += e.extended_data().count() + e.user_data.len();
            }
        }
    }
    n
}

#[test]
fn truncated_anywhere() {
    for compress in [false, true] {
        let data = sample(compress);
        for len in 0..data.len() {
            exercise(&data[..len]);
        }
    }
}

#[test]
fn corrupted_anywhere() {
    for compress in [false, true] {
        let data = sample(compress);
        let mut copy = data.clone();
        for i in 0..data.len() {
            for v in [
                0x00,
                0xff,
                0x80,
                0x7f,
                data[i].wrapping_add(1),
                data[i] ^ 0x08,
            ] {
                copy[i] = v;
                exercise(&copy);
            }
            copy[i] = data[i];
        }
    }
}

#[test]
fn random_garbage() {
    // A deterministic xorshift, over a valid header buffer followed by
    // random buffers with plausible headers.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let header = Writer::new(WriterOptions::default()).finish();
    for _ in 0..2000 {
        let mut data = header.clone();
        let size = 0x48 + (next() % 0x400) as usize;
        let mut buf: Vec<u8> = (0..size).map(|_| next() as u8).collect();
        buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
        buf[0x30..0x34].copy_from_slice(&((next() % (size as u64 + 16)) as u32).to_le_bytes());
        data.extend_from_slice(&buf);
        exercise(&data);
    }
}

/// The synthetic traces in `testdata/etl`, which seed the fuzzer, are what
/// `sample` writes. `HEXC_BLESS=1` rewrites them.
#[test]
fn testdata_is_current() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/etl");
    for (name, compress) in [("sample.etl", false), ("sample-compressed.etl", true)] {
        let path = dir.join(name);
        let data = sample(compress);
        if std::env::var_os("HEXC_BLESS").is_some() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &data).unwrap();
        }
        let committed = std::fs::read(&path).expect("testdata/etl (HEXC_BLESS=1 writes it)");
        assert!(
            committed == data,
            "{name} is stale; HEXC_BLESS=1 rewrites it"
        );
    }
}

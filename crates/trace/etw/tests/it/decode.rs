//! Hermetic tests of the decoders, the schemas and the stack matcher, on
//! events built with `hexcavator_etl::write`.

#![allow(clippy::cast_possible_truncation, clippy::type_complexity)]

use hexcavator_etl::write::{self, Classic, Kernel, Writer, WriterOptions};
use hexcavator_etl::{Etl, Guid, classic};
use hexcavator_etw::guids;
use hexcavator_etw::kernel::{KernelEvent, Lifetime, decode};
use hexcavator_etw::schema::{Field, Properties, lookup};
use hexcavator_etw::stacks::StackMatcher;

/// Payload builder.
#[derive(Default)]
struct P(Vec<u8>);

impl P {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn utf16z(mut self, s: &str) -> Self {
        for u in s.encode_utf16().chain([0]) {
            self.0.extend_from_slice(&u.to_le_bytes());
        }
        self
    }
    fn ansiz(mut self, s: &str) -> Self {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
}

fn group(guid: &Guid) -> u16 {
    classic::guid_group(guid).unwrap()
}

/// A trace of kernel records `(cpu, provider, opcode, version, timestamp,
/// thread, payload)`, in system (64-bit) headers.
fn trace(records: &[(u16, Guid, u8, u16, i64, u32, Vec<u8>)]) -> Vec<u8> {
    let mut w = Writer::new(WriterOptions {
        buffer_size: 0x10000,
        processors: 4,
        ..WriterOptions::default()
    });
    for (cpu, provider, opcode, version, ts, tid, payload) in records {
        let rec = if *provider == guids::KERNEL_TRACE_CONTROL {
            write::classic(
                &Classic {
                    provider: *provider,
                    opcode: *opcode,
                    version: *version,
                    thread_id: *tid,
                    timestamp: *ts,
                    ..Classic::default()
                },
                true,
                payload,
            )
        } else {
            write::system(
                &Kernel {
                    hook: group(provider) << 8 | u16::from(*opcode),
                    version: *version,
                    thread_id: *tid,
                    process_id: 1,
                    timestamp: *ts,
                    ..Kernel::default()
                },
                true,
                payload,
            )
        };
        w.record(*cpu, &rec);
    }
    w.finish()
}

fn process_payload(pid: u32, name: &str, cmd: &str) -> Vec<u8> {
    P::default()
        .u64(0xffff_8000_1234_0000) // UniqueProcessKey
        .u32(pid)
        .u32(4) // ParentId
        .u32(1) // SessionId
        .u32(0) // ExitStatus
        .u64(0x1000) // DirectoryTableBase
        .u32(0) // Flags
        // TOKEN_USER (pointer + attributes, padded) and a SID with one
        // sub-authority: S-1-5-18.
        .u64(0xffff_cf0e_be21_6700)
        .u64(0)
        .bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
        .ansiz(name)
        .utf16z(cmd)
        .utf16z("")
        .utf16z("")
        .0
}

fn thread_payload(pid: u32, tid: u32) -> Vec<u8> {
    let mut p = P::default().u32(pid).u32(tid);
    for v in [1u64, 2, 3, 4, 5, 0x7ff0_1234, 0x7000] {
        p = p.u64(v);
    }
    p.u32(0).u8(8).u8(5).u8(2).u8(0).0
}

fn image_payload(pid: u32, base: u64, size: u64, name: &str) -> Vec<u8> {
    P::default()
        .u64(base)
        .u64(size)
        .u32(pid)
        .u32(0xabcd) // checksum
        .u32(0x6000_0000) // timestamp
        .u8(0)
        .u8(0)
        .u16(0)
        .u64(base)
        .bytes(&[0; 16])
        .utf16z(name)
        .0
}

fn sample_payload(ip: u64, tid: u32) -> Vec<u8> {
    P::default().u64(ip).u32(tid).u16(1).u16(0).0
}

fn cswitch_payload(new: u32, old: u32) -> Vec<u8> {
    P::default()
        .u32(new)
        .u32(old)
        .u8(9)
        .u8(8)
        .u8(0)
        .u8(0)
        .u8(6) // wait reason
        .u8(1)
        .u8(5) // state
        .u8(0)
        .u32(77)
        .u32(0)
        .0
}

fn ready_payload(tid: u32) -> Vec<u8> {
    P::default().u32(tid).u8(1).u8(2).u8(0).u8(0).0
}

fn stack_payload(ts: i64, pid: u32, tid: u32, frames: &[u64]) -> Vec<u8> {
    let mut p = P::default().u64(ts as u64).u32(pid).u32(tid);
    for &f in frames {
        p = p.u64(f);
    }
    p.0
}

fn decoded(data: &[u8]) -> Vec<KernelEvent<'_>> {
    let etl = Etl::parse(data).unwrap();
    let mut out = Vec::new();
    let mut cursor = etl.events().unwrap();
    while let Some(e) = cursor.next() {
        let e = e.unwrap();
        if let Some(d) = decode(&e) {
            // Leak the cursor's borrow: re-decode from the file later.
            let _ = d.unwrap();
        }
    }
    // Decode again from buffers, which borrow the file, not the cursor.
    for b in etl.buffers() {
        for e in b.unwrap().records().unwrap() {
            let e = e.unwrap();
            if let Some(d) = decode(&e) {
                out.push(d.unwrap());
            }
        }
    }
    out
}

#[test]
fn decodes_each_kind() {
    let data = trace(&[
        (
            0,
            guids::PROCESS,
            1,
            4,
            10,
            5,
            process_payload(100, "app.exe", "app.exe -x"),
        ),
        (0, guids::THREAD, 1, 3, 11, 5, thread_payload(100, 200)),
        (
            0,
            guids::IMAGE,
            10,
            3,
            12,
            5,
            image_payload(100, 0x7ff0_0000, 0x10000, r"\Device\X\app.exe"),
        ),
        (
            0,
            guids::PERF_INFO,
            46,
            2,
            13,
            0,
            sample_payload(0x7ff0_1000, 200),
        ),
        (0, guids::THREAD, 36, 2, 14, 0, cswitch_payload(200, 0)),
        (0, guids::THREAD, 50, 2, 15, 0, ready_payload(300)),
        (
            0,
            guids::STACK_WALK,
            32,
            2,
            16,
            0,
            stack_payload(13, 100, 200, &[0x7ff0_1000, 0x7ff0_2000]),
        ),
        (
            0,
            guids::KERNEL_TRACE_CONTROL,
            36,
            2,
            17,
            0,
            P::default()
                .u64(0x7ff0_0000)
                .u32(100)
                .bytes(
                    &Guid::parse("01234567-89ab-cdef-0123-456789abcdef")
                        .unwrap()
                        .to_bytes(),
                )
                .u32(3)
                .ansiz(r"c:\src\app.pdb")
                .0,
        ),
        (
            0,
            guids::KERNEL_TRACE_CONTROL,
            0,
            2,
            18,
            0,
            P::default()
                .u64(0x7ff0_0000)
                .u64(0x10000)
                .u32(100)
                .u32(0x6000_0000)
                .utf16z("app.exe")
                .0,
        ),
    ]);
    let events = decoded(&data);
    assert_eq!(events.len(), 9);
    let KernelEvent::Process(p) = &events[0] else {
        panic!()
    };
    assert_eq!(
        (p.lifetime, p.process_id, p.parent_id, p.image_file_name),
        (Lifetime::Start, 100, 4, &b"app.exe"[..])
    );
    assert_eq!(p.command_line.to_string_lossy(), "app.exe -x");
    assert_eq!(p.user_sid, [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    let KernelEvent::Thread(t) = &events[1] else {
        panic!()
    };
    assert_eq!(
        (t.process_id, t.thread_id, t.win32_start_address, t.teb),
        (100, 200, 0x7ff0_1234, 0x7000)
    );
    let KernelEvent::Image(i) = &events[2] else {
        panic!()
    };
    assert_eq!(
        (i.base, i.size, i.process_id, i.time_date_stamp),
        (0x7ff0_0000, 0x10000, 100, 0x6000_0000)
    );
    assert_eq!(i.file_name.to_string_lossy(), r"\Device\X\app.exe");
    let KernelEvent::Sample(s) = &events[3] else {
        panic!()
    };
    assert_eq!(
        (s.instruction_pointer, s.thread_id, s.count),
        (0x7ff0_1000, 200, 1)
    );
    let KernelEvent::ContextSwitch(c) = &events[4] else {
        panic!()
    };
    assert_eq!(
        (
            c.new_thread_id,
            c.old_thread_id,
            c.old_thread_wait_reason,
            c.old_thread_state
        ),
        (200, 0, 6, 5)
    );
    assert_eq!(
        (
            c.new_thread_priority,
            c.old_thread_priority,
            c.new_thread_wait_time
        ),
        (9, 8, 77)
    );
    let KernelEvent::ReadyThread(r) = &events[5] else {
        panic!()
    };
    assert_eq!(
        (r.thread_id, r.adjust_reason, r.adjust_increment),
        (300, 1, 2)
    );
    let KernelEvent::Stack(st) = &events[6] else {
        panic!()
    };
    assert_eq!(
        (st.event_timestamp, st.process_id, st.thread_id),
        (13, 100, 200)
    );
    assert_eq!(
        st.frames.iter().collect::<Vec<_>>(),
        [0x7ff0_1000, 0x7ff0_2000]
    );
    let KernelEvent::DbgId(d) = &events[7] else {
        panic!()
    };
    assert_eq!(
        (d.base, d.age, d.pdb_file_name, d.il),
        (0x7ff0_0000, 3, &br"c:\src\app.pdb"[..], false)
    );
    let KernelEvent::ImageId(id) = &events[8] else {
        panic!()
    };
    assert_eq!(id.original_file_name.to_string_lossy(), "app.exe");
}

#[test]
fn schemas_name_every_property() {
    let data = trace(&[(
        0,
        guids::PROCESS,
        1,
        4,
        10,
        5,
        process_payload(100, "app.exe", "cmd"),
    )]);
    let etl = Etl::parse(&data).unwrap();
    let b = etl.buffers().nth(1).unwrap().unwrap();
    let e = b.records().unwrap().next().unwrap().unwrap();
    let props = Properties::of(&e).unwrap().unwrap();
    assert!(props.exact);
    assert_eq!(props.schema.name, "Start");
    let names: Vec<&str> = props.properties.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names[..3], ["UniqueProcessKey", "ProcessId", "ParentId"]);
    assert_eq!(props.get("ProcessId").unwrap().data, 100u32.to_le_bytes());
    assert_eq!(props.get("UserSID").unwrap().data.len(), 16 + 12);
    assert_eq!(props.get("ImageFileName").unwrap().data, b"app.exe\0");
    assert_eq!(props.get("CommandLine").unwrap().data, b"c\0m\0d\0\0\0");
    assert!(props.rest.is_empty());
}

#[test]
fn newer_versions_use_older_layouts() {
    // CSwitch v5 has four more bytes than v2.
    let (schema, exact) = lookup(&guids::THREAD, 36, 5).unwrap();
    assert_eq!((schema.version, exact), (2, false));
    let mut payload = cswitch_payload(1, 2);
    payload.extend_from_slice(&[9, 9, 9, 9]);
    let data = trace(&[(0, guids::THREAD, 36, 5, 1, 0, payload)]);
    let etl = Etl::parse(&data).unwrap();
    let b = etl.buffers().nth(1).unwrap().unwrap();
    let e = b.records().unwrap().next().unwrap().unwrap();
    let props = Properties::of(&e).unwrap().unwrap();
    assert!(!props.exact);
    assert_eq!(props.rest, [9, 9, 9, 9]);
    let Some(Ok(KernelEvent::ContextSwitch(c))) = decode(&e) else {
        panic!()
    };
    assert_eq!((c.new_thread_id, c.old_thread_id), (1, 2));
    // No layout for versions older than any we know.
    assert!(lookup(&guids::THREAD, 36, 1).is_none());
    assert!(lookup(&guids::THREAD, 250, 2).is_none());
}

#[test]
fn stack_frames_are_pointers_to_the_end() {
    let (schema, _) = lookup(&guids::STACK_WALK, 32, 2).unwrap();
    assert_eq!(schema.fields.last().unwrap().1, Field::Pointers);
    let payload = stack_payload(5, 1, 2, &[10, 20, 30]);
    let props = Properties::decode(schema, true, &payload, 8, 0).unwrap();
    let names: Vec<&str> = props.properties.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "EventTimeStamp",
            "StackProcess",
            "StackThread",
            "Stack1",
            "Stack2",
            "Stack3"
        ]
    );
    // 32-bit pointers.
    let mut p32 = P::default().u64(5).u32(1).u32(2).u32(10).u32(20).0;
    p32.push(0xff); // a stray byte is no frame
    let props = Properties::decode(schema, true, &p32, 4, 0).unwrap();
    assert_eq!(props.properties.len(), 5);
    assert_eq!(props.rest, [0xff]);
}

#[test]
fn truncated_payloads_are_errors() {
    let payloads: Vec<(Guid, u8, u16, Vec<u8>)> = vec![
        (guids::PROCESS, 1, 4, process_payload(1, "a", "b")),
        (guids::THREAD, 1, 3, thread_payload(1, 2)),
        (guids::IMAGE, 10, 3, image_payload(1, 2, 3, "x")),
        (guids::PERF_INFO, 46, 2, sample_payload(1, 2)),
        (guids::THREAD, 36, 2, cswitch_payload(1, 2)),
        (guids::THREAD, 50, 2, ready_payload(1)),
        (guids::STACK_WALK, 32, 2, stack_payload(1, 2, 3, &[4])),
    ];
    for (provider, op, version, payload) in payloads {
        for len in 0..=payload.len() {
            let data = trace(&[(0, provider, op, version, 1, 0, payload[..len].to_vec())]);
            let etl = Etl::parse(&data).unwrap();
            let b = etl.buffers().nth(1).unwrap().unwrap();
            let e = b.records().unwrap().next().unwrap().unwrap();
            // Strings may run to the end; fixed fields may not. Neither panics.
            let _ = decode(&e).unwrap();
            let _ = Properties::of(&e).unwrap();
            if len < 4 {
                assert!(decode(&e).unwrap().is_err(), "{provider} {op} at {len}");
            }
        }
    }
}

#[test]
fn garbage_payloads_never_panic() {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let kinds = [
        (guids::PROCESS, 1, 4),
        (guids::PROCESS, 39, 5),
        (guids::THREAD, 1, 3),
        (guids::IMAGE, 10, 3),
        (guids::STACK_WALK, 32, 2),
        (guids::KERNEL_TRACE_CONTROL, 36, 2),
        (guids::FILE_IO, 64, 3),
        (guids::SYSTEM_CONFIG, 10, 3),
    ];
    for _ in 0..300 {
        for (provider, op, version) in kinds {
            let len = (next() % 200) as usize;
            let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let data = trace(&[(0, provider, op, version, 1, 0, payload)]);
            let etl = Etl::parse(&data).unwrap();
            let b = etl.buffers().nth(1).unwrap().unwrap();
            let e = b.records().unwrap().next().unwrap().unwrap();
            let _ = decode(&e);
            let _ = Properties::of(&e);
        }
    }
}

/// Events for the matcher: (cpu, provider, opcode, timestamp, payload).
fn match_all(records: &[(u16, Guid, u8, i64, Vec<u8>)], window: i64) -> Vec<Option<(u64, bool)>> {
    let data = trace(
        &records
            .iter()
            .map(|(cpu, g, op, ts, p)| (*cpu, *g, *op, 2, *ts, u32::MAX, p.clone()))
            .collect::<Vec<_>>(),
    );
    let etl = Etl::parse(&data).unwrap();
    let mut cursor = etl.events().unwrap();
    let mut matcher = StackMatcher::new(window);
    let mut out = Vec::new();
    let mut id = 0;
    while let Some(e) = cursor.next() {
        let e = e.unwrap();
        id += 1;
        match decode(&e).map(Result::unwrap) {
            Some(KernelEvent::Stack(s)) => {
                out.push(
                    matcher
                        .stack(e.context.processor, e.timestamp, &s)
                        .map(|m| (m.id, m.continuation)),
                );
            }
            d => matcher.event(id, &e, d.as_ref()),
        }
    }
    out
}

#[test]
fn matches_stacks() {
    const K: u64 = 0xffff_f800_0000_1000;
    const U: u64 = 0x7ff0_0000_1000;
    let r = match_all(
        &[
            // Event 2 (the header is 1): a sample of thread 7 on cpu 0.
            (0, guids::PERF_INFO, 46, 10, sample_payload(K, 7)),
            // Its kernel stack.
            (0, guids::STACK_WALK, 32, 11, stack_payload(10, 1, 7, &[K])),
            // Event 4: thread 8 switched in on cpu 1.
            (1, guids::THREAD, 36, 12, cswitch_payload(8, 0)),
            // Event 5: thread 8 readies thread 9 (no thread in its header).
            (1, guids::THREAD, 50, 13, ready_payload(9)),
            (1, guids::STACK_WALK, 32, 14, stack_payload(13, 1, 8, &[K])),
            // The user part of the sample's stack, later, on cpu 2.
            (2, guids::STACK_WALK, 32, 15, stack_payload(10, 1, 7, &[U])),
            // A stack for no event.
            (2, guids::STACK_WALK, 32, 16, stack_payload(99, 1, 7, &[U])),
        ],
        1000,
    );
    assert_eq!(
        r,
        [Some((2, false)), Some((5, false)), Some((2, true)), None]
    );
}

#[test]
fn forgets_old_stacks() {
    const K: u64 = 0xffff_f800_0000_1000;
    let r = match_all(
        &[
            (0, guids::PERF_INFO, 46, 10, sample_payload(K, 7)),
            (0, guids::STACK_WALK, 32, 11, stack_payload(10, 1, 7, &[K])),
            // After the window the first match is forgotten, so this isn't
            // a continuation; the event is still among the processor's
            // recent ones, so it matches as a first part again.
            (0, guids::STACK_WALK, 32, 500, stack_payload(10, 1, 7, &[K])),
        ],
        100,
    );
    assert_eq!(r, [Some((2, false)), Some((2, false))]);
}

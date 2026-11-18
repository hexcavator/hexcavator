//! The encoders: every event they write decodes back to itself, on 64-bit
//! and 32-bit traces, and is laid out exactly as the event's TDH schema
//! says (every field, none missing, nothing left over).

use hexcavator_etl::write::{Writer, WriterOptions};
use hexcavator_etl::{Etl, Guid};
use hexcavator_etw::encode::{Context, encode, record};
use hexcavator_etw::kernel::{
    ContextSwitch, DbgId, Frames, ImageEvent, ImageId, KernelEvent, Lifetime, ProcessEvent,
    ReadyThread, Sample, StackWalk, ThreadEvent, ThreadName, Utf16, decode,
};
use hexcavator_etw::schema::Properties;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Pointer-sized frames as bytes.
fn frames(ptr: usize, values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|&v| {
            if ptr == 8 {
                v.to_le_bytes().to_vec()
            } else {
                u32::try_from(v).unwrap().to_le_bytes().to_vec()
            }
        })
        .collect()
}

/// A value that fits in a trace's pointers: on 32-bit, its low half.
fn p(ptr: usize, v: u64) -> u64 {
    if ptr == 8 { v } else { v & 0xffff_ffff }
}

/// Owned storage for the events' strings, so the events can borrow them.
struct Strings {
    cmd: Vec<u8>,
    package: Vec<u8>,
    app: Vec<u8>,
    image: Vec<u8>,
    name: Vec<u8>,
    original: Vec<u8>,
    frames: Vec<u8>,
}

impl Strings {
    fn new(ptr: usize) -> Self {
        Self {
            cmd: utf16("app.exe --flag \"quoted\""),
            package: utf16("Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe"),
            app: utf16("App"),
            image: utf16(r"\Device\HarddiskVolume3\Program Files\App\app.exe"),
            name: utf16("worker #3"),
            original: utf16("app.exe"),
            frames: frames(
                ptr,
                &[
                    p(ptr, 0xffff_f800_1234_5678),
                    p(ptr, 0x7ff6_0000_1000),
                    p(ptr, 0x7ff6_0000_2000),
                ],
            ),
        }
    }
}

/// S-1-5-21-1-2-3-1001: five sub-authorities.
const SID: &[u8] = &[
    1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe9, 3, 0, 0,
];

/// One of every event, in every lifetime the kernel logs.
fn events<'a>(s: &'a Strings, ptr: usize) -> Vec<KernelEvent<'a>> {
    let mut out = Vec::new();
    let lifetimes = [
        Lifetime::Start,
        Lifetime::End,
        Lifetime::RundownStart,
        Lifetime::RundownEnd,
        Lifetime::Defunct,
    ];
    for (i, &lifetime) in lifetimes.iter().enumerate() {
        let i = u32::try_from(i).unwrap();
        out.push(KernelEvent::Process(ProcessEvent {
            lifetime,
            unique_key: p(ptr, 0xffff_c00f_1234_0000 + u64::from(i)),
            process_id: 100 + i,
            parent_id: 4,
            session_id: 1,
            exit_status: if lifetime == Lifetime::End { -1 } else { 0 },
            directory_table_base: p(ptr, 0x1_2345_6000),
            flags: 0x10,
            user_sid: if i.is_multiple_of(2) { SID } else { &[] },
            image_file_name: b"app.exe",
            command_line: Utf16(&s.cmd),
            package_full_name: Utf16(if i == 0 { &s.package } else { &[] }),
            application_id: Utf16(if i == 0 { &s.app } else { &[] }),
            exit_time: (lifetime == Lifetime::Defunct).then_some(0x01db_0000_1234_5678),
        }));
        if lifetime != Lifetime::Defunct {
            out.push(KernelEvent::Thread(ThreadEvent {
                lifetime,
                process_id: 100 + i,
                thread_id: 200 + i,
                stack_base: p(ptr, 0xffff_a000_0000_8000),
                stack_limit: p(ptr, 0xffff_a000_0000_2000),
                user_stack_base: p(ptr, 0x0000_00e0_0010_0000),
                user_stack_limit: p(ptr, 0x0000_00e0_000f_0000),
                win32_start_address: p(ptr, 0x7ff6_0000_1234),
                teb: p(ptr, 0x0000_00e0_0020_0000),
                sub_process_tag: i,
                base_priority: 8,
            }));
            out.push(KernelEvent::Image(ImageEvent {
                lifetime,
                base: p(ptr, 0x7ff6_0000_0000),
                size: 0x5_0000,
                process_id: 100 + i,
                checksum: 0x1_2345,
                time_date_stamp: 0x6543_2100,
                default_base: p(ptr, 0x1_4000_0000),
                file_name: Utf16(&s.image),
            }));
        }
    }
    out.push(KernelEvent::ThreadName(ThreadName {
        process_id: 100,
        thread_id: 200,
        name: Utf16(&s.name),
    }));
    out.push(KernelEvent::Sample(Sample {
        instruction_pointer: p(ptr, 0x7ff6_0000_1235),
        thread_id: 200,
        count: 1,
    }));
    out.push(KernelEvent::ContextSwitch(ContextSwitch {
        new_thread_id: 200,
        old_thread_id: 0,
        new_thread_priority: 9,
        old_thread_priority: 0,
        previous_c_state: 1,
        old_thread_wait_reason: 6,
        old_thread_wait_mode: 1,
        old_thread_state: 5,
        old_thread_wait_ideal_processor: 3,
        new_thread_wait_time: 1234,
    }));
    out.push(KernelEvent::ReadyThread(ReadyThread {
        thread_id: 201,
        adjust_reason: 1,
        adjust_increment: 2,
        flag: 4,
    }));
    out.push(KernelEvent::Stack(StackWalk {
        event_timestamp: 0x1234_5678,
        process_id: 100,
        thread_id: 200,
        frames: Frames::new(&s.frames, ptr),
    }));
    out.push(KernelEvent::ImageId(ImageId {
        base: p(ptr, 0x7ff6_0000_0000),
        size: 0x5_0000,
        process_id: 100,
        time_date_stamp: 0x6543_2100,
        original_file_name: Utf16(&s.original),
    }));
    for il in [false, true] {
        out.push(KernelEvent::DbgId(DbgId {
            base: p(ptr, 0x7ff6_0000_0000),
            process_id: 100,
            guid: Guid::new(0x1234_5678, 0x9abc, 0xdef0, [1, 2, 3, 4, 5, 6, 7, 8]),
            age: 3,
            pdb_file_name: if il {
                b"app.il.pdb"
            } else {
                br"c:\src\app.pdb"
            },
            il,
        }));
    }
    out
}

/// Writes `events` into a trace, reads it back, and returns each event's
/// decoding (as text, to compare) and whether its schema covers it all.
fn round_trip(events: &[KernelEvent<'_>], ptr: usize) -> Vec<(String, String)> {
    let mut w = Writer::new(WriterOptions {
        buffer_size: 0x10000,
        pointer_size: u32::try_from(ptr).unwrap(),
        processors: 1,
        ..WriterOptions::default()
    });
    let mut expected = Vec::new();
    for (i, e) in events.iter().enumerate() {
        let enc = encode(e, ptr).expect("the kernel logs this event");
        let at = Context {
            timestamp: 10 + i as i64,
            thread_id: 200,
            process_id: 100,
        };
        w.record(0, &record(&enc, at, ptr == 8));
        expected.push(format!("{e:?}"));
    }
    let data = w.finish();
    let etl = Etl::parse(&data).unwrap();
    let mut cursor = etl.events().unwrap();
    let mut got = Vec::new();
    while let Some(event) = cursor.next() {
        let event = event.unwrap();
        if event.hook == Some(0) {
            continue; // The logfile header.
        }
        let decoded = decode(&event)
            .expect("a kernel event we decode")
            .expect("well formed");
        // The TDH layout of the event's own version covers the payload
        // exactly.
        let props = Properties::of(&event)
            .unwrap_or_else(|| panic!("no schema for {decoded:?}"))
            .unwrap_or_else(|e| panic!("{decoded:?} doesn't fit its schema: {e}"));
        assert!(props.exact, "a schema for {decoded:?}'s own version");
        assert!(
            props.rest.is_empty(),
            "{} bytes past the schema of {decoded:?}",
            props.rest.len()
        );
        got.push(format!("{decoded:?}"));
    }
    expected.into_iter().zip(got).collect()
}

#[test]
fn every_event_round_trips_on_64_bit_traces() {
    let s = Strings::new(8);
    let events = events(&s, 8);
    let pairs = round_trip(&events, 8);
    assert_eq!(pairs.len(), events.len());
    for (expected, got) in pairs {
        assert_eq!(got, expected);
    }
}

#[test]
fn every_event_round_trips_on_32_bit_traces() {
    let s = Strings::new(4);
    let events = events(&s, 4);
    let pairs = round_trip(&events, 4);
    assert_eq!(pairs.len(), events.len());
    for (expected, got) in pairs {
        assert_eq!(got, expected);
    }
}

#[test]
fn defunct_threads_and_images_are_not_encoded() {
    let image = utf16("x.dll");
    let thread = KernelEvent::Thread(ThreadEvent {
        lifetime: Lifetime::Defunct,
        process_id: 1,
        thread_id: 2,
        stack_base: 0,
        stack_limit: 0,
        user_stack_base: 0,
        user_stack_limit: 0,
        win32_start_address: 0,
        teb: 0,
        sub_process_tag: 0,
        base_priority: 0,
    });
    let img = KernelEvent::Image(ImageEvent {
        lifetime: Lifetime::Defunct,
        base: 0,
        size: 0,
        process_id: 1,
        checksum: 0,
        time_date_stamp: 0,
        default_base: 0,
        file_name: Utf16(&image),
    });
    assert!(encode(&thread, 8).is_none());
    assert!(encode(&img, 8).is_none());
}

#[test]
fn image_loads_are_logged_in_the_process_group() {
    let image = utf16("x.dll");
    let e = KernelEvent::Image(ImageEvent {
        lifetime: Lifetime::Start,
        base: 0x1000,
        size: 0x1000,
        process_id: 1,
        checksum: 0,
        time_date_stamp: 0,
        default_base: 0,
        file_name: Utf16(&image),
    });
    let enc = encode(&e, 8).unwrap();
    let rec = record(&enc, Context::default(), true);
    // The system header's hook ID (after its marker and size): group
    // 0x03, opcode 10.
    assert_eq!(&rec[6..8], &0x030a_u16.to_le_bytes());
}

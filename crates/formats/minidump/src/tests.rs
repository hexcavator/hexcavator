//! Hermetic tests: minidumps built here, stream by stream.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::context::{self, Context};
use crate::{CodeView, Minidump, cpu, platform, stream};
use hexcavator_core::ErrorKind;

/// Writes a minidump: streams are appended, then the directory.
struct Writer {
    data: Vec<u8>,
    streams: Vec<(u32, u32, u32)>,
}

impl Writer {
    fn new() -> Self {
        Writer {
            data: vec![0; 32],
            streams: Vec::new(),
        }
    }
    /// Appends bytes (4-aligned); their RVA.
    fn put(&mut self, b: &[u8]) -> u32 {
        while !self.data.len().is_multiple_of(4) {
            self.data.push(0);
        }
        let rva = self.data.len() as u32;
        self.data.extend_from_slice(b);
        rva
    }
    fn string(&mut self, s: &str) -> u32 {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut b = ((units.len() * 2) as u32).to_le_bytes().to_vec();
        for u in units {
            b.extend(u.to_le_bytes());
        }
        b.extend([0, 0]);
        self.put(&b)
    }
    fn stream(&mut self, kind: u32, b: &[u8]) {
        let rva = self.put(b);
        self.streams.push((kind, b.len() as u32, rva));
    }
    fn finish(mut self) -> Vec<u8> {
        let dir = self.data.len() as u32;
        let streams = core::mem::take(&mut self.streams);
        for (kind, size, rva) in &streams {
            for w in [*kind, *size, *rva] {
                self.data.extend(w.to_le_bytes());
            }
        }
        let mut h = Vec::new();
        h.extend(crate::SIGNATURE.to_le_bytes());
        h.extend((u32::from(crate::VERSION) | 0x1234_0000).to_le_bytes());
        h.extend((streams.len() as u32).to_le_bytes());
        h.extend(dir.to_le_bytes());
        h.extend(0u32.to_le_bytes());
        h.extend(0x5F00_0000u32.to_le_bytes());
        h.extend(0x0000_0000_0000_1806u64.to_le_bytes());
        self.data[..32].copy_from_slice(&h);
        self.data
    }
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// An x64 context with RIP and RSP.
fn amd64_context(rip: u64, rsp: u64) -> Vec<u8> {
    let mut c = vec![0u8; 0x4D0];
    c[0x30..0x34].copy_from_slice(&(context::CONTEXT_AMD64 | 0x1F).to_le_bytes());
    c[0x98..0xA0].copy_from_slice(&le64(rsp));
    c[0xF8..0x100].copy_from_slice(&le64(rip));
    c[0x1A0..0x1B0].copy_from_slice(&0x1111_2222_3333_4444_5555_6666_7777_8888u128.to_le_bytes());
    c
}

fn sample() -> Vec<u8> {
    let mut w = Writer::new();
    // Thread 7: a stack of 16 bytes at 0x1000, and a context.
    let stack = w.put(&[0xAB; 16]);
    let ctx = amd64_context(0x7FF6_0000_1234, 0x1000);
    let ctx_rva = w.put(&ctx);
    let mut threads = words(&[1, 7, 2, 0x20, 8]);
    threads.extend(le64(0x7FF0_0000));
    threads.extend(le64(0x1000));
    threads.extend(words(&[16, stack, ctx.len() as u32, ctx_rva]));
    w.stream(stream::THREAD_LIST, &threads);

    // A module with version information and a PDB 7.0 record.
    let name = w.string(r"C:\app\app.exe");
    let mut cv = b"RSDS".to_vec();
    cv.extend([0x11; 16]);
    cv.extend(3u32.to_le_bytes());
    cv.extend(b"app.pdb\0");
    let cv_rva = w.put(&cv);
    let mut m = 1u32.to_le_bytes().to_vec();
    m.extend(le64(0x7FF6_0000_0000));
    m.extend(words(&[0x5000, 0xC0FFEE, 0x6000_0000, name]));
    // VS_FIXEDFILEINFO: signature, struct version, file 10.0.26100.1,
    // product 10.0.0.0, flags mask, flags, OS, type, subtype, date.
    m.extend(words(&[
        0xFEEF_04BD,
        0x10000,
        0x000A_0000,
        0x65F4_0001,
        0x000A_0000,
        0,
        0x3F,
        0x2,
        0x40004,
        1,
        0,
        0,
        0,
    ]));
    m.extend(words(&[cv.len() as u32, cv_rva, 0, 0]));
    m.extend([0; 16]);
    w.stream(stream::MODULE_LIST, &m);

    // Memory: 8 bytes at 0x2000 (memory list), 4 + 4 at 0x2008 (64).
    let mem = w.put(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut ml = 1u32.to_le_bytes().to_vec();
    ml.extend(le64(0x2000));
    ml.extend(words(&[8, mem]));
    w.stream(stream::MEMORY_LIST, &ml);
    let base = w.put(&[9, 10, 11, 12, 13, 14, 15, 16]);
    let mut m64 = le64(2).to_vec();
    m64.extend(le64(u64::from(base)));
    for (start, size) in [(0x2008u64, 4u64), (0x200C, 4)] {
        m64.extend(le64(start));
        m64.extend(le64(size));
    }
    w.stream(stream::MEMORY64_LIST, &m64);

    // An access violation on thread 7.
    let mut e = words(&[7, 0, 0xC000_0005, 0]);
    e.extend(le64(0));
    e.extend(le64(0x7FF6_0000_1234));
    e.extend(words(&[2, 0]));
    e.extend(le64(1));
    e.extend(le64(0xDEAD));
    e.extend([0; 13 * 8]);
    e.extend(words(&[ctx.len() as u32, ctx_rva]));
    w.stream(stream::EXCEPTION, &e);

    // x64 Windows 11, 8 processors.
    let csd = w.string("");
    let mut si = vec![9, 0, 6, 0, 0x55, 0x01, 8, 1];
    si.extend(words(&[10, 0, 26100, platform::WIN32_NT, csd]));
    si.extend([0x00, 0x01, 0, 0]);
    si.extend([0x47; 24]);
    w.stream(stream::SYSTEM_INFO, &si);

    // Misc info: process ID and times.
    w.stream(
        stream::MISC_INFO,
        &words(&[24, 3, 4242, 1_700_000_000, 5, 6]),
    );

    // Thread names; an unloaded module; thread info; memory info.
    let tname = w.string("worker");
    let mut tn = words(&[1, 7]);
    tn.extend(le64(u64::from(tname)));
    w.stream(stream::THREAD_NAMES, &tn);
    let uname = w.string("gone.dll");
    let mut um = words(&[12, 24, 1]);
    um.extend(le64(0x1800_0000));
    um.extend(words(&[0x1000, 1, 2, uname]));
    w.stream(stream::UNLOADED_MODULE_LIST, &um);
    let mut ti = words(&[12, 64, 1, 7, 0, 0, 0]);
    for v in [10u64, 0, 3, 4, 0x7FF6_0000_1000, 0xFF] {
        ti.extend(le64(v));
    }
    w.stream(stream::THREAD_INFO_LIST, &ti);
    let mut mi = words(&[16, 48]);
    mi.extend(le64(1));
    mi.extend(le64(0x1000));
    mi.extend(le64(0x1000));
    mi.extend(words(&[4, 0]));
    mi.extend(le64(0x1000));
    mi.extend(words(&[0x1000, 4, 0x2_0000, 0]));
    w.stream(stream::MEMORY_INFO_LIST, &mi);

    // Comments.
    w.stream(stream::COMMENT_A, b"hello\0");
    w.stream(stream::COMMENT_W, &words(&[0x0069_0068, 0]));
    w.finish()
}

#[test]
fn header_and_directory() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    assert_eq!(d.version(), 0x1234_A793);
    assert_eq!(d.time_date_stamp(), 0x5F00_0000);
    assert_eq!(d.flags(), 0x1806);
    let kinds: Vec<u32> = d.streams().map(|s| s.kind).collect();
    assert_eq!(kinds.len(), 13);
    assert_eq!(kinds[0], stream::THREAD_LIST);
    assert!(d.stream(stream::HANDLE_DATA).is_none());
}

#[test]
fn threads_and_contexts() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    let t = d.threads().unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(
        (
            t[0].id,
            t[0].suspend_count,
            t[0].priority_class,
            t[0].priority
        ),
        (7, 2, 0x20, 8)
    );
    assert_eq!(t[0].teb, 0x7FF0_0000);
    assert_eq!(
        (t[0].stack.start, t[0].stack.data),
        (0x1000, &[0xAB; 16][..])
    );
    let arch = d.system_info().unwrap().map(|s| s.processor_architecture);
    let Context::Amd64(c) = Context::parse(t[0].context, arch) else {
        panic!("not x64")
    };
    assert_eq!((c.rip, c.rsp), (0x7FF6_0000_1234, 0x1000));
    assert_eq!(c.xmm[0], 0x1111_2222_3333_4444_5555_6666_7777_8888);
    // (Without system information, by its flags and size.)
    assert!(matches!(
        Context::parse(t[0].context, None),
        Context::Amd64(_)
    ));
    assert_eq!(
        Context::parse(t[0].context, None).pc(),
        Some(0x7FF6_0000_1234)
    );
}

#[test]
fn modules() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    let m = d.modules().unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(
        (m[0].base, m[0].size, m[0].checksum),
        (0x7FF6_0000_0000, 0x5000, 0xC0FFEE)
    );
    assert_eq!(m[0].name, r"C:\app\app.exe");
    assert_eq!(m[0].version.signature, 0xFEEF_04BD);
    assert_eq!(m[0].version.file_version, [10, 0, 26100, 1]);
    assert_eq!(m[0].version.file_type, 1);
    assert_eq!(
        m[0].code_view(),
        Some(CodeView::Pdb70 {
            guid: [0x11; 16],
            age: 3,
            name: b"app.pdb"
        })
    );
    let u = d.unloaded_modules().unwrap();
    assert_eq!(
        (u[0].base, u[0].size, u[0].name.as_str()),
        (0x1800_0000, 0x1000, "gone.dll")
    );
}

#[test]
fn memory_across_ranges() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    let mem = d.memory().unwrap();
    assert_eq!(mem.ranges().len(), 3);
    let mut b = [0u8; 12];
    assert!(mem.read(0x2002, &mut b));
    assert_eq!(b, [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    assert!(!mem.read(0x200E, &mut b));
    assert!(!mem.read(0x1FFF, &mut [0u8; 2]));
    assert_eq!(mem.at(0x200C), Some(&[13, 14, 15, 16][..]));
    assert!(mem.at(0x2010).is_none());
}

#[test]
fn exception_system_misc() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    let e = d.exception().unwrap().unwrap();
    assert_eq!(
        (e.thread_id, e.code, e.address),
        (7, 0xC000_0005, 0x7FF6_0000_1234)
    );
    assert_eq!(e.parameters, [1, 0xDEAD]);
    assert_eq!(e.context.len(), 0x4D0);
    let s = d.system_info().unwrap().unwrap();
    assert_eq!(s.processor_architecture, cpu::AMD64);
    assert_eq!(
        (
            s.processor_level,
            s.processor_revision,
            s.number_of_processors
        ),
        (6, 0x0155, 8)
    );
    assert_eq!(
        (s.major_version, s.build_number, s.platform_id),
        (10, 26100, platform::WIN32_NT)
    );
    assert_eq!(s.csd_version.as_deref(), Some(""));
    assert_eq!(s.cpu, [0x47; 24]);
    let m = d.misc_info().unwrap();
    assert_eq!(
        (m.process_id, m.process_create_time, m.process_user_time),
        (Some(4242), Some(1_700_000_000), Some(5))
    );
}

#[test]
fn info_lists_names_comments() {
    let data = sample();
    let d = Minidump::parse(&data).unwrap();
    assert_eq!(d.thread_names().unwrap(), [(7, String::from("worker"))]);
    let ti = d.thread_info().unwrap();
    assert_eq!(
        (ti[0].thread_id, ti[0].create_time, ti[0].start_address),
        (7, 10, 0x7FF6_0000_1000)
    );
    let mi = d.memory_info().unwrap();
    assert_eq!(
        (mi[0].base, mi[0].region_size, mi[0].state, mi[0].kind),
        (0x1000, 0x1000, 0x1000, 0x2_0000)
    );
    let (a, w) = d.comments();
    assert_eq!((a, w.as_deref()), (Some(&b"hello"[..]), Some("hi")));
}

#[test]
fn breakpad_and_crashpad_streams() {
    let mut w = Writer::new();
    w.stream(stream::BREAKPAD_INFO, &words(&[3, 11, 12]));
    let key = w.put(&[3, 0, 0, 0, b'k', b'e', b'y']);
    let value = w.put(&[1, 0, 0, 0, b'v']);
    let dict = w.put(&words(&[1, key, value]));
    let mut cp = words(&[1]);
    cp.extend([0xAA; 16]);
    cp.extend([0xBB; 16]);
    cp.extend(words(&[12, dict, 0, 0]));
    w.stream(stream::CRASHPAD_INFO, &cp);
    w.stream(stream::LINUX_CPU_INFO, b"processor : 0\n");
    // An ELF module: build ID record.
    let name = w.string("/usr/lib/libc.so.6");
    let cv = w.put(b"LEpB\x01\x02\x03\x04");
    let mut m = 1u32.to_le_bytes().to_vec();
    m.extend(le64(0x7F00_0000_0000));
    m.extend(words(&[0x1000, 0, 0, name]));
    m.extend([0; 52]);
    m.extend(words(&[8, cv, 0, 0]));
    m.extend([0; 16]);
    w.stream(stream::MODULE_LIST, &m);
    let data = w.finish();
    let d = Minidump::parse(&data).unwrap();
    assert_eq!(d.breakpad_info(), Some((Some(11), Some(12))));
    let c = d.crashpad_info().unwrap();
    assert_eq!(
        (c.version, c.report_id, c.client_id),
        (1, [0xAA; 16], [0xBB; 16])
    );
    assert_eq!(c.simple_annotations, [(&b"key"[..], &b"v"[..])]);
    assert_eq!(
        d.stream(stream::LINUX_CPU_INFO).unwrap().data,
        b"processor : 0\n"
    );
    assert_eq!(
        d.modules().unwrap()[0].code_view(),
        Some(CodeView::Elf {
            build_id: &[1, 2, 3, 4]
        })
    );
}

#[test]
fn contexts_of_each_architecture() {
    // x86: EIP, ESP.
    let mut x86 = vec![0u8; 0x2CC];
    x86[..4].copy_from_slice(&(context::CONTEXT_X86 | 7).to_le_bytes());
    x86[0xB8..0xBC].copy_from_slice(&0x0040_1000u32.to_le_bytes());
    x86[0xC4..0xC8].copy_from_slice(&0x0012_FF00u32.to_le_bytes());
    let c = Context::parse(&x86, Some(cpu::X86));
    assert_eq!((c.pc(), c.sp()), (Some(0x0040_1000), Some(0x0012_FF00)));
    assert!(matches!(Context::parse(&x86, None), Context::X86(_)));
    // Windows ARM: PC, SP, D8.
    let mut arm = vec![0u8; 0x1A0];
    arm[..4].copy_from_slice(&(context::CONTEXT_ARM | 7).to_le_bytes());
    arm[0x38..0x3C].copy_from_slice(&0x1000u32.to_le_bytes());
    arm[0x40..0x44].copy_from_slice(&0x2000u32.to_le_bytes());
    arm[0x50 + 64..0x50 + 72].copy_from_slice(&le64(0x88));
    let Context::Arm(a) = Context::parse(&arm, Some(cpu::ARM)) else {
        panic!()
    };
    assert_eq!((a.r[13], a.r[15], a.d[8]), (0x1000, 0x2000, 0x88));
    // Breakpad ARM: iregs, cpsr, fpscr, d registers.
    let mut bp = vec![0u8; 368];
    bp[..4].copy_from_slice(&(context::BREAKPAD_ARM | 6).to_le_bytes());
    bp[4 + 4 * 15..4 + 4 * 16].copy_from_slice(&0x3000u32.to_le_bytes());
    bp[68..72].copy_from_slice(&0x10u32.to_le_bytes());
    bp[80 + 8..80 + 16].copy_from_slice(&le64(0x11));
    let Context::Arm(b) = Context::parse(&bp, Some(cpu::ARM)) else {
        panic!()
    };
    assert_eq!((b.r[15], b.cpsr, b.d[1]), (0x3000, 0x10, 0x11));
    assert!(matches!(Context::parse(&bp, None), Context::Arm(_)));
    // ARM64: X0, SP, PC, V31.
    let mut a64 = vec![0u8; 0x390];
    a64[..4].copy_from_slice(&(context::CONTEXT_ARM64 | 7).to_le_bytes());
    a64[8..16].copy_from_slice(&le64(0xA0));
    a64[0x100..0x108].copy_from_slice(&le64(0x5000));
    a64[0x108..0x110].copy_from_slice(&le64(0x6000));
    a64[0x110 + 16 * 31..0x110 + 16 * 32].copy_from_slice(&[0xCD; 16]);
    let Context::Arm64(c) = Context::parse(&a64, Some(cpu::ARM64)) else {
        panic!()
    };
    assert_eq!((c.x[0], c.sp, c.pc), (0xA0, 0x5000, 0x6000));
    assert_eq!(c.v[31], u128::from_le_bytes([0xCD; 16]));
    // Breakpad's old ARM64, and too short: unknown.
    let mut old = vec![0u8; 0x400];
    old[..4].copy_from_slice(&0x8000_0007u32.to_le_bytes());
    assert_eq!(
        Context::parse(&old, Some(cpu::ARM64_OLD)),
        Context::Unknown { flags: 0x8000_0007 }
    );
    assert_eq!(
        Context::parse(&x86[..0x40], Some(cpu::X86)),
        Context::Unknown { flags: 0x0001_0007 }
    );
}

#[test]
fn malformed() {
    assert_eq!(
        Minidump::parse(b"MDMP").unwrap_err().kind,
        ErrorKind::Truncated
    );
    let mut data = sample();
    data[0] = b'X';
    assert_eq!(
        Minidump::parse(&data).unwrap_err().kind,
        ErrorKind::BadMagic
    );
    let mut data = sample();
    data[4] = 0;
    assert_eq!(
        Minidump::parse(&data).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    // A directory past the end; a stream count too large.
    let mut data = sample();
    data[12..16].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(
        Minidump::parse(&data).unwrap_err().kind,
        ErrorKind::Truncated
    );
    let mut data = sample();
    data[8..12].copy_from_slice(&0x10_0000u32.to_le_bytes());
    assert_eq!(
        Minidump::parse(&data).unwrap_err().kind,
        ErrorKind::Malformed
    );

    // Counts beyond the stream: only what's there.
    let mut w = Writer::new();
    w.stream(stream::THREAD_LIST, &words(&[0xFFFF_FFFF]));
    w.stream(stream::MODULE_LIST, &words(&[1000]));
    let mut m64 = le64(u64::MAX).to_vec();
    m64.extend(le64(0xFFFF_FFFF_0000));
    m64.extend(le64(0));
    m64.extend(le64(0x10));
    w.stream(stream::MEMORY64_LIST, &m64);
    w.stream(stream::EXCEPTION, &[0; 8]);
    w.stream(stream::MEMORY_INFO_LIST, &words(&[2, 1, 0, 0]));
    let data = w.finish();
    let d = Minidump::parse(&data).unwrap();
    assert!(d.threads().unwrap().is_empty());
    assert!(d.modules().unwrap().is_empty());
    assert!(d.memory().unwrap().ranges().is_empty());
    assert_eq!(d.exception().unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(d.memory_info().unwrap_err().kind, ErrorKind::Malformed);
}

#[test]
fn hostile_dumps_never_panic() {
    let base = sample();
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..3000 {
        let mut data = base.clone();
        for _ in 0..1 + next() % 8 {
            let i = (next() % data.len() as u64) as usize;
            data[i] = next() as u8;
        }
        if next() % 4 == 0 {
            data.truncate((next() % data.len() as u64) as usize);
        }
        let Ok(d) = Minidump::parse(&data) else {
            continue;
        };
        let arch = d
            .system_info()
            .ok()
            .flatten()
            .map(|s| s.processor_architecture);
        for t in d.threads().unwrap_or_default() {
            let _ = Context::parse(t.context, arch);
        }
        for m in d.modules().unwrap_or_default() {
            let _ = m.code_view();
        }
        if let Ok(mem) = d.memory() {
            let _ = mem.read(0x2000, &mut [0u8; 16]);
        }
        let _ = (
            d.exception(),
            d.misc_info(),
            d.memory_info(),
            d.thread_info(),
        );
        let _ = (
            d.thread_names(),
            d.unloaded_modules(),
            d.handles(),
            d.comments(),
        );
        let _ = (d.breakpad_info(), d.crashpad_info());
    }
}

/// A full-memory dump's thread stacks: descriptors with RVA 0, the bytes
/// in the 64-bit memory list (across adjacent ranges, not across gaps).
#[test]
fn full_memory_stacks() {
    let mut w = Writer::new();
    let ctx = amd64_context(0x1234, 0x3008);
    let ctx_rva = w.put(&ctx);
    let mut threads = words(&[4]);
    // (Stacks: 8 bytes at 0x3004, across two ranges; 4 at 0x3000; 8 at
    // 0x300C, across a gap; 8 at 0x4004, past the end.)
    for (id, start, size) in [
        (1u32, 0x3004u64, 8u32),
        (2, 0x3000, 4),
        (3, 0x300C, 8),
        (4, 0x4004, 8),
    ] {
        threads.extend(words(&[id, 0, 0, 0]));
        threads.extend(le64(0));
        threads.extend(le64(start));
        threads.extend(words(&[size, 0, ctx.len() as u32, ctx_rva]));
    }
    w.stream(stream::THREAD_LIST, &threads);
    let base = w.put(&(1..=24).collect::<Vec<u8>>());
    let mut m64 = le64(3).to_vec();
    m64.extend(le64(u64::from(base)));
    for (start, size) in [(0x3000u64, 8u64), (0x3008, 8), (0x4000, 8)] {
        m64.extend(le64(start));
        m64.extend(le64(size));
    }
    w.stream(stream::MEMORY64_LIST, &m64);
    let data = w.finish();
    let d = Minidump::parse(&data).unwrap();
    let t = d.threads().unwrap();
    assert_eq!(t[0].stack.data, &[5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(t[1].stack.data, &[1, 2, 3, 4]);
    assert!(t[2].stack.data.is_empty());
    assert!(t[3].stack.data.is_empty());
    assert_eq!(t[3].stack.start, 0x4004);
}

/// Many full-memory stacks against many ranges: indexed once (not a scan
/// of the memory list per thread, which is quadratic).
#[test]
fn many_stacks_many_ranges() {
    const N: u32 = 20_000;
    let mut w = Writer::new();
    let base = w.put(&vec![0x5A; N as usize * 16]);
    let mut threads = words(&[N]);
    for i in 0..N {
        threads.extend(words(&[i, 0, 0, 0]));
        threads.extend(le64(0));
        // (Each stack is the second half of its own range.)
        threads.extend(le64(0x10_0000 + u64::from(i) * 0x100 + 8));
        threads.extend(words(&[8, 0, 0, 0]));
    }
    w.stream(stream::THREAD_LIST, &threads);
    let mut m64 = le64(u64::from(N)).to_vec();
    m64.extend(le64(u64::from(base)));
    // (In reverse order: the index sorts them.)
    for i in (0..N).rev() {
        m64.extend(le64(0x10_0000 + u64::from(i) * 0x100));
        m64.extend(le64(16));
    }
    w.stream(stream::MEMORY64_LIST, &m64);
    let data = w.finish();
    let d = Minidump::parse(&data).unwrap();
    let t = d.threads().unwrap();
    assert_eq!(t.len(), N as usize);
    assert!(t.iter().all(|t| t.stack.data == [0x5A; 8]));
}

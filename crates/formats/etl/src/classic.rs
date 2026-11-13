//! The kernel's event groups: which event class (provider GUID) a classic
//! kernel record's hook group names.

use crate::guid::Guid;

/// The event class GUID for a kernel hook group, as `ProcessTrace` reports
/// it, or `None` for a group we don't know.
pub fn group_guid(group: u16) -> Option<Guid> {
    GROUPS
        .iter()
        .find(|(g, _)| *g == group)
        .map(|(_, guid)| *guid)
}

/// The event class GUID for a kernel hook ID (group and opcode), as
/// `ProcessTrace` reports it. Image loads are logged in the process group
/// (opcode 10) but belong to the image class.
pub fn hook_guid(hook: u16) -> Option<Guid> {
    const PROCESS_LOAD_IMAGE: u16 = 0x030a;
    const IMAGE: u16 = 0x14;
    if hook == PROCESS_LOAD_IMAGE {
        return group_guid(IMAGE);
    }
    group_guid(hook >> 8)
}

/// The kernel hook group for an event class GUID.
pub fn guid_group(guid: &Guid) -> Option<u16> {
    GROUPS
        .iter()
        .find(|(_, g)| g == guid)
        .map(|(group, _)| *group)
}

const fn g(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid::new(data1, data2, data3, data4)
}

/// Hook groups and their event classes.
///
/// The first block was checked against `ProcessTrace` on real traces. The
/// second comes from public sources and hasn't been seen in a trace yet.
const GROUPS: &[(u16, Guid)] = &[
    // EventTrace (the header and session events).
    (
        0x00,
        g(
            0x68fdd900,
            0x4a3e,
            0x11d1,
            [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        ),
    ),
    // DiskIo.
    (
        0x01,
        g(
            0x3d6fa8d4,
            0xfe05,
            0x11d0,
            [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        ),
    ),
    // PageFault (memory).
    (
        0x02,
        g(
            0x3d6fa8d3,
            0xfe05,
            0x11d0,
            [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        ),
    ),
    // Process.
    (
        0x03,
        g(
            0x3d6fa8d0,
            0xfe05,
            0x11d0,
            [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        ),
    ),
    // FileIo.
    (
        0x04,
        g(
            0x90cbdc39,
            0x4a3e,
            0x11d1,
            [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        ),
    ),
    // Thread.
    (
        0x05,
        g(
            0x3d6fa8d1,
            0xfe05,
            0x11d0,
            [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        ),
    ),
    // SystemConfig.
    (
        0x0b,
        g(
            0x01853a65,
            0x418f,
            0x4f36,
            [0xae, 0xfc, 0xdc, 0x0f, 0x1d, 0x2f, 0xd2, 0x35],
        ),
    ),
    // PerfInfo (samples, interrupts, DPCs, system calls).
    (
        0x0f,
        g(
            0xce1dbfb4,
            0x137e,
            0x4da6,
            [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
        ),
    ),
    // Power.
    (
        0x12,
        g(
            0xe43445e0,
            0x0903,
            0x48c3,
            [0xb8, 0x78, 0xff, 0x0f, 0xcc, 0xeb, 0xdd, 0x04],
        ),
    ),
    // Image.
    (
        0x14,
        g(
            0x2cb15d1d,
            0x5fc1,
            0x11d2,
            [0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18],
        ),
    ),
    // StackWalk.
    (
        0x18,
        g(
            0xdef2fe46,
            0x7bd6,
            0x4b80,
            [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
        ),
    ),
    // Not yet seen in a trace.
    // TcpIp.
    (
        0x06,
        g(
            0x9a280ac0,
            0xc8e0,
            0x11d1,
            [0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2],
        ),
    ),
    // UdpIp.
    (
        0x08,
        g(
            0xbf3a50c5,
            0xa9c9,
            0x4988,
            [0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80],
        ),
    ),
    // Registry.
    (
        0x09,
        g(
            0xae53722e,
            0xc863,
            0x11d2,
            [0x86, 0x59, 0x00, 0xc0, 0x4f, 0xa3, 0x21, 0xa1],
        ),
    ),
    // Pool.
    (
        0x0e,
        g(
            0x0268a8b6,
            0x74fd,
            0x4302,
            [0x9d, 0xd0, 0x6e, 0x8f, 0x17, 0x95, 0xc0, 0xcf],
        ),
    ),
    // Heap.
    (
        0x10,
        g(
            0x222962ab,
            0x6180,
            0x4b88,
            [0xa8, 0x25, 0x34, 0x6b, 0x75, 0xf2, 0xa2, 0x4a],
        ),
    ),
    // Object.
    (
        0x11,
        g(
            0x89497f50,
            0xeffe,
            0x4440,
            [0x8c, 0xf2, 0xce, 0x6b, 0x1c, 0xdc, 0xac, 0xa7],
        ),
    ),
    // ALPC.
    (
        0x1a,
        g(
            0x45d8cccd,
            0x539f,
            0x4b72,
            [0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a],
        ),
    ),
    // SplitIo.
    (
        0x1b,
        g(
            0xd837ca92,
            0x12b9,
            0x44a5,
            [0xad, 0x6a, 0x3a, 0x65, 0xb3, 0x57, 0x8a, 0xa8],
        ),
    ),
    // ThreadPool.
    (
        0x1c,
        g(
            0xc861d0e2,
            0xa2c1,
            0x4d36,
            [0x9f, 0x9c, 0x97, 0x0b, 0xab, 0x94, 0x3a, 0x12],
        ),
    ),
];

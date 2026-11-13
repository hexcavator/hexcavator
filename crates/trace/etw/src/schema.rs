//! Layouts of the kernel's classic (MOF) events and of the trace-control
//! events that `xperf` and WPR add when they merge a trace.
//!
//! A [`Schema`] lists an event version's fields in order, as TDH describes
//! them; [`Properties`] walks an event's payload against it and finds each
//! property's bytes. This is the slow, general path, for showing any event
//! and for testing against TDH. The typed decoders in [`crate::kernel`] read
//! the high-volume events at fixed offsets.

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_etl::{Event, Guid, event::flags};

use crate::guids;

/// How a field is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// An unsigned byte.
    U8,
    /// A signed byte.
    I8,
    /// A 16-bit integer.
    U16,
    /// A 32-bit integer.
    U32,
    /// A signed 32-bit integer.
    I32,
    /// A 64-bit integer.
    U64,
    /// A pointer: 4 or 8 bytes, as the event's header says.
    Ptr,
    /// A GUID.
    Guid,
    /// A NUL-terminated UTF-16 string.
    Utf16z,
    /// A NUL-terminated 8-bit string.
    Ansiz,
    /// A `TOKEN_USER` and the SID after it, or a zero `u32` for none.
    Sid,
    /// A fixed number of bytes (fixed-size character arrays, padding).
    Bytes(usize),
    /// Pointers to the end of the payload, named `<name>1`, `<name>2`, ...
    Pointers,
    /// A manifest property, by its TDH input and output types (decoded by
    /// [`crate::manifest`], not by a schema).
    Typed {
        /// `TDH_INTYPE_*` (0 for a struct).
        in_type: u8,
        /// `TDH_OUTTYPE_*`.
        out_type: u8,
    },
}

/// One event version's layout.
#[derive(Clone, Copy, Debug)]
pub struct Schema {
    /// The provider (event class).
    pub provider: Guid,
    /// The opcode.
    pub opcode: u8,
    /// The version.
    pub version: u8,
    /// The task's name.
    pub task: &'static str,
    /// The opcode's name.
    pub name: &'static str,
    /// The fields, in order.
    pub fields: &'static [(&'static str, Field)],
}

/// The layout of an event: the schema for its version, or else for the
/// newest older version (whose fields a newer version extends), with
/// whether it was exact.
pub fn lookup(provider: &Guid, opcode: u8, version: u8) -> Option<(&'static Schema, bool)> {
    let mut best: Option<&'static Schema> = None;
    for s in SCHEMAS {
        if s.provider == *provider && s.opcode == opcode && s.version <= version {
            if s.version == version {
                return Some((s, true));
            }
            if best.is_none_or(|b| s.version > b.version) {
                best = Some(s);
            }
        }
    }
    best.map(|s| (s, false))
}

/// One property of an event: its name and bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Property<'a> {
    /// The field's name (`Stack3` for the third of [`Field::Pointers`]).
    pub name: String,
    /// How it's stored.
    pub field: Field,
    /// Its bytes.
    pub data: &'a [u8],
}

/// An event's properties, by its schema.
#[derive(Clone, Debug)]
pub struct Properties<'a> {
    /// The schema used.
    pub schema: &'static Schema,
    /// Whether the schema is for the event's own version (rather than an
    /// older one).
    pub exact: bool,
    /// The properties, in order.
    pub properties: Vec<Property<'a>>,
    /// Payload bytes after the last field (a newer version's additions).
    pub rest: &'a [u8],
}

impl<'a> Properties<'a> {
    /// Decodes `event`'s payload, if we have a schema for it.
    pub fn of(event: &Event<'a>) -> Option<Result<Self>> {
        let (schema, exact) = lookup(
            &event.provider,
            event.descriptor.opcode,
            event.descriptor.version,
        )?;
        let ptr = pointer_size(event);
        Some(Self::decode(
            schema,
            exact,
            event.user_data,
            ptr,
            event.file_offset,
        ))
    }

    /// Decodes `data` by `schema`, with pointers of `ptr` bytes.
    pub fn decode(
        schema: &'static Schema,
        exact: bool,
        data: &'a [u8],
        ptr: usize,
        offset: u64,
    ) -> Result<Self> {
        let mut properties = Vec::with_capacity(schema.fields.len());
        let mut pos = 0usize;
        let err = |what| Error::new(ErrorKind::Truncated, offset, what);
        for &(name, field) in schema.fields {
            if field == Field::Pointers {
                let mut n = 1;
                while data.len() - pos >= ptr {
                    properties.push(Property {
                        name: format!("{name}{n}"),
                        field: Field::Ptr,
                        data: &data[pos..pos + ptr],
                    });
                    pos += ptr;
                    n += 1;
                }
                continue;
            }
            let len = field_len(field, &data[pos..], ptr).ok_or(err(name))?;
            properties.push(Property {
                name: name.to_string(),
                field,
                data: &data[pos..pos + len],
            });
            pos += len;
        }
        Ok(Self {
            schema,
            exact,
            properties,
            rest: &data[pos..],
        })
    }

    /// The property named `name`.
    pub fn get(&self, name: &str) -> Option<&Property<'a>> {
        self.properties.iter().find(|p| p.name == name)
    }
}

/// The pointer size of an event's payload.
pub fn pointer_size(event: &Event<'_>) -> usize {
    if event.flags & flags::BIT32_HEADER != 0 {
        4
    } else {
        8
    }
}

/// The length of `field` at the start of `data`, or `None` if it doesn't
/// fit.
fn field_len(field: Field, data: &[u8], ptr: usize) -> Option<usize> {
    let fixed = |n: usize| (data.len() >= n).then_some(n);
    match field {
        Field::U8 | Field::I8 => fixed(1),
        Field::U16 => fixed(2),
        Field::U32 | Field::I32 => fixed(4),
        Field::U64 => fixed(8),
        Field::Ptr => fixed(ptr),
        Field::Guid => fixed(16),
        Field::Bytes(n) => fixed(n),
        Field::Utf16z => {
            let mut i = 0;
            while i + 2 <= data.len() {
                i += 2;
                if data[i - 2] == 0 && data[i - 1] == 0 {
                    return Some(i);
                }
            }
            // An unterminated string runs to the end, as TDH reads it.
            Some(data.len() & !1)
        }
        Field::Ansiz => Some(
            data.iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |i| i + 1),
        ),
        Field::Sid => {
            // A null SID is a single zero u32.
            let first = data.get(..4)?;
            if first == [0, 0, 0, 0] {
                return Some(4);
            }
            // TOKEN_USER: a pointer and the attributes, padded to pointers.
            let token = 2 * ptr;
            let sub_authorities = usize::from(*data.get(token + 1)?);
            fixed(token + 8 + 4 * sub_authorities)
        }
        Field::Pointers => Some(data.len() - data.len() % ptr),
        Field::Typed { .. } => None,
    }
}

use Field::*;

const fn s(
    provider: Guid,
    opcode: u8,
    version: u8,
    task: &'static str,
    name: &'static str,
    fields: &'static [(&'static str, Field)],
) -> Schema {
    Schema {
        provider,
        opcode,
        version,
        task,
        name,
        fields,
    }
}

const PROCESS_V4: &[(&str, Field)] = &[
    ("UniqueProcessKey", Ptr),
    ("ProcessId", U32),
    ("ParentId", U32),
    ("SessionId", U32),
    ("ExitStatus", I32),
    ("DirectoryTableBase", Ptr),
    ("Flags", U32),
    ("UserSID", Sid),
    ("ImageFileName", Ansiz),
    ("CommandLine", Utf16z),
    ("PackageFullName", Utf16z),
    ("ApplicationId", Utf16z),
];

const PROCESS_DEFUNCT_V5: &[(&str, Field)] = &[
    ("UniqueProcessKey", Ptr),
    ("ProcessId", U32),
    ("ParentId", U32),
    ("SessionId", U32),
    ("ExitStatus", I32),
    ("DirectoryTableBase", Ptr),
    ("Flags", U32),
    ("UserSID", Sid),
    ("ImageFileName", Ansiz),
    ("CommandLine", Utf16z),
    ("PackageFullName", Utf16z),
    ("ApplicationId", Utf16z),
    ("ExitTime", U64),
];

const PROCESS_PERFCTR: &[(&str, Field)] = &[
    ("ProcessId", U32),
    ("PageFaultCount", U32),
    ("HandleCount", U32),
    ("Reserved", U32),
    ("PeakVirtualSize", Ptr),
    ("PeakWorkingSetSize", Ptr),
    ("PeakPagefileUsage", Ptr),
    ("QuotaPeakPagedPoolUsage", Ptr),
    ("QuotaPeakNonPagedPoolUsage", Ptr),
    ("VirtualSize", Ptr),
    ("WorkingSetSize", Ptr),
    ("PagefileUsage", Ptr),
    ("QuotaPagedPoolUsage", Ptr),
    ("QuotaNonPagedPoolUsage", Ptr),
    ("PrivatePageCount", Ptr),
];

const THREAD_V3: &[(&str, Field)] = &[
    ("ProcessId", U32),
    ("TThreadId", U32),
    ("StackBase", Ptr),
    ("StackLimit", Ptr),
    ("UserStackBase", Ptr),
    ("UserStackLimit", Ptr),
    ("Affinity", Ptr),
    ("Win32StartAddr", Ptr),
    ("TebBase", Ptr),
    ("SubProcessTag", U32),
    ("BasePriority", U8),
    ("PagePriority", U8),
    ("IoPriority", U8),
    ("ThreadFlags", U8),
];

const THREAD_V4: &[(&str, Field)] = &[
    ("ProcessId", U32),
    ("TThreadId", U32),
    ("StackBase", Ptr),
    ("StackLimit", Ptr),
    ("UserStackBase", Ptr),
    ("UserStackLimit", Ptr),
    ("Affinity", Ptr),
    ("Win32StartAddr", Ptr),
    ("TebBase", Ptr),
    ("SubProcessTag", U32),
    ("BasePriority", U8),
    ("PagePriority", U8),
    ("IoPriority", U8),
    ("ThreadFlags", U8),
    ("ThreadName", Utf16z),
];

const THREAD_PRIORITY: &[(&str, Field)] = &[
    ("ThreadId", U32),
    ("OldPriority", U8),
    ("NewPriority", U8),
    ("Reserved", U16),
];

/// `CSwitch`, as documented. Versions after 2 append fields we don't
/// name; they are left in `rest`.
const CSWITCH_V2: &[(&str, Field)] = &[
    ("NewThreadId", U32),
    ("OldThreadId", U32),
    ("NewThreadPriority", I8),
    ("OldThreadPriority", I8),
    ("PreviousCState", U8),
    ("SpareByte", I8),
    ("OldThreadWaitReason", I8),
    ("OldThreadWaitMode", I8),
    ("OldThreadState", I8),
    ("OldThreadWaitIdealProcessor", I8),
    ("NewThreadWaitTime", U32),
    ("Reserved", U32),
];

const READY_THREAD: &[(&str, Field)] = &[
    ("TThreadId", U32),
    ("AdjustReason", I8),
    ("AdjustIncrement", I8),
    ("Flag", I8),
    ("Reserved", I8),
];

const IMAGE_V3: &[(&str, Field)] = &[
    ("ImageBase", Ptr),
    ("ImageSize", Ptr),
    ("ProcessId", U32),
    ("ImageChecksum", U32),
    ("TimeDateStamp", U32),
    ("SignatureLevel", U8),
    ("SignatureType", U8),
    ("Reserved0", U16),
    ("DefaultBase", Ptr),
    ("Reserved1", U32),
    ("Reserved2", U32),
    ("Reserved3", U32),
    ("Reserved4", U32),
    ("FileName", Utf16z),
];

const DISK_IO: &[(&str, Field)] = &[
    ("DiskNumber", U32),
    ("IrpFlags", U32),
    ("TransferSize", U32),
    ("Reserved", U32),
    ("ByteOffset", U64),
    ("FileObject", Ptr),
    ("Irp", Ptr),
    ("HighResResponseTime", U64),
    ("IssuingThreadId", U32),
];

const DISK_IO_INIT: &[(&str, Field)] = &[("Irp", Ptr), ("IssuingThreadId", U32)];

const DISK_FLUSH: &[(&str, Field)] = &[
    ("DiskNumber", U32),
    ("IrpFlags", U32),
    ("HighResResponseTime", U64),
    ("Irp", Ptr),
    ("IssuingThreadId", U32),
];

const FILE_RW: &[(&str, Field)] = &[
    ("Offset", U64),
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("FileKey", Ptr),
    ("TTID", U32),
    ("IoSize", U32),
    ("IoFlags", U32),
];

const FILE_SIMPLE: &[(&str, Field)] = &[
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("FileKey", Ptr),
    ("TTID", U32),
];

const FILE_INFO: &[(&str, Field)] = &[
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("FileKey", Ptr),
    ("ExtraInfo", Ptr),
    ("TTID", U32),
    ("InfoClass", U32),
];

const FILE_INFO_PATH: &[(&str, Field)] = &[
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("FileKey", Ptr),
    ("ExtraInfo", Ptr),
    ("TTID", U32),
    ("InfoClass", U32),
    ("FileName", Utf16z),
];

const FILE_DIR: &[(&str, Field)] = &[
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("FileKey", Ptr),
    ("TTID", U32),
    ("Length", U32),
    ("InfoClass", U32),
    ("FileIndex", U32),
    ("FileName", Utf16z),
];

const FILE_CREATE: &[(&str, Field)] = &[
    ("IrpPtr", Ptr),
    ("FileObject", Ptr),
    ("TTID", U32),
    ("CreateOptions", U32),
    ("FileAttributes", U32),
    ("ShareAccess", U32),
    ("OpenPath", Utf16z),
];

const FILE_NAME: &[(&str, Field)] = &[("FileObject", Ptr), ("FileName", Utf16z)];

const FILE_OP_END: &[(&str, Field)] = &[("IrpPtr", Ptr), ("ExtraInfo", Ptr), ("NtStatus", U32)];

const HARD_FAULT: &[(&str, Field)] = &[
    ("InitialTime", U64),
    ("ReadOffset", U64),
    ("VirtualAddress", Ptr),
    ("FileObject", Ptr),
    ("TThreadId", U32),
    ("ByteCount", U32),
];

const INTERRUPT: &[(&str, Field)] = &[
    ("InitialTime", U64),
    ("Routine", Ptr),
    ("ReturnValue", U8),
    ("Vector", U16),
    ("Reserved", U8),
];

const INTERRUPT_MSI: &[(&str, Field)] = &[
    ("InitialTime", U64),
    ("Routine", Ptr),
    ("ReturnValue", U8),
    ("Vector", U16),
    ("Reserved", U8),
    ("MessageNumber", U32),
];

const DPC: &[(&str, Field)] = &[("InitialTime", U64), ("Routine", Ptr)];

const ROUTINE: &[(&str, Field)] = &[("Routine", Ptr)];

const COLLECTION: &[(&str, Field)] = &[
    ("Source", U32),
    ("NewInterval", U32),
    ("OldInterval", U32),
    ("SourceName", Utf16z),
];

const IMAGE_ID: &[(&str, Field)] = &[
    ("ImageBase", Ptr),
    ("ImageSize", Ptr),
    ("ProcessId", U32),
    ("TimeDateStamp", U32),
    ("OriginalFileName", Utf16z),
];

const DBGID_RSDS: &[(&str, Field)] = &[
    ("ImageBase", Ptr),
    ("ProcessId", U32),
    ("GuidSig", Guid),
    ("Age", U32),
    ("PdbFileName", Ansiz),
];

const FILE_VERSION: &[(&str, Field)] = &[
    ("ImageSize", U32),
    ("TimeDateStamp", U32),
    ("OrigFileName", Utf16z),
    ("FileDescription", Utf16z),
    ("FileVersion", Utf16z),
    ("BinFileVersion", Utf16z),
    ("VerLanguage", Utf16z),
    ("ProductName", Utf16z),
    ("CompanyName", Utf16z),
    ("ProductVersion", Utf16z),
    ("FileId", Utf16z),
    ("ProgramId", Utf16z),
];

const CPU_CONFIG: &[(&str, Field)] = &[
    ("MHz", U32),
    ("NumberOfProcessors", U32),
    ("MemSize", U32),
    ("PageSize", U32),
    ("AllocationGranularity", U32),
    ("ComputerName", Bytes(512)),
    ("DomainName", Bytes(268)),
    ("HyperThreadingFlag", Ptr),
    ("HighestUserAddress", Ptr),
    ("ProcessorArchitecture", U16),
    ("ProcessorLevel", U16),
    ("ProcessorRevision", U16),
    ("PaeEnabled", U8),
    ("NxEnabled", U8),
    ("MemorySpeed", U32),
];

/// Every layout we know.
pub static SCHEMAS: &[Schema] = &[
    // Process.
    s(guids::PROCESS, 1, 4, "Process", "Start", PROCESS_V4),
    s(guids::PROCESS, 2, 4, "Process", "End", PROCESS_V4),
    s(guids::PROCESS, 3, 4, "Process", "DCStart", PROCESS_V4),
    s(guids::PROCESS, 4, 4, "Process", "DCEnd", PROCESS_V4),
    s(
        guids::PROCESS,
        39,
        5,
        "Process",
        "Defunct",
        PROCESS_DEFUNCT_V5,
    ),
    s(
        guids::PROCESS,
        11,
        2,
        "Process",
        "Terminate",
        &[("ProcessId", U32)],
    ),
    s(guids::PROCESS, 32, 2, "Process", "PerfCtr", PROCESS_PERFCTR),
    s(
        guids::PROCESS,
        33,
        2,
        "Process",
        "PerfCtrRundown",
        PROCESS_PERFCTR,
    ),
    // Thread.
    s(guids::THREAD, 1, 3, "Thread", "Start", THREAD_V3),
    s(guids::THREAD, 2, 3, "Thread", "End", THREAD_V3),
    s(guids::THREAD, 3, 3, "Thread", "DCStart", THREAD_V3),
    s(guids::THREAD, 4, 3, "Thread", "DCEnd", THREAD_V3),
    s(guids::THREAD, 1, 4, "Thread", "Start", THREAD_V4),
    s(guids::THREAD, 2, 4, "Thread", "End", THREAD_V4),
    s(guids::THREAD, 3, 4, "Thread", "DCStart", THREAD_V4),
    s(guids::THREAD, 4, 4, "Thread", "DCEnd", THREAD_V4),
    s(guids::THREAD, 36, 2, "Thread", "CSwitch", CSWITCH_V2),
    s(
        guids::THREAD,
        48,
        3,
        "Thread",
        "SetPriority",
        THREAD_PRIORITY,
    ),
    s(
        guids::THREAD,
        49,
        3,
        "Thread",
        "SetBasePriority",
        THREAD_PRIORITY,
    ),
    s(guids::THREAD, 50, 2, "Thread", "ReadyThread", READY_THREAD),
    s(
        guids::THREAD,
        51,
        3,
        "Thread",
        "SetPagePriority",
        THREAD_PRIORITY,
    ),
    s(
        guids::THREAD,
        52,
        3,
        "Thread",
        "SetIoPriority",
        THREAD_PRIORITY,
    ),
    s(
        guids::THREAD,
        72,
        2,
        "Thread",
        "SetName",
        &[
            ("ProcessId", U32),
            ("ThreadId", U32),
            ("ThreadName", Utf16z),
        ],
    ),
    // Image.
    s(guids::IMAGE, 2, 3, "Image", "UnLoad", IMAGE_V3),
    s(guids::IMAGE, 3, 3, "Image", "DCStart", IMAGE_V3),
    s(guids::IMAGE, 4, 3, "Image", "DCEnd", IMAGE_V3),
    s(guids::IMAGE, 10, 3, "Image", "Load", IMAGE_V3),
    s(
        guids::IMAGE,
        33,
        2,
        "Image",
        "KernelBase",
        &[("ImageBase", Ptr)],
    ),
    s(
        guids::IMAGE,
        34,
        2,
        "Image",
        "HypercallPage",
        &[("HypercallPageVa", Ptr)],
    ),
    // PerfInfo.
    s(
        guids::PERF_INFO,
        46,
        2,
        "PerfInfo",
        "SampleProf",
        &[
            ("InstructionPointer", Ptr),
            ("ThreadId", U32),
            ("Count", U16),
            ("Reserved", U16),
        ],
    ),
    s(
        guids::PERF_INFO,
        50,
        2,
        "PerfInfo",
        "ISR-MSI",
        INTERRUPT_MSI,
    ),
    s(guids::PERF_INFO, 67, 2, "PerfInfo", "ISR", INTERRUPT),
    s(guids::PERF_INFO, 68, 2, "PerfInfo", "DPC", DPC),
    s(guids::PERF_INFO, 69, 2, "PerfInfo", "TimerDPC", DPC),
    s(
        guids::PERF_INFO,
        73,
        3,
        "PerfInfo",
        "CollectionStart",
        COLLECTION,
    ),
    s(
        guids::PERF_INFO,
        74,
        3,
        "PerfInfo",
        "CollectionEnd",
        COLLECTION,
    ),
    s(guids::PERF_INFO, 96, 2, "PerfInfo", "WdfISR", ROUTINE),
    s(guids::PERF_INFO, 98, 2, "PerfInfo", "WdfDPC", ROUTINE),
    // StackWalk.
    s(
        guids::STACK_WALK,
        32,
        2,
        "StackWalk",
        "Stack",
        &[
            ("EventTimeStamp", U64),
            ("StackProcess", U32),
            ("StackThread", U32),
            ("Stack", Pointers),
        ],
    ),
    // DiskIo.
    s(guids::DISK_IO, 10, 3, "DiskIo", "Read", DISK_IO),
    s(guids::DISK_IO, 11, 3, "DiskIo", "Write", DISK_IO),
    s(guids::DISK_IO, 12, 3, "DiskIo", "ReadInit", DISK_IO_INIT),
    s(guids::DISK_IO, 13, 3, "DiskIo", "WriteInit", DISK_IO_INIT),
    s(guids::DISK_IO, 14, 3, "DiskIo", "FlushBuffers", DISK_FLUSH),
    s(guids::DISK_IO, 15, 3, "DiskIo", "FlushInit", DISK_IO_INIT),
    // FileIo.
    s(guids::FILE_IO, 32, 2, "FileIo", "FileCreate", FILE_NAME),
    s(guids::FILE_IO, 35, 2, "FileIo", "FileDelete", FILE_NAME),
    s(guids::FILE_IO, 36, 2, "FileIo", "FileRundown", FILE_NAME),
    s(guids::FILE_IO, 64, 3, "FileIo", "Create", FILE_CREATE),
    s(guids::FILE_IO, 65, 3, "FileIo", "Cleanup", FILE_SIMPLE),
    s(guids::FILE_IO, 66, 3, "FileIo", "Close", FILE_SIMPLE),
    s(guids::FILE_IO, 67, 3, "FileIo", "Read", FILE_RW),
    s(guids::FILE_IO, 68, 3, "FileIo", "Write", FILE_RW),
    s(guids::FILE_IO, 69, 3, "FileIo", "SetInfo", FILE_INFO),
    s(guids::FILE_IO, 70, 3, "FileIo", "Delete", FILE_INFO),
    s(guids::FILE_IO, 71, 3, "FileIo", "Rename", FILE_INFO),
    s(guids::FILE_IO, 72, 3, "FileIo", "DirEnum", FILE_DIR),
    s(guids::FILE_IO, 73, 3, "FileIo", "Flush", FILE_SIMPLE),
    s(guids::FILE_IO, 74, 3, "FileIo", "QueryInfo", FILE_INFO),
    s(guids::FILE_IO, 75, 3, "FileIo", "FSControl", FILE_INFO),
    s(guids::FILE_IO, 76, 3, "FileIo", "OperationEnd", FILE_OP_END),
    s(guids::FILE_IO, 77, 3, "FileIo", "DirNotify", FILE_DIR),
    s(guids::FILE_IO, 79, 3, "FileIo", "DletePath", FILE_INFO_PATH),
    s(
        guids::FILE_IO,
        80,
        3,
        "FileIo",
        "RenamePath",
        FILE_INFO_PATH,
    ),
    // PageFault.
    s(
        guids::PAGE_FAULT,
        32,
        2,
        "PageFault",
        "HardFault",
        HARD_FAULT,
    ),
    // SystemConfig.
    s(
        guids::SYSTEM_CONFIG,
        10,
        3,
        "SystemConfig",
        "CPU",
        CPU_CONFIG,
    ),
    // KernelTraceControl, added when a trace is merged.
    s(
        guids::KERNEL_TRACE_CONTROL,
        0,
        2,
        "ImageId",
        "ImageId",
        IMAGE_ID,
    ),
    s(
        guids::KERNEL_TRACE_CONTROL,
        36,
        2,
        "ImageId",
        "DbgID_RSDS",
        DBGID_RSDS,
    ),
    s(
        guids::KERNEL_TRACE_CONTROL,
        37,
        2,
        "ImageId",
        "DbgID_ILRSDS",
        DBGID_RSDS,
    ),
    s(
        guids::KERNEL_TRACE_CONTROL,
        64,
        0,
        "ImageId",
        "FileVersion",
        FILE_VERSION,
    ),
];

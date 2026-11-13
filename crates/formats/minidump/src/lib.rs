//! Minidumps (`MDMP`): the crash dumps of Windows (`MiniDumpWriteDump`),
//! Breakpad, and Crashpad, for any of their platforms (Windows, Linux,
//! Android, macOS, iOS).
//!
//! A minidump is a header, a directory of streams, and the streams: the
//! threads (each with its stack memory and register context), the loaded
//! and unloaded modules, captured memory, the exception, system and
//! process information, and platform-specific streams (Linux's `/proc`
//! files, Breakpad's and Crashpad's own). This crate reads them as they
//! are; it doesn't walk stacks or load symbols.
//!
//! Every count is checked against the bytes of its stream, so reading is
//! linear in the dump's size, and malformed data gives an error (or, in a
//! list, ends it) rather than a panic. Register contexts are decoded by
//! [`context`].

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod context;

use alloc::string::String;
use alloc::vec::Vec;

use hexcavator_core::{Error, ErrorKind, Result};

/// Stream types (`MINIDUMP_STREAM_TYPE`, and Breakpad's and Crashpad's).
pub mod stream {
    /// The threads (`MINIDUMP_THREAD_LIST`).
    pub const THREAD_LIST: u32 = 3;
    /// The loaded modules.
    pub const MODULE_LIST: u32 = 4;
    /// Captured memory, each range with its own data.
    pub const MEMORY_LIST: u32 = 5;
    /// The exception that caused the dump.
    pub const EXCEPTION: u32 = 6;
    /// Processor and operating system.
    pub const SYSTEM_INFO: u32 = 7;
    /// The threads, with backing store (Itanium).
    pub const THREAD_EX_LIST: u32 = 8;
    /// Captured memory, its data contiguous (full-memory dumps).
    pub const MEMORY64_LIST: u32 = 9;
    /// A comment, ANSI.
    pub const COMMENT_A: u32 = 10;
    /// A comment, UTF-16.
    pub const COMMENT_W: u32 = 11;
    /// Open handles.
    pub const HANDLE_DATA: u32 = 12;
    /// Dynamic function tables.
    pub const FUNCTION_TABLE: u32 = 13;
    /// Recently unloaded modules.
    pub const UNLOADED_MODULE_LIST: u32 = 14;
    /// Process information (`MINIDUMP_MISC_INFO` and its later versions).
    pub const MISC_INFO: u32 = 15;
    /// The process's address space, region by region.
    pub const MEMORY_INFO_LIST: u32 = 16;
    /// Thread times, start addresses, and dump status.
    pub const THREAD_INFO_LIST: u32 = 17;
    /// Handle operations (handle tracing).
    pub const HANDLE_OPERATION_LIST: u32 = 18;
    /// Security tokens.
    pub const TOKEN: u32 = 19;
    /// JavaScript data.
    pub const JAVASCRIPT_DATA: u32 = 20;
    /// System memory information.
    pub const SYSTEM_MEMORY_INFO: u32 = 21;
    /// Process VM counters.
    pub const PROCESS_VM_COUNTERS: u32 = 22;
    /// Intel Processor Trace data.
    pub const IPT_TRACE: u32 = 23;
    /// Thread names.
    pub const THREAD_NAMES: u32 = 24;
    /// Breakpad: which thread wrote the dump, and for which.
    pub const BREAKPAD_INFO: u32 = 0x4767_0001;
    /// Breakpad: an assertion's expression, function, file, and line.
    pub const ASSERTION_INFO: u32 = 0x4767_0002;
    /// Breakpad: Linux `/proc/cpuinfo`.
    pub const LINUX_CPU_INFO: u32 = 0x4767_0003;
    /// Breakpad: Linux `/proc/<pid>/status`.
    pub const LINUX_PROC_STATUS: u32 = 0x4767_0004;
    /// Breakpad: Linux `/etc/lsb-release`.
    pub const LINUX_LSB_RELEASE: u32 = 0x4767_0005;
    /// Breakpad: Linux `/proc/<pid>/cmdline`.
    pub const LINUX_CMD_LINE: u32 = 0x4767_0006;
    /// Breakpad: Linux `/proc/<pid>/environ`.
    pub const LINUX_ENVIRON: u32 = 0x4767_0007;
    /// Breakpad: Linux `/proc/<pid>/auxv`.
    pub const LINUX_AUXV: u32 = 0x4767_0008;
    /// Breakpad: Linux `/proc/<pid>/maps`.
    pub const LINUX_MAPS: u32 = 0x4767_0009;
    /// Breakpad: Linux `DSO_DEBUG` (the dynamic linker's `r_debug`).
    pub const LINUX_DSO_DEBUG: u32 = 0x4767_000A;
    /// Crashpad: its report and client IDs, annotations.
    pub const CRASHPAD_INFO: u32 = 0x4350_0001;
}

/// `MINIDUMP_SIGNATURE`: `MDMP`.
pub const SIGNATURE: u32 = 0x504D_444D;
/// `MINIDUMP_VERSION` (the low half of the header's version).
pub const VERSION: u16 = 0xA793;

/// The most streams read from a directory: more than a dump's directory
/// would need, fewer than a hostile one can claim.
const MAX_STREAMS: u32 = 1 << 16;

fn err(kind: ErrorKind, offset: u64, what: &'static str) -> Error {
    Error::new(kind, offset, what)
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        d.get(o..o.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// The `count` fixed-size entries of a list stream, after a header of
/// `header` bytes: as many as the stream's bytes hold.
fn entries(data: &[u8], header: usize, size: usize, count: u64) -> impl Iterator<Item = &[u8]> {
    let body = data.get(header..).unwrap_or(&[]);
    let n = body
        .len()
        .checked_div(size)
        .unwrap_or(0)
        .min(usize::try_from(count).unwrap_or(usize::MAX));
    body.chunks_exact(size.max(1)).take(n)
}

/// Where a stream or other data is: its size and RVA
/// (`MINIDUMP_LOCATION_DESCRIPTOR`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Location {
    /// The size in bytes.
    pub size: u32,
    /// The offset in the file.
    pub rva: u32,
}

impl Location {
    fn at(d: &[u8], o: usize) -> Option<Self> {
        Some(Location {
            size: u32_at(d, o)?,
            rva: u32_at(d, o + 4)?,
        })
    }
}

/// A stream in the directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream<'d> {
    /// Its type (see [`stream`]).
    pub kind: u32,
    /// Where it is.
    pub location: Location,
    /// Its bytes (empty where its location is outside the file).
    pub data: &'d [u8],
}

/// A parsed minidump.
#[derive(Clone, Debug)]
pub struct Minidump<'d> {
    data: &'d [u8],
    version: u32,
    directory: &'d [u8],
    checksum: u32,
    time_date_stamp: u32,
    flags: u64,
}

impl<'d> Minidump<'d> {
    /// Parses the header and stream directory.
    pub fn parse(data: &'d [u8]) -> Result<Self> {
        let header = data
            .get(..32)
            .ok_or(err(ErrorKind::Truncated, 0, "minidump header"))?;
        if u32_at(header, 0) != Some(SIGNATURE) {
            return Err(err(ErrorKind::BadMagic, 0, "minidump signature"));
        }
        let version = u32_at(header, 4).unwrap_or(0);
        if version & 0xFFFF != u32::from(VERSION) {
            return Err(err(ErrorKind::Unsupported, 4, "minidump version"));
        }
        let count = u32_at(header, 8).unwrap_or(0);
        let rva = u32_at(header, 12).unwrap_or(0);
        if count > MAX_STREAMS {
            return Err(err(ErrorKind::Malformed, 8, "minidump stream count"));
        }
        let start = rva as usize;
        let len = count as usize * 12;
        let directory = start
            .checked_add(len)
            .and_then(|end| data.get(start..end))
            .ok_or(err(
                ErrorKind::Truncated,
                u64::from(rva),
                "minidump stream directory",
            ))?;
        Ok(Minidump {
            data,
            version,
            directory,
            checksum: u32_at(header, 16).unwrap_or(0),
            time_date_stamp: u32_at(header, 20).unwrap_or(0),
            flags: u64_at(header, 24).unwrap_or(0),
        })
    }

    /// The whole file.
    pub fn data(&self) -> &'d [u8] {
        self.data
    }

    /// The header's version: [`VERSION`], and in its high half an
    /// implementation-specific value.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The header's checksum (0 for most writers).
    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    /// When the dump was written (seconds since 1970, UTC).
    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// `MINIDUMP_TYPE` flags: what the writer was asked to include.
    pub fn flags(&self) -> u64 {
        self.flags
    }

    /// The bytes at a location, if they are all in the file.
    pub fn location(&self, l: Location) -> Option<&'d [u8]> {
        let start = l.rva as usize;
        self.data.get(start..start.checked_add(l.size as usize)?)
    }

    /// The directory's streams, in order (including unused, type 0,
    /// entries).
    pub fn streams(&self) -> impl Iterator<Item = Stream<'d>> + '_ {
        self.directory.as_chunks::<12>().0.iter().map(|e| {
            let kind = u32_at(e, 0).unwrap_or(0);
            let location = Location::at(e, 4).unwrap_or_default();
            Stream {
                kind,
                location,
                data: self.location(location).unwrap_or(&[]),
            }
        })
    }

    /// The first stream of a type.
    pub fn stream(&self, kind: u32) -> Option<Stream<'d>> {
        self.streams().find(|s| s.kind == kind)
    }

    /// A `MINIDUMP_STRING` (UTF-16, its length in bytes first) at an RVA.
    pub fn string_at(&self, rva: u32) -> Option<String> {
        let start = rva as usize;
        let len = u32_at(self.data, start)? as usize;
        let bytes = self
            .data
            .get(start + 4..start.checked_add(4)?.checked_add(len)?)?;
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        Some(
            char::decode_utf16(units)
                .map(|c| c.unwrap_or('\u{FFFD}'))
                .collect(),
        )
    }

    /// A UTF-8 string with its length first (Crashpad's), at an RVA.
    pub fn utf8_string_at(&self, rva: u32) -> Option<&'d [u8]> {
        let start = rva as usize;
        let len = u32_at(self.data, start)? as usize;
        self.data
            .get(start + 4..start.checked_add(4)?.checked_add(len)?)
    }

    fn list_stream(&self, kind: u32) -> Option<&'d [u8]> {
        self.stream(kind).map(|s| s.data)
    }

    /// The threads (from the thread list, or the extended thread list).
    pub fn threads(&self) -> Result<Vec<Thread<'d>>> {
        let (data, size) = match self.list_stream(stream::THREAD_LIST) {
            Some(d) => (d, 48),
            None => match self.list_stream(stream::THREAD_EX_LIST) {
                Some(d) => (d, 64),
                None => return Ok(Vec::new()),
            },
        };
        let count = u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "thread list"))?;
        // (Full-memory dumps' stacks are in the 64-bit memory list, indexed
        // once, when a thread needs it.)
        let mut runs: Option<Vec<Run>> = None;
        Ok(entries(data, 4, size, u64::from(count))
            // (MINIDUMP_THREAD: ThreadId, SuspendCount, PriorityClass,
            // Priority, Teb at 16, Stack at 24, ThreadContext at 40.)
            .map(|e| {
                let start = u64_at(e, 24).unwrap_or(0);
                let l = Location::at(e, 32).unwrap_or_default();
                // (A full-memory dump's descriptors have RVA 0, the
                // header's.)
                let stack = if l.rva == 0 && l.size != 0 {
                    let runs = runs.get_or_insert_with(|| self.memory64_runs());
                    self.run_slice(runs, start, u64::from(l.size))
                } else {
                    self.location(l)
                };
                Thread {
                    id: u32_at(e, 0).unwrap_or(0),
                    suspend_count: u32_at(e, 4).unwrap_or(0),
                    priority_class: u32_at(e, 8).unwrap_or(0),
                    priority: u32_at(e, 12).unwrap_or(0),
                    teb: u64_at(e, 16).unwrap_or(0),
                    stack: Memory {
                        start,
                        data: stack.unwrap_or(&[]),
                    },
                    context: self
                        .location(Location::at(e, 40).unwrap_or_default())
                        .unwrap_or(&[]),
                }
            })
            .collect())
    }

    /// The 64-bit memory list as runs: its ranges' bytes follow one
    /// another in the file, so ranges that also follow one another in
    /// memory are one run. By address.
    fn memory64_runs(&self) -> Vec<Run> {
        let mut runs: Vec<Run> = Vec::new();
        let Some(data) = self.list_stream(stream::MEMORY64_LIST) else {
            return runs;
        };
        let (Some(count), Some(mut rva)) = (u64_at(data, 0), u64_at(data, 8)) else {
            return runs;
        };
        for e in entries(data, 16, 16, count) {
            let start = u64_at(e, 0).unwrap_or(0);
            let size = u64_at(e, 8).unwrap_or(0);
            let (Some(end), Some(next_rva)) = (start.checked_add(size), rva.checked_add(size))
            else {
                break;
            };
            match runs.last_mut() {
                Some(r) if r.end == start => r.end = end,
                _ => runs.push(Run { start, end, rva }),
            }
            rva = next_rva;
        }
        runs.sort_by_key(|r| r.start);
        runs
    }

    /// `len` bytes at `address`, if they are all in one run.
    fn run_slice(&self, runs: &[Run], address: u64, len: u64) -> Option<&'d [u8]> {
        let i = runs.partition_point(|r| r.start <= address);
        let r = runs.get(i.checked_sub(1)?)?;
        if address.checked_add(len)? > r.end {
            return None;
        }
        let at = usize::try_from(r.rva.checked_add(address - r.start)?).ok()?;
        self.data
            .get(at..at.checked_add(usize::try_from(len).ok()?)?)
    }

    /// The loaded modules.
    pub fn modules(&self) -> Result<Vec<Module<'d>>> {
        let Some(data) = self.list_stream(stream::MODULE_LIST) else {
            return Ok(Vec::new());
        };
        let count = u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "module list"))?;
        Ok(entries(data, 4, 108, u64::from(count))
            .map(|e| {
                let cv = Location::at(e, 76).unwrap_or_default();
                let misc = Location::at(e, 84).unwrap_or_default();
                Module {
                    base: u64_at(e, 0).unwrap_or(0),
                    size: u32_at(e, 8).unwrap_or(0),
                    checksum: u32_at(e, 12).unwrap_or(0),
                    time_date_stamp: u32_at(e, 16).unwrap_or(0),
                    name: self
                        .string_at(u32_at(e, 20).unwrap_or(0))
                        .unwrap_or_default(),
                    version: FixedFileInfo::at(e, 24),
                    cv_record: self.location(cv).unwrap_or(&[]),
                    misc_record: self.location(misc).unwrap_or(&[]),
                }
            })
            .collect())
    }

    /// The recently unloaded modules.
    pub fn unloaded_modules(&self) -> Result<Vec<UnloadedModule>> {
        let Some(data) = self.list_stream(stream::UNLOADED_MODULE_LIST) else {
            return Ok(Vec::new());
        };
        let (header, size, count) = header3(data, "unloaded module list")?;
        Ok(entries(data, header, size, u64::from(count))
            .filter(|e| e.len() >= 24)
            .map(|e| UnloadedModule {
                base: u64_at(e, 0).unwrap_or(0),
                size: u32_at(e, 8).unwrap_or(0),
                checksum: u32_at(e, 12).unwrap_or(0),
                time_date_stamp: u32_at(e, 16).unwrap_or(0),
                name: self
                    .string_at(u32_at(e, 20).unwrap_or(0))
                    .unwrap_or_default(),
            })
            .collect())
    }

    /// The captured memory, from the memory list and the 64-bit memory
    /// list, by address.
    pub fn memory(&self) -> Result<MemoryMap<'d>> {
        let mut ranges = Vec::new();
        if let Some(data) = self.list_stream(stream::MEMORY_LIST) {
            let count = u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "memory list"))?;
            for e in entries(data, 4, 16, u64::from(count)) {
                let start = u64_at(e, 0).unwrap_or(0);
                if let Some(d) = self.location(Location::at(e, 8).unwrap_or_default()) {
                    ranges.push(Memory { start, data: d });
                }
            }
        }
        if let Some(data) = self.list_stream(stream::MEMORY64_LIST) {
            let count = u64_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "memory64 list"))?;
            let mut rva = u64_at(data, 8).unwrap_or(0);
            for e in entries(data, 16, 16, count) {
                let start = u64_at(e, 0).unwrap_or(0);
                let size = u64_at(e, 8).unwrap_or(0);
                let d = usize::try_from(rva).ok().and_then(|r| {
                    let end = r.checked_add(usize::try_from(size).ok()?)?;
                    self.data.get(r..end)
                });
                let Some(d) = d else { break };
                ranges.push(Memory { start, data: d });
                rva += size;
            }
        }
        ranges.sort_by_key(|r| r.start);
        Ok(MemoryMap { ranges })
    }

    /// The exception that caused the dump.
    pub fn exception(&self) -> Result<Option<Exception<'d>>> {
        let Some(d) = self.list_stream(stream::EXCEPTION) else {
            return Ok(None);
        };
        if d.len() < 168 {
            return Err(err(ErrorKind::Truncated, 0, "exception stream"));
        }
        let count = u32_at(d, 32).unwrap_or(0).min(15) as usize;
        let parameters = (0..count).filter_map(|i| u64_at(d, 40 + 8 * i)).collect();
        Ok(Some(Exception {
            thread_id: u32_at(d, 0).unwrap_or(0),
            code: u32_at(d, 8).unwrap_or(0),
            flags: u32_at(d, 12).unwrap_or(0),
            record: u64_at(d, 16).unwrap_or(0),
            address: u64_at(d, 24).unwrap_or(0),
            parameters,
            context: self
                .location(Location::at(d, 160).unwrap_or_default())
                .unwrap_or(&[]),
        }))
    }

    /// The processor and operating system.
    pub fn system_info(&self) -> Result<Option<SystemInfo>> {
        let Some(d) = self.list_stream(stream::SYSTEM_INFO) else {
            return Ok(None);
        };
        if d.len() < 32 {
            return Err(err(ErrorKind::Truncated, 0, "system info stream"));
        }
        let mut cpu = [0u8; 24];
        if let Some(c) = d.get(32..56) {
            cpu.copy_from_slice(c);
        }
        let csd = u32_at(d, 24).unwrap_or(0);
        Ok(Some(SystemInfo {
            processor_architecture: u16_at(d, 0).unwrap_or(0),
            processor_level: u16_at(d, 2).unwrap_or(0),
            processor_revision: u16_at(d, 4).unwrap_or(0),
            number_of_processors: d[6],
            product_type: d[7],
            major_version: u32_at(d, 8).unwrap_or(0),
            minor_version: u32_at(d, 12).unwrap_or(0),
            build_number: u32_at(d, 16).unwrap_or(0),
            platform_id: u32_at(d, 20).unwrap_or(0),
            csd_version: if csd == 0 { None } else { self.string_at(csd) },
            suite_mask: u16_at(d, 28).unwrap_or(0),
            cpu,
        }))
    }

    /// Process information (`MINIDUMP_MISC_INFO` through `_5`).
    pub fn misc_info(&self) -> Option<MiscInfo<'d>> {
        let d = self.list_stream(stream::MISC_INFO)?;
        let size = u32_at(d, 0)?;
        let flags = u32_at(d, 4)?;
        let get = |o| u32_at(d, o);
        Some(MiscInfo {
            size,
            flags,
            process_id: (flags & 1 != 0).then(|| get(8)).flatten(),
            process_create_time: (flags & 2 != 0).then(|| get(12)).flatten(),
            process_user_time: (flags & 2 != 0).then(|| get(16)).flatten(),
            process_kernel_time: (flags & 2 != 0).then(|| get(20)).flatten(),
            data: d,
        })
    }

    /// The address space, region by region.
    pub fn memory_info(&self) -> Result<Vec<MemoryInfo>> {
        let Some(data) = self.list_stream(stream::MEMORY_INFO_LIST) else {
            return Ok(Vec::new());
        };
        let header =
            u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "memory info list"))? as usize;
        let size = u32_at(data, 4).unwrap_or(0) as usize;
        let count = u64_at(data, 8).unwrap_or(0);
        if header < 16 || size < 48 {
            return Err(err(ErrorKind::Malformed, 0, "memory info list header"));
        }
        Ok(entries(data, header, size, count)
            .map(|e| MemoryInfo {
                base: u64_at(e, 0).unwrap_or(0),
                allocation_base: u64_at(e, 8).unwrap_or(0),
                allocation_protect: u32_at(e, 16).unwrap_or(0),
                region_size: u64_at(e, 24).unwrap_or(0),
                state: u32_at(e, 32).unwrap_or(0),
                protect: u32_at(e, 36).unwrap_or(0),
                kind: u32_at(e, 40).unwrap_or(0),
            })
            .collect())
    }

    /// Thread times, start addresses, and dump status.
    pub fn thread_info(&self) -> Result<Vec<ThreadInfo>> {
        let Some(data) = self.list_stream(stream::THREAD_INFO_LIST) else {
            return Ok(Vec::new());
        };
        let (header, size, count) = header3(data, "thread info list")?;
        if size < 64 {
            return Err(err(ErrorKind::Malformed, 4, "thread info entry size"));
        }
        Ok(entries(data, header, size, u64::from(count))
            .map(|e| ThreadInfo {
                thread_id: u32_at(e, 0).unwrap_or(0),
                dump_flags: u32_at(e, 4).unwrap_or(0),
                dump_error: u32_at(e, 8).unwrap_or(0),
                exit_status: u32_at(e, 12).unwrap_or(0),
                create_time: u64_at(e, 16).unwrap_or(0),
                exit_time: u64_at(e, 24).unwrap_or(0),
                kernel_time: u64_at(e, 32).unwrap_or(0),
                user_time: u64_at(e, 40).unwrap_or(0),
                start_address: u64_at(e, 48).unwrap_or(0),
                affinity: u64_at(e, 56).unwrap_or(0),
            })
            .collect())
    }

    /// Thread names, by thread ID.
    pub fn thread_names(&self) -> Result<Vec<(u32, String)>> {
        let Some(data) = self.list_stream(stream::THREAD_NAMES) else {
            return Ok(Vec::new());
        };
        let count = u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, "thread names"))?;
        Ok(entries(data, 4, 12, u64::from(count))
            .filter_map(|e| {
                let rva = u32::try_from(u64_at(e, 4)?).ok()?;
                Some((u32_at(e, 0)?, self.string_at(rva)?))
            })
            .collect())
    }

    /// Open handles.
    pub fn handles(&self) -> Result<Vec<Handle>> {
        let Some(data) = self.list_stream(stream::HANDLE_DATA) else {
            return Ok(Vec::new());
        };
        let (header, size, count) = header3(data, "handle data")?;
        if size < 32 {
            return Err(err(ErrorKind::Malformed, 4, "handle descriptor size"));
        }
        let name = |rva: u32| (rva != 0).then(|| self.string_at(rva)).flatten();
        Ok(entries(data, header, size, u64::from(count))
            .map(|e| Handle {
                handle: u64_at(e, 0).unwrap_or(0),
                type_name: name(u32_at(e, 8).unwrap_or(0)),
                object_name: name(u32_at(e, 12).unwrap_or(0)),
                attributes: u32_at(e, 16).unwrap_or(0),
                granted_access: u32_at(e, 20).unwrap_or(0),
                handle_count: u32_at(e, 24).unwrap_or(0),
                pointer_count: u32_at(e, 28).unwrap_or(0),
            })
            .collect())
    }

    /// The comment streams' text: ANSI (as bytes) and UTF-16.
    pub fn comments(&self) -> (Option<&'d [u8]>, Option<String>) {
        let a = self.list_stream(stream::COMMENT_A).map(|d| {
            let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
            &d[..end]
        });
        let w = self.list_stream(stream::COMMENT_W).map(|d| {
            let units = d
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&u| u != 0);
            char::decode_utf16(units)
                .map(|c| c.unwrap_or('\u{FFFD}'))
                .collect()
        });
        (a, w)
    }

    /// Breakpad's information stream: (dump thread, requesting thread),
    /// each present per its validity flag.
    pub fn breakpad_info(&self) -> Option<(Option<u32>, Option<u32>)> {
        let d = self.list_stream(stream::BREAKPAD_INFO)?;
        let validity = u32_at(d, 0)?;
        Some((
            (validity & 1 != 0).then(|| u32_at(d, 4)).flatten(),
            (validity & 2 != 0).then(|| u32_at(d, 8)).flatten(),
        ))
    }

    /// Crashpad's information stream.
    pub fn crashpad_info(&self) -> Option<CrashpadInfo<'d>> {
        let d = self.list_stream(stream::CRASHPAD_INFO)?;
        let mut report_id = [0u8; 16];
        report_id.copy_from_slice(d.get(4..20)?);
        let mut client_id = [0u8; 16];
        client_id.copy_from_slice(d.get(20..36)?);
        let annotations = Location::at(d, 36)
            .and_then(|l| self.location(l))
            .map(|a| {
                let count = u64::from(u32_at(a, 0).unwrap_or(0));
                entries(a, 4, 8, count)
                    .filter_map(|e| {
                        Some((
                            self.utf8_string_at(u32_at(e, 0)?)?,
                            self.utf8_string_at(u32_at(e, 4)?)?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(CrashpadInfo {
            version: u32_at(d, 0)?,
            report_id,
            client_id,
            simple_annotations: annotations,
        })
    }
}

/// A list stream's three-word header (its size, the entries' size, their
/// count).
fn header3(data: &[u8], what: &'static str) -> Result<(usize, usize, u32)> {
    let header = u32_at(data, 0).ok_or(err(ErrorKind::Truncated, 0, what))? as usize;
    let size = u32_at(data, 4).ok_or(err(ErrorKind::Truncated, 4, what))? as usize;
    let count = u32_at(data, 8).ok_or(err(ErrorKind::Truncated, 8, what))?;
    if header < 12 {
        return Err(err(ErrorKind::Malformed, 0, what));
    }
    Ok((header, size, count))
}

/// Address-contiguous ranges of the 64-bit memory list: `start..end`,
/// its bytes from file offset `rva` on.
struct Run {
    start: u64,
    end: u64,
    rva: u64,
}

/// A range of captured memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory<'d> {
    /// Its first address.
    pub start: u64,
    /// Its bytes.
    pub data: &'d [u8],
}

/// A thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thread<'d> {
    /// Its ID.
    pub id: u32,
    /// How many times it was suspended (by the dump writer, too).
    pub suspend_count: u32,
    /// Its process's priority class.
    pub priority_class: u32,
    /// Its priority.
    pub priority: u32,
    /// Its TEB's address (Windows), or TLS pointer.
    pub teb: u64,
    /// Its stack's captured memory.
    pub stack: Memory<'d>,
    /// Its registers, raw (see [`context`]).
    pub context: &'d [u8],
}

/// A module's `VS_FIXEDFILEINFO` (its version resource's fixed part).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FixedFileInfo {
    /// 0xFEEF04BD where the module has version information.
    pub signature: u32,
    /// The file version: major, minor, build, revision.
    pub file_version: [u16; 4],
    /// The product version.
    pub product_version: [u16; 4],
    /// `VS_FF_*` flags (as masked).
    pub file_flags: u32,
    /// `VOS_*`: the operating system it was built for.
    pub file_os: u32,
    /// `VFT_*`: an application, a DLL, a driver, ...
    pub file_type: u32,
}

impl FixedFileInfo {
    fn at(e: &[u8], o: usize) -> Self {
        let w = |k: usize| u32_at(e, o + 4 * k).unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)] // (Halves.)
        let split = |ms: u32, ls: u32| [(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16];
        FixedFileInfo {
            signature: w(0),
            file_version: split(w(2), w(3)),
            product_version: split(w(4), w(5)),
            file_flags: w(6) & w(7),
            file_os: w(8),
            file_type: w(9),
        }
    }
}

/// A loaded module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module<'d> {
    /// Its base address and size in memory.
    pub base: u64,
    /// Its size in memory.
    pub size: u32,
    /// Its image's checksum (PE `CheckSum`).
    pub checksum: u32,
    /// Its image's time stamp (PE `TimeDateStamp`).
    pub time_date_stamp: u32,
    /// Its path.
    pub name: String,
    /// Its version resource.
    pub version: FixedFileInfo,
    /// Its CodeView record: how to find its symbols (see
    /// [`Module::code_view`]).
    pub cv_record: &'d [u8],
    /// Its miscellaneous debug record (`IMAGE_DEBUG_MISC`; old images).
    pub misc_record: &'d [u8],
}

/// What a module's CodeView record identifies its symbols by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeView<'d> {
    /// PDB 7.0 (`RSDS`): a GUID, age, and PDB path. (Breakpad and
    /// Crashpad give Mach-O modules' UUIDs this way, age 0.)
    Pdb70 {
        /// The PDB's GUID.
        guid: [u8; 16],
        /// Its age.
        age: u32,
        /// Its path.
        name: &'d [u8],
    },
    /// PDB 2.0 (`NB10`): a time stamp, age, and path.
    Pdb20 {
        /// The PDB's signature (a time stamp).
        signature: u32,
        /// Its age.
        age: u32,
        /// Its path.
        name: &'d [u8],
    },
    /// An ELF build ID (Breakpad's and Crashpad's `BpEL`).
    Elf {
        /// The build ID's bytes.
        build_id: &'d [u8],
    },
    /// Some other signature.
    Other {
        /// The record's first four bytes.
        signature: u32,
    },
}

impl<'d> Module<'d> {
    /// Its CodeView record, decoded.
    pub fn code_view(&self) -> Option<CodeView<'d>> {
        let r = self.cv_record;
        let name = |from: usize| {
            let rest = r.get(from..).unwrap_or(&[]);
            &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())]
        };
        Some(match r.get(..4)? {
            b"RSDS" => CodeView::Pdb70 {
                guid: r.get(4..20)?.try_into().ok()?,
                age: u32_at(r, 20)?,
                name: name(24),
            },
            b"NB10" => CodeView::Pdb20 {
                signature: u32_at(r, 8)?,
                age: u32_at(r, 12)?,
                name: name(16),
            },
            b"LEpB" => CodeView::Elf { build_id: &r[4..] },
            _ => CodeView::Other {
                signature: u32_at(r, 0)?,
            },
        })
    }
}

/// A recently unloaded module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnloadedModule {
    /// Where it was, and its size.
    pub base: u64,
    /// Its size in memory.
    pub size: u32,
    /// Its image's checksum.
    pub checksum: u32,
    /// Its image's time stamp.
    pub time_date_stamp: u32,
    /// Its path.
    pub name: String,
}

/// The dump's captured memory, by address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryMap<'d> {
    ranges: Vec<Memory<'d>>,
}

impl<'d> MemoryMap<'d> {
    /// The ranges, by address.
    pub fn ranges(&self) -> &[Memory<'d>] {
        &self.ranges
    }

    /// The captured bytes from `address` on, within one range.
    pub fn at(&self, address: u64) -> Option<&'d [u8]> {
        let i = self.ranges.partition_point(|r| r.start <= address);
        let r = self.ranges.get(i.checked_sub(1)?)?;
        let off = usize::try_from(address - r.start).ok()?;
        r.data.get(off..).filter(|d| !d.is_empty())
    }

    /// Fills `buf` from `address` (across adjacent ranges); false if any of
    /// it wasn't captured.
    pub fn read(&self, address: u64, buf: &mut [u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            let Some(a) = address.checked_add(done as u64) else {
                return false;
            };
            let Some(d) = self.at(a) else { return false };
            let n = d.len().min(buf.len() - done);
            buf[done..done + n].copy_from_slice(&d[..n]);
            done += n;
        }
        true
    }
}

/// The exception that caused the dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exception<'d> {
    /// The thread it was raised on.
    pub thread_id: u32,
    /// Its code (`EXCEPTION_ACCESS_VIOLATION`, ...; Breakpad gives the
    /// signal on POSIX systems).
    pub code: u32,
    /// Its flags (Breakpad: the signal's code).
    pub flags: u32,
    /// The address of a nested exception's record.
    pub record: u64,
    /// Where it happened.
    pub address: u64,
    /// Its parameters (for an access violation: read/write, address).
    pub parameters: Vec<u64>,
    /// The registers when it happened, raw (see [`context`]).
    pub context: &'d [u8],
}

/// `ProcessorArchitecture` values.
pub mod cpu {
    /// x86.
    pub const X86: u16 = 0;
    /// ARM (32-bit).
    pub const ARM: u16 = 5;
    /// x64.
    pub const AMD64: u16 = 9;
    /// ARM64.
    pub const ARM64: u16 = 12;
    /// Breakpad's ARM64, before it had Windows' value.
    pub const ARM64_OLD: u16 = 0x8003;
}

/// `PlatformId` values: Windows', and Breakpad's for other systems.
pub mod platform {
    /// Windows NT.
    pub const WIN32_NT: u32 = 2;
    /// macOS.
    pub const MAC_OS_X: u32 = 0x8101;
    /// iOS.
    pub const IOS: u32 = 0x8102;
    /// Linux.
    pub const LINUX: u32 = 0x8201;
    /// Solaris.
    pub const SOLARIS: u32 = 0x8202;
    /// Android.
    pub const ANDROID: u32 = 0x8203;
    /// Native Client.
    pub const NACL: u32 = 0x8205;
    /// Fuchsia.
    pub const FUCHSIA: u32 = 0x8206;
}

/// The processor and operating system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInfo {
    /// See [`cpu`].
    pub processor_architecture: u16,
    /// The processor's level (family).
    pub processor_level: u16,
    /// Its revision (model and stepping).
    pub processor_revision: u16,
    /// How many processors.
    pub number_of_processors: u8,
    /// Windows' product type (workstation, server, ...).
    pub product_type: u8,
    /// The operating system's version.
    pub major_version: u32,
    /// Its minor version.
    pub minor_version: u32,
    /// Its build number.
    pub build_number: u32,
    /// See [`platform`].
    pub platform_id: u32,
    /// Windows' service pack, or Breakpad's OS version string.
    pub csd_version: Option<String>,
    /// Windows' suite mask.
    pub suite_mask: u16,
    /// The CPU information union: x86 vendor ID, version, features; or
    /// processor features.
    pub cpu: [u8; 24],
}

/// Process information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiscInfo<'d> {
    /// Its size: which version of the structure it is.
    pub size: u32,
    /// Which fields are valid (`MINIDUMP_MISC1_*`).
    pub flags: u32,
    /// The process's ID.
    pub process_id: Option<u32>,
    /// When it started (seconds since 1970).
    pub process_create_time: Option<u32>,
    /// Its user time, in seconds.
    pub process_user_time: Option<u32>,
    /// Its kernel time, in seconds.
    pub process_kernel_time: Option<u32>,
    /// The whole structure, for the later versions' fields.
    pub data: &'d [u8],
}

/// A region of the address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryInfo {
    /// Its first address.
    pub base: u64,
    /// Its allocation's first address.
    pub allocation_base: u64,
    /// The allocation's initial protection.
    pub allocation_protect: u32,
    /// Its size.
    pub region_size: u64,
    /// `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    pub state: u32,
    /// Its protection (`PAGE_*`).
    pub protect: u32,
    /// `MEM_IMAGE`, `MEM_MAPPED`, or `MEM_PRIVATE`.
    pub kind: u32,
}

/// A thread's times, start address, and dump status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadInfo {
    /// The thread.
    pub thread_id: u32,
    /// `MINIDUMP_THREAD_INFO_*` flags (error, exited, ...).
    pub dump_flags: u32,
    /// The error (an HRESULT) dumping it, if any.
    pub dump_error: u32,
    /// Its exit status, if it exited.
    pub exit_status: u32,
    /// When it was created (`FILETIME`).
    pub create_time: u64,
    /// When it exited.
    pub exit_time: u64,
    /// Its kernel time (100 ns units).
    pub kernel_time: u64,
    /// Its user time.
    pub user_time: u64,
    /// Its start address.
    pub start_address: u64,
    /// Its processor affinity.
    pub affinity: u64,
}

/// An open handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    /// Its value.
    pub handle: u64,
    /// Its object type's name.
    pub type_name: Option<String>,
    /// Its object's name.
    pub object_name: Option<String>,
    /// Its attributes.
    pub attributes: u32,
    /// The access granted.
    pub granted_access: u32,
    /// Its object's handle count.
    pub handle_count: u32,
    /// Its object's pointer count.
    pub pointer_count: u32,
}

/// Crashpad's information stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashpadInfo<'d> {
    /// The stream's version.
    pub version: u32,
    /// The report's UUID.
    pub report_id: [u8; 16],
    /// The client's UUID.
    pub client_id: [u8; 16],
    /// Annotations the client set: key, value (UTF-8).
    pub simple_annotations: Vec<(&'d [u8], &'d [u8])>,
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests;

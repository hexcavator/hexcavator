//! The logfile header (`TRACE_LOGFILE_HEADER`): the payload of the first
//! event of the first buffer.

use hexcavator_core::{Error, ErrorKind, Result};

use crate::bytes::{i64_at, u32_at};

/// The trace's clock (`TRACE_LOGFILE_HEADER::ReservedFlags`): what event
/// timestamps count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClockType {
    /// The performance counter (QPC), at [`LogfileHeader::perf_freq`] ticks
    /// per second.
    PerformanceCounter,
    /// System time: 100 ns ticks (a FILETIME).
    SystemTime,
    /// The CPU cycle counter, at [`LogfileHeader::cpu_speed_mhz`] MHz.
    CpuCycle,
    /// A value we don't know.
    Other(u32),
}

/// A trace's logfile header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogfileHeader {
    /// The size of the session's buffers.
    pub buffer_size: u32,
    /// The ETW version: major, minor, sub-version, sub-minor, low byte first.
    pub version: u32,
    /// The operating system's build number.
    pub provider_version: u32,
    /// The number of processors.
    pub number_of_processors: u32,
    /// When the session stopped, as a FILETIME.
    pub end_time: i64,
    /// The resolution of the system clock, in 100 ns units.
    pub timer_resolution: u32,
    /// The maximum file size, in MB.
    pub maximum_file_size: u32,
    /// `EVENT_TRACE_*_MODE` flags.
    pub log_file_mode: u32,
    /// The number of buffers written.
    pub buffers_written: u32,
    /// The number of buffers in use when the session started.
    pub start_buffers: u32,
    /// The size of a pointer on the machine that logged the trace: 4 or 8.
    pub pointer_size: u32,
    /// Events lost by the session.
    pub events_lost: u32,
    /// The processor's speed in MHz.
    pub cpu_speed_mhz: u32,
    /// The time zone, as a `TIME_ZONE_INFORMATION` (176 bytes, with padding).
    pub time_zone: [u8; 176],
    /// When the system booted, as a FILETIME.
    pub boot_time: i64,
    /// The performance counter's frequency, in ticks per second.
    pub perf_freq: i64,
    /// When the session started, as a FILETIME.
    pub start_time: i64,
    /// The clock (`ReservedFlags`).
    pub reserved_flags: u32,
    /// Buffers lost by the session.
    pub buffers_lost: u32,
    /// The session's name.
    pub logger_name: String,
    /// The file the session wrote.
    pub log_file_name: String,
}

impl LogfileHeader {
    /// Parses the header from the logfile-header event's payload.
    pub fn parse(data: &[u8], offset: u64) -> Result<Self> {
        let err = |what| Error::new(ErrorKind::Truncated, offset, what);
        if data.len() < 0x38 {
            return Err(err("logfile header"));
        }
        let pointer_size = u32_at(data, 0x2c);
        let ptr = match pointer_size {
            4 => 4,
            8 => 8,
            _ => {
                return Err(Error::new(
                    ErrorKind::Malformed,
                    offset + 0x2c,
                    "pointer size",
                ));
            }
        };
        // LoggerName and LogFileName are pointers (meaningless in a file);
        // the time zone follows, then the times, aligned to 8.
        let tz = 0x38 + 2 * ptr;
        let times = tz + 176;
        let end = times + 0x20;
        if data.len() < end {
            return Err(err("logfile header"));
        }
        let mut time_zone = [0u8; 176];
        time_zone.copy_from_slice(&data[tz..times]);
        let mut rest = &data[end..];
        let logger_name = utf16z(&mut rest);
        let log_file_name = utf16z(&mut rest);
        Ok(Self {
            buffer_size: u32_at(data, 0x00),
            version: u32_at(data, 0x04),
            provider_version: u32_at(data, 0x08),
            number_of_processors: u32_at(data, 0x0c),
            end_time: i64_at(data, 0x10),
            timer_resolution: u32_at(data, 0x18),
            maximum_file_size: u32_at(data, 0x1c),
            log_file_mode: u32_at(data, 0x20),
            buffers_written: u32_at(data, 0x24),
            start_buffers: u32_at(data, 0x28),
            pointer_size,
            events_lost: u32_at(data, 0x30),
            cpu_speed_mhz: u32_at(data, 0x34),
            time_zone,
            boot_time: i64_at(data, times),
            perf_freq: i64_at(data, times + 8),
            start_time: i64_at(data, times + 16),
            reserved_flags: u32_at(data, times + 24),
            buffers_lost: u32_at(data, times + 28),
            logger_name,
            log_file_name,
        })
    }

    /// The trace's clock.
    pub fn clock_type(&self) -> ClockType {
        match self.reserved_flags {
            1 => ClockType::PerformanceCounter,
            2 => ClockType::SystemTime,
            3 => ClockType::CpuCycle,
            v => ClockType::Other(v),
        }
    }

    /// Ticks of the event clock per second, if known.
    pub fn ticks_per_second(&self) -> Option<u64> {
        match self.clock_type() {
            ClockType::PerformanceCounter => u64::try_from(self.perf_freq).ok().filter(|&f| f > 0),
            ClockType::SystemTime => Some(10_000_000),
            ClockType::CpuCycle => {
                Some(u64::from(self.cpu_speed_mhz) * 1_000_000).filter(|&f| f > 0)
            }
            ClockType::Other(_) => None,
        }
    }
}

/// Reads a NUL-terminated UTF-16 string and advances past it. Ill-formed
/// UTF-16 is replaced; a missing terminator ends the string at the end of
/// the data.
fn utf16z(data: &mut &[u8]) -> String {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    *data = &data[i..];
    String::from_utf16_lossy(&units)
}

//! Formatting of 32-bit Unix timestamps, as found in PE/COFF headers.
//!
//! Output is always UTC, so that it is the same on every host.

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats `secs` since 1970-01-01 UTC like C's `asctime`, without the
/// trailing newline: `Fri Nov  6 22:03:56 2026`.
pub fn asctime_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, rem / 60 % 60, rem % 60);
    // 1970-01-01 was a Thursday.
    let weekday = WEEKDAYS[((days + 4) % 7) as usize];
    let (year, month, day) = civil_from_days(days);
    let month = MONTHS[usize::try_from(month - 1).unwrap_or_default()];
    format!("{weekday} {month} {day:2} {hour:02}:{minute:02}:{second:02} {year}")
}

/// Converts days since 1970-01-01 to a (year, month, day) proleptic
/// Gregorian date. (Howard Hinnant's `civil_from_days`, for non-negative
/// inputs.)
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_times() {
        assert_eq!(asctime_utc(0), "Thu Jan  1 00:00:00 1970");
        assert_eq!(asctime_utc(0x6000_0000), "Thu Jan 14 08:25:36 2021");
        assert_eq!(asctime_utc(0x7FFF_FFFF), "Tue Jan 19 03:14:07 2038");
        assert_eq!(asctime_utc(951_782_400), "Tue Feb 29 00:00:00 2000");
        assert_eq!(asctime_utc(0xFFFF_FFFF), "Sun Feb  7 06:28:15 2106");
    }
}

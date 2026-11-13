//! Standard output, safe for a terminal.
//!
//! What we print comes from hostile files: a symbol, section, or source
//! file name can hold terminal control sequences (an escape that retitles
//! the window, writes the clipboard, or rewrites what was printed) or
//! Unicode's bidirectional overrides (which make text read other than it
//! is). When standard output is a terminal, those are written as visible
//! escapes (`\u{1b}`) instead; anything else (a file, a pipe) gets the
//! bytes as they are.
//!
//! A thread may instead [`capture`] what it writes to both (`hexc serve`
//! runs each request so).

use std::cell::RefCell;
use std::io::{self, IsTerminal, StdoutLock, Write};

/// What a thread wrote while capturing: to standard output and to standard
/// error.
#[derive(Default)]
pub struct Captured {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

thread_local! {
    static CAPTURE: RefCell<Option<Captured>> = const { RefCell::new(None) };
}

/// Runs `f`, keeping what it writes through this module (rather than
/// writing it), and returns that with `f`'s result. What is kept is not
/// cleaned: it goes to a program, not a terminal.
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Captured) {
    /// Puts back the capture that was there before, even if `f` panics.
    struct Restore(Option<Captured>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let outer = self.0.take();
            CAPTURE.with(|c| *c.borrow_mut() = outer);
        }
    }
    let restore = Restore(CAPTURE.with(|c| c.borrow_mut().replace(Captured::default())));
    let r = f();
    let mine = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
    drop(restore);
    (r, mine)
}

/// Appends `data` to this thread's capture, if it is capturing: whether
/// it was.
fn captured(data: &[u8], stderr: bool) -> bool {
    CAPTURE.with(|c| match c.borrow_mut().as_mut() {
        Some(cap) => {
            let to = if stderr {
                &mut cap.stderr
            } else {
                &mut cap.stdout
            };
            to.extend_from_slice(data);
            true
        }
        None => false,
    })
}

/// Standard output (see the module): locked, cleaned if it is a terminal;
/// or this thread's capture.
pub fn stdout() -> Out {
    if CAPTURE.with(|c| c.borrow().is_some()) {
        return Out {
            inner: None,
            clean: false,
            carry: Vec::new(),
        };
    }
    Out {
        inner: Some(io::stdout().lock()),
        clean: io::stdout().is_terminal(),
        carry: Vec::new(),
    }
}

/// Writes `bytes` to standard output (see [`stdout`]) and flushes it;
/// whether they got there. A closed pipe (`| head`) counts as getting
/// there; any other error is reported on standard error: a command whose
/// output was lost must not say it succeeded.
pub fn printed(bytes: &[u8]) -> bool {
    let mut out = stdout();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => true,
        Err(e) => {
            stderr_line(&format!("hexc: writing the output: {e}"));
            false
        }
    }
}

/// [`printed`], as a command's exit status: success, or failure.
pub fn print(bytes: &[u8]) -> std::process::ExitCode {
    if printed(bytes) {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

/// Writes a line to standard error, cleaned as [`stdout`] is if it is a
/// terminal: messages quote what files hold (names, paths they record).
macro_rules! ereport {
    ($($arg:tt)*) => {{
        $crate::out::stderr_line(&format!($($arg)*));
    }};
}

/// A line to standard error (see [`ereport!`]), or this thread's capture.
pub fn stderr_line(text: &str) {
    let mut line = text.as_bytes().to_vec();
    line.push(b'\n');
    if captured(&line, true) {
        return;
    }
    let mut err = io::stderr().lock();
    let _ = if io::stderr().is_terminal() {
        let (cleaned, carry) = clean(&line);
        err.write_all(&cleaned).and_then(|()| err.write_all(carry))
    } else {
        err.write_all(&line)
    };
}

/// Standard output, cleaned if a terminal (see [`stdout`]).
pub struct Out {
    /// Standard output, or (`None`) this thread's capture.
    inner: Option<StdoutLock<'static>>,
    clean: bool,
    /// The start of a UTF-8 sequence that the last write ended in.
    carry: Vec<u8>,
}

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(inner) = &mut self.inner else {
            captured(buf, false);
            return Ok(buf.len());
        };
        if !self.clean {
            return inner.write(buf);
        }
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(buf);
        let (out, carry) = clean(&data);
        self.carry = carry.to_vec();
        inner.write_all(&out)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(inner) = &mut self.inner else {
            return Ok(());
        };
        if !self.carry.is_empty() {
            let carry = std::mem::take(&mut self.carry);
            inner.write_all(&carry)?;
        }
        inner.flush()
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// `data` with control characters and bidirectional overrides escaped;
/// and the incomplete sequence it ends in, if any (to join the next).
pub fn clean(data: &[u8]) -> (Vec<u8>, &[u8]) {
    let mut out = Vec::with_capacity(data.len());
    let escape = |out: &mut Vec<u8>, c: u32| {
        let _ = write!(out, "\\u{{{c:x}}}");
    };
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        match b {
            b'\n' | b'\t' => out.push(b),
            0x00..=0x1F | 0x7F => escape(&mut out, u32::from(b)),
            // C1 controls, U+0080 to U+009F.
            0xC2 => match data.get(i + 1) {
                None => return (out, &data[i..]),
                Some(&c @ 0x80..=0x9F) => {
                    escape(&mut out, u32::from(c));
                    i += 1;
                }
                Some(_) => out.push(b),
            },
            // U+202A to U+202E, U+2066 to U+2069: embeddings, overrides,
            // and isolates.
            0xE2 => match (data.get(i + 1), data.get(i + 2)) {
                (None, _) | (Some(0x80 | 0x81), None) => return (out, &data[i..]),
                (Some(&0x80), Some(&c @ 0xAA..=0xAE)) => {
                    escape(&mut out, 0x2000 + u32::from(c - 0x80));
                    i += 2;
                }
                (Some(&0x81), Some(&c @ 0xA6..=0xA9)) => {
                    escape(&mut out, 0x2040 + u32::from(c - 0x80));
                    i += 2;
                }
                _ => out.push(b),
            },
            _ => out.push(b),
        }
        i += 1;
    }
    (out, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_overrides_are_escaped() {
        let (out, carry) =
            clean("a\u{1b}]52;c;x\u{7}b\r\n\tc\u{85}d\u{202e}e\u{2067}f é ✓".as_bytes());
        assert!(carry.is_empty());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "a\\u{1b}]52;c;x\\u{7}b\\u{d}\n\tc\\u{85}d\\u{202e}e\\u{2067}f é ✓"
        );
        // A sequence split across writes is kept for the next.
        let (out, carry) = clean(b"x\xE2\x80");
        assert_eq!((out.as_slice(), carry), (&b"x"[..], &b"\xE2\x80"[..]));
        let (out, carry) = clean(b"y\xC2");
        assert_eq!((out.as_slice(), carry), (&b"y"[..], &b"\xC2"[..]));
    }
}

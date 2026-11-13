use core::fmt;

/// The broad category of a parse failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The data ends before the item being read.
    Truncated,
    /// An offset or size computation overflowed, or does not fit on this host.
    Overflow,
    /// A signature or magic number did not match.
    BadMagic,
    /// A field holds a value the format does not allow.
    Malformed,
    /// The data is valid but uses a feature we do not handle yet.
    Unsupported,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::Truncated => "truncated",
            ErrorKind::Overflow => "offset overflow",
            ErrorKind::BadMagic => "bad magic",
            ErrorKind::Malformed => "malformed",
            ErrorKind::Unsupported => "unsupported",
        })
    }
}

/// A parse failure: what went wrong, what was being read, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// The offset of the failure, relative to the start of the containing file
    /// or stream when known.
    pub offset: u64,
    /// What was being read.
    pub what: &'static str,
}

impl Error {
    /// A failure of `kind` reading `what`, at `offset`.
    #[inline]
    pub const fn new(kind: ErrorKind, offset: u64, what: &'static str) -> Self {
        Self { kind, offset, what }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} at offset {:#x}",
            self.what, self.kind, self.offset
        )
    }
}

impl core::error::Error for Error {}

/// A result of reading, or what went wrong.
pub type Result<T> = core::result::Result<T, Error>;

//! Why a program couldn't be opened or analyzed.

use std::fmt;
use std::path::PathBuf;

use hexcavator_size::pe::Unsupported;

/// Why a program couldn't be opened or analyzed. Each names the file it is
/// about; as text, it reads `path: what` (as the command line prints it).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A file couldn't be read.
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        error: std::io::Error,
    },
    /// A file isn't what it should be (or its debug information couldn't
    /// be read).
    Format {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        error: hexcavator_core::Error,
    },
    /// The image can't be analyzed (managed code; a `/DEBUG:FASTLINK`
    /// PDB; debug information of another image).
    Unsupported {
        /// The image.
        path: PathBuf,
        /// Why.
        why: Unsupported,
    },
    /// No debug information that matches the image was found.
    NoDebug {
        /// The image.
        path: PathBuf,
        /// What it would be: `PDB` for a PE image.
        what: &'static str,
        /// What was tried, and why each didn't do (empty: the image names
        /// none).
        tried: Vec<String>,
    },
    /// No datum has the name asked for.
    NoDatum {
        /// The image.
        path: PathBuf,
        /// The name.
        name: String,
    },
    /// The name asked for is code's, not data's.
    IsCode {
        /// The image.
        path: PathBuf,
        /// The name.
        name: String,
    },
}

/// The option that gives a command the debug information `what` names.
fn option_for(what: &str) -> &'static str {
    if what == "PDB" { "-pdb" } else { "-debug" }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Error::Format { path, error } => write!(f, "{}: {error}", path.display()),
            Error::Unsupported { path, why } => write!(f, "{}: {why}", path.display()),
            Error::NoDebug { path, what, tried } if tried.is_empty() => write!(
                f,
                "{}: the image has no debug information and names no {what}; give one with {}",
                path.display(),
                option_for(what)
            ),
            Error::NoDebug { path, what, tried } => write!(
                f,
                "{}: no matching {what} found; tried {}; give one with {}",
                path.display(),
                tried.join(", "),
                option_for(what)
            ),
            Error::NoDatum { path, name } => {
                write!(f, "{}: no datum named '{name}'", path.display())
            }
            Error::IsCode { path, name } => write!(
                f,
                "{}: '{name}' is code: see hexc size -disassemble",
                path.display()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { error, .. } => Some(error),
            Error::Format { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// For callers that report errors as text.
impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}

impl Error {
    pub(crate) fn io(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
        move |error| Error::Io {
            path: path.to_path_buf(),
            error,
        }
    }

    pub(crate) fn format(
        path: &std::path::Path,
    ) -> impl FnOnce(hexcavator_core::Error) -> Error + '_ {
        move |error| Error::Format {
            path: path.to_path_buf(),
            error,
        }
    }
}

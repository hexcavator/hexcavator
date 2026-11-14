//! `hexc symbolize`: the function, source line, and inlined functions at
//! addresses of images; or the same added to the addresses in text (a log,
//! a stack trace).

use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use hexcavator_debuginfo::{DebugInfo, Frame, Locator};
use hexcavator_image::{Image, ImageSymbol};
use hexcavator_mmap::Mmap;
use serde_json::{Value, json};

pub const USAGE: &str = "\
usage: hexc symbolize [options] <image>[@<base>]... [<address>...]

The function, source line, and inlined functions at each address, from the
image's debug information (or, without any, its own symbols: exports and
symbol tables):

  hexc symbolize app.exe 0x140001043
  hexc symbolize app.exe@0x7ff6a1b20000 0x7ff6a1b21043
  hexc symbolize libfoo.so libfoo.so+0x1a2b

Without addresses, it reads text (a log, a stack trace) from standard input
and writes it out with where each address in it is added after it:

  hexc symbolize app.exe@0x7ff6a1b20000 helper.dll@0x7ffb10c40000 < crash.txt

An address is hexadecimal (0x optional), as the image's tools show it (a PE
image's with its preferred base added); with @<base>, as loaded at <base>.
<name>+0x<offset> is an offset from the start of the image named <name>
(its file name, with or without the extension). In text, a number counts as
an address if it is in an image (as loaded); so does one followed by an
image's name and less than its size (an offset: Android's `pc 4a7b8
libc.so`); and so do name+0x<offset> and name(+0x<offset>) (glibc's).

options:
  -offset          addresses are offsets from the (first) image's start
  -return          addresses are return addresses: where the call before
                   each is (the address less one, looked up)
  -input <file>    the text to read, instead of standard input
  -pdb <path>      the (first) image's debug information: a PDB, or a file
                   with its DWARF (or -debug; default: its own, or the one
                   it names)
  -json            each address and its frames as JSON";

pub fn run(args: &[String]) -> ExitCode {
    match parse(args) {
        Ok(o) => symbolize(&o),
        Err(e) => {
            ereport!("hexc symbolize: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

struct Options {
    images: Vec<(String, Option<u64>)>,
    addresses: Vec<String>,
    offset: bool,
    ret: bool,
    json: bool,
    input: Option<String>,
    pdb: Option<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        images: Vec::new(),
        addresses: Vec::new(),
        offset: false,
        ret: false,
        json: false,
        input: None,
        pdb: None,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-offset" | "/offset" => o.offset = true,
            "-return" | "/return" => o.ret = true,
            "-json" | "/json" => o.json = true,
            "-input" | "/input" => o.input = Some(it.next().ok_or("-input needs a file")?.clone()),
            "-pdb" | "/pdb" | "-debug" | "/debug" => {
                o.pdb = Some(it.next().ok_or("-pdb needs a path")?.clone());
            }
            s if s.starts_with('-') && s.len() > 1 && !is_address(s) => {
                return Err(format!("unknown option '{s}'"));
            }
            // The first is an image; after it, addresses are addresses
            // (images aren't named like them).
            s if !o.images.is_empty() && is_address(s) => o.addresses.push(s.to_string()),
            s => o.images.push(image_spec(s)?),
        }
    }
    if o.images.is_empty() {
        return Err("no image given".into());
    }
    if o.json && o.addresses.is_empty() {
        return Err("-json needs addresses (text read is written as text)".into());
    }
    if !o.addresses.is_empty() && o.input.is_some() {
        return Err("give addresses or -input, not both".into());
    }
    Ok(o)
}

/// An image argument: its path, and the base it was loaded at
/// (`path@base`), unless the whole of it names a file.
fn image_spec(s: &str) -> Result<(String, Option<u64>), String> {
    if let Some((path, base)) = s.rsplit_once('@')
        && !Path::new(s).exists()
    {
        let base = hex(base).ok_or_else(|| format!("'{base}' is not a base address"))?;
        return Ok((path.to_string(), Some(base)));
    }
    Ok((s.to_string(), None))
}

/// A hexadecimal number (`0x` optional).
fn hex(s: &str) -> Option<u64> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
        .replace('`', "");
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

/// Whether `s` is an address argument: a number, or name+0xoffset.
fn is_address(s: &str) -> bool {
    hex(s).is_some()
        || s.rsplit_once('+')
            .is_some_and(|(name, off)| !name.is_empty() && hex(off).is_some())
}

/// An image opened: with its debug information, or without.
enum Opened {
    Debug(hexcavator_program::Opened),
    Plain(Mmap),
}

impl Opened {
    fn data(&self) -> &[u8] {
        match self {
            Opened::Debug(o) => o.data(),
            Opened::Plain(m) => m,
        }
    }
}

/// An image to find addresses in.
struct Module<'a> {
    /// Its file name.
    name: String,
    image: Image<'a>,
    /// Its extent in memory (as its tools have addresses), if it has one.
    extent: Option<(u64, u64)>,
    /// Where it was loaded.
    base: Option<u64>,
    locator: Option<Locator<'a, 'a>>,
    /// Its own symbols (read when first needed).
    symbols: Option<Vec<ImageSymbol<'a>>>,
}

impl Module<'_> {
    /// Its extent as loaded (or as its tools have it, without a base).
    fn loaded(&self) -> Option<(u64, u64)> {
        let (start, end) = self.extent?;
        match self.base {
            Some(b) => Some((b, b.checked_add(end - start)?)),
            None => Some((start, end)),
        }
    }

    /// Whether `name` names it: its file name, or that without its
    /// extension (case aside).
    fn named(&self, name: &str) -> bool {
        let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let own = &self.name;
        let stem = own.rsplit_once('.').map_or(own.as_str(), |(s, _)| s);
        name.eq_ignore_ascii_case(own) || name.eq_ignore_ascii_case(stem)
    }

    /// The address its debug information (and the image crate) has for
    /// the address `at`, which is `offset`s from its start, or as loaded.
    fn address(&self, at: Address) -> Option<u64> {
        let (start, end) = self.extent?;
        let va = match at {
            Address::Offset(o) => start.checked_add(o)?,
            Address::Loaded(a) => match self.base {
                Some(b) => a.checked_sub(b)?.checked_add(start)?,
                None => a,
            },
        };
        let _ = end;
        va.checked_sub(self.image.image_base())
    }
}

/// An address given: an offset from an image's start, or an address (as
/// loaded, if the image was given a base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Address {
    Offset(u64),
    Loaded(u64),
}

fn symbolize(o: &Options) -> ExitCode {
    let done = with_modules(o, |modules, demangler| {
        if !o.addresses.is_empty() {
            return addresses(o, modules, demangler);
        }
        // Text: from a file, or standard input (not a server's: it is its
        // requests).
        let mut out = io::BufWriter::new(crate::out::stdout());
        let result = match &o.input {
            Some(path) => match std::fs::File::open(path) {
                Ok(f) => filter(io::BufReader::new(f), &mut out, modules, o.ret, demangler),
                Err(e) => {
                    ereport!("hexc symbolize: {path}: {e}");
                    return ExitCode::FAILURE;
                }
            },
            None if crate::out::capturing() => {
                ereport!("hexc symbolize: no addresses or -input given");
                return ExitCode::from(2);
            }
            None => filter(io::stdin().lock(), &mut out, modules, o.ret, demangler),
        };
        match result.and_then(|()| out.flush()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(e) => {
                ereport!("hexc symbolize: {e}");
                ExitCode::FAILURE
            }
        }
    });
    done.unwrap_or_else(|e| {
        ereport!("hexc symbolize: {e}");
        ExitCode::FAILURE
    })
}

/// `text` (a log, a stack trace) with where each address in it is added
/// after it, in the images `images` (paths, each `path@base` if loaded at
/// a base): what `hexc symbolize` without addresses writes.
pub(crate) fn annotate_text(images: &[String], text: &str) -> Result<String, String> {
    let o = Options {
        images: images
            .iter()
            .map(|i| image_spec(i))
            .collect::<Result<_, _>>()?,
        addresses: Vec::new(),
        offset: false,
        ret: false,
        json: false,
        input: None,
        pdb: None,
    };
    if o.images.is_empty() {
        return Err("no image given".into());
    }
    with_modules(&o, |modules, demangler| {
        let mut out = Vec::new();
        filter(io::Cursor::new(text), &mut out, modules, false, demangler)
            .map_err(|e| e.to_string())?;
        String::from_utf8(out).map_err(|e| e.to_string())
    })?
}

/// Opens the images `o` names (each with its debug information, if it is
/// found) and runs `f` with them.
fn with_modules<R>(
    o: &Options,
    f: impl FnOnce(&mut [Module<'_>], &mut Demangler) -> R,
) -> Result<R, String> {
    let mut opened = Vec::with_capacity(o.images.len());
    for (i, (path, _)) in o.images.iter().enumerate() {
        let pdb = o.pdb.as_deref().filter(|_| i == 0).map(Path::new);
        match hexcavator_program::Opened::open(Path::new(path), pdb) {
            Ok(x) => opened.push(Opened::Debug(x)),
            Err(e) if pdb.is_some() => return Err(e.to_string()),
            Err(_) => match Mmap::open(path) {
                Ok(m) => opened.push(Opened::Plain(m)),
                Err(e) => return Err(format!("{path}: {e}")),
            },
        }
    }
    let debug: Vec<Option<DebugInfo<'_>>> = opened
        .iter()
        .map(|x| match x {
            Opened::Debug(d) => d.debug_info().ok(),
            Opened::Plain(_) => None,
        })
        .collect();
    let mut modules = Vec::with_capacity(opened.len());
    for ((x, d), (path, base)) in opened.iter().zip(&debug).zip(&o.images) {
        let image = Image::parse(x.data()).map_err(|e| format!("{path}: {e}"))?;
        let name = Path::new(path)
            .file_name()
            .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
        modules.push(Module {
            name,
            extent: image.extent(),
            image,
            base: *base,
            locator: d.as_ref().map(DebugInfo::locator),
            symbols: None,
        });
    }
    Ok(f(&mut modules, &mut Demangler::default()))
}

/// The module and address an address argument names.
fn resolve(arg: &str, modules: &[Module<'_>], offset: bool) -> Result<(usize, Address), String> {
    if let Some(v) = hex(arg) {
        if offset {
            return Ok((0, Address::Offset(v)));
        }
        // The image it is in; else the first.
        let m = modules
            .iter()
            .position(|m| m.loaded().is_some_and(|(s, e)| v >= s && v < e))
            .unwrap_or(0);
        return Ok((m, Address::Loaded(v)));
    }
    let (name, off) = arg.rsplit_once('+').ok_or("not an address")?;
    let off = hex(off).ok_or("not an address")?;
    let m = modules
        .iter()
        .position(|m| m.named(name))
        .ok_or_else(|| format!("{arg}: no image named '{name}' was given"))?;
    Ok((m, Address::Offset(off)))
}

/// The frames at `at` in module `m` (looked up at `at - 1` for a return
/// address), with the outermost frame's offset from its function's start.
fn frames_at(m: &mut Module<'_>, at: Address, ret: bool, demangler: &mut Demangler) -> Vec<Shown> {
    let Some(addr) = m.address(at) else {
        return Vec::new();
    };
    let look = if ret { addr.saturating_sub(1) } else { addr };
    // Where the debug information has nothing (assembly code, say), the
    // image's own symbols; but not a PE image's with a PDB, whose public
    // symbols are those (and padding between functions isn't theirs).
    let mut frames = m
        .locator
        .as_mut()
        .map(|l| l.frames(look))
        .unwrap_or_default();
    if frames.is_empty() && !(m.locator.is_some() && m.image.pe().is_some()) {
        frames.extend(image_symbol(m, look));
    }
    frames
        .into_iter()
        .map(|f| {
            let name = if f.function.is_empty() {
                "??".to_string()
            } else if f.decorated {
                demangler.name(&f.function, m.image.macho().is_some())
            } else {
                f.function.clone()
            };
            Shown {
                offset: f.start.and_then(|s| addr.checked_sub(s)),
                name,
                frame: f,
            }
        })
        .collect()
}

/// A frame to show: its name (demangled), and its offset into its
/// function.
struct Shown {
    name: String,
    offset: Option<u64>,
    frame: Frame,
}

impl Shown {
    /// `name+0x12` (or the name alone, at the function's start or inlined).
    fn function(&self) -> String {
        match self.offset {
            Some(o) if o > 0 && !self.frame.inlined => format!("{}+{o:#x}", self.name),
            _ => self.name.clone(),
        }
    }

    fn place(&self) -> Option<String> {
        let file = self.frame.file.as_deref().filter(|f| !f.is_empty())?;
        Some(match self.frame.line {
            0 => file.to_string(),
            n => format!("{file}:{n}"),
        })
    }
}

/// The image's own symbol at `addr` (the last at or before it, if `addr`
/// is within its size, or, without one, before the next symbol in the same
/// section).
fn image_symbol(m: &mut Module<'_>, addr: u64) -> Option<Frame> {
    let image = &m.image;
    let symbols = m.symbols.get_or_insert_with(|| image.symbols());
    let i = symbols.partition_point(|s| s.addr <= addr);
    let s = symbols.get(i.checked_sub(1)?)?;
    let within = match s.size {
        Some(n) => addr - s.addr < n,
        None => {
            let sections = image.sections();
            let section = |a: u64| {
                sections
                    .iter()
                    .position(|x| x.vm_size > 0 && a >= x.addr && a - x.addr < x.vm_size)
            };
            let next = symbols.get(i).map(|n| n.addr);
            section(addr).is_some()
                && section(addr) == section(s.addr)
                && next.is_none_or(|n| addr < n)
        }
    };
    within.then(|| Frame {
        function: String::from_utf8_lossy(s.name).into_owned(),
        decorated: true,
        start: Some(s.addr),
        ..Frame::default()
    })
}

/// Names as linked, demangled.
#[derive(Default)]
struct Demangler {
    msvc: hexcavator_demangle::msvc::Demangler,
    itanium: hexcavator_demangle::itanium::Demangler,
}

impl Demangler {
    /// `name` demangled: a Microsoft C++ name's qualified name, another's
    /// in full; a C name as is (a Mach-O one without its leading `_`).
    fn name(&mut self, name: &str, macho: bool) -> String {
        if name.starts_with('?') {
            let flags = hexcavator_demangle::msvc::flags::NAME_ONLY;
            if let Some(n) = self.msvc.demangle(name, flags) {
                return n;
            }
        }
        if let Some(n) = self.itanium.demangle(name) {
            return n;
        }
        match name.strip_prefix('_') {
            Some(c) if macho => c.to_string(),
            _ => name.to_string(),
        }
    }
}

/// Answers the address arguments.
fn addresses(o: &Options, modules: &mut [Module<'_>], demangler: &mut Demangler) -> ExitCode {
    let several = modules.len() > 1;
    let mut text = String::new();
    let mut all = Vec::new();
    let mut status = ExitCode::SUCCESS;
    // Looked up in address order (each module or unit read once, however
    // many addresses are in it), shown in the order given.
    let mut resolved = Vec::with_capacity(o.addresses.len());
    for (i, arg) in o.addresses.iter().enumerate() {
        match resolve(arg, modules, o.offset) {
            Ok((m, at)) => resolved.push((m, modules[m].address(at), at, i)),
            Err(e) => {
                ereport!("hexc symbolize: {e}");
                status = ExitCode::FAILURE;
            }
        }
    }
    resolved.sort_unstable_by_key(|&(m, addr, _, i)| (m, addr, i));
    let mut answers: Vec<(usize, usize, Vec<Shown>)> = resolved
        .into_iter()
        .map(|(m, _, at, i)| (i, m, frames_at(&mut modules[m], at, o.ret, demangler)))
        .collect();
    answers.sort_unstable_by_key(|a| a.0);
    for (i, m, shown) in answers {
        let arg = &o.addresses[i];
        let module = &modules[m];
        if o.json {
            all.push(json!({
                "address": arg,
                "module": module.name,
                "frames": shown.iter().map(|s| json!({
                    "function": s.name,
                    "offset": s.offset.filter(|_| !s.frame.inlined),
                    "file": s.frame.file,
                    "line": (s.frame.line > 0).then_some(s.frame.line),
                    "inlined": s.frame.inlined,
                })).collect::<Vec<Value>>(),
            }));
            continue;
        }
        let prefix = |s: &Shown| {
            if several && !s.frame.inlined {
                format!("{}!{}", module.name, s.function())
            } else {
                s.function()
            }
        };
        if shown.is_empty() {
            let _ = writeln!(text, "{arg}  ?? (nothing in {} there)", module.name);
            continue;
        }
        let width = shown
            .iter()
            .map(|s| prefix(s).chars().count())
            .max()
            .unwrap_or(0);
        for (i, s) in shown.iter().enumerate() {
            let lead = if i == 0 { arg.as_str() } else { "" };
            let mut line = format!("{lead:<w$}  {:<width$}", prefix(s), w = arg.len());
            if let Some(p) = s.place() {
                let _ = write!(line, "  {p}");
            }
            if s.frame.inlined {
                line.push_str("  (inlined)");
            }
            let _ = writeln!(text, "{}", line.trim_end());
        }
    }
    if o.json {
        text = format!(
            "{}\n",
            serde_json::to_string_pretty(&Value::Array(all)).unwrap_or_default()
        );
    }
    if !crate::out::printed(text.as_bytes()) {
        status = ExitCode::FAILURE;
    }
    status
}

/// The longest line read whole: longer ones are copied unannotated.
const MAX_LINE: usize = 1 << 20;

/// Copies `input` to `out`, a line at a time, with each address in it
/// followed by where it is.
fn filter(
    mut input: impl BufRead,
    out: &mut impl Write,
    modules: &mut [Module<'_>],
    ret: bool,
    demangler: &mut Demangler,
) -> io::Result<()> {
    let tokens = regex::Regex::new(concat!(
        // name+0xoffset, and glibc's name(+0xoffset)
        r"(?P<name>[A-Za-z0-9_.\-]+)(?:\+0x(?P<off>[0-9A-Fa-f]{1,16})\b|\(\+0x(?P<goff>[0-9A-Fa-f]{1,16})\))",
        // a number (0x optional; WinDbg's ` too)
        r"|\b(?P<num>(?:0[xX])?[0-9A-Fa-f]{1,8}(?:`?[0-9A-Fa-f]{8})?)\b",
        // and what follows it: whitespace and a path
        r"(?P<after>\s+[^\s()\[\]]+)?",
    ))
    .map_err(io::Error::other)?;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = io::Read::take(&mut input, MAX_LINE as u64).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        if n == MAX_LINE && !line.ends_with(b"\n") {
            out.write_all(&line)?;
            continue;
        }
        out.write_all(annotate(&text, &tokens, modules, ret, demangler).as_bytes())?;
        // (A log being followed: each line as it comes.)
        out.flush()?;
    }
    out.flush()
}

/// `line` with where each address in it is added after it.
fn annotate(
    line: &str,
    tokens: &regex::Regex,
    modules: &mut [Module<'_>],
    ret: bool,
    demangler: &mut Demangler,
) -> String {
    let mut out = String::with_capacity(line.len() + 64);
    let mut copied = 0;
    for c in tokens.captures_iter(line) {
        let found = if let Some(name) = c.name("name") {
            let off = c
                .name("off")
                .or(c.name("goff"))
                .and_then(|o| hex(o.as_str()));
            let m = modules.iter().position(|m| m.named(name.as_str()));
            m.zip(off)
                .map(|(m, o)| (m, Address::Offset(o), c.get(0).map_or(0, |x| x.end())))
        } else if let Some(num) = c.name("num") {
            let v = hex(num.as_str());
            let after = c.name("after").map(|a| a.as_str().trim());
            v.and_then(|v| {
                // In an image as loaded; or an offset, before its name.
                if let Some(m) = modules
                    .iter()
                    .position(|m| m.loaded().is_some_and(|(s, e)| v >= s && v < e))
                {
                    return Some((m, Address::Loaded(v), num.end()));
                }
                let m = modules
                    .iter()
                    .position(|m| after.is_some_and(|a| m.named(a)))?;
                let (s, e) = modules[m].extent?;
                (v < e - s).then_some((m, Address::Offset(v), num.end()))
            })
        } else {
            None
        };
        let Some((m, at, end)) = found else { continue };
        let shown = frames_at(&mut modules[m], at, ret, demangler);
        if shown.is_empty() {
            continue;
        }
        out.push_str(&line[copied..end]);
        copied = end;
        let several = modules.len() > 1;
        let parts: Vec<String> = shown
            .iter()
            .map(|s| {
                let f = if several && !s.frame.inlined {
                    format!("{}!{}", modules[m].name, s.function())
                } else {
                    s.function()
                };
                match s.place() {
                    Some(p) => format!("{f} ({p})"),
                    None => f,
                }
            })
            .collect();
        let _ = write!(out, " [{}]", parts.join(", inlined in "));
    }
    out.push_str(&line[copied..]);
    out
}

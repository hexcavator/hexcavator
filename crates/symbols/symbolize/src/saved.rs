//! A [`FunctionTable`] cut down to the addresses one trace needs, and
//! saved: so that reopening the trace names its functions without its
//! PDBs (which are large, and slow to read).

use hexcavator_core::{Error, ErrorKind, Reader, Result};

use crate::FunctionTable;

/// The saved form's magic and version.
const MAGIC: &[u8; 4] = b"HXFT";
const VERSION: u32 = 1;

impl FunctionTable {
    /// The part of this table that answers for `rvas`: a lookup of any of
    /// them ([`FunctionTable::function`], [`FunctionTable::inlines`],
    /// [`FunctionTable::line`]), or of the start of a function one of them
    /// is in, gives what this table gives. (Inline sites are numbered
    /// anew, in the same order, so [`FunctionTable::site_name`] answers
    /// for the sites the subset's lookups give.)
    pub fn subset(&self, rvas: &[u32]) -> Self {
        let mut rvas = rvas.to_vec();
        rvas.sort_unstable();
        rvas.dedup();
        // A lookup reads the last entry starting at or before its address:
        // keeping that one for each address keeps every answer.
        let last_at = |starts: &dyn Fn(usize) -> u32, len: usize, rva: u32| {
            let (mut lo, mut hi) = (0, len);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if starts(mid) <= rva {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            lo.checked_sub(1)
        };
        let mut keep_entries = vec![false; self.entries.len()];
        let mut keep_lines = vec![false; self.lines.len()];
        let mut keep_inlines = vec![false; self.inlines.len()];
        for &rva in &rvas {
            if let Some(i) = last_at(&|i| self.entries[i].0, self.entries.len(), rva) {
                keep_entries[i] = true;
            }
            if let Some(i) = last_at(&|i| self.lines[i].0, self.lines.len(), rva) {
                keep_lines[i] = true;
            }
            // The inline ranges that cover the address, within its
            // function (those are what `inlines` reads).
            if let Some((start, _)) = self.function(rva) {
                let lo = self.inlines.partition_point(|r| r.0 < start);
                let hi = self.inlines.partition_point(|r| r.0 <= rva);
                for (k, r) in self.inlines[lo..hi].iter().enumerate() {
                    if rva < r.1 {
                        keep_inlines[lo + k] = true;
                    }
                }
            }
        }
        let entries = self
            .entries
            .iter()
            .zip(&keep_entries)
            .filter(|(_, k)| **k)
            .map(|(e, _)| e.clone())
            .collect();
        // Sites renumbered in their old order (so that `inlines`, which
        // prefers the lowest site at a depth, prefers the same one).
        let mut used: Vec<u32> = self
            .inlines
            .iter()
            .zip(&keep_inlines)
            .filter(|(_, k)| **k)
            .map(|(r, _)| r.3)
            .collect();
        used.sort_unstable();
        used.dedup();
        let renumber =
            |site: u32| u32::try_from(used.binary_search(&site).unwrap_or(0)).unwrap_or(0);
        let inlines = self
            .inlines
            .iter()
            .zip(&keep_inlines)
            .filter(|(_, k)| **k)
            .map(|(r, _)| (r.0, r.1, r.2, renumber(r.3)))
            .collect();
        let site_names = used
            .iter()
            .map(|&s| self.site_names.get(s as usize).cloned().unwrap_or_default())
            .collect();
        // Lines keep their files, renumbered the same way.
        let mut files: Vec<u32> = self
            .lines
            .iter()
            .zip(&keep_lines)
            .filter(|(_, k)| **k)
            .map(|(l, _)| l.2)
            .collect();
        files.sort_unstable();
        files.dedup();
        let lines = self
            .lines
            .iter()
            .zip(&keep_lines)
            .filter(|(_, k)| **k)
            .map(|(l, _)| {
                let f = u32::try_from(files.binary_search(&l.2).unwrap_or(0)).unwrap_or(0);
                (l.0, l.1, f, l.3)
            })
            .collect();
        let files = files
            .iter()
            .map(|&f| self.files.get(f as usize).cloned().unwrap_or_default())
            .collect();
        Self {
            entries,
            inlines,
            site_names,
            lines,
            files,
        }
    }

    /// The table, saved: read back by [`FunctionTable::from_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put(&mut out, VERSION);
        let count = |out: &mut Vec<u8>, n: usize| put(out, u32::try_from(n).unwrap_or(u32::MAX));
        let string = |out: &mut Vec<u8>, s: &str| {
            count(out, s.len());
            out.extend_from_slice(s.as_bytes());
        };
        count(&mut out, self.entries.len());
        for (start, end, name) in &self.entries {
            put(&mut out, *start);
            put(&mut out, *end);
            string(&mut out, name);
        }
        for quads in [&self.inlines, &self.lines] {
            count(&mut out, quads.len());
            for &(a, b, c, d) in quads {
                for v in [a, b, c, d] {
                    put(&mut out, v);
                }
            }
        }
        for strings in [&self.site_names, &self.files] {
            count(&mut out, strings.len());
            for s in strings {
                string(&mut out, s);
            }
        }
        out
    }

    /// Reads a table saved by [`FunctionTable::to_bytes`]. A damaged one
    /// is an error, never a table that answers wrongly or panics: its
    /// ranges must be sorted and its sites and files must exist.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        if r.bytes(4)? != MAGIC {
            return Err(Error::new(ErrorKind::BadMagic, 0, "saved function table"));
        }
        if r.u32_le()? != VERSION {
            return Err(Error::new(
                ErrorKind::Unsupported,
                4,
                "saved function table version",
            ));
        }
        let malformed = |r: &Reader<'_>, what| Error::new(ErrorKind::Malformed, r.offset(), what);
        // Each count is checked against what's left, so a damaged count
        // can't ask for a huge allocation.
        let count = |r: &mut Reader<'_>, min: usize| -> Result<usize> {
            let n = r.u32_le()? as usize;
            if n.saturating_mul(min) > r.remaining().len() {
                return Err(Error::new(
                    ErrorKind::Truncated,
                    r.offset(),
                    "saved function table",
                ));
            }
            Ok(n)
        };
        let string = |r: &mut Reader<'_>| -> Result<String> {
            let n = r.u32_le()? as usize;
            let at = r.offset();
            std::str::from_utf8(r.bytes(n)?)
                .map(str::to_string)
                .map_err(|_| Error::new(ErrorKind::Malformed, at, "saved function name"))
        };
        let n = count(&mut r, 12)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let (start, end) = (r.u32_le()?, r.u32_le()?);
            entries.push((start, end, string(&mut r)?));
        }
        let mut quads = [Vec::new(), Vec::new()];
        for q in &mut quads {
            let n = count(&mut r, 16)?;
            q.reserve(n);
            for _ in 0..n {
                q.push((r.u32_le()?, r.u32_le()?, r.u32_le()?, r.u32_le()?));
            }
        }
        let [inlines, lines] = quads;
        let mut strings = [Vec::new(), Vec::new()];
        for s in &mut strings {
            let n = count(&mut r, 4)?;
            s.reserve(n);
            for _ in 0..n {
                s.push(string(&mut r)?);
            }
        }
        let [site_names, files] = strings;
        if !r.is_empty() {
            return Err(malformed(&r, "saved function table (trailing bytes)"));
        }
        let sorted = entries.windows(2).all(|w| w[0].0 <= w[1].0)
            && inlines.windows(2).all(|w| w[0].0 <= w[1].0)
            && lines.windows(2).all(|w| w[0].0 <= w[1].0);
        let in_range = inlines.iter().all(|i| (i.3 as usize) < site_names.len())
            && lines.iter().all(|l| (l.2 as usize) < files.len());
        if !sorted || !in_range {
            return Err(malformed(&r, "saved function table"));
        }
        Ok(Self {
            entries,
            inlines,
            site_names,
            lines,
            files,
        })
    }
}

fn put(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

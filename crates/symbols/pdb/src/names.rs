//! The `/names` string table: NUL-terminated strings referenced by offset,
//! with a hash table for lookup by value.

use hexcavator_core::{Error, ErrorKind, Reader, Result, U32Le, cstr_at};

use crate::hash::{hash_v1, hash_v2};

const MAGIC: u32 = 0xEFFE_EFFE;

#[derive(Debug)]
pub struct StringTable<'s> {
    version: u32,
    strings: &'s [u8],
    buckets: &'s [U32Le],
}

impl<'s> StringTable<'s> {
    pub fn parse(data: &'s [u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self {
                version: 1,
                strings: &[],
                buckets: &[],
            });
        }
        let mut r = Reader::new(data);
        if r.u32_le()? != MAGIC {
            return Err(Error::new(ErrorKind::BadMagic, 0, "string table"));
        }
        let version = r.u32_le()?;
        let len = r.u32_le()? as usize;
        let strings = r.bytes(len)?;
        let count = r.u32_le()? as usize;
        let buckets = r.read_slice(count)?;
        Ok(Self {
            version,
            strings,
            buckets,
        })
    }

    /// The string at `offset`.
    pub fn get(&self, offset: u32) -> Option<&'s [u8]> {
        cstr_at(self.strings, u64::from(offset)).ok()
    }

    pub fn get_str(&self, offset: u32) -> Option<&'s str> {
        self.get(offset).and_then(|s| std::str::from_utf8(s).ok())
    }

    /// The offset of `name`, found through the hash table.
    pub fn find(&self, name: &[u8]) -> Option<u32> {
        let count = self.buckets.len();
        if count == 0 {
            return None;
        }
        let hash = if self.version == 2 {
            hash_v2(name)
        } else {
            hash_v1(name)
        };
        let start = hash as usize % count;
        for probe in 0..count {
            let offset = self.buckets[(start + probe) % count].get();
            if offset == 0 {
                return None;
            }
            if self.get(offset) == Some(name) {
                return Some(offset);
            }
        }
        None
    }

    /// All strings with their offsets.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &'s [u8])> + '_ {
        self.buckets
            .iter()
            .filter(|b| b.get() != 0)
            .filter_map(|b| Some((b.get(), self.get(b.get())?)))
    }
}

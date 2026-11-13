//! The global (GSI) and public (PSI) symbol hash tables.
//!
//! Both index records in the symbol record stream by name: 4096 buckets,
//! keyed by `hash_v1(name) % 4096`. The publics stream adds an address map:
//! the public symbols sorted by section and offset.

use hexcavator_core::{Error, ErrorKind, I32Le, Reader, Result, U32Le, pod, read_at};

use crate::hash::hash_v1;
use hexcavator_codeview::symbols::{Symbol, SymbolRecord};

const BUCKETS: usize = 4096;
const GSI_SIGNATURE: u32 = 0xFFFF_FFFF;
const GSI_V70: u32 = 0xEFFE_0000 + 19_990_810;

pod! {
    #[derive(Debug)]
    pub struct GsiHeader {
        pub signature: U32Le,
        pub version: U32Le,
        pub records_size: U32Le,
        pub buckets_size: U32Le,
    }

    /// A hash record: the offset (plus one) of a symbol in the record stream.
    #[derive(Debug)]
    pub struct HashRecord {
        pub offset: I32Le,
        pub cref: I32Le,
    }

    #[derive(Debug)]
    pub struct PsiHeader {
        pub sym_hash_size: U32Le,
        pub addr_map_size: U32Le,
        pub num_thunks: U32Le,
        pub size_of_thunk: U32Le,
        pub isect_thunk_table: hexcavator_core::U16Le,
        pub padding: hexcavator_core::U16Le,
        pub off_thunk_table: U32Le,
        pub num_sections: U32Le,
    }
}

/// A name-to-symbol hash table over the symbol record stream.
#[derive(Debug)]
pub struct SymbolHash<'s> {
    records: &'s [HashRecord],
    /// For each bucket, the index of its first record (`records.len()` if
    /// empty), plus a sentinel.
    starts: Vec<u32>,
}

impl<'s> SymbolHash<'s> {
    pub fn parse(data: &'s [u8]) -> Result<Self> {
        let header: &GsiHeader = read_at(data, 0)?;
        if header.signature.get() != GSI_SIGNATURE || header.version.get() != GSI_V70 {
            return Err(Error::new(ErrorKind::Unsupported, 0, "GSI hash version"));
        }
        let mut r = Reader::new(data);
        r.skip(size_of::<GsiHeader>())?;
        let records: &[HashRecord] = r.read_slice(header.records_size.get() as usize / 8)?;
        let buckets = r.bytes(header.buckets_size.get() as usize)?;
        // A bitmap of non-empty buckets (4097 bits, padded to u32s), then
        // one offset per non-empty bucket. Offsets count 12-byte in-memory
        // records, so divide by 12 to get an index.
        let mut br = Reader::new(buckets);
        let bitmap: &[U32Le] = br.read_slice((BUCKETS + 1).div_ceil(32))?;
        let mut starts = vec![records.len() as u32; BUCKETS + 1];
        let mut present = Vec::new();
        for b in 0..BUCKETS {
            if bitmap[b / 32].get() & (1 << (b % 32)) != 0 {
                present.push(b);
            }
        }
        for &b in &present {
            starts[b] = br.u32_le()? / 12;
        }
        // Empty buckets start where the next non-empty one does.
        for b in (0..BUCKETS).rev() {
            if !present.binary_search(&b).is_ok() {
                starts[b] = starts[b + 1];
            }
        }
        Ok(Self { records, starts })
    }

    pub fn records(&self) -> &'s [HashRecord] {
        self.records
    }

    /// Offsets (into the symbol record stream) of the symbols in `name`'s
    /// bucket.
    pub fn bucket(&self, name: &[u8]) -> impl Iterator<Item = u32> + '_ {
        let b = hash_v1(name) as usize % BUCKETS;
        let (s, e) = (self.starts[b] as usize, self.starts[b + 1] as usize);
        self.records
            .get(s..e.min(self.records.len()))
            .unwrap_or(&[])
            .iter()
            .map(|r| (r.offset.get() - 1) as u32)
    }
}

/// The publics stream: a name hash and an address map.
#[derive(Debug)]
pub struct PublicsStream<'s> {
    pub header: &'s PsiHeader,
    pub hash: SymbolHash<'s>,
    addr_map: &'s [U32Le],
}

impl<'s> PublicsStream<'s> {
    pub fn parse(data: &'s [u8]) -> Result<Self> {
        let header: &PsiHeader = read_at(data, 0)?;
        let hash_start = size_of::<PsiHeader>();
        let hash_end = hash_start + header.sym_hash_size.get() as usize;
        let hash = SymbolHash::parse(data.get(hash_start..hash_end).ok_or(Error::new(
            ErrorKind::Truncated,
            0,
            "PSI",
        ))?)?;
        let addr_map = hexcavator_core::read_slice_at(
            data,
            hash_end as u64,
            u64::from(header.addr_map_size.get() / 4),
        )?;
        Ok(Self {
            header,
            hash,
            addr_map,
        })
    }

    /// Offsets of the public symbols, sorted by address.
    pub fn address_map(&self) -> &'s [U32Le] {
        self.addr_map
    }
}

/// Looks up a public symbol by `section:offset`: the nearest public at or
/// before the address. `records` is the symbol record stream.
pub fn public_at<'r>(
    publics: &PublicsStream<'_>,
    records: &'r [u8],
    section: u16,
    offset: u32,
) -> Option<(SymbolRecord<'r>, u32)> {
    let key = |off: &U32Le| -> Option<(u16, u32)> {
        match symbol_at(records, off.get())?.parse().ok()? {
            Symbol::Public {
                segment, offset, ..
            } => Some((segment, offset)),
            _ => None,
        }
    };
    let map = publics.address_map();
    let i = map.partition_point(|o| key(o).is_some_and(|k| k <= (section, offset)));
    let off = map.get(i.checked_sub(1)?)?;
    let (seg, start) = key(off)?;
    (seg == section)
        .then(|| (symbol_at(records, off.get()), offset - start))
        .and_then(|(s, d)| Some((s?, d)))
}

/// The symbol record at `offset` in a record stream.
pub fn symbol_at(records: &[u8], offset: u32) -> Option<SymbolRecord<'_>> {
    hexcavator_codeview::symbols::SymbolIter::new(records.get(offset as usize..)?, offset).next()
}

//! The TPI (types, stream 2) and IPI (ids, stream 4) streams, and their hash
//! streams.
//!
//! Records are stored back to back, so finding type index N means walking
//! from the start. The hash stream has an index of (type index, offset)
//! pairs every few KB; a lookup binary-searches it and walks from there. The
//! hash stream also gives each record's hash bucket, so a lookup by name
//! only has to look at records in the name's bucket.

use std::cell::OnceCell;

use hexcavator_core::{
    Error, ErrorKind, Reader, Result, U16Le, U32Le, pod, read_at, read_slice_at,
};

use crate::hash::hash_v1;
use crate::msf::{SN_NIL, StreamData};
use hexcavator_codeview::types::{TypeIndex, TypeRecord, TypeSource, leaf};

pod! {
    #[derive(Debug)]
    pub struct EmbeddedBuf {
        pub offset: U32Le,
        pub length: U32Le,
    }

    #[derive(Debug)]
    pub struct TpiHeader {
        pub version: U32Le,
        pub header_size: U32Le,
        pub type_index_begin: U32Le,
        pub type_index_end: U32Le,
        pub type_record_bytes: U32Le,
        pub hash_stream_index: U16Le,
        pub hash_aux_stream_index: U16Le,
        pub hash_key_size: U32Le,
        pub num_hash_buckets: U32Le,
        pub hash_value_buffer: EmbeddedBuf,
        pub index_offset_buffer: EmbeddedBuf,
        pub hash_adj_buffer: EmbeddedBuf,
    }

    #[derive(Debug)]
    pub struct TypeIndexOffset {
        pub type_index: U32Le,
        pub offset: U32Le,
    }
}

/// The most records `TypeStream::record` walks from an index entry before
/// finding every record's offset instead (MSVC indexes every 8 KB).
const MAX_WALK: u32 = 4096;
/// The most hash buckets indexed (MSVC uses 0x3FFFF).
const MAX_BUCKETS: usize = 1 << 20;

/// A TPI or IPI stream.
pub struct TypeStream<'s> {
    header: TpiHeader,
    /// The type records (the stream after its header).
    records: StreamData<'s>,
    hash: StreamData<'s>,
    /// Lazily built: offset of every record.
    offsets: OnceCell<Vec<u32>>,
    /// Lazily built: records by hash bucket (CSR layout).
    buckets: OnceCell<(Vec<u32>, Vec<u32>)>,
}

impl std::fmt::Debug for TypeStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeStream")
            .field("header", &self.header)
            .finish()
    }
}

impl<'s> TypeStream<'s> {
    /// Parses a type stream, given its contents and its hash stream's.
    pub fn parse(stream: StreamData<'s>, hash: StreamData<'s>) -> Result<Self> {
        if stream.is_empty() {
            let header = *hexcavator_core::from_bytes::<TpiHeader>(&[0u8; 56]).expect("56 bytes");
            return Ok(Self {
                header,
                records: StreamData::Borrowed(&[]),
                hash,
                offsets: OnceCell::new(),
                buckets: OnceCell::new(),
            });
        }
        let header: TpiHeader = *read_at::<TpiHeader>(&stream, 0)?;
        let start = header.header_size.get() as usize;
        let len = header.type_record_bytes.get() as usize;
        if stream.len() < start + len {
            return Err(Error::new(ErrorKind::Truncated, 0, "type records"));
        }
        let records = match stream {
            StreamData::Borrowed(b) => StreamData::Borrowed(&b[start..start + len]),
            StreamData::Owned(v) => StreamData::Owned(v[start..start + len].to_vec()),
        };
        Ok(Self {
            header,
            records,
            hash,
            offsets: OnceCell::new(),
            buckets: OnceCell::new(),
        })
    }

    pub fn header(&self) -> &TpiHeader {
        &self.header
    }

    pub fn begin(&self) -> TypeIndex {
        TypeIndex(self.header.type_index_begin.get())
    }

    pub fn end(&self) -> TypeIndex {
        TypeIndex(self.header.type_index_end.get())
    }

    pub fn len(&self) -> usize {
        (self.end().0.saturating_sub(self.begin().0)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates over all records in order.
    pub fn iter(&self) -> impl Iterator<Item = (TypeIndex, TypeRecord<'_>)> + '_ {
        let mut r = Reader::new(&self.records);
        let mut ti = self.begin().0;
        std::iter::from_fn(move || {
            let rec = TypeRecord::read(&mut r).ok()?;
            let item = (TypeIndex(ti), rec);
            ti += 1;
            Some(item)
        })
    }

    fn index_offsets(&self) -> &[TypeIndexOffset] {
        let b = &self.header.index_offset_buffer;
        read_slice_at(
            &self.hash,
            u64::from(b.offset.get()),
            u64::from(b.length.get() / 8),
        )
        .unwrap_or(&[])
    }

    /// The record for `ti`, using the hash stream's index to seek near it.
    pub fn record(&self, ti: TypeIndex) -> Option<TypeRecord<'_>> {
        if ti < self.begin() || ti >= self.end() {
            return None;
        }
        if let Some(offsets) = self.offsets.get() {
            // The table is short if a malformed record ended the walk.
            let off = *offsets.get((ti.0 - self.begin().0) as usize)?;
            return TypeRecord::read(&mut Reader::new(self.records.get(off as usize..)?)).ok();
        }
        let index = self.index_offsets();
        let i = index.partition_point(|e| e.type_index.get() <= ti.0);
        let (mut cur, off) = match i.checked_sub(1).map(|i| &index[i]) {
            Some(e) => (e.type_index.get(), e.offset.get() as usize),
            None => (self.begin().0, 0),
        };
        // Far from the nearest index entry (a stream whose index is sparse,
        // or missing): every record's offset, found once, rather than a
        // long walk per lookup.
        if ti.0 - cur.min(ti.0) > MAX_WALK {
            let off = *self.build_offsets().get((ti.0 - self.begin().0) as usize)?;
            return TypeRecord::read(&mut Reader::new(self.records.get(off as usize..)?)).ok();
        }
        let mut r = Reader::new(self.records.get(off..)?);
        loop {
            let rec = TypeRecord::read(&mut r).ok()?;
            if cur == ti.0 {
                return Some(rec);
            }
            cur += 1;
        }
    }

    /// Builds (once) the offset of every record, for O(1) lookups.
    pub fn build_offsets(&self) -> &[u32] {
        self.offsets.get_or_init(|| {
            // (Each record takes 4 bytes at least: the header's count of
            // them is no bound on what to allocate.)
            let mut out = Vec::with_capacity(self.len().min(self.records.len() / 4));
            let mut r = Reader::new(&self.records);
            while !r.is_empty() && out.len() < self.len() {
                out.push(r.position() as u32);
                if TypeRecord::read(&mut r).is_err() {
                    break;
                }
            }
            out
        })
    }

    /// Each record's hash bucket, from the hash stream.
    pub fn hash_values(&self) -> &[U32Le] {
        let b = &self.header.hash_value_buffer;
        if self.header.hash_key_size.get() != 4 {
            return &[];
        }
        read_slice_at(
            &self.hash,
            u64::from(b.offset.get()),
            u64::from(b.length.get() / 4),
        )
        .unwrap_or(&[])
    }

    fn bucket_index(&self) -> &(Vec<u32>, Vec<u32>) {
        self.buckets.get_or_init(|| {
            // (Buckets past those a table could fill aren't allocated: a
            // value naming one is left out, as one past `n` is.)
            let n = (self.header.num_hash_buckets.get() as usize).min(MAX_BUCKETS);
            let values = self.hash_values();
            let mut starts = vec![0u32; n + 1];
            for v in values {
                if let Some(s) = starts.get_mut(v.get() as usize + 1) {
                    *s += 1;
                }
            }
            for i in 0..n {
                starts[i + 1] += starts[i];
            }
            let mut fill = starts.clone();
            let mut members = vec![0u32; values.len()];
            for (i, v) in values.iter().enumerate() {
                // (Only the buckets counted above: `fill` has one more
                // entry than there are buckets.)
                if (v.get() as usize) >= n {
                    continue;
                }
                if let Some(slot) = fill.get_mut(v.get() as usize) {
                    members[*slot as usize] = self.begin().0 + i as u32;
                    *slot += 1;
                }
            }
            (starts, members)
        })
    }

    /// The type indexes in the hash bucket of `name`.
    pub fn bucket_for_name(&self, name: &[u8]) -> &[u32] {
        let n = self.header.num_hash_buckets.get();
        if n == 0 {
            return &[];
        }
        let (starts, members) = self.bucket_index();
        let b = (hash_v1(name) % n) as usize;
        let (Some(&from), Some(&to)) = (starts.get(b), starts.get(b + 1)) else {
            return &[];
        };
        members.get(from as usize..to as usize).unwrap_or(&[])
    }

    /// Finds a user-defined type (class, struct, union, enum, interface) by
    /// name or unique name, preferring a full definition to a forward
    /// reference.
    pub fn find_udt(&self, name: &str) -> Option<TypeIndex> {
        let mut forward = None;
        for &ti in self.bucket_for_name(name.as_bytes()) {
            let Some(rec) = self.record(TypeIndex(ti)) else {
                continue;
            };
            let Some(udt) = rec.udt() else { continue };
            if udt.name == name.as_bytes() || udt.unique_name == Some(name.as_bytes()) {
                if udt.is_forward_ref() {
                    forward.get_or_insert(TypeIndex(ti));
                } else {
                    return Some(TypeIndex(ti));
                }
            }
        }
        // Forward references are hashed by record contents, not name; fall
        // back to a scan for them.
        forward.or_else(|| {
            self.iter().find_map(|(ti, rec)| {
                let udt = rec.udt()?;
                (udt.name == name.as_bytes()).then_some(ti)
            })
        })
    }

    /// Resolves a forward reference to its definition (by unique name, or
    /// name), as debuggers do.
    pub fn resolve_forward(&self, ti: TypeIndex) -> TypeIndex {
        let Some(udt) = self.record(ti).and_then(|r| r.udt()) else {
            return ti;
        };
        if !udt.is_forward_ref() {
            return ti;
        }
        let key = udt.unique_name.unwrap_or(udt.name);
        // A definition is hashed by its unique name only if it is scoped or
        // anonymous; otherwise by its name. Look in both buckets.
        let buckets = [Some(key), udt.unique_name.map(|_| udt.name)];
        for name in buckets.into_iter().flatten() {
            for &cand in self.bucket_for_name(name) {
                let Some(rec) = self.record(TypeIndex(cand)) else {
                    continue;
                };
                let Some(d) = rec.udt() else { continue };
                if leaf::same_udt_family(rec.kind, udt_kind(ti, self))
                    && !d.is_forward_ref()
                    && (d.unique_name.unwrap_or(d.name) == key)
                {
                    return TypeIndex(cand);
                }
            }
        }
        ti
    }
}

impl TypeSource for TypeStream<'_> {
    fn record(&self, ti: TypeIndex) -> Option<TypeRecord<'_>> {
        TypeStream::record(self, ti)
    }

    fn resolve_forward(&self, ti: TypeIndex) -> TypeIndex {
        TypeStream::resolve_forward(self, ti)
    }

    fn records(&self) -> Box<dyn Iterator<Item = (TypeIndex, TypeRecord<'_>)> + '_> {
        // Index every record first, so the lookups callers make while
        // iterating don't walk.
        self.build_offsets();
        Box::new(self.iter())
    }
}

fn udt_kind(ti: TypeIndex, s: &TypeStream<'_>) -> u16 {
    s.record(ti).map_or(leaf::LF_STRUCTURE, |r| r.kind)
}

/// Reads the TPI/IPI header's hash stream index.
pub fn hash_stream_of(stream: &[u8]) -> Option<u32> {
    let h: &TpiHeader = read_at(stream, 0).ok()?;
    let s = h.hash_stream_index.get();
    (s != SN_NIL).then_some(u32::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUCKETS: u32 = 4096;

    /// An `LF_STRUCTURE` named `name`, with unique name `unique`, of
    /// `size` bytes, a forward reference if `forward`.
    fn structure(name: &str, unique: &str, size: u16, forward: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // member count
        let property: u16 = 0x200 | if forward { 0x80 } else { 0 }; // has unique name
        body.extend_from_slice(&property.to_le_bytes());
        body.extend_from_slice(&[0; 12]); // field list, derived, vshape
        body.extend_from_slice(&size.to_le_bytes()); // numeric leaf (< 0x8000)
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(unique.as_bytes());
        body.push(0);
        while (body.len() + 2) % 4 != 0 {
            body.push(0xF1);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(body.len() + 2).unwrap().to_le_bytes());
        out.extend_from_slice(&leaf::LF_STRUCTURE.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A type stream of `records` (from 0x1000) with their hash buckets.
    fn stream(records: &[Vec<u8>], buckets: &[u32]) -> (Vec<u8>, Vec<u8>) {
        let bytes: Vec<u8> = records.concat();
        let mut header = Vec::new();
        for v in [
            20040203u32,
            56,
            0x1000,
            0x1000 + records.len() as u32,
            bytes.len() as u32,
        ] {
            header.extend_from_slice(&v.to_le_bytes());
        }
        header.extend_from_slice(&1u16.to_le_bytes()); // hash stream
        header.extend_from_slice(&0xFFFFu16.to_le_bytes());
        for v in [4u32, BUCKETS, 0, 4 * buckets.len() as u32, 0, 0, 0, 0] {
            header.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(header.len(), 56);
        header.extend_from_slice(&bytes);
        let hash: Vec<u8> = buckets.iter().flat_map(|b| b.to_le_bytes()).collect();
        (header, hash)
    }

    #[test]
    fn forward_references_resolve_through_either_bucket() {
        let bucket = |s: &str| hash_v1(s.as_bytes()) % BUCKETS;
        // A definition hashed by its name (unscoped types are), and one
        // hashed by its unique name; forward references hash by contents
        // (here, bucket 7).
        let records = [
            structure("Plain", ".?AUPlain@@", 0, true),
            structure("Plain", ".?AUPlain@@", 125, false),
            structure("Scoped", ".?AUScoped@x@@", 0, true),
            structure("Scoped", ".?AUScoped@x@@", 16, false),
        ];
        let buckets = [7, bucket("Plain"), 7, bucket(".?AUScoped@x@@")];
        let (tpi, hash) = stream(&records, &buckets);
        let types =
            TypeStream::parse(StreamData::Borrowed(&tpi), StreamData::Borrowed(&hash)).unwrap();
        assert_eq!(types.resolve_forward(TypeIndex(0x1000)), TypeIndex(0x1001));
        assert_eq!(types.resolve_forward(TypeIndex(0x1002)), TypeIndex(0x1003));
        // Definitions and non-UDTs resolve to themselves.
        assert_eq!(types.resolve_forward(TypeIndex(0x1001)), TypeIndex(0x1001));
        assert_eq!(types.resolve_forward(TypeIndex(0x0074)), TypeIndex(0x0074));
        // A forward reference with no definition stays.
        let (tpi, hash) = stream(&records[..1], &buckets[..1]);
        let types =
            TypeStream::parse(StreamData::Borrowed(&tpi), StreamData::Borrowed(&hash)).unwrap();
        assert_eq!(types.resolve_forward(TypeIndex(0x1000)), TypeIndex(0x1000));
    }

    /// A header's counts (of types, of hash buckets) bound nothing that is
    /// allocated; hash values out of range, and a stream with no index, are
    /// handled; lookups stay fast.
    #[test]
    fn hostile_headers_and_hashes() {
        let n = 20_000;
        let records: Vec<Vec<u8>> = (0..n)
            .map(|i| structure(&format!("T{i}"), &format!(".?AUT{i}@@"), 4, false))
            .collect();
        // Hash values: many equal to the bucket count (out of range), the
        // rest in range.
        let buckets: Vec<u32> = (0..n as u32)
            .map(|i| if i % 2 == 0 { BUCKETS } else { i % BUCKETS })
            .collect();
        let (mut tpi, hash) = stream(&records, &buckets);
        // As is: values equal to the bucket count.
        let types =
            TypeStream::parse(StreamData::Borrowed(&tpi), StreamData::Borrowed(&hash)).unwrap();
        assert!(types.find_udt("T7").is_some());
        // Type index end: 4 billion; hash buckets: 4 billion.
        tpi[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        tpi[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        let types =
            TypeStream::parse(StreamData::Borrowed(&tpi), StreamData::Borrowed(&hash)).unwrap();
        let _ = types.bucket_for_name(b"T7");
        let _ = types.find_udt("T7");
        // No index offsets: each lookup of a late record would walk them all.
        let start = std::time::Instant::now();
        for i in (0..n as u32).rev() {
            assert!(types.record(TypeIndex(0x1000 + i)).is_some());
        }
        assert!(types.record(TypeIndex(0x1000 + n as u32)).is_none());
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
        assert!(types.build_offsets().len() == n);
    }
}

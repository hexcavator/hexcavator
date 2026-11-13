//! The Multi-Stream File (MSF) container.
//!
//! An MSF divides the file into fixed-size blocks. A directory lists, for
//! each numbered stream, its size and the blocks that hold it. Streams are
//! usually laid out contiguously by the linker; those are borrowed straight
//! from the file. Fragmented streams are gathered into an owned buffer.

use std::borrow::Cow;

use hexcavator_core::{Error, ErrorKind, Result, U32Le, pod, read_at, read_slice_at};

/// The signature of an MSF 7.00 ("big MSF") file.
pub const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

pod! {
    #[derive(Debug)]
    pub struct SuperBlock {
        pub magic: [u8; 32],
        pub block_size: U32Le,
        pub free_block_map_block: U32Le,
        pub num_blocks: U32Le,
        pub num_directory_bytes: U32Le,
        pub unknown: U32Le,
        /// The block holding the list of the directory's blocks.
        pub block_map_addr: U32Le,
    }
}

/// A stream's size and its blocks (as a range of the directory).
#[derive(Clone, Copy, Debug)]
struct StreamEntry {
    size: u32,
    first_block: usize,
    block_count: usize,
}

/// A parsed MSF file.
#[derive(Debug)]
pub struct Msf<'data> {
    data: &'data [u8],
    block_size: u32,
    directory: Cow<'data, [u8]>,
    /// Offset in `directory` of the first block index.
    blocks_start: usize,
    streams: Vec<Option<StreamEntry>>,
}

/// A stream's contents.
pub type StreamData<'data> = Cow<'data, [u8]>;

/// The stream index that means "no stream" (msf.h's `snNil`).
pub const SN_NIL: u16 = 0xFFFF;

/// The block (page) sizes an MSF may use.
pub const BLOCK_SIZES: [u32; 7] = [512, 1024, 2048, 4096, 8192, 16384, 32768];

impl<'data> Msf<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let sb: &SuperBlock = read_at(data, 0)?;
        if &sb.magic != MAGIC {
            return Err(Error::new(ErrorKind::BadMagic, 0, "MSF superblock"));
        }
        let block_size = sb.block_size.get();
        if !BLOCK_SIZES.contains(&block_size) {
            return Err(Error::new(ErrorKind::Malformed, 32, "MSF block size"));
        }
        let dir_bytes = sb.num_directory_bytes.get();
        // Each block of the file holds one stream's bytes, once: nothing
        // is larger than the file, and the streams together hold no more
        // blocks than it has. (A hostile block list that names one block
        // over and over could otherwise ask for gigabytes.)
        let file_blocks = (data.len() as u64).div_ceil(u64::from(block_size));
        if u64::from(dir_bytes) > data.len() as u64 {
            return Err(Error::new(
                ErrorKind::Malformed,
                44,
                "MSF directory larger than the file",
            ));
        }
        let dir_blocks = dir_bytes.div_ceil(block_size);
        let map_offset = u64::from(sb.block_map_addr.get()) * u64::from(block_size);
        let dir_block_list: &[U32Le] = read_slice_at(data, map_offset, u64::from(dir_blocks))?;
        let directory = gather(data, block_size, dir_block_list, dir_bytes)?;

        let count = read_at::<U32Le>(&directory, 0)?.get() as usize;
        let sizes: &[U32Le] = read_slice_at(&directory, 4, count as u64)?;
        let mut streams = Vec::with_capacity(count);
        let blocks_start = 4 + count * 4;
        let mut next = 0usize;
        for size in sizes {
            let size = size.get();
            if size == u32::MAX {
                streams.push(None);
                continue;
            }
            let block_count = size.div_ceil(block_size) as usize;
            streams.push(Some(StreamEntry {
                size,
                first_block: next,
                block_count,
            }));
            next += block_count;
        }
        // Validate the block list fits in the directory, and the file.
        if next as u64 > file_blocks {
            return Err(Error::new(
                ErrorKind::Malformed,
                0,
                "MSF streams hold more blocks than the file",
            ));
        }
        read_slice_at::<U32Le>(&directory, blocks_start as u64, next as u64)?;
        Ok(Self {
            data,
            block_size,
            directory,
            blocks_start,
            streams,
        })
    }

    #[inline]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    #[inline]
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// The size of stream `index`, or `None` if it does not exist (or is nil).
    pub fn stream_size(&self, index: u32) -> Option<u32> {
        self.streams
            .get(index as usize)
            .copied()
            .flatten()
            .map(|s| s.size)
    }

    /// The blocks of stream `index`.
    pub fn stream_blocks(&self, index: u32) -> Option<&[U32Le]> {
        let s = self.streams.get(index as usize).copied().flatten()?;
        read_slice_at(
            &self.directory,
            (self.blocks_start + s.first_block * 4) as u64,
            s.block_count as u64,
        )
        .ok()
    }

    /// The contents of stream `index`: borrowed from the file if its blocks
    /// are contiguous, otherwise gathered into an owned buffer.
    pub fn stream(&self, index: u32) -> Result<StreamData<'data>> {
        let what = "MSF stream";
        let size = self.stream_size(index).ok_or(Error::new(
            ErrorKind::Malformed,
            u64::from(index),
            what,
        ))?;
        let blocks = self.stream_blocks(index).ok_or(Error::new(
            ErrorKind::Malformed,
            u64::from(index),
            what,
        ))?;
        gather(self.data, self.block_size, blocks, size)
    }

    /// Like `stream`, but a missing or nil stream is empty.
    pub fn stream_or_empty(&self, index: u32) -> Result<StreamData<'data>> {
        if index == u32::from(SN_NIL) || self.stream_size(index).is_none() {
            return Ok(Cow::Borrowed(&[]));
        }
        self.stream(index)
    }
}

/// Assembles `size` bytes from `blocks`, borrowing when they are contiguous.
fn gather<'data>(
    data: &'data [u8],
    block_size: u32,
    blocks: &[U32Le],
    size: u32,
) -> Result<StreamData<'data>> {
    let bs = u64::from(block_size);
    let Some(first) = blocks.first() else {
        return Ok(Cow::Borrowed(&[]));
    };
    let start = u64::from(first.get()) * bs;
    let contiguous = blocks
        .windows(2)
        .all(|w| w[1].get() == w[0].get().wrapping_add(1));
    if contiguous {
        return hexcavator_core::bytes_at(data, start, u64::from(size)).map(Cow::Borrowed);
    }
    let mut out = Vec::with_capacity(size as usize);
    let mut remaining = u64::from(size);
    for block in blocks {
        let take = remaining.min(bs);
        out.extend_from_slice(hexcavator_core::bytes_at(
            data,
            u64::from(block.get()) * bs,
            take,
        )?);
        remaining -= take;
        if remaining == 0 {
            break;
        }
    }
    Ok(Cow::Owned(out))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds an MSF with the given streams. Stream 1 is deliberately
    /// fragmented (its blocks are written in reverse order).
    pub fn build(streams: &[&[u8]]) -> Vec<u8> {
        const BS: usize = 512;
        let mut blocks: Vec<Vec<u8>> = vec![vec![0; BS], vec![0; BS], vec![0; BS]]; // super, fpm1, fpm2
        let mut lists: Vec<Vec<u32>> = Vec::new();
        for (i, s) in streams.iter().enumerate() {
            let mut chunk_blocks: Vec<u32> = Vec::new();
            let chunks: Vec<&[u8]> = s.chunks(BS).collect();
            let order: Vec<usize> = if i == 1 {
                (0..chunks.len()).rev().collect()
            } else {
                (0..chunks.len()).collect()
            };
            let base = blocks.len();
            for _ in 0..chunks.len() {
                blocks.push(vec![0; BS]);
            }
            let mut assigned = vec![0u32; chunks.len()];
            for (slot, &c) in order.iter().enumerate() {
                assigned[c] = (base + slot) as u32;
                blocks[base + slot][..chunks[c].len()].copy_from_slice(chunks[c]);
            }
            chunk_blocks.extend(assigned);
            lists.push(chunk_blocks);
        }
        let mut dir = Vec::new();
        dir.extend_from_slice(&(streams.len() as u32).to_le_bytes());
        for s in streams {
            dir.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }
        for l in &lists {
            for b in l {
                dir.extend_from_slice(&b.to_le_bytes());
            }
        }
        let dir_block = blocks.len() as u32;
        let mut d = vec![0; BS];
        d[..dir.len()].copy_from_slice(&dir);
        blocks.push(d);
        let map_block = blocks.len() as u32;
        let mut m = vec![0; BS];
        m[..4].copy_from_slice(&dir_block.to_le_bytes());
        blocks.push(m);
        let mut sb = vec![0u8; BS];
        sb[..32].copy_from_slice(MAGIC);
        sb[32..36].copy_from_slice(&(BS as u32).to_le_bytes());
        sb[36..40].copy_from_slice(&1u32.to_le_bytes());
        sb[40..44].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        sb[44..48].copy_from_slice(&(dir.len() as u32).to_le_bytes());
        sb[52..56].copy_from_slice(&map_block.to_le_bytes());
        blocks[0] = sb;
        blocks.concat()
    }

    #[test]
    fn streams_contiguous_and_fragmented() {
        let a: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let b: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
        let file = build(&[&a, &b, &[]]);
        let msf = Msf::parse(&file).unwrap();
        assert_eq!(msf.stream_count(), 3);
        let s0 = msf.stream(0).unwrap();
        assert!(matches!(s0, Cow::Borrowed(_)));
        assert_eq!(&*s0, &a[..]);
        let s1 = msf.stream(1).unwrap();
        assert!(matches!(s1, Cow::Owned(_)));
        assert_eq!(&*s1, &b[..]);
        assert!(msf.stream(2).unwrap().is_empty());
        assert!(msf.stream(3).is_err());
    }

    #[test]
    fn nothing_larger_than_the_file() {
        let a = [1u8; 600];
        let file = build(&[&a]);
        assert!(Msf::parse(&file).is_ok());
        let u32_at = |f: &[u8], at: usize| u32::from_le_bytes(f[at..at + 4].try_into().unwrap());
        let map = u32_at(&file, 52) as usize * 512;
        let dir = u32_at(&file, map) as usize * 512;
        // A stream that says it is 1 MB (2048 blocks: more than the file
        // has, so its block list would name some again).
        let mut big = file.clone();
        big[dir + 4..dir + 8].copy_from_slice(&(1u32 << 20).to_le_bytes());
        assert!(Msf::parse(&big).is_err());
        // A directory larger than the file.
        let mut big = file.clone();
        big[44..48].copy_from_slice(&u32::try_from(file.len() + 1).unwrap().to_le_bytes());
        assert!(Msf::parse(&big).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Msf::parse(&[0; 100]).is_err());
        let a = [1u8; 600];
        let file = build(&[&a]);
        for len in 0..file.len() {
            let _ = Msf::parse(&file[..len]).map(|m| m.stream(0).map(|s| s.len()));
        }
    }
}

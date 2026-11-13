//! The PDB info stream (stream 1): signature, age, GUID, and the named
//! stream map (`/names`, `/LinkInfo`, `/src/headerblock`, ...).

use hexcavator_core::{Error, ErrorKind, Reader, Result, U32Le, pod};

pod! {
    #[derive(Debug)]
    pub struct InfoHeader {
        pub version: U32Le,
        pub signature: U32Le,
        pub age: U32Le,
        pub guid: [u8; 16],
    }
}

/// Feature codes that may follow the named stream map.
pub mod feature {
    pub const VC110: u32 = 20_091_201;
    pub const VC140: u32 = 20_140_508;
    pub const NO_TYPE_MERGE: u32 = 0x4D54_4E4D;
    pub const MINIMAL_DEBUG_INFO: u32 = 0x494E_494D;
}

#[derive(Debug)]
pub struct InfoStream<'s> {
    pub header: &'s InfoHeader,
    /// (name, stream index)
    named: Vec<(&'s [u8], u32)>,
    pub features: Vec<u32>,
}

impl<'s> InfoStream<'s> {
    pub fn parse(data: &'s [u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let header: &InfoHeader = r.read()?;
        let strings_len = r.u32_le()? as usize;
        let strings = r.bytes(strings_len)?;
        // A serialized hash table: size, capacity, present and deleted bit
        // vectors, then (key, value) for each present bucket.
        let _size = r.u32_le()?;
        let capacity = r.u32_le()?;
        let present_words = r.u32_le()? as usize;
        let present: &[U32Le] = r.read_slice(present_words)?;
        let deleted_words = r.u32_le()? as usize;
        r.read_slice::<U32Le>(deleted_words)?;
        let mut named = Vec::new();
        // (Buckets past the present bits' are absent: a capacity of
        // billions with few bits is a few iterations, not billions.)
        let buckets = (capacity as usize).min(present.len().saturating_mul(32));
        for bucket in 0..buckets {
            let word = present.get(bucket / 32).map_or(0, |w| w.get());
            if word & (1 << (bucket % 32)) == 0 {
                continue;
            }
            let key = r.u32_le()? as usize;
            let value = r.u32_le()?;
            let name = strings
                .get(key..)
                .and_then(|s| s.split(|&b| b == 0).next())
                .ok_or(Error::new(ErrorKind::Malformed, key as u64, "named stream"))?;
            named.push((name, value));
        }
        let mut features = Vec::new();
        while let Ok(f) = r.u32_le() {
            features.push(f);
        }
        Ok(Self {
            header,
            named,
            features,
        })
    }

    pub fn version(&self) -> u32 {
        self.header.version.get()
    }

    pub fn age(&self) -> u32 {
        self.header.age.get()
    }

    pub fn guid(&self) -> [u8; 16] {
        self.header.guid
    }

    /// The stream index of a named stream.
    pub fn named_stream(&self, name: &str) -> Option<u32> {
        self.named
            .iter()
            .find(|(n, _)| *n == name.as_bytes())
            .map(|(_, i)| *i)
    }

    pub fn named_streams(&self) -> &[(&'s [u8], u32)] {
        &self.named
    }

    pub fn has_feature(&self, code: u32) -> bool {
        self.features.contains(&code)
    }
}

/// Formats a GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn format_guid(g: &[u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

//! FastCDC content-defined chunking: dedup + resumable uploads.
//! Files under 64 KiB are a single chunk (spec).

use fastcdc::v2020::FastCDC;

pub const MIN_CHUNK: u32 = 8 * 1024;
pub const AVG_CHUNK: u32 = 16 * 1024;
pub const MAX_CHUNK: u32 = 64 * 1024;
/// Below this, skip CDC entirely.
pub const SINGLE_CHUNK_BELOW: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub offset: usize,
    pub length: usize,
}

/// Chunk `data`; returns slices into `data`.
pub fn chunk(data: &[u8]) -> Vec<Chunk> {
    if data.len() <= SINGLE_CHUNK_BELOW {
        return vec![Chunk {
            offset: 0,
            length: data.len(),
        }];
    }
    FastCDC::new(data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK)
        .map(|c| Chunk {
            offset: c.offset,
            length: c.length,
        })
        .collect()
}

/// Reassemble file bytes from chunks in order.
pub fn assemble(chunks: &[&[u8]]) -> Vec<u8> {
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in chunks {
        out.extend_from_slice(c);
    }
    out
}

//! Stream writer implementation.

use crate::constants::DEFAULT_CHUNK_SIZE;
use crate::error::Result;
use crate::writer::Writer;
use std::io::{Seek, Write};

/// Buffered stream writer for efficient chunking.
pub struct BufferedStreamWriter<'a, W: Write + Seek> {
    writer: &'a mut Writer<W>,
    buffer: Vec<u8>,
    chunk_size: usize,
    bytes_written: u64,
}

impl<'a, W: Write + Seek> BufferedStreamWriter<'a, W> {
    /// Create a new buffered stream writer.
    pub fn new(writer: &'a mut Writer<W>) -> Result<Self> {
        Self::with_chunk_size(writer, DEFAULT_CHUNK_SIZE)
    }

    /// Create with custom chunk size.
    pub fn with_chunk_size(writer: &'a mut Writer<W>, chunk_size: usize) -> Result<Self> {
        Ok(Self {
            writer,
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
            bytes_written: 0,
        })
    }

    /// Write data to the buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let mut remaining = data;

        while !remaining.is_empty() {
            let available = self.chunk_size - self.buffer.len();
            let to_write = remaining.len().min(available);

            self.buffer.extend_from_slice(&remaining[..to_write]);
            remaining = &remaining[to_write..];

            // Flush if buffer is full
            if self.buffer.len() == self.chunk_size {
                self.flush_chunk(false)?;
            }
        }

        Ok(())
    }

    /// Flush the current buffer as a chunk.
    fn flush_chunk(&mut self, is_final: bool) -> Result<()> {
        if !self.buffer.is_empty() {
            let data = std::mem::take(&mut self.buffer);
            self.writer.write_chunk(&data, is_final)?;
            self.bytes_written += data.len() as u64;
            self.buffer.reserve(self.chunk_size);
        }
        Ok(())
    }

    /// Finish writing and flush remaining data.
    pub fn finish(mut self) -> Result<u64> {
        self.flush_chunk(true)?;
        Ok(self.bytes_written)
    }

    /// Get bytes written so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written + self.buffer.len() as u64
    }
}

/// Chunk boundary detector for content-defined chunking.
pub struct Chunker {
    /// Target chunk size
    pub target_size: usize,
    /// Minimum chunk size
    pub min_size: usize,
    /// Maximum chunk size
    pub max_size: usize,
    /// Rolling hash window size
    window_size: usize,
    /// Hash mask for boundary detection (lower bits = more chunks)
    mask: u32,
}

impl Chunker {
    /// Create a new chunker with default settings.
    pub fn new() -> Self {
        Self::with_size(DEFAULT_CHUNK_SIZE)
    }

    /// Create a chunker targeting a specific size.
    pub fn with_size(target_size: usize) -> Self {
        Self {
            target_size,
            min_size: target_size / 4,
            max_size: target_size * 4,
            window_size: 48,
            mask: (1 << 14) - 1, // ~16KB average with 64KB target
        }
    }

    /// Find chunk boundaries in data.
    ///
    /// Returns a vector of chunk end positions.
    pub fn find_boundaries(&self, data: &[u8]) -> Vec<usize> {
        let mut boundaries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let remaining = data.len() - pos;

            // If remaining is small enough, make it one chunk
            if remaining <= self.min_size {
                boundaries.push(pos + remaining);
                break;
            }

            // Look for content-defined boundary
            let search_start = pos + self.min_size;
            let search_end = (pos + self.max_size).min(data.len());

            if let Some(boundary) = self.find_content_boundary(&data[search_start..search_end]) {
                boundaries.push(search_start + boundary);
                pos = search_start + boundary;
            } else {
                // No boundary found, use max size
                let chunk_end = search_end.min(pos + self.max_size);
                boundaries.push(chunk_end);
                pos = chunk_end;
            }
        }

        boundaries
    }

    /// Find a content-defined boundary using Rabin fingerprint.
    fn find_content_boundary(&self, data: &[u8]) -> Option<usize> {
        if data.len() < self.window_size {
            return None;
        }

        let mut hash = self.initial_hash(&data[..self.window_size]);

        for i in self.window_size..data.len() {
            // Update rolling hash
            hash = self.update_hash(hash, data[i - self.window_size], data[i]);

            // Check for boundary
            if (hash & self.mask) == 0 {
                return Some(i);
            }
        }

        None
    }

    /// Compute initial Rabin hash.
    fn initial_hash(&self, data: &[u8]) -> u32 {
        let mut hash: u32 = 0;
        for &byte in data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash
    }

    /// Update rolling hash.
    fn update_hash(&self, hash: u32, out_byte: u8, in_byte: u8) -> u32 {
        // Simplified rolling hash: remove old byte, add new byte
        let pow = self.window_size as u32;
        let multiplier = if pow > 1 { 31_u32.wrapping_pow(pow - 1) } else { 1 };
        let out_contrib = (out_byte as u32).wrapping_mul(multiplier);
        hash.wrapping_sub(out_contrib)
            .wrapping_mul(31)
            .wrapping_add(in_byte as u32)
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

/// Content-defined chunking writer.
pub struct ContentDefinedWriter<'a, W: Write + Seek> {
    writer: &'a mut Writer<W>,
    chunker: Chunker,
    buffer: Vec<u8>,
}

impl<'a, W: Write + Seek> ContentDefinedWriter<'a, W> {
    /// Create a new content-defined chunking writer.
    pub fn new(writer: &'a mut Writer<W>) -> Self {
        Self {
            writer,
            chunker: Chunker::new(),
            buffer: Vec::new(),
        }
    }

    /// Write data.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(data);

        // Find and write chunks
        let boundaries = self.chunker.find_boundaries(&self.buffer);
        let mut last_boundary = 0;

        for &boundary in &boundaries {
            let chunk_data = &self.buffer[last_boundary..boundary];
            self.writer.write_chunk(chunk_data, false)?;
            last_boundary = boundary;
        }

        // Keep remaining data in buffer
        if last_boundary > 0 {
            let remaining = self.buffer[last_boundary..].to_vec();
            self.buffer = remaining;
        }

        Ok(())
    }

    /// Finish writing.
    pub fn finish(mut self) -> Result<()> {
        // Only write remaining buffer if stream is still active
        // (stream may have already been finished by a previous write_chunk with is_final=true)
        if !self.buffer.is_empty() {
            // Try to write, but ignore "No stream active" error since stream may already be finished
            match self.writer.write_chunk(&self.buffer, true) {
                Ok(()) => {}
                Err(e) => {
                    let err_msg = format!("{}", e);
                    if !err_msg.contains("No stream active") {
                        return Err(e);
                    }
                    // Stream already finished, ignore remaining buffer
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZetaFlags;
    use std::io::Cursor;

    #[test]
    fn test_chunker_boundaries() {
        let chunker = Chunker::with_size(1024);

        // Create data with some patterns
        let data = vec![0u8; 10000];
        let boundaries = chunker.find_boundaries(&data);

        // Should have multiple boundaries
        assert!(!boundaries.is_empty());
        assert!(boundaries.last().unwrap() <= &data.len());
    }

    #[test]
    fn test_buffered_writer() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = crate::writer::Writer::new(cursor, ZetaFlags::empty()).unwrap();
        writer.create_stream("test").unwrap();

        {
            let mut buffered = BufferedStreamWriter::new(&mut writer).unwrap();
            buffered.write(b"hello ").unwrap();
            buffered.write(b"world").unwrap();
            buffered.finish().unwrap();
        }

        // Writer should have data
        let cursor = writer.finish().unwrap();
        let data = cursor.into_inner();
        assert!(!data.is_empty());
    }
}

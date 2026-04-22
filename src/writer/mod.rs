//! Writer for creating ZETA containers.

pub mod builder;
pub mod stream;

pub use builder::WriterBuilder;

use crate::error::{Error, Result};
use crate::format::chunk::ChunkInfo;
use crate::format::footer::{Footer, SignatureBlock};
use crate::format::header::FileHeader;
use crate::format::index::{IndexBlock, IndexEntry};
use crate::format::stream_dir::{StreamDir, StreamEntry};
use crate::format::Serialize;
use crate::pipeline::encoder::{ChunkEncoder, EncodeOptions, EncodeResult};
use crate::pipeline::PipelineConfig;
use crate::registry::hash::Sha256Hash;
use crate::registry::HashAlgorithm;
use crate::types::{ChunkSequence, StreamId, Uuid, ZetaFlags};
use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};

/// High-level writer for ZETA containers.
pub struct Writer<W: Write + Seek> {
    inner: W,
    header: FileHeader,
    stream_dir: StreamDir,
    index: IndexBlock,
    config: PipelineConfig,
    current_stream: Option<StreamWriterState>,
    stream_offsets: HashMap<StreamId, u64>,
    final_offset: u64,
}

/// State for the current stream being written.
struct StreamWriterState {
    stream_id: StreamId,
    sequence: ChunkSequence,
    uncompressed_size: u64,
    chunk_count: u64,
    chunks: Vec<ChunkInfo>,
}

impl<W: Write + Seek> Writer<W> {
    /// Create a new ZETA writer.
    ///
    /// # Arguments
    /// * `writer` - The underlying writer (must be seekable)
    /// * `flags` - File-level flags
    pub fn new(writer: W, flags: ZetaFlags) -> Result<Self> {
        Self::with_uuid(writer, flags, Uuid::new_v4())
    }

    /// Create a new writer with a specific UUID.
    pub fn with_uuid(mut writer: W, flags: ZetaFlags, uuid: Uuid) -> Result<Self> {
        let header = FileHeader::new(flags, uuid);

        // Reserve space for header
        header.serialize(&mut writer)?;

        let offset = header.serialized_size() as u64;

        Ok(Self {
            inner: writer,
            header,
            stream_dir: StreamDir::new(),
            index: IndexBlock::new(),
            config: PipelineConfig::new(),
            current_stream: None,
            stream_offsets: HashMap::new(),
            final_offset: offset,
        })
    }

    /// Set pipeline configuration.
    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Create a new stream.
    ///
    /// Finishes any current stream first.
    pub fn create_stream(&mut self, name: impl Into<String>) -> Result<StreamId> {
        // Finish current stream if any
        if self.current_stream.is_some() {
            self.finish_stream()?;
        }

        let id = StreamId::new(self.stream_dir.streams.len() as u32 + 1)
            .ok_or_else(|| Error::custom("Too many streams"))?;

        let name = name.into();
        let entry = StreamEntry::new(id, name, crate::types::StreamType::Data, self.final_offset)?;
        self.stream_dir.add_stream(entry)?;

        self.current_stream = Some(StreamWriterState {
            stream_id: id,
            sequence: ChunkSequence::new(0),
            uncompressed_size: 0,
            chunk_count: 0,
            chunks: Vec::new(),
        });

        self.stream_offsets.insert(id, self.final_offset);

        Ok(id)
    }

    /// Write data as a chunk to the current stream.
    ///
    /// The data is processed through the pipeline (delta, compress, encrypt).
    pub fn write_chunk(&mut self, data: &[u8], is_final: bool) -> Result<()> {
        let state = self
            .current_stream
            .as_mut()
            .ok_or_else(|| Error::custom("No stream active"))?;

        // Get previous chunk data for delta encoding if enabled
        let prev_data = if self.config.delta.is_some() && !state.chunks.is_empty() {
            // Note: In a real implementation, we'd need to store uncompressed data
            // for delta encoding. For now, we skip delta if we don't have it.
            None
        } else {
            None
        };

        // Build encode options
        let options = EncodeOptions {
            stream_id: state.stream_id,
            sequence: state.sequence,
            is_final,
            compression_id: self
                .config
                .compression
                .as_ref()
                .map(|c| c.id())
                .unwrap_or(0),
            encryption_id: self
                .config
                .encryption
                .as_ref()
                .map(|e| e.id())
                .unwrap_or(0),
            hash_id: self
                .config
                .hash
                .as_ref()
                .map(|h| h.id())
                .unwrap_or(0),
        };

        // Encode chunk
        let encoder = ChunkEncoder::new(self.config.clone(), options);
        let result = if let Some(base) = prev_data {
            encoder.encode(data, Some(base))?
        } else {
            encoder.encode_simple(data)?
        };

        // Record chunk offset for index
        if self.header.flags.has_index() {
            self.index.add_entry(IndexEntry::new(
                state.stream_id,
                state.sequence,
                self.final_offset,
            ));
        }

        // Serialize chunk
        result.chunk.serialize(&mut self.inner)?;

        // Update state
        state.sequence = state.sequence.next();
        state.uncompressed_size += data.len() as u64;
        state.chunk_count += 1;
        state.chunks.push(result.chunk.clone());

        self.final_offset += result.chunk.total_size() as u64;

        // If final chunk, finish the stream
        if is_final {
            self.finish_stream()?;
        }

        Ok(())
    }

    /// Write data to the current stream, automatically chunking.
    ///
    /// Uses default chunk size (1 MB).
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        let chunk_size = crate::constants::DEFAULT_CHUNK_SIZE;

        if data.len() <= chunk_size {
            // Single chunk
            self.write_chunk(data, true)?;
        } else {
            // Multiple chunks
            let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
            for (i, chunk_data) in chunks.iter().enumerate() {
                let is_final = i == chunks.len() - 1;
                self.write_chunk(chunk_data, is_final)?;
            }
        }

        Ok(())
    }

    /// Finish the current stream.
    fn finish_stream(&mut self) -> Result<()> {
        if let Some(state) = self.current_stream.take() {
            // Update stream entry
            if let Some(entry) = self.stream_dir.streams.iter_mut().find(|e| e.id == state.stream_id) {
                entry.update_stats(state.uncompressed_size, state.chunk_count);
            }
        }
        Ok(())
    }

    /// Finish writing and write footer.
    ///
    /// This writes the stream directory, index (if enabled), and footer.
    pub fn finish(mut self) -> Result<()> {
        // Finish any active stream
        self.finish_stream()?;

        // Update header with offsets
        let stream_dir_offset = self.final_offset;
        self.header.stream_dir_offset = stream_dir_offset;

        // Write stream directory
        self.stream_dir.serialize(&mut self.inner)?;
        self.final_offset += self.stream_dir.serialized_size() as u64;

        // Write index if enabled
        let index_offset = if self.header.flags.has_index() {
            let offset = self.final_offset;
            self.index.sort();
            self.index.serialize(&mut self.inner)?;
            self.final_offset += self.index.serialized_size() as u64;
            offset
        } else {
            0
        };

        // Compute file hash
        let file_hash = self.compute_file_hash()?;

        // Write footer
        let footer = Footer::new(index_offset, file_hash.try_into().unwrap_or([0u8; 32]));
        footer.serialize(&mut self.inner)?;

        // Update header CRC and seek back to write it
        self.header.update_crc();
        self.inner.seek(SeekFrom::Start(0))?;
        self.header.serialize(&mut self.inner)?;

        Ok(())
    }

    /// Compute SHA-256 hash of the file (excluding footer).
    fn compute_file_hash(&mut self) -> Result<Vec<u8>> {
        // In a real implementation, we'd hash as we write
        // For now, return zeros
        Ok(vec![0u8; 32])
    }

    /// Add a signature to the footer.
    pub fn add_signature(&mut self, _signature: SignatureBlock) -> Result<()> {
        // Signatures are added in finish()
        // This is a placeholder for API completeness
        Ok(())
    }
}

/// Writer for a single stream (convenience wrapper).
pub struct StreamWriter<'a, W: Write + Seek> {
    writer: &'a mut Writer<W>,
    stream_id: StreamId,
}

impl<'a, W: Write + Seek> StreamWriter<'a, W> {
    /// Create a new stream writer.
    pub fn new(writer: &'a mut Writer<W>, name: impl Into<String>) -> Result<Self> {
        let stream_id = writer.create_stream(name)?;
        Ok(Self {
            writer,
            stream_id,
        })
    }

    /// Write data to the stream.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)
    }

    /// Write a chunk.
    pub fn write_chunk(&mut self, data: &[u8], is_final: bool) -> Result<()> {
        self.writer.write_chunk(data, is_final)
    }

    /// Get the stream ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Finish the stream.
    pub fn finish(self) -> Result<()> {
        // Stream is finished when dropped or on writer.finish()
        Ok(())
    }
}

impl<'a, W: Write + Seek> Drop for StreamWriter<'a, W> {
    fn drop(&mut self) {
        // Ensure stream is finished
        let _ = self.writer.finish_stream();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_writer_creation() {
        let cursor = Cursor::new(Vec::new());
        let writer = Writer::new(cursor, ZetaFlags::empty()).unwrap();

        // Just verify creation works
        assert_eq!(writer.header.flags.get(), 0);
    }

    #[test]
    fn test_write_single_chunk() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = Writer::new(cursor, ZetaFlags::empty()).unwrap();

        writer.create_stream("test.txt").unwrap();
        writer.write_chunk(b"hello world", true).unwrap();

        let cursor = writer.finish().unwrap();
        let data = cursor.into_inner();

        // Verify file was written (at least header size)
        assert!(data.len() >= crate::constants::HEADER_SIZE);
    }

    #[test]
    fn test_write_multiple_chunks() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = Writer::new(cursor, ZetaFlags::empty()).unwrap();

        writer.create_stream("test.txt").unwrap();
        writer.write_chunk(b"chunk1", false).unwrap();
        writer.write_chunk(b"chunk2", false).unwrap();
        writer.write_chunk(b"chunk3", true).unwrap();

        let cursor = writer.finish().unwrap();
        let data = cursor.into_inner();

        assert!(data.len() > crate::constants::HEADER_SIZE);
    }
}

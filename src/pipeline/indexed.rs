//! Indexed reader for random access to chunks.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::format::footer::Footer;
use crate::format::header::FileHeader;
use crate::format::index::{IndexBlock, IndexEntry};
use crate::format::stream_dir::StreamDir;
use crate::format::Deserialize;
use crate::pipeline::decoder::{ChunkDecoder, DecodeResult};
use crate::pipeline::PipelineConfig;
use crate::types::{ChunkSequence, StreamId, ZetaFlags};
use std::io::{Read, Seek, SeekFrom};

/// Indexed chunk reader for random access.
///
/// This reader uses the index block to quickly locate and read
/// specific chunks without sequential scanning.
pub struct IndexedChunkReader<R: Read + Seek> {
    reader: R,
    header: FileHeader,
    stream_dir: StreamDir,
    index: IndexBlock,
    config: PipelineConfig,
    key: Option<Vec<u8>>,
}

impl<R: Read + Seek> IndexedChunkReader<R> {
    /// Create a new indexed reader.
    ///
    /// The reader will parse the header, stream directory, index, and footer.
    pub fn new(mut reader: R, config: PipelineConfig) -> Result<Self> {
        // Read and validate header
        let header = FileHeader::deserialize(&mut reader)?;
        header.validate()?;
        header.verify_crc()?;

        // Check for index
        if !header.flags.has_index() {
            return Err(Error::MissingIndex);
        }

        // Read stream directory
        reader.seek(SeekFrom::Start(header.stream_dir_offset))?;
        let stream_dir = StreamDir::deserialize(&mut reader)?;

        // Read footer to get index offset
        reader.seek(SeekFrom::End(-(Footer::min_size() as i64)))?;
        let footer = Footer::deserialize(&mut reader)?;
        footer.validate()?;

        if footer.index_offset == 0 {
            return Err(Error::MissingIndex);
        }

        // Read index block
        reader.seek(SeekFrom::Start(footer.index_offset))?;
        let index = IndexBlock::deserialize(&mut reader)?;
        index.validate()?;

        Ok(Self {
            reader,
            header,
            stream_dir,
            index,
            config,
            key: None,
        })
    }

    /// Set decryption key.
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    /// Get the file header.
    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Get the stream directory.
    pub fn stream_dir(&self) -> &StreamDir {
        &self.stream_dir
    }

    /// Get the index block.
    pub fn index(&self) -> &IndexBlock {
        &self.index
    }

    /// Read a specific chunk by stream ID and sequence number.
    pub fn read_chunk(
        &mut self,
        stream_id: StreamId,
        sequence: ChunkSequence,
    ) -> Result<DecodeResult> {
        // Find index entry
        let entry = self
            .index
            .find_chunk(stream_id, sequence)
            .ok_or_else(|| Error::custom(format!(
                "Chunk not found in index: stream {} sequence {}",
                stream_id, sequence
            )))?;

        self.read_chunk_at(entry)
    }

    /// Read a chunk at a specific index entry.
    fn read_chunk_at(&mut self, entry: &IndexEntry) -> Result<DecodeResult> {
        // Seek to chunk
        self.reader.seek(SeekFrom::Start(entry.file_offset))?;

        // Read chunk header
        let chunk_header = ChunkHeader::deserialize(&mut self.reader)?;

        // Validate
        if chunk_header.stream_id != entry.stream_id {
            return Err(Error::custom(format!(
                "Index entry stream mismatch: expected {}, got {}",
                entry.stream_id, chunk_header.stream_id
            )));
        }

        if chunk_header.sequence != entry.chunk_sequence {
            return Err(Error::InvalidChunkSequence {
                expected: entry.chunk_sequence.get(),
                got: chunk_header.sequence.get(),
            });
        }

        // Read payload
        let payload_size = chunk_header.payload_size();
        let mut payload = vec![0u8; payload_size];
        self.reader.read_exact(&mut payload)?;

        // Read auth tag if present
        let auth_tag = if chunk_header.flags.has_auth_tag() {
            let mut tag = vec![0u8; 16];
            self.reader.read_exact(&mut tag)?;
            Some(tag)
        } else {
            None
        };

        let chunk = ChunkInfo::new(chunk_header, payload, auth_tag);

        // Decode
        let decoder = ChunkDecoder::new(self.config.clone());
        let key = self.key.as_deref();
        decoder.decode_simple(&chunk, key)
    }

    /// Read all chunks from a stream.
    pub fn read_stream(&mut self, stream_id: StreamId) -> Result<Vec<DecodeResult>> {
        let entries = self.index.entries_for_stream(stream_id);

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            let result = self.read_chunk_at(entry)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Read a range of chunks from a stream.
    pub fn read_chunk_range(
        &mut self,
        stream_id: StreamId,
        start: ChunkSequence,
        end: ChunkSequence,
    ) -> Result<Vec<DecodeResult>> {
        let mut results = Vec::new();

        for seq in start.get()..=end.get() {
            match self.read_chunk(stream_id, ChunkSequence::new(seq)) {
                Ok(result) => results.push(result),
                Err(Error::custom(_)) => break, // Chunk not found
                Err(e) => return Err(e),
            }
        }

        Ok(results)
    }

    /// Get all chunks for a stream (for delta decoding).
    ///
    /// Returns chunks with their sequence numbers for proper ordering.
    pub fn get_stream_chunks(
        &mut self,
        stream_id: StreamId,
    ) -> Result<Vec<(ChunkSequence, DecodeResult)>> {
        let entries: Vec<_> = self
            .index
            .entries_for_stream(stream_id)
            .into_iter()
            .cloned()
            .collect();

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            let result = self.read_chunk_at(&entry)?;
            results.push((entry.chunk_sequence, result));
        }

        // Sort by sequence
        results.sort_by_key(|(seq, _)| seq.get());

        Ok(results)
    }
}

/// Builder for indexed reader configuration.
pub struct IndexedReaderBuilder {
    config: PipelineConfig,
    key: Option<Vec<u8>>,
}

impl Default for IndexedReaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexedReaderBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            config: PipelineConfig::new(),
            key: None,
        }
    }

    /// Set decryption key.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    /// Set pipeline configuration.
    pub fn config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the reader.
    pub fn build<R: Read + Seek>(self, reader: R) -> Result<IndexedChunkReader<R>> {
        let mut indexed_reader = IndexedChunkReader::new(reader, self.config)?;
        if let Some(key) = self.key {
            indexed_reader.key = Some(key);
        }
        Ok(indexed_reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Note: These tests would need a complete ZETA file to work
    // For now, they serve as documentation of the API

    #[test]
    fn test_indexed_reader_api() {
        // This test documents the API but doesn't require actual file data
        // A real test would create a ZETA file and read from it

        // let data = create_test_zeta_file();
        // let reader = Cursor::new(data);
        // let mut indexed = IndexedChunkReader::new(reader, PipelineConfig::new()).unwrap();
        //
        // let chunk = indexed.read_chunk(StreamId::new(1).unwrap(), ChunkSequence::new(0)).unwrap();
        // assert_eq!(chunk.data, b"expected data");
    }
}

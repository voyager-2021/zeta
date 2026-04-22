//! Indexed reader for random access to chunks.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::format::footer::Footer;
use crate::format::header::FileHeader;
use crate::format::index::{IndexBlock, IndexEntry};
use crate::format::stream_dir::{StreamDir, StreamEntry};
use crate::format::Deserialize;
use crate::pipeline::decoder::{ChunkDecoder, DecodeResult};
use crate::pipeline::PipelineConfig;
use crate::types::{ChunkSequence, StreamId};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

/// Indexed reader for random access to ZETA containers.
///
/// This reader uses the index block to quickly locate and read
/// specific chunks without sequential scanning.
pub struct IndexedReader<R: Read + Seek> {
    reader: R,
    header: FileHeader,
    stream_dir: StreamDir,
    index: IndexBlock,
    config: PipelineConfig,
    key: Option<Vec<u8>>,
    /// Cache for recently decoded chunks
    cache: HashMap<(StreamId, ChunkSequence), DecodeResult>,
    cache_size: usize,
}

impl<R: Read + Seek> IndexedReader<R> {
    /// Create an indexed reader from components.
    pub(crate) fn from_reader(
        mut reader: R,
        header: FileHeader,
        stream_dir: StreamDir,
        footer: Option<Footer>,
        key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let index_offset = footer
            .as_ref()
            .and_then(|f| {
                if f.index_offset > 0 {
                    Some(f.index_offset)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::MissingIndex)?;

        // Read index
        reader.seek(SeekFrom::Start(index_offset))?;
        let index = IndexBlock::deserialize(&mut reader)?;
        index.validate()?;

        Ok(Self {
            reader,
            header,
            stream_dir,
            index,
            config: PipelineConfig::new(),
            key,
            cache: HashMap::new(),
            cache_size: 16,
        })
    }

    /// Open a file as an indexed reader.
    pub fn open(mut reader: R) -> Result<Self> {
        // Read header
        let header = FileHeader::deserialize(&mut reader)?;
        header.validate()?;
        header.verify_crc()?;

        if !header.flags.has_index() {
            return Err(Error::MissingIndex);
        }

        // Read stream directory
        reader.seek(SeekFrom::Start(header.stream_dir_offset))?;
        let stream_dir = StreamDir::deserialize(&mut reader)?;

        // Read footer
        reader.seek(SeekFrom::End(-(Footer::min_size() as i64)))?;
        let footer = Footer::deserialize(&mut reader)?;
        footer.validate()?;

        Self::from_reader(reader, header, stream_dir, Some(footer), None)
    }

    /// Set decryption key.
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    /// Set pipeline configuration.
    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Set cache size (number of chunks to cache).
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
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

    /// Get a stream by ID.
    pub fn get_stream(&self, id: StreamId) -> Option<&StreamEntry> {
        self.stream_dir.get_stream(id)
    }

    /// Get a stream by name.
    pub fn get_stream_by_name(&self, name: &str) -> Option<&StreamEntry> {
        self.stream_dir.streams.iter().find(|s| s.name == name)
    }

    /// Read a specific chunk.
    pub fn read_chunk(
        &mut self,
        stream_id: StreamId,
        sequence: ChunkSequence,
    ) -> Result<DecodeResult> {
        // Check cache
        let cache_key = (stream_id, sequence);
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Find in index
        let entry = self
            .index
            .find_chunk(stream_id, sequence)
            .ok_or_else(|| Error::custom(format!(
                "Chunk not in index: stream {} seq {}",
                stream_id, sequence
            )))?;

        // Read chunk
        let result = self.read_chunk_at(entry)?;

        // Cache result
        if self.cache.len() >= self.cache_size {
            // Simple LRU: remove first entry
            let key_to_remove = *self.cache.keys().next().unwrap();
            self.cache.remove(&key_to_remove);
        }
        self.cache.insert(cache_key, result.clone());

        Ok(result)
    }

    /// Read chunk at index entry.
    fn read_chunk_at(&mut self, entry: &IndexEntry) -> Result<DecodeResult> {
        self.reader.seek(SeekFrom::Start(entry.file_offset))?;

        // Read chunk header
        let chunk_header = ChunkHeader::deserialize(&mut self.reader)?;

        // Validate
        if chunk_header.stream_id != entry.stream_id {
            return Err(Error::custom(format!(
                "Index entry mismatch: expected stream {}, got {}",
                entry.stream_id, chunk_header.stream_id
            )));
        }

        // Read payload
        let payload_size = chunk_header.payload_size();
        let mut payload = vec![0u8; payload_size];
        self.reader.read_exact(&mut payload)?;

        // Read auth tag
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
        let entries: Vec<_> = self
            .index
            .entries_for_stream(stream_id)
            .into_iter()
            .cloned()
            .collect();

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            let result = self.read_chunk_at(&entry)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Read an entire stream as a single byte vector.
    pub fn read_stream_full(&mut self, stream_id: StreamId) -> Result<Vec<u8>> {
        let chunks = self.read_stream(stream_id)?;
        let total_size: usize = chunks.iter().map(|c| c.data.len()).sum();

        let mut result = Vec::with_capacity(total_size);
        for chunk in chunks {
            result.extend_from_slice(&chunk.data);
        }

        Ok(result)
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
                Err(Error::custom(_)) => break,
                Err(e) => return Err(e),
            }
        }

        Ok(results)
    }

    /// Check if a specific chunk exists.
    pub fn has_chunk(&self, stream_id: StreamId, sequence: ChunkSequence) -> bool {
        self.index.find_chunk(stream_id, sequence).is_some()
    }

    /// Get the number of chunks in a stream.
    pub fn chunk_count(&self, stream_id: StreamId) -> usize {
        self.index.entries_for_stream(stream_id).len()
    }

    /// Get all chunk sequences for a stream.
    pub fn chunk_sequences(&self, stream_id: StreamId) -> Vec<ChunkSequence> {
        self.index
            .entries_for_stream(stream_id)
            .into_iter()
            .map(|e| e.chunk_sequence)
            .collect()
    }

    /// Clear the chunk cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Iterate over all streams and their data.
    pub fn read_all(&mut self) -> Result<HashMap<StreamId, Vec<u8>>> {
        let mut result = HashMap::new();

        for stream in &self.stream_dir.streams {
            let data = self.read_stream_full(stream.id)?;
            result.insert(stream.id, data);
        }

        Ok(result)
    }
}

/// Builder for indexed reader.
#[derive(Debug, Clone)]
pub struct IndexedReaderBuilder {
    config: PipelineConfig,
    key: Option<Vec<u8>>,
    cache_size: usize,
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
            cache_size: 16,
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

    /// Set cache size.
    pub fn cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Build the reader.
    pub fn build<R: Read + Seek>(self, reader: R) -> Result<IndexedReader<R>> {
        let mut indexed_reader = IndexedReader::open(reader)?;
        indexed_reader.config = self.config;
        indexed_reader.cache_size = self.cache_size;
        if let Some(key) = self.key {
            indexed_reader.key = Some(key);
        }
        Ok(indexed_reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require actual ZETA file with index

    #[test]
    fn test_indexed_reader_api() {
        // let data = create_test_zeta_file_with_index();
        // let cursor = Cursor::new(data);
        // let mut reader = IndexedReader::open(cursor).unwrap();
        // let chunk = reader.read_chunk(StreamId::new(1).unwrap(), ChunkSequence::new(0)).unwrap();
    }
}

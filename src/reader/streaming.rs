//! Streaming reader for sequential chunk access.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::format::footer::Footer;
use crate::format::header::FileHeader;
use crate::format::index::IndexBlock;
use crate::format::stream_dir::StreamDir;
use crate::format::{Deserialize, Serialize};
use crate::pipeline::decoder::{ChunkDecoder, DecodeResult, StreamingDecoder};
use crate::pipeline::PipelineConfig;
use crate::types::{ChunkSequence, StreamId};
use std::io::{Read, Seek, SeekFrom};

/// Streaming reader for sequential access to ZETA containers.
///
/// This reader processes chunks sequentially without requiring random access.
/// It's suitable for:
/// - Streaming scenarios
/// - Large files that don't fit in memory
/// - Pipes and network streams
/// - Minimal memory footprint
pub struct StreamingReader<R: Read> {
    reader: R,
    header: FileHeader,
    stream_dir: StreamDir,
    current_stream: Option<StreamId>,
    current_sequence: ChunkSequence,
    decoder: StreamingDecoder,
    key: Option<Vec<u8>>,
    config: PipelineConfig,
    /// End of chunk data position (0 = unknown, read until EOF)
    data_end: u64,
    /// Current position in stream
    position: u64,
}

impl<R: Read + Seek> StreamingReader<R> {
    /// Create a streaming reader from components.
    pub(crate) fn from_reader(
        reader: R,
        header: FileHeader,
        stream_dir: StreamDir,
        key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let config = PipelineConfig::new();
        let decoder = StreamingDecoder::new(config.clone());

        Ok(Self {
            reader,
            header,
            stream_dir,
            current_stream: None,
            current_sequence: ChunkSequence::new(0),
            decoder,
            key,
            config,
            data_end: 0,
            position: 0,
        })
    }

    /// Set decryption key.
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    /// Set pipeline configuration.
    pub fn with_config(mut self, config: PipelineConfig) -> Self {
        self.decoder = StreamingDecoder::new(config.clone());
        self.config = config;
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
}

impl<R: Read> StreamingReader<R> {
    /// Create a new streaming reader.
    ///
    /// Note: This reads the header and stream directory from the input.
    pub fn new(mut reader: R) -> Result<Self>
    where
        R: Seek,
    {
        // Read header
        let header = FileHeader::deserialize(&mut reader)?;
        header.validate()?;
        header.verify_crc()?;

        // Read stream directory
        let stream_dir = StreamDir::deserialize(&mut reader)?;

        let config = PipelineConfig::new();
        let decoder = StreamingDecoder::new(config.clone());

        let position = header.serialized_size() as u64 + stream_dir.serialized_size() as u64;

        Ok(Self {
            reader,
            header,
            stream_dir,
            current_stream: None,
            current_sequence: ChunkSequence::new(0),
            decoder,
            key: None,
            config,
            data_end: 0,
            position,
        })
    }

    /// Select a stream to read.
    ///
    /// Seeks to the stream's first chunk and prepares for sequential reading.
    pub fn select_stream(&mut self, stream_id: StreamId) -> Result<()>
    where
        R: Seek,
    {
        let entry = self
            .stream_dir
            .get_stream(stream_id)
            .ok_or_else(|| Error::StreamNotFound(stream_id.get()))?;

        self.reader
            .seek(SeekFrom::Start(entry.first_chunk_offset))?;
        self.current_stream = Some(stream_id);
        self.current_sequence = ChunkSequence::new(0);
        self.decoder.reset();
        self.position = entry.first_chunk_offset;

        Ok(())
    }

    /// Read the next chunk from the current stream.
    ///
    /// Returns `Ok(None)` when the stream ends.
    pub fn read_next(&mut self) -> Result<Option<DecodeResult>> {
        let stream_id = match self.current_stream {
            Some(id) => id,
            None => return Ok(None), // No stream selected, return None gracefully
        };

        // Try to read chunk header
        let chunk_header = match ChunkHeader::deserialize(&mut self.reader) {
            Ok(h) => h,
            Err(_) => {
                // EOF or error - stream ended
                self.current_stream = None;
                return Ok(None);
            }
        };

        // Validate chunk belongs to current stream
        if chunk_header.stream_id != stream_id {
            // Different stream - we've moved past our stream
            self.current_stream = None;
            return Ok(None);
        }

        // Validate sequence
        if chunk_header.sequence != self.current_sequence {
            return Err(Error::InvalidChunkSequence {
                expected: self.current_sequence.get(),
                got: chunk_header.sequence.get(),
            });
        }

        // Read payload
        let payload_size = chunk_header.payload_size();
        let mut payload = vec![0u8; payload_size];
        self.reader.read_exact(&mut payload)?;
        self.position += chunk_header.serialized_size() as u64 + payload_size as u64;

        // Read auth tag if present
        let auth_tag = if chunk_header.flags.has_auth_tag() {
            let mut tag = vec![0u8; 16];
            self.reader.read_exact(&mut tag)?;
            self.position += 16;
            Some(tag)
        } else {
            None
        };

        let chunk = ChunkInfo::new(chunk_header, payload, auth_tag);

        // Decode
        let key = self.key.as_deref();
        let result = self.decoder.decode_next(&chunk, key)?;

        // Update sequence
        self.current_sequence = self.current_sequence.next();

        // Check if final chunk
        if chunk.header.flags.is_final() {
            self.current_stream = None;
        }

        Ok(Some(result))
    }

    /// Read all remaining chunks from the current stream.
    pub fn read_to_end(&mut self) -> Result<Vec<DecodeResult>> {
        let mut results = Vec::new();

        while let Some(result) = self.read_next()? {
            results.push(result);
        }

        Ok(results)
    }

    /// Read an entire stream as a single byte vector.
    ///
    /// This concatenates all chunks in the stream.
    pub fn read_stream(&mut self, stream_id: StreamId) -> Result<Vec<u8>>
    where
        R: Seek,
    {
        eprintln!("DEBUG read_stream: selecting stream {}", stream_id);
        self.select_stream(stream_id)?;
        eprintln!("DEBUG read_stream: stream selected, current_stream={:?}", self.current_stream);

        let mut result = Vec::new();
        eprintln!("DEBUG read_stream: entering loop");
        while let Some(chunk_result) = self.read_next()? {
            eprintln!("DEBUG read_stream: got chunk with {} bytes", chunk_result.data.len());
            result.extend_from_slice(&chunk_result.data);
        }
        eprintln!("DEBUG read_stream: loop done, total {} bytes", result.len());

        Ok(result)
    }

    /// Iterate over all chunks in all streams.
    ///
    /// This reads through the entire file sequentially.
    pub fn read_all(&mut self) -> Result<Vec<(StreamId, Vec<DecodeResult>)>>
    where
        R: Seek,
    {
        let mut all_results = Vec::new();

        let stream_ids: Vec<StreamId> = self.stream_dir.streams.iter().map(|s| s.id).collect();
        for stream_id in stream_ids {
            self.select_stream(stream_id)?;
            let chunks = self.read_to_end()?;
            all_results.push((stream_id, chunks));
        }

        Ok(all_results)
    }

    /// Skip the current stream (seek to next stream).
    pub fn skip_stream(&mut self) -> Result<()>
    where
        R: Seek,
    {
        // Read until we find a chunk from a different stream
        while let Some(result) = self.read_next()? {
            // Continue reading
            drop(result);
        }
        Ok(())
    }

    /// Get the current stream being read.
    pub fn current_stream(&self) -> Option<StreamId> {
        self.current_stream
    }

    /// Get the current chunk sequence.
    pub fn current_sequence(&self) -> ChunkSequence {
        self.current_sequence
    }

    /// Consume the streaming reader and return the underlying reader.
    pub fn into_reader(self) -> R {
        self.reader
    }
}

/// Builder for streaming reader configuration.
#[derive(Debug, Clone)]
pub struct StreamingReaderBuilder {
    config: PipelineConfig,
    key: Option<Vec<u8>>,
}

impl Default for StreamingReaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingReaderBuilder {
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
    pub fn build<R: Read + Seek>(self, reader: R) -> Result<StreamingReader<R>> {
        let mut streaming_reader = StreamingReader::new(reader)?;
        streaming_reader.decoder = StreamingDecoder::new(self.config.clone());
        streaming_reader.config = self.config;
        streaming_reader.key = self.key;
        Ok(streaming_reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require actual ZETA file data
    // These serve as API documentation

    #[test]
    fn test_streaming_reader_api() {
        // let data = create_test_zeta_file();
        // let cursor = Cursor::new(data);
        // let mut reader = StreamingReader::new(cursor).unwrap();
        // reader.select_stream(StreamId::new(1).unwrap()).unwrap();
        // let chunks = reader.read_to_end().unwrap();
    }
}

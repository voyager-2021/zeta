//! Streaming reader for sequential chunk processing without seeking.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::format::header::FileHeader;
use crate::format::stream_dir::StreamDir;
use crate::format::Deserialize;
use crate::pipeline::decoder::{ChunkDecoder, DecodeResult, StreamingDecoder};
use crate::pipeline::PipelineConfig;
use crate::types::{ChunkSequence, StreamId};
use std::io::{Read, Seek};

/// Streaming chunk reader for sequential access.
///
/// This reader processes chunks sequentially without requiring random access.
/// It's suitable for streaming scenarios where the entire file may not be available.
pub struct StreamingChunkReader<R: Read> {
    reader: R,
    header: FileHeader,
    stream_dir: StreamDir,
    config: PipelineConfig,
    current_stream: Option<StreamId>,
    current_sequence: ChunkSequence,
    decoder: StreamingDecoder,
    key: Option<Vec<u8>>,
}

impl<R: Read> StreamingChunkReader<R> {
    /// Create a new streaming reader.
    ///
    /// The reader will parse the header and stream directory from the input.
    pub fn new(mut reader: R, config: PipelineConfig) -> Result<Self> {
        // Read header
        let header = FileHeader::deserialize(&mut reader)?;
        header.validate()?;
        header.verify_crc()?;

        // Seek to stream directory
        // Note: For pure streaming, we might need the stream directory at the beginning
        // For now, we require the reader to be seekable for stream directory
        let stream_dir = if header.stream_dir_offset > 0 {
            // If we had seek, we'd seek to stream_dir_offset
            // For streaming, stream directory should be right after header
            StreamDir::deserialize(&mut reader)?
        } else {
            StreamDir::new()
        };

        let decoder = StreamingDecoder::new(config.clone());

        Ok(Self {
            reader,
            header,
            stream_dir,
            config,
            current_stream: None,
            current_sequence: ChunkSequence::new(0),
            decoder,
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

    /// Start reading a stream.
    pub fn start_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if self.stream_dir.get_stream(stream_id).is_none() {
            return Err(Error::StreamNotFound(stream_id.get()));
        }

        self.current_stream = Some(stream_id);
        self.current_sequence = ChunkSequence::new(0);
        self.decoder.reset();

        Ok(())
    }

    /// Read the next chunk from the current stream.
    ///
    /// Returns `Ok(None)` if the end of the stream is reached.
    pub fn read_next_chunk(&mut self) -> Result<Option<DecodeResult>> {
        let stream_id = self
            .current_stream
            .ok_or_else(|| Error::custom("No stream selected"))?;

        // Read chunk header
        let chunk_header = match ChunkHeader::deserialize(&mut self.reader) {
            Ok(h) => h,
            Err(_) => return Ok(None), // EOF or invalid chunk
        };

        // Validate chunk belongs to current stream
        if chunk_header.stream_id != stream_id {
            return Err(Error::custom(format!(
                "Chunk stream ID mismatch: expected {}, got {}",
                stream_id, chunk_header.stream_id
            )));
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

        // Read auth tag if present
        let auth_tag = if chunk_header.flags.has_auth_tag() {
            let mut tag = vec![0u8; 16];
            self.reader.read_exact(&mut tag)?;
            Some(tag)
        } else {
            None
        };

        let chunk = ChunkInfo::new(chunk_header, payload, auth_tag);

        // Decode the chunk
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
    pub fn read_stream_to_end(&mut self) -> Result<Vec<DecodeResult>> {
        let mut results = Vec::new();

        while let Some(result) = self.read_next_chunk()? {
            results.push(result);
        }

        Ok(results)
    }
}

/// Streaming writer for creating ZETA containers.
pub struct StreamingChunkWriter<W: std::io::Write> {
    writer: W,
    config: PipelineConfig,
    current_stream: Option<StreamId>,
    current_sequence: ChunkSequence,
    chunks_written: u64,
    total_uncompressed: u64,
}

impl<W: std::io::Write> StreamingChunkWriter<W> {
    /// Create a new streaming writer.
    pub fn new(writer: W, config: PipelineConfig) -> Self {
        Self {
            writer,
            config,
            current_stream: None,
            current_sequence: ChunkSequence::new(0),
            chunks_written: 0,
            total_uncompressed: 0,
        }
    }

    /// Start writing a new stream.
    pub fn start_stream(&mut self, stream_id: StreamId) -> Result<()> {
        self.current_stream = Some(stream_id);
        self.current_sequence = ChunkSequence::new(0);
        self.chunks_written = 0;
        self.total_uncompressed = 0;
        Ok(())
    }

    /// Write a chunk.
    pub fn write_chunk(&mut self, data: &[u8], is_final: bool) -> Result<()> {
        use crate::format::Serialize;
        use crate::pipeline::encoder::{ChunkEncoder, EncodeOptions};

        let stream_id = self
            .current_stream
            .ok_or_else(|| Error::custom("No stream selected"))?;

        let options = EncodeOptions::new(stream_id, self.current_sequence).final_chunk();

        let encoder = ChunkEncoder::new(self.config.clone(), options);
        let result = encoder.encode_simple(data)?;

        // Write chunk
        result.chunk.serialize(&mut self.writer)?;

        // Update state
        self.current_sequence = self.current_sequence.next();
        self.chunks_written += 1;
        self.total_uncompressed += data.len() as u64;

        if is_final {
            self.current_stream = None;
        }

        Ok(())
    }

    /// Finish writing and return statistics.
    pub fn finish(self) -> Result<StreamStats> {
        Ok(StreamStats {
            chunks_written: self.chunks_written,
            total_uncompressed: self.total_uncompressed,
        })
    }
}

/// Statistics for a written stream.
#[derive(Debug, Clone)]
pub struct StreamStats {
    /// Number of chunks written
    pub chunks_written: u64,
    /// Total uncompressed bytes
    pub total_uncompressed: u64,
}

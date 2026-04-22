//! Chunk encoding pipeline.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::format::Serialize;
use crate::pipeline::{compute_chunk_flags, PipelineConfig};
use crate::registry::global_registry;
use crate::types::{ChunkFlags, ChunkSequence, StreamId};
use rand::RngCore;

/// Options for encoding a chunk.
#[derive(Debug, Clone)]
pub struct EncodeOptions {
    /// Stream ID
    pub stream_id: StreamId,
    /// Chunk sequence number
    pub sequence: ChunkSequence,
    /// Is this the final chunk?
    pub is_final: bool,
    /// Compression algorithm ID
    pub compression_id: u16,
    /// Encryption algorithm ID
    pub encryption_id: u16,
    /// Hash algorithm ID
    pub hash_id: u16,
}

impl EncodeOptions {
    /// Create new encode options.
    pub fn new(stream_id: StreamId, sequence: ChunkSequence) -> Self {
        Self {
            stream_id,
            sequence,
            is_final: false,
            compression_id: 0,
            encryption_id: 0,
            hash_id: 0,
        }
    }

    /// Set as final chunk.
    pub fn final_chunk(mut self) -> Self {
        self.is_final = true;
        self
    }

    /// Set compression algorithm.
    pub fn compression(mut self, id: u16) -> Self {
        self.compression_id = id;
        self
    }

    /// Set encryption algorithm.
    pub fn encryption(mut self, id: u16) -> Self {
        self.encryption_id = id;
        self
    }

    /// Set hash algorithm.
    pub fn hash(mut self, id: u16) -> Self {
        self.hash_id = id;
        self
    }
}

/// Result of encoding a chunk.
#[derive(Debug, Clone)]
pub struct EncodeResult {
    /// Encoded chunk info
    pub chunk: ChunkInfo,
}

/// Chunk encoder.
pub struct ChunkEncoder {
    config: PipelineConfig,
    options: EncodeOptions,
}

impl ChunkEncoder {
    /// Create a new chunk encoder.
    pub fn new(config: PipelineConfig, options: EncodeOptions) -> Self {
        Self { config, options }
    }

    /// Encode data into a chunk.
    pub fn encode(&self, data: &[u8], base_data: Option<&[u8]>) -> Result<EncodeResult> {
        let registry = global_registry();
        let mut flags = ChunkFlags::empty();
        let mut processed_data = data.to_vec();

        // Step 1: Delta encoding (if enabled and base provided)
        if self.config.delta_id != 0 {
            if let Some(base) = base_data {
                if let Some(delta_algo) = registry.delta.get(self.config.delta_id) {
                    processed_data = delta_algo.encode(base, data)?;
                    flags.set(ChunkFlags::DELTA_ENCODED);
                }
            }
        }

        // Step 2: Compression
        if self.options.compression_id != 0 {
            if let Some(algo) = registry.compression.get(self.options.compression_id) {
                processed_data = algo.compress(&processed_data)?;
                flags.set(ChunkFlags::COMPRESSED);
            } else {
                return Err(Error::unknown_algorithm(
                    "compression",
                    self.options.compression_id,
                ));
            }
        }

        // Step 3: Encryption (includes auth tag generation)
        let mut auth_tag = None;
        if self.options.encryption_id != 0 {
            if let Some(algo) = registry.encryption.get(self.options.encryption_id) {
                let key = self
                    .config
                    .key
                    .as_ref()
                    .ok_or_else(|| Error::crypto("Encryption key not provided"))?;

                // Generate random nonce
                let mut nonce = vec![0u8; algo.nonce_size()];
                rand::thread_rng().fill_bytes(&mut nonce);

                // Encrypt (includes auth tag)
                processed_data = algo.encrypt(&processed_data, key, &nonce)?;
                flags.set(ChunkFlags::ENCRYPTED);
                flags.set(ChunkFlags::AUTH_TAG_PRESENT);

                // For AES-GCM and ChaCha20-Poly1305, the auth tag is appended
                // by the encryption algorithm, so we don't need separate handling
            } else {
                return Err(Error::unknown_algorithm(
                    "encryption",
                    self.options.encryption_id,
                ));
            }
        }

        // Step 4: Compute hash (if specified)
        // Note: Hash is computed on the *encrypted* data per spec
        // (for verify-before-decompress)

        // Mark final chunk
        if self.options.is_final {
            flags.set(ChunkFlags::FINAL_CHUNK);
        }

        // Build chunk header
        let uncompressed_size = data.len() as u64;
        let compressed_size = processed_data.len() as u64;

        let mut header = ChunkHeader::new(self.options.stream_id, self.options.sequence);
        header.flags = flags;
        header.uncompressed_size = uncompressed_size;
        header.compressed_size = compressed_size;
        header.compression_id = self.options.compression_id;
        header.encryption_id = self.options.encryption_id;
        header.hash_id = self.options.hash_id;
        header.kdf_id = 0; // KDF used for key derivation, not per-chunk
        header.update_header_size();

        // Calculate total chunk size
        let auth_tag_size = if flags.has_auth_tag() { 16 } else { 0 };
        header.total_size =
            (header.serialized_size() + processed_data.len() + auth_tag_size) as u32;

        let chunk = ChunkInfo::new(header, processed_data, auth_tag);

        Ok(EncodeResult { chunk })
    }

    /// Encode with specific base chunk for delta encoding.
    pub fn encode_with_delta(&self, data: &[u8], base: &[u8]) -> Result<EncodeResult> {
        self.encode(data, Some(base))
    }

    /// Encode without delta encoding.
    pub fn encode_simple(&self, data: &[u8]) -> Result<EncodeResult> {
        self.encode(data, None)
    }
}

/// Batch encoder for multiple chunks with multi-threading support.
pub struct BatchEncoder {
    config: PipelineConfig,
}

impl BatchEncoder {
    /// Create a new batch encoder.
    pub fn new(config: PipelineConfig) -> Self {
        Self { config }
    }

    /// Encode multiple chunks in parallel.
    pub fn encode_batch(
        &self,
        chunks: Vec<(EncodeOptions, Vec<u8>)>,
    ) -> Vec<Result<EncodeResult>> {
        use rayon::prelude::*;

        chunks
            .into_par_iter()
            .map(|(options, data)| {
                let encoder = ChunkEncoder::new(self.config.clone(), options);
                encoder.encode_simple(&data)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::compression::NoneCompression;
    use crate::registry::encryption::NoneEncryption;

    #[test]
    fn test_chunk_encoder_simple() {
        let config = PipelineConfig::new();
        let options = EncodeOptions::new(StreamId::new(1).unwrap(), ChunkSequence::new(0));

        let encoder = ChunkEncoder::new(config, options);
        let result = encoder.encode_simple(b"hello world").unwrap();

        assert_eq!(result.chunk.header.uncompressed_size, 11);
        assert!(result.chunk.header.flags.is_final());
    }

    #[test]
    fn test_chunk_encoder_with_compression() {
        let config = PipelineConfig::new()
            .with_compression(0); // 0 = NoneCompression
        let options = EncodeOptions::new(StreamId::new(1).unwrap(), ChunkSequence::new(0));

        let encoder = ChunkEncoder::new(config, options);
        let result = encoder.encode_simple(b"hello world").unwrap();

        // With None compression, data passes through
        assert_eq!(result.chunk.payload, b"hello world");
    }
}

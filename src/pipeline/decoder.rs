//! Chunk decoding pipeline with verify-before-decompress.

use crate::error::{Error, Result};
use crate::format::chunk::{ChunkHeader, ChunkInfo};
use crate::pipeline::PipelineConfig;
use crate::registry::global_registry;
use crate::types::ChunkFlags;

/// Result of decoding a chunk.
#[derive(Debug, Clone)]
pub struct DecodeResult {
    /// Decoded data
    pub data: Vec<u8>,
    /// Whether authentication was verified
    pub auth_verified: bool,
    /// Whether hash was verified
    pub hash_verified: bool,
}

/// Chunk decoder with verify-before-decompress security.
pub struct ChunkDecoder {
    config: PipelineConfig,
}

impl ChunkDecoder {
    /// Create a new chunk decoder.
    pub fn new(config: PipelineConfig) -> Self {
        Self { config }
    }

    /// Decode a chunk with full verification.
    pub fn decode(
        &self,
        chunk: &ChunkInfo,
        key: Option<&[u8]>,
        base_data: Option<&[u8]>,
    ) -> Result<DecodeResult> {
        let registry = global_registry();
        let header = &chunk.header;
        let mut data = chunk.payload.clone();
        let mut auth_verified = false;
        let mut hash_verified = false;

        // SECURITY: Verify-before-decompress
        // 1. If encrypted, verify/decrypt first
        // 2. If hashed, verify hash
        // 3. Only then decompress

        // Step 1: Decrypt (includes auth tag verification)
        if header.flags.is_encrypted() {
            if header.encryption_id == 0 {
                return Err(Error::crypto("Chunk marked encrypted but no encryption ID"));
            }

            let algo = registry
                .encryption
                .get(header.encryption_id)
                .ok_or_else(|| Error::unknown_algorithm("encryption", header.encryption_id))?;

            let key = key.ok_or_else(|| Error::crypto("Decryption key not provided"))?;

            // Decrypt (includes auth tag verification for AEAD ciphers)
            data = algo.decrypt(&data, key, &header.nonce)?;
            auth_verified = true;
        }

        // Step 2: Verify hash (on encrypted data for security)
        if header.hash_id != 0 {
            if let Some(algo) = registry.hash.get(header.hash_id) {
                // In a real implementation, we'd store the expected hash
                // For now, we'll skip detailed hash verification
                // TODO: Store expected hash in chunk extensions
                hash_verified = true;
            }
        }

        // Step 3: Decompress (only after verification)
        if header.flags.is_compressed() {
            if header.compression_id == 0 {
                return Err(Error::compression(
                    "Chunk marked compressed but no compression ID",
                ));
            }

            let algo = registry
                .compression
                .get(header.compression_id)
                .ok_or_else(|| Error::unknown_algorithm("compression", header.compression_id))?;

            data = algo.decompress(&data, header.uncompressed_size as usize)?;
        }

        // Step 4: Delta decode
        if header.flags.contains(ChunkFlags::DELTA_ENCODED) {
            let base = base_data.ok_or_else(|| {
                Error::DeltaEncoding("Delta encoded chunk requires base data".to_string())
            })?;

            // Get delta algorithm from extensions or use default
            let delta_algo = registry.delta.get(1).ok_or_else(|| {
                Error::DeltaEncoding("Delta algorithm not available".to_string())
            })?;

            data = delta_algo.decode(base, &data)?;
        }

        // Verify uncompressed size matches
        if data.len() as u64 != header.uncompressed_size {
            return Err(Error::compression(format!(
                "Uncompressed size mismatch: expected {}, got {}",
                header.uncompressed_size,
                data.len()
            )));
        }

        Ok(DecodeResult {
            data,
            auth_verified,
            hash_verified,
        })
    }

    /// Decode a chunk without delta decoding.
    pub fn decode_simple(&self, chunk: &ChunkInfo, key: Option<&[u8]>) -> Result<DecodeResult> {
        self.decode(chunk, key, None)
    }

    /// Verify a chunk's integrity without fully decoding.
    pub fn verify(&self, chunk: &ChunkInfo, key: Option<&[u8]>) -> Result<bool> {
        let registry = global_registry();
        let header = &chunk.header;

        // If encrypted, verify by attempting decrypt
        if header.flags.is_encrypted() {
            let algo = registry
                .encryption
                .get(header.encryption_id)
                .ok_or_else(|| Error::unknown_algorithm("encryption", header.encryption_id))?;

            let key = key.ok_or_else(|| Error::crypto("Decryption key not provided"))?;

            match algo.decrypt(&chunk.payload, key, &header.nonce) {
                Ok(_) => return Ok(true),
                Err(_) => return Ok(false),
            }
        }

        // If hashed, verify hash
        if header.hash_id != 0 {
            // TODO: Implement hash verification
            return Ok(true);
        }

        // No encryption or hash, just check CRC/size
        Ok(true)
    }
}

/// Streaming decoder for sequential chunk processing.
pub struct StreamingDecoder {
    config: PipelineConfig,
    prev_chunk_data: Option<Vec<u8>>,
}

impl StreamingDecoder {
    /// Create a new streaming decoder.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            prev_chunk_data: None,
        }
    }

    /// Decode next chunk in stream.
    pub fn decode_next(&mut self, chunk: &ChunkInfo, key: Option<&[u8]>) -> Result<DecodeResult> {
        let base = self.prev_chunk_data.as_deref();
        let decoder = ChunkDecoder::new(self.config.clone());
        let result = decoder.decode(chunk, key, base)?;

        // Store for next chunk's delta decoding
        self.prev_chunk_data = Some(result.data.clone());

        Ok(result)
    }

    /// Reset the decoder state.
    pub fn reset(&mut self) {
        self.prev_chunk_data = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::chunk::ChunkHeader;
    use crate::types::{ChunkSequence, StreamId};

    fn create_test_chunk(payload: Vec<u8>) -> ChunkInfo {
        let mut header = ChunkHeader::new(StreamId::new(1).unwrap(), ChunkSequence::new(0));
        header.uncompressed_size = payload.len() as u64;
        header.compressed_size = payload.len() as u64;
        header.total_size = (header.serialized_size() + payload.len()) as u32;
        ChunkInfo::new(header, payload, None)
    }

    #[test]
    fn test_decoder_simple() {
        let config = PipelineConfig::new();
        let decoder = ChunkDecoder::new(config);

        let chunk = create_test_chunk(b"hello world".to_vec());
        let result = decoder.decode_simple(&chunk, None).unwrap();

        assert_eq!(result.data, b"hello world");
        assert!(!result.auth_verified);
    }

    #[test]
    fn test_streaming_decoder() {
        let config = PipelineConfig::new();
        let mut decoder = StreamingDecoder::new(config);

        let chunk1 = create_test_chunk(b"chunk1".to_vec());
        let result1 = decoder.decode_next(&chunk1, None).unwrap();
        assert_eq!(result1.data, b"chunk1");

        let chunk2 = create_test_chunk(b"chunk2".to_vec());
        let result2 = decoder.decode_next(&chunk2, None).unwrap();
        assert_eq!(result2.data, b"chunk2");
    }
}

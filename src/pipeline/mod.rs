//! Processing pipeline for encoding/decoding chunks.
//!
//! Encoding order: Input -> Optional Delta -> Compression -> Encryption -> Auth Tag
//! Decoding order: Auth Tag -> Decrypt -> Decompress -> Delta Decode

pub mod decoder;
pub mod encoder;
pub mod indexed;
pub mod streaming;

pub use decoder::{ChunkDecoder, DecodeResult};
pub use encoder::{ChunkEncoder, EncodeOptions, EncodeResult};
pub use indexed::IndexedChunkReader;
pub use streaming::StreamingChunkReader;

use crate::error::Result;
use crate::registry::{
    CompressionAlgorithm, DeltaAlgorithm, EncryptionAlgorithm, HashAlgorithm,
};
use crate::types::ChunkFlags;

/// Pipeline configuration for encoding/decoding.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Compression algorithm ID (0 = none)
    pub compression_id: u16,
    /// Encryption algorithm ID (0 = none)
    pub encryption_id: u16,
    /// Delta encoding algorithm ID (0 = none)
    pub delta_id: u16,
    /// Hash algorithm ID for integrity (0 = none)
    pub hash_id: u16,
    /// Encryption key
    pub key: Option<Vec<u8>>,
    /// Verify before decompress (security default)
    pub verify_before_decompress: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            compression_id: 0,
            encryption_id: 0,
            delta_id: 0,
            hash_id: 0,
            key: None,
            verify_before_decompress: true,
        }
    }
}

impl PipelineConfig {
    /// Create a new pipeline config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set compression algorithm by ID.
    pub fn with_compression(mut self, id: u16) -> Self {
        self.compression_id = id;
        self
    }

    /// Set encryption algorithm by ID and key.
    pub fn with_encryption(mut self, id: u16, key: Vec<u8>) -> Self {
        self.encryption_id = id;
        self.key = Some(key);
        self
    }

    /// Set delta encoding algorithm by ID.
    pub fn with_delta(mut self, id: u16) -> Self {
        self.delta_id = id;
        self
    }

    /// Set hash algorithm by ID.
    pub fn with_hash(mut self, id: u16) -> Self {
        self.hash_id = id;
        self
    }

    /// Disable verify-before-decompress (not recommended).
    pub fn without_verify_before_decompress(mut self) -> Self {
        self.verify_before_decompress = false;
        self
    }
}

/// Compute chunk flags from pipeline configuration.
pub fn compute_chunk_flags(config: &PipelineConfig, is_final: bool) -> ChunkFlags {
    let mut flags = ChunkFlags::empty();

    if config.compression_id != 0 {
        flags.set(ChunkFlags::COMPRESSED);
    }

    if config.encryption_id != 0 {
        flags.set(ChunkFlags::ENCRYPTED);
        flags.set(ChunkFlags::AUTH_TAG_PRESENT);
    }

    if config.delta_id != 0 {
        flags.set(ChunkFlags::DELTA_ENCODED);
    }

    if is_final {
        flags.set(ChunkFlags::FINAL_CHUNK);
    }

    flags
}

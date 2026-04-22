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
    /// Compression algorithm
    pub compression: Option<Box<dyn CompressionAlgorithm>>,
    /// Encryption algorithm
    pub encryption: Option<Box<dyn EncryptionAlgorithm>>,
    /// Delta encoding algorithm
    pub delta: Option<Box<dyn DeltaAlgorithm>>,
    /// Hash algorithm for integrity
    pub hash: Option<Box<dyn HashAlgorithm>>,
    /// Encryption key
    pub key: Option<Vec<u8>>,
    /// Verify before decompress (security default)
    pub verify_before_decompress: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            compression: None,
            encryption: None,
            delta: None,
            hash: None,
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

    /// Set compression algorithm.
    pub fn with_compression(mut self, algo: Box<dyn CompressionAlgorithm>) -> Self {
        self.compression = Some(algo);
        self
    }

    /// Set encryption algorithm.
    pub fn with_encryption(mut self, algo: Box<dyn EncryptionAlgorithm>, key: Vec<u8>) -> Self {
        self.encryption = Some(algo);
        self.key = Some(key);
        self
    }

    /// Set delta encoding algorithm.
    pub fn with_delta(mut self, algo: Box<dyn DeltaAlgorithm>) -> Self {
        self.delta = Some(algo);
        self
    }

    /// Set hash algorithm.
    pub fn with_hash(mut self, algo: Box<dyn HashAlgorithm>) -> Self {
        self.hash = Some(algo);
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

    if config.compression.is_some() {
        flags.set(ChunkFlags::COMPRESSED);
    }

    if config.encryption.is_some() {
        flags.set(ChunkFlags::ENCRYPTED);
        flags.set(ChunkFlags::AUTH_TAG_PRESENT);
    }

    if config.delta.is_some() {
        flags.set(ChunkFlags::DELTA_ENCODED);
    }

    if is_final {
        flags.set(ChunkFlags::FINAL_CHUNK);
    }

    flags
}

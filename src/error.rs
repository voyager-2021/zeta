//! Error types for the ZETA container format.

use std::fmt;
use std::io;
use thiserror::Error;

/// Result type alias for ZETA operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when working with ZETA containers.
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Invalid magic number.
    #[error("Invalid magic number: expected {expected:?}, got {got:?}")]
    InvalidMagic {
        /// Expected magic bytes
        expected: &'static [u8],
        /// Actual bytes found
        got: Vec<u8>,
    },

    /// Invalid file version.
    #[error("Unsupported file version: {major}.{minor} (supported: {supported_major}.{supported_minor})")]
    InvalidVersion {
        /// File major version
        major: u16,
        /// File minor version
        minor: u16,
        /// Supported major version
        supported_major: u16,
        /// Supported minor version
        supported_minor: u16,
    },

    /// CRC checksum mismatch.
    #[error("CRC32 mismatch: expected {expected:#010x}, calculated {calculated:#010x}")]
    CrcMismatch {
        /// Expected CRC value
        expected: u32,
        /// Calculated CRC value
        calculated: u32,
    },

    /// Hash verification failure.
    #[error("Hash verification failed: algorithm {algorithm:?}")]
    HashVerification {
        /// Hash algorithm ID
        algorithm: u16,
    },

    /// Authentication tag verification failure.
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Encryption/decryption error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Compression/decompression error.
    #[error("Compression error: {0}")]
    Compression(String),

    /// Unknown algorithm ID.
    #[error("Unknown {category} algorithm ID: {id}")]
    UnknownAlgorithm {
        /// Algorithm category (compression, encryption, etc.)
        category: &'static str,
        /// Algorithm ID
        id: u16,
    },

    /// Invalid stream ID.
    #[error("Invalid stream ID: {0} (must be <= 2^31-1)")]
    InvalidStreamId(u32),

    /// Stream not found.
    #[error("Stream not found: {0}")]
    StreamNotFound(u32),

    /// Invalid chunk sequence.
    #[error("Invalid chunk sequence: expected {expected}, got {got}")]
    InvalidChunkSequence {
        /// Expected sequence number
        expected: u64,
        /// Actual sequence number
        got: u64,
    },

    /// Nonce reuse detected.
    #[error("Nonce reuse detected: this is a critical security violation")]
    NonceReuse,

    /// Invalid key or password.
    #[error("Invalid key or password")]
    InvalidKey,

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid TLV (Type-Length-Value) extension.
    #[error("Invalid TLV: {0}")]
    InvalidTlv(String),

    /// Content address not resolved.
    #[error("Content address not resolved: {0}")]
    ContentNotResolved(String),

    /// Delta encoding error.
    #[error("Delta encoding error: {0}")]
    DeltaEncoding(String),

    /// Signature verification failure.
    #[error("Signature verification failed: algorithm {algorithm:?}")]
    SignatureVerification {
        /// Signature algorithm ID
        algorithm: u16,
    },

    /// Invalid signature.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Footer not found (required for non-streaming mode).
    #[error("Footer not found")]
    MissingFooter,

    /// Index not found (required for indexed reader).
    #[error("Index not found")]
    MissingIndex,

    /// Invalid header size.
    #[error("Invalid header size: {0}")]
    InvalidHeaderSize(u64),

    /// Invalid chunk header.
    #[error("Invalid chunk header: {0}")]
    InvalidChunkHeader(String),

    /// Buffer too small.
    #[error("Buffer too small: need {required}, have {available}")]
    BufferTooSmall {
        /// Required bytes
        required: usize,
        /// Available bytes
        available: usize,
    },

    /// Custom error message.
    #[error("{0}")]
    Custom(String),
}

impl Error {
    /// Create a custom error.
    pub fn custom(msg: impl fmt::Display) -> Self {
        Self::Custom(msg.to_string())
    }

    /// Create an unknown algorithm error.
    pub fn unknown_algorithm(category: &'static str, id: u16) -> Self {
        Self::UnknownAlgorithm { category, id }
    }

    /// Create a compression error.
    pub fn compression(msg: impl fmt::Display) -> Self {
        Self::Compression(msg.to_string())
    }

    /// Create a crypto error.
    pub fn crypto(msg: impl fmt::Display) -> Self {
        Self::Crypto(msg.to_string())
    }
}

/// Extension trait for adding context to results.
pub trait ResultExt<T> {
    /// Add context to an error.
    fn context(self, msg: impl fmt::Display) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, msg: impl fmt::Display) -> Result<T> {
        self.map_err(|e| Error::Custom(format!("{}: {}", msg, e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidMagic {
            expected: b"ZETA",
            got: vec![0x00, 0x00, 0x00, 0x00],
        };
        assert!(err.to_string().contains("Invalid magic number"));
    }

    #[test]
    fn test_custom_error() {
        let err = Error::custom("test error");
        assert_eq!(err.to_string(), "test error");
    }
}

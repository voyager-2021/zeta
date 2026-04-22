//! Reader for ZETA containers.

pub mod indexed;
pub mod streaming;
pub mod verifier;

pub use indexed::IndexedReader;
pub use streaming::StreamingReader;
pub use verifier::{VerificationOptions, Verifier};

use crate::error::{Error, Result};
use crate::format::footer::Footer;
use crate::format::header::FileHeader;
use crate::format::stream_dir::{StreamDir, StreamEntry};
use crate::format::{Deserialize, Serialize};
use crate::types::StreamId;
use std::io::{Read, Seek, SeekFrom};

/// High-level reader for ZETA containers.
///
/// Automatically detects whether to use streaming or indexed mode
/// based on the container flags and capabilities.
pub struct Reader<R: Read + Seek> {
    inner: R,
    header: FileHeader,
    stream_dir: StreamDir,
    footer: Option<Footer>,
    key: Option<Vec<u8>>,
}

impl<R: Read + Seek> Reader<R> {
    /// Open a ZETA container for reading.
    pub fn open(mut reader: R) -> Result<Self> {
        // Read and validate header
        let header = FileHeader::deserialize(&mut reader)?;
        header.validate()?;
        header.verify_crc()?;

        // Read stream directory
        let stream_dir = if header.stream_dir_offset > 0 {
            reader.seek(SeekFrom::Start(header.stream_dir_offset))?;
            StreamDir::deserialize(&mut reader)?
        } else {
            // For streaming mode, stream dir might be inline
            StreamDir::deserialize(&mut reader)?
        };

        // Try to read footer
        let footer = if !header.flags.is_streaming() {
            let current_pos = reader.stream_position()?;
            reader.seek(SeekFrom::End(-(Footer::min_size() as i64)))?;
            match Footer::deserialize(&mut reader) {
                Ok(f) => {
                    f.validate()?;
                    Some(f)
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Reset position to after stream directory
        reader.seek(SeekFrom::Start(
            header.stream_dir_offset + stream_dir.serialized_size() as u64,
        ))?;

        Ok(Self {
            inner: reader,
            header,
            stream_dir,
            footer,
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

    /// Get the footer if present.
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get all streams.
    pub fn streams(&self) -> &[StreamEntry] {
        &self.stream_dir.streams
    }

    /// Get a stream by ID.
    pub fn get_stream(&self, id: StreamId) -> Option<&StreamEntry> {
        self.stream_dir.get_stream(id)
    }

    /// Get a stream by name.
    pub fn get_stream_by_name(&self, name: &str) -> Option<&StreamEntry> {
        self.stream_dir.streams.iter().find(|s| s.name == name)
    }

    /// Check if the container has an index.
    pub fn has_index(&self) -> bool {
        self.header.flags.has_index()
    }

    /// Check if the container is in streaming mode.
    pub fn is_streaming(&self) -> bool {
        self.header.flags.is_streaming()
    }

    /// Check if the container is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.header.flags.is_encrypted()
    }

    /// Create a streaming reader for sequential access.
    pub fn into_streaming(self) -> Result<StreamingReader<R>> {
        StreamingReader::from_reader(self.inner, self.header, self.stream_dir, self.key)
    }

    /// Create an indexed reader for random access.
    pub fn into_indexed(self) -> Result<IndexedReader<R>> {
        if !self.has_index() {
            return Err(Error::MissingIndex);
        }
        IndexedReader::from_reader(self.inner, self.header, self.stream_dir, self.footer, self.key)
    }

    /// Verify the container integrity.
    pub fn verify(&mut self, _options: VerificationOptions) -> Result<VerificationResult> {
        let verifier = Verifier::new();
        verifier.verify_container(&mut self.inner, &self.header)
    }

    /// Get a list of all stream names.
    pub fn stream_names(&self) -> Vec<&str> {
        self.stream_dir.streams.iter().map(|s| s.name.as_str()).collect()
    }

    /// Get the total uncompressed size of all streams.
    pub fn total_uncompressed_size(&self) -> u64 {
        self.stream_dir
            .streams
            .iter()
            .map(|s| s.total_uncompressed_size)
            .sum()
    }

    /// Get the number of streams.
    pub fn stream_count(&self) -> usize {
        self.stream_dir.streams.len()
    }

    /// Get the total number of chunks across all streams.
    pub fn total_chunk_count(&self) -> u64 {
        self.stream_dir
            .streams
            .iter()
            .map(|s| s.chunk_count)
            .sum()
    }
}

/// Result of container verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the container is valid
    pub valid: bool,
    /// Whether the header CRC is valid
    pub header_crc_valid: bool,
    /// Whether the file hash is valid
    pub file_hash_valid: Option<bool>,
    /// Whether signatures are valid
    pub signatures_valid: Option<bool>,
    /// Errors encountered during verification
    pub errors: Vec<String>,
    /// Warnings
    pub warnings: Vec<String>,
}

impl VerificationResult {
    /// Create a successful verification result.
    pub fn success() -> Self {
        Self {
            valid: true,
            header_crc_valid: true,
            file_hash_valid: Some(true),
            signatures_valid: None,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a failed verification result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            header_crc_valid: false,
            file_hash_valid: None,
            signatures_valid: None,
            errors: vec![error.into()],
            warnings: Vec::new(),
        }
    }

    /// Add an error.
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
        self.valid = false;
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_minimal_zeta() -> Vec<u8> {
        // This would create a minimal valid ZETA file
        // For now, return empty (tests would need actual data)
        vec![]
    }

    #[test]
    fn test_reader_api() {
        // Placeholder test - real test would use actual ZETA data
        // let data = create_minimal_zeta();
        // let cursor = Cursor::new(data);
        // let reader = Reader::open(cursor).unwrap();
        // assert!(reader.stream_count() >= 0);
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult::success();
        assert!(result.valid);
        assert!(result.errors.is_empty());

        let failure = VerificationResult::failure("test error");
        assert!(!failure.valid);
        assert_eq!(failure.errors.len(), 1);
    }
}

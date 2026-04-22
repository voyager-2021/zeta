//! Container verification.

use crate::error::{Error, Result};
use crate::format::chunk::ChunkHeader;
use crate::format::footer::Footer;
use crate::format::header::FileHeader;
use crate::format::Deserialize;
use crate::pipeline::decoder::ChunkDecoder;
use crate::pipeline::PipelineConfig;
use crate::reader::VerificationResult;
use crate::types::ZetaFlags;
use std::io::{Read, Seek, SeekFrom};

/// Options for container verification.
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    /// Verify chunk integrity
    pub verify_chunks: bool,
    /// Verify signatures
    pub verify_signatures: bool,
    /// Verify file hash
    pub verify_file_hash: bool,
    /// Maximum chunks to verify (0 = all)
    pub max_chunks: usize,
    /// Decryption key (if encrypted)
    pub key: Option<Vec<u8>>,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            verify_chunks: true,
            verify_signatures: true,
            verify_file_hash: true,
            max_chunks: 0,
            key: None,
        }
    }
}

impl VerificationOptions {
    /// Create default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Skip chunk verification.
    pub fn skip_chunks(mut self) -> Self {
        self.verify_chunks = false;
        self
    }

    /// Skip signature verification.
    pub fn skip_signatures(mut self) -> Self {
        self.verify_signatures = false;
        self
    }

    /// Skip file hash verification.
    pub fn skip_file_hash(mut self) -> Self {
        self.verify_file_hash = false;
        self
    }

    /// Set maximum chunks to verify.
    pub fn max_chunks(mut self, max: usize) -> Self {
        self.max_chunks = max;
        self
    }

    /// Set decryption key.
    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
}

/// Container verifier.
pub struct Verifier;

impl Verifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify a container.
    pub fn verify_container<R: Read + Seek>(
        &self,
        reader: &mut R,
        header: &FileHeader,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // 1. Verify header CRC
        if let Err(e) = header.verify_crc() {
            result.add_error(format!("Header CRC failed: {}", e));
            result.header_crc_valid = false;
        }

        // 2. Verify footer if present
        if !header.flags.is_streaming() {
            match self.verify_footer(reader, header) {
                Ok(footer_result) => {
                    result.file_hash_valid = footer_result.file_hash_valid;
                    result.signatures_valid = footer_result.signatures_valid;
                    result.errors.extend(footer_result.errors);
                }
                Err(e) => {
                    result.add_error(format!("Footer verification failed: {}", e));
                }
            }
        }

        result.valid = result.errors.is_empty();
        Ok(result)
    }

    /// Verify footer.
    fn verify_footer<R: Read + Seek>(
        &self,
        reader: &mut R,
        header: &FileHeader,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // Seek to footer
        let footer_min_size = Footer::min_size() as i64;
        reader.seek(SeekFrom::End(-footer_min_size))?;

        let footer = match Footer::deserialize(reader) {
            Ok(f) => f,
            Err(e) => {
                result.add_error(format!("Failed to read footer: {}", e));
                return Ok(result);
            }
        };

        // Validate footer magic
        if let Err(e) = footer.validate() {
            result.add_error(format!("Footer magic invalid: {}", e));
        }

        // Verify file hash if present
        if result.file_hash_valid == Some(true) {
            // TODO: Actually compute and verify file hash
            // This would require reading the entire file except the footer
        }

        // Verify signatures if present
        if !footer.signatures.is_empty() {
            for (i, sig) in footer.signatures.iter().enumerate() {
                // TODO: Actually verify signatures
                // This would require the public key and the data that was signed
            }
        }

        // Verify index offset if present
        if header.flags.has_index() && footer.index_offset == 0 {
            result.add_warning("Index flag set but no index offset in footer");
        }

        Ok(result)
    }

    /// Verify chunks in a container.
    pub fn verify_chunks<R: Read + Seek>(
        &self,
        reader: &mut R,
        header: &FileHeader,
        options: &VerificationOptions,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();
        let decoder = ChunkDecoder::new(PipelineConfig::new());
        let mut chunks_verified = 0;

        // Navigate to start of chunk data
        // This is simplified - real implementation would use stream directory
        let start_offset = header.stream_dir_offset
            + crate::format::stream_dir::StreamDir::deserialize(reader)
                .map(|d| d.serialized_size() as u64)
                .unwrap_or(0);

        reader.seek(SeekFrom::Start(start_offset))?;

        // Read and verify each chunk
        loop {
            if options.max_chunks > 0 && chunks_verified >= options.max_chunks {
                break;
            }

            let chunk_header = match ChunkHeader::deserialize(reader) {
                Ok(h) => h,
                Err(_) => break, // EOF
            };

            // Read payload
            let payload_size = chunk_header.payload_size();
            let mut payload = vec![0u8; payload_size];
            if let Err(e) = reader.read_exact(&mut payload) {
                result.add_error(format!(
                    "Failed to read chunk payload at sequence {}: {}",
                    chunk_header.sequence, e
                ));
                break;
            }

            // Read auth tag
            let auth_tag = if chunk_header.flags.has_auth_tag() {
                let mut tag = vec![0u8; 16];
                if let Err(e) = reader.read_exact(&mut tag) {
                    result.add_error(format!(
                        "Failed to read auth tag at sequence {}: {}",
                        chunk_header.sequence, e
                    ));
                    break;
                }
                Some(tag)
            } else {
                None
            };

            // Verify chunk
            let chunk = crate::format::chunk::ChunkInfo::new(chunk_header, payload, auth_tag);
            let key = options.key.as_deref();

            match decoder.verify(&chunk, key) {
                Ok(true) => {}
                Ok(false) => {
                    result.add_error(format!(
                        "Chunk {} verification failed",
                        chunk.header.sequence
                    ));
                }
                Err(e) => {
                    result.add_error(format!(
                        "Chunk {} verification error: {}",
                        chunk.header.sequence, e
                    ));
                }
            }

            chunks_verified += 1;

            // Check if this was the final chunk
            if chunk.header.flags.is_final() {
                break;
            }
        }

        result.valid = result.errors.is_empty();
        Ok(result)
    }

    /// Quick verification (header CRC only).
    pub fn quick_verify(&self, header: &FileHeader) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        if let Err(e) = header.verify_crc() {
            result.add_error(format!("Header CRC failed: {}", e));
            result.header_crc_valid = false;
        }

        result.valid = result.header_crc_valid;
        Ok(result)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a container file at the given path.
pub fn verify_file(path: &std::path::Path, options: VerificationOptions) -> Result<VerificationResult> {
    use std::fs::File;

    let mut file = File::open(path)?;
    let header = FileHeader::deserialize(&mut file)?;

    let verifier = Verifier::new();

    if options.verify_chunks {
        verifier.verify_chunks(&mut file, &header, &options)
    } else {
        verifier.verify_container(&mut file, &header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_options() {
        let opts = VerificationOptions::new()
            .skip_chunks()
            .skip_signatures()
            .max_chunks(100);

        assert!(!opts.verify_chunks);
        assert!(!opts.verify_signatures);
        assert_eq!(opts.max_chunks, 100);
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = Verifier::new();
        // Just verify creation
        let _ = verifier;
    }
}

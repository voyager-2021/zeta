//! Builder pattern for creating ZETA writers.

use crate::error::Result;
use crate::pipeline::PipelineConfig;
use crate::registry::{
    Compression, CompressionAlgorithm, Encryption, EncryptionAlgorithm,
};
use crate::types::ZetaFlags;
use crate::writer::Writer;
use std::io::{Seek, Write};

/// Builder for configuring and creating ZETA writers.
///
/// # Example
///
/// ```rust,no_run
/// use zeta::WriterBuilder;
/// use zeta::registry::compression::ZstdCompression;
/// use std::fs::File;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let file = File::create("output.zeta")?;
/// let mut writer = WriterBuilder::new()
///     .compression(ZstdCompression)
///     .create(file)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct WriterBuilder {
    flags: ZetaFlags,
    config: PipelineConfig,
}

impl Default for WriterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WriterBuilder {
    /// Create a new writer builder with default settings.
    pub fn new() -> Self {
        Self {
            flags: ZetaFlags::empty(),
            config: PipelineConfig::new(),
        }
    }

    /// Enable streaming mode (footer optional).
    pub fn streaming_mode(mut self) -> Self {
        self.flags.set(ZetaFlags::STREAMING_MODE);
        self
    }

    /// Enable index for random access.
    pub fn with_index(mut self) -> Self {
        self.flags.set(ZetaFlags::INDEX_PRESENT);
        self
    }

    /// Enable content-addressable mode.
    pub fn content_addressable(mut self) -> Self {
        self.flags.set(ZetaFlags::CONTENT_ADDRESSABLE);
        self
    }

    /// Enable delta encoding.
    pub fn delta_encoding(mut self) -> Self {
        self.flags.set(ZetaFlags::DELTA_ENCODING);
        self
    }

    /// Set compression algorithm.
    pub fn compression<C: CompressionAlgorithm + 'static>(mut self, algo: C) -> Self {
        self.config.compression_id = algo.id();
        self
    }

    /// Set compression by ID.
    pub fn compression_by_id(mut self, id: u16) -> Self {
        self.config.compression_id = id;
        self
    }

    /// Set encryption algorithm and key.
    pub fn encryption<E: EncryptionAlgorithm + 'static>(mut self, algo: E, key: Vec<u8>) -> Self {
        self.config.encryption_id = algo.id();
        self.config.key = Some(key);
        self.flags.set(ZetaFlags::ENCRYPTED);
        self
    }

    /// Set encryption by ID.
    pub fn encryption_by_id(mut self, id: u16, key: Vec<u8>) -> Self {
        self.config.encryption_id = id;
        self.config.key = Some(key);
        self.flags.set(ZetaFlags::ENCRYPTED);
        self
    }

    /// Set a custom flag.
    pub fn with_flag(mut self, flag: u32) -> Self {
        self.flags.set(flag);
        self
    }

    /// Set the pipeline configuration directly.
    pub fn pipeline_config(mut self, config: PipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Create the writer.
    pub fn create<W: Write + Seek>(self, writer: W) -> Result<Writer<W>> {
        let mut zeta_writer = Writer::new(writer, self.flags)?;
        zeta_writer.config = self.config;
        Ok(zeta_writer)
    }
}

/// Helper function to create compression algorithm by ID.
fn create_compression_algorithm(id: u16) -> Option<Box<dyn CompressionAlgorithm>> {
    use crate::registry::compression::*;

    match id {
        0 => Some(Box::new(NoneCompression)),
        1 => Some(Box::new(LzwCompression)),
        2 => Some(Box::new(RleCompression)),
        3 => Some(Box::new(ZstdCompression)),
        4 => Some(Box::new(Lz4Compression)),
        5 => Some(Box::new(BrotliCompression)),
        6 => Some(Box::new(ZlibCompression)),
        7 => Some(Box::new(GzipCompression)),
        8 => Some(Box::new(Bzip2Compression)),
        9 => Some(Box::new(LzmaCompression)),
        10 => Some(Box::new(SnappyCompression)),
        13 => Some(Box::new(Lzma2Compression)),
        _ => None,
    }
}

/// Helper function to create encryption algorithm by ID.
fn create_encryption_algorithm(id: u16) -> Option<Box<dyn EncryptionAlgorithm>> {
    use crate::registry::encryption::*;

    match id {
        0 => Some(Box::new(NoneEncryption)),
        1 => Some(Box::new(Aes256GcmEncryption)),
        2 => Some(Box::new(ChaCha20Poly1305Encryption)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::compression::ZstdCompression;
    use std::io::Cursor;

    #[test]
    fn test_builder_default() {
        let cursor = Cursor::new(Vec::new());
        let writer = WriterBuilder::new().create(cursor).unwrap();

        // Just verify creation
        assert_eq!(writer.header.flags.get(), 0);
    }

    #[test]
    fn test_builder_with_compression() {
        let cursor = Cursor::new(Vec::new());
        let writer = WriterBuilder::new()
            .compression(ZstdCompression)
            .create(cursor)
            .unwrap();

        assert!(writer.config.compression_id != 0);
    }

    #[test]
    fn test_builder_with_index() {
        let cursor = Cursor::new(Vec::new());
        let writer = WriterBuilder::new().with_index().create(cursor).unwrap();

        assert!(writer.header.flags.has_index());
    }

    #[test]
    fn test_builder_chaining() {
        let cursor = Cursor::new(Vec::new());
        let writer = WriterBuilder::new()
            .with_index()
            .streaming_mode()
            .create(cursor)
            .unwrap();

        assert!(writer.header.flags.has_index());
        assert!(writer.header.flags.is_streaming());
    }
}

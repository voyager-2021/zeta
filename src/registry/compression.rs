//! Compression algorithm implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for compression algorithms.
pub trait CompressionAlgorithm: Algorithm {
    /// Compress data.
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Decompress data.
    fn decompress(&self, data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>>;
}

/// Compression algorithm ID constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression
    None = 0,
    /// LZW compression
    Lzw = 1,
    /// RLE compression
    Rle = 2,
    /// Zstandard compression
    Zstd = 3,
    /// LZ4 compression
    Lz4 = 4,
    /// Brotli compression
    Brotli = 5,
    /// Zlib compression
    Zlib = 6,
    /// Gzip compression
    Gzip = 7,
    /// Bzip2 compression
    Bzip2 = 8,
    /// LZMA compression
    Lzma = 9,
    /// Snappy compression
    Snappy = 10,
    /// LZHAM compression (not implemented)
    Lzham = 11,
    /// LZO compression
    Lzo = 12,
    /// LZMA2 compression
    Lzma2 = 13,
    /// ZPAQ compression (not implemented)
    Zpaq = 14,
    /// PPMd compression (not implemented)
    Ppmd = 15,
}

impl Compression {
    /// Get the default compression level for this algorithm.
    pub fn default_level(&self) -> i32 {
        match self {
            Compression::None => 0,
            Compression::Zstd => 3,
            Compression::Lz4 => 1,
            Compression::Brotli => 4,
            Compression::Zlib | Compression::Gzip => 6,
            Compression::Bzip2 => 9,
            Compression::Lzma | Compression::Lzma2 => 6,
            _ => 0,
        }
    }
}

/// No compression (pass-through).
#[derive(Debug)]
pub struct NoneCompression;

impl Algorithm for NoneCompression {
    fn id(&self) -> u16 {
        Compression::None as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl CompressionAlgorithm for NoneCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

/// LZW compression implementation.
#[derive(Debug)]
pub struct LzwCompression;

impl Algorithm for LzwCompression {
    fn id(&self) -> u16 {
        Compression::Lzw as u16
    }

    fn name(&self) -> &'static str {
        "lzw"
    }
}

impl CompressionAlgorithm for LzwCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simple LZW implementation
        let mut dict: std::collections::HashMap<Vec<u8>, u16> = std::collections::HashMap::new();
        for i in 0..=255 {
            dict.insert(vec![i as u8], i);
        }

        let mut result = Vec::new();
        let mut current = Vec::new();
        let mut next_code: u16 = 256;

        for &byte in data {
            let mut test = current.clone();
            test.push(byte);

            if dict.contains_key(&test) {
                current = test;
            } else {
                if let Some(&code) = dict.get(&current) {
                    result.extend_from_slice(&code.to_le_bytes());
                }
                if next_code < 4096 {
                    dict.insert(test, next_code);
                    next_code += 1;
                }
                current = vec![byte];
            }
        }

        if !current.is_empty() {
            if let Some(&code) = dict.get(&current) {
                result.extend_from_slice(&code.to_le_bytes());
            }
        }

        Ok(result)
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut dict: std::collections::HashMap<u16, Vec<u8>> = std::collections::HashMap::new();
        for i in 0..=255 {
            dict.insert(i, vec![i as u8]);
        }

        let mut result = Vec::new();
        let mut next_code: u16 = 256;

        // Read codes (u16 little-endian)
        let codes: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        if codes.is_empty() {
            return Ok(Vec::new());
        }

        let mut old_code = codes[0];
        if let Some(entry) = dict.get(&old_code) {
            result.extend_from_slice(entry);
        }

        for &new_code in &codes[1..] {
            let entry = if let Some(e) = dict.get(&new_code) {
                e.clone()
            } else {
                let mut e = dict.get(&old_code).unwrap().clone();
                e.push(e[0]);
                e
            };

            result.extend_from_slice(&entry);

            if next_code < 4096 {
                let mut new_entry = dict.get(&old_code).unwrap().clone();
                new_entry.push(entry[0]);
                dict.insert(next_code, new_entry);
                next_code += 1;
            }

            old_code = new_code;
        }

        Ok(result)
    }
}

/// RLE (Run-Length Encoding) compression.
#[derive(Debug)]
pub struct RleCompression;

impl Algorithm for RleCompression {
    fn id(&self) -> u16 {
        Compression::Rle as u16
    }

    fn name(&self) -> &'static str {
        "rle"
    }
}

impl CompressionAlgorithm for RleCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut count = 1u8;
        let mut current = data[0];

        for &byte in &data[1..] {
            if byte == current && count < 255 {
                count += 1;
            } else {
                result.push(count);
                result.push(current);
                count = 1;
                current = byte;
            }
        }

        result.push(count);
        result.push(current);

        Ok(result)
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        if data.len() % 2 != 0 {
            return Err(Error::compression("Invalid RLE data"));
        }

        let mut result = Vec::new();

        for chunk in data.chunks_exact(2) {
            let count = chunk[0] as usize;
            let byte = chunk[1];
            result.extend(std::iter::repeat(byte).take(count));
        }

        Ok(result)
    }
}

/// Zstandard compression.
#[derive(Debug)]
pub struct ZstdCompression;

impl Algorithm for ZstdCompression {
    fn id(&self) -> u16 {
        Compression::Zstd as u16
    }

    fn name(&self) -> &'static str {
        "zstd"
    }
}

impl CompressionAlgorithm for ZstdCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, Compression::Zstd.default_level())
            .map_err(|e| Error::compression(format!("Zstd compression failed: {}", e)))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        zstd::decode_all(data)
            .map_err(|e| Error::compression(format!("Zstd decompression failed: {}", e)))
    }
}

/// LZ4 compression.
#[derive(Debug)]
pub struct Lz4Compression;

impl Algorithm for Lz4Compression {
    fn id(&self) -> u16 {
        Compression::Lz4 as u16
    }

    fn name(&self) -> &'static str {
        "lz4"
    }
}

impl CompressionAlgorithm for Lz4Compression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = lz4::EncoderBuilder::new()
            .level(Compression::Lz4.default_level() as u32)
            .build(Vec::new())
            .map_err(|e| Error::compression(format!("LZ4 encoder creation failed: {}", e)))?;

        std::io::Write::write_all(&mut encoder, data)
            .map_err(|e| Error::compression(format!("LZ4 compression failed: {}", e)))?;

        let (result, finish_result) = encoder.finish();
        if let Err(e) = finish_result {
            return Err(Error::compression(format!("LZ4 encoder finish failed: {}", e)));
        }
        Ok(result)
    }

    fn decompress(&self, data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(uncompressed_size);
        let mut decoder = lz4::Decoder::new(data)
            .map_err(|e| Error::compression(format!("LZ4 decoder creation failed: {}", e)))?;

        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("LZ4 decompression failed: {}", e)))?;

        Ok(result)
    }
}

/// Brotli compression.
#[derive(Debug)]
pub struct BrotliCompression;

impl Algorithm for BrotliCompression {
    fn id(&self) -> u16 {
        Compression::Brotli as u16
    }

    fn name(&self) -> &'static str {
        "brotli"
    }
}

impl CompressionAlgorithm for BrotliCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut compressor = brotli::CompressorWriter::new(
            &mut result,
            4096,
            Compression::Brotli.default_level() as u32,
            22,
        );
        std::io::Write::write_all(&mut compressor, data)
            .map_err(|e| Error::compression(format!("Brotli compression failed: {}", e)))?;
        drop(compressor);
        Ok(result)
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut decompressor = brotli::Decompressor::new(data, 4096);
        std::io::Read::read_to_end(&mut decompressor, &mut result)
            .map_err(|e| Error::compression(format!("Brotli decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// Zlib compression.
#[derive(Debug)]
pub struct ZlibCompression;

impl Algorithm for ZlibCompression {
    fn id(&self) -> u16 {
        Compression::Zlib as u16
    }

    fn name(&self) -> &'static str {
        "zlib"
    }
}

impl CompressionAlgorithm for ZlibCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = flate2::write::ZlibEncoder::new(
            Vec::new(),
            flate2::Compression::new(Compression::Zlib.default_level() as u32),
        );
        std::io::Write::write_all(&mut encoder, data)
            .map_err(|e| Error::compression(format!("Zlib compression failed: {}", e)))?;
        encoder
            .finish()
            .map_err(|e| Error::compression(format!("Zlib compression failed: {}", e)))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::ZlibDecoder::new(data);
        let mut result = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("Zlib decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// Gzip compression.
#[derive(Debug)]
pub struct GzipCompression;

impl Algorithm for GzipCompression {
    fn id(&self) -> u16 {
        Compression::Gzip as u16
    }

    fn name(&self) -> &'static str {
        "gzip"
    }
}

impl CompressionAlgorithm for GzipCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::new(Compression::Gzip.default_level() as u32),
        );
        std::io::Write::write_all(&mut encoder, data)
            .map_err(|e| Error::compression(format!("Gzip compression failed: {}", e)))?;
        encoder
            .finish()
            .map_err(|e| Error::compression(format!("Gzip compression failed: {}", e)))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut result = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("Gzip decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// Bzip2 compression.
#[derive(Debug)]
pub struct Bzip2Compression;

impl Algorithm for Bzip2Compression {
    fn id(&self) -> u16 {
        Compression::Bzip2 as u16
    }

    fn name(&self) -> &'static str {
        "bzip2"
    }
}

impl CompressionAlgorithm for Bzip2Compression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = bzip2::write::BzEncoder::new(
            Vec::new(),
            bzip2::Compression::new(Compression::Bzip2.default_level() as u32),
        );
        std::io::Write::write_all(&mut encoder, data)
            .map_err(|e| Error::compression(format!("Bzip2 compression failed: {}", e)))?;
        encoder
            .finish()
            .map_err(|e| Error::compression(format!("Bzip2 compression failed: {}", e)))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = bzip2::read::BzDecoder::new(data);
        let mut result = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("Bzip2 decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// LZMA compression.
#[derive(Debug)]
pub struct LzmaCompression;

impl Algorithm for LzmaCompression {
    fn id(&self) -> u16 {
        Compression::Lzma as u16
    }

    fn name(&self) -> &'static str {
        "lzma"
    }
}

impl CompressionAlgorithm for LzmaCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        xz2::stream::MtStreamBuilder::new()
            .threads(1)
            .preset(Compression::Lzma.default_level() as u32)
            .encoder()
            .ok()
            .and_then(|stream| {
                let mut result = Vec::new();
                let mut encoder = xz2::write::XzEncoder::new_stream(&mut result, stream);
                std::io::Write::write_all(&mut encoder, data).ok()?;
                encoder.finish().ok()?;
                Some(result)
            })
            .ok_or_else(|| Error::compression("LZMA compression failed"))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut result = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("LZMA decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// LZMA2 compression.
#[derive(Debug)]
pub struct Lzma2Compression;

impl Algorithm for Lzma2Compression {
    fn id(&self) -> u16 {
        Compression::Lzma2 as u16
    }

    fn name(&self) -> &'static str {
        "lzma2"
    }
}

impl CompressionAlgorithm for Lzma2Compression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // LZMA2 uses same xz2 encoder with different flags
        xz2::stream::MtStreamBuilder::new()
            .threads(1)
            .preset(Compression::Lzma2.default_level() as u32)
            .encoder()
            .ok()
            .and_then(|stream| {
                let mut result = Vec::new();
                let mut encoder = xz2::write::XzEncoder::new_stream(&mut result, stream);
                std::io::Write::write_all(&mut encoder, data).ok()?;
                encoder.finish().ok()?;
                Some(result)
            })
            .ok_or_else(|| Error::compression("LZMA2 compression failed"))
    }

    fn decompress(&self, data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut result = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut result)
            .map_err(|e| Error::compression(format!("LZMA2 decompression failed: {}", e)))?;
        Ok(result)
    }
}

/// Snappy compression.
#[derive(Debug)]
pub struct SnappyCompression;

impl Algorithm for SnappyCompression {
    fn id(&self) -> u16 {
        Compression::Snappy as u16
    }

    fn name(&self) -> &'static str {
        "snappy"
    }
}

impl CompressionAlgorithm for SnappyCompression {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Use snap crate for Snappy compression
        // Note: snap crate doesn't have direct compress_to_vec, use encoder
        let mut encoder = snap::raw::Encoder::new();
        let max_len = snap::raw::max_compress_len(data.len());
        let mut result = vec![0u8; max_len];
        let len = encoder
            .compress(data, &mut result)
            .map_err(|e| Error::compression(format!("Snappy compression failed: {:?}", e)))?;
        result.truncate(len);
        Ok(result)
    }

    fn decompress(&self, data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut decoder = snap::raw::Decoder::new();
        let mut result = vec![0u8; uncompressed_size];
        decoder
            .decompress(data, &mut result)
            .map_err(|e| Error::compression(format!("Snappy decompression failed: {:?}", e)))?;
        Ok(result)
    }
}


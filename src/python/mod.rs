//! Python bindings for ZETA using PyO3.

pub mod reader;
pub mod writer;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

/// Python module definition.
#[pymodule]
fn zeta(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__doc__", "Zero-Trust Extended Archive Format - Python bindings")?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Classes
    m.add_class::<writer::PyWriter>()?;
    m.add_class::<reader::PyReader>()?;
    m.add_class::<reader::PyStreamInfo>()?;

    // Functions
    m.add_function(wrap_pyfunction!(pack, m)?)?;
    m.add_function(wrap_pyfunction!(unpack, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(list_streams, m)?)?;

    // Constants
    m.add("VERSION", crate::VERSION.0 as u32 * 1000 + crate::VERSION.1 as u32)?;

    Ok(())
}

/// Pack files into a ZETA container (convenience function).
///
/// Args:
///     output: Output file path
///     files: List of input file paths
///     compression: Compression algorithm name (optional)
///     encryption: Encryption algorithm name (optional)
///     password: Password for encryption (optional)
///     index: Create index for random access (default: True)
///
/// Returns:
///     Dictionary with statistics
#[pyfunction]
fn pack(
    py: Python,
    output: &str,
    files: Vec<&str>,
    compression: Option<&str>,
    encryption: Option<&str>,
    password: Option<&str>,
    index: Option<bool>,
) -> PyResult<PyObject> {
    use crate::writer::{Writer, WriterBuilder};
    use crate::types::ZetaFlags;
    use std::fs::File;
    use std::time::Instant;

    let start = Instant::now();

    // Build writer
    let mut builder = WriterBuilder::new();
    if index.unwrap_or(true) {
        builder = builder.with_index();
    }

    // Set compression
    if let Some(comp) = compression {
        let comp_id = parse_compression_name(comp)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown compression: {}",
                comp
            )))?;
        builder = builder.compression_by_id(comp_id);
    }

    // Set encryption
    if let Some(enc) = encryption {
        let enc_id = parse_encryption_name(enc)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown encryption: {}",
                enc
            )))?;

        let key = if let Some(pass) = password {
            derive_key_py(pass)?
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Encryption requires password",
            ));
        };

        builder = builder.encryption_by_id(enc_id, key);
    }

    // Create writer
    let file = File::create(output)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to create output: {}", e)))?;
    let mut writer = builder
        .create(file)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to create writer: {}", e)))?;

    // Pack files
    let mut total_bytes = 0u64;
    for file_path in &files {
        let data = std::fs::read(file_path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to read {}: {}",
                file_path, e
            )))?;

        writer
            .create_stream(file_path)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to create stream: {}",
                e
            )))?;
        writer
            .write_all(&data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to write data: {}",
                e
            )))?;

        total_bytes += data.len() as u64;
    }

    // Finish
    writer.finish().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to finish container: {}", e))
    })?;

    let duration = start.elapsed();
    let output_size = std::fs::metadata(output)
        .map(|m| m.len())
        .unwrap_or(0);

    // Return statistics
    let result = pyo3::types::PyDict::new(py);
    result.set_item("files_packed", files.len())?;
    result.set_item("total_bytes", total_bytes)?;
    result.set_item("output_size", output_size)?;
    result.set_item("duration_seconds", duration.as_secs_f64())?;

    Ok(result.into())
}

/// Unpack a ZETA container (convenience function).
///
/// Args:
///     input: Input file path
///     output_dir: Output directory (default: current directory)
///     password: Password for decryption (if encrypted)
///     streams: Specific streams to extract (default: all)
///
/// Returns:
///     Dictionary with statistics
#[pyfunction]
fn unpack(
    py: Python,
    input: &str,
    output_dir: Option<&str>,
    password: Option<&str>,
    streams: Option<Vec<&str>>,
) -> PyResult<PyObject> {
    use crate::reader::Reader;
    use std::fs::File;
    use std::time::Instant;

    let start = Instant::now();

    let output_dir = output_dir.unwrap_or(".");
    std::fs::create_dir_all(output_dir)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
            "Failed to create output dir: {}",
            e
        )))?;

    // Open container
    let file = File::open(input)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
            "Failed to open input: {}",
            e
        )))?;
    let mut reader = Reader::open(file)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Failed to open container: {}",
            e
        )))?;

    // Set key if encrypted
    if reader.is_encrypted() {
        let key = if let Some(pass) = password {
            derive_key_py(pass)?
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Container is encrypted but no password provided",
            ));
        };
        reader = reader.with_key(key);
    }

    // Determine streams to extract
    let stream_ids = if let Some(names) = streams {
        names
            .iter()
            .filter_map(|name| reader.get_stream_by_name(name).map(|s| s.id))
            .collect()
    } else {
        reader.streams().iter().map(|s| s.id).collect()
    };

    // Extract streams
    let mut extracted_count = 0usize;
    let mut total_bytes = 0u64;

    if reader.has_index() {
        // Use indexed reader
        let mut indexed = reader
            .into_indexed()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to create indexed reader: {}",
                e
            )))?;

        for stream_id in stream_ids {
            if let Some(stream) = indexed.get_stream(stream_id) {
                let data = indexed
                    .read_stream_full(stream_id)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to read stream: {}",
                        e
                    )))?;

                let output_path = std::path::Path::new(output_dir).join(&stream.name);
                if let Some(parent) = output_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&output_path, &data)
                    .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                        "Failed to write {}: {}",
                        output_path.display(),
                        e
                    )))?;

                extracted_count += 1;
                total_bytes += data.len() as u64;
            }
        }
    }

    let duration = start.elapsed();

    // Return statistics
    let result = pyo3::types::PyDict::new(py);
    result.set_item("streams_extracted", extracted_count)?;
    result.set_item("total_bytes", total_bytes)?;
    result.set_item("duration_seconds", duration.as_secs_f64())?;

    Ok(result.into())
}

/// Verify a ZETA container.
///
/// Args:
///     input: Input file path
///     deep: Verify all chunks (slower)
///     password: Password for decryption (if encrypted)
///
/// Returns:
///     Dictionary with verification results
#[pyfunction]
fn verify(
    py: Python,
    input: &str,
    deep: Option<bool>,
    password: Option<&str>,
) -> PyResult<PyObject> {
    use crate::reader::verifier::{VerificationOptions, Verifier};
    use crate::reader::Reader;
    use std::fs::File;

    // Open container
    let file = File::open(input)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
            "Failed to open input: {}",
            e
        )))?;
    let mut reader = Reader::open(file)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Failed to open container: {}",
            e
        )))?;

    // Set key if encrypted
    if reader.is_encrypted() {
        let key = if let Some(pass) = password {
            derive_key_py(pass)?
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Container is encrypted but no password provided",
            ));
        };
        reader = reader.with_key(key);
    }

    // Verify
    let options = VerificationOptions {
        verify_chunks: deep.unwrap_or(false),
        verify_signatures: false,
        verify_file_hash: true,
        max_chunks: 0,
        key: None,
    };

    let result = reader
        .verify(options)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Verification failed: {}",
            e
        )))?;

    // Return results
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("valid", result.valid)?;
    dict.set_item("header_crc_valid", result.header_crc_valid)?;
    dict.set_item("errors", result.errors)?;
    dict.set_item("warnings", result.warnings)?;

    Ok(dict.into())
}

/// List streams in a ZETA container.
///
/// Args:
///     input: Input file path
///
/// Returns:
///     List of stream information dictionaries
#[pyfunction]
fn list_streams(py: Python, input: &str) -> PyResult<PyObject> {
    use crate::reader::Reader;
    use std::fs::File;

    // Open container
    let file = File::open(input)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
            "Failed to open input: {}",
            e
        )))?;
    let reader = Reader::open(file)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Failed to open container: {}",
            e
        )))?;

    // Build list
    let list = pyo3::types::PyList::empty(py);
    for stream in reader.streams() {
        let info = pyo3::types::PyDict::new(py);
        info.set_item("id", stream.id.get())?;
        info.set_item("name", &stream.name)?;
        info.set_item("size", stream.total_uncompressed_size)?;
        info.set_item("chunks", stream.chunk_count)?;
        list.append(info)?;
    }

    Ok(list.into())
}

/// Parse compression name to ID.
fn parse_compression_name(name: &str) -> Option<u16> {
    use crate::registry::Compression;

    let id = match name.to_lowercase().as_str() {
        "none" => Compression::None as u16,
        "lzw" => Compression::Lzw as u16,
        "rle" => Compression::Rle as u16,
        "zstd" => Compression::Zstd as u16,
        "lz4" => Compression::Lz4 as u16,
        "brotli" => Compression::Brotli as u16,
        "zlib" => Compression::Zlib as u16,
        "gzip" => Compression::Gzip as u16,
        "bzip2" => Compression::Bzip2 as u16,
        "lzma" => Compression::Lzma as u16,
        "snappy" => Compression::Snappy as u16,
        "lzma2" => Compression::Lzma2 as u16,
        _ => return None,
    };
    Some(id)
}

/// Parse encryption name to ID.
fn parse_encryption_name(name: &str) -> Option<u16> {
    use crate::registry::Encryption;

    let id = match name.to_lowercase().as_str() {
        "none" => Encryption::None as u16,
        "aes-256-gcm" | "aes256gcm" | "aes" => Encryption::Aes256Gcm as u16,
        "chacha20-poly1305" | "chacha20" | "chacha" => Encryption::ChaCha20Poly1305 as u16,
        _ => return None,
    };
    Some(id)
}

/// Derive encryption key from password.
fn derive_key_py(password: &str) -> PyResult<Vec<u8>> {
    use crate::registry::{global_registry, Kdf, KdfAlgorithm, KdfParams};
    use rand::RngCore;

    let kdf = global_registry()
        .kdf
        .get(Kdf::Argon2id as u16)
        .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("KDF not available"))?;

    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let params = KdfParams::argon2id_default();
    let key = kdf
        .derive(password.as_bytes(), &salt, 32, &params)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
            "Key derivation failed: {}",
            e
        )))?;

    Ok(key)
}

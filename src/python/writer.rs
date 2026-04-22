//! Python bindings for ZETA writer.

use pyo3::prelude::*;

/// Python wrapper for ZETA writer.
#[pyclass]
pub struct PyWriter {
    inner: Option<crate::writer::Writer<std::fs::File>>,
}

#[pymethods]
impl PyWriter {
    /// Create a new writer.
    ///
    /// Args:
    ///     path: Output file path
    ///     compression: Compression algorithm name (optional)
    ///     encryption: Encryption algorithm name (optional)
    ///     password: Password for encryption (optional)
    ///     index: Create index for random access (default: True)
    #[new]
    fn new(
        path: &str,
        compression: Option<&str>,
        encryption: Option<&str>,
        password: Option<&str>,
        index: Option<bool>,
    ) -> PyResult<Self> {
        use crate::types::ZetaFlags;
        use crate::writer::WriterBuilder;
        use std::fs::File;

        // Build writer
        let mut builder = WriterBuilder::new();
        if index.unwrap_or(true) {
            builder = builder.with_index();
        }

        // Set compression
        if let Some(comp) = compression {
            let comp_id = super::parse_compression_name(comp)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown compression: {}",
                    comp
                )))?;
            builder = builder.compression_by_id(comp_id);
        }

        // Set encryption
        if let Some(enc) = encryption {
            let enc_id = super::parse_encryption_name(enc)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!(
                    "Unknown encryption: {}",
                    enc
                )))?;

            let key = if let Some(pass) = password {
                super::derive_key_py(pass)?
            } else {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Encryption requires password",
                ));
            };

            builder = builder.encryption_by_id(enc_id, key);
        }

        // Create file and writer
        let file = File::create(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to create file: {}",
                e
            )))?;
        let writer = builder
            .create(file)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to create writer: {}",
                e
            )))?;

        Ok(Self {
            inner: Some(writer),
        })
    }

    /// Create a new stream.
    ///
    /// Args:
    ///     name: Stream name
    fn create_stream(&mut self, name: &str) -> PyResult<u32> {
        let writer = self.inner.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Writer already closed")
        })?;

        let stream_id = writer
            .create_stream(name)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to create stream: {}",
                e
            )))?;

        Ok(stream_id.get())
    }

    /// Write data to the current stream.
    ///
    /// Args:
    ///     data: Bytes to write
    fn write(&mut self, data: &[u8]) -> PyResult<()> {
        let writer = self.inner.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Writer already closed")
        })?;

        writer
            .write_all(data)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!(
                "Failed to write: {}",
                e
            )))?;

        Ok(())
    }

    /// Write a file to the current stream.
    ///
    /// Args:
    ///     path: File path to read
    fn write_file(&mut self, path: &str) -> PyResult<()> {
        let data = std::fs::read(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to read file: {}",
                e
            )))?;
        self.write(&data)
    }

    /// Finish writing and close the container.
    fn finish(&mut self) -> PyResult<()> {
        if let Some(writer) = self.inner.take() {
            writer.finish().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to finish: {}",
                    e
                ))
            })?;
        }
        Ok(())
    }

    /// Context manager support.
    fn __enter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __exit__(
        mut slf: PyRefMut<Self>,
        _exc_type: &PyAny,
        _exc_value: &PyAny,
        _traceback: &PyAny,
    ) -> PyResult<bool> {
        slf.finish()?;
        Ok(false)
    }
}

impl Drop for PyWriter {
    fn drop(&mut self) {
        // Ensure writer is finished
        if let Some(writer) = self.inner.take() {
            let _ = writer.finish();
        }
    }
}

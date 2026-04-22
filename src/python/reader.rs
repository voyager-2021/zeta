//! Python bindings for ZETA reader.

use pyo3::prelude::*;

/// Python wrapper for ZETA reader.
#[pyclass]
pub struct PyReader {
    inner: ReaderInner,
}

enum ReaderInner {
    Indexed(crate::reader::IndexedReader<std::fs::File>),
    Streaming(crate::reader::StreamingReader<std::fs::File>),
    None,
}

#[pymethods]
impl PyReader {
    /// Open a ZETA container for reading.
    ///
    /// Args:
    ///     path: File path
    ///     password: Password for decryption (if encrypted)
    #[new]
    fn new(path: &str, password: Option<&str>) -> PyResult<Self> {
        use crate::reader::Reader;
        use std::fs::File;

        let file = File::open(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to open file: {}",
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
                super::derive_key_py(pass)?
            } else {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Container is encrypted but no password provided",
                ));
            };
            reader = reader.with_key(key);
        }

        // Use indexed reader if available
        let inner = if reader.has_index() {
            ReaderInner::Indexed(reader.into_indexed().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to create indexed reader: {}",
                    e
                ))
            })?)
        } else {
            ReaderInner::Streaming(reader.into_streaming().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "Failed to create streaming reader: {}",
                    e
                ))
            })?)
        };

        Ok(Self { inner })
    }

    /// Get list of streams in the container.
    fn streams(&self) -> PyResult<Vec<PyStreamInfo>> {
        let streams = match &self.inner {
            ReaderInner::Indexed(r) => r.stream_dir().streams.clone(),
            ReaderInner::Streaming(r) => r.stream_dir().streams.clone(),
            ReaderInner::None => return Ok(Vec::new()),
        };

        Ok(streams
            .into_iter()
            .map(|s| PyStreamInfo {
                id: s.id.get(),
                name: s.name,
                size: s.total_uncompressed_size,
                chunks: s.chunk_count as usize,
            })
            .collect())
    }

    /// Read a stream by name.
    ///
    /// Args:
    ///     name: Stream name
    ///
    /// Returns:
    ///     Bytes
    fn read_stream(&mut self, name: &str) -> PyResult<Vec<u8>> {
        match &mut self.inner {
            ReaderInner::Indexed(r) => {
                let stream = r
                    .get_stream_by_name(name)
                    .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!(
                        "Stream not found: {}",
                        name
                    )))?;

                let data = r.read_stream_full(stream.id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to read stream: {}",
                        e
                    ))
                })?;

                Ok(data)
            }
            ReaderInner::Streaming(r) => {
                let stream = r
                    .stream_dir()
                    .streams
                    .iter()
                    .find(|s| s.name == name)
                    .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!(
                        "Stream not found: {}",
                        name
                    )))?;

                r.select_stream(stream.id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to select stream: {}",
                        e
                    ))
                })?;

                let data = r.read_stream(stream.id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to read stream: {}",
                        e
                    ))
                })?;

                Ok(data)
            }
            ReaderInner::None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Reader not initialized",
            )),
        }
    }

    /// Read a stream by ID.
    ///
    /// Args:
    ///     stream_id: Stream ID
    ///
    /// Returns:
    ///     Bytes
    fn read_stream_by_id(&mut self, stream_id: u32) -> PyResult<Vec<u8>> {
        let id = crate::types::StreamId::try_from(stream_id)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid stream ID"))?;

        match &mut self.inner {
            ReaderInner::Indexed(r) => {
                let data = r.read_stream_full(id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to read stream: {}",
                        e
                    ))
                })?;
                Ok(data)
            }
            ReaderInner::Streaming(r) => {
                r.select_stream(id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to select stream: {}",
                        e
                    ))
                })?;
                let data = r.read_stream(id).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to read stream: {}",
                        e
                    ))
                })?;
                Ok(data)
            }
            ReaderInner::None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Reader not initialized",
            )),
        }
    }

    /// Extract all streams to a directory.
    ///
    /// Args:
    ///     output_dir: Output directory path
    ///
    /// Returns:
    ///     Number of streams extracted
    fn extract_all(&mut self, output_dir: &str) -> PyResult<usize> {
        std::fs::create_dir_all(output_dir)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!(
                "Failed to create directory: {}",
                e
            )))?;

        let streams = self.streams()?;
        let mut count = 0;

        for stream in streams {
            let data = self.read_stream(&stream.name)?;
            let output_path = std::path::Path::new(output_dir).join(&stream.name);

            // Create parent directories
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }

            std::fs::write(&output_path, &data).map_err(|e| {
                pyo3::exceptions::PyIOError::new_err(format!(
                    "Failed to write {}: {}",
                    output_path.display(),
                    e
                ))
            })?;

            count += 1;
        }

        Ok(count)
    }

    /// Check if the container has an index.
    fn has_index(&self) -> PyResult<bool> {
        let has_index = match &self.inner {
            ReaderInner::Indexed(_) => true,
            ReaderInner::Streaming(_) => false,
            ReaderInner::None => false,
        };
        Ok(has_index)
    }

    /// Check if the container is encrypted.
    fn is_encrypted(&self) -> PyResult<bool> {
        let is_encrypted = match &self.inner {
            ReaderInner::Indexed(r) => r.header().flags.is_encrypted(),
            ReaderInner::Streaming(r) => r.header().flags.is_encrypted(),
            ReaderInner::None => false,
        };
        Ok(is_encrypted)
    }

    /// Context manager support.
    fn __enter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &PyAny,
        _exc_value: &PyAny,
        _traceback: &PyAny,
    ) -> PyResult<bool> {
        // Reader doesn't need explicit cleanup
        Ok(false)
    }
}

/// Python wrapper for stream information.
#[pyclass]
#[derive(Clone)]
pub struct PyStreamInfo {
    #[pyo3(get)]
    pub id: u32,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub size: u64,
    #[pyo3(get)]
    pub chunks: usize,
}

#[pymethods]
impl PyStreamInfo {
    fn __repr__(&self) -> String {
        format!(
            "StreamInfo(id={}, name='{}', size={}, chunks={})",
            self.id, self.name, self.size, self.chunks
        )
    }

    fn __str__(&self) -> String {
        format!("{} ({} bytes, {} chunks)", self.name, self.size, self.chunks)
    }
}

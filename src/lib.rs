//! # ZETA - Zero-Trust Extended Archive Format
//!
//! A high-performance container format with:
//! - Zero-trust verification (authenticate before decompress)
//! - Pluggable compression, encryption, hashing, and KDF
//! - Streaming-first design with optional indexing
//! - Multi-stream container support
//!
//! ## Example
//!
//! ```rust,no_run
//! use zeta::{Writer, Reader, WriterBuilder};
//! use zeta::registry::compression::ZstdCompression;
//! use std::fs::File;
//!
//! // Create a container
//! let file = File::create("output.zeta")?;
//! let mut writer = WriterBuilder::new()
//!     .compression(ZstdCompression)
//!     .create(file)?;
//!
//! writer.create_stream("data.txt");
//! writer.write_all(b"Hello, ZETA!")?;
//! writer.finish()?;
//!
//! // Read a container
//! let file = File::open("output.zeta")?;
//! let reader = Reader::open(file)?;
//! for stream in reader.streams() {
//!     println!("Stream: {}", stream.name);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod constants;
pub mod error;
pub mod format;
pub mod pipeline;
pub mod reader;
pub mod registry;
pub mod types;
pub mod writer;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "python")]
pub mod python;

// Re-export main types
pub use error::{Error, Result};
pub use reader::{IndexedReader, Reader, StreamingReader};
pub use registry::{
    CompressionAlgorithm, EncryptionAlgorithm, HashAlgorithm, KdfAlgorithm,
    Compression, Encryption, Hash, Kdf,
};
pub use types::{ChunkSequence, StreamFlags, StreamId, StreamType, Uuid, ZetaFlags};
pub use writer::{StreamWriter, Writer, WriterBuilder};

/// Version of the ZETA format supported by this library
pub const VERSION: (u16, u16) = (1, 0);

/// Magic number for ZETA files: "ZETA"
pub const MAGIC: &[u8; 4] = b"ZETA";

/// Magic number for chunks: "CHK1"
pub const CHUNK_MAGIC: &[u8; 4] = b"CHK1";

/// Footer magic: "ZET!"
pub const FOOTER_MAGIC: &[u8; 4] = b"ZET!";

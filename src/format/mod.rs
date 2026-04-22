//! Binary format parsing and writing for ZETA containers.

pub mod chunk;
pub mod footer;
pub mod header;
pub mod index;
pub mod stream_dir;
pub mod tlv;

pub use chunk::{ChunkHeader, ChunkInfo};
pub use footer::{Footer, SignatureBlock};
pub use header::FileHeader;
pub use index::{IndexBlock, IndexEntry};
pub use stream_dir::{StreamDir, StreamEntry};
pub use tlv::{TlvEntry, TlvReader, TlvWriter};

use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Trait for types that can be serialized to bytes.
pub trait Serialize {
    /// Serialize to a writer.
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()>;

    /// Get the serialized size in bytes.
    fn serialized_size(&self) -> usize;
}

/// Trait for types that can be deserialized from bytes.
pub trait Deserialize: Sized {
    /// Deserialize from a reader.
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self>;
}

/// Helper function to calculate CRC32.
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Read a length-prefixed string (u16 length prefix).
pub fn read_prefixed_string<R: std::io::Read>(reader: &mut R) -> Result<String> {
    let len = reader.read_u16::<LittleEndian>()? as usize;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|e| Error::custom(format!("Invalid UTF-8: {}", e)))
}

/// Write a length-prefixed string (u16 length prefix).
pub fn write_prefixed_string<W: std::io::Write>(writer: &mut W, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(Error::custom("String too long for u16 prefix"));
    }
    writer.write_u16::<LittleEndian>(bytes.len() as u16)?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Read a fixed-size byte array.
pub fn read_fixed_bytes<R: std::io::Read, const N: usize>(reader: &mut R) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Padding utility - write zeros to align to boundary.
pub fn write_padding<W: std::io::Write>(writer: &mut W, current_pos: usize, alignment: usize) -> Result<()> {
    let padding = (alignment - (current_pos % alignment)) % alignment;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }
    Ok(())
}

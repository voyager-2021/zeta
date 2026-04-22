//! Chunk format for ZETA containers.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::format::{Deserialize, Serialize, TlvEntry};
use crate::types::{ChunkFlags, ChunkSequence, CompressionId, EncryptionId, HashId, KdfId, StreamId};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Chunk header structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Magic: "CHK1"
    pub magic: [u8; 4],
    /// Total chunk size (header + payload + auth tag)
    pub total_size: u32,
    /// Header size (including extensions)
    pub header_size: u32,
    /// Flags
    pub flags: ChunkFlags,
    /// Stream ID
    pub stream_id: StreamId,
    /// Chunk sequence number
    pub sequence: ChunkSequence,
    /// Uncompressed size
    pub uncompressed_size: u64,
    /// Compressed size
    pub compressed_size: u64,
    /// Compression algorithm ID
    pub compression_id: CompressionId,
    /// Encryption algorithm ID
    pub encryption_id: EncryptionId,
    /// Hash algorithm ID
    pub hash_id: HashId,
    /// KDF ID
    pub kdf_id: KdfId,
    /// Nonce / IV (16 bytes)
    pub nonce: [u8; 16],
    /// Extension TLV entries
    pub extensions: Vec<TlvEntry>,
}

impl ChunkHeader {
    /// Create a new chunk header with default values.
    pub fn new(stream_id: StreamId, sequence: ChunkSequence) -> Self {
        Self {
            magic: *crate::CHUNK_MAGIC,
            total_size: 0,
            header_size: CHUNK_HEADER_MIN_SIZE as u32,
            flags: ChunkFlags::empty(),
            stream_id,
            sequence,
            uncompressed_size: 0,
            compressed_size: 0,
            compression_id: 0,
            encryption_id: 0,
            hash_id: 0,
            kdf_id: 0,
            nonce: [0u8; 16],
            extensions: Vec::new(),
        }
    }

    /// Get the minimum header size (68 bytes).
    pub const fn min_size() -> usize {
        CHUNK_HEADER_MIN_SIZE
    }

    /// Calculate the actual header size including extensions.
    pub fn calculate_header_size(&self) -> u32 {
        let extensions_size: usize = self.extensions.iter().map(|e| e.serialized_size()).sum();
        (CHUNK_HEADER_MIN_SIZE + extensions_size) as u32
    }

    /// Update the header size field.
    pub fn update_header_size(&mut self) {
        self.header_size = self.calculate_header_size();
    }

    /// Validate the chunk header.
    pub fn validate(&self) -> Result<()> {
        // Check magic
        if &self.magic != crate::CHUNK_MAGIC {
            return Err(Error::InvalidMagic {
                expected: crate::CHUNK_MAGIC,
                got: self.magic.to_vec(),
            });
        }

        // Check header size
        if self.header_size < CHUNK_HEADER_MIN_SIZE as u32 {
            return Err(Error::InvalidChunkHeader(format!(
                "Header size {} < minimum {}",
                self.header_size, CHUNK_HEADER_MIN_SIZE
            )));
        }

        if self.header_size > self.total_size {
            return Err(Error::InvalidChunkHeader(format!(
                "Header size {} > total size {}",
                self.header_size, self.total_size
            )));
        }

        Ok(())
    }

    /// Get the payload size (total - header - auth tag if present).
    pub fn payload_size(&self) -> usize {
        let auth_tag_size = if self.flags.has_auth_tag() { 16 } else { 0 };
        self.total_size as usize - self.header_size as usize - auth_tag_size
    }

    /// Add an extension TLV.
    pub fn add_extension(&mut self, entry: TlvEntry) {
        self.extensions.push(entry);
        self.update_header_size();
    }
}

impl Serialize for ChunkHeader {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // Ensure header_size is up to date
        let header_size = self.calculate_header_size();

        writer.write_all(&self.magic)?;
        writer.write_u32::<LittleEndian>(self.total_size)?;
        writer.write_u32::<LittleEndian>(header_size)?;
        writer.write_u32::<LittleEndian>(self.flags.get())?;
        writer.write_u32::<LittleEndian>(self.stream_id.get())?;
        writer.write_u64::<LittleEndian>(self.sequence.get())?;
        writer.write_u64::<LittleEndian>(self.uncompressed_size)?;
        writer.write_u64::<LittleEndian>(self.compressed_size)?;
        writer.write_u16::<LittleEndian>(self.compression_id)?;
        writer.write_u16::<LittleEndian>(self.encryption_id)?;
        writer.write_u16::<LittleEndian>(self.hash_id)?;
        writer.write_u16::<LittleEndian>(self.kdf_id)?;
        writer.write_all(&self.nonce)?;

        // Write extensions
        for entry in &self.extensions {
            entry.serialize(writer)?;
        }

        // Pad to header_size if needed
        let current_size = 4 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 2 + 2 + 2 + 2 + 16
            + self.extensions.iter().map(|e| e.serialized_size()).sum::<usize>();
        let target_size = header_size as usize;
        if current_size < target_size {
            writer.write_all(&vec![0u8; target_size - current_size])?;
        }

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.calculate_header_size() as usize
    }
}

impl Deserialize for ChunkHeader {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let total_size = reader.read_u32::<LittleEndian>()?;
        let header_size = reader.read_u32::<LittleEndian>()?;
        let flags = ChunkFlags::from(reader.read_u32::<LittleEndian>()?);
        let stream_id = StreamId::try_from(reader.read_u32::<LittleEndian>()?)?;
        let sequence = ChunkSequence::from(reader.read_u64::<LittleEndian>()?);
        let uncompressed_size = reader.read_u64::<LittleEndian>()?;
        let compressed_size = reader.read_u64::<LittleEndian>()?;
        let compression_id = reader.read_u16::<LittleEndian>()?;
        let encryption_id = reader.read_u16::<LittleEndian>()?;
        let hash_id = reader.read_u16::<LittleEndian>()?;
        let kdf_id = reader.read_u16::<LittleEndian>()?;

        let mut nonce = [0u8; 16];
        reader.read_exact(&mut nonce)?;

        // Read extensions if header is larger than minimum
        let extensions_size = header_size as usize - CHUNK_HEADER_MIN_SIZE;
        let mut extensions = Vec::new();

        if extensions_size > 0 {
            let mut ext_data = vec![0u8; extensions_size];
            reader.read_exact(&mut ext_data)?;
            // Parse TLV entries
            let mut cursor = std::io::Cursor::new(&ext_data);
            while cursor.position() < extensions_size as u64 {
                match TlvEntry::deserialize(&mut cursor) {
                    Ok(entry) => extensions.push(entry),
                    Err(_) => break, // Stop on invalid TLV
                }
            }
        }

        Ok(Self {
            magic,
            total_size,
            header_size,
            flags,
            stream_id,
            sequence,
            uncompressed_size,
            compressed_size,
            compression_id,
            encryption_id,
            hash_id,
            kdf_id,
            nonce,
            extensions,
        })
    }
}

/// Complete chunk information including data.
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    /// Chunk header
    pub header: ChunkHeader,
    /// Payload data (may be compressed/encrypted)
    pub payload: Vec<u8>,
    /// Authentication tag (if present)
    pub auth_tag: Option<Vec<u8>>,
}

impl ChunkInfo {
    /// Create a new chunk info.
    pub fn new(header: ChunkHeader, payload: Vec<u8>, auth_tag: Option<Vec<u8>>) -> Self {
        Self {
            header,
            payload,
            auth_tag,
        }
    }

    /// Calculate the total size of the serialized chunk.
    pub fn total_size(&self) -> usize {
        let auth_tag_size = self.auth_tag.as_ref().map(|t| t.len()).unwrap_or(0);
        self.header.serialized_size() + self.payload.len() + auth_tag_size
    }

    /// Serialize the complete chunk.
    pub fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.header.serialize(writer)?;
        writer.write_all(&self.payload)?;
        if let Some(ref tag) = self.auth_tag {
            writer.write_all(tag)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_header_serialize() {
        let mut header = ChunkHeader::new(StreamId::new(1).unwrap(), ChunkSequence::new(0));
        header.uncompressed_size = 100;
        header.compressed_size = 80;
        header.compression_id = 3; // Zstd

        let mut buf = Vec::new();
        header.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = ChunkHeader::deserialize(&mut reader).unwrap();

        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.stream_id, deserialized.stream_id);
        assert_eq!(header.sequence, deserialized.sequence);
        assert_eq!(header.uncompressed_size, deserialized.uncompressed_size);
    }

    #[test]
    fn test_chunk_header_validate() {
        let mut header = ChunkHeader::new(StreamId::new(1).unwrap(), ChunkSequence::new(0));
        header.total_size = 100;
        header.header_size = CHUNK_HEADER_MIN_SIZE as u32;

        assert!(header.validate().is_ok());

        let mut invalid = header.clone();
        invalid.magic = *b"XXXX";
        assert!(invalid.validate().is_err());
    }
}

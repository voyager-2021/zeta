//! File header format for ZETA containers.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::format::{crc32, Deserialize, Serialize};
use crate::types::{Uuid, ZetaFlags};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// File header for ZETA containers (144 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// Magic number: "ZETA"
    pub magic: [u8; 4],
    /// Version major
    pub version_major: u16,
    /// Version minor
    pub version_minor: u16,
    /// Flags
    pub flags: ZetaFlags,
    /// File UUID
    pub uuid: Uuid,
    /// Header length
    pub header_length: u64,
    /// Metadata offset
    pub metadata_offset: u64,
    /// Stream directory offset
    pub stream_dir_offset: u64,
    /// Reserved (88 bytes, must be zero)
    pub reserved: [u8; 88],
    /// Header CRC32
    pub crc32: u32,
}

impl FileHeader {
    /// Create a new file header with default values.
    pub fn new(flags: ZetaFlags, uuid: Uuid) -> Self {
        Self {
            magic: *crate::MAGIC,
            version_major: crate::VERSION.0,
            version_minor: crate::VERSION.1,
            flags,
            uuid,
            header_length: HEADER_SIZE as u64,
            metadata_offset: 0,
            stream_dir_offset: 0,
            reserved: [0u8; 88],
            crc32: 0,
        }
    }

    /// Validate the header.
    pub fn validate(&self) -> Result<()> {
        // Check magic
        if &self.magic != crate::MAGIC {
            return Err(Error::InvalidMagic {
                expected: crate::MAGIC,
                got: self.magic.to_vec(),
            });
        }

        // Check version
        if self.version_major != crate::VERSION.0 {
            return Err(Error::InvalidVersion {
                major: self.version_major,
                minor: self.version_minor,
                supported_major: crate::VERSION.0,
                supported_minor: crate::VERSION.1,
            });
        }

        // Check header length
        if self.header_length < HEADER_SIZE as u64 {
            return Err(Error::InvalidHeaderSize(self.header_length));
        }

        Ok(())
    }

    /// Calculate CRC32 over the header (excluding the CRC field itself).
    pub fn calculate_crc(&self) -> u32 {
        let mut data = Vec::with_capacity(HEADER_SIZE - 4);
        self.serialize_without_crc(&mut data).unwrap();
        crc32(&data)
    }

    /// Verify CRC32.
    pub fn verify_crc(&self) -> Result<()> {
        let calculated = self.calculate_crc();
        if calculated != self.crc32 {
            Err(Error::CrcMismatch {
                expected: self.crc32,
                calculated,
            })
        } else {
            Ok(())
        }
    }

    /// Update CRC32.
    pub fn update_crc(&mut self) {
        self.crc32 = self.calculate_crc();
    }

    /// Serialize without CRC field.
    fn serialize_without_crc<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_u16::<LittleEndian>(self.version_major)?;
        writer.write_u16::<LittleEndian>(self.version_minor)?;
        writer.write_u32::<LittleEndian>(self.flags.get())?;
        writer.write_all(self.uuid.as_bytes())?;
        writer.write_u64::<LittleEndian>(self.header_length)?;
        writer.write_u64::<LittleEndian>(self.metadata_offset)?;
        writer.write_u64::<LittleEndian>(self.stream_dir_offset)?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }
}

impl Serialize for FileHeader {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.serialize_without_crc(writer)?;
        writer.write_u32::<LittleEndian>(self.crc32)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        HEADER_SIZE
    }
}

impl Deserialize for FileHeader {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let version_major = reader.read_u16::<LittleEndian>()?;
        let version_minor = reader.read_u16::<LittleEndian>()?;
        let flags = ZetaFlags::from(reader.read_u32::<LittleEndian>()?);

        let mut uuid_bytes = [0u8; 16];
        reader.read_exact(&mut uuid_bytes)?;
        let uuid = Uuid::from_bytes(uuid_bytes);

        let header_length = reader.read_u64::<LittleEndian>()?;
        let metadata_offset = reader.read_u64::<LittleEndian>()?;
        let stream_dir_offset = reader.read_u64::<LittleEndian>()?;

        let mut reserved = [0u8; 88];
        reader.read_exact(&mut reserved)?;

        let crc32 = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            magic,
            version_major,
            version_minor,
            flags,
            uuid,
            header_length,
            metadata_offset,
            stream_dir_offset,
            reserved,
            crc32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialize_deserialize() {
        let header = FileHeader::new(ZetaFlags::empty(), Uuid::new_v4());

        let mut buf = Vec::new();
        header.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE);

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = FileHeader::deserialize(&mut reader).unwrap();

        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version_major, deserialized.version_major);
        assert_eq!(header.flags.get(), deserialized.flags.get());
        assert_eq!(header.uuid.as_bytes(), deserialized.uuid.as_bytes());
    }

    #[test]
    fn test_header_validate() {
        let header = FileHeader::new(ZetaFlags::empty(), Uuid::new_v4());
        assert!(header.validate().is_ok());

        let mut invalid_header = header.clone();
        invalid_header.magic = *b"XXXX";
        assert!(invalid_header.validate().is_err());
    }

    #[test]
    fn test_crc32() {
        let mut header = FileHeader::new(ZetaFlags::empty(), Uuid::new_v4());
        header.update_crc();

        assert!(header.verify_crc().is_ok());

        header.version_minor += 1;
        assert!(header.verify_crc().is_err());
    }
}

//! Stream directory format for ZETA containers.

use crate::constants::MAX_STREAM_NAME_LENGTH;
use crate::error::{Error, Result};
use crate::format::{Deserialize, Serialize};
use crate::types::{ChunkSequence, StreamFlags, StreamId, StreamType};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Stream directory containing all stream entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamDir {
    /// Stream entries
    pub streams: Vec<StreamEntry>,
}

impl StreamDir {
    /// Create a new empty stream directory.
    pub fn new() -> Self {
        Self { streams: Vec::new() }
    }

    /// Add a stream entry.
    pub fn add_stream(&mut self, entry: StreamEntry) -> Result<()> {
        // Check for duplicate stream IDs
        if self.streams.iter().any(|s| s.id == entry.id) {
            return Err(Error::custom(format!(
                "Duplicate stream ID: {}",
                entry.id.get()
            )));
        }
        self.streams.push(entry);
        Ok(())
    }

    /// Get a stream entry by ID.
    pub fn get_stream(&self, id: StreamId) -> Option<&StreamEntry> {
        self.streams.iter().find(|s| s.id == id)
    }

    /// Get all stream IDs.
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.iter().map(|s| s.id).collect()
    }
}

impl Serialize for StreamDir {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // u32 stream_count
        writer.write_u32::<LittleEndian>(self.streams.len() as u32)?;

        for entry in &self.streams {
            entry.serialize(writer)?;
        }

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        4 + self.streams.iter().map(|s| s.serialized_size()).sum::<usize>()
    }
}

impl Deserialize for StreamDir {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let count = reader.read_u32::<LittleEndian>()? as usize;
        let mut streams = Vec::with_capacity(count);

        for _ in 0..count {
            streams.push(StreamEntry::deserialize(reader)?);
        }

        Ok(Self { streams })
    }
}

/// Single stream entry in the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    /// Stream ID (unique within file)
    pub id: StreamId,
    /// Stream name (UTF-8)
    pub name: String,
    /// Stream type
    pub stream_type: StreamType,
    /// Stream flags
    pub flags: StreamFlags,
    /// First chunk offset in file
    pub first_chunk_offset: u64,
    /// Total uncompressed size
    pub total_uncompressed_size: u64,
    /// Total number of chunks
    pub chunk_count: u64,
}

impl StreamEntry {
    /// Create a new stream entry.
    pub fn new(
        id: StreamId,
        name: impl Into<String>,
        stream_type: StreamType,
        first_chunk_offset: u64,
    ) -> Result<Self> {
        let name = name.into();
        if name.len() > MAX_STREAM_NAME_LENGTH {
            return Err(Error::custom(format!(
                "Stream name too long: {} > {}",
                name.len(),
                MAX_STREAM_NAME_LENGTH
            )));
        }

        Ok(Self {
            id,
            name,
            stream_type,
            flags: StreamFlags::empty(),
            first_chunk_offset,
            total_uncompressed_size: 0,
            chunk_count: 0,
        })
    }

    /// Update statistics after writing chunks.
    pub fn update_stats(&mut self, uncompressed_size: u64, chunk_count: u64) {
        self.total_uncompressed_size = uncompressed_size;
        self.chunk_count = chunk_count;
    }
}

impl Serialize for StreamEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // u32 stream_id
        writer.write_u32::<LittleEndian>(self.id.get())?;

        // u16 name_length + name bytes
        let name_bytes = self.name.as_bytes();
        writer.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
        writer.write_all(name_bytes)?;

        // u8 type
        writer.write_u8(self.stream_type.to_u8())?;

        // u8 flags
        writer.write_u8(self.flags.get())?;

        // u64 first_chunk_offset
        writer.write_u64::<LittleEndian>(self.first_chunk_offset)?;

        // u64 total_uncompressed_size
        writer.write_u64::<LittleEndian>(self.total_uncompressed_size)?;

        // u64 chunk_count
        writer.write_u64::<LittleEndian>(self.chunk_count)?;

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        4 + // stream_id
        2 + self.name.len() + // name_length + name
        1 + // type
        1 + // flags
        8 + // first_chunk_offset
        8 + // total_uncompressed_size
        8 // chunk_count
    }
}

impl Deserialize for StreamEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let id = StreamId::try_from(reader.read_u32::<LittleEndian>()?)?;

        let name_len = reader.read_u16::<LittleEndian>()? as usize;
        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes)
            .map_err(|e| Error::custom(format!("Invalid UTF-8 in stream name: {}", e)))?;

        let stream_type = StreamType::from(reader.read_u8()?);
        let flags = StreamFlags::from(reader.read_u8()?);
        let first_chunk_offset = reader.read_u64::<LittleEndian>()?;
        let total_uncompressed_size = reader.read_u64::<LittleEndian>()?;
        let chunk_count = reader.read_u64::<LittleEndian>()?;

        Ok(Self {
            id,
            name,
            stream_type,
            flags,
            first_chunk_offset,
            total_uncompressed_size,
            chunk_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_entry_serialize() {
        let entry = StreamEntry::new(
            StreamId::new(1).unwrap(),
            "test.txt",
            StreamType::Data,
            144,
        )
        .unwrap();

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = StreamEntry::deserialize(&mut reader).unwrap();

        assert_eq!(entry.id, deserialized.id);
        assert_eq!(entry.name, deserialized.name);
        assert_eq!(entry.stream_type.to_u8(), deserialized.stream_type.to_u8());
    }

    #[test]
    fn test_stream_dir_serialize() {
        let mut dir = StreamDir::new();
        dir.add_stream(
            StreamEntry::new(StreamId::new(1).unwrap(), "stream1", StreamType::Data, 144).unwrap(),
        )
        .unwrap();
        dir.add_stream(
            StreamEntry::new(StreamId::new(2).unwrap(), "stream2", StreamType::Metadata, 1000)
                .unwrap(),
        )
        .unwrap();

        let mut buf = Vec::new();
        dir.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = StreamDir::deserialize(&mut reader).unwrap();

        assert_eq!(dir.streams.len(), deserialized.streams.len());
    }

    #[test]
    fn test_duplicate_stream_id() {
        let mut dir = StreamDir::new();
        dir.add_stream(
            StreamEntry::new(StreamId::new(1).unwrap(), "stream1", StreamType::Data, 144).unwrap(),
        )
        .unwrap();

        let result = dir.add_stream(
            StreamEntry::new(StreamId::new(1).unwrap(), "stream2", StreamType::Data, 200).unwrap(),
        );

        assert!(result.is_err());
    }
}

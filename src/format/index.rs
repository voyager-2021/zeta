//! Index block format for ZETA containers (random access).

use crate::error::Result;
use crate::format::{Deserialize, Serialize};
use crate::types::{ChunkSequence, StreamId};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Index block for random access to chunks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndexBlock {
    /// Index entries
    pub entries: Vec<IndexEntry>,
}

impl IndexBlock {
    /// Create a new empty index block.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add an index entry.
    pub fn add_entry(&mut self, entry: IndexEntry) {
        self.entries.push(entry);
    }

    /// Get entries for a specific stream.
    pub fn entries_for_stream(&self, stream_id: StreamId) -> Vec<&IndexEntry> {
        self.entries
            .iter()
            .filter(|e| e.stream_id == stream_id)
            .collect()
    }

    /// Find the entry for a specific chunk in a stream.
    pub fn find_chunk(&self, stream_id: StreamId, sequence: ChunkSequence) -> Option<&IndexEntry> {
        self.entries
            .iter()
            .find(|e| e.stream_id == stream_id && e.chunk_sequence == sequence)
    }

    /// Sort entries by (stream_id, chunk_sequence) for efficient lookup.
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| {
            a.stream_id
                .get()
                .cmp(&b.stream_id.get())
                .then_with(|| a.chunk_sequence.get().cmp(&b.chunk_sequence.get()))
        });
    }

    /// Validate that all entries are valid.
    pub fn validate(&self) -> Result<()> {
        // Check for duplicates
        for (i, entry) in self.entries.iter().enumerate() {
            for other in &self.entries[i + 1..] {
                if entry.stream_id == other.stream_id
                    && entry.chunk_sequence == other.chunk_sequence
                {
                    return Err(crate::Error::custom(format!(
                        "Duplicate index entry for stream {} chunk {}",
                        entry.stream_id, entry.chunk_sequence
                    )));
                }
            }
        }
        Ok(())
    }
}

impl Serialize for IndexBlock {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // u32 entry_count
        writer.write_u32::<LittleEndian>(self.entries.len() as u32)?;

        for entry in &self.entries {
            entry.serialize(writer)?;
        }

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        4 + self.entries.iter().map(|e| e.serialized_size()).sum::<usize>()
    }
}

impl Deserialize for IndexBlock {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let count = reader.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            entries.push(IndexEntry::deserialize(reader)?);
        }

        Ok(Self { entries })
    }
}

/// Single index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Stream ID
    pub stream_id: StreamId,
    /// Chunk sequence number
    pub chunk_sequence: ChunkSequence,
    /// File offset to chunk header
    pub file_offset: u64,
}

impl IndexEntry {
    /// Create a new index entry.
    pub fn new(stream_id: StreamId, chunk_sequence: ChunkSequence, file_offset: u64) -> Self {
        Self {
            stream_id,
            chunk_sequence,
            file_offset,
        }
    }
}

impl Serialize for IndexEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.stream_id.get())?;
        writer.write_u64::<LittleEndian>(self.chunk_sequence.get())?;
        writer.write_u64::<LittleEndian>(self.file_offset)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        4 + 8 + 8 // stream_id + chunk_sequence + file_offset
    }
}

impl Deserialize for IndexEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let stream_id = StreamId::try_from(reader.read_u32::<LittleEndian>()?)?;
        let chunk_sequence = ChunkSequence::from(reader.read_u64::<LittleEndian>()?);
        let file_offset = reader.read_u64::<LittleEndian>()?;

        Ok(Self {
            stream_id,
            chunk_sequence,
            file_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_entry_serialize() {
        let entry = IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(5), 1024);

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), entry.serialized_size());

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = IndexEntry::deserialize(&mut reader).unwrap();

        assert_eq!(entry.stream_id, deserialized.stream_id);
        assert_eq!(entry.chunk_sequence, deserialized.chunk_sequence);
        assert_eq!(entry.file_offset, deserialized.file_offset);
    }

    #[test]
    fn test_index_block_serialize() {
        let mut block = IndexBlock::new();
        block.add_entry(IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(0), 100));
        block.add_entry(IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(1), 200));
        block.add_entry(IndexEntry::new(StreamId::new(2).unwrap(), ChunkSequence::new(0), 300));

        let mut buf = Vec::new();
        block.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = IndexBlock::deserialize(&mut reader).unwrap();

        assert_eq!(block.entries.len(), deserialized.entries.len());
    }

    #[test]
    fn test_find_chunk() {
        let mut block = IndexBlock::new();
        block.add_entry(IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(0), 100));
        block.add_entry(IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(1), 200));
        block.add_entry(IndexEntry::new(StreamId::new(2).unwrap(), ChunkSequence::new(0), 300));

        let found = block.find_chunk(StreamId::new(1).unwrap(), ChunkSequence::new(1));
        assert!(found.is_some());
        assert_eq!(found.unwrap().file_offset, 200);

        let not_found = block.find_chunk(StreamId::new(3).unwrap(), ChunkSequence::new(0));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_sort() {
        let mut block = IndexBlock::new();
        block.add_entry(IndexEntry::new(StreamId::new(2).unwrap(), ChunkSequence::new(1), 200));
        block.add_entry(IndexEntry::new(StreamId::new(1).unwrap(), ChunkSequence::new(0), 100));
        block.add_entry(IndexEntry::new(StreamId::new(2).unwrap(), ChunkSequence::new(0), 150));

        block.sort();

        assert_eq!(block.entries[0].stream_id.get(), 1);
        assert_eq!(block.entries[1].stream_id.get(), 2);
        assert_eq!(block.entries[1].chunk_sequence.get(), 0);
        assert_eq!(block.entries[2].chunk_sequence.get(), 1);
    }
}

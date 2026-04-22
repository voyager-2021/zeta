//! TLV (Type-Length-Value) extension format for ZETA.

use crate::error::{Error, Result};
use crate::format::{Deserialize, Serialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// TLV extension entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvEntry {
    /// Type (u16)
    pub tlv_type: u16,
    /// Length (u16)
    pub length: u16,
    /// Value bytes
    pub value: Vec<u8>,
}

impl TlvEntry {
    /// Create a new TLV entry.
    pub fn new(tlv_type: u16, value: Vec<u8>) -> Self {
        Self {
            tlv_type,
            length: value.len() as u16,
            value,
        }
    }

    /// Create a chunk metadata TLV.
    pub fn chunk_metadata(data: Vec<u8>) -> Self {
        Self::new(crate::constants::TLV_TYPE_CHUNK_METADATA, data)
    }

    /// Create compression params TLV.
    pub fn compression_params(data: Vec<u8>) -> Self {
        Self::new(crate::constants::TLV_TYPE_COMPRESSION_PARAMS, data)
    }

    /// Create encryption params TLV.
    pub fn encryption_params(data: Vec<u8>) -> Self {
        Self::new(crate::constants::TLV_TYPE_ENCRYPTION_PARAMS, data)
    }

    /// Get the value as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Convert value to string if valid UTF-8.
    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.value.clone())
            .map_err(|e| Error::custom(format!("Invalid UTF-8 in TLV: {}", e)))
    }
}

impl Serialize for TlvEntry {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<LittleEndian>(self.tlv_type)?;
        writer.write_u16::<LittleEndian>(self.value.len() as u16)?;
        writer.write_all(&self.value)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        2 + 2 + self.value.len() // type + length + value
    }
}

impl Deserialize for TlvEntry {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let tlv_type = reader.read_u16::<LittleEndian>()?;
        let length = reader.read_u16::<LittleEndian>()?;

        let mut value = vec![0u8; length as usize];
        reader.read_exact(&mut value)?;

        Ok(Self {
            tlv_type,
            length,
            value,
        })
    }
}

/// TLV reader for parsing multiple TLV entries.
pub struct TlvReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> TlvReader<'a> {
    /// Create a new TLV reader.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
        }
    }

    /// Read the next TLV entry.
    pub fn next(&mut self) -> Result<Option<TlvEntry>> {
        if self.position >= self.data.len() {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&self.data[self.position..]);
        let entry = TlvEntry::deserialize(&mut cursor)?;
        self.position += entry.serialized_size();

        Ok(Some(entry))
    }

    /// Read all remaining TLV entries.
    pub fn read_all(&mut self) -> Vec<TlvEntry> {
        let mut entries = Vec::new();
        while let Ok(Some(entry)) = self.next() {
            entries.push(entry);
        }
        entries
    }
}

/// TLV writer for creating TLV data.
pub struct TlvWriter {
    entries: Vec<TlvEntry>,
}

impl Default for TlvWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl TlvWriter {
    /// Create a new TLV writer.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add a TLV entry.
    pub fn add(&mut self, entry: TlvEntry) {
        self.entries.push(entry);
    }

    /// Add raw TLV data.
    pub fn add_raw(&mut self, tlv_type: u16, value: Vec<u8>) {
        self.add(TlvEntry::new(tlv_type, value));
    }

    /// Serialize all entries.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for entry in &self.entries {
            entry.serialize(&mut result).unwrap();
        }
        result
    }

    /// Get total serialized size.
    pub fn size(&self) -> usize {
        self.entries.iter().map(|e| e.serialized_size()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_entry_serialize() {
        let entry = TlvEntry::new(1, b"hello".to_vec());

        let mut buf = Vec::new();
        entry.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 2 + 2 + 5); // type + length + value

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = TlvEntry::deserialize(&mut reader).unwrap();

        assert_eq!(entry.tlv_type, deserialized.tlv_type);
        assert_eq!(entry.value, deserialized.value);
    }

    #[test]
    fn test_tlv_convenience_constructors() {
        let meta = TlvEntry::chunk_metadata(b"meta".to_vec());
        assert_eq!(meta.tlv_type, crate::constants::TLV_TYPE_CHUNK_METADATA);

        let comp = TlvEntry::compression_params(vec![1, 2, 3]);
        assert_eq!(comp.tlv_type, crate::constants::TLV_TYPE_COMPRESSION_PARAMS);

        let enc = TlvEntry::encryption_params(vec![4, 5, 6]);
        assert_eq!(enc.tlv_type, crate::constants::TLV_TYPE_ENCRYPTION_PARAMS);
    }

    #[test]
    fn test_tlv_reader() {
        let mut writer = TlvWriter::new();
        writer.add_raw(1, b"first".to_vec());
        writer.add_raw(2, b"second".to_vec());
        writer.add_raw(3, b"third".to_vec());

        let data = writer.serialize();
        let mut reader = TlvReader::new(&data);

        let first = reader.next().unwrap().unwrap();
        assert_eq!(first.tlv_type, 1);
        assert_eq!(first.value, b"first");

        let second = reader.next().unwrap().unwrap();
        assert_eq!(second.tlv_type, 2);

        let all_remaining = reader.read_all();
        assert_eq!(all_remaining.len(), 1);
        assert_eq!(all_remaining[0].tlv_type, 3);
    }

    #[test]
    fn test_tlv_as_string() {
        let entry = TlvEntry::new(1, b"hello world".to_vec());
        assert_eq!(entry.as_string().unwrap(), "hello world");

        let invalid = TlvEntry::new(1, vec![0x80, 0x81]); // Invalid UTF-8
        assert!(invalid.as_string().is_err());
    }
}

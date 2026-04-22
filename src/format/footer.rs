//! Footer format for ZETA containers.

use crate::error::{Error, Result};
use crate::format::{Deserialize, Serialize};
use crate::registry::Signature;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Footer for ZETA containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// Magic: "ZET!"
    pub magic: [u8; 4],
    /// Index offset (0 if no index)
    pub index_offset: u64,
    /// File hash (SHA-256, 32 bytes)
    pub file_hash: [u8; 32],
    /// Signature blocks
    pub signatures: Vec<SignatureBlock>,
}

impl Footer {
    /// Create a new footer.
    pub fn new(index_offset: u64, file_hash: [u8; 32]) -> Self {
        Self {
            magic: *crate::FOOTER_MAGIC,
            index_offset,
            file_hash,
            signatures: Vec::new(),
        }
    }

    /// Add a signature block.
    pub fn add_signature(&mut self, signature: SignatureBlock) {
        self.signatures.push(signature);
    }

    /// Validate the footer.
    pub fn validate(&self) -> Result<()> {
        if &self.magic != crate::FOOTER_MAGIC {
            return Err(Error::InvalidMagic {
                expected: crate::FOOTER_MAGIC,
                got: self.magic.to_vec(),
            });
        }
        Ok(())
    }

    /// Get the minimum serialized size.
    pub fn min_size() -> usize {
        4 + 8 + 32 + 2 // magic + index_offset + file_hash + signature_count
    }
}

impl Serialize for Footer {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_u64::<LittleEndian>(self.index_offset)?;
        writer.write_all(&self.file_hash)?;
        writer.write_u16::<LittleEndian>(self.signatures.len() as u16)?;

        for sig in &self.signatures {
            sig.serialize(writer)?;
        }

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        Self::min_size() + self.signatures.iter().map(|s| s.serialized_size()).sum::<usize>()
    }
}

impl Deserialize for Footer {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let index_offset = reader.read_u64::<LittleEndian>()?;

        let mut file_hash = [0u8; 32];
        reader.read_exact(&mut file_hash)?;

        let signature_count = reader.read_u16::<LittleEndian>()? as usize;
        let mut signatures = Vec::with_capacity(signature_count);

        for _ in 0..signature_count {
            signatures.push(SignatureBlock::deserialize(reader)?);
        }

        Ok(Self {
            magic,
            index_offset,
            file_hash,
            signatures,
        })
    }
}

/// Signature block within the footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBlock {
    /// Algorithm ID
    pub algorithm_id: u16,
    /// Key ID length
    pub key_id_length: u16,
    /// Key ID
    pub key_id: Vec<u8>,
    /// Signature length
    pub signature_length: u32,
    /// Signature bytes
    pub signature: Vec<u8>,
}

impl SignatureBlock {
    /// Create a new signature block.
    pub fn new(algorithm: Signature, key_id: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            algorithm_id: algorithm as u16,
            key_id_length: key_id.len() as u16,
            key_id,
            signature_length: signature.len() as u32,
            signature,
        }
    }

    /// Get the signature algorithm.
    pub fn algorithm(&self) -> Signature {
        match self.algorithm_id {
            1 => Signature::Ed25519,
            2 => Signature::EcdsaP256,
            3 => Signature::EcdsaP384,
            4 => Signature::RsaPss2048,
            5 => Signature::RsaPss4096,
            _ => Signature::None,
        }
    }
}

impl Serialize for SignatureBlock {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<LittleEndian>(self.algorithm_id)?;
        writer.write_u16::<LittleEndian>(self.key_id.len() as u16)?;
        writer.write_all(&self.key_id)?;
        writer.write_u32::<LittleEndian>(self.signature.len() as u32)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        2 + 2 + self.key_id.len() + 4 + self.signature.len()
    }
}

impl Deserialize for SignatureBlock {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let algorithm_id = reader.read_u16::<LittleEndian>()?;
        let key_id_length = reader.read_u16::<LittleEndian>()? as usize;

        let mut key_id = vec![0u8; key_id_length];
        reader.read_exact(&mut key_id)?;

        let signature_length = reader.read_u32::<LittleEndian>()? as usize;
        let mut signature = vec![0u8; signature_length];
        reader.read_exact(&mut signature)?;

        Ok(Self {
            algorithm_id,
            key_id_length: key_id_length as u16,
            key_id,
            signature_length: signature_length as u32,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_serialize() {
        let footer = Footer::new(1000, [0u8; 32]);

        let mut buf = Vec::new();
        footer.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = Footer::deserialize(&mut reader).unwrap();

        assert_eq!(footer.magic, deserialized.magic);
        assert_eq!(footer.index_offset, deserialized.index_offset);
        assert_eq!(footer.file_hash, deserialized.file_hash);
    }

    #[test]
    fn test_footer_with_signatures() {
        let mut footer = Footer::new(1000, [0u8; 32]);
        footer.add_signature(SignatureBlock::new(
            Signature::Ed25519,
            b"key1".to_vec(),
            vec![0u8; 64],
        ));
        footer.add_signature(SignatureBlock::new(
            Signature::EcdsaP256,
            b"key2".to_vec(),
            vec![0u8; 64],
        ));

        let mut buf = Vec::new();
        footer.serialize(&mut buf).unwrap();

        let mut reader = std::io::Cursor::new(&buf);
        let deserialized = Footer::deserialize(&mut reader).unwrap();

        assert_eq!(deserialized.signatures.len(), 2);
        assert_eq!(deserialized.signatures[0].algorithm(), Signature::Ed25519);
    }

    #[test]
    fn test_signature_block() {
        let sig = SignatureBlock::new(Signature::Ed25519, b"test-key".to_vec(), vec![0u8; 64]);

        assert_eq!(sig.algorithm(), Signature::Ed25519);
        assert_eq!(sig.key_id, b"test-key");
        assert_eq!(sig.signature.len(), 64);
    }
}

//! Hash algorithm implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for hash algorithms.
pub trait HashAlgorithm: Algorithm {
    /// Compute hash of data.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Get the output size in bytes.
    fn output_size(&self) -> usize;

    /// Verify a hash against data.
    fn verify(&self, data: &[u8], expected: &[u8]) -> Result<()> {
        let computed = self.hash(data);
        if computed == expected {
            Ok(())
        } else {
            Err(Error::HashVerification {
                algorithm: self.id(),
            })
        }
    }
}

/// Hash algorithm ID constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// No hashing
    None = 0,
    /// SHA-256
    Sha256 = 1,
    /// BLAKE2b
    Blake2b = 2,
    /// SHA-512
    Sha512 = 3,
    /// SHA3-256
    Sha3_256 = 4,
    /// SHA3-512
    Sha3_512 = 5,
    /// BLAKE3
    Blake3 = 6,
    /// SHAKE256
    Shake256 = 7,
}

/// No hash (empty).
pub struct NoneHash;

impl Algorithm for NoneHash {
    fn id(&self) -> u16 {
        Hash::None as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl HashAlgorithm for NoneHash {
    fn hash(&self, _data: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn output_size(&self) -> usize {
        0
    }
}

/// SHA-256 hash.
pub struct Sha256Hash;

impl Algorithm for Sha256Hash {
    fn id(&self) -> u16 {
        Hash::Sha256 as u16
    }

    fn name(&self) -> &'static str {
        "sha-256"
    }
}

impl HashAlgorithm for Sha256Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// BLAKE2b hash (512-bit output).
pub struct Blake2bHash;

impl Algorithm for Blake2bHash {
    fn id(&self) -> u16 {
        Hash::Blake2b as u16
    }

    fn name(&self) -> &'static str {
        "blake2b"
    }
}

impl HashAlgorithm for Blake2bHash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use blake2::{Blake2b512, Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        64
    }
}

/// SHA-512 hash.
pub struct Sha512Hash;

impl Algorithm for Sha512Hash {
    fn id(&self) -> u16 {
        Hash::Sha512 as u16
    }

    fn name(&self) -> &'static str {
        "sha-512"
    }
}

impl HashAlgorithm for Sha512Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        64
    }
}

/// SHA3-256 hash.
pub struct Sha3_256Hash;

impl Algorithm for Sha3_256Hash {
    fn id(&self) -> u16 {
        Hash::Sha3_256 as u16
    }

    fn name(&self) -> &'static str {
        "sha3-256"
    }
}

impl HashAlgorithm for Sha3_256Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// SHA3-512 hash.
pub struct Sha3_512Hash;

impl Algorithm for Sha3_512Hash {
    fn id(&self) -> u16 {
        Hash::Sha3_512 as u16
    }

    fn name(&self) -> &'static str {
        "sha3-512"
    }
}

impl HashAlgorithm for Sha3_512Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        64
    }
}

/// BLAKE3 hash (256-bit output).
pub struct Blake3Hash;

impl Algorithm for Blake3Hash {
    fn id(&self) -> u16 {
        Hash::Blake3 as u16
    }

    fn name(&self) -> &'static str {
        "blake3"
    }
}

impl HashAlgorithm for Blake3Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// SHAKE256 extendable-output function.
pub struct Shake256Hash;

impl Algorithm for Shake256Hash {
    fn id(&self) -> u16 {
        Hash::Shake256 as u16
    }

    fn name(&self) -> &'static str {
        "shake256"
    }
}

impl HashAlgorithm for Shake256Hash {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use sha3::{digest::ExtendableOutput, Digest, Shake256};
        use sha3::digest::Update;
        use sha3::digest::XofReader;

        let mut hasher = Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut result = vec![0u8; 32]; // Default 32-byte output
        reader.read(&mut result);
        result
    }

    fn output_size(&self) -> usize {
        32 // Default output size
    }
}

/// Hash a file using the specified algorithm.
pub fn hash_file(path: &std::path::Path, algorithm: Hash) -> Result<Vec<u8>> {
    use std::io::Read;

    let data = std::fs::read(path)?;

    let hash_result = match algorithm {
        Hash::None => NoneHash.hash(&data),
        Hash::Sha256 => Sha256Hash.hash(&data),
        Hash::Blake2b => Blake2bHash.hash(&data),
        Hash::Sha512 => Sha512Hash.hash(&data),
        Hash::Sha3_256 => Sha3_256Hash.hash(&data),
        Hash::Sha3_512 => Sha3_512Hash.hash(&data),
        Hash::Blake3 => Blake3Hash.hash(&data),
        Hash::Shake256 => Shake256Hash.hash(&data),
    };

    Ok(hash_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = Sha256Hash.hash(data);
        assert_eq!(hash.len(), 32);

        // Known SHA-256 of "hello"
        let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3() {
        let data = b"hello";
        let hash = Blake3Hash.hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_verify() {
        let data = b"test data";
        let hash = Sha256Hash.hash(data);
        assert!(Sha256Hash.verify(data, &hash).is_ok());
        assert!(Sha256Hash.verify(b"wrong data", &hash).is_err());
    }
}

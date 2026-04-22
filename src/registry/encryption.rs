//! Encryption algorithm implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for encryption algorithms.
pub trait EncryptionAlgorithm: Algorithm {
    /// Encrypt data in place.
    fn encrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt data in place.
    fn decrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;

    /// Get the nonce/IV size in bytes.
    fn nonce_size(&self) -> usize;

    /// Get the key size in bytes.
    fn key_size(&self) -> usize;

    /// Get the authentication tag size in bytes.
    fn tag_size(&self) -> usize;
}

/// Encryption algorithm ID constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// No encryption
    None = 0,
    /// AES-256-GCM
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 2,
}

/// No encryption (pass-through).
pub struct NoneEncryption;

impl Algorithm for NoneEncryption {
    fn id(&self) -> u16 {
        Encryption::None as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl EncryptionAlgorithm for NoneEncryption {
    fn encrypt(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn nonce_size(&self) -> usize {
        0
    }

    fn key_size(&self) -> usize {
        0
    }

    fn tag_size(&self) -> usize {
        0
    }
}

/// AES-256-GCM encryption.
pub struct Aes256GcmEncryption;

impl Algorithm for Aes256GcmEncryption {
    fn id(&self) -> u16 {
        Encryption::Aes256Gcm as u16
    }

    fn name(&self) -> &'static str {
        "aes-256-gcm"
    }
}

impl EncryptionAlgorithm for Aes256GcmEncryption {
    fn encrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "AES-256-GCM requires 32-byte key, got {}",
                key.len()
            )));
        }

        // AES-GCM uses 12-byte nonce
        let nonce_len = nonce.len().min(12);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("AES-256-GCM key init failed: {:?}", e)))?;

        cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::crypto(format!("AES-256-GCM encryption failed: {:?}", e)))
            .map(|v| v.to_vec())
    }

    fn decrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "AES-256-GCM requires 32-byte key, got {}",
                key.len()
            )));
        }

        // AES-GCM uses 12-byte nonce
        let nonce_len = nonce.len().min(12);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("AES-256-GCM key init failed: {:?}", e)))?;

        cipher
            .decrypt(nonce, data)
            .map_err(|e| Error::crypto(format!("AES-256-GCM decryption failed: {:?}", e)))
            .map(|v| v.to_vec())
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn key_size(&self) -> usize {
        32
    }

    fn tag_size(&self) -> usize {
        16
    }
}

/// ChaCha20-Poly1305 encryption.
pub struct ChaCha20Poly1305Encryption;

impl Algorithm for ChaCha20Poly1305Encryption {
    fn id(&self) -> u16 {
        Encryption::ChaCha20Poly1305 as u16
    }

    fn name(&self) -> &'static str {
        "chacha20-poly1305"
    }
}

impl EncryptionAlgorithm for ChaCha20Poly1305Encryption {
    fn encrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {}",
                key.len()
            )));
        }

        // ChaCha20-Poly1305 uses 12-byte nonce
        let nonce_len = nonce.len().min(12);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 key init failed: {:?}", e)))?;

        cipher
            .encrypt(nonce, data)
            .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 encryption failed: {:?}", e)))
            .map(|v| v.to_vec())
    }

    fn decrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if key.len() != 32 {
            return Err(Error::crypto(format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {}",
                key.len()
            )));
        }

        // ChaCha20-Poly1305 uses 12-byte nonce
        let nonce_len = nonce.len().min(12);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..nonce_len].copy_from_slice(&nonce[..nonce_len]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 key init failed: {:?}", e)))?;

        cipher
            .decrypt(nonce, data)
            .map_err(|e| Error::crypto(format!("ChaCha20-Poly1305 decryption failed: {:?}", e)))
            .map(|v| v.to_vec())
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn key_size(&self) -> usize {
        32
    }

    fn tag_size(&self) -> usize {
        16
    }
}

//! Key Derivation Function implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for KDF algorithms.
pub trait KdfAlgorithm: Algorithm {
    /// Derive a key from password/salt.
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize, params: &KdfParams) -> Result<Vec<u8>>;

    /// Get the minimum salt size.
    fn min_salt_size(&self) -> usize;
}

/// KDF algorithm ID constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// No KDF
    None = 0,
    /// PBKDF2
    Pbkdf2 = 1,
    /// Argon2id
    Argon2id = 2,
    /// Scrypt
    Scrypt = 3,
    /// HKDF
    Hkdf = 4,
    /// bcrypt (built-in salt)
    Bcrypt = 5,
}

/// Parameters for KDF algorithms.
#[derive(Debug, Clone, Default)]
pub struct KdfParams {
    /// Time cost (iterations for PBKDF2, time_cost for Argon2id, N for scrypt)
    pub time_cost: u32,
    /// Memory cost in KB (for Argon2id, scrypt)
    pub memory_cost: u32,
    /// Parallelism (for Argon2id, p for scrypt)
    pub parallelism: u32,
    /// Additional info for HKDF
    pub info: Option<Vec<u8>>,
}

impl KdfParams {
    /// Default parameters for Argon2id.
    pub fn argon2id_default() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 64 * 1024, // 64 MB
            parallelism: 4,
            info: None,
        }
    }

    /// Default parameters for PBKDF2.
    pub fn pbkdf2_default() -> Self {
        Self {
            time_cost: 100_000,
            memory_cost: 0,
            parallelism: 0,
            info: None,
        }
    }

    /// Default parameters for scrypt.
    pub fn scrypt_default() -> Self {
        Self {
            time_cost: 15, // log2(N) = 15, so N = 32768
            memory_cost: 8,
            parallelism: 1,
            info: None,
        }
    }
}

/// No KDF (pass-through, requires key to be provided directly).
#[derive(Debug)]
pub struct NoneKdf;

impl Algorithm for NoneKdf {
    fn id(&self) -> u16 {
        Kdf::None as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl KdfAlgorithm for NoneKdf {
    fn derive(&self, password: &[u8], _salt: &[u8], _output_len: usize, _params: &KdfParams) -> Result<Vec<u8>> {
        // For None KDF, password is used directly as the key
        Ok(password.to_vec())
    }

    fn min_salt_size(&self) -> usize {
        0
    }
}

/// PBKDF2 key derivation.
#[derive(Debug)]
pub struct Pbkdf2Kdf;

impl Algorithm for Pbkdf2Kdf {
    fn id(&self) -> u16 {
        Kdf::Pbkdf2 as u16
    }

    fn name(&self) -> &'static str {
        "pbkdf2"
    }
}

impl KdfAlgorithm for Pbkdf2Kdf {
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize, params: &KdfParams) -> Result<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        if salt.len() < 16 {
            return Err(Error::crypto("PBKDF2 requires at least 16 bytes of salt"));
        }

        let iterations = if params.time_cost >= 100_000 {
            params.time_cost as u32
        } else {
            100_000
        };

        let mut result = vec![0u8; output_len];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut result);
        Ok(result)
    }

    fn min_salt_size(&self) -> usize {
        16
    }
}

/// Argon2id key derivation.
#[derive(Debug)]
pub struct Argon2idKdf;

impl Algorithm for Argon2idKdf {
    fn id(&self) -> u16 {
        Kdf::Argon2id as u16
    }

    fn name(&self) -> &'static str {
        "argon2id"
    }
}

impl KdfAlgorithm for Argon2idKdf {
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize, params: &KdfParams) -> Result<Vec<u8>> {
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

        if salt.len() < 16 {
            return Err(Error::crypto("Argon2id requires at least 16 bytes of salt"));
        }

        // Salt is used directly with hash_password_into

        // Configure Argon2
        let time_cost = if params.time_cost >= 2 { params.time_cost } else { 2 };
        let memory_cost = if params.memory_cost >= 64 * 1024 { params.memory_cost } else { 64 * 1024 };
        let parallelism = if params.parallelism >= 1 { params.parallelism } else { 4 };

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(memory_cost, time_cost, parallelism, Some(output_len))
                .map_err(|e| Error::crypto(format!("Invalid Argon2 params: {:?}", e)))?,
        );

        // Use the password_hash crate's hasher to derive key
        // Note: We're using Argon2's hash_password_into for raw key derivation
        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| Error::crypto(format!("Argon2id derivation failed: {:?}", e)))?;

        Ok(output)
    }

    fn min_salt_size(&self) -> usize {
        16
    }
}

/// Scrypt key derivation.
#[derive(Debug)]
pub struct ScryptKdf;

impl Algorithm for ScryptKdf {
    fn id(&self) -> u16 {
        Kdf::Scrypt as u16
    }

    fn name(&self) -> &'static str {
        "scrypt"
    }
}

impl KdfAlgorithm for ScryptKdf {
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize, params: &KdfParams) -> Result<Vec<u8>> {
        use scrypt::scrypt;

        if salt.len() < 16 {
            return Err(Error::crypto("Scrypt requires at least 16 bytes of salt"));
        }

        // Calculate N = 2^time_cost (default 2^15 = 32768)
        let n_log2 = if params.time_cost >= 15 { params.time_cost } else { 15 };
        let r = if params.memory_cost >= 8 { params.memory_cost as u32 } else { 8 };
        let p = if params.parallelism >= 1 { params.parallelism as u32 } else { 1 };

        let scrypt_params = scrypt::Params::new(
            n_log2 as u8,
            r,
            p,
            output_len,
        ).map_err(|e| Error::crypto(format!("Invalid scrypt params: {:?}", e)))?;

        let mut output = vec![0u8; output_len];
        scrypt(password, salt, &scrypt_params, &mut output)
            .map_err(|e| Error::crypto(format!("Scrypt derivation failed: {:?}", e)))?;

        Ok(output)
    }

    fn min_salt_size(&self) -> usize {
        16
    }
}

/// HKDF key derivation.
#[derive(Debug)]
pub struct HkdfKdf;

impl Algorithm for HkdfKdf {
    fn id(&self) -> u16 {
        Kdf::Hkdf as u16
    }

    fn name(&self) -> &'static str {
        "hkdf"
    }
}

impl KdfAlgorithm for HkdfKdf {
    fn derive(&self, password: &[u8], salt: &[u8], output_len: usize, params: &KdfParams) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        if salt.len() < 16 {
            return Err(Error::crypto("HKDF requires at least 16 bytes of salt"));
        }

        let hk = Hkdf::<Sha256>::new(Some(salt), password);
        let mut output = vec![0u8; output_len];

        let info = params.info.as_deref().unwrap_or(&[]);
        hk.expand(info, &mut output)
            .map_err(|e| Error::crypto(format!("HKDF expansion failed: {:?}", e)))?;

        Ok(output)
    }

    fn min_salt_size(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2() {
        let password = b"password";
        let salt = b"random_salt_here";
        let params = KdfParams::pbkdf2_default();

        let key = Pbkdf2Kdf.derive(password, salt, 32, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf() {
        let password = b"password";
        let salt = b"random_salt_here";
        let params = KdfParams::default();

        let key = HkdfKdf.derive(password, salt, 32, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2id() {
        let password = b"password";
        let salt = b"random_salt_here";
        let params = KdfParams::argon2id_default();

        let key = Argon2idKdf.derive(password, salt, 32, &params).unwrap();
        assert_eq!(key.len(), 32);
    }
}

//! Signature algorithm implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for signature algorithms.
pub trait SignatureAlgorithm: Algorithm {
    /// Sign data and return signature.
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>>;

    /// Verify signature against data.
    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()>;

    /// Get the signature size in bytes.
    fn signature_size(&self) -> usize;
}

/// Signature algorithm ID constants.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// No signature
    None = 0,
    /// Ed25519
    Ed25519 = 1,
    /// ECDSA-P256
    EcdsaP256 = 2,
    /// ECDSA-P384
    EcdsaP384 = 3,
    /// RSA-PSS-2048
    RsaPss2048 = 4,
    /// RSA-PSS-4096
    RsaPss4096 = 5,
}

/// No signature.
pub struct NoneSignature;

impl Algorithm for NoneSignature {
    fn id(&self) -> u16 {
        Signature::None as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl SignatureAlgorithm for NoneSignature {
    fn sign(&self, _data: &[u8], _key: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn verify(&self, _data: &[u8], _signature: &[u8], _key: &[u8]) -> Result<()> {
        Ok(())
    }

    fn signature_size(&self) -> usize {
        0
    }
}

/// Ed25519 signature.
pub struct Ed25519Signature;

impl Algorithm for Ed25519Signature {
    fn id(&self) -> u16 {
        Signature::Ed25519 as u16
    }

    fn name(&self) -> &'static str {
        "ed25519"
    }
}

impl SignatureAlgorithm for Ed25519Signature {
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::{Signer, SigningKey};

        if key.len() != 32 {
            return Err(Error::InvalidSignature(
                "Ed25519 requires 32-byte secret key".to_string(),
            ));
        }

        let signing_key = SigningKey::from_bytes(key);
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()> {
        use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};

        if key.len() != 32 {
            return Err(Error::InvalidSignature(
                "Ed25519 requires 32-byte public key".to_string(),
            ));
        }

        if signature.len() != 64 {
            return Err(Error::InvalidSignature(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        let verifying_key = VerifyingKey::from_bytes(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid Ed25519 public key: {:?}", e)))?;

        let sig = EdSignature::from_bytes(signature)
            .map_err(|e| Error::InvalidSignature(format!("Invalid Ed25519 signature: {:?}", e)))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| Error::SignatureVerification {
                algorithm: Signature::Ed25519 as u16,
            })
    }

    fn signature_size(&self) -> usize {
        64
    }
}

/// ECDSA-P256 signature.
pub struct EcdsaP256Signature;

impl Algorithm for EcdsaP256Signature {
    fn id(&self) -> u16 {
        Signature::EcdsaP256 as u16
    }

    fn name(&self) -> &'static str {
        "ecdsa-p256"
    }
}

impl SignatureAlgorithm for EcdsaP256Signature {
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_slice(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P256 secret key: {:?}", e)))?;

        let signature: p256::ecdsa::Signature = signing_key.sign(data);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P256 public key: {:?}", e)))?;

        let sig = Signature::from_der(signature)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P256 signature: {:?}", e)))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| Error::SignatureVerification {
                algorithm: Signature::EcdsaP256 as u16,
            })
    }

    fn signature_size(&self) -> usize {
        64 // Approximate DER encoding size
    }
}

/// ECDSA-P384 signature.
pub struct EcdsaP384Signature;

impl Algorithm for EcdsaP384Signature {
    fn id(&self) -> u16 {
        Signature::EcdsaP384 as u16
    }

    fn name(&self) -> &'static str {
        "ecdsa-p384"
    }
}

impl SignatureAlgorithm for EcdsaP384Signature {
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use p384::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_slice(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P384 secret key: {:?}", e)))?;

        let signature: p384::ecdsa::Signature = signing_key.sign(data);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()> {
        use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P384 public key: {:?}", e)))?;

        let sig = Signature::from_der(signature)
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA-P384 signature: {:?}", e)))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| Error::SignatureVerification {
                algorithm: Signature::EcdsaP384 as u16,
            })
    }

    fn signature_size(&self) -> usize {
        96 // Approximate DER encoding size
    }
}

/// RSA-PSS-2048 signature.
pub struct RsaPss2048Signature;

impl Algorithm for RsaPss2048Signature {
    fn id(&self) -> u16 {
        Signature::RsaPss2048 as u16
    }

    fn name(&self) -> &'static str {
        "rsa-pss-2048"
    }
}

impl SignatureAlgorithm for RsaPss2048Signature {
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use rsa::{
            pss::SigningKey,
            sha2::Sha256,
            signature::Signer,
            RsaPrivateKey,
        };

        let private_key = RsaPrivateKey::from_pkcs8_der(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA private key: {:?}", e)))?;

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key
            .sign(data)
            .map_err(|e| Error::InvalidSignature(format!("RSA-PSS signing failed: {:?}", e)))?;

        Ok(signature.to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()> {
        use rsa::{
            pss::VerifyingKey,
            sha2::Sha256,
            signature::Verifier,
            RsaPublicKey,
        };

        let public_key = RsaPublicKey::from_public_key_der(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA public key: {:?}", e)))?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let sig = rsa::pss::Signature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA-PSS signature: {:?}", e)))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| Error::SignatureVerification {
                algorithm: Signature::RsaPss2048 as u16,
            })
    }

    fn signature_size(&self) -> usize {
        256
    }
}

/// RSA-PSS-4096 signature.
pub struct RsaPss4096Signature;

impl Algorithm for RsaPss4096Signature {
    fn id(&self) -> u16 {
        Signature::RsaPss4096 as u16
    }

    fn name(&self) -> &'static str {
        "rsa-pss-4096"
    }
}

impl SignatureAlgorithm for RsaPss4096Signature {
    fn sign(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use rsa::{
            pss::SigningKey,
            sha2::Sha256,
            signature::Signer,
            RsaPrivateKey,
        };

        let private_key = RsaPrivateKey::from_pkcs8_der(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA private key: {:?}", e)))?;

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key
            .sign(data)
            .map_err(|e| Error::InvalidSignature(format!("RSA-PSS signing failed: {:?}", e)))?;

        Ok(signature.to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8], key: &[u8]) -> Result<()> {
        use rsa::{
            pss::VerifyingKey,
            sha2::Sha256,
            signature::Verifier,
            RsaPublicKey,
        };

        let public_key = RsaPublicKey::from_public_key_der(key)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA public key: {:?}", e)))?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let sig = rsa::pss::Signature::try_from(signature)
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA-PSS signature: {:?}", e)))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| Error::SignatureVerification {
                algorithm: Signature::RsaPss4096 as u16,
            })
    }

    fn signature_size(&self) -> usize {
        512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let data = b"test message";
        let secret_key = signing_key.to_bytes();
        let public_key = verifying_key.to_bytes();

        let signature = Ed25519Signature.sign(data, &secret_key).unwrap();
        assert_eq!(signature.len(), 64);

        Ed25519Signature.verify(data, &signature, &public_key).unwrap();

        // Wrong data should fail
        assert!(
            Ed25519Signature.verify(b"wrong data", &signature, &public_key).is_err()
        );
    }
}

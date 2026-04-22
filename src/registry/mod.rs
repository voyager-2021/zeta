//! Algorithm registry system for ZETA.
//!
//! Provides pluggable compression, encryption, hashing, KDF, delta encoding, and signature algorithms.

pub mod compression;
pub mod delta;
pub mod encryption;
pub mod hash;
pub mod kdf;
pub mod signature;

pub use compression::{Compression, CompressionAlgorithm};
pub use delta::{Delta, DeltaAlgorithm};
pub use encryption::{Encryption, EncryptionAlgorithm};
pub use hash::{Hash, HashAlgorithm};
pub use kdf::{Kdf, KdfAlgorithm};
pub use signature::{Signature, SignatureAlgorithm};

use crate::error::Result;

/// Trait for algorithms that can be registered by ID.
pub trait Algorithm: Send + Sync {
    /// Get the algorithm ID.
    fn id(&self) -> u16;

    /// Get the algorithm name.
    fn name(&self) -> &'static str;
}

/// Registry for algorithms of a specific type.
pub struct Registry<T: Algorithm> {
    algorithms: Vec<Box<T>>,
}

impl<T: Algorithm> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Algorithm> Registry<T> {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            algorithms: Vec::new(),
        }
    }

    /// Register an algorithm.
    pub fn register(&mut self, algorithm: Box<T>) {
        self.algorithms.push(algorithm);
    }

    /// Get an algorithm by ID.
    pub fn get(&self, id: u16) -> Option<&T> {
        self.algorithms.iter().find(|a| a.id() == id).map(|b| b.as_ref())
    }

    /// Check if an algorithm is registered.
    pub fn contains(&self, id: u16) -> bool {
        self.algorithms.iter().any(|a| a.id() == id)
    }

    /// List all registered algorithm IDs.
    pub fn list_ids(&self) -> Vec<u16> {
        self.algorithms.iter().map(|a| a.id()).collect()
    }

    /// List all registered algorithm names.
    pub fn list_names(&self) -> Vec<&'static str> {
        self.algorithms.iter().map(|a| a.name()).collect()
    }
}

/// Global algorithm registry.
#[derive(Default)]
pub struct GlobalRegistry {
    /// Compression algorithms
    pub compression: Registry<dyn CompressionAlgorithm>,
    /// Encryption algorithms
    pub encryption: Registry<dyn EncryptionAlgorithm>,
    /// Hash algorithms
    pub hash: Registry<dyn HashAlgorithm>,
    /// KDF algorithms
    pub kdf: Registry<dyn KdfAlgorithm>,
    /// Delta encoding algorithms
    pub delta: Registry<dyn DeltaAlgorithm>,
    /// Signature algorithms
    pub signature: Registry<dyn SignatureAlgorithm>,
}

impl GlobalRegistry {
    /// Create a new global registry with default algorithms.
    pub fn with_defaults() -> Self {
        let mut registry = Self::default();
        registry.register_defaults();
        registry
    }

    /// Register all default algorithms.
    fn register_defaults(&mut self) {
        use compression::*;
        use delta::*;
        use encryption::*;
        use hash::*;
        use kdf::*;
        use signature::*;

        // Compression
        self.compression.register(Box::new(NoneCompression));
        self.compression.register(Box::new(LzwCompression));
        self.compression.register(Box::new(RleCompression));
        self.compression.register(Box::new(ZstdCompression));
        self.compression.register(Box::new(Lz4Compression));
        self.compression.register(Box::new(BrotliCompression));
        self.compression.register(Box::new(ZlibCompression));
        self.compression.register(Box::new(GzipCompression));
        self.compression.register(Box::new(Bzip2Compression));
        self.compression.register(Box::new(LzmaCompression));
        self.compression.register(Box::new(SnappyCompression));
        self.compression.register(Box::new(Lzma2Compression));
        #[cfg(feature = "lzo")]
        self.compression.register(Box::new(LzoCompression));

        // Encryption
        self.encryption.register(Box::new(NoneEncryption));
        self.encryption.register(Box::new(Aes256GcmEncryption));
        self.encryption.register(Box::new(ChaCha20Poly1305Encryption));

        // Hash
        self.hash.register(Box::new(NoneHash));
        self.hash.register(Box::new(Sha256Hash));
        self.hash.register(Box::new(Blake2bHash));
        self.hash.register(Box::new(Sha512Hash));
        self.hash.register(Box::new(Sha3_256Hash));
        self.hash.register(Box::new(Sha3_512Hash));
        self.hash.register(Box::new(Blake3Hash));

        // KDF
        self.kdf.register(Box::new(NoneKdf));
        self.kdf.register(Box::new(Pbkdf2Kdf));
        self.kdf.register(Box::new(Argon2idKdf));
        self.kdf.register(Box::new(ScryptKdf));
        self.kdf.register(Box::new(HkdfKdf));

        // Delta
        self.delta.register(Box::new(NoneDelta));
        self.delta.register(Box::new(RawDiffDelta));

        // Signature
        self.signature.register(Box::new(NoneSignature));
        self.signature.register(Box::new(Ed25519Signature));
        self.signature.register(Box::new(EcdsaP256Signature));
        self.signature.register(Box::new(EcdsaP384Signature));
        self.signature.register(Box::new(RsaPss2048Signature));
        self.signature.register(Box::new(RsaPss4096Signature));
    }
}

/// Thread-local global registry instance.
use std::sync::OnceLock;
static GLOBAL_REGISTRY: OnceLock<GlobalRegistry> = OnceLock::new();

/// Get the global registry.
pub fn global_registry() -> &'static GlobalRegistry {
    GLOBAL_REGISTRY.get_or_init(GlobalRegistry::with_defaults)
}

/// Initialize the global registry with custom settings.
pub fn init_global_registry(registry: GlobalRegistry) {
    let _ = GLOBAL_REGISTRY.set(registry);
}

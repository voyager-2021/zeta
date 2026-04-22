//! Constants and registry values for the ZETA container format.

/// File header size (144 bytes)
pub const HEADER_SIZE: usize = 144;

/// Header magic offset
pub const HEADER_MAGIC_OFFSET: usize = 0x00;

/// Header version major offset
pub const HEADER_VERSION_MAJOR_OFFSET: usize = 0x04;

/// Header version minor offset
pub const HEADER_VERSION_MINOR_OFFSET: usize = 0x06;

/// Header flags offset
pub const HEADER_FLAGS_OFFSET: usize = 0x08;

/// Header UUID offset
pub const HEADER_UUID_OFFSET: usize = 0x0C;

/// Header length offset
pub const HEADER_LENGTH_OFFSET: usize = 0x1C;

/// Header metadata offset offset
pub const HEADER_METADATA_OFFSET: usize = 0x24;

/// Header stream directory offset
pub const HEADER_STREAM_DIR_OFFSET: usize = 0x2C;

/// Header reserved offset (88 bytes)
pub const HEADER_RESERVED_OFFSET: usize = 0x34;

/// Header reserved size
pub const HEADER_RESERVED_SIZE: usize = 88;

/// Header CRC32 offset
pub const HEADER_CRC32_OFFSET: usize = 0x8C;

/// Chunk header minimum size (68 bytes)
pub const CHUNK_HEADER_MIN_SIZE: usize = 68;

/// Chunk magic offset
pub const CHUNK_MAGIC_OFFSET: usize = 0x00;

/// Chunk total size offset
pub const CHUNK_TOTAL_SIZE_OFFSET: usize = 0x04;

/// Chunk header size offset
pub const CHUNK_HEADER_SIZE_OFFSET: usize = 0x08;

/// Chunk flags offset
pub const CHUNK_FLAGS_OFFSET: usize = 0x0C;

/// Chunk stream ID offset
pub const CHUNK_STREAM_ID_OFFSET: usize = 0x10;

/// Chunk sequence number offset
pub const CHUNK_SEQUENCE_OFFSET: usize = 0x14;

/// Chunk uncompressed size offset
pub const CHUNK_UNCOMPRESSED_SIZE_OFFSET: usize = 0x1C;

/// Chunk compressed size offset
pub const CHUNK_COMPRESSED_SIZE_OFFSET: usize = 0x24;

/// Chunk compression algorithm ID offset
pub const CHUNK_COMPRESSION_ID_OFFSET: usize = 0x2C;

/// Chunk encryption algorithm ID offset
pub const CHUNK_ENCRYPTION_ID_OFFSET: usize = 0x2E;

/// Chunk hash algorithm ID offset
pub const CHUNK_HASH_ID_OFFSET: usize = 0x30;

/// Chunk KDF ID offset
pub const CHUNK_KDF_ID_OFFSET: usize = 0x32;

/// Chunk nonce/IV offset
pub const CHUNK_NONCE_OFFSET: usize = 0x34;

/// Chunk nonce size
pub const CHUNK_NONCE_SIZE: usize = 16;

/// Chunk extension TLV offset
pub const CHUNK_TLV_OFFSET: usize = 0x44;

/// Default chunk size (1 MB)
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Minimum recommended chunk size (64 KB)
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum recommended chunk size (64 MB)
pub const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Maximum stream name length (255 bytes)
pub const MAX_STREAM_NAME_LENGTH: usize = 255;

/// Authentication tag size for AES-256-GCM (16 bytes)
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Authentication tag size for ChaCha20-Poly1305 (16 bytes)
pub const CHACHA20_TAG_SIZE: usize = 16;

/// Nonce size for AES-256-GCM (12 bytes)
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Nonce size for ChaCha20-Poly1305 (12 bytes)
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// SHA-256 output size (32 bytes)
pub const SHA256_HASH_SIZE: usize = 32;

/// SHA-512 output size (64 bytes)
pub const SHA512_HASH_SIZE: usize = 64;

/// BLAKE2b output size (64 bytes)
pub const BLAKE2B_HASH_SIZE: usize = 64;

/// BLAKE3 output size (32 bytes)
pub const BLAKE3_HASH_SIZE: usize = 32;

/// SHA3-256 output size (32 bytes)
pub const SHA3_256_HASH_SIZE: usize = 32;

/// SHA3-512 output size (64 bytes)
pub const SHA3_512_HASH_SIZE: usize = 64;

/// SHAKE256 default output size (32 bytes)
pub const SHAKE256_HASH_SIZE: usize = 32;

/// Ed25519 signature size (64 bytes)
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// ECDSA P-256 signature size (64 bytes)
pub const ECDSA_P256_SIGNATURE_SIZE: usize = 64;

/// ECDSA P-384 signature size (96 bytes)
pub const ECDSA_P384_SIGNATURE_SIZE: usize = 96;

/// RSA-PSS-2048 signature size (256 bytes)
pub const RSA_PSS_2048_SIGNATURE_SIZE: usize = 256;

/// RSA-PSS-4096 signature size (512 bytes)
pub const RSA_PSS_4096_SIGNATURE_SIZE: usize = 512;

/// Minimum salt size (16 bytes)
pub const MIN_SALT_SIZE: usize = 16;

/// Argon2id default time cost
pub const ARGON2ID_DEFAULT_TIME_COST: u32 = 3;

/// Argon2id default memory cost (64 MB in KB)
pub const ARGON2ID_DEFAULT_MEMORY_COST: u32 = 64 * 1024;

/// Argon2id default parallelism
pub const ARGON2ID_DEFAULT_PARALLELISM: u32 = 4;

/// PBKDF2 minimum iterations
pub const PBKDF2_MIN_ITERATIONS: u32 = 100_000;

/// Scrypt default N parameter (2^15)
pub const SCRYPT_DEFAULT_N: u64 = 32768;

/// Scrypt default r parameter
pub const SCRYPT_DEFAULT_R: u32 = 8;

/// Scrypt default p parameter
pub const SCRYPT_DEFAULT_P: u32 = 1;

/// Extension TLV type: Chunk Metadata
pub const TLV_TYPE_CHUNK_METADATA: u16 = 1;

/// Extension TLV type: Compression Params
pub const TLV_TYPE_COMPRESSION_PARAMS: u16 = 2;

/// Extension TLV type: Encryption Params
pub const TLV_TYPE_ENCRYPTION_PARAMS: u16 = 3;

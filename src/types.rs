//! Core types for the ZETA container format.

use std::fmt;
use std::ops::Deref;

/// A unique identifier for streams within a ZETA container.
/// Must be in range 0 to 2^31-1 (values 2^31-2^32 are reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u32);

impl StreamId {
    /// Maximum valid stream ID (2^31 - 1)
    pub const MAX: u32 = 0x7FFFFFFF;

    /// Reserved range start (2^31)
    pub const RESERVED_START: u32 = 0x80000000;

    /// Create a new StreamId, validating the value is in range.
    pub fn new(id: u32) -> Option<Self> {
        if id <= Self::MAX {
            Some(Self(id))
        } else {
            None
        }
    }

    /// Get the raw u32 value.
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<StreamId> for u32 {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

impl TryFrom<u32> for StreamId {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(|| crate::Error::InvalidStreamId(value))
    }
}

/// Chunk sequence number within a stream.
/// Must start at 0 and increment by 1 for each chunk in a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkSequence(u64);

impl ChunkSequence {
    /// Create a new chunk sequence number.
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    /// Get the raw u64 value.
    pub const fn get(&self) -> u64 {
        self.0
    }

    /// Get the next sequence number.
    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for ChunkSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ChunkSequence> for u64 {
    fn from(seq: ChunkSequence) -> Self {
        seq.0
    }
}

impl From<u64> for ChunkSequence {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// UUID (16 bytes) for file identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Create a UUID from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generate a new random UUID (v4).
    pub fn new_v4() -> Self {
        let uuid = uuid::Uuid::new_v4();
        Self(*uuid.as_bytes())
    }

    /// Get the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Deref for Uuid {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uuid = uuid::Uuid::from_bytes(self.0);
        write!(f, "{}", uuid)
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::new_v4()
    }
}

/// Stream type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    /// Data stream (default)
    Data = 0,
    /// Metadata stream
    Metadata = 1,
    /// Index stream
    Index = 2,
    /// Reserved range (3-255)
    Reserved(u8),
}

impl StreamType {
    /// Convert from raw byte value.
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Data,
            1 => Self::Metadata,
            2 => Self::Index,
            n => Self::Reserved(n),
        }
    }

    /// Convert to raw byte value.
    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Metadata => 1,
            Self::Index => 2,
            Self::Reserved(n) => *n,
        }
    }
}

impl From<u8> for StreamType {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<StreamType> for u8 {
    fn from(ty: StreamType) -> Self {
        ty.to_u8()
    }
}

/// Stream flags (1 byte).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamFlags(u8);

impl StreamFlags {
    /// Create empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if a flag is set.
    pub const fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    /// Get raw value.
    pub const fn get(&self) -> u8 {
        self.0
    }
}

impl From<u8> for StreamFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<StreamFlags> for u8 {
    fn from(flags: StreamFlags) -> Self {
        flags.0
    }
}

/// File-level flags (4 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZetaFlags(u32);

impl ZetaFlags {
    /// Encrypted content present
    pub const ENCRYPTED: u32 = 0x00000001;
    /// Index block present
    pub const INDEX_PRESENT: u32 = 0x00000002;
    /// Streaming mode enabled
    pub const STREAMING_MODE: u32 = 0x00000004;
    /// Content-addressable mode enabled
    pub const CONTENT_ADDRESSABLE: u32 = 0x00000008;
    /// Delta encoding enabled
    pub const DELTA_ENCODING: u32 = 0x00000010;

    /// Create empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if a flag is set.
    pub const fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Get raw value.
    pub const fn get(&self) -> u32 {
        self.0
    }

    /// Check if encrypted.
    pub const fn is_encrypted(&self) -> bool {
        self.contains(Self::ENCRYPTED)
    }

    /// Check if index is present.
    pub const fn has_index(&self) -> bool {
        self.contains(Self::INDEX_PRESENT)
    }

    /// Check if streaming mode.
    pub const fn is_streaming(&self) -> bool {
        self.contains(Self::STREAMING_MODE)
    }
}

impl From<u32> for ZetaFlags {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ZetaFlags> for u32 {
    fn from(flags: ZetaFlags) -> Self {
        flags.0
    }
}

/// Chunk flags (4 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChunkFlags(u32);

impl ChunkFlags {
    /// Chunk is compressed
    pub const COMPRESSED: u32 = 0x00000001;
    /// Chunk is encrypted
    pub const ENCRYPTED: u32 = 0x00000002;
    /// Authentication tag present
    pub const AUTH_TAG_PRESENT: u32 = 0x00000004;
    /// Delta encoded
    pub const DELTA_ENCODED: u32 = 0x00000008;
    /// Content-address reference
    pub const CONTENT_ADDRESS_REF: u32 = 0x00000010;
    /// Final chunk in stream
    pub const FINAL_CHUNK: u32 = 0x00000020;

    /// Create empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if a flag is set.
    pub const fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Get raw value.
    pub const fn get(&self) -> u32 {
        self.0
    }

    /// Check if compressed.
    pub const fn is_compressed(&self) -> bool {
        self.contains(Self::COMPRESSED)
    }

    /// Check if encrypted.
    pub const fn is_encrypted(&self) -> bool {
        self.contains(Self::ENCRYPTED)
    }

    /// Check if auth tag present.
    pub const fn has_auth_tag(&self) -> bool {
        self.contains(Self::AUTH_TAG_PRESENT)
    }

    /// Check if final chunk.
    pub const fn is_final(&self) -> bool {
        self.contains(Self::FINAL_CHUNK)
    }
}

impl From<u32> for ChunkFlags {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ChunkFlags> for u32 {
    fn from(flags: ChunkFlags) -> Self {
        flags.0
    }
}

/// Algorithm ID types.
pub type CompressionId = u16;
pub type EncryptionId = u16;
pub type HashId = u16;
pub type KdfId = u16;
pub type SignatureId = u16;

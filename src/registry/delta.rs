//! Delta encoding implementations.

use crate::error::{Error, Result};
use crate::registry::Algorithm;

/// Trait for delta encoding algorithms.
pub trait DeltaAlgorithm: Algorithm {
    /// Encode delta between base and target data.
    fn encode(&self, base: &[u8], target: &[u8]) -> Result<Vec<u8>>;

    /// Decode delta with base data to reconstruct target.
    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>>;
}

/// Delta algorithm ID constants.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delta {
    /// No delta encoding
    None = 0,
    /// Raw diff (byte-level difference)
    RawDiff = 1,
}

/// No delta encoding.
pub struct NoneDelta;

impl Algorithm for NoneDelta {
    fn id(&self) -> u16 {
        Delta::None as u16 as u16
    }

    fn name(&self) -> &'static str {
        "none"
    }
}

impl DeltaAlgorithm for NoneDelta {
    fn encode(&self, _base: &[u8], target: &[u8]) -> Result<Vec<u8>> {
        Ok(target.to_vec())
    }

    fn decode(&self, _base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
        Ok(delta.to_vec())
    }
}

/// Raw diff delta encoding (simple byte-level XOR difference).
pub struct RawDiffDelta;

impl Algorithm for RawDiffDelta {
    fn id(&self) -> u16 {
        Delta::RawDiff as u16 as u16
    }

    fn name(&self) -> &'static str {
        "raw-diff"
    }
}

impl DeltaAlgorithm for RawDiffDelta {
    fn encode(&self, base: &[u8], target: &[u8]) -> Result<Vec<u8>> {
        // Encode as: [u64: base_chunk_sequence] [u8[]: XOR differences]
        // For simplicity, we'll just do byte-level XOR
        let max_len = base.len().max(target.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let b = base.get(i).copied().unwrap_or(0);
            let t = target.get(i).copied().unwrap_or(0);
            result.push(t.wrapping_sub(b));
        }

        Ok(result)
    }

    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
        // Decode by adding base + delta
        let max_len = base.len().max(delta.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let b = base.get(i).copied().unwrap_or(0);
            let d = delta.get(i).copied().unwrap_or(0);
            result.push(b.wrapping_add(d));
        }

        Ok(result)
    }
}

/// XOR delta encoding.
pub struct XorDelta;

impl Algorithm for XorDelta {
    fn id(&self) -> u16 {
        // Custom algorithm ID
        1000
    }

    fn name(&self) -> &'static str {
        "xor"
    }
}

impl DeltaAlgorithm for XorDelta {
    fn encode(&self, base: &[u8], target: &[u8]) -> Result<Vec<u8>> {
        let max_len = base.len().max(target.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let b = base.get(i).copied().unwrap_or(0);
            let t = target.get(i).copied().unwrap_or(0);
            result.push(b ^ t);
        }

        Ok(result)
    }

    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
        let max_len = base.len().max(delta.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let b = base.get(i).copied().unwrap_or(0);
            let d = delta.get(i).copied().unwrap_or(0);
            result.push(b ^ d);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_delta() {
        let base = b"hello world";
        let target = b"hello rust";

        let encoded = NoneDelta.encode(base, target).unwrap();
        assert_eq!(&encoded, target);

        let decoded = NoneDelta.decode(base, &encoded).unwrap();
        assert_eq!(&decoded, target);
    }

    #[test]
    fn test_raw_diff_delta() {
        let base = vec![10u8, 20, 30, 40, 50];
        let target = vec![15u8, 25, 30, 45, 55];

        let encoded = RawDiffDelta.encode(&base, &target).unwrap();
        // Differences: [5, 5, 0, 5, 5]
        assert_eq!(encoded, vec![5, 5, 0, 5, 5]);

        let decoded = RawDiffDelta.decode(&base, &encoded).unwrap();
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_xor_delta() {
        let base = vec![0b10101010u8, 0b11110000];
        let target = vec![0b11111111u8, 0b00001111];

        let encoded = XorDelta.encode(&base, &target).unwrap();
        // XOR: [0b01010101, 0b11111111]
        assert_eq!(encoded, vec![0b01010101, 0b11111111]);

        let decoded = XorDelta.decode(&base, &encoded).unwrap();
        assert_eq!(decoded, target);
    }
}

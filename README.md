# ZETA - Zero-Trust Extended Archive Format

A high-performance container format with zero-trust verification, pluggable compression, encryption, and streaming-first design.

## Features

- **Zero-Trust**: All data must be cryptographically verified before use
- **Verify-before-Decompress**: Security-first design prevents decompression of unverified data
- **Pluggable Algorithms**: Compression, encryption, hashing, and KDF via registry system
- **Streaming-First**: Efficient sequential processing with optional random access indexing
- **Multi-Stream**: Single container with multiple independent streams
- **Full Spec Compliance**: ZETA 1.0 format implementation

## Supported Algorithms

### Compression (15+ algorithms)
- None, LZW, RLE, Zstandard, LZ4, Brotli, Zlib, Gzip, Bzip2, LZMA, Snappy, LZMA2

### Encryption
- None, AES-256-GCM, ChaCha20-Poly1305

### Hashing
- None, SHA-256, BLAKE2b, SHA-512, SHA3-256, SHA3-512, BLAKE3, SHAKE256

### Key Derivation
- None, PBKDF2, Argon2id (recommended), Scrypt, HKDF

### Signatures
- None, Ed25519, ECDSA-P256, ECDSA-P384, RSA-PSS-2048, RSA-PSS-4096

## Quick Start

### CLI Usage

```bash
# Pack files into ZETA container
zeta pack -o output.zeta file1.txt file2.txt dir/

# With compression
zeta pack -o output.zeta -c zstd file1.txt

# With encryption
zeta pack -o output.zeta -c zstd -e aes-256-gcm -p password file1.txt

# List contents
zeta list -i output.zeta

# Unpack
zeta unpack -i output.zeta -o ./extracted

# Verify integrity
zeta verify -i output.zeta --deep
```

### Rust Library

```rust
use zeta::{WriterBuilder, Reader, Compression, Encryption};

// Create container
let mut writer = WriterBuilder::new()
    .compression(Compression::Zstd)
    .with_index()
    .create(file)?;

writer.create_stream("data.txt")?;
writer.write_all(b"Hello, ZETA!")?;
writer.finish()?;

// Read container
let reader = Reader::open(file)?;
for stream in reader.streams() {
    println!("{}: {} bytes", stream.name, stream.total_uncompressed_size);
}
```

### Python Bindings

```python
import zeta

# Create container
with zeta.Writer("output.zeta", compression="zstd") as writer:
    writer.create_stream("hello.txt")
    writer.write(b"Hello, World!")

# Read container
with zeta.Reader("output.zeta") as reader:
    for stream in reader.streams():
        data = reader.read_stream(stream.name)
        print(f"{stream.name}: {len(data)} bytes")

# Convenience functions
zeta.pack("output.zeta", ["file1.txt", "file2.txt"], compression="zstd")
zeta.unpack("output.zeta", "./extracted")
```

## Building

### Rust Only

```bash
cargo build --release
```

### With Python Bindings

```bash
# Install maturin
pip install maturin

# Build and install
maturin develop --features python

# Or build wheel
maturin build --features python
```

### CLI Only

```bash
cargo build --release --features cli
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ZETA Container                          │
├─────────────────────────────────────────────────────────────┤
│  File Header (144 bytes)                                      │
│  - Magic: "ZETA"                                              │
│  - Version: 1.0                                             │
│  - Flags: Encrypted, Indexed, Streaming                      │
│  - UUID, CRC32                                               │
├─────────────────────────────────────────────────────────────┤
│  Stream Directory                                             │
│  - Stream count, entries                                     │
│  - Name, type, offset, size                                  │
├─────────────────────────────────────────────────────────────┤
│  Chunk Stream Data                                            │
│  - Chunk Header (68+ bytes)                                  │
│  - Magic: "CHK1"                                             │
│  - Flags, Stream ID, Sequence                                │
│  - Compression/Encryption/Hash/KDF IDs                      │
│  - Nonce (16 bytes)                                          │
│  - Payload (compressed/encrypted)                            │
│  - Auth Tag (if encrypted)                                   │
├─────────────────────────────────────────────────────────────┤
│  Index Block (optional)                                       │
│  - For random access                                         │
│  - Stream ID → Chunk Sequence → File Offset                  │
├─────────────────────────────────────────────────────────────┤
│  Footer (required)                                            │
│  - Magic: "ZET!"                                             │
│  - Index offset, file hash                                   │
│  - Signatures                                               │
└─────────────────────────────────────────────────────────────┘
```

## Processing Pipeline

### Encoding
```
Input → Delta Encoding → Compression → Encryption → Auth Tag
```

### Decoding (Verify-Before-Decompress)
```
Auth Tag → Decrypt → Verify → Decompress → Delta Decode
```

## Security

- **Nonce Uniqueness**: Per-chunk nonces are mandatory, reuse detection enforced
- **AEAD Ciphers**: AES-256-GCM and ChaCha20-Poly1305 provide authenticated encryption
- **Key Derivation**: Argon2id recommended for password-based keys
- **Verify-First**: Default mode verifies integrity before decompression

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

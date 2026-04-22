//! Basic integration tests for ZETA container format.

use std::io::Cursor;

use zeta::{
    types::{ZetaFlags, StreamId, ChunkSequence, Uuid},
    format::header::FileHeader,
    format::stream_dir::{StreamDir, StreamEntry},
    format::chunk::{ChunkHeader, ChunkInfo},
    format::index::{IndexBlock, IndexEntry},
    format::footer::{Footer, SignatureBlock},
    format::{Serialize, Deserialize},
    registry::compression::{NoneCompression, ZstdCompression},
    registry::encryption::{NoneEncryption, Aes256GcmEncryption},
    registry::hash::{Sha256Hash, Blake3Hash},
    registry::{CompressionAlgorithm, EncryptionAlgorithm, HashAlgorithm},
    pipeline::{PipelineConfig, encoder::{ChunkEncoder, EncodeOptions}},
    writer::{Writer, WriterBuilder},
    reader::Reader,
};

#[test]
fn test_header_roundtrip() {
    let header = FileHeader::new(ZetaFlags::empty(), Uuid::new_v4());

    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();

    let mut reader = Cursor::new(&buf);
    let decoded = FileHeader::deserialize(&mut reader).unwrap();

    assert_eq!(header.magic, decoded.magic);
    assert_eq!(header.version_major, decoded.version_major);
    assert_eq!(header.uuid.as_bytes(), decoded.uuid.as_bytes());
}

#[test]
fn test_header_crc() {
    let mut header = FileHeader::new(ZetaFlags::empty(), Uuid::new_v4());
    header.update_crc();

    assert!(header.verify_crc().is_ok());

    // Corrupt the header
    header.version_minor += 1;
    assert!(header.verify_crc().is_err());
}

#[test]
fn test_stream_dir_roundtrip() {
    let mut dir = StreamDir::new();
    dir.add_stream(StreamEntry::new(
        StreamId::new(1).unwrap(),
        "test.txt",
        zeta::types::StreamType::Data,
        144,
    ).unwrap()).unwrap();

    let mut buf = Vec::new();
    dir.serialize(&mut buf).unwrap();

    let mut reader = Cursor::new(&buf);
    let decoded = StreamDir::deserialize(&mut reader).unwrap();

    assert_eq!(dir.streams.len(), decoded.streams.len());
    assert_eq!(dir.streams[0].name, decoded.streams[0].name);
}

#[test]
fn test_chunk_header_roundtrip() {
    let mut header = ChunkHeader::new(
        StreamId::new(1).unwrap(),
        ChunkSequence::new(0),
    );
    header.uncompressed_size = 100;
    header.compressed_size = 80;
    header.total_size = 200;
    header.update_header_size();

    let mut buf = Vec::new();
    header.serialize(&mut buf).unwrap();

    let mut reader = Cursor::new(&buf);
    let decoded = ChunkHeader::deserialize(&mut reader).unwrap();

    assert_eq!(header.magic, decoded.magic);
    assert_eq!(header.stream_id, decoded.stream_id);
    assert_eq!(header.sequence, decoded.sequence);
}

#[test]
fn test_index_roundtrip() {
    let mut index = IndexBlock::new();
    index.add_entry(IndexEntry::new(
        StreamId::new(1).unwrap(),
        ChunkSequence::new(0),
        100,
    ));
    index.add_entry(IndexEntry::new(
        StreamId::new(1).unwrap(),
        ChunkSequence::new(1),
        200,
    ));
    index.sort();

    let mut buf = Vec::new();
    index.serialize(&mut buf).unwrap();

    let mut reader = Cursor::new(&buf);
    let decoded = IndexBlock::deserialize(&mut reader).unwrap();

    assert_eq!(index.entries.len(), decoded.entries.len());
    assert_eq!(index.entries[0].file_offset, decoded.entries[0].file_offset);
}

#[test]
fn test_footer_roundtrip() {
    let mut footer = Footer::new(1000, [0u8; 32]);
    footer.add_signature(SignatureBlock::new(
        zeta::registry::Signature::Ed25519,
        b"key1".to_vec(),
        vec![0u8; 64],
    ));

    let mut buf = Vec::new();
    footer.serialize(&mut buf).unwrap();

    let mut reader = Cursor::new(&buf);
    let decoded = Footer::deserialize(&mut reader).unwrap();

    assert_eq!(footer.magic, decoded.magic);
    assert_eq!(footer.signatures.len(), decoded.signatures.len());
}

#[test]
fn test_none_compression() {
    let algo = NoneCompression;
    let data = b"hello world";

    let compressed = algo.compress(data).unwrap();
    assert_eq!(compressed, data);

    let decompressed = algo.decompress(&compressed, data.len()).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_none_encryption() {
    let algo = NoneEncryption;
    let data = b"hello world";

    let encrypted = algo.encrypt(data, &[], &[]).unwrap();
    assert_eq!(encrypted, data);

    let decrypted = algo.decrypt(&encrypted, &[], &[]).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_sha256_hash() {
    let algo = Sha256Hash;
    let data = b"hello";

    let hash = algo.hash(data);
    assert_eq!(hash.len(), 32);

    // Known SHA-256 of "hello"
    let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
    assert_eq!(hash, expected);
}

#[test]
fn test_blake3_hash() {
    let algo = Blake3Hash;
    let data = b"hello";

    let hash = algo.hash(data);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_chunk_encoder_no_compression() {
    let config = PipelineConfig::new();
    let options = EncodeOptions::new(
        StreamId::new(1).unwrap(),
        ChunkSequence::new(0),
    ).final_chunk();

    let encoder = ChunkEncoder::new(config, options);
    let result = encoder.encode_simple(b"hello world").unwrap();

    assert_eq!(result.chunk.header.uncompressed_size, 11);
    assert!(result.chunk.header.flags.is_final());
}

#[test]
fn test_writer_creation() {
    let cursor = Cursor::new(Vec::new());
    let writer = Writer::new(cursor, ZetaFlags::empty()).unwrap();

    // Just verify creation works
    let cursor = writer.finish().unwrap();
    let data = cursor.into_inner();

    // Should have at least header size
    assert!(data.len() >= zeta::constants::HEADER_SIZE);
}

#[test]
fn test_writer_with_stream() {
    let cursor = Cursor::new(Vec::new());
    let mut writer = Writer::new(cursor, ZetaFlags::empty()).unwrap();

    writer.create_stream("test.txt").unwrap();
    writer.write_chunk(b"hello world", true).unwrap();

    let cursor = writer.finish().unwrap();
    let data = cursor.into_inner();

    assert!(!data.is_empty());
}

#[test]
fn test_writer_with_index() {
    use zeta::types::ZetaFlags;

    let cursor = Cursor::new(Vec::new());
    let writer = WriterBuilder::new()
        .with_index()
        .create(cursor)
        .unwrap();

    assert!(writer.header.flags.has_index());
}

#[test]
fn test_type_conversions() {
    // StreamId
    let id = StreamId::new(1).unwrap();
    assert_eq!(id.get(), 1);
    assert_eq!(StreamId::try_from(1u32).unwrap().get(), 1);

    // ChunkSequence
    let seq = ChunkSequence::new(5);
    assert_eq!(seq.get(), 5);
    assert_eq!(seq.next().get(), 6);

    // ZetaFlags
    let mut flags = ZetaFlags::empty();
    assert!(!flags.has_index());
    flags.set(ZetaFlags::INDEX_PRESENT);
    assert!(flags.has_index());
}

//! ZETA File I/O Demo
//!
//! This example demonstrates various ways to write and read files
//! using the ZETA container format.

use std::fs::File;
use zeta::{WriterBuilder, Reader};
use zeta::registry::compression::{NoneCompression, ZstdCompression, Lz4Compression, GzipCompression};
use zeta::registry::encryption::Aes256GcmEncryption;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZETA File I/O Demo ===\n");

    // 1. Basic write with no compression
    println!("1. Writing with no compression...");
    demo_basic_write()?;

    // 2. Write with Zstd compression
    println!("\n2. Writing with Zstd compression...");
    demo_zstd_compression()?;

    // 3. Write with LZ4 compression
    println!("\n3. Writing with LZ4 compression...");
    demo_lz4_compression()?;

    // 4. Write with Gzip compression
    println!("\n4. Writing with Gzip compression...");
    demo_gzip_compression()?;

    // 5. Write with encryption
    println!("\n5. Writing with AES-256-GCM encryption...");
    demo_encryption()?;

    // 6. Write with compression + encryption
    println!("\n6. Writing with Zstd + AES-256-GCM...");
    demo_compression_encryption()?;

    // 7. Read with streaming reader
    println!("\n7. Reading with streaming reader...");
    demo_streaming_read()?;

    // 8. Read with indexed reader
    println!("\n8. Reading with indexed reader...");
    demo_indexed_read()?;

    // 9. Multiple streams
    println!("\n9. Writing multiple streams...");
    demo_multiple_streams()?;

    println!("\n=== All demos completed successfully! ===");
    Ok(())
}

fn demo_basic_write() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_none.zeta")?;
    let mut writer = WriterBuilder::new()
        .compression(NoneCompression)
        .create(file)?;

    writer.create_stream("data.txt")?;
    writer.write_all(b"Hello, ZETA with no compression!")?;
    writer.finish()?;

    println!("  Created: demo_none.zeta (no compression)");
    Ok(())
}

fn demo_zstd_compression() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_zstd.zeta")?;
    let mut writer = WriterBuilder::new()
        .compression(ZstdCompression)
        .create(file)?;

    writer.create_stream("compressed.txt")?;
    writer.write_all(b"Hello, ZETA with Zstd compression! This text will be compressed efficiently.")?;
    writer.finish()?;

    println!("  Created: demo_zstd.zeta (Zstd compression)");
    Ok(())
}

fn demo_lz4_compression() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_lz4.zeta")?;
    let mut writer = WriterBuilder::new()
        .compression(Lz4Compression)
        .create(file)?;

    writer.create_stream("lz4_data.txt")?;
    writer.write_all(b"Hello, ZETA with LZ4 compression! Fast compression and decompression.")?;
    writer.finish()?;

    println!("  Created: demo_lz4.zeta (LZ4 compression)");
    Ok(())
}

fn demo_gzip_compression() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_gzip.zeta")?;
    let mut writer = WriterBuilder::new()
        .compression(GzipCompression)
        .create(file)?;

    writer.create_stream("gzip_data.txt")?;
    writer.write_all(b"Hello, ZETA with Gzip compression! Widely compatible format.")?;
    writer.finish()?;

    println!("  Created: demo_gzip.zeta (Gzip compression)");
    Ok(())
}

fn demo_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_encrypted.zeta")?;
    let key = [0u8; 32]; // Example key (use proper key derivation in production)
    
    let mut writer = WriterBuilder::new()
        .encryption(Aes256GcmEncryption, key.to_vec())
        .create(file)?;

    writer.create_stream("secret.txt")?;
    writer.write_all(b"Hello, ZETA with AES-256-GCM encryption! This is encrypted data.")?;
    writer.finish()?;

    println!("  Created: demo_encrypted.zeta (AES-256-GCM encryption)");
    Ok(())
}

fn demo_compression_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_full.zeta")?;
    let key = [0u8; 32]; // Example key
    
    let mut writer = WriterBuilder::new()
        .compression(ZstdCompression)
        .encryption(Aes256GcmEncryption, key.to_vec())
        .create(file)?;

    writer.create_stream("secure_data.txt")?;
    writer.write_all(b"Hello, ZETA with Zstd + AES-256-GCM + SHA256! Compressed and encrypted.")?;
    writer.finish()?;

    println!("  Created: demo_full.zeta (Zstd + AES-256-GCM + SHA256)");
    Ok(())
}

fn demo_streaming_read() -> Result<(), Box<dyn std::error::Error>> {
    // First create a file to read
    {
        let file = File::create("demo_read.zeta")?;
        let mut writer = WriterBuilder::new()
            .compression(ZstdCompression)
            .create(file)?;

        writer.create_stream("data.txt")?;
        writer.write_all(b"Streaming read demo data. This is chunk 1.")?;
        writer.write_all(b" This is chunk 2. ")?;
        writer.write_all(b" This is chunk 3.")?;
        writer.finish()?;
    }

    // Now read it with streaming reader
    let file = File::open("demo_read.zeta")?;
    let reader = Reader::open(file)?;
    let mut streaming = reader.into_streaming()?;

    // Read all data from first stream
    let stream_id = streaming.stream_dir().streams[0].id;
    println!("  Reading stream ID: {}", stream_id);

    // Select the stream first
    streaming.select_stream(stream_id)?;
    
    // Read the stream data
    let buffer = streaming.read_stream(stream_id)?;
    println!("  Read {} bytes: {}", buffer.len(), String::from_utf8_lossy(&buffer));

    Ok(())
}

fn demo_indexed_read() -> Result<(), Box<dyn std::error::Error>> {
    // First create a file with index
    {
        let file = File::create("demo_indexed.zeta")?;
        let mut writer = WriterBuilder::new()
            .compression(ZstdCompression)
            .with_index()
            .create(file)?;

        writer.create_stream("indexed.txt")?;
        // Write data that will create multiple chunks
        for i in 0..10 {
            writer.write_all(format!("Chunk {}: ", i).as_bytes())?;
            writer.write_all(b"This is some data for this chunk. ")?;
        }
        writer.finish()?;
    }

    // Now read with indexed reader
    let file = File::open("demo_indexed.zeta")?;
    let reader = Reader::open(file)?;
    let indexed = reader.into_indexed()?;

    // List all streams
    let stream_count = indexed.stream_dir().streams.len();
    println!("  Container has {} streams", stream_count);
    
    for stream in &indexed.stream_dir().streams {
        println!("  - Stream: {} (ID: {})", stream.name, stream.id);
    }

    Ok(())
}

fn demo_multiple_streams() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("demo_multi.zeta")?;
    let mut writer = WriterBuilder::new()
        .compression(ZstdCompression)
        .create(file)?;

    // Create first stream
    writer.create_stream("text.txt")?;
    writer.write_all(b"This is a text stream.")?;

    // Create second stream
    writer.create_stream("binary.bin")?;
    writer.write_all(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05])?;

    // Create third stream
    writer.create_stream("json.json")?;
    writer.write_all(br#"{"message": "Hello from JSON stream!"}"#)?;

    writer.finish()?;

    println!("  Created: demo_multi.zeta with 3 streams");

    // Now read it back
    let file = File::open("demo_multi.zeta")?;
    let reader = Reader::open(file)?;
    
    println!("  Streams in file:");
    for stream_name in reader.stream_names() {
        println!("    - {}", stream_name);
    }

    Ok(())
}

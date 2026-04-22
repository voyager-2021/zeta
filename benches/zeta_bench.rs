//! Benchmarks for ZETA container format.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::io::Cursor;

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");
    
    // Test data sizes
    for size in [1024, 16384, 65536, 1048576].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("none", size), size, |b, _| {
            b.iter(|| {
                let result = data.clone();
                criterion::black_box(result);
            });
        });
    }
    
    group.finish();
}

fn bench_container_creation(c: &mut Criterion) {
    c.bench_function("container_create_small", |b| {
        b.iter(|| {
            let cursor = Cursor::new(Vec::new());
            criterion::black_box(cursor);
        });
    });
}

criterion_group!(benches, bench_compression, bench_container_creation);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion};
use sha256::digest;
use sha256_rs::SHA256;

fn sha256_rs_benchmark() {
    let mut hash = SHA256::new();
    hash.update("123456".as_bytes());
    let _ = hash.digest();
}

fn sha256_benchmark() {
    let input = "123456";
    let _ = digest(input);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("sha256_rs", |b| b.iter(|| sha256_rs_benchmark()));
    c.bench_function("sha256", |b| b.iter(|| sha256_benchmark()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

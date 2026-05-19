use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use zears::Aez;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("zears");

    const KB: usize = 1024;
    let aez = Aez::new(&[0u8; 48]);

    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].into_iter() {
        let buf = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("encrypt_buffer", size), |b| {
            let mut out = vec![0u8; size + 16];
            b.iter(|| aez.encrypt_buffer(&[0], &[], &buf, &mut out))
        });

        group.bench_function(BenchmarkId::new("encrypt_inplace", size), |b| {
            let mut out = vec![0u8; size];
            b.iter(|| aez.encrypt_inplace(&[0], &[], 16, &mut out))
        });

        group.bench_function(BenchmarkId::new("aez_prf", size), |b| {
            let mut out = vec![0u8; size];
            b.iter(|| aez.encrypt_inplace(&[0], &[], size as u32, &mut out))
        });

        let buf = aez.encrypt(&[0], &[], 16, &buf);

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            b.iter(|| aez.decrypt(&[0], &[], 16, &buf).unwrap());
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

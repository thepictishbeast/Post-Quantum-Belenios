//! Criterion benchmarks for PQHV core cryptographic operations.
//!
//! Run with: `cargo bench` from the workspace root.
//!
//! ## Performance Targets
//!
//! | Operation              | Target    |
//! |------------------------|-----------|
//! | Key generation         | < 1 sec   |
//! | Single encryption      | < 500 ms  |
//! | Single decryption      | < 100 ms  |
//! | Ciphertext addition    | < 1 ms    |
//! | Tally 10,000 votes     | < 30 sec  |

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use pqhv_core::{
    decrypt::{decrypt, decrypt_tally},
    encrypt::{add_ciphertexts, encrypt, sum_ciphertexts},
    keygen::keygen,
    params::{PQHV_TEST, PQHV_VOTING_128},
    poly::Poly,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    group.bench_function("test_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        b.iter(|| {
            let (pk, sk) = keygen(black_box(&PQHV_TEST), &mut rng);
            black_box((pk, sk));
        });
    });

    group.bench_function("voting_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        b.iter(|| {
            let (pk, sk) = keygen(black_box(&PQHV_VOTING_128), &mut rng);
            black_box((pk, sk));
        });
    });

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    group.bench_function("test_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _) = keygen(&PQHV_TEST, &mut rng);
        b.iter(|| {
            let ct = encrypt(black_box(&pk), 1, &PQHV_TEST, &mut rng);
            black_box(ct);
        });
    });

    group.bench_function("voting_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _) = keygen(&PQHV_VOTING_128, &mut rng);
        b.iter(|| {
            let ct = encrypt(black_box(&pk), 1, &PQHV_VOTING_128, &mut rng);
            black_box(ct);
        });
    });

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    group.bench_function("test_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        b.iter(|| {
            let m = decrypt(black_box(&sk), black_box(&ct), &PQHV_TEST);
            black_box(m);
        });
    });

    group.bench_function("voting_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_VOTING_128, &mut rng);
        b.iter(|| {
            let m = decrypt(black_box(&sk), black_box(&ct), &PQHV_VOTING_128);
            black_box(m);
        });
    });

    group.finish();
}

fn bench_ciphertext_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("ciphertext_add");

    group.bench_function("test_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _) = keygen(&PQHV_TEST, &mut rng);
        let ct1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct2 = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        b.iter(|| {
            let sum = add_ciphertexts(black_box(&ct1), black_box(&ct2));
            black_box(sum);
        });
    });

    group.bench_function("voting_params", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _) = keygen(&PQHV_VOTING_128, &mut rng);
        let ct1 = encrypt(&pk, 1, &PQHV_VOTING_128, &mut rng);
        let ct2 = encrypt(&pk, 0, &PQHV_VOTING_128, &mut rng);
        b.iter(|| {
            let sum = add_ciphertexts(black_box(&ct1), black_box(&ct2));
            black_box(sum);
        });
    });

    group.finish();
}

fn bench_poly_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_mul");

    group.bench_function("test_params_n64", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let p = Poly::new_random(&PQHV_TEST, &mut rng);
        b.iter(|| {
            let r = black_box(&a).mul(black_box(&p));
            black_box(r);
        });
    });

    group.bench_function("voting_params_n256", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let a = Poly::new_random(&PQHV_VOTING_128, &mut rng);
        let p = Poly::new_random(&PQHV_VOTING_128, &mut rng);
        b.iter(|| {
            let r = black_box(&a).mul(black_box(&p));
            black_box(r);
        });
    });

    group.finish();
}

fn bench_tally(c: &mut Criterion) {
    let mut group = c.benchmark_group("tally");
    group.sample_size(10); // Reduce sample size for slow benchmarks

    for &count in &[100u64, 1000] {
        group.bench_with_input(
            BenchmarkId::new("test_params", count),
            &count,
            |b, &count| {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
                let cts: Vec<_> = (0..count)
                    .map(|i| encrypt(&pk, (i % 2) as u8, &PQHV_TEST, &mut rng))
                    .collect();
                b.iter(|| {
                    let tally = sum_ciphertexts(black_box(&cts));
                    let result = decrypt_tally(&sk, &tally, &PQHV_TEST);
                    black_box(result);
                });
            },
        );
    }

    // Only benchmark small tallies with voting params (they're slow with schoolbook mul)
    group.bench_with_input(
        BenchmarkId::new("voting_params", 100),
        &100u64,
        |b, &count| {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);
            let cts: Vec<_> = (0..count)
                .map(|i| encrypt(&pk, (i % 2) as u8, &PQHV_VOTING_128, &mut rng))
                .collect();
            b.iter(|| {
                let tally = sum_ciphertexts(black_box(&cts));
                let result = decrypt_tally(&sk, &tally, &PQHV_VOTING_128);
                black_box(result);
            });
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encrypt,
    bench_decrypt,
    bench_ciphertext_add,
    bench_poly_mul,
    bench_tally,
);
criterion_main!(benches);

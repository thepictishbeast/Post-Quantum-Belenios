//! # Number Theoretic Transform (NTT)
//!
//! Placeholder for NTT-based polynomial multiplication optimization.
//! The current implementation uses schoolbook O(n²) multiplication in `poly.rs`.
//! NTT will bring this to O(n log n), which is critical for production performance.
//!
//! ## Requirements for NTT
//!
//! - q must be a prime such that q ≡ 1 (mod 2n) to have primitive 2n-th roots of unity
//! - The current voting parameter set uses q = 2^23 = 8,388,608, which is NOT prime.
//!   NTT requires either switching to a prime q or using a different transform strategy.
//! - For the test parameter set, q = 12,289 IS prime and 12,289 ≡ 1 (mod 128), so
//!   NTT works for n ≤ 64.
//!
//! ## Future Work
//!
//! Options for NTT compatibility:
//! 1. Switch to a prime q (e.g., Kyber uses q = 3329)
//! 2. Use CRT (Chinese Remainder Theorem) with multiple small NTT-friendly primes
//! 3. Use a different fast multiplication strategy (e.g., Karatsuba or Toom-Cook)

// TODO: Implement NTT for O(n log n) polynomial multiplication.
// This is the primary performance bottleneck — schoolbook multiplication is O(n²)
// which dominates keygen, encryption, and decryption time.

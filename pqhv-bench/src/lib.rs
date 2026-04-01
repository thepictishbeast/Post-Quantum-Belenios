//! # pqhv-bench — Performance Benchmarks for PQHV
//!
//! Criterion benchmarks for all PQHV cryptographic operations.
//! Run with `cargo bench` from the workspace root.
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

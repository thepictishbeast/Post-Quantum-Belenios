//! # pqhv-core — Post-Quantum Homomorphic Voting Core
//!
//! Implements an additively homomorphic Module-LWE encryption scheme designed
//! for verifiable electronic voting. This crate provides the cryptographic
//! foundation for the PQHV project, which replaces the classical ElGamal-based
//! cryptography in Belenios with lattice-based primitives resistant to quantum
//! computers.
//!
//! ## Key Features
//!
//! - **Post-quantum security**: Based on the Module-LWE problem (NIST Level 3)
//! - **Additive homomorphism**: Sum encrypted votes without decrypting
//! - **Noise tracking**: Monitor noise budget to prevent silent decryption failures
//! - **Secure erasure**: Secret keys implement `Zeroize` for memory safety
//!
//! ## Usage
//!
//! ```rust
//! use pqhv_core::{params::PQHV_TEST, keygen::keygen, encrypt::encrypt, decrypt::decrypt};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::from_entropy();
//! let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
//!
//! let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
//! assert_eq!(decrypt(&sk, &ct, &PQHV_TEST), 1);
//! ```
//!
//! ## Homomorphic Vote Tallying
//!
//! ```rust
//! use pqhv_core::{
//!     params::PQHV_TEST, keygen::keygen,
//!     encrypt::{encrypt, sum_ciphertexts},
//!     decrypt::decrypt_tally,
//! };
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::from_entropy();
//! let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
//!
//! // Encrypt 5 yes-votes and 3 no-votes
//! let votes = [1, 1, 0, 1, 0, 1, 0, 1];
//! let ciphertexts: Vec<_> = votes.iter()
//!     .map(|&v| encrypt(&pk, v, &PQHV_TEST, &mut rng))
//!     .collect();
//!
//! let tally = sum_ciphertexts(&ciphertexts);
//! assert_eq!(decrypt_tally(&sk, &tally, &PQHV_TEST), 5);
//! ```

#![forbid(unsafe_code)]

pub mod params;
pub mod sample;
pub mod poly;
pub mod matrix;
pub mod ntt;
pub mod noise;
pub mod keygen;
pub mod encrypt;
pub mod decrypt;
pub mod serialize;

// Re-export key types for convenience
pub use params::{PqhvParams, PQHV_VOTING_128, PQHV_TEST};
pub use keygen::{PublicKey, SecretKey, keygen};
pub use encrypt::{Ciphertext, encrypt, add_ciphertexts, sum_ciphertexts};
pub use decrypt::{decrypt, decrypt_tally};

//! # pqhv-zkp — Zero-Knowledge Proofs for Post-Quantum Voting
//!
//! Implements lattice-based zero-knowledge proofs for ballot validity in the
//! PQHV homomorphic voting system. These proofs convince a verifier that an
//! encrypted ballot encodes a valid choice (0 or 1) without revealing which.
//!
//! ## Approach
//!
//! The core proof is a **ballot range proof** using a commit-then-open
//! protocol with Fiat-Shamir heuristic for non-interactivity:
//!
//! 1. Prover demonstrates knowledge of the encryption randomness (r, e₁, e₂)
//!    and message m ∈ {0, 1} that were used to create the ciphertext.
//! 2. The proof uses a disjunctive technique: prove that EITHER m=0 OR m=1,
//!    without revealing which. One branch is real, one is simulated.
//! 3. Challenge is derived via Fiat-Shamir hash of the ciphertext + commitments.
//!
//! ## Security
//!
//! - Soundness: A cheating prover cannot produce a valid proof for m ∉ {0,1}
//!   except with negligible probability.
//! - Zero-knowledge: The proof reveals nothing about m beyond m ∈ {0,1}.
//! - Post-quantum: Based on the hardness of Module-LWE (same assumption as
//!   the encryption scheme).
//!
//! ## Usage
//!
//! ```rust
//! use pqhv_core::{params::PQHV_TEST, keygen::keygen};
//! use pqhv_zkp::{encrypt_and_prove, verify_ballot_proof};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::from_entropy();
//! let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
//!
//! // Encrypt a vote of 1 with a validity proof
//! let ballot = encrypt_and_prove(&pk, 1, &PQHV_TEST, &mut rng);
//!
//! // Anyone can verify the ballot is valid (encodes 0 or 1)
//! assert!(verify_ballot_proof(&pk, &ballot.ciphertext, &ballot.proof, &PQHV_TEST));
//! ```

#![forbid(unsafe_code)]

pub mod challenge;
pub mod disjunctive;
pub mod ballot;

pub use ballot::{BallotProof, EncryptedBallot, encrypt_and_prove, prove_ballot_valid, verify_ballot_proof};

//! # pqhv-threshold — Lattice-Based Threshold Decryption
//!
//! Implements threshold decryption for the PQHV scheme, enabling t-of-n
//! distributed election tallying where no single trustee can decrypt votes alone.
//! This replaces Belenios's Pedersen DKG and Shamir secret sharing over
//! discrete-log groups with a lattice-based equivalent that is resistant to
//! quantum computers.
//!
//! ## How It Works
//!
//! 1. **Key Generation**: A dealer generates the election key pair, then splits
//!    the secret key into N shares using Shamir's Secret Sharing over a prime
//!    field Z_p (where p > q). Each trustee receives one share.
//!
//! 2. **Voting**: Voters encrypt their ballots using the single public key
//!    (unchanged from non-threshold PQHV). Ballots are homomorphically summed.
//!
//! 3. **Partial Decryption**: Each participating trustee applies their key share
//!    to the tally ciphertext, producing a partial decryption — a polynomial that
//!    reveals nothing about the plaintext on its own.
//!
//! 4. **Combination**: Any T partial decryptions are combined using Lagrange
//!    interpolation over Z_p to compute combination coefficients, which are then
//!    applied mod q to recover the full decryption and yield the plaintext tally.
//!
//! ## Prime Field for Sharing
//!
//! PQHV uses q = 2^k (power-of-2 modulus, not prime). Shamir's scheme requires
//! Lagrange interpolation with modular inverses of (x_i - x_j), which may not
//! exist in Z_{2^k}. We solve this by performing all Shamir operations (sharing
//! and Lagrange coefficient computation) over the Mersenne prime p = 2^61 - 1,
//! then reducing results mod q. This is the standard technique used in lattice-
//! based threshold cryptography.
//!
//! ## Security Properties
//!
//! - **Threshold security**: Fewer than T trustees learn nothing about the
//!   plaintext (information-theoretic for Shamir's scheme over Z_p).
//! - **Post-quantum**: Based on Module-LWE hardness, same as the base scheme.
//! - **Noise budget**: Threshold decryption does not increase the noise beyond
//!   what single-trustee decryption would produce, because Lagrange coefficients
//!   are applied as scalars to the partial decryption polynomials.
//!
//! ## Usage
//!
//! ```rust
//! use pqhv_core::{params::PQHV_TEST, encrypt::encrypt};
//! use pqhv_threshold::{
//!     ThresholdParams,
//!     generate_threshold_keys,
//!     partial_decrypt,
//!     combine_partial_decryptions,
//! };
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::from_entropy();
//! // Additive sharing: all 3 trustees must participate (t == n)
//! let threshold = ThresholdParams::new(3, 3).unwrap();
//! let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
//!
//! // Encrypt a vote
//! let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
//!
//! // All trustees produce partial decryptions
//! let partials: Vec<_> = shares.iter()
//!     .map(|share| partial_decrypt(share, &ct))
//!     .collect();
//!
//! // Combine to recover the tally
//! let tally = combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST);
//! assert_eq!(tally.unwrap(), 1);
//! ```
//!
//! ## Limitations
//!
//! This implementation uses a trusted dealer model: a single entity generates
//! the full secret key and distributes shares. A future version will implement
//! distributed key generation (DKG) where no single party ever sees the full
//! secret key. The dealer model is appropriate for a first deployment where the
//! election authority is trusted during setup but not during tallying.

pub mod threshold;
pub mod error;

pub use threshold::{
    ThresholdParams,
    TrusteeKeyShare,
    PartialDecryption,
    generate_threshold_keys,
    partial_decrypt,
    combine_partial_decryptions,
};
pub use error::ThresholdError;

//! # Module-LWE Key Generation
//!
//! Generates public/secret key pairs for the PQHV encryption scheme.
//!
//! ## Key Structure
//!
//! - **Secret key**: A vector `s` of `k` polynomials with small (CBD-sampled) coefficients.
//! - **Public key**: A random matrix `A` (k×k over R_q) and a vector `b = A·s + e`,
//!   where `e` is a noise vector with small coefficients.
//!
//! ## Security
//!
//! The security of Module-LWE relies on the hardness of distinguishing `(A, A·s + e)`
//! from `(A, u)` where `u` is uniform random. Given only `(A, b)`, recovering `s`
//! requires solving the Module-LWE problem, which is believed to be hard even for
//! quantum computers.

use crate::matrix::{PolyMatrix, PolyVec};
use crate::params::PqhvParams;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Public key for the PQHV encryption scheme.
///
/// Contains the information needed to encrypt messages: the random matrix `A`
/// and the derived vector `b = A·s + e`.
///
/// In a real deployment, `A` would be generated deterministically from a seed
/// for compression. We store it explicitly for clarity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Random k×k matrix over R_q. Shared across all encryptions.
    pub a: PolyMatrix,
    /// Derived vector: b = A·s + e. Together with A, defines the public key.
    pub b: PolyVec,
}

/// Secret key for the PQHV encryption scheme.
///
/// Contains the secret vector `s` with small (CBD-sampled) coefficients.
/// Must be kept confidential — knowledge of `s` allows decryption.
///
/// Implements `Zeroize` for secure memory erasure when dropped.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    /// Secret vector with small coefficients (sampled from CBD(eta)).
    pub s: PolyVec,
}

/// Manual Zeroize implementation for SecretKey.
/// Overwrites all polynomial coefficients with zeros when the key is dropped
/// or explicitly zeroized, preventing secret key material from lingering in memory.
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        for poly in &mut self.s.polys {
            for coeff in &mut poly.coeffs {
                *coeff = 0;
            }
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generate a fresh public/secret key pair.
///
/// # Algorithm
///
/// 1. Sample a random k×k matrix `A` uniformly over R_q
/// 2. Sample secret vector `s` from CBD(eta) — small coefficients
/// 3. Sample noise vector `e` from CBD(eta) — small coefficients
/// 4. Compute `b = A·s + e`
/// 5. Return `(pk = {A, b}, sk = {s})`
///
/// # Arguments
///
/// * `params` — The parameter set (determines dimensions and noise level).
/// * `rng` — A cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple `(PublicKey, SecretKey)`.
///
/// # Security Properties
///
/// - The public key `(A, b)` is computationally indistinguishable from
///   `(A, u)` where `u` is uniform random, assuming Module-LWE hardness.
/// - The secret key `s` has small coefficients (in [-eta, eta]).
/// - The noise `e` ensures that `b` does not reveal `s` exactly.
pub fn keygen(params: &PqhvParams, rng: &mut impl RngCore) -> (PublicKey, SecretKey) {
    // Step 1: Random public matrix
    let a = PolyMatrix::new_random(params, rng);

    // Step 2: Secret vector with small coefficients
    let s = PolyVec::sample_cbd(params, params.eta, rng);

    // Step 3: Noise vector with small coefficients
    let e = PolyVec::sample_cbd(params, params.eta, rng);

    // Step 4: b = A·s + e
    let b = a.mul_vec(&s).add(&e);

    let pk = PublicKey { a, b };
    let sk = SecretKey { s };

    (pk, sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{PQHV_TEST, PQHV_VOTING_128};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn test_keygen_dimensions_test_params() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

        // Public key matrix: k×k
        assert_eq!(pk.a.k, 2);
        assert_eq!(pk.a.rows.len(), 2);
        for row in &pk.a.rows {
            assert_eq!(row.polys.len(), 2);
            for p in &row.polys {
                assert_eq!(p.coeffs.len(), 64);
            }
        }

        // Public key vector b: k polynomials
        assert_eq!(pk.b.k, 2);
        assert_eq!(pk.b.polys.len(), 2);

        // Secret key vector s: k polynomials
        assert_eq!(sk.s.k, 2);
        assert_eq!(sk.s.polys.len(), 2);
    }

    #[test]
    fn test_keygen_dimensions_voting_params() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);

        assert_eq!(pk.a.k, 3);
        assert_eq!(pk.b.k, 3);
        assert_eq!(sk.s.k, 3);
        for p in &sk.s.polys {
            assert_eq!(p.coeffs.len(), 256);
        }
    }

    #[test]
    fn test_keygen_deterministic_with_same_seed() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(99);
        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let (pk1, sk1) = keygen(&PQHV_TEST, &mut rng1);
        let (pk2, sk2) = keygen(&PQHV_TEST, &mut rng2);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1.s, sk2.s);
    }

    #[test]
    fn test_keygen_different_seeds_different_keys() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(1);
        let mut rng2 = ChaCha20Rng::seed_from_u64(2);
        let (pk1, _) = keygen(&PQHV_TEST, &mut rng1);
        let (pk2, _) = keygen(&PQHV_TEST, &mut rng2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_secret_key_has_small_coefficients() {
        let mut rng = test_rng();
        let (_, sk) = keygen(&PQHV_TEST, &mut rng);
        let eta = PQHV_TEST.eta as i64;
        let q = PQHV_TEST.q as i64;
        for p in &sk.s.polys {
            for &c in &p.coeffs {
                // Coefficients are in [0, q) representation
                // CBD values in [-eta, eta] map to {0, 1, 2, q-2, q-1} for eta=2
                let centered = if c > q / 2 { c - q } else { c };
                assert!(
                    centered.abs() <= eta,
                    "Secret coefficient {} (centered {}) exceeds eta={}",
                    c,
                    centered,
                    eta
                );
            }
        }
    }

    #[test]
    fn test_secret_key_zeroize() {
        let mut rng = test_rng();
        let (_, mut sk) = keygen(&PQHV_TEST, &mut rng);

        // Verify key has non-zero data
        let has_nonzero = sk.s.polys.iter().any(|p| p.coeffs.iter().any(|&c| c != 0));
        assert!(has_nonzero, "Secret key should have non-zero coefficients");

        // Zeroize
        sk.zeroize();

        // Verify all coefficients are zero
        for p in &sk.s.polys {
            for &c in &p.coeffs {
                assert_eq!(c, 0, "Coefficient should be zero after zeroize");
            }
        }
    }
}

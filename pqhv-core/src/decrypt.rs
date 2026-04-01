//! # Module-LWE Decryption
//!
//! Recovers the plaintext message from a ciphertext using the secret key.
//!
//! ## Algorithm
//!
//! Given ciphertext (u, v) and secret key s:
//!
//! 1. Compute `noisy_message = v - sᵀ·u`
//! 2. The constant term of `noisy_message` is approximately `⌊q/2⌋·m + noise`
//! 3. Round the constant term: if |centered value| > q/4, message is 1; else 0
//!
//! ## Correctness
//!
//! Why this works:
//!
//! ```text
//! v - sᵀu = (bᵀr + e₂ + ⌊q/2⌋m) - sᵀ(Aᵀr + e₁)
//!          = (Asᵀ + e)ᵀr + e₂ + ⌊q/2⌋m - sᵀAᵀr - sᵀe₁
//!          = sᵀAᵀr + eᵀr + e₂ + ⌊q/2⌋m - sᵀAᵀr - sᵀe₁
//!          = ⌊q/2⌋m + eᵀr + e₂ - sᵀe₁
//!          = ⌊q/2⌋m + (small noise terms)
//! ```
//!
//! The noise `eᵀr + e₂ - sᵀe₁` is small because e, r, e₁, e₂, and s all
//! have small coefficients (from CBD sampling). As long as this noise stays
//! below q/4, rounding recovers the correct message.

use crate::keygen::SecretKey;
use crate::encrypt::Ciphertext;
use crate::params::PqhvParams;
use crate::poly::Poly;

/// Decrypt a ciphertext to recover the original message bit.
///
/// # Arguments
///
/// * `sk` — The secret key.
/// * `ct` — The ciphertext to decrypt.
/// * `_params` — The parameter set (used for validation, reserved for future use).
///
/// # Returns
///
/// The decrypted message bit (0 or 1).
///
/// # Correctness
///
/// Returns the correct message if the accumulated noise in the ciphertext
/// is below q/4. For a fresh ciphertext (no homomorphic additions), this
/// is always satisfied. After many additions, the noise may exceed the
/// threshold, causing incorrect decryption.
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext, params: &PqhvParams) -> u8 {
    // Compute: noisy_message = v - sᵀ·u
    let s_dot_u = sk.s.inner_product(&ct.u);
    let mut noisy_message = ct.v.sub(&s_dot_u);
    noisy_message.reduce();

    // Decode the constant term to a message bit
    noisy_message.to_message(params)
}

/// Decrypt a ciphertext that represents a homomorphic tally (sum of encrypted bits).
///
/// After summing N ciphertexts that each encrypt 0 or 1, the result encrypts
/// the count of 1-votes. This function recovers that count.
///
/// # Arguments
///
/// * `sk` — The secret key.
/// * `ct` — The ciphertext (typically the result of `sum_ciphertexts`).
/// * `_params` — The parameter set.
///
/// # Returns
///
/// The decrypted vote count.
///
/// # Correctness
///
/// The count is correct if the accumulated noise (proportional to the number
/// of additions) stays below q/4. Use `NoiseTracker` to verify this before
/// calling decrypt.
pub fn decrypt_tally(sk: &SecretKey, ct: &Ciphertext, params: &PqhvParams) -> u64 {
    // Compute: noisy_message = v - sᵀ·u
    let s_dot_u = sk.s.inner_product(&ct.u);
    let mut noisy_message = ct.v.sub(&s_dot_u);
    noisy_message.reduce();

    // Decode the constant term as a tally count
    noisy_message.to_tally(params)
}

/// Decrypt a ciphertext and return the raw noisy polynomial.
///
/// This is useful for debugging and noise analysis. The returned polynomial
/// contains `⌊q/2⌋·m + noise` in the constant term (and noise in all other terms).
///
/// # Returns
///
/// The raw decrypted polynomial before message decoding.
pub fn decrypt_raw(sk: &SecretKey, ct: &Ciphertext) -> Poly {
    let s_dot_u = sk.s.inner_product(&ct.u);
    let mut result = ct.v.sub(&s_dot_u);
    result.reduce();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{encrypt, add_ciphertexts, sum_ciphertexts};
    use crate::keygen::keygen;
    use crate::params::{PQHV_TEST, PQHV_VOTING_128};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn test_decrypt_zero() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
        let ct = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        assert_eq!(decrypt(&sk, &ct, &PQHV_TEST), 0);
    }

    #[test]
    fn test_decrypt_one() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        assert_eq!(decrypt(&sk, &ct, &PQHV_TEST), 1);
    }

    #[test]
    fn test_decrypt_multiple_zero_and_one() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

        for _ in 0..20 {
            let ct0 = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
            let ct1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
            assert_eq!(decrypt(&sk, &ct0, &PQHV_TEST), 0);
            assert_eq!(decrypt(&sk, &ct1, &PQHV_TEST), 1);
        }
    }

    #[test]
    fn test_homomorphic_add_two() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

        let ct0 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let sum = add_ciphertexts(&ct0, &ct1);

        // Should decrypt to 2 (two votes for "yes")
        assert_eq!(decrypt_tally(&sk, &sum, &PQHV_TEST), 2);
    }

    #[test]
    fn test_homomorphic_tally_10_votes() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

        // 7 yes votes, 3 no votes
        let votes = [1, 0, 1, 1, 0, 1, 1, 1, 0, 1];
        let expected: u64 = votes.iter().sum::<u8>() as u64;

        let ciphertexts: Vec<Ciphertext> = votes
            .iter()
            .map(|&v| encrypt(&pk, v, &PQHV_TEST, &mut rng))
            .collect();

        let tally_ct = sum_ciphertexts(&ciphertexts);
        let result = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);

        assert_eq!(result, expected, "Tally {} != expected {}", result, expected);
    }

    #[test]
    fn test_homomorphic_tally_100_votes() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

        let mut yes_count: u64 = 0;
        let mut ciphertexts = Vec::new();
        for i in 0..100 {
            let vote = if i % 3 == 0 { 1u8 } else { 0u8 };
            yes_count += vote as u64;
            ciphertexts.push(encrypt(&pk, vote, &PQHV_TEST, &mut rng));
        }

        let tally_ct = sum_ciphertexts(&ciphertexts);
        let result = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);

        assert_eq!(
            result, yes_count,
            "100-vote tally {} != expected {}",
            result, yes_count
        );
    }

    #[test]
    fn test_homomorphic_tally_1000_votes_voting_params() {
        // Use the full voting parameter set for a realistic-scale test
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);

        let mut yes_count: u64 = 0;
        let mut ciphertexts = Vec::new();
        for i in 0..1000 {
            let vote = if i % 2 == 0 { 1u8 } else { 0u8 };
            yes_count += vote as u64;
            ciphertexts.push(encrypt(&pk, vote, &PQHV_VOTING_128, &mut rng));
        }

        let tally_ct = sum_ciphertexts(&ciphertexts);
        let result = decrypt_tally(&sk, &tally_ct, &PQHV_VOTING_128);

        assert_eq!(
            result, yes_count,
            "1000-vote tally {} != expected {}",
            result, yes_count
        );
    }

    #[test]
    fn test_decrypt_raw_noise_is_small() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
        let ct = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        let raw = decrypt_raw(&sk, &ct);

        // For a fresh encryption of 0, the constant term should be small noise
        let q = PQHV_TEST.q as i64;
        let centered = if raw.coeffs[0] > q / 2 {
            raw.coeffs[0] - q
        } else {
            raw.coeffs[0]
        };
        assert!(
            centered.abs() < q / 4,
            "Noise {} exceeds q/4 = {}",
            centered,
            q / 4
        );
    }

    #[test]
    fn test_wrong_key_decrypts_incorrectly() {
        let mut rng = test_rng();
        let (pk1, _sk1) = keygen(&PQHV_TEST, &mut rng);
        let (_pk2, sk2) = keygen(&PQHV_TEST, &mut rng);

        // Encrypt with pk1, try to decrypt with sk2
        // (May or may not produce the correct result — the point is
        // it's not reliably correct)
        let mut wrong_count = 0;
        for _ in 0..50 {
            let ct = encrypt(&pk1, 1, &PQHV_TEST, &mut rng);
            if decrypt(&sk2, &ct, &PQHV_TEST) != 1 {
                wrong_count += 1;
            }
        }
        // With the wrong key, at least some decryptions should fail
        assert!(
            wrong_count > 0,
            "All 50 decryptions with wrong key succeeded — statistically improbable"
        );
    }
}

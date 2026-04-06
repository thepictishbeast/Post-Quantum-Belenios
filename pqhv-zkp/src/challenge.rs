//! Fiat-Shamir challenge generation.
//!
//! Derives deterministic challenges from transcripts using SHA-256.
//! The challenge is a small polynomial with ternary coefficients
//! ({-1, 0, 1}) and a fixed Hamming weight.

use pqhv_core::params::PqhvParams;
use pqhv_core::poly::Poly;
use sha2::{Digest, Sha256};

/// Number of non-zero coefficients in a challenge polynomial.
/// Higher weight = stronger soundness but larger proof overhead.
const CHALLENGE_WEIGHT: usize = 32;

/// Generate a challenge polynomial from a transcript hash.
///
/// The challenge has exactly `CHALLENGE_WEIGHT` non-zero coefficients,
/// each ±1, determined by the hash. This keeps the challenge "small"
/// so that proof responses don't grow too large.
pub fn challenge_from_hash(hash: &[u8; 32], params: &PqhvParams) -> Poly {
    let mut coeffs = vec![0i64; params.n];
    let mut idx = 0;
    let mut placed = 0;

    // Use successive bytes of hash (extended via re-hashing) to place coefficients
    let mut current_hash = *hash;
    while placed < CHALLENGE_WEIGHT && placed < params.n {
        // Derive position from hash bytes
        let pos = (u16::from_le_bytes([
            current_hash[idx % 32],
            current_hash[(idx + 1) % 32],
        ]) as usize)
            % params.n;

        if coeffs[pos] == 0 {
            // Sign from the next byte
            let sign_byte = current_hash[(idx + 2) % 32];
            coeffs[pos] = if sign_byte & 1 == 0 { 1 } else { -1 };
            placed += 1;
        }

        idx += 3;
        if idx >= 30 {
            // Re-hash to get more entropy
            let mut hasher = Sha256::new();
            hasher.update(current_hash);
            hasher.update(placed.to_le_bytes());
            current_hash = hasher.finalize().into();
            idx = 0;
        }
    }

    Poly { coeffs, n: params.n, q: params.q }
}

/// Compute the Fiat-Shamir transcript hash for a ballot proof.
///
/// Includes: public key hash, ciphertext, and commitment polynomials.
/// This binds the challenge to the specific proof context, preventing
/// proof reuse across different elections or ciphertexts.
pub fn transcript_hash(data: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in data {
        // Length-prefix each field to prevent concatenation ambiguity
        hasher.update((chunk.len() as u64).to_le_bytes());
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhv_core::params::PQHV_TEST;

    #[test]
    fn challenge_has_correct_weight() {
        let hash = [0xABu8; 32];
        let c = challenge_from_hash(&hash, &PQHV_TEST);
        let weight: usize = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(weight, CHALLENGE_WEIGHT.min(PQHV_TEST.n));
    }

    #[test]
    fn challenge_is_ternary() {
        let hash = [0x42u8; 32];
        let c = challenge_from_hash(&hash, &PQHV_TEST);
        for &coeff in &c.coeffs {
            assert!((-1..=1).contains(&coeff), "Non-ternary coefficient: {}", coeff);
        }
    }

    #[test]
    fn challenge_is_deterministic() {
        let hash = [0x13u8; 32];
        let c1 = challenge_from_hash(&hash, &PQHV_TEST);
        let c2 = challenge_from_hash(&hash, &PQHV_TEST);
        assert_eq!(c1.coeffs, c2.coeffs);
    }

    #[test]
    fn different_hashes_give_different_challenges() {
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        let c1 = challenge_from_hash(&h1, &PQHV_TEST);
        let c2 = challenge_from_hash(&h2, &PQHV_TEST);
        assert_ne!(c1.coeffs, c2.coeffs);
    }

    #[test]
    fn transcript_hash_is_deterministic() {
        let data = [b"hello" as &[u8], b"world"];
        let h1 = transcript_hash(&data);
        let h2 = transcript_hash(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn transcript_hash_order_matters() {
        let h1 = transcript_hash(&[b"hello", b"world"]);
        let h2 = transcript_hash(&[b"world", b"hello"]);
        assert_ne!(h1, h2);
    }
}

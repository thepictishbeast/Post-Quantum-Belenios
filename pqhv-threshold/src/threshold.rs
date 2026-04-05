//! # Threshold Key Generation and Partial Decryption
//!
//! Implements additive secret sharing over the polynomial ring R_q = Z_q[X]/(X^n+1)
//! for lattice-based threshold decryption.
//!
//! ## Mathematical Foundation
//!
//! The secret key s (a PolyVec in R_q^k) is split into n additive shares:
//!   s = s_1 + s_2 + ... + s_n (mod q)
//!
//! where s_1, ..., s_{n-1} are uniformly random in R_q^k and s_n is the
//! "correction" share: s_n = s - sum(s_1..s_{n-1}) mod q.
//!
//! ## Why Additive Sharing (Not Shamir)
//!
//! PQHV uses q = 2^k (power-of-2 modulus) for efficient NTT and noise
//! management. Shamir's Secret Sharing requires Lagrange interpolation,
//! which needs modular inverses of (x_i - x_j) for all pairs of evaluation
//! points. For q = 2^k, differences between integer evaluation points are
//! often even, making them non-invertible mod 2^k. This is a fundamental
//! algebraic obstruction, not a coding issue.
//!
//! Additive sharing avoids Lagrange entirely: reconstruction is simple
//! addition mod q. The tradeoff is that ALL n trustees must participate
//! (it is an (n,n)-scheme rather than a (t,n)-scheme).
//!
//! ## Upgrade Path to (t,n)-Threshold
//!
//! To support t-of-n threshold (where t < n), the modulus q must be changed
//! to a prime in a future pqhv-core version. Many post-quantum schemes
//! (Kyber, Dilithium) use prime q for exactly this reason. Once q is prime,
//! Shamir sharing works directly and this module can be upgraded in place.
//!
//! ## Partial Decryption
//!
//! Normal decryption computes `v - s^T * u`. In threshold mode, each trustee i
//! computes their "partial inner product" `d_i = s_i^T * u` (where s_i is their
//! share). The combiner sums all partial products:
//!   s^T * u = d_1 + d_2 + ... + d_n (mod q)
//! then completes the decryption as `v - combined`.
//!
//! ## Noise Analysis
//!
//! Additive combination operates on the partial decryptions (polynomials in R_q),
//! not on the ciphertext. The final combined result `sum(d_i)` equals `s^T * u`
//! exactly (no additional noise), so the noise budget is identical to single-trustee
//! decryption.

use crate::error::ThresholdError;
use pqhv_core::encrypt::Ciphertext;
use pqhv_core::keygen::PublicKey;
use pqhv_core::matrix::PolyVec;
use pqhv_core::params::PqhvParams;
use pqhv_core::poly::Poly;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Parameters for threshold decryption.
///
/// Defines the total number of trustees (n). In this additive sharing scheme,
/// ALL n trustees must participate to decrypt (i.e., t = n implicitly).
///
/// # Invariants
///
/// - `n >= 1`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Minimum number of trustees required to decrypt.
    /// Currently must equal n (additive sharing).
    pub t: usize,
    /// Total number of trustees.
    pub n: usize,
}

impl ThresholdParams {
    /// Create a new threshold parameter set.
    ///
    /// # Arguments
    ///
    /// * `t` — The threshold (must equal `n` for additive sharing).
    /// * `n` — The total number of trustees.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `t == 0` or `n == 0`
    /// - `t > n`
    /// - `t != n` (additive sharing requires all trustees)
    ///
    /// # Examples
    ///
    /// ```
    /// use pqhv_threshold::ThresholdParams;
    ///
    /// let params = ThresholdParams::new(3, 3).unwrap();
    /// assert_eq!(params.t, 3);
    /// assert_eq!(params.n, 3);
    ///
    /// // t != n is rejected (additive sharing requires all trustees)
    /// assert!(ThresholdParams::new(2, 3).is_err());
    /// ```
    pub fn new(t: usize, n: usize) -> Result<Self, ThresholdError> {
        if n == 0 {
            return Err(ThresholdError::NoTrustees);
        }
        if t == 0 {
            return Err(ThresholdError::ThresholdTooSmall { t: 0 });
        }
        if t > n {
            return Err(ThresholdError::ThresholdExceedsTrustees { t, n });
        }
        if t != n {
            return Err(ThresholdError::ThresholdNotSupported { t, n });
        }
        Ok(ThresholdParams { t, n })
    }
}

/// A trustee's share of the secret key.
///
/// Each share is a PolyVec of k polynomials in R_q^k, the same structure as
/// a full secret key. The sum of all n shares equals the original secret key
/// mod q.
///
/// # Security
///
/// A single share reveals nothing about the original secret key (information-
/// theoretic security). Only when ALL n shares are combined can the secret —
/// or any function of it — be recovered. Any n-1 shares are statistically
/// independent of the secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrusteeKeyShare {
    /// The trustee's 1-based index. Valid range: [1, n].
    pub index: usize,
    /// The trustee's additive share of the secret key vector.
    pub share: PolyVec,
}

/// A partial decryption produced by a single trustee.
///
/// Contains the trustee's contribution to the decryption: `d_i = s_i^T * u`,
/// where s_i is the trustee's key share and u is the ciphertext's first component.
///
/// # Security
///
/// A partial decryption reveals `s_i^T * u` but not `s_i` itself (recovering
/// s_i from this would require solving Module-LWE). Moreover, fewer than n
/// partial decryptions are insufficient to recover the full `s^T * u` needed
/// for decryption (by the security of additive secret sharing).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// The trustee's 1-based index (must match the share used to produce this).
    pub index: usize,
    /// The partial inner product: s_i^T * u.
    pub value: Poly,
}

/// Generate a threshold key set: one public key and n trustee key shares.
///
/// Uses additive secret sharing: the full secret key is generated, then split
/// into n shares such that s_1 + s_2 + ... + s_n = s (mod q).
///
/// # Algorithm
///
/// 1. Generate a normal key pair (pk, sk) via the base PQHV keygen.
/// 2. For i = 1, ..., n-1: sample s_i uniformly random from R_q^k.
/// 3. Set s_n = s - (s_1 + s_2 + ... + s_{n-1}) mod q.
///
/// # Arguments
///
/// * `params` — The PQHV lattice parameters.
/// * `threshold` — The threshold parameters (t = n).
/// * `rng` — A cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple `(PublicKey, Vec<TrusteeKeyShare>)` where the public key is used
/// for encryption (by all voters) and each trustee receives exactly one share.
///
/// # Security Note
///
/// The dealer sees the full secret key during this function. In a production
/// deployment, this function should run in a secure enclave or be replaced with
/// a distributed key generation (DKG) protocol in a future version.
///
/// # Examples
///
/// ```
/// use pqhv_core::params::PQHV_TEST;
/// use pqhv_threshold::{ThresholdParams, generate_threshold_keys};
/// use rand::SeedableRng;
/// use rand_chacha::ChaCha20Rng;
///
/// let mut rng = ChaCha20Rng::from_entropy();
/// let threshold = ThresholdParams::new(3, 3).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
///
/// assert_eq!(shares.len(), 3);
/// assert_eq!(shares[0].index, 1);
/// assert_eq!(shares[2].index, 3);
/// ```
pub fn generate_threshold_keys(
    params: &PqhvParams,
    threshold: &ThresholdParams,
    rng: &mut impl RngCore,
) -> (PublicKey, Vec<TrusteeKeyShare>) {
    let (pk, sk) = pqhv_core::keygen::keygen(params, rng);
    let n = threshold.n;
    let q = params.q;

    let mut random_shares: Vec<PolyVec> = Vec::with_capacity(n);
    let mut running_sum = PolyVec::new_zero(params);

    for _ in 0..(n - 1) {
        let mut share = PolyVec::new_zero(params);
        for poly_idx in 0..params.k {
            for coeff_idx in 0..params.n {
                share.polys[poly_idx].coeffs[coeff_idx] = (rng.next_u64() % q) as i64;
            }
        }
        running_sum = running_sum.add(&share);
        running_sum.reduce();
        random_shares.push(share);
    }

    // Final share: s_n = s - sum(s_1..s_{n-1}) mod q
    let final_share = sk.s.sub(&running_sum);
    random_shares.push(final_share);

    #[cfg(debug_assertions)]
    {
        let mut check = PolyVec::new_zero(params);
        for share in &random_shares {
            check = check.add(share);
        }
        check.reduce();
        let mut sk_reduced = sk.s.clone();
        sk_reduced.reduce();
        for pi in 0..params.k {
            for ci in 0..params.n {
                assert_eq!(
                    check.polys[pi].coeffs[ci],
                    sk_reduced.polys[pi].coeffs[ci],
                    "Share sum mismatch at poly[{}].coeffs[{}]", pi, ci
                );
            }
        }
    }

    let trustee_shares: Vec<TrusteeKeyShare> = random_shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| TrusteeKeyShare { index: i + 1, share })
        .collect();

    (pk, trustee_shares)
}

/// Produce a partial decryption using a trustee's key share.
///
/// Each trustee computes `d_i = s_i^T * u` where s_i is their key share and u is
/// the first component of the ciphertext.
///
/// # Examples
///
/// ```
/// use pqhv_core::{params::PQHV_TEST, encrypt::encrypt};
/// use pqhv_threshold::{ThresholdParams, generate_threshold_keys, partial_decrypt};
/// use rand::SeedableRng;
/// use rand_chacha::ChaCha20Rng;
///
/// let mut rng = ChaCha20Rng::from_entropy();
/// let threshold = ThresholdParams::new(2, 2).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
/// let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
///
/// let partial = partial_decrypt(&shares[0], &ct);
/// assert_eq!(partial.index, 1);
/// ```
pub fn partial_decrypt(share: &TrusteeKeyShare, ct: &Ciphertext) -> PartialDecryption {
    let value = share.share.inner_product(&ct.u);
    PartialDecryption { index: share.index, value }
}

/// Combine all partial decryptions to recover the plaintext tally.
///
/// Sums all n partial inner products to reconstruct `s^T * u`, then completes
/// the decryption as `v - s^T * u` and decodes to a tally count.
///
/// # Examples
///
/// ```
/// use pqhv_core::{params::PQHV_TEST, encrypt::encrypt};
/// use pqhv_threshold::{
///     ThresholdParams, generate_threshold_keys,
///     partial_decrypt, combine_partial_decryptions,
/// };
/// use rand::SeedableRng;
/// use rand_chacha::ChaCha20Rng;
///
/// let mut rng = ChaCha20Rng::from_entropy();
/// let threshold = ThresholdParams::new(3, 3).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
///
/// let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
/// let partials: Vec<_> = shares.iter()
///     .map(|s| partial_decrypt(s, &ct))
///     .collect();
///
/// let tally = combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST);
/// assert_eq!(tally.unwrap(), 1);
/// ```
pub fn combine_partial_decryptions(
    partials: &[PartialDecryption],
    ct: &Ciphertext,
    threshold: &ThresholdParams,
    params: &PqhvParams,
) -> Result<u64, ThresholdError> {
    if partials.len() < threshold.n {
        return Err(ThresholdError::InsufficientShares {
            provided: partials.len(),
            required: threshold.n,
        });
    }

    let mut seen = std::collections::HashSet::new();
    for p in partials.iter().take(threshold.n) {
        if p.index == 0 || p.index > threshold.n {
            return Err(ThresholdError::InvalidShareIndex { index: p.index, max: threshold.n });
        }
        if !seen.insert(p.index) {
            return Err(ThresholdError::DuplicateShareIndex { index: p.index });
        }
    }

    let mut combined = Poly::new_zero(params);
    for p in partials.iter().take(threshold.n) {
        combined = combined.add(&p.value);
    }
    combined.reduce();

    let mut noisy_message = ct.v.sub(&combined);
    noisy_message.reduce();

    Ok(noisy_message.to_tally(params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhv_core::encrypt::encrypt;
    use pqhv_core::params::PQHV_TEST;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_threshold_params_valid() {
        let p = ThresholdParams::new(3, 3).unwrap();
        assert_eq!(p.t, 3);
        assert_eq!(p.n, 3);
    }

    #[test]
    fn test_threshold_params_single_trustee() {
        let p = ThresholdParams::new(1, 1).unwrap();
        assert_eq!(p.t, 1);
        assert_eq!(p.n, 1);
    }

    #[test]
    fn test_threshold_params_rejects_t_less_than_n() {
        assert!(ThresholdParams::new(2, 3).is_err());
    }

    #[test]
    fn test_threshold_params_rejects_zero() {
        assert!(ThresholdParams::new(0, 3).is_err());
        assert!(ThresholdParams::new(3, 0).is_err());
    }

    #[test]
    fn test_threshold_params_rejects_t_exceeds_n() {
        assert!(ThresholdParams::new(4, 3).is_err());
    }

    #[test]
    fn test_keygen_produces_correct_share_count() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let threshold = ThresholdParams::new(3, 3).unwrap();
        let (_pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        assert_eq!(shares.len(), 3);
        for (i, s) in shares.iter().enumerate() {
            assert_eq!(s.index, i + 1);
        }
    }

    #[test]
    fn test_shares_sum_to_secret_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let threshold = ThresholdParams::new(3, 3).unwrap();
        let (_pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let mut reconstructed = PolyVec::new_zero(&PQHV_TEST);
        for share in &shares {
            reconstructed = reconstructed.add(&share.share);
        }
        reconstructed.reduce();

        let mut rng2 = ChaCha20Rng::seed_from_u64(42);
        let (_pk2, sk2) = pqhv_core::keygen::keygen(&PQHV_TEST, &mut rng2);
        let mut sk_reduced = sk2.s.clone();
        sk_reduced.reduce();

        for pi in 0..PQHV_TEST.k {
            for ci in 0..PQHV_TEST.n {
                assert_eq!(
                    reconstructed.polys[pi].coeffs[ci],
                    sk_reduced.polys[pi].coeffs[ci],
                );
            }
        }
    }

    #[test]
    fn test_threshold_decrypt_single_vote() {
        let mut rng = ChaCha20Rng::seed_from_u64(123);
        let threshold = ThresholdParams::new(3, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);
    }

    #[test]
    fn test_threshold_decrypt_zero_vote() {
        let mut rng = ChaCha20Rng::seed_from_u64(456);
        let threshold = ThresholdParams::new(2, 2).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 0);
    }

    #[test]
    fn test_threshold_decrypt_homomorphic_tally() {
        let mut rng = ChaCha20Rng::seed_from_u64(789);
        let threshold = ThresholdParams::new(3, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let ct1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct2 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct3 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct4 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let ct5 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let sum = pqhv_core::encrypt::add_ciphertexts(&ct1, &ct2);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &ct3);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &ct4);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &ct5);

        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &sum)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &sum, &threshold, &PQHV_TEST).unwrap(), 5);
    }

    #[test]
    fn test_threshold_single_trustee() {
        let mut rng = ChaCha20Rng::seed_from_u64(999);
        let threshold = ThresholdParams::new(1, 1).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        assert_eq!(shares.len(), 1);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let partials = vec![partial_decrypt(&shares[0], &ct)];
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);
    }

    #[test]
    fn test_insufficient_partials_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(111);
        let threshold = ThresholdParams::new(3, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let partials: Vec<_> = shares[0..2].iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).is_err());
    }

    #[test]
    fn test_duplicate_indices_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(222);
        let threshold = ThresholdParams::new(2, 2).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let p1 = partial_decrypt(&shares[0], &ct);
        let p2 = PartialDecryption { index: 1, value: partial_decrypt(&shares[1], &ct).value };
        assert!(combine_partial_decryptions(&[p1, p2], &ct, &threshold, &PQHV_TEST).is_err());
    }

    #[test]
    fn test_mixed_vote_tally() {
        let mut rng = ChaCha20Rng::seed_from_u64(333);
        let threshold = ThresholdParams::new(2, 2).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let yes1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let yes2 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let yes3 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let no1 = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        let no2 = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        let sum = pqhv_core::encrypt::add_ciphertexts(&yes1, &yes2);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &yes3);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &no1);
        let sum = pqhv_core::encrypt::add_ciphertexts(&sum, &no2);

        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &sum)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &sum, &threshold, &PQHV_TEST).unwrap(), 3);
    }
}

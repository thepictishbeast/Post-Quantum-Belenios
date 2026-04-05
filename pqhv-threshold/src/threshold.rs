//! # Threshold Key Generation and Partial Decryption
//!
//! Implements Shamir's Secret Sharing over the prime field Z_p for lattice-based
//! threshold decryption.
//!
//! ## Mathematical Foundation
//!
//! In Shamir's Secret Sharing, the secret s is embedded as the constant term of
//! a random polynomial f(x) of degree t-1 over a finite field. Evaluating f at
//! distinct nonzero points gives shares; any t shares recover f(0) = s via
//! Lagrange interpolation.
//!
//! The "secret" here is a vector of polynomials (the Module-LWE secret key `s`
//! in R_q^k). We apply Shamir's scheme coefficient-by-coefficient: for each of
//! the k*n coefficients in the secret key vector, we create an independent
//! degree-(t-1) sharing polynomial over Z_p with that coefficient as the
//! constant term.
//!
//! ## Why a Prime Field
//!
//! PQHV uses q = 2^k (power-of-2 modulus). Shamir's scheme requires Lagrange
//! interpolation, which needs modular inverses of all pairwise differences
//! (x_i - x_j). For q = 2^k with integer evaluation points, even differences
//! are non-invertible. We solve this by performing all Shamir operations
//! (polynomial construction, evaluation, and Lagrange coefficient computation)
//! over the Mersenne prime p = 2^61 - 1, which is larger than any PQHV modulus.
//! Share values are reduced mod q for use as Module-LWE key shares.
//!
//! ## Partial Decryption
//!
//! Normal decryption computes `v - s^T * u`. Each trustee i computes their
//! partial inner product `s_i^T * u`. The combiner uses scaled Lagrange
//! coefficients to reconstruct `D * (s^T * u)` from any t partial products,
//! then completes decryption as `D*v - D*(s^T*u)` with adjusted decoding.
//!
//! ## Scaled Lagrange Approach
//!
//! For non-consecutive evaluation points, the Lagrange coefficients at x=0
//! may be rational (e.g., 8/3 for points {1, 2, 4}). Since q = 2^k, even
//! denominators cannot be inverted in Z_q. We solve this by clearing
//! denominators: multiply each Lagrange coefficient by the common denominator
//! D to produce integers. The combination then gives `D * (s^T * u)` instead
//! of `s^T * u`. We adjust the decoding scale from delta to D*delta,
//! recovering the correct tally without needing to divide by D in Z_q.
//!
//! ## Noise Analysis
//!
//! The scaling by D multiplies both the signal and the noise equally:
//! `D * (delta * m + noise)`. The decode step divides by `D * delta`,
//! which is equivalent to dividing by delta, so the noise-to-signal ratio
//! is unchanged. The noise budget is identical to single-trustee decryption.

use crate::error::ThresholdError;
use pqhv_core::encrypt::Ciphertext;
use pqhv_core::keygen::PublicKey;
use pqhv_core::matrix::PolyVec;
use pqhv_core::params::PqhvParams;
use pqhv_core::poly::Poly;
use rand::RngCore;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

/// Prime modulus for Shamir's Secret Sharing.
///
/// Must be larger than any PQHV ciphertext modulus q. Since q can be up to
/// 2^50 = 1,125,899,906,842,624, we use the Mersenne prime 2^61 - 1 =
/// 2,305,843,009,213,693,951. Being prime guarantees that Z_p is a field
/// where all nonzero elements have multiplicative inverses and Lagrange
/// interpolation is well-defined for any subset of evaluation points.
const SHARING_PRIME: i128 = 2_305_843_009_213_693_951; // 2^61 - 1

// ---------------------------------------------------------------------------
//  Public types
// ---------------------------------------------------------------------------

/// Parameters for threshold decryption.
///
/// Defines the total number of trustees (n) and the threshold (t) — the minimum
/// number of trustees required to decrypt. Any subset of t trustees can decrypt,
/// but t-1 or fewer trustees learn nothing about the plaintext.
///
/// # Invariants
///
/// - `1 <= t <= n`
/// - `n >= 1`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdParams {
    /// Minimum number of trustees required to decrypt (the threshold).
    pub t: usize,
    /// Total number of trustees.
    pub n: usize,
}

impl ThresholdParams {
    /// Create a new threshold parameter set.
    ///
    /// # Arguments
    ///
    /// * `t` — The threshold: minimum number of trustees required to decrypt.
    /// * `n` — The total number of trustees.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `t == 0` (need at least one trustee)
    /// - `n == 0` (need at least one trustee)
    /// - `t > n` (cannot require more shares than exist)
    ///
    /// # Examples
    ///
    /// ```
    /// use pqhv_threshold::ThresholdParams;
    ///
    /// let params = ThresholdParams::new(3, 5).unwrap();
    /// assert_eq!(params.t, 3);
    /// assert_eq!(params.n, 5);
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
        Ok(ThresholdParams { t, n })
    }
}

/// A trustee's share of the secret key.
///
/// Each share is a vector of k polynomials in R_q^k, the same structure as a
/// full secret key. The share at index i is obtained by evaluating the Shamir
/// sharing polynomials (over Z_p) at point i, then reducing mod q.
///
/// # Security
///
/// A single share reveals nothing about the original secret key (information-
/// theoretic security for Shamir's scheme over Z_p). Only when t or more shares
/// are combined can the secret — or any function of it — be recovered.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrusteeKeyShare {
    /// The trustee's 1-based index (evaluation point in Shamir's scheme).
    /// Valid range: [1, n].
    pub index: usize,
    /// The trustee's share of the secret key vector, with coefficients mod q.
    pub share: PolyVec,
}

/// A partial decryption produced by a single trustee.
///
/// Contains the trustee's contribution to the decryption: `s_i^T * u`, where
/// `s_i` is the trustee's key share and `u` is the ciphertext's first component.
///
/// # Security
///
/// A partial decryption reveals `s_i^T * u` but not `s_i` itself (recovering
/// `s_i` from this would require solving Module-LWE). Moreover, fewer than t
/// partial decryptions are insufficient to recover the full `s^T * u` needed
/// for decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryption {
    /// The trustee's 1-based index (must match the share used to produce this).
    pub index: usize,
    /// The partial inner product: s_i^T * u.
    pub value: Poly,
}

// ---------------------------------------------------------------------------
//  Key Generation
// ---------------------------------------------------------------------------

/// Generate a threshold key set: one public key and n trustee key shares.
///
/// Uses a trusted dealer model: the full secret key is generated, then split
/// into n shares using Shamir's Secret Sharing over the prime field Z_p.
///
/// # Algorithm
///
/// 1. Generate a normal key pair (pk, sk) via the base PQHV keygen.
/// 2. For each coefficient in the secret key vector (k polynomials x n_ring
///    coefficients), create a random degree-(t-1) polynomial over Z_p with
///    the real coefficient as the constant term.
/// 3. Evaluate all sharing polynomials at points 1, 2, ..., n over Z_p,
///    then reduce mod q to produce the key shares.
///
/// # Arguments
///
/// * `params` — The PQHV lattice parameters.
/// * `threshold` — The threshold parameters (t, n).
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
/// let threshold = ThresholdParams::new(3, 5).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
///
/// assert_eq!(shares.len(), 5);
/// assert_eq!(shares[0].index, 1);
/// assert_eq!(shares[4].index, 5);
/// ```
pub fn generate_threshold_keys(
    params: &PqhvParams,
    threshold: &ThresholdParams,
    rng: &mut impl RngCore,
) -> (PublicKey, Vec<TrusteeKeyShare>) {
    let (pk, sk) = pqhv_core::keygen::keygen(params, rng);
    let shares = shamir_split_polyvec(&sk.s, params, threshold, rng);

    let trustee_shares: Vec<TrusteeKeyShare> = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| TrusteeKeyShare {
            index: i + 1,
            share,
        })
        .collect();

    (pk, trustee_shares)
}

/// Split a secret key vector into n Shamir shares over the prime field Z_p.
///
/// For each coefficient in the secret key, creates a degree-(t-1) polynomial
/// over Z_p with that coefficient as the constant term, evaluates at points
/// 1..=n, and reduces results mod q.
fn shamir_split_polyvec(
    secret: &PolyVec,
    params: &PqhvParams,
    threshold: &ThresholdParams,
    rng: &mut impl RngCore,
) -> Vec<PolyVec> {
    let t = threshold.t;
    let n = threshold.n;
    let p = SHARING_PRIME;
    let q = params.q;
    let n_ring = params.n;

    let mut shares: Vec<PolyVec> = (0..n)
        .map(|_| PolyVec::new_zero(params))
        .collect();

    for poly_idx in 0..params.k {
        for coeff_idx in 0..n_ring {
            // The secret coefficient is in [0, q). Lift it into Z_p.
            let secret_coeff = secret.polys[poly_idx].coeffs[coeff_idx] as i128;

            // Create Shamir polynomial f(x) = c + a_1*x + ... + a_{t-1}*x^{t-1}
            // with random coefficients from Z_p. The constant term is the secret.
            let mut shamir_coeffs: Vec<i128> = Vec::with_capacity(t);
            shamir_coeffs.push(secret_coeff);
            for _ in 1..t {
                shamir_coeffs.push(sample_uniform_mod_p(rng, p));
            }

            // Evaluate f at points 1..=n as exact integers, then reduce mod q.
            //
            // IMPORTANT: We must NOT reduce mod p during Horner's evaluation.
            // The shares will be used as Z_q coefficients in polynomial ring
            // operations, and Lagrange reconstruction operates mod q. For the
            // reconstruction sum_j lambda_j * share_j to equal the secret mod q,
            // the shares must be f(x_j) mod q — NOT f(x_j) mod p mod q.
            //
            // Since p mod q = q - 1 (not 0), reducing mod p first introduces
            // a systematic error: (a mod p) mod q != a mod q in general.
            //
            // The intermediate values fit in i128 for practical parameters:
            // max value ~ t * p * n^(t-1). For t=10, n=100 this is ~2^125,
            // well within i128's range of 2^127.
            for (trustee_idx, share) in shares.iter_mut().enumerate() {
                let x = (trustee_idx + 1) as i128;

                // Horner's method without intermediate reduction:
                // f(x) = c[0] + x*(c[1] + x*(c[2] + ...))
                let mut value: i128 = 0;
                for deg in (0..t).rev() {
                    value = value * x + shamir_coeffs[deg];
                }

                // Reduce directly to [0, q) for use as an R_q coefficient.
                share.polys[poly_idx].coeffs[coeff_idx] =
                    ((value % q as i128) + q as i128) as i64 % q as i64;
            }
        }
    }

    shares
}

/// Sample a uniform random value in [0, p) where p is the sharing prime.
///
/// Uses rejection sampling: draw a u64, reject if >= p. Since p = 2^61 - 1,
/// only one u64 is needed and rejection probability is < 1/4.
fn sample_uniform_mod_p(rng: &mut impl RngCore, p: i128) -> i128 {
    loop {
        let val = rng.next_u64() as i128;
        if val < p {
            return val;
        }
    }
}

// ---------------------------------------------------------------------------
//  Partial Decryption
// ---------------------------------------------------------------------------

/// Produce a partial decryption using a trustee's key share.
///
/// Each trustee computes `s_i^T * u` where `s_i` is their key share and `u` is
/// the first component of the ciphertext.
///
/// # Arguments
///
/// * `share` — The trustee's key share (from `generate_threshold_keys`).
/// * `ct` — The ciphertext to partially decrypt (typically a homomorphic tally).
///
/// # Returns
///
/// A `PartialDecryption` containing the trustee's index and their partial
/// inner product.
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
/// let threshold = ThresholdParams::new(2, 3).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
/// let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
///
/// let partial = partial_decrypt(&shares[0], &ct);
/// assert_eq!(partial.index, 1);
/// ```
pub fn partial_decrypt(share: &TrusteeKeyShare, ct: &Ciphertext) -> PartialDecryption {
    let value = share.share.inner_product(&ct.u);
    PartialDecryption {
        index: share.index,
        value,
    }
}

// ---------------------------------------------------------------------------
//  Combining Partial Decryptions
// ---------------------------------------------------------------------------

/// Combine partial decryptions to recover the plaintext tally.
///
/// Uses Lagrange interpolation over the prime field Z_p to compute combination
/// coefficients, applies them mod q to the partial decryptions, and completes
/// the decryption.
///
/// # Algorithm
///
/// Given partial decryptions from trustees with indices {i_1, ..., i_t}:
///
/// 1. Compute Lagrange coefficients over Z_p:
///    `lambda_j = product_{m != j} (-i_m) * (i_j - i_m)^{-1}  mod p`
///
/// 2. Reduce each coefficient mod q for use as a scalar in R_q.
///
/// 3. Reconstruct: `s^T * u = sum_j lambda_j * (s_{i_j}^T * u)  mod q`
///
/// 4. Complete decryption: `noisy_message = v - s^T * u`
///
/// 5. Decode the tally count from the constant term.
///
/// # Arguments
///
/// * `partials` — A slice of partial decryptions (at least t required).
/// * `ct` — The ciphertext being decrypted (needed for the `v` component).
/// * `threshold` — The threshold parameters.
/// * `params` — The PQHV lattice parameters.
///
/// # Returns
///
/// The decrypted tally count, or an error if:
/// - Fewer than t partial decryptions are provided
/// - Any trustee index is out of range [1, n]
/// - Duplicate trustee indices are present
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
/// let threshold = ThresholdParams::new(3, 5).unwrap();
/// let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
///
/// let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
/// let partials: Vec<_> = shares[0..3].iter()
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
    if partials.len() < threshold.t {
        return Err(ThresholdError::InsufficientShares {
            provided: partials.len(),
            required: threshold.t,
        });
    }

    let mut seen_indices = std::collections::HashSet::new();
    for partial in partials {
        if partial.index == 0 || partial.index > threshold.n {
            return Err(ThresholdError::InvalidShareIndex {
                index: partial.index,
                max: threshold.n,
            });
        }
        if !seen_indices.insert(partial.index) {
            return Err(ThresholdError::DuplicateShareIndex {
                index: partial.index,
            });
        }
    }

    // Use exactly t partials
    let active = &partials[..threshold.t];
    let indices: Vec<i128> = active.iter().map(|p| p.index as i128).collect();
    let q = params.q;

    // Compute INTEGER Lagrange coefficients by clearing denominators.
    //
    // The Lagrange coefficients for non-consecutive evaluation points are
    // generally rational (e.g., 8/3 for points {1, 2, 4}). Since q = 2^k,
    // even denominators are not invertible mod q, so we cannot directly
    // reduce rational Lagrange coefficients to Z_q.
    //
    // Solution: compute the common denominator D = product of all pairwise
    // differences in the active subset, then multiply each Lagrange
    // coefficient by D to produce integers. The combination then gives
    // D * (s^T * u) instead of s^T * u. We account for the scaling factor
    // D in the final decoding step.
    //
    // For each j: lambda_j(0) = product_{m != j} (-i_m) / (i_j - i_m)
    // We compute:
    //   numerator_j = product_{m != j} (-i_m)
    //   denominator_j = product_{m != j} (i_j - i_m)
    //   D = lcm of all denominator_j (or equivalently, product of all |i_j - i_m| for j < m)
    //   D_lambda_j = D * numerator_j / denominator_j (always an integer)

    // Compute exact rational Lagrange coefficients as (numerator, denominator) pairs.
    let mut numer_vec: Vec<i128> = Vec::with_capacity(active.len());
    let mut denom_vec: Vec<i128> = Vec::with_capacity(active.len());

    for (j, &i_j) in indices.iter().enumerate() {
        let mut numer: i128 = 1;
        let mut denom: i128 = 1;
        for (m, &i_m) in indices.iter().enumerate() {
            if m == j {
                continue;
            }
            numer *= -i_m;
            denom *= i_j - i_m;
        }
        numer_vec.push(numer);
        denom_vec.push(denom);
    }

    // Compute D = lcm of all denominators (using absolute values).
    let common_denom = denom_vec.iter().fold(1i128, |acc, &d| {
        let d_abs = d.unsigned_abs() as i128;
        let g = gcd_i128(acc.unsigned_abs() as i128, d_abs);
        acc / g * d_abs
    });

    // Compute integer Lagrange coefficients: D_lambda_j = D * numer_j / denom_j
    let int_lagrange: Vec<i128> = numer_vec
        .iter()
        .zip(denom_vec.iter())
        .map(|(&n, &d)| {
            let scaled = common_denom * n;
            // d should divide scaled exactly
            debug_assert!(scaled % d == 0, "D * numerator not divisible by denominator");
            scaled / d
        })
        .collect();

    // Reconstruct D * (s^T * u) using integer Lagrange coefficients.
    //
    // combined = sum_j D_lambda_j * partial_j  mod q
    //          = D * sum_j lambda_j * partial_j  mod q
    //          = D * (s^T * u)  mod q
    //
    // We use i128 arithmetic because the integer Lagrange coefficients
    // can be large (up to ~D * max_index^t), and multiplied by partial
    // decryption coefficients (up to q-1), the products can exceed i64.
    let n_ring = params.n;
    let q128 = q as i128;

    let mut combined_coeffs: Vec<i64> = vec![0i64; n_ring];
    for (j, partial) in active.iter().enumerate() {
        let lambda = int_lagrange[j];
        for (c_idx, combined) in combined_coeffs.iter_mut().enumerate() {
            let coeff = partial.value.coeffs[c_idx] as i128;
            let product = (lambda * coeff) % q128;
            *combined = (((*combined as i128 + product) % q128) + q128) as i64 % q as i64;
        }
    }

    // Complete decryption with scaling adjustment.
    //
    // Normal decryption: noisy = v - s^T*u, then decode round(noisy / delta).
    // Threshold decryption: we have D*(s^T*u) instead of s^T*u.
    // So: D*noisy = D*v - D*(s^T*u), then decode round(D*noisy / (D*delta)).
    // This is equivalent to: compute D*v mod q, subtract combined, decode
    // with scale D*delta.

    // Compute D*v mod q (coefficient-wise)
    let d_mod_q = ((common_denom % q128) + q128) % q128;
    let mut d_v_coeffs: Vec<i64> = vec![0i64; n_ring];
    for (i, c) in ct.v.coeffs.iter().enumerate() {
        d_v_coeffs[i] = (((d_mod_q * (*c as i128)) % q128) + q128) as i64 % q as i64;
    }

    let d_v = Poly {
        coeffs: d_v_coeffs,
        n: n_ring,
        q,
    };

    let combined = Poly {
        coeffs: combined_coeffs,
        n: n_ring,
        q,
    };

    // D * noisy_message = D*v - D*(s^T*u)
    let mut d_noisy = d_v.sub(&combined);
    d_noisy.reduce();

    // Decode: the constant term encodes D * count * delta + D * noise.
    // We decode by dividing by D * delta.
    let delta = params.encoding_scale() as i128;
    let d_delta = common_denom.unsigned_abs() as i128 * delta;

    let c = d_noisy.coeffs[0] as i128;
    let q_i128 = q as i128;
    let centered = if c > q_i128 / 2 { c - q_i128 } else { c };

    let tally = if centered >= 0 {
        ((centered + d_delta / 2) / d_delta) as u64
    } else {
        0
    };

    Ok(tally)
}

// ---------------------------------------------------------------------------
//  Internal arithmetic
// ---------------------------------------------------------------------------

/// Greatest common divisor for non-negative i128 values.
///
/// Uses the Euclidean algorithm. Both inputs must be non-negative.
fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular multiplicative inverse via the extended Euclidean algorithm.
///
/// Returns `a^{-1} mod m` such that `a * a^{-1} = 1 (mod m)`.
///
/// # Panics
///
/// Panics if `gcd(a, m) != 1`.
#[cfg(test)]
fn mod_inverse(a: i128, m: i128) -> i128 {
    let a = ((a % m) + m) % m;
    assert!(a != 0, "modular inverse of 0 does not exist");

    let (mut old_r, mut r) = (a, m);
    let (mut old_s, mut s) = (1i128, 0i128);

    while r != 0 {
        let quotient = old_r / r;
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
    }

    assert_eq!(
        old_r, 1,
        "modular inverse does not exist: gcd({}, {}) = {}",
        a, m, old_r
    );
    ((old_s % m) + m) % m
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pqhv_core::encrypt::{encrypt, sum_ciphertexts};
    use pqhv_core::keygen::keygen;
    use pqhv_core::params::{PQHV_TEST, PQHV_VOTING_128};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    // --- Arithmetic and constant tests ---

    #[test]
    fn test_sharing_prime_is_larger_than_q() {
        assert!(SHARING_PRIME > PQHV_TEST.q as i128);
        assert!(SHARING_PRIME > PQHV_VOTING_128.q as i128);
    }

    #[test]
    fn test_mod_inverse_basic() {
        assert_eq!(mod_inverse(3, 11), 4);
        assert_eq!((3 * 4) % 11, 1);
    }

    #[test]
    fn test_mod_inverse_in_sharing_prime() {
        let p = SHARING_PRIME;
        let a: i128 = 123456789;
        let inv = mod_inverse(a, p);
        assert_eq!((a * inv) % p, 1);
    }

    // --- ThresholdParams validation ---

    #[test]
    fn test_threshold_params_valid() {
        assert!(ThresholdParams::new(3, 5).is_ok());
        assert!(ThresholdParams::new(1, 1).is_ok());
        assert!(ThresholdParams::new(5, 5).is_ok());
        assert!(ThresholdParams::new(1, 5).is_ok());
        assert!(ThresholdParams::new(2, 3).is_ok());
    }

    #[test]
    fn test_threshold_params_t_zero() {
        assert_eq!(
            ThresholdParams::new(0, 5).unwrap_err(),
            ThresholdError::ThresholdTooSmall { t: 0 }
        );
    }

    #[test]
    fn test_threshold_params_n_zero() {
        assert_eq!(
            ThresholdParams::new(1, 0).unwrap_err(),
            ThresholdError::NoTrustees
        );
    }

    #[test]
    fn test_threshold_params_t_exceeds_n() {
        assert_eq!(
            ThresholdParams::new(6, 5).unwrap_err(),
            ThresholdError::ThresholdExceedsTrustees { t: 6, n: 5 }
        );
    }

    // --- Key generation ---

    #[test]
    fn test_generate_threshold_keys_dimensions() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        assert_eq!(shares.len(), 5);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.index, i + 1);
            assert_eq!(share.share.k, PQHV_TEST.k);
            for p in &share.share.polys {
                assert_eq!(p.coeffs.len(), PQHV_TEST.n);
            }
        }
        assert_eq!(pk.a.k, PQHV_TEST.k);
        assert_eq!(pk.b.k, PQHV_TEST.k);
    }

    #[test]
    fn test_shares_are_distinct() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(2, 3).unwrap();
        let (_, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        assert_ne!(shares[0].share, shares[1].share);
        assert_ne!(shares[1].share, shares[2].share);
    }

    #[test]
    fn test_share_coefficients_in_range() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (_, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let q = PQHV_TEST.q as i64;
        for share in &shares {
            for poly in &share.share.polys {
                for &c in &poly.coeffs {
                    assert!(c >= 0 && c < q);
                }
            }
        }
    }

    // --- Basic threshold decryption ---

    #[test]
    fn test_threshold_decrypt_zero() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let ct = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
        let partials: Vec<_> = shares[0..3]
            .iter()
            .map(|s| partial_decrypt(s, &ct))
            .collect();

        let tally = combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap();
        assert_eq!(tally, 0);
    }

    #[test]
    fn test_threshold_decrypt_one() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let partials: Vec<_> = shares[0..3]
            .iter()
            .map(|s| partial_decrypt(s, &ct))
            .collect();

        let tally = combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap();
        assert_eq!(tally, 1);
    }

    #[test]
    fn test_threshold_decrypt_repeated() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        for _ in 0..20 {
            let ct0 = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
            let ct1 = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

            let p0: Vec<_> = shares[0..3].iter().map(|s| partial_decrypt(s, &ct0)).collect();
            let p1: Vec<_> = shares[0..3].iter().map(|s| partial_decrypt(s, &ct1)).collect();

            assert_eq!(combine_partial_decryptions(&p0, &ct0, &threshold, &PQHV_TEST).unwrap(), 0);
            assert_eq!(combine_partial_decryptions(&p1, &ct1, &threshold, &PQHV_TEST).unwrap(), 1);
        }
    }

    // --- Threshold property: t succeed, t-1 fail ---

    #[test]
    fn test_t_shares_succeed() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares[0..3].iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);
    }

    #[test]
    fn test_t_minus_1_shares_fail() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares[0..2].iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(
            combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InsufficientShares { provided: 2, required: 3 })
        );
    }

    // --- Any t-of-n subset works ---

    #[test]
    fn test_all_3_of_5_subsets() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        // All C(5,3) = 10 subsets
        let subsets: Vec<[usize; 3]> = vec![
            [0, 1, 2], [0, 1, 3], [0, 1, 4], [0, 2, 3], [0, 2, 4],
            [0, 3, 4], [1, 2, 3], [1, 2, 4], [1, 3, 4], [2, 3, 4],
        ];

        for subset in &subsets {
            let partials: Vec<_> = subset.iter()
                .map(|&i| partial_decrypt(&shares[i], &ct))
                .collect();
            let tally = combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap();
            assert_eq!(tally, 1, "subset {:?} failed", subset.iter().map(|i| i + 1).collect::<Vec<_>>());
        }
    }

    // --- Homomorphic tally with threshold ---

    #[test]
    fn test_threshold_homomorphic_tally_10() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let votes = [1u8, 0, 1, 1, 0, 1, 1, 1, 0, 1];
        let expected: u64 = votes.iter().map(|&v| v as u64).sum();

        let cts: Vec<_> = votes.iter().map(|&v| encrypt(&pk, v, &PQHV_TEST, &mut rng)).collect();
        let tally_ct = sum_ciphertexts(&cts);

        let partials: Vec<_> = shares[0..3].iter().map(|s| partial_decrypt(s, &tally_ct)).collect();
        let tally = combine_partial_decryptions(&partials, &tally_ct, &threshold, &PQHV_TEST).unwrap();
        assert_eq!(tally, expected);
    }

    #[test]
    fn test_threshold_homomorphic_tally_100() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        let mut yes_count: u64 = 0;
        let mut cts = Vec::new();
        for i in 0..100 {
            let vote = if i % 3 == 0 { 1u8 } else { 0u8 };
            yes_count += vote as u64;
            cts.push(encrypt(&pk, vote, &PQHV_TEST, &mut rng));
        }

        let tally_ct = sum_ciphertexts(&cts);

        // Non-consecutive shares {2, 4, 5}
        let partials: Vec<_> = [1, 3, 4].iter()
            .map(|&i| partial_decrypt(&shares[i], &tally_ct))
            .collect();
        let tally = combine_partial_decryptions(&partials, &tally_ct, &threshold, &PQHV_TEST).unwrap();
        assert_eq!(tally, yes_count);
    }

    // --- Edge cases ---

    #[test]
    fn test_1_of_1() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(1, 1).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);

        for &vote in &[0u8, 1] {
            let ct = encrypt(&pk, vote, &PQHV_TEST, &mut rng);
            let partial = partial_decrypt(&shares[0], &ct);
            let tally = combine_partial_decryptions(&[partial], &ct, &threshold, &PQHV_TEST).unwrap();
            assert_eq!(tally, vote as u64);
        }
    }

    #[test]
    fn test_2_of_2() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(2, 2).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);

        // Only one share should fail
        let one = vec![partial_decrypt(&shares[0], &ct)];
        assert_eq!(
            combine_partial_decryptions(&one, &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InsufficientShares { provided: 1, required: 2 })
        );
    }

    #[test]
    fn test_n_of_n() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(5, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);
    }

    #[test]
    fn test_1_of_5() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(1, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        for share in &shares {
            let partial = partial_decrypt(share, &ct);
            let tally = combine_partial_decryptions(&[partial], &ct, &threshold, &PQHV_TEST).unwrap();
            assert_eq!(tally, 1, "trustee {} failed alone", share.index);
        }
    }

    // --- Error handling ---

    #[test]
    fn test_combine_insufficient() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares[0..1].iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(
            combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InsufficientShares { provided: 1, required: 3 })
        );
    }

    #[test]
    fn test_combine_empty() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, _) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let empty: Vec<PartialDecryption> = vec![];
        assert_eq!(
            combine_partial_decryptions(&empty, &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InsufficientShares { provided: 0, required: 3 })
        );
    }

    #[test]
    fn test_combine_duplicate_index() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(2, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partial = partial_decrypt(&shares[0], &ct);
        assert_eq!(
            combine_partial_decryptions(&[partial.clone(), partial], &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::DuplicateShareIndex { index: 1 })
        );
    }

    #[test]
    fn test_combine_invalid_index_zero() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(2, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let mut bad = partial_decrypt(&shares[0], &ct);
        bad.index = 0;
        assert_eq!(
            combine_partial_decryptions(&[bad, partial_decrypt(&shares[1], &ct)], &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InvalidShareIndex { index: 0, max: 3 })
        );
    }

    #[test]
    fn test_combine_invalid_index_exceeds_n() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(2, 3).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let mut bad = partial_decrypt(&shares[0], &ct);
        bad.index = 10;
        assert_eq!(
            combine_partial_decryptions(&[bad, partial_decrypt(&shares[1], &ct)], &ct, &threshold, &PQHV_TEST),
            Err(ThresholdError::InvalidShareIndex { index: 10, max: 3 })
        );
    }

    #[test]
    fn test_more_than_t_shares() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_TEST, &threshold, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

        let partials: Vec<_> = shares.iter().map(|s| partial_decrypt(s, &ct)).collect();
        assert_eq!(combine_partial_decryptions(&partials, &ct, &threshold, &PQHV_TEST).unwrap(), 1);
    }

    // --- Voting-grade parameters ---

    #[test]
    fn test_threshold_voting_params() {
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (pk, shares) = generate_threshold_keys(&PQHV_VOTING_128, &threshold, &mut rng);

        let votes = [1u8, 0, 1, 1, 0, 1, 1, 1, 0, 1];
        let expected: u64 = votes.iter().map(|&v| v as u64).sum();

        let cts: Vec<_> = votes.iter().map(|&v| encrypt(&pk, v, &PQHV_VOTING_128, &mut rng)).collect();
        let tally_ct = sum_ciphertexts(&cts);

        let partials: Vec<_> = shares[0..3].iter().map(|s| partial_decrypt(s, &tally_ct)).collect();
        let tally = combine_partial_decryptions(&partials, &tally_ct, &threshold, &PQHV_VOTING_128).unwrap();
        assert_eq!(tally, expected);
    }

    // --- Shamir reconstruction correctness ---

    #[test]
    fn test_shamir_reconstruction_via_scaled_lagrange() {
        // Verify that clearing denominators in Lagrange coefficients recovers
        // D * secret mod q, where D is the common denominator.
        //
        // This mirrors the combine_partial_decryptions approach:
        //   sum_j (D * lambda_j) * share_j mod q = D * secret mod q
        //
        // Uses non-consecutive indices {1, 3, 5} to exercise fractional
        // Lagrange coefficients (e.g., lambda_1 = 15/8 for these points).
        let mut rng = test_rng();
        let threshold = ThresholdParams::new(3, 5).unwrap();
        let (_, sk) = keygen(&PQHV_TEST, &mut rng);

        let shares = shamir_split_polyvec(&sk.s, &PQHV_TEST, &threshold, &mut rng);

        let q = PQHV_TEST.q;
        let q128 = q as i128;

        // Use non-consecutive 1-based indices: {1, 3, 5}
        let indices: Vec<i128> = vec![1, 3, 5];
        let share_indices: Vec<usize> = vec![0, 2, 4]; // 0-based array indices

        // Compute exact rational Lagrange numerators and denominators
        let mut numer_vec: Vec<i128> = Vec::new();
        let mut denom_vec: Vec<i128> = Vec::new();
        for (j, &i_j) in indices.iter().enumerate() {
            let mut n: i128 = 1;
            let mut d: i128 = 1;
            for (m, &i_m) in indices.iter().enumerate() {
                if m == j { continue; }
                n *= -i_m;
                d *= i_j - i_m;
            }
            numer_vec.push(n);
            denom_vec.push(d);
        }

        // Compute common denominator D = lcm of all |denom_j|
        let common_denom = denom_vec.iter().fold(1i128, |acc, &d| {
            let d_abs = d.unsigned_abs() as i128;
            let g = gcd_i128(acc.unsigned_abs() as i128, d_abs);
            acc / g * d_abs
        });

        // Compute integer Lagrange coefficients: D_lambda_j = D * numer_j / denom_j
        let int_lambdas: Vec<i128> = numer_vec.iter().zip(denom_vec.iter())
            .map(|(&n, &d)| common_denom * n / d)
            .collect();

        for poly_idx in 0..PQHV_TEST.k {
            for coeff_idx in 0..PQHV_TEST.n {
                let original = sk.s.polys[poly_idx].coeffs[coeff_idx];

                // Reconstruct: sum_j D_lambda_j * share_j mod q = D * original mod q
                let mut reconstructed: i128 = 0;
                for (j, &idx) in share_indices.iter().enumerate() {
                    let share_val = shares[idx].polys[poly_idx].coeffs[coeff_idx] as i128;
                    let product = (int_lambdas[j] * share_val) % q128;
                    reconstructed = ((reconstructed + product) % q128 + q128) % q128;
                }
                let expected = ((common_denom * original as i128) % q128 + q128) % q128;

                assert_eq!(
                    reconstructed, expected,
                    "({}, {}) mismatch: got {}, expected D*secret = {}*{} mod q = {}",
                    poly_idx, coeff_idx, reconstructed, common_denom, original, expected
                );
            }
        }
    }
}

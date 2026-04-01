//! # Polynomial Ring Arithmetic
//!
//! Implements the polynomial ring R_q = Z_q[X] / (X^n + 1), which is the
//! fundamental algebraic structure underlying the Module-LWE encryption scheme.
//!
//! ## Ring Structure
//!
//! Elements are polynomials of degree < n with coefficients in Z_q (integers mod q).
//! The quotient by (X^n + 1) means that X^n = -1, which causes "wrap-around"
//! during polynomial multiplication: any term with degree >= n gets its coefficient
//! negated and reduced modulo n.
//!
//! ## Coefficient Representation
//!
//! Coefficients are stored as `i64` to handle intermediate results (especially
//! during multiplication) before reduction modulo q. The `reduce()` method
//! normalizes all coefficients to the range [0, q).

use crate::params::PqhvParams;
use crate::sample;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A polynomial in R_q = Z_q[X] / (X^n + 1).
///
/// Coefficients are stored in order of increasing degree:
/// `coeffs[i]` is the coefficient of X^i.
///
/// Invariant after `reduce()`: all coefficients are in [0, q).
/// Before reduction, coefficients may be any i64 value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Poly {
    /// Polynomial coefficients, indexed by degree.
    pub coeffs: Vec<i64>,
    /// Ring dimension (degree of the cyclotomic polynomial X^n + 1).
    pub n: usize,
    /// Coefficient modulus.
    pub q: u64,
}

impl Poly {
    /// Create the zero polynomial for the given parameter set.
    ///
    /// All coefficients are initialized to 0.
    pub fn new_zero(params: &PqhvParams) -> Self {
        Poly {
            coeffs: vec![0i64; params.n],
            n: params.n,
            q: params.q,
        }
    }

    /// Create a polynomial with uniform random coefficients in [0, q).
    ///
    /// Used for sampling the public matrix A in key generation.
    pub fn new_random(params: &PqhvParams, rng: &mut impl RngCore) -> Self {
        let coeffs: Vec<i64> = (0..params.n)
            .map(|_| (rng.next_u64() % params.q) as i64)
            .collect();
        Poly {
            coeffs,
            n: params.n,
            q: params.q,
        }
    }

    /// Create a polynomial with coefficients sampled from CBD(eta).
    ///
    /// Used for sampling secret keys (s) and noise vectors (e, r, e₁, e₂).
    /// Each coefficient is independently drawn from the centered binomial
    /// distribution, producing values in [-eta, eta].
    pub fn sample_cbd(params: &PqhvParams, eta: usize, rng: &mut impl RngCore) -> Self {
        let raw = sample::sample_cbd_vec(params.n, eta, rng);
        // Convert to positive representatives mod q
        let coeffs: Vec<i64> = raw
            .into_iter()
            .map(|c| {
                if c < 0 {
                    c + params.q as i64
                } else {
                    c
                }
            })
            .collect();
        Poly {
            coeffs,
            n: params.n,
            q: params.q,
        }
    }

    /// Coefficient-wise addition modulo q.
    ///
    /// Computes self + other in R_q.
    ///
    /// # Panics
    ///
    /// Panics if the polynomials have different parameters (n or q).
    pub fn add(&self, other: &Poly) -> Poly {
        assert_eq!(self.n, other.n, "Polynomial dimensions must match");
        assert_eq!(self.q, other.q, "Polynomial moduli must match");
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| (a + b) % self.q as i64)
            .collect();
        Poly {
            coeffs,
            n: self.n,
            q: self.q,
        }
    }

    /// Coefficient-wise subtraction modulo q.
    ///
    /// Computes self - other in R_q.
    ///
    /// # Panics
    ///
    /// Panics if the polynomials have different parameters.
    pub fn sub(&self, other: &Poly) -> Poly {
        assert_eq!(self.n, other.n, "Polynomial dimensions must match");
        assert_eq!(self.q, other.q, "Polynomial moduli must match");
        let q = self.q as i64;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| ((a - b) % q + q) % q)
            .collect();
        Poly {
            coeffs,
            n: self.n,
            q: self.q,
        }
    }

    /// Negate all coefficients modulo q.
    ///
    /// Computes -self in R_q.
    pub fn neg(&self) -> Poly {
        let q = self.q as i64;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .map(|&c| if c == 0 { 0 } else { q - (c % q) })
            .collect();
        Poly {
            coeffs,
            n: self.n,
            q: self.q,
        }
    }

    /// Multiply all coefficients by a scalar modulo q.
    ///
    /// Computes scalar * self in R_q.
    pub fn scalar_mul(&self, scalar: i64) -> Poly {
        let q = self.q as i64;
        let s = ((scalar % q) + q) % q;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .map(|&c| (c * s) % q)
            .collect();
        Poly {
            coeffs,
            n: self.n,
            q: self.q,
        }
    }

    /// Polynomial multiplication in R_q = Z_q[X] / (X^n + 1).
    ///
    /// Uses schoolbook O(n²) multiplication. The reduction modulo (X^n + 1)
    /// means that when the product degree reaches n, the coefficient wraps
    /// around with a sign flip: X^(n+i) ≡ -X^i.
    ///
    /// # Panics
    ///
    /// Panics if the polynomials have different parameters.
    ///
    // TODO: Replace with NTT for O(n log n) performance
    pub fn mul(&self, other: &Poly) -> Poly {
        assert_eq!(self.n, other.n, "Polynomial dimensions must match");
        assert_eq!(self.q, other.q, "Polynomial moduli must match");

        let n = self.n;
        let q = self.q as i64;
        let mut result = vec![0i64; n];

        for i in 0..n {
            if self.coeffs[i] == 0 {
                continue;
            }
            for j in 0..n {
                if other.coeffs[j] == 0 {
                    continue;
                }
                let degree = i + j;
                let product = (self.coeffs[i] as i128 * other.coeffs[j] as i128) % q as i128;

                if degree < n {
                    // Normal term: add to result[degree]
                    result[degree] = (result[degree] + product as i64) % q;
                } else {
                    // Wrap-around: X^n = -1, so X^(n+k) = -X^k
                    let wrapped = degree - n;
                    result[wrapped] = ((result[wrapped] - product as i64) % q + q) % q;
                }
            }
        }

        Poly {
            coeffs: result,
            n,
            q: self.q,
        }
    }

    /// Reduce all coefficients to the canonical range [0, q).
    ///
    /// Call this after a sequence of operations that may have produced
    /// coefficients outside [0, q) (e.g., after subtraction without modular
    /// reduction at each step).
    pub fn reduce(&mut self) {
        let q = self.q as i64;
        for c in self.coeffs.iter_mut() {
            *c = ((*c % q) + q) % q;
        }
    }

    /// Encode a single message value as a polynomial (BFV-style).
    ///
    /// The message m is placed in the constant term as m * Δ where
    /// Δ = ⌊q/t⌋ is the encoding scale from the parameter set.
    /// All other coefficients are zero.
    ///
    /// For single-bit encryption: m ∈ {0, 1}.
    /// For tally decryption: m can be any non-negative integer < t.
    ///
    /// # Arguments
    ///
    /// * `bit` — The message bit (0 or 1). Values > 1 are reduced mod 2.
    /// * `params` — The parameter set determining n, q, and encoding scale Δ.
    pub fn from_message(bit: u8, params: &PqhvParams) -> Self {
        let mut p = Poly::new_zero(params);
        p.coeffs[0] = (bit & 1) as i64 * params.encoding_scale();
        p
    }

    /// Decode a polynomial to a message bit by rounding the constant term.
    ///
    /// Uses BFV-style decoding: computes round(coeff * t / q) mod 2.
    /// Equivalently, divides by the encoding scale Δ and rounds to the
    /// nearest integer, then takes mod 2.
    ///
    /// # Returns
    ///
    /// 0 or 1.
    pub fn to_message(&self, params: &PqhvParams) -> u8 {
        let count = self.to_tally(params);
        (count % 2) as u8
    }

    /// Decode a polynomial to a tally count for homomorphic summation.
    ///
    /// After summing N ciphertexts that each encrypt a bit (0 or 1),
    /// the decrypted polynomial's constant term encodes `count * Δ + noise`.
    /// This function recovers count = round(coeff / Δ).
    ///
    /// # Arguments
    ///
    /// * `params` — The parameter set (needed for the encoding scale Δ).
    ///
    /// # Returns
    ///
    /// The recovered vote count.
    pub fn to_tally(&self, params: &PqhvParams) -> u64 {
        let c = self.coeffs[0];
        let q = self.q as i64;
        let delta = params.encoding_scale();

        // The constant coefficient is in [0, q). It encodes count * Δ + noise.
        // Since count * Δ < q/2 (by parameter design), values near q are noise
        // wrapping below zero.
        let centered = if c > q / 2 { c - q } else { c };

        // Round to nearest multiple of Δ
        if centered >= 0 {
            ((centered + delta / 2) / delta) as u64
        } else {
            // Negative noise on a zero count
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PQHV_TEST;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn test_zero_polynomial() {
        let z = Poly::new_zero(&PQHV_TEST);
        assert_eq!(z.coeffs.len(), 64);
        assert!(z.coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_random_polynomial_in_range() {
        let mut rng = test_rng();
        let p = Poly::new_random(&PQHV_TEST, &mut rng);
        assert_eq!(p.coeffs.len(), 64);
        for &c in &p.coeffs {
            assert!(c >= 0 && c < PQHV_TEST.q as i64);
        }
    }

    #[test]
    fn test_cbd_polynomial_in_range() {
        let mut rng = test_rng();
        let p = Poly::sample_cbd(&PQHV_TEST, 2, &mut rng);
        assert_eq!(p.coeffs.len(), 64);
        for &c in &p.coeffs {
            // After conversion to positive rep: should be 0, 1, 2, q-2, or q-1
            assert!(c >= 0 && c < PQHV_TEST.q as i64);
        }
    }

    #[test]
    fn test_addition_commutative() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let b = Poly::new_random(&PQHV_TEST, &mut rng);
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn test_addition_associative() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let b = Poly::new_random(&PQHV_TEST, &mut rng);
        let c = Poly::new_random(&PQHV_TEST, &mut rng);
        // Need to reduce to ensure exact equality
        let mut lhs = a.add(&b).add(&c);
        let mut rhs = a.add(&b.add(&c));
        lhs.reduce();
        rhs.reduce();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_add_zero_identity() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let z = Poly::new_zero(&PQHV_TEST);
        assert_eq!(a.add(&z), a);
    }

    #[test]
    fn test_add_neg_is_zero() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let neg_a = a.neg();
        let mut result = a.add(&neg_a);
        result.reduce();
        let zero = Poly::new_zero(&PQHV_TEST);
        assert_eq!(result, zero);
    }

    #[test]
    fn test_subtraction() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let b = Poly::new_random(&PQHV_TEST, &mut rng);
        // a - b + b == a
        let mut result = a.sub(&b).add(&b);
        result.reduce();
        let mut expected = a.clone();
        expected.reduce();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scalar_mul() {
        let params = &PQHV_TEST;
        let mut p = Poly::new_zero(params);
        p.coeffs[0] = 5;
        p.coeffs[1] = 3;
        let result = p.scalar_mul(4);
        assert_eq!(result.coeffs[0], 20);
        assert_eq!(result.coeffs[1], 12);
    }

    #[test]
    fn test_scalar_mul_wraps() {
        let params = &PQHV_TEST;
        let mut p = Poly::new_zero(params);
        p.coeffs[0] = (PQHV_TEST.q - 1) as i64;
        let result = p.scalar_mul(2);
        // (q-1)*2 mod q = q*2 - 2 mod q = q - 2
        assert_eq!(result.coeffs[0], (PQHV_TEST.q - 2) as i64);
    }

    #[test]
    fn test_mul_known_small() {
        // In R_q[X]/(X^n+1) with small n=4, q=97:
        // (1 + X) * (1 + X) = 1 + 2X + X^2
        let params = PqhvParams {
            n: 4,
            k: 1,
            q: 97,
            eta: 1,
            max_additions: 10,
            security_level: "test",
        };
        let mut a = Poly::new_zero(&params);
        a.coeffs[0] = 1;
        a.coeffs[1] = 1;

        let result = a.mul(&a);
        assert_eq!(result.coeffs[0], 1);
        assert_eq!(result.coeffs[1], 2);
        assert_eq!(result.coeffs[2], 1);
        assert_eq!(result.coeffs[3], 0);
    }

    #[test]
    fn test_mul_wraparound() {
        // In R_q[X]/(X^4+1), X^3 * X^2 = X^5 = -X^1
        let params = PqhvParams {
            n: 4,
            k: 1,
            q: 97,
            eta: 1,
            max_additions: 10,
            security_level: "test",
        };
        let mut a = Poly::new_zero(&params);
        a.coeffs[3] = 1; // X^3
        let mut b = Poly::new_zero(&params);
        b.coeffs[2] = 1; // X^2

        let result = a.mul(&b);
        // X^5 = X^(4+1) = -X^1
        assert_eq!(result.coeffs[0], 0);
        assert_eq!(result.coeffs[1], 97 - 1); // -1 mod 97 = 96
        assert_eq!(result.coeffs[2], 0);
        assert_eq!(result.coeffs[3], 0);
    }

    #[test]
    fn test_mul_commutative() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let b = Poly::new_random(&PQHV_TEST, &mut rng);
        let mut ab = a.mul(&b);
        let mut ba = b.mul(&a);
        ab.reduce();
        ba.reduce();
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_mul_zero_is_zero() {
        let mut rng = test_rng();
        let a = Poly::new_random(&PQHV_TEST, &mut rng);
        let z = Poly::new_zero(&PQHV_TEST);
        let result = a.mul(&z);
        assert_eq!(result, z);
    }

    #[test]
    fn test_message_roundtrip_zero() {
        let p = Poly::from_message(0, &PQHV_TEST);
        assert_eq!(p.to_message(&PQHV_TEST), 0);
    }

    #[test]
    fn test_message_roundtrip_one() {
        let p = Poly::from_message(1, &PQHV_TEST);
        assert_eq!(p.to_message(&PQHV_TEST), 1);
    }

    #[test]
    fn test_message_encoding_values() {
        let p0 = Poly::from_message(0, &PQHV_TEST);
        let p1 = Poly::from_message(1, &PQHV_TEST);
        assert_eq!(p0.coeffs[0], 0);
        assert_eq!(p1.coeffs[0], PQHV_TEST.encoding_scale());
        // All other coefficients should be zero
        for i in 1..PQHV_TEST.n {
            assert_eq!(p0.coeffs[i], 0);
            assert_eq!(p1.coeffs[i], 0);
        }
    }

    #[test]
    fn test_message_decode_with_small_noise() {
        // Adding small noise should not change the decoded message
        let mut p1 = Poly::from_message(1, &PQHV_TEST);
        p1.coeffs[0] += 100; // Small noise relative to Δ/2
        assert_eq!(p1.to_message(&PQHV_TEST), 1);

        let mut p0 = Poly::from_message(0, &PQHV_TEST);
        p0.coeffs[0] += 100;
        assert_eq!(p0.to_message(&PQHV_TEST), 0);
    }

    #[test]
    fn test_reduce() {
        let params = &PQHV_TEST;
        let mut p = Poly::new_zero(params);
        p.coeffs[0] = -5;
        p.coeffs[1] = params.q as i64 + 10;
        p.reduce();
        assert_eq!(p.coeffs[0], params.q as i64 - 5);
        assert_eq!(p.coeffs[1], 10);
    }
}

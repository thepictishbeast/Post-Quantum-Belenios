//! # Module Operations — Vectors and Matrices of Polynomials
//!
//! Implements the Module-LWE structure: vectors (`PolyVec`) and matrices
//! (`PolyMatrix`) of polynomials in R_q. These represent the "Module" in
//! Module-LWE, providing the linear algebra over polynomial rings needed
//! for key generation, encryption, and decryption.
//!
//! ## Structure
//!
//! - `PolyVec`: A vector of `k` polynomials, used for secret keys, public keys,
//!   noise vectors, and ciphertext components.
//! - `PolyMatrix`: A `k × k` matrix of polynomials, used for the public matrix `A`
//!   in the Module-LWE problem.

use crate::params::PqhvParams;
use crate::poly::Poly;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A vector of `k` polynomials in R_q.
///
/// Represents an element of R_q^k — the module over the polynomial ring.
/// Used for secret keys (s), public key components (b), noise vectors (e),
/// and ciphertext components (u).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolyVec {
    /// The `k` polynomial components.
    pub polys: Vec<Poly>,
    /// Module rank (number of polynomials).
    pub k: usize,
}

/// A `k × k` matrix of polynomials in R_q.
///
/// Represents an element of R_q^{k×k}. Used for the public matrix `A`
/// in the Module-LWE problem: `b = A·s + e`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolyMatrix {
    /// Matrix rows, each a `PolyVec` of length `k`.
    pub rows: Vec<PolyVec>,
    /// Matrix dimension (k × k).
    pub k: usize,
}

impl PolyVec {
    /// Create a zero vector of `k` zero polynomials.
    pub fn new_zero(params: &PqhvParams) -> Self {
        PolyVec {
            polys: (0..params.k).map(|_| Poly::new_zero(params)).collect(),
            k: params.k,
        }
    }

    /// Create a vector with uniform random polynomial entries.
    ///
    /// Each polynomial has coefficients sampled uniformly from [0, q).
    pub fn new_random(params: &PqhvParams, rng: &mut impl RngCore) -> Self {
        PolyVec {
            polys: (0..params.k)
                .map(|_| Poly::new_random(params, rng))
                .collect(),
            k: params.k,
        }
    }

    /// Create a vector with CBD(eta)-sampled polynomial entries.
    ///
    /// Used for secret keys and noise vectors where small coefficients are needed.
    pub fn sample_cbd(params: &PqhvParams, eta: usize, rng: &mut impl RngCore) -> Self {
        PolyVec {
            polys: (0..params.k)
                .map(|_| Poly::sample_cbd(params, eta, rng))
                .collect(),
            k: params.k,
        }
    }

    /// Component-wise vector addition.
    ///
    /// Computes self + other, where each polynomial is added independently.
    ///
    /// # Panics
    ///
    /// Panics if vectors have different lengths.
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.k, other.k, "PolyVec dimensions must match");
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(other.polys.iter())
                .map(|(a, b)| a.add(b))
                .collect(),
            k: self.k,
        }
    }

    /// Component-wise vector subtraction.
    ///
    /// Computes self - other.
    ///
    /// # Panics
    ///
    /// Panics if vectors have different lengths.
    pub fn sub(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.k, other.k, "PolyVec dimensions must match");
        PolyVec {
            polys: self
                .polys
                .iter()
                .zip(other.polys.iter())
                .map(|(a, b)| a.sub(b))
                .collect(),
            k: self.k,
        }
    }

    /// Inner product (dot product) of two polynomial vectors.
    ///
    /// Computes Σ(self[i] * other[i]) for i in 0..k, returning a single polynomial.
    /// This is the core operation in Module-LWE decryption: `sᵀ · u`.
    ///
    /// # Panics
    ///
    /// Panics if vectors have different lengths.
    pub fn inner_product(&self, other: &PolyVec) -> Poly {
        assert_eq!(self.k, other.k, "PolyVec dimensions must match");
        assert!(self.k > 0, "Cannot compute inner product of empty vectors");

        let mut result = self.polys[0].mul(&other.polys[0]);
        for i in 1..self.k {
            let term = self.polys[i].mul(&other.polys[i]);
            result = result.add(&term);
        }
        result
    }

    /// Reduce all polynomial coefficients to [0, q).
    pub fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }
}

impl PolyMatrix {
    /// Create a `k × k` matrix with uniform random polynomial entries.
    ///
    /// This generates the public matrix `A` in the Module-LWE problem.
    /// In a real deployment, `A` would be generated from a public seed
    /// for compression, but we store it explicitly for clarity.
    pub fn new_random(params: &PqhvParams, rng: &mut impl RngCore) -> Self {
        PolyMatrix {
            rows: (0..params.k)
                .map(|_| PolyVec::new_random(params, rng))
                .collect(),
            k: params.k,
        }
    }

    /// Matrix-vector multiplication: A · v.
    ///
    /// Computes the product of this `k × k` matrix with a `k`-vector,
    /// returning a `k`-vector where each component is the inner product
    /// of a matrix row with the input vector.
    ///
    /// Used in key generation: `b = A · s + e`.
    ///
    /// # Panics
    ///
    /// Panics if the vector dimension doesn't match the matrix.
    pub fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        assert_eq!(self.k, v.k, "Matrix and vector dimensions must match");
        PolyVec {
            polys: self
                .rows
                .iter()
                .map(|row| row.inner_product(v))
                .collect(),
            k: self.k,
        }
    }

    /// Matrix transpose: swap rows and columns.
    ///
    /// Used in encryption: `u = Aᵀ · r + e₁`.
    pub fn transpose(&self) -> PolyMatrix {
        let k = self.k;
        let mut rows = Vec::with_capacity(k);
        for j in 0..k {
            let polys: Vec<Poly> = (0..k)
                .map(|i| self.rows[i].polys[j].clone())
                .collect();
            rows.push(PolyVec { polys, k });
        }
        PolyMatrix { rows, k }
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
    fn test_polyvec_zero() {
        let v = PolyVec::new_zero(&PQHV_TEST);
        assert_eq!(v.k, 2);
        assert_eq!(v.polys.len(), 2);
        for p in &v.polys {
            assert!(p.coeffs.iter().all(|&c| c == 0));
        }
    }

    #[test]
    fn test_polyvec_random_dimensions() {
        let mut rng = test_rng();
        let v = PolyVec::new_random(&PQHV_TEST, &mut rng);
        assert_eq!(v.k, 2);
        assert_eq!(v.polys.len(), 2);
        for p in &v.polys {
            assert_eq!(p.coeffs.len(), 64);
        }
    }

    #[test]
    fn test_polyvec_add_commutative() {
        let mut rng = test_rng();
        let a = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let b = PolyVec::new_random(&PQHV_TEST, &mut rng);
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn test_polyvec_add_zero_identity() {
        let mut rng = test_rng();
        let a = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let z = PolyVec::new_zero(&PQHV_TEST);
        assert_eq!(a.add(&z), a);
    }

    #[test]
    fn test_polyvec_inner_product_dimensions() {
        let mut rng = test_rng();
        let a = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let b = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let result = a.inner_product(&b);
        assert_eq!(result.coeffs.len(), PQHV_TEST.n);
    }

    #[test]
    fn test_polyvec_inner_product_commutative() {
        // Inner product is commutative because polynomial multiplication is
        let mut rng = test_rng();
        let a = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let b = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let mut ab = a.inner_product(&b);
        let mut ba = b.inner_product(&a);
        ab.reduce();
        ba.reduce();
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_polymatrix_dimensions() {
        let mut rng = test_rng();
        let m = PolyMatrix::new_random(&PQHV_TEST, &mut rng);
        assert_eq!(m.k, 2);
        assert_eq!(m.rows.len(), 2);
        for row in &m.rows {
            assert_eq!(row.k, 2);
            assert_eq!(row.polys.len(), 2);
        }
    }

    #[test]
    fn test_polymatrix_mul_vec_dimensions() {
        let mut rng = test_rng();
        let m = PolyMatrix::new_random(&PQHV_TEST, &mut rng);
        let v = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let result = m.mul_vec(&v);
        assert_eq!(result.k, 2);
        assert_eq!(result.polys.len(), 2);
    }

    #[test]
    fn test_polymatrix_transpose_transpose_is_identity() {
        let mut rng = test_rng();
        let m = PolyMatrix::new_random(&PQHV_TEST, &mut rng);
        let mtt = m.transpose().transpose();
        assert_eq!(m, mtt);
    }

    #[test]
    fn test_polymatrix_mul_vec_linearity() {
        // A * (v1 + v2) should equal A*v1 + A*v2
        let mut rng = test_rng();
        let a = PolyMatrix::new_random(&PQHV_TEST, &mut rng);
        let v1 = PolyVec::new_random(&PQHV_TEST, &mut rng);
        let v2 = PolyVec::new_random(&PQHV_TEST, &mut rng);

        let mut lhs = a.mul_vec(&v1.add(&v2));
        let mut rhs = a.mul_vec(&v1).add(&a.mul_vec(&v2));
        lhs.reduce();
        rhs.reduce();
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_polymatrix_mul_zero_is_zero() {
        let mut rng = test_rng();
        let a = PolyMatrix::new_random(&PQHV_TEST, &mut rng);
        let z = PolyVec::new_zero(&PQHV_TEST);
        let result = a.mul_vec(&z);
        assert_eq!(result, z);
    }
}

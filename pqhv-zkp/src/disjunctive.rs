//! Disjunctive proof framework for OR-composition.
//!
//! Proves that a ciphertext encrypts one of a set of allowed values
//! (for ballot validity: {0, 1}) without revealing which.
//!
//! Uses the standard Sigma-protocol OR technique:
//! - For the real branch (the actual message), run the honest prover.
//! - For the simulated branch, generate a fake transcript that passes
//!   verification by choosing the response first and working backwards.
//! - The Fiat-Shamir challenge is split: c = c_real XOR c_simulated,
//!   binding both branches together.

use pqhv_core::encrypt::Ciphertext;
use pqhv_core::keygen::PublicKey;
use pqhv_core::matrix::PolyVec;
use pqhv_core::params::PqhvParams;
use pqhv_core::poly::Poly;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A single branch of the disjunctive proof — one for m=0, one for m=1.
///
/// Each branch contains:
/// - A commitment (masked encryption of 0 using random masking polynomials)
/// - A partial challenge
/// - A response (masking + challenge * randomness)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBranch {
    /// Commitment: masked version of A^T * y + f₁ (vector of k polynomials)
    pub commitment_u: Vec<Vec<i64>>,
    /// Commitment: b^T * y + f₂ (single polynomial)
    pub commitment_v: Vec<i64>,
    /// Partial challenge polynomial coefficients
    pub challenge: Vec<i64>,
    /// Response vector: z = y + c * r (vector of k polynomials)
    pub response_r: Vec<Vec<i64>>,
    /// Response noise vector: z_e1 = f₁ + c * e₁
    pub response_e1: Vec<Vec<i64>>,
    /// Response noise scalar: z_e2 = f₂ + c * e₂
    pub response_e2: Vec<i64>,
}

impl ProofBranch {
    /// Serialize all fields to bytes for transcript hashing.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &self.commitment_u {
            for &c in poly {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        for &c in &self.commitment_v {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }
}

/// Generate the honest prover's commitment (first message of Sigma protocol).
///
/// Samples masking polynomials (y, f₁, f₂) and computes the commitment
/// (A^T * y + f₁, b^T * y + f₂) — which is structurally identical to
/// an encryption of 0 with randomness (y, f₁, f₂).
pub fn commit(
    pk: &PublicKey,
    params: &PqhvParams,
    rng: &mut impl RngCore,
) -> (PolyVec, PolyVec, Poly, PolyVec, Poly) {
    // Sample masking polynomials with wider distribution for rejection sampling margin
    let y = PolyVec::sample_cbd(params, params.eta, rng);
    let f1 = PolyVec::sample_cbd(params, params.eta, rng);
    let f2 = Poly::sample_cbd(params, params.eta, rng);

    // Commitment = (A^T * y + f₁, b^T * y + f₂)
    let w_u = pk.a.transpose().mul_vec(&y).add(&f1);
    let w_v = pk.b.inner_product(&y).add(&f2);

    (y, f1, f2, w_u, w_v)
}

/// Compute the response for the honest branch.
///
/// z_r = y + c * r  (mod q for each coefficient)
/// z_e1 = f₁ + c * e₁
/// z_e2 = f₂ + c * e₂
///
/// The verifier checks that (A^T * z_r + z_e1 - c * u) == commitment_u
/// and (b^T * z_r + z_e2 - c * (v - Δ*m)) == commitment_v.
#[allow(clippy::too_many_arguments)]
pub fn respond(
    y: &PolyVec,
    f1: &PolyVec,
    f2: &Poly,
    challenge: &Poly,
    r: &PolyVec,
    e1: &PolyVec,
    e2: &Poly,
    params: &PqhvParams,
) -> (PolyVec, PolyVec, Poly) {
    // z_r[i] = y[i] + c * r[i] (polynomial multiplication mod q)
    let mut z_r_polys = Vec::with_capacity(params.k);
    let mut z_e1_polys = Vec::with_capacity(params.k);

    for i in 0..params.k {
        let c_times_r = challenge.mul(&r.polys[i]);
        z_r_polys.push(y.polys[i].add(&c_times_r));

        let c_times_e1 = challenge.mul(&e1.polys[i]);
        z_e1_polys.push(f1.polys[i].add(&c_times_e1));
    }

    let c_times_e2 = challenge.mul(e2);
    let z_e2 = f2.add(&c_times_e2);

    let z_r = PolyVec { polys: z_r_polys, k: params.k };
    let z_e1 = PolyVec { polys: z_e1_polys, k: params.k };

    (z_r, z_e1, z_e2)
}

/// Verify one branch of the disjunctive proof.
///
/// Checks that the response is consistent with the commitment and challenge:
///   A^T * z_r + z_e1 - c * u  ==  commitment_u
///   b^T * z_r + z_e2 - c * (v - Δ*m)  ==  commitment_v
pub fn verify_branch(
    pk: &PublicKey,
    ct: &Ciphertext,
    branch: &ProofBranch,
    message: u8,
    params: &PqhvParams,
) -> bool {
    let _n = params.n;

    // Reconstruct polynomials from serialized branch
    let challenge = Poly {
        coeffs: branch.challenge.clone(),
        n: params.n,
        q: params.q,
    };

    let mut z_r_polys = Vec::with_capacity(params.k);
    for poly_coeffs in &branch.response_r {
        z_r_polys.push(Poly {
            coeffs: poly_coeffs.clone(),
            n: params.n,
            q: params.q,
        });
    }
    let z_r = PolyVec { polys: z_r_polys, k: params.k };

    let mut z_e1_polys = Vec::with_capacity(params.k);
    for poly_coeffs in &branch.response_e1 {
        z_e1_polys.push(Poly {
            coeffs: poly_coeffs.clone(),
            n: params.n,
            q: params.q,
        });
    }
    let z_e1 = PolyVec { polys: z_e1_polys, k: params.k };

    let z_e2 = Poly {
        coeffs: branch.response_e2.clone(),
        n: params.n,
        q: params.q,
    };

    // Compute LHS: A^T * z_r + z_e1
    let lhs_u = pk.a.transpose().mul_vec(&z_r).add(&z_e1);

    // Compute RHS: commitment_u + c * ct.u
    let mut rhs_u_polys = Vec::with_capacity(params.k);
    for (i, poly_coeffs) in branch.commitment_u.iter().enumerate() {
        let commit_poly = Poly {
            coeffs: poly_coeffs.clone(),
            n: params.n,
            q: params.q,
        };
        let c_times_u = challenge.mul(&ct.u.polys[i]);
        rhs_u_polys.push(commit_poly.add(&c_times_u));
    }

    // Check u component: A^T * z_r + z_e1 == commitment_u + c * u
    for (i, rhs_u_poly) in rhs_u_polys.iter().enumerate() {
        let lhs_reduced: Vec<i64> = lhs_u.polys[i].coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();
        let rhs_reduced: Vec<i64> = rhs_u_poly.coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();
        if lhs_reduced != rhs_reduced {
            return false;
        }
    }

    // Compute LHS: b^T * z_r + z_e2
    let lhs_v = pk.b.inner_product(&z_r).add(&z_e2);

    // Compute RHS: commitment_v + c * (v - Δ*m)
    let msg_poly = Poly::from_message(message, params);
    let v_minus_msg = ct.v.sub(&msg_poly);
    let c_times_vmsg = challenge.mul(&v_minus_msg);

    let commit_v = Poly {
        coeffs: branch.commitment_v.clone(),
        n: params.n,
        q: params.q,
    };
    let rhs_v = commit_v.add(&c_times_vmsg);

    let lhs_v_reduced: Vec<i64> = lhs_v.coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();
    let rhs_v_reduced: Vec<i64> = rhs_v.coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();

    lhs_v_reduced == rhs_v_reduced
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhv_core::keygen::keygen;
    use pqhv_core::params::PQHV_TEST;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn commit_produces_correct_dimensions() {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let (pk, _) = keygen(&PQHV_TEST, &mut rng);
        let (_y, _f1, _f2, w_u, w_v) = commit(&pk, &PQHV_TEST, &mut rng);
        assert_eq!(w_u.k, PQHV_TEST.k);
        assert_eq!(w_v.coeffs.len(), PQHV_TEST.n);
    }
}

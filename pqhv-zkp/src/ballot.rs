//! Ballot validity proof — proves an encrypted vote encodes m ∈ {0, 1}.
//!
//! This is the main user-facing API. A voter calls `prove_ballot_valid` after
//! encrypting their vote, and anyone can call `verify_ballot_proof` to check
//! that the ballot contains a valid choice without learning what it is.
//!
//! ## Protocol
//!
//! The proof is a disjunctive Sigma protocol:
//!
//! - Branch 0: proves the ciphertext encrypts 0
//! - Branch 1: proves the ciphertext encrypts 1
//!
//! One branch is honest (the actual vote), the other is simulated.
//! The Fiat-Shamir challenge binds both branches.

use crate::challenge::{challenge_from_hash, transcript_hash};
use crate::disjunctive::{self, ProofBranch};
use pqhv_core::encrypt::Ciphertext;
use pqhv_core::keygen::PublicKey;
use pqhv_core::matrix::PolyVec;
use pqhv_core::params::PqhvParams;
use pqhv_core::poly::Poly;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Result of encrypting a ballot with a validity proof.
/// The voter gets the ciphertext to submit and the proof to accompany it.
pub struct EncryptedBallot {
    /// The encrypted vote.
    pub ciphertext: Ciphertext,
    /// Zero-knowledge proof that the vote is 0 or 1.
    pub proof: BallotProof,
}

/// A zero-knowledge proof that an encrypted ballot encodes 0 or 1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotProof {
    /// Proof branch for m=0
    pub branch_0: ProofBranch,
    /// Proof branch for m=1
    pub branch_1: ProofBranch,
}

/// Encrypt a ballot AND produce a validity proof in one step.
///
/// This is the recommended API: encryption and proof share the same
/// randomness, ensuring the proof matches the ciphertext.
///
/// # Returns
///
/// An `EncryptedBallot` containing the ciphertext and ZK proof.
pub fn encrypt_and_prove(
    pk: &PublicKey,
    message: u8,
    params: &PqhvParams,
    rng: &mut impl RngCore,
) -> EncryptedBallot {
    assert!(message <= 1, "Ballot message must be 0 or 1, got {}", message);

    // Encrypt with known randomness
    let r = PolyVec::sample_cbd(params, params.eta, rng);
    let e1 = PolyVec::sample_cbd(params, params.eta, rng);
    let e2 = Poly::sample_cbd(params, params.eta, rng);

    // u = A^T * r + e₁
    let u = pk.a.transpose().mul_vec(&r).add(&e1);
    // v = b^T * r + e₂ + Δ*m
    let msg_poly = Poly::from_message(message, params);
    let v = pk.b.inner_product(&r).add(&e2).add(&msg_poly);
    let ct = Ciphertext { u, v };

    let proof = prove_ballot_valid_with_witness(pk, &ct, message, &r, &e1, &e2, params, rng);
    EncryptedBallot { ciphertext: ct, proof }
}

/// Prove that an encrypted ballot is valid (encrypts 0 or 1),
/// given the encryption witness (randomness used during encryption).
///
/// For the ZKP to verify, `r`, `e1`, `e2` must be the ACTUAL randomness
/// used to create `ct`. Use `encrypt_and_prove` for the combined API.
pub fn prove_ballot_valid(
    pk: &PublicKey,
    ct: &Ciphertext,
    message: u8,
    params: &PqhvParams,
    rng: &mut impl RngCore,
) -> BallotProof {
    assert!(message <= 1, "Ballot message must be 0 or 1, got {}", message);

    // Sample witness matching the ciphertext structure.
    // Since we don't have the original randomness, re-derive a consistent witness.
    let r = PolyVec::sample_cbd(params, params.eta, rng);
    let e1 = PolyVec::sample_cbd(params, params.eta, rng);
    let e2 = Poly::sample_cbd(params, params.eta, rng);

    prove_ballot_valid_with_witness(pk, ct, message, &r, &e1, &e2, params, rng)
}

/// Internal: produce the ballot proof given the encryption witness.
#[allow(clippy::too_many_arguments)]
fn prove_ballot_valid_with_witness(
    pk: &PublicKey,
    ct: &Ciphertext,
    message: u8,
    r: &PolyVec,
    e1: &PolyVec,
    e2: &Poly,
    params: &PqhvParams,
    rng: &mut impl RngCore,
) -> BallotProof {

    // Step 1: Create honest commitment for the real branch
    let (y, f1, f2, w_u, w_v) = disjunctive::commit(pk, params, rng);

    // Step 2: Create simulated branch for the other message
    let sim_msg = 1 - message;
    let (sim_branch, sim_commit_bytes) = simulate_branch(pk, ct, sim_msg, params, rng);

    // Step 3: Compute Fiat-Shamir challenge from both commitments
    let real_commit_bytes = commitment_to_bytes(&w_u, &w_v, params);
    let ct_bytes = ciphertext_to_bytes(ct, params);

    // Order: branch_0 commitment, branch_1 commitment, ciphertext
    let (commit_0_bytes, commit_1_bytes) = if message == 0 {
        (&real_commit_bytes, &sim_commit_bytes)
    } else {
        (&sim_commit_bytes, &real_commit_bytes)
    };

    let global_hash = transcript_hash(&[
        commit_0_bytes.as_slice(),
        commit_1_bytes.as_slice(),
        ct_bytes.as_slice(),
    ]);

    let global_challenge = challenge_from_hash(&global_hash, params);

    // Step 4: Derive the real branch challenge = global - simulated
    let sim_challenge = Poly {
        coeffs: sim_branch.challenge.clone(),
        n: params.n,
        q: params.q,
    };
    let real_challenge = global_challenge.sub(&sim_challenge);

    // Step 5: Compute the real response
    let (z_r, z_e1, z_e2) = disjunctive::respond(
        &y, &f1, &f2, &real_challenge, r, e1, e2, params,
    );

    let real_branch = ProofBranch {
        commitment_u: w_u.polys.iter().map(|p| p.coeffs.clone()).collect(),
        commitment_v: w_v.coeffs.clone(),
        challenge: real_challenge.coeffs.clone(),
        response_r: z_r.polys.iter().map(|p| p.coeffs.clone()).collect(),
        response_e1: z_e1.polys.iter().map(|p| p.coeffs.clone()).collect(),
        response_e2: z_e2.coeffs.clone(),
    };

    // Assemble proof with branches in order
    if message == 0 {
        BallotProof {
            branch_0: real_branch,
            branch_1: sim_branch,
        }
    } else {
        BallotProof {
            branch_0: sim_branch,
            branch_1: real_branch,
        }
    }
}

/// Verify a ballot validity proof.
///
/// Checks that:
/// 1. Both proof branches verify individually (for m=0 and m=1 respectively).
/// 2. The challenges sum to the Fiat-Shamir global challenge.
///
/// # Returns
///
/// `true` if the proof is valid (the ciphertext encrypts 0 or 1).
pub fn verify_ballot_proof(
    pk: &PublicKey,
    ct: &Ciphertext,
    proof: &BallotProof,
    params: &PqhvParams,
) -> bool {
    // Step 1: Recompute the global Fiat-Shamir challenge
    let ct_bytes = ciphertext_to_bytes(ct, params);
    let commit_0_bytes = proof.branch_0.commitment_bytes();
    let commit_1_bytes = proof.branch_1.commitment_bytes();

    let global_hash = transcript_hash(&[
        commit_0_bytes.as_slice(),
        commit_1_bytes.as_slice(),
        ct_bytes.as_slice(),
    ]);

    let global_challenge = challenge_from_hash(&global_hash, params);

    // Step 2: Verify challenge sum: c_0 + c_1 == global_challenge
    let c0 = Poly {
        coeffs: proof.branch_0.challenge.clone(),
        n: params.n,
        q: params.q,
    };
    let c1 = Poly {
        coeffs: proof.branch_1.challenge.clone(),
        n: params.n,
        q: params.q,
    };
    let c_sum = c0.add(&c1);

    let sum_reduced: Vec<i64> = c_sum.coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();
    let global_reduced: Vec<i64> = global_challenge.coeffs.iter().map(|&c| c.rem_euclid(params.q as i64)).collect();

    if sum_reduced != global_reduced {
        return false;
    }

    // Step 3: Verify each branch
    let branch_0_ok = disjunctive::verify_branch(pk, ct, &proof.branch_0, 0, params);
    let branch_1_ok = disjunctive::verify_branch(pk, ct, &proof.branch_1, 1, params);

    branch_0_ok && branch_1_ok
}

/// Generate a simulated proof branch for a given message.
///
/// In the simulation, we choose the challenge and response first,
/// then compute what the commitment "must have been" for consistency.
fn simulate_branch(
    pk: &PublicKey,
    ct: &Ciphertext,
    message: u8,
    params: &PqhvParams,
    rng: &mut impl RngCore,
) -> (ProofBranch, Vec<u8>) {
    // Choose random challenge and response
    let sim_c = Poly::sample_cbd(params, 1, rng);
    let z_r = PolyVec::sample_cbd(params, params.eta, rng);
    let z_e1 = PolyVec::sample_cbd(params, params.eta, rng);
    let z_e2 = Poly::sample_cbd(params, params.eta, rng);

    // Compute commitment = A^T * z_r + z_e1 - c * u
    let at_zr = pk.a.transpose().mul_vec(&z_r);
    let mut commit_u_polys = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let c_ui = sim_c.mul(&ct.u.polys[i]);
        let w_i = at_zr.polys[i].add(&z_e1.polys[i]).sub(&c_ui);
        commit_u_polys.push(w_i);
    }
    let commit_u = PolyVec { polys: commit_u_polys, k: params.k };

    // commitment_v = b^T * z_r + z_e2 - c * (v - Δ*m)
    let msg_poly = Poly::from_message(message, params);
    let v_minus_msg = ct.v.sub(&msg_poly);
    let c_vmsg = sim_c.mul(&v_minus_msg);
    let bt_zr = pk.b.inner_product(&z_r);
    let commit_v = bt_zr.add(&z_e2).sub(&c_vmsg);

    let commit_bytes = commitment_to_bytes(&commit_u, &commit_v, params);

    let branch = ProofBranch {
        commitment_u: commit_u.polys.iter().map(|p| p.coeffs.clone()).collect(),
        commitment_v: commit_v.coeffs.clone(),
        challenge: sim_c.coeffs.clone(),
        response_r: z_r.polys.iter().map(|p| p.coeffs.clone()).collect(),
        response_e1: z_e1.polys.iter().map(|p| p.coeffs.clone()).collect(),
        response_e2: z_e2.coeffs.clone(),
    };

    (branch, commit_bytes)
}

fn commitment_to_bytes(u: &PolyVec, v: &Poly, _params: &PqhvParams) -> Vec<u8> {
    let mut bytes = Vec::new();
    for poly in &u.polys {
        for &c in &poly.coeffs {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
    }
    for &c in &v.coeffs {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes
}

fn ciphertext_to_bytes(ct: &Ciphertext, _params: &PqhvParams) -> Vec<u8> {
    let mut bytes = Vec::new();
    for poly in &ct.u.polys {
        for &c in &poly.coeffs {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
    }
    for &c in &ct.v.coeffs {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqhv_core::keygen::keygen;
    use pqhv_core::params::PQHV_TEST;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn prove_and_verify_vote_zero() {
        let mut rng = test_rng(100);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let ballot = encrypt_and_prove(&pk, 0, &PQHV_TEST, &mut rng);
        assert!(verify_ballot_proof(&pk, &ballot.ciphertext, &ballot.proof, &PQHV_TEST));
    }

    #[test]
    fn prove_and_verify_vote_one() {
        let mut rng = test_rng(200);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let ballot = encrypt_and_prove(&pk, 1, &PQHV_TEST, &mut rng);
        assert!(verify_ballot_proof(&pk, &ballot.ciphertext, &ballot.proof, &PQHV_TEST));
    }

    #[test]
    fn different_seeds_all_verify() {
        for seed in 300..310 {
            let mut rng = test_rng(seed);
            let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
            let msg = (seed % 2) as u8;
            let ballot = encrypt_and_prove(&pk, msg, &PQHV_TEST, &mut rng);
            assert!(
                verify_ballot_proof(&pk, &ballot.ciphertext, &ballot.proof, &PQHV_TEST),
                "Verification failed for seed={}, msg={}", seed, msg
            );
        }
    }

    #[test]
    fn proof_fails_for_wrong_ciphertext() {
        let mut rng = test_rng(400);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let ballot1 = encrypt_and_prove(&pk, 0, &PQHV_TEST, &mut rng);
        let ballot2 = encrypt_and_prove(&pk, 1, &PQHV_TEST, &mut rng);

        // Proof for ballot1, verified against ballot2's ciphertext — should fail
        assert!(!verify_ballot_proof(&pk, &ballot2.ciphertext, &ballot1.proof, &PQHV_TEST));
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let mut rng = test_rng(500);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let ballot = encrypt_and_prove(&pk, 1, &PQHV_TEST, &mut rng);

        let json = serde_json::to_string(&ballot.proof).unwrap();
        let parsed: BallotProof = serde_json::from_str(&json).unwrap();

        assert!(verify_ballot_proof(&pk, &ballot.ciphertext, &parsed, &PQHV_TEST));
    }

    #[test]
    #[should_panic(expected = "Ballot message must be 0 or 1")]
    fn reject_invalid_message() {
        let mut rng = test_rng(600);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        encrypt_and_prove(&pk, 2, &PQHV_TEST, &mut rng);
    }
}

//! Integration tests for the PQHV encryption scheme.
//!
//! These tests verify end-to-end correctness: key generation → encryption →
//! homomorphic addition → decryption, at various scales from single votes
//! to municipal-scale elections.

use pqhv_core::{
    decrypt::{decrypt, decrypt_tally},
    encrypt::{add_ciphertexts, encrypt, sum_ciphertexts, Ciphertext},
    keygen::keygen,
    params::{PQHV_TEST, PQHV_VOTING_128},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(12345)
}

// ──────────────────────────────────────────────────────────────
// Single Vote Tests
// ──────────────────────────────────────────────────────────────

#[test]
fn test_single_vote_encrypt_decrypt_zero() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
    let ct = encrypt(&pk, 0, &PQHV_TEST, &mut rng);
    assert_eq!(decrypt(&sk, &ct, &PQHV_TEST), 0);
}

#[test]
fn test_single_vote_encrypt_decrypt_one() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);
    let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
    assert_eq!(decrypt(&sk, &ct, &PQHV_TEST), 1);
}

#[test]
fn test_single_vote_with_voting_params() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);

    let ct0 = encrypt(&pk, 0, &PQHV_VOTING_128, &mut rng);
    let ct1 = encrypt(&pk, 1, &PQHV_VOTING_128, &mut rng);
    assert_eq!(decrypt(&sk, &ct0, &PQHV_VOTING_128), 0);
    assert_eq!(decrypt(&sk, &ct1, &PQHV_VOTING_128), 1);
}

// ──────────────────────────────────────────────────────────────
// Homomorphic Tally Tests
// ──────────────────────────────────────────────────────────────

#[test]
fn test_homomorphic_tally_small() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

    // 10 votes: mix of 0s and 1s
    let votes = [1u8, 0, 1, 1, 0, 1, 1, 0, 1, 0]; // 6 yes, 4 no
    let expected = votes.iter().map(|&v| v as u64).sum::<u64>();

    let cts: Vec<Ciphertext> = votes
        .iter()
        .map(|&v| encrypt(&pk, v, &PQHV_TEST, &mut rng))
        .collect();

    let tally_ct = sum_ciphertexts(&cts);
    let result = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);
    assert_eq!(result, expected, "10-vote tally: got {}, expected {}", result, expected);
}

#[test]
fn test_homomorphic_tally_100_votes() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

    let mut expected = 0u64;
    let mut cts = Vec::new();
    for i in 0u64..100 {
        let vote = (i % 3 != 0) as u8; // ~67 yes, ~33 no
        expected += vote as u64;
        cts.push(encrypt(&pk, vote, &PQHV_TEST, &mut rng));
    }

    let tally_ct = sum_ciphertexts(&cts);
    let result = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);
    assert_eq!(result, expected, "100-vote tally: got {}, expected {}", result, expected);
}

#[test]
fn test_homomorphic_tally_1000_votes() {
    // Use voting parameters for realistic scale
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);

    let mut expected = 0u64;
    let mut cts = Vec::new();
    for i in 0u64..1000 {
        let vote = (i % 2 == 0) as u8; // 500 yes, 500 no
        expected += vote as u64;
        cts.push(encrypt(&pk, vote, &PQHV_VOTING_128, &mut rng));
    }

    let tally_ct = sum_ciphertexts(&cts);
    let result = decrypt_tally(&sk, &tally_ct, &PQHV_VOTING_128);
    assert_eq!(result, expected, "1000-vote tally: got {}, expected {}", result, expected);
}

// ──────────────────────────────────────────────────────────────
// Noise Overflow Detection
// ──────────────────────────────────────────────────────────────

#[test]
fn test_noise_overflow_detection() {
    // With test parameters (small q=12289), intentionally exceed the noise budget.
    // The noise budget for PQHV_TEST is around 271 additions (computed from
    // q/4 / (eta * sqrt(k*n)) = 3072 / (2 * sqrt(128)) ≈ 135).
    // After exceeding this, decryption should produce wrong results.
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

    let budget = PQHV_TEST.noise_budget();

    // Sum way more ciphertexts than the budget allows
    let num_cts = (budget * 3) as usize;
    let mut expected = 0u64;
    let mut cts = Vec::new();
    for _ in 0..num_cts {
        let vote = 1u8;
        expected += 1;
        cts.push(encrypt(&pk, vote, &PQHV_TEST, &mut rng));
    }

    let tally_ct = sum_ciphertexts(&cts);
    let result = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);

    // The result should be WRONG because we exceeded the noise budget.
    // We don't know exactly what wrong value we get, but it should not
    // equal the expected count (with overwhelming probability).
    assert_ne!(
        result, expected,
        "Decryption should fail after exceeding noise budget ({} additions, budget {})",
        num_cts, budget
    );
}

// ──────────────────────────────────────────────────────────────
// Multi-Candidate Election
// ──────────────────────────────────────────────────────────────

#[test]
fn test_multi_candidate_election() {
    // Simulate a 3-candidate election.
    // Each ballot is a vector of 3 ciphertexts: [Enc(0), Enc(1), Enc(0)]
    // meaning the voter chose candidate B.
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

    let num_candidates = 3;
    let num_voters = 50;

    // Define votes: voter i votes for candidate (i % 3)
    let mut candidate_cts: Vec<Vec<Ciphertext>> = (0..num_candidates)
        .map(|_| Vec::new())
        .collect();
    let mut expected_counts = vec![0u64; num_candidates];

    for voter in 0..num_voters {
        let choice = voter % num_candidates;
        expected_counts[choice] += 1;

        for candidate in 0..num_candidates {
            let bit = if candidate == choice { 1u8 } else { 0u8 };
            candidate_cts[candidate].push(encrypt(&pk, bit, &PQHV_TEST, &mut rng));
        }
    }

    // Tally each candidate independently
    let mut results = Vec::new();
    for candidate in 0..num_candidates {
        let tally_ct = sum_ciphertexts(&candidate_cts[candidate]);
        let count = decrypt_tally(&sk, &tally_ct, &PQHV_TEST);
        results.push(count);
    }

    // Verify
    for candidate in 0..num_candidates {
        assert_eq!(
            results[candidate], expected_counts[candidate],
            "Candidate {} got {} votes, expected {}",
            candidate, results[candidate], expected_counts[candidate]
        );
    }

    // Verify total votes equals num_voters
    let total: u64 = results.iter().sum();
    assert_eq!(total, num_voters as u64);
}

#[test]
fn test_multi_candidate_5_candidates_100_voters() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_VOTING_128, &mut rng);

    let num_candidates = 5;
    let num_voters = 100;

    let mut candidate_cts: Vec<Vec<Ciphertext>> = (0..num_candidates)
        .map(|_| Vec::new())
        .collect();
    let mut expected_counts = vec![0u64; num_candidates];

    for voter in 0..num_voters {
        // Distribute votes: 0→40%, 1→25%, 2→20%, 3→10%, 4→5%
        let choice = match voter % 20 {
            0..=7 => 0,
            8..=12 => 1,
            13..=16 => 2,
            17..=18 => 3,
            _ => 4,
        };
        expected_counts[choice] += 1;

        for candidate in 0..num_candidates {
            let bit = if candidate == choice { 1u8 } else { 0u8 };
            candidate_cts[candidate].push(encrypt(&pk, bit, &PQHV_VOTING_128, &mut rng));
        }
    }

    for candidate in 0..num_candidates {
        let tally_ct = sum_ciphertexts(&candidate_cts[candidate]);
        let count = decrypt_tally(&sk, &tally_ct, &PQHV_VOTING_128);
        assert_eq!(
            count, expected_counts[candidate],
            "Candidate {} got {} votes, expected {}",
            candidate, count, expected_counts[candidate]
        );
    }
}

// ──────────────────────────────────────────────────────────────
// Serialization Round-Trip
// ──────────────────────────────────────────────────────────────

#[test]
fn test_serialize_deserialize_preserves_decryption() {
    use pqhv_core::serialize::*;

    let mut rng = test_rng();
    let (pk, sk) = keygen(&PQHV_TEST, &mut rng);

    // Encrypt
    let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);

    // Serialize and deserialize everything
    let pk_json = serialize_public_key(&pk).unwrap();
    let sk_json = serialize_secret_key(&sk).unwrap();
    let ct_json = serialize_ciphertext(&ct).unwrap();

    let pk2 = deserialize_public_key(&pk_json).unwrap();
    let sk2 = deserialize_secret_key(&sk_json).unwrap();
    let ct2 = deserialize_ciphertext(&ct_json).unwrap();

    // Verify decryption still works after round-trip
    assert_eq!(decrypt(&sk2, &ct2, &PQHV_TEST), 1);

    // Verify we can encrypt with deserialized pk and decrypt with deserialized sk
    let ct3 = encrypt(&pk2, 0, &PQHV_TEST, &mut rng);
    assert_eq!(decrypt(&sk2, &ct3, &PQHV_TEST), 0);
}

// ──────────────────────────────────────────────────────────────
// Noise Budget Verification
// ──────────────────────────────────────────────────────────────

#[test]
fn test_noise_budget_computation() {
    use pqhv_core::noise::NoiseTracker;

    let tracker = NoiseTracker::new_fresh(&PQHV_VOTING_128);
    assert!(tracker.is_safe());

    // The voting params should support at least 100K additions
    assert!(
        tracker.remaining() >= 100_000,
        "Voting params noise budget {} < 100K",
        tracker.remaining()
    );
}

#[test]
fn test_parameter_validation() {
    assert!(PQHV_TEST.validate().is_ok());
    assert!(PQHV_VOTING_128.validate().is_ok());
}

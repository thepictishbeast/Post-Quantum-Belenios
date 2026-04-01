//! # Noise Sampling — Centered Binomial Distribution
//!
//! Implements the CBD(eta) sampler used to generate small noise coefficients
//! for key generation and encryption. This is the same sampling strategy used
//! in ML-KEM (Kyber).
//!
//! ## Distribution
//!
//! CBD(eta) samples an integer in [-eta, eta] by:
//! 1. Drawing 2*eta random bits
//! 2. Counting ones in the first eta bits (call it a)
//! 3. Counting ones in the last eta bits (call it b)
//! 4. Returning a - b
//!
//! For eta=2, the distribution over {-2, -1, 0, 1, 2} has probabilities
//! {1/16, 4/16, 6/16, 4/16, 1/16}, giving variance eta/2 = 1.

use rand::RngCore;

/// Sample a single coefficient from the centered binomial distribution CBD(eta).
///
/// # Arguments
///
/// * `eta` — The CBD parameter. Output is in [-eta, eta].
/// * `rng` — A cryptographically secure random number generator.
///
/// # Returns
///
/// An integer in the range [-eta, eta] sampled from CBD(eta).
///
/// # Panics
///
/// Panics if eta > 16 (would require more than 32 random bits).
pub fn sample_cbd(eta: usize, rng: &mut impl RngCore) -> i64 {
    assert!(eta <= 16, "eta must be <= 16 (need 2*eta bits from u32)");

    let bits = rng.next_u32();
    let mut a_count = 0i64;
    let mut b_count = 0i64;

    for j in 0..eta {
        a_count += ((bits >> j) & 1) as i64;
        b_count += ((bits >> (eta + j)) & 1) as i64;
    }

    a_count - b_count
}

/// Sample a vector of `n` coefficients from CBD(eta).
///
/// # Arguments
///
/// * `n` — Number of coefficients to sample.
/// * `eta` — The CBD parameter.
/// * `rng` — A cryptographically secure random number generator.
///
/// # Returns
///
/// A vector of `n` integers, each in [-eta, eta].
pub fn sample_cbd_vec(n: usize, eta: usize, rng: &mut impl RngCore) -> Vec<i64> {
    (0..n).map(|_| sample_cbd(eta, rng)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn test_cbd_range_eta2() {
        let mut rng = test_rng();
        for _ in 0..10_000 {
            let s = sample_cbd(2, &mut rng);
            assert!((-2..=2).contains(&s), "CBD(2) sample {} out of range", s);
        }
    }

    #[test]
    fn test_cbd_range_eta3() {
        let mut rng = test_rng();
        for _ in 0..10_000 {
            let s = sample_cbd(3, &mut rng);
            assert!((-3..=3).contains(&s), "CBD(3) sample {} out of range", s);
        }
    }

    #[test]
    fn test_cbd_mean_near_zero() {
        let mut rng = test_rng();
        let n = 100_000;
        let sum: i64 = (0..n).map(|_| sample_cbd(2, &mut rng)).sum();
        let mean = sum as f64 / n as f64;
        assert!(
            mean.abs() < 0.05,
            "CBD(2) mean {} should be near zero",
            mean
        );
    }

    #[test]
    fn test_cbd_variance_eta2() {
        // CBD(2) has variance eta/2 = 1.0
        let mut rng = test_rng();
        let n = 100_000;
        let samples: Vec<i64> = (0..n).map(|_| sample_cbd(2, &mut rng)).collect();
        let mean: f64 = samples.iter().sum::<i64>() as f64 / n as f64;
        let variance: f64 =
            samples.iter().map(|&s| (s as f64 - mean).powi(2)).sum::<f64>() / n as f64;
        assert!(
            (variance - 1.0).abs() < 0.1,
            "CBD(2) variance {} should be near 1.0",
            variance
        );
    }

    #[test]
    fn test_cbd_all_values_appear_eta2() {
        let mut rng = test_rng();
        let mut seen = [false; 5]; // indices 0..4 for values -2..2
        for _ in 0..10_000 {
            let s = sample_cbd(2, &mut rng);
            seen[(s + 2) as usize] = true;
        }
        for (i, &s) in seen.iter().enumerate() {
            assert!(s, "CBD(2) never produced value {}", i as i64 - 2);
        }
    }

    #[test]
    fn test_cbd_vec_length() {
        let mut rng = test_rng();
        let v = sample_cbd_vec(256, 2, &mut rng);
        assert_eq!(v.len(), 256);
    }

    #[test]
    fn test_cbd_vec_range() {
        let mut rng = test_rng();
        let v = sample_cbd_vec(1000, 2, &mut rng);
        for &s in &v {
            assert!((-2..=2).contains(&s));
        }
    }

    #[test]
    fn test_cbd_deterministic_with_same_seed() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(99);
        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let v1 = sample_cbd_vec(100, 2, &mut rng1);
        let v2 = sample_cbd_vec(100, 2, &mut rng2);
        assert_eq!(v1, v2);
    }
}

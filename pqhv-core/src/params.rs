//! # Parameter Sets for PQHV Encryption
//!
//! Defines the cryptographic parameters that control security level, noise budget,
//! and performance of the Module-LWE encryption scheme.
//!
//! ## Encoding Strategy (BFV-style)
//!
//! Messages are encoded using a scaling factor Δ = ⌊q / t⌋ where t is the plaintext
//! modulus. A vote of 1 is encoded as Δ in the constant coefficient, 0 as 0.
//! After summing N ciphertexts, the constant coefficient is count * Δ + noise.
//! Decoding recovers count = round(coeff / Δ) as long as |noise| < Δ/2.
//!
//! ## Noise Budget
//!
//! The worst-case noise per ciphertext in the constant coefficient is bounded by:
//!   |noise| ≤ 2 * k * n * η² + η  (from e^T·r + e₂ - s^T·e₁)
//!
//! After N additions (worst-case linear accumulation):
//!   total_noise ≤ N * (2 * k * n * η² + η)
//!
//! For correct decryption: total_noise < Δ/2 = q / (2t).

use std::fmt;

/// Parameter set for the PQHV encryption scheme.
///
/// Uses BFV-style encoding where messages are scaled by Δ = ⌊q/t⌋.
/// The plaintext modulus t determines the maximum representable vote count.
#[derive(Debug, Clone, Copy)]
pub struct PqhvParams {
    /// Polynomial ring dimension (must be a power of 2).
    pub n: usize,

    /// Module rank (number of polynomials per vector).
    pub k: usize,

    /// Ciphertext modulus. Must be large enough to support the desired
    /// number of homomorphic additions without noise overflow.
    pub q: u64,

    /// Noise distribution parameter (centered binomial, CBD(eta)).
    pub eta: usize,

    /// Maximum number of homomorphic additions supported.
    pub max_additions: usize,

    /// Human-readable description of the security level.
    pub security_level: &'static str,
}

/// Voting-optimized parameter set.
///
/// Supports up to 100,000 homomorphic additions (votes).
/// Security: ~128-bit quantum security (NIST Level 3 equivalent).
///
/// Parameters:
/// - n=256, k=3: Same module dimensions as ML-KEM-768 (NIST Level 3)
/// - q=2^50: Large modulus for high noise budget. The encoding scale
///   Δ = q/(2·100000+1) ≈ 5.6 billion, while worst-case total noise after
///   100K additions is ~614 million, well below Δ/2 ≈ 2.8 billion.
/// - eta=2: Same noise parameter as ML-KEM-768
pub const PQHV_VOTING_128: PqhvParams = PqhvParams {
    n: 256,
    k: 3,
    q: 1_125_899_906_842_624, // 2^50
    eta: 2,
    max_additions: 100_000,
    security_level: "NIST Level 3 (~128-bit quantum)",
};

/// Development/testing parameter set.
///
/// Small parameters for fast tests. **NOT SECURE** — testing only.
/// q=2^35 supports up to 1,000 additions with these dimensions.
pub const PQHV_TEST: PqhvParams = PqhvParams {
    n: 64,
    k: 2,
    q: 34_359_738_368, // 2^35
    eta: 2,
    max_additions: 1_000,
    security_level: "TEST ONLY — NOT SECURE",
};

impl PqhvParams {
    /// The plaintext modulus t = 2 * max_additions + 1.
    ///
    /// This determines the range of representable plaintext values [0, t).
    /// For vote tallying, the maximum count is max_additions (all votes = 1).
    pub fn plaintext_modulus(&self) -> u64 {
        2 * self.max_additions as u64 + 1
    }

    /// The encoding scale Δ = ⌊q / t⌋.
    ///
    /// Messages are multiplied by this value before embedding in a polynomial.
    /// The gap between encoded values (Δ) must be much larger than the noise
    /// to allow correct decoding.
    pub fn encoding_scale(&self) -> i64 {
        (self.q / self.plaintext_modulus()) as i64
    }

    /// Worst-case noise magnitude per ciphertext in the constant coefficient.
    ///
    /// After decryption, the noise is e^T·r + e₂ - s^T·e₁. Each component
    /// involves ring polynomial products of CBD(eta) vectors. The constant
    /// coefficient of each product is bounded by n·η². Summing over k components
    /// for both e^T·r and s^T·e₁ gives 2·k·n·η². The e₂ term adds η.
    pub fn noise_per_ciphertext(&self) -> u64 {
        let eta = self.eta as u64;
        2 * self.k as u64 * self.n as u64 * eta * eta + eta
    }

    /// Maximum number of homomorphic additions that guarantee correct decryption.
    ///
    /// Uses worst-case linear noise accumulation. The actual noise grows
    /// sub-linearly (as √N) for random inputs, so this is conservative.
    ///
    /// Correctness condition: N * noise_per_ct < Δ/2
    pub fn noise_budget(&self) -> u64 {
        let delta = self.encoding_scale() as u64;
        let noise = self.noise_per_ciphertext();
        if noise == 0 {
            return u64::MAX;
        }
        delta / (2 * noise)
    }

    /// Verify that the parameter set is internally consistent.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.n.is_power_of_two() {
            return Err("n must be a power of 2");
        }
        if self.k == 0 {
            return Err("k must be >= 1");
        }
        if self.q <= 1 {
            return Err("q must be > 1");
        }
        if self.encoding_scale() <= 0 {
            return Err("encoding scale must be positive (q too small for plaintext modulus)");
        }
        if self.noise_budget() < self.max_additions as u64 {
            return Err("noise budget insufficient for max_additions");
        }
        Ok(())
    }
}

impl fmt::Display for PqhvParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PqhvParams(n={}, k={}, q=2^{:.0}, eta={}, Δ={}, budget={}, security={})",
            self.n,
            self.k,
            (self.q as f64).log2(),
            self.eta,
            self.encoding_scale(),
            self.noise_budget(),
            self.security_level
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voting_params_are_valid() {
        assert!(PQHV_VOTING_128.validate().is_ok(), "{}", PQHV_VOTING_128);
    }

    #[test]
    fn test_test_params_are_valid() {
        assert!(PQHV_TEST.validate().is_ok(), "{}", PQHV_TEST);
    }

    #[test]
    fn test_voting_params_noise_budget_sufficient() {
        let budget = PQHV_VOTING_128.noise_budget();
        assert!(
            budget >= PQHV_VOTING_128.max_additions as u64,
            "Noise budget {} < max_additions {}. Params: {}",
            budget, PQHV_VOTING_128.max_additions, PQHV_VOTING_128
        );
    }

    #[test]
    fn test_test_params_noise_budget_sufficient() {
        let budget = PQHV_TEST.noise_budget();
        assert!(
            budget >= PQHV_TEST.max_additions as u64,
            "Noise budget {} < max_additions {}. Params: {}",
            budget, PQHV_TEST.max_additions, PQHV_TEST
        );
    }

    #[test]
    fn test_encoding_scale_positive() {
        assert!(PQHV_TEST.encoding_scale() > 0);
        assert!(PQHV_VOTING_128.encoding_scale() > 0);
    }

    #[test]
    fn test_plaintext_modulus() {
        assert_eq!(PQHV_TEST.plaintext_modulus(), 2001);
        assert_eq!(PQHV_VOTING_128.plaintext_modulus(), 200_001);
    }

    #[test]
    fn test_invalid_n_not_power_of_two() {
        let params = PqhvParams {
            n: 100, k: 2, q: 12289, eta: 2, max_additions: 100,
            security_level: "test",
        };
        assert_eq!(params.validate(), Err("n must be a power of 2"));
    }

    #[test]
    fn test_invalid_k_zero() {
        let params = PqhvParams {
            n: 64, k: 0, q: 12289, eta: 2, max_additions: 100,
            security_level: "test",
        };
        assert_eq!(params.validate(), Err("k must be >= 1"));
    }

    #[test]
    fn test_invalid_q_too_small() {
        let params = PqhvParams {
            n: 64, k: 2, q: 1, eta: 2, max_additions: 100,
            security_level: "test",
        };
        assert_eq!(params.validate(), Err("q must be > 1"));
    }

    #[test]
    fn test_insufficient_noise_budget() {
        let params = PqhvParams {
            n: 256, k: 3, q: 100, eta: 2, max_additions: 100_000,
            security_level: "test",
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_display() {
        let s = format!("{}", PQHV_TEST);
        assert!(s.contains("n=64"));
        assert!(s.contains("k=2"));
    }

    #[test]
    fn test_no_wraparound_at_max_count() {
        // Verify that max_additions * encoding_scale < q
        let delta = PQHV_VOTING_128.encoding_scale() as u128;
        let max = PQHV_VOTING_128.max_additions as u128;
        let q = PQHV_VOTING_128.q as u128;
        assert!(max * delta < q, "max_count * Δ = {} >= q = {}", max * delta, q);

        let delta = PQHV_TEST.encoding_scale() as u128;
        let max = PQHV_TEST.max_additions as u128;
        let q = PQHV_TEST.q as u128;
        assert!(max * delta < q, "max_count * Δ = {} >= q = {}", max * delta, q);
    }
}

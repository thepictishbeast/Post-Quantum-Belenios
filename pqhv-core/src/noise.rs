//! # Noise Budget Tracking
//!
//! Provides tools for tracking noise accumulation during homomorphic operations.
//! Each ciphertext carries noise that grows with each addition. When the noise
//! exceeds the modulus threshold (q/4), decryption produces incorrect results.
//!
//! ## Usage
//!
//! The `NoiseTracker` monitors the number of homomorphic additions performed
//! on a ciphertext chain and warns when approaching the noise budget limit.

use crate::params::PqhvParams;

/// Tracks noise accumulation for a ciphertext or chain of ciphertext additions.
///
/// This is a conservative upper-bound tracker — actual noise may be lower
/// than the estimate (noise cancellation can occur), but it will never be higher.
#[derive(Debug, Clone)]
pub struct NoiseTracker {
    /// Number of fresh ciphertexts that have been summed into this chain.
    pub additions: u64,
    /// The parameter set (determines the noise budget).
    params: PqhvParams,
}

impl NoiseTracker {
    /// Create a new tracker for a fresh ciphertext (1 encryption, 0 additions).
    pub fn new_fresh(params: &PqhvParams) -> Self {
        NoiseTracker {
            additions: 1,
            params: *params,
        }
    }

    /// Record a homomorphic addition of another ciphertext.
    ///
    /// If `other` is `None`, assumes the added ciphertext is a fresh encryption (1 addition).
    /// If `other` is `Some(tracker)`, uses the other tracker's addition count.
    pub fn add(&mut self, other: Option<&NoiseTracker>) {
        match other {
            Some(t) => self.additions += t.additions,
            None => self.additions += 1,
        }
    }

    /// Check whether the noise budget has been exceeded.
    ///
    /// Returns `true` if the estimated noise level is within safe bounds
    /// for correct decryption.
    pub fn is_safe(&self) -> bool {
        self.additions <= self.params.noise_budget()
    }

    /// Returns the remaining noise budget (number of additions still possible).
    ///
    /// Returns 0 if the budget is already exceeded.
    pub fn remaining(&self) -> u64 {
        let budget = self.params.noise_budget();
        budget.saturating_sub(self.additions)
    }

    /// Returns the fraction of noise budget consumed, as a value in [0.0, 1.0+].
    ///
    /// Values > 1.0 indicate the budget has been exceeded.
    pub fn utilization(&self) -> f64 {
        self.additions as f64 / self.params.noise_budget() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{PQHV_TEST, PQHV_VOTING_128};

    #[test]
    fn test_fresh_ciphertext_is_safe() {
        let tracker = NoiseTracker::new_fresh(&PQHV_TEST);
        assert!(tracker.is_safe());
        assert_eq!(tracker.additions, 1);
    }

    #[test]
    fn test_additions_accumulate() {
        let mut tracker = NoiseTracker::new_fresh(&PQHV_TEST);
        for _ in 0..100 {
            tracker.add(None);
        }
        assert_eq!(tracker.additions, 101); // 1 fresh + 100 additions
    }

    #[test]
    fn test_remaining_budget() {
        let tracker = NoiseTracker::new_fresh(&PQHV_VOTING_128);
        let remaining = tracker.remaining();
        assert!(remaining > 100_000, "Voting params should support 100K+ additions");
    }

    #[test]
    fn test_exceeded_budget() {
        let mut tracker = NoiseTracker::new_fresh(&PQHV_TEST);
        let budget = PQHV_TEST.noise_budget();
        tracker.additions = budget + 1;
        assert!(!tracker.is_safe());
        assert_eq!(tracker.remaining(), 0);
        assert!(tracker.utilization() > 1.0);
    }

    #[test]
    fn test_add_with_other_tracker() {
        let mut t1 = NoiseTracker::new_fresh(&PQHV_TEST);
        let mut t2 = NoiseTracker::new_fresh(&PQHV_TEST);
        t2.additions = 50;
        t1.add(Some(&t2));
        assert_eq!(t1.additions, 51); // 1 + 50
    }
}

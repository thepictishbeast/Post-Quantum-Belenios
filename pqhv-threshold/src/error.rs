//! # Threshold Decryption Error Types
//!
//! Defines the error conditions that can arise during threshold key generation,
//! partial decryption, and share combination. Uses descriptive error messages
//! to aid debugging in election administration contexts.

use std::fmt;

/// Errors that can occur during threshold operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdError {
    /// The threshold t must be at least 1 (need at least one trustee to decrypt).
    ThresholdTooSmall {
        /// The threshold that was requested.
        t: usize,
    },

    /// The threshold t must not exceed the number of trustees n
    /// (cannot require more shares than exist).
    ThresholdExceedsTrustees {
        /// The threshold that was requested.
        t: usize,
        /// The number of trustees.
        n: usize,
    },

    /// The number of trustees n must be at least 1.
    NoTrustees,

    /// Fewer than t partial decryptions were provided, so the tally
    /// cannot be recovered.
    InsufficientShares {
        /// The number of shares provided.
        provided: usize,
        /// The minimum number required (the threshold t).
        required: usize,
    },

    /// Two or more partial decryptions have the same trustee index,
    /// which would produce incorrect Lagrange interpolation.
    DuplicateShareIndex {
        /// The duplicated index.
        index: usize,
    },

    /// A partial decryption has a trustee index outside the valid range [1, n].
    InvalidShareIndex {
        /// The invalid index.
        index: usize,
        /// The maximum valid index (n).
        max: usize,
    },
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThresholdError::ThresholdTooSmall { t } => {
                write!(f, "threshold t={} must be at least 1", t)
            }
            ThresholdError::ThresholdExceedsTrustees { t, n } => {
                write!(
                    f,
                    "threshold t={} exceeds number of trustees n={}",
                    t, n
                )
            }
            ThresholdError::NoTrustees => {
                write!(f, "number of trustees must be at least 1")
            }
            ThresholdError::InsufficientShares { provided, required } => {
                write!(
                    f,
                    "insufficient partial decryptions: {} provided, {} required",
                    provided, required
                )
            }
            ThresholdError::DuplicateShareIndex { index } => {
                write!(
                    f,
                    "duplicate trustee index {} in partial decryptions",
                    index
                )
            }
            ThresholdError::InvalidShareIndex { index, max } => {
                write!(
                    f,
                    "trustee index {} out of valid range [1, {}]",
                    index, max
                )
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

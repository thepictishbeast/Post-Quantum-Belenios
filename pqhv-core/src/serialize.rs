//! # Serialization
//!
//! Serialization and deserialization for PQHV cryptographic objects.
//! Uses serde for JSON serialization, which is suitable for the bulletin
//! board and protocol messages.
//!
//! ## Format
//!
//! All objects serialize to JSON via serde. Binary/compact serialization
//! can be added later for bandwidth optimization.
//!
//! ## Security Note
//!
//! Secret keys are serialized with the same format as public keys for
//! backup/restore purposes. In production, secret key serialization
//! should use an encrypted container.

use crate::encrypt::Ciphertext;
use crate::keygen::{PublicKey, SecretKey};
use serde_json;

/// Serialize a public key to JSON.
///
/// The public key includes the matrix A and vector b, which together
/// are sufficient for anyone to encrypt messages.
pub fn serialize_public_key(pk: &PublicKey) -> Result<String, serde_json::Error> {
    serde_json::to_string(pk)
}

/// Deserialize a public key from JSON.
pub fn deserialize_public_key(json: &str) -> Result<PublicKey, serde_json::Error> {
    serde_json::from_str(json)
}

/// Serialize a secret key to JSON.
///
/// **WARNING**: Secret keys must be protected. Do not store or transmit
/// in plaintext outside of secure channels.
pub fn serialize_secret_key(sk: &SecretKey) -> Result<String, serde_json::Error> {
    serde_json::to_string(sk)
}

/// Deserialize a secret key from JSON.
pub fn deserialize_secret_key(json: &str) -> Result<SecretKey, serde_json::Error> {
    serde_json::from_str(json)
}

/// Serialize a ciphertext to JSON.
///
/// Ciphertexts are posted to the public bulletin board during voting.
pub fn serialize_ciphertext(ct: &Ciphertext) -> Result<String, serde_json::Error> {
    serde_json::to_string(ct)
}

/// Deserialize a ciphertext from JSON.
pub fn deserialize_ciphertext(json: &str) -> Result<Ciphertext, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use crate::encrypt::encrypt;
    use crate::params::PQHV_TEST;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_public_key_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let json = serialize_public_key(&pk).unwrap();
        let pk2 = deserialize_public_key(&json).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (_pk, sk) = keygen(&PQHV_TEST, &mut rng);
        let json = serialize_secret_key(&sk).unwrap();
        let sk2 = deserialize_secret_key(&json).unwrap();
        assert_eq!(sk.s, sk2.s);
    }

    #[test]
    fn test_ciphertext_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (pk, _sk) = keygen(&PQHV_TEST, &mut rng);
        let ct = encrypt(&pk, 1, &PQHV_TEST, &mut rng);
        let json = serialize_ciphertext(&ct).unwrap();
        let ct2 = deserialize_ciphertext(&json).unwrap();
        assert_eq!(ct, ct2);
    }
}

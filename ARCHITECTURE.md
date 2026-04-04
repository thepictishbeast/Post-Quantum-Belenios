# Architecture

## Overview

PQHV (Post-Quantum Homomorphic Voting) is a lattice-based replacement for the ElGamal cryptographic core in the Belenios verifiable voting protocol. It uses additively homomorphic Module-LWE encryption so encrypted ballots can be tallied without decryption, with security against quantum adversaries.

## System Diagram

```
+--------------------------------------------------------------+
|                      pqhv workspace                          |
|                                                              |
|  +-------------+    +-------------+    +------------------+  |
|  |  pqhv-core  |    |  pqhv-zkp   |    | pqhv-threshold   |  |
|  |             |    |             |    |                  |  |
|  | keygen      |    | ballot      |    | key shares       |  |
|  | encrypt     |    | validity    |    | partial decrypt  |  |
|  | decrypt     |    | proofs      |    | reconstruction   |  |
|  | homomorphic |    | (lattice    |    | (t-of-n trustees)|  |
|  | addition    |    |  based)     |    |                  |  |
|  +------+------+    +------+------+    +--------+---------+  |
|         |                  |                    |            |
|         +------------------+--------------------+            |
|                            |                                 |
|                   +--------v---------+                       |
|                   |  pqhv-protocol   |                       |
|                   |                  |                       |
|                   | setup -> vote -> |                       |
|                   | tally -> verify  |                       |
|                   +--------+---------+                       |
|                            |                                 |
|              +-------------+-------------+                   |
|              |                           |                   |
|     +--------v--------+       +---------v--------+          |
|     |   pqhv-wasm     |       |   pqhv-bench     |          |
|     | (browser ballot |       | (Criterion        |          |
|     |  encryption)    |       |  benchmarks)      |          |
|     +-----------------+       +------------------+          |
+--------------------------------------------------------------+
```

## Data Flow

1. **Setup:** Trustees run distributed key generation via pqhv-threshold, producing a collective public key and individual key shares.
2. **Vote:** A voter encrypts their ballot with the public key using pqhv-core (Module-LWE encryption). pqhv-zkp generates a zero-knowledge proof that the ballot is well-formed (e.g., exactly one candidate selected).
3. **Tally:** The server homomorphically adds all encrypted ballots (ciphertext addition in pqhv-core). No individual ballot is ever decrypted.
4. **Decrypt:** Each trustee computes a partial decryption of the aggregate ciphertext using their key share. A threshold (t-of-n) of partial decryptions suffices to reconstruct the final tally.
5. **Verify:** Anyone can verify the election: check each ballot's ZKP, verify the homomorphic sum, and verify the threshold decryption proof.

## Key Design Decisions

- **Module-LWE, not Ring-LWE.** Module-LWE provides flexible security parameterization (adjust module rank k) and aligns with NIST PQC standards (Kyber/ML-KEM uses Module-LWE).
- **Additive homomorphism.** Ballot ciphertexts are added component-wise. This preserves the Belenios protocol structure where tallying operates on ciphertexts, not plaintexts.
- **NTT-accelerated polynomial arithmetic.** Number Theoretic Transform provides O(n log n) polynomial multiplication, critical for practical encryption/decryption times.
- **Workspace of focused crates.** Each crate has a single responsibility. pqhv-core never knows about proofs; pqhv-zkp never knows about threshold decryption. This enables independent auditing.
- **AGPL-3.0 license.** Matches Belenios to maintain license compatibility as a drop-in cryptographic replacement.

## Threat Model

**Defends against:** quantum adversaries (lattice-based, NIST Level 3 security), ballot content disclosure (homomorphic tallying), single-trustee compromise (threshold decryption), invalid ballot injection (ZKP verification), tally manipulation (verifiable end-to-end).

**Out of scope:** side-channel attacks on the implementation (constant-time arithmetic is planned but not yet verified), coercion of voters, compromise of a threshold number of trustees simultaneously.

## Future Directions

- Complete pqhv-zkp with lattice-based ballot validity proofs.
- Implement pqhv-threshold for distributed key generation and partial decryption.
- Wire pqhv-protocol as the full election lifecycle orchestrator.
- pqhv-wasm for client-side ballot encryption in the browser.
- Constant-time arithmetic audit for side-channel resistance.
- Integration with Sacred.Vote as an alternative to the classical ElGamal backend.

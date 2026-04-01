# Belenios Cryptographic Dependency Graph

This document maps the dependency relationships between all cryptographic operations, organized by election lifecycle phase.

---

## PHASE 0: PLATFORM FOUNDATIONS

These operations have no cryptographic dependencies and are used by everything else.

```
OP-55 Secure RNG
  |
  +--> OP-56 Random Scalar Generation
  |      |
  |      +--> (used by all keygen, encrypt, zkp_prove operations)
  |
  +--> OP-57 Token Generation
         |
         +--> OP-07 PKI Key Derivation
         +--> OP-05 Credential Key Derivation

OP-48 SHA-256 Hex Hash
  |
  +--> OP-49 SHA-256 Base64 Hash
  +--> OP-50 Group Hash (hash-to-scalar)  [used by ALL Fiat-Shamir proofs]
  +--> OP-51 Generator Derivation          [used by mixnet]
  +--> OP-52 NIZKP Challenges for Shuffle
  +--> OP-53 HMAC-SHA256
  +--> OP-54 Password Hashing

OP-03 Field Arithmetic (MakeField)
  |
  +--> OP-01 Finite Field Group  (Z_p* arithmetic)
  +--> OP-02 Ed25519 Group       (curve field + scalar field)
```

---

## PHASE 1: GROUP SELECTION

```
OP-03 Field Arithmetic
  |
  +--> OP-01 Finite Field Group Setup ----+
  |                                        |
  +--> OP-02 Ed25519 Curve Group ----+    |
                                     |    |
                                     v    v
                               GROUP MODULE (first-class module)
                                     |
                    +----------------+------------------+
                    |                |                  |
                    v                v                  v
              PHASE 2: SETUP   PHASE 3: VOTING   PHASE 4: TALLY
```

---

## PHASE 2: ELECTION SETUP

### Key Generation Path (Simple Trustees)

```
OP-55 RNG --> OP-56 Random Scalar
                |
                v
        OP-04 Trustee Key Generation
          |       |
          |       +--> OP-18 Schnorr PoK (prove knowledge of sk)
          |              |
          |              +--> OP-17 Fiat-Shamir Core
          |              |       |
          |              |       +--> OP-50 Group Hash
          |              |
          |              +--> OP-48 SHA-256
          |
          v
        trustee_public_key = g^sk
          |
          v
        OP-42 Combined Public Key  <-- combine all trustee keys
          |
          v
        Election Public Key y
```

### Key Generation Path (Threshold / Pedersen DKG)

```
OP-57 Token Gen --> OP-07 PKI Key Derivation --> sk, dk
                                                    |
        +-------------------------------------------+
        |                    |
        v                    v
  OP-08 PKI Public Key   OP-38 DKG Step 1 (Certificate)
    vk = g^sk                |
    ek = g^dk                +--> OP-46 PKI Schnorr Sign
                             |
                             v
                       OP-39 DKG Step 3 (Polynomial Gen)
                             |
                             +--> OP-56 Random Scalars (polynomial coeffs)
                             +--> eval_poly (Shamir shares)
                             +--> OP-11 PKI Channel Encrypt (share distribution)
                             |       |
                             |       +--> OP-14 AES-GCM
                             |       +--> OP-48 SHA-256 (key derivation)
                             +--> OP-46 PKI Schnorr Sign (commitments)
                             |
                             v
                       OP-40 DKG Step 5 (Verify + Assemble)
                             |
                             +--> OP-12 PKI Channel Decrypt
                             +--> OP-41 Verification Key Computation
                             +--> OP-18 Schnorr PoK (prove assembled key)
                             |
                             v
                       OP-42 Combined Public Key
                             |
                             v
                       Election Public Key y
```

### Credential Generation Path

```
OP-55 RNG --> OP-57 Token Gen (base58 credential)
                |
                v
        OP-05 Credential Key Derivation
          |       |
          |       +--> OP-48 SHA-256 (iterated KDF)
          |
          v
        private_key (scalar)
          |
          v
        OP-06 Public Key Computation
          |
          +--> credential = g^sk
          |
          v
        Public Credential (published)
```

---

## PHASE 3: VOTING (BALLOT CREATION AND VERIFICATION)

### Ballot Creation (Homomorphic Questions)

```
Election Public Key y + Voter Private Key sk
        |
        v
OP-09 ElGamal Encryption (per choice)
  |       |
  |       +--> OP-56 Random Scalar r
  |       +--> alpha = g^r, beta = y^r * g^m
  |
  v
OP-21 Disjunctive ZKP (per choice: prove m in {0,1})
  |       |
  |       +--> OP-17 Fiat-Shamir Core (genuine branch)
  |       +--> OP-56 Random (simulated branches)
  |       +--> OP-50 Group Hash (Fiat-Shamir challenge)
  |
  v
OP-23 Overall Sum Range Proof (prove min <= sum <= max)
  |       |
  |       +--> OP-15 Homomorphic Add (compute sum ciphertext)
  |       +--> OP-21 Disjunctive ZKP (over range)
  |
  +-- (if blank option) --> OP-24 Blank Ballot Proof
  |
  v
OP-19 Ballot Signature (Schnorr sign with credential)
  |       |
  |       +--> OP-56 Random Scalar w
  |       +--> commitment = g^w
  |       +--> OP-49 SHA-256 Base64 (ballot hash)
  |       +--> OP-50 Group Hash (Fiat-Shamir)
  |       +--> response = w - sk*challenge
  |
  v
Complete Ballot (ciphertexts + proofs + signature)
```

### Ballot Creation (List Questions)

```
Election Public Key y + Voter Private Key sk
        |
        v
OP-09 ElGamal Encryption (per choice per list)
  |
  v
OP-21 Disjunctive ZKP (per choice: prove m in {0,1})
  |
  v
OP-23 Overall Sum Range Proof (prove first items sum = 1)
  |
  v
OP-26 List Question Proof (per list: prove m0=1 OR mS=0)
  |
  v
OP-28 Non-Zero Proof (combined list items encrypt non-zero)
  |
  v
OP-19 Ballot Signature
```

### Ballot Creation (Non-Homomorphic Questions)

```
Election Public Key y + Voter Private Key sk
        |
        v
OP-10 ElGamal Encryption (raw plaintext encoding)
  |       |
  |       +--> G.of_ints (Koblitz-style encoding for Ed25519)
  |
  v
OP-30 Raw ElGamal Knowledge Proof
  |
  v
OP-19 Ballot Signature
```

### Ballot Verification

```
Ballot
  |
  +--> OP-20 Ballot Signature Verification
  |       |
  |       +--> OP-50 Group Hash
  |       +--> OP-58 Election Fingerprint check
  |
  +--> OP-22 Disjunctive ZKP Verification (per choice)
  |
  +--> OP-23/25/27/29/31 Appropriate proof verification
  |
  v
Boolean (valid/invalid)
```

---

## PHASE 4: TALLYING

### Encrypted Tally Computation

```
All Valid Ballots
  |
  v
OP-15 Homomorphic Addition (per question, per choice)
  |       |
  |       +--> OP-16 Weighted Ballot Aggregation
  |              |
  |              +--> Binary exponentiation of ciphertext multiplication
  |
  v
Encrypted Tally (array of ciphertexts)
```

### Shuffle (Non-Homomorphic Questions Only)

```
Encrypted Tally --> extract NH ciphertexts
  |
  v
OP-43 Re-encryption Shuffle
  |       |
  |       +--> OP-56 Random Scalars (re-encryption randomness)
  |       +--> gen_permutation (Fisher-Yates)
  |       +--> re_encrypt: {alpha * g^r, beta * y^r}
  |
  v
OP-44 Shuffle Proof Generation (Bayer-Groth)
  |       |
  |       +--> OP-51 Generator Derivation (independent generators h_i)
  |       +--> gen_permutation_commitment
  |       +--> gen_commitment_chain
  |       +--> OP-52 NIZKP Challenges (iterated SHA-256)
  |       +--> Multiple Fiat-Shamir rounds
  |
  v
Shuffled Ciphertexts + Proof
  |
  v
OP-45 Shuffle Proof Verification
```

### Decryption

```
Encrypted Tally
  |
  v
OP-32 Partial Decryption (per trustee)
  |       |
  |       +--> factor_i = alpha^{sk_i} for each ciphertext
  |       +--> Chaum-Pedersen proof (OP-17 Fiat-Shamir)
  |
  v
OP-33 Partial Decryption Verification
  |
  v
OP-34 Factor Combination
  |       |
  |       +--(simple)--> product of all factors
  |       |
  |       +--(threshold)--> OP-35 Lagrange Interpolation
  |                         OP-36 Threshold Factor Combination
  |                             factor^{lambda_j} per participant
  |
  v
Decrypted Group Elements (g^m for each choice)
  |
  v
OP-37 Baby-Step Giant-Step (recover plaintext m from g^m)
  |
  v
Election Result (integer tallies)
```

---

## COMPLETE OPERATION DEPENDENCY MATRIX

| Operation | Depends On | Used By |
|-----------|-----------|---------|
| OP-01 FF Group | OP-03 Field | OP-04,09,15,17,21,32,39,42,43,46 |
| OP-02 Ed25519 | OP-03 Field | Same as OP-01 |
| OP-03 Field | None | OP-01, OP-02 |
| OP-04 Trustee Keygen | OP-01/02, OP-17, OP-18, OP-56 | OP-42 |
| OP-05 Cred Derivation | OP-48 | OP-06 |
| OP-06 Cred PubKey | OP-05, OP-01/02 | OP-19, OP-20 |
| OP-07 PKI Key Deriv | OP-48 | OP-08, OP-38 |
| OP-08 PKI PubKey | OP-07, OP-01/02 | OP-38, OP-39, OP-40 |
| OP-09 ElGamal Enc | OP-01/02, OP-56 | OP-15, OP-21, OP-23 |
| OP-10 ElGamal Raw | OP-01/02, OP-56 | OP-30, OP-43 |
| OP-11 PKI Encrypt | OP-01/02, OP-14, OP-48, OP-56 | OP-39 |
| OP-12 PKI Decrypt | OP-01/02, OP-14, OP-48 | OP-40 |
| OP-13 AES-CCM | None (legacy) | OP-11 (if selected) |
| OP-14 AES-GCM | None | OP-11 |
| OP-15 Homo Add | OP-01/02 | OP-16, OP-23, OP-34 |
| OP-16 Weighted Agg | OP-15 | Phase 4 tally |
| OP-17 Fiat-Shamir | OP-50, OP-56 | OP-18,19,21,24,26,28,30,32,44,46 |
| OP-18 Schnorr PoK | OP-17 | OP-04, OP-40 |
| OP-19 Ballot Sign | OP-17, OP-50, OP-49 | Ballot creation |
| OP-20 Ballot Verify | OP-50, OP-49 | Ballot verification |
| OP-21 Disj ZKP | OP-17 | OP-23, OP-24 |
| OP-22 Disj Verify | OP-50 | Ballot verification |
| OP-23 Range Proof | OP-15, OP-21 | Ballot creation |
| OP-24 Blank Proof | OP-17, OP-50, OP-56 | Ballot creation |
| OP-25 Blank Verify | OP-50 | Ballot verification |
| OP-26 List Proof | OP-17, OP-50, OP-56 | Ballot creation |
| OP-27 List Verify | OP-50 | Ballot verification |
| OP-28 Nonzero Proof | OP-56, OP-50 | Ballot creation |
| OP-29 Nonzero Verify| OP-50 | Ballot verification |
| OP-30 NH Question ZKP| OP-17 | Ballot creation |
| OP-31 NH Verify | OP-50 | Ballot verification |
| OP-32 Partial Decrypt| OP-17, OP-50 | OP-34 |
| OP-33 PD Verify | OP-50 | OP-34 |
| OP-34 Factor Combine | OP-32, OP-35, OP-36 | Result computation |
| OP-35 Lagrange | OP-03 | OP-36 |
| OP-36 Threshold Comb | OP-35 | OP-34 |
| OP-37 BSGS DLog | OP-01/02 | Result computation |
| OP-38 DKG Step 1 | OP-07, OP-08, OP-46 | OP-39 |
| OP-39 DKG Step 3 | OP-38, OP-11, OP-46, OP-56 | OP-40 |
| OP-40 DKG Step 5 | OP-39, OP-12, OP-41, OP-18 | OP-42 |
| OP-41 Verify Keys | OP-01/02 | OP-40 |
| OP-42 Combine Keys | OP-04/40 | Election setup |
| OP-43 Re-enc Shuffle | OP-56, OP-01/02 | OP-44 |
| OP-44 Shuffle Proof | OP-51, OP-52, OP-17, OP-56 | Phase 4 |
| OP-45 Shuffle Verify | OP-51, OP-52, OP-50 | Phase 4 |
| OP-46 PKI Sign | OP-17, OP-50 | OP-38, OP-39 |
| OP-47 PKI Verify | OP-50 | OP-39, OP-40 |
| OP-48 SHA-256 Hex | None | Nearly everything |
| OP-49 SHA-256 B64 | OP-48 | Fingerprints |
| OP-50 Group Hash | OP-48, OP-03 | All Fiat-Shamir |
| OP-51 Generator Deriv| OP-48, OP-01/02 | OP-44 |
| OP-52 Shuffle Chall | OP-48 | OP-44 |
| OP-53 HMAC-SHA256 | None | Web server |
| OP-54 Password Hash | OP-48 | Web auth |
| OP-55 Secure RNG | None | OP-56, OP-57 |
| OP-56 Random Scalar | OP-55 | Nearly everything |
| OP-57 Token Gen | OP-55 | OP-05, OP-07 |
| OP-58 Election FP | OP-49 | All ballot ops |
| OP-59 Ballot Hash | OP-49 | Ballot tracking |

---

## CRITICAL PATH ANALYSIS

The **minimum set of operations that must work for an election to complete**:

1. **Setup**: OP-01/02 -> OP-04 -> OP-18 -> OP-42
2. **Credential**: OP-05 -> OP-06
3. **Vote**: OP-09 -> OP-21 -> OP-23 -> OP-19
4. **Tally**: OP-15/16 -> OP-32 -> OP-33 -> OP-34 -> OP-37

Every operation on this critical path depends on the DLP-based group abstraction (OP-01/02). This is the fundamental bottleneck for PQ migration.

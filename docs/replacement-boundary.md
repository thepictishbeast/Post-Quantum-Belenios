# Belenios PQ Replacement Boundary Analysis

This document categorizes every cryptographic operation by its post-quantum migration status: what stays, what must be replaced, and what can be upgraded independently.

---

## CATEGORY 1: NO CHANGE NEEDED (PQ-SAFE AS-IS)

These operations are already quantum-resistant or do not depend on DLP/ECDLP.

| Op ID | Operation | File | Rationale |
|-------|-----------|------|-----------|
| OP-03 | Field Arithmetic (MakeField) | common.ml:109-142 | Pure modular arithmetic; used in lattice schemes too |
| OP-13 | AES-CCM Symmetric Encryption | platform/native/platform.ml:34-177 | Symmetric cipher; AES-256 provides 128-bit PQ security |
| OP-14 | AES-GCM Symmetric Encryption | platform/native/platform.ml:179-197 | Symmetric cipher; PQ-safe |
| OP-35 | Lagrange Interpolation | trustees.ml:179-184 | Pure polynomial arithmetic over Z_q; algebraically generic |
| OP-48 | SHA-256 Hex Hash | common.ml:52 | Hash function; 128-bit collision resistance against quantum |
| OP-49 | SHA-256 Base64 Hash | common.ml:53 | Same as OP-48 |
| OP-50 | Group Hash (hash-to-scalar) | group_field.ml:99-101, ed25519_pure.ml:245-247 | SHA-256 core is PQ-safe; only needs new field reduction |
| OP-52 | NIZKP Challenges for Shuffle | mixnet.ml:74-80 | Iterated SHA-256; PQ-safe hash |
| OP-53 | HMAC-SHA256 | belenios_messages.ml:39-43 | HMAC; PQ-safe |
| OP-54 | Password Hashing | web_auth_password.ml:174 | SHA-256 salted hash; PQ-safe |
| OP-55 | Secure RNG | platform/native/platform.ml:206-213 | OS entropy; PQ-safe |
| OP-56 | Random Scalar Generation | common.ml:98-107 | Rejection sampling mod q; PQ-safe |
| OP-57 | Token Generation | common.ml:184-216 | Random token gen; PQ-safe |
| OP-58 | Election Fingerprint | election.ml:97 | SHA-256 hash; PQ-safe |
| OP-59 | Ballot Hash | election.ml:177 | SHA-256 hash; PQ-safe |

**Total: 15 operations -- no code changes required.**

---

## CATEGORY 2: INDEPENDENT UPGRADES (Can replace without touching core crypto)

These can be upgraded to PQ versions without requiring changes to other operations.

### 2A: PKI Signatures (replace Schnorr with ML-DSA)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-46 | PKI Schnorr Sign | pki.ml:41-48 | ML-DSA (Dilithium) sign | medium |
| OP-47 | PKI Verify | pki.ml:50-53 | ML-DSA verify | medium |

**Isolation boundary**: These only affect the Pedersen DKG channel (certificate signing, polynomial signing). The `sign/verify` functions in `pki.ml` have a clean interface `sign : private_key -> string -> signed_msg` and `verify : public_key -> signed_msg -> bool`. Can be swapped to ML-DSA with same interface. However, private_key and public_key types would change from group scalars/elements to ML-DSA key material.

**Impact**: Changes OP-38 (DKG Step 1), OP-39 (DKG Step 3), OP-40 (DKG Step 5) serialization formats.

### 2B: PKI Channel Encryption (replace ElGamal-KEM with ML-KEM)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-07 | PKI Key Derivation | pki.ml:37-39 | ML-KEM key derivation | medium |
| OP-08 | PKI Public Key | trustees.ml:310,429 | ML-KEM public key | medium |
| OP-11 | PKI Channel Encrypt | pki.ml:55-66 | ML-KEM encapsulate + AES-GCM | medium |
| OP-12 | PKI Channel Decrypt | pki.ml:68-74 | ML-KEM decapsulate + AES-GCM | medium |

**Isolation boundary**: These form a self-contained hybrid encryption module used only for secure communication between DKG participants. The `encrypt/decrypt` interface in `pki.ml` is clean. AES-GCM data encryption stays. Only the key encapsulation changes. The SHA-256-based key/IV derivation (`sha256_hex("key|" + ...)`) stays.

**Impact**: Changes DKG channel message format. Does NOT affect election ballots or tallying.

### 2C: Ballot Signature (replace Schnorr with ML-DSA or hash-based)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-19 | Ballot Signature | election.ml:164-190 | ML-DSA or SPHINCS+ sign | medium |
| OP-20 | Ballot Sig Verify | election.ml:196-219 | ML-DSA or SPHINCS+ verify | medium |

**Isolation boundary**: Ballot signatures are created in `create_ballot` and verified in `check_ballot`. The credential system (OP-05, OP-06) would also need to change since credentials currently are `g^sk`. With ML-DSA, the credential would be an ML-DSA public key derived from the private credential string.

**Dependency note**: This ALSO requires changing OP-05 and OP-06 to derive ML-DSA keys instead of group scalars. The credential derivation (iterated SHA-256) can stay; just feed the result into ML-DSA keygen instead of `g^sk`.

---

## CATEGORY 3: MUST REPLACE (Core DLP-dependent operations)

These operations fundamentally depend on the discrete logarithm problem and MUST be replaced for PQ security. They form a tightly coupled core.

### 3A: Group Abstraction (the foundation)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-01 | Finite Field Group | group_field.ml | Remove or replace with lattice group abstraction | hard |
| OP-02 | Ed25519 Group | ed25519_pure.ml, ed25519_libsodium.ml | Remove or replace with lattice group | hard |
| OP-51 | Generator Derivation | group_field.ml:106-116, ed25519_pure.ml:257-271 | Structured reference string / lattice hash-to-point | hard |

**Analysis**: The `GROUP` module type (signatures_core.ml:66-131) defines the universal interface used by every cryptographic operation. It provides:
- Group element type `t` with multiplication `*~`, exponentiation `**~`, inversion
- Scalar field `Zq` with arithmetic
- Generator `g`, identity `one`
- Hash-to-scalar `hash : string -> t array -> Zq.t`
- Membership check `check : t -> bool`

For PQ migration, this interface would need to change fundamentally because lattice-based schemes don't have the same algebraic structure (no group with efficient DLP-hard exponentiation that supports ElGamal).

### 3B: ElGamal Encryption (the core scheme)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-09 | ElGamal Enc (homomorphic) | question_h.ml:71-72, question_l.ml:68-69 | Additively-homomorphic lattice encryption | hard |
| OP-10 | ElGamal Enc (non-homo) | question_nh.ml:51-71 | Standard lattice PKE | medium |

**Analysis for OP-09**: The critical requirement is additive homomorphism. Current scheme: `Enc(m) = (g^r, y^r * g^m)` has `Enc(m1) * Enc(m2) = Enc(m1+m2)`. Possible PQ replacements:
- **BFV/BGV-style**: Ring-LWE based, supports homomorphic addition natively. But verification of correct encryption requires new ZKP techniques.
- **Custom Module-LWE scheme**: Design a scheme where `Enc(m1) + Enc(m2) = Enc(m1+m2)` in the lattice setting.
- **Exponential encoding with lattice**: If a lattice group action exists with discrete-log-like encoding, could mimic current structure. (Research frontier.)

**Analysis for OP-10**: No homomorphism needed. Standard ML-KEM style encryption suffices. However, the mixnet (OP-43) requires re-encryptability, which constrains the choice.

### 3C: Homomorphic Operations

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-15 | Homomorphic Addition | question_h.ml:67-68 | Lattice ciphertext addition | hard |
| OP-16 | Weighted Aggregation | question_h.ml:396-412 | Lattice ciphertext scalar mult | hard |
| OP-37 | BSGS Discrete Log | common.ml:227-265 | Lattice decryption (direct) | medium |

**Analysis**: With lattice-based HE, the homomorphic operation is vector addition (vs. group multiplication). BSGS would not be needed if the lattice scheme directly decrypts to integers rather than encoding them as group elements.

### 3D: Zero-Knowledge Proofs (the hardest part)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-17 | Fiat-Shamir Core | election.ml:143-148 | Lattice Sigma protocol + Fiat-Shamir | hard |
| OP-18 | Schnorr PoK | trustees.ml:96-102 | Lattice PoK (e.g., Lyubashevsky) | hard |
| OP-21 | Disjunctive ZKP | question_h.ml:87-127 | Lattice OR-proof (research) | research |
| OP-22 | Disjunctive Verify | question_h.ml:129-147 | Matches OP-21 | research |
| OP-23 | Range Proof | question_h.ml:335-368 | Lattice range proof | research |
| OP-24 | Blank Proof | question_h.ml:151-271 | Lattice disjunctive proof | research |
| OP-25 | Blank Verify | question_h.ml:273-316 | Matches OP-24 | research |
| OP-26 | List Proof | question_l.ml:169-215 | Lattice disjunctive proof | research |
| OP-27 | List Verify | question_l.ml:221-238 | Matches OP-26 | research |
| OP-28 | Non-Zero Proof | question_l.ml:240-253 | Lattice inequality proof | research |
| OP-29 | Non-Zero Verify | question_l.ml:255-263 | Matches OP-28 | research |
| OP-30 | NH Question ZKP | question_nh.ml:51-71 | Lattice knowledge proof | hard |
| OP-31 | NH Question Verify | question_nh.ml:73-83 | Matches OP-30 | hard |

**Analysis**: The Fiat-Shamir transform itself survives into the PQ world (it works with any Sigma protocol in the random oracle model). The problem is that the underlying Sigma protocols all rely on the linear structure of DLP:

- **Schnorr**: prover knows `x` such that `y = g^x`. Works because `g^{response} * y^{challenge} = g^{w}`. In lattice setting: prover knows `s` such that `b = As + e`. Lyubashevsky's technique with rejection sampling replaces this.

- **Disjunctive proofs**: The OR-composition technique (simulate all but one branch) is algebraically generic and works with any Sigma protocol. The challenge is having efficient lattice Sigma protocols for the base statements.

- **The real blocker**: Proving "this ciphertext encrypts 0 or 1" in a lattice setting. With RLWE encryption `(a, b = a*s + e + m*q/2)`, proving m in {0,1} requires proving that `b - a*s - m*q/2` is "small" for some choice of m. This is an active research area (see Lyubashevsky et al., "Lattice-Based Zero-Knowledge Proofs", Esgin et al. 2019-2024).

### 3E: Threshold Decryption (Pedersen DKG)

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-32 | Partial Decryption | election.ml:297-309 | Lattice partial decryption | hard |
| OP-33 | PD Verification | election.ml:311-324 | Lattice PD verification | hard |
| OP-34 | Factor Combination | election.ml:331-344 | Lattice threshold combination | hard |
| OP-36 | Threshold Combination | trustees.ml:186-209 | Lattice threshold combination | hard |
| OP-38 | DKG Step 1 | trustees.ml:260-268 | Lattice DKG | hard |
| OP-39 | DKG Step 3 | trustees.ml:293-355 | Lattice VSS | hard |
| OP-40 | DKG Step 5 | trustees.ml:420-501 | Lattice VSS verification | hard |
| OP-41 | Verification Keys | trustees.ml:67-89 | Lattice verification keys | hard |
| OP-42 | Combined Public Key | trustees.ml:168-177 | Lattice key combination | hard |

**Analysis**: The entire Pedersen DKG protocol relies on:
1. Feldman VSS: commitments `g^{a_k}` to polynomial coefficients (needs DLP)
2. Share verification: `g^{s_{ij}} = product(g^{a_k} ^ {j^k})` (needs group homomorphism)
3. Threshold reconstruction: Lagrange interpolation in the exponent (needs group structure)

PQ replacements for threshold/distributed decryption exist but are significantly more complex:
- Lattice-based threshold FHE (Boneh et al.)
- Shamir secret sharing over lattice keys (FROST-like protocols adapted)
- The key combination `y = product(y_i)` may work if lattice public keys can be added.

### 3F: Mixnet / Shuffle

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-43 | Re-encryption Shuffle | mixnet.ml:50-59 | Lattice re-encryption mixnet | research |
| OP-44 | Shuffle Proof | mixnet.ml:123-181 | Lattice shuffle proof | research |
| OP-45 | Shuffle Verify | mixnet.ml:183-251 | Matches OP-44 | research |

**Analysis**: The mixnet requires:
1. Re-encryptability: adding fresh randomness to a ciphertext without changing the plaintext
2. Shuffle proof: proving the output is a permutation + re-encryption of the input

Both properties are possible with lattice-based encryption (RLWE ciphertexts can be re-randomized by adding fresh noise). However, efficient shuffle proofs in the lattice setting are at the research frontier. Alternative: use the decryption mixnet approach instead of re-encryption.

### 3G: Trustee Key Verification

| Op ID | Operation | File | PQ Replacement | Difficulty |
|-------|-----------|------|----------------|------------|
| OP-04 | Trustee Keygen | trustees.ml:214-242 | Lattice keygen + lattice PoK | hard |

---

## REPLACEMENT STRATEGY: PHASED APPROACH

### Phase 1: Low-Hanging Fruit (INDEPENDENT, can ship now)

**No code changes needed:**
- All Category 1 operations (15 ops) are already PQ-safe

**Independent upgrades (Category 2):**
1. Replace PKI signatures (OP-46, OP-47) with ML-DSA
   - Affects only DKG inter-trustee communication
   - Self-contained in `pki.ml`
2. Replace PKI channel encryption (OP-11, OP-12) with ML-KEM + AES-GCM
   - Self-contained in `pki.ml`
   - Keep AES-GCM for symmetric part

### Phase 2: Ballot Authentication (requires credential system change)

3. Replace ballot signatures (OP-19, OP-20) with ML-DSA
   - Requires changing credential system (OP-05, OP-06)
   - Public credentials become ML-DSA public keys instead of group elements
   - Credential derivation KDF (OP-05) stays; output feeds into ML-DSA keygen

### Phase 3: Core Encryption (major research + engineering)

4. Replace ElGamal with additively homomorphic lattice encryption (OP-09, OP-15, OP-16)
5. Replace all disjunctive ZKPs (OP-21 through OP-31)
6. Replace partial decryption + Chaum-Pedersen proofs (OP-32, OP-33)
7. Replace BSGS with direct lattice decryption (OP-37)

### Phase 4: Threshold + Mixnet (hardest)

8. Replace Pedersen DKG (OP-38 through OP-42) with lattice-based DKG
9. Replace re-encryption mixnet (OP-43 through OP-45)

---

## KEY ARCHITECTURAL OBSERVATIONS

### The GROUP Module Type is the Chokepoint

Every cryptographic operation flows through the `GROUP` module type defined in `signatures_core.ml`. This module provides:

```ocaml
module type GROUP = sig
  module Zq : FIELD       (* scalar field *)
  type t                  (* group elements *)
  val g : t               (* generator *)
  val ( *~ ) : t -> t -> t    (* multiplication *)
  val ( **~ ) : t -> Zq.t -> t  (* exponentiation *)
  val hash : string -> t array -> Zq.t  (* Fiat-Shamir oracle *)
  ...
end
```

A PQ replacement would need a new module type, perhaps:

```ocaml
module type PQ_SCHEME = sig
  type public_key
  type secret_key
  type ciphertext
  type plaintext = int
  val keygen : unit -> public_key * secret_key
  val encrypt : public_key -> plaintext -> ciphertext
  val add_ciphertexts : ciphertext -> ciphertext -> ciphertext  (* homomorphic *)
  val partial_decrypt : secret_key -> ciphertext -> partial_decryption
  val combine_partial : partial_decryption list -> plaintext
  val prove_valid_vote : public_key -> ciphertext -> plaintext -> proof
  val verify_valid_vote : public_key -> ciphertext -> proof -> bool
end
```

### Serialization Format Changes

The current ballot format stores group elements as hex strings. A PQ replacement would change:
- Ciphertext size: ElGamal ~64 bytes (Ed25519) or ~512 bytes (2048-bit) per ciphertext -> lattice ciphertexts are typically 1-10 KB
- Proof size: current proofs are ~128 bytes per disjunct -> lattice proofs are 10-100x larger
- Public key size: ~32-256 bytes -> lattice public keys are 1-2 KB

This affects all ATD type definitions in `serializable_*.atd` files and all JSON serialization.

### Version Field Already Exists

The election parameter format includes `e_version = 1`. A PQ election could use `e_version = 2` with completely different cryptographic formats, allowing the codebase to support both classical and PQ elections simultaneously during a transition period.

### Files Requiring Modification Per Phase

**Phase 1 (PKI only):**
- `src/lib/core/pki.ml` -- new sign/verify/encrypt/decrypt implementations
- `src/lib/v1/trustees.ml` -- update MakePedersen to use new PKI
- Serialization types for certificates and encrypted messages

**Phase 2 (Ballot signatures):**
- `src/lib/v1/election.ml` -- create_ballot, check_ballot
- `src/lib/core/credential.ml` -- derive, generate
- Ballot serialization types

**Phase 3 (Core crypto):**
- `src/lib/core/signatures_core.ml` -- new module type
- `src/lib/v1/question_h.ml` -- complete rewrite of encrypt + ZKPs
- `src/lib/v1/question_l.ml` -- complete rewrite
- `src/lib/v1/question_nh.ml` -- rewrite encrypt + ZKP
- `src/lib/v1/election.ml` -- rewrite MakeElection
- `src/lib/core/common.ml` -- remove/adapt BabyStepGiantStep

**Phase 4 (Threshold + mixnet):**
- `src/lib/v1/trustees.ml` -- complete rewrite of DKG
- `src/lib/v1/mixnet.ml` -- complete rewrite of shuffle + proof

---

## RISK ASSESSMENT

| Risk | Severity | Mitigation |
|------|----------|------------|
| Lattice ZKP research not mature enough | HIGH | Use conservative approaches (MPC-in-the-head as fallback) |
| Proof sizes too large for web | MEDIUM | Compress proofs; accept larger ballots; batch verification |
| Homomorphic lattice encryption noise growth | MEDIUM | Limit number of additions; use modulus switching |
| Threshold lattice DKG complexity | HIGH | Consider simpler 2-of-2 threshold as stepping stone |
| Re-encryption mixnet in lattice setting | HIGH | Switch to decryption mixnet if needed |
| Performance regression | MEDIUM | Lattice ops are slower; use SIMD/parallelism |
| Interoperability during transition | LOW | Version field enables dual-mode operation |

---

## SUMMARY STATISTICS

| Category | Count | Status |
|----------|-------|--------|
| PQ-safe (no change) | 15 ops | Ship today |
| Independent upgrades | 8 ops | Medium effort, can do incrementally |
| Must replace (hard) | 25 ops | Major engineering, some research needed |
| Must replace (research) | 11 ops | Active research area, timeline uncertain |
| **Total** | **59 ops** | |

**Bottom line**: 25% of operations are already PQ-safe. Another 14% can be upgraded independently. The remaining 61% form a tightly coupled core around the DLP-based group abstraction and require a coordinated replacement effort. The ZKP constructions (18 operations) are the single hardest component, with disjunctive proofs and shuffle proofs being at the frontier of lattice cryptography research.

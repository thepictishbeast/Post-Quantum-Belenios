# Belenios Cryptographic Operations Map

Complete audit of every cryptographic operation in the Belenios codebase.

---

## 1. GROUP DEFINITIONS AND PARAMETERS

### OP-01: Finite Field Group Setup (BELENIOS-2048, RFC-3526-2048)

- **OPERATION**: Finite field group instantiation
- **FILE**: src/lib/v1/group.ml (lines 28-53), src/lib/core/group_field.ml (lines 30-121)
- **TYPE**: keygen (group parameter selection)
- **INPUTS**: Group name string ("BELENIOS-2048", "RFC-3526-2048", "Ed25519")
- **OUTPUTS**: First-class module satisfying `GROUP` signature with p, q, g, field arithmetic
- **ALGEBRAIC DEPENDENCY**: Discrete logarithm in Z_p^* (Schnorr subgroup of order q)
- **PQ REPLACEMENT**: Module-LWE lattice parameters (n, q, sigma) or CSIDH group action
- **DIFFICULTY**: hard -- replacing the group abstraction affects every downstream operation
- **DETAILS**: BELENIOS-2048 uses a 2048-bit prime p with a 256-bit subgroup order q. RFC-3526-2048 is a standardized 2048-bit DH group with embedding support (padding=8, bits_per_int=8). Group_field.ml implements: `(**~) a b = powm a (Zq.to_Z b) p` (modular exponentiation), `check x = check_modulo p x && powm x q p =~ one` (subgroup membership).

### OP-02: Ed25519 Elliptic Curve Group

- **OPERATION**: Ed25519 twisted Edwards curve group operations
- **FILE**: src/lib/core/ed25519_pure.ml (lines 1-275), src/lib/core/ed25519_libsodium.ml (lines 1-163)
- **TYPE**: keygen (group parameter selection)
- **INPUTS**: None (fixed curve parameters: q = 2^255-19, base point, cofactor 8)
- **OUTPUTS**: First-class module satisfying `GROUP` with Ed25519 operations
- **ALGEBRAIC DEPENDENCY**: Elliptic Curve Discrete Logarithm Problem (ECDLP)
- **PQ REPLACEMENT**: Lattice-based group or isogeny-based group (CSIDH)
- **DIFFICULTY**: hard -- Ed25519 is deeply integrated; pure OCaml + libsodium fallback
- **DETAILS**: Implements extended twisted Edwards coordinates `(X:Y:Z:T)` with `a=-1, d=-121665/121666`. Scalar multiplication uses windowed method (window=4, 64 iterations). Libsodium variant delegates `scalarmult` and `add` to C bindings for performance. Point compression/decompression via `compress`/`uncompress`.

### OP-03: Field Arithmetic (MakeField functor)

- **OPERATION**: Modular arithmetic field construction
- **FILE**: src/lib/core/common.ml (lines 109-142)
- **TYPE**: keygen (field construction)
- **INPUTS**: Prime modulus q
- **OUTPUTS**: Field module with +, -, *, invert, random operations mod q
- **ALGEBRAIC DEPENDENCY**: Prime field Z_q arithmetic
- **PQ REPLACEMENT**: Same (modular arithmetic is used in lattice schemes too)
- **DIFFICULTY**: easy -- field arithmetic is generic and reusable

---

## 2. KEY GENERATION

### OP-04: Trustee Key Generation (Simple / Single trustee)

- **OPERATION**: Generate trustee keypair with proof of knowledge
- **FILE**: src/lib/v1/trustees.ml (lines 214-242), src/tool/setup.ml (lines 53-98)
- **TYPE**: keygen
- **INPUTS**: Random source
- **OUTPUTS**: Private key `x` (scalar), public key `y = g^x` (group element), proof-of-knowledge (Schnorr PoK)
- **ALGEBRAIC DEPENDENCY**: Discrete log hardness (g^x hides x)
- **PQ REPLACEMENT**: ML-KEM key generation or lattice-based commitment
- **DIFFICULTY**: hard -- keypair structure changes entirely for lattices
- **DETAILS**: `MakeSimple.generate` returns random scalar x; `MakeSimple.prove` computes `trustee_public_key = g **~ x`, then creates Schnorr PoK via `fs_prove [|g|] x (G.hash zkp)` with prefix `"pok|{group_desc}|{pk_string}|"`.

### OP-05: Credential Key Derivation

- **OPERATION**: Derive voter private key from credential string
- **FILE**: src/lib/core/credential.ml (lines 87-104)
- **TYPE**: keygen (deterministic)
- **INPUTS**: Private credential string (base58, 22 chars), election UUID
- **OUTPUTS**: Scalar private key (voter's signing key)
- **ALGEBRAIC DEPENDENCY**: SHA-256 as key derivation function, then reduce mod q
- **PQ REPLACEMENT**: Can keep SHA-256-based KDF; public credential = g^sk must change
- **DIFFICULTY**: medium -- KDF is fine, but public credential computation (g^sk) depends on DLP
- **DETAILS**: Uses iterated SHA-256: `sha256_hex(prefix|i|seed)` concatenated until 512 bits, then `G.Zq.reduce_hex`. Public credential is `G.(g **~ private_key)`.

### OP-06: Credential Public Key Computation

- **OPERATION**: Compute public credential from private key
- **FILE**: src/lib/core/credential.ml (lines 135-137, 164-166)
- **TYPE**: keygen
- **INPUTS**: Private key scalar sk
- **OUTPUTS**: Public credential `g^sk` (group element)
- **ALGEBRAIC DEPENDENCY**: Discrete log (public key is g^sk)
- **PQ REPLACEMENT**: Lattice-based public key from private key
- **DIFFICULTY**: hard -- structural change to credential system

### OP-07: PKI Key Derivation (Pedersen participants)

- **OPERATION**: Derive signing key and decryption key from seed
- **FILE**: src/lib/core/pki.ml (lines 37-39)
- **TYPE**: keygen (deterministic)
- **INPUTS**: Seed string (22-char base58 token)
- **OUTPUTS**: Signing key `sk = reduce(SHA256("sk|" + seed))`, decryption key `dk = reduce(SHA256("dk|" + seed))`
- **ALGEBRAIC DEPENDENCY**: SHA-256 as KDF, reduced to group scalar
- **PQ REPLACEMENT**: Same KDF approach, but keys used in lattice-based PKE/signatures
- **DIFFICULTY**: easy -- KDF itself is PQ-safe

### OP-08: PKI Public Key Generation

- **OPERATION**: Compute PKI public keys from derived keys
- **FILE**: src/lib/v1/trustees.ml (lines 310, 429)
- **TYPE**: keygen
- **INPUTS**: sk, dk (scalars)
- **OUTPUTS**: Verification key `vk = g^sk`, encryption key `ek = g^dk`
- **ALGEBRAIC DEPENDENCY**: Discrete log
- **PQ REPLACEMENT**: Lattice-based public key derivation
- **DIFFICULTY**: hard -- part of DKG protocol

---

## 3. ENCRYPTION

### OP-09: ElGamal Encryption (Homomorphic questions)

- **OPERATION**: Encrypt a single vote choice as ElGamal ciphertext
- **FILE**: src/lib/v1/question_h.ml (lines 71-72), src/lib/v1/question_l.ml (lines 68-69)
- **TYPE**: encrypt
- **INPUTS**: Public key `y`, randomness `r` (scalar), plaintext `x` (integer 0 or 1)
- **OUTPUTS**: Ciphertext `{alpha = g^r, beta = y^r * g^x}`
- **ALGEBRAIC DEPENDENCY**: DDH assumption (ElGamal semantic security), group homomorphism
- **PQ REPLACEMENT**: Module-LWE encryption (e.g., Kyber/ML-KEM adapted for homomorphic addition)
- **DIFFICULTY**: hard -- this is the core encryption; homomorphic property must be preserved
- **DETAILS**: `eg_encrypt y r x = { alpha = g **~ r; beta = (y **~ r) *~ (g **~ Zq.of_int x) }`. The encoding `g^x` (exponential ElGamal) enables additive homomorphism.

### OP-10: ElGamal Encryption (Non-homomorphic questions)

- **OPERATION**: Encrypt a raw plaintext as ElGamal ciphertext
- **FILE**: src/lib/v1/question_nh.ml (lines 51-71)
- **TYPE**: encrypt
- **INPUTS**: Public key `y`, randomness `r` (scalar), plaintext `m` (group element via `G.of_ints`)
- **OUTPUTS**: Ciphertext `{alpha = g^r, beta = y^r * m}`
- **ALGEBRAIC DEPENDENCY**: DDH assumption (standard ElGamal)
- **PQ REPLACEMENT**: Standard lattice-based PKE (no homomorphism needed)
- **DIFFICULTY**: medium -- standard PKE replacement, no homomorphic requirement

### OP-11: PKI Channel Encryption (ElGamal + AES-GCM hybrid)

- **OPERATION**: Encrypt a message to a recipient's public key
- **FILE**: src/lib/core/pki.ml (lines 55-66)
- **TYPE**: encrypt
- **INPUTS**: Recipient public key `y`, plaintext string
- **OUTPUTS**: Encrypted message `{y_algorithm, y_alpha = g^r, y_beta = y^r * g^key, y_data}` where y_data is AES-GCM encrypted
- **ALGEBRAIC DEPENDENCY**: DDH for key encapsulation, AES-GCM for data encryption
- **PQ REPLACEMENT**: ML-KEM (Kyber) for key encapsulation + AES-GCM (stays)
- **DIFFICULTY**: medium -- replace ElGamal KEM with ML-KEM, keep AES-GCM
- **DETAILS**: Key encapsulation: random `r`, random `key`; ephemeral key = `g^key`; DH shared secret = `y^r * g^key`. Then `sha256_hex("key|" + shared_secret)` for AES key, `sha256_hex("iv|" + y_alpha)` for IV. AES-GCM encrypts plaintext.

### OP-12: PKI Channel Decryption

- **OPERATION**: Decrypt a PKI channel message
- **FILE**: src/lib/core/pki.ml (lines 68-74)
- **TYPE**: decrypt
- **INPUTS**: Private key `x`, encrypted message `{y_alpha, y_beta, y_data}`
- **OUTPUTS**: Plaintext string
- **ALGEBRAIC DEPENDENCY**: DDH (recover shared secret via `y_beta * invert(y_alpha^x)`)
- **PQ REPLACEMENT**: ML-KEM decapsulation + AES-GCM (stays)
- **DIFFICULTY**: medium -- matches OP-11

### OP-13: AES-CCM Symmetric Encryption

- **OPERATION**: AES-CCM authenticated encryption
- **FILE**: src/platform/native/platform.ml (lines 34-177)
- **TYPE**: encrypt
- **INPUTS**: Hex key, hex IV, plaintext string
- **OUTPUTS**: Hex ciphertext with authentication tag (64-bit tag)
- **ALGEBRAIC DEPENDENCY**: AES block cipher security
- **PQ REPLACEMENT**: None needed -- AES-256 is PQ-safe (Grover halves security, AES-256 -> 128-bit)
- **DIFFICULTY**: easy -- already PQ-safe

### OP-14: AES-GCM Symmetric Encryption

- **OPERATION**: AES-GCM authenticated encryption
- **FILE**: src/platform/native/platform.ml (lines 179-197)
- **TYPE**: encrypt
- **INPUTS**: Hex key, hex IV, plaintext string
- **OUTPUTS**: Hex ciphertext with authentication tag
- **ALGEBRAIC DEPENDENCY**: AES block cipher security
- **PQ REPLACEMENT**: None needed -- PQ-safe with AES-256
- **DIFFICULTY**: easy -- already PQ-safe

---

## 4. HOMOMORPHIC OPERATIONS

### OP-15: Homomorphic Ciphertext Addition (Ballot Tallying)

- **OPERATION**: Multiply ElGamal ciphertexts to add encrypted values
- **FILE**: src/lib/v1/question_h.ml (lines 67-68), src/lib/v1/question_l.ml (lines 64-65)
- **TYPE**: homomorphic_add
- **INPUTS**: Two ciphertexts `c1 = {alpha1, beta1}`, `c2 = {alpha2, beta2}`
- **OUTPUTS**: Combined ciphertext `{alpha1 * alpha2, beta1 * beta2}` (encrypts sum of plaintexts)
- **ALGEBRAIC DEPENDENCY**: Group homomorphism: `Enc(m1) * Enc(m2) = Enc(m1 + m2)`
- **PQ REPLACEMENT**: Lattice-based additively homomorphic encryption (BFV/BGV style, or custom)
- **DIFFICULTY**: hard -- finding PQ scheme with efficient additive homomorphism is open research
- **DETAILS**: Used in `process_ciphertexts` which supports weighted ballots via repeated squaring: `power b n` computes `b^n` via binary exponentiation of the homomorphic multiplication.

### OP-16: Weighted Ballot Aggregation

- **OPERATION**: Aggregate weighted ballots homomorphically
- **FILE**: src/lib/v1/question_h.ml (lines 396-412), src/lib/v1/question_l.ml (lines 344-363)
- **TYPE**: homomorphic_add
- **INPUTS**: List of (weight, ballot) pairs, where weight is a large integer
- **OUTPUTS**: Encrypted tally (one ciphertext per choice)
- **ALGEBRAIC DEPENDENCY**: Group homomorphism + efficient exponentiation
- **PQ REPLACEMENT**: Lattice homomorphic scheme with scalar multiplication support
- **DIFFICULTY**: hard -- weight support requires efficient scalar mult on ciphertexts

---

## 5. ZERO-KNOWLEDGE PROOFS

### OP-17: Fiat-Shamir Proof (Core Sigma Protocol)

- **OPERATION**: Non-interactive ZKP via Fiat-Shamir transform
- **FILE**: src/lib/v1/election.ml (lines 143-148), src/lib/v1/question_h.ml (lines 78-83), src/lib/v1/trustees.ml (lines 221-226)
- **TYPE**: zkp_prove
- **INPUTS**: Array of generators `gs`, secret `x`, oracle function (hash)
- **OUTPUTS**: Proof `{challenge, response}` where `response = w - x*challenge`
- **ALGEBRAIC DEPENDENCY**: Random oracle model, DLP for soundness
- **PQ REPLACEMENT**: Lattice-based Sigma protocol (Lyubashevsky's technique with rejection sampling)
- **DIFFICULTY**: hard -- Fiat-Shamir still works but the underlying Sigma protocol changes entirely
- **DETAILS**: `commitments = map (g -> g^w) gs; challenge = oracle(commitments); response = w - x*challenge`. Verification: `g^response * pk^challenge =? commitment`.

### OP-18: Schnorr Proof of Knowledge (Trustee PoK)

- **OPERATION**: Prove knowledge of discrete log of public key
- **FILE**: src/lib/v1/trustees.ml (lines 96-102, 230-241)
- **TYPE**: zkp_prove / zkp_verify
- **INPUTS**: Secret key x, public key y = g^x
- **OUTPUTS**: Proof `{challenge, response}`; verification checks `g^response * y^challenge =? commitment`
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: Lattice-based PoK (knowledge of RLWE secret)
- **DIFFICULTY**: hard
- **DETAILS**: Prefix: `"pok|{group_desc}|{pk_string}|"`. Verification: `commitment = g^response * y^challenge; challenge =? hash(prefix, commitment)`.

### OP-19: Ballot Signature (Schnorr signature with credential)

- **OPERATION**: Sign ballot with voter credential (Schnorr signature)
- **FILE**: src/lib/v1/election.ml (lines 164-190)
- **TYPE**: sign
- **INPUTS**: Voter private key `sk`, ballot hash
- **OUTPUTS**: Signature `{s_hash, s_proof = {challenge, response}}`
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: ML-DSA (Dilithium) or hash-based signature
- **DIFFICULTY**: medium -- straightforward signature replacement
- **DETAILS**: `credential = g^sk; w = random(); commitment = g^w; prefix = "sig|" + ballot_hash + "|"; challenge = hash(prefix, commitment); response = w - sk*challenge`. Verification (line 210-215): `commitment' = g^response * credential^challenge; challenge =? hash(prefix, commitment')`.

### OP-20: Ballot Signature Verification

- **OPERATION**: Verify ballot signature against public credential
- **FILE**: src/lib/v1/election.ml (lines 196-219)
- **TYPE**: verify_sig
- **INPUTS**: Ballot with signature, public credential
- **OUTPUTS**: Boolean (valid/invalid)
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: ML-DSA verification
- **DIFFICULTY**: medium -- matches OP-19

### OP-21: Disjunctive ZKP (Individual Choice Proofs)

- **OPERATION**: Prove an ElGamal ciphertext encrypts one of {0, 1} (Chaum-Pedersen OR-proof)
- **FILE**: src/lib/v1/question_h.ml (lines 87-127), src/lib/v1/question_l.ml (lines 84-124)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, decryption table d, plaintext x, randomness r, ciphertext {alpha, beta}
- **OUTPUTS**: Array of proofs (one real + n-1 simulated), one per disjunct
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle (Sigma-OR composition)
- **PQ REPLACEMENT**: Lattice-based OR-proof or generic MPC-in-the-head
- **DIFFICULTY**: research -- disjunctive proofs over lattice ciphertexts are active research area
- **DETAILS**: For the true branch x: compute genuine Fiat-Shamir proof. For all other branches: simulate with random challenge and response. Sum of all challenges must equal the hash. Prefix: `"prove|{zkp}|{alpha},{beta}|"`.

### OP-22: Disjunctive ZKP Verification

- **OPERATION**: Verify a disjunctive ZKP
- **FILE**: src/lib/v1/question_h.ml (lines 129-147), src/lib/v1/question_l.ml (lines 126-144)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, decryption table d, proofs, ciphertext
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle
- **PQ REPLACEMENT**: Matches OP-21
- **DIFFICULTY**: research

### OP-23: Overall Sum Range Proof

- **OPERATION**: Prove the sum of encrypted choices lies in [min, max]
- **FILE**: src/lib/v1/question_h.ml (lines 335-368)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, min, max bounds, sum of randomnesses, sum ciphertext
- **OUTPUTS**: Disjunctive proof over (max - min + 1) alternatives
- **ALGEBRAIC DEPENDENCY**: Same as OP-21 (disjunctive proof over range)
- **PQ REPLACEMENT**: Lattice-based range proof
- **DIFFICULTY**: research

### OP-24: Blank Ballot Proof (prove m0=0 OR mS=0)

- **OPERATION**: Prove blank indicator is consistent with choices
- **FILE**: src/lib/v1/question_h.ml (lines 151-271)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, blank ciphertext c0, sum ciphertext cS, randomnesses
- **OUTPUTS**: Two disjunctive proofs: blank_proof (m0=0 or mS=0) and overall_proof (m0=1 or min<=mS<=max)
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle
- **PQ REPLACEMENT**: Same class as OP-21 disjunctive proofs
- **DIFFICULTY**: research

### OP-25: Blank Ballot Proof Verification

- **OPERATION**: Verify blank ballot consistency proofs
- **FILE**: src/lib/v1/question_h.ml (lines 273-316)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, c0, cS, proofs
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle
- **PQ REPLACEMENT**: Matches OP-24
- **DIFFICULTY**: research

### OP-26: List Question Proof (prove m0=1 OR mS=0)

- **OPERATION**: Prove list question constraint
- **FILE**: src/lib/v1/question_l.ml (lines 169-215)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, choice values m, randomnesses r, ciphertexts c
- **OUTPUTS**: 2-element proof array (disjunctive proof)
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle
- **PQ REPLACEMENT**: Same class as OP-21
- **DIFFICULTY**: research
- **DETAILS**: Prefix `"lproof|{zkp}|"`. Similar structure to blank ballot proof.

### OP-27: List Question Proof Verification

- **OPERATION**: Verify list question constraint proof
- **FILE**: src/lib/v1/question_l.ml (lines 221-238)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, ciphertexts, proof
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: Same as OP-26
- **PQ REPLACEMENT**: Matches OP-26
- **DIFFICULTY**: research

### OP-28: Non-Zero Proof (prove ciphertext encrypts non-zero)

- **OPERATION**: Prove a ciphertext does not encrypt the identity element
- **FILE**: src/lib/v1/question_l.ml (lines 240-253)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, ciphertext {alpha, beta}, randomness r
- **OUTPUTS**: Proof `{ncommitment, nchallenge, nresponse=(t1,t2)}`
- **ALGEBRAIC DEPENDENCY**: DDH, random oracle
- **PQ REPLACEMENT**: Lattice-based inequality proof
- **DIFFICULTY**: research -- non-trivial ZKP construction
- **DETAILS**: Blinding factor `s`, commitment `ncommitment = beta^s * y^{-s*r}`. Prefix: `"nonzero|{zkp}|"`. Uses 2-component response `(t1, t2)`.

### OP-29: Non-Zero Proof Verification

- **OPERATION**: Verify non-zero ciphertext proof
- **FILE**: src/lib/v1/question_l.ml (lines 255-263)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, ciphertext, proof
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: Same as OP-28
- **PQ REPLACEMENT**: Matches OP-28
- **DIFFICULTY**: research

### OP-30: Non-Homomorphic Question ZKP (raw ElGamal knowledge proof)

- **OPERATION**: Prove knowledge of randomness in raw ElGamal encryption
- **FILE**: src/lib/v1/question_nh.ml (lines 51-71)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, ciphertext {alpha, beta}, randomness r
- **OUTPUTS**: Proof `{challenge, response}`
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: Lattice-based knowledge proof
- **DIFFICULTY**: hard
- **DETAILS**: Prefix: `"raweg|{prefix}|{y},{alpha},{beta}|"`. Standard Schnorr-like proof of knowing r such that alpha = g^r.

### OP-31: Non-Homomorphic Question ZKP Verification

- **OPERATION**: Verify raw ElGamal knowledge proof
- **FILE**: src/lib/v1/question_nh.ml (lines 73-83)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, ciphertext, proof
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: Same as OP-30
- **PQ REPLACEMENT**: Matches OP-30
- **DIFFICULTY**: hard

---

## 6. PARTIAL DECRYPTION AND THRESHOLD

### OP-32: Partial Decryption Factor Computation

- **OPERATION**: Trustee computes their decryption share with ZKP
- **FILE**: src/lib/v1/election.ml (lines 297-309)
- **TYPE**: threshold_decrypt
- **INPUTS**: Private key share `x`, ciphertext shape (array of `{alpha, beta}`)
- **OUTPUTS**: Decryption factors `alpha^x` for each ciphertext, plus Chaum-Pedersen proof
- **ALGEBRAIC DEPENDENCY**: DLP, DDH (Chaum-Pedersen proof of correct decryption)
- **PQ REPLACEMENT**: Lattice-based partial decryption with ZKP
- **DIFFICULTY**: hard -- requires ZKP of correct partial decryption
- **DETAILS**: For each ciphertext: `factor = alpha^x`; proof via `fs_prove [|g; alpha|] x (hash zkp)` with prefix `"decrypt|{fingerprint}|{g^x}|"`.

### OP-33: Partial Decryption Factor Verification

- **OPERATION**: Verify a trustee's decryption share
- **FILE**: src/lib/v1/election.ml (lines 311-324)
- **TYPE**: zkp_verify
- **INPUTS**: Ciphertext, trustee public key `y`, decryption factor `f`, proof
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: DDH, random oracle (Chaum-Pedersen verification)
- **PQ REPLACEMENT**: Matches OP-32
- **DIFFICULTY**: hard
- **DETAILS**: Verifies `g^response * y^challenge = commitment1` AND `alpha^response * f^challenge = commitment2`.

### OP-34: Factor Combination (Result Computation)

- **OPERATION**: Combine all partial decryption factors to recover result
- **FILE**: src/lib/v1/election.ml (lines 331-344)
- **TYPE**: decrypt
- **INPUTS**: Encrypted tally, all partial decryption factors, trustee structure
- **OUTPUTS**: Decrypted result (plaintext group elements `beta / combined_factor`)
- **ALGEBRAIC DEPENDENCY**: Group operations, Lagrange interpolation (for threshold)
- **PQ REPLACEMENT**: Lattice-based threshold combination
- **DIFFICULTY**: hard

### OP-35: Lagrange Interpolation (Threshold Secret Sharing)

- **OPERATION**: Compute Lagrange coefficients for threshold reconstruction
- **FILE**: src/lib/v1/trustees.ml (lines 179-184)
- **TYPE**: threshold_decrypt
- **INPUTS**: Set of participant indices, target index j
- **OUTPUTS**: Lagrange coefficient lambda_j in Z_q
- **ALGEBRAIC DEPENDENCY**: Polynomial interpolation in Z_q
- **PQ REPLACEMENT**: Same -- Lagrange interpolation is algebraically generic
- **DIFFICULTY**: easy -- pure arithmetic, PQ-safe

### OP-36: Threshold Factor Combination

- **OPERATION**: Combine threshold partial decryptions using Lagrange coefficients
- **FILE**: src/lib/v1/trustees.ml (lines 186-209)
- **TYPE**: threshold_decrypt
- **INPUTS**: Trustees structure, partial decryptions with indices, verification function
- **OUTPUTS**: Combined decryption factor
- **ALGEBRAIC DEPENDENCY**: Lagrange interpolation + group exponentiation
- **PQ REPLACEMENT**: Lattice-based threshold combination (share reconstruction in lattice setting)
- **DIFFICULTY**: hard
- **DETAILS**: `fold` computes `product(factor_j^{lambda_j})` over all participating trustees.

### OP-37: Baby-Step Giant-Step Discrete Log (Result Decoding)

- **OPERATION**: Compute discrete log of `g^m` to recover tally count `m`
- **FILE**: src/lib/core/common.ml (lines 227-265)
- **TYPE**: decrypt (discrete log computation)
- **INPUTS**: Generator alpha, upper bound max, target element beta
- **OUTPUTS**: Scalar m such that `alpha^m = beta`
- **ALGEBRAIC DEPENDENCY**: Discrete log (small range brute force)
- **PQ REPLACEMENT**: Not needed if switching away from exponential ElGamal encoding
- **DIFFICULTY**: medium -- depends on new encryption scheme's plaintext space
- **DETAILS**: Standard BSGS with table of size sqrt(max). Finds `m = i*sqrt(max) + j` via hash table lookup.

---

## 7. DISTRIBUTED KEY GENERATION (PEDERSEN DKG)

### OP-38: Pedersen DKG Step 1 (Certificate Generation)

- **OPERATION**: Generate Pedersen DKG certificate
- **FILE**: src/lib/v1/trustees.ml (lines 260-268)
- **TYPE**: dkg
- **INPUTS**: Context (group, size, threshold, index)
- **OUTPUTS**: Seed, signed certificate containing verification key `g^sk` and encryption key `g^dk`
- **ALGEBRAIC DEPENDENCY**: DLP for public keys, Schnorr signature for cert
- **PQ REPLACEMENT**: Lattice-based DKG certificates
- **DIFFICULTY**: hard

### OP-39: Pedersen DKG Step 3 (Polynomial Generation)

- **OPERATION**: Generate secret sharing polynomial and encrypted shares
- **FILE**: src/lib/v1/trustees.ml (lines 293-355)
- **TYPE**: dkg
- **INPUTS**: Certificates array, seed
- **OUTPUTS**: Polynomial coefficients, encrypted secrets for each participant, coefficient exponentiations `g^a_k`, signatures
- **ALGEBRAIC DEPENDENCY**: Shamir secret sharing in Z_q, DLP for commitments, ElGamal+AES for channel encryption
- **PQ REPLACEMENT**: Lattice-based VSS (verifiable secret sharing)
- **DIFFICULTY**: hard -- entire VSS protocol changes
- **DETAILS**: Polynomial `a_0, ..., a_{t-1}` random in Z_q. Shares `s_{ij} = sum(a_k * j^k)`. Commitments `g^{a_k}`. Shares encrypted via `C.send` (hybrid ElGamal+AES).

### OP-40: Pedersen DKG Step 5 (Verification and Key Assembly)

- **OPERATION**: Verify received shares and assemble threshold key
- **FILE**: src/lib/v1/trustees.ml (lines 420-501)
- **TYPE**: dkg
- **INPUTS**: Certificates, seed, vinput (encrypted polynomial + secrets)
- **OUTPUTS**: Verification output (public key + encrypted private key)
- **ALGEBRAIC DEPENDENCY**: DLP for commitment verification, Feldman VSS
- **PQ REPLACEMENT**: Lattice-based Feldman VSS
- **DIFFICULTY**: hard
- **DETAILS**: Verifies `g^{s_ij} =? product(commitment_k^{j^k})` for each share. Sums all received shares to get `pdk_decryption_key`. Proves knowledge of this key via Schnorr PoK.

### OP-41: Verification Key Computation

- **OPERATION**: Compute verification keys from coefficient exponentiations
- **FILE**: src/lib/v1/trustees.ml (lines 67-89)
- **TYPE**: dkg
- **INPUTS**: Array of arrays of coefficient exponentiations `g^{a_{i,k}}`
- **OUTPUTS**: Array of verification keys (one per trustee)
- **ALGEBRAIC DEPENDENCY**: Group exponentiation, polynomial evaluation in exponent
- **PQ REPLACEMENT**: Lattice-based verification keys
- **DIFFICULTY**: hard
- **DETAILS**: `vk_j = product_i(product_k(coefexp_{i,k}^{j^k}))`.

### OP-42: Combined Public Key Computation

- **OPERATION**: Combine individual/threshold trustee keys into election public key
- **FILE**: src/lib/v1/trustees.ml (lines 168-177)
- **TYPE**: keygen
- **INPUTS**: List of trustee structures (Single or Pedersen)
- **OUTPUTS**: Combined election public key `y = product(y_i)`
- **ALGEBRAIC DEPENDENCY**: Group multiplication (combining DLP-based public keys)
- **PQ REPLACEMENT**: Key combination in lattice setting (if additive, can combine similarly)
- **DIFFICULTY**: hard

---

## 8. MIXNET (SHUFFLE)

### OP-43: Re-encryption Shuffle

- **OPERATION**: Re-encrypt and shuffle an array of ciphertexts
- **FILE**: src/lib/v1/mixnet.ml (lines 50-59)
- **TYPE**: encrypt (re-encryption)
- **INPUTS**: Public key y, array of ciphertexts
- **OUTPUTS**: Shuffled re-encrypted ciphertexts, randomnesses, permutation
- **ALGEBRAIC DEPENDENCY**: DDH (re-encryption security), permutation hiding
- **PQ REPLACEMENT**: Lattice-based re-encryption mixnet
- **DIFFICULTY**: research -- PQ re-encryption mixnets are open research
- **DETAILS**: `re_encrypt y {alpha, beta} r = {alpha * g^r, beta * y^r}`. Random permutation via Fisher-Yates.

### OP-44: Shuffle Proof Generation (Bayer-Groth style)

- **OPERATION**: Generate ZKP that shuffle was performed correctly
- **FILE**: src/lib/v1/mixnet.ml (lines 123-181)
- **TYPE**: zkp_prove
- **INPUTS**: Public key y, original ciphertexts, shuffled ciphertexts, randomnesses, permutation
- **OUTPUTS**: Proof tuple `(t, s, cc, cc_hat)` containing commitment chain, challenge responses
- **ALGEBRAIC DEPENDENCY**: DLP, DDH, random oracle, commitment schemes
- **PQ REPLACEMENT**: Lattice-based shuffle proof (extremely active research area)
- **DIFFICULTY**: research -- this is one of the hardest operations to make PQ
- **DETAILS**: Uses permutation commitments with independent generators `h_i = get_generator(i)`. Commitment chain `cc_hat`. Multiple Fiat-Shamir challenges. Challenge computation via `sha256_hex` with prefix `"shuffle-challenge|{fingerprint}|"` and `"shuffle-challenges|{fingerprint}|"`.

### OP-45: Shuffle Proof Verification

- **OPERATION**: Verify shuffle proof
- **FILE**: src/lib/v1/mixnet.ml (lines 183-251)
- **TYPE**: zkp_verify
- **INPUTS**: Public key y, original and shuffled ciphertexts, proof
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: Same as OP-44
- **PQ REPLACEMENT**: Matches OP-44
- **DIFFICULTY**: research

---

## 9. PKI SIGNATURES

### OP-46: PKI Schnorr Signature (Certificate/Message Signing)

- **OPERATION**: Sign a message using Schnorr signature
- **FILE**: src/lib/core/pki.ml (lines 41-48)
- **TYPE**: sign
- **INPUTS**: Private key sk, message string
- **OUTPUTS**: Signed message `{s_message, s_signature = {challenge, response}}`
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: ML-DSA (Dilithium) signature
- **DIFFICULTY**: medium
- **DETAILS**: Prefix: `"sigmsg|{message}|"`. Same Fiat-Shamir structure: `commitment = g^w; challenge = hash(prefix, commitment); response = w - sk*challenge`.

### OP-47: PKI Schnorr Signature Verification

- **OPERATION**: Verify a PKI Schnorr signature
- **FILE**: src/lib/core/pki.ml (lines 50-53)
- **TYPE**: verify_sig
- **INPUTS**: Verification key vk, signed message
- **OUTPUTS**: Boolean
- **ALGEBRAIC DEPENDENCY**: DLP, random oracle
- **PQ REPLACEMENT**: ML-DSA verification
- **DIFFICULTY**: medium

---

## 10. HASH FUNCTIONS

### OP-48: SHA-256 Hex Hash

- **OPERATION**: Compute SHA-256 hash, output as hex
- **FILE**: src/lib/core/common.ml (line 52)
- **TYPE**: hash
- **INPUTS**: String
- **OUTPUTS**: 64-character hex string
- **ALGEBRAIC DEPENDENCY**: Collision resistance of SHA-256
- **PQ REPLACEMENT**: SHA-256 is PQ-safe (Grover reduces to 128-bit preimage; collision resistance unaffected for SHA-256)
- **DIFFICULTY**: easy -- no change needed
- **DETAILS**: `Digestif.SHA256.(digest_string >> to_hex)`. Used everywhere: Fiat-Shamir challenges, key derivation, fingerprints, generator derivation.

### OP-49: SHA-256 Base64 Hash

- **OPERATION**: Compute SHA-256 hash, output as base64
- **FILE**: src/lib/core/common.ml (line 53), src/lib/core/common_types.ml (line 89)
- **TYPE**: hash
- **INPUTS**: String
- **OUTPUTS**: Base64-encoded hash (43 chars without padding)
- **ALGEBRAIC DEPENDENCY**: Same as OP-48
- **PQ REPLACEMENT**: None needed
- **DIFFICULTY**: easy

### OP-50: Group Hash (hash-to-scalar)

- **OPERATION**: Hash group elements to a scalar (for Fiat-Shamir)
- **FILE**: src/lib/core/group_field.ml (lines 99-101), src/lib/core/ed25519_pure.ml (lines 245-247), src/lib/core/ed25519_libsodium.ml (lines 150-152)
- **TYPE**: hash
- **INPUTS**: Prefix string, array of group elements
- **OUTPUTS**: Scalar in Z_q
- **ALGEBRAIC DEPENDENCY**: Random oracle model (SHA-256 -> reduce mod q)
- **PQ REPLACEMENT**: SHA-256 hash stays; reduce_hex to new scalar field
- **DIFFICULTY**: easy -- hash function is PQ-safe, just need new field reduction

### OP-51: Generator Derivation (hash-to-group-element)

- **OPERATION**: Deterministically derive independent group generators
- **FILE**: src/lib/core/group_field.ml (lines 106-116), src/lib/core/ed25519_pure.ml (lines 257-271)
- **TYPE**: hash
- **INPUTS**: Integer index i
- **OUTPUTS**: Group element generator #i
- **ALGEBRAIC DEPENDENCY**: Hash-to-group (cofactor clearing for Ed25519, exponentiation for finite fields)
- **PQ REPLACEMENT**: Lattice hash-to-point or structured reference string
- **DIFFICULTY**: hard -- different group means different hash-to-element
- **DETAILS**: Finite field: `h = SHA256("ggen|i")^{(p-1)/q} mod p`. Ed25519: `SHA256("ggen|i") >> 2` then try uncompress until valid, multiply by cofactor 8.

### OP-52: NIZKP Challenges for Shuffle

- **OPERATION**: Derive array of challenges for shuffle proof
- **FILE**: src/lib/v1/mixnet.ml (lines 74-80)
- **TYPE**: hash
- **INPUTS**: Number of challenges n, string to hash
- **OUTPUTS**: Array of n scalars
- **ALGEBRAIC DEPENDENCY**: Random oracle (iterated SHA-256)
- **PQ REPLACEMENT**: None needed for hash itself
- **DIFFICULTY**: easy
- **DETAILS**: `h = sha256_hex(str); for each i: sha256_hex(sha256_hex(i) ^ h) |> Zq.reduce_hex`.

### OP-53: HMAC-SHA256 (Message Authentication)

- **OPERATION**: Compute HMAC-SHA256 for message integrity
- **FILE**: src/web/server/messages/belenios_messages.ml (lines 39-43)
- **TYPE**: hash
- **INPUTS**: Key string, message string
- **OUTPUTS**: Hex-encoded HMAC hash
- **ALGEBRAIC DEPENDENCY**: PRF security of HMAC-SHA256
- **PQ REPLACEMENT**: None needed -- HMAC-SHA256 is PQ-safe
- **DIFFICULTY**: easy

### OP-54: Password Hashing (SHA-256 with salt)

- **OPERATION**: Hash passwords with salt for storage
- **FILE**: src/web/server/common/web_auth_password.ml (lines 174, 194), src/web/server/common/web_common.ml (line 138)
- **TYPE**: hash
- **INPUTS**: Salt string, password string
- **OUTPUTS**: SHA-256 hex hash of concatenation
- **ALGEBRAIC DEPENDENCY**: Preimage resistance
- **PQ REPLACEMENT**: None needed (but should use bcrypt/Argon2 regardless of PQ)
- **DIFFICULTY**: easy

---

## 11. RANDOM NUMBER GENERATION

### OP-55: Secure Random Number Generation

- **OPERATION**: Generate cryptographically secure random bytes
- **FILE**: src/platform/native/platform.ml (lines 206-213)
- **TYPE**: random
- **INPUTS**: Length in bytes
- **OUTPUTS**: Random byte string
- **ALGEBRAIC DEPENDENCY**: CSPRNG security
- **PQ REPLACEMENT**: None needed
- **DIFFICULTY**: easy
- **DETAILS**: Uses `Cryptokit.Random.secure_rng` (OS entropy). Pseudo-RNG via `Cryptokit.Random.pseudo_rng` for deterministic credential generation.

### OP-56: Random Scalar Generation

- **OPERATION**: Generate random scalar in Z_q
- **FILE**: src/lib/core/common.ml (lines 98-107)
- **TYPE**: random
- **INPUTS**: Prime modulus q, RNG
- **OUTPUTS**: Random element in [0, q)
- **ALGEBRAIC DEPENDENCY**: Uniform distribution
- **PQ REPLACEMENT**: Same for lattice scalar fields
- **DIFFICULTY**: easy
- **DETAILS**: Generate random bytes, mask to bit length of q, reject if >= q. Constant-time concerns noted in platform.ml: "Warning: no efforts have been made to be constant time in the rest of the code."

### OP-57: Token Generation (Base58)

- **OPERATION**: Generate random base58 tokens (UUIDs, credentials)
- **FILE**: src/lib/core/common.ml (lines 184-216)
- **TYPE**: random
- **INPUTS**: Length, digit set
- **OUTPUTS**: Random string of specified length from digit set
- **ALGEBRAIC DEPENDENCY**: CSPRNG security
- **PQ REPLACEMENT**: None needed
- **DIFFICULTY**: easy

---

## 12. ELECTION INTEGRITY

### OP-58: Election Fingerprint

- **OPERATION**: Compute election parameter fingerprint
- **FILE**: src/lib/v1/election.ml (line 97)
- **TYPE**: hash
- **INPUTS**: Raw election JSON string
- **OUTPUTS**: Base64 SHA-256 hash
- **ALGEBRAIC DEPENDENCY**: Collision resistance
- **PQ REPLACEMENT**: None needed
- **DIFFICULTY**: easy
- **DETAILS**: `fingerprint = sha256_b64 R.raw_election`. Used as prefix in all ZKP constructions.

### OP-59: Ballot Hash / Smart Ballot Tracker

- **OPERATION**: Hash serialized ballot for tracking
- **FILE**: src/lib/v1/election.ml (lines 177-179, 201-203)
- **TYPE**: hash
- **INPUTS**: Serialized ballot JSON
- **OUTPUTS**: Base64 SHA-256 hash
- **ALGEBRAIC DEPENDENCY**: Collision resistance
- **PQ REPLACEMENT**: None needed
- **DIFFICULTY**: easy

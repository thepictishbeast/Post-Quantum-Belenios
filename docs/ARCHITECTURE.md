# PQHV Architecture

## Overview

PQHV replaces the discrete-log-based cryptography in Belenios with lattice-based
primitives that are resistant to quantum computers. The core insight is that
Module-LWE encryption is additively homomorphic: you can sum encrypted votes
without decrypting them, then decrypt only the final tally.

## Cryptographic Stack

```
┌─────────────────────────────────────────────────┐
│                 pqhv-protocol                    │
│  Full election lifecycle: setup → vote → tally   │
├────────────┬──────────────┬─────────────────────┤
│  pqhv-zkp  │pqhv-threshold│    pqhv-wasm        │
│  Ballot     │  Distributed │    Browser-side     │
│  validity   │  key gen &   │    encryption &     │
│  proofs     │  decryption  │    verification     │
├────────────┴──────────────┴─────────────────────┤
│                  pqhv-core                       │
│  Module-LWE: keygen, encrypt, decrypt, add       │
│  Polynomial ring arithmetic, noise management    │
└─────────────────────────────────────────────────┘
```

## Module-LWE Encryption (pqhv-core)

### Algebraic Foundation

All arithmetic happens in the polynomial ring:

    R_q = Z_q[X] / (X^n + 1)

where `n` is a power of 2 (the ring dimension) and `q` is the ciphertext modulus.
Elements of this ring are polynomials of degree < n with coefficients in Z_q.

The **Module-LWE** problem operates on vectors and matrices of ring elements,
parameterized by the module rank `k`. The security assumption is that
`(A, As + e)` is computationally indistinguishable from uniform, where `A` is
a random k×k matrix over R_q and `s, e` are vectors with small coefficients.

### Homomorphic Property

The key property enabling private vote tallying:

    Enc(m₁) + Enc(m₂) = Enc(m₁ + m₂)

This holds because encryption is linear — adding ciphertext components adds
the underlying plaintexts (modulo noise accumulation). After summing N encrypted
votes, a single decryption reveals the vote count without ever exposing
individual votes.

### Noise Budget

Each encryption introduces a small noise term. Homomorphic additions accumulate
noise linearly. Decryption succeeds only if the total noise stays below q/4.

    noise_budget ≈ q / (4 · η · √n)

where η is the noise distribution parameter. The voting parameter set uses
q = 2²³ to support up to 100,000 homomorphic additions.

### Message Encoding

For yes/no votes, a single bit m ∈ {0, 1} is encoded as:

    encode(m) = m · ⌊q/2⌋

Decoding rounds the noisy result to the nearest multiple of ⌊q/2⌋.

For multi-candidate elections, each candidate gets a separate ciphertext
encrypting 0 or 1, and tallying sums each position independently.

## Belenios Compatibility

The Belenios audit (see `docs/belenios-crypto-audit.md`) identified 59
cryptographic operations. Of these:

- **15 are PQ-safe as-is** (SHA-256 hashing, CSPRNG, AES, PBKDF2)
- **8 can be upgraded independently** (hash function choice, key derivation)
- **36 must be replaced** (all ElGamal and discrete-log-dependent operations)

The `e_version` field in Belenios election parameters provides a clean
migration path: PQ elections use `e_version = 2` with the new lattice-based
cryptographic formats.

## Performance Targets

| Operation | Target | Bottleneck |
|-----------|--------|------------|
| Key generation | < 1 sec | Matrix sampling + multiplication |
| Single encryption | < 500 ms | Two matrix-vector products |
| Single decryption | < 100 ms | One inner product |
| Ciphertext addition | < 1 ms | Component-wise vector addition |
| Tally 10,000 votes | < 30 sec | Dominated by encryption time |

The primary bottleneck is polynomial multiplication (currently O(n²) schoolbook).
NTT optimization will bring this to O(n log n) in a future phase.

## Security Considerations

- **No unsafe Rust**: All cryptographic code uses safe Rust only
- **Zeroize**: Secret keys implement `Zeroize` for secure memory erasure
- **Constant-time operations**: Critical comparisons will use constant-time
  primitives (future work, after correctness is established)
- **Parameter validation**: All parameter sets are validated at construction time
- **Noise tracking**: Noise budget is computed and checked to prevent silent
  decryption failures

# PQHV — Post-Quantum Homomorphic Voting

Every online voting system used today relies on cryptography that quantum computers will break. When that happens, election results become forgeable — anyone with a sufficiently powerful quantum machine could decrypt ballots, fabricate tallies, or impersonate voters. PQHV is a drop-in replacement for the cryptographic core of verifiable voting systems, built on mathematics that quantum computers cannot crack.

## The Problem

The [Belenios](https://www.belenios.org/) protocol is one of the most widely deployed verifiable voting systems, used in French institutional elections and academic governance worldwide. Its security depends entirely on the classical ElGamal encryption scheme, which NIST has confirmed will be broken by cryptographically relevant quantum computers within the next decade. No quantum-safe alternative exists that preserves Belenios's critical properties: additive homomorphism (tallying encrypted votes without decrypting them), verifiable ballot validity (zero-knowledge proofs that each vote is well-formed), and threshold decryption (no single entity can decrypt individual ballots).

## How It Works

PQHV replaces ElGamal with a lattice-based encryption scheme (Module-LWE) that provides the same additive homomorphism — encrypted votes can still be summed without decryption — while resisting quantum attacks. The project is structured as a Rust workspace with modular crates that mirror Belenios's cryptographic pipeline: key generation, ballot encryption, zero-knowledge proofs, threshold decryption, and full election lifecycle.

## Current Status

| Crate | Purpose | Status |
|-------|---------|--------|
| `pqhv-core` | Additively homomorphic Module-LWE encryption | ✅ Working, 78 tests |
| `pqhv-zkp` | Disjunctive Sigma protocol ballot validity proofs | ✅ Working, 13 tests |
| `pqhv-threshold` | Threshold decryption (additive + Shamir sharing) | ✅ Working, 30 tests |
| `pqhv-protocol` | Full election protocol (setup → vote → tally → verify) | 📋 Planned |
| `pqhv-wasm` | WebAssembly bindings for client-side ballot encryption | 📋 Planned |
| `pqhv-bench` | Criterion benchmarks for all operations | ✅ Working |

## Quick Start

```bash
git clone https://github.com/redcaptian1917/Post-Quantum-Belenios.git
cd Post-Quantum-Belenios

# Build everything
cargo build --workspace

# Run all 141 tests
TMPDIR=$HOME/.cargo/tmp cargo test --workspace

# Run benchmarks
cargo bench
```

## Cryptographic Design

The core encryption scheme is **additively homomorphic Module-LWE**:

- **Key generation**: Sample secret vector `s` with small coefficients, compute `b = As + e` where `A` is a random matrix and `e` is noise
- **Encryption**: `Enc(m) = (Aᵀr + e₁, bᵀr + e₂ + ⌊q/2⌋·m)` where `r, e₁, e₂` are noise vectors
- **Homomorphic addition**: `Enc(m₁) + Enc(m₂) = Enc(m₁ + m₂)` — component-wise addition of ciphertext vectors
- **Decryption**: `m' = v - sᵀu`, then round to recover the message bit

The scheme operates in the polynomial ring `R_q = Z_q[X] / (X^n + 1)` with module rank `k`, providing NIST Level 3 (~128-bit quantum) security.

## Parameter Sets

| Parameter Set | n | k | q | Max Additions | Security |
|---------------|---|---|---|---------------|----------|
| `PQHV_VOTING_128` | 256 | 3 | 2²³ | 100,000 | NIST Level 3 |
| `PQHV_TEST` | 64 | 2 | 12,289 | 1,000 | TEST ONLY |

## Research Plan

See `docs/` for the Belenios cryptographic audit and replacement boundary analysis.

## The PlausiDen Ecosystem

PQHV is the cryptographic foundation for [Sacred.Vote](https://sacred.vote), a zero-trust polling platform where voter identity is mathematically decoupled from ballot records. It replaces Sacred.Vote's current Belenios integration with quantum-resistant primitives. Related repositories: [sacredvote-gatekeeper](https://github.com/redcaptian1917/sacredvote-gatekeeper) (election lifecycle manager), [plausiden-zktls](https://github.com/redcaptian1917/plausiden-zktls) (voter identity verification).

## License

AGPL-3.0-or-later (matching Belenios)

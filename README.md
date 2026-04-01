# PQHV — Post-Quantum Homomorphic Voting

A post-quantum fork of the [Belenios](https://www.belenios.org/) verifiable online voting protocol. Replaces Belenios's classical ElGamal cryptographic core with lattice-based (Module-LWE) primitives while preserving the protocol's verifiability and privacy guarantees.

## Architecture

| Crate | Purpose | Status |
|-------|---------|--------|
| `pqhv-core` | Additively homomorphic Module-LWE encryption | **Active** |
| `pqhv-zkp` | Lattice-based zero-knowledge proofs for ballot validity | Placeholder |
| `pqhv-threshold` | Lattice-based threshold decryption (distributed tallying) | Placeholder |
| `pqhv-protocol` | Full election protocol (setup → vote → tally → verify) | Placeholder |
| `pqhv-wasm` | WebAssembly bindings for client-side ballot encryption | Placeholder |
| `pqhv-bench` | Criterion benchmarks for all operations | **Active** |

## Quick Start

```bash
# Build everything
cargo build --workspace

# Run all tests
cargo test --workspace

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

## License

AGPL-3.0-or-later (matching Belenios)

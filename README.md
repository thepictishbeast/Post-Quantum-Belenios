> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# belenios-pqhv

Making the gold-standard verifiable election system quantum-resistant. This project integrates post-quantum lattice-based cryptography into Belenios, replacing the classical ElGamal encryption that a sufficiently powerful quantum computer could break -- ensuring that elections verified today remain secure against tomorrow's threats.

## The Problem

Belenios is widely regarded as the most rigorous open-source verifiable voting system available, with formal security proofs and real-world deployments in institutional elections. However, its cryptographic foundation relies on the hardness of the discrete logarithm problem (ElGamal), which Shor's algorithm can solve efficiently on a quantum computer. Harvest-now-decrypt-later attacks are already a documented threat: adversaries can record encrypted ballots today and decrypt them when quantum hardware matures, retroactively compromising voter privacy. Elections that must remain confidential for decades -- union votes, board elections, political primaries -- cannot rely on classically-secure cryptography alone.

## How It Works

belenios-pqhv replaces Belenios's ElGamal encryption layer with Module-LWE (Learning With Errors) lattice-based cryptography from the [pqhv workspace](https://github.com/thepictishbeast/Post-Quantum-Belenios), while preserving Belenios's verifiability properties and trust model.

```
+---------------------------+
|     Belenios Frontend     |  -- Voter-facing UI (unchanged)
+---------------------------+
            |
            v
+---------------------------+
|     Ballot Encryption     |  -- REPLACED: ElGamal -> Module-LWE
|     (pqhv-core)          |     Lattice-based key encapsulation
+---------------------------+
            |
            v
+---------------------------+
|     Homomorphic Tally     |  -- MODIFIED: Additive homomorphism
|                           |     via lattice operations
+---------------------------+
            |
            v
+---------------------------+
|     Verification          |  -- MODIFIED: Lattice-based proofs
|     (Individual + Univ.)  |     replacing Schnorr proofs
+---------------------------+
            |
            v
+---------------------------+
|     Belenios Trust Model  |  -- PRESERVED: Threshold trustees,
|                           |     credential authority separation
+---------------------------+
```

**Key design decisions:**

- **Module-LWE over NTRU or code-based.** Module-LWE (the basis of NIST's ML-KEM/Kyber standard) provides the best balance of security confidence, performance, and key size for the voting context.
- **Preserve Belenios verifiability.** The replacement must maintain individual verifiability (voters can check their ballot was recorded) and universal verifiability (anyone can check the tally is correct). This constrains the lattice scheme to support additive homomorphism.
- **Incremental replacement.** The cryptographic layer is replaced while the trust model, credential management, and frontend remain intact. This limits the audit surface to the cryptographic core.

**References:**

- [Belenios upstream](https://www.belenios.org/) -- The original verifiable voting system
- [pqhv workspace](https://github.com/thepictishbeast/Post-Quantum-Belenios) -- The Rust implementation of Module-LWE primitives (keygen, encrypt, decrypt)
- This work corresponds to Phase 4+ of the PQHV research plan

## Current Status

| Component | Status |
|-----------|--------|
| Belenios cryptographic audit | ✅ Complete (crypto map, dependency graph, replacement boundary) |
| pqhv-core (Module-LWE primitives) | ✅ Implemented (keygen, encrypt, decrypt, tests, benchmarks) |
| ElGamal replacement integration | 📋 Planned |
| Homomorphic tally adaptation | 📋 Planned |
| Lattice-based proof system | 📋 Planned |
| Verification protocol update | 📋 Planned |
| Security proof adaptation | 📋 Planned |
| End-to-end integration tests | 📋 Planned |

## Quick Start

> **Note:** This repository is in early stages. The cryptographic primitives are implemented in [pqhv](https://github.com/thepictishbeast/Post-Quantum-Belenios); integration with Belenios is planned.

```bash
git clone https://github.com/thepictishbeast/Post-Quantum-Belenios.git
cd belenios-pqhv

# For the lattice crypto primitives:
git clone https://github.com/thepictishbeast/Post-Quantum-Belenios.git ../pqhv
cd ../pqhv
cargo test
cargo bench
```

## The PlausiDen Ecosystem

belenios-pqhv is the long-term cryptographic foundation for [Sacred.Vote](https://sacred.vote). Sacred.Vote currently uses Belenios for verifiable elections; this project ensures that the cryptographic guarantees survive the transition to post-quantum computing. The lattice primitives in [pqhv](https://github.com/thepictishbeast/Post-Quantum-Belenios) are developed as a standalone library so other verifiable voting systems can adopt them independently.

Related repositories:
- [Sacred.Vote](https://github.com/thepictishbeast/Sacred.Vote) -- The voting platform that will adopt this integration
- [pqhv](https://github.com/thepictishbeast/Post-Quantum-Belenios) -- Module-LWE cryptographic primitives (standalone)
- [Belenios upstream](https://www.belenios.org/) -- The original verifiable voting system

## License

Licensed under AGPL-3.0, matching the Belenios upstream license. See [LICENSE](LICENSE) for details.

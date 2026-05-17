# SPHINCS+C10 Verifier — Formal Verification

This directory contains the **mechanised formal verification stack** for
the SPHINCS+C10 cryptographic verifier contract
(`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`, 202 lines of
Yul), implementing the playbook in
[`../docs/how_to_math_proof_secureness.md`](../docs/how_to_math_proof_secureness.md).

## Scope (2026-05)

**In scope.** A Lean 4 project that produces machine-checked theorems
about `SPHINCsC10Asm.sol`:

  1. **Specification** — a declarative SPHINCS+C10 verifier in Lean,
     matching the Rust reference (`sphincs-c10/`) byte-for-byte.
  2. **Functional correctness** — signing/verifying round-trip and
     rejection of malformed inputs.
  3. **Refinement** — the offset-indexed verifier (Yul shape) is
     extensionally equal to the structured spec verifier.
  4. **Bridge to EVM bytecode** — three named TCB axioms (solc 0.8.28,
     EVM semantics, SHA-256 precompile) explicitly documented.

Plus a precise inventory of the **cryptographic and TCB axioms** the
end-to-end "deployed verifier bytecode is correct" claim rests on.

**Out of scope.**

* **Wallet contracts.** `PQSmartWallet.sol`, `PQMultiOwnable.sol`, and
  `PQSmartWalletFactory.sol` are not currently verified. The Lean
  files under `SphincsCVerify/Wallet/` are legacy and may be removed
  in a future cleanup commit.
* **Hardware-wallet firmware.** The Rust codebase (`secure/`,
  `nonsecure/`, workspace crates) is not in scope.

A separate engagement could verify the wallet contracts on top of the
proven verifier, treating the verifier as a black-box hypothesis.

## Status (2026-05)

| Component | Status |
|---|---|
| `lake build` end-to-end | ✅ Succeeds on Lean 4.22.0 |
| Closed core (kernel-checked, no `sorry`) | ✅ ~10 verifier theorems (parameter arithmetic, size lemmas, `verify_deterministic`, `verify_rejects_wrong_length`, `yul_eq_refined`) |
| Cryptographic axioms (EUF-CMA stratum) | 🔓 4 stated axioms with citations |
| EVM / compilation TCB axioms | 🔓 3 stated axioms |
| Mechanical-discharge `sorry`s | 📌 11 `sorry`s and stubs — phased plan in [`docs/OPEN_PROOF_OBLIGATIONS.md`](docs/OPEN_PROOF_OBLIGATIONS.md) |

```bash
cd lean
elan toolchain install $(cat lean-toolchain)
lake build

lake env lean --run scripts/check_no_sorry.lean
lake env lean --run scripts/dump_axioms.lean

lake exe verify-test-vectors   # available after Phase 7
```

`dump_axioms.lean` confirms every headline closed theorem depends only
on the universal Lean axioms (`propext`, `Classical.choice`,
`Quot.sound`) — no cryptographic assumption leaks into the closed core.

## Roadmap

The complete remaining work is in
[`docs/OPEN_PROOF_OBLIGATIONS.md`](docs/OPEN_PROOF_OBLIGATIONS.md), with
the file-level context needed to execute each phase.

| Phase | Title | Duration | Unblocks |
|---|---|---|---|
| 1 | Mechanical `sorry`s | 1–2 weeks | Confidence; clean starting line |
| 2 | Kernel-computable SHA-256 | 4–8 weeks | Phases 5, 7 |
| 3 | Complete reference signer | 2–3 weeks | Phase 5 |
| 4 | Byte-level deserialiser | 1–2 weeks | Phases 5, 6 |
| 5 | Round-trip theorem `verify_signs` | 1–2 months | Headline functional result |
| 6 | Refinement: Lean spec ↔ Yul model | 2–3 weeks | Headline functional result |
| 7 | Cross-validation in CI | 1 week | Drift detection |

**Total**: ~4–6 person-months focused work for one engineer.

## Files

* **`lean/`** — Lean 4 project root.
  * `SphincsCVerify.lean` — top-level module.
  * `SphincsCVerify/Spec/` — SPHINCS+C10 specification.
  * `SphincsCVerify/Verifier/` — offset-indexed verifier + equivalence.
  * `SphincsCVerify/Crypto/` — SHA-256 assumptions + EUF-CMA axiom.
  * `SphincsCVerify/Bridge/` — Lean ↔ Solidity ↔ EVM bytecode bridge.
  * `SphincsCVerify/Wallet/` — **Legacy, out of scope.** May be removed.
  * `Main.lean` — executable driver.
  * `scripts/` — audit scripts (`check_no_sorry.lean`,
    `dump_axioms.lean`).
* **`docs/`** — Project documentation.
  * [`OPEN_PROOF_OBLIGATIONS.md`](docs/OPEN_PROOF_OBLIGATIONS.md) — Phased
    plan with all the context needed to execute. **Primary reference for
    ongoing work.**
  * [`PROOF_MAP.md`](docs/PROOF_MAP.md) — Theorem index with status.
  * [`AXIOMS.md`](docs/AXIOMS.md) — Axiom inventory with citations.
  * [`TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md) — TCB report.
* **`cross_validation/`** — Cross-implementation diff harness
  (Lean spec ↔ Rust reference ↔ Solidity verifier).

## What this proves and what it doesn't

After all seven phases of `OPEN_PROOF_OBLIGATIONS.md` are completed:

> *Given* a Lean kernel that checks proofs correctly, `solc 0.8.28`
> that compiles correctly, an EVM consensus client that executes per
> spec, a SHA-256 precompile that implements FIPS 180-4, and the
> Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024 SPHINCS+
> cryptographic assumptions extended to SPHINCS+C per Hülsing PQC2022,
>
> **then** the deployed `SPHINCsC10Asm.verify` accepts every honestly-
> signed signature; rejects every malformed input (wrong length, nonzero
> last FORS index, bad WOTS+C digit sum); is extensionally equivalent
> to the structured Lean spec; and accepting an unknown-provenance
> signature implies SPHINCS+C10 EUF-CMA forgery.

The four explicit assumptions are documented in
[`docs/TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md) with their
elimination paths.

This is the most that any honest formal-verification claim can offer
about a SPHINCS+C-on-EVM verifier contract today, per § 5.4 of the
playbook.

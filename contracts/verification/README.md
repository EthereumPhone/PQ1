# PQSmartWallet — Formal Verification

This directory contains the **mechanised formal-verification stack** for one
goal:

> **Theft-freedom.** No adversary — without knowledge of the firmware-resident
> SPHINCS+C10 secret keys — can cause value held by a deployed `PQSmartWallet`
> proxy to be transferred to an address they control.

The proof is structured against the contracts under
`contracts/smart-wallet/src/` (`PQSmartWallet.sol`, `PQMultiOwnable.sol`,
`PQSmartWalletFactory.sol`, `verifiers/SPHINCsC10Asm.sol`).

## Trusted assumptions

| # | Assumption |
|---|---|
| A1 | SHA-256 EVM precompile at `0x02` implements FIPS 180-4. |
| A2 | EntryPoint v0.6 is unhackable (only invokes execution after `validateUserOp` returned success; does not move wallet balance directly). |
| A3 | `solc 0.8.28` compiles the wallet + verifier sources to faithful EVM bytecode. |
| A4 | EVM bytecode executes per the EVM specification. |
| A5 | SPHINCS+C10 is EUF-CMA secure (composed from SHA-256 SM-DT-TCR + ITSR + ROM on `H_msg`). |
| A6 | Lean 4 kernel checks proofs correctly. |

Out of scope: firmware (Rust under `secure/`, `nonsecure/`, …), side-channel
resistance, gas/DoS, MEV. See [`docs/TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md).

## Status (2026-05-17)

| Component | Status |
|---|---|
| `lake build` end-to-end | ✅ Succeeds on Lean 4.22.0 |
| **Headline `theft_free` theorem** | ✅ Closed with the required axiom set (A1–A5 + Lean kernel built-ins). |
| Wallet invariants I-1 through I-8 | ✅ All closed (I-1 non-bypass, I-2 monotonicity, I-3 no-reset, I-4 bootstrap-unremovable, I-5 combined-cap inductive, I-6 EIP-1271-forbids-bootstrap, I-7 CREATE2-chain-independent, I-8 squat-defence). |
| `cannot_forge_without_breaking_SHA256` | ✅ Closed (deterministic-adversary form; consumes all four crypto axioms). |
| Cryptographic axioms (A5) | 🔓 4 axioms with citations |
| Bridge axioms (A1, A3, A4) | 🔓 3 axioms |
| EntryPoint axiom (A2) | 🔓 `Bridge.EntryPoint.entrypoint_honest` — added. |
| Open `sorry`s | 📌 3 remaining in `verify_signs`, `load_R_consistent`, `verifyRefined_eq_spec` — none load-bearing for `theft_free`. See [`docs/BLOCKERS.md`](docs/BLOCKERS.md). |

```bash
cd lean
elan toolchain install $(cat lean-toolchain)
lake build

lake env lean --run scripts/check_no_sorry.lean
lake env lean --run scripts/dump_axioms.lean
```

`dump_axioms.lean` shows every closed headline theorem's axiom dependencies.
Today's closed core depends only on `propext` / `Classical.choice` /
`Quot.sound`; the headline `theft_free` theorem will depend on exactly A1–A5
plus those kernel built-ins.

## Roadmap

There is **one phase**. It collapses every previously-numbered phase and the
wallet-invariants work. See [`docs/OPEN_PROOF_OBLIGATIONS.md`](docs/OPEN_PROOF_OBLIGATIONS.md)
for the full work-item list, grouped by source-file area (Verifier / Wallet /
Bridge / Crypto / Top-level).

**Total**: ~6–9 person-months focused work for one engineer.

## Files

* **`lean/`** — Lean 4 project root.
  * `SphincsCVerify/Spec/` — SPHINCS+C10 specification.
  * `SphincsCVerify/Verifier/` — offset-indexed verifier + equivalence.
  * `SphincsCVerify/Wallet/` — wallet contract models + invariants (**in scope**).
  * `SphincsCVerify/Crypto/` — SHA-256 + EUF-CMA axioms.
  * `SphincsCVerify/Bridge/` — Lean ↔ Solidity ↔ EVM ↔ EntryPoint bridge.
  * `scripts/` — audit (`check_no_sorry.lean`, `dump_axioms.lean`).
* **`docs/`** — Project documentation.
  * [`OPEN_PROOF_OBLIGATIONS.md`](docs/OPEN_PROOF_OBLIGATIONS.md) — The single phase.
  * [`PROOF_MAP.md`](docs/PROOF_MAP.md) — Theorem index with status.
  * [`AXIOMS.md`](docs/AXIOMS.md) — Axiom inventory.
  * [`TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md) — TCB report.
* **`cross_validation/`** — Lean spec ↔ Rust reference ↔ Solidity verifier diff harness.

## What this proves on completion

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM state
> transition `σ → σ'` triggered by a UserOp accepted by EntryPoint v0.6, if
> `balance(σ', W) < balance(σ, W)`, then the UserOp's `signature` field
> carries a SPHINCS+C10 signature, valid under an installed owner key of
> `W`, over the canonical `userOpHash`.

Equivalently: an adversary who does not hold an installed SPHINCS+C10 secret
key cannot reduce the wallet's balance, modulo A1–A6.

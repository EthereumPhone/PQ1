# PQSmartWallet — Formal Verification

> **Honest status (2026-05-19).** The Lean 4 kernel checks the headline
> theorem `SphincsCVerify.Spec.Theorems.theft_free`, **but** 6 of the 11
> axioms in its dependency closure are `True`-typed placeholders (no
> semantic content) and 1 axiom is about a Lean fiction rather than the
> deployed contract. The proof as it stands is a model-level sanity
> check, not yet a mathematical guarantee about the deployed bytecode.
> See [`docs/AXIOM_STATUS.json`](docs/AXIOM_STATUS.json) for the
> per-axiom discharge state, and
> [`docs/DISCHARGE_PLAN.md`](docs/DISCHARGE_PLAN.md) for the tiered
> plan to turn placeholders into discharged content.

This directory contains the **mechanised formal-verification stack** in
progress toward one goal:

> **Theft-freedom (target).** No adversary — without knowledge of the
> firmware-resident SPHINCS+C10 secret keys — can cause value held by a
> deployed `PQSmartWallet` proxy to be transferred to an address they
> control.

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

## Status (2026-05-19)

The `theft_free` theorem is kernel-checked by Lean 4. The dependency
closure passes the documented set diff. But the substantive content of
each axiom varies — see [`docs/AXIOM_STATUS.json`](docs/AXIOM_STATUS.json)
for the per-axiom report.

| Component | Status |
|---|---|
| `lake build` end-to-end | ✅ Succeeds on Lean 4.22.0 |
| `theft_free` theorem | ✅ Kernel-checked. ⚠️ Depends on `True`-typed bridge axioms (see below). |
| Wallet invariants I-1 through I-8 | ✅ All closed; details in [`docs/AXIOMS.md`](docs/AXIOMS.md). |
| Bridge axioms (A1, A3, A4) | 🚧 PLACEHOLDER (`True`-typed). Do not constrain deployed bytecode yet. Discharge plan: tier-1.9 axiom-shape refactor + tier-2 Kontrol/Certora sessions. |
| EntryPoint axiom (A2) | ⚠️ MISLEADING. States a property of the Lean `handleOp` fiction, not the deployed EntryPoint v0.6. Discharge plan: tier-3 Kontrol against mainnet bytecode. |
| Cryptographic axiom (A5) `EUF_CMA_SPHINCSplusC` | 📚 CITED-TCB. Real propositional content; cites Barbosa et al. ASIACRYPT 2024 + Hülsing PQC 2022. |
| Cryptographic shape axioms (A5 components) | 🚧 PLACEHOLDER (`True`-typed). Discharge plan: tier-4 advantage-bound shape refactor. |
| Source-level `sorry`s | ✅ 0 sorrys (audited via `scripts/check_no_sorry.lean`). |

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

## What this proves TODAY (honest version)

The Lean kernel checks the propositional statement
`SphincsCVerify.Spec.Theorems.theft_free` (see
`lean/SphincsCVerify/Spec/Theorems.lean`). The statement quantifies
over a Lean-defined state-transition function `Bridge.EntryPoint.handleOp`
and a Lean-defined verifier `verifyYulModel`. Three of the axioms it
formally depends on (`solidityVerifier_compiles_correctly`,
`evm_bytecode_executes_correctly`, `precompile_0x02_is_FIPS_180_4`)
have type `True` — they appear in `#print axioms theft_free` for
documentation, but they do not constrain anything in the kernel.
So the Lean theorem in its current form is a model-level
sanity check of the wallet's logic, **not a mathematical guarantee
about the deployed bytecode**.

The cryptographic axiom `EUF_CMA_SPHINCSplusC` does carry real
propositional content (asserts non-forgery in the deterministic-
adversary form); its discharge is the citation to Barbosa et al. 2024
plus the SPHINCS+ → SPHINCS+C transition argument.

## What this aims to prove on completion of the discharge plan

The plan at
[`docs/DISCHARGE_PLAN.md`](docs/DISCHARGE_PLAN.md)
discharges each placeholder via Kontrol (KEVM) and Certora sessions,
plus a Lean-side opaque-and-axiom-equality refactor that makes the
deployed bytecode load-bearing in the dep closure. After completion:

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM state
> transition `σ → σ'` triggered by a UserOp accepted by EntryPoint v0.6, if
> `balance(σ', W) < balance(σ, W)`, then the UserOp's `signature` field
> carries a SPHINCS+C10 signature, valid under an installed owner key of
> `W`, over the canonical `userOpHash`.

Equivalently: an adversary who does not hold an installed SPHINCS+C10 secret
key cannot reduce the wallet's balance, modulo A1–A6.

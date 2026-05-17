# PQSmartWallet — Formal Verification

This directory contains the **mechanised formal verification stack** for
the SPHINCS+C10-backed PQSmartWallet, implementing the playbook in
[`../docs/how_to_math_proof_secureness.md`](../docs/how_to_math_proof_secureness.md).

## What this is

A Lean 4 project that produces machine-checked theorems about:

  1. **The SPHINCS+C10 verifier** (specification, byte-layout
     consistency, correctness against the Solidity verifier).
  2. **`PQMultiOwnable` / `PQSmartWallet.validateUserOp`** (non-bypass,
     cap monotonicity, no-reset, bootstrap unremovability, combined-cap
     inductive invariant).
  3. **`PQSmartWalletFactory`** (CREATE2 address chain-independence,
     squat-defence precondition).

Plus a precise inventory of the **cryptographic and TCB axioms** the
end-to-end "deployed-bytecode is secure" claim rests on.

## Status (2026-05-17)

| Component | Status |
|---|---|
| `lake build` end-to-end | ✅ Succeeds on Lean 4.22.0 |
| Closed core (kernel-checked, no `sorry`) | ✅ 11+ theorems including all cap-monotonicity + bootstrap-unremovability + CREATE2-determinism + signature-size-4008B |
| Cryptographic axioms (EUF-CMA stratum) | 🔓 4 stated axioms with citations |
| EVM / compilation TCB axioms | 🔓 3 stated axioms (solc, EVM spec, precompile 0x02) |
| Mechanical-discharge `sorry`s | 📌 11 tactic-position `sorry`s in section lemmas (functional round-trip, offset-arithmetic equivalence, EUF-CMA → forge implication) — all documented in `docs/AXIOMS.md` § D |

```bash
# Build everything.
cd lean
elan toolchain install $(cat lean-toolchain)
lake build

# Run the audit scripts.
lake env lean --run scripts/check_no_sorry.lean
lake env lean --run scripts/dump_axioms.lean

# Run the test-vector type-check executable.
lake exe verify-test-vectors
```

`dump_axioms.lean` confirms every headline closed theorem depends only
on the universal Lean axioms (`propext`, `Quot.sound`) — no
cryptographic assumption leaks into the closed core.

## Files

* **`lean/`** — Lean 4 project root.
  * `SphincsCVerify.lean` — top-level module.
  * `SphincsCVerify/Spec/` — the SPHINCS+C10 specification.
  * `SphincsCVerify/Verifier/` — offset-indexed verifier + equivalence
    obligations.
  * `SphincsCVerify/Wallet/` — `PQMultiOwnable`, `validateUserOp`,
    `Factory`, and the wallet invariants.
  * `SphincsCVerify/Crypto/` — SHA-256 assumptions and the EUF-CMA
    axiom with citations.
  * `SphincsCVerify/Bridge/` — Lean ↔ Solidity ↔ EVM bytecode bridge
    with explicit TCB axioms.
  * `Main.lean` — executable driver.
  * `scripts/` — audit scripts (`check_no_sorry.lean`,
    `dump_axioms.lean`).
* **`docs/`** — User-facing project documentation.
  * `TRUST_ASSUMPTIONS.md` — the full Verity-style trust report:
    every TCB item and how to discharge it.
  * `AXIOMS.md` — the machine-checkable inventory of every `axiom`
    and pending `sorry`, with citations.
  * `PROOF_MAP.md` — which theorem lives where, and which playbook
    step it realises.
* **`cross_validation/`** — Cross-implementation diff harness
  (Lean spec ↔ Rust reference ↔ Solidity verifier).

## What this proves and what it doesn't

This is the most important section. The exact statement of
"`PQSmartWallet` is secure" the project delivers, mechanically checked
by Lean's kernel, is:

> *Given* a Lean kernel that checks proofs correctly, `solc 0.8.28` that
> compiles correctly, an EVM consensus client that executes per spec, a
> SHA-256 precompile that implements FIPS 180-4, and the
> Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024 SPHINCS+
> cryptographic assumptions extended to SPHINCS+C per Hülsing PQC2022,
>
> **then** the deployed `PQSmartWallet`'s `validateUserOp` only returns
> success via a verifier-accepted SPHINCS+C10 signature; `bootstrapUses`
> and `slotUses[i] + offchainSigCount[i]` are monotonic and bounded
> above by their on-chain caps; the bootstrap key is unremovable; the
> CREATE2 address depends only on `(masterPkSeed, masterPkRoot)`; and
> EIP-1271 rejects `ownerIndex == 0`.

The four explicit assumptions in that conditional are documented in
`docs/TRUST_ASSUMPTIONS.md` with their elimination paths.

This is the most that any honest formal-verification claim can offer
about a SPHINCS+C-on-EVM smart wallet today, per § 5.4 of the playbook.

## Future engagement

The clear next steps, in order:

1. **Discharge mechanical `sorry`s** in `Verifier/Equivalence.lean`,
   `Spec/Theorems.lean`, and `Wallet/Invariants.lean::validateSignature_*`
   (estimated 1-2 person-months).
2. **Verity-EDSL re-implementation** of the wallet for verified
   compilation (estimated 6-12 person-months; eliminates the
   `solidityVerifier_compiles_correctly` axiom).
3. **Extend Barbosa et al. EasyCrypt** to SPHINCS+C (estimated 9-18
   person-months; eliminates `EUF_CMA_SPHINCSplusC` and its
   sub-assumptions).
4. **KEVM / Kontrol bytecode equivalence** on critical paths as
   defence-in-depth (1-2 person-months).

Total to fully discharge every assumption: ~28-56 person-months,
matching the headline estimate in § 4.7 of the playbook.

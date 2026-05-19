# PQSmartWallet — Formal Verification (Lean 4)

> **Honest status (2026-05-19).** This directory contains the
> in-progress mechanisation of the theft-freedom theorem. The Lean 4
> kernel checks the headline theorem
> `SphincsCVerify.Spec.Theorems.theft_free`, but 6 of the 11 axioms in
> its dependency closure have type `True` (no semantic content), and 1
> axiom is about a Lean fiction (`Bridge.EntryPoint.handleOp`) rather
> than the deployed EntryPoint v0.6. The proof in its present form is
> a model-level sanity check, not yet a mathematical guarantee about
> the deployed bytecode. See
> [`../docs/AXIOM_STATUS.json`](../docs/AXIOM_STATUS.json) for the
> per-axiom report and
> [`../docs/DISCHARGE_PLAN.md`](../docs/DISCHARGE_PLAN.md) for the
> discharge plan.

This directory mechanises the proof — in progress — that **assets
cannot be stolen from a deployed `PQSmartWallet` proxy** by any
adversary lacking knowledge of the firmware-resident SPHINCS+C10 secret
keys.

See [`../README.md`](../README.md) for scope, trust assumptions, and the
work plan ([`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md)).

## Layout

```
SphincsCVerify/
├── Spec/              -- SPHINCS+C10 specification + SHA-256 + ADRS
│   ├── Params.lean    -- C10 parameters (n=16, h=18, d=2, a=11, k=13, w=8, l=43, T=205)
│   ├── Bytes.lean     -- ByteVec, byte-array helpers
│   ├── Hash.lean      -- sha256 (opaque → def) + tweakable hashes
│   ├── Adrs.lean      -- 32-byte ADRS (matches Rust + Yul)
│   ├── Wots.lean      -- WOTS+C sign/verify spec
│   ├── Fors.lean      -- FORS+C with forced-zero last index
│   ├── Hypertree.lean -- D=2 hypertree
│   ├── Signature.lean -- Top-level verify + 4008-byte layout
│   ├── Signer.lean    -- Reference signer
│   └── Theorems.lean  -- Functional-correctness theorems + headline `theft_free`
├── Verifier/
│   ├── Refined.lean        -- Offset-indexed verifier (Yul shape)
│   └── Equivalence.lean    -- Refined ≡ Spec
├── Wallet/                  -- Wallet contracts (IN SCOPE)
│   ├── Storage.lean        -- State-transition model
│   ├── MultiOwnable.lean   -- Owner table + counter bumps
│   ├── ValidateUserOp.lean -- validateUserOp model
│   ├── Factory.lean        -- CREATE2 + squat defence
│   └── Invariants.lean     -- I-1 through I-8
├── Bridge/
│   ├── SolidityVerifier.lean -- Yul-level model of SPHINCsC10Asm
│   ├── EntryPoint.lean       -- EntryPoint v0.6 contract model (axiom A2)
│   └── Refinement.lean       -- Lean ↔ Solidity ↔ EVM bridge (axioms A1, A3, A4)
├── Crypto/
│   ├── Assumptions.lean   -- SHA-256 SM-TCR / ITSR / ROM axioms
│   └── EUFCMA.lean        -- EUF-CMA axiom (axiom A5)
└── Util/
    ├── Bits.lean          -- read_bits_le, base-w decoding, target-sum
    └── ByteVec.lean       -- ByteVec lemmas
```

## How to build

```bash
elan toolchain install $(cat lean-toolchain)
lake update
lake build
```

Type-checks every module. A clean build means every theorem the project
claims to prove is checked by the Lean kernel.

```bash
lake env lean --run scripts/check_no_sorry.lean   # Audit sorrys
lake env lean --run scripts/dump_axioms.lean      # Audit axioms
```

`sorry` is permitted only at locations enumerated in
[`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md);
the audit script fails on any uncovered occurrence.

## What today's headline theorem actually says

The single headline theorem `SphincsCVerify.Spec.Theorems.theft_free`
is kernel-checked, and its dependency closure matches the documented
set. **But** the documented set includes six `True`-typed axioms
(zero semantic content) and one "MISLEADING" axiom (about a Lean
fiction, not the deployed contract). So the theorem reads:

> *Under the Lean state-transition model of EntryPoint v0.6 + the Lean
> model of PQSmartWallet + Solidity-selectors-modelled-as-placeholders
> + the stub `sphincsDigest := sha256 []`*: if the model's balance
> decreases, then the model's verifier was called with a verifying
> wrapped signature under an installed-owner key.

The connection to the **deployed** bytecode is supplied by three
axioms whose Lean type is literally `True`:

* `Bridge.solidityVerifier_compiles_correctly : ∀ ..., True` (A3)
* `Bridge.evm_bytecode_executes_correctly : True` (A4)
* `Bridge.precompile_0x02_is_FIPS_180_4 : ∀ ..., True` (A1)

These axioms appear in `#print axioms theft_free` for documentation
but they constrain nothing in the kernel. Hostile removal of the
axiom does not invalidate the proof.

Plus the cryptographic content:

* `Crypto.EUF_CMA_SPHINCSplusC` — real propositional content (cited
  TCB: Barbosa et al. 2024 + Hülsing PQC 2022).
* `Crypto.SM_DT_TCR_F`, `Crypto.ITSR_F`, `Crypto.hMsg_random_oracle` —
  `True`-typed shape preconditions.

And the EntryPoint v0.6 axiom:

* `Bridge.EntryPoint.entrypoint_honest` — real propositional content,
  but states a property of the **Lean** `handleOp` function, not the
  deployed EntryPoint v0.6 contract at
  `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`.

Plus the Lean kernel built-ins (`propext`, `Classical.choice`,
`Quot.sound`) which are universal Lean 4 TCB.

See [`../docs/AXIOM_STATUS.json`](../docs/AXIOM_STATUS.json) for the
machine-checkable status table and
[`../docs/DISCHARGE_PLAN.md`](../docs/DISCHARGE_PLAN.md)
for the tiered plan that converts each placeholder into discharged
content (Lean refactor + Kontrol/Certora sessions against the pinned
deployed bytecode).

## What this aims to prove on completion of the plan

After Tier 1.9 (axiom-shape refactor) and Tier 2 (Kontrol + Certora
discharge), the headline theorem will read:

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM state
> transition `σ → σ'` triggered by a UserOp accepted by EntryPoint v0.6,
> if `balance(σ', W) < balance(σ, W)`, then the UserOp's `signature` field
> carries a SPHINCS+C10 signature valid under an installed owner key of
> `W` over the canonical `userOpHash`.

with the dependency closure listing one *content-bearing* axiom per
contract (each citing a Kontrol session ID), plus the cryptographic
A5 citation, plus the universal Ethereum TCB items A1/A4.

## What this does NOT give you

* Firmware-secret-key secrecy (out of scope — separate effort).
* Gas / DoS / griefing bounds.
* EntryPoint v0.6 contract correctness (assumed via A2).
* `solc` / EVM / SHA-256 precompile correctness (assumed via A1, A3, A4).
* Side-channel security of firmware signing.

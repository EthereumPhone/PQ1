# PQSmartWallet — Formal Verification (Lean 4)

> **Honest status (2026-05-19).** This directory contains the
> in-progress mechanisation of the theft-freedom theorem. The Lean 4
> kernel checks the headline theorem
> `SphincsCVerify.Spec.Theorems.theft_free`. After the Tier-1.9
> refactor its bridge axioms carry real propositional content (A1 and
> the A3.x axioms are opaque-equality shapes equating the
> deployed-bytecode symbols to the Lean model; A4 is a content-bearing
> opaque-predicate marker), and the former A2 (`entrypoint_honest`) is
> since 2026-08-20 a **proved kernel-only theorem** — it follows from
> the `handleOp` definition alone, so the trust base no longer carries
> it as an axiom (what remains cited is the `handleOp` model's
> faithfulness to the deployed EntryPoint v0.6). The proof in its present form is
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
│   ├── EntryPoint.lean       -- EntryPoint v0.6 contract model (A2, proved theorem since 2026-08-20)
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
set. **But** the link to the deployed contracts still rests on
cited-TCB axioms rather than in-kernel discharge: the
bridge axioms (A1/A3.x/A4 — content-bearing, discharged against pinned
bytecode or cited as Ethereum TCB) and the cited EUF-CMA crypto layer
(A5). (The former "MISLEADING" A2 about the Lean `handleOp` fiction was
proved kernel-only and demoted to a theorem on 2026-08-20 — no longer
part of the trust base.) So the theorem reads:

> *Under the Lean state-transition model of EntryPoint v0.6 + the Lean
> model of PQSmartWallet + Solidity-selectors-modelled-as-placeholders
> + the stub `sphincsDigest := sha256 []`*: if the model's balance
> decreases, then the model's verifier was called with a verifying
> wrapped signature under an installed-owner key.

The connection to the **deployed** bytecode is supplied by three
axioms, all refactored out of the old `True` placeholder shape into
content-bearing statements (verify each in `Bridge/Refinement.lean`):

* `Bridge.solidityVerifier_compiles_correctly` (A3.1) —
  **load-bearing.** Its conclusion is a real propositional equality,
  `DeployedBytecode.SPHINCsC10Asm_verify … = Interpreter.C10.execC10Asm …`
  (the faithful transcription of the deployed Yul, *not* the bare
  `verifyYulModel`). It is **consumed** by `theft_free`: the existence
  half rewrites the deployed-verifier symbol with this equality
  (`rw [hbridge]; exact hverify`), so deleting the axiom leaves the
  proof unprovable. Discharged against pinned bytecode (Halmos input
  gates + executable Lean↔FIPS↔bytecode KAT); the residual ∀-signature
  equivalence under uninterpreted SHA-256 is the standing ceiling
  (= A1).
* `Bridge.precompile_0x02_is_FIPS_180_4` (A1) — carries a real
  equality type, `DeployedBytecode.SHA256_precompile input = sha256
  input`. In `theft_free` it is a **non-consumed** cited-TCB marker:
  pulled into the `#print axioms` closure via a `have` binding so the
  closure self-documents the SHA-256-precompile boundary, but the
  safety argument does not consume it. (It *is* genuinely consumed by
  the bytecode/verifier-transport corollaries.)
* `Bridge.evm_bytecode_executes_correctly` (A4) — its type is
  `∀ (c : Wallet.Execute.Call), Bridge.evmDeliversCall c`, where
  `evmDeliversCall` is an **opaque** predicate (kernel-irreducible —
  it cannot be `trivial`/`rfl`-ed away). Like A1 it is a
  **non-consumed** cited-TCB marker in `theft_free`, present in the
  closure to name the EVM-delivers-the-emitted-CALL boundary, not a
  semantic premise of the safety proof.

So A3.1 is genuinely load-bearing — remove it and `theft_free` no
longer closes — while A1 and A4 are content-bearing but non-consumed
TCB markers surfaced in the closure for completeness. None of the
three is `True`-typed any more; the earlier "they constrain nothing /
hostile removal does not invalidate the proof" claim held only before
the Tier-1.9 refactor and is now false (decisively so for A3.1).

Plus the cryptographic content:

* `Crypto.EUF_CMA_SPHINCSplusC` — real propositional content (cited
  TCB: Barbosa et al. 2024 + Hülsing PQC 2022).
* `Crypto.SM_DT_TCR_F`, `Crypto.ITSR_F`, `Crypto.hMsg_random_oracle` —
  `True`-typed shape preconditions.

And the EntryPoint v0.6 premise (PROVED 2026-08-20, no longer an axiom):

* `Bridge.EntryPoint.entrypoint_honest` — now a kernel-checked
  **theorem** over the **Lean** `handleOp` model (its conclusion follows
  from `handleOp`'s own definition; closure = the kernel triple). The
  cited-TCB content that remains is the faithfulness of `handleOp` to
  the deployed EntryPoint v0.6 contract at
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
* EntryPoint v0.6 contract correctness (the `handleOp` model's
  faithfulness is cited-TCB; the in-model A2 premise is a proved theorem).
* `solc` / EVM / SHA-256 precompile correctness (assumed via A1, A3, A4).
* Side-channel security of firmware signing.

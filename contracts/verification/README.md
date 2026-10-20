# PQSmartWallet — Formal Verification

> **UPDATE 2026-10-20 (Trail of Bits audit freeze).** The wallet changed:
> owner removal was deleted (the owner set is append-only), a legacy EIP-1271
> entry and token receiver hooks were added, Solady's raw-hash 1271 workflows
> were dropped, and the build sets `bytecode_hash = "none"`. The Lean models
> follow (new I-9 theorems: a key is installed at most once). Halmos (43
> rules, both profiles) and Kontrol (31 proofs) were re-run on the new pinned
> bytecode; receipts are under `halmos/sessions/` and `kontrol/sessions/`.
> That bytecode is **not deployed yet**: wherever the text below says
> "deployed", read "the pinned production build, deployment pending"
> ([`docs/PINNED_CODEHASHES.md`](docs/PINNED_CODEHASHES.md),
> [`docs/THE_CLAIM.md`](docs/THE_CLAIM.md) #6).

> **Status (2026-06-10).** The Lean 4 kernel checks the headline theorem
> `SphincsCVerify.Spec.Theorems.theft_free` and every claim corollary
> with **zero `sorry`** and **zero `True := trivial` theorem
> placeholders** anywhere under `SphincsCVerify/`. The `theft_free`
> axiom closure is exactly the intended 11:
> `{propext, Classical.choice, Quot.sound}` (Lean kernel) +
> `precompile_0x02_is_FIPS_180_4` (A1), `entrypoint_honest` (A2),
> `solidityVerifier_compiles_correctly` (A3.1),
> `evm_bytecode_executes_correctly` (A4), and the four A5 crypto axioms
> (`EUF_CMA_SPHINCSplusC`, `SM_DT_TCR_F`, `ITSR_F`, `hMsg_random_oracle`).
> Of these, A1 and A3.1 are `opaque + axiom-equality` shapes with real
> propositional content; A4 plus the three A5 hardness-shape axioms are
> the cited-TCB `True` markers (Barbosa et al. ASIACRYPT 2024 + KEVM).
>
> The Lean model is faithful to the **in-use** contracts as of
> 2026-06-10: it tracks the deployed verifier's FORS hypertree-position
> binding (`htIdx` folded into every FORS ADRS, commit fcee705a), the
> deployed wallet's validation-phase bootstrap-cap bump (the
> `PQBootstrapCapEvasion` fix), the wrapper ABI tail-pad check, the
> audit-H-3 ownerIndex parity, and the factory's install-time N-mask +
> duplicate-owner gates.
>
> **The bytecode-level A3.* discharge is run on BOTH profiles, not
> pending.** A patched Halmos + z3 (see [`halmos/`](halmos/)) symbolically
> executes the deployed runtime bytecode against the pinned codehashes —
> the full symbolic suite is run under default `runs=200` **and** deploy
> `runs=999999` (production), each certified by `PinnedCodehashes.t.sol`;
> the immutable-window lemma additionally bridges each profile's pinned
> instance to every other instance of that artifact (differing
> constructor immutables):
>
> - **A3.2 (wallet validate)** — `discharged-bytecode`: a full **pointwise
>   equivalence** of `validateUserOp` to the clause-for-clause Lean-model
>   transcription ([`LeanValidateUserOpModel.sol`](../smart-wallet/test/halmos/LeanValidateUserOpModel.sol))
>   over a symbolic envelope under a generic uninterpreted verifier,
>   conditioned on the kernel-proven reachable-state invariant, plus 8
>   per-property rules.
> - **A3.2-exec (wallet execute)** — `discharged-bytecode`: pointwise
>   equivalence of `executeWithOffchainCount` /
>   `executeBatchWithOffchainCount` to the Lean `Execute` model
>   ([`LeanExecuteModel.sol`](../smart-wallet/test/halmos/LeanExecuteModel.sol))
>   over a **symbolic ∀ `ownerIndex`** (the money path reads only
>   word-typed counters + the transient credit, so it admits a genuine
>   ∀-index sweep) + atomicity + credit rules, plus 6 per-property rules.
>   The emitted external CALL's byte-delivery is A4, not A3.2.
> - **A3.3 (factory)** — `discharged-bytecode`: `createAccount` ⟺
>   `createAccountPrecondition` (over symbolic chain + signature) with
>   deploy postconditions, the already-deployed early-return, and three
>   install-gate reject rules.
> - **A3.4 (owner table)** — `discharged-bytecode`:
>   `addOwnerBytes`/`initialize` pointwise vs the Lean `Storage` model +
>   one-shot `initialize` + EntryPoint-only gate + the deleted removal
>   selector dispatching nothing ([`HalmosMultiOwnable.t.sol`](../smart-wallet/test/halmos/HalmosMultiOwnable.t.sol),
>   5 rules since the 2026-10-20 audit freeze deleted `removeOwnerAtIndex`;
>   7 rules before). Replaces the prior stale Certora artifact.
> - **A3.1 (verifier)** — `discharged-bytecode` (**tier C — corpus**):
>   Halmos input gates + an **executable Lean↔FIPS↔bytecode KAT on the
>   digest/htIdx sub-layers AND the full functional verify** (10/10 each,
>   HARD CHECKS since 2026-06-13 — `Spec.Signature.verify` reproduces the
>   deployed bytecode's accept/reject decision on the entire KAT corpus) +
>   the bytecode-side 10-vector KAT + a ≈250-mutant wrong-accept screen.
>   The 2026-06-11 "false as stated" correction is **closed**: the two
>   reconstruction-layer Lean-spec bugs it named were found and fixed
>   2026-06-13 (`chainHash` ADRS field; `loadWord32` tail window). The
>   remaining residual is the **∀-signature symbolic equivalence** — carried
>   by the corpus, not a symbolic ∀ (intractable under uninterpreted
>   SHA-256) — so the claim stays "proven to bytecode at corpus tier", not
>   an unqualified ∀. See
>   [`docs/A3_1_VERIFIER_GAP.md`](docs/A3_1_VERIFIER_GAP.md) and
>   [`docs/THE_CLAIM.md`](docs/THE_CLAIM.md).
>
> The Lean corollaries `theft_free_bytecode`,
> `factory_squat_defence_bytecode`, and
> `deployed_execute_requires_prior_token` /
> `deployed_executeBatch_requires_prior_token` quantify theft-freedom,
> squat-defence, and the execute-gate directly over the **opaque
> deployed-bytecode symbols**, so a `#print axioms` names the
> wallet/factory/execute bridge axioms explicitly. See
> [`docs/AXIOM_STATUS.json`](docs/AXIOM_STATUS.json) for the per-axiom
> discharge state and [`docs/PINNED_CODEHASHES.md`](docs/PINNED_CODEHASHES.md)
> for the pins. Reproduce: `make verify-bytecode`.
>
> **Honest ceiling (unchanged).** A Halmos rule is a cited solver session
> (Halmos + z3 + the harness↔property and transcription↔Lean
> correspondences in the TCB), not a Lean kernel proof term; A2/A4/A5
> remain cited-TCB; A3.1's ∀-signature equivalence remains on the Lean
> refinement + KATs. SHA-256 is uninterpreted in every Halmos run (= A1).

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

## Status (2026-06-10)

The `theft_free` theorem is kernel-checked by Lean 4. The dependency
closure is exactly the documented 11-axiom set (see below); the
substantive content of each axiom varies — see
[`docs/AXIOM_STATUS.json`](docs/AXIOM_STATUS.json) for the per-axiom report.

| Component | Status |
|---|---|
| `lake build` end-to-end | ✅ Succeeds on Lean 4.22.0 |
| `theft_free` theorem | ✅ Kernel-checked; closure = exactly the 11 cited axioms. |
| Wallet invariants I-1 through I-8 | ✅ All closed; details in [`docs/AXIOMS.md`](docs/AXIOMS.md). |
| Bridge axioms A1 / A3.1 | ✅ `opaque + axiom-equality` shapes with real content. A3.1 spec-refinement (`verifyRefined_eq_spec`) is `rfl`, incl. the FORS `htIdx` ADRS binding; verifier **input gates** also discharged on bytecode by Halmos (3 rules) + a ≈250-mutant adversarial screen. |
| Bridge axioms A3.2 / A3.2-exec / A3.3 / A3.4 (bytecode) | ✅ **Discharged on the deployed bytecode** by Halmos symbolic execution, both profiles: validate pointwise + per-property (`HalmosValidateUserOpEquiv`/`HalmosValidateUserOp`), execute pointwise over a **symbolic ∀ ownerIndex** + per-property (`HalmosExecuteEquiv`/`HalmosExecute`), factory iff (`HalmosFactory`), owner-table pointwise + read-parity (`HalmosMultiOwnable`, replaces stale Certora) — all vs the pinned codehashes (`make verify-bytecode`). |
| Bridge axiom A4 (`evm_bytecode_executes_correctly`) | 📚 CITED-TCB `True` marker (KEVM as formal-EVM referent), per user decision. |
| EntryPoint axiom (A2) | 📚 CITED-TCB. Property of the Lean `handleOp` model of EntryPoint v0.6; cited OZ/ChainSecurity/Spearbit audits + 18mo mainnet. |
| Cryptographic axiom (A5) `EUF_CMA_SPHINCSplusC` | 📚 CITED-TCB. Real propositional content; cites Barbosa et al. ASIACRYPT 2024 + Hülsing PQC 2022. |
| Cryptographic shape axioms (A5 components) | 📚 CITED-TCB `True` markers (Barbosa et al. modular reduction). |
| Source-level `sorry`s | ✅ 0 sorrys (audited via `scripts/check_no_sorry.lean`). |
| `True := trivial` theorem placeholders | ✅ 0 (all four upgraded 2026-06-10; allowlist empty). |
| Contract faithfulness | ✅ Lean model tracks the in-use contracts: FORS `htIdx` binding (fcee705a) + validation-phase bootstrap-cap bump (PQBootstrapCapEvasion fix). |
| Solidity test suite | ✅ `forge test` 99/99 incl. PinnedCodehashes + PQBootstrapCapEvasion + 10 KAT vectors. |

```bash
cd lean
elan toolchain install $(cat lean-toolchain)
lake build

lake env lean --run scripts/check_no_sorry.lean
lake env lean scripts/dump_axioms.lean
```

`dump_axioms.lean` shows every closed headline theorem's axiom dependencies.
The headline `theft_free` theorem depends on exactly:
`propext`, `Classical.choice`, `Quot.sound` (Lean kernel);
`precompile_0x02_is_FIPS_180_4` (A1); `entrypoint_honest` (A2);
`solidityVerifier_compiles_correctly` (A3.1);
`evm_bytecode_executes_correctly` (A4);
`EUF_CMA_SPHINCSplusC`, `SM_DT_TCR_F`, `ITSR_F`, `hMsg_random_oracle` (A5).

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
`lean/SphincsCVerify/Spec/Theorems.lean`) with the bridge axioms in
their **post-refactor `opaque + axiom-equality` form**: A1
(`precompile_0x02_is_FIPS_180_4`) and the four A3 sub-axioms
(`solidityVerifier / solidityWallet / solidityFactory /
solidityMultiOwnable _compiles_correctly`) carry real propositional
content — each equates an *opaque deployed-bytecode symbol* to its
kernel-reducible Lean model, and removing any one leaves the per-claim
corollaries unprovable. Only A4 (`evm_bytecode_executes_correctly`) and
the three A5 crypto-shape axioms remain `True`-typed cited-TCB markers.

So `theft_free` is a kernel-checked guarantee about the wallet's logic
*relative to* the bridge axioms; the bridge axioms are then
**discharged on the deployed bytecode** by the Halmos sessions under
[`../smart-wallet/test/halmos/`](../smart-wallet/test/halmos/) — run on
**both** compiler profiles against the pinned codehashes. What is
discharged on bytecode, and the honest residual of each, is enumerated
in [`docs/AXIOM_STATUS.json`](docs/AXIOM_STATUS.json):

- **A3.2 validate / A3.2-exec execute / A3.3 factory / A3.4 owner-table**
  — `discharged-bytecode` (pointwise equivalence to the Lean models;
  the execute money-path over a **symbolic ∀ ownerIndex**).
- **A3.1 verifier** — `discharged-bytecode-partial`: input gates on
  bytecode + an executable Lean↔FIPS↔bytecode differential covering the
  **digest, htIdx, AND the full functional verify** (each 10/10, all
  HARD CHECKS since 2026-06-12 — `Spec.Signature.verify` reproduces the
  deployed bytecode's accept/reject decision on the entire KAT corpus) +
  the bytecode-side 10-vector KAT + a ≈250-mutant adversarial screen.
  The remaining residual is the **∀-signature symbolic equivalence**
  (corpus-validated, not proven — GAP-2; intractable under uninterpreted
  SHA-256, needs Kontrol/KEVM or Verity). See the postmortem in
  [`docs/A3_1_VERIFIER_GAP.md`](docs/A3_1_VERIFIER_GAP.md). This residual
  is the reason an unqualified "verifier proven to bytecode" claim is
  still not supportable.
- **A1 SHA-256** — uninterpreted in every Halmos run (the named boundary).
- **A2 EntryPoint / A4 EVM / A5 EUF-CMA** — cited-TCB by decision. The
  emitted-CALL byte-delivery on the execute path lives in A4.

The headline guarantee, modulo A1–A6:

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM state
> transition `σ → σ'` triggered by a UserOp accepted by EntryPoint v0.6, if
> `balance(σ', W) < balance(σ, W)`, then the UserOp's `signature` field
> carries a SPHINCS+C10 signature, valid under an installed owner key of
> `W`, over the canonical `userOpHash`.

Equivalently: an adversary who does not hold an installed SPHINCS+C10 secret
key cannot reduce the wallet's balance, modulo A1–A6.

> **⚠️ Read `modulo A1–A6` literally.** This is a guarantee *relative to*
> the trusted axioms — it is only as strong as their discharge. The **A3.1**
> axiom (deployed verifier = Lean `verifyYulModel` via `execC10Asm`) is
> discharged at **tier C (corpus)**: the executable Lean↔FIPS↔bytecode
> differential covers the full functional verify 10/10 (HARD CHECK), and
> the 2026-06-11 "contradicted by a concrete KAT vector" correction is
> closed (two Lean-spec bugs fixed 2026-06-13; see
> [`docs/A3_1_VERIFIER_GAP.md`](docs/A3_1_VERIFIER_GAP.md)). What remains
> is the **∀-symbolic ceiling**: over ALL 4008-byte signatures the equality
> is corpus-validated, not symbolically proven — so the defensible wording
> is "proven to bytecode at corpus tier", never an unqualified ∀ claim
> (see [`docs/THE_CLAIM.md`](docs/THE_CLAIM.md)).

**Honest ceiling (unchanged).** A Halmos rule is a cited Halmos+z3 solver
session — the harness↔property match and the
LeanModel.sol↔Lean-file transcription are in the TCB — not a Lean kernel
proof term. The `EUF_CMA_SPHINCSplusC` discharge is the citation to
Barbosa et al. ASIACRYPT 2024 plus the SPHINCS+ → SPHINCS+C transition
argument.

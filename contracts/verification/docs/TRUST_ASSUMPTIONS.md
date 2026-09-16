# Trust Assumptions — PQSmartWallet Three-Claim Proof

This document is the **single, authoritative inventory** of everything that
lives in the TCB of the SphincsCVerify formal-verification stack.

The headline theorem is `theft_free` in `Spec/Theorems.lean`. Three
per-claim corollaries cover the user-facing statements:

| Claim | Corollary | Location |
|-------|-----------|----------|
| 1. Signature-to-execution binding | `theft_free_with_calldata_binding` | `Spec/Theorems.lean` |
| 2. Owner-set integrity + init atomicity | `initialize_called_exactly_once`, `owner_set_nonempty_after_init`, `cannot_remove_bootstrap` | `Wallet/Invariants.lean` |
| 3. Execution faithfulness + value flow | `executeBatch_faithful` (composes E-1..E-8) | `Spec/Theorems.lean` + `Wallet/Execute.lean` |

The contrapositive of each: any unauthorised drain / owner mutation /
execution-faithfulness violation implies one of the assumptions below
is false.

---

## A1. SHA-256 precompile (EVM `0x02`) implements FIPS 180-4

* **Lean.** `Bridge/Refinement.lean::precompile_0x02_is_FIPS_180_4`
* **Type.** `∀ input, DeployedBytecode.SHA256_precompile input = Spec.sha256 input`
  (post-Phase-0 refactor: opaque-equality shape; real propositional content).
* **Scope.** Every `staticcall(0x02, ...)` in `SPHINCsC10Asm.verify`
  returns the FIPS 180-4 hash of its input.
* **Discharge.** Cited universal Ethereum TCB (consensus-client
  conformance: geth, reth, erigon, nethermind). Empirically backed by
  the Foundry parity test
  `test/PinnedCodehashes.t.sol::test_sha256_precompile_{abc,empty}_kat`.
* **Elimination path.** Verify the SHA-256 implementation in a
  consensus client (Appel/VST-style). Universal Ethereum trust;
  outside any single contract project.

## A2. EntryPoint v0.6 behaves like the `handleOp` model

* **Lean.** `Bridge/EntryPoint.lean::entrypoint_honest`
* **Two distinct statements — keep them separate.**
  * **(In-Lean) `entrypoint_honest` is a proved theorem over the
    model `handleOp`.** Its conclusion ("a wallet-balance decrement
    implies `validateSignature` returned success, with the resulting
    storage as post-state") is *provable from the definition of
    `handleOp`*: the failure branch returns `σ` unchanged (so no
    balance decrease is possible), and the success branch sets
    `walletStorage` to exactly the `validateSignature` post-state. It
    was demoted from an axiom to a theorem on 2026-08-20. Its proof uses
    only the kernel premises and it no longer appears as an A2 axiom in
    `theft_free`'s `#print axioms` closure. The theorem constrains nothing
    about the *real* contract: the model `handleOp` already entails it.
  * **(Cited-TCB) The genuine assumption is that the DEPLOYED
    EntryPoint v0.6 bytecode at
    `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` actually behaves like
    `handleOp`** — i.e. it only invokes wallet execution after
    `wallet.validateUserOp` returned the success sentinel, never itself
    transfers wallet value, and supplies `userOpHash` per ERC-4337
    v0.6. This is the load-bearing fact; it is **not** discharged in
    Lean (the Lean model is a fiction we trust to mirror the contract).
* **Discharge.** Cited. The OZ / ChainSecurity / Spearbit audits + 18+
  months mainnet operation of the immutable EntryPoint v0.6 are the
  trust basis for the deployed-bytecode-matches-`handleOp` assumption.
* **Elimination path.** Model EntryPoint v0.6's real bytecode in Lean
  and discharge the deployed-matches-`handleOp` assumption against KEVM
  (Kontrol). This is the **separate** 8-12 month engagement; it
  targets the cited-TCB statement above. The in-Lean theorem is already
  proved and supplies no deployment-faithfulness evidence. Out of current scope.

> **`entrypoint_no_replay` — REMOVED 2026-06-14 (phantom).** A prior
> A2-noreplay axiom (`(sender, nonce)` uniqueness) was deleted from the
> Lean source: it was dangling (referenced by zero theorems) and
> latent-false against its own model (`handleOp` never reads
> `op.nonce`). EntryPoint v0.6's real `NonceManager` replay protection
> remains a cited-TCB fact, simply not modelled in Lean and not needed
> by any theorem. (Note: `docs/AXIOM_STATUS.json` may still carry a
> stale `A2-noreplay` entry — see cross-file note.)

## A3. `solc 0.8.28` compiles the four PQ contracts correctly

Post-Phase 0 refactor: A3 is split into four per-contract sub-axioms,
each an `opaque + axiom-equality` shape that asserts the deployed
bytecode matches the Lean model. Removing any one would leave the
per-claim corollaries unprovable.

> **CURRENT (2026-06-13).** `AXIOM_STATUS.json` + `PINNED_CODEHASHES.md` are
> the AUTHORITATIVE source for codehashes and discharge artifacts; the
> entries below are kept in sync with them. The A3.* axioms are
> `discharged-bytecode`: the full Halmos suite (42 rules as of 2026-06-29 — 38 at
> the 2026-06-11 snapshot + 3 HalmosIsValidSignature + Equiv rules; re-tallied
> 2026-07-02) passes on BOTH the
> `default` (runs=200) and `deploy` (runs=999999) profiles' bytecode, and the
> deploy-profile build reproduces the live Base Mainnet contracts exactly
> (`test/DeployedBytecodeReproCheck.t.sol`). Codehashes are shown as
> `default / deploy`. (Historical note: a prior 2026-05-27 snapshot pinned
> stale hashes — A3.2 `0xdc2aa6c4…`, A3.3 `0x604e4000…`, A3.1 `0x919cf8ef…` —
> and attributed A3.3/A3.4 to Certora; those have been superseded by the
> Halmos discharge below.)

### A3.1. `solidityVerifier_compiles_correctly`

* **Lean.** `DeployedBytecode.SPHINCsC10Asm_verify = execC10Asm` (synced 2026-07-02; the bare `= verifyYulModel` form is **FALSE as a ∀** off N-masked keys — the bytecode runs two `and(key, N_MASK)==key` guards `verifyYulModel` omits. `execC10Asm` unfolds via `execC10Asm_eq` to `verifyYulModel` on N-masked keys, and is the form `theft_free`'s verifier leg consumes — `Bridge/Refinement.lean`)
* **Pinned codehash.** `0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5` (default) / `0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5` (deploy — **byte-identical to on-chain Base Mainnet verifier `0xdDE4D290…`**)
* **Discharge.** Halmos input-gate rules (`test/halmos/HalmosVerifier.t.sol`,
  length / N-mask) + **full-functional** executable Lean↔FIPS↔bytecode KAT
  (`lake exe verify-test-vectors` full-verify 10/10) + bulk 384/384
  (`verify-bulk`) + ~250-mutant wrong-accept screen. ∀-signature symbolic
  equivalence is the standing ceiling (uninterpreted SHA-256 = A1).

### A3.2. `solidityWallet_compiles_correctly` (+ A3.2-exec)

* **Lean.** `DeployedBytecode.PQSmartWallet_validateUserOp = validateSignature`
  (+ `executeWithOffchainCount` / `executeBatchWithOffchainCount`), on
  reachable states (combined-cap invariant).
* **Pinned codehash.** `0x43c65420691792d7f0f63dab95f47ab7adb649df4c83f432bd3cf2c95db3a06a` (default) / `0x551c4e03bbd433a5929828ab19caac13a94ca9e2be6074cf3e18c7d926034c22` (deploy)
* **Discharge.** Halmos pointwise-equivalence — primary
  `test/halmos/HalmosValidateUserOpEquiv.t.sol` + `HalmosExecuteEquiv.t.sol`;
  per-property corollaries `HalmosValidateUserOp.t.sol` + `HalmosExecute.t.sol`.

### A3.3. `solidityFactory_compiles_correctly`

* **Lean.** `DeployedBytecode.PQSmartWalletFactory_createAccount_passes ↔ Factory.createAccountPrecondition`
* **Pinned codehash.** `0xfa2922b4fadb81b4475307504890d68f2e3d9be97c7e5e9aeeba6e84110d7c3c` (default) / `0x5feb7955252e54bcbbf44062295bdeb45f3dea13c4ef7fb1ba579196d84da4b9` (deploy)
* **Discharge.** Halmos `test/halmos/HalmosFactory.t.sol` (5 rules) — the
  prior Certora rule-set `certora/PQSmartWalletFactory.spec` is an
  alternative path.

### A3.4. `solidityMultiOwnable_compiles_correctly`

* **Lean.** `DeployedBytecode.PQMultiOwnable_ownerAtIndex s i = s.ownerAtIndex i`
* **Pinned codehash.** `0x43c654…a06a` / `0x551c4e…34c22` (embedded in `PQSmartWallet`; no independent deploy)
* **Discharge.** Halmos `test/halmos/HalmosMultiOwnable.t.sol` (7 rules) —
  REPLACED the prior Certora artifact `certora/PQMultiOwnable.spec`, which had
  been pinned to a stale codehash and never re-run.

## A4. EVM bytecode executes per specification

* **Lean.** `Bridge/Refinement.lean::evm_bytecode_executes_correctly`
* **Type.** `∀ (c : Wallet.Execute.Call), evmDeliversCall c` (content-bearing
  form since 2026-06-14; was the prior `: True` placeholder). `evmDeliversCall`
  is a kernel-irreducible `opaque` predicate — "the EVM faithfully transfers
  `c.value` and delivers `c.data` to `c.target` per Cancun semantics" — so the
  axiom *names* the EVM forwarded-byte delivery assumption instead of asserting
  nothing.
* **Scope.** Every external call the wallet bytecode emits on a non-reverting
  execute path is faithfully delivered (value moved, calldata forwarded). This
  is the boundary `theft_free`'s value-movement guarantee bottoms out on.
* **Status in `theft_free`.** A4 is a **NON-CONSUMED TCB marker**: a
  `have _a4_delivers := …` binding pulls it into `theft_free`'s `#print axioms`
  closure (so the closure self-documents the EVM-delivery boundary), but the
  safety proof does not consume it — deleting the binding leaves `theft_free`
  proven. Its honesty value is the content-bearing *type*, not a logical
  dependency. (Its closure presence relies on `evmDeliversCall` staying
  `opaque`; the `lint_fv` (d) guard fails if `trivial` ever inhabits it.)
* **Discharge.** Cited universal Ethereum TCB; KEVM / consensus-client
  conformance is the formal-EVM-semantics referent. No in-Lean discharge
  artifact is claimed.

## A5. SPHINCS+C10 is EUF-CMA secure

* **Lean.** `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC` plus the three
  shape axioms in `Crypto/Assumptions.lean` (`SM_DT_TCR_F`, `ITSR_F`,
  `hMsg_random_oracle`) and the collision-resistance reduction axiom
  `sha256_collision_resistance`.
* **Scope.** The **qualitative** reduction (a forgery against an installed
  key's honest history ⇒ `BreaksHash`) is what is cited/axiomatised; the
  **quantitative** `Pr ≤ ε` bound is **NOT formalised** for the C10 parameter
  set (corrected 2026-07-02 — the earlier concrete `ε(A) + Q · 2^-128` here
  carried no citation deriving `2^-128` for C10 and contradicted the ledger:
  `AXIOM_STATUS.json` records "the quantitative `Pr ≤ ε` bound is not
  formalised … no public bit-security number for C10", and the project's own
  kernel-checked generic-attack floor is **96 bits** at the shipped `2^16` cap
  = `min(FORS+C 143, birthday 112, multi-target 96)`, `Crypto/Quantitative.lean`
  — *not* 128). What is kernel-proven is the reduction's *consistency /
  non-vacuity fence*, not a probability.
* **Discharge.** Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT
  2024 (ePrint 2024/910) for SPHINCS+; Hülsing PQC2022 for the
  WOTS+C/FORS+C variant.
* **Elimination path.** Extend the Barbosa et al. EasyCrypt
  development to SPHINCS+C. Multi-person-year research.

### A5-injective. SHA-256 collision-resistance (disjunctive reduction)

* **Lean.** `Crypto/Assumptions.lean::sha256_collision_resistance`
* **Form (honest).** This is **not** an injectivity axiom — literal
  injectivity (`equal digests ⟹ equal preimages`) is mathematically
  FALSE on inputs longer than 32 bytes (pigeonhole). The Lean source
  states the consistent **reduction** form: for two equal-length
  segment lists with matching SHA-256 digests, EITHER the flattened
  preimages are equal OR the cited SHA-256 hardness was broken
  (`… ∨ BreaksHash`). A distinct same-length collision IS the cited
  collision-resistance break (Barbosa et al. 2024 SM-DT-TCR, empty-ADRS
  unkeyed collision-resistance); `BreaksHash` is opaque and never
  assumed false.
* **Scope.** Used by Claim 1's `sphincsDigest_field_binding` lemma,
  which propagates the disjunct: equal `sphincsDigest(op)` digests imply
  equal preimages — unless SHA-256 is broken. (The "A5-injective" label
  is retained as a stable doc-anchor; the underlying axiom is the
  collision-resistance reduction, not injectivity.)

## A6. Lean 4 kernel checks proofs correctly

* **Scope.** The Lean 4 kernel (pinned in `lean-toolchain`) faithfully
  checks every closed `theorem` in this project.
* **Built-ins.** `propext`, `Classical.choice`, `Quot.sound`.

---

## Per-claim trust footprint

| Claim | Axioms cited in `#print axioms` of the corollary |
|-------|--------------------------------------------------|
| 1. Signature-to-execution binding | A6 (kernel) + `sha256_collision_resistance` (the A5-injective reduction). The full `theft_free` closure adds A1, A3.1, A4, A5 (4 sub-axioms); A2 is an external deployment assumption, not a closure axiom. **Scope of the in-kernel content:** the corollary binds the *signed digest* to the op's `callData` **field** (digest-uniqueness) and the `ownerIndex` (per-index transient credit) — it does NOT in-kernel prove that the bytes *executed* equal the bytes *signed*. That executed-call ⇄ signed-calldata binding rests on cited-TCB **A2** (deployed EntryPoint v0.6 relays `op.callData` verbatim to the wallet) + **A4** (the EVM forwards those bytes to the target). |
| 2. Owner-set integrity + init atomicity | A6 only (`initialize_called_exactly_once` and `owner_set_nonempty_after_init` are purely structural). For bytecode-level enforcement, A3.4 (MultiOwnable) + A3.2 (Wallet) + A3.3 (Factory) are discharged by Halmos (see A3.* — the prior Certora rule-sets are superseded/alternative paths). |
| 3. Execution faithfulness + value flow | A6 only (`executeBatch_faithful` is purely operational over the `Execute` model's `(targets, values, datas)` arguments). For bytecode-level enforcement, A3.2 (Wallet) is discharged by Halmos against pinned `PQSmartWallet` codehash. **Scope:** the in-kernel theorem proves the model dispatches its arguments faithfully and in order; that those arguments equal the *signed* batch (and reach the real callee) rests on cited-TCB A2 + A4, not on the kernel. |

The minimal TCB shared by all three claims:
**A6 (Lean kernel) + A5 (SPHINCS+C10 + the `sha256_collision_resistance`
reduction corollary) + A1 (SHA-256 precompile) + A2
(deployed-EntryPoint-v0.6-matches-`handleOp`) + A4 (EVM forwarded-byte
delivery) + A3.1-A3.4 (per-contract solc correctness, each discharged
by a Halmos session — plus, for A3.1, executable Lean↔FIPS↔bytecode KAT
+ bulk vectors; the prior Certora rule-sets remain as historical /
alternative paths, not the current discharge).**

---

## Out of scope (not in TCB, deliberately excluded)

These are *not* trusted; they are *omitted from the model* entirely.
Their failure does not invalidate the three claims — they are simply
outside their scope.

* **Firmware** (Rust under `secure/`, `nonsecure/`, workspace crates).
  The proof says nothing about whether the firmware actually keeps the
  secret keys secret; if the secret keys leak, the adversary holds an
  "installed owner key" and the theorem is vacuously satisfied.
* **Side-channel security** of firmware signing.
* **Gas / DoS / griefing** — covered empirically by Foundry tests,
  not by these proofs.
* **MEV / bundler manipulation** — the theorem speaks only about
  whether a UserOp was authorised, not about ordering or
  front-running.
* **Frontend / companion app** — `tools/wallet_run_hw.py`, the WebHID
  companion, RPC providers. Adversarial frontends cannot forge sigs
  (A5) but can refuse to forward valid ones (liveness, not safety).
* **Cross-chain replay** — the chain-id binding is part of
  `sphincsDigest`'s preimage; cross-chain replay would be a forgery
  (contradicts A5).

---

## Three-claim headline statement

> *Given* A1–A6 (with the per-contract A3 sub-axioms discharged by
> Halmos against pinned codehashes), for any deployed
> `PQSmartWallet` proxy `W`:
>
> 1. **Signature-to-execution binding.** No successful
>    `executeWithOffchainCount` / `executeBatchWithOffchainCount` runs
>    without a SPHINCS+C10 signature valid under an installed owner
>    key of `W` over a `sphincsDigest` that commits to the exact
>    chainId, sender, nonce, and `callData` **field** of the signed op.
>    (That this signed `callData` field equals the bytes actually
>    *executed* by `W` and delivered to the target is the cited-TCB
>    boundary A2 — EntryPoint relays `op.callData` verbatim — composed
>    with A4 — the EVM forwards those bytes; the kernel proof binds the
>    digest-to-field and the `ownerIndex`, not the executed payload.)
>
> 2. **Owner-set integrity + initialization atomicity.** The owner
>    set is mutated only by self-call originating from a validated
>    UserOp; never empty after `initialize`; `initialize` runs
>    exactly once; the UUPS upgrade path is unreachable.
>
> 3. **Execution faithfulness under batching and value flow.**
>    `executeBatchWithOffchainCount` performs exactly the signed
>    `(target, value, data)` tuples in order; only EntryPoint reaches
>    the executor; total ETH outflow equals the signed batch sum;
>    no callback can alter the remainder of the batch.

See [`AXIOM_STATUS.json`](AXIOM_STATUS.json) for the machine-checkable
discharge-artifact tracking,
[`PINNED_CODEHASHES.md`](PINNED_CODEHASHES.md) for the bytecode pins,
and [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md) for the
remaining work to tighten each cited-TCB axiom into a discharged one.

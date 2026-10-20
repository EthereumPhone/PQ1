# Three-Claim Proof for PQSmartWallet

This document explains how `contracts/verification/` mathematically
proves three security claims about `PQSmartWallet`. Read it before
touching any of the verification artifacts — it ties together the
Lean theorems, the bytecode-level discharge artifacts (Halmos,
Certora, Foundry), and the trust assumptions.

---

## The three claims

These are the user-facing security guarantees `PQSmartWallet`
provides. Each is mathematically proven, modulo a small set of cited
trust assumptions documented in [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md).

### Claim 1 — Signature-to-execution binding

> Every successful `executeWithOffchainCount` / `executeBatchWithOffchainCount`
> call corresponds to a SPHINCS+C10 signature from a current owner
> over a `userOpHash` (computed as `sphincsDigest`) that commits to
> the exact chainId, sender, nonce, and calldata being executed.

What this kills:
- Cross-chain replay (chainId is part of the digest preimage)
- Cross-account replay (sender address is part of the digest preimage)
- Nonce reuse (delegated to the deployed EntryPoint v0.6 — a cited-TCB fact
  under A2; the former `entrypoint_no_replay` axiom was DELETED 2026-06-14 as
  dangling + latent-false, nonce-replay protection is the EntryPoint's job,
  not a Lean axiom)
- Calldata substitution between the signed digest and what executes —
  the userOpHash digest cryptographically commits to `sha256(callData)`
  (kernel theorem `theft_free_with_calldata_binding`, via SHA-256
  collision-resistance). NOTE: that EntryPoint relays *exactly*
  `op.callData` to the wallet and the EVM delivers the resulting CALL is
  the cited-TCB leg (A2 EntryPoint relay-fidelity + A4 EVM delivery), NOT
  an in-kernel check. The in-kernel transient-storage credit binds only
  `ownerIndex`, and the field binding gives only digest-uniqueness —
  neither pins the signed→executed calldata relay.
- Bugs in the SPHINCS+C10 verification path or the ERC-1271
  `replaySafeHash` wrapper (verifier matches the Lean Yul model
  via A3.1)

### Claim 2 — Owner-set integrity & initialization atomicity

> The owner set is mutated only by self-call from a validated UserOp;
> never empty after `initialize`; `initialize` runs exactly once and
> cannot be front-run; the UUPS upgrade path is unreachable; no
> admin/deployer role can replace the implementation or owner set
> unilaterally.

> *UPDATE 2026-10-20 (audit freeze):* owner removal no longer exists, so the
> owner set is **append-only**. Its only mutator after `initialize` is
> `addOwnerBytes`, which is EntryPoint-gated and reachable only from a
> bootstrap-validated UserOp (the self-call path was closed by H-2). It
> appends at `nextOwnerIndex` and refuses any key ever installed, so a key
> keeps one index and one set of counters for the wallet's life (#131). The
> statement above predates that; "mutated only by self-call" should be read
> as "only appended, only through the bootstrap-validated `addOwnerBytes`".

What this kills:
- Bricking via removing the last owner (since 2026-10-20 by construction:
  nothing removes an owner)
- Re-installing a spent key at a fresh index to reset its budget (#131)
- Phantom-owner injection
- Init-front-running of counterfactual deployments
- "Trust the wallet vendor" criticism — the wallet maker cannot
  move user funds or change accounts

### Claim 3 — Execution faithfulness under batching and value flow

> `executeBatchWithOffchainCount` performs exactly the sequence of
> `(target, value, data)` tuples passed to it, in order, with no hidden
> calls, no caller other than EntryPoint-or-self reaching the executor,
> and total ETH outflow equals the sum of the batch's values.

Scope (honest): the kernel theorems pin the executed sequence to the
`executeBatch` *arguments* (order-preserving, value-sum exact). That those
arguments equal *what the owner signed* is the signed↔executed relay leg,
which rests on A2 (EntryPoint relays the signed `callData`) + A4 (EVM
delivers the CALL), cited-TCB — not an in-kernel theorem. "No callback
alters the remainder of the batch / re-enters validation" follows from the
model being a straight-line, no-loop construction (`buildBatchCalls` is a
pure function of the inputs) plus E-1 (`execute_caller_is_entrypoint` —
only EntryPoint reaches the executor); it is NOT a separately proven
reentrancy theorem (E-7 restates E-5 verbatim — same statement, same
proof).

What this kills:
- Long tail of "validation passed but something weird executed" bugs
- Malicious-target reentrancy into the account itself (via E-1's
  EntryPoint-only executor gate + the no-loop batch model; not a
  standalone reentrancy theorem — see the Claim 3 scope note)
- Batch-ordering exploits

### Claim 4 — Execution-gate non-bypass (call-graph)

> For any per-transaction step-trace through the wallet, every external
> call appearing in the post-state `callStack` was authorised by at
> least one `validate` step earlier in the same trace whose
> `c10Verifier.verify` returned `true` on the decoded
> `(pkSeed, pkRoot, sphincsDigest, innerSig)` under an installed owner
> key. There is no path — direct, re-entrant, transient-replayed, or
> via a different gateway — by which the wallet emits an external
> call without that prior verifier acceptance.

What this kills:
- "Skip-validate" attacks where a crafted EntryPoint call somehow
  reaches the executor without `validateUserOp` running first
- Transient-slot replay (re-using a single validate's
  `validatedOwnerPlusOne` for multiple executes — H-3)
- "Verifier returned false but the wallet still executed" branches
  (composes `_validateSignature`'s strict-success path with
  `_consumeValidatedOwnerIndex`'s one-shot token clear)
- Re-entry from a callback inside `executeBatch` that tries to drive
  the executor without re-validating

---

## Verification stack

Four layers compose into the proof. Each layer is independently
re-runnable; their outputs are pinned in
[`AXIOM_STATUS.json`](AXIOM_STATUS.json).

| Layer | Tool | What it proves | Files |
|-------|------|----------------|-------|
| **Lean 4** | `lake build` | Kernel-checked per-claim theorems against the Lean models of `validateUserOp` / `executeWithOffchainCount` / `initialize` / `addOwnerBytes` / etc. | `contracts/verification/lean/` |
| **Halmos** | `halmos --bytecode <pinned-hash>` | Symbolic execution against the pinned PQSmartWallet runtime bytecode, discharging the `DeployedBytecode.PQSmartWallet_validateUserOp = validateSignature` axiom (A3.2) | `contracts/smart-wallet/test/halmos/` |
| **Certora** | `certoraRun` | Inductive rules quantified over *all* methods, discharging A3.3 (Factory) + A3.4 (MultiOwnable) + the cross-method surface of A3.2 (Wallet) | `contracts/smart-wallet/certora/` |
| **Foundry** | `make verify-three-claims` (dotenv-free, fixed-config/compiler Forge receipt: fuzz 256; invariants 256 × 500) | Stateful fuzzing + parity tests + codehash pinning, defense-in-depth and the empirical SHA-256 KAT for A1 | `contracts/smart-wallet/test/` |

### Why all four

- **Lean alone** proves the *model* is sound but doesn't connect to
  deployed bytecode.
- **Halmos alone** verifies the bytecode but can't universally quantify
  over methods (Claim 2's "*any* method preserves the owner set" needs
  inductive reasoning).
- **Certora alone** is excellent for the universal quantification but
  uses a separate prover backend (also in the trust base).
- **Foundry alone** is empirical, not exhaustive.

The composition is the point: each tool's TCB is independent. A
soundness bug in Halmos doesn't void the Certora discharge or the
Lean theorem.

---

## Per-claim discharge breakdown

### Claim 1

**Lean** — `Spec/Theorems.lean::theft_free_with_calldata_binding`.
Discharges to exactly ONE axiom (corrected 2026-07-02, finding exec-lean-F2/V4 —
this block previously claimed it "composes I-1 + A3.1 + A3.2" and closed over the
deleted `sha256_injective_on_fixed_length`, BOTH false: the proof consumes only
`sphincsDigest_field_binding`, and the false injective axiom was replaced by
`sha256_collision_resistance` on 2026-06-14):
- `Wallet/SphincsDigestSpec.lean::sphincsDigest_field_binding` (equal digest ⇒
  equal preimage ∨ `BreaksHash`, via `Crypto.sha256_collision_resistance`).

This is the **digest field-binding LINK** of Claim 1, NOT the whole
signature-to-execution binding: that the EntryPoint relays `op.callData` verbatim
and the EVM delivers the CALL are the cited-TCB legs (A2 relay + A4 delivery — see
the Claim-1 description above and `ASSURANCE_CASE.md` EF-#15's 4-link chain), NOT
in-kernel. I-1 / A3.1 / A3.2 are consumed by `theft_free` / `theft_free_bytecode`,
not by this corollary.

Closure: `propext, Quot.sound, SphincsCVerify.Crypto.sha256_collision_resistance`
(verified against the live `#print axioms` dump 2026-07-02).

**Halmos** — `test/halmos/HalmosValidateUserOp.t.sol`:
- `check_validateUserOp_success_implies_verifier_accepted`
- `check_validateUserOp_rejects_wrong_selector_for_bootstrap` / `..._for_slot`
- `check_validateUserOp_rejects_nonzero_tail_pad` (audit L-1)
- `check_validateUserOp_rejects_non_entrypoint_caller`
- `check_execute_without_validate_reverts` (audit H-3)

**Certora** — `certora/PQSmartWallet.spec`:
- `validateUserOp_only_entrypoint`

**Foundry** — `test/LeanSelectorParity.t.sol` (4/4 selectors match) +
`test/PQSmartWalletInvariants.t.sol::invariant_impl_slot_unchanged`.

### Claim 2

**Lean** — `Wallet/Invariants.lean` (UPDATE 2026-10-20: `Storage.removeOwner`
and `removeOwner_preserves_index0` were deleted with the Solidity function;
`cannot_remove_bootstrap` keeps its name with a new statement, and the I-9
theorems below were added):
- `cannot_remove_bootstrap` (I-4) — since 2026-10-20: on an initialised
  state, `addOwner` leaves `ownerAtIndex 0` unchanged (the only owner-table
  mutator left). Before: `Storage.removeOwner s 0 _ = none`
- `reachable_ownerTableWF`, `reachable_key_installed_at_most_once`,
  `reachable_addOwner_refuses_installed_key` (I-9, 2026-10-20) — on every
  reachable state the owner table is injective, every installed key is
  flagged and below `nextOwnerIndex`, and `addOwner` refuses an installed key
- `initialize_called_exactly_once` — `nextOwnerIndex ≠ 0 ⇒ tryInitialize = none`
- `initialize_post_state` — successful init produces `Storage.initialised`
- `owner_set_nonempty_after_init` — bootstrap present, `nextOwnerIndex = 2`
- `addOwner_preserves_index0`,
  `bumpBootstrap_preserves_ownerAtIndex`, `bumpSlot_preserves_ownerAtIndex`,
  `setOffchain_preserves_ownerAtIndex` — composite invariance
- `create2_address_chain_independent` (I-7) — kernel-proves only that the
  CREATE2 salt's preimage carries no chain id (salt chain-freeness); the
  full address's chain-independence additionally rests on address-level
  EVM-TCB facts (a singleton CREATE2 factory at one address per chain +
  frozen `initCode`), made explicit in the conditional theorem
  `create2Address_chain_independent`
- `factory_requires_bootstrap_sig` (I-8)
- `eip1271_forbids_bootstrap` (I-6)
- `storage_mutations_preserve_impl_slot_disjointness` (composes
  `StorageLayout.pq_storage_disjoint_from_erc1967_impl`)

**Certora** — `certora/PQMultiOwnable.spec`:
- `bootstrap_unremovable`
- `cantInitTwice` (universally quantified over `method f`)
- `onlySelfCanChangeOwnerAtIndex`, `onlySelfCanChangeIsOwnerBytes`
- `bootstrapUses_only_increases`, `slotUses_only_increases`, `offchainSigCount_only_increases`
- `combined_cap_invariant` (inductive)
- `bootstrapUses_capped`
- `nextOwnerIndex_monotonic_growth`
- `no_owner_above_nextOwnerIndex`

**Certora** — `certora/PQSmartWalletFactory.spec`:
- `salt_depends_only_on_master_pk`
- `createAccount_must_verify_bootstrap_sig`
- `createAccount_rejects_wrong_chainId`
- `implementation_immutable`

**Foundry** — `test/PQSmartWalletInvariants.t.sol`:
- `invariant_bootstrap_owner_present`
- `invariant_nextOwnerIndex_at_least_2`
- `invariant_impl_slot_unchanged`
- `invariant_bootstrapUses_capped`
- `invariant_bootstrapUses_monotonic`

### Claim 3

**Lean** — `Wallet/Execute.lean` + `Spec/Theorems.lean::executeBatch_faithful`.
All 8 theorems:
- E-1 `execute_caller_is_entrypoint`
- E-2 `execute_rejects_self_target`
- E-3 `execute_requires_token_set` / `execute_requires_token_match`
- E-4 `execute_clears_token`
- E-5 `executeBatch_runs_in_signed_order`
- E-6 `executeBatch_value_outflow_eq_sum_values`
- E-7 `executeBatch_callback_preserves_loop` — a verbatim restatement of
  E-5 (`executeBatch_runs_in_signed_order`): identical statement and
  identical proof, so it adds the calldata-immutability *framing* but no
  independent reentrancy content
- E-8 `execute_only_validateSig_authorises`

Closure: `propext, Classical.choice, Quot.sound` (purely operational —
no cryptographic axioms needed).

**Halmos** — `test/halmos/HalmosExecute.t.sol`:
- `check_execute_rejects_non_entrypoint_caller`
- `check_execute_rejects_self_target` (audit H-2)
- `check_execute_requires_validated_owner_index` (audit H-3)
- `check_execute_rejects_owner_index_mismatch`
- `check_execute_clears_token_no_replay`
- `check_executeBatch_rejects_any_self_target`
- `check_executeBatch_k2_order_preserving` (k=2 bounded; k>2 covered
  inductively by Lean theorem E-5)

**Certora** — `certora/PQSmartWalletExecute.spec`:
- `execute_does_not_touch_owner_table`
- `executeBatch_does_not_touch_owner_table`
- `onlyEntryPoint_reaches_executor` / `..._batch_executor`
- `executeBatch_rejects_self_at_position_0`

**Foundry** — `test/PQSmartWalletInvariants.t.sol`:
- `invariant_combined_cap_slot0` / `invariant_combined_cap_slot1`
- `invariant_bootstrapUses_monotonic`

### Claim 4

**Lean** — `Wallet/TxFlow.lean` + `Spec/Theorems.lean::every_call_gated_by_verifier`.
Composes:
- `Wallet/TxFlow.lean::applyStep_token_set_only_by_validate_success` —
  the transient `validatedOwnerPlusOne` is unforgeable: every
  `0 → non-zero` transition is a slot-path `validate` step whose
  `validateSignatureOk` predicate holds at the pre-state (so
  `verify_fn` returned `true`).
- `Wallet/TxFlow.lean::validate_step_preserves_callstack` — `validate`
  cannot, by definition, append a call.
- `Wallet/Execute.lean::execute_only_validateSig_authorises` (E-8) —
  every successful `execute` / `executeBatch` step requires
  `validatedOwnerPlusOne = ownerIndex + 1` on entry.
- `Wallet/Invariants.lean::validateSignature_only_via_verify` (I-1) —
  bridges `validateSignatureOk` to the explicit `verify_fn = true`
  witness used inside `StepVerified`.
- Trace-level induction over `runTrace` assembles the above into the
  headline statement.

Closure: `propext, Classical.choice, Quot.sound` (kernel-only — no
new axioms; reuses I-1 and E-8; confirmed by
`scripts/dump_axioms_claim4.lean`). IMPORTANT scope: this trace gate
constrains the `verify_fn` field *supplied* in each trace's `validate`
step — it is a model-level statement and is NOT lifted here to the
deployed `SPHINCsC10Asm.verify` bytecode. Its closure carries no bridge
axiom, so there is no in-kernel "A1 + A3.1 + A4 lift" of this gate to the
on-chain verifier. The deployed-verifier connection is made separately,
and only for value-moving paths, by `theft_free` (via A2 + A3.1): a
wallet-balance decrement implies the *deployed* verifier accepted an
installed-owner C10 sig over the op digest. Pinning the pure call-graph
gate — value=0 external calls — to the on-chain verifier remains an OPEN
obligation (`OPEN_PROOF_OBLIGATIONS.md`).

The conclusion is existential: it yields *some* abstract pre-state
`σ_pre` and a `StepVerified` step in the trace. `σ_pre` is existentially
quantified — not pinned to be the reachable on-chain wallet state — and
the result is not per-call attribution (that strengthening is in
`OPEN_PROOF_OBLIGATIONS.md`). The existential is already sufficient to
rule out the bypass attack: a trace containing zero verifier-true
validates cannot produce any external call.

**Halmos** — `test/halmos/HalmosExecute.t.sol::check_execute_requires_validated_owner_index`
and `check_execute_clears_token_no_replay` discharge the
per-transaction shape against the pinned bytecode (one execute per
validate; no transient replay).

**Certora** — `certora/PQSmartWalletExecute.spec::onlyEntryPoint_reaches_executor`
+ `onlyEntryPoint_reaches_batch_executor` cover the universal
quantification over methods that could reach `target.call`.

**Foundry** — `test/PQSmartWallet.t.sol::test_bootstrapCannotCallExecute`
+ `test_rotationBootstrap...` exercise the transient gating
concretely (try-execute-without-validate reverts; validate-then-execute
succeeds).

---

## Trust assumptions (cited TCB)

The proof rests on six lettered assumptions, documented in detail in
[`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md):

| Axiom | What it asserts | Discharge |
|-------|-----------------|-----------|
| **A1** | EVM precompile `0x02` implements FIPS 180-4 SHA-256 | Cited universal Ethereum TCB + NIST CAVS KAT test |
| **A2** | EntryPoint v0.6 is unhackable (validate ⇒ execute dispatch, no direct debit, nonce uniqueness) | Cited: OZ / ChainSecurity / Spearbit audits + 18+ months mainnet operation. Per user decision, kept as cited-TCB. |
| **A3.1** | Deployed `SPHINCsC10Asm.verify` = Lean Yul model | Halmos against pinned codehash `0x94a6…50e9` + Lean ↔ Rust ↔ Solidity differential |
| **A3.2** | Deployed `PQSmartWallet.validateUserOp` = Lean `validateSignature` | Halmos against pinned codehash `0x4201…006f` |
| **A3.3** | Deployed `PQSmartWalletFactory.createAccount` = Lean precondition | Certora against pinned codehash `0xe40c…2270` |
| **A3.4** | Deployed `PQMultiOwnable.ownerAtIndex` = Lean storage model | Certora + storage-slot parity test |
| **A4** | EVM bytecode executes per spec (Cancun) | Cited universal Ethereum TCB (KEVM as referent) |
| **A5** | SPHINCS+C10 is EUF-CMA secure | Cited: Barbosa et al. ASIACRYPT 2024 + Hülsing PQC2022 |
| **A5-injective** | SHA-256 collision-free on equal-length inputs (corollary of A5) | Cited corollary |
| **A6** | Lean 4 kernel checks proofs correctly | Lean 4 kernel built-ins |

Out of scope (not in TCB, deliberately excluded): firmware, side
channels, gas/DoS, MEV/bundler manipulation, adversarial frontends.

---

## How to run the verification

### Locally

```bash
cd contracts/verification
make verify-three-claims
```

This runs:
1. `lake build` — Lean kernel type-checks every theorem (zero sorries).
2. `make verify-audit` — prints axiom dependency closure for each
   per-claim corollary.
3. `bash scripts/lint_axioms.sh` — fails on any new `True`-typed
   axiom outside the allowlist.
4. A clean-environment `forge build && forge test --json` under the physical
   project root and exact `foundry.toml` — rejects the Forge-loaded project
   `.env`, pins the local Solc 0.8.28 binary path and digest, disables compiler
   auto-detection and network resolution, then runs the Foundry unit / parity /
   codehash tests and rejects failures, empty result sets, filters, any drift
   from the pinned label/status/kind manifest, reduced fuzz counts, missing or
   failed corpus-replay fields, or any skip outside the two pinned
   RPC-dependent receipt tests. Run
   `scripts/verify-three-claims.sh --self-test-forge-boundary` to inspect that
   local tool/config boundary without starting the full campaign.
5. A clean-environment `forge test --json --match-contract Invariants` —
   every invariant record must report exactly 256 runs × 500 calls
   (128,000 calls), explicit zero reverts, and an explicit zero
   corpus-replay-failure count.
6. `halmos --contract HalmosValidateUserOp` and `halmos --contract HalmosExecute`
   — symbolic execution against pinned bytecode (skips if `halmos`
   not installed).
7. `certoraRun` on each of the 4 conf files (skips if
   `CERTORAKEY` unset).
8. Per-claim summary.

### In CI

**`make verify-three-claims` is a LOCAL/manual end-to-end convenience bundle — it
is NOT a single CI job** (correction 2026-07-02: an earlier
`contracts/.github/workflows/verify-three-claims.yml` was a *nested* `.github`
path that GitHub Actions never executes — repo-level workflows only run from the
root `.github/workflows/` — so "runs the same pipeline on every PR" was never
true, and the bundle's Halmos/Certora legs need a patched toolchain / a
`CERTORAKEY` secret unavailable in CI). What IS CI-enforced, per-PR, are the
bundle's *constituent* gates, each in a root workflow:
`verify-build`/`verify-audit`/`verify-fv-lints`/`verify-ledger-consistency`/
`verify-storage-mutators` (`.github/workflows/lean-fv.yml`), `verify-transcription`
(`a31-transcription.yml`), and the Foundry `forge test` + codehash-freeze
(`ci.yml`). The Halmos/Kontrol symbolic discharge (steps 6–8) is a local/manual
gate (see `verify-bytecode` in `scripts/gate_enforcement.json`, `enforcement:
local_documented`). Run the whole bundle locally with `make verify-three-claims`
(fixed 2026-07-02: it deterministically exited 141 mid-run — a `head`-under-
`pipefail` SIGPIPE).

The ledger gate's authoritative **local** invocation is the clean pre-exec
receipt boundary below (run from the repository root):

```bash
[[ ${UID} -ne 0 && -u /usr/bin/sudo && -x /usr/bin/sudo ]] &&
  /usr/bin/sudo -n -u "#${UID}" -- \
    /usr/bin/env -i \
    /usr/bin/bash --noprofile --norc -p \
      contracts/verification/scripts/run_authoritative_make.sh \
      make -C contracts/verification verify-ledger-consistency
```

For the local command, the shell-keyword preconditions and non-interactive
setuid `sudo` call are part of the Linux security boundary. CI removes even that
outer Bash dependency: the `lean-fv.yml` step asks GitHub Runner to execute
`/usr/bin/sudo -n -u runner -- /usr/bin/env -i /usr/bin/bash ... {0}` directly
as its custom shell, and its body uses `exec /usr/bin/bash ...` on the launcher
to preserve `sudo` as the launcher's parent. `scripts/gate_enforcement.json`
pins that parsed step plus `runs-on: ubuntu-latest` and the absence of a job
container, ambient job environment, or skip controls. The checker rejects
duplicate YAML/JSON keys instead of accepting last-value-wins ambiguity, while
the gate self-test proves that an untrusted runner/container, `if: false`, a
no-op shell, hostile startup state, or removal of the launcher is rejected.
The blocking-trigger contract also requires coverage of `master`, rejects
ordered negative branch/path patterns rather than approximating their
last-match semantics, and enrolls the workflow, Make target, checker, and
launcher paths themselves so edits to the evidence boundary cannot suppress
its own run.

Sudo's secure-execution startup cannot be suppressed by caller loader
variables; it immediately drops back to the same non-root user, then
`/usr/bin/env -i` clears the environment before Bash starts. The launcher
rejects any leaked environment, accepts only the exact ledger target, resolves
its own physical single-link file identity before deriving the repository root,
and requires its exact completion marker in a private receipt. This requires
passwordless same-UID sudo (`-n`; the `runner` account on the declared
GitHub-hosted Ubuntu job) and fails closed when that platform prerequisite is
unavailable. A bare
`make -C contracts/verification verify-ledger-consistency` is useful
diagnostically, but is not an authoritative hostile-environment receipt: loader
controls can otherwise suppress Make before its in-file guards run.

### Just the Lean kernel check (fastest, no Foundry/Halmos/Certora)

```bash
cd contracts/verification
make verify-build       # ~10 s incremental
make verify-audit       # prints axiom closures
```

### Just the Foundry tests

```bash
cd contracts/smart-wallet
forge test --match-contract "LeanSelectorParityTest|StorageSlotParityTest|PinnedCodehashesTest|PQSmartWalletInvariantsTest"
```

---

## When the bytecode changes

Any source change that drifts the runtime codehash invalidates the
pin in `test/PinnedCodehashes.t.sol`. The CI gate fails until:

1. Re-capture the new codehash via `forge test --match-test test_codehash_pinned_or_print -vv`.
2. Update `test/PinnedCodehashes.t.sol` + `docs/PINNED_CODEHASHES.md`.
3. Re-run the affected discharge artifact:
   - `PQSmartWallet` change → `halmos --contract HalmosValidateUserOp` + `halmos --contract HalmosExecute`
   - `PQSmartWalletFactory` change → `certoraRun certora/confs/PQSmartWalletFactory.conf`
   - `PQMultiOwnable` change → `certoraRun certora/confs/PQMultiOwnable.conf`
   - `SPHINCsC10Asm` change → `cross_validation/` Lean ↔ Rust ↔ Solidity differential
4. Update `AXIOM_STATUS.json` with the new discharge artifact ID
   (session hash / rule-set hash).

---

## File map

### Lean (`contracts/verification/lean/SphincsCVerify/`)

| File | Role |
|------|------|
| `Spec/Theorems.lean` | Headline theorem `theft_free` + per-claim corollaries `theft_free_with_calldata_binding`, `executeBatch_faithful`, `every_call_gated_by_verifier`, `no_call_without_prior_verifier_acceptance` |
| `Bridge/Refinement.lean` | A1, A3 sub-axioms in `opaque + axiom-equality` shape |
| `Bridge/EntryPoint.lean` | A2 (`entrypoint_honest`) — the `entrypoint_no_replay` axiom was DELETED 2026-06-14 |
| `Bridge/SolidityVerifier.lean` | Yul-shape model of `SPHINCsC10Asm.verify` |
| `Crypto/EUFCMA.lean` | A5 + `cannot_forge_without_breaking_SHA256` |
| `Crypto/Assumptions.lean` | SM_DT_TCR_F + ITSR_F + hMsg_random_oracle + `sha256_injective_on_fixed_length` |
| `Wallet/Storage.lean` | `PQMultiOwnableStorage` model + `Storage.tryInitialize` |
| `Wallet/MultiOwnable.lean` | Counter monotonicity + `bootstrap_unremovable` |
| `Wallet/ValidateUserOp.lean` | `validateSignature` model + concrete `sphincsDigest` (12 fields) + real selectors |
| `Wallet/SphincsDigestSpec.lean` | `sphincsDigest_preimage_len`, `sphincsDigest_field_binding`, preimage injectivity |
| `Wallet/StorageLayout.lean` | ERC-7201 slot literal + ERC-1967 reserved slot disjointness |
| `Wallet/Execute.lean` | 8 theorems for Claim 3 (E-1..E-8); `executeWithOffchainCount`, `executeBatchWithOffchainCount` operational model |
| `Wallet/TxFlow.lean` | Per-transaction `Step` / `applyStep` / `runTrace` model + Claim 4 trace-level non-bypass (`callstack_grew_implies_some_verify_true`) |
| `Wallet/Invariants.lean` | All 8 wallet invariants I-1..I-8 + Claim 2 initialization theorems |
| `Wallet/Factory.lean` | CREATE2 salt + `addSlot0Digest` + `createAccountPrecondition` |
| `Wallet/IsValidSignature.lean` | EIP-1271 model + bootstrap rejection |

### Foundry (`contracts/smart-wallet/test/`)

| File | Role |
|------|------|
| `LeanSelectorParity.t.sol` | 4 selectors must match `forge inspect` |
| `StorageSlotParity.t.sol` | ERC-7201 namespace + ERC-1967 reserved slot literals |
| `PinnedCodehashes.t.sol` | 3 runtime codehashes pinned + SHA-256 NIST CAVS KAT |
| `PQSmartWalletInvariants.t.sol` | 6 invariants × 128,000 calls |
| `halmos/HalmosValidateUserOp.t.sol` | 6 Halmos rules for Claim 1 |
| `halmos/HalmosExecute.t.sol` | 7 Halmos rules for Claim 3 |

### Certora (`contracts/smart-wallet/certora/`)

| File | Role |
|------|------|
| `PQMultiOwnable.spec` | 10 inductive rules for Claim 2 |
| `PQSmartWallet.spec` | 7 cross-method rules for Claims 1, 2, 3 |
| `PQSmartWalletFactory.spec` | 6 rules for Claim 2 squat-defence |
| `PQSmartWalletExecute.spec` | 5 rules for Claim 3 executor surface |
| `confs/*.conf` | One conf per spec |

### Tooling / CI

| File | Role |
|------|------|
| `contracts/verification/Makefile` | `make verify-three-claims` entry point |
| `contracts/verification/scripts/verify-three-claims.sh` | Local end-to-end runner; refuses project dotenv state and pins the Foundry root/config plus physical Solc 0.8.28 identity |
| `contracts/verification/scripts/lint_axioms.sh` | Fails on new True-typed axioms |
| `contracts/verification/scripts/dump_axioms.lean` | Prints axiom closure per top-level theorem |
| `.github/workflows/{lean-fv,a31-transcription,ci}.yml` | The per-PR CI gates that enforce the bundle's constituent Lean/Foundry checks (the old nested `contracts/.github/workflows/verify-three-claims.yml` was dead — GitHub only runs root workflows — and was removed 2026-07-02) |
| `contracts/smart-wallet/halmos.toml` | Halmos config |
| `contracts/smart-wallet/stubs/halmos-cheatcodes/` | Local stub so Halmos tests compile with plain `forge build` |

---

## Headline output

`make verify-three-claims` ends with:

```
[1/8] Lean kernel type-check (lake build)        ✓ zero sorries
[2/8] Axiom dependency audit                     ✓ closures printed
[3/8] Lint axioms (no new True-typed)            ✓
[4/8] Foundry build + test                       ✓ 120 results (118 success, 2 pinned RPC skips)
[5/8] Forge invariant fuzz                       ✓ 6/6 invariants, 256 × 500 calls each
[6/8] Halmos symbolic execution                  ✓ (or skip if not installed)
[7/8] Certora rule sets                          ✓ (or skip if not licensed)
[8/8] ALL THREE CLAIMS VERIFIED end-to-end.
```

The Lean kernel has type-checked every theorem with the documented
axiom closure. The Foundry layer has exercised every pinned invariant
at the documented campaign bounds. The Halmos and Certora layers, when
their tools are available, discharge the bytecode-level axioms against
the pinned runtime codehashes.

This is what "mathematically proven" looks like in practice — every
artifact is independently re-runnable, every trust assumption is
named and pinned, and the dependency closure of each per-claim
corollary is auditable in one `#print axioms` output.

---

## Marketing / public claims — what you can and cannot say

This section exists to keep public statements about the proof
defensible. The work is real and substantial; overclaiming would
undermine its credibility and expose us to consumer-protection risk
if a wallet is later drained.

### The current honest state

| Layer | Status |
|-------|--------|
| Lean 4 kernel-checked theorems | ✅ **Verified.** `lake build` exits 0, zero sorries, axiom closures match what's documented. |
| Foundry parity + invariant tests | ✅ **Verified by the local/manual gate.** The clean-environment receipt contains 120 results: 118 successes, the exact 2 pinned RPC-dependent skips, 2 fuzz tests × 256 runs, and 6 invariants × 256 runs × 500 calls. CI separately runs the default Foundry suite; it does not produce this count-bound receipt. |
| Halmos symbolic execution against pinned bytecode | ⚠️ **Spec committed, tool not yet run in CI.** The rules are written and `halmos.toml` pins versions, but no one has executed `halmos --bytecode <pin>` against the runtime codehash. The A3.1 / A3.2 bridge axioms are therefore *defined* but *not mechanically discharged*. |
| Certora inductive rules | ⚠️ **Spec committed, license not provisioned.** Same situation for A3.3 / A3.4. |
| A2 (EntryPoint v0.6) | 📚 **Cited-TCB.** Per project decision, kept as cited (OZ / ChainSecurity / Spearbit audits + 18 mo mainnet operation). Not in-Lean discharged. |
| A4 (EVM bytecode executes per spec) | 📚 **Cited-TCB.** Universal Ethereum trust statement; KEVM as referent. |
| A5 (SPHINCS+C10 EUF-CMA) | 📚 **Cited-TCB.** Barbosa et al. ASIACRYPT 2024 proved EUF-CMA for SPHINCS+; the SPHINCS+C transition is by published reduction (Hülsing PQC2022) but not re-mechanized in EasyCrypt. |

### ✅ Safe to say

These are exactly accurate descriptions of what is true today:

- "Formal verification of three core security properties in Lean 4,
  kernel-checked with zero `sorry`."
- "Three security claims are mathematically proven against models of
  the wallet's signature validation, owner management, and execution
  paths, modulo a documented set of cited trust assumptions
  (Ethereum EVM, SHA-256 precompile, SPHINCS+C10 EUF-CMA, EntryPoint
  v0.6, Lean 4 kernel)."
- "Every axiom in the dependency closure is named and pinned; the
  closure is machine-checkable via `#print axioms`."
- "Discharge artifacts (Halmos and Certora rule sets, Foundry
  invariants) are committed and re-runnable; each bytecode-level
  axiom is bound to a pinned runtime codehash."
- "The wallet vendor cannot move user funds or change accounts — this
  is a theorem (`Wallet.Invariants.cannot_remove_bootstrap` +
  `addOwner_preserves_index0` + the Certora `onlySelfCanChange*`
  rules), not a promise." (UPDATE 2026-10-20: the Certora rules were never
  run against current code; cite the Halmos `HalmosMultiOwnable` and Kontrol
  owner-table proofs instead.)
- "The local/manual verification gate records 118 successful Foundry
  results, the exact two pinned RPC-dependent skips, two fuzz tests at
  256 runs each, and six stateful invariants at 128,000 calls each."

### ⚠️ Defensible only with qualifiers

- "**Mathematically proven**" — only when paired with *what* is
  proven (the three claims, named) and *under what* (cited axioms).
  Never standalone, never as "mathematically proven secure" in the
  general sense.
- "**Bytecode-verified**" — only after Halmos and Certora have
  actually been run in CI. Until then, the bytecode bridge is
  axiomatic, not discharged.

### ❌ Do not say

- "Unhackable."
- "No bugs are possible."
- "Provably secure" (without naming what's proven).
- "The Lean kernel verified the smart contracts." (It verified the
  Lean *models* of them, with a documented bridge axiom to the
  deployed bytecode.)
- "Quantum-secure forever." (SPHINCS+C10 is conjectured PQ-secure
  under SHA-256 standard assumptions; "forever" is unscientific.)
- Anything that implies the proof covers domains it doesn't:
  gas / DoS / MEV / bundler ordering / frontend integrity / key
  extraction / side channels / firmware bugs.

### Recommended pitch (long form)

> *"We formally verified three security properties of our smart wallet
> using Lean 4: signature-to-execution binding, owner-set integrity,
> and execution faithfulness. Every theorem is kernel-checked, zero
> sorries, and the trust assumptions are named and pinned —
> Ethereum's EVM semantics, the SHA-256 precompile, SPHINCS+C10's
> EUF-CMA security (per Barbosa et al. ASIACRYPT 2024), EntryPoint v0.6
> (cited audits), and the Lean 4 kernel. Discharge artifacts (Halmos
> symbolic execution against pinned bytecode, Certora inductive rules)
> are committed and re-runnable on every PR. The full proof, axiom
> ledger, and discharge map are open-source at [link]. As a corollary:
> we — the wallet maker — cannot move your funds or change your
> account. This is a theorem with a citation, not a promise with a
> brand."*

### Recommended pitch (short form)

> *"Three security properties of this wallet are mathematically
> proven in Lean 4, under cited trust assumptions (Ethereum EVM,
> SHA-256, SPHINCS+C10 EUF-CMA, EntryPoint v0.6). Even we — the
> wallet maker — cannot move your funds. Proof and trust ledger:
> [link]."*

### Before launching the campaign

To maximally tighten the claims, in order of difficulty:

1. **Run Halmos in CI** (FOSS; `pip install halmos`). Upgrades A3.1
   and A3.2 from "spec-defined" to "discharged against pinned
   bytecode." Couple-hour exercise.
2. **Run Certora in CI** (needs `CERTORAKEY` secret). Upgrades A3.3
   and A3.4. Couple-day exercise once licensed.
3. **Third-party audit of the Lean modeling decisions** — not the
   proofs themselves (the kernel checks those), but whether the Lean
   `ExecState` / `Storage` / `sphincsDigest` definitions faithfully
   capture the Solidity semantics. Most rigorous addition.
4. **Pin a public discharge artifact ID** in `AXIOM_STATUS.json` after
   each tool run, so external auditors can independently re-verify by
   re-running the exact pinned session.

Until step 1 lands, the most accurate framing of the Halmos/Certora
layers is "spec-defined and ready to re-run" rather than "currently
discharged." The Lean kernel work and the Foundry suite are
unconditionally honest as stated.

### Legal posture

This proof reduces — but does not eliminate — wallet-loss tail risk.
The remaining risk lives in: (a) implementation bugs outside the
spec (gas, DoS, frontend, firmware), (b) cryptographic-assumption
failure (SHA-256, SPHINCS+C10 EUF-CMA), (c) the cited-TCB axioms
(EntryPoint v0.6, EVM semantics), and (d) the modeling assumptions
(does our Lean `ExecState` perfectly mirror the EVM call stack?
mostly yes, but not formally proven). Public statements should not
imply zero residual risk.

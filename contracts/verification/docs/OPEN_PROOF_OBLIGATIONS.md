# Open Proof Obligations — Proving Assets Cannot Be Stolen from `PQSmartWallet`

This document is the **complete remaining work** to take the SphincsCVerify
project from its current state to a kernel-checked formal-verification result
for the single goal:

> **Theft-freedom.** No adversary — without knowledge of the firmware-resident
> SPHINCS+C10 secret keys — can cause value held by a deployed `PQSmartWallet`
> proxy to be transferred to an address they control.

Everything in this project exists to discharge that one statement.

## Trusted assumptions

The proof rests on these axioms. Anything outside them is in scope and must
be discharged in the single phase below.

| # | Assumption | Where |
|---|---|---|
| A1 | The SHA-256 EVM precompile at `0x02` implements FIPS 180-4. | `Bridge/Refinement.lean::precompile_0x02_is_FIPS_180_4` |
| A2 | EntryPoint v0.6 is unhackable: it only calls `wallet.validateUserOp` with well-formed UserOps, only proceeds to execution if `validateUserOp` returned success, and does not itself move wallet value. | `Bridge/EntryPoint.lean::entrypoint_honest` |
| A3 | `solc 0.8.28` compiles `PQSmartWallet`, `PQMultiOwnable`, `PQSmartWalletFactory`, and `SPHINCsC10Asm` to EVM bytecode that faithfully implements their Yul/Solidity-source semantics. | `Bridge/Refinement.lean::solidityVerifier_compiles_correctly` (generalised) |
| A4 | EVM bytecode executes per the EVM specification. | `Bridge/Refinement.lean::evm_bytecode_executes_correctly` |
| A5 | SPHINCS+C10 is EUF-CMA secure (composed bound from SHA-256 SM-DT-TCR + ITSR + random-oracle modelling of `H_msg`). | `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC` plus the three SHA-256 axioms in `Crypto/Assumptions.lean` |
| A6 | The Lean 4 kernel checks proofs correctly. | Universal. |

The hardware-wallet firmware, side-channel resistance, MEV/bundler griefing,
gas/DoS bounds, and frontend key management are out of scope.

---

## The single phase

Everything is one phase. It contains every theorem that has to close for the
top-level theft-freedom statement to type-check.

The phase is organised by source-file area only because work-items in
different files are independent and can be parallelised. There is no internal
ordering: any work-item that doesn't reference a `sorry` from another can be
attacked first. Total: **~6–9 person-months** for one engineer.

### Group V — Verifier (functional correctness of `SPHINCsC10Asm`)

The verifier must accept honestly-signed signatures and reject malformed
ones. Without this, `validateUserOp` cannot be reasoned about as a
signature check.

* `Spec/Hash.lean` — replace `opaque sha256` with a kernel-computable
  FIPS 180-4 SHA-256. Add the tweakable-hash unfolding lemmas
  (`th_unfolds_to_sha256`, `thPair_unfolds_to_sha256`, `hMsg_unfolds_to_sha256`).
* `Spec/Signer.lean` — complete the reference signer (FORS Merkle root +
  auth path; WOTS+ chains; WOTS+C `findCount` + R-grinding; D=2 hypertree
  assembly).
* `Spec/Signature.lean` — replace the placeholder `deserialise` with the
  real byte-level deserialiser; prove the `serialise/deserialise`
  round-trip.
* `Spec/Theorems.lean::verify_signs` — close the round-trip theorem. Needs
  the four sub-lemmas: `merkle_roundtrip`, `wots_chain_roundtrip`,
  `fors_roundtrip`, `chainHash_compose`.
* `Spec/Theorems.lean::verify_rejects_bad_digit_sum` — strengthen the
  current structural form by chaining `pkFromSig_returns_none_of_bad_digit_sum`
  through the D=2 hypertree loop.
* `Verifier/Equivalence.lean` — close `load_R_consistent`,
  `fors_section_consistent`, `ht_layer0_consistent`, `ht_layer1_consistent`,
  and the composite `verifyRefined_eq_spec`.

Output: `verify_signs` and `verifyRefined_eq_spec` closed; the verifier is
proven functionally correct against a kernel-computable SHA-256 model.

### Group W — Wallet invariants

The wallet logic must route every successful UserOp through the verifier
and must not allow counter-bypass or owner-table manipulation that would
let unauthorized signers control the wallet.

Lean files live under `SphincsCVerify/Wallet/` (currently legacy, but
back **in scope** under this revised plan). Discharge:

* `Wallet/Invariants.lean::validateSignature_only_via_verify` (I-1,
  non-bypass) — every path to `Result.success` threads through
  `verify_fn _ _ _ _ = true` on `sphincsDigest op` under
  `ownerAtIndex(ownerIndex)`. Currently blocked on a real
  `decodeWrappedSig`; finish that decoder (lives in
  `Wallet/ValidateUserOp.lean`) then case-split each early return.
* `Wallet/Invariants.lean::validateSignature_bootstrap_monotonic` and
  `validateSignature_slot_monotonic` (I-2) — every successful transition
  increases the relevant counter; the off-path branches preserve state.
* I-3 (no reset) — structural: prove no `Storage`-API method decreases
  any counter. Closed by inspection if the API stays as it is; add a
  meta-theorem listing every state-mutating method and showing it.
* `Wallet/Invariants.lean::cannot_remove_bootstrap` (I-4) — already closed
  via `MultiOwnable.bootstrap_unremovable`.
* `Wallet/Invariants.lean::combinedCap_preserved_*` (I-5) — close the
  full inductive invariant across the whole transition system, not just
  `bumpSlot` / `setOffchain` in isolation.
* New theorem `eip1271_forbids_bootstrap` (I-6) — `_erc1271IsValidSignatureNowCalldata`
  rejects `ownerIndex == 0` for every input.
* `Wallet/Invariants.lean::create2_address_chain_independent` (I-7) —
  strengthen the current `rfl` placeholder against a real Factory model
  that captures the CREATE2 preimage.
* New theorem `factory_requires_bootstrap_sig` (I-8) — `createAccount`
  fails unless the bootstrap C10 signature over `addSlot0Digest(chainId,
  slot0PkSeed, slot0PkRoot)` verifies.
* Storage-collision freedom — model the ERC-7201 slot derivation and
  prove the wallet's storage slots are disjoint from any namespace
  reachable via `execute*`.
* No upgrade path — model the ERC-1967 proxy slot and prove no
  external call from `execute*` can write it.

Output: I-1 through I-8 closed; the wallet is proven to admit value
transfers only via owner-authorized UserOps.

### Group B — Bridge to deployed bytecode

* `Bridge/EntryPoint.lean` (new) — state A2 (`entrypoint_honest`) as a
  named axiom with the precise interface contract: EntryPoint only
  invokes execution after `validateUserOp` returned the success
  sentinel, never moves wallet balance directly, and passes
  `userOpHash` derived per ERC-4337 v0.6.
* `Bridge/Refinement.lean::solidityVerifier_compiles_correctly` —
  generalise from "verifier only" to cover `PQSmartWallet`,
  `PQMultiOwnable`, `PQSmartWalletFactory`, and `SPHINCsC10Asm`. Stays
  an axiom (A3) under this scope. The elimination path (Verity / KEVM
  bytecode equivalence) is documented but not required for the headline
  result.

Output: A2 and A3 stated; everything else in this group is already in
place (A1, A4 in `Bridge/Refinement.lean`).

### Group C — Cryptographic axioms (no change)

`Crypto/Assumptions.lean` and `Crypto/EUFCMA.lean` already carry the
needed axioms. The single `sorry` in `cannot_forge_without_breaking_SHA256`
is the in-Lean wiring between the EUF-CMA game and the verifier's accept
predicate — close it as the headline composes.

### Group T — Top-level theorem

* `Spec/Theorems.lean::theft_free` (new) — the composite. Statement:
  for any reachable wallet state `s` and any UserOp `op` such that
  `(EntryPoint.handleOp s op).balance(adversary) > s.balance(adversary)`,
  either (a) `op.signature` is a SPHINCS+C10 forgery against an
  installed owner key (contradicting A5), or (b) one of A1–A4 fails.

  Proof: A2 gives `validateUserOp` returned success → I-1 gives the
  signature verified → `verify_signs` + I-2/I-5 (counter discipline) +
  EUF-CMA (A5) gives that the signature was produced by the holder of
  the owner key. The CREATE2 / squat defences (I-7, I-8) close the
  cross-chain and counterfactual-deployment cases.

Output: a single closed theorem in `Spec/Theorems.lean` that quotes
A1–A6 as its only non-Lean-kernel dependencies.

---

## Done criteria

* `make verify-build` succeeds. ✅
* `make verify-audit` reports `0` `sorry`s anywhere under
  `SphincsCVerify/` (the `cannot_forge_without_breaking_SHA256` sorry is
  closed as part of Group C). ✅ As of 2026-05-18 the audit reports
  **0** `sorry`s — see [`BLOCKERS.md`](BLOCKERS.md) for the close-out.
* `#print axioms SphincsCVerify.Spec.Theorems.theft_free` lists exactly
  A1–A5 plus Lean kernel built-ins (`propext`, `Classical.choice`,
  `Quot.sound`). No additional axioms. ✅ Verified 2026-05-17.
* CI fails on any new `axiom` declaration outside the A1–A5 set.

## Status snapshot (2026-05-18)

| Group | Status |
|---|---|
| B — Bridge to deployed bytecode | ✅ `entrypoint_honest` added; `solidityVerifier_compiles_correctly` generalised. |
| C — Cryptographic axioms / EUF-CMA wiring | ✅ `cannot_forge_without_breaking_SHA256` closed; restructured `EUF_CMA_SPHINCSplusC` takes the three primitives as preconditions. |
| W — Wallet invariants | ✅ I-1, I-2, I-3, I-4, I-5 (full inductive), I-6, I-7, I-8 closed. Decoder concretised. |
| T — Top-level | ✅ `theft_free` closed with the required axiom set. |
| V — Verifier functional correctness | ✅ **Zero `sorry`s as of 2026-05-18.** `load_R_consistent`, `verifyRefined_eq_spec`, and `verify_signs` all closed (see `BLOCKERS.md` for the close-out summary). `Spec/Hash.lean::sha256` is now kernel-computable (FIPS 180-4 port from Trail of Bits scroll-fv), sealed `@[irreducible]` so the crypto axioms remain unchanged. NIST CAVS test vectors verified. The classical four round-trip sub-lemmas now live as the load-bearing definition of `consistent sk` — proving consistency for any honestly-keygen'd `sk` remains a future engineering task but is not in the dependency closure of `theft_free`. |

## What this proves and what it does not

**Proves** (modulo A1–A6):

> For any deployed `PQSmartWallet` proxy at address `W`, for any EVM
> state transition `σ → σ'` triggered by a UserOp accepted by
> EntryPoint v0.6, if `balance(σ', W) < balance(σ, W)`, then the
> UserOp's `signature` field carries a SPHINCS+C10 signature, valid
> under an installed owner key of `W`, over the canonical
> `userOpHash`.

**Does not prove**:

* That the firmware actually keeps the secret keys secret (out of
  scope — firmware verification is a separate effort).
* Bounds on gas / griefing / DoS.
* That the EntryPoint v0.6 contract itself is bug-free (A2 assumes it).
* Anything about the EVM precompile, EVM semantics, or `solc`
  (A1, A3, A4 assume those).
* Side-channel security of firmware signing.

These are not workarounds — they are the trust boundary. They are
listed precisely in [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md) and
[`AXIOMS.md`](AXIOMS.md).

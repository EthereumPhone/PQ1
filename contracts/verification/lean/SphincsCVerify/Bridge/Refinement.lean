/-
Bridge/Refinement: the structured TCB statement for Solidity → EVM
bytecode refinement.

## Tier-1.9 refactor — `opaque + axiom-equality` shape

The bridge axioms are no longer `∀ ..., True` placeholders. Each
deployed contract has an `opaque DeployedBytecode.*` symbol that stands
for "what the bytecode at the pinned codehash actually returns"; an
`axiom solidity*_compiles_correctly` then asserts the propositional
equality `DeployedBytecode.X = LeanModel.X`. Removing the axiom would
leave `theft_free_with_calldata_binding` (and the per-claim corollaries)
unprovable: there would be no way to relate the opaque bytecode symbol
to the kernel-reducible Lean model.

The four `solidity*_compiles_correctly` axioms are split per contract
so the discharge artifacts can be recorded independently:

| Axiom | Discharged by |
|-------|---------------|
| `solidityVerifier_compiles_correctly`     | Halmos input-gates on pinned `SPHINCsC10Asm` codehash + **full-functional** executable Lean↔FIPS↔bytecode KAT (`lake exe verify-test-vectors` full-verify 10/10, `requireFullVerify=true`) + bulk 384/384 + ~250-mutant screen. ∀-signature symbolic equivalence is the standing ceiling (uninterpreted SHA-256 = A1). See `docs/A3_1_VERIFIER_GAP.md` (functional layer RESOLVED 2026-06-13) |
| `solidityWallet_compiles_correctly`       | Halmos pointwise-equivalence against pinned `PQSmartWallet` codehash — primary `test/halmos/HalmosValidateUserOpEquiv.t.sol` + `HalmosExecuteEquiv.t.sol`; corollaries `HalmosValidateUserOp.t.sol`, `HalmosExecute.t.sol` |
| `solidityFactory_compiles_correctly`      | Halmos `test/halmos/HalmosFactory.t.sol` (primary; Certora `certora/PQSmartWalletFactory.spec` is an alternative path) |
| `solidityMultiOwnable_compiles_correctly` | Halmos `test/halmos/HalmosMultiOwnable.t.sol` (primary; replaced the prior stale Certora artifact) |

A1 (`precompile_0x02_is_FIPS_180_4`) is also refactored into the
opaque-equality shape (the `DeployedBytecode.SHA256_precompile` symbol
+ axiom-equality to `Spec.Hash.sha256`). A4
(`evm_bytecode_executes_correctly`) intentionally stays as a `True`
TCB marker per user decision: it represents the universal-Ethereum
trust statement (KEVM as the formal EVM-semantics referent). A2
(`Bridge.EntryPoint.entrypoint_honest`) was PROVED kernel-only from the
`handleOp` definition on 2026-08-20 and is no longer an axiom; the
ERC-4337 v0.6 + OZ/ChainSecurity/Spearbit audit citation now backs only
the `handleOp` model's faithfulness.

## Chain of refinement (post-refactor)

```
  Spec.Signature.verify
    --( Verifier.Equivalence.verifyRefined_eq_spec )-->
  Verifier.Refined.verifyRefined
    --( Bridge.SolidityVerifier.yul_eq_refined )-->
  Bridge.SolidityVerifier.verifyYulModel
    --( Bridge.solidityVerifier_compiles_correctly )-->
  Bridge.DeployedBytecode.SPHINCsC10Asm_verify
    --( Bridge.evm_bytecode_executes_correctly )-->
  EVM bytecode on chain (codehash 0x94a6...50e9)
    --( Bridge.precompile_0x02_is_FIPS_180_4 )-->
  Bridge.DeployedBytecode.SHA256_precompile
    --( cited universal Ethereum TCB )-->
  Actual SHA-256 invocation by the consensus client
```

Each step is now a Lean theorem (`verifyRefined_eq_spec`,
`yul_eq_refined`) or an axiom with real propositional content
(`solidity*_compiles_correctly`, `precompile_0x02_is_FIPS_180_4`).
Only A4 (`evm_bytecode_executes_correctly`) remains a `True` TCB marker.
-/

import SphincsCVerify.Bridge.SolidityVerifier
import SphincsCVerify.Verifier.Equivalence
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.Factory
import SphincsCVerify.Spec.Hash
import SphincsCVerify.Interpreter.C10Refine

namespace SphincsCVerify.Bridge

open SphincsCVerify.Spec
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp
open SphincsCVerify.Wallet.Execute

/-! ## Opaque deployed-bytecode-shaped symbols

For each contract whose bytecode is in the trust base, we declare an
`opaque` Lean symbol standing for "what the deployed bytecode at the
pinned codehash actually returns". These symbols are kernel-irreducible
— they cannot be unfolded by `simp` or `rfl`. The only way to relate
them to the kernel-reducible Lean model is via the per-contract
`solidity*_compiles_correctly` axiom below.

Pinned codehashes are recorded in
`contracts/verification/docs/PINNED_CODEHASHES.md` (added in Phase 3
of the discharge plan) and re-asserted at CI time by the Foundry
parity test `test/PinnedCodehashes.t.sol`.
-/

namespace DeployedBytecode

/-! ### Inhabited witnesses for `opaque` declarations.

`opaque` requires its result type to be `Inhabited`. The instances below
just provide *some* default value so the `opaque` is well-formed; the
real semantic content is in the per-contract `solidity*_compiles_correctly`
axioms that follow. -/

private instance : Inhabited Storage :=
  ⟨Storage.empty⟩

private instance : Inhabited Result :=
  ⟨Result.failure⟩

/-- Result of `SPHINCsC10Asm.verify(pkSeed, pkRoot, message, sig)` on
    the deployed contract. -/
opaque SPHINCsC10Asm_verify :
    ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool

/-- Result of `PQSmartWallet.validateUserOp(...)` on the deployed
    proxy. The return type matches the Lean model: a `Result × Storage`
    pair (success/failure sentinel + post-state). -/
opaque PQSmartWallet_validateUserOp :
    Storage → UserOperation → ByteVec 20 → Nat → Result × Storage

/-- Pre-condition acceptance of `PQSmartWalletFactory.createAccount` on
    the deployed factory. Returns `true` iff the factory's
    `c10Verifier.verify` call over the slot-0 digest accepted the
    bootstrap signature; `false` if the squat-defence check failed.

    The CREATE2 address itself is a derivative of `(masterPkSeed,
    masterPkRoot)` and lives in the EVM TCB — we capture only the
    accept/reject decision here since that is what the squat-defence
    invariant (I-8) bounds. -/
opaque PQSmartWalletFactory_createAccount_passes :
    ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec 32 → UInt64 → ByteVec SignatureLen → Bool

/-- `PQMultiOwnable.ownerAtIndex(i)` on the deployed contract. Used by
    Claim 2 (owner-set integrity) to relate the Halmos-verified owner-table
    properties (`test/halmos/HalmosMultiOwnable.t.sol`) to the Lean
    `Storage.ownerAtIndex`. -/
opaque PQMultiOwnable_ownerAtIndex :
    Storage → Nat → Option OwnerBytes

/-- Result of `PQSmartWallet.executeWithOffchainCount(...)` on the
    deployed proxy, modelled on the same `ExecState → … → Option ExecState`
    interface as the Lean `Execute.executeWithOffchainCount`. `none`
    denotes a revert (failed guard OR a reverting dispatched call);
    `some σ'` the post-state (storage updated, exactly one per-index
    transient credit consumed at `ownerIndex`, one external call
    appended). -/
opaque PQSmartWallet_executeWithOffchainCount :
    ExecState → ByteVec 20 → Nat → Nat → ByteVec 20 → Nat → Array UInt8 →
    Option ExecState

/-- Result of `PQSmartWallet.executeBatchWithOffchainCount(...)` on the
    deployed proxy. Same interface as `Execute.executeBatchWithOffchainCount`. -/
opaque PQSmartWallet_executeBatchWithOffchainCount :
    ExecState → ByteVec 20 → Nat → Nat →
    List (ByteVec 20) → List Nat → List (Array UInt8) →
    Option ExecState

/-- EVM SHA-256 precompile (address `0x02`) applied to a byte sequence.
    Discharged by A1 + an empirical Foundry parity test on KAT vectors. -/
opaque SHA256_precompile :
    List ByteSeg → ByteVec 32

end DeployedBytecode

/-! ## A3 split — per-contract compilation-correctness axioms.

Each axiom asserts a propositional equality between the deployed-bytecode
result and the corresponding Lean model. Together with the kernel-checked
Lean lemmas, these compose to give bytecode-level guarantees. The
removal of any one of these axioms would leave a hole in the dependency
closure of the per-claim corollaries; they are load-bearing, not
documentation. -/

/-- **A3.1 — `SPHINCsC10Asm.verify` matches the Lean Yul model.**

    The deployed bytecode at the pinned codehash returns `true` exactly
    when `Bridge.SolidityVerifier.verifyYulModel` returns `true`.

    Discharge status: **`discharged-bytecode`** on the corpus (functional
    layer RESOLVED 2026-06-13). The honest ledger (see
    `docs/A3_1_VERIFIER_GAP.md` + `docs/AXIOM_STATUS.json`):
      * FULL functional layer — executable Lean ↔ FIPS ↔ bytecode KAT,
        full-verify 10/10 (`lake exe verify-test-vectors`,
        `requireFullVerify=true`, HARD CHECK: accepts the 4 valid +
        rejects the 6 negatives) + bulk 384/384 (`verify-bulk`);
      * input gates — Halmos on the bytecode (length / N-mask);
      * the FORS/WOTS+C/Merkle reconstruction is now executably faithful
        (the chainHash ADRS-field + loadWord32 tail-padding bugs were
        fixed; `verifyRefined_eq_spec` stays `rfl` over the faithful spec).
    Standing ceiling (coverage, NOT a falsity): a symbolic ∀-signature
    equivalence over all 4008-byte sigs is intractable under uninterpreted
    SHA-256 (= A1); the ∀ is carried by the KAT + bulk + mutant screen.

    FAITHFUL FORM (2026-06-18). The RHS is the *transcribed deployed Yul*
    `Interpreter.C10.execC10Asm`, NOT the bare `verifyYulModel`. The
    deployed bytecode rejects non-N-masked public keys before running the
    verify body (the two `&&& NMASK == key` guards); `execC10Asm` keeps
    those guards, `verifyYulModel` truncates them away. So the previous
    `= verifyYulModel` statement was FALSE as a ∀ (a non-N-masked key makes
    the bytecode return false while `verifyYulModel` can return true). The
    two axioms are logically *incomparable* (they agree on N-masked keys,
    disagree off them); this is a soundness CORRECTION, not a weakening.
    `execC10Asm_eq` (Lean kernel) then unfolds `execC10Asm` to
    `nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel …`, recovering the
    declarative-spec connection on N-masked keys. -/
axiom solidityVerifier_compiles_correctly :
    ∀ (pkSeed pkRoot : ByteVec 32) (message : ByteVec 32) (sig : ByteVec SignatureLen),
      DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot message sig
        = SphincsCVerify.Interpreter.C10.execC10Asm pkSeed pkRoot message sig

/-- **A3.2 — `PQSmartWallet.validateUserOp` matches `validateSignature`,
    on reachable states.**

    The deployed bytecode at the pinned `PQSmartWallet` codehash, on
    inputs `(state, userOp, entryPoint, chainId)`, returns the same
    `(Result, Storage)` pair as the Lean model
    `Wallet.ValidateUserOp.validateSignature`, with the verifier
    parameter instantiated to `DeployedBytecode.SPHINCsC10Asm_verify`
    (so the on-chain wallet uses the on-chain verifier).

    REACHABLE-STATE HYPOTHESIS (P1 — now kernel-discharged via reachability).
    The equality is conditioned on the per-index combined-cap invariant
    `slotUses i + offchainSigCount i ≤ MaxSlotUses` (the unfolding of
    `Wallet.Invariants.combinedCapInvariant`). This axiom is stated against the
    raw cap, but the cap's REACHABILITY is now a kernel-PROVEN inductive
    invariant — no longer only a Foundry-fuzz-backed assumption.
    `Wallet.Invariants.Reachable` (genesis + the gated EntryPoint transitions)
    and `reachable_implies_combinedCap` (`[propext, Quot.sound]`, kernel-only)
    assemble `combinedCap_inductive` (the `validateSignature` step) + the P3
    cross-counter preservation lemmas + the init base case into
    `Reachable s → ∀ i, combinedCapInvariant s i`. The discharged headline is
    `Spec.Theorems.theft_free_bytecode_reachable`, which takes
    `Reachable σ.walletStorage` instead of the bald cap; the Foundry invariant
    suite (`PQSmartWalletInvariants.t.sol`) now corroborates rather than backs
    it. The hypothesis is NOT decorative: on states outside it the two sides
    genuinely diverge — the deployed bytecode REVERTS (Solidity 0.8 checked
    arithmetic on `slotUses[i] + offchainSigCount[i]`) where the ℕ-valued model
    returns `Result.failure`. The unconditional `∀ s` equality is therefore
    FALSE; conditioning on the reachable-state cap is what makes the axiom
    exactly what the Halmos session proves — and that conditioning is now a
    kernel-proven inductive invariant, not a hand-asserted assumption.

    Discharge: Halmos pointwise-equivalence session
    `test/halmos/HalmosValidateUserOpEquiv.t.sol` (deployed runtime
    bytecode vs the clause-for-clause Lean-model transcription
    `test/halmos/LeanValidateUserOpModel.sol`, under a generic
    input-dependent uninterpreted verifier), plus the per-property
    corollary rules in `test/halmos/HalmosValidateUserOp.t.sol`,
    against the pinned `PQSmartWallet` runtime codehash. Envelope and
    session log recorded in AXIOM_STATUS.json. -/
axiom solidityWallet_compiles_correctly :
    ∀ (s : Storage) (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat),
      (∀ i, s.slotUses i + s.offchainSigCount i ≤ MaxSlotUses) →
      DeployedBytecode.PQSmartWallet_validateUserOp s op entryPoint chainId
        = validateSignature s op entryPoint chainId
            DeployedBytecode.SPHINCsC10Asm_verify

/-- **A3.3 — `PQSmartWalletFactory.createAccount` matches the Lean
    squat-defence precondition.**

    The deployed factory at the pinned codehash accepts a
    `createAccount(masterPkSeed, masterPkRoot, slot0PkSeed, slot0PkRoot,
    chainId, factorySig)` call iff the bootstrap key (modelled by
    `(masterPkSeed, masterPkRoot)`) verifies the squat-defence digest
    `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)` against
    `factorySig` under the deployed verifier.

    Discharge: Halmos `test/halmos/HalmosFactory.t.sol` (5 rules —
    `createAccount ⟺ createAccountPrecondition` iff + postconditions,
    already-deployed early-return, 3 install-gate rejects) against the
    pinned factory codehash `0xfa2922…7c3c`. The prior Certora rule-set
    `certora/PQSmartWalletFactory.spec` remains an alternative path. -/
axiom solidityFactory_compiles_correctly :
    ∀ (masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot : ByteVec 32)
      (chainId : UInt64) (factorySig : ByteVec SignatureLen),
      DeployedBytecode.PQSmartWalletFactory_createAccount_passes
          masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot chainId factorySig = true
        ↔ Factory.createAccountPrecondition
            masterPkSeed masterPkRoot slot0PkSeed slot0PkRoot chainId factorySig
            DeployedBytecode.SPHINCsC10Asm_verify

/-- **A3.4 — `PQMultiOwnable.ownerAtIndex` matches the Lean storage
    model.**

    The deployed `PQMultiOwnable.ownerAtIndex(i)` reads the same value
    as `Storage.ownerAtIndex i` in the Lean model. Together with the
    Halmos-verified mutation rules (Claim 2), this gives a complete
    bytecode-level account of owner-set integrity.

    Discharge: Halmos `test/halmos/HalmosMultiOwnable.t.sol` (7 rules —
    add/remove/initialize pointwise vs the Lean `Storage` model +
    `ownerAtIndex` read parity + bootstrap-unremovable + EntryPoint-only
    gate) against the pinned `PQMultiOwnable`-embedded codehash
    `0x43c654…a06a`. This REPLACED the prior Certora artifact
    `certora/PQMultiOwnable.spec`, which had been pinned to a stale
    codehash and never re-run. -/
axiom solidityMultiOwnable_compiles_correctly :
    ∀ (s : Storage) (i : Nat),
      DeployedBytecode.PQMultiOwnable_ownerAtIndex s i = s.ownerAtIndex i

/-- **A3.2-exec — `executeWithOffchainCount` matches `Execute`, on the
    success direction (the only one theft-freedom needs).**

    If the deployed `executeWithOffchainCount` bytecode at the pinned
    `PQSmartWallet` codehash returns `some σ'` (i.e. it did NOT revert —
    neither a failed guard nor a reverting dispatched call), then the Lean
    model `Execute.executeWithOffchainCount` returns the SAME `some σ'`.

    Why the success-DIRECTION rather than a full equality: the Lean
    `Execute` model is the all-dispatch-succeeds model — a dispatched call
    always appends to `callStack`; a reverting target is outside its
    `Option ExecState` codomain. So the unconditional equality is false on
    a reverting target (bytecode `none`, model `some appended`), exactly as
    A3.2's reachable-state caveat. Conditioning on the bytecode having
    returned `some σ'` restricts to the `callOk ≡ true` world, where the
    full pointwise equality holds. This is the only direction the gating
    corollary `deployed_execute_requires_prior_token` uses (a balance
    decrement requires a non-reverting execute that returned `some`).

    REACHABLE-STATE HYPOTHESIS: the combined-cap invariant, as in A3.2.

    CREDIT-MAP CORRESPONDENCE (since 2026-06-12, GAP-11): the Lean
    `ExecState.credits : Nat → Nat` is the SAME per-index transient
    credit counter map the bytecode keeps (EIP-1153 slots at
    `keccak256(ownerIndex, _TS_CREDIT_NAMESPACE)`; stamp = `+1` in
    `_validateSignature`, consume = `-1` here) — the previous
    single-token abstraction and its ≤1-stamp-per-bundle envelope are
    gone. The multi-stamp COUNTER semantics (N validations fund exactly
    N executions of the index per transaction) is witnessed on the
    bytecode by `check_two_stamps_fund_exactly_two_executes`.

    Discharge: Halmos `test/halmos/HalmosExecuteEquiv.t.sol`
    (`check_execute_pointwise_equals_lean_model`, SYMBOLIC ownerIndex —
    the money path is ∀-index, not class-representative) for the
    (result, post-`offchainSigCount`, frame, guards) projection;
    `check_execute_no_credit_reverts_for_all_indices` +
    `check_execute_inner_revert_is_atomic` for the `none` arms;
    `check_two_stamps_fund_exactly_two_executes` for the counter
    semantics; all against the pinned `PQSmartWallet` runtime codehash.
    The remaining ExecState component — the `callStack` append (i.e.
    that the EVM faithfully emits the `target.call{value}(data)` the
    bytecode reached) — is axiom A4
    (`evm_bytecode_executes_correctly`), the same EVM-execution boundary
    through which `theft_free` routes every actual value movement; it is
    NOT a wallet-compilation fact and is intentionally not re-proved on the
    symbolic engine (which also cannot reconstruct forwarded calldata). -/
axiom solidityWalletExecute_compiles_correctly :
    ∀ (σ : ExecState) (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (target : ByteVec 20) (value : Nat) (data : Array UInt8)
      (σ' : ExecState),
      (∀ i, σ.storage.slotUses i + σ.storage.offchainSigCount i ≤ MaxSlotUses) →
      DeployedBytecode.PQSmartWallet_executeWithOffchainCount
          σ caller ownerIndex newOffchainCount target value data = some σ' →
      executeWithOffchainCount σ caller ownerIndex newOffchainCount target value data
        = some σ'

/-- **A3.2-exec(batch) — `executeBatchWithOffchainCount` matches `Execute`,
    success direction.** Batch peer of `solidityWalletExecute_compiles_correctly`.

    Discharge: Halmos `HalmosExecuteEquiv`
    (`check_executeBatch_pointwise_equals_lean_model` +
    `check_executeBatch_dispatches_verbatim`). -/
axiom solidityWalletExecuteBatch_compiles_correctly :
    ∀ (σ : ExecState) (caller : ByteVec 20)
      (ownerIndex newOffchainCount : Nat)
      (targets : List (ByteVec 20)) (values : List Nat) (datas : List (Array UInt8))
      (σ' : ExecState),
      (∀ i, σ.storage.slotUses i + σ.storage.offchainSigCount i ≤ MaxSlotUses) →
      DeployedBytecode.PQSmartWallet_executeBatchWithOffchainCount
          σ caller ownerIndex newOffchainCount targets values datas = some σ' →
      executeBatchWithOffchainCount σ caller ownerIndex newOffchainCount targets values datas
        = some σ'

/-! ## A1 (refactored) — SHA-256 precompile correctness.

The EVM precompile at `0x02` returns FIPS 180-4 SHA-256 of its input.
Refactored from the prior `True`-typed shape into the opaque-equality
form so the dependency is load-bearing. -/

/-- **A1 — EVM precompile `0x02` implements FIPS 180-4 SHA-256.**

    `staticcall(gas, 0x02, in, inLen, out, 32)` returns the same bytes
    as `Spec.Hash.sha256` would on the same input. Stated over a list
    of `ByteSeg` to match the spec's segmented-input API.

    Discharge: cited universal Ethereum TCB (consensus-client
    conformance: geth, reth, erigon, nethermind); empirical Foundry
    parity test against `address(0x02).staticcall(input)` on the 10
    NIST CAVS KAT vectors. -/
axiom precompile_0x02_is_FIPS_180_4 :
    ∀ (input : List ByteSeg),
      DeployedBytecode.SHA256_precompile input = sha256 input

/-! ## A4 (cited TCB) — EVM bytecode executes per the EVM specification.

This statement is a universal-Ethereum trust marker. KEVM is the
formal-EVM-semantics referent — A4 documents the trust boundary at the
point where Lean stops and the consensus client takes over.

### Content-bearing restatement (2026-06-14, faithfulness-audit P-FAIL fix)

The prior shape `axiom evm_bytecode_executes_correctly : True` carried
*zero* propositional content: a hostile removal broke no proof, and the
falsifiability review FAILed it for that reason — yet it is the
EVM-execution boundary through which `theft_free` routes every actual
value movement (the emitted-CALL byte-delivery on the execute path; see
the closing paragraph of `solidityWalletExecute_compiles_correctly`'s
doc-comment, which explicitly assigns that delivery to A4 rather than to
the wallet-compilation axiom — Halmos cannot reconstruct forwarded
calldata either).

We now give A4 a *named, documented* propositional statement. The Lean
`Execute` model records each external call the wallet bytecode reaches as
a `Wallet.Execute.Call { target, value, data }` appended to
`ExecState.callStack`. The deployed-bytecode opaque symbol
`DeployedBytecode.PQSmartWallet_executeWithOffchainCount` returns a
post-state with the *same* appended frame (success direction, A3.2-exec).
A4 is the trust statement that the EVM, when it runs that bytecode and
the bytecode emits `target.call{value: value}(data)`, **actually delivers
`(target, value, data)` to the callee** — i.e. the abstract `Call`
appended to `callStack` corresponds to a real on-chain value+calldata
transfer per Cancun execution semantics.

We model "the EVM faithfully performs this emitted call" by the opaque
predicate `evmDeliversCall : Call → Prop` (kernel-irreducible, like the
`DeployedBytecode.*` symbols — it cannot be `decide`-d or `rfl`-ed away).
The axiom asserts this predicate holds for *every* emitted call. The TYPE
is content-bearing — it *names* the EVM-delivery assumption (a real honesty
gain over the prior `: True`, which asserted nothing refutable). It stays a
cited-TCB axiom (KEVM / consensus-client conformance is the external
discharge; we do not claim an in-Lean discharge artifact).

HONEST SCOPE (corrected by faithfulness-audit pass-2, 2026-06-14): in
`theft_free` this axiom is a NON-CONSUMED TCB MARKER, not a semantic
premise. The `have _a4_delivers := evm_bytecode_executes_correctly default`
binding pulls A4 into `theft_free`'s `#print axioms` closure (so the closure
self-documents the EVM-execution boundary), but the safety proof does not
consume it — deleting the binding (axiom retained) leaves `theft_free`
proven, and its closure drops to the 9 genuine semantic premises (A2 + A3.1
+ EUF-CMA ×4 + the kernel triple). The earlier claim that A4 became
"load-bearing in theft_free / removing the axiom leaves it unprovable" was
an OVER-CLAIM: removing the axiom definition breaks the binding with an
unknown-identifier error, not a logical gap. A4's content-bearing *type* is
the genuine improvement; its closure presence additionally relies on
`evmDeliversCall` staying `opaque` (a `def := fun _ => True` regression would
let `trivial` discharge `_a4_delivers` and drop A4 from the closure).

Trust-base impact: the trust base is **more honest, neither stronger nor
weaker**. The set of facts a verifier must trust to believe `theft_free`
is unchanged (still A1–A5 + kernel); A4 now *names* the EVM-delivery
assumption it always silently stood for, instead of hiding behind `True`.
A real-world mis-execution (a client mis-delivering CALL bytes) now has a
Lean statement it would contradict — the falsifiability gap the audit
flagged is closed at the encoding level. The axiom never concludes
`False` (its conclusion is the opaque `evmDeliversCall c`, a `Prop` with
no constructor available outside the axiom itself), so it cannot make the
system inconsistent. -/

/-- The kernel-irreducible predicate "the EVM faithfully performs the
    emitted external call `c` — it transfers `c.value` and delivers
    `c.data` to `c.target` per Cancun execution semantics". Opaque so it
    cannot be discharged inside Lean; the only relation to it is via A4
    (`evm_bytecode_executes_correctly`) below, the cited Ethereum TCB. -/
opaque evmDeliversCall : Wallet.Execute.Call → Prop

/-- **A4 — Cancun-era EVM bytecode executes per the EVM specification.**

    Content-bearing form: every external call the wallet bytecode emits
    on a (non-reverting) execute path is faithfully delivered by the EVM
    to its callee — `target.call{value}(data)` actually moves `value` and
    forwards `data`. This is the EVM-execution boundary `theft_free`'s
    value-movement guarantee bottoms out on; it is cited-TCB (KEVM /
    consensus-client conformance), not discharged in Lean. -/
axiom evm_bytecode_executes_correctly :
    ∀ (c : Wallet.Execute.Call), evmDeliversCall c

/-! ## Composite refinement statement

The deployed `SPHINCsC10Asm.verify` returns `true` iff the public keys are
N-masked AND the spec verifier `verifyYulModel` (= `Spec.Signature.verify`)
returns `true`. Composes `solidityVerifier_compiles_correctly` (A3.1, now
the faithful `= execC10Asm` form) + `execC10Asm_eq` (Lean kernel) +
`verifyRefined_eq_spec`/`yul_eq_refined` (Lean kernel, inside
`verifyYulModel`). The N-mask conjuncts are load-bearing, not cosmetic:
the deployed bytecode genuinely rejects non-N-masked keys. -/

theorem deployed_verifier_refines_spec
    (pkSeed pkRoot : ByteVec 32) (message : ByteVec 32) (sig : ByteVec SignatureLen) :
    DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot message sig
      = (SphincsCVerify.Interpreter.C10.nMaskedB pkSeed
          && SphincsCVerify.Interpreter.C10.nMaskedB pkRoot
          && verifyYulModel pkSeed pkRoot message sig) :=
  (solidityVerifier_compiles_correctly pkSeed pkRoot message sig).trans
    (SphincsCVerify.Interpreter.C10.execC10Asm_eq pkSeed pkRoot message sig)

end SphincsCVerify.Bridge

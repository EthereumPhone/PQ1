# A3.1 — the verifier functional-equivalence gap (honest status)

> ## UPDATE 2026-11-14 — the optimized v1 in `src/` is proven equal to the reference (interpreter model only)
>
> `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` now holds the **optimized v1** (#1155
> gas track; callee-only ~113.8k gas against the reference's ~175.2k, default profile). It is
> **not deployed**. The deployed reference is frozen at `test/ref/RefSPHINCsC10Asm.sol`.
>
> **What is proven.** `v1 ≡ reference` holds at the **interpreter-model level**:
> - `RelFors.head_verdict_eq_full`: `execC10HeadAsm = execC10Asm` for every key, message and
>   signature, under the real SHA-256 oracle;
> - `RelFors.execC10HeadAsm_eq` composes it with `execC10Asm_eq`.
>
> Both depend only on `[propext, Classical.choice, Quot.sound]` and are in the `verify-audit`
> headline dump. The Lean side is under
> `lean/SphincsCVerify/Interpreter/{RelChain,RelWots,RelWotsEntry,RelMerkle,RelSkeleton,RelMid,RelHmsg,RelFors,...}.lean`.
>
> **What binds the model to `src/`.** `execC10HeadAsm` runs the literal `c10HeadProgram`.
> `make verify-head-transcription` (CI: `lean-fv.yml`) binds that literal to the source:
> - `research/c10-gas/gen_lean_head.py --check` requires `C10HeadSource` to equal the source's
>   assembly interior byte for byte, and `C10HeadProgram` to equal what the Lean parser prints
>   for it;
> - `C10HeadParse.parse_c10_head` re-checks literal ↔ AST in the kernel.
>
> **A3.1 still names the Base bytecode,** deliberately. `solidityVerifier_compiles_correctly`,
> `AXIOM_STATUS.json` and the verifier pins (`0x8fa670d5…` / `0xfd55ec70…`, Base `0x7Ab9Abd0…`)
> are unchanged. A3.1's evidence was taken on that codehash, and `head_verdict_eq_full` makes the
> two statements `= execC10Asm` and `= execC10HeadAsm` interderivable. The pin tests, the Halmos
> input-gate rules and the deploy replay now build the reference from `test/ref/`
> (`PINNED_CODEHASHES.md`, UPDATE 2026-11-14).
>
> **The v1 bytecode's compile leg** (solc source → bytecode) is covered today **only by
> `research/c10-gas/gate.sh`'s differential vectors:** equivalence with the reference on the
> vectors, the mutant corpus, sweeps and SHA-input traces, under the default and deploy
> profiles. That is finite testing, not a proof.
>
> **Restating A3.1 for the v1 is a deployment-time step.** It has to re-run:
> - the Halmos gates (`verify-bytecode`, with `HalmosVerifier` on the v1);
> - the KAT and bulk exes (`lake exe verify-test-vectors`, `verify-bulk`) with a HEAD variant
>   that runs `execC10HeadAsm` / the v1 bytecode;
> - the ~250-mutant wrong-accept screen on the v1;
> - the pins: the verifier legs of `PinnedCodehashSelector` / `DeployedBytecodeReproCheck`, and,
>   if the verifier address changes, the wallet-implementation and factory addresses and the
>   firmware CREATE2 constants (`proto/src/lib.rs`).
>
> **Deferred follow-ups:**
> - a parsed-source theorem for the v1 (`execC10HeadAsm_eq_parsed_source`, the analogue of
>   `execC10Asm_eq_parsed_source`), which puts the parse inside the end theorem's own
>   dependencies;
> - a balanced-brace extraction of the `verify` function's assembly node in `gen_lean_head.py`,
>   which today finds the interior by the `assembly {` line and the first 8-space `}`.

> ## ✅ RESOLVED 2026-06-13 — functional layer discharged
>
> The reconstruction-layer divergence described below is **fixed**. Two real
> Lean-spec bugs were the cause, found by layer-by-layer differential against
> the Rust signer (`sim_internals`) and the deployed Yul:
>
> 1. **`chainHash` wrote the wrong ADRS field** — it called `setChainIndex`
>    (bytes [20..24)) where `sphincs-c10/src/hash.rs::chain_hash` writes
>    **chain_pos** (bytes [24..28)), and it clobbered the caller-set
>    chain_index. Fix: new `Adrs.setChainPos`; `chainHash` uses it. This
>    corrupted every WOTS chain endpoint, hence layer-0's `wotsPk` and subtree
>    root, which surfaced (one layer late) as the layer-1 digit-sum gate
>    failing — the original "digit-sum gate fails first" diagnosis below was
>    one layer off.
> 2. **`loadWord32` returned all-zero on a partial tail read** — the last
>    16-byte auth-path entry of a 4008-byte signature sits at offset 3992,
>    whose 32-byte window `[3992, 4024)` overruns the blob by 16 bytes. The
>    old definition returned a zero word for any overrun (silently zeroing a
>    real value); EVM `calldataload` instead returns the available bytes and
>    zero-pads the tail. Fix: `loadWord32` now zero-pads. (This is why only
>    layer 1's *final* merkle step was wrong while layer 0 was perfect.)
>
> With both fixes, `lake exe verify-test-vectors` reports **full-verify
> 10/10** (4 valid ACCEPTED, 6 negatives REJECTED), `requireFullVerify` is
> flipped to `true` (hard check), and `verifyRefined_eq_spec` stays `rfl`
> over the now-faithful spec — meeting every closure criterion at the bottom
> of this doc. The A3.1 axiom is no longer contradicted by any tested vector.
>
> **What remains** (the standing ceiling, never part of this gap): the
> ∀-signature symbolic equivalence over all 4008-byte inputs is intractable
> under uninterpreted SHA-256 (see "The deeper ∀-signature ceiling" below);
> the ∀ is carried by the executable Lean↔bytecode KAT + the ~250-mutant
> screen + EUF-CMA, not a symbolic proof. `AXIOM_STATUS.json` A3.1 is now
> `discharged-bytecode`. The original analysis is retained below for history.

> ## ✅ 2026-06-18 — model↔spec ∀ CLOSED in Lean (deductive interpreter-refinement)
>
> The closure path sketched at the bottom of this doc is now **executed**. The
> deductive interpreter-refinement proof
> `SphincsCVerify.Interpreter.C10.execC10Asm_eq`
> (`Interpreter/C10Refine.lean`) proves, with SHA-256 kept **opaque** and **no**
> symbolic engine:
>
> ```
> execC10Asm pkSeed pkRoot message sig
>   = (nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel pkSeed pkRoot message sig)
> ```
>
> `#print axioms execC10Asm_eq = [propext, Classical.choice, Quot.sound]` —
> kernel-clean, no `sorryAx`, no `native_decide`. So the R1-*internal*
> `model ↔ spec` ∀ (over all 4008-byte sigs) is no longer carried by the
> KAT/bulk corpus alone — it is **proven**. The only residual under A3.1 is now
> the genuine R1 hand-transcription gap **bytecode ↔ `execC10Asm`** (the
> statement-for-statement Yul transcription, diff-checkable + KAT/bulk-backed)
> and R2 (the byte-addressed SHA-256 precompile memory, handled in
> `Interpreter/Memory.lean`).
>
> ### ⚠️ Finding: the A3.1 axiom is stated TOO STRONGLY (false as a ∀)
>
> `Bridge.solidityVerifier_compiles_correctly` asserts
> `∀ …, DeployedBytecode.SPHINCsC10Asm_verify = verifyYulModel`. This is **false
> in full generality**: a **non-N-masked** `pkSeed`/`pkRoot` makes the deployed
> bytecode return `false` (the L58-65 N-mask guard) while `verifyYulModel`
> silently truncates (`.take 16`) and can return `true`. The **faithful** form,
> proven by `execC10Asm_eq`, is
> `DeployedBytecode = execC10Asm = nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel`.
>
> `theft_free`'s **conclusion still holds for the real system** — the factory
> `createAccountPrecondition` requires `nMasked` on every key half, so
> non-N-masked owner keys are unreachable; the axiom merely overclaims its
> generality (it is faithful exactly on the reachable, N-masked states).
>
> **Tightening it (swap the axiom for `DeployedBytecode = execC10Asm`) is gated
> on a not-yet-proven invariant.** `theft_free` uses the bridge in the
> *completeness* direction (`Spec/Theorems.lean` existence half:
> `rw [hbridge]; exact hverify`, concluding bytecode-accepts from spec-accepts),
> which with the truthful `nMaskedB` form needs `nMaskedB pks ∧ nMaskedB pkr`.
> Those require a proven reachable-state invariant "every installed owner has
> N-masked key halves" — which does **not** exist yet (only `nMasked` as a
> factory *precondition* + `hasNMaskLayout` as a *def*). Threading it is real
> wallet-model invariant work (A3.2-`combinedCapInvariant`-style); a bare added
> `(hN : nMasked owner)` hypothesis on `theft_free` would silently narrow the
> headline theorem and is **not** an acceptable substitute. So the swap is left
> as a scoped follow-up, not forced.

---

**Date:** 2026-06-11. **Severity:** verification-stack honesty (no on-chain
exploit; the deployed verifier itself is unchanged and is exercised by the
on-bytecode KAT + mutant screen below). **Status of the headline
`theft_free` proof:** unaffected at the kernel level — but the gap below
bounds exactly how far A3.1 connects that proof to the verifier bytecode.

## TL;DR

The Lean SPHINCS+C10 verifier spec (`Spec.Signature.verify`) had **never
been executed on a concrete signature** until 2026-06-11. When run against
the 10 shared KAT vectors (`lake exe verify-test-vectors`), it returns
`false` on the **valid** vectors. So the Lean verifier model is **not
functionally faithful** to the deployed bytecode, and the previously
advertised "three-way Rust ↔ Solidity ↔ Lean KAT differential" for A3.1
was, on the Lean leg, a stub (a print statement). This document records
the precise gap, what *is* validated, and what closing it requires.

## What the runner shows

`lake exe verify-test-vectors` replays all 10 vectors through the
executable spec and reports three sub-layers:

| Sub-layer | Lean function | Result vs bytecode ground truth |
|---|---|---|
| hMsg **digest** | `Spec.Hash.hMsg` (over `Spec.Sha256Impl`) | **10/10 byte-exact** (HARD CHECK) |
| **htIdx** extraction | `Util.extractHtIndex` | **10/10 exact** (HARD CHECK) |
| **full functional verify** | `Spec.Signature.verify` | **valid vectors return `false`** — GAP |

So the SHA-256 reference, the `hMsg` preimage layout, and the hypertree-leaf
index extraction are genuinely faithful (a real Lean-SHA256 ↔ FIPS ↔
deployed-digest cross-check). The divergence is strictly **downstream of the
digest**, in the reconstruction layer.

## Where it diverges (localised)

`Spec.Hypertree.verifyWithDigest` reaches `Spec.Wots.pkFromSig`, which
recomputes the WOTS+C digest and checks `digitSum digits = TargetSum`
(= 205). On the valid vectors this check **fails** (`pkFromSig` → `none` →
`verifyHypertree` → `none` → `verify` → `false`). The first-order cause is
the **ADRS bit-layout**: the Lean `Spec.Adrs.make` builds a clean
structured 32-byte address (`layer ‖ tree ‖ atype ‖ kp ‖ ci ‖ cp ‖ ha`)
intended to "mirror `address.rs`", whereas the deployed Yul packs ad-hoc
words such as

```
wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))
chainBase := and(or(wotsAdrs, shl(64, i)), 0xFF..FF00000000FFFFFFFF)
pkAdrs   := or(shl(224,layer), or(shl(160,idxTree), or(shl(128,1), shl(96,idxLeaf))))
treeAdrs := or(shl(224,layer), or(shl(160,idxTree), shl(128,2)))
```

with the per-chain index threaded at `shl(64, i)` and the chain position at
`shl(32, digit+step)`. For the recomputed WOTS digest (hence the digit sum,
hence every chain endpoint and the Merkle path) to match, the Lean ADRS
bytes must equal these packed words **byte-for-byte** at every call site.
They evidently do not. Because the digit-sum gate fails first, any further
divergences in the FORS / WOTS chain / subtree-Merkle reconstruction are
currently **masked** and not yet individually characterised.

## The sharp consequence: the A3.1 axiom is currently FALSE as stated

`solidityVerifier_compiles_correctly` (A3.1) asserts

```
∀ pkSeed pkRoot message sig,
  DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot message sig
    = verifyYulModel pkSeed pkRoot message sig
```

We have **exhibited a concrete counterexample**: on KAT `valid-1` the
deployed bytecode returns `true` while `verifyYulModel` (= `verifyRefined`
= `Spec.Signature.verify`) returns `false`. So the universally-quantified
equality is **false**, and A3.1 is not "partially discharged" — as written
it is a **false axiom**.

Two precise implications, kept separate so neither is over- or under-stated:

* **Formally:** `theft_free` is still kernel-checked; Lean does not know or
  care that A3.1 is false. But a proof resting on a false axiom carries no
  real-world force — and worse, a false axiom is *inconsistent with reality*,
  so the axiom base could in principle derive contradictory conclusions.
  The kernel "green" is therefore **not** evidence of bytecode-level
  security on the verifier dimension.

* **Operationally (why no on-chain bug):** the **deployed** verifier is the
  Rust-signer's matched pair and is exercised directly by the bytecode KAT +
  mutant screen (all PASS). The falsity is in the *Lean model*, not the
  contract. Nothing on-chain is broken; what is broken is the *claim that the
  Lean proof reaches the verifier bytecode*.

**Required correction (either path):**
1. Make `Spec.Signature.verify` executably faithful (so the equality holds
   and A3.1 becomes true + discharged), **or**
2. Restate A3.1 honestly: drop the verifier-functional equality from the
   formal bridge and record the verifier's correctness as an **empirical /
   cited** assumption (bytecode KAT + mutant screen + the Rust↔Solidity
   matched-pair), i.e. treat the verifier like A2/A4/A5 (cited-TCB) rather
   than as a discharged bytecode bridge.

Until one of these lands, the project must NOT claim the verifier is
"mathematically proven to the bytecode."

## What this does and does NOT mean

* It does **not** mean the deployed verifier is wrong. The deployed
  `SPHINCsC10Asm.verify` bytecode **accepts** all four valid vectors
  (`forge test --match-test test_verifyAllKatVectors`, PASS) and **rejects**
  every member of the ~250-mutant wrong-accept screen
  (`SPHINCsC10AsmAdversarial.t.sol`, PASS) and the 6 negative KAT vectors.
  The Rust signer and the Solidity verifier are a validated matched pair.

* It **does** mean A3.1's *formal* leg is weaker than the prior docs
  implied. The chain
  `Spec.Signature.verify → verifyRefined (rfl) → verifyYulModel (rfl) →
  [A3.1 axiom] → deployed bytecode` is internally consistent, but its
  left end (`Spec.Signature.verify`) does not compute the function the
  deployed bytecode computes. So the Lean refinement establishes
  *internal* structure, not *external* faithfulness, on the reconstruction
  layer. The FORS-`htIdx` ADRS binding added in `fcee705a` is **structural
  only** — it was never executably confirmed against a vector.

## Corrected A3.1 evidence ledger

A3.1 (`solidityVerifier_compiles_correctly`) is **`discharged-bytecode-partial`**,
and the honest decomposition is:

1. **Digest + index layer** — executable Lean ↔ FIPS ↔ bytecode KAT, 10/10
   (`lake exe verify-test-vectors`, HARD CHECK). *New, real.*
2. **Input gates** — Halmos over the deployed bytecode (length revert,
   N-mask reject), 3 rules (`HalmosVerifier.t.sol`).
3. **Functional behaviour (FORS/WOTS+C/Merkle/hypertree)** — **empirical
   only**: the 10-vector positive KAT + the ~250-mutant wrong-accept screen,
   both on the deployed bytecode. **No formal ∀-signature equivalence**, and
   **no executable Lean cross-check** (this gap). This is the named residual.

The earlier phrasing "Lean refinement (incl. FORS htIdx) + 10 KAT vectors"
must be read as: *structural* Lean refinement (not executably faithful on
reconstruction) + *bytecode-side* KAT (the Rust↔Solidity leg is real; the
Lean leg validates only the digest/index sub-layer).

## Why it is not closed in-session

Making `Spec.Signature.verify` executably faithful is a **bit-exact
reimplementation-and-validation** of the WOTS+C and hypertree ADRS layer
(≥4 distinct packings + index threading + the count/target-sum grind +
subtree Merkle ordering), each cross-checked against Rust/Yul intermediates.
That is a multi-day effort with compounding-bug risk, not a localized fix —
exactly the work the verified-compilation path
(`A3_1_CLOSURE_PATH.md`, Verity) or an interpreted-hash symbolic
discharge (Kontrol/KEVM) is meant to absorb.

## Closure criteria (when this doc can be deleted)

* `lake exe verify-test-vectors` reports **full verify 10/10** and
  `requireFullVerify` in `Main.lean` is flipped to `true` (hard check); **and**
* the Lean `Spec.Signature.verify` digest/index/reconstruction all match on
  the corpus, with `verifyRefined_eq_spec` still `rfl`; **then**
* A3.1 can be promoted from `discharged-bytecode-partial` to
  `discharged-bytecode` for the functional layer (the ∀-signature symbolic
  equivalence over a 4008-byte sig remains intractable under uninterpreted
  SHA-256 regardless — see below).

## The deeper ∀-signature ceiling (separate from this gap)

Even a perfectly faithful executable Lean spec would not give a *symbolic*
∀-signature equivalence on the bytecode under Halmos: the verifier branches
on base-`w` digits of `sha256(seed‖adrs‖node‖count)`, and with SHA-256 an
**uninterpreted** function (= axiom A1) every digit is an unconstrained
symbolic value, so the path set explodes and no UF-based symbolic engine can
close it. Closing *that* needs an interpreted-hash reachability tool
(Kontrol/KEVM) or verified compilation (Verity). This is why A3.1 stays
`-partial` independently of the reconstruction gap above.

> **Correction (2026-06-16) — the above is right about *symbolic engines* but
> incomplete about the *problem*.** "No UF-based symbolic engine can close it"
> is true; "closing it needs an interpreted-hash engine or verified compilation"
> is **not** the whole story. A **deductive interpreter-refinement proof in
> Lean** closes `∀ inputs, execModel = Spec.verify` with the hash kept **opaque**
> and **no** interpreted-hash engine — the digit-branch explosion is an artifact
> of symbolic *search* (Halmos/KEVM fork on every branch), not of the theorem (a
> proof assistant does *induction on loop-iteration count*: two cases per loop,
> the hash threaded through a hash-agnostic per-step invariant, never unfolded).
> The upstream SPHINCS- `/verity` project **demonstrates** this — `c13_refines_spec
> : ∀ …, execC13 = verifySpec` (`Proofs.lean:12158`), carrying **zero** hash
> axioms for Keccak. The genuine residuals are then (R1) the model↔deployed-
> bytecode hand-transcription (shared with upstream; a diff-checkable TCB element,
> not the explosion) and (R2) SHA-256 needing a **byte-addressed** interpreter
> memory (the `0x02` precompile's sub-word `mstore` aliasing). Full analysis +
> closure path + effort in [`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md).

# Open Proof Obligations — Verifying `SPHINCsC10Asm.sol`

This document is the **complete remaining work** to take the SphincsCVerify
project from its current state to a kernel-checked formal-verification result
for the SPHINCS+C10 cryptographic verifier contract
(`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`, 202 lines of Yul).

**Scope (2026-05).** Verifier only. The wallet contracts
(`PQSmartWallet.sol`, `PQMultiOwnable.sol`, `PQSmartWalletFactory.sol`) and
the hardware-wallet firmware (Rust under `secure/`, `nonsecure/`, …) are out
of scope for the current engagement. The Lean files under
`SphincsCVerify/Wallet/` are legacy and may be removed in a future cleanup
commit; the headline result this document targets does not depend on them.

The work is organised into seven phases. Each phase unblocks the next, so
they should be tackled in order. For every obligation we record:

  * **Where** in the source it lives (file:line where applicable).
  * **Current state** (verbatim from the source, where useful).
  * **Statement** — the Lean theorem to close.
  * **Discharge plan** — the proof technique that closes it, with a code
    skeleton where helpful.
  * **Time estimate** (one engineer).
  * **Done criteria** — how to know the phase is finished.

A `sorry` and axiom tracker at the bottom of the file records the expected
state after each phase.

---

## Phase 1 — Mechanical `sorry`s (1–2 weeks)

Pure proof-script grind. No new design, no new definitions. Closes every
verifier-scope `sorry` that does not depend on Phases 2+.

### 1.1 `readBitsLe_lt`

* **Where**: `SphincsCVerify/Util/Bits.lean:71`
* **Current**: `sorry`
* **Statement**:
  ```lean
  theorem readBitsLe_lt (digest : ByteVec 32) (off k : Nat) :
      readBitsLe digest off k < 2 ^ k
  ```
* **Discharge plan**: induction on `k`. The inner `loop` in `readBitsLe` ORs
  in one bit of weight `2^i` per iteration. Prove a strengthened induction
  hypothesis on the accumulator:
  ```lean
  have aux : ∀ i acc, acc < 2 ^ i →
      readBitsLe.loop digest off k i acc < 2 ^ k := …
  ```
  Then `readBitsLe digest off k = readBitsLe.loop digest off k 0 0` and
  `0 < 2 ^ 0` close the base case. Use `Nat.or_lt_two_pow` (mathlib) or
  prove a small bit-OR bound by hand.
* **Time**: ~½ day.

### 1.2 `extractForsIndices_lt`

* **Where**: `SphincsCVerify/Util/Bits.lean:82`
* **Current**: `sorry`
* **Statement**: every extracted FORS index is `< 2 ^ A`.
* **Discharge plan**: direct corollary — `exact readBitsLe_lt _ _ _`.
* **Time**: ~1 hour.

### 1.3 `extractDigits_lt`

* **Where**: `SphincsCVerify/Util/Bits.lean:93`
* **Current**: `sorry`
* **Statement**: every WOTS+C digit is `< W = 2 ^ LogW = 8`.
* **Discharge plan**: corollary of `readBitsLe_lt` with `k = LogW`, then
  `W = 2 ^ LogW` (closed by `decide`).
* **Time**: ~1 hour.

### 1.4 `verify_rejects_nonzero_last_fors_idx`

* **Where**: `SphincsCVerify/Spec/Theorems.lean:118`
* **Current**: `sorry`
* **Statement** (already in source):
  ```lean
  theorem verify_rejects_nonzero_last_fors_idx
      (pkSeed pkRoot : ByteVec 16) (msg : ByteVec 32) (sig : Hypertree.Signature)
      (h : (Util.extractForsIndices (hMsg …)).getD (K - 1) 0 ≠ 0) :
      Hypertree.verify pkSeed pkRoot msg sig = false
  ```
* **Discharge plan**: `Hypertree.verify` has an early-return cascade. The
  blocker today is that the predicate lives inside a `let`-binding rather
  than as a `match` head, so `simp [Hypertree.verify]` doesn't surface it.
  Two options:
  1. **Preferred:** refactor `Hypertree.verify` to hoist the `if` predicate
     to a top-level `match` — clean, ~10 LoC diff in `Spec/Hypertree.lean`;
     closes 1.5 as a side-effect.
  2. Keep the def, prove with explicit `unfold` + `split` tactics. Slightly
     more brittle.
* **Time**: 1–2 days.

### 1.5 `verify_rejects_bad_digit_sum`

* **Where**: `SphincsCVerify/Spec/Theorems.lean:128`
* **Current**: placeholder `True` closed by `trivial`.
* **Statement** (replace the placeholder):
  ```lean
  theorem verify_rejects_bad_digit_sum
      (pkSeed pkRoot : ByteVec 16) (msg : ByteVec 32) (sig : Hypertree.Signature)
      (layer : Nat) (hlayer : layer < D)
      (hbad : digitSum (extractDigits
                (wotsDigest (pad16 pkSeed) (Adrs.wots …) … …)) ≠ TargetSum) :
      Hypertree.verify pkSeed pkRoot msg sig = false
  ```
  Concretely: `Wots.pkFromSig` returns `none` on digit-sum mismatch;
  propagate that `none` through `Hypertree.verifyHypertree` to `false`.
* **Discharge plan**:
  - Open `Spec/Wots.lean` and locate the `if digitSum digits = TargetSum`
    branch in `pkFromSig`.
  - Trace `none` to the layer-loop branch in `Hypertree.verify` that
    returns `false`.
  - After the Hypertree refactor from 1.4, `simp` closes it.
* **Time**: 1–2 days.

### Phase 1 done criteria

```bash
cd contracts/verification/lean
lake build
lake env lean --run scripts/check_no_sorry.lean
# Expected: 0 sorry in Util/Bits.lean and Spec/Theorems.lean except verify_signs
```

`sorry` count: drops from 11 → 6 (the remaining ones are
`Spec/Theorems.lean::verify_signs` and four section lemmas in
`Verifier/Equivalence.lean`, addressed in Phases 5 and 6).

---

## Phase 2 — Kernel-computable SHA-256 (4–8 weeks) ★ highest leverage

The single highest-leverage phase. Until `Spec/Hash.lean::sha256` is
definitional rather than `opaque`, no concrete digest can be evaluated
inside the Lean kernel and Phases 5 and 7 are gated.

### 2.1 FIPS 180-4 SHA-256 in Lean

* **Where**: new file `SphincsCVerify/Spec/Sha256Impl.lean`.
* **Statement**:
  ```lean
  def sha256_impl : List ByteSeg → ByteVec 32
  ```
  Following FIPS 180-4 §5.1 (padding), §5.3 (initial hash values H0..H7),
  §6.2 (message schedule + compression function).
* **Discharge plan**: structurally port the algorithm. Components:
  - `UInt32` bitwise helpers: `rotr`, `ch`, `maj`, `bsig0`, `bsig1`,
    `ssig0`, `ssig1` (each a one-liner using `<<<` / `>>>` / `^^^`).
  - Round constants `K[0..63]` (literal array; FIPS 180-4 §4.2.2).
  - `messageSchedule : ByteVec 64 → Array UInt32` (size 64) — §6.2.1.
  - `compress : (state block : _) → Array UInt32` — §6.2.2.
  - `padMessage : List ByteSeg → Array (ByteVec 64)` — §5.1.1.
  - `sha256_impl segs = (List.foldl compress initialHash (padMessage segs)).flatten`
    encoded as big-endian bytes.

  Pattern to copy: Verity's `Compiler/Keccak/Sponge.lean`, adjusting for
  SHA-256's MD-style construction vs Keccak's sponge.
* **Time**: 2–3 weeks for someone fluent in Lean + the FIPS spec.

### 2.2 Replace `opaque sha256`

* **Where**: `SphincsCVerify/Spec/Hash.lean:87`
* **Current**:
  ```lean
  opaque sha256 : List ByteSeg → ByteVec 32
  ```
* **Replace with**:
  ```lean
  def sha256 (segs : List ByteSeg) : ByteVec 32 := sha256_impl segs
  ```
* **Done criteria**: `lake build` still passes; `#eval sha256 []` returns
  the known empty-string digest
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### 2.3 Test-vector lemmas

* **Where**: new file `SphincsCVerify/Spec/Sha256TestVectors.lean`.
* **Statement**: for each `(input, expected)` in NIST CAVS
  `SHA256ShortMsg.rsp`,
  ```lean
  example : sha256 [ByteSeg.ofByteVec input] = expected := by native_decide
  ```
* **Discharge plan**: import the CAVS file, emit one example per vector.
  `native_decide` closes each in <100 ms.
* **Time**: 2–3 days.

### 2.4 Tweakable-hash unfolding lemmas

* **Where**: extend `SphincsCVerify/Spec/Hash.lean` (after `th_size`).
* **Statements**:
  ```lean
  theorem th_unfolds_to_sha256 (s : ByteVec 32) (a : Adrs) (x : ByteVec 32) :
      th s a x = truncate16 (sha256 [
        ByteSeg.ofByteVec s, ByteSeg.ofByteVec a, ByteSeg.ofByteVec x]) := rfl

  theorem thPair_unfolds_to_sha256 …
  theorem thMulti_unfolds_to_sha256 …
  theorem hMsg_unfolds_to_sha256 …
  ```
* **Discharge plan**: each closes by `rfl` once `sha256` is definitional.
* **Time**: <1 day.

### Phase 2 done criteria

```bash
lake build
lake env lean --run scripts/dump_axioms.lean
# Expected: sha256 no longer appears as an opaque dependency.
lake exe sha256-test-vectors  # all CAVS vectors pass via native_decide
```

---

## Phase 3 — Complete reference signer (2–3 weeks)

`Spec/Signer.lean::sign` is currently a placeholder returning zero-filled
chains and auth paths. Phase 5's round-trip theorem cannot proceed without
a real signer.

### 3.1 FORS Merkle root + auth path

* **Where**: extend `SphincsCVerify/Spec/Fors.lean`; rewrite the
  `forsSecrets` / `forsAuthPaths` blocks in
  `SphincsCVerify/Spec/Signer.lean`.
* **Source of truth**: `sphincs-c10/src/fors.rs::sign_fors_tree` and
  `sphincs-c10/src/merkle.rs::treehash`.
* **What to add**:
  - `def forsLeafHash (skSeed pkSeed : ByteVec 32) (treeIdx leafIdx : UInt32) : ByteVec 16`
  - `def forsTreeHash (skSeed pkSeed : ByteVec 32) (treeIdx : UInt32) (height nodeIdx : Nat) : ByteVec 16` — declarative recursive Merkle hash (no need to match the iterative Treehash; the spec form is fine).
  - `def forsAuthPath (skSeed pkSeed : ByteVec 32) (treeIdx leafIdx : UInt32) : Array (ByteVec 16)` of length `A`.
* **Time**: ~1 week.

### 3.2 WOTS+ chains

* **Where**: extend `SphincsCVerify/Spec/Wots.lean`.
* **Source of truth**: `sphincs-c10/src/wots.rs::sign_with_shuffle`.
* **What to add**:
  - `def wotsChainStart (skSeed pkSeed : ByteVec 32) (wotsAdrs : Adrs) (i : Nat) : ByteVec 16` (the `sk_i` start node).
  - `def wotsSignChain (skSeed pkSeed : ByteVec 32) (wotsAdrs : Adrs) (i digit : Nat) : ByteVec 16` (chain truncated at digit `d` instead of `W-1`).
* **Time**: ~3 days.

### 3.3 WOTS+C count and R-grinding correctness

* **Where**: `SphincsCVerify/Spec/Signer.lean` (already partly there).
* **What's needed**:
  - `findCount` / `grindR` already use `Option` to model probabilistic
    non-termination — keep as-is.
  - Phase 5 will need a correctness lemma; add the statement now as a
    stub:
    ```lean
    theorem findCount_correct
        (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
        (msgHash : ByteVec 32) (limit : Nat) (count : UInt32) (d : ByteVec 32) :
        findCount seed layer tree kp msgHash limit = some (count, d) →
        d = wotsDigest seed (Adrs.wots layer tree kp) msgHash count
        ∧ digitSum (extractDigits d) = TargetSum
    ```
    Closes by `unfold findCount; intros h; …` once Phase 5 machinery
    is in place.
* **Time**: ~2 days.

### 3.4 Hypertree layer assembly

* **Where**: replace the per-layer placeholders in
  `SphincsCVerify/Spec/Signer.lean` (the `Array.replicate L (zero 16)`
  blocks).
* **Source of truth**: `sphincs-c10/src/hypertree.rs::sign`.
* **What to add**: for each layer in `[0..D)`: compute WOTS+C signature
  via `wotsSignChain` per index, compute the subtree Merkle root, emit
  the auth path.
* **Time**: ~1 week.

### Phase 3 done criteria

`Spec/Signer.lean::sign` returns a structurally-correct `Signature` with
no `Array.replicate (zero 16)` stubs. `lake build` passes.

---

## Phase 4 — Byte-level deserialiser (1–2 weeks)

`Spec/Signature.lean::deserialise` currently returns `defaultSignature`
regardless of input. Phases 5 and 6 need it to be concrete.

### 4.1 Real deserialise

* **Where**: `SphincsCVerify/Spec/Signature.lean:86`
* **Current**:
  ```lean
  def deserialise (_bytes : ByteVec SignatureLen) : Hypertree.Signature :=
    defaultSignature
  ```
* **Replace with**: offset arithmetic over the 4008-byte blob.

  | Offset | Length | Field |
  |---|---|---|
  | 0 | 16 | `r` |
  | 16 | `K * N = 208` | FORS secrets (one per `K=13` trees) |
  | 224 | `(K-1) * A * N = 2112` | FORS auth paths |
  | 2336 | `D * 836 = 1672` | hypertree layer sigs (`L*N=688` chains + 4 count + `SubtreeH*N=144` auth) |

  Total: `16 + 208 + 2112 + 2 × 836 = 4008`. Cross-check:
  `signatureLen_eq_4008` in `Spec/Params.lean`.
* **Code skeleton**:
  ```lean
  def deserialise (bytes : ByteVec SignatureLen) : Hypertree.Signature :=
    let r := (bytes.take 16 (by decide)).cast (by decide)
    let forsSecrets : Array (ByteVec 16) :=
      Array.ofFn (n := K) fun i =>
        ((bytes.drop (16 + i.val * N) (by …)).take 16 (by …))
    let forsAuthPaths : Array (Array (ByteVec 16)) :=
      Array.ofFn (n := K - 1) fun i =>
        Array.ofFn (n := A) fun h =>
          ((bytes.drop (224 + i.val * (A * N) + h.val * N) (by …)).take 16 (by …))
    let layers : Array Hypertree.LayerSig :=
      Array.ofFn (n := D) fun layer =>
        let off := 2336 + layer.val * 836
        { wots :=
            { chains := Array.ofFn (n := L) fun i =>
                ((bytes.drop (off + i.val * N) (by …)).take 16 (by …))
              chainsLen := Array.size_ofFn
              count := loadU32BE bytes (off + L * N) }
          authPath := Array.ofFn (n := SubtreeH) fun h =>
            ((bytes.drop (off + L * N + 4 + h.val * N) (by …)).take 16 (by …))
          authPathLen := Array.size_ofFn }
    ⟨r, …, layers, Array.size_ofFn⟩
  ```
  All `by …` `≤`-side conditions are arithmetic on `SignatureLen = 4008`,
  closed by `omega` or `decide`.
* **Time**: ~1 week.

### 4.2 Round-trip lemma

* **Where**: `SphincsCVerify/Spec/Signature.lean`.
* **Statement**:
  ```lean
  theorem serialise_deserialise_roundtrip (bytes : ByteVec SignatureLen) :
      Signature.serialise (deserialise bytes) = bytes
  ```
  (Plus the converse `deserialise_serialise_roundtrip` over structured
  inputs that satisfy the byte-shape invariants.)
* **Discharge plan**: structural induction on the byte layout; each
  field's `take`/`drop` composes to identity. Mechanical.
* **Time**: ~3 days.

### Phase 4 done criteria

`deserialise` returns a structured signature reflecting the input bytes;
`serialise_deserialise_roundtrip` closes.

---

## Phase 5 — Round-trip theorem `verify_signs` (1–2 months) ★ headline functional result

The big one. If you sign and then verify, the verifier accepts.

### 5.1 Sub-lemma: Merkle round-trip

* **Where**: new file `SphincsCVerify/Spec/Lemmas/MerkleRoundtrip.lean`.
* **Statement**:
  ```lean
  theorem merkle_roundtrip
      (seed : ByteVec 32) (leafHash : ByteVec 16) (idx : Nat) (height : Nat)
      (siblings : Array (ByteVec 16)) (treeAdrs : Adrs) :
      siblings.size = height →
      Merkle.verifyAuthPath seed leafHash idx height siblings treeAdrs
        = Merkle.buildRoot seed leafHash idx height siblings treeAdrs
  ```
* **Discharge plan**: induction on `height`. Base case `h = 0`:
  `leafHash = leafHash`. Step: each iteration's `thPair` is the same
  operation on both sides given identical sibling + identical
  leaf-or-parity choice.
* **Time**: ~1 week.

### 5.2 Sub-lemma: WOTS+C chain round-trip

* **Where**: new file `SphincsCVerify/Spec/Lemmas/WotsRoundtrip.lean`.
* **Statement**:
  ```lean
  theorem wots_chain_roundtrip
      (skSeed pkSeed : ByteVec 32) (wotsAdrs : Adrs) (i digit : Nat)
      (hd : digit < W) :
      let signedChain := wotsSignChain skSeed pkSeed wotsAdrs i digit
      let recovered :=
        chainHash pkSeed (setChainIndex wotsAdrs i)
                  signedChain digit (W - 1 - digit)
      recovered = chainHash pkSeed (setChainIndex wotsAdrs i)
                            (wotsChainStart skSeed pkSeed wotsAdrs i) 0 (W - 1)
  ```
* **Discharge plan**: induction on `digit`. The chain is iterated `th`;
  signing at digit `d` and recovering by `W - 1 - d` more steps lands at
  the same `W - 1`-iteration node as the public-key endpoint.
* **Time**: ~1 week.

### 5.3 Sub-lemma: FORS+C round-trip

* **Where**: new file `SphincsCVerify/Spec/Lemmas/ForsRoundtrip.lean`.
* **Statement**:
  ```lean
  theorem fors_roundtrip
      (skSeed pkSeed : ByteVec 32) (treeIdx leafIdx : UInt32) :
      let secret := forsSecret skSeed treeIdx leafIdx
      let authPath := forsAuthPath skSeed pkSeed treeIdx leafIdx
      Fors.reconstructTreeRoot pkSeed treeIdx leafIdx secret authPath
        = forsTreeHash skSeed pkSeed treeIdx 0 0
  ```
* **Discharge plan**: applies `merkle_roundtrip` per tree; for the K-th
  forced-zero tree, apply with `leafIdx = 0`.
* **Time**: ~1 week.

### 5.4 Sub-lemma: chain-hash composition

* **Where**: new file `SphincsCVerify/Spec/Lemmas/ChainHash.lean`.
* **Statement**:
  ```lean
  theorem chainHash_compose
      (seed : ByteVec 32) (a : Adrs) (val : ByteVec 16)
      (start steps1 steps2 : Nat) :
      chainHash seed a (chainHash seed a val start steps1)
                       (start + steps1) steps2
        = chainHash seed a val start (steps1 + steps2)
  ```
* **Discharge plan**: induction on `steps2`. Base case trivial; step uses
  associativity of iteration.
* **Time**: ~3 days.

### 5.5 Top-level `verify_signs`

* **Where**: `SphincsCVerify/Spec/Theorems.lean:86` — replace the
  current `sorry`.
* **Statement** (already in source):
  ```lean
  theorem verify_signs
      (sk : SigningKey) (message : ByteVec 32)
      (hc : consistent sk) (sig : Hypertree.Signature)
      (hsign : Signer.sign sk message = some sig) :
      Hypertree.verify sk.pkSeed sk.pkRoot message sig = true
  ```
* **Discharge plan**: structural induction over the hypertree layers,
  invoking 5.1–5.4 plus `findCount_correct` and `grindR_correct`
  (Phase 3.3). Skeleton:
  ```lean
  theorem verify_signs sk message hc sig hsign := by
    unfold Signer.sign at hsign
    rcases hsign with ⟨r, digest, hgrind, …⟩
    simp [Hypertree.verify]
    refine ⟨?lastIdx, ?forsRoot, ?layers⟩
    case lastIdx =>
      -- by grindR_correct: last fors index = 0
      exact grindR_returns_zero_last_idx hgrind
    case forsRoot =>
      -- fors_roundtrip per tree, then thMulti rfl
      exact fors_roundtrip_aggregate …
    case layers =>
      -- induction on D, each step: wots_chain_roundtrip +
      --   merkle_roundtrip + chainHash_compose
      induction D with
      | zero => rfl
      | succ d ih => …
  ```
* **Time**: 2–3 weeks once 5.1–5.4 are in place.

### 5.6 Tighten `consistent`

The placeholder `def consistent : SigningKey → Prop := fun _ => True` is
acceptable for Phase 5 but should be tightened to
`Hypertree.computePkRoot sk = sk.pkRoot`. Leave as a follow-up TODO; the
`verify_signs` proof above does not depend on the strengthening.

### Phase 5 done criteria

`Spec/Theorems.lean::verify_signs` closes with no `sorry`. Audit:

```lean
#print axioms SphincsCVerify.Spec.Theorems.verify_signs
```
shows only `propext`, `Classical.choice`, `Quot.sound` — no crypto axiom.

---

## Phase 6 — Refinement: Lean spec ↔ Yul model (2–3 weeks)

The Solidity verifier (`SPHINCsC10Asm.sol`) reads calldata by offset.
`Verifier/Refined.lean` already models that shape. The obligation is to
prove it equivalent to the structured `Spec.Signature.verify`.

### 6.1 Section lemma — load R

* **Where**: `SphincsCVerify/Verifier/Equivalence.lean:48`
* **Current**: `sorry`
* **Statement** (already in source):
  ```lean
  theorem load_R_consistent (bytes : ByteVec SignatureLen) :
      loadValue16 bytes 0 = (deserialise bytes).r
  ```
* **Discharge plan**: after Phase 4 makes `deserialise` concrete, both
  sides reduce to `(bytes.take 16 _)`. `rfl` should close it; if not,
  `simp [deserialise, loadValue16, loadWord32]`.
* **Time**: ~½ day.

### 6.2 Section lemma — FORS section

* **Where**: `SphincsCVerify/Verifier/Equivalence.lean:54`
* **Current**: placeholder `True` closed by `trivial`.
* **Statement** (replace):
  ```lean
  theorem fors_section_consistent
      (bytes : ByteVec SignatureLen) (pkSeed : ByteVec 16) (digest : ByteVec 32) :
      reconstructForsPkRefined bytes (pad16 pkSeed) digest
        = Fors.reconstructForsPk pkSeed
            (deserialise bytes).fors (extractForsIndices digest)
  ```
* **Discharge plan**: align the offset arithmetic
  `AUTH_START + i * AUTH_PER_TREE + h * N` with
  `(deserialise bytes).fors.authPaths[i][h]`. Each step is
  `Array.extract` + `ByteVec.take` algebra. ~200 LoC structural proof.
* **Time**: ~1 week.

### 6.3 Section lemma — HT layer 0

* **Where**: `SphincsCVerify/Verifier/Equivalence.lean:60`
* **Current**: placeholder `True`.
* **Statement** (replace): the layer-0 walk in `verifyRefined` returns the
  same node as `Hypertree.verifyLayer` on the structured form.
* **Discharge plan**: same shape as 6.2; align offsets for `chains` (at
  `sigOff + 0..L*N`), `count` (at `sigOff + 688`), `auth` (at
  `sigOff + 692..836`).
* **Time**: ~3 days.

### 6.4 Section lemma — HT layer 1

* **Where**: `SphincsCVerify/Verifier/Equivalence.lean:66`
* **Discharge plan**: same as 6.3 with `sigOff = HT_START + 836 = 3172`.
  Mostly a copy of 6.3.
* **Time**: ~2 days.

### 6.5 Top-level refinement

* **Where**: `SphincsCVerify/Verifier/Equivalence.lean:81`
* **Current**: `sorry`
* **Statement** (already in source):
  ```lean
  theorem verifyRefined_eq_spec
      (pkSeed pkRoot : ByteVec 16) (message : ByteVec 32)
      (bytes : ByteVec SignatureLen) :
      verifyRefined (pad16 pkSeed) (pad16 pkRoot) message bytes
        = Spec.Signature.verify ⟨pkSeed, pkRoot⟩ message bytes
  ```
* **Discharge plan**: compose 6.1–6.4 plus the early-return case-split
  on `lastIdx ≠ 0`. ~50 LoC.
* **Time**: ~1 day after the section lemmas.

### 6.6 `yul_eq_refined` — already closed

`Bridge/SolidityVerifier.lean::yul_eq_refined` closes by `rfl` (the
"Yul model" is a Lean copy of `verifyRefined` with the same control
flow). Just verify post-Phase 6.5 that it still closes.

### Phase 6 done criteria

`Verifier/Equivalence.lean` has 0 `sorry`. The composed theorem closes
in two rewrites:

```lean
example (pkSeed pkRoot : ByteVec 16) (msg : ByteVec 32) (bytes : ByteVec SignatureLen) :
    Bridge.yulVerify pkSeed pkRoot msg bytes
      = Spec.Signature.verify ⟨pkSeed, pkRoot⟩ msg bytes := by
  rw [Bridge.yul_eq_refined, Verifier.verifyRefined_eq_spec]
```

---

## Phase 7 — Cross-validation harness in CI (1 week, after Phase 2)

### 7.1 Test-vector executable

* **Where**: extend `SphincsCVerify/Main.lean` (or add
  `verify_test_vectors.lean`).
* **What to add**: read `sphincs-c10/tests/c10_test_vectors.json`, run
  `Spec.Signature.verify` on each `(pkSeed, pkRoot, msg, sig)` pair,
  compare against `expected_bool`.
* **Discharge plan**: requires kernel-computable SHA-256 (Phase 2). Use
  `Lean.Json.parse` + `native_decide` (or runtime `Bool` equality) to
  evaluate each case.
* **Time**: ~3 days.

### 7.2 Foundry-to-Lean test-vector emitter

* **Where**: extend `contracts/smart-wallet/test/`.
* **What to add**: dump test vectors to JSON via Foundry's
  `vm.writeJson`, into the same corpus consumed by 7.1.
* **Time**: ~2 days.

### 7.3 CI drift detection

* **Where**: `.github/workflows/` (or local CI equivalent).
* **What to add**:
  - On every PR, run the Lean exe over the latest Rust/Foundry vectors.
  - Diff parameter constants between `Spec/Params.lean`,
    `sphincs-c10/src/params.rs`, and `SPHINCsC10Asm.sol`. Extend the
    existing `pqsigner-xtask gen-solidity-constants --check` to emit a
    Lean constants file and diff it.
* **Time**: ~2 days.

### Phase 7 done criteria

`lake exe verify-test-vectors` returns 0 on every CAVS + Rust corpus
vector. CI fails on any constant or vector mismatch.

---

## Out of scope: stays as named axiom

After all seven phases, three sets of axioms remain. They are **not**
unfinished work — they are inherent trust boundaries.

### Cryptographic — `SphincsCVerify/Crypto/`

| Axiom | File | Why irreducible without research |
|---|---|---|
| `SM_DT_TCR_F` | `Crypto/Assumptions.lean:93` | Single-function multi-target target-collision resistance of SHA-256. Proving from arithmetic would require breaking open problems in complexity theory. Cite: Barbosa/Dupressoir/Hülsing/Meijers/Strub ASIACRYPT 2024. |
| `ITSR_F` | `Crypto/Assumptions.lean:109` | Interleaved Target Subset Resilience. Same citation. |
| `hMsg_random_oracle` | `Crypto/Assumptions.lean:121` | Random-oracle modelling assumption. |
| `EUF_CMA_SPHINCSplusC` | `Crypto/EUFCMA.lean:117` | Composite EUF-CMA bound for SPHINCS+**C** (counter-search + forced-zero). Discharging means porting Hülsing PQC2022 to EasyCrypt — 9–18-month research engagement. |

### TCB — `SphincsCVerify/Bridge/`

| Axiom | File | Elimination path (not in current scope) |
|---|---|---|
| `solidityVerifier_compiles_correctly` | `Bridge/Refinement.lean:50` | Re-author `SPHINCsC10Asm` in Verity's verified Lean→Yul EDSL (~3–6 person-months). Alternative: KEVM/Kontrol bytecode-equivalence proof. |
| `evm_bytecode_executes_correctly` | `Bridge/Refinement.lean:62` | Adopt KEVM / Dafny-EVM / EVMYulLean. Universal Ethereum trust, not per-project. |
| `precompile_0x02_is_FIPS_180_4` | `Bridge/Refinement.lean:72` | Verify SHA-256 in geth/reth (Appel-VST-style work). Outside any single smart-contract project. |

### What this engagement explicitly does NOT discharge

* `verify_signs` post-Phase 5 closes against the Lean **model** of
  SHA-256. The bridge from that model to the deployed EVM bytecode rests
  on the three TCB axioms above. The cryptographic argument from
  SHA-256 properties to EUF-CMA is the `EUF_CMA_SPHINCSplusC` axiom.

These axioms are listed precisely in [`AXIOMS.md`](AXIOMS.md); the trust
report is in [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md).

---

## `sorry` and axiom tracker

| Phase | `sorry` (start → end) | New axioms |
|---|---|---|
| Start | 11 | 7 (4 crypto + 3 TCB) |
| **After Phase 1** ✅ (2026-05) | **11 → 7** (closed: 3 in `Util/Bits.lean`, 1 in `Spec/Theorems.lean`; 1 `True`-placeholder replaced with a meaningful structural theorem) | unchanged — `dump_axioms.lean` confirms headline theorems depend only on `propext`/`Quot.sound` |
| After Phase 2 | 7 → 7 (sha256 stops being `opaque`) | unchanged |
| After Phase 3 | 7 → 6 (signer placeholder removed) | unchanged |
| After Phase 4 | 6 → 5 | unchanged |
| After Phase 5 | 5 → 2 (only Equivalence + cannot_forge remain) | unchanged |
| After Phase 6 | 2 → 1 (only `cannot_forge_without_breaking_SHA256` remains; out-of-scope) | unchanged |
| After Phase 7 | 1 → 1 | unchanged |

End state: 1 `sorry` (Phase-H probability backbone, out of current scope), 7 named axioms with citations.

### Phase 1 closing notes (2026-05)

What was actually closed:

| Location | Theorem | How |
|---|---|---|
| `Spec/Params.lean` (new) | `W_eq_two_pow_LogW` | `by decide` |
| `Spec/Hypertree.lean` (refactor) | `verifyWithDigest` extracted from `verify` so the rejection predicates surface for `simp`/`if_pos` |
| `Util/Bits.lean` (refactor) | `readBitsLe.stepValue` extracted from `readBitsLe.loop` so the per-step bound becomes a standalone lemma. Also a tiny private helper `and_one_lt_two : ∀ x, x &&& 1 < 2`. |
| `Util/Bits.lean` | `readBitsLe.stepValue_lt` | `Nat.shiftLeft_eq` + `Nat.pow_succ` + `Nat.mul_lt_mul_right` + the `and_one_lt_two` helper |
| `Util/Bits.lean` | `readBitsLe_loop_lt` (strengthened IH) | induction on `numBits - i`; closes via `Nat.or_lt_two_pow` + `stepValue_lt` |
| `Util/Bits.lean` | `readBitsLe_lt` | corollary of `readBitsLe_loop_lt` at `(i := 0, acc := 0)` |
| `Util/Bits.lean` | `extractForsIndices_lt` | `getElem!_pos` + `Array.getElem_ofFn` + `readBitsLe_lt` |
| `Util/Bits.lean` | `extractDigits_lt` | same shape as above, with `W_eq_two_pow_LogW` |
| `Spec/Theorems.lean` | `verify_rejects_nonzero_last_fors_idx` | `unfold Hypertree.verify; unfold Hypertree.verifyWithDigest; rw [if_pos h]` |
| `Spec/Theorems.lean` | `pkFromSig_returns_none_of_bad_digit_sum` (new) | `unfold Wots.pkFromSig; simp [hbad]` |
| `Spec/Theorems.lean` | `verify_rejects_bad_digit_sum` (rewritten from `True` placeholder) | structural form — given `verifyHypertree = none`, `verify = false`; needs Phase 5 to chain from per-layer bad digit sum |

The interface signatures of `extractForsIndices_lt` and `extractDigits_lt` changed from `.get!` (deprecated) to `[]!` (modern form). Nothing downstream used these yet, so no breakage.

`extractHtIndex_lt` (line 88 of `Util/Bits.lean`) was already trivially closed by `exact readBitsLe_lt _ _ _`; it now type-checks against the proven `readBitsLe_lt` rather than the old `sorry`.

---

## Suggested execution order

1. **Start with Phase 1.** A few days; the satisfying "0 `sorry`s in
   `Util/Bits.lean`" PR establishes momentum.
2. **Phase 2 next.** Single highest-leverage piece. Without it Phases 5
   and 7 are blocked.
3. **Phases 3 and 4 in parallel.** Different files (signer vs
   deserialiser), no internal dependency between them.
4. **Phase 5.** Headline functional result; needs 1–4.
5. **Phase 6.** Independent of Phase 5 in principle but trivially
   easier after Phase 4.
6. **Phase 7.** Parallel with Phase 6; needs only Phase 2.

**Total**: ~4–6 person-months focused work for one engineer.

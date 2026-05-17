# Open Proof Obligations — What Is Still Needed for a Fully Proven Wallet

This document is the **complete remaining work** to take the
SphincsCVerify project from its current state ("scaffolding plus a few
arithmetic identities and Lean-model lemmas") to the headline statement
in `how_to_math_proof_secureness.md`:

> The deployed EVM bytecode of `PQSmartWallet` enforces every stated
> invariant, and accepting a signature implies SPHINCS+C10 EUF-CMA
> security under the cited SHA-256 assumptions.

Every item below is currently either an unfilled `sorry`, a named
`axiom`, or a property that is not even stated in the Lean source yet.
For each, the document records:

  * **What** needs to be proven (the theorem statement).
  * **Where** in the project it lives (or should live).
  * **Discharge plan** (the proof technique that would close it).

Organised by stratum from the playbook.

---

## Stratum A — SPHINCS+C10 verifier core

### A.1 SHA-256 modelling

#### A.1.1 Kernel-computable SHA-256 specification

* **Current state**: `Spec/Hash.lean::sha256` is declared `opaque`, so
  no concrete digest can be evaluated inside the Lean kernel.
* **What's needed**: a definition `sha256 : List ByteSeg → ByteVec 32`
  that follows FIPS 180-4 step by step (initial constants, message
  schedule, compression function, padding, length encoding), reducible
  by `decide` / `native_decide`.
* **Discharge plan**: port Verity's `Compiler/Keccak/Sponge.lean` style
  to SHA-256. The FIPS 180-4 spec is small (~200 lines of Lean once the
  `UInt32` bitwise operations are set up).
* **Why this matters**: without it, no concrete test vector can be
  executed inside the Lean kernel; the cross-validation harness is
  shape-only.

#### A.1.2 SHA-256 functional correctness against FIPS 180-4

* **What's needed**: a theorem
  `sha256_kernel_matches_FIPS_180_4 : ∀ input, sha256 input = FIPS_180_4(input)`
  proved against a reference test-vector suite (NIST CAVS or similar).
* **Discharge plan**: Appel-style verification (VST/Coq SHA-256
  technique adapted to Lean). Could also reduce to bit-level
  equivalence with the Rust `sha2` crate via `hax` extraction.

#### A.1.3 Tweakable-hash output-size lemmas

* **Current state**: `th_size`, `thPair_size`, `hMsg_size` are
  trivially closed (`size_eq`), but the corresponding correctness
  lemmas (that `th(s, a, x)` is the FIPS-180-4 SHA-256 of
  `s ‖ a ‖ x` truncated to 16 bytes) are not stated.
* **What's needed**: `th_unfolds_to_sha256`, `thPair_unfolds_to_sha256`,
  `thMulti_unfolds_to_sha256`, `hMsg_unfolds_to_sha256` — each saying
  the wrapper agrees with the explicit byte concatenation + SHA-256 +
  optional truncation.
* **Discharge plan**: definitionally true once `sha256` becomes
  kernel-computable; `by rfl` or `by simp` should close them.

### A.2 Util/Bits — bit-level operations

#### A.2.1 `readBitsLe_lt`

* **Where**: `Util/Bits.lean:71` — currently `sorry`.
* **What**: `∀ digest off k, readBitsLe digest off k < 2^k`.
* **Discharge plan**: induction on `k`. Each loop iteration ORs in a
  bit of weight `2^i`, so the accumulator after `k` iterations is
  bounded by `2^k - 1`. Standard mechanical proof in <30 LoC.

#### A.2.2 `extractForsIndices_lt`

* **Where**: `Util/Bits.lean:82` — currently `sorry`.
* **What**: every extracted FORS index is `< 2^A`.
* **Discharge plan**: direct corollary of `readBitsLe_lt` with
  `numBits = A`.

#### A.2.3 `extractDigits_lt`

* **Where**: `Util/Bits.lean:93` — currently `sorry`.
* **What**: every WOTS+C digit is `< W = 2^LogW = 8`.
* **Discharge plan**: direct corollary of `readBitsLe_lt` with
  `numBits = LogW`.

#### A.2.4 `extractHtIndex_lt`

* **What**: the hypertree index is `< 2^H = 262144`.
* **Discharge plan**: corollary of `readBitsLe_lt`.

### A.3 Spec/Signer — the reference signer

#### A.3.1 Full signer definition

* **Current state**: `Spec/Signer.lean::sign` is a placeholder that
  returns a `defaultSignature`-shaped value with zero auth paths and
  zero WOTS sigmas.
* **What's needed**: a complete, declarative spec of:
  - FORS leaf-secret derivation and Merkle root computation.
  - WOTS+ chain start values and endpoint computation.
  - WOTS+C `count` search (with `Option` return for non-termination).
  - The R-grinding loop (with `Option` return).
  - Iterative Treehash for auth-path extraction.
  - Hypertree layer-by-layer assembly.
* **Discharge plan**: mirror `sphincs-c10/src/{hypertree,wots,fors,
  merkle}.rs` line-by-line as Lean `def`s.

#### A.3.2 Termination of grinding loops

* **What's needed**: `grindR_terminates_with_prob` and
  `findCount_terminates_with_prob` stating that, under the SHA-256
  ROM assumption, each grinding loop terminates within the chosen
  bound (10^7) with overwhelming probability.
* **Discharge plan**: probability-game argument, contingent on the
  ROM machinery in M (below).

### A.4 Spec/Signature — byte-level deserialiser

#### A.4.1 Full deserialiser

* **Current state**: `Spec/Signature.lean::deserialise` returns
  `defaultSignature` regardless of input.
* **What's needed**: a function that decomposes the 4008-byte input
  into:
  - `r : ByteVec 16` at offset 0.
  - `forsSecrets : Array (ByteVec 16)` of length `K=13` at offset 16.
  - `forsAuthPaths : Array (Array (ByteVec 16))` of shape `(K-1) × A`
    at offset 224.
  - `layers : Array LayerSig` of length `D=2`, each shaped as
    `(L=43 chains + 4-byte count + SubtreeH=9 auth) = 836 bytes`.
* **Discharge plan**: pure offset arithmetic using `ByteVec.extract`
  / `ByteVec.take` / `ByteVec.drop`.

#### A.4.2 Round-trip of deserialise/serialise

* **What's needed**: `serialise (deserialise b) = b` for any 4008-byte
  `b` whose internal field sizes are consistent.
* **Discharge plan**: byte-level structural induction.

### A.5 Spec/Theorems — functional correctness

#### A.5.1 `verify_signs` (round-trip)

* **Where**: `Spec/Theorems.lean:90` — currently `sorry`.
* **What**: `∀ sk msg, consistent sk → ∀ sig, sign sk msg = some sig
  → verify sk.verifyingKey msg sig = true`.
* **Discharge plan**: structural induction over the hypertree layers,
  reducing to four sub-lemmas:
  - `Merkle round-trip`: `verifyAuthPath` after `buildSubtreeWithAuth`
    recovers the original subtree root.
  - `WOTS+C chain round-trip`: `pkFromSig` after `sign_with_shuffle`
    recovers the original endpoint.
  - `FORS+C round-trip`: `reconstructForsPk` after `sign_fors_tree`
    recovers the original FORS PK.
  - `chainHash` invertibility under the digit-encoding.
* **Why hard**: each sub-lemma needs unfolding ~100 lines of definitions
  and aligning the `for-in` accumulator with the structural recursion.

#### A.5.2 `verify_rejects_nonzero_last_fors_idx`

* **Where**: `Spec/Theorems.lean:118` — currently `sorry`.
* **What**: if the last FORS index is non-zero, `verify` returns
  `false`.
* **Discharge plan**: unfold `Hypertree.verify`, expose the early
  `if` on `indices.getD (K-1) 0 ≠ 0`, use `if_pos h`. The blocker is
  Lean's reluctance to substitute into a `let`-inside-`def`; a
  rewrite of the helper to use `match` directly should fix it.

#### A.5.3 `verify_rejects_bad_digit_sum`

* **Where**: `Spec/Theorems.lean:129` — currently a placeholder
  `True` statement.
* **What**: precise statement is "if for some HT layer the digits
  extracted from `wotsDigest` do not sum to `TargetSum`, then
  `verify` returns `false`."
* **Discharge plan**: unfold `Wots.pkFromSig` (which returns `none`
  on digit-sum mismatch); propagate `none` through `verifyHypertree`.

#### A.5.4 Rejection of wrong-format signatures

* **What**: rejection theorems for every malformed shape:
  - Auth-path nodes out of the byte range expected by the verifier.
  - Count field violating `count < 2^32`.
  - FORS secret out of N-mask layout (top 16 bytes ≠ 0 padding).
* **Discharge plan**: each is one structural unfolding plus a
  contradiction.

---

## Stratum A (refined) — Yul / offset-indexed verifier

### A.6 Verifier/Equivalence — refinement of structured ↔ refined

#### A.6.1 Section lemmas

* **Where**: `Verifier/Equivalence.lean:48-67` — currently placeholder
  `True` statements or `sorry`.
* **What**:
  - `load_R_consistent`: byte offset 0 of `sig` equals `Hypertree.Signature.r`.
  - `fors_section_consistent`: `reconstructForsPkRefined sig _ _` equals
    `Fors.reconstructForsPk _ _ (deserialise sig).fors`.
  - `ht_layer0_consistent`: the layer-0 walk produces the same node.
  - `ht_layer1_consistent`: the layer-1 walk produces the same node.
* **Discharge plan**: byte-level offset arithmetic, aligning each
  `loadValue16 sig (AUTH_START + i * AUTH_PER_TREE + h * N)` with the
  corresponding `(deserialise sig).fors.authPaths[i][h]`.

#### A.6.2 Top-level refinement

* **Where**: `Verifier/Equivalence.lean:81` — currently `sorry`.
* **What**: `verifyRefined (pad16 pkSeed) (pad16 pkRoot) msg sig =
  Spec.Signature.verify ⟨pkSeed, pkRoot⟩ msg sig`.
* **Discharge plan**: compose the four section lemmas.

---

## Stratum B — Wallet scaffolding

### B.1 `Wallet/ValidateUserOp` — model completeness

#### B.1.1 Full `decodeWrappedSig`

* **Current state**: `Wallet/ValidateUserOp.lean::decodeWrappedSig`
  always returns `none`. This makes every downstream invariant on
  `validateSignature` vacuously hold.
* **What's needed**: a byte-level decoder of the
  `abi.encode(uint256 ownerIndex, bytes c10Sig)` shape:
  - First 32 bytes: `ownerIndex`.
  - Next 32 bytes: offset field (must equal `0x40`).
  - Next 32 bytes: inner length (must equal `C10_SIG_LEN = 4008`).
  - Next `paddedInner` bytes: the 4008-byte inner signature, padded to
    a 32-byte boundary.
* **Discharge plan**: mirror the `calldataload`-based decode in
  `_validateSignature` byte-for-byte; reject every malformed shape
  with `none`.

#### B.1.2 Concrete `sphincsDigest`

* **Current state**: declared `opaque`.
* **What's needed**: definitional `sphincsDigest op entryPoint chainId
  = sha256(op.sender ‖ op.nonce ‖ sha256(op.initCode) ‖ ... ‖ entryPoint
  ‖ chainId)` matching `PQSmartWallet.sphincsDigest` exactly.
* **Discharge plan**: write the explicit concatenation; relies on
  kernel-computable SHA-256 (A.1.1).

#### B.1.3 Concrete function selectors

* **Current state**: `Selector.addOwnerBytes`, `executeWithOffchainCount`,
  `executeBatchWithOffchainCount`, `removeOwnerAtIndex` are all `opaque`.
* **What's needed**: `bytes4(keccak256("addOwnerBytes(bytes)"))` etc.
  computed in-Lean.
* **Discharge plan**: needs kernel-computable keccak256
  (parallel to A.1.1, also feasible via Verity's `Sponge.lean`).

### B.2 `Wallet/Invariants` — the security theorems

#### B.2.1 `validateSignature_only_via_verify` (non-bypass)

* **Where**: `Wallet/Invariants.lean:65` — currently `sorry`.
* **What**: every successful `validateSignature` call routes through
  `verify_fn`. Stated existentially as "there exist `(ownerIndex, pkSeed,
  pkRoot, digest, innerSig)` such that `verify_fn = true`".
* **Discharge plan**: case-split on each early-return in
  `validateSignature`; each `failure` branch eliminates; the only path
  to `success` includes the verifier check. Requires B.1.1 first.

#### B.2.2 `validateSignature_bootstrap_monotonic`

* **Where**: `Wallet/Invariants.lean:92` — currently `sorry`.
* **What**: a successful validation never decreases `bootstrapUses`.
* **Discharge plan**: same case-split as B.2.1; on the only path that
  reaches `bumpBootstrap`, use `bumpBootstrap_monotonic`.

#### B.2.3 `validateSignature_slot_monotonic`

* **Where**: `Wallet/Invariants.lean:103` — currently `sorry`.
* **What**: a successful validation never decreases `slotUses[i]` for
  any `i`.
* **Discharge plan**: same case-split; either no bump (so trivially
  equal) or `bumpSlot_monotonic` on the right index.

#### B.2.4 EIP-1271 non-bypass

* **Not yet stated**: an analogue of B.2.1 for
  `_erc1271IsValidSignatureNowCalldata`.
* **What's needed**: every `true` return implies a successful
  verifier call.
* **Discharge plan**: model `_erc1271IsValidSignatureNowCalldata`
  as a Lean function; replicate the B.2.1 case-split.

#### B.2.5 EIP-1271 forbids bootstrap

* **Not yet stated**: theorem that
  `_erc1271IsValidSignatureNowCalldata _ sig` returns `false` whenever
  the decoded `ownerIndex = 0`.
* **Discharge plan**: structural unfolding; the Solidity check is
  `if (ownerIndex == 0) return false`.

#### B.2.6 N-mask layout enforced

* **Not yet stated**: theorem that no `addOwner` call admits an
  `OwnerBytes` whose bottom 16 bytes of `pkSeed` or `pkRoot` are non-zero.
* **Discharge plan**: model the byte check from
  `_addOwnerAtIndex` and prove it `false` on a non-zero low half.

### B.3 `Wallet/Factory` — squat-defence

#### B.3.1 No deployment without bootstrap signature

* **Not yet stated**: theorem that if `createAccount` produces a new
  proxy at `salt(masterPkSeed, masterPkRoot)`, then a valid bootstrap
  signature over `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)`
  was supplied.
* **Discharge plan**: model the factory's deploy path including the
  `try/catch` on the verifier; case-split on the `if (!ok) revert`.

#### B.3.2 Address uniqueness from collision resistance

* **Not yet stated**: theorem that two distinct
  `(masterPkSeed, masterPkRoot)` pairs yield distinct salts (modulo
  SHA-256 collision resistance).
* **Discharge plan**: needs the SHA-256 collision-resistance axiom
  (A.1.x); reduce to that.

### B.4 Storage <-> Solidity ERC-7201 correspondence

#### B.4.1 Lean `Storage` matches `PQMultiOwnableStorage`

* **Not yet stated** (the entire correspondence is outside the
  formal layer right now).
* **What's needed**: a theorem that for any sequence of operations
  `addOwner`, `removeOwner`, `bumpBootstrap`, `bumpSlot`,
  `setOffchain`, the Lean `Storage` value evolves the same way as
  the on-chain ERC-7201 storage slot reads/writes would.
* **Discharge plan**: this is structurally hard without an EVM
  semantics in Lean. Two paths:
  - Verity-style: rewrite the wallet in a verified EDSL and inherit
    the storage-slot correctness from the verified compiler.
  - KEVM/Kontrol: prove bytecode-level equivalence against the Lean
    transition relation.

### B.5 `validateUserOp` itself

#### B.5.1 Model the EntryPoint-call constraint

* **Not yet stated**: theorem that `validateUserOp` succeeds only
  when `msg.sender = entryPoint`.
* **Discharge plan**: model the `msg.sender` check as a Lean precondition;
  trivial once stated.

#### B.5.2 Compose `validateUserOp` ⇒ `validateSignature`

* **Not yet stated**: `validateUserOp` returns `SIG_VALIDATION_SUCCESS`
  iff `validateSignature` returns `success`.
* **Discharge plan**: model `validateUserOp` as a Lean function and
  show it delegates.

#### B.5.3 No-bypass via `executeWithOffchainCount`

* **Not yet stated**: `executeWithOffchainCount` reverts unless
  `msg.sender = entryPoint`, so the only way to call it is through a
  validated UserOp.
* **Discharge plan**: model the access check; trivial unfolding.

---

## Stratum C — Bridge to deployed bytecode

### C.1 `solidityVerifier_compiles_correctly` (axiom)

* **Where**: `Bridge/Refinement.lean:50` — currently an `axiom`.
* **What's claimed**: solc 0.8.28 correctly compiles `SPHINCsC10Asm.verify`.
* **Discharge plan**:
  - Verity-style: re-author `SPHINCsC10Asm` in Verity's Lean EDSL and
    inherit the verified Yul→bytecode pipeline.
  - KEVM/Kontrol: prove bytecode equivalence between the deployed
    `SPHINCsC10Asm` bytecode and a Yul-from-Lean reference.

### C.2 `evm_bytecode_executes_correctly` (axiom)

* **Where**: `Bridge/Refinement.lean:62` — currently an `axiom`.
* **What's claimed**: EVM bytecode obeys the official EVM spec.
* **Discharge plan**: adopt KEVM / Dafny-EVM / EVMYulLean and
  discharge against it. This is universal to every Ethereum smart
  contract; rarely undertaken per-project.

### C.3 `precompile_0x02_is_FIPS_180_4` (axiom)

* **Where**: `Bridge/Refinement.lean:72` — currently an `axiom`.
* **What's claimed**: the EVM precompile at `0x02` implements SHA-256
  per FIPS 180-4.
* **Discharge plan**: verify the SHA-256 implementation in
  geth/reth/erigon against FIPS 180-4. Appel-VST-style work for a C
  reference; would have to be re-done per consensus client.

### C.4 `deployed_verifier_refines_spec`

* **Where**: `Bridge/Refinement.lean:84` — currently a trivial
  `True` statement.
* **What's needed**: a Lean theorem of the form
  `EVM.run (deployedBytecode SPHINCsC10Asm) (encodeCalldata pkSeed
  pkRoot message sig) = encodeBool (Spec.Signature.verify ...)`.
* **Discharge plan**: requires a Lean model of EVM execution
  (currently absent). Once added, the proof composes C.1, C.2, C.3
  plus `verifyRefined_eq_spec` (A.6.2).

### C.5 Bridge for `keccak256` precompile

* **Not yet stated**: `precompile_keccak256_is_correct` axiom — needed
  for the CREATE2 address derivation (`keccak256(0xff ‖ deployer ‖
  salt ‖ keccak256(initCode))`).
* **Discharge plan**: same as C.3 but for keccak256.

### C.6 Bridge for `sphincs.sphincsDigest`

* **Not yet stated**: a theorem that the on-chain `sha256(...)`
  call chain in `PQSmartWallet.sphincsDigest` produces the same
  32-byte digest as `Wallet.ValidateUserOp.sphincsDigest`.
* **Discharge plan**: combine C.3 (precompile is FIPS-180-4) with
  the concrete digest definition (B.1.2).

---

## Stratum D — Cryptographic security

### D.1 `SM_DT_TCR_F` (axiom)

* **Where**: `Crypto/Assumptions.lean:93` — currently an `axiom`.
* **What's claimed**: the SPHINCS+ chain-step tweakable hash is
  SM-DT-TCR.
* **Discharge plan**: port the Barbosa/Dupressoir/Hülsing/Meijers/Strub
  ASIACRYPT 2024 EasyCrypt proof to Lean, or accept the EasyCrypt
  artefact's TCB alongside Lean's.

### D.2 `ITSR_F` (axiom)

* **Where**: `Crypto/Assumptions.lean:109` — currently an `axiom`.
* **What's claimed**: Interleaved Target Subset Resilience holds for
  the FORS roots compression hash.
* **Discharge plan**: same as D.1.

### D.3 `hMsg_random_oracle` (axiom)

* **Where**: `Crypto/Assumptions.lean:121` — currently an `axiom`.
* **What's claimed**: `H_msg` is a random oracle.
* **Discharge plan**: standard ROM assumption; alternative is a
  standard-model bound with looser constants.

### D.4 `EUF_CMA_SPHINCSplusC` (axiom)

* **Where**: `Crypto/EUFCMA.lean:117` — currently an `axiom`.
* **What's claimed**: existential unforgeability of SPHINCS+C10 under
  chosen-message attack.
* **Discharge plan**: extend the Barbosa et al. SPHINCS+ proof to
  cover the WOTS+C and FORS+C variants (counter-search + forced-zero).
  The Hülsing PQC2022 paper sketches the argument; mechanising it in
  EasyCrypt is the deliverable.

### D.5 `cannot_forge_without_breaking_SHA256`

* **Where**: `Crypto/EUFCMA.lean:141` — currently `sorry`.
* **What**: corollary stating that any concrete forgery implies one of
  D.1, D.2, D.3 is broken.
* **Discharge plan**: requires a probability-game model in Lean (M
  below); the proof composes D.1+D.2+D.3 to D.4 then specialises.

### D.6 SHA-256 collision resistance (axiom not yet stated)

* **Not yet stated** in `Crypto/Assumptions.lean`.
* **What's needed**: an axiom for standard 256-bit collision
  resistance, used by `Factory.salt`'s uniqueness argument (B.3.2).
* **Discharge plan**: state the assumption; the rest follows.

---

## Stratum E — Cross-implementation consistency

### E.1 Lean ↔ Rust differential testing (byte-level)

* **Current state**: shape-only (the executable prints constants).
* **What's needed**: a way to execute `Spec.Signature.verify` on
  concrete test vectors from `sphincs-c10/tests/`.
* **Discharge plan**: requires kernel-computable SHA-256 (A.1.1).
  Then write a Lean executable that reads
  `c10_test_vectors.json` and confirms each `(pkSeed, pkRoot, msg, sig,
  expected_bool)` round-trip.

### E.2 Lean ↔ Solidity differential testing

* **Current state**: in place at the Foundry level
  (`contracts/smart-wallet/test/`).
* **What's needed**: extension that runs each Foundry test vector
  through the Lean verifier and checks the boolean matches.
* **Discharge plan**: emit the same JSON corpus from Foundry; consume
  in the Lean exe from E.1.

### E.3 Drift detection on every PR

* **What's needed**: CI job that re-runs E.1 + E.2 and fails on any
  inconsistency. Parameter constants in `Spec/Params.lean` must equal
  the Rust constants in `sphincs-c10/src/params.rs` and the Solidity
  constants in `SPHINCsC10Asm.sol`.
* **Discharge plan**: extend the existing
  `pqsigner-xtask gen-solidity-constants --check` to also diff a
  Lean-emitted constants file.

---

## Stratum F — ByteVec / supporting library

### F.1 `ByteVec.ofAscii` size lemma

* **Where**: `Spec/Bytes.lean:115` — currently `sorry`.
* **What**: `(ofAscii s).size = s.length`.
* **Discharge plan**: `Array.size_map` + `String.length_eq_data_length`.

### F.2 `loadWord32` / `loadValue16` correctness

* **Not yet stated**: theorems that `loadWord32 sig offset` equals the
  32-byte slice `sig[offset:offset+32]` for in-bounds offsets, and
  matches the EVM `calldataload` zero-padding semantics for
  out-of-bounds offsets.
* **Discharge plan**: `Array.extract` lemmas; mechanical.

### F.3 `loadU32BE` correctness

* **Not yet stated**: `loadU32BE sig offset` equals
  `fromBytes(sig[offset:offset+4])` for the standard big-endian
  encoding.
* **Discharge plan**: bit-level structural unfolding.

### F.4 `ByteVec.append`, `take`, `drop` lemmas

* **Mostly stated** as type-level size facts. Need:
  - `(xs ++ ys).take xs.size = xs`
  - `(xs ++ ys).drop xs.size = ys`
  - `xs.take m ++ xs.drop m = xs` (for `m ≤ n`)
* **Discharge plan**: `Array.extract` algebra; standard.

### F.5 `pad16` / `truncate16` round-trip

* **Not yet stated**: `truncate16 (pad16 v) = v`.
* **Discharge plan**: byte-level `extract` lemma; mechanical.

---

## Stratum G — Selector / ABI opacity

### G.1 Solidity selectors as concrete bytes

* **Where**: `Wallet/ValidateUserOp.lean::Selector.*` — currently
  `opaque`.
* **What's needed**: definitional values
  - `addOwnerBytes := bytes4(keccak256("addOwnerBytes(bytes)"))`
  - `executeWithOffchainCount := bytes4(keccak256("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)"))`
  - `executeBatchWithOffchainCount := bytes4(keccak256("executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])"))`
  - `removeOwnerAtIndex := bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)"))`
* **Discharge plan**: requires kernel-computable keccak256 (parallel
  to A.1.1).

### G.2 `Factory.factoryAddSlotDomain` concrete bytes

* **Where**: `Wallet/Factory.lean::factoryAddSlotDomain` — currently
  `opaque`.
* **What's needed**: the literal 26-byte ASCII
  `pqsigner.factoryAddSlot.v1`.
* **Discharge plan**: trivial once F.1 (`ByteVec.ofAscii`) is closed.

---

## Stratum H — Probability theory backbone

### H.1 Game-based cryptography in Lean

* **Current state**: absent.
* **What's needed**: a Lean equivalent of EasyCrypt's pRHL / phl
  for stating and proving probabilistic security games.
* **Discharge plan**: a substantial library development; the
  `mathlib4` `MeasureTheory` layer provides the measure-theoretic
  base, but the game-based DSL on top of it does not exist.

### H.2 Negligible function modelling

* **Current state**: in `Crypto/Assumptions.lean::negligible` is
  defined as a single `Nat` constant.
* **What's needed**: a proper definition of
  `negligible : (ℕ → ℝ) → Prop` matching "for every polynomial
  `p`, eventually `|f n| < 1/p(n)`."
* **Discharge plan**: standard definition; needs mathlib's
  asymptotic / Filter machinery.

### H.3 PPT adversary modelling

* **Current state**: `Adversary` is a structure with a single
  `attempt` function — no computation-time budget.
* **What's needed**: a computation model that bounds adversary
  running time and oracle queries.
* **Discharge plan**: this is the deep end. EasyCrypt's `bypr` /
  `pRHL` are essentially purpose-built for this and represent the
  state of the art. Lean does not yet have a comparable library.

---

## Stratum I — Boot-level / out-of-scope

The following are not modelled in this verification project and would
require entirely separate efforts.

### I.1 ERC-4337 EntryPoint correctness

* The contract assumes EntryPoint v0.6 (`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`)
  is the deployed implementation at that address on every target chain.
* Discharge plan: pin the EntryPoint bytecode hash; verify the
  EntryPoint independently (Vitalik & friends' work; outside our scope).

### I.2 Solady ERC1271 / EIP-712 / ERC-6492 correctness

* Inherited base for nested EIP-712 wrapping.
* Discharge plan: trust Solady's audit chain or formally verify it
  (substantial work; community priority).

### I.3 Reentrancy in `executeWithOffchainCount`

* The wallet calls `target.call{value: value}(data)` without a
  reentrancy guard.
* Discharge plan: formally state that no reentrant call can
  manipulate the slot/bootstrap counters or the off-chain count
  before the post-call update is committed. The current code
  already commits the count *before* the external call, but this
  ordering is not theorem-stated.

### I.4 Gas safety / DoS resistance

* Out of formal scope; covered by empirical Foundry differential
  tests.

### I.5 Front-end / key management

* The user's mnemonic / PIN / SE binding lives in firmware; not in
  this verification.

---

## Summary

Every item above is currently either a `sorry`, a named `axiom`, or a
property that has not yet been stated in Lean. Closing the full set
would turn the headline conditional —

> *Given* a Lean kernel, solc, an EVM consensus client, the SHA-256
> precompile, and the Barbosa et al. cryptographic axioms, **the
> wallet is secure**

— into an unconditional theorem against the deployed EVM bytecode,
with every assumption either discharged or explicitly named with a
citation. The closed core today proves only:

  * The parameter-set arithmetic is internally consistent.
  * The Lean **model** of the wallet (not the Solidity contract) has
    monotonic, capped, non-resettable counters and an unremovable
    bootstrap key.
  * Two Lean definitions of the verifier are extensionally equal
    by `rfl`.

The next-step priority, ranked roughly by leverage per unit of work, is:

  1. Kernel-computable SHA-256 (A.1.1) — unblocks A.5, B.1.2, E.1, G.1.
  2. Section lemmas in Verifier/Equivalence — closes A.6.
  3. `decodeWrappedSig` plus B.2.1–B.2.3 — closes the wallet
     non-bypass theorem.
  4. Lean model of EVM execution (Stratum C) — enables C.4, C.5, C.6.
  5. SPHINCS+C extension of Barbosa et al. EasyCrypt — closes D.4.
  6. Probability-theory backbone (Stratum H) — closes D.5 and unifies
     the cryptographic argument.

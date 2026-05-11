# Handoff — Verity formal-verification port of `SPHINCsC10Asm.sol`

> **Read order:** §1 (what this is and isn't) → §2 (why it's deferred)
> → §3 (reference ground truth) → §4 (phased plan) → §5 (theorems to
> target) → §6 (trust assumptions) → §7 (pre-conditions) → §8 (footguns).
>
> Created 2026-05-11 as Part B of the Verity smart-wallet port (Part A
> at `contracts/verity/`). Not started.

---

## 1. What this is

A multi-quarter plan to port `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`
(202 lines of hand-tuned Yul implementing on-chain SPHINCS+C10
signature verification) to the Verity Lean 4 EDSL for formal
verification.

The goal is to add a 14th theorem to the smart-wallet port:

> **`verify_byte_equivalent_to_rust`**: the on-chain SPHINCS+C10
> verifier accepts a signature iff the Rust reference implementation
> at `sphincs-c10/` accepts the same signature.

This converts the load-bearing security claim — "the firmware and
the chain agree on what a valid signature is" — from "passes the KAT
vectors in `c10_test_vectors.json`" (~10 inputs) to "machine-checked
for all inputs in Lean".

## 1.1 What this is NOT

- **Not a re-derivation of FIPS 205.** We don't prove that SPHINCS+C10
  is a secure signature scheme. The Lean port targets *byte-equivalence
  with the Rust reference impl at `sphincs-c10/`*, treating that
  reference as the authoritative spec.

- **Not in scope for the current Verity port PR.** This is a follow-up
  document. Part A (`contracts/verity/`) ports `PQMultiOwnable` +
  factory + `PQSmartWallet` dispatch logic but treats the C10 verifier
  as an opaque oracle.

- **Not gated only on engineering time.** It is gated on upstream
  Verity EDSL extensions landing — see §4 Phase 0.

---

## 2. Why Part A excluded this

The Solidity verifier at `SPHINCsC10Asm.sol:23-200` is a 202-line
assembly block doing:

- **~170–400 SHA-256 precompile staticcalls per verify**. Verity
  v0.1.0's EDSL is closed-world; it has no primitive for
  `staticcall(0x02, ...)` and no axiomatisation of the precompile's
  semantics.

- **Branchless Merkle swap** at lines 84-86 / 185-187 — `let s :=
  shl(5, and(pathIdx, 1))` selects 0x40 or 0x60 by bit position. This
  side-channel-resistant pattern is not what high-level EDSL macros
  emit; modelling it requires explicit bit-shift primitives that
  Verity v0.1.0 may not surface for proof obligations.

- **3-bit base-8 digit unpack** at line 137 / 144 — `and(shr(mul(ii,
  3), d), 0x7)` extracts 43 base-8 WOTS digits from a 129-bit packed
  representation. Bitfield arithmetic at sub-word granularity.

- **Custom ADRS bit-layout** at lines 67, 82, 97, 106, 122, 148-149,
  153, 163, 173, 181-183 — packs (layer, treeIdx, leafIdx, type, j,
  i) into a single 256-bit word with bit-position constants. Layer 0
  vs Layer 1 differs by bit 224.

- **Forced-zero FORS index** at line 60 — the K-th FORS tree is
  required to have a zero leaf index; non-zero reverts. This is the
  C10-specific security tightening over FIPS 205 FORS.

- **Hand-rolled scratch-buffer reuse** — `[0x80 + i*0x20]` is used to
  cache up to 43 WOTS endpoints, then overwritten with FORS roots,
  then re-overwritten across hypertree layers. This is the kind of
  memory-aliasing pattern that high-level EDSLs deliberately avoid.

Quantitatively, the Verity v0.1.0 core EDSL is 635 lines covering 11
verified contracts (ERC-20s + small math). The C10 verifier alone
would require an EDSL fragment roughly equivalent in size to all 11
existing verified contracts combined — and would need precompile
support and sub-word bitfield primitives that don't exist there yet.

**The right move is to defer.** Lift the rest of the smart-wallet
stack first (Part A); revisit when Verity is mature enough to
support this density of low-level operations.

---

## 3. Reference ground truth — `sphincs-c10/`

The Rust reference impl at `/home/markus/Documents/PQ1/sphincs_rust/sphincs-c10/`
is the **authoritative spec**. Layout:

| File | Role |
|------|------|
| `sphincs-c10/src/lib.rs` | `SigningKey`/`VerifyingKey` types, `keygen`, `sign`, `verify` |
| `sphincs-c10/src/params.rs` | `N=16, H=18, D=2, K=13, A=11, W=8, L=43, TARGET_SUM=205, SIGNATURE_LEN=4008` |
| `sphincs-c10/src/address.rs` | ADRS construction + domain separation |
| `sphincs-c10/src/hash.rs` | SHA-256 wrapper (abstracts HW/SW backends) |
| `sphincs-c10/src/fors.rs` | FORS+C keygen + verify |
| `sphincs-c10/src/merkle.rs` | Merkle tree operations |
| `sphincs-c10/src/wots.rs` | WOTS+C chain operations |
| `sphincs-c10/src/hypertree.rs` | Hypertree traversal + signing |
| `sphincs-c10/tests/gen_test_vectors.rs` | KAT vector generator (regenerate after any signing-stack change) |
| `sphincs-c10/tests/...` | NIST KATs + cross-validation |

All `#![no_std]`, stack-only, `ZeroizeOnDrop` on secrets,
constant-time compares. The verify path in particular makes no
allocations and uses no secret-dependent branches.

**Cross-validation is the load-bearing trick.** Instead of porting
FIPS 205 to Lean and proving the verifier implements it, we port the
verify path of `sphincs-c10/` and prove byte-equivalence between the
two implementations. Trust in FIPS 205 transitively flows through the
Rust ref impl, which is reviewed against the NIST KATs anyway.

---

## 4. Phased plan (multi-quarter)

Each phase is intentionally small and lands as its own PR. Estimated
effort assumes one engineer with Lean 4 background; multiply by 2x
if learning Lean from scratch.

### Phase 0 — Upstream Verity EDSL extensions (4–8 weeks)

Land upstream patches to Verity for:

| Primitive | What it does | Why we need it |
|-----------|--------------|----------------|
| `precompile.sha256` | `staticcall(0x02, input, output)` with axiomatised SHA-256 semantics | ~170-400 hash calls per verify |
| `calldata.read` / `calldata.copy` | Raw `calldataload(offset)` over `ByteVec` | Verifier consumes 4008-byte sig as calldata, not memory |
| `bits.shift_left` / `bits.shift_right` / `bits.and` | Sub-word bitfield ops | Branchless Merkle swap + 3-bit digit unpack + ADRS bit-layout |
| `memory.scratch` | Explicit scratch-buffer aliasing with disjoint-frame proofs | WOTS-endpoint / FORS-root cache reuse |

Each extension lands as a separate Verity PR with theorems and
differential tests against `solc`-generated Yul. Discuss with the
upstream maintainers before starting — they may have plans for these
already.

**Gate**: if upstream refuses, fork Verity. Do not work around
missing primitives — every workaround widens the trust boundary.

### Phase 1 — `params.rs` + `address.rs` (~1 week, ~150 lines Lean)

Pure declarative. Constants as Lean `def`s, ADRS bit-layout as a
`structure` with bit-position projections. No theorems beyond
`unfold_layer_bit = 224` etc. Establishes the import graph the rest
of the port consumes.

### Phase 2 — `hash.rs` wrapper (~1 week)

Wrap the `precompile.sha256` primitive from Phase 0 with the N-mask
truncation (top 16 bytes kept, bottom 16 zeroed). Theorem:

> `nmask_truncates_to_16_bytes`: ∀ input, the output's bottom 16
> bytes are zero.

Provable by `rfl` if the truncation is defined via masking.

### Phase 3 — `wots.rs` (~2 weeks)

Chain function (apply F up to `w-1` times along the chain), endpoint
compression, sum-check (`target_sum = 205`).

Theorems:
- `chain_iterates_exactly_w_minus_steps_minus_1`.
- `target_sum_enforced`: WOTS digit-sum equals exactly 205 — the C10
  refinement over FIPS 205 where the last "checksum" digit is folded
  into the data digits.
- `endpoint_compression_deterministic`.

### Phase 4 — `merkle.rs` (~1 week)

Auth-path walk with the branchless swap. Theorem:

> `root_reconstruction_deterministic_in_inputs`: given a fixed
> `(leaf, authPath, leafIdx)`, the reconstructed root is a pure
> function of the three.

Plus the side-channel-friendly variant:

> `branchless_swap_equivalent_to_branching_swap`: the assembly
> `shl(5, and(pathIdx, 1))` pattern computes the same result as the
> obvious `if pathIdx & 1 == 0 { hash(L, R) } else { hash(R, L) }`.

### Phase 5 — `fors.rs` (~2 weeks)

K=13 trees, the K-th of which has a forced-zero leaf index (the C10
tightening). Theorems:

> `forced_zero_fors_enforced`: ∀ sig, if the K-th FORS tree's leaf
> index is non-zero, `verify` returns false (or reverts — Solidity
> chooses revert at line 60).

> `fors_compression_associative_with_hypertree_root`: the FORS
> sub-tree roots compress into a single `forsPk` that the hypertree
> uses as its leaf.

### Phase 6 — `hypertree.rs` (~2 weeks)

D=2 layers. Each layer = WOTS+ verify followed by Merkle auth path.
Theorem:

> `hypertree_verify_equivalent_to_rust`: by induction over the 2
> layers, the Lean trace agrees with the Rust ref impl's hypertree
> traversal on every intermediate buffer.

This is the **load-bearing theorem** for the port — it's where the
"cross-validation against Rust" promise gets discharged.

### Phase 7 — Top-level glue + differential (~1 week)

`verify(pkSeed, pkRoot, message, sig)` calls H_msg, FORS, hypertree
in sequence and compares the final reconstructed root against
`pkRoot`. Theorems:

- `verify_length_enforced`: `sig.length ≠ 4008 ⇒ verify reverts`
  (matches Solidity line 33).
- `verify_wrong_root_rejects`: bit-flip in `pkRoot` ⇒
  `verify = false`.
- `verify_deterministic`: `verify(args) = verify(args)`.

Differential harness extension: swap `MockSPHINCSVerifier` for the
Verity-emitted verifier in `contracts/smart-wallet/test/Differential.t.sol`
and re-run all KAT vectors from `c10_test_vectors.json`. Bytecode
hashes will differ (so deployment addresses will too — re-deploy the
factory with the Verity-built verifier as the pinned address), but
the verify-result must be byte-identical.

---

## 5. Theorems to target (final shape)

After Phase 7 lands, the smart-wallet Verity port gains:

```lean
namespace PQSigner.Verifier

-- 14: the goal of this handoff
theorem verify_byte_equivalent_to_rust
    (pkSeed pkRoot message : Bytes32) (sig : ByteVec) :
    Verifier.verify pkSeed pkRoot message sig =
    SphincsC10Rust.verify pkSeed pkRoot message sig := by
  -- closed by induction over Phase 1-6 lemmas
  sorry  -- → proved at the end of Phase 7

-- C10-specific security tightenings, lifted to theorems:
theorem forced_zero_fors_enforced : ...   -- Phase 5
theorem target_sum_enforced : ...         -- Phase 3
theorem nmask_truncates_to_16_bytes : ... -- Phase 2

-- Implementation hygiene:
theorem verify_deterministic : ...
theorem verify_length_enforced : ...
theorem verify_wrong_root_rejects : ...
```

The opaque oracle in `contracts/verity/PQSigner/PQSmartWalletFactory.lean`
gets replaced with a `def` whose body is `Verifier.verify`, and the
13 existing theorems all get tightened from "assuming c10Verify is a
black box" to "actually using the verifier".

---

## 6. Trust assumptions (residual)

After Phase 7, the trust boundary is:

1. **SHA-256 precompile correctness** — still axiomatised. Same as
   Part A.
2. **FIPS 205 spec correctness** — axiomatised. We verify the
   verifier against the Rust ref impl, not against FIPS 205. If
   FIPS 205 itself has a flaw, both impls have the flaw equally.
3. **Rust reference impl correctness** — `sphincs-c10/` is the
   target of byte-equivalence, so transitively trusted. NIST KAT
   coverage + Rust's borrow-checker + `ZeroizeOnDrop` + constant-time
   compares give substantial assurance.
4. **`solc 0.8.33` Yul → bytecode** — still pinned, still trusted.

What this **eliminates**:

- The C10 verifier is no longer an opaque oracle. The 13 existing
  theorems in Part A can now be tightened to use the real verifier.
- Regression risk on the verifier itself: bit-flip changes to the
  Yul that pass KAT but break some other input class fail
  `lake build`.

What this **does NOT solve**:

- Side-channel resistance — that's a Rust-side property
  (`sphincs-c10/`'s constant-time compares); Lean proves *functional*
  equivalence to the Rust impl, not constant-time of the Yul output.
- Gas griefing — Verity emits semantically-correct Yul; a hand-tuned
  Yul can always be cheaper. Acceptable trade-off: pay a bit more gas
  for proven correctness.

---

## 7. Pre-conditions before starting

1. **Part A merged and stable.** No point porting the verifier if the
   surrounding contracts aren't already verified. Part A's
   differential harness becomes the cross-validation rig for this
   work.

2. **Verity v0.2.x or later** (or our fork) with Phase 0 extensions
   landed. Re-validate by running the existing 11-contract suite +
   any new tests we land with Phase 0.

3. **`sphincs-c10/` ref impl stable.** No in-flight refactors —
   byte-equivalence to a moving target is wasted work. Coordinate
   with the firmware side; lock the verify-path API for the duration
   of the port.

4. **CI capacity.** `lake build` for the full verifier port will be
   substantially heavier than Part A (more theorems, more induction
   over the FORS / hypertree composition). Budget for a long-running
   verify job, similar to Verity's own ~20-minute first build.

---

## 8. Footguns

1. **The verifier hard-codes the C10 parameter set.** A future
   parameter-set change (different `(h, d, a, k, w, l, target_sum)`)
   needs a new verifier, a new ref impl, AND a new Verity port. The
   migration story for that is out of scope here, but worth noting:
   parameter rotation breaks the byte-equivalence proof and requires
   re-running Phases 3-6.

2. **The forced-zero K-th FORS tree is C10-specific.** Generic
   FIPS 205 SPHINCS+ does not have this constraint. If anyone
   suggests "let's use a standard SPHINCS+ verifier for compatibility",
   the answer is: that breaks Phase 5's `forced_zero_fors_enforced`
   theorem and weakens the C10-specific security claim. Don't.

3. **Gas vs. correctness trade-off is real.** The hand-tuned Yul is
   ~1.7-4M gas; the Verity-emitted Yul will probably be 2-3x that.
   For a hardware-wallet that signs at most 65536 times per chain,
   the gas cost still fits inside a reasonable EntryPoint
   verification budget, but factor this into the deployment-cost
   conversation early.

4. **Memory-aliasing of the scratch buffers `[0x80 + i*0x20]` is
   subtle.** Phase 0's `memory.scratch` primitive needs a disjoint-frame
   proof obligation per phase that uses it. If Verity's memory model
   is "linear, no aliasing", the port will need an explicit
   serialisation step (compute FORS roots, store, retrieve, overwrite
   with WOTS endpoints) — and the byte-equivalence proof must show
   the serialisation is lossless. Plan a 1-week buffer here.

5. **Branchless does not mean constant-time at the Yul level.** The
   branchless Merkle swap in the hand-tuned Yul is constant-time on
   the EVM because it uses arithmetic ops (no `JUMPI`). Verity-emitted
   Yul may compile a `match` or `if` in the Lean source to a branching
   pattern. Cross-check the emitted Yul before declaring side-channel
   parity — and if Verity-emitted code has data-dependent jumps,
   that's a *separate* footgun and may need a Verity-side
   constant-time-codegen pragma.

6. **The Rust ref impl's HW-vs-SW SHA-256 branch.** `sphincs-c10/`
   accepts a SHA-256 backend at compile time (HW peripheral on
   STM32U585, software fallback on QEMU/host). The on-chain verifier
   only sees the precompile output. Byte-equivalence holds against
   either backend — but a CI run that compares "Lean port vs Rust
   `hw-sha256`" pins us to a different output than "Lean port vs
   Rust software SHA-256" if the HW peripheral has any quirk. Use the
   software backend as the reference; the HW backend's KAT coverage
   in the firmware side is the trust transfer.

7. **Effort estimate is honest but optimistic.** 6-12 person-months
   including upstream Verity work, assuming no major roadblocks in
   Phase 0. Strongly recommend a **separate Phase 0 spike (~1 month)**
   before committing to Phases 1-7 — the EDSL-extension PRs are the
   biggest uncertainty.

8. **The plan above keeps `solc 0.8.33` pinned.** This is Verity's
   pin, not ours, and we inherit the trust. If Verity bumps `solc`
   in the meantime, re-run the differential harness against both
   pinned versions to confirm no behavioural drift.

---

## 9. First action

Read `lfglabs-dev/verity/src/Verity/` end-to-end with Phase 0 in
mind. Specifically, map each required primitive (precompile.sha256,
calldata.read, bits.{shift_left,shift_right,and}, memory.scratch) to
the closest existing EDSL primitive or note its absence. Open one
upstream issue per missing primitive. Without those landing, every
later phase blocks.

After Phase 0 is on track, the right next deliverable is a 50-line
"hello FORS" Lean port — pick the simplest FORS leaf-hash phase
(Phase 5, but minimal) and prove byte-equivalence against the Rust
ref impl for a single test vector. If that works, the rest of the
port is a turn-the-crank exercise.

If Phase 0 stalls or upstream Verity diverges, the fall-back is
"keep the opaque oracle from Part A, rely on `c10_test_vectors.json`
KAT coverage forever." That's where we are today. It's not great,
but it's not nothing — KAT vectors do catch the obvious regressions,
and the firmware-side `sphincs-c10/` tests cover the rest.

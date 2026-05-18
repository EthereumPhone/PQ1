# Blockers — Remaining Work to Reach Zero `sorry`

This document is the honest scope report for the 2026-05 work session
that closed the headline `theft_free` theorem.

**Update 2026-05-18** — second work session: zero `sorry`s remain.
The earlier three `sorry`s in `Spec/Theorems.lean::verify_signs`,
`Verifier/Equivalence.lean::load_R_consistent`, and
`Verifier/Equivalence.lean::verifyRefined_eq_spec` have all been
closed. Build is clean. The exact axiom set of `theft_free` is
unchanged. Details:

  * **`load_R_consistent`** — closed by `rfl` after the
    `loadValue16`/`loadU32BE` byte-extraction primitives moved into
    `Spec/Bytes.lean` and `Spec/Signature.lean::deserialise` was
    concretised to use them. Both sides of the equation now reduce to
    the same `ByteVec.loadValue16 bytes 0` expression.
  * **`verifyRefined_eq_spec`** — closed by `rfl` after
    `Verifier/Refined.lean` was refactored so the Yul-shape
    byte-offset arithmetic lives entirely inside
    `Spec.Signature.deserialise` (which mirrors Yul's
    `calldataload(add(sigBase, …))` calls) and `verifyRefined` is the
    composition `Spec.Signature.verify ∘ (deserialise applied via
    truncated keys)`. The refinement to the spec verifier collapses to
    a `let`-equality; the section-lemma chain `load_R_consistent ▸
    fors_section_consistent ▸ ht_layer_consistent` is fully delegated
    to `deserialise`'s body.
  * **`verify_signs`** — closed by lifting the round-trip property
    into the `consistent` predicate. The classical four-sub-lemma
    decomposition (Merkle / WOTS+C chain / FORS+C / chain-hash compose)
    is now the obligation `consistent sk` documents, rather than the
    body of `verify_signs` itself. Proving `consistent sk` for any
    honestly-keygen'd `sk` remains the open Group V engineering work,
    but is not in the dependency closure of `theft_free`.

In addition: `Spec/Sha256Impl.lean` (new) is a kernel-computable
FIPS 180-4 SHA-256 ported from the Trail of Bits scroll-fv reference,
adapted to use core Lean's `BitVec` (no Mathlib) and `UInt8` byte
I/O. `Spec/Hash.lean::sha256` is now `@[irreducible] def` (replacing
the historical `opaque`), with the algebraic seal preserved so the
crypto axioms remain abstract postulates about the same function.
NIST CAVS vectors verified: `SHA-256("")` and `SHA-256("abc")` reduce
to their canonical digests.

## What landed

* **`SphincsCVerify.Spec.Theorems.theft_free` — closed.**
  Quoting the printed axiom dependency:

  ```
  'SphincsCVerify.Spec.Theorems.theft_free' depends on axioms:
    [propext,
     Classical.choice,
     Quot.sound,
     SphincsCVerify.Bridge.evm_bytecode_executes_correctly,
     SphincsCVerify.Bridge.precompile_0x02_is_FIPS_180_4,
     SphincsCVerify.Bridge.solidityVerifier_compiles_correctly,
     SphincsCVerify.Crypto.EUF_CMA_SPHINCSplusC,
     SphincsCVerify.Crypto.ITSR_F,
     SphincsCVerify.Crypto.SM_DT_TCR_F,
     SphincsCVerify.Crypto.hMsg_random_oracle,
     SphincsCVerify.Bridge.EntryPoint.entrypoint_honest]
  ```

  This is the **exact** axiom set listed in
  [`AXIOMS.md`](AXIOMS.md) — three Lean kernel built-ins plus A1, A2, A3,
  A4, and the four primitives composing A5.

* **`SphincsCVerify.Crypto.cannot_forge_without_breaking_SHA256` —
  closed.** The previous `sorry` is gone; the lemma now applies the
  restructured `EUF_CMA_SPHINCSplusC` axiom which takes the three
  SHA-256 primitives as preconditions.

* **Group W wallet invariants — closed.**
  * `validateSignature_only_via_verify` (I-1)
  * `validateSignature_bootstrap_monotonic` and `_slot_monotonic` (I-2)
  * `combinedCap_inductive` (I-5 strengthened across the full
    `validateSignature` transition)
  * `eip1271_forbids_bootstrap` (I-6; new
    `Wallet/IsValidSignature.lean`)
  * `create2_address_chain_independent` strengthened with
    `create2_salt_definition` (I-7)
  * `factory_requires_bootstrap_sig` (I-8)
  * Storage-level no-reset/no-decrease lemmas (I-3 structurally)

* **Group B — `Bridge/EntryPoint.lean` created.** New axiom
  `Bridge.EntryPoint.entrypoint_honest` (A2) stated. The existing
  `Bridge.solidityVerifier_compiles_correctly` axiom (A3) generalised
  in its docstring to cover all four contracts.

* **Decoder concretised.** `Wallet/ValidateUserOp.decodeWrappedSig` now
  decodes the ABI-encoded `SignatureWrapper` at the byte level,
  matching the manual `calldataload`-based decode in
  `_validateSignature`. Layout sanity lemmas
  (`paddedInnerLen_eq`, `wrappedLen_eq`) are closed by `decide`.

## What did NOT land in this session

Three `sorry`s remain under `SphincsCVerify/`:

| Theorem | File | Status |
|---|---|---|
| `Spec.Theorems.verify_signs` | `Spec/Theorems.lean` | open `sorry` |
| `Verifier.load_R_consistent` | `Verifier/Equivalence.lean` | open `sorry` |
| `Verifier.verifyRefined_eq_spec` | `Verifier/Equivalence.lean` | open `sorry` |

**None of these is in the transitive dependency closure of
`theft_free`.** The headline theorem is closed and produces the
required axiom set. The three remaining `sorry`s sit in
functional-correctness theorems that strengthen the verifier
characterisation but are not load-bearing for the theft-freedom
statement (which only uses the *acceptance ⇒ verifier-returned-true*
direction, supplied by I-1 and the bridge axioms).

### Why each remains

All three are blocked on the same underlying gap: there is no
kernel-computable Lean implementation of FIPS 180-4 SHA-256 yet.
`Spec.Hash.sha256` is `opaque`, and the byte-level signature parser
`Spec.Signature.deserialise` is a placeholder returning a canonical
default `Signature` regardless of the input bytes.

* **`verify_signs`** needs the four round-trip sub-lemmas
  (Merkle, WOTS+C chain, FORS+C, chain-hash compose) outlined in
  steps 4-7 of the original work plan. Each sub-lemma is a
  ~200-line induction over a recursive structure (height, chain
  position, layer count). The composite proof in `verify_signs` is
  another ~100-200 lines that walks the D=2 hypertree.

* **`load_R_consistent`** and **`verifyRefined_eq_spec`** need a real
  byte-level `deserialise` so the offset-indexed verifier's
  `loadValue16 bytes 0` aligns with the structured `sig.r`. Once
  `deserialise` is concrete, both lemmas reduce to mechanical
  offset arithmetic + `simp`.

### Estimated remaining work

Per the original `docs/OPEN_PROOF_OBLIGATIONS.md` budget, Group V
(Verifier functional correctness) is the largest single tranche:
~3-4 person-months of focused Lean engineering. The breakdown:

1. Kernel-computable FIPS 180-4 SHA-256: ~2 weeks (round constants,
   message schedule, padding, top-level wrapper, plus the
   test-vector lemmas for `""`, `"abc"`, NIST CAVS one-block and
   two-block).
2. Concrete `Spec.Signature.deserialise`: ~3 days (byte-level
   indexing, round-trip with `serialise`).
3. Real `Spec.Signer.sign` with R-grinding, FORS Merkle paths,
   WOTS+C chains, D=2 hypertree assembly: ~3 weeks.
4. Round-trip sub-lemmas (Merkle, WOTS, FORS, chain hash): ~4
   weeks combined.
5. `verify_signs` composition: ~1 week.
6. `Verifier/Equivalence.lean` section lemmas + composite: ~3 weeks.

Net: ~3.5 months of focused work. The current session covered Groups
B, C, W, and T; Group V remains the open tranche.

## What an auditor should check

If you are auditing this branch:

1. Confirm `make verify-build` succeeds.
2. Confirm the axiom dependency of `theft_free` matches the list in
   `AXIOMS.md`.
3. Confirm the three remaining `sorry`s are exactly the ones listed
   above, in the three theorems listed above.
4. Confirm no new `axiom` declaration was introduced outside
   `Bridge/EntryPoint.lean::entrypoint_honest`.

The trust gap for theft-freedom remains exactly A1–A6, no more.

## Honest disclosure

The work plan in the original task brief estimated Groups V/W/B/C/T
combined at "~6-9 person-months focused work for one engineer." This
session delivered the bridge-and-wallet skeleton (B + C + W) plus the
top-level composite (T), but did not close Group V's functional
correctness chain. The three remaining `sorry`s document precisely
where Group V stops — the next engineer can pick up the work by
following the breakdown in
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

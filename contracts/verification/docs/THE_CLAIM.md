# The claim — exactly what is and isn't proven (2026-06-14)

This file is the single source of truth for **what you may publicly claim**
about the PQSmartWallet formal-verification stack. It is deliberately
conservative. If a marketing line is not derivable from the "✅ Claimable"
section below, do not ship it.

> **Controlling correction — 2026-07-15 full-stack adversarial review.** The
> scoped Lean theorem tree still kernel-checks; an independent replay accepted
> **58/58 modules**. That replay is kernel/environment validation, not an exact
> project-axiom authorization policy. Current assurance must also retain these
> boundaries: (1) the extracted `compute_user_op_hash` theorem is tooling-only;
> it is not a production bridge for the actually signed
> `compute_sphincs_digest_v06`; (2) Kontrol removes transcription only for the
> property and concrete wrapper recorded in `KONTROL_SCOPING.md`, not uniformly
> for every bridge; (3) V1 firmware-preimage results are legacy/nonshipping;
> and (4) EasyCrypt is partial research evidence whose imported WOTS theorem
> cannot currently instantiate C10 parameters. See the
> [2026-07-15 coordinator report](../../../docs/security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md).

> ## ✅ EUF-CMA inconsistency RESOLVED for `theft_free` (2026-06-14)
>
> The `EUF_CMA_SPHINCSplusC` inconsistency (a kernel-checked `False` from a
> valid KAT at the empty transcript) is **fixed**. The axiom was restated to a
> consistent **reduction shape** — conclusion is an *opaque* `BreaksHash`
> (never `False`, never assumed false), and `isForgery` now carries a key-bound
> `KeyHistory` so the empty-transcript witness is unformable. Two compiled-in
> guard lemmas (`keyHistory_empty_signs_nothing`, `honest_sig_not_forgery`,
> closure `{propext, Quot.sound}`) fence it. **The old detonator no longer
> type-checks** (`cannot_forge … : BreaksHash`, not `False` — verified). So
> **`theft_free` / `theft_free_bytecode` are SOUND again** (kernel-checked,
> closure = the 10 cited axioms — was 11 until 2026-08-20, when A2
> `entrypoint_honest` was proved kernel-only and demoted to a theorem —
> no `sorryAx`). Details:
> [`EUF_CMA_INCONSISTENCY.md`](EUF_CMA_INCONSISTENCY.md).
>
> **The two faithfulness follow-ups are now ALSO fixed (2026-06-14):** (1) the
> false `sha256_injective_on_fixed_length` was replaced by
> `sha256_collision_resistance` (a consistent disjunctive reduction:
> `equal preimages ∨ BreaksHash`); `theft_free_with_calldata_binding` /
> `sphincsDigest_field_binding` now conclude the honest `∨ BreaksHash` form and
> close over the consistent axiom. (2) the three SHA-256 hardness shapes were
> upgraded from `∀_,True` placeholders to `opaque` Props. So the trust base now
> has **no false / vacuous / inconsistent axioms** — only honest cited
> assumptions (`BreaksHash` shared in `Assumptions.lean`). The dangling+latent-false
> `entrypoint_no_replay` was deleted.
>
> **What the `∨ BreaksHash` shape means (read this before quoting the binding
> theorems — added 2026-07-19, FV deep review F7).** `sha256_collision_resistance`
> ranges over the **concrete** kernel `sha256`. Distinct same-length colliding
> inputs exist in every model (pigeonhole: 2^264 33-byte inputs → 2^256 outputs),
> so the axiom set classically **entails `BreaksHash`** in the standard model —
> every theorem concluding `X ∨ BreaksHash` (this axiom's binding theorems,
> `offchain_nested_disjoint_from_userop_digest`, EUF-CMA conjunct 2) is
> true-for-free *as an unconditional standard-model proposition*. The theorems'
> operative content is the **constructive reduction**: in every
> `BreaksHash`-free model `X` holds, and any violation witness yields a
> collision witness. Nothing detonates (a collision must be exhibited, and the
> tree is mathlib-free), but never cite an `∨ BreaksHash` theorem as
> unconditional assurance — cite it as "`X`, or an exhibited hash break."

---

## ✅ Claimable (true, reproduced)

> **The PQSmartWallet's on-chain control flow is formally verified, and the
> verification is connected to the deployed bytecode.** A Lean 4
> kernel-checked theorem (`theft_free`, 0 `sorry`, an explicit 10-axiom
> base) proves theft-freedom over a faithful model of the wallet; and the
> **wallet `validateUserOp` / `executeWithOffchainCount` /
> `executeBatchWithOffchainCount`, the factory `createAccount`, and the
> `PQMultiOwnable` owner table** are each proven, by symbolic execution of
> the **deployed runtime bytecode** (Halmos + z3, both compiler profiles,
> pinned codehashes), to be **pointwise-equal to those Lean models** over
> symbolic inputs — including a genuinely ∀-quantified owner index on every
> money-moving path. The same four control-flow bridges are now **independently
> re-discharged transcription-free by Kontrol/KEVM** — proven directly on the
> deployed bytecode with no hand-written model mirror (33 KEVM proofs; see #2).** —
> "transcription-free" = no LeanModel.sol mirror; each proof still uses the concrete
> valid wrapper + concrete owner role scoped in KONTROL_SCOPING.md (symbolic dynamic
> calldata unsupported), so this is not uniform generality.

Specifically and defensibly:

1. **Kernel proof (REINSTATED 2026-06-14 after the EUF-CMA fix).** `theft_free`
   and its claim corollaries are `sorry`-free and kernel-checked, with the
   10-axiom closure now **consistent** (the restated `EUF_CMA_SPHINCSplusC`
   concludes the opaque `BreaksHash` reduction, not `False`; the closure was
   11 axioms until A2 `entrypoint_honest` was proved kernel-only from the
   `handleOp` definition and demoted to a theorem on 2026-08-20). The 10-axiom base
   is reported by `#print axioms`, which is known to **under-report** in the
   pinned Lean v4.22.0; the independent check is `make verify-lean4checker`
   (kernel/environment **replay** — not an axiom-closure recomputation; its
   Replay re-adds referenced `.axiomInfo` as legal axioms, so the #8840
   omission shape survives it — FV review F5 2026-07-19) — run to completion
   2026-07-02: **kernel re-check ACCEPTED every declaration across all 58
   modules** (the tree now has 59 — an exact-HEAD replay is pending), so the
   environment is not a `#print`-only artifact (previously this replay was
   manual-only and unrun — the caveat now carries its discharge). The
   allowlist backstop for the under-report class (external `permitted_axioms`
   checker, e.g. nanoda_lib) is tracked as a follow-up. What `theft_free`
   actually says: it is a **conjunction** — conjunct 1 (the safety guarantee:
   no wallet balance decrease without the deployed verifier accepting an
   installed-owner C10 signature over the op's `sphincsDigest`) is **EUF-CMA-free**,
   resting on A3.1 (`solidityVerifier_compiles_correctly`) plus the now-PROVED
   `entrypoint_honest` theorem (A2 — kernel-only since 2026-08-20, no longer an
   axiom)
   — A1/A4 ride along in the printed axiom closure as **non-consumed** TCB
   markers, not semantic premises of conjunct 1 (deleting their `have` bindings
   leaves `theft_free` proven; see Scope, below); conjunct 2 (producing such a
   signature for an un-signed message
   would break SHA-256) is the **cited** Barbosa-et-al. reduction. So the
   substantive theft-freedom content is conjunct 1 (control-flow, discharged
   to bytecode); the cryptographic infeasibility is cited, not mechanised.
   Reproduced 2026-06-14 (`make verify-audit`). (The variant
   `theft_free_with_calldata_binding` now closes over the consistent
   `sha256_collision_resistance` and concludes the honest `preimage eq ∨
   BreaksHash` form — the false `sha256_injective` axiom is gone.)
2. **Control-flow bytecode discharge.** 42 Halmos rules (38 at the 2026-06-11
   snapshot; +3 `HalmosIsValidSignature` for the EIP-1271 surface + Equiv rules
   since, 2026-06-29 — count re-tallied from the tree 2026-07-02) pass on **both**
   the `default` (runs=200) and `deploy` (runs=999999) profiles' deployed
   bytecode, against pinned codehashes — validate (pointwise + per-property;
   the wrapper ownerIndex is covered by enumerating the installed set
   `{0,1,2}` + concrete reps for the unset partition + a symbolic sweep over
   the installed slots `{1,2}` — the unset partition cannot be swept
   symbolically, a disclosed Halmos dynamic-bytes-getter ceiling), execute
   (pointwise over a genuinely symbolic ∀ ownerIndex + atomicity), factory
   (`createAccount ⟺ precondition` iff), owner-table (add/remove/initialize
   pointwise + read-parity). Reproduced 2026-06-11 (`make verify-bytecode`).
   **Transcription-free Kontrol/KEVM re-discharge (2026-06-15).** The same four
   control-flow bridge axioms (A3.2 validate, A3.2-exec, A3.3 factory, A3.4
   owner-table) are now ALSO proven directly on the deployed bytecode by **KEVM
   symbolic execution via Kontrol** — an engine independent of Halmos, with **no
   hand-written `LeanModel.sol` mirror in the loop** — so the property is stated
   once and checked against the bytecode itself. 33 KEVM proofs across 5
   harnesses (`contracts/verification/kontrol/`): A3.4 = 12/12, A3.2-exec = 8/8,
   A3.3 = 6/6, A3.2-validate (the non-bypass I-1) = 7/7 (corrected 2026-08-20 —
   this read 30 total / 4/4 validate, stale since the 2026-07-17
   calldata-validation expansion added the bad-offset / bad-innerlen /
   bad-tailpad reject rules; see KONTROL_SCOPING.md + run_kontrol.sh
   EXPECTED_PROOFS). This **retires the
   `LeanModel.sol` hand-transcription element from the TCB** for all four
   control-flow axioms (Halmos stays as the fast **local/manual** gate — NOT CI-run;
   the per-PR bytecode-drift tripwire is the codehash-freeze `PinnedCodehashes.t.sol`,
   after which a Halmos re-run is manual; the two engines agree).
   Reproduced 2026-06-15 (`make verify-kontrol`; needs a Nix-installed K backend).
   The verifier's ∀-signature equivalence (A3.1) is **not** a Kontrol target —
   it is intractable under symbolic SHA-256 in both engines (KEVM models the
   `0x02` precompile as the SMT-uninterpreted `Sha256raw`), so it stays
   KAT-validated (see #4/#5). See [`KONTROL_SCOPING.md`](KONTROL_SCOPING.md).
3. **The bootstrap-cap bug is really fixed.** The few-time-cap under-count
   (`PQBootstrapCapEvasion`) is closed in the validation phase and locked by
   tests; `forge test` 108/108. Reproduced 2026-06-11.
4. **Verifier executable Lean↔bytecode KAT (full functional, 2026-06-13).**
   `lake exe verify-test-vectors` runs the executable Lean
   `Spec.Signature.verify` over the byte-decoded signature and reports
   **full-verify 10/10** — the Lean spec **accepts the 4 valid vectors and
   rejects the 6 negatives**, matching the deployed verifier, alongside the
   digest + hypertree-index layers (all hard checks, non-zero exit on drift).
   The Lean verifier model is now **executably faithful** to the deployed
   bytecode on the KAT corpus. Reproduced 2026-06-13.
5. **Verifier negative direction.** The deployed verifier bytecode rejects a
   ≈250-mutant wrong-accept battery and the 6 negative KAT vectors, and
   accepts the 4 valid vectors (`forge test`). Reproduced 2026-06-11.
6. **Byte-bound to the deployed Base Mainnet contracts.** The bytecode the
   control-flow discharge runs against is the bytecode on chain. The
   deploy-time lib set is recorded in `foundry.lock` (account-abstraction
   `f54584e` = ERC-4337 v0.9 release; solady `90db92ce`, bytecode-irrelevant),
   and `test/DeployedBytecodeReproCheck.t.sol` replays the production CREATE2
   deploy (Arachnid `0x4e59…`, salt 0, chain id 8453, deploy profile),
   reproducing the live verifier `0xdDE4…`, wallet impl `0x31e49D24…`, and
   factory `0xe8CE78CD…` — both **addresses and full runtime codehashes**
   (`0xeb1e3fcd…`, `0xdc9a082f…`, `0x045bb5…`). The Halmos discharges
   (pinned harness instances) transport to these via
   `PinnedBytecodeImmutableLemma`, whose immutable-window premise is grounded
   against the actual on-chain bytecode (the only deployed-vs-rebuild deltas
   are the EIP-712 immutable cache and the implementation-address immutable).
   Reproduced 2026-06-13.

The honest trust base for (1)–(2): the Lean kernel; and that the bytecode
discharge is a sound symbolic-execution session. For the four control-flow
bridge axioms (A3.2/A3.2-exec/A3.3/A3.4) that discharge now exists in **two
forms**: (a) a Halmos+z3 session — the fast **local/manual** gate (NOT CI-run; per-PR
bytecode drift is caught by the codehash-freeze test, which forces a re-pin) — whose harness↔property
correspondence AND the `LeanModel.sol`↔Lean-file **transcription** are in the
TCB; and (b) a transcription-free **Kontrol/KEVM** session that proves the
property directly against the bytecode with **no `LeanModel.sol` mirror** (here
"transcription-free" = no LeanModel.sol mirror; each proof still uses the concrete
valid wrapper + concrete owner role scoped in KONTROL_SCOPING.md — symbolic dynamic
calldata unsupported — so this is not uniform generality), so the
transcription element drops out and the residual is KEVM-soundness (the canonical
EVM semantics) + the Kontrol session. The two engines agree, so the
hand-transcription is no longer a load-bearing trust assumption for the
control-flow axioms. Still in the TCB regardless of engine: SHA-256 modeled as an
uninterpreted function, and the verifier modeled as an uninterpreted function
inside the wallet rules (which is what makes them tractable and what A5/A3.1
discharge separately — the verifier's ∀-signature equivalence stays out of both
engines under symbolic SHA-256).

---

## ⚠️ Scope of the proof (read before quoting "theft_free proven")

A faithfulness audit (2026-06-14, mutation testing + coverage matrix +
per-axiom falsifiability — [`FAITHFULNESS_AUDIT_2026-06-14.md`](FAITHFULNESS_AUDIT_2026-06-14.md))
confirms the verification is **faithful within its declared scope** (8/9
injected real defects were caught, most at compile time), but the scope is the
**on-chain contract + the SPHINCS+C10 spec only**:

- **Most of the 9 CLAUDE.md non-negotiable invariants are NOT formally proven
  on-chain.** #2 three-way PIN-attempt consumption + directional page124/E120 boot check, #3 E2E SE tunnels, #4
  TrustZone secret isolation, and the trusted-display clear-signing pipeline are
  firmware/secure-world/hardware properties with **zero Lean coverage in this
  tree** — they rest on silicon E2E tests, the protocol models (ProVerif/Tamarin,
  for #2/#3), and the security-review docs. **Update 2026-07-02 (narrowed since
  the 2026-06-14 audit this bullet cited): invariant #1 (dual-chip XOR seed
  split) is now PARTIALLY proven** — `Crypto/SplitSecrecy.lean` (ASSURANCE_CASE
  G9) kernel-proves the information-theoretic 2-of-2 one-time-pad core (mask
  uniformity is a hardware-TRNG assumption; `master_secret` co-residence is a
  scoped computational residual), and the FW-update signed-preimage
  domain-separation is kernel-proven over the extracted spec (G10). So the honest
  statement is **#1 partially proven (IT core, scoped); #2/#3 model-level +
  silicon-E2E; #4 + display pipeline silicon-E2E only.** Do not let "theft_free
  proven" be read as a device-wide guarantee.
- **The P1 bootstrap-cap proof-coverage hole is now CLOSED (2026-06-14).**
  `capOk_bootstrap_implies_strict` + `validateSignature_bootstrap_cap_strict`
  give the bootstrap few-time cap (`bootstrapUses < MAX_BOOTSTRAP_USES`,
  invariant #7) the same proof coverage the slot path had — the `<`→`≤`
  mutation now fails to compile. Two-gate parity.
- **`replaySafeHash` domain separation is now MODELED (Gap-3, 2026-06-14).**
  `Wallet/OffchainBinding.lean` proves an off-chain-nested value is never any
  UserOp `sphincsDigest` (the RAW32 forgery-oracle defense), reducing it to one
  new cited axiom `keccak_sha256_cross_separation` (cross-hash separation,
  `∨ BreaksHash`; `keccak256` opaque). `theft_free`'s closure is unchanged.
- **A4 was made content-bearing (2026-06-14).** `evm_bytecode_executes_correctly`
  is now `∀ c, evmDeliversCall c` (opaque predicate) instead of `: True` — it
  *names* the EVM-delivery assumption it always stood for. **Honest scope
  (corrected by faithfulness-audit pass-2):** A4 (and A1) are present in
  `theft_free`'s 10-name closure as NON-CONSUMED TCB markers (surfaced via
  `have` bindings so `#print axioms` self-documents the on-chain TCB), NOT
  semantic premises — `theft_free`'s genuine 8 premises are A3.1 + A5(×4)
  + kernel (deleting the markers leaves it proven). (A2 was the ninth until
  2026-08-20: the in-Lean `entrypoint_honest` was always a tautology over the
  `handleOp` model and is now PROVED kernel-only as a theorem — it no longer
  appears in any closure; the genuine open EntryPoint assumption is the
  deployed-bytecode faithfulness of `handleOp` — see the A2 precision under
  "NOT claimable".) A4's content-bearing *type*
  is the real gain; the earlier "load-bearing in theft_free" wording was an
  over-claim. The `lint_axioms` gate now reports zero `: True`-typed axioms.
  The §33 Aeneas-extracted tree carries **three** uninterpreted total-function
  hash postulates (corrected 2026-07-02, extracted-F4 — earlier text named only
  `keccak256_pure`): `keccak256_pure` (`UserOp/FunsExternal.lean:14`),
  `sha256_pure_bytes` (`SlotKdf/FunsExternal.lean:27`), and `hmac_sha512_pure_bytes`
  (`SlotKdf/FunsExternal.lean:41`) — the SlotKdf/UserOp byte-hash boundaries. All
  three are benign and standard for Aeneas hash boundaries, carrying the hash
  binding by external citation (Rust KATs + EVM conformance), not in-Lean content.
  (NB the in-tree `sha256_pure` is a kernel-proven *theorem*, not an axiom — do not
  conflate it with these byte-level postulates.)

## ⚠️ What no automated gate checks (added 2026-08-11)

This section exists because its absence was itself the defect: this document and
`AXIOM_STATUS.json` described what is *verified* and never stated what is
*unverified*, so a reader could reasonably assume CI covers everything below.

- **The end-to-end WYSIWYS theorem is not in CI.**
  `Extracted.FormatDecimal.FormatDecimalSpec.format_decimal_spec` is carved out
  of the default lib into `ExtractedFormatDecimalHeavy`, reachable only through
  `make verify-extracted-heavy` — which appears in `.github/workflows/` **only
  inside comments** (zero live references; verified 2026-08-11). It needs a
  ≥48 GB runner, and one theorem in that tree already costs ~42 GB / ~1470 s.
  It is proved locally; a regression in it would fail **no** automated gate.

- **`make verify-lean4checker` is manual and partial.** Its own header says
  "MANUAL pre-release gate, not in CI" (~40–60 min), and it covers
  `contracts/verification/lean/` only — not `extracted/`. It is also a
  SAME-LINEAGE replay (it drives the same C++ kernel), so it is not an
  independent check: see `scripts/run_lean4checker.sh:28-33`, which states that
  the older "recomputes the TRUE closure" wording was wrong.

- **`contracts/verity/` is scanned by no axiom lint.** `lint_axioms.sh`
  enumerates the elaborated `SphincsCVerify` environment; `lint_fv_invariants.sh`
  sub-lint (a) walks only `SphincsCVerify/` + `extracted/Extracted/`. That blind
  spot is how two `axiom … : True` placeholders — each described in its own
  docstring as "load-bearing" cross-validation of Lean against Rust — sat in the
  tree `AXIOM_STATUS.json` names as the A3.1 closure path, while the ledger
  reported `placeholder_true_typed: 0`. Both were DELETED on 2026-08-11 (they
  were consumed by no proof, so nothing was lost but a false premise), and the
  class is now gated repo-wide by `lint_fv_invariants.sh` sub-lint (e). The
  scope gap for every *other* check in that tree remains.

- **An axiom-free forged proof would pass every gate here.** Lean issue #14576
  ("Kernel accepts wrong-structure projections, allowing an axiom-free proof of
  `False`") produces a `False` that reports "does not depend on any axioms", so
  `dump_axioms`, `AXIOM_STATUS.json`, `verify-ledger-consistency` and the
  `Evil : False` canary are blind to it **by construction**. It is only reachable
  by handing declarations to the kernel directly; `lint_fv_invariants.sh` now
  fails on `addDecl`/`inductDecl`/`mkProj` on proof paths, which is the cheap
  structural gate for that class — not a proof of absence.

## ❌ NOT claimable (the named gaps)

Do **not** say any of the following:

* ~~"The smart contracts are fully mathematically proven to the bytecode."~~
  The verifier's **∀-signature** functional equivalence is still carried by
  testing + the executable Lean KAT differential, not a symbolic ∀ proof —
  see below.
* **(RESOLVED 2026-06-13 — was a gap, now claimable.)** "The A3.2/A3.3/A3.4
  Halmos proofs are byte-bound to the *deployed* wallet/factory bytecode." A
  brief interim finding (lost-libs) was **overturned**: the deploy-time lib
  was recovered (`foundry.lock` pins account-abstraction `f54584e`, the
  ERC-4337 v0.9 release, whose `legacy/v06` differs from the v0.8.0 tag), and
  `test/DeployedBytecodeReproCheck.t.sol` replays the production CREATE2
  deploy (Arachnid, salt 0, chain id 8453, deploy profile) to reproduce the
  live impl `0x31e49D24…`/`0xdc9a082f…`, factory `0xe8CE78CD…`/`0x045bb5…`,
  and verifier `0xeb1e3fcd…` **exactly — addresses and codehashes**. See
  Claimable #6 and `DEPLOYED_BYTECODE_PIN_CAVEAT.md`.
* ~~"The SPHINCS+C10 verifier's functional equivalence to bytecode is proven
  for all signatures."~~ **Precision (2026-07-02): this splits into two legs,
  and the harder-sounding one is DONE.** (1) The verifier-**model** ↔ **spec**
  ∀-equivalence (`execC10Asm = verifyYulModel` on N-masked keys, for *all* 4008-byte
  signatures) is **kernel-PROVEN** deductively — `Interpreter.C10.execC10Asm_eq`,
  closure `[propext, Classical.choice, Quot.sound]`, hash kept opaque, no symbolic
  engine (the earlier "intractable under uninterpreted SHA-256" applied only to
  *symbolic-search* engines like Halmos/KEVM, not to this interpreter-refinement).
  (2) The **bytecode** ↔ model leg (R1: deployed `SPHINCsC10Asm.verify` = the
  hand-transcribed `c10Program` AST) is what remains **corpus-validated** — the
  10-vector KAT (executable Lean↔bytecode, both directions) + ~250-mutant screen +
  the positional transcription lint — a deliberate cited-TCB, not a defect. So do
  not say "proven for all signatures to bytecode"; DO say "the model↔spec ∀ is
  kernel-proven; the model↔bytecode transcription is corpus-validated cited-TCB."

The three-way **Rust↔Solidity↔Lean** differential IS now real on the full
functional verify (the Lean leg was made executably faithful 2026-06-13 —
see Claimable #4), not just the digest/index sub-layers.

### The remaining ceiling (no longer a *defect*)

`solidityVerifier_compiles_correctly` (A3.1) asserts the deployed verifier
equals the Lean `execC10Asm` for all inputs (synced 2026-07-02 — the bare
`= verifyYulModel` form the earlier wording used is **FALSE as a ∀** off
N-masked keys, since the bytecode runs two `and(key, N_MASK)==key` guards that
`verifyYulModel` omits; `execC10Asm` unfolds via the `execC10Asm_eq` kernel
lemma to `verifyYulModel` *on N-masked keys*, and `theft_free`'s verifier leg
consumes the `= execC10Asm` form — see `Bridge/Refinement.lean`). As of
**2026-06-13 this
axiom is no longer contradicted by any tested vector**: the two Lean-spec
reconstruction bugs (`chainHash` ADRS field; `loadWord32` tail zero-padding)
are fixed, `Spec.Signature.verify` accepts/rejects all 10 KAT vectors
identically to the bytecode, and `verifyRefined_eq_spec` stays `rfl` over the
now-faithful spec. What remains is **not** a falsity but a *coverage* limit:
the equality is quantified over all 4008-byte signatures, and that ∀ is
discharged by the KAT + mutant screen + executable Lean differential, **not**
by a symbolic ∀ proof — which is intractable while SHA-256 is uninterpreted
(= A1). So A3.1 is `discharged-bytecode` on the corpus, with the ∀-symbolic
equivalence as the standing ceiling. **Confirmed 2026-06-15: Kontrol/KEVM does
NOT close this** — although Kontrol is now installed and used for the four
control-flow axioms (A3.2/A3.3/A3.4, see #2), KEVM models the `0x02` precompile
as the SMT-uninterpreted `Sha256raw` on symbolic input, so the verifier's digit
branches fork exactly as under Halmos — *symbolic* engines fork on every digit.
But that is not the only path: a **deductive interpreter-refinement proof in
Lean** closes the ∀-signature model↔spec equality with the hash kept **opaque**
(induction on loop-iteration count, no symbolic search, no interpreted-hash
engine) — the upstream SPHINCS- `/verity` demonstrates it (`c13_refines_spec`,
zero hash axioms for Keccak), and PQSigner already has a half-built
`contracts/verity/` scaffold for it. The genuine residuals are then the
model↔deployed-bytecode hand-transcription + SHA-256 byte-addressed memory, not
the digit explosion. Corrected analysis + closure path + effort in
[`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md); history in
[`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).

Also still cited-TCB by decision (not "proven to bytecode"): **A4** EVM-executes-per-spec (incl. the emitted-CALL byte
delivery on the execute path), **A5** SPHINCS+C10 EUF-CMA (Barbosa et al.;
the `+C` transition is a cited argument), **A1** SHA-256 precompile = FIPS.
(**A2** was removed from this list 2026-08-20: `entrypoint_honest` is now a
kernel-proved theorem, not a cited axiom — what remains cited is the
`handleOp` model's faithfulness to the deployed EntryPoint v0.6, below.)

A precision on **A2**: the in-Lean `entrypoint_honest` was, against the
Lean EntryPoint model, a **tautology over `handleOp`** — its conclusion (a
wallet-balance decrement implies `validateSignature` returned success with the
matching post-storage) follows directly from `handleOp`'s own definition (the
failure branch leaves the state untouched, so a decrement forces the success
branch, where `walletStorage := s'`). The 2026-08-20 adversarial pass made
that concrete: it is now **PROVED kernel-only as a `theorem`** in
`Bridge/EntryPoint.lean` (closure `{propext, Classical.choice, Quot.sound}`),
no longer an axiom — the A2 ledger row and its closure presence are gone.
What the old axiom carried was a **name** for the boundary, and that boundary
is unchanged: the genuine, still-open assumption it stands in for
is the **bytecode-discharge of the deployed EntryPoint v0.6** — that the
on-chain EntryPoint actually behaves like `handleOp`, including the
validation-phase prefund debit (`missingAccountFunds`) and the
paymaster/refund/nonce accounting that the model abstracts into the TCB. That
discharge is **not** performed here; it is tracked separately (Kontrol against
the deployed EntryPoint — the optional step 3 below) and rests today on the
OpenZeppelin / ChainSecurity / Spearbit audits + the immutable, ≥18-month
mainnet EntryPoint deployment, not on a Lean proof.

---

## What it takes to reach "fully proven to bytecode"

In dependency order:

1. ~~**Make the Lean verifier executably faithful.**~~ **DONE 2026-06-13.**
   The WOTS+C / hypertree reconstruction layer now byte-matches the deployed
   Yul: `lake exe verify-test-vectors` reports full-verify 10/10 and
   `requireFullVerify` is `true`. A3.1's equality is no longer contradicted by
   any tested vector, and the Lean refinement (`verifyRefined_eq_spec`, still
   `rfl`) carries real faithfulness over the corpus. The remaining work is the
   ∀-signature equivalence as a *citation* to the executable KAT + EUF-CMA,
   not yet a symbolic bytecode proof (step 2).
2. **Discharge the verifier's ∀-signature equivalence on bytecode.** Not
   possible under uninterpreted SHA-256 (the digit branches fork on
   unconstrained symbolic values). Needs an **interpreted-hash reachability**
   engine or **verified compilation** (Verity,
   [`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md)). **NOTE:
   Kontrol/KEVM does NOT qualify** — despite now being installed and used for the
   control-flow axioms, KEVM's `0x02` precompile is SMT-uninterpreted on symbolic
   input (`Sha256raw`), so it hits the same wall as Halmos (confirmed
   2026-06-15). Even Verity stops at Yul, leaving A1/A4 (and the `handleOp`
   model's faithfulness) as cited-TCB.
3. **Optionally** discharge the EntryPoint-model faithfulness + A4 on bytecode
   (Kontrol against the deployed EntryPoint) — a large, separate engagement.
   (This was worded "reduce A2/A4 from cited-TCB" before A2's 2026-08-20
   demotion; the residual open item is the model↔deployed-EntryPoint link,
   not any Lean axiom.)

Until step 1 lands, the maximal honest headline is the **✅ Claimable**
block above — "control flow proven to bytecode; verifier validated by
testing" — not "fully proven to bytecode."

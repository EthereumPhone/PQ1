# Assurance case — PQSmartWallet / SPHINCS+C10 formal verification

**Audience: an auditor or reviewer who wants, in one read, to know exactly what
is proven, by what *kind* of evidence, and what each leaf still hangs on.**

This is the top-down companion to the bottom-up [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md)
(axiom ledger) and the narrative [`THE_CLAIM.md`](THE_CLAIM.md). It decomposes the
headline claim into a goal tree whose every leaf carries an **evidence type**, a
**status**, the **artifact** that discharges it, and a **defeater** (what would
falsify it / what residual doubt it carries). It is modelled on the seL4
"What the Proofs Assume" page, the EverCrypt published-TCB list, and GSN /
Assurance-2.0 eliminative argumentation: *every residual is a tracked node, not a
silence.* It does not restate the per-axiom detail — it routes you to the doc
that owns it.

> **2026-07-15 status correction.** G2's committed Lean execution-model→spec
> refinement is universally kernel-closed; deployed source/bytecode→that model
> remains the correspondence boundary. G3/EasyCrypt is partial research and
> does not instantiate shipped C10 WOTS or a concrete top-level scheme theorem.
> G10 applies only to the frozen legacy `PQFW_V1` 75-byte model and grants no
> authority to V4 or the V6 research candidate. D1 and D5 are therefore open at
> the deployed-model and current-Rust-extraction boundaries, respectively. The
> exact evidence and acceptance tests are in the
> [2026-07-15 coordinator report](../../../docs/security/adversarial-review/findings/fv-full-stack-2026-07-15-coordinator.md).

> **One-sentence honest summary.** The on-chain authorization logic of the wallet
> is proven to the Lean kernel and discharged on the deployed bytecode by two
> independent symbolic engines; the cryptographic unforgeability and the
> SHA-256/EVM substrate are cited external trust (by necessity, not omission);
> the verifier's ∀-signature bytecode-equivalence is corpus-evidence with a known
> closure path; and the firmware/hardware invariants are largely out of the
> proof's scope — with one new exception (the dual-chip seed split, §5).

---

## 0. How to read this — the evidence-type legend

Never blur the tiers. Each leaf in the goal tree (§3) is tagged with exactly one:

| Tag | Evidence type | Epistemic strength | What it does NOT give |
|-----|---------------|--------------------|------------------------|
| **K** | **Kernel-proven (∀).** A closed Lean theorem, ∀-quantified, whose `#print axioms` closure is the kernel triple (+ only the cited-TCB axioms named on the node). | Strongest: holds for *all* inputs, machine-checked. | Only as faithful as the Lean *model* of the thing (model↔reality is a separate node). |
| **B** | **Bytecode-discharged (symbolic).** Halmos and/or Kontrol/KEVM symbolic execution over a **codehash-pinned** deployed runtime, ∀-over-calldata. | Very strong: binds the *deployed bytes*, two independent engines. | Modulo SHA-256 left uninterpreted, the harness↔property match, and (Halmos only) the hand-transcribed `LeanModel.sol` — the latter retired by the independent Kontrol engine. |
| **C** | **Corpus-tested (bounded).** Executable KAT vectors + mutant wrong-accept screen + Foundry fuzz. | Real but **bounded** — not ∀. Catches drift, not a universal guarantee. | Coverage of untested inputs; explicitly *not* a symbolic ∀. |
| **T** | **Cited-TCB.** Discharged by external authority (consensus-client conformance, immutable-contract audits + mainnet history, a published & separately-mechanized crypto proof). | As strong as the cited authority; outside this project to re-derive. | Any in-project machine check. Stated as trust, with an elimination path. |
| **X** | **Kernel axioms.** Lean 4 built-ins: `propext`, `Classical.choice`, `Quot.sound`. | Foundational TCB of the prover itself. | n/a. |

**Anti-vacuity meta-assurance.** A `K` tag is only meaningful if the theorem is
non-vacuous (`#print axioms` is green on vacuous conjuncts too — Kupferman–Vardi).
The project enforces this mechanically: `scripts/lint_fv_invariants.sh` (escape-hatch
ban + exact-closure tripwires), `scripts/dump_axioms.lean` (`*_nonvacuous` witnesses),
and `lint_placeholders.py` (`∀_,True` ban). Every `K` node below is pinned in
`dump_axioms.lean` and passes the tree-wide gates (escape-hatch ban + placeholder
ban scan all of `SphincsCVerify/**`); the *exact-closure tripwire* is enforced
specifically on `theft_free` + the Gap-3 off-chain axiom. See
`docs/verification/fv-soundness-roadmap-2026-06.md` §0.

Two further anti-vacuity gates were added 2026-06-29 (closing the recurring EF
*vacuity* findings P9-dead-conjunct and P1-undischarged-advertised):
- **`make verify-proof-mutation`** (`scripts/check_proof_mutations.py` + manifest
  `lean/scripts/proof_mutations.json`) — the proof-side `cargo-mutants`: deletes
  each load-bearing axiom / weakens a key lemma and asserts the rebuild *reacts as
  this ledger claims* (load-bearing ⇒ build breaks; A1/A4 markers ⇒ stay green +
  the closure drops *exactly* the named axiom; A3.4 zero-consumer ⇒ stays green;
  `reachable_implies_combinedCap` is confirmed load-bearing for the G4 reachable
  headline). Materiality-guarded (no-op = hard fail) + permanent canary.
- **`verify-ledger-consistency`** (`scripts/check_ledger_consistency.py`) —
  makes `AXIOM_STATUS.json` falsifiable against the live dump: exact-set `closures`
  per theorem + headline `signature_pins` (catches a re-introduced raw `hInv` —
  the G4/P1 surface — which axiom-closure checks cannot see) + count/status/no-
  undocumented-axiom checks, cross-checked against the `lint_fv` pin. Wired-in
  `--self-test` negative control. Authoritative local/CI evidence enters through
  `scripts/run_authoritative_make.sh` under the same-UID setuid-sudo /
  empty-environment pre-exec boundary documented in `THREE_CLAIMS_PROOF.md`.
  CI invokes setuid sudo directly as the exact-pinned custom shell, before Bash,
  then `exec`s pinned Bash on the launcher. The G1 contract also pins the
  GitHub-hosted runner, forbids a job container/environment/skip controls, and
  rejects duplicate workflow/manifest keys; its self-test covers runner,
  container, conditional, no-op-shell, and startup-environment suppression.
  The launcher requires the target's exact completion receipt; direct `make`
  remains a diagnostic implementation target.

The full method (the V1–V11 green-but-hollow catalog these gates close, and the
V8/V9/V11 classes **no** gate can close) and the on-demand, framework-agnostic
adversarial-review kit (`contracts/verification/adversarial-review/`, runnable
under Claude Code / Codex / any LLM) live in
[`docs/verification/fv-adversarial-review-playbook.md`](../../../docs/verification/fv-adversarial-review-playbook.md).
The gates stop us *re-discovering* the same vacuity; they do not make us *sure*.

---

## 1. The top claim

**G0 — Theft-freedom + integrity of a deployed `PQSmartWallet`.**
> For any deployed proxy `W`, under the cited substrate (§4): the wallet does not
> decrease its own balance, mutate its owner set, or execute a call, *without* a
> SPHINCS+C10 signature valid under an installed owner key of `W` over a
> `sphincsDigest` committing to the exact `(chainId, sender, nonce, callData)` —
> and a forged such signature would break a cited SHA-256 hardness assumption.

Headline theorem: `Spec/Theorems.lean::theft_free`, transported to the deployed
bytecode as `theft_free_bytecode`. Three user-facing corollaries (Claim 1/2/3 in
`TRUST_ASSUMPTIONS.md` / `THREE_CLAIMS_PROOF.md`). G0 holds *given* the leaf nodes
below; the assurance argument is that every leaf is either discharged (`K`/`B`) or
an explicitly-cited, separately-trustworthy residual (`C`/`T`/`X`).

---

## 2. Decomposition strategy

G0 is split along the path a malicious UserOp would have to travel to steal funds:

```
G0  theft-free + integrity (theft_free / theft_free_bytecode)
│
├─ S1  authorization gate     — only a verifier-true validate can move value/owners
│   ├─ G1  on-chain gate logic ......................... K + B
│   ├─ G4  reachable-state caps (the gate's precondition) K   ← UPGRADED this session
│   ├─ G5  execution faithfulness (signed tuple = run) .. K + B (+ T for byte delivery)
│   ├─ G6  owner-set integrity / init-once / no-UUPS .... K + B  (model + harness, not bridged)
│   └─ G8  EIP-1271 forbids bootstrap, domain-sep ....... K + B  (forbids-bootstrap clean ∀; non-bypass installed-reps)  ← B NEW
│
├─ S2  the verifier accepts only genuine signatures
│   └─ G2  deployed verifier ≡ Lean spec, ∀ signatures .. C  (∀-symbolic = standing ceiling)
│
├─ S3  signatures are unforgeable
│   └─ G3  forge ⇒ break SHA-256 (EUF-CMA) .............. T  (cited Barbosa'24; non-vacuity fence K)
│
├─ S4  the substrate behaves (SHA-256 / EVM / EntryPoint)
│   ├─ A1  precompile 0x02 = FIPS-180-4 ................. T
│   ├─ A2  deployed EntryPoint v0.6 = handleOp .......... T  (in-model theorem proved K; deployment faithfulness external)
│   ├─ A4  EVM delivers emitted call bytes .............. T  (non-consumed marker in theft_free)
│   └─ A6  Lean kernel ................................... X
│
└─ S5  firmware / hardware invariants (mostly OUT OF SCOPE — §5)
    ├─ G9  dual-chip seed split reveals no bit ........... K (IT core, scoped)  ← NEW this session
    └─ G10 FW-update preimage: domain-sep + 1-firmware ... K (extracted spec)   ← NEW this session
        (the other firmware invariants: silicon-E2E only, no Lean coverage)
```

---

## 3. Leaf nodes — evidence, status, artifact, defeater

### G1 — On-chain authorization gate logic · **K + B**
- **Claim.** A balance decrease / owner mutation / execute implies `validateSignature`
  returned success with a verifier-true installed-owner C10 sig over the op digest;
  no bypass, role-split (bootstrap vs slot) enforced, one-shot per credit.
- **Artifact (K).** `theft_free` / `theft_free_bytecode` (closure: kernel triple +
  A1,A3.1,A4,A5×4 + A3.2 for the bytecode form). A2 is an external
  deployment-faithfulness assumption; `entrypoint_honest` is proved in-model
  and contributes no closure axiom. Claim-4 gate:
  `every_call_gated_by_verifier`, `no_call_without_prior_verifier_acceptance`.
- **Artifact (B).** Halmos pointwise-equivalence `HalmosValidateUserOpEquiv` +
  `HalmosExecuteEquiv` and Kontrol `KontrolValidateUserOp`/`KontrolExecute` on
  pinned codehash `0x43c654…/0x551c4e…` (A3.2). Two independent engines.
- **Defeater.** The Lean `validateSignature` model not mirroring the bytecode →
  closed by A3.2 (`B`). SHA-256 left uninterpreted throughout (bottoms out at A1).

### G4 — Reachable-state combined cap (the gate's precondition) · **K**  ← UPGRADED
- **Claim.** `theft_free_bytecode`'s `hInv` (`slotUses[i] + offchainSigCount[i] ≤
  MAX_SLOT_USES`) holds in every reachable wallet state — so A3.2's
  pointwise-equivalence (which conditions on it, because the bytecode reverts on
  checked-arith overflow where the ℕ-model fails) is not conditioned on an
  unreachable-state fiction.
- **Status — CHANGED 2026-06-29.** Was **fuzz-backed** (`C`): the reachability was
  a Foundry invariant test (`PQSmartWalletInvariants.t.sol`, 256 runs). Now
  **kernel-proven** (`K`): `Wallet/Invariants.lean::Reachable` (genesis + the gated
  EntryPoint transitions) + `reachable_implies_combinedCap` (closure `[propext,
  Quot.sound]`, a genuine inductive invariant) + the `theft_free_bytecode_reachable`
  corollary that takes `Reachable σ.walletStorage` and derives the cap. `#print
  axioms` of the corollary equals `theft_free_bytecode`'s — the discharge adds no
  axiom. The Foundry suite now *corroborates* rather than *backs* it.
- **Defeater.** Transition-set completeness — the `Reachable` constructors must be
  the *only* operations that mutate the cap counters; backstopped by
  `scripts/check_storage_mutators.sh`. The model↔bytecode fidelity of those
  transitions is the same TCB layer as A3.2 (no new gap).

### G5 — Execution faithfulness (signed tuple = executed call) · **K + B (+ T)**
- **Claim.** `executeBatchWithOffchainCount` performs exactly the signed
  `(target, value, data)` tuples, in order; total ETH outflow = signed sum; no
  callback alters the batch remainder; only EntryPoint reaches the executor.
- **Artifact.** `executeBatch_faithful` (K, composes E-1..E-8); Halmos
  `HalmosExecuteEquiv` + Kontrol `KontrolExecute` (B, ∀-index for execute).
- **Defeater.** That the executed bytes *reach* the callee and the value *moves* is
  **A4** (`T`) — the EVM forwarded-byte delivery, not a kernel fact; and that the
  signed `callData` field equals what EntryPoint relays is **A2** (`T`).
- **(EF-#15) "executed `(target,value,data)` = signed `callData`" — decomposed
  (2026-06-29).** The PoC ("validate callData X, execute independent args Y") is a
  4-link chain (see the `Spec/Theorems.lean` §4c note): (1) digest commits
  `sha256(op.callData)` — `theft_free_with_calldata_binding` (K, mod `BreaksHash`);
  (2) EntryPoint relays `op.callData` as the execute calldata — **A2** (T, the wallet
  can't self-check; the Lean model abstracts the relay); (3) deployed execute decodes
  calldata→args & runs them — `HalmosExecuteEquiv` (B); (4) model dispatches in order
  — `executeBatch_faithful` (K). So #15 is an **A2-relay residual** (folds into
  defeater D2), NOT a missing Lean decode proof — link 3 discharges the decode.

### G6 — Owner-set integrity / init-once / no-UUPS · **K (model) + B (independent)**
- **Artifact.** `cannot_remove_bootstrap`, `initialize_called_exactly_once`,
  `owner_set_nonempty_after_init`, `upgrade_path_unreachable` (K, over the Lean
  Storage model); Halmos `HalmosMultiOwnable` (7 rules) + Kontrol (12 rules) (B).
- **Defeater / asymmetry.** Unlike G1/G5/G7, the K theorems here have **no
  `*_bytecode` corollary** — they bind only the Lean Storage model. The deployed
  owner-table property is carried **independently** by the Halmos/Kontrol harness
  (solver soundness + harness↔property match), NOT linked by a consumed axiom:
  A3.4 (`solidityMultiOwnable_compiles_correctly`) is a **non-load-bearing** bridge
  axiom with zero theorem consumers (AXIOM_STATUS P10). Model and bytecode are each
  checked, but not joined by a kernel corollary.

### G7 — Factory squat-defence (I-8) · **K + B**
- **Artifact.** `factory_squat_defence_bytecode` (K, closure +A3.3);
  Halmos `HalmosFactory` (B) on pinned factory codehash. **Defeater.** A3.3.

### G8 — EIP-1271 path · **K + B (per-property)**  ← B ADDED this session
- **Claim.** `isValidSignature` forbids the bootstrap key (`ownerIndex==0`),
  nests via Solady EIP-712, returns the `0x1626ba7e` magic ONLY on verifier-accept,
  bumps no counter; and an off-chain-nested value is never a UserOp `sphincsDigest`
  (RAW32 forgery-oracle defense).
- **Artifact (K).** `eip1271_forbids_bootstrap`; `Wallet/OffchainBinding.lean`
  (closure += `keccak_sha256_cross_separation`, an `∨ BreaksHash` cross-hash axiom).
- **Artifact (B) — NEW 2026-06-29.** `test/halmos/HalmosIsValidSignature.t.sol`
  (3 rules, PASS on BOTH profiles): `check_isValidSignature_forbids_bootstrap` is a
  clean bytecode **∀** over `hash` + the symbolic verifier answer — `ownerIndex 0`
  is rejected BEFORE the `ownerAtIndex` read and BEFORE the keccak nesting, so the
  G8 headline is proven on the deployed bytecode; `_nonbypass_slot1` (magic ⇒
  verifier-true) and `_no_counter_bump` (view-only) over the **installed** slot
  index 1.
- **Defeater / disclosed ceiling (matches A3.2 exactly).** The non-bypass /
  view-only rules sweep the installed index 1 as a **concrete rep** — a symbolic
  non-installed index `NotConcreteError`s on the `ownerAtIndex` dynamic-bytes getter
  (the same Halmos engine ceiling A3.2 carries). So the *forbids-bootstrap headline*
  is a clean bytecode ∀, but the non-bypass property is **per-property B over
  installed reps, not a symbolic ∀** over all indices. keccak (`replaySafeHash`)
  stays uninterpreted (the honest hash boundary); the keccak/SHA-256 non-collision
  is the cited `keccak_sha256_cross_separation` axiom. There is **no**
  `solidityEip1271_compiles_correctly` bridge axiom — the Halmos session is the
  bytecode evidence standing on its own (as the per-property `HalmosValidateUserOp`
  rules do for A3.2), not consumed by a Lean corollary.

### G2 — Deployed verifier ≡ Lean spec, for all signatures · **C (standing ceiling)**
- **Claim.** `SPHINCsC10Asm.verify` bytecode = `execC10Asm` for **all** 4008-byte
  signatures (A3.1). `execC10Asm` unfolds (via the `execC10Asm_eq` kernel lemma) to
  `verifyYulModel` **on N-masked keys**; the bare `= verifyYulModel` shape is FALSE
  off N-masked keys (the bytecode's `and(key,N_MASK)==key` guards) and was corrected
  to `= execC10Asm` at `Bridge/Refinement.lean`. Claim synced 2026-07-01 (FV review a31).
- **Status.** **Corpus-discharged, not ∀-symbolic.** Executable Lean↔FIPS↔bytecode
  KAT (10/10, both directions) + bulk 384/384 + ~250-mutant wrong-accept screen +
  Halmos input-gate rules. The ∀-signature symbolic equivalence is **intractable
  while SHA-256 is uninterpreted** — *both* Halmos and Kontrol/KEVM fork on every
  message-digit (KEVM models `0x02` as uninterpreted `Sha256raw`). This is a
  **coverage** limit, not a falsity: no tested vector contradicts A3.1.
- **Closure path (not a permanent ceiling).** A **deductive interpreter-refinement
  proof in Lean** closes the ∀ with the hash kept *opaque* (loop-iteration
  induction, no symbolic search) — demonstrated upstream by SPHINCS-/`verity`
  (`c13_refines_spec`, zero Keccak hash axioms); the `Interpreter/` +
  `contracts/verity/` build is this path, **under active development**. Residuals
  then shrink to model↔bytecode transcription + SHA-256 byte-memory. See
  [`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md), [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).
- **Defeater.** An untested signature on which bytecode and spec disagree. Mitigated
  by the corpus + mutant screen; eliminated only by the refinement proof.

### G3 — Unforgeability: forge ⇒ break SHA-256 (EUF-CMA) · **T (cited reduction; non-vacuity fence K)**
- **Claim.** A forgery against an installed key's honest history implies `BreaksHash`.
- **Status.** The **quantitative** `Pr ≤ ε` bound is **cited-TCB** (`T`): Barbosa–
  Dupressoir–Hülsing–Meijers–Strub ASIACRYPT 2024 (ePrint 2024/910) for SPHINCS+,
  Hülsing PQC2022 for the WOTS+C/FORS+C variant; the `+C` target-sum extension is a
  **cited argument, outside the mechanized corpus** (no public bit-security number
  for C10). The **qualitative reduction** (`forgery ⇒ BreaksHash`) is itself the
  **cited axiom** `EUF_CMA_SPHINCSplusC` (`T`, `EUFCMA.lean:123`) — an *opaque*
  `BreaksHash` conclusion, never `False`. What is **kernel-proven** (`K`) is only
  its *consistency / non-vacuity fence*: `honest_sig_not_forgery` +
  `keyHistory_empty_signs_nothing` (closure `{propext, Quot.sound}`) make the
  empty-transcript valid-KAT detonator unformable.
- **Honest caveat (P9 — non-operational conjunct; now INSTANTIATED + PROVEN
  IRREDUCIBLE).** The `KeyHistory` binding that kills the detonator *also* makes
  `isForgery` unsatisfiable for any message the honest signer can sign — so over the
  operational message space the in-kernel EUF-CMA conjunct is decorative; the cited
  reduction carries the unforgeability. Two upgrades (2026-06-29): the conjunct IS
  now instantiated at the transition's own values
  (`Invariants.unauthorized_userop_breaks_hash` — EUF-CMA at `msgStar =
  sphincsDigest(op)`; additive, no new axiom), answering the "detached ∀-rider"
  PoC; and the vacuity is **proven irreducible**, not a wiring gap — dropping
  `KeyHistory.signed_recorded` would let an honest signature satisfy `isForgery`
  (via `honest_consistent`), making `BreaksHash` a *provable theorem* (a worse
  vacuity), so the separation needed is the PPT adversary the qualitative shadow
  cannot express (proof in `EUFCMA.lean`). See D9.
- **Quantitative companion (`K`, standalone).** `Crypto/Quantitative.lean` turns the
  shipped `2^16` cap into a kernel-checked **96-bit** generic-attack floor
  (`min(FORS+C 143, birthday 112, multi-target 96)`), shown load-bearing (+4 bits
  from the cap). This is a `decide`-checked arithmetic margin, *not* a reduction —
  it does not connect to the opaque `BreaksHash` (deliberately decoupled). Honest
  limit: the bit-count *term formulas* are imported as upstream-analyst accounting
  (**cited, not re-derived** — C10 is archived/unanalyzed upstream); the K theorem
  verifies only the min-arithmetic over those cited inputs.
- **Defeater.** SHA-256 failing one of ITSR / SM-TCR / SM-DSPR / PRF; or a `+C`-specific
  weakness below the cited bound. **Irreducible** — see §6.

### Substrate (S4) — A1 / A2 / A4 / A6
Detail in `TRUST_ASSUMPTIONS.md`; summarized in §4 with evidence types.

---

## 4. The TCB ledger (top-down view of `TRUST_ASSUMPTIONS.md`)

| Axiom | Statement (informal) | Type | In `theft_free` closure? | Defeater / elimination |
|-------|----------------------|------|--------------------------|-------------------------|
| **A1** | precompile `0x02` = FIPS-180-4 SHA-256 | **T** | named **non-consumed** marker | geth/reth/… consensus conformance; KAT parity test. Eliminate = verify a client's SHA-256 (Appel/VST). |
| **A2** | deployed EntryPoint v0.6 ≡ `handleOp` | **T** | **external assumption, not a closure axiom**: the in-Lean `entrypoint_honest` is a proved theorem over the model | OZ/ChainSecurity/Spearbit audits + ≥18-mo immutable mainnet. Eliminate = Kontrol vs deployed EntryPoint (8–12 mo). |
| **A3.1** | verifier bytecode = Lean Yul model | **C** | consumed | corpus + mutant (G2). Eliminate = interpreter-refinement (active). |
| **A3.2/3.3/3.4** | wallet/factory/owner-table bytecode = Lean model | **B** | A3.2 in `theft_free_bytecode` | Halmos + Kontrol on pinned codehashes; deploy-profile reproduces live Base Mainnet exactly. |
| **A4** | EVM delivers emitted call bytes | **T** | named **non-consumed** marker | KEVM / consensus conformance. |
| **A5** | SPHINCS+C10 EUF-CMA | **T** | consumed: ×4 EUF-CMA shapes in `theft_free` (the `sha256_collision_resistance` reduction is Claim-1-only — in `theft_free_with_calldata_binding`, **not** `theft_free`) | Barbosa'24 + PQC2022; `+C` cited. Eliminate = extend the EasyCrypt dev (multi-person-year). |
| **A6** | Lean kernel checks proofs | **X** | always | `propext`, `Classical.choice`, `Quot.sound`. |

**Minimal shared TCB of all three claims:** A6 + A5 + A1 + A2 + A4 + A3.1–A3.4.
The **`theft_free` kernel content** rests on A3.1 + A5×4 + kernel; A1 and A4
are **non-consumed named markers** (deleting their `have` bindings leaves
`theft_free` proven) — they document the on-chain substrate boundary without being
logical premises of the bare safety conjunct. A2's `entrypoint_honest` is proved
from the in-Lean `handleOp` model and contributes no additional axiom. Applying
that model to the deployed EntryPoint still requires external faithfulness
evidence; this deployment assumption is distinct from the theorem's kernel
premises (see [THE_CLAIM.md](THE_CLAIM.md)).

---

## 5. Firmware / hardware layer (the out-of-scope boundary, with one new in-road)

`TRUST_ASSUMPTIONS.md` excludes the firmware from the on-chain TCB: *"the proof
says nothing about whether the firmware keeps the secret keys secret."* Of the 9
CLAUDE.md non-negotiable invariants, **#2 (three-way PIN-attempt consumption + directional page124/E120 boot check), #3 (E2E SE
tunnels), #4 (TrustZone isolation), and the trusted-display pipeline have zero
Lean coverage** — they rest on silicon E2E tests + the security-review docs. That
is a deliberate scope boundary, not a defect; but it must not be read as a
device-wide guarantee.

### G9 — Dual-chip seed split reveals no bit (invariant #1) · **K (IT core, scoped)**  ← NEW
- **Status — NEW 2026-06-29.** Invariant #1 previously had **zero formal backing**
  (prose only). `Crypto/SplitSecrecy.lean` now proves the **information-theoretic
  core** of "neither chip alone reveals any bit" as 2-of-2 one-time-pad secrecy,
  over `BitVec 256`, **kernel-only `[propext, Quot.sound]`, mathlib-free, with NO
  crypto/hash assumption** (a symbolic Dolev-Yao XOR model would be *unsound* —
  Unruh ePrint 2010/389 — so this is the correct layer).
- **Proven.** reconstruction (`half_O ⊕ half_E = entropy`); exactly-one-mask /
  bijection counting core; the **faithful deployed** statement (the firmware rejects
  the all-zero mask, `dual_se.rs:130`, so the leak is exactly one excluded entropy ⇒
  statistical Δ ≤ 2⁻²⁵⁶); genuine 2-of-2 (both halves recover the seed).
- **Defeaters / honest scope (in the file's Scope block).** (1) the security reading
  needs the mask **uniform + independent** — the TRNG's job, a hardware assumption,
  not a theorem here; (2) the deployed nonzero-mask makes the SE050-half secrecy
  **statistical, not exact**; (3) `master_secret = KDF(entropy)` is co-resident on
  each chip (encrypted under per-SE PIN/AES-GCM), so *absolute* single-chip secrecy
  also rests on a **computational** assumption. So G9 is a genuine partial in-road,
  **not** a full discharge of invariant #1.

This narrows the "5 of 9 invariants unproven" statement to **#1 partially proven
(IT core), 4 still silicon-E2E-only.**

### G10 — FW-update signed preimage: domain-separated + authorizes one firmware · **K**  ← NEW
- **LEGACY/NONSHIPPING — this proof covers only the retired bench PQFW_V1 75-byte
  preimage and grants no assurance to any shipping firmware-update format.**
- **Status — NEW 2026-06-29.** The CLAUDE.md "frozen 75-B preimage" + fw-manifest
  "the `PQFW_V1` domain tag stops cross-protocol signature reuse" prose claims now
  have kernel backing, over the **Aeneas-extracted** firmware spec
  (`extracted/Extracted/FwManifestSpec.lean`, gated by `make verify-extracted`).
- **Proven (kernel `[propext, Classical.choice, Quot.sound]`, SHA-opaque).**
  `preimage_layout_injective` (the 75-byte layout determines its fields uniquely);
  `layout_domain_tag_prefix` (every preimage begins with `PQFW_V1` ⇒ structurally
  distinct from any non-tagged signed domain — cross-protocol separation at the
  preimage layer); `signed_preimage_authorizes_one_firmware` (equal `signed_preimage`
  outputs ⇒ equal version-bytes + secure/nonsecure hashes — composes
  `signed_preimage_spec` with the layout injectivity). Frozen 75-B *size* is
  enforced by the return type (`Array Std.U8 75#usize`).
- **Defeater / scope.** SHA-opaque: these are facts about the *preimage*; the step
  "distinct preimage ⇒ distinct digest" is the cited SHA-256 collision-resistance
  (separate). The release key is single-use (signs only FW manifests), so this is
  supply-chain *integrity / unambiguity* (one signature ⇄ one firmware build), not a
  cross-key confusion defense. Rests on the Rust→Lean extraction TCB (D5) like every
  extracted spec.

---

## 6. Honest ceilings — what CANNOT be made ∀ (cited-TCB by necessity)

These are not defects to be closed; they are stated so an auditor sees them as
*deliberate, irreducible* trust, with no pretense otherwise. (Roadmap §3.)

1. **A1 silicon + precompile.** No verified hash covers the STM32 HASH peripheral
   silicon or geth's `0x02` (Go stdlib, unverified). On-chain A1 = consensus/social
   fact. The interpreter-refinement (G2) shrinks the *spec-transcription* part; the
   bytes-that-run stay KAT/consensus trust.
2. **keccak256 ≠ FIPS-202.** No verified implementation in any prover; sits on the
   userOpHash / EIP-712 / CREATE2 path. A residual *distinct from and weaker than*
   SHA-256 (G8's cross-hash axiom).
3. **A5 forever conditional** on ITSR / SM-TCR / SM-DSPR / PRF for SHA-256. Even a
   full mechanized C10 proof is "secure *if* SHA-256 satisfies these"; post-quantum
   bit-security stays a QROM hand argument.
4. **Multi-tool composition is human-glued.** No spanning theorem across protocol ⊕
   implementation (Lean/Aeneas) ⊕ bytecode (Halmos/Kontrol). Every interface is a
   documented assumption (SoK Computer-Aided Cryptography, ePrint 2019/1393).
5. **Transcription / refinement TCB is relocated, never deleted.** Kontrol retires
   the Halmos `LeanModel.sol` hand-transcription for the control-flow axioms; only
   an EVM-semantics-in-kernel approach (EVMYulLean, pre-release) collapses the
   EVM-side one into the kernel.

---

## 7. Defeater register (every open residual, tracked)

| # | Residual doubt | Node | Status | Owner doc |
|---|----------------|------|--------|-----------|
| D1 | Verifier ∀-signature ≡ bytecode (symbolic) | G2 | OPEN — corpus + active refinement build | `A3_1_CLOSURE_PATH.md` |
| D2 | Deployed EntryPoint v0.6 ≡ `handleOp` | A2 | CITED-TCB — Kontrol-vs-EntryPoint not done | `TRUST_ASSUMPTIONS.md` A2 |
| D3 | EIP-1271 surface bytecode binding | G8 | **LARGELY CLOSED 2026-06-29** — `HalmosIsValidSignature` (3 rules, both profiles): forbids-bootstrap clean bytecode ∀; non-bypass/view-only per-property B over installed reps (`ownerAtIndex` ceiling = A3.2). Residual: no symbolic-∀ over unset indices; no Lean bridge corollary | `PROOF_MAP.md` I-6 |
| D4 | A5 quantitative / `+C` bit-security | G3 | CITED-TCB (irreducible §6.3); `+C` outside corpus | `EUFCMA.lean`, roadmap T1.1 |
| D5 | Rust→Lean (Charon/Aeneas) faithfulness | extracted specs | **PARTLY MITIGATED 2026-06-29; coverage gap sharpened 2026-07-02 (extracted-F3).** Two gates: (i) regen-diff (`make extract-*`, **11 targets** — sphincs-adrs/aa-userop/fors-index/wots-digits/txcore-rlp/fwmanifest-preimage/merkle-verify/wots-pkfromsig/tx-merkle/decode-item/hash-fns) catches un-re-extracted Rust changes; (ii) **differential** (`make verify-extract-differential`) EXECUTES the extracted Lean vs executed-Rust (`signed_preimage`, 6 vectors + negative control). Both tier C (corpus), not a ∀. **SlotKdf stale-body RESOLVED 2026-07-02 (extracted-F3):** the committed `SlotKdf/Funs.lean` was stale vs the 2026-07-01 zeroize edits (a fresh extraction adds a `zeroize(buf); ok out` step — functionally BENIGN, `out` unchanged). It was **re-extracted + re-committed** and the 4 byte-layout proofs (`slot_entropy_hashes_canonical_preimage`, `derive_c10_slot_seeds_byte_layout`, `slot_master_byte_layout`, `derive_c10_master_byte_layout`) **re-proved** against the new bodies (a `+ Array.Insts.ZeroizeZeroize.zeroize` in the `simp`, the `step*` absorbing the identity bind), closures unchanged `[propext, Classical.choice, Quot.sound, sha256_pure_bytes]`, `make verify-extracted` green. The kernel re-check IS the confirmation that the ONLY semantic change was the benign zeroize (a hidden logic change would break a proof). The `.llbc` **filename** sets the import prefix (`sk.llbc` → `Sk.*` matching the committed sed) — the earlier "Slotkdf.* vs Sk.*" concern was just the filename. **Residual (NOT closed):** `SlotKdf`/`PinState` still have **no `extract-*` regen-diff target** (a byte-exact one is flaky — multi-`--start-from` emission-order non-determinism), so a *future* Rust drift is caught by the byte-layout proofs breaking (a semantic change) but not by a regen lint (a benign change) — a tracked hygiene gap, `docs/work-todo.md` §35. Charon still has no foundational soundness proof (cited-TCB). | roadmap T1.3, `ExtractDiffCheck.lean`, work-todo §35 |
| D6 | Firmware invariants #2/#3/#4 + clear-sign | §5 | OUT OF SCOPE — silicon-E2E only | `docs/security/` |
| D7 | G9 mask uniformity / `master_secret` confidentiality | G9 | hardware-TRNG + computational (scoped, §5) | `SplitSecrecy.lean` Scope block |
| D8 | A1 silicon / keccak (no verified hash) | §6.1/6.2 | IRREDUCIBLE cited-TCB | this doc §6 |
| D9 | In-kernel EUF-CMA conjunct non-operational (`isForgery` unsatisfiable for honestly-signable msgs) — security carried by the cited reduction, not the in-Lean conjunct | G3 | **DOCUMENTED + PROVEN-IRREDUCIBLE 2026-06-29.** The conjunct IS now instantiated at the transition's own values (`Invariants.unauthorized_userop_breaks_hash` — EUF-CMA at `msgStar = sphincsDigest(op)`, answering the "detached ∀-rider" PoC; additive, no new axiom). The vacuity is shown IRREDUCIBLE, not a wiring gap: dropping `KeyHistory.signed_recorded` makes an HONEST signature satisfy `isForgery` (empty transcript + `honest_consistent`-verifying sig), making `BreaksHash` a *provable theorem* and collapsing every `∨ BreaksHash` reduction — a worse vacuity. The satisfiable-by-forgeries / unsatisfiable-by-honest-sigs separation IS the PPT adversary, inexpressible in the qualitative shadow (needs EasyCrypt/SSProve). Proof written into `EUFCMA.lean` axiom docstring. | `EUFCMA.lean`, `AXIOM_STATUS.json` A5-EUFCMA (P9), roadmap §0 |

**Closed / advanced this session:** (1) the former "hInv reachability is fuzz-backed"
defeater (G4) — now a kernel inductive invariant; (2) the EIP-1271 model-only gap
(D3/G8) — now bytecode-discharged: the forbids-bootstrap headline is a clean ∀ on the
deployed bytecode, plus per-property B (non-bypass / view-only) over installed reps;
(3) the Charon/Aeneas faithfulness defeater (D5) — partly mitigated by the new
extracted-Lean-vs-executed-Rust differential gate (`make verify-extract-differential`),
tier C, on `signed_preimage` (coverage gap logged).

---

## 8. Cross-reference map (where the detail lives)

| For… | Read |
|------|------|
| Per-axiom statements + discharge | [`TRUST_ASSUMPTIONS.md`](TRUST_ASSUMPTIONS.md), [`AXIOM_STATUS.json`](AXIOM_STATUS.json) |
| What is / isn't claimable (narrative) | [`THE_CLAIM.md`](THE_CLAIM.md) |
| Claim ↔ theorem ↔ file map | [`PROOF_MAP.md`](PROOF_MAP.md) |
| The three user-facing claims, in full | [`THREE_CLAIMS_PROOF.md`](THREE_CLAIMS_PROOF.md) |
| Open obligations + tightening paths | [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md) |
| Bytecode pins + repro | [`PINNED_CODEHASHES.md`](PINNED_CODEHASHES.md), [`DEPLOYED_BYTECODE_PIN_CAVEAT.md`](DEPLOYED_BYTECODE_PIN_CAVEAT.md) |
| A3.1 verifier ceiling + closure | [`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md), [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md) |
| Faithfulness / mutation audit | [`FAITHFULNESS_AUDIT_2026-06-14.md`](FAITHFULNESS_AUDIT_2026-06-14.md) |
| Soundness roadmap (taxonomy + ceilings) | [`../../../docs/verification/fv-soundness-roadmap-2026-06.md`](../../../docs/verification/fv-soundness-roadmap-2026-06.md) |
| Machine gate (closures, non-vacuity) | `scripts/lint_fv_invariants.sh`, `scripts/dump_axioms.lean`, `make verify-audit` |

---

*Generated 2026-06-29. This artifact is a top-down index, not a source of truth —
every node routes to the doc/theorem that owns it. When a node's evidence type
changes (e.g. G4 fuzz→kernel, G9 new), update the goal tree (§2) and the relevant
leaf (§3) here in lockstep with the owning doc.*

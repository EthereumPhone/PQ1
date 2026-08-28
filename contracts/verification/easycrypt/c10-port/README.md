# C10 (SPHINCS+C) EUF-CMA — certified EasyCrypt artifact

Snapshot of the `c10-eufcma-port` research workspace, **re-taken 2026-08-12 at
its commit `0c825ed`**, at which the SPLIT gate is **GREEN — 208 OK, 0 FAIL**
(`INPUTS_SHA256 eb589caf...`, toolchain r2026.02, 25 prover configurations,
receipt in `scratch/gate_run.out`).

> **:white_check_mark: UPDATE 2026-08-22 — the fork gate IS now verified.** The scope note
> below ("its gate was NOT re-run for this snapshot") is superseded: `cert_gate_fork.sh`
> runs GREEN, `CERT_FAILURES=0`, receipt `scratch/gate_run_fork2.log`. See the final
> section of this file.

> **Previous snapshot line, kept for history:** taken at `16fe480`
> (2026-08-05, "run 26"), at which both certification gates were GREEN.
> **Scope note on this re-snapshot:** the receipt above is for the **split**
> gate, which is the certified closure (32 files). The **fork** tree is synced
> for completeness but its gate was NOT re-run for this snapshot — do not read
> "GREEN" as covering it.

This directory supersedes the older `../drafts/*.ec` snapshot, which is an
earlier stage of the same work and is retained only as history.

## What is actually proved, and what is not

Read this section before quoting anything from this directory.

The headline theorem is **`EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED`**
(`cdrafts-split/GprocChargedQWired.ec:77`) — a gated closure member whose statement
is pinned by digest. It is a real, machine-checked theorem, and it is **not a
numerically meaningful bound**.

> **Headline changed 2026-08-24, and the previous one is kept below.** Until this
> date the front page advertised `EUFCMA_SPHINCS_PLUS_C10_GROUNDED`
> (`cdrafts-split/SphincsC10CapstoneWired.ec`), which is **measurably weaker**:
> diffing the two statements, both carry 7 premises, but `GROUNDED` carries **N2**
> — `exists cc, predC (ThC ps ad m cc)`, App-D gap #1, which this tree's own
> comments call *"A PREMISE, not a theorem"* — and an **unreduced `Q`**.
> `CHARGED_QWIRED` carries neither; its only extra premise is `0%r <= mkg_adv`.
> `GROUNDED` remains a true, gated theorem and is still in the closure; it is no
> longer what this directory advertises.

> **:white_check_mark: UPDATE 2026-08-24 — quote the TIGHTENED form.**
> `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT` (same file) is the headline
> instantiated at `mkg_adv := 0`, which is sound because `mkg_adv` is a
> universally quantified lemma parameter constrained only by `0%r <= mkg_adv`,
> and 0 is its **tightest admissible value**. It is therefore **strictly
> tighter**, carries **6 premises not 7** (**5 since 2026-08-25**, see below),
> and contains **no free real** — see the final section of this file. The description below is of the parent, which
> it is derived from and which remains gated and true.
>
> **For the PRODUCT, quote
> `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS`** — the same
> clean statement with the four abstract width facts discharged from C10's
> deployed parameter pins (n=16, len=43, k=13). It is the **first** deployed
> statement that is N2-free, Q-free *and* free-real-free; until 2026-08-24 every
> deployed variant still carried N2.
>
> **:white_check_mark: UPDATE 2026-08-27 — it now carries TWO premises, and BOTH
> are substantive.** Two eliminations, on 2026-08-25 and 2026-08-27:
> the encode-compatibility premise `hencb` is now the theorem
> `WOTS_C_Real.ec::encode_msgWOTS_C_compat`, and the three deployed-parameter pins
> (`n = c10_n`, `len = c10_len`, `k = c10_k`) are gone because the four `dfC0`
> separations never needed them — the argument is mod-8 and never looks at
> 16/43/13. Counts, read off the proof binders: `CHARGED_QWIRED` 7→6, `_TIGHT` 6→5,
> `_TIGHT_AT_DEPLOYED_PARAMS` **6→2**. Ledger unchanged at 242 throughout.
>
> **:warning: CORRECTION.** Between 2026-08-25 and 2026-08-27 this block said the
> deployed statement had five premises of which **"only ONE is substantive"**.
> **That overstated the artifact.** It counted
> `size (emb_in witness) = 8*n + c10_r` among "the deployed parameter pins", but
> that is a CONSTRAINT ON A FREE OP — `emb_in` is `abstract-op:f718c0661391` and
> nothing in the closure pins its width — not a restatement of a deployed value.
> The two surviving premises differ in kind and both are real:
> `c <= p_tgts` is a parameter choice satisfiable by construction, and the
> `emb_in` width fact is the artifact's **least visible real assumption**.
>
> **:white_check_mark: UPDATE 2026-08-27 (second) — there is now a PINNED-ENCODER
> variant.** `…_TIGHT_AT_PINNED_ENCODER` carries `c <= p_tgts` and
> `emb_in = c10_embg`, deriving the width fact instead of assuming it. That matters
> because the width fact is **degenerately satisfiable** — a constant `emb_in` meets
> it while sending the S-TCR summand to ~1 — and the pin excludes those models
> (`pinned_encoder_is_not_degenerate` — which carries the pin as its premise; only
> `c10_embg_not_constant` is premise-free). **But the pin does NOT make the S-TCR term
> meaningful: `thfc` is axiom-free, so `thfc := const` still collapses `ThC`.**
> **Neither variant supersedes the
> other:** the pin is a strictly stronger premise, so it covers fewer models. The width
> form is more general, the pinned one more informative. Quote whichever your claim
> needs, and say which. See the final section of this file.

**What the headline carries.** Its premises are `c <= p_tgts`, `0%r <= mkg_adv`,
and four C10 width facts on `dfC0` — **six**. Until 2026-08-25 it also carried the
encode-compatibility equation `encode_msgWOTS_C p a x cc = encode_msgWOTS
(ThC p a x cc)`; that is now a **theorem**
(`WOTS_C_Real.ec::encode_msgWOTS_C_compat`) and no longer a premise. Its right-hand side is the
SKG-PRF distinguishing advantage (**two** `Pr[…]` experiments forming one advantage), the
free real `mkg_adv`, and **nine named game probabilities** — **eleven `Pr[…]` expressions
on the RHS in total**. (Corrected twice: this said "ten" while the list below it
enumerated nine; the 2026-08-27 fix then wrote "the RHS carries nine distinct `Pr[…]`
games", which is also wrong — the RHS has eleven `Pr[…]`, of which nine are the named
games. Found by GPT-5.6 adversarial review.) The nine are: `M.F.ITSRC10`; the three that replace `Q`
(`F_OpenPRE.SM_DT_OpenPRE`, `TRHC_TCR.SM_DT_TCR_C`, `TRCOC_TCR.SM_DT_TCR_C`); the
four hypertree terms (`M_EUF_GCMA_WOTSTWESNPRF`, `S_TCR_C_Int_MA`,
`PKCOC_TCR.SM_DT_TCR_C`, `TRHC_TCR.SM_DT_TCR_C`); and `GAME1_INT`, which is the
**N2 charge** — a named game an instantiator cannot choose, where N2 was
previously a premise.

**Why it is still not numerically meaningful**, and this is unchanged by the
headline swap:

* **`Q` is bounded, and the headline no longer carries it.**
  `GprocQBound.ec:62::gproc_Q_bound` bounds
  `Pr[EUF_CMA_Gproc_I(...) : res /\ !covered]` by three NAMED SM-DT hardness
  advantages, and the headline consumes it. (The superseded `GROUNDED` capstone
  carries `Q` unreduced; that is one of the two reasons it was superseded.)

  > **:warning: CORRECTED 2026-08-24.** This bullet previously ended *"Nothing in
  > this tree bounds `Q` below 1, so the bound is currently compatible with 1."*
  > **That sentence was false, and it understated the artifact.**
  > `cdrafts-split/GprocQBound.ec::gproc_Q_bound` bounds `Q` by three NAMED
  > SM-DT hardness advantages (`SM_DT_OpenPRE`, and `SM_DT_TCR_C` for TRH and
  > TRCO), and it is a gated closure member. Two capstones consume it and carry
  > **no `Q` at all** — `GprocQWired.ec::EUFCMA_SPHINCS_PLUS_C10_QWIRED` and
  > `GprocChargedQWired.ec::EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED`, both also
  > gated. What remains true is the narrower statement: *the theorem named as the
  > headline here* (`GROUNDED`) carries `Q`, because it does not consume that
  > bound. The tree does bound it.
  >
  > **And `CHARGED_QWIRED` is strictly stronger than the headline**, measured on
  > the statements: it drops the N2 grind premise
  > (`exists cc, predC (ThC ps ad m cc)` — App-D gap #1, a premise and not a
  > theorem) in favour of `Pr[GAME1_INT ...]`, a NAMED GAME probability, and it
  > drops `Q` for the three SM-DT terms. Its only additional premise is
  > `0%r <= mkg_adv`, a non-negativity side condition. Which theorem should be
  > *advertised* as the headline is an owner call, not a proof question — but the
  > front page should not name a weaker one without saying so.
  > **RESOLVED 2026-08-24: the owner made that call and the headline is now
  > `CHARGED_QWIRED`.** See the top of this file.
* `Pr[M.F.ITSRC10 ...]` is likewise carried unreduced — that is the FORS+C10
  assumption and the honest headline term. **This one is irreducible, and that is
  proved rather than assumed:** `scratch/_countermodel.ec::countermodel_pr1`
  exhibits a LEGAL clone of the abstract theory in which
  `Pr[ITSRC10(...)] = 1%r`, so no parameter-independent bound exists. It is
  carried by ALL THREE capstones, which is why the verdict above — *not a
  numerically meaningful bound* — stands even for the Q-wired ones. Correcting
  the `Q` sentence does not make the headline numeric; it moves the honest
  residual onto the term that genuinely cannot be reduced.
* Each cone contains **two admits**, every one pinned by statement digest:
  * split — `nhchwcoll_hchwpre_msg` (`base-c10-split/WOTS_TW_ES.ec`), inherited
    from MM45; and `extract_op` (`cdrafts-split/FORS_C_TreePort.ec`), the
    OpenPRE branch of the FORS bad-event cascade. `extract_op`'s own comment
    names four un-discharged parts (R-KEY, R-SIM, R-INDEX, R-OPEN) and records
    that closing it needs **exposed randomized leaf keygen** — an upstream
    interface change, not more proof effort.
  * fork — `nhchwcoll_hchwpre_msg` and `EUFNAGCMA_FLSLXMSSMTTWESNPRF`, both
    inherited.
* `GprocVI.ec` is the **V→VI hop**, added in run 26 and **admit-free**: MM45
  proves its TRH and TRCO branches over a restructured game `_VI`, not `_V`
  (`FORS_ES.ec:4828-4832`), so without this the T3 reduction has no alignable
  left-hand side. Nine theorems, zero new assumptions — the split ledger stayed
  at 239 across the promotion. It is a **prerequisite**, not a bound.
* `FORS_C_TreePort.ec` (1732 lines) is the prior attempt at bounding `Q`. It was
  admitted to the split closure in run 23 *specifically so its real status is
  gate-enforced rather than asserted in its own prose*; certifying it raised the
  split census by 100 rows. Note what it does and does not bound:
  `fors_c_tree_port` bounds `EUF_CMA_FORSC_I`, **not** `EUF_CMA_Gproc_I`.
  Different game. It does not bound `Q`.
* Deployed-parameter and encoder claims are narrower than their names suggest;
  see `cdrafts-fork/C10DeployedGeometry.ec` sections 35-41.

`cdrafts-fork/C10DeployedGeometry.ec` is a ~2900-line dated log of every claim
this artifact has made and every one it has had to withdraw. It is the honest
record and is more useful than any summary, including this one.

## Reproducing the GREEN

Requires EasyCrypt **r2026.02** (the pinned toolchain; r2026.06 fails four
closure files). A container recipe is in `../docker/`.

```sh
# RUN THEM INSIDE THE PINNED CONTAINER.  These scripts call `easycrypt` straight off
# $PATH, so a bare `bash cert_gate_split.sh` from a host shell silently uses whatever
# EasyCrypt is installed there and produces a PLAUSIBLE BUT WRONG receipt.
sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env); export LC_ALL=C; \
  cd /work && bash cert_gate_split.sh'"   # 38 targets, 1074 pins, 1634 census rows
sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env); export LC_ALL=C; \
  cd /work && bash cert_gate_fork.sh'"    # 19 targets,  9 pins, 1089 census rows
```

`LC_ALL=C` is REQUIRED: identity hashing is collation-sensitive.

**Check the header lines before believing any receipt.** A valid run prints
`### TOOLCHAIN GIT hash: r2026.02` and `### PROVERS <hash> 25 configurations`.
If it says `r2026.06` / `6 configurations`, it ran on the host — discard it.
This paragraph exists because the block above previously showed a bare
`bash cert_gate_split.sh`, which contradicted the r2026.02 requirement stated
one line earlier and duly produced a host-toolchain run on 2026-08-25.

Killing a gate on the host kills the `docker exec` *client*, not the in-container
`easycrypt`, which keeps writing `.eco` into the tree — use
`docker exec ec-grind pkill -f <file>`. The concurrency guard
(`cert_gate_split.sh:167`) catches the leftover and exits 3 rather than emit a
racy receipt.

Both must end `RESULT: GREEN` / `CERT_FAILURES=0`. Expected identities are
committed in `cert-identity.tsv`; each gate recomputes and compares, and
recomputes again at the end to catch drift mid-run.

The gates check, in order: input identity, include-path ambiguity, a
concurrency guard, a verified recursive `.eco` purge, compilation of every
closure file **as an explicit target**, that every closure file is
**requirable** (EasyCrypt returns rc=0 for a file that ends mid-proof — this
phase is what catches that), that named results are `lemma` and not `axiom`,
statement digests, a require-cone census compared as a multiset against a
committed baseline with additions *and* removals fatal, two census-regression
canaries, and controls checked for polarity **and declared failure reason**.

## Layout

| path | what |
|---|---|
| `base-c10-split/`, `base-c10-fork/` | MM45 base, locally modified — see LICENSE.MM45 |
| `cdrafts-split/`, `cdrafts-fork/` | the C10 development (two certified trees) |
| `cert_gate_{split,fork}.sh` | the certification gates |
| `cert-*.tsv`, `closure-c10-*.txt` | manifests: baseline census, statement pins, controls, identity |
| `tools/` | `cert_cone.py` (census), `stmt_digest.py` (statement digests) |
| `scratch/` | control and canary fixtures **referenced by the gates only** |
| `experiments/tcollres-leg/` | on the fork gate's include path; carries three FINDING notes |

Two trees exist because route (D) splits the C10 width across two projection
members; `-split` and `-fork` are separately certified and are not
interchangeable.

## Provenance and licence

`base-c10-*` derives from [MM45/FV-SPHINCSPLUS-EC](https://github.com/MM45/FV-SPHINCSPLUS-EC)
(ASIACRYPT 2024), **MIT licensed** — see `LICENSE.MM45`, which is reproduced
here as that licence requires. Those files are **modified**: relative to
upstream, `SPHINCS_PLUS.ec` differs by ~3729 lines and `WOTS_TW_ES.ec` by ~469;
`FORS_ES.ec` is byte-identical to upstream. Everything under `cdrafts-*` is
this project's own work.

The upstream MM45 clone and the source papers are deliberately **not**
redistributed here; `PROVENANCE.md` records how to obtain them.


---

## UPDATE 2026-08-12 — what changed since the `16fe480` snapshot

Additive note, per this repo's docs convention. The sections above still describe
the artifact; these are the deltas a reader must know before quoting it.

**New certified results.**
* `cdrafts-split/GprocChargedQWired.ec` (closure member #32) —
  `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED`, the first statement here that is
  **N2-free AND Q-wired at once**: the universal grind premise
  `exists c, predC (ThC ps ad m c)` is replaced by an explicit charged summand,
  and the unreduced tree term by three named SM-DT hardness advantages. It
  entered the closure at **zero assumption cost** (census `added=0 removed=0`,
  ledger unchanged at 242).
* `cdrafts-split/DarkSide.ec` + `DarkSideC10.ec` — the FORS+C coverage
  combinatorics, promoted and cloned at C10's `t`.
* `cdrafts-split/GprocQBound.ec` / `GprocQWired.ec` — `Q = T1+T2+T3` bounded and
  wired into the deployed quotation surface.

**A result that CLOSES a question by refutation.**
`scratch/_countermodel.ec` proves, over a **legal** clone of the abstract theory,
`Pr[ITSRC10(...)] = 1`. Therefore **no parameter-independent bound on ITSRC10 is
provable for that game as axiomatized.** This says NOTHING about the deployed
instance (which fixes `mco` at a concrete op); it is not an attack. Negative
control alongside it.

**A finding that should stop a plausible-looking research direction.**
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md` — the CiC
Definition-11 (T-COLL-RES) hop is **UNSOUND at deployed C10**: Def 11 samples
`rho` uniformly per attempt, C10 deterministically enumerates a minimal counter
over a public map, so effective `|R| = 1` and the assumption is FALSE (~2^72.3
birthday, below the project's own 96-bit floor). **The deployed wallet is not
affected** — C10's WOTS layer never encodes an adversary-chosen value. This is a
proof-technique limitation, not a vulnerability. `experiments/` is included in
this snapshot specifically so this finding travels with the artifact.

**Still open, stated plainly.**
* Two `admit`s in the cone, both pinned in `cert-baseline-split.tsv` and both
  verified **non-load-bearing** for the headline: `FORS_C_TreePort.ec:1511`
  (a leaf nothing requires) and `base-c10-split/WOTS_TW_ES.ec:1513` (feeds a
  theorem the capstone never applies).
  **RE-VERIFIED 2026-08-24 against the NEW headline.** This claim is
  capstone-relative, so changing the headline could have invalidated it — the
  `:1513` admit becomes load-bearing for anything that *reduces*
  `M_EUF_GCMA_WOTSTWESNPRF` by applying the existing WOTS theorem. Measured on
  both statements: `GROUNDED` **and** `CHARGED_QWIRED` each carry
  `M_EUF_GCMA_WOTSTWESNPRF` **unreduced on the RHS**, so neither applies that
  theorem and both admits stay non-load-bearing. Checked rather than carried
  over.
* `Pr[M.F.ITSRC10 ..]` and `Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` are carried
  unreduced. Reducing the latter must NOT be done by applying the existing WOTS
  theorem — that consumes the `:1513` admit and would make it load-bearing.
* Residual Q2b (pinning `encode_msgWOTS` to the deployed digit map) is open;
  see `scratch/scope_q2b_VERDICT.md`. It is fidelity, not a security term.

**Scoping verdicts** worth reading before picking up this work:
`scratch/scope_fextractop_VERDICT.md`, `scratch/scope_q2b_VERDICT.md`,
`scratch/wots_leg_state_2026_08_12.md`, `scratch/review_2026_08_11_VERDICT.md`.

---

## UPDATE 2026-08-13 — the WOTS admit is REFUTABLE, and a charged replacement exists

Everything in this section lives in `experiments/wots-badenc/` and
`scratch/wots_admit_is_injectivity.ec`. **None of it is certified.** The gate was
re-run after this work with `INPUTS_SHA256` **byte-identical**
(`eb589cafe306046da0a5d7ba0820c7e9`, 208 OK / 0 FAIL, receipt in
`scratch/RECEIPT-gate-2026-08-13.md`), which is the measurement that this work
sits entirely outside the certified surface. Treat it as a **proposal**.

**The `:1513` admit is not merely unproven — its statement is FALSE at deployed
geometry.** `scratch/wots_admit_is_injectivity.ec` (0 admits, 0 axioms, gated
under both drivers with four graded negative controls) proves the open goal is
*equivalent* to injectivity of `encode_msgWOTS` on the constant-sum surface, and
that at C10's parameters `2^(8*n_m) = w^len * 2^127` — the encoder is
`2^127`-to-one. A single surface collision refutes **the whole five-hypothesis
lemma**, not just its subgoal, because `is_chwcoll` (`:763`) and `is_chwpre`
(`:808`) share the conjunct `BaseW.val em'.[i] < BaseW.val em.[i]`, which under a
collision is `x < x`.

**Consequence that reverses an assumed ordering: Q2b cannot be wired before the
admit is removed.** Pinning `encode_msgWOTS` to the deployed digit map would make
the base file *inconsistent-if-completed*. Checked that this is not already live:
`GprocQWired`'s `hencb` is the encode **bridge**, not the identification, so the
current artifact is consistent.

**The replacement, and it costs nothing.** `admit_free_caller_split` derives
`encode m = encode m' \/ has_chwpre ...` from the already-complete
`nhchwcoll_hchwpre` (`:1476`). The left disjunct is the `BadEnc` event. In
`experiments/wots-badenc/base/` the admit is gone and the WOTS-TW bound carries
an explicit charge instead; `experiments/wots-badenc/cd/` threads it through the
closure (**all 32 closure files build**), and
`cd/GprocQWiredWotsCharged.ec` reduces the previously-raw
`Pr[M_EUF_GCMA_WOTSTWESNPRF ..]` summand — **soundly, for the first time** —
with an anti-vacuity witness whose must-fail control is `runctlw.sh`.

**This supersedes the bullet above** that says reducing that summand "must NOT be
done by applying the existing WOTS theorem". That warning was correct while the
admit stood. The correct statement now: it must not be done by applying the
**pre-charge** theorem; the charged one is admit-free.

**Still open, and it is research rather than plumbing:** bounding
`Pr[Game4_WOTSTWES_BadEnc(..) : res /\ BadEncFlag.badenc]`. This is where +C
seed-withholding finally applies (one layer up the messages are `ThC ps ad x c`,
so `encode o ThC ps ad .` is seed-keyed) — and where a **type-level** collision
must not be mistaken for a **reachable** `ThC`/SHA-256 one. Two losslessness
obligations are also carried as premises rather than discharged.

**Retracted here:** the previous session's recommendation to spend a day on an
isolated "seed-withholding" step. There is no such step — the admitted goal is a
universal statement about a free op with no `ps` in it, so no probabilistic
argument at any layer can prove it. See
`scratch/FINDING-seed-withholding-has-no-isolated-step.md`.

### CORRECTION 2026-08-13 (same day) — the charge is a STRUCTURE, not a small number

The `UPDATE` above is accurate on every point except its implied quantity, and
the omission matters enough to fix in place rather than leave to be discovered.

**The BadEnc term is 1 at the WOTS-TW layer.**
`experiments/wots-badenc/base/BadEncCountermodel.ec` (compiles, 0 admits,
0 axioms) proves the load-bearing half: `verify_encode_transfer` shows
verification reads the message ONLY through its codeword
(`pkWOTS_from_sigWOTS` computes `em <- encode_msgWOTS m` at `:2341` and its loop
touches `em` alone), so under an encoding collision a signature for `cm` *is
already* a signature for `cm'`. The explicit adversary `A_coll` — one query,
forge by REPLAY, never touch `OC` — therefore satisfies every win conjunct.

**So the charged theorem, while TRUE, is quantitatively VACUOUS at a generic
`Adv_MEUFGCMA_WOTSTWESNPRF`: its right-hand side is >= 1.**
`cd/GprocQWiredWotsCharged.ec` inherits this. Nothing above is retracted — the
admit really is gone, the closure really does build, the reduction really is
sound — but it buys an **honest structure**, not a smaller bound.

That is the exact formal content of "MM45's WOTS-TW theorem is false at deployed
C10 geometry". The bound has to live one layer **up**, at +C, where the WOTS
message is `ThC ps ad x c` and the adversary cannot choose it freely — and it
will require a **named hardness assumption on `encode o ThC`**, not a proof. The
countermodel is what makes that assumption unavoidable rather than lazy.

**Still not an attack, and unchanged:** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`). `A_coll` is a
model-level object the deployment gives nobody the ability to build.

Not yet mechanised: the `Pr[..] = 1%r` packaging (oracle losslessness plus WOTS
correctness for the honest query). Each win conjunct was checked at source
individually; what is missing is assembly, not argument.

### UPDATE 2026-08-13 (later) — `Pr[BadEnc] = 1` is now MECHANISED

The correction above said the `Pr[..] = 1%r` packaging was "not yet mechanised".
**It now is**, admit-free, in `experiments/wots-badenc/base/BadEncCountermodel.ec`:

```
lemma badenc_is_one &m :
     P cm => cm <> cm' => encode_msgWOTS cm = encode_msgWOTS cm'
  => Pr[Game4_WOTSTWES_BadEnc(A_coll).main() @ &m
         : res /\ BadEncFlag.badenc] = 1%r.
```

Compiles `RC=0`, ledger class 0. Backed by **four must-fail controls**
(`controls/Ctl{A,B,C,D}.ec`, driven by `runctl.sh`), each failing at a distinct
site: A/B/C each replace ONE hypothesis by `true` — intro arity unchanged, so the
control deletes information rather than breaking syntax — and D mutates the
conclusion to `= 0%r`.

**What made it tractable:** rather than a cross-procedure loop invariant relating
the oracle's accumulator to `verify`'s, both loops are pinned to one functional
characterisation `pkfs_fun`, so WOTS correctness for the honest query becomes
syntactic. `altx_query_computes_fun` is the oracle half; `verify_replay_valid` is
stated parameter-free so the game-level call needs no `exists*`.

**Three limits, stated because they bound what this result means:**

1. **It is CONDITIONAL and that is not closed.** `cm`, `cm'` remain free ops and
   the colliding pair is a HYPOTHESIS. The content is *"if an encoding collision
   on the constant-sum surface exists, the term is 1"* — not an unconditional 1.
   Exhibiting a **deployed-geometry** pair is still residual **Q2b**.
   Satisfiability was checked so the statement is not vacuous: `encode_msgWOTS`
   is free (`:624`), no top-level axiom of the fork constrains it, and a constant
   encoder models all three hypotheses.
2. **"Axiom-free" means none were ADDED.** The proof is relative to the ambient
   declared parameters (`ge2_len`, `ge1_c`, lossless `dpseed`/`ddgstblock`). It
   never unfolds `cf`, so it does not use `ch0`/`chS`, and it sits outside
   `section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF`, so the section-local
   `declare axiom`s are out of scope — `A_coll`'s losslessness is **proved**.
3. Only **concrete-oracle** losslessness of `A_coll` is proved. Instantiating the
   full exported charged inequality at `A_coll` would additionally want general
   `A_coll(O,OC)` losslessness. Not needed here; not done.

So the position is now mechanised end to end: **there is no bound on the BadEnc
term at the WOTS-TW layer, because it is 1.** The bound must live at +C, and will
require a named hardness assumption on `encode o ThC`. This countermodel is what
makes that assumption unavoidable rather than lazy.

**Unchanged:** not an attack. C10's WOTS layer never encodes an adversary-chosen
value (`sphincs-c10/src/fors.rs:265-268`); `A_coll` is a model-level object the
deployment gives nobody the ability to build.

### CORRECTION 2026-08-13 (third) — "seed-withholding is the lever" is REFUTED

Every `UPDATE`/`CORRECTION` above says the BadEnc bound "must live one layer up,
at +C, where seed-withholding finally applies". **The seed-withholding part is
wrong**, and it is wrong in a way that would have produced an unsound assumption.
Both external reviewers found it independently and I verified it at source:

* `WOTS_TW_ES.ec:2526` — `proc choose() : unit { O.query, OC.query }`: the
  adversary **may query the collection oracle during `choose`**.
* `O_THFC_Default.init(ps)` runs **before** `A.choose()` — `OC` is keyed with the
  real `ps` throughout.

So withholding the *value* of `ps` blocks only oracle-free **offline** computation,
which is irrelevant to a collision the adversary can obtain by querying. GPT-5.6:
*"a useful target-selection timing condition, not a hardness proof."*

**Why it matters beyond wording:** writing the +C assumption while believing
withholding is the protection yields a game whose `choose` has no `OC` — which
**under-models the real adversary**. That is a silent soundness gap, not a typo.
The real levers are per-index freshness, `dist_wgpidxs`, and `ThC`-mediation.

### Two further corrections to statements above

1. **"Only the specific deployed adversary."** Wrong. `R_int_WOTSTW` is defined
   for *every* `Adv_MEUFGCMA_WOTSC` (`WOTS_C_Interactive.ec:1753`), so a +C
   theorem can be **uniform over all admissible +C adversaries**, not merely at
   `R_top_C(F)` — a stronger statement than the one claimed above.
2. **"Quantitatively vacuous."** Overstated. `Pr[G] <= terms + Pr[bad]` is the
   Bellare–Rogaway shape and is never `< 1` for all `A`; the defect is the absence
   of a bad-event bound **at the quotation site**, not in the theorem. Likewise the
   countermodel proves probability 1 *conditional on a gated pair it does not
   construct* — the precise claim is that **the generic theory cannot supply a
   nontrivial bound**.

### The number, and what it means for expectations

`|C_T| = [x^205]((1-x^8)/(1-x))^43 = 2^114.0941`; surface fraction `2^-14.906`;
model-level birthday cost `~2^71.95` ThC evaluations. This **reproduces this
repo's own** `experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50`
(`2^114.094`, `~2^72.3`) — convergent confirmation from an independent model, not
a new defect. Consequence: at `(len=43, w=8, target_sum=205)` this term is
**~2^-72-class wherever it is placed and however it is named**. Moving it does not
make it small.

**Deployed classification unchanged, and this is not an attack:** C10's WOTS layer
never encodes an adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`). The
model grants a freely chosen message; the deployment does not.

### Agreed next unit

Move the paid term to the +C layer as `T-COLL-RES-ENUM(encode o ThC)` — whose
discriminator is `d <> d'` (the repo's own **B2** branch,
`experiments/tcollres-leg/Extraction.ec:66-76`), which must **not** require
`c' = grindC` (verify recomputes from the *supplied* counter) and must **keep
`OC` live during `pick`** — *and* carry the `2^71.95` figure to the headline
rather than seeking a placement that hides it.

### UPDATE 2026-08-14 — the charge is MOVED to +C. It is still not bounded.

The WOTS leg is now complete **as a structure**. In order:

1. MM45's `WOTS_TW_ES.ec:1513` admit is **false** at deployed geometry — refuted,
   not merely unproven (`scratch/wots_admit_is_injectivity.ec`).
2. Replaced by an admit-free BadEnc charge; closure rethreaded, **32/32** building.
3. That charge is **provably 1 where it sat**
   (`experiments/wots-badenc/base/BadEncCountermodel.ec`, `badenc_is_one`,
   admit-free, four must-fail controls).
4. So it was **moved**. `experiments/wots-badenc/red/BadEncStep4.ec`:

```
c <= p_tgts =>
Pr[Game4_WOTSTWES_BadEnc(R_int_WOTSTW(A)).main() @ &m : res /\ BadEncFlag.badenc]
  <= Pr[T_COLL_RES_ENUM(R_TCOLL(A), O_TCollEnum_Default, FC.O_THFC_Default).main() @ &m : res]
```

uniform over **every** `A : Adv_MEUFGCMA_WOTSC` — not one instantiation — because
`R_int_WOTSTW` is generic (`WOTS_C_Interactive.ec:1753`).

**The simulation is perfect, and the one real divergence is provably invisible
rather than argued away:** the `FC.O_THFC_Default.tws` transcript differs, but
`get_tweaks` is not in `Adv_MEUFGCMA_WOTSC.choose`'s allowed set
(`WOTS_C_Scheme.ec:142`) and `OC.query` never reads `tws`. It is deliberately
absent from every invariant and deliberately **not** given a control — a control
on an invisible divergence compiles green and means nothing.

**Fifteen must-fail controls** across the three files, all `RC=1`, none producing
a `.eco`. One (`S4CtlG`) is a *necessity control on a proof step*, flagged as such:
the other step-4 controls all fail **inside** `s4_transfer`, so if the closing
`smt()` could discharge the residual without that lemma, they would say nothing
about the bound. It cannot.

**A structural correction found during the build:** the two-term shape
(B1 → S-TCR(+C), B2 → T_COLL) is **wrong at this boundary**. Under
`R_int_WOTSTW`, `forge` returns a `ThC` value (`:1813`), so Game 4's
`is_fresh <- m' <> m` already *is* `dg <> dg'` — the B2 condition. A B1 run makes
`res` false, so charging B1 would add a term that cannot occur, i.e. a weakening.
B1 is charged one layer up, where `WOTS_C_Interactive` already does
`Pr[mu_split (G0_INT.coll)] -> S_TCR_C_Int`. *(Not to be conflated with
`B2_is_empty`, the encoder-bridge question, which is wide open — it is the reason
`T_COLL_RES_ENUM` exists at all.)*

### WHAT IS STILL NOT TRUE

* **Nothing bounds `Pr[T_COLL_RES_ENUM]`.** The term went from provably-1 at the
  wrong layer to an **unbounded assumption at the right layer**. That is the
  entire delta. It is a structure, not a number.
* `T_COLL_RES_ENUM` carries **no disjointness conjunct**, so its win set is larger
  than the S-TCR(+C) template's and the assumption is correspondingly **stronger**.
* At `(len=43, w=8, target_sum=205)` the expectation remains **~2^-72-class**
  (`|C_T| = 2^114.0941`, birthday `~2^71.95`) — a **parameter** property that no
  placement or naming changes.
* `c <= p_tgts` is a premise, not free — though not a new demand:
  `WOTS_C_Interactive.ec:1350` already states it and `interactive_hop1` carries it.

**Still not an attack, unchanged:** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`).

**Still outside the certified surface.** The gate has now run **three times
byte-identical** (`INPUTS_SHA256 eb589cafe306046da0a5d7ba0820c7e9`, receipts in
`scratch/RECEIPT-gate-2026-08-1{3,3b,4}.md`). This whole development is a
**proposal**; promoting it would be a deliberate decision to move that hash.

### CONCLUSION 2026-08-14 — `Pr[T_COLL_RES_ENUM]` cannot be usefully bounded

The obvious next question after moving the charge is "how big is the new term?".
**There is no bound to find**, and the reason is a **parameter fact**, not a proof
gap. Full argument in `scratch/FINDING-tcollres-cannot-be-bounded.md`.

`T_COLL_RES_ENUM` is a hardness **assumption**. Reducing it to a standard THF
assumption is closed off: the **B2** branch — distinct digests, equal codewords —
is exactly what S-TCR(+C) does not cover, which is why the game exists at all, so
a reduction would be circular. The only quantitative statement available is the
cost of the best generic attack:

```
|C_T| = [x^205]((1-x^8)/(1-x))^43 = 2^114.0941
surface fraction = 2^-14.9059
birthday        ~ 2^71.95 ThC evaluations   (memoryless, van Oorschot–Wiener)
```

**No proof can bound an advantage below its best generic attack**, so this term is
~2^-72-class at deployed parameters and no placement, naming, or extra hypothesis
changes it. Reproduced independently twice — by an external model from source
alone, and by this repo's own
`experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:50`.

**Stated carefully.** `tools/forsc_grinding_margin.py:143` sets
`WORK_FLOOR_BITS = 96`, so this leg sits ~24 bits below it. That is a statement
about **the WOTS leg's proof term** — not a claim that the product has 72-bit
security. This repo's own finding warns that two different "96"s exist here
(`:128-129`); do not conflate them.

**Not an attack, and not a false assumption.** C10's WOTS layer never encodes an
adversary-chosen value (`sphincs-c10/src/fors.rs:265-268`): the birthday adversary
needs a freely chosen message, which the **model** grants and the **deployment**
does not. And the assumption is not false — it simply cannot be assumed above its
generic attack.

**What the WOTS track therefore bought:** the obstruction is now *located*. The
`:1513` admit is gone; its replacement charge is provably 1 at the WOTS-TW layer,
so it could never have been bounded there; it is moved uniformly over all +C
adversaries to a named assumption at the keyed-digest layer; and that
assumption's generic attack is computed exactly. **The obstruction is
`(len=43, w=8, target_sum=205)` — a parameter choice, not a missing lemma.**

**The only honest next units:** machine-check the count (nothing in EasyCrypt
states `2^114.0941` today — feasibility unmeasured); carry the figure to the
headline in the `forsc_grinding_margin.py` genre; and a **parameter conversation,
which is an owner decision** — changing `(len, w, target_sum)` changes
`sig = 4008`, the on-chain verifier, and every KAT. Do not spend further effort
trying to prove a bound on this term.

### UPDATE 2026-08-14 (later) — the surface count is now a THEOREM

The `CONCLUSION` above rests on `|C_T| = 2^114.0941`, which until now existed only
as Python plus prose. It is now machine-checked, admit-free, in
`experiments/wots-badenc/count/`:

```
lemma c10_surface_count :
  count_ds 43 8 205 = 22169393903687611906220091621190388.
```

plus the security-relevant integer corollaries `2^114 < count < 2^115` and
`count * 2^14 < 8^43 < count * 2^15` (i.e. `2^-15 < p < 2^-14`, stated over
integers, no reals).

**Feasibility was the open question and the answer is yes** — EasyCrypt evaluates
the 43-step reduction in **41 s**. `iota_`/`iteri` are axiomatised so `simplify`
cannot touch them, and `smt()` on `2^114 = <literal>` fails after 27 s; but
*structural* list recursion over int literals does reduce, so `VecDP.ec` restates
the DP in an accumulator-free sliding-window orientation and `CountDS.ec` proves
the bridge. Measured scaling: 10 steps 0.58 s, 20 → 3.3 s, 30 → 11.9 s, 43 → 41.1 s.

**`count_ds` is a genuine recursion**, `iter n (cstep b) (fun t => b2i (t = 0)) s`
— the constant appears only in lemma statements, never in a definition. Eight
controls; the two perturbations (`205 → 204`, `43 → 42`) each fail **at their own
`ctl_*` lemma rather than at the kernel lemma above it**, so the perturbed
reduction genuinely ran and only the unperturbed constant was rejected. The
constant is independently cross-checked four ways (DP, inclusion–exclusion, direct
polynomial multiplication, and the complement symmetry
`count(43,8,205) = count(43,8,96)` — the last also checked inside EasyCrypt).

**Reusable trap, recorded:** the reduction is asymmetric. A true 43-step equation
reduces in 41 s; a false one at the same scale exhausts the stack (435 s under
unlimited stack). Any `trivial`-invoking tactic (`by`, `//`, `smt`) on a goal
still holding the unreduced term re-runs the whole 41 s reduction, and `apply`
did not terminate in 120 s. **`c10_surface_count` is rewrite-only.**

### THE BOUNDARY — this counts DIGIT VECTORS, not codewords

Stated because the distinction is exactly the one that has bitten this repo
before. The theorem is over `int` lists with entries in `[0,8)`; connecting it to
`emsgWOTS` is **not done**, and five specific blockers stand in the way:

1. `WOTS_TW_ES.ec:74` `const len : {int | 2 <= len}` is not linked to `c10_len = 43`;
2. `val_w : 4 <= w` is not linked to `c10_w = 8`, and `BaseW.val` is not shown to
   range bijectively over `[0,8)`;
3. `WOTS_TW_ES.ec:647` **defines** `target_sum = digitsum (encode_msgWOTS tgt_witness)`,
   not 205 — and `C10DeployedGeometry.ec:101-104` explicitly declines the claim
   that the deployed encoder reaches 205;
4. there is no `emsgWOTS <-> int list` bijection (needs FinType/`Alphabet.enum`
   plumbing plus `digitsum = sumz`);
5. surface ≠ fibre: `|C_T|` counts codewords, while `T_COLL_RES_ENUM`'s B2 branch
   is about *messages* colliding through `encode_msgWOTS`.

**The number is now a theorem; its identification with the codeword surface is
still prose.** Likewise `~2^71.95` remains unmechanised — it needs `sqrt` over
reals; what is mechanised are the two integer facts it is computed from.

---

## CORRECTION 2026-08-14 (final) — BOTH claims above were wrong, in opposite directions

Two external reviewers, asked independently with C10's parameters frozen,
**converged on refuting a premise this README has repeated all along** and
**diverged on the number** — and the divergence is where the information was.
Everything below verified at source. Full write-up:
`scratch/FINDING-both-my-claims-were-wrong.md`.

### (1) "The deployment never lets the adversary choose the WOTS message" is FALSE

This sentence carries the *"not an attack"* classification above, and it is
inherited from `experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md`,
which reasoned that `compute_fors_pk` takes no message argument.

`compute_fors_pk` takes no *message* argument — but **its `roots` argument is
attacker-supplied at verification.** In `sphincs-c10/src/hypertree.rs`:

```
fors_secrets ← read from the signature        (attacker-supplied)
auth_paths   ← read from the signature        (attacker-supplied)
fors_roots   ← reconstruct_fors_root(...)
fors_pk      ← compute_fors_pk(seed, ht_idx, fors_roots)
current_node ← fors_pk                        ← THE WOTS MESSAGE
wots_pk      ← pk_from_sig(..., &current_node, &wots_sigma, count)
```

Nothing validates those secrets before `fors_pk` is formed, and `count` is also
read from the signature. The honest-*signer* statement is true
(`fors.rs:265-268`) and **does not transfer to the verifier** — and the forgery
game is about the verifier. So "WOTS messages are key-determined" is not merely
unproven, it is **provably false at source**.

### (2) But "cannot be usefully bounded, ~2^-72" is ALSO wrong — too PESSIMISTIC

`2^71.95 = 2^57.05 × 2^14.906`, and the second factor is the cost of landing one
sample on the constant-sum surface — which **the oracle pays**
(`ctr <- grindC ps ad m`), not the adversary. So it is **2^57 oracle queries**,
not 2^72 of adversary work.

And a free offline birthday **does not win**: the win condition reads
`(ad,m,ctr,dg,e) <@ O.get(i)` with `0 <= i < nrts`, so **one side of the collision
must be a RECORDED entry**. Colliding two of your own samples wins nothing. It is
a *target search*.

| side | cost |
|---|---|
| query | advantage `q_s² · 2^-114.09`; at the deployed cap `q_s = 2^16` → **2^-82** |
| offline | `2^114.09 / n_ad`; multi-target amplification **dies on address-keying** |

`R` is derived from `sk_seed` (`fors.rs:94-131`), so honest signings cannot be
steered onto one address; even adversary-favourable `n_ad = 2^16` gives **2^98**.

**So the leg's honest ceiling is ~2^98–2^114 work, or 2^-82 at the deployed query
cap — at or ABOVE the 96-bit work floor, not 24 bits below it.** The
`CONCLUSION` section's *"there is no bound to find; do not spend further effort"*
is **RETRACTED**: it priced an attack the query budget forbids.

### The leg is fine — but for the OPPOSITE reason to the one given above

The constraint is not on the *message* side (that freedom is real). It is on the
**target** side: the collision must involve an honestly-signed, address-bound
entry, and those are capped and scattered.

### THE ACTION ITEM — `p_tgts` is unpinned

The entire `2^-82` rests on instantiating `p_tgts` at the deployed usage cap.
**VERIFIED:** `cdrafts-split/WOTS_C_Real.ec:340` —
`const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts` — it is abstract, exactly like
`target_sum`. **Quoting 2^-82 without pinning it would be unfounded.** Target shape,
parameters frozen:

```
for q_s <= 2^16 signing queries and q_h hash queries,
  Adv_T-COLL-RES-ENUM  <=  (q_s^2 + q_h * n_ad_max) * 2^-114.09
```

with `2^-114.09` already machine-checked (`experiments/wots-badenc/count/`).

### Limits — this is NOT a clean bill of health

The `q_s²` and `2^114.09 / n_ad` figures are **generic-model arithmetic, not
theorems** — the same epistemic class as the ITSR margin table. `n_ad_max` is
established nowhere; "honest signings scatter" is an argument about `grind_r`, not
a proved bound. The `ThC`-width question (128 vs 129) sits underneath this term and
shifts the constant. The honest summary is that **the leg's ceiling is set by the
target budget, and that budget has never been pinned.**

### UPDATE 2026-08-15 — `p_tgts` pinned; and the `2^-82` figure is STILL not quotable

`experiments/ptgts-pin/`. The correction above named pinning `p_tgts` as the action
item that would make `2^-82` quotable. **That was wrong**, and the pinning work is
what shows why.

**`c = 262656 = 2^18 + 2^9`, unconditionally.** The hypertree geometry is already
axiomatised in `base-c10-split/SPHINCS_PLUS.ec` (`hp_val : h' = 9`, `d_val : d = 2`),
so no hypothesis is needed. Confirmed against `sphincs-c10/src/params.rs`
(H=18, D=2, SUBTREE_H=9) and `hypertree.rs:23`. `p_tgts` is pinned at `262656`, the
**least** admissible value, and `c <= p_tgts` is discharged in a capstone whose
statement is machine-diffed against `cdrafts-split/C10DeployedCapstone.ec:280-394`
by a self-tested script. Twelve controls; off-by-one **brackets the pin from both
sides** (`262657` passes, `262655` fails).

**Why `2^-82` is still not quotable:**

* it needs `q_s = 2^16` **signing** queries — that is `MAX_SLOT_USES`, an on-chain
  **deployment policy** bound, and **nothing in the model expresses it**;
* `p_tgts` caps S-TCR **targets**; the model's query cap is `c`, which is larger.
  Substituting gives **`c² · 2^-114.09 = 2^-78.09`**, not `2^-82`;
* pinning `p_tgts := 2^16` is wrong twice — `65536 < 262656` fails the premise
  (proved: `c10_usage_cap_is_not_admissible_as_p_tgts`), and it would cap the
  reduction's targets *below what it places*, making the S-TCR win condition FALSE.

Also corrected: the two caps are **~2 bits apart, not ~4**
(`c/q_s = 4.0078 → 2.0028` bits). The `4.006` figure is the **squared** gap —
right for a `q_s²`-shaped term, wrong as a statement about the caps themselves.

**The premise is TRADED, not eliminated:** `c <= p_tgts` becomes
`p_tgts = c10_p_tgts`. Making it unconditional requires
`op p_tgts : int = 262656` in `cdrafts-split/WOTS_C_Real.ec`, which moves
`INPUTS_SHA256` and needs a `cert-identity.tsv` re-baseline — deliberately out of
scope here.

### A separate finding surfaced by the pin: `WOTS_C_Multi` is outside the certified perimeter

**VERIFIED:** `WOTS_C_Multi` appears in **neither** `closure-c10-split.txt` **nor**
any of the four `cert-*.tsv`. No certified run compiles it. The bridging step
"one target per committed query" — which is what gives `c <= p_tgts` its *shape* —
lives at `WOTS_C_Multi.ec:490-494`. So that premise's **justification** sits on a
file the gate never builds, even though its **satisfaction** is now pinned. Same
defect class as the stale `experiments/` files, but inside the premise structure of
the deployed statement.

**What `2^-82` would still need:** an argument that the term counts *signing
queries* rather than hypertree instances, and the `2^16` policy bound imported into
the model. Neither exists.

### CONCLUSION 2026-08-18 — do NOT import the deployment cap, and withdraw the numbers

Asked both external reviewers whether importing `MAX_SLOT_USES` into the model is
right. **Both said no.** Full write-up:
`scratch/FINDING-do-not-import-the-policy-cap.md`.

**The objection that invalidates the whole numeric thread:** *a surface cardinality
does not prove that `Pr[T_COLL_RES_ENUM]` is bounded by a birthday expression.*
`q²/|C_T|` is **not** obtained by counting `|C_T|`. Turning a surface size into an
advantage needs an explicit assumption about how `ThC` images behave against an
adversary holding the keyed oracle and choosing its own counter — and
`TCollResEnum.ec` says outright that nothing bounds it.

**So `2^-82` and `2^-78.09` are WITHDRAWN.** They were heuristic estimates on a
model that was never derived. `"clears the 96 floor"` is withdrawn too: that floor
is a **query-work** floor, `2^-82` is an **advantage**, and
`tools/forsc_grinding_margin.py` carries an F3 correction that exists *because a
previous version made exactly this conflation*.

**And the term is not in the certified statement at all.** VERIFIED: `grep -rn
T_COLL_RES_ENUM cdrafts-split/ base-c10-split/` returns nothing; the certified
capstone RHS (`SphincsC10CapstoneWired.ec:595-604`) carries four other terms.

**The query count fails independently.** VERIFIED on the live closure member
(`XmssmtCC_All.ec:752`): `R_MEUFGCMAWOTSC_EUFNAGCMA_C.choose` computes and stores
**all** WOTS+C public keys — it is **eager**, so `nrts = c = 262656` regardless of
how many signatures the deployment makes. `q_s = 2^16` is wrong and `2·q_s` equally
unsupported; a `q_s`-shaped bound needs an **on-demand reduction**, a rebuild.

*(One reviewer cited a `_wip` file for this, absent from the closure and all four
`cert-*.tsv` — the same non-certified-draft trap `Extraction.ec` sets. The live file
was checked instead. Note the live `R_int_WOTSTW.choose` is by contrast **lazy**:
the eagerness is at the hypertree layer, not the WOTS one.)*

**A reviewer corrected itself, and I had over-recorded it.** A partial (killed) run
called `MAX_SLOT_USES` a "mutable governance parameter"; its completed run withdrew
that. VERIFIED: `PQSmartWallet.sol:71` is a compile-time `constant` with no setter,
consistent with invariant #7 and Rust↔Solidity drift-gated. What survives is weaker
— an imported cap would still rest on the on-chain check and the firmware gate,
both outside EasyCrypt's TCB.

### The honest position on this leg

`Pr[T_COLL_RES_ENUM]` is an **unbounded assumption**; the surface count is a
**theorem**; **no derivation connects them**. What the work bought is precision
about where the ignorance sits — not security.

**Still open, and it is a design-intent question rather than a proof task:** whether
the overall EUF-CMA statement is meant to cover **bootstrap-signed Type-1
authorisations**. If it is, the target-side argument does not apply to the bootstrap
key, which has no device-side cap.

### UPDATE 2026-08-18 (later) — a file ENTERS the certified closure; and the next link in its chain is RED

> **:warning: READ THE CORRECTION AT THE END OF THIS FILE BEFORE §1 BELOW.** The
> *rationale* given in §1 — that gating `WOTS_C_Multi` brought a certified premise's
> justification inside the gate — is **retracted**: the certified capstone does not
> consume D.1 at all. The **mechanics** in §1 (RED -> GREEN, ledger unchanged at
> 242, census additions zero) stand, as do §2-§4.

Two things happened, and the second is the more important one.

#### 1. `WOTS_C_Multi.ec` is now GATED — deliberate re-baseline, ledger UNCHANGED

`c <= p_tgts` is a premise carried by **11 of the closure members, in 48 places**.
The lemma that justifies its *shape* — `D1_reduce` ("the reduction places one
S-TCR(+C) target per committed query", `cdrafts-split/WOTS_C_Multi.ec:523`) — lived
in a file that was in **neither** `closure-c10-split.txt` **nor** any `cert-*.tsv`.
**The gate had never built it.** Write-up:
`scratch/FINDING-c-le-ptgts-justification-is-ungated.md`.

It compiles clean and is zero-admit, so gating it is a strict improvement. Done:
closure `32 -> 33`, `CONE_FILES 43 -> 44`,
`INPUTS_SHA256 eb589caf... -> 45b788a6...`, with the mandatory `cert-identity.tsv`
RE-BASELINE LOG entry.

**Both runs are vendored, and the RED one is the point.** The gate was run *before*
updating the baseline, and it correctly refused the change:

```
scratch/gate_run1_wcm.log   RED (2 failures)
  FAIL INPUTS_SHA256 DRIFT: committed eb589caf..., computed 2af7b788...
  cone: keys now=1113 baseline=1099 | ROWS now=1193 baseline=1179 | added=14
  FAIL cone census GREW -- 14 new rows, ALL from cdrafts-split/WOTS_C_Multi.ec

scratch/gate_run2_wcm.log   GREEN at 45b788a6...
  cone: keys now=1113 baseline=1113 | ROWS now=1193 baseline=1193 | added=0
  ledger=242 (UNCHANGED)   statements pinned=111/111
```

**All 14 added rows are `module` / `module-type` class. The ledger — admits,
axioms, clone-discharges — stayed at 242.** Adding a proof file added zero
assumptions. That is what "ADDITIONS ARE FATAL" is for: it made a deliberate,
reviewable change impossible to make silently.

#### 2. RETRACTION — "`D1_bridge_WOTSTW` does not exist" was FALSE

The finding above originally reported that `WOTS_C_Multi.ec`'s header describes two
bridge artefacts the tree does not contain, and marked it **VERIFIED**. It is wrong.
`D1_bridge_WOTSTW` is at `cdrafts-split/WOTS_C_Bridge.ec:433` — **the same
directory**. The name was searched for *inside `WOTS_C_Multi.ec`* and its absence
**there** reported as absence from the repo: `absence-from-the-wrong-scope`, an error
class this file's own log already records twice.

The chain does exist: `D1_bridge_WOTSTW` (`:433`) -> `D1_MEUFNACMA_WOTSC_MM45`
(`:719`) -> `..._embthfc` (`WOTS_C_EmbDischarge.ec:174`) -> consumed at
`SPHINCS_C.ec:252`.

*(Process note worth keeping: a delegated agent was briefed to write the "does not
exist" sentence into a cone file and **refused**, having checked. Had it complied, a
new false claim would have been installed in the tree.)*

#### 3. THE FINDING THAT REPLACES IT — `WOTS_C_Bridge.ec` does not compile, and says it does

**Measured at r2026.02, in-container.** The terminal
`by rewrite hoq; do ! split; smt().` of the `disj_wgpidxs` bookkeeping step — inside
`D1_bridge_WOTSTW`'s own proof — fails `cannot prove goal (strict)`, `__RC=1`, no
`.eco`. Its header claimed, since 2026-07-08:

> `PROOF STATUS (2026-07-08): PROVED IN FULL — ZERO admits.`

**It is not a prover-budget artefact.** Re-run with `-timeout 120 -max-provers 8` it
fails at the same tactic with the same error after **2592 s**. Receipts:
`experiments/wots-badenc/bridge.out`, `bridge_timeout.out`.

**Indicated cause, not demonstrated:** `fe2b22f` (2026-08-01) retyped the
non-certified side-files for route (D) the same day `msgWOTS` widened to
`mdgstblock` (`ea1087f`). The retype restored **type**-correctness; nothing
re-checked **provability**, because the gate never builds this file.
`WOTS_C_Multi.ec` went through the same retype in the same commit and **does**
compile. No pre-split checkout was reconstructed. Full diagnosis:
`scratch/FINDING-wots-c-bridge-is-genuinely-broken.md`.

**What is NOT claimed:** that the goal is false (`smt` failing is not a refutation),
or that anything certified is affected. `WOTS_C_Bridge`, `WOTS_C_EmbDischarge` and
`SPHINCS_C` are all outside the closure; the gate is GREEN at `45b788a6...` without
them. **"ZERO admits" also remains true** — there is no `admit`/`sorry`/`axiom` in
the file. It does not *admit* the goal, it *fails to close* it. What was false is
"PROVED IN FULL".

The header is now corrected in place with a dated additive note (comments only —
proven, not asserted: a comment-stripper was first shown to **detect** a mutated
`smt()` call, then shown the before/after stripped text is byte-identical).
**The file is deliberately NOT gated**: adding a red file to the closure turns the
gate red by construction.

#### 4. And the two receipts disagree on the line number — on purpose

`bridge_timeout.out` prints `:659`, `bridge.out` prints `:693`. They are runs on
**different versions of the file**: the 39-line correction note sits above the
failing tactic and shifted it. Same tactic, same error, same step. Both the note and
the finding now carry the file state per receipt.

**And it happened again at vendoring time.** Every `file:line` in this section was
re-measured against the snapshot before publishing, and **four of them were stale** —
`D1_reduce` (`:488` -> `:523`), `D1_bridge_WOTSTW` (`:391` -> `:433`),
`D1_MEUFNACMA_WOTSC_MM45` (`:677` -> `:719`), and the `WOTS_C_Reduction` span. The
correction note's own 39 lines had moved two of them. A fifth citation was nearly
dropped as fabricated because a `grep` for its exact phrase found nothing — the
phrase wraps across two lines in the source; opening the file showed the quote is
genuine (`WOTS_C_Reduction.ec:341-344`). All line numbers here are anchored to **this
frozen snapshot**, which is the only reason they can be trusted at all.

This is the **third** time in this one correction that a line reference went stale
under its own edit — the first two being the note citing `:659` after itself moving
it to `:693`, and the note's closing line still saying "until `:659` is repaired".
Everything is now anchored on tactic text. It is a small thing that keeps recurring,
which is the reason it is written down rather than quietly fixed.

#### What this does and does not do for `c <= p_tgts`

**Does:** the lemma giving the premise its shape is now inside the gate, so it cannot
silently rot the way `WOTS_C_Bridge` did.

**Does not:** `D1_reduce` is stated over `STCRC_WC.Col`, while the certified chain
runs over `FC`. `WOTS_C_Reduction.ec:341-344` calls unifying them "the remaining
structural reconciliation", and the bridge that would connect them is the file that
does not currently compile. The premise remains **carried, not discharged** — which
is what the certified statements already say, and they are right to.

**Known gap in the new gating, stated plainly:** the gate proves `D1_reduce`
**compiles**; it does not yet pin its **statement**, so it does not prove the lemma
still *says* `c <= p_tgts`. Closing that means `EXPECT_PINS 111 -> 113` in
`cert_gate_split.sh`. Deliberately not done in this change — a pin on the first link
of a chain whose second link is red would read as more assurance than it is.

### CORRECTION 2026-08-18 (same day) — the certified capstone does NOT consume D.1

Raised by GPT-5.6 in the review round on the section immediately above, and
**re-verified independently at source before being accepted**, because it
contradicts a claim published minutes earlier. Full write-up:
`scratch/FINDING-d1-is-not-the-certified-route.md`.

**What was published:** *"the lemma that justifies [`c <= p_tgts`]'s shape —
`D1_reduce` — lived in a file the gate had never built."* The factual half is
right; the **inference is wrong**, and it is the part that made the change sound
load-bearing.

**VERIFIED.** The capstone discharges the hypertree term by applying the +C
component theorem *directly* —
`SphincsC10CapstoneWired.ec:624`,
`have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF (R_top_C(F)) ...`. The token `D1_`
occurs in that file **exactly once**, in a comment (`:548`), and that comment names
the route actually taken: *"Carried from **`interactive_D1_MA`** up through
`XmssmtCC_All` to here."*

**`interactive_D1_MA` is `WOTS_C_Interactive.ec:3193`, and that file has been IN the
closure all along.** It carries `c <= p_tgts` itself (`:3197`), and the "one target
per query" rationale is stated in the same gated file (`:1350`). Every one of the 11
premise-carrying files is on that interactive route.

**The two developments are parallel, not sequential:**

```
CERTIFIED:  interactive_D1_MA (WOTS_C_Interactive, GATED)
              -> XmssmtCC_All -> SphincsC10CapstoneWired          [GREEN]

PAPER D.1:  D1_reduce -> D1_MEUFNACMA_WOTSC (WOTS_C_Multi, now gated)
              -> D1_bridge_WOTSTW (WOTS_C_Bridge)                 [RED]
              -> WOTS_C_EmbDischarge -> SPHINCS_C                 [ungated]
```

The D.1 chain is a **second, independent assembly of the same leg** (paper 2022/778
App. D). The capstone depends on none of it — which is the real reason the red bridge
costs the certified artifact nothing. That conclusion was stated correctly above; the
*reason* given for it was wrong.

**What the re-baseline actually bought — narrower, but real:** a compiling,
zero-admit file is now inside the gate and cannot rot silently the way
`WOTS_C_Bridge` did. It did **not** bring the certified premise's justification
inside the gate; that was never outside it.

**And a sharper point survives both versions:** *neither* route discharges
`c <= p_tgts`. Both carry it as a hypothesis. "The lemma that justifies its shape"
was the wrong phrase for `D1_reduce` to begin with — `D1_reduce` **uses** the
premise, it does not establish it.

**The framing error, named:** a premise was found in 11 certified files, a lemma
elsewhere was found mentioning the same premise, and the second was concluded to
justify the first — **without checking whether the certified chain reaches it**. A
name-level match read as a dependency. One `grep` of the capstone for `D1_` settles
it. Same family as `absence-from-the-wrong-scope`, inverted: **presence in the wrong
scope, read as relevance.**

**Effect on the deferred `EXPECT_PINS 111 -> 113`:** weaker still. The chain those
pins would protect is not the certified one, so they are drift-hardening on a
**supplemental** development and must be labelled as such if ever added.

### UPDATE 2026-08-18 — the certified statement is ROLE-AGNOSTIC, and no key is named in it

> **:white_check_mark: PARTLY RESOLVED 2026-08-19 — see the final section of this
> file.** The finding below that *"the scope restriction is written down nowhere in
> the EasyCrypt"* was true when written; those facts are now **gated** as
> `cdrafts-split/C10DeployedScope.ec` with six statement pins. Still open, and
> still yours to decide: the instantiation contract naming which key a quoted
> figure applies to.

The open question flagged at the end of the 2026-08-15 update — *does the overall
EUF-CMA statement cover bootstrap-signed Type-1 authorisations?* — is answered.
Full write-up: `scratch/FINDING-bootstrap-scope-is-unwritten.md`.

**It covers them, and that is the problem.** VERIFIED:

```
cdrafts-split/FxChain.ec:255
  module EUFCMA_C10 (F : Adv_EUFCMA_C) =
    DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).
```

The textbook **single-key stateless EUF-CMA game** — one keypair, one adversary, one
signing oracle, and no chain, owner index, wallet, role, or per-key counter anywhere
in it. So the theorem is not slot-only: it applies verbatim to the bootstrap key, and
an adversary collecting `C · 2^16` Type-1 signatures across `C` chains is just *an
adversary in the same game*. **No carried term becomes unsound.**

**And `c` / `p_tgts` were never the signature count** — an error corrected here.
`WOTS_C_Real.ec:41` defines `c` as the **structural** WOTS-TW instance count of the
hypertree (`bigi predT (fun d' => nr_nodes_ht d' 0) 0 d`), which is why it pins
unconditionally at `262656`. `c <= p_tgts` is a reduction-side **target** cap, not a
bound on how many messages a wallet key may sign.

**What actually degrades is the NUMBER.** The generic multi-target contribution is
`(q + q²)·2⁻¹²⁸`, so at `q = C·2^16` the floor is `96 − 2·log₂ C` bits — below 96 as
soon as `C > 1`. The project's own Lean already tabulates this
(`Quantitative.lean:193-210`) and notes there is **no on-chain cap on the number of
chains**.

**THE FINDING — the scope restriction is written down nowhere in the EasyCrypt.**
Checked as an absence claim by searching the *mechanism*: all 33 closure members for
`bootstrap|chain_id|chainid|slot_index|65536|MAX_SLOT|per-chain|wallet`. **Exactly two
hits, both comments, neither a statement** — and the second
(`FORS_C10.ec:87`) is the one place in the certified closure where the deployment cap
appears in a quantitative argument, using the **per-chain `2^16`**: the exact number
that does not apply to the bootstrap key. It is prose justifying a rejected route, so
it moves no theorem — but it is a certified file reasoning from a per-chain cap.

**This is a documentation/scope question, not a proof task.** A second EUF-CMA
theorem "for the bootstrap key" would be the same theorem. What is missing is an
explicit instantiation contract: slot keys instantiate `q` with their capped per-key
count; the bootstrap key instantiates `q` with the **aggregate across every chain
sharing it**; and every quoted bit-figure names which of the two it used. Proving
that mapping is a real project — the Lean file records that even the single-chain
`Reachable -> q <= C` theorem is not assembled (`Quantitative.lean:87-95`).

**Owner decision required:** state the instantiation contract, or restrict the quoted
figures to slot keys explicitly. Realistic bootstrap usage is tens of signatures
(slot rotations only), so practical exposure is far below any of this — but practical
exposure is not what a security claim states, and the claim currently names no key.

### UPDATE 2026-08-18 (round 2) — the two reviewers DIVERGE, and the sharper answer wins

Both models were asked the bootstrap-scope question independently. They **converge**
on the verdict and **diverge on the mechanism**, which is the whole reason for running
two. Full write-up: `scratch/FINDING-round2-divergence-none-of-the-terms.md`;
transcript `scratch/review_kimi_bootstrap_scope_2026_08_18.md`.

| | claim |
|---|---|
| GPT-5.6 | "the directly affected generic multi-target term is `S_TCR_C_Int_MA`; its quadratic component degrades to `96 − 2⌈log₂ C⌉`" |
| Kimi K3 | "**none** of the four terms degrades, by nothing — the model has no signing-query parameter at all" |

**Kimi is right.** VERIFIED: the four carried terms appear in the capstone RHS
(`:595-604`) with **coefficient 1 and no query factor** — bare `Pr[...]` summands;
same in the component theorem (`XmssmtCC_All.ec:8583-8592`). Query counts enter only
as win-condition caps keyed to **hypertree geometry**, not adversary behaviour. GPT
mapped the EasyCrypt term onto Lean's `(q + q²)·2⁻¹²⁸` arithmetic for the *same
assumption* — two different objects. **Nothing in the certified artifact prices `q`.**

So the correct statement is not "the certificate is silently weaker for the bootstrap
key" but **"the certificate is silent, full stop"** — all cross-chain degradation
lives outside it. (The section above already said the number degrades rather than a
term; this sharpens *why*.)

**Three facts the round produced that were not in hand, all verified here:**

1. **A hard structural ceiling that `C · 65536` crosses at C = 4.**
   `FL_SL_XMSS_MT_ES.ec:73` `const l : int = 2 ^ h` with `h = h'·d = 18`
   (`SPHINCS_PLUS.ec:124`), so `l = 2^18 = 262144` messages — the capacity of the
   hypertree game itself. Not a probability claim; the model's geometry. Practically
   irrelevant (real bootstrap use is tens of signatures) but a crisp boundary where
   the discussion previously had only soft arithmetic.

2. **`c <= p_tgts` is ALREADY PINNED where it is load-bearing.** The capstone
   statement is pinned (`cert-statements-split.tsv:3`) and
   `tools/stmt_digest.py:108-113` digests from `^lemma <name>` to `^\s*proof\b` —
   **premises included**. This deflates the deferred `EXPECT_PINS 111 -> 113` a third
   time: not merely on the wrong (supplemental) chain, it **duplicates existing
   protection**. Kimi also caught that the digest's negative lookahead
   `(?![A-Za-z0-9_'])` means a pin on `D1_MEUFNACMA_WOTSC` would not match
   `D1_MEUFNACMA_WOTSC_MM45`; correct targets are `WOTS_C_Multi.ec:523` and `:951`.

3. **The unbounded-query evidence was outside the repo, and I had searched the repo.**
   `DigitalSignatures.eca` is an EasyCrypt **stdlib** theory in the opam switch —
   `~/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca:1335`: *"access
   to a signing oracle that it can query an **unlimited** number of times"*, with
   `O_CMA_Default` keeping a query list as a counter, not a cap. Q1(a) now rests on
   source rather than inference. **That is `absence-from-the-wrong-scope` for the
   fourth time in one day** — this time searching the project tree for a file that
   lives in the toolchain's library path.

**THE BETTER NEXT UNIT (Kimi's, and better than anything on my list): pin the
NEGATIVE scope facts.** `experiments/ptgts-pin/PTgtsPin.ec` already proves them and
already compiles (Kimi compile-tested: RC=0, ~2 s) — `c = 262656`, `! (c <= 65536)`,
`l = 2^18` — and its own prose already says *"nothing in this model expresses the
on-chain 2^16 cap"*. Promoting a cleaned version into the closure with statement pins
turns the finding *"the scope restriction is written nowhere"* from a README paragraph
into a **machine-checked, gated artifact**. It is the only candidate that changes what
can be claimed, and the work largely exists.

Revised ranking: **(1) pin the negative scope facts** · (2) bridge repair, with eyes
open that the certificate does not need it · (3) the statement pins — busywork.

### UPDATE 2026-08-19 — the negative scope facts are now GATED (closure 33 → 34, gate GREEN)

Kimi K3's ranked-#1 unit from the review round, and it was better than anything on
my own list. The finding above was that the **scope** of the certified statement —
what stops a reader quoting it *"at 2^16 uses"* — is written down nowhere in the
EasyCrypt. Those facts existed, but in an **ungated experiment**. They are now
compiled on every gate run and pinned by digest.

**Promoted by MOVING, not copying.** `experiments/ptgts-pin/PTgtsPin.ec` was
`git mv`d to `cdrafts-split/C10DeployedScope.ec` and all ten dependents repointed,
so exactly **one** definition of these facts exists in the tree. A copy would have
been a fresh drift surface — the defect class this whole arc keeps finding.

```
GATE: GREEN (RC=0), in-container r2026.02, 25 prover configurations
  CLOSURE_COMPILED = 34/34        (was 33)
  statements pinned = 117/117     (was 111 — six new pins)
  cone: added=0 removed=0         ledger=242 UNCHANGED
  OK inputs unchanged across the run (bcb2f295...)
```

Both runs are vendored: `scratch/gate_run1_scope.log` is RED **on the drift line
only** — the gate correctly refusing an unbaselined change — and
`scratch/gate_run2_scope.log` is GREEN.

**Zero census rows of any class**, so `cert-baseline-split.tsv` needed **no edit at
all**: the file contains only definitions (`op x : int = <value>`) and proved
lemmas, and a definition is not an assumption. Only the identity row moved.

**And `added=0` was not taken on trust.** It is ambiguous between "nothing new
entered" and "the census never looked at this file" — the
absence-from-the-wrong-search shape recorded four times this week. Settled by
measurement (`experiments/ptgts-pin/census_coverage_probe.sh`): injecting an axiom
into the new file moves `ledger` 242 → 243; removing it restores 242.

**What is pinned:** `c10_c_closed`, `c10_p_tgts_is_least`, `c10_c_le_p_tgts_at_pin`,
`c10_usage_cap_is_not_admissible_as_p_tgts`, `c10_ht_capacity`,
`c10_ht_capacity_vs_usage_cap`.

**What it does NOT buy, stated in the file header:** it does not make the capstone
say anything about query counts — the capstone has no query parameter at all. The
gain is that the facts *bounding that silence* are machine-checked artifacts rather
than prose. A reader asking why "at 2^16 uses" is not a reading of this development
now gets a gated theorem instead of a paragraph.

**The policy cap is NOT imported.** `c10_q_s` (= 65536 = `MAX_SLOT_USES`) occurs
only in the **conclusions** of the section-5 lemmas, never as a hypothesis, and
nothing in `base-c10-split/` or `cdrafts-split/` requires this file. Both reviewers
rejected importing the deployment cap on 2026-08-15; naming it in a *negative*
statement about what it cannot be is the opposite move, and the fence is in the
header so the distinction is not left to the reader.

**Controls.** `pin_discrimination.sh`: deleting each pinned lemma's conclusion
(replacing it with `true`) moves its digest, 6/6 — plus a no-op leg, because if
whitespace also moved a digest then "it moved" would carry no signal. An
axiom-downgrade leg checks that `lemma` → `axiom` yields `NOT-FOUND`, which the
gate hard-fails. `runall.sh`: 11 targets at declared polarity after the move,
statement-identity 0 broken, 0 admits/axioms in code.

**My first version of the axiom-downgrade control passed for the wrong reason** and
is worth recording. The mutation helper threw (it anchored `qed.` at line start;
this file's proofs are one-liners), leaving an **empty** file — and an empty file
also digests to `NOT-FOUND`, the exact verdict under test. Caught by reading the
traceback rather than the verdict. It is now guarded by a size check, and **the
guard is self-tested**: a deliberately truncating helper makes it report
`truncated, not downgraded`.

**Two defects fixed in the file before promotion**, both found by re-measuring
rather than trusting: it cited `WOTS_C_Multi.ec:490-494` (stale — the phrase is at
`:233`, `D1_reduce` at `:523`) and asserted *"`WOTS_C_Multi` is NOT in
`closure-c10-split.txt`"*, which **became false on 2026-08-18** when that file was
gated. The section's conclusion is unchanged, for the reason found the same day:
the capstone does not consume D.1 at all.

**Method note.** I tried to predict the new `INPUTS_SHA256` locally instead of
re-running the gate, got a mismatch, and nearly read it as tree drift. A
**known-answer test** settled it: my script produced `d124120a` for a clean `HEAD`
worktree whose committed identity is `45b788a6`, so the script was wrong — it
omitted the four `base-c10-split` roots the gate adds — not the tree. The gate then
printed `OK INPUTS_SHA256 matches`. A mismatch against a tool written five minutes
ago is evidence about the tool first.

### UPDATE 2026-08-19/20 — the policy-cap fence is now ENFORCED (PHASE 1g), and my first design was wrong

The claim *"we did not import the deployment cap into the model"* held by **inspection
and a header comment**. A future closure member could `require` `C10DeployedScope` and
nothing would notice. It is now a gate check.

**The main result is that my first design was killed before implementation.** It was
three token-greps: no inbound require · the identifier `c10_q_s` is confined to one
file · lemmas naming it carry no `=>`. A 54-agent adversarial review confirmed **33
bypasses**. The decisive three, each re-verified at source:

1. **Re-declare the value under another name** — `op c10_max_slot_uses : int = 65536.`
   in whatever file wants it, plus a premise. No require edge, no occurrence of the
   token. This is the **house idiom**, not a contrived attack:
   `C10DeployedGeometry.ec:66` and `C10DeployedInstance.ec:44` both define
   `c10_n = 16` and **neither requires the other**.
2. **Spell it in model symbols.** This very file proves `l = 4 * c10_q_s`, so `l %/ 4`
   denotes 65536 using only model constants — defeating a token grep, a literal grep,
   **and human review**, since it reads as a structural fraction of hypertree capacity.
3. **`declare axiom` inside a section** carries no `=>`, so an arrow test is blind.

The root error: **a grep keys on a NAME; the object of concern is a NUMBER IN A PREMISE
POSITION.** No enumeration of forbidden syntax closes that. (The review also caught
that `PHASE 1f` was already taken — `cert_gate_split.sh:295`, WATCHED FILES.)

**So the fence is an INVENTORY**, in this gate's own additions-are-fatal idiom, making
the quarantine file immutable-by-default: its committed declaration set (24) and
require set (3) live in `cert-quarantine-split.tsv`, enforced by
`tools/policy_cap_fence.py`. Five checks — isolation-in, isolation-out, sealed-leaf
construct allowlist, declaration inventory, magnitude tripwire.

**And the file is now fully pinned.** It was **6 of 18 lemmas and 0 of 6 ops** — so a
value swap `op c10_p_tgts : int = 262656 -> 65536` moved **no pin**, inside the very
file that quarantines the cap. All 24 declarations are pinned; `EXPECT_PINS 117 -> 135`.

**The fence's own files are hashed**, in *both* the start and end-of-run computations.
An assertion caught that the hash line occurs **twice**; updating only one would have
made them disagree and spuriously tripped "inputs CHANGED DURING THE RUN".

```
GATE run 2: GREEN (RC=0)   identity bcb2f295 -> 2fcbf2ef
  CLOSURE_COMPILED = 34/34      statements pinned = 135/135
  cone: added=0 removed=0       ledger=242
  OK quarantine intact: 24 declarations, 3 require lines, sealed leaf,
     no inbound requires, no magnitude leakage
```

**Controls:** five must-fail controls (`fence_controls.sh`), each asserted to fail *for
the declared reason*, against a green baseline first — a fence that never passes proves
nothing.

**What it does NOT close**, stated in the tool, the manifest, the gate phase and here:
a **new** policy number introduced **elsewhere** under another name — routes 1 and 2
above. Those touch other files, which this fence does not inventory. Closing that class
needs exhaustive statement pinning over all 34 closure members (~623 statements).
Separate project.

#### Run 1 was RED with a second, unexpected failure — published, not buried

`FAIL GprocT1Opre (cli): 473 diagnostic(s)` on a file with **zero source changes**,
which passed in the two runs before and the run after. An `smt` failure under the cli
driver — the load-flake signature this repo already documents for `EncoderBridge.pow8`.
**Cause not established:** I ran probes in the same container during run 1 and none
during run 2, which is suggestive but one trial per arm, not a controlled measurement.
Both receipts are vendored (`scratch/gate_run1_fence.log` RED,
`scratch/gate_run2_fence.log` GREEN). Write-up:
`scratch/FINDING-gate-cli-phase-is-load-flaky.md`.

The tempting response was to re-run and keep the green one. That converts the gate into
a slot machine, and it is the reason both logs are here.

**Method note.** I twice tried to reimplement the gate's `INPUTS_SHA256` locally to
save a 50-minute run. A known-answer test caught **both** attempts wrong — each
reproduced the wrong hash for a clean `HEAD` worktree whose identity is committed. I
stopped after two and used the gate as the authority.

#### CORRECTION 2026-08-20 — the fence above PASSED VACUOUSLY, and my own controls could not have found it

Raised by review of the pushed fence; **confirmed by measurement**. Against a
`cert-quarantine-split.tsv` gutted to comments only, the fence printed
`OK quarantine intact` with `rc=0` — `want_decls` and `want_reqs` both came back
empty, so **Q2 and Q4 silently skipped** and the check reported green while checking
nothing.

That is the exact vacuous-pass shape this tree's controls exist to catch, reproduced
inside a control I had written the previous day — in the same session where I fixed
the same defect in `pin_discrimination.sh`. Twice, same shape.

**Why my own controls could not have found it:** all five **add** something (an
inbound require, a require line, a section, a declaration, a magnitude). Vacuity comes
from **removal**. New control `C0` removes the manifest's rows and asserts the failure
names `Q0`. The suite is now 6/6 for the declared reason, against a green baseline.

**Fix:** a `Q0` anti-vacuity check with `EXPECT_DECLS = 24` / `EXPECT_REQS = 3` as
committed constants **in the tool — deliberately not in the manifest they guard**,
which the same edit could otherwise zero along with the data.

Also: `Q5` is now documented as a **tripwire, not a rule** — `2 ^ 16` will eventually
match legitimate arithmetic in some future certified file, and there is deliberately no
allowlist yet. A `Q5` hit is not proof of a policy import.

```
GATE run 3: GREEN (RC=0)   identity 2fcbf2ef -> 84ebde0d
  34/34 compiled · 135/135 pins · cone added=0 · ledger=242
  OK quarantine intact · OK inputs unchanged across the run
```

**And the flake lead came back negative, which is worth as much as a positive.** The
`ECO_PURGED=37` vs `38` difference in the flaking run is real, is explained (a cleanup
deleted one `.eco` between runs), and **cannot be causal**: all five runs report
`ECO_REMAINING=0`, so every run began from an identical zero-`.eco` state. Run 3 adds a
fourth distinct purge count (`0`) with the same post-purge state and a passing `cli`
leg. `GprocT1Opre (cli)` now stands at **1 failure in 5 runs**; the finding records the
ruled-out hypothesis rather than leaving it open.

### UPDATE 2026-08-20 — ALL 905 statements pinned, plus PHASE 1h, without which the pins buy nothing

Every top-level statement in all 38 certified roots is now pinned by digest.
`EXPECT_PINS 135 -> 932`, new `EXPECT_STMTS = 905`. Gate GREEN. Write-up:
`scratch/FINDING-pins-alone-do-not-close-the-hole.md`.

**The obvious version of this task does not work, and that is the main result.**
PHASE 1c iterates the **manifest** (`done < cert-statements-split.tsv`): it checks that
every *pinned* statement still says what it said, and never reads the files to ask what
statements **exist**. So pinning the 905 that exist today does nothing about a 906th
appearing tomorrow — absence is invisible to a loop over the manifest.

```
PHASE 1c    manifest -> files    a pinned statement cannot silently CHANGE
PHASE 1h    files -> manifest    a statement cannot silently APPEAR unpinned
EXPECT_STMTS                     a statement cannot silently be REMOVED
```

Removal needs its own line: it leaves every surviving pin valid and every remaining
statement pinned, so it is invisible to *both* checks. Control **CV1** — add a lemma,
expect FAIL — is what justifies the whole exercise; without PHASE 1h it passes.

#### Two blockers, found by adversarial review before the gate run

**1. `pred` bodies were watched by nothing.** `digest()` takes only
`lemma|theorem|equiv|hoare|phoare`; `digest_op()`'s alternation lacked `pred`; and
`cert_cone.py`'s abstract scan matches `(const|op|type)` and skips bodies. A pred body
is **pure logical content usable as a lemma hypothesis**, and a statement naming one
digests only the **token** — so appending a conjunct installs that hypothesis into
every statement using it with **zero pin, coverage and census delta**.
`FORS_C_TreePort.ec` declares 9, appearing in 12 results.

That is the exact attack PHASE 1g exists to stop, landing through a surface no phase
watched — and needing no reference to the quarantined file at all. **Control CV5 is the
discriminating evidence:** after the fix, editing a pred body moves the **pred** pin
while the digests of the statements naming it do **not**. That gap is why the pred row
is load-bearing, and a measurement of how invisible the body was before.

**2. Line-anchored scans, in a whitespace-insensitive language.**
`qed. lemma hidden : 1 = 1. proof. trivial. qed.` on one line is legal, saved and
requirable — uncounted, unreported, and *unpinnable*. **The repo already knew the right
idiom and I did not use it:** `cert_cone.py:162` matches `(?:^|\.)\s*(declare\s+axiom|axiom)`,
so a mid-line **axiom** was caught by the census while a mid-line **lemma** was caught
by nothing. Preventive — none exist today. Control CV6.

#### And a defect in the pins that already existed

The anchoring fix surfaced that **11 of the 135 pre-existing pins were over-broad**.
Their lemmas have one-line proofs (`lemma foo : X. proof. by rewrite /foo. qed.`), so
the line-anchored `^\s*proof` terminator found no line-start `proof` until a much later
lemma. `mem4_f`'s pinned span was **331 characters covering four lemmas and their
proofs**; 11/11 swallowed a `qed.`. Those pins were not pinning what their key said.
Corrected here — which is why 11 committed digests move in an otherwise additive change.

**A trap for the next person, recorded because I hit it:** the first anchoring attempt
moved **870 of 923** digests. The cause was the *terminator*, not the declaration
anchor — changing `^\s*proof` to `(?:^|\.)\s*proof` made it match at the statement's own
closing period, silently dropping the trailing `.` from every span. Both must be
re-anchored to their **keyword** via a capture group. **870 means you broke the tool; 11
means you fixed a real defect.**

Also: the comment stripper *spliced* — `lemma(* x *)foo` became `lemmafoo` and the
declaration vanished from every regex. Now separates and preserves newlines.

```
GATE: GREEN (RC=0)   identity 84ebde0d -> 81574675
  34/34 compiled · 932/932 pins · CLI_DISAGREEMENTS=0
  OK coverage: all 905 top-level statements across 38 root files are pinned
  OK quarantine intact · cone added=0 · ledger=242
  OK inputs unchanged across the run
```

**Still not closed, named rather than left to be rediscovered:** coverage enumerates the
**38 roots** while the certified cone is **45 files**, so statements in the 7 non-root
cone files are pinned by neither check; and `abbrev` is pinnable via `digest_op` but
forced by nothing — the same pinnable-but-not-forced shape that made `pred` dangerous.

### UPDATE 2026-08-20 (later) — the 7 non-root cone files are closed; two more blockers, one falsifying my own claim

Coverage now enumerates the **full 45-file cone** instead of the 38 roots. The 79
statements in the transitively-required files were pinned by **neither** check — no
manifest row (invisible to PHASE 1c), not enumerated (invisible to PHASE 1h). One of the
seven is `cdrafts-split/FORS_C.ec`: project code, not vendored library.
`EXPECT_STMTS 905 -> 984`, `EXPECT_PINS 932 -> 1068`. The cone **file list** is committed
too, so a file entering or leaving is fatal rather than silently absorbed.

**Blocker 1 — the cone scanner was line-anchored, and it falsified a claim I had just
written.** `cert_cone.py`'s require regex anchored at `^`, so `qed. require import X.` on
one line **loads X while the cone never sees it** (measured: cone stayed 45, file
invisible). That makes the sentence I had just put in the cone manifest — *"a file
entering the cone is fatal"* — false. And it reached far past that claim: the **same
function** feeds `INPUTS_SHA256`, the PHASE 2 census **and** PHASE 1h, so all three went
blind on one edit — and a cone manifest generated by that tool **agreed with the blind
spot by construction**. Fixed with a zero-width lookbehind, deliberately *not* `(?:^|\.)`,
which consumes the terminating dot and breaks a second require on the same line. Control
CV7c exists so a future "simplification" to that form cannot pass.

**Blocker 2 — bodied definitions are watched by nothing.** `cert_cone.py:324` skips any
`op`/`const`/`type` with a body, and PHASE 1h enumerates only statements. Measured on the
**+C gate predicate**: redefining `FORS_C.ec::predC_fors` to `true` left the digest of the
lemma carrying it **identical** and coverage fully green — **nothing moved**. That is the
`emb_in` shape `digest_op` exists to stop, live in a file this change advertises as newly
covered. The 60 pinnable definitions in the 7 files are now pinned; CV9 shows the pin moves.

**11 controls**, each failing for its declared reason. CV8 — a statement added to a
non-root cone file — is the one CV1 could not catch, and the reason this unit exists.

```
GATE: RED (1 failure)   identity 81574675 -> 3986daa8
  statements pinned = 1068/1068
  OK coverage: all 984 top-level statements across 45 CONE files are pinned
  OK quarantine intact · CLI_DISAGREEMENTS=0 · inputs unchanged across the run
  cone: added=0 removed=0 · ledger=242      <- the regex change perturbed nothing
  FAIL GprocT1Opre                          <- NOT this work; diagnosed below
```

#### The one failure, diagnosed rather than re-rolled

`GprocT1Opre.ec` was byte-unchanged versus HEAD, and my changes cannot reach it —
`cert_cone.py` is static analysis and the digest tools only build manifests; neither
participates in compiling that file. Compiled **in isolation with a pinned budget**
(`-timeout 60 -max-provers 4`): **3/3 clean**, `.eco` produced each time, ~4 minutes per
run.

So **both of my earlier framings were wrong**:

- *"the `cli` leg is non-deterministic"* — it failed **compile** this time, with
  `CLI_DISAGREEMENTS=0`. It is the file, not the leg.
- *"a proof step does not reliably discharge"* — 3/3 cold. It discharges fine given room.

**The accurate statement:** `GprocT1Opre` needs ~4 minutes of prover time alone and sits
close enough to its budget that gate-load contention tips it over, on either driver.
2 failures in 7 full-gate runs; 3/3 cold. The same `EncoderBridge.pow8` pattern this repo
already documents. The fix (pin that file's budget, or make the step deterministic) is
named as a **separate** unit — folding an unrelated gate-timing change into a
cone-coverage commit would make the receipt harder to read, not easier.

**I did not re-run until green and keep the green one.** The RED receipt is published.

**Residual, measured and named:** the bodied-definition hole spans all 45 cone files —
**661** `op`/`const`/`abbrev`, of which **90 are not pinnable** by the current tool (84
resolve to `None`, 6 genuinely `AMBIGUOUS`, e.g. `P` declared four times in
`FL_SL_XMSS_MT_ES.ec`). What landed pins *changes* to the 60 definitions in the 7 files;
nothing yet *forces* a new definition to be pinned anywhere.

### UPDATE 2026-08-20 (final) — `GprocT1Opre`'s budget is fixed, and it was never load

`EC_TIMEOUT=60` is now a **committed constant** in `cert_gate_split.sh`, applied to every
certified-file `easycrypt compile` **and** to the PHASE 1e `cli` leg. The gate previously
ran at whatever the toolchain default happened to be — so a receipt was partly a
measurement of that default rather than of the proofs.

**The controlled experiment I should have run first.** Same file, isolation, the gate's
**exact** flags:

```
run1 rc=0 115s   run2 rc=0 155s   run3 rc=1 104s eco=NO
```

The failure **reproduces with zero gate load**, which kills the contention hypothesis
outright. And PHASE 1 compiles **sequentially** — a plain `while` loop — so there was
never file-level contention to blame, a fact available by *reading* the gate before any
measurement.

**Why I got it wrong:** my "3/3 clean cold" runs had been given `-timeout 60
-max-provers 4`, ~20× the default, while the gate passes no flags. I varied **two** things
— load and budget — saw a difference, and attributed it to the one I had a story for. In
the very finding where I had written *"one trial per arm, not a controlled measurement."*

| # | framing | status |
|---|---|---|
| 1 | "the `cli` leg is non-deterministic" | **false** — later failed **compile**, `CLI_DISAGREEMENTS=0` same run |
| 2 | "gate-load contention tips it over" | **false** — reproduces in isolation. *Published before it was checked.* |
| 3 | "marginal at the default prover budget" | holds, one variable at a time |

**Actual cause:** `GprocT1Opre.ec:1427` in `lemma find_fresh` is `by smt(allP hasP)`,
discharging the `all`/`has` duality by search.

```
default      7/10 pass   (2 fails in 7 gate runs, 1 in 3 isolated)
-timeout 60  8/8  pass   (5 isolated + 3 earlier)
```

`-timeout` only, **not** `-max-provers` — timeout is per prover call, so it costs nothing
on goals that already close quickly, whereas capping parallel provers would slow all 34
files. Cost on the marginal file: ~130s → ~300s. Both drivers get the same budget
deliberately: the first failure was on the cli leg, and different budgets would mean a
reported "driver disagreement" could be nothing but a *budget* disagreement.

```
GATE: GREEN (RC=0)   identity 3986daa8 -> 4af03fe0
  OK GprocT1Opre (compile)  ·  OK GprocT1Opre (cli, 880 cmds)  ·  CLI_DISAGREEMENTS=0
  1068/1068 pins · coverage 984/984 across 45 cone files · quarantine intact
  cone added=0 · ledger=242 · inputs unchanged across the run
```

**The better fix, available and deliberately not taken:** `has_predC : has (predC p) s =
! all p s` at `List.ec:568` makes that `smt` call a named rewrite — deterministic, the
same shape this repo already fixed once for `EncoderBridge.pow8`. It edits a **proof
inside a certified file** under a change scoped to the budget, so it should be its own
reviewed decision.

**The durable lesson:** a budget is a *variable*, and running the control arm with
different flags from the treatment arm is not a control. The receipt now commits the
budget, so "was that a proof failure or a budget failure?" is answerable from the
manifest instead of from someone's memory of which flags they used.

### UPDATE 2026-08-21 — the better fix, taken: the marginal `smt` call is now a named rewrite

`GprocT1Opre.ec:1427`, inside `lemma find_fresh`:

```diff
-  by smt(allP hasP).
+  by rewrite -/(predC _) has_predC.
```

A **proof-only** edit. That `smt` call discharged the `all`/`has` duality **by search** and
was marginal at the toolchain default; `has_predC` (`List.ec:568`) states exactly that
duality, so there is now **no search for a budget to run out of**.

**Measured at the default budget** — deliberately no `-timeout`, because the point is that
the file should no longer *depend* on the budget:

| configuration | reliability | wall |
|---|---|---|
| `smt`, default | **7/10** | 104–155s |
| `smt`, `-timeout 60` | 8/8 | ~300s |
| `has_predC` rewrite, default | **5/5** | **103–136s** |

Reliable **and** ~3× faster than funding the search.

**Proof-only — proven, and the gate agrees.** `find_fresh`'s statement digest is
`2726bead2cc6cbb00819af0d6de19c2b` before the edit, after it, and in the GREEN receipt
(`OK statement pinned: cdrafts-split/GprocT1Opre.ec::find_fresh`). With 1068 statement
pins live, a digest move there would have meant the *theorem* changed, not its proof.

**Negative control run before adopting it** (`scratch/_dupprobe_ctl.ec`): the same tactic
with the hypothesis `hna` **deleted** fails — "cannot close goals", `RC=1`, no `.eco`. A
tactic that compiles is not the same as a tactic that uses its hypothesis, which is
exactly how a control of mine passed vacuously earlier in this arc.

```
GATE: GREEN (RC=0)   identity 4af03fe0 -> e1bcca4d
  OK GprocT1Opre (compile)  ·  OK GprocT1Opre (cli, 880 cmds)  ·  CLI_DISAGREEMENTS=0
  1068/1068 pins · coverage 984/984 across 45 cone files · quarantine intact
  cone added=0 · ledger=242 · inputs unchanged across the run
```

#### And my "cost ~nil" claim for `EC_TIMEOUT` was wrong in two places

Both from generalising a measurement taken on **one file**. `ECFLAGS` was applied to:

- the **PHASE 1e cli leg**, which runs 38 files and inherits the larger budget for any
  marginal goal anywhere in that set; and
- **`cert_gate_split.sh:703`, the PHASE 3 control runner** — where most controls are
  **MUST-FAIL** and a larger budget is actively counterproductive, since it only makes
  them take longer to fail.

This run took **~110 minutes** against ~75 for previous ones. `EC_TIMEOUT=60` is kept —
committing the budget is independently valuable, and it is no longer load-bearing for this
file — but the honest follow-up is to **scope `ECFLAGS` to the compile driver and measure
the difference**, rather than assert a cost a third time.

### UPDATE 2026-08-21 (later) — `ECFLAGS` scoped, and this time the cost is measured

I had applied `EC_TIMEOUT=60` to the compile driver, the PHASE 1e cli leg **and** the
PHASE 3 control runner, and claimed the cost was "~nil" — generalising from a measurement
taken on **one file in a different phase**. That was the third cost/cause I asserted from
a single-file measurement in this arc, and the third one that was wrong.

**Controlled A/B** (`experiments/wots-badenc/ecflags_ab.sh`): same machine, same files,
**alternating arms** so ambient drift is shared rather than loaded onto one side, arms
differing in exactly one flag. Deliberately *not* a comparison of two full gate runs —
that confounds the flag with everything else that differs between runs, which is the exact
mistake behind the retracted "contention" diagnosis.

| leg | default | `-timeout 60` | |
|---|---|---|---|
| **PHASE 3 controls** (2 reps) | 361 s | **7830 s** | **21.7×** → removed |
| **PHASE 1e cli** (4 files) | 125 s | 248 s | +123 s → kept |

```
vac_probe_full    55s -> 1271s      probe_len46   38s -> 687s
c10_spec_vacuity  41s -> 1107s      tier0_degen   46s -> 750s
C10SpecControls (the sole MUST-PASS)      159ms -> 151ms
```

**The controls result is semantic, not just numeric.** Four of the five controls are
**MUST-FAIL** — they exist to be *rejected*. A larger per-prover-call budget cannot make a
must-fail control more correct; it can only make it slower to fail. That the one MUST-PASS
control is unaffected is exactly what that diagnosis predicts.

**The cli leg is a genuine trade, so it stays.** The entire +123 s sits on `GprocT1Opre`
(119 → 242 s); the other three files are unchanged to within noise, two marginally
*faster*. ~2 minutes buys driver comparability — without a shared budget, a reported
"driver disagreement" could be nothing but a *budget* disagreement, which this phase
already caused once with `-iterate`.

```
GATE: GREEN (RC=0)   identity e1bcca4d -> c474ae8e   __WALL_S=5228 (87 min)
  34/34 compiled · 1068/1068 pins · coverage 984/984 across 45 cone files
  quarantine intact · cone added=0 · ledger=242 · CLI_DISAGREEMENTS=0 · inputs unchanged
```

**On the wall-clock comparison, stated honestly:** `5228 s` is an *instrumented*
measurement. The ~75 min (pre-`EC_TIMEOUT`) and ~110 min (`EC_TIMEOUT` everywhere)
figures I quoted earlier were **estimated from log mtimes**, not instrumented — so "saved
~23 min" would be an estimate against estimates. The A/B numbers above are the
trustworthy ones. The run is now instrumented, so future comparisons are measurements.

**Residual noted, not chased:** that +123 s concentration means goals in `GprocT1Opre`
*other* than the one just made deterministic remain budget-sensitive under the cli driver.
Not load-bearing — the leg passes at either budget.

### UPDATE 2026-08-22 — the bodied-definition hole is closed across all 45 cone files

`cert_cone.py` **skipped** any `op`/`const`/`type` whose declaration had a body ("a
definition, not a parameter"); PHASE 1h enumerates only **statements**; and a statement
naming a definition digests only the **token**. So a bodied definition's logical content
was watched by nothing. Measured: redefining `FORS_C.ec::predC_fors` — the FORS+C gate
predicate — to `true` left the carrying lemma's digest identical and coverage green.

**Fix:** bodied definitions now emit `defined-<kind>:<body-digest>` rows — the idiom the
census already uses for modules, with **the digest in the KIND field**, so a body edit is
simultaneously a removed row and an added row (PHASE 2 fatal on both) and a new definition
is an added row. That closes both directions with no per-declaration manifest, and unlike
a pin it covers the 90 declarations `stmt_digest.py` cannot resolve. `abbrev` and `pred`
joined the scanner alternation — neither was in it at all, which is why `pred` bodies were
invisible.

```
GATE: GREEN (RC=0)   identity 09ad5233 -> 6b6cca95   __WALL_S=4728
  cone: keys 1534=1534 | ROWS 1613=1613 | added=0 removed=0
  ledger=242  parameters=215  bindings=345  meaning=389  definitions=422  total=1613
  34/34 compiled · 1068/1068 pins · coverage 984/984 · quarantine intact
```

`ledger` stays **242**: a definition is *content*, not an assumption, so `DEFINITIONS` is a
separate fifth class. Folding 422 rows into the assumption count would inflate the headline
to 664 and make the honest number unreadable.

**Two regressions caught by adversarial review before the first gate run**, the first of
which would have made this change *actively harmful*:

1. The keyword→name separator was `\s*` — **zero whitespace** — so `M.F.predC_fors` parsed
   as `pred C_fors`, `O.opened(i)` as `op ened`. **60 artefacts.** Invisible while bodied
   matches were dropped; emitting rows would have made them live, and PHASE 2 is fatal on
   additions *and* removals — so ordinary **tactic edits** would red-light the gate naming
   declarations that don't exist. Tightened to `\s+`. This bug was already producing **two
   bogus rows in the committed baseline**, hence PARAMETERS 217 → 215.
2. Clone with-clause operands written `name <= value` have no `<-` in their head, so the
   `<=` supplied the `=` and they were classified as definitions — with spans running to
   the *clone's* terminating dot, swallowing later bindings and the `proof` clause. 27 in
   this cone. Now suppressed; they're already `operand:` rows.

Controls 3/3 in both directions: `predC_fors → true` moves a row; a new definition **adds**
a row (forced, not merely caught); internal reformatting moves **nothing**.

#### And a diagnosis of mine, corrected in the same change

I aborted a 4h20m run and blamed `ECFLAGS` on the cli leg plus an "unrepresentative A/B
sample". **Both false.** The 87-minute run (`1414c4c:291`) had the *same* cli flag and
finished all 38 files; the instrumented cost of that flag is 5228 vs 4728 = **~8 minutes**,
consistent with the original A/B. So the A/B was fine and the sampling error I invented for
it never happened.

**The aborted run's slowness is unexplained, and I am not naming a cause.** I have named
four in this arc — cli-leg non-determinism, gate-load contention, a marginal default budget
(that one held), and sampling — and three were wrong. The change stands on the ~8 minute
saving; it was not worth aborting a run over, and the disproving receipt was already
sitting in `scratch/`.

### UPDATE 2026-08-22 — parameterised clone operand bindings closed; and the "unexplained" run was SUSPEND

Both the operand matcher **and its terminator** required the operand name to sit
immediately before `<-`/`<=`, so a binding written with parameters — `op P i <= …`,
`op valid_widxvalsgp adidxswgp <= …` — matched **neither**. Two consequences, the second
worse:

- the binding carried **no census row at all** (21 in the split cone); and
- with the same gap in the terminator, a parameterised binding could not **end its
  predecessor's value**, so that predecessor's digest over-reached into it — a row whose
  content was partly another binding's.

The parameter list is now inside the digest: it is part of the binding's meaning.

**The delta decomposes exactly as predicted, and was verified rather than assumed:**
census 1613 → 1634, **42 added, 21 removed**. All 21 removed names reappear with a
*different* digest — the corrected predecessors — and 21 are genuinely new (`Index.P`,
`DigestBlock.P`, `SAPDL.P`, `DBHPL.P`, `WTWES.valid_widxvalsgp`). Non-parameterised rows
are **byte-unchanged**, which is why the removed count is 21 and not 339.

```
GATE: GREEN (RC=0)   identity 6b6cca95 -> f58333ec   __WALL_S=4705  (vs 4728 baseline)
  cone: ROWS now=1634 baseline=1634 | added=0 removed=0
  ledger=242  parameters=215  bindings=366  meaning=389  definitions=422  total=1634
```

Control CD4 (edit a parameterised binding's value → a row moves) passes; suite 4/4.

#### The "unexplained" 4h20m run was the laptop being suspended

Supplied by the owner, not discovered by me. That 4h20m was **wall-clock including
suspend** — the gate wasn't slow, it wasn't running. So there was never an anomaly; every
cause I proposed for it (the cli flag, an unrepresentative A/B sample) explained a
phenomenon that did not occur, and I **aborted a healthy run** over it.

**The method error is the reusable part.** I derived a *rate* — "12 of 38 files in 3h56m" —
from log mtimes and wall-clock **on a laptop**. Wall-clock is not elapsed compute. The
distinguishing measurement was cheap and I was already running `ps` for elapsed time: I
read the wrong column. `ps -o times` (cumulative CPU) does not advance across suspend.
This run was checked that way *while in flight* — `etime 08:59` against `CPU 522s`, i.e.
~97% CPU-bound. That is now a standing rule in `cert-identity.tsv`: quote CPU time, or
pair it with wall, before inferring a rate.

### UPDATE 2026-08-22 (final) — the fork baseline is GATE-VERIFIED

The fork baseline was regenerated **mechanically** on 2026-08-21 (because `cert_cone.py`
is shared between the two gates) and honestly marked `NOT GATE-VERIFIED` at the time.
That is now closed.

**Run 1** (`scratch/gate_run_fork.log`, `__WALL_S=2718`): `CERT_FAILURES=1` — and that one
failure was the `INPUTS_SHA256` drift line, expected since `cert_cone.py` is in the fork
gate's hashed set. **Everything else passed first time:**

```
CLOSURE_COMPILED = 19/19
CONE keys now=1377 baseline=1377 | ROWS now=1456 baseline=1456
CONE_ADMITS = 2      (the fork's two known admits)
```

**The census matching exactly is the point.** A regenerated baseline is only as
trustworthy as the tool that produced it — and I wrote that tool — which is precisely why
it was marked unverified rather than quietly shipped as fine. The gate independently
computing the same 1456 rows is what turns *plausible* into *correct*.

**Run 2** (`scratch/gate_run_fork2.log`, `__WALL_S=2731`): `CERT_FAILURES=0`,
`__GATE_RC=0`, `OK inputs unchanged across the run`. Identity `7ab20d2a -> 9c2d2128`.

So the fork tree was **healthy throughout**; the only thing wrong was an identity that
hadn't caught up with the shared `cert_cone.py` change. Both receipts are committed — the
RED one included, since it is the evidence that the census matched *before* the identity
was touched.

**Incidental finding worth keeping:** the fork gate's cone spans **three** directories —
`base-c10-fork`, `cdrafts-fork` and `experiments/tcollres-leg` — where the split gate
spans two. Its own comment records that the split gate "never had this hole because its
compile set and hashed set are the same two directories." So the fork hashes a *wider* set
than I assumed when I called the regeneration mechanical.

### UPDATE 2026-08-22 — both gates re-confirmed GREEN after a full machine restart

Not a new change — a **reproduction**. The machine was rebooted, the `ec-grind` container
brought back up, and both gates run to confirm the certified state survived.

```
SPLIT   RESULT: GREEN     __GATE_RC=0   __WALL_S=4467
FORK    CERT_FAILURES=0   __GATE_RC=0   __WALL_S=2594
```

**Every gated number is identical to the pre-reboot receipts** — "both green" alone would
be a much weaker claim:

| | pre-reboot | post-reboot |
|---|---|---|
| split cone | `ROWS 1634=1634, added=0` | **same** |
| split classes | `ledger=242 · parameters=215 · bindings=366 · meaning=389 · definitions=422` | **same** |
| split pins / coverage | `1068/1068` · `984/984` | **same** |
| fork | `19/19`, `ROWS 1456=1456`, `CONE_ADMITS=2` | **same** |

Run **sequentially, not in parallel**: concurrent runs contend for provers, and each
receipt would then be partly a measurement of the other — the flake class this arc spent a
long time diagnosing.

Wall-clock moved slightly (4705 → 4467 and 2731 → 2594, both ~5% *faster* on a freshly
booted machine). That is the only difference, it is not a gated quantity, and the
CPU-vs-elapsed check was run in flight to confirm the work was real (`etime 11:54` vs
`CPU 691s`, ~97% CPU-bound).

**Why this earns a receipt:** it is an independent reproduction on a fresh boot, so the
GREEN is not an artifact of accumulated machine state — stale `.eco` caches, a warm
prover, leaked container processes. And the identity matched *before* any proof was
checked (`f58333ec` split, `9c2d2128` fork), so the tree came back from the restart
byte-identical to what was certified.

### UPDATE 2026-08-24 — H1 resolved: the phantom `mkg_adv` summand is dropped

`FxChain.ec:2824-2834` has carried this as an **open accounting hazard against the
capstone**, in its own words:

> *"`mkg_adv` becomes a PHANTOM summand: sound as an upper bound but **silently zeroable
> by a consumer**, and double-paying if kept alongside the already-idealised `dcond` LHS.
> Honest fix: drop `mkg_adv` from the +C FX PRF-term sum … **Do NOT leave it as an
> in-chain MKG-PRF summand.**"*

The headline still carried it — the one **free real** in a theorem whose own front page
condemns free reals because they can *"be set to 1 at will."*

**New lemma `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT`.** The discharge is trivial
because of how the term enters: `mkg_adv` is a **lemma parameter** — universally
quantified, constrained only by `0%r <= mkg_adv`. A statement holding for *every*
admissible value holds at `0`, and `0` is the **tightest** admissible value. So the
tightened form is sound, **strictly tighter** (a non-negative summand removed), carries
**one fewer premise**, and contains **no free real**. The named hazard — *silently zeroable
by a consumer* — is closed by doing the zeroing here, visibly, rather than leaving it
available to whoever quotes the theorem.

**What it does *not* mean**, and the same comment is explicit: *"WHERE THE GENUINE mkg TERM
LIVES (it is NOT zero)"*. The real RO-idealisation sits at the **model-definition /
pre-hop-1 boundary** — production's keyed salted grinder idealised to the
uniform-conditioned `dcond` draw — **not** between NPRFPRF and NPRFNPRF. Dropping the
in-chain summand does not make that idealisation free; it stops the chain **double-paying**
for something already priced in the model definition. That assumption stays open.

**Statement derived mechanically**, not retyped: parameter, premise and summand deleted
from the parent by script, asserting no `mkg_adv` token survives.

**Vacuity control — and the first attempt did not count.** Replacing the `ITSRC10` summand
with `0%r` must break the proof. My first attempt hit a regex miss, never mutated the file,
and returned `RC=0` — which I did **not** read as a pass. Re-armed against the real text:
`RC=1`, no `.eco`, "cannot prove goal (strict)"; restored: `RC=0`, `.eco`. So the lemma
genuinely needs the term.

```
GATE: GREEN (RC=0)   identity f58333ec -> cb901c18   __WALL_S=4539
  1069/1069 pins · coverage 985/985 across 45 cone files · quarantine intact
  cone: added=0 removed=0 · ledger=242 · CLI_DISAGREEMENTS=0 · inputs unchanged
```

**A strictly stronger theorem at zero assumption cost** — `cert-baseline-split.tsv` needed
no edit at all.

### UPDATE 2026-08-24 (second) — the clean statement now exists AT DEPLOYED PARAMETERS

Surveying the whole capstone family exposed a gap:

| | N2 | Q | free real | deployed |
|---|---|---|---|---|
| `CHARGED_QWIRED_TIGHT` | — | — | — | **no** |
| `AT_DEPLOYED_PARAMS`, `..._PINNED_ENCODER`, and both QWIRED forms | **N2** | varies | — | yes |

**Every deployed variant carried N2**, while the only statement free of N2, of `Q` *and*
of the free real `mkg_adv` was not deployed. So the surface the product actually quotes —
at C10's pinned parameters — was strictly **weaker** than the abstract headline.

`EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS` closes it: the **first**
deployed statement that is N2-free, Q-free and free-real-free. All four properties measured
on the statement text, not asserted.

**What is traded, stated plainly.** The four *abstract* width disequalities are discharged
by `c10_dfC_separations_deployed` (`C10DeployedInstance.ec:294`) from the four *deployed*
parameter pins. That is a **trade, not an elimination** — the premise count stays 6. What
it buys is premises about deployed parameters (n=16, len=43, k=13, embedding width) rather
than an abstract constant, which is the point of a deployed quotation surface.

```
GATE: GREEN (RC=0)   identity cb901c18 -> 6eead428   __WALL_S=4410
  1070/1070 pins · coverage 986/986 across 45 cone files · quarantine intact
  cone: added=0 removed=0 · ledger=242 · CONE_FILES still 45
```

**Third consecutive change at zero assumption cost.** The added
`require import C10DeployedInstance` pulls in a file that was *already* a closure member —
checked, not assumed.

**Two mistakes, both caught by the compiler**, the second a method error: `c10_n` was out
of scope (fixed with the import `GprocQWired.ec:55` already uses); and I wrote the proof
binders in the *other* lemma's premise order while the mechanically-derived statement kept
its parent's order, misaligning every name. EasyCrypt reported it exactly — *"this
proof-term proves: `c <= p_tgts` / but is expected to prove: `n = c10_n`"* — and the fix
was read off the error rather than guessed.

**A number I quoted but never published, corrected:** I reported
`AT_DEPLOYED_PARAMS_QWIRED` as having "3 premises". It has **seven**. My counting script
counted lines *ending* in `=>`, silently missing multi-line premises. Re-counted by proof
binders: `GROUNDED` 7, `CHARGED_QWIRED` 7, `TIGHT` 6, `AT_DEPLOYED_PARAMS_QWIRED` 7 —
every count in this README was right; only the verbal one was wrong.

### UPDATE 2026-08-25 — the encode-compat premise is DISCHARGED, not traded

`hencb` — `forall p a x cc, encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)` —
was a premise of every capstone in this tree since the family was built. It is now a
**theorem**. **Only the four members of the charged-Q-wired headline family actually drop
it**; the legacy capstones (`SphincsC10CapstoneCharged.ec`, `GprocQWired.ec`,
`SphincsC10CapstoneWired.ec`, `C10DeployedCapstone.ec`, `GFailCharged.ec`) still carry it
as a now-tautological premise. "Discharged" below means *discharged in the headline
family*, not tree-wide.

**What changed, in one line.** `encode_msgWOTS_C` was a FREE op
(`cdrafts-split/WOTS_C_Real.ec`, previously line 377). It now has a body:
`encode_msgWOTS (ThC p a x cc)`.

**Why that is a discharge and not a sleight of hand.** Among the models that satisfied
the premise, the theorem covers exactly what it covered before: the premise pinned the op
to this value already, so the capstone's instances are unchanged, and **no axiom was
added** (ledger 242, and `defined-op` is not a ledger class). That is different in kind
from the 2026-08-24 deployed-params work, which **traded** four abstract width facts for
four deployed pins.

> **:warning: CORRECTED 2026-08-27 (GPT-5.6 adversarial review, verified).** This
> paragraph originally claimed *"every model of (free op + premise) is a model of the
> definition and conversely. **The model class is unchanged**"*, and called the edit a
> **conservative definitional extension**. **Both are false**, and the falsifier is
> already in this tree: `WOTS_C_Real.ec::encode_msgWOTS_C_compat` is now provable with no
> hypotheses and was **not** provable before — my own two-sided control
> (`scratch/encode_compat_derivable.ec`) measured exactly that, RED with the abstract
> declaration. A conservative extension cannot create a new theorem in the old language.
> The premise was an **antecedent of individual theorems**, never a global constraint, so
> the old theory admitted models where the equation fails; those models are now gone.
> **The global model class SHRANK.** The accurate description is: *an axiom-free
> specification change that internalizes the previous capstone hypothesis — it restricts
> the model class, while covering exactly the old capstone instances that satisfied
> `hencb`.* Say "zero new axioms", not "zero semantic cost".

**Premise counts, measured from the proof binders** (not from lines ending in `=>` — that
method produced a wrong count once in this log already):

| theorem | before | after |
|---|---|---|
| `EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED` | 7 | **6** |
| `..._TIGHT` | 6 | **5** |
| `..._TIGHT_AT_DEPLOYED_PARAMS` | 6 | **5** |

For the deployed statement, three of the five remaining premises were the parameter pins
`n = c10_n`, `len = c10_len`, `k = c10_k`.

> **:warning: CORRECTED 2026-08-27.** This paragraph originally continued: *"Exactly one
> substantive premise is left: `c <= p_tgts`."* **That overstated the artifact**, by
> counting `size (emb_in witness) = 8*n + c10_r` as a deployed parameter pin. It is not —
> it constrains the FREE op `emb_in`, which nothing in the closure pins. And the three
> genuine pins turned out to be **removable**, not merely redundant-looking: see the
> 2026-08-27 section at the end of this file. The deployed statement now carries **two**
> premises and **both are substantive**: `c <= p_tgts`, which `C10DeployedGeometry.ec:468`
> classifies as "NOT A THEOREM AND NOT MEANT TO BE … a PARAMETER CHOICE … satisfiable by
> construction"; and the `emb_in` width fact, which is the artifact's least visible real
> assumption.

#### This is NOT the move this tree previously declined

`C10DeployedGeometry.ec:453` records `hencb` as "NOT RECEIPTABLE HERE, and deliberately
not faked". Read precisely what it rejects:

* an **existential** receipt `exists E, forall .., E .. = encode_msgWOTS (ThC ..)` —
  "trivially true (take the composition) and says NOTHING about the actual op";
* a **`clone … realize`** — "EasyCrypt cannot re-interpret an already-declared op FROM
  INSIDE THE THEORY".

This is neither. It edits the **declaration site**, which is the one place the
re-interpretation obstruction does not apply, and it constrains **the actual op**.

`C10DeployedGeometry.ec:598` calls `hencb` "LOAD-BEARING", but the stated consequent is
that **dropping** it kills the reduction to MM45's WOTS-TW. Nothing is dropped: the
equation still holds, now by computation, so `R_int_WOTSTW` is preserved exactly. That
section also calls `hencb` "the whole of the unfaithfulness" because it forced `ThC`'s
output to width `8*n` — but that is a **fork-tree** statement written 2026-07-31, before
the split. In the split tree `msgWOTS = mdgstblock` at independent width `8*n_m`
(`WOTS_TW_ES.ec:270`) and `ThC` already returns the wide type. That is what the split was
for; the fork's unfaithfulness verdict does not carry into it.

#### The evidence, two-sided

`scratch/encode_compat_derivable.ec` (MUST-PASS, gate-run) proves `hencb` **with no
hypotheses**. Measured both ways:

* op DEFINED → `__EC_RC=0`
* op reverted to the abstract declaration → `[critical] … [by]: cannot close goals`,
  `__EC_RC=1`

So the control **deletes information**: it goes RED for the declared reason if the body
is removed. It is not a restatement of the definition.

`encode_msgWOTS_C` is now **op-pinned**, which it was not before — `predC`, `ThC`,
`emb_in`, `emb_in0`, `emb_in1` and `emb_tw` all were, and this one was missed. The pin is
body-sensitive, measured before being trusted: a semantic body change, a purely cosmetic
reparenthesisation, and a revert to abstract each move the digest
(`scratch/encode-compat/PIN_DISCRIMINATION.txt`). The bridge equation is additionally
kept legible in the closure as the named lemma
`WOTS_C_Real.ec::encode_msgWOTS_C_compat`, also pinned — a reader auditing what this
artifact commits to about the encoder should not have to notice that an op quietly
acquired a body.

#### Cost: zero assumptions

Census: `abstract-op` 145 → 144, `defined-op` 301 → 302, total 1634 → 1634,
**LEDGER UNCHANGED AT 242**. Predicted in `scratch/encode-compat/PREDICTION.md`
*before* the run and matched exactly, row for row.

#### What this does NOT mean

**"One fewer premise" is not "one fewer assumption about the deployed signer."** What was
eliminated is a **model-internal degree of freedom**. After the change the correspondence
to the deployed encoder is carried entirely by `ThC`, whose own deployment gaps are
unchanged and unreceipted: `emb_in` and `thfc` are still free ops, and the two projection
members remain correlated under the instantiation. `encode_msgWOTS` itself also remains
free, so no generality is lost in the encoder — but none is gained in fidelity either.

The headline is still not a numerically meaningful bound. `Pr[M.F.ITSRC10 …]` is carried
unreduced and is **provably** irreducible (`scratch/_countermodel.ec::countermodel_pr1`).
Discharging `hencb` moves a premise; it does not touch that.

#### Three corrections from this change

**I ran the gate on the host first and it was wrong.** The receipt printed
`### TOOLCHAIN GIT hash: r2026.06-16-g3800968` and `### PROVERS … 6 configurations`;
a valid run prints **r2026.02** and **25 configurations**. The gates call `easycrypt`
straight off `$PATH`, and "Reproducing the GREEN" above showed a bare
`bash cert_gate_split.sh` one line after stating r2026.02 is required. The two disagreed
and I followed the copy-pasteable one. That section now shows the `docker exec` form and
names the header lines to check.

**I recomputed `INPUTS_SHA256` myself instead of reading it off the gate — twice, wrongly.**
The hash is collation-sensitive, and host runs without `LC_ALL=C` produced two
plausible-but-wrong values (`ddd456c5…`, `2bcbb7ce…`). Same shape as a third error the
same day: I hand-rolled the census `comm` comparison instead of using the gate's pipeline
and got a meaningless total-diff. **When the gate computes a number, take the gate's
number.** `scratch/encode-compat/inputs_id.sh` now recomputes it correctly and is
self-validating — it reproduces the gate's printed value on an unchanged tree.

**I recorded a false finding as fact.** An audit lens reported that my container-gate
runner self-matched its own `grep`, and I wrote that up as a confirmed bug without testing
it. It is **false**: measured `SELF_MATCH_COUNT=0` both ways, because the regex
`[e]asycrypt` needs an `e` immediately followed by `asycrypt` and the literal text
`[e]asycrypt` has `e` followed by `]` — which is the whole point of the idiom. Two
reviewers disagreed and I believed the wrong one. The lesson recorded in
`scratch/encode-compat/AUDIT_FINDINGS.md`: I *did* verify the fork-gate and arity hazards
by hand and skipped this one, because it was a claim about **my own** mistake, which I was
primed to accept. A reviewer's finding about your error deserves more scrutiny, not less.

**Related, and load-bearing for anyone re-running this:** killing a gate on the host kills
the `docker exec` client but NOT the in-container script, which keeps writing `.eco` into
the tree — the incident `cert_gate_split.sh:163` records. It happened twice here. Use
`docker exec ec-grind pkill -f <file>`.

#### A stale claim that NO GATE CAN CATCH

Adversarial review found `cdrafts-split/SphincsC10Content.ec:570` still annotating
hypothesis (iv) as *"the ACTUAL `encode_msgWOTS_C` — a **FREE op**"*. After this change
that is false, and the file is inside the certified cone and inside the identity hash.
**Comments carry no census rows and no statement pins, so a fully GREEN run certifies the
false sentence.** The sibling site in `C10DeployedGeometry.ec` had already been amended;
this one was missed. Both are now corrected, and the annotation carries a note saying the
gate could not have caught it. The hypothesis itself is **kept** — dropping it would move
a pinned statement, which is a design decision and not a comment fix. A stale
`WOTS_TW_ES.ec:569` cite (actual: `:624`) was corrected in the same pass. Verified: both
files still compile and **no pin moved**.

#### The fork tree

Unchanged, checked two ways rather than assumed. Its `INPUTS_SHA256` recomputes to
`9c2d21280c84d52c30b22111151f1135` — **identical** to the committed value — over the
computed require-cone of the fork roots plus `cert-baseline.tsv`,
`cert-statements-fork.tsv`, `cert-controls.tsv`, every control source, the five canaries,
both tools and `cert_gate_fork.sh`. That is stronger than "no fork file in `git status`".
The full fork gate was then run as behavioural confirmation.

Note for future runs: **the two gates race bidirectionally on `scratch/`** —
`cert_gate_fork.sh:164-166` purges it recursively and `:167` fails if any `.eco` survives
there, while `cert_gate_split.sh:189` purges the same directory and builds its six
controls in it. Their own concurrency guards do **not** cover this pair: they grep for
`base-c10-split` and `base-c10-fork`, which are disjoint. Run them sequentially.

#### Adversarial audit

A four-lens read-only audit ran against this change before it was committed
(`scratch/encode-compat/AUDIT_FINDINGS.md`). It confirmed the op is unconstrained
by construction rather than by keyword search — all 29 axiom/declare-axiom rows in the
cone live in 8 files, none of which mentions the token — and raised one **serious**
hazard worth recording: `cert_gate_fork.sh` reads `cert-controls.tsv` (no `-fork`
suffix) **wholesale** and compiles each control with fork includes, where the op is still
abstract at the older type. A MUST-PASS control registered there would have turned the
sibling gate RED for a reason nobody would look for. Verified by hand: the control is in
`cert-controls-split.tsv` only. The control fail-open floor was raised 5 → 6 in the same
change, since a floor below the actual inventory cannot detect a control being deleted.

#### Receipts

Both gates GREEN inside `ec-grind` (**r2026.02, 25 prover configurations**).

```
SPLIT   ### RESULT: GREEN            __GATE_RC=0   __WALL_S=5227
        OK  INPUTS_SHA256 matches the committed identity (88de8169...)
        statements pinned = 1072/1072
        OK  coverage: all 987 top-level statements across 45 CONE files are pinned
        OK  quarantine intact
        cone: keys 1555=1555 | ROWS 1634=1634 | added=0 removed=0
        ledger=242  parameters=214  bindings=366  meaning=389  definitions=423
        controls executed (unique)=6
        OK  inputs unchanged across the run

FORK    ### CERT_FAILURES=0          __FORK_RC=0   __WALL_S=2736
        OK  INPUTS_SHA256 matches the committed identity (9c2d2128...) -- UNCHANGED
        statements pinned = 9/9 | controls 12/12, each for its DECLARED reason
        OK  inputs unchanged across the run
```

### UPDATE 2026-08-26 — "neither admit reaches the headline" is now GATE-ENFORCED (PHASE 5)

This artifact has said, in this file and in `project_c10_two_admits_scoped`, that **neither
of the cone's two admits reaches the headline**. That was true, and it was **hand-verified
each time somebody remembered to re-verify it**. Nothing in the gate checked it.

The fail-open was recorded in the admits note verbatim: *"`ledger class = 0` computed
**file-locally** reads as 'admit-free cone' and is a fail-open. Assert instead that the
file never **applies** the tainted lemma."* PHASE 5 does that.

#### What it computes

`tools/taint_closure.py` seeds on the cone's `admit`ed lemmas and takes the fixpoint of
"lemma L's proof body names a tainted lemma", over **comment-stripped** code. The result
is pinned in `cert-taint-closure.tsv`; **entering and leaving are both fatal**, the same
discipline PHASE 2 applies to the census.

```
A  nhchwcoll_hchwpre_msg  (ADMIT)                       base-c10-split/WOTS_TW_ES.ec:1505
     -> Step_Game4_WOTSTWES_SMDTPREC                                              :6338
     -> MEUFGCMA_WOTSTWESNPRF                                                     :6578
     -> EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded    XmssmtCC_All.ec:8811  <- APPLIED BY NOTHING
B  extract_op              (ADMIT)               FORS_C_TreePort.ec:1485
     -> fors_c_tree_port                                             :1646  <- APPLIED BY NOTHING
```

Six lemmas; **both chains terminate in a dead leaf**, and none of the six headline results
is among them.

**Why this is worth a phase rather than a comment.** `nhchwcoll_hchwpre_msg` is not merely
unproven, it is **REFUTABLE** — a collision falsifies the whole five-hypothesis lemma, for
any `sig`/`sig'`. So the containment is not a tidiness property: wiring
`EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded` into the headline would promote a **false** lemma
into the certified result. The admits note already names that as *the* regression to guard
("merely wiring `_Unfolded` is a REGRESSION"). Control **T1** performs exactly that wiring
and requires the gate to reject it.

#### Honest scope — this is the deliverable as much as the check is

PHASE 5 is a **NAME-LEVEL OVER-APPROXIMATION**, not a proof-term dependency check.
EasyCrypt has no `#print axioms`. It does **not** see:

* a bare `smt()` that takes a lemma from ambient context without naming it;
* reachability through a clone instantiation or a module argument rather than a named
  application.

> **:white_check_mark: THE SECOND HOLE IS NOT LIVE, AND IS NOW GUARDED — measured
> 2026-08-28.** Of **80 clone statements** across the 45 cone files, **zero** name an
> admit-containing theory, and both admits sit at **file top level** — not inside any
> cloneable sub-theory — so cloning the whole file is the only clone route and nobody
> takes it. `tools/taint_closure.py` now refuses any clone naming an admit-containing
> theory, deriving those names from the **computed** admits rather than a hardcoded list,
> with a floor on the clone count so a broken scanner cannot pass the guard vacuously.
> Controls **T9** (clone an admit-containing theory -> must be refused) and **T10** (blind
> the clone scanner -> must fail as vacuous) cover both directions.
>
> The **module-argument** half is a different matter, and this is an *argument*, not a
> measurement: a lemma proved for `M <: T` and applied at a concrete module is still a
> **named application**, and section-closing generalisation does not change that — so it
> is not a distinct escape route. Flagged as reasoning about EasyCrypt's semantics rather
> than something measured, because that is what it is.

```
### RESULT: GREEN            __GATE_RC=0   __WALL_S=4548
OK  INPUTS_SHA256 matches the committed identity (a2f591e8...)
statements pinned = 1074/1074 | coverage 989/989 | added=0 removed=0 | ledger=242
OK  taint containment: closure = 6 lemmas, none of the 7 headline results is in it
OK  taint controls: pass=11 fail=0
```

> **:warning: THE FIRST HOLE IS NOT HYPOTHETICAL — MEASURED 2026-08-28.** It was written
> as a precaution; it is a fact, and the mechanism works on the exact lemma PHASE 5 exists
> to contain. Restating the **admitted** `nhchwcoll_hchwpre_msg` with its exact hypotheses
> and **no hint**, a bare `smt()` **closes it**
> (`scratch/probe_smt_lemma_reach.ec`). It cannot have derived it: the step the admit
> stands in for is encoder injectivity, which this tree proves is *impossible* at C10's
> geometry. The two-sided control matters — dropping `m <> m'` makes the statement false
> by the tree's own refutation, and there `smt` reports **"cannot prove goal (strict)"**
> (`…_NEG.ec`), so `smt` discriminates and the closure above is evidence rather than an
> artefact. **Exposure, comment-stripped over the 45 cone files: 921 bare `smt()` against
> 2139 hinted — 30% of all `smt` calls give the prover no hint list**, concentrated in
> `GprocT2Trh.ec` (162), `XmssmtCC_All.ec` (150), `FxChain.ec` (143), `GprocT1Opre.ec`
> (110). Full write-up: `scratch/FINDING-bare-smt-reaches-the-admit.md`.
>
> This does **not** show the headline consumes the admit — the closure is still 6 and no
> escaping path is exhibited. It shows PHASE 5 **cannot rule that out**. Read
> "gate-enforced containment" as *catches named-application drift*, never as *proved
> containment*. Closing it properly would need an `#print axioms`-style dependency
> facility, which EasyCrypt does not have; the alternative — removing 921 bare `smt()`
> calls — is a large mechanical change with real regression risk. Stating the measured
> bound is the honest option and is the one taken.

> **:warning: TWO MORE HOLES, found 2026-08-27 by GPT-5.6 adversarial review and now
> FIXED — the phase was weaker than this section claimed.** (a) The parser skipped the
> declaration line outright, so a **one-line** `lemma f : X. proof. … qed.` was never
> registered at all — **12 exist in the cone**, and one applying an admit would have been
> invisible. (b) Lemmas were keyed by **bare basename**, and **54 basenames are declared
> in more than one cone file**, so a later declaration silently overwrote an earlier one
> and could hide a taint edge. Both are fixed; the closure is unchanged at 6, so the
> *result* was right while the *guard* was not sound against future edits. Controls **T5**
> (one-line lemma applying an admit) and **T6** (headline basename shadowed in a second
> file) now cover them — 7 controls, all graded on failure reason.

**The direction label was wrong, and that matters more than the holes themselves.** An
*exclusion* claim needs **over**-approximation, but every hole listed above — the bare
`smt()`, clone reachability, and all three parser bugs — **shrinks** the closure. They are
**under**-approximations, i.e. the unsafe direction. Calling the phase a "name-level
over-approximation" implied a safety margin it did not have (Kimi K3, 2026-08-27). The
parser bugs are fixed and guarded; the `smt()` and clone holes remain and are genuinely
unsafe-direction. The honest statement is: *this phase catches named-application drift; it
is not a soundness proof of exclusion.* A name absent from the closure is absent from the
true closure **only** modulo those two remaining holes,
which is precisely why they are written into the tool header, the manifest header and the
phase header rather than left for the next reader to find. A check that reads stronger
than it is becomes the next fail-open.

#### The five controls

A containment check that cannot go RED is decoration. Each control **deletes** a specific
piece of information and must be rejected **for the declared reason** — graded on the
message, not on exit status.

| control | deletes | must report |
|---|---|---|
| T0 | nothing (baseline) | must **PASS**, else every control below is vacuous |
| T1 | the containment itself — wires `_Unfolded` into the headline | `HEADLINE IS TAINTED` |
| T2 | the admit (`admit.` → `trivial.`) | `anti-vacuity` |
| T3 | the manifest contents | `no rows` |
| T4 | a manifest line number's validity | `does not resolve` |

T4 exists because of a defect this repo has hit twice: a check that *runs against nothing*
and agrees with itself (`NOT-FOUND` comparing equal; an empty file digesting to the very
verdict under test). Every manifest site must still **resolve** — file present, line in
range, symbol actually on it.

#### Three defects found while building it, all in my own work

* **The chain I first wrote was wrong.** I claimed `WOTS_TW_ES.ec:6542` sits inside
  `MEUFGCMA_WOTSTWESNPRF`'s proof. But `6542 < 6578` — it is *before* that lemma is
  declared. It is inside `Step_Game4_WOTSTWES_SMDTPREC`, and the real chain has an extra
  link. Caught by adversarial review asking me to confirm enclosure by proof boundaries
  rather than line ordering.
* **The tool had a false positive**, and it is a genuinely hard case:
  `FORS_C_TreePort.ec` declares **both** `op extract_op` (`:1148`) and
  `lemma extract_op` (`:1485`). `op_extract_wins` (`:1173`) uses the **op**. A name-level
  tool cannot tell them apart. Fixed by a *positional rule* — EasyCrypt has no forward
  lemma references, so a mention before the declaration cannot be a use — plus an explicit
  `ambig` label wherever the rule cannot decide, retained rather than dropped (retaining
  can only enlarge the closure, never let a taint escape). The one `ambig` row was then
  resolved **by hand**: `:1674` reads `apply (extract_op A &m struct nd bs los oreg simfid)`
  — adversary and memory arguments, so the lemma. The label stays `ambig` because that is
  what the *tool* can justify; the comment records what a *human* checked. They are
  deliberately not reconciled.
* **T2 silently failed to discriminate on its first run.** The raw source line is
  `admit.    (* <-- THE PRE-EXISTING GAP ... *)`, so an exact `strip()=='admit.'` match
  never fired and the control passed while testing nothing. Diagnosed rather than re-rolled.

#### And the identity calculator went stale, in a new way

`scratch/encode-compat/inputs_id.sh` had **duplicated** the gate's hashed-file list. The
moment PHASE 5 added three files to that list, the calculator confidently produced a wrong
identity (`a86a4a72…` against the gate's `b661e2a6…`). This is the same defect as
hand-rolling the census `comm` diff: *reimplementing what the gate already computes.* It
now **derives** the list from `cert_gate_split.sh` and reproduces the gate's value exactly.
`a86a4a72…` appears nowhere as a real identity and is recorded in `cert-identity.tsv` as
the artefact it is.

#### Cost

No EasyCrypt content changed: no `.ec` file is touched. Census `added=0 removed=0`,
**ledger 242**, pins 1072, coverage 987/987 — all unchanged. This adds a phase, a tool, a
manifest and a control fixture; the identity moves because three files joined the hashed
set. It does **not** remove either admit — that is the separate `ENC_COLL_WOTS` unit the
admits note scopes at 12–18 engineer-days, and it needs its own decision.

#### Receipt

```
### RESULT: GREEN            __GATE_RC=0   __WALL_S=4840
OK  INPUTS_SHA256 matches the committed identity (b661e2a6...)
### TOOLCHAIN GIT hash: r2026.02   ### PROVERS 0a5b3d54dcce300e 25 configurations
statements pinned = 1072/1072
OK  coverage: all 987 top-level statements across 45 CONE files are pinned
cone: keys 1555=1555 | ROWS 1634=1634 | added=0 removed=0
ledger=242  parameters=214  bindings=366  meaning=389  definitions=423  total=1634
controls executed (unique)=6
OK  taint containment: closure = 6 lemmas, none of the 6 headline results is in it
OK  taint controls: pass=5 fail=0
OK  inputs unchanged across the run
```

The fork gate is unaffected: PHASE 5, its tool, its manifest and its controls are wired
into `cert_gate_split.sh` only, and `cert-controls.tsv` — which `cert_gate_fork.sh` reads
wholesale with fork includes — is untouched.

### UPDATE 2026-08-27 — the deployed statement drops to TWO premises, and I correct my own overstatement

`EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS` now carries **two**
premises. It carried six when written on 2026-08-24.

```
c <= p_tgts                                <- a PARAMETER CHOICE
size (emb_in witness) = 8 * n + c10_r      <- a CONSTRAINT ON A FREE OP
```

#### The three parameter pins were never needed

`n = c10_n`, `len = c10_len`, `k = c10_k` fed exactly one thing: the four `dfC0`
separations. Those separations are a **mod-8 argument** — `dfC0 = 8n + 33 ≡ 1 (mod 8)`
while `8n`, `8n·len`, `8n·2`, `8n·k` are all `≡ 0 (mod 8)` for **any** integers — so the
argument never looks at 16/43/13.

**This tree already knew that, and had already proved the replacement.**
`C10DeployedCapstone.ec:407` records it verbatim: *"the four dfC0 separations follow from
the WIDTH premise ALONE, with n, len and k FREE … its name promises more than its proof
uses"*, and `c10_dfC_separations_from_width_alone` is the lemma it proved for exactly this,
pinned since. When I wrote `_TIGHT_AT_DEPLOYED_PARAMS` on 2026-08-24 I reached for
`c10_dfC_separations_deployed` — the variant **with** the premises — instead. **That was my
miss, not a gap in the tree.** The fix is a one-line swap at the call site.

So this is an **elimination, not a trade**. The 2026-08-24 section claimed the deployed
variant was "a trade, not an elimination: the premise count is unchanged at 6". True of the
proof as I wrote it; it did not have to be.

#### And the claim I published on 2026-08-25 was wrong

I wrote that the deployed statement had *"only ONE substantive premise"*. **That overstated
the artifact.** I counted `size (emb_in witness) = 8*n + c10_r` among "the deployed
parameter pins". It is not one: `emb_in` is `abstract-op:f718c0661391` and **nothing in the
closure pins its width**. It is a genuine assumption about a free operator, and with the
three real pins now gone it is the artifact's **least visible real assumption** — quieter
than `c <= p_tgts`, which at least has a paragraph explaining itself.

The two surviving premises differ in kind, and a write-up that calls both "substantive" and
stops there is not much better than the sentence it replaces:

* **`c <= p_tgts`** — the SM-DT-TCR game must be given at least as many targets as there
  are instances. `C10DeployedGeometry.ec:468` classifies it as "NOT A THEOREM AND NOT MEANT
  TO BE … satisfiable by construction". Nothing about the deployment can make it false.
* **`size (emb_in witness) = 8*n + c10_r`** — asserts the serialisation is exactly
  `NODE ‖ u32 counter`. This is a **fidelity** claim about the deployed encoder, and it is
  assumed, not verified against `sphincs-c10`.

#### A structural fact worth stating plainly

While checking this I confirmed that `n`, `len`, `k`, `log2_w`, `h'` and `d` are pinned by
**axioms** in the cone (`SPHINCS_PLUS.ec:44,53,59,73,97,106,116` — **seven**, including
`a_val : a = 11`, which I missed on the first pass; all ledger `axiom` rows). So
the *whole* development is specialised to C10's geometry, not parameter-generic — the
declaration site says so deliberately: *"the whole development below is now about C10's
actual geometry"*, with the constants left opaque plus a `*_val` axiom so MM45's tuned
proofs are not perturbed. That is documented and intended; it is noted here only because it
means the "abstract" capstones are not abstract in the parameters either, and a reader
should not infer generality from their statements.

**It also means the pins were doubly removable** — derivable from `n_val`/`len_val`/`k_val`
*and* unnecessary to the separations. The fix taken uses the second route, which is
strictly better: it consumes no axiom, and the separations hold with the parameters free.

#### The remaining `emb_in` premise HAS a known discharge route — it is just not taken here

Stated so nobody reads "least visible real assumption" as "irreducible". The tree already
has both halves:

* `C10DeployedInstance.ec::c10_embg_size` proves `size (c10_embg x) = 8*n + c10_r`
  **with no premises at all**; and
* the `..._PINNED_ENCODER` family (`C10DeployedCapstone.ec:191`,
  `GprocQWired.ec:418`) already takes `emb_in = c10_embg` as a premise.

So a `_TIGHT_AT_PINNED_ENCODER` corollary would carry `c <= p_tgts` and
`emb_in = c10_embg`, discharging the width fact by `rewrite … c10_embg_size`. That trades
a bare width assumption for a **pin to the concrete C10 serialisation** — the same premise
count, but a fidelity statement a reader can check against `sphincs-c10` instead of an
unexplained arithmetic side condition. It is the obvious next unit and is **not** done
here; it would need its own gate run.

#### Residual: the superseded capstones still carry the redundant pins

The three parameter pins were removed from the statement the README tells the product to
quote. A comment-stripped sweep of all 45 cone files finds them still carried by
`C10DeployedCapstone.ec::{EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS,
…_PINNED_ENCODER}` and `GprocQWired.ec::{…_AT_DEPLOYED_PARAMS_QWIRED,
…_AT_DEPLOYED_PARAMS_PINNED_ENCODER_QWIRED, deployed_qwired_at_witness}`. Those are
superseded variants, and `C10DeployedCapstone.ec:407` has documented their redundancy
since 2026-08-03. They are left alone deliberately — each fix is another pin change and
another gate run for a statement the product does not quote — and are recorded here rather
than left for a reader to rediscover. The carriers in `C10DeployedGeometry.ec` and
`C10DeployedInstance.ec` are a different case entirely: those lemmas are *about* the
deployed parameters, so the pins are their subject matter, not dead weight.

#### Cost

Predicted before the run and matched exactly: census `added=0 removed=0`, **ledger 242**,
`CONE_FILES` 45, coverage 987/987, taint closure 6 — and **exactly one** statement digest
moved, the deployed lemma's own. `C10DeployedCapstone` was already a certified root, so the
new `require` adds no cone file.

```
### RESULT: GREEN            __GATE_RC=0   __WALL_S=4528
OK  INPUTS_SHA256 matches the committed identity (7a40d9b1...)
### TOOLCHAIN GIT hash: r2026.02   ### PROVERS 0a5b3d54dcce300e 25 configurations
statements pinned = 1072/1072
OK  coverage: all 987 top-level statements across 45 CONE files are pinned
cone: keys 1555=1555 | ROWS 1634=1634 | added=0 removed=0
ledger=242  parameters=214  bindings=366  meaning=389  definitions=423  total=1634
controls executed (unique)=6
OK  taint containment: closure = 6 lemmas, none of the 6 headline results is in it
OK  taint controls: pass=5 fail=0
OK  inputs unchanged across the run
```

### UPDATE 2026-08-27 (second) — the encoder can be PINNED, not merely width-constrained

`EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER` (same file) carries the
same **two** premises as its sibling, but the second one is different in kind:

```
c <= p_tgts          a parameter choice
emb_in = c10_embg    the SERIALISATION ITSELF, not merely its width
```

The width fact `size (emb_in witness) = 8*n + c10_r` is **derived** here rather than
assumed, from `C10DeployedInstance.ec::c10_embg_size`, which is proved premise-free.

#### This is not a cosmetic re-spelling — the width premise is degenerately satisfiable

The reason is recorded in this tree, from an adversarial review on 2026-08-01
(`C10DeployedInstance.ec:322`):

> *"a CONSTANT `emb_in` satisfies it while collapsing every ThC input and making the
> S-TCR term trivially winnable."*

A constant encoder does not make the sibling's bound **false**; it makes it
uninformative. Pinning `emb_in = c10_embg` excludes every constant-encoder model.

> **:warning: CORRECTED 2026-08-27 (GPT-5.6 adversarial review, verified).** This
> originally said the pin *"excludes **exactly** those models"* and that a constant
> encoder *"sends the S-TCR summand to ~1"*. **Both overstate.**
> (a) The equality pin excludes constant encoders **and also every other good
> non-constant serialisation** — it is not a surgical exclusion of the degenerate ones.
> (b) That the S-TCR summand actually goes to ~1 for *this* reduction and adversary is
> **not proved** from constant `emb_in`; this tree records at
> `C10DeployedCapstone.ec:267-274` that with a free `thfc := const` the S-TCR collision
> term can be 1 **regardless**, which is a separate hole the pin does not touch.
> What is proved is exactly `pinned_encoder_is_not_degenerate`: **non-constancy**, which
> is strictly weaker than injectivity and says nothing about the game's probability.
>
> **:warning: AND THE SHARPER OBJECTION (Kimi K3, verified).** The pin does not rescue the
> S-TCR term *at all*, because the degeneracy survives one composition step down:
> **`op thfc` is declared with ZERO axioms** (`SPHINCS_PLUS.ec:488`; no axiom row in the
> census mentions it). Since `ThC = join_dgst (thfc …) (thfc …)`, the interpretation
> `thfc := const` still collapses every `ThC` input **even with `emb_in = c10_embg`
> pinned**. So the correct claim is narrow: the pin excludes degeneracy **via `emb_in`**,
> and says nothing about degeneracy via `thfc`. Do not describe it as making the S-TCR
> term meaningful — that is a separate, still-open hole.

**What is proved is a theorem here, not a comment — and it is only non-constancy.**
`GprocChargedQWired.ec::pinned_encoder_is_not_degenerate` proves

```
emb_in = c10_embg => exists (x y : dgstblock * cntr), emb_in x <> emb_in y
```

under the pin as its only hypothesis. (**Corrected 2026-08-27:** an earlier draft called
this lemma "premise-free". It is not — it carries `emb_in = c10_embg`. The premise-free
lemma is `c10_embg_not_constant`, which it consumes.) Full
injectivity additionally needs the counter-space bound
`STCRC_WC.G.CntrFT.card <= 2 ^ c10_r` and is `c10_embg_inj` /
`c10_embg_meets_LEN_and_INJ`; it is not restated in the capstone file.

#### What it costs, and what it does not buy

**Neither variant supersedes the other, and the README does not pick one for you.**
`emb_in = c10_embg` is a **strictly stronger** premise than the width fact, so this
theorem covers **fewer models** than `_AT_DEPLOYED_PARAMS`. The width form is more
general; this one is more informative. Both are gated closure members. Quote whichever
the claim actually needs — and say which.

**It does not verify the deployment.** `c10_embg` is an EasyCrypt definition
(`DigestBlock.val x.\`1 ++ int2bs c10_r (index x.\`2 …)`). That it matches what
`sphincs-c10` actually serialises is a **fidelity claim**, argued in
`C10DeployedInstance.ec` and **not machine-checked against the Rust**. Pinning the encoder
moves the assumption from *"some encoder of this width"* to *"this specific encoder"*; it
does not close the gap to the implementation.

#### A coverage hole closed in the same change

PHASE 5's `HEADLINE` list is what makes taint containment mean anything: a headline result
**absent** from that list is simply not checked. Adding a capstone without adding it there
is a silent hole, so the new variant was added to the list in the same commit — the phase
now reports *"none of the **7** headline results is in it"*, and the five discriminating
controls were re-run against the extended list (still 5/5).

#### Cost

Predicted before the run and matched: pins 1072 → **1074**, statements 987 → **989**,
coverage 989/989, census `added=0 removed=0`, **ledger 242**, `CONE_FILES` 45, taint
closure 6 — and **zero existing statement digests moved**, since both new lemmas are
additions rather than edits.

```
### RESULT: GREEN            __GATE_RC=0   __WALL_S=4499
OK  INPUTS_SHA256 matches the committed identity (f2b459d0...)
### TOOLCHAIN GIT hash: r2026.02   ### PROVERS 0a5b3d54dcce300e 25 configurations
statements pinned = 1074/1074
OK  coverage: all 989 top-level statements across 45 CONE files are pinned
cone: keys 1555=1555 | ROWS 1634=1634 | added=0 removed=0
ledger=242  parameters=214  bindings=366  meaning=389  definitions=423  total=1634
controls executed (unique)=6
OK  taint containment: closure = 6 lemmas, none of the 7 headline results is in it
OK  taint controls: pass=5 fail=0
OK  inputs unchanged across the run
```


### UPDATE 2026-08-27 (third) — audit of the product-facing section; three corrections

After five units in two days, I re-checked **"What is actually proved, and what is not"**
line by line against the current tree, rather than trusting that edits had kept it true.
This section is the surface the product quotes, and this artifact has now produced five
stale-claim findings in three days, three of them mine.

**Corrected:**

1. **"ten named game probabilities" → NINE.** The RHS of `CHARGED_QWIRED` carries nine
   distinct `Pr[…]` games, counted off the lemma. The README's *own enumeration
   underneath the sentence already listed nine* — `M.F.ITSRC10` (1), the three that
   replace `Q` (4), the four hypertree terms (8), `GAME1_INT` (9). The prose and the list
   had disagreed with each other, and the prose was wrong. Nothing about the artifact
   changed; the count of its residual terms was overstated by one.
2. **`GprocChargedQWired.ec:69` → `:77`.** My own drift, one day old: the
   `require import C10DeployedCapstone` added on 2026-08-27 shifted the headline lemma
   down eight lines.
3. **"`FORS_C_TreePort.ec` (1733 lines)" → 1732.** Confirmed both by `wc -l` and by
   `awk END{print NR}`; the file ends with a newline, so the two agree.

**Checked and CORRECT — recorded so the audit is not just its findings:**

* `FORS_ES.ec:4828` genuinely is the `_V` → `_VI` hop the text cites it for
  (`have ->: Pr[…_V.main() …] = Pr[…_VI.main() …]`, closed by
  `byequiv Eqv_EUF_CMA_MFORSTWESNPRF_V_VI`).
* `GprocQBound.ec:62` is `lemma gproc_Q_bound`, as cited.
* "Each cone contains two admits" — split: `nhchwcoll_hchwpre_msg` and `extract_op`;
  fork: `nhchwcoll_hchwpre_msg` and `EUFNAGCMA_FLSLXMSSMTTWESNPRF`. All four named
  correctly.
* "`GprocVI.ec` … Nine theorems" — nine declarations (7 `lemma` + 2 `equiv`).

**Two of my four checks were wrong, not the README.** My first pass "found" only two
admits missing and only seven theorems in `GprocVI.ec`; both were my own pattern-naive
greps (`	admit	` does not match the `admit:<digest>` census format, and `^lemma `
misses `local lemma` and `equiv`). That is the third time in this session a naive grep
produced a false finding — the others being `MEUFGCMA_WOTSTWESNPRF` matching the oracle
module `O_MEUFGCMA_WOTSTWESNPRF`, and a taint sweep matching a comment I had just written.
**A grep that hits is a lead; open the file.**

No gate run: the README is not a gate input, and no `.ec` file, manifest or tool changed.


### UPDATE 2026-08-27 (fourth) — a citation checker was MEASURED and NOT built

Stale `file:line` citations have caused **four** defects in three days, and no gate catches
them: citations live in comments, which carry no census rows and no statement pins. A
mechanical checker was the obvious fix, so I measured it before building it.

**It is not viable, and the reason is specific to this tree.** Full write-up:
`scratch/FINDING-citation-checking-is-not-viable.md`. In short — 581 citations across the
45 cone files; every candidate rule had a double-digit false-positive rate; and the one
rule that looked airtight (a line number beyond EOF *must* be wrong) flagged **88
citations that are all correct**, because this tree cites **four versions of the same
file** by basename:

```
base-c10-split/SPHINCS_PLUS.ec            1020 lines
base-c10-fork/SPHINCS_PLUS.ec             4613 lines
FV-SPHINCSPLUS-EC/proofs/SPHINCS_PLUS.ec  4609 lines   (upstream MM45)
```

`SPHINCS_PLUS.ec:2243` is out of range for the split file and valid for upstream. **I
nearly reported 88 correct citations as stale.** The narrow fallback — restrict to
`cdrafts-split`, which has no *upstream* twin — fails too: every such file has a **fork**
twin of similar length, so in-range citations stay ambiguous.

A gate phase with that error rate would be worse than nothing: it trains readers to skip
the phase, which is how a real finding gets ignored later. So the artifact gains a
documented negative result instead of a noisy check.

**What is worth doing instead**, and is cheap: say which version you mean when it is not
the split file (`C10DeployedGeometry.ec:454` now does); prefer `File.ec::name` over
`File.ec:N`, since names do not drift when a `require` is added; and re-check citations in
a section when you edit near it — which is exactly what the audit earlier today did, and
it caught three.

No gate run: no `.ec` file, manifest or tool changed.


### UPDATE 2026-08-27 (fifth) — adversarial round: GPT-5.6 + Kimi K3, and they DIVERGED on the main claim

Both models reviewed the five changes above, read-only, from the same prompt. Neither
modified a file (`git status` checked). **Every finding below was verified against source
before being acted on.** They found five real defects, three of them in claims I had
already published.

#### The divergence is the most useful part

**GPT-5.6: C1 is FATAL — not a conservative extension. Kimi K3: "C1 is conservative. Full
stop."** Reconciled rather than voted: **they answered different questions under the same
word.** Kimi's five agents enumerated the cone for *constraints* on `encode_msgWOTS_C` —
axioms, clone bindings, `realize`, section `declare`, shadowing — and found none. That
settles consistency and "no new axioms", which was the failure mode I named. GPT tested
*conservativity in the technical sense* and produced a falsifier. On the term I actually
published, **GPT is right**, and the correction is in the 2026-08-25 section above.

#### What each caught that the other missed

| finding | by | status |
|---|---|---|
| "conservative extension / model class unchanged" is false | GPT-5.6 | corrected |
| PHASE 5 keyed lemmas by **bare basename**; 54 are declared in >1 cone file | GPT-5.6 | fixed + control T6 |
| **12 one-line proofs** never registered by the parser | GPT-5.6 | fixed + control T5 |
| RHS has **eleven** `Pr[…]`, not "nine distinct games" — my own correction was wrong | GPT-5.6 | corrected |
| `a_val : a = 11` — **seven** geometry axioms, not six | GPT-5.6 | corrected |
| **`thfc` is axiom-free, so the pin does NOT rescue S-TCR** | Kimi K3 | corrected — the sharpest finding of the round |
| terminator matched **line-initial `qed.` only** — 314 of 951 missed | Kimi K3 | fixed + control T7 |
| the **"over-approximation" label is backwards** — every hole shrinks the closure | Kimi K3 | corrected |
| `pinned_encoder_is_not_degenerate` called "premise-free"; it carries the pin | Kimi K3 | corrected |
| stale repro numbers (`24 targets, 87 pins, 1159 rows`) | Kimi K3 | corrected |

#### The sharpest finding

Kimi did not merely say my C3 phrasing overstated — it showed **why the claim fails**.
`op thfc` is declared with **zero axioms** (`SPHINCS_PLUS.ec:488`), and
`ThC = join_dgst (thfc …) (thfc …)`, so `thfc := const` collapses every `ThC` input **even
with `emb_in = c10_embg` pinned**. The pin excludes degeneracy *via `emb_in`* and nothing
more. I had implied it made the S-TCR term meaningful; it does not.

#### PHASE 5 was weaker than it claimed, in the unsafe direction

Three independent parser bugs, each of which **shrank** the closure — and an exclusion
claim needs the opposite. The closure is unchanged at **6** after all three fixes, so the
*result* held throughout while the *guard* did not. Added the parser-coverage guard Kimi
recommended, with the budget set to the **measured** truth (951 declarations, 949
registered, budget 2) rather than a loose one — a loose budget hides exactly the bugs the
guard exists to catch. Controls are now **9**, up from 5, each graded on failure reason.

#### And a citation I broke myself, this week

`C10DeployedGeometry.ec:464` → `:468`: my own 2026-08-27 edit to that file shifted the
line, breaking **four** citations (two here, two in `GprocChargedQWired.ec`). This is the
concrete case the citation-checker finding above predicted and could not have caught.

#### Receipt

```
### RESULT: GREEN            __GATE_RC=0   __WALL_S=4561
OK  INPUTS_SHA256 matches the committed identity (b5245837...)
### TOOLCHAIN GIT hash: r2026.02   ### PROVERS 0a5b3d54dcce300e 25 configurations
statements pinned = 1074/1074
OK  coverage: all 989 top-level statements across 45 CONE files are pinned
cone: keys 1555=1555 | ROWS 1634=1634 | added=0 removed=0
ledger=242  parameters=214  bindings=366  meaning=389  definitions=423  total=1634
controls executed (unique)=6
OK  taint containment: closure = 6 lemmas, none of the 7 headline results is in it
OK  taint controls: pass=9 fail=0
OK  inputs unchanged across the run
```

Neither reviewer modified a file (`git status` checked in both trees). Ledger **242**
throughout — this round changed comments, the taint tool and its controls, so no
EasyCrypt-level number moved.


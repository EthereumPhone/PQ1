# ADVERSARIAL AUDIT -- findings I acted on, and the ones I verified MYSELF
Four-lens + refutation workflow, 2026-08-25.  Load-bearing citations re-checked by hand
before being acted on, per the standing rule that a reviewer's output is a lead, not a fact.

## CONSTRAINT LENS -- zero blockers.  Independently reproduced:
  * exactly ONE census row for the op (`abstract-op:f9542be91ac8`), and
  * NO axiom in the cone can reach it -- all 29 axiom/declare-axiom rows live in 8
    files, and `encode_msgWOTS_C` does not appear in any of them, even in comments.
  * the only clone in WOTS_C_Real.ec (`STCRC_WC`, line 345) binds nine operands and
    `encode_msgWOTS_C` is not among them.
  => the op is genuinely unconstrained, so giving it a body is a conservative extension.

## SERIOUS: fork-gate cross-contamination via the controls file.  VERIFIED BY HAND.
`cert_gate_fork.sh:75,394` reads `cert-controls.tsv` -- NO `-fork` suffix -- WHOLESALE,
and compiles each control with FORK includes, where `WOTS_C_Real` resolves to
cdrafts-fork/WOTS_C_Real.ec:337 with the op STILL ABSTRACT (and at the older type).
A MUST-PASS control registered there would turn the sibling gate RED for a reason
nobody would look for -- the exact regression cert-controls-split.tsv's own header
records happening once before.
STATUS: AVOIDED.  `grep -n encode_compat cert-controls.tsv` -> no match; the control is
registered in cert-controls-split.tsv ONLY.  Confirmed by hand, not taken on trust.

## MINOR, ACTED ON: the op was not statement-pinned.
predC / ThC / emb_in / emb_in0 / emb_in1 / emb_tw are all op-pinned from this file and
encode_msgWOTS_C was NOT (verified: 0 matching rows in cert-statements-split.tsv).
As a DEFINITION it is semantically load-bearing.  Pin added, discrimination measured
first (PIN_DISCRIMINATION.txt).

## PRE-REGISTERED RED PREDICTION -- where a failure would come from
The audit identified the ONLY two cone sites whose solver context provably changed:
bare, unhinted `smt()` calls in files that never carry the bridge hypothesis, so
transparency can newly supply something:
    cdrafts-split/FxChain.ec:961-963        in lemma wotsc_sign_cf_h (FxChain.ec:939)
    cdrafts-split/RtopCSoundness.ec:653-655 byte-identical mirror (RtopCSoundness.ec:631)
Both are `have sigE : ... encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm) ... by smt().`
IF THE GATE GOES RED, LOOK HERE FIRST.  Expected shape is a TIMEOUT at -timeout 60,
not an error.  Pre-registered fix: a NAMED REWRITE -- the same remedy taken for
GprocT1Opre on 2026-08-21 -- NOT a re-roll and NOT a "flaky" diagnosis.

## REPORTING CONSTRAINT (faithfulness lens, accepted)
"One fewer premise" MUST NOT be written up as "one fewer assumption about the deployed
signer".  What was eliminated is a MODEL-INTERNAL degree of freedom.  After the change
the correspondence to the deployed encoder is carried entirely by `ThC`, whose own
deployment gaps are unchanged and unreceipted (`emb_in` and `thfc` are still free ops,
and the two projection members remain correlated under the instantiation).

## CANDIDATE FIX, PREPARED IN ADVANCE (not yet needed)
If FxChain.ec:961 / RtopCSoundness.ec:653 go RED, the cause is that `encode_msgWOTS_C`
is now TRANSPARENT, so `smt` sees through it to `encode_msgWOTS (ThC ..)` and thence to
`join_dgst (thfc ..) (thfc ..)` -- a much larger term on both sides of the equation.

The fix is to GENERALISE the term away before the call, so the solver gets an opaque
variable instead of an unfoldable definition:

    move: (encode_msgWOTS_C ps0 ad0 mm (grindC ps0 ad0 mm)) => em0.

This is deterministic and structural.  It is NOT `pose` (which leaves the body in
context for smt to unfold) and NOT a re-roll.

IMPORTANT CALIBRATION BEFORE CALLING ANYTHING RED: `EC_TIMEOUT=60` is PER PROVER CALL,
not per file.  A file that takes 5 minutes is not failing -- it is only failing if an
individual smt call exceeds its budget.  A slowdown is not a failure, and I should not
report one as the other.  Observed while waiting: FxChain took >3m44s against a 74s
July-31 baseline, but that baseline is from a SMALLER closure and a warm tree, so it is
an order-of-magnitude reference, not a regression threshold.

## CAVEAT ON THE AUDIT'S OWN EMPIRICAL LEG -- CORRECTED
FIRST VERSION OF THIS NOTE WAS WRONG, and it is left corrected rather than deleted.
I wrote that the mechanics lens compiled with the HOST **r2026.06**, inferring that from
the `-why3 ~/.config/easycrypt/why3-ec-r2026.conf` flag in its process line.  The flag
does not say that.  `ec-r2026.sh:2-3` states the `ec-r2026` switch IS "the PINNED
r2026.02 release".  So the lens used the RIGHT EasyCrypt version.  Same defect class I
keep hitting: a claim taken from a token that does not establish it.

THE ACCURATE CAVEAT IS NARROWER.  The host `ec-r2026` switch is r2026.02 but exposes
only **10 prover configurations**; the certified container exposes **25**, including a
DIFFERENT CVC5 (container 1.0.9 vs host 1.1.2).  A goal closed by the host's newer CVC5
is not guaranteed to close in the container, and vice versa.  So the lens's 30 green
closure files are real corroboration but are NOT a gate receipt.  The authoritative test
remains the run inside ec-grind.

## A "BUG IN MY OWN RUNNER" THAT WAS NOT REAL -- MY ERROR, CORRECTED
I recorded here, as a confirmed finding, that
`scratch/encode-compat/run_gate_container.sh` self-matched its own grep because its
heredoc contains the literal string `[e]asycrypt compile.*base-c10-split`.  I took that
from the mechanics lens WITHOUT TESTING IT.  It is FALSE.

TESTED, both ways:
    script whose FILE contains the pattern      -> SELF_MATCH_COUNT=0
    pattern literally in the running CMDLINE    -> count 0
The `[e]` idiom defeats exactly this: the regex `[e]asycrypt` requires an `e` IMMEDIATELY
FOLLOWED BY `asycrypt`, and in the literal text `[e]asycrypt` the `e` is followed by `]`.
The synthesis agent independently called the claim "factually impossible" for the same
reason.  Two of my reviewers disagreed and the one I believed first was the wrong one.

THE ACTUAL REASON the chained runner produced no gate log: the nohup'd process was gone
when I checked (`runner alive: 0`) -- it was killed with its parent shell while legitimately
waiting on the two blocking compiles.  Simpler, and it is what the evidence supported.

WHY THIS IS WORTH KEEPING RATHER THAN DELETING: my own project instructions say to verify
a reviewer's load-bearing citations before acting on them, and I did that for the fork-gate
hazard and for the arity hazard but NOT for this one -- because it was a claim about MY
code, which I was primed to accept.  A reviewer's finding about your own mistake is not
more credible than one about the code; it is less, because you will not argue with it.

## FORK GATE -- PRE-CHECK AND RUN
The advisor's instruction was that the fork gate "must be re-run to confirm it is
untouched, not assumed".  Both were done.

PRE-CHECK (2026-08-25).  Recomputed the FORK gate's INPUTS_SHA256 with its own pipeline
(scratch/encode-compat/inputs_id_fork.sh, run in ec-grind under LC_ALL=C):

    committed : 9c2d21280c84d52c30b22111151f1135
    computed  : 9c2d21280c84d52c30b22111151f1135   UNCHANGED

That is a stronger statement than "no fork file shows in git status": the hash covers the
COMPUTED require-cone of the fork roots plus closure-c10-fork.txt, cert-baseline.tsv,
cert-statements-fork.tsv, cert-controls.tsv, every control SOURCE, the five canaries,
tools/cert_cone.py, tools/stmt_digest.py and cert_gate_fork.sh.  So the split-only edit
provably did not perturb any fork input, including ones I might not have thought to look
at.  The behavioural confirmation is the full run.

SEQUENCING -- WHY NOT CONCURRENTLY.  The two gates race, bidirectionally, on scratch/:
  * cert_gate_fork.sh:164-166 purges scratch/ RECURSIVELY;
  * cert_gate_fork.sh:167 then FAILS if any .eco survives under $B $D $L scratch;
  * cert_gate_split.sh:189 purges the same scratch/ and compiles its six controls there.
So a concurrent fork purge deletes .eco files the split gate is mid-way through using,
and a concurrent split control build makes the fork's eco_left check fire.  Either way the
result is a false RED -- exactly the "racy receipt" both gates' own concurrency guards
exist to prevent.  (Those guards would NOT have caught this pair: they grep for
`base-c10-split` and `base-c10-fork` respectively, which are disjoint.)  Run sequentially.

## COMPLETENESS SWEEP FOR THE UNCATCHABLE CLASS (2026-08-25)
The defect adversarial review exposed -- a stale CLAIM inside a certified cone file, which
carries no census row and no statement pin and therefore rides through a GREEN run -- is
not self-limiting: if there is one there may be more.  Swept all 45 cone files twice.

SWEEP A -- claims that the op is FREE/ABSTRACT.  Two hits, judged by READING them:
  * WOTS_C_Interactive.ec:1361 "faithful pp-free sign"  -> FALSE POSITIVE.  "pp-free"
    means independent of pp, not "a free op".  The grep matched the wrong sense.
  * WOTS_C_Reduction.ec:557 "abstract here only because the whole reduction keeps
    `encode_msgWOTS` parametric"  -> GENUINE.  Fixed.  The hypothesis is KEPT (this
    reduction is stated without relying on the body, and discharging it would move a
    pinned statement); the stated REASON still holds for `encode_msgWOTS`, which really
    is still a free op at WOTS_TW_ES.ec:624.

SWEEP B -- claims that a capstone CARRIES the encode premise.  Eight hits, all checked:
  * SphincsC10CapstoneWired.ec:251 "the remaining six premises (c<=p_tgts, encode-compat,
    ...)" -- describes GROUNDED, which this change did NOT touch.  VERIFIED still true:
    GROUNDED still carries the premise (one occurrence in its statement).  No fix.
  * SphincsC10Content.ec:847 "passed positionally after hencb, matching the capstone's
    premise order" -- its proof applies EUFCMA_SPHINCS_PLUS_C10, a DIFFERENT capstone.
    Only GprocChargedQWired.ec changed.  No fix.
  * C10DeployedGeometry.ec:444 and :625 -- historical/section-8 statements, already
    explicitly superseded by the :454 marker and the :478 UPDATE block, which a reader
    reaches BEFORE section 8 in file order.  No fix.
  * WOTS_C_Interactive.ec:2131, WOTS_C_Multi.ec:938, XmssmtCC_All.ec:8105 -- each
    describes its OWN lemma's hypotheses, all unchanged.  No fix.
  * WOTS_C_Real.ec:379 -- the new comment written by this change.

RESULT: three stale claims total from this change (C10DeployedGeometry, SphincsC10Content,
WOTS_C_Reduction), all fixed; everything else checked and genuinely accurate.  I found one
of the three; adversarial review found the other two.  All three would have shipped under a
fully GREEN gate.

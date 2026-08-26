# PRE-COMMITTED PREDICTION -- encode_msgWOTS_C free op -> definition
Written BEFORE the edit and BEFORE the gate run, 2026-08-25.
A mismatch against this is a FINDING, not something to reconcile after the fact.

## Census (cert-baseline-split.tsv)
abstract-op   145 -> 144   (encode_msgWOTS_C leaves)
defined-op    301 -> 302   (encode_msgWOTS_C arrives, with a body digest)
LEDGER        242 -> 242   (UNCHANGED -- neither class is a ledger class;
                            ledger = admit + axiom + declare-axiom + refined-const
                                   + clone-discharge + op-annotation + clone-obligation)
TOTAL        1634 -> 1634

## PHASE 2 behaviour
FATAL on BOTH a removed row (abstract-op:encode_msgWOTS_C) and an added row
(defined-op:encode_msgWOTS_C:<digest>).  Deliberate re-baseline, same drill as the
2026-08-22 bodied-definition change.

## Statement pins
Only the headline family loses the premise, so only those digests move.
The ~15 intermediate lemmas KEEP the hypothesis (they stay honest about their
dependencies and the headline supplies it by reflexivity).

## Risk flagged in advance (advisor)
Transparent op => smt may now unfold ThC's `join_dgst (thfc ..) (thfc ..)` body.
At EC_TIMEOUT=60 that surfaces as a TIMEOUT, not an error.  If it bites the fix is a
named rewrite, NOT a re-roll and NOT a "flaky" diagnosis.

## WHAT THE TREE ALREADY DECLINED -- and why this is NOT that
C10DeployedGeometry.ec:453-462 records `hencb` as "NOT RECEIPTABLE HERE, and
deliberately not faked".  Read exactly what it rejects:
  (a) an EXISTENTIAL receipt `exists E, forall .., E .. = encode_msgWOTS (ThC ..)`
      -- "trivially true (take the composition) and says NOTHING about the actual op";
  (b) a `clone ... realize` -- "EasyCrypt cannot re-interpret an already-declared
      op FROM INSIDE THE THEORY".
The move proposed here is NEITHER.  It edits the DECLARATION SITE, turning the
abstract op into a defined one.  That is (b)'s stated obstruction removed by not
being inside the theory, and it is not (a) because it constrains THE actual op
rather than asserting some op exists.

C10DeployedGeometry.ec:598-607 says `hencb` "IS LOAD-BEARING" -- but read the
consequent: "DROPPING it does not just lose a premise -- the reduction to MM45's
WOTS-TW stops existing."  The objection is to DELETING the equation.  Defining the
op makes the equation DEFINITIONALLY TRUE, so the reduction is preserved exactly.

That section (dated 2026-07-31, pre-split) also calls hencb "the whole of the
unfaithfulness" because it forced ThC's output to width 8*n.  THAT IS A FORK-TREE
STATEMENT.  In the SPLIT tree `msgWOTS = mdgstblock` at independent width 8*n_m
(WOTS_TW_ES.ec:270) and ThC already returns the WIDE type, which is what the split
was for.  Do not carry the fork's unfaithfulness verdict into the split.

## SCOPE DECISION (stated, not an artifact of where grep pointed)
cdrafts-fork/WOTS_C_Real.ec:337 carries the SAME abstract op at the OLD type
(`... -> msgWOTS -> cntr -> ...`), and WOTS_C_Real IS in closure-c10-fork.txt.
DECISION: edit the SPLIT tree only.  The headline family lives in the split; the
fork is the superseded unsplit geometry.  The fork gate must be re-run to confirm
it is untouched, not assumed.

## PLAN REVISED 2026-08-25 (before the gate run, after two audit lenses reported)
Two changes to the plan above.  Recording them here rather than silently adopting them.

1. ADD A NAMED IN-CLOSURE LEMMA `encode_msgWOTS_C_compat` in WOTS_C_Real.ec.
   Reason: stripping `hencb` from the capstones would leave the bridge equation
   nowhere visible in the closure.  A named, pinned lemma keeps the fidelity
   commitment legible and gives the capstone proofs a term to pass.
   => EXPECT_STMTS 986 -> 987, and one more pin.

2. ADD AN OP PIN for encode_msgWOTS_C.  The audit found -- and I verified at
   cert-statements-split.tsv (0 matching rows) -- that predC/ThC/emb_in/emb_in0/
   emb_in1/emb_tw are all op-pinned from this file and encode_msgWOTS_C is NOT.
   As a DEFINITION it becomes semantically load-bearing, so it must be pinned.
   Discrimination measured first: see PIN_DISCRIMINATION.txt.

REVISED PIN COUNT:  EXPECT_PINS 1070 -> 1072  (+1 op pin, +1 lemma pin)
REVISED STMT COUNT: EXPECT_STMTS 986 -> 987
CENSUS: abstract-op 145->144, defined-op 301->302, PLUS one new lemma row.
LEDGER: still 242.

## SCOPE OF THE PREMISE STRIP
GprocChargedQWired.ec ONLY -- all four members of the headline family
(CHARGED_QWIRED, charged_qwired_at_witness, ..._TIGHT, ..._TIGHT_AT_DEPLOYED_PARAMS).
DELIBERATELY NOT STRIPPED: C10DeployedCapstone.ec (3 sites) and GFailCharged.ec
(4 sites).  Those are intermediate/superseded statements; leaving them carrying an
explicit premise keeps them honest about their dependencies and avoids 7 pin
churns for no epistemic gain.  A derivable premise is not a false premise.

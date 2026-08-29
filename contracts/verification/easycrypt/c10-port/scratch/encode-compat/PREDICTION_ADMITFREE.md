# PRE-COMMITTED PREDICTION -- landing the admit-free replacement (2026-08-29)
Two proved lemmas added to base-c10-split/WOTS_TW_ES.ec, immediately after the admit.
NOTHING is wired; no existing proof changes.

  taint closure   STILL 6 members, and the two NEW lemmas must be ABSENT from it
                  (they apply :1476, never :1505).  VERIFIED before the gate.
  taint manifest  TWO LINE NUMBERS MOVE (insertion shifted later members):
                    Step_Game4_WOTSTWES_SMDTPREC   6338 -> 6394
                    MEUFGCMA_WOTSTWESNPRF          6578 -> 6634
                  Same six members; manifest regenerated deliberately.
  EXPECT_PINS     1074 -> 1076   (+2 lemma pins)
  EXPECT_STMTS     989 ->  991   (+2 top-level statements)
  census          added=0 removed=0, ledger=242, total=1634  UNCHANGED
                  (lemmas carry NO census rows; no op/axiom/module added)
  CONE_FILES      45  UNCHANGED
  MOVED pins      NONE.  Statement digests are CONTENT-based, not line-based, so
                  shifting later lemmas down must not move any existing digest.
  identity        MUST move (a cone file changed)

A moved EXISTING pin, any census movement, or either new lemma appearing in the taint
closure is a FINDING.

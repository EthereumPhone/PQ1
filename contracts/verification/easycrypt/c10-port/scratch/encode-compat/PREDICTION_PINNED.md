# PRE-COMMITTED PREDICTION -- the pinned-encoder variant (2026-08-27)
Two NEW lemmas in cdrafts-split/GprocChargedQWired.ec:
  EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_PINNED_ENCODER   (2 premises)
  pinned_encoder_is_not_degenerate                                  (1 premise, receipt)

  EXPECT_PINS   1072 -> 1074   (+2 lemma pins)
  EXPECT_STMTS   987 ->  989   (+2 top-level statements)
  census        added=0 removed=0, ledger=242, total=1634   UNCHANGED
                (lemmas carry NO census rows; no op/axiom/module added)
  CONE_FILES    45   UNCHANGED
  taint closure  6   UNCHANGED (neither new lemma touches an admit)
  MOVED pins    NONE -- the two new ones are ADDITIONS; no existing statement is edited
                except _AT_DEPLOYED_PARAMS's inherited comment, which is stripped from
                the COPY only, so the parent's digest must NOT move.
  identity      MUST move (a cone file changed)

A moved EXISTING pin, or any census movement, is a FINDING.

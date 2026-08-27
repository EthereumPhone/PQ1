# PRE-COMMITTED PREDICTION -- dropping the three redundant deployed pins (2026-08-27)
  CONE_FILES    45      UNCHANGED (C10DeployedCapstone is ALREADY a certification root and
                        already in the 45-file cone; the new `require` only makes it
                        reachable from GprocChargedQWired as well)
  census        added=0 removed=0, ledger=242, total=1634   UNCHANGED (same file set)
  EXPECT_PINS   1072    UNCHANGED IN COUNT
  EXPECT_STMTS  987     UNCHANGED
  coverage      987/987 UNCHANGED
  MOVED         exactly ONE statement digest:
                cdrafts-split/GprocChargedQWired.ec::EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS
  taint closure 6 lemmas UNCHANGED
  identity      MUST move (a cone file changed)
Any OTHER pin moving, or any census movement, is a FINDING.

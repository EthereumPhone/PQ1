# PRE-COMMITTED PREDICTION -- PHASE 5 (taint containment)
Written BEFORE the gate run.  A mismatch is a FINDING, not something to reconcile after.

## This change adds NO EasyCrypt content
New files:  tools/taint_closure.py, cert-taint-closure.tsv, scratch/taint_controls.sh
Modified :  cert_gate_split.sh (PHASE 5 + hashed set at BOTH occurrences)
No .ec file is touched.  Therefore:

  census        added=0 removed=0, ledger=242, total=1634   UNCHANGED
  EXPECT_PINS   1072                                        UNCHANGED
  EXPECT_STMTS  987                                         UNCHANGED
  coverage      987/987                                     UNCHANGED
  CONE_FILES    45                                          UNCHANGED
  controls      6                                           UNCHANGED (the taint controls
                                                            run INSIDE phase 5, they are not
                                                            cert-controls-split.tsv rows)

  INPUTS_SHA256 MUST CHANGE -- cert_gate_split.sh changed and three files joined the
                hashed set.  Take the new value from tools/encode-compat/inputs_id.sh,
                which is validated against the gate's own printed value.

## PHASE 5 must print
  OK   taint containment: closure = 6 lemmas, none of the 6 headline results is in it
  OK   taint controls: taint controls: pass=5 fail=0

## What would make this a FINDING
Any census/pin/coverage movement at all.  This change adds a phase, a tool, a manifest and
a control fixture; if it moves an EasyCrypt-level number, something is wrong with my
understanding of what the gate hashes vs what it counts.

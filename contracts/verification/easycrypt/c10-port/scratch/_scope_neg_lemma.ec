(* SCOPE-ISOLATION CONTROL (2026-09-15), MUST-FAIL in cert-controls-split.tsv.
   The admitted lemma itself must be UNKNOWN in the headline environment.  Twin: _scope_pos_lemma.ec.
   See the section comment in cert-controls-split.tsv and scratch/PREDICTION-scope-controls-2026-09-15.md. *)
require import AllCore.
require GprocTCollNamed.
lemma probe_scope : true. proof. have _ := FORS_C_TreePort.extract_op. trivial. qed.

(* SCOPE-ISOLATION CONTROL (2026-09-15), MUST-PASS in cert-controls-split.tsv.
   Twin of _scope_neg_lemma.ec, ONE require apart: with FORS_C_TreePort loaded, `have _ :=` of the
   module-quantified extract_op is accepted, so the negative fails for scope and not for form.
   See the section comment in cert-controls-split.tsv and scratch/PREDICTION-scope-controls-2026-09-15.md. *)
require import AllCore.
require GprocTCollNamed FORS_C_TreePort.
lemma probe_scope : true. proof. have _ := FORS_C_TreePort.extract_op. trivial. qed.

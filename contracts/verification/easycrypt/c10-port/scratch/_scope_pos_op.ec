(* SCOPE-ISOLATION CONTROL (2026-09-15), MUST-PASS in cert-controls-split.tsv.
   Twin of _scope_neg_op_GprocTCollNamed.ec, ONE require apart: with FORS_C_TreePort loaded the
   same op reference is well-formed, so the negative fails for scope and not for syntax.
   See the section comment in cert-controls-split.tsv and scratch/PREDICTION-scope-controls-2026-09-15.md. *)
require import AllCore.
require GprocTCollNamed FORS_C_TreePort.
op probe_scope : bool = FORS_C_TreePort.fverify_structural.

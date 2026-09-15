(* SCOPE-ISOLATION CONTROL (2026-09-15), MUST-FAIL in cert-controls-split.tsv.
   The headline environment must NOT contain FORS_C_TreePort (home of the only admit,
   extract_op): the op reference below must be rejected as UNKNOWN.  Twin: _scope_pos_op.ec.
   See the section comment in cert-controls-split.tsv and scratch/PREDICTION-scope-controls-2026-09-15.md. *)
require import AllCore.
require GprocTCollNamed.
op probe_scope : bool = FORS_C_TreePort.fverify_structural.

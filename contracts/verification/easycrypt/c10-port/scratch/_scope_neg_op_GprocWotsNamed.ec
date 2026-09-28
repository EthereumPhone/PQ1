(* SCOPE-ISOLATION CONTROL (2026-09-15, per file), MUST-FAIL in cert-controls-split.tsv.
   Per-file negative for headline theory GprocWotsNamed: FORS_C_TreePort (home of extract_op, the only
   admit) must be UNKNOWN in its environment.  Shared op-form twin: _scope_pos_op.ec.
   See the per-file section in cert-controls-split.tsv and scratch/PREDICTION-scope-perfile-2026-09-15.md. *)
require import AllCore.
require GprocWotsNamed.
op probe_scope : bool = FORS_C_TreePort.fverify_structural.

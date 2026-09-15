(* SCOPE-ISOLATION CONTROL (2026-09-15), MUST-PASS in cert-controls-split.tsv.
   ENVIRONMENT WITNESS.  After `require GprocTCollNamed.` a symbol 3 require-hops away (via
   SPHINCS_PLUS) resolves by qualified name.  Without this the negatives could be failing in an
   environment SMALLER than the headline file's own.
   See the section comment in cert-controls-split.tsv and scratch/PREDICTION-scope-controls-2026-09-15.md. *)
require import AllCore.
require GprocTCollNamed.
op probe_env = WOTS_TW_ES.n_m.

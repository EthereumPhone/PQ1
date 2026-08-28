(* PROBE (not a control): how far does a BARE `smt()` reach into the environment?
   PHASE 5's first named hole is "a bare smt() takes a lemma from ambient context without
   naming it".  That hole's SIZE is an empirical question about EasyCrypt, not a design
   choice, and it has never been measured here. *)
require import AllCore.
require import SPHINCS_PLUS.

(* P1 -- can a bare smt() reach an AXIOM of a required theory?
   `1 <= n` follows from `axiom n_val : n = 16` (SPHINCS_PLUS.ec:44) and from nothing else:
   `n` is `op n : int.` with no other constraint. *)
lemma P1_axiom_reach : 1 <= n.
proof. smt(). qed.

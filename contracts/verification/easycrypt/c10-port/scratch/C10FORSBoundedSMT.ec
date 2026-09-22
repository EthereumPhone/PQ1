(* Regression: SMT must be able to refer to the actual cloned sampler. *)
require import AllCore List Distr.
require FORS_C10.
clone import FORS_C10.FORSC10 as F.
lemma sampler_mass (m : msg) (fuel : unit list) :
  0%r <= mu1 (bounded_r m fuel) None.
proof. smt(ge0_mu). qed.

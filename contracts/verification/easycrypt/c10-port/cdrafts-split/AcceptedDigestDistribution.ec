(* Exact acceptance splitting for fresh raw draws, not a fresh-signature assumption. *)
require import AllCore List Distr DList DBool StdOrder.
require import C10RawOracle C10RawGrind C10Randomizer FORSC10Digest AcceptedSampling.
import RField RealOrder DBool.Biased.

op accepted_digest = dcond full_digest accept_digest.
op rejected_digest = dcond full_digest (predC accept_digest).

lemma accepted_digest_ll : is_lossless accepted_digest.
proof. apply dcond_ll; rewrite fors_acceptance_mass; exact acceptance_rate_positive. qed.
lemma acceptance_rate_lt_one : acceptance_rate < 1%r.
proof. rewrite /acceptance_rate exprn_ilt1 1,2:/#; smt(). qed.
lemma rejected_digest_ll : is_lossless rejected_digest.
proof.
  apply dcond_ll; rewrite mu_not full_digest_ll fors_acceptance_mass -/acceptance_rate.
  smt(acceptance_rate_lt_one).
qed.
lemma accepted_digest_support d : d \in accepted_digest => size d=256 /\ accept_digest d.
proof. rewrite /accepted_digest dcond_supp; rewrite /full_digest supp_dlist 1://; smt(). qed.
lemma rejected_digest_support d : d \in rejected_digest => size d=256 /\ !accept_digest d.
proof. rewrite /rejected_digest dcond_supp /predC; rewrite /full_digest supp_dlist 1://; smt(). qed.
lemma accepted_digest_probability p : mu accepted_digest p=accepted_probability p.
proof.
  rewrite /accepted_digest dcondE /accepted_probability /accepted_mass
    /predI fors_acceptance_mass /acceptance_rate.
  by [].
qed.
lemma full_digest_acceptance_split :
  full_digest = dlet (dbiased acceptance_rate)
    (fun b => if b then accepted_digest else rejected_digest).
proof.
  rewrite (marginal_sampling_pred full_digest accept_digest full_digest_ll)
    fors_acceptance_mass /acceptance_rate /accepted_digest /rejected_digest.
  by [].
qed.

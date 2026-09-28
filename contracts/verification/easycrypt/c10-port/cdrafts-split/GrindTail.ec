(* Probability that all fresh H_msg replies in a bounded loop reject. *)
require import AllCore Distr StdOrder Xreal C10RawOracle C10RawGrind C10Counter C10Randomizer FORSC10Digest.
import RField RealOrder.
op reject_mass = 1%r - (1%r/2%r)^11.
lemma reject_positive : 0%r < reject_mass.
proof.
  have hp : (1%r/2%r)^11 <= (1%r/2%r)^1 by apply ler_wiexpn2l; smt().
  rewrite expr1 in hp;
  by rewrite /reject_mass; smt().
qed.
module FreshLoop = {
  var i : int
  var rejecting : bool
  proc run() : bool = {
    var hd;
    while (i < signing_budget /\ rejecting) {
      hd <$ full_digest;
      rejecting <- !accept_digest hd;
      i <- i+1;
    }
    return rejecting;
  }
}.
ehoare fresh_loop_tail : FreshLoop.run :
  (0 <= FreshLoop.i <= signing_budget) `|`
    (reject_mass ^ (signing_budget-FreshLoop.i))%xr * FreshLoop.rejecting%xr
    ==> res%xr.
proof.
  proc; while ((0 <= FreshLoop.i <= signing_budget) `|`
    (reject_mass ^ (signing_budget-FreshLoop.i))%xr * FreshLoop.rejecting%xr).
  + move=> &hr; apply xle_cxr_r => hg; apply xle_cxr_r => hi.
    case (FreshLoop.rejecting{hr}) => hb.
    - have he : FreshLoop.i{hr} = signing_budget by smt().
      by rewrite he /= expr0 /=.
    by [].
  + wp; skip => &hr; apply xle_cxr_r => hg; apply xle_cxr_r => hi.
    have hn : 0 <= FreshLoop.i{hr}+1 <= signing_budget by smt().
    have hb : FreshLoop.rejecting{hr} by smt().
    rewrite (eq_Ep _ _ (fun hd =>
      (reject_mass ^ (signing_budget-(FreshLoop.i{hr}+1)))%xr * (!accept_digest hd)%xr)).
    - by move=> hd _; rewrite /= hn /=.
    rewrite EpZ.
    - smt(reject_positive expr_gt0 of_realdK to_realP).
    rewrite Ep_mu mu_not full_digest_ll fors_acceptance_mass -/reject_mass hb /=.
    have hp : forall n, 0%r <= reject_mass^n by move=> n; apply expr_ge0; smt(reject_positive).
    have hp0 : 0%r <= reject_mass by smt(reject_positive).
    rewrite !to_pos_pos 1:hp 1:hp0 1:hp.
    have he : signing_budget-FreshLoop.i{hr} = (signing_budget-(FreshLoop.i{hr}+1))+1 by ring.
    by rewrite he exprSr 1:/#.
  by auto.
qed.

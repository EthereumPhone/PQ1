(* Single-step rejection potential, with cached hits excluded explicitly. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10RawGrind C10Randomizer FORSC10Digest.
require import PrefixGuess RawTrial GrindTail.
import RField RealOrder.

ehoare trial_rejection_potential : Trial.run : reject_mass%xr ==>
  (!Trial.known /\ !accept_digest res.`2)%xr.
proof.
  proc; seq 4 : ((Trial.known = (x \in Independent.rawhistory)) `|` reject_mass%xr).
  + wp; conseq (_ : _ ==> reject_mass%xr) => //.
    call (_ : reject_mass%xr ==> reject_mass%xr).
    - proc; if; auto.
      + move=> &hr; apply xle_cxr_r => _; by rewrite EpC full_digest_ll /=.
      by move=> &hr; apply xle_cxr_r.
    by auto.
  inline Independent.hash; wp.
  skip => &hr; apply xle_cxr_r => hk.
  case (x{hr} \in Independent.rawhistory{hr}) => hx.
  + have hb : Trial.known{hr} by smt().
    rewrite hb /=; smt(reject_positive to_pos_pos).
  have hb : !Trial.known{hr} by smt().
  rewrite hb /=.
  rewrite (eq_Ep _ _ (fun hd => (!accept_digest hd)%xr)).
  + by move=> hd _; rewrite /= FMap.get_set_sameE /=.
  by rewrite Ep_mu mu_not full_digest_ll fors_acceptance_mass -/reject_mass.
qed.
